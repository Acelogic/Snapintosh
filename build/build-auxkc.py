#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage, link (through build/kmutil-auxkc.sh) and pin a code-bearing AuxKC.

kmutil silently drops kexts that are not root:wheel and still exits 0, so the
only link step is the lead's verified `sudo build/kmutil-auxkc.sh`, which
stages root-owned copies, links with -x against the pinned BootKC and the KDK,
and fails unless the output holds exactly the requested bundle ids. Nothing
here calls kmutil itself and nothing here needs root except that one script.

  1. stage (no sudo): for a boot-framebuffer profile, generate the codeless
     SnapintoshBootFramebuffer.kext from drivers/boot-framebuffer and
     probes/bootfb.py (the profile's nub personality). Prints the link line.

       python3 build/build-auxkc.py stage --out build/auxkc-hello-bootfb \\
           --guest-profile j700ap-26A428-bootfb-auxkc

  2. link (the user, with sudo; the exact line stage printed):

       sudo build/kmutil-auxkc.sh build/auxkc-hello-bootfb/aux.kc \\
           build/auxkc-hello-bootfb/SnapintoshBootFramebuffer.kext \\
           build/auxkc-20260925/SnapHello.kext

  3. pin (no sudo): admit the collection exactly as the loader will and write
     <kc>.json, the manifest whose sha256 the loader and audits require.

       python3 build/build-auxkc.py pin --kc build/auxkc-20260925/aux-hello.kc \\
           --guest-profile j700ap-26A428-xars-uniform-auxkc \\
           --bundle org.snapintosh.driver.SnapHello \\
           --sha256 4d23b139739beb1a429f98e479f587ff665feafe92ae0b6b9829fd76a2644b08

`link` runs 1-3 in one go for the user (it invokes sudo on the script only).
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'probes'))
import auxkc
import bootfb
import xnuboot as xb

LINK_SCRIPT = ROOT / 'build/kmutil-auxkc.sh'
BOOTFB_SOURCE = ROOT / 'drivers/boot-framebuffer/SnapintoshBootFramebuffer.kext/Contents/Info.plist'
BOOTFB_KEXT = 'SnapintoshBootFramebuffer.kext'


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def profile(name):
    xb.configure_guest(name)
    if not xb.GUEST_PROFILE.aux_collection_linked:
        raise SystemExit(f'profile {name} does not load a linked AuxKC')
    return xb.GUEST_PROFILE


def kext_bundle_id(path):
    info = plistlib.loads((Path(path) / 'Contents/Info.plist').read_bytes())
    bundle = info.get('CFBundleIdentifier')
    if not isinstance(bundle, str) or not bundle:
        raise SystemExit(f'{path}: no CFBundleIdentifier')
    return bundle


def stage(out, guest):
    """The generated codeless bundle, or None for a profile without it."""
    if not guest.boot_framebuffer_aux:
        return None
    kext = Path(out) / BOOTFB_KEXT
    if kext.exists():
        raise SystemExit(f'{kext} exists; choose a fresh --out')
    generated = bootfb.kext_info(plistlib.loads(BOOTFB_SOURCE.read_bytes()),
                                 dedicated=guest.boot_framebuffer_nub)
    (kext / 'Contents').mkdir(parents=True)
    (kext / 'Contents/Info.plist').write_bytes(
        plistlib.dumps(generated, fmt=plistlib.FMT_XML, sort_keys=True))
    return kext


def link_command(kc, kexts):
    return ['sudo', str(LINK_SCRIPT), str(kc)] + [str(k) for k in kexts]


def kext_errors(collection, bundles):
    """kmutil's own rejection notes (__KCGEN_INFO,__kext_errs) naming our bundles."""
    section = collection.sections.get(('__KCGEN_INFO', '__kext_errs'))
    if section is None:
        return {}
    _, size, off = section
    try:
        notes = plistlib.loads(collection.data[off:off + size].rstrip(b'\0'))
    except Exception:
        return {}
    return {k: v for k, v in notes.items() if any(b in k or b in str(v) for b in bundles)}


def pin(kc, guest, requested, expected_sha=None):
    """Admit `kc` for `guest` and write its manifest. Returns the manifest."""
    kc = Path(kc).resolve()
    manifest_path = auxkc.manifest_path(kc)
    if manifest_path.exists():
        raise SystemExit(f'{manifest_path} exists; a pin is written once')
    kernel = xb.DEFAULT_KERNELCACHE
    kernel_sha = xb.PROFILE_FIRMWARE[guest.kernelcache]
    if sha256(kernel) != kernel_sha:
        raise SystemExit(f'{kernel} is not the pinned {guest.name} kernelcache')
    data = kc.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha is not None and digest != expected_sha.lower():
        raise SystemExit(f'{kc} is {digest}, not the expected {expected_sha}')
    requested = sorted(set(requested))
    if bootfb.BUNDLE_ID in requested:
        raise SystemExit(f'{bootfb.BUNDLE_ID} is added from the profile, not --bundle')
    bundles = sorted(requested + ([bootfb.BUNDLE_ID] if guest.boot_framebuffer_aux else []))
    collection = auxkc.Collection(data)
    errors = kext_errors(collection, bundles)
    if errors:
        raise SystemExit('kmutil recorded errors for requested bundles:\n' +
                         '\n'.join(f'  {k}: {v}' for k, v in errors.items()))
    image = xb.kc_load.Image(kernel.read_bytes())
    personality = (bootfb.collection_personality(plistlib.loads(BOOTFB_SOURCE.read_bytes()),
                                                 dedicated=guest.boot_framebuffer_nub)
                   if guest.boot_framebuffer_aux else None)
    admission = auxkc.admit(collection, image, bootfb._prelink_info(image), bundles, personality)
    manifest = dict(format=auxkc.MANIFEST_FORMAT, sha256=digest, bytes=len(data),
                    kernel_sha256=kernel_sha, guest_profile=guest.name,
                    bundles=bundles, requested=requested,
                    builder=dict(script=str(LINK_SCRIPT.relative_to(ROOT)),
                                 sha256=sha256(LINK_SCRIPT) if LINK_SCRIPT.is_file() else None),
                    admission=admission,
                    pinned=datetime.datetime.now(datetime.timezone.utc).isoformat())
    # The loader's own admission path, before anything is written.
    with manifest_path.open('x') as stream:
        stream.write(json.dumps(manifest, indent=2) + '\n')
    try:
        xb.linked_auxkc(image, kc)
    except Exception:
        manifest_path.unlink()
        raise
    return manifest


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='command', required=True)
    s = sub.add_parser('stage', help='generate the codeless bundle and print the sudo link line')
    s.add_argument('--out', type=Path, required=True, help='fresh directory for the generated bundle')
    s.add_argument('--kext', type=Path, action='append', default=[], help='our kext bundle(s)')
    s.add_argument('--guest-profile', default='j700ap-26A428-bootfb-auxkc')
    p = sub.add_parser('pin', help='admit a linked collection and write <kc>.json')
    p.add_argument('--kc', type=Path, required=True)
    p.add_argument('--bundle', action='append', required=True,
                   help='our bundle id(s) the collection must hold (the boot framebuffer '
                        'bundle is added from the profile)')
    p.add_argument('--sha256', help='refuse unless the collection has this sha256')
    p.add_argument('--guest-profile', default='j700ap-26A428-bootfb-auxkc')
    l = sub.add_parser('link', help='stage, run sudo build/kmutil-auxkc.sh, pin')
    l.add_argument('--out', type=Path, required=True, help='fresh directory; the KC is <out>/aux.kc')
    l.add_argument('--kext', type=Path, action='append', required=True)
    l.add_argument('--guest-profile', default='j700ap-26A428-bootfb-auxkc')
    args = ap.parse_args()
    if os.geteuid() == 0:
        raise SystemExit('run this as the user; only build/kmutil-auxkc.sh needs sudo')
    guest = profile(args.guest_profile)
    if args.command == 'pin':
        manifest = pin(args.kc, guest, args.bundle, args.sha256)
        print(json.dumps(dict(kc=str(args.kc), manifest=str(auxkc.manifest_path(args.kc.resolve())),
                              sha256=manifest['sha256'], bundles=manifest['bundles'],
                              fixups=manifest['admission']['fixups'], top=manifest['admission']['top']),
                         indent=2))
        print(f'boot: probes/run.py xnuboot --guest-profile {guest.name} --auxkc {args.kc} ...')
        return
    if args.out.exists() and any(args.out.iterdir()):
        raise SystemExit(f'{args.out} is not empty; choose a fresh --out')
    args.out.mkdir(parents=True, exist_ok=True)
    generated = stage(args.out, guest)
    kexts = ([generated] if generated else []) + [k.resolve() for k in args.kext]
    bundles = [kext_bundle_id(k) for k in args.kext]
    kc = args.out / 'aux.kc'
    command = link_command(kc, kexts)
    if args.command == 'stage':
        print(' '.join(command))
        print(f'then: python3 build/build-auxkc.py pin --kc {kc} --guest-profile {guest.name} ' +
              ' '.join(f'--bundle {b}' for b in bundles))
        return
    if not LINK_SCRIPT.is_file():
        raise SystemExit(f'{LINK_SCRIPT} is missing')
    subprocess.run(command, check=True)
    manifest = pin(kc, guest, bundles)
    print(json.dumps(dict(kc=str(kc), sha256=manifest['sha256'], bundles=manifest['bundles']), indent=2))


if __name__ == '__main__':
    main()
