#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Append our CDHashes to the pinned Apple boot trust cache, offline.

Replaces the adreno prototype `injection/augment_trustcache.py`, whose rows
ended 00 02 02 00 (flags u16 first) where Apple's end 02 00 cc 00 (hash type,
flags, u16 category) and whose collision check was dead code.

    # record a signed bundle's CDHash (codesign reads the bundle)
    tools/augment-trust-cache.py --additions build/gpu-trust.json \\
        --add-bundle build/AdrenoMetal.bundle --category 2
    # check the whole cache against the profile and the loader reservation
    tools/augment-trust-cache.py --additions build/gpu-trust.json \\
        --output build/gpu-trust.trustcache

The loader never reads --output: it rebuilds the same bytes from the pinned
base and the additions file (xnuboot.trust_cache_spec), and audits verify the
resident cache the same way. The file is for inspection and diffing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
from trustcache import AugmentedTrustCacheSpec, addition_entries, parse_v2, MAX_PAYLOAD


def bundle_cdhash(path):
    """The code directory hash codesign reports for a signed bundle."""
    result = subprocess.run(['codesign', '-d', '--verbose=4', str(path)],
                            capture_output=True, text=True)
    hashes = re.findall(r'^CDHash=([0-9a-f]{40})$', result.stderr, re.M)
    types = re.findall(r'^Hash type=(\S+)', result.stderr, re.M)
    if result.returncode or len(hashes) != 1:
        raise ValueError(f'{path}: no single CDHash from codesign:\n{result.stderr}')
    if types and types[0] != 'sha256':
        raise ValueError(f'{path}: CDHash type {types[0]}, expected sha256')
    return hashes[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--guest-profile', default='j700ap-26A428-bootfb-auxkc-gpu')
    ap.add_argument('--additions', type=Path, required=True,
                    help='JSON rows {"cdhash", "category", "name"}; created by --add-*')
    ap.add_argument('--add-bundle', type=Path, action='append', default=[],
                    help='append the CDHash codesign reports for this signed bundle')
    ap.add_argument('--add-cdhash', action='append', default=[], metavar='HEX',
                    help='append a 40-hex-digit (or 64) CDHash directly')
    ap.add_argument('--category', type=int, default=2,
                    help='trust-cache category for appended rows (Apple paravirt plug-in: 2)')
    ap.add_argument('--output', type=Path, help='write the augmented cache for inspection')
    args = ap.parse_args()
    xb.configure_guest(args.guest_profile)
    spec = xb.GUEST_PROFILE.trust_cache
    if not isinstance(spec, AugmentedTrustCacheSpec):
        raise SystemExit(f'profile {args.guest_profile} pins the unmodified Apple cache')
    rows = json.loads(args.additions.read_text()) if args.additions.exists() else []
    added = [(bundle_cdhash(p), p.name) for p in args.add_bundle]
    added += [(h.lower(), 'cdhash') for h in args.add_cdhash]
    for digest, name in added:
        if not re.fullmatch(r'[0-9a-f]{40}([0-9a-f]{24})?', digest):
            raise SystemExit(f'invalid CDHash {digest!r}')
        rows.append(dict(cdhash=digest[:40], category=args.category, name=name))
    # Everything is checked before the additions file changes.
    bound = spec.bind(addition_entries(rows))
    payload = bound.load(xb.FIRMWARE_DIR)
    bound.verify(payload)
    if len(payload) > MAX_PAYLOAD or not xb.static_trust_fits(len(payload)):
        raise SystemExit(f'{len(payload)} bytes exceed the monitor/loader trust reservation')
    if added:
        args.additions.write_text(json.dumps(rows, indent=2) + '\n')
    entries = parse_v2(payload)['entries']
    positions = {row[:20].hex(): n for n, row in enumerate(entries)}
    if args.output:
        args.output.write_bytes(payload)
    print(json.dumps(dict(profile=args.guest_profile, base_entries=spec.base.entries,
        appended=len(bound.appended), entries=bound.entries, bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        rows=[dict(r, index=positions[r['cdhash'][:40]], trailer=entries[positions[r['cdhash'][:40]]][20:].hex())
              for r in rows],
        output=str(args.output) if args.output else None), indent=2))


if __name__ == '__main__':
    main()
