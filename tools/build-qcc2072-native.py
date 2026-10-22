#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile, audit and link the native QCC2072 controller without hardware access.

Failure inventory: drivers/snap-qcc2072/re/build-failures.md.
Uses the existing passwordless AuxKC workflow; does not install or change defaults.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'drivers/snap-qcc2072'
BUNDLE = 'org.snapintosh.driver.SnapintoshQCC2072'
PROFILE = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks'
GUEST_KC = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
GUEST_SHA256 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
BUILD_TOOLS = [
    Path(__file__).resolve(), ROOT / 'tools/build-auxkc-user.py',
    ROOT / 'tools/auxkc-autoload.py', ROOT / 'build/build-auxkc.py',
    ROOT / 'tools/verify-qcc2072-linked.py', ROOT / 'tools/gen-iomfb-header.py',
    ROOT / 'probes/auxkc.py', ROOT / 'tools/kc-load.py',
]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def tree_hashes(directory):
    return {str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and not p.name.startswith('._') and '__pycache__' not in p.parts}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True,
                   help='directory containing the qualified AdrenoX2/SnapI2CHID bundles')
    p.add_argument('--expected-baseline-sha256', required=True,
                   help='exact SHA256 of baseline/adreno-input.kc')
    args = p.parse_args()
    out, baseline = args.output.absolute(), args.baseline.resolve()
    if out.exists() or out.is_symlink():
        p.error('output must be new')
    if sha(baseline / 'adreno-input.kc') != args.expected_baseline_sha256:
        p.error('baseline collection hash changed')
    if sha(GUEST_KC) != GUEST_SHA256:
        p.error('guest kernel collection differs from the audited 26A428 build')
    sources = tree_hashes(DRIVER)
    tool_sources = {str(path.relative_to(ROOT)): sha(path) for path in BUILD_TOOLS}
    out.mkdir(parents=True)
    logs = out / 'logs'
    logs.mkdir()
    report = {'status': 'BUILDING', 'hardware_access': False, 'installed': False,
              'native_interface_registered': False, 'firmware_ready': False,
              'scanning_qualified': False, 'connecting_qualified': False,
              'source_sha256': sha(__file__), 'driver_sources': sources,
              'tool_sources': tool_sources,
              'guest_collection': str(GUEST_KC), 'guest_collection_sha256': GUEST_SHA256,
              'baseline': str(baseline), 'baseline_collection_sha256': args.expected_baseline_sha256,
              'commands': [], 'outputs': {}}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

    def run(label, command, extra_env=None):
        report['commands'].append({'label': label, 'argv': list(map(str, command))})
        with (logs / (label + '.log')).open('x') as log:
            subprocess.run(list(map(str, command)), cwd=ROOT, check=True,
                           env=dict(env, **(extra_env or {})), stdout=log, stderr=subprocess.STDOUT)

    try:
        run('compiler-version', ['/usr/bin/xcrun', 'clang', '--version'])
        run('sdk-version', ['/usr/bin/xcrun', '--show-sdk-version'])
        basecopy = out / 'baseline'
        basecopy.mkdir()
        baseline_hashes = {}
        bundles = []
        for name in ['AdrenoX2.kext', 'SnapI2CHID.kext']:
            source = baseline / name
            baseline_hashes[name] = tree_hashes(source)
            if not baseline_hashes[name]:
                raise ValueError('missing baseline bundle: ' + name)
            dest = basecopy / name
            shutil.copytree(source, dest, copy_function=shutil.copy2)
            if tree_hashes(dest) != baseline_hashes[name]:
                raise ValueError('baseline copy mismatch: ' + name)
            bundles.append(dest)
        report['baseline_bundle_files'] = baseline_hashes
        run('compile', ['/bin/sh', DRIVER / 'build.sh'], {'OUT': str(out / 'kext')})
        kext = out / 'kext/SnapintoshQCC2072.kext'
        binary = kext / 'Contents/MacOS/SnapintoshQCC2072'
        run('native-abi', [sys.executable, '-B', DRIVER / 're/verify-controller-abi.py',
                           '--binary', binary, '--report', out / 'native-abi.json'])
        bundles.append(kext)
        ids = [plistlib.loads((b / 'Contents/Info.plist').read_bytes())['CFBundleIdentifier']
               for b in bundles]
        if len(set(ids)) != 3 or BUNDLE not in ids:
            raise ValueError('unexpected candidate bundle set')
        raw, final = out / 'native-wifi.raw.kc', out / 'native-wifi.kc'
        run('link', [sys.executable, '-B', ROOT / 'tools/build-auxkc-user.py', raw, *bundles])
        bundle_args = [x for identifier in ids for x in ['--bundle', identifier]]
        run('autoload', [sys.executable, '-B', ROOT / 'tools/auxkc-autoload.py', raw, final,
                         '--expected-sha256', sha(raw), *bundle_args,
                         '--record', out / 'packaging.json'])
        run('pin', [sys.executable, '-B', ROOT / 'build/build-auxkc.py', 'pin', '--kc', final,
                    '--guest-profile', PROFILE, '--sha256', sha(final), *bundle_args])
        run('linked-abi', [sys.executable, '-B', ROOT / 'tools/verify-qcc2072-linked.py',
                           '--binary', binary, '--collection', final,
                           '--abi-report', out / 'native-abi.json',
                           '--report', out / 'linked-abi.json'])
        if tree_hashes(DRIVER) != sources:
            raise ValueError('driver sources changed during build')
        if {str(path.relative_to(ROOT)): sha(path) for path in BUILD_TOOLS} != tool_sources:
            raise ValueError('build/verification tools changed during build')
        for name, expected in baseline_hashes.items():
            if tree_hashes(baseline / name) != expected or tree_hashes(basecopy / name) != expected:
                raise ValueError('baseline bundle changed: ' + name)
        if sha(baseline / 'adreno-input.kc') != args.expected_baseline_sha256:
            raise ValueError('baseline collection changed during build')
        if sha(GUEST_KC) != GUEST_SHA256:
            raise ValueError('guest collection changed during build')
        report['bundle_identifiers'] = sorted(ids)
        report['outputs'] = {str(f.relative_to(out)): sha(f) for f in
                             [binary, raw, final, out / 'native-abi.json', out / 'linked-abi.json',
                              out / 'packaging.json',
                              out / 'native-wifi.kc.json', out / 'native-wifi.raw.kc.build.json']}
        report['log_sha256'] = {str(f.relative_to(out)): sha(f)
                               for f in sorted(logs.glob('*.log'))}
        report['status'] = 'NATIVE_WIFI_AUXKC_LINKED_RUNTIME_UNQUALIFIED'
    except Exception as error:
        report['status'] = 'FAILED'
        report['error'] = str(error)
        raise
    finally:
        (out / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': report['status'], 'receipt': str(out / 'build.json'),
                          'hardware_access': False, 'installed': False}))


if __name__ == '__main__':
    main()
