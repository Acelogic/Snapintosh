#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that a kmutil AuxKC holds exactly the kext bundles it was asked for.

    tools/auxkc-bundles.py OUT.kc KEXT_BUNDLE...

build/kmutil-auxkc.sh runs this (as root, stdlib only, no bytecode) after
kmutil. A code-bearing kext is a LC_FILESET_ENTRY *and* a __PRELINK_INFO
row; a codeless one (SnapintoshBootFramebuffer.kext) is only a prelink row,
so an entry_id check alone reports it missing. Exits 1 on any difference:
a dropped kext, an added one (kmutil adds Apple kexts without -x), or a code
kext linked without its executable.
"""
import plistlib
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'probes'))
import auxkc


def requested(kexts):
    result = {}
    for kext in kexts:
        info = plistlib.loads((Path(kext) / 'Contents/Info.plist').read_bytes())
        bundle = info.get('CFBundleIdentifier')
        if not isinstance(bundle, str) or bundle in result:
            raise ValueError(f'{kext}: missing or duplicate CFBundleIdentifier')
        result[bundle] = 'CFBundleExecutable' in info
    return result


def check(data, wanted):
    """Problems as text lines; empty means exact."""
    collection = auxkc.Collection(data)
    kexts = collection.prelink_info()['_PrelinkInfoDictionary']
    held = {k.get('CFBundleIdentifier'): 'CFBundleExecutable' in k for k in kexts}
    entries = {name for name, _, _ in collection.entries}
    problems = [f'MISSING: {b}' for b in sorted(set(wanted) - set(held))]
    problems += [f'UNREQUESTED: {b}' for b in sorted(set(held) - set(wanted))]
    for bundle, coded in sorted(wanted.items()):
        if bundle in held and held[bundle] != coded:
            problems.append(f'EXECUTABLE MISMATCH: {bundle}')
        if coded and bundle not in entries:
            problems.append(f'NO FILESET ENTRY: {bundle}')
    problems += [f'ENTRY WITHOUT CODE KEXT: {e}' for e in sorted(entries - {b for b, c in held.items() if c})]
    return problems


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    wanted = requested(sys.argv[2:])
    problems = check(Path(sys.argv[1]).read_bytes(), wanted)
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        return 1
    print('bundles:', ' '.join(f'{b}{"" if c else " (codeless)"}' for b, c in sorted(wanted.items())))
    return 0


if __name__ == '__main__':
    sys.exit(main())
