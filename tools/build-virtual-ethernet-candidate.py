#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a disconnected Ethernet identity candidate without installing or pinning it.

Reuses hash-verified GPU objects from the saved console-release qualification.
Native kmutil linking is the ABI/dependency check; runtime behavior is unproven.
Failure inventory: docs/VIRTUAL-ETHERNET-CLOCK-IDENTITY-20260927.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT.with_name('Snapintosh-adreno-pipeline')
BASE = PIPELINE / 'build/adreno-console-release-20260927/integration-v1'
BASE_SHA = '4fdd2dd445f960ffd9eabcf6c6d05073a7b7e6fb6133a79bc9aac96e80cbd16b'
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(8 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def macho(data, offset=0):
    assert struct.unpack_from('<I', data, offset)[0] == 0xfeedfacf
    count = struct.unpack_from('<I', data, offset + 16)[0]
    p = offset + 32
    uuid, segments, entries = None, {}, {}
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, p)
        assert size >= 8
        if cmd == 0x1b:
            uuid = data[p + 8:p + 24].hex()
        elif cmd == 0x19:
            name = data[p + 8:p + 24].rstrip(b'\0').decode()
            segments[name] = struct.unpack_from('<QQQQ', data, p + 24)
        elif cmd == 0x80000035:
            _, fileoff, strx = struct.unpack_from('<QQI', data, p + 8)
            name = data[p + strx:data.index(b'\0', p + strx)].decode()
            entries[name] = fileoff
        p += size
    return uuid, segments, entries


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands, inputs = [], {}

    def bind(path, expected=None):
        path = Path(path).resolve()
        digest = sha(path)
        assert expected is None or digest == expected, str(path)
        inputs[str(path)] = digest
        return path

    def run(name, argv):
        argv = [str(x) for x in argv]
        commands.append(argv)
        path = out / (name + '.log')
        with path.open('x') as log:
            subprocess.run(argv, cwd=ROOT, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        return path.read_text()

    bind(__file__)
    bind(ROOT / 'docs/VIRTUAL-ETHERNET-CLOCK-IDENTITY-20260927.md')
    record = json.loads(bind(BASE / 'qualification.json', BASE_SHA).read_text())
    for name, digest in record['sources_sha256'].items():
        bind(PIPELINE / name, digest)
    objdir = out / 'obj'
    objdir.mkdir()
    objects = []
    for name, digest in record['artifacts_sha256'].items():
        if name.startswith('kext/obj/') and name.endswith('.o'):
            src = bind(BASE / name, digest)
            dest = objdir / src.name
            shutil.copyfile(src, dest)
            assert sha(dest) == digest
            objects.append(dest)
    assert len(objects) == 10
    source = PIPELINE / 'gpu/adreno-kext/kext/src/SnapintoshVirtualEthernet.cpp'
    bind(source)
    bind(source.with_suffix('.h'))
    sdk = Path(run('sdk', ['xcrun', '--show-sdk-path']).strip())
    headers = sdk / 'System/Library/Frameworks/Kernel.framework/Headers'
    for name in ('IOEthernetController', 'IONetworkController', 'IONetworkInterface',
                 'IOEthernetInterface', 'IONetworkMedium', 'IOOutputQueue'):
        bind(headers / ('IOKit/network/' + name + '.h'))
    virtual = objdir / 'SnapintoshVirtualEthernet.o'
    common = ['xcrun', 'clang++', '-target', 'arm64e-apple-macos27.0',
              '-isysroot', sdk, '-mkernel']
    run('compile', common + ['-nostdinc', '-I' + str(headers), '-DKERNEL', '-DAPPLE',
        '-DNeXT', '-O2', '-g', '-Wall', '-Werror', '-Wno-unused-private-field',
        '-fno-common', '-std=gnu++17', '-fapple-kext', '-fno-exceptions', '-fno-rtti',
        '-Wno-inconsistent-missing-override', '-c', source, '-o', virtual])
    sizes = {}
    for name, expected in [('IOEthernetController', 0x118),
                           ('IONetworkController', 0x110),
                           ('SnapintoshVirtualEthernet', 0x130)]:
        dwarf = run('dwarf-' + name,
                    ['xcrun', 'dwarfdump', '--name=' + name, virtual])
        matches = re.findall(r'DW_AT_byte_size\s+\((0x[0-9a-fA-F]+)\)', dwarf)
        assert matches and {int(x, 16) for x in matches} == {expected}, name
        sizes[name] = expected

    family = KDK / 'System/Library/Extensions/IONetworkingFamily.kext'
    native = bind(family / 'Contents/MacOS/IONetworkingFamily')
    family_plist = plistlib.loads(bind(family / 'Contents/Info.plist').read_bytes())
    thin = out / 'IONetworkingFamily.arm64e'
    fat = native.read_bytes()
    assert struct.unpack_from('>I', fat)[0] == 0xcafebabe
    slices = [struct.unpack_from('>IIIII', fat, 8 + 20 * i)
              for i in range(struct.unpack_from('>I', fat, 4)[0])]
    selected = [s for s in slices if s[0] == 0x100000c and (s[1] & 0xffffff) == 2]
    assert len(selected) == 1
    _, _, offset, length, _ = selected[0]
    data = fat[offset:offset + length]
    assert len(data) == length
    thin.write_bytes(data)
    nuuid, nsegs, _ = macho(data)
    guest = bind(ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p',
                 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62')
    gdata = guest.read_bytes()
    _, _, entries = macho(gdata)
    ident = 'com.apple.iokit.IONetworkingFamily'
    guuid, gsegs, _ = macho(gdata, entries[ident])
    assert nuuid == guuid
    witnesses = []
    for name, address, word in [('IOEthernetController', 0x4020, 0x52802303),
                                 ('IONetworkController', 0xe7e8, 0x52802203)]:
        segname, seg = next((n, v) for n, v in nsegs.items()
                            if v[0] <= address < v[0] + v[3])
        relative = address - seg[0]
        nw = struct.unpack_from('<I', data, seg[2] + relative)[0]
        gs = gsegs[segname]
        gw = struct.unpack_from('<I', gdata, gs[2] + relative)[0]
        assert nw == gw == word
        assert ((word >> 5) & 0xffff) == sizes[name]
        witnesses.append(dict(class_name=name, kdk_address=hex(address),
            guest_address=hex(gs[0] + relative), word=hex(word), size=sizes[name]))

    bundle = out / 'AdrenoX2.kext'
    contents = bundle / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    plistpath = bind(BASE / 'kext/AdrenoX2.kext/Contents/Info.plist',
                    record['artifacts_sha256']['kext/AdrenoX2.kext/Contents/Info.plist'])
    info = plistlib.loads(plistpath.read_bytes())
    info['OSBundleLibraries'][ident] = family_plist['CFBundleVersion']
    info['IOKitPersonalities']['SnapintoshVirtualEthernet'] = dict(
        CFBundleIdentifier=info['CFBundleIdentifier'], IOClass='SnapintoshVirtualEthernet',
        IOProviderClass='AdrenoAcceleratorX2', IOMatchCategory='SnapintoshVirtualEthernet',
        SnapintoshVirtualInterface=True, NetworkConnectivityImplemented=False,
        IOBuiltin=False)
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    binary = contents / 'MacOS/AdrenoX2'
    run('link-kext', common + ['-nostdlib', '-Xlinker', '-kext', '-Xlinker',
        '-export_dynamic', '-o', binary, *objects, virtual, '-L' + str(sdk / 'usr/lib'),
        '-lkmodc++', '-lkmod', '-lcc_kext'])
    run('sign', ['codesign', '-f', '-s', '-', bundle])
    run('verify-signature', ['codesign', '--verify', '--strict', bundle])
    builder = bind(ROOT / 'tools/build-auxkc-user.py')
    raw, collection = out / 'AdrenoX2-explicit.kc', out / 'AdrenoX2.kc'
    run('link-auxkc', [sys.executable, builder, raw, bundle])
    autoload = bind(ROOT / 'tools/auxkc-autoload.py')
    run('autoload', [sys.executable, autoload, raw, collection,
        '--expected-sha256', sha(raw), '--bundle', info['CFBundleIdentifier'],
        '--record', out / 'packaging.json'])
    for path, digest in inputs.items():
        assert sha(path) == digest, path
    result = dict(status='VIRTUAL_ETHERNET_NATIVE_LINKED_NOT_INSTALLED',
        sources_sha256=inputs, baseline_objects=10, class_sizes=sizes,
        networking_uuid=nuuid, native_size_witnesses=witnesses,
        kext_sha256=sha(binary), collection_sha256=sha(collection), commands=commands,
        artifacts_sha256={str(p.relative_to(out)): sha(p)
                          for p in sorted(out.rglob('*')) if p.is_file()},
        boundary='Offline native compile/link only. Clock, WindowServer, panel and input unproven.')
    report = out / 'qualification.json'
    report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], report=str(report), sha256=sha(report))))


if __name__ == '__main__':
    main()
