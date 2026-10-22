#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the combined driver with the early-stop request against the booted one.

The booted driver is kext 3c10369c inside AuxKC 1f22aed6 (build/ca-network-* in
../Snapintosh-adreno-buffer-textures, qualification 0c7936724e). This build adds
only the kext side of early stop (docs/EARLY-STOP-KEXT-20260928.md): one new object,
AdrenoEarlyStop.o, and hooks in AdrenoX2.o and AdrenoDisplay.o. Everything else
must be the booted driver's: the ten classes, the Info.plist (personalities and the
IONetworkingFamily 3.4 dependency), and every other object section. The linked
collection must hold that bundle and those personalities, built the password-free
way and pinned for the loader. Built artifacts only; no hardware.

    python3 tools/qualify-early-stop-kext.py
"""
from pathlib import Path
import hashlib
import json
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = 'ba4c27c'
MAIN = ROOT.parent / 'Snapintosh'
BOOTED = ROOT.parent / 'Snapintosh-adreno-buffer-textures'
ACCEPTED = BOOTED / 'build/ca-network-kext-20260928-v1'
ACCEPTED_KC = BOOTED / 'build/ca-network-auxkc-20260928-v1'
BUILT = ROOT / 'build/early-stop-kext-20260928-v1'
KC = ROOT / 'build/early-stop-auxkc-20260928-v1'
OUT = ROOT / 'build/early-stop-kext-qualification-20260928-v1.json'
OBJDUMP = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
BUNDLE = 'org.snapintosh.driver.AdrenoX2'
CHANGED_OBJECTS = ['AdrenoDisplay.o', 'AdrenoX2.o']
NEW_OBJECTS = ['AdrenoEarlyStop.o']
KEXT_SOURCES = {'compat/adreno-guest.h', 'compat/early-stop.h', 'gpu/adreno-kext/include/AdrenoContract.h',
                'gpu/adreno-kext/kext/build.sh', 'gpu/adreno-kext/kext/src/AdrenoDisplay.cpp',
                'gpu/adreno-kext/kext/src/AdrenoEarlyStop.cpp', 'gpu/adreno-kext/kext/src/AdrenoEarlyStop.h',
                'gpu/adreno-kext/kext/src/AdrenoX2.cpp', 'gpu/adreno-kext/kext/src/AdrenoX2.h'}
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
inputs = {}


def bind(path, expected=None):
    path = Path(path)
    digest = sha(path)
    assert expected is None or digest == expected, (str(path), digest)
    inputs[str(path)] = digest
    return path


def read(path, expected=None):
    return json.loads(bind(path, expected).read_text())


def classes(binary):
    output = subprocess.check_output(['xcrun', 'nm', '-gU', str(bind(binary))], text=True)
    result = re.findall(r'__ZN\d+([A-Za-z_][A-Za-z_0-9]*?)10gMetaClassE$', output, re.M)
    assert len(set(result)) == len(result)
    return sorted(result)


def sections(path):
    """Non-debug section contents of a Mach-O object, as in qualify-ca-network-kext.py."""
    data = bind(path).read_bytes()
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    result, position = {}, 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, position)
        assert size >= 8 and position + size <= len(data)
        if command == 0x19:
            for index in range(struct.unpack_from('<I', data, position + 64)[0]):
                at = position + 72 + 80 * index
                name, segment, address, length, offset, align, relocations, count, flags, _, _, _ = \
                    struct.unpack_from('<16s16sQQIIIIIIII', data, at)
                name, segment = [v.split(b'\0')[0].decode() for v in (name, segment)]
                if segment == '__DWARF' or flags & 0x02000000:
                    continue
                zero_fill = flags & 0xff in (1, 12, 18)
                assert zero_fill or offset + length <= len(data)
                payload = b'' if zero_fill else data[offset:offset + length]
                result[segment + ',' + name] = dict(bytes=length, flags=flags, align=align,
                                                    sha256=hashlib.sha256(payload).hexdigest())
        position += size
    return result


def function(text, pattern):
    found = re.search(r'<(' + pattern + r')>:\n(.*?)\n\n', text, re.S)
    assert found, pattern
    return found[2]


def prelink_entry(collection_path):
    collection = auxkc.Collection(collection_path.read_bytes())
    entries = collection.prelink_info()['_PrelinkInfoDictionary']
    assert len(entries) == 1 and entries[0]['CFBundleIdentifier'] == BUNDLE
    return entries[0]


assert not OUT.exists(), f'{OUT} exists; qualifications are written once'
# The booted driver, as its own qualification recorded it.
accepted_record = read(BOOTED / 'build/ca-network-qualification-20260928-v2.json',
                       '0c7936724e05c8ce706ddd9148b72bc060849b1604e8caf2675d8d2e2e7720d3')
assert accepted_record['status'] == 'CA_NETWORK_COMBINED_DRIVER_QUALIFIED_NOT_BOOTED'
old, new = ACCEPTED / 'AdrenoX2.kext/Contents', BUILT / 'AdrenoX2.kext/Contents'
bind(old / 'MacOS/AdrenoX2', accepted_record['kext_sha256'])
bind(ACCEPTED_KC / 'adreno.kc', accepted_record['collection_sha256'])
accepted_manifest = read(ACCEPTED_KC / 'adreno.kc.json')
assert accepted_manifest['sha256'] == accepted_record['collection_sha256']

# Sources: only the kext side of early stop differs from the booted driver's checkout.
changed = subprocess.check_output(['git', '-C', str(ROOT), 'diff', '--name-only', BASE], text=True).split()
changed += subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '--others', '--exclude-standard'],
                                   text=True).split()
kext_side = {p for p in changed if p.startswith(('compat/', 'gpu/', 'probes/', 'shadow/'))}
assert kext_side == KEXT_SOURCES, sorted(kext_side ^ KEXT_SOURCES)
booted_head = subprocess.check_output(['git', '-C', str(BOOTED), 'rev-parse', 'HEAD'], text=True).strip()
assert booted_head.startswith(BASE), booted_head
for path in (ROOT / 'gpu/adreno-kext').rglob('*'):
    if path.is_file() and path.suffix in ('.h', '.cpp', '.c', '.plist', '.sh') and '/plugin/' not in str(path):
        bind(path)
for name in ('compat/adreno-guest.h', 'compat/early-stop.h'):
    bind(ROOT / name)
header = (ROOT / 'compat/early-stop.h').read_bytes()
monitor_header = ROOT.parent / 'Snapintosh-early-stop/compat/early-stop.h'
if monitor_header.exists():
    assert header == bind(monitor_header).read_bytes(), 'the ABI header differs from the monitor side'

# Classes, Info.plist, dependency.
required = classes(old / 'MacOS/AdrenoX2')
assert len(required) == 10 and 'SnapintoshVirtualEthernet' in required
assert classes(new / 'MacOS/AdrenoX2') == required
assert bind(new / 'Info.plist').read_bytes() == bind(old / 'Info.plist').read_bytes()
info = plistlib.loads((new / 'Info.plist').read_bytes())
assert info['CFBundleIdentifier'] == BUNDLE
assert info['OSBundleLibraries']['com.apple.iokit.IONetworkingFamily'] == '3.4'

# Objects: two changed, one new, every other section the booted driver's.
old_objects = sorted(p.name for p in (ACCEPTED / 'obj').glob('*.o'))
new_objects = sorted(p.name for p in (BUILT / 'obj').glob('*.o'))
assert len(old_objects) == 11 and 'SnapintoshVirtualEthernet.o' in old_objects
assert new_objects == sorted(old_objects + NEW_OBJECTS)
unchanged, differing = {}, []
for name in old_objects:
    before, after = sections(ACCEPTED / 'obj' / name), sections(BUILT / 'obj' / name)
    if before == after:
        unchanged[name] = after
    else:
        differing.append(name)
assert differing == CHANGED_OBJECTS, differing
added = {name: sections(BUILT / 'obj' / name) for name in NEW_OBJECTS}

# The request is exactly what the monitor admits, and the hooks sit where they belong.
binary = new / 'MacOS/AdrenoX2'
raw = subprocess.run([OBJDUMP, '-d', str(binary)], capture_output=True, text=True, check=True).stdout
text = subprocess.run([OBJDUMP, '-d', '--no-show-raw-insn', str(binary)], capture_output=True, text=True,
                      check=True).stdout
request = function(raw, r'__Z\d+AdrenoEarlyStopRequest\w*')
assert 'd415a2c2' in request.replace(' ', '')                          # hvc #0xad16
assert re.search(r'mov\s+[wx]0, #0x6\b', request) and re.search(r'movk\s+[wx]0, #0x1, lsl #16', request)
hooks = {
    'AdrenoDisplay::presentGated': (r'__ZN13AdrenoDisplay12presentGatedEP\w+', 'AdrenoEarlyStopPresented'),
    'AdrenoAcceleratorX2::configureDevice': (r'__ZN19AdrenoAcceleratorX215configureDeviceEP9IOService',
                                             'AdrenoEarlyStopConfigure'),
    'AdrenoAcceleratorX2::setProperties': (r'__ZN19AdrenoAcceleratorX213setPropertiesEP8OSObject',
                                           'AdrenoEarlyStopRequest'),
    'AdrenoAcceleratorX2::start': (r'__ZN19AdrenoAcceleratorX25startEP9IOService', 'AdrenoEarlyStopEnabled'),
}
for caller, (pattern, callee) in hooks.items():
    assert re.search(r'bl\s+\S+ <__Z\d+' + callee + r'\w*>', function(text, pattern)), caller
strings = binary.read_bytes()
for key in (b'AdrenoEarlyStopABI\0', b'AdrenoEarlyStopPluginFailure\0', b'snapintosh,guest-stop-abi\0',
            b'snapintosh,guest-stop-delay\0'):
    assert key in strings, key
subprocess.run(['codesign', '--verify', '--strict', str(BUILT / 'AdrenoX2.kext')], check=True)

# The collection: built password-free from exactly this bundle, packaged for autoload, pinned.
build = read(KC / 'raw.kc.build.json')
assert build['status'] == 'PASSWORDLESS_AUXKC_BUILT' and build['cleanup']['stage_removed']
assert build['caller_uid'] == build['kmutil_uid'] == build['collection_owner'] != 0
assert not build['administrator_dialog'] and not build['policy_changed']
assert build['bundle_identifiers'] == [BUNDLE]
for name in ('MacOS/AdrenoX2', 'Info.plist', '_CodeSignature/CodeResources'):
    assert build['inputs_sha256'][str(new / name)] == sha(new / name), name
for path, digest in build['inputs_sha256'].items():
    bind(path, digest)
for path, digest in build['artifacts_sha256'].items():
    bind(KC / path, digest)
packaged = read(KC / 'packaging.json')
assert packaged['source_sha256'] == build['collection_sha256'] == sha(KC / 'raw.kc')
assert packaged['unchanged_executable_and_fixup_bytes'] and not packaged['explicit_load_after']
assert packaged['tool_sha256'] == read(ACCEPTED_KC / 'packaging.json')['tool_sha256']
bind(KC / 'adreno.kc', packaged['output_sha256'])
manifest = read(KC / 'adreno.kc.json')
assert manifest['sha256'] == sha(KC / 'adreno.kc') and manifest['bundles'] == [BUNDLE]
for key in ('format', 'kernel_sha256', 'guest_profile', 'requested', 'builder'):
    assert manifest[key] == accepted_manifest[key], key
assert manifest['admission']['executables'] == [BUNDLE] and manifest['admission']['top'] == '0x48000'

sys.dont_write_bytecode = True
sys.path.insert(0, str(MAIN / 'probes'))
import auxkc                                                            # noqa: E402
bind(MAIN / 'probes/auxkc.py')
held, booted = prelink_entry(KC / 'adreno.kc'), prelink_entry(ACCEPTED_KC / 'adreno.kc')
assert set(held['IOKitPersonalities']) == set(info['IOKitPersonalities'])
for name, personality in info['IOKitPersonalities'].items():
    assert all(held['IOKitPersonalities'][name].get(k) == v for k, v in personality.items()), name
assert held['IOKitPersonalities'] == booted['IOKitPersonalities']
assert held['OSBundleLibraries'] == booted['OSBundleLibraries'] == info['OSBundleLibraries']
assert held.get('OSBundleRequireExplicitLoad') is False and booted.get('OSBundleRequireExplicitLoad') is False

bind(__file__)
record = dict(
    status='EARLY_STOP_KEXT_AUXKC_QUALIFIED_NOT_BOOTED',
    base_commit=BASE, booted_kext_sha256=accepted_record['kext_sha256'],
    booted_collection_sha256=accepted_record['collection_sha256'],
    kext_side_sources=sorted(KEXT_SOURCES),
    required_classes=required, classes_equal_to_booted=True,
    info_plist_identical_to_booted=True, info_plist_sha256=sha(new / 'Info.plist'),
    personalities=sorted(info['IOKitPersonalities']), dependencies=info['OSBundleLibraries'],
    unchanged_object_sections=unchanged, changed_objects=differing, new_object_sections=added,
    request_instruction='hvc #0xad16 (d415a2c2) with x0 = ADRENO_GUEST_STOP 0x10006',
    hooks={caller: callee for caller, (_, callee) in hooks.items()},
    linked_collection_personalities_equal_to_booted=True,
    kext_bundle=str(BUILT / 'AdrenoX2.kext'), kext_sha256=sha(new / 'MacOS/AdrenoX2'),
    raw_collection_sha256=sha(KC / 'raw.kc'), collection=str(KC / 'adreno.kc'),
    collection_sha256=sha(KC / 'adreno.kc'), manifest_sha256=sha(KC / 'adreno.kc.json'),
    guest_profile=manifest['guest_profile'], fixups=manifest['admission']['fixups'],
    inputs_sha256=inputs, hardware_access=False, guest_verified=False,
    boundary='Built bundle, objects, instruction and linked collection only. A boot must show the '
             'request reaching the monitor (EV_EARLY_STOP_REQUEST) and the run ending with exit 12.')
OUT.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], output=str(OUT), sha256=sha(OUT),
                      kext_sha256=record['kext_sha256'], collection_sha256=record['collection_sha256'])))
