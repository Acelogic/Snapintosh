#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the combined graphics/network driver against actual boot evidence.

Failure inventory: docs/ADRENO-COMBINED-NETWORK-20260928.md. This checks built
artifacts and native stopped evidence, not hardware execution of the correction.
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
MAIN = ROOT.parent/'Snapintosh'
PIPE = ROOT.parent/'Snapintosh-adreno-pipeline'
BUILT = ROOT/'build/ca-network-kext-20260928-v1'
KC = ROOT/'build/ca-network-auxkc-20260928-v1'
OUT = ROOT/'build/ca-network-qualification-20260928-v2.json'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
inputs = {}


def bind(path, expected=None):
    path = Path(path)
    digest = sha(path)
    assert expected is None or digest == expected, path
    inputs[str(path)] = digest
    return path


def read(path, expected=None):
    return json.loads(bind(path, expected).read_text())


def classes(binary):
    output = subprocess.check_output(['xcrun','nm','-gU',str(bind(binary))],text=True)
    result = re.findall(r'__ZN\d+([A-Za-z_][A-Za-z_0-9]*?)10gMetaClassE$',output,re.M)
    assert len(set(result)) == len(result)
    return sorted(result)


def sections(path):
    data = bind(path).read_bytes()
    assert struct.unpack_from('<I',data)[0] == 0xfeedfacf
    result, position = {}, 32
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        command,size = struct.unpack_from('<II',data,position)
        assert size >= 8 and position+size <= len(data)
        if command == 0x19:
            for index in range(struct.unpack_from('<I',data,position+64)[0]):
                at = position+72+80*index
                name,segment,address,length,offset,align,relocations,count,flags,_,_,_ = struct.unpack_from('<16s16sQQIIIIIIII',data,at)
                name,segment = [v.split(b'\0')[0].decode() for v in (name,segment)]
                if segment == '__DWARF' or flags & 0x02000000:
                    continue
                zero_fill = flags & 0xff in (1,12,18)
                assert zero_fill or offset+length <= len(data)
                payload = b'' if zero_fill else data[offset:offset+length]
                result[segment+','+name] = dict(bytes=length,flags=flags,align=align,
                    sha256=hashlib.sha256(payload).hexdigest())
        position += size
    return result


assert not OUT.exists()
native = read(MAIN/'build/installed-metal-ca-3600s-20260928-native-startup-state-v1.json',
              'ed87df3d6e783700bb2c65ad8a5e0bca7f79b9d3839cbde033ce41978cfed4aa')
binding = read(MAIN/'build/installed-metal-ca-3600s-20260928-native-startup-state-v1-binding.json',
               'abb203cbe1de867c87d9f854d50051499d6ce77f9a3e45bf1f3b3d20d4320123')
assert binding['status'] == 'NATIVE_STARTUP_STATE_CAPTURED' and binding['generation'] == 59
assert not binding['writes'] and not binding['guest_resumed'] and native['ioreg_state']['complete']
assert binding['output_sha256'] == sha(MAIN/'build/installed-metal-ca-3600s-20260928-native-startup-state-v1.json')
audit = read(MAIN/'build/installed-metal-ca-3600s-20260928-audit.json',binding['verification_sha256'])
assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
clock = [e for e in native['ioreg_state']['detail_entries'] if e.get('class_name') == 'IOTimeSyncClockManager']
assert len(clock) == 1 and not clock[0]['registered'] and clock[0]['clock_manager_snapshot']['bringup_flag_bit0']
assert not any(e.get('class_name') in ['SnapintoshVirtualEthernet','IOEthernetInterface'] for e in native['ioreg_state']['entries'])

good = MAIN/'build/panel-mode-argument-candidate-20260928-v1/AdrenoX2.kext/Contents'
bad = PIPE/'build/ca-integrated-kext-20260928-v1/AdrenoX2.kext/Contents'
new = BUILT/'AdrenoX2.kext/Contents'
bind(good/'MacOS/AdrenoX2','c530c55866ea4f8e365369113ec6b7eff0962dcff7fd2f2508138d18bdf0052a')
bind(bad/'MacOS/AdrenoX2','54d32bb79af174703a17a21286231b6af6d555ca67d57d7662815a9c4717a9d1')
required = classes(good/'MacOS/AdrenoX2')
assert len(required) == 10 and 'SnapintoshVirtualEthernet' in required
missing = sorted(set(required)-set(classes(bad/'MacOS/AdrenoX2')))
assert missing == ['SnapintoshVirtualEthernet']
assert classes(new/'MacOS/AdrenoX2') == required
assert sorted(native['linked_auxkc']['classes']) == classes(bad/'MacOS/AdrenoX2')
old_info = plistlib.loads(bind(good/'Info.plist','0d8312354fdf96f2a5e68a0e21e64d99d39a58f6b8c2fbae4e2bd430070f02e4').read_bytes())
new_info = plistlib.loads(bind(new/'Info.plist').read_bytes())
assert new_info == old_info
assert new_info['OSBundleLibraries']['com.apple.iokit.IONetworkingFamily'] == '3.4'
assert b'AdrenoIBCopyABI' in (new/'MacOS/AdrenoX2').read_bytes()
old_objects = PIPE/'build/ca-integrated-kext-20260928-v1/obj'
objects = list(sorted(old_objects.glob('*.o')))
assert len(objects) == 10
preserved = {}
for old in objects:
    actual,expected = sections(BUILT/'obj'/old.name),sections(old)
    assert actual == expected, old.name
    preserved[old.name] = actual
network = MAIN/'build/virtual-ethernet-clock-20260927/native-link-v3/obj/SnapintoshVirtualEthernet.o'
bind(network,'cea28f410de15dd682dc6db91071746fefec62fa5b106d9f7df345dac4811f29')
assert sections(network) == sections(BUILT/'obj/SnapintoshVirtualEthernet.o')
for name,digest in [('SnapintoshVirtualEthernet.cpp','bdce27050e9d26a88bcd0fb422157da3f6ecb412e2fcd1e52123f792505c0f05'),
                    ('SnapintoshVirtualEthernet.h','8f58aa2929c04a1d4d4749c67f007274e611609f06c2272ac35ed885a5645c94')]:
    bind(ROOT/'gpu/adreno-kext/kext/src'/name,digest)
for path in (ROOT/'gpu/adreno-kext/kext').rglob('*'):
    if path.is_file() and path.suffix in ['.h','.cpp','.c','.plist','.sh']:
        bind(path)
build = read(KC/'raw.kc.build.json')
assert build['status'] == 'PASSWORDLESS_AUXKC_BUILT' and build['cleanup']['stage_removed']
assert build['caller_uid'] == build['kmutil_uid'] == build['collection_owner'] != 0
assert build['inputs_sha256'][str(new/'MacOS/AdrenoX2')] == sha(new/'MacOS/AdrenoX2')
assert build['inputs_sha256'][str(new/'Info.plist')] == sha(new/'Info.plist')
for path,digest in build['inputs_sha256'].items(): bind(path,digest)
for path,digest in build['artifacts_sha256'].items(): bind(KC/path,digest)
packaged = read(KC/'packaging.json')
assert packaged['unchanged_executable_and_fixup_bytes']
bind(KC/'adreno.kc',packaged['output_sha256'])
bind(KC/'adreno.kc.json')
sys.path.insert(0,str(MAIN/'probes'))
import auxkc
bind(MAIN/'probes/auxkc.py')
collection = auxkc.Collection((KC/'adreno.kc').read_bytes())
entries = collection.prelink_info()['_PrelinkInfoDictionary']
assert len(entries) == 1 and entries[0]['CFBundleIdentifier'] == new_info['CFBundleIdentifier']
held = entries[0]['IOKitPersonalities']
assert set(held) == set(new_info['IOKitPersonalities'])
for name,personality in new_info['IOKitPersonalities'].items():
    assert all(held[name].get(key) == value for key,value in personality.items()), name
assert entries[0]['OSBundleLibraries']['com.apple.iokit.IONetworkingFamily'] == '3.4'
subprocess.run(['codesign','--verify','--strict',str(BUILT/'AdrenoX2.kext')],check=True)
bind(__file__)
record = dict(status='CA_NETWORK_COMBINED_DRIVER_QUALIFIED_NOT_BOOTED',inputs_sha256=inputs,
              original_regression_missing_classes=missing,required_classes=required,
              personalities_equal_to_accepted=True,prior_ten_object_sections_unchanged=preserved,
              linked_collection_personalities_verified=True,
              accepted_network_object_sections_unchanged=True,
              kext_bundle=str(BUILT/'AdrenoX2.kext'),kext_sha256=sha(new/'MacOS/AdrenoX2'),
              collection=str(KC/'adreno.kc'),collection_sha256=sha(KC/'adreno.kc'),
              hardware_access=False,guest_verified=False,desktop_verified=False,
              boundary='Complete built bundle/class/personality and linked collection qualification; next boot must prove service publication and GUI')
OUT.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(status=record['status'],output=str(OUT),sha256=sha(OUT))))
