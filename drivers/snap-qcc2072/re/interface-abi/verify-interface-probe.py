#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end offline verification of native interface targets and PAC.

This deliberately does not approve request layouts, return semantics, runtime
instantiation, class publication, hardware data paths or native scan/connect.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from evidence_guard import start_phase, write_new_text
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
start_phase(out, 'verification', ['interface-abi-receipt.json'])
source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('interface_generator',source/'generate-interface-candidate.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
c = generator.c

manifest = json.loads((out/'candidate-generation.json').read_text())
for name, reference in manifest['reference_binaries'].items():
    assert hashlib.sha256(Path(reference['path']).read_bytes()).hexdigest() == reference['sha256'], \
           'reference binary changed after generation'
    assert hashlib.sha256((out/(name+'.arm64e')).read_bytes()).hexdigest() == reference['thin_sha256'], \
           'thin reference slice changed after generation'
for reference in manifest['historical_references']:
    assert hashlib.sha256(Path(reference['path']).read_bytes()).hexdigest() == reference['sha256'], \
           'historical reference changed after generation'
binary = out/'offline-interface-abi-probe'
actual = c.MachOKext(binary).vtable('OfflineInterfaceABIProbe')
family = c.MachOKext(out/'IO80211Family.arm64e').vtable('IO80211InfraProtocol')
concrete = c.MachOKext(out/'AppleBCMWLANCore.arm64e').vtable('AppleBCMWLANSkywalkInterface')
names = c.demangle([r[1] for r in actual+family+concrete])
assert len(actual) == len(family) == 683, 'wrong vtable length'
checks = []
for got, wanted in zip(actual, family):
    slot = got[0]
    assert (got[2],got[4],got[5]) == (wanted[2],wanted[4],wanted[5]), \
           f'slot {slot}: wrong PAC/key/address diversity'
    pure = wanted[1] == c.PURE
    if slot in (0,1):
        target = 'OfflineInterfaceABIProbe::~OfflineInterfaceABIProbe()'
    elif slot == 7:
        target = 'OfflineInterfaceABIProbe::getMetaClass() const'
    elif pure:
        assert concrete[slot][2] == wanted[2], 'concrete reference PAC mismatch'
        target = 'OfflineInterfaceABIProbe::'+names[concrete[slot][1]].split('::',1)[1]
    else:
        target = names[wanted[1]]
    assert names[got[1]] == target, f'slot {slot}: target mismatch'
    assert got[1] != c.PURE, f'slot {slot}: unresolved pure virtual'
    checks.append({'slot':slot,'target':target,'pac':hex(got[2]),
                   'address_diversity':got[4],'key':got[5],'required_pure':pure})
assert sum(r['required_pure'] for r in checks) == 201
artifacts = {}
for name in ['IO80211Interface26A428.candidate.h','offline-interface-abi-probe.cpp',
             'offline-interface-abi-probe.o','offline-interface-abi-probe',
             'candidate-generation.json','build-receipt.json']:
    artifacts[name] = hashlib.sha256((out/name).read_bytes()).hexdigest()
report = {
    'status':'INTERFACE_VTABLE_AND_PAC_MATCH',
    'hardware_access':False,'instantiated':False,'packaged_as_kext':False,
    'native_wifi_runtime_qualified':False,
    'slot_count':683,'implemented_pure_slots':201,
    'target_mismatches':0,'pac_mismatches':0,'remaining_pure':0,
    'unqualified_return_declarations':len(manifest['unqualified_returns']),
    'chain':manifest['chain'],'artifacts_sha256':artifacts,
    'tool_sources_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in source.glob('*.py')},
    'common_helper_sha256':hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest(),
    'limits':[
        'All201 probe overrides return Unsupported only to emit a complete vtable.',
        'The probe has no driver personality, provider matching or registration flow.',
        'PAC authenticates slot identities; it does not encode return types.',
        'Historical return-type hints are not exact-target runtime qualification either.',
        'Opaque returns, argument layouts, register semantics and call contracts remain unqualified.',
        'No native scanning, association or data-plane behavior is implemented or demonstrated.',
    ],'slots':checks}
write_new_text(out/'interface-abi-receipt.json', json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ('status','slot_count','implemented_pure_slots',
                                      'target_mismatches','pac_mismatches',
                                      'unqualified_return_declarations')}))
