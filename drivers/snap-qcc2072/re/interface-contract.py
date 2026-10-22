#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive 26A428 native interface contracts from Apple concrete implementations.

Failure modes: wrong KDK slice, missing concrete method, missing PAC or a shifted
slot must be reported, never filled with a guessed method or successful stub.
Only evidence is emitted; no drivers are loaded and no hardware is accessed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[2]
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')
spec = importlib.util.spec_from_file_location('interface_gen_common', ROOT/'tools/gen-iomfb-header.py')
common = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = common
spec.loader.exec_module(common)

def table(name, classes):
    binary = KDK / f'System/Library/Extensions/{name}.kext/Contents/MacOS/{name}'
    with tempfile.NamedTemporaryFile(prefix='interface-', dir=BASE) as tmp:
        common.arm64e_slice(binary, tmp.name)
        image = common.MachOKext(tmp.name)
        tables = {cls: image.vtable(cls) for cls in classes}
    return {'binary': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'tables': tables}

def main():
    bases = table('IO80211Family', ['IO80211SkywalkInterface', 'IO80211InfraInterface', 'IO80211InfraProtocol', 'IO80211NoneProtocol'])
    concrete = table('AppleBCMWLANCore', ['AppleBCMWLANSkywalkInterface'])
    derived = concrete['tables']['AppleBCMWLANSkywalkInterface']
    names = common.demangle([row[1] for row in derived])
    contracts = {}
    for cls, base in bases['tables'].items():
        required = []
        if cls == 'IO80211NoneProtocol':
            continue
        for row in base:
            index, target, diversity, local, ad, key = row
            if target != common.PURE:
                continue
            impl = derived[index]
            required.append({'slot': index, 'vptr_offset': hex(index*8),
                'base_pac': hex(diversity), 'implementation_pac': hex(impl[2]),
                'pac_matches': diversity == impl[2], 'address_diversity': ad,
                'key': key, 'mangled': impl[1], 'method': names[impl[1]],
                'concrete': impl[1] != common.PURE})
        contracts[cls] = {'slots': len(base), 'required_pure_overrides': required}
    result = {'qualification': 'OFFLINE_APPLE_ABI_REFERENCE_ONLY',
              'hardware_access': False, 'apple_binaries': [
                  {k:v for k,v in x.items() if k!='tables'} for x in (bases,concrete)],
              'contracts': contracts, 'concrete_vtable': [
                  {'slot':r[0], 'mangled':r[1], 'method':names[r[1]], 'pac':hex(r[2]),
                   'address_diversity':r[4], 'key':r[5]} for r in derived],
              'none_protocol_vtable': bases['tables']['IO80211NoneProtocol']}
    (BASE/'interface-contract.json').write_text(json.dumps(result,indent=2)+'\n')
    for cls, contract in contracts.items():
        required=contract['required_pure_overrides']
        print(cls, contract['slots'], 'pure overrides',len(required),'PAC mismatches',
              sum(not r['pac_matches'] for r in required))
        for r in required:
            if cls=='IO80211InfraInterface' or any(k in r['method'] for k in ['SCAN', 'ASSOCIATE', 'CIPHER', 'SSID', 'BSSID']):
                print(r['slot'],r['vptr_offset'],r['base_pac'],r['method'])

if __name__=='__main__': main()
