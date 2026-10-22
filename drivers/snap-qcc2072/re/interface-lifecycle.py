#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture exact native station lifecycle evidence from 26A428, offline.

Failures considered before implementation: wrong architecture or UUID, unnamed
or truncated functions, inherited methods mistaken for concrete implementations,
and legacy requests mistaken for WCL requests. Output is disassembly evidence;
it does not qualify any C++ header, instantiate an interface or contact hardware.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = Path(__file__).resolve().parent
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')
SPECS = {
    'IO80211Family': (
        '697DD7F8-8DDF-313D-8B37-BD25DD09744A',
        ('IO80211InfraInterface::start(', 'IO80211InfraInterface::init(',
         'IO80211InfraInterface::registerInfraEthernetInterface(',
         'IO80211SkywalkInterface::start(', 'IO80211SkywalkInterface::init(',
         'IO80211Controller::attachInterface(',
         'IO80211ScanManager::initWithControllerAndSkywalkInterface(',
         'setSCAN_REQ(', 'setASSOCIATE(', 'getSCAN_RESULT('),
    ),
    'AppleBCMWLANCore': (
        '7503D11C-C083-312A-BF46-BF67364D3D11',
        ('AppleBCMWLANSkywalkInterface::init(', 'AppleBCMWLANSkywalkInterface::start(',
         'AppleBCMWLANSkywalkInterface::setMacAddress(',
         'AppleBCMWLANSkywalkInterface::withProvider(',
         'AppleBCMWLANSkywalkInterface::initWithProviderAndParameters(',
         'AppleBCMWLANSkywalkInterface::withController(',
         'AppleBCMWLANInfraProtocol::initWithProvider(',
         'AppleBCMWLANCore::createSkywalkInterface(',
         'AppleBCMWLANInfraProtocol::setWCL_SCAN_REQ(',
         'AppleBCMWLANInfraProtocol::setWCL_ASSOCIATE(',
         'AppleBCMWLANInfraProtocol::setCIPHER_KEY('),
    ),
}

def run(*args, input=None):
    return subprocess.run(args, input=input, check=True, text=True,
                          capture_output=True).stdout

def main():
    artifacts = []
    for name, (uuid, prefixes) in SPECS.items():
        binary = KDK / f'System/Library/Extensions/{name}.kext/Contents/MacOS/{name}'
        assert f'UUID: {uuid} (arm64e)' in run('/usr/bin/dwarfdump', '--uuid', str(binary))
        syms = []
        for line in run('/usr/bin/nm', '-arch', 'arm64e', '-n', str(binary)).splitlines():
            m = re.match(r'^([0-9a-f]{16}) [Tt] (.+)$', line)
            if m:
                syms.append((m[1], m[2]))
        names = run('/usr/bin/c++filt', input='\n'.join(s[1] for s in syms)).splitlines()
        functions = []
        for (addr, symbol), demangled in zip(syms, names):
            if not demangled.startswith(prefixes):
                continue
            assembly = run('/usr/bin/xcrun', 'llvm-objdump', '--macho',
                           '--arch=arm64e', '-d', '--dis-symname', symbol, str(binary))
            assert symbol + ':' in assembly
            functions.append({'symbol': symbol, 'demangled': demangled,
                              'address': '0x' + addr, 'assembly': assembly})
        artifacts.append({'binary': str(binary), 'uuid': uuid, 'architecture': 'arm64e',
                          'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                          'functions': functions})
        print(name, len(functions), 'functions captured')
    result = {'qualification': 'OFFLINE_DISASSEMBLY_ONLY', 'hardware_access': False,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'artifacts': artifacts}
    (BASE/'interface-lifecycle.json').write_text(json.dumps(result, indent=2)+'\n')
    (BASE/'interface-lifecycle.txt').write_text('\n\n'.join(
        f"{f['demangled']} at {f['address']}\n{f['assembly']}"
        for artifact in artifacts for f in artifact['functions']))

if __name__ == '__main__':
    main()
