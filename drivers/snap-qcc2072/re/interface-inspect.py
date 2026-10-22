#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recover exact KDK Wi-Fi interface lifecycle evidence offline.

Failure modes: a different architecture/build, missing symbols, truncated disassembly,
or alias labels must never be treated as the 26A428 arm64e interface ABI. This script
does not instantiate a class, claim runtime success, or contact hardware.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct
import tempfile

BASE = Path(__file__).resolve().parent
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')
BINARY = KDK / 'System/Library/Extensions/IO80211Family.kext/Contents/MacOS/IO80211Family'
EXPECTED_UUID = '697DD7F8-8DDF-313D-8B37-BD25DD09744A'

def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout

def main():
    uuids = run('/usr/bin/dwarfdump', '--uuid', str(BINARY))
    assert f'UUID: {EXPECTED_UUID} (arm64e)' in uuids
    rows = []
    for line in run('/usr/bin/nm', '-arch', 'arm64e', '-n', str(BINARY)).splitlines():
        match = re.match(r'^([0-9a-f]{16}) ([A-Za-z]) (.+)$', line)
        if match:
            rows.append((int(match[1], 16), match[2], match[3]))
    names = [r[2] for r in rows]
    pretty = subprocess.run(['/usr/bin/c++filt'], input='\n'.join(names),
                            check=True, capture_output=True, text=True).stdout.splitlines()
    selected = []
    prefixes = ('IO80211SkywalkInterface::', 'IO80211InfraInterface::', 'IO80211InfraProtocol::')
    methods = ('::init(', '::start(', '::stop(', '::free(', '::MetaClass::MetaClass(',
               '::initIvars(', '::registerInfraEthernetInterface(', '::setInterfaceRole(',
               '::getInterfaceRole(', '::setController(', '::setInfraProtocol(',
               '::getInfraProtocol(', '::getBSDName(', '::apple80211Request(',
               '::attach(', '::configureReport(', '::newUserClient(', '::getInterfaceType(')
    extras = ('IO80211Controller::attachInterface(', 'IO80211Controller::detachInterface(',
              'apple80211getSCAN_RESULT(', 'apple80211setSCAN_REQ(',
              'apple80211setASSOCIATE(', 'apple80211setCIPHER_KEY(')
    for row, demangled in zip(rows, pretty):
        address, kind, symbol = row
        if kind != 'T':
            continue
        if ((demangled.startswith(prefixes) and any(m in demangled for m in methods))
                or demangled.startswith(extras)):
            assembly = run('/usr/bin/xcrun', 'llvm-objdump', '--macho', '--arch=arm64e',
                           '-d', '--dis-symname', symbol, str(BINARY))
            assert symbol + ':' in assembly
            selected.append({'symbol': symbol, 'demangled': demangled,
                             'address': hex(address), 'assembly': assembly})
    data = BINARY.read_bytes()
    magic, count = struct.unpack_from('>II', data)
    assert magic == 0xcafebabe
    slices = [struct.unpack_from('>IIIII', data, 8 + i * 20) for i in range(count)]
    arm = [s for s in slices if s[0] == 0x100000c and s[1] == 0xc0000002]
    assert len(arm) == 1
    _, _, offset, size, _ = arm[0]
    with tempfile.NamedTemporaryFile(prefix='interface-', dir=BASE) as tmp:
        tmp.write(data[offset:offset + size])
        tmp.flush()
        fixup_text = run('/usr/bin/dyld_info', '-fixups', tmp.name)
    fixups = {}
    addresses = {address: symbol for address, kind, symbol in reversed(rows) if kind in 'Tt'}
    symbols = {symbol: address for address, kind, symbol in rows}
    for line in fixup_text.splitlines():
        m = re.search(r'(0x[0-9A-F]+)\s+auth-rebase\s+(0x[0-9A-F]+) \(div=(0x[0-9A-F]+) ad=(\d) key=(\w+)\)', line)
        if m:
            target = int(m[2], 16)
            fixups[int(m[1], 16)] = (addresses.get(target, hex(target)), m[3], m[4], m[5])
            continue
        m = re.search(r'(0x[0-9A-F]+)\s+auth-bind\s+\S*?/(\S+) \(div=(0x[0-9A-F]+) ad=(\d) key=(\w+)\)', line)
        if m:
            fixups[int(m[1], 16)] = (m[2], m[3], m[4], m[5])
    vtables = {}
    for cls in ['IO80211Controller', 'IO80211SkywalkInterface', 'IO80211InfraInterface', 'IO80211InfraProtocol']:
        base = symbols[f'__ZTV{len(cls)}{cls}'] + 16
        entries = []
        while base + len(entries) * 8 in fixups:
            target, diversity, ad, key = fixups[base + len(entries) * 8]
            entries.append({'slot': len(entries), 'vptr_offset': hex(len(entries)*8),
                            'target': target, 'diversity': diversity,
                            'address_diversity': ad == '1', 'key': key})
        vtables[cls] = entries
    receipt = {'qualification': 'OFFLINE_DISASSEMBLY_ONLY', 'hardware_access': False,
               'binary': str(BINARY), 'binary_sha256': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
               'architecture': 'arm64e', 'uuid': EXPECTED_UUID,
               'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'functions': selected, 'vtables': vtables}
    (BASE / 'interface-disassembly.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (BASE / 'interface-disassembly.txt').write_text('\n'.join(
        '\n=== ' + e['demangled'] + ' ===\n' + e['assembly'] for e in selected))
    print(json.dumps({'uuid': EXPECTED_UUID, 'function_count': len(selected),
                      'functions': [{'name': e['demangled'], 'address': e['address']}
                                    for e in selected]}, indent=2))

if __name__ == '__main__':
    main()
