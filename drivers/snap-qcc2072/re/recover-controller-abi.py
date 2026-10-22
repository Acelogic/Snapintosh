#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recover exact 26A428 controller slots and PAC fixups; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')
UUID = '697DD7F8-8DDF-313D-8B37-BD25DD09744A'
SUPER_UUID = '6D6673F0-D592-36F4-B789-A5A6632C33B2'
CONCRETE_UUID = '7503D11C-C083-312A-BF46-BF67364D3D11'


def run(*args, input=None):
    return subprocess.run(args, input=input, check=True, text=True,
                          capture_output=True).stdout


def require(condition, message):
    if not condition:
        raise ValueError(message)


def thin(path):
    data = path.read_bytes()
    if data[:4] == b'\xcf\xfa\xed\xfe':
        require(struct.unpack_from('<II', data, 4) == (0x100000c, 0xc0000002),
                'expected exact arm64e.kernel thin binary')
        return data
    magic, count = struct.unpack_from('>II', data)
    require(magic == 0xcafebabe, 'expected 32-bit FAT header')
    choices = []
    for i in range(count):
        cpu, subtype, off, size, _ = struct.unpack_from('>IIIII', data, 8 + 20 * i)
        if cpu == 0x100000c and subtype == 0xc0000002:
            choices.append(data[off:off + size])
    require(len(choices) == 1, 'expected exactly one arm64e.kernel slice')
    return choices[0]


def segments(data):
    count, size = struct.unpack_from('<II', data, 16)
    pos, result = 32, []
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, pos)
        require(length >= 8 and pos + length <= 32 + size, 'bad load command')
        if cmd == 0x19:
            name = data[pos + 8:pos + 24].split(b'\0')[0].decode()
            va, span, off, disk = struct.unpack_from('<4Q', data, pos + 24)
            result.append((name, va, span, off, disk))
        pos += length
    return result


def inspect(path, cls, expected_uuid=None):
    uuid_text = run('/usr/bin/xcrun', 'dwarfdump', '--uuid', str(path))
    exact = re.findall(r'UUID: ([0-9A-F-]+) \(arm64e\)', uuid_text)
    require(len(exact) == 1, 'missing exact arm64e UUID')
    if expected_uuid:
        require(exact[0] == expected_uuid, 'wrong target UUID')
    raw_symbols = run('/usr/bin/xcrun', 'nm', '-n', '-arch', 'arm64e', str(path))
    symbols = []
    for line in raw_symbols.splitlines():
        m = re.match(r'([0-9a-fA-F]+)\s+(\S)\s+(.+)', line)
        if m:
            symbols.append((int(m[1], 16), m[2], m[3]))
    names = {s[2]: s[0] for s in symbols}
    by_addr = {}
    for addr, _, name in symbols:
        by_addr.setdefault(addr, []).append(name)
    vname = '__ZTV' + str(len(cls)) + cls
    start = names[vname]
    end = min(addr for addr, _, _ in symbols if addr > start)
    require((end - start) % 8 == 0, 'unaligned vtable boundary')
    fixup_text = run('/usr/bin/xcrun', 'dyld_info', '-arch', 'arm64e.kernel',
                     '-fixups', str(path))
    slots = {}
    pattern = (r'\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(.+?)'
               r'(?: \(div=(0x[0-9A-Fa-f]+) ad=([01]) key=(\w+)\))?$')
    for line in fixup_text.splitlines():
        match = re.match(pattern, line)
        if not match:
            continue
        addr = int(match[1], 16)
        if not start + 16 <= addr < end:
            continue
        target = match[3]
        if target.startswith('0x'):
            target_address = int(target, 16)
            target_names = by_addr.get(target_address, [])
        else:
            target_address = None
            target_names = [target.split('/', 1)[-1]]
        require(target_names, 'unresolved vtable target ' + line)
        slots[(addr - start - 16) // 8] = {
            'slot': (addr - start - 16) // 8, 'address': hex(addr),
            'kind': match[2], 'target_address': hex(target_address) if target_address else None,
            'symbols': target_names, 'diversity': match[4],
            'address_diversity': int(match[5]) if match[5] is not None else None,
            'key': match[6],
        }
    data = thin(path)
    segs = segments(data)
    def code(addr, count):
        for _, va, _, off, disk in segs:
            if va <= addr and addr + count <= va + disk:
                return data[off + addr - va:off + addr - va + count]
        raise ValueError('address has no file-backed segment')
    expected_slots = max(slots) + 1
    padding_begin = start + 16 + 8 * expected_slots
    require(end - padding_begin <= 8 and code(padding_begin, end - padding_begin) ==
            bytes(end - padding_begin), 'unexpected data following last vtable fixup')
    require(set(slots) == set(range(expected_slots)), 'missing interior vtable fixup')
    all_names = [slot['symbols'][0] for slot in slots.values()]
    demangled = run('/usr/bin/c++filt', input='\n'.join(all_names) + '\n').splitlines()
    for slot, text in zip(slots.values(), demangled):
        slot['demangled'] = text
    require(code(start, 16) == bytes(16), 'unexpected vtable prefix')
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    functions = {}
    wanted = ['__ZN' + str(len(cls)) + cls + '9MetaClassC1Ev',
              '__ZN' + str(len(cls)) + cls + 'C2EPK11OSMetaClass']
    for name in wanted:
        if name not in names:
            continue
        begin = names[name]
        finish = min(a for a, _, _ in symbols if a > begin)
        functions[name] = [
            {'address': hex(ins.address), 'mnemonic': ins.mnemonic, 'operands': ins.op_str}
            for ins in decoder.disasm(code(begin, finish - begin), begin)]
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'uuid': exact[0], 'class': cls, 'vtable': hex(start),
            'next_symbol_address': hex(end), 'tail_padding_bytes': end - padding_begin,
            'slot_count': expected_slots,
            'slots': list(slots.values()), 'constructors': functions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--concrete-output', type=Path)
    args = parser.parse_args()
    root = KDK / 'System/Library/Extensions'
    controller = inspect(root / 'IO80211Family.kext/Contents/MacOS/IO80211Family',
                         'IO80211Controller', UUID)
    base = inspect(root / 'IONetworkingFamily.kext/Contents/MacOS/IONetworkingFamily',
                   'IOEthernetController', SUPER_UUID)
    if args.concrete_output:
        concrete = inspect(root / 'AppleBCMWLANCore.kext/Contents/MacOS/AppleBCMWLANCore',
                           'AppleBCMWLANCore', CONCRETE_UUID)
        with args.concrete_output.open('x') as stream:
            json.dump(concrete, stream, indent=2, sort_keys=True)
            stream.write('\n')
    base_slots = base['slots']
    for slot in controller['slots']:
        i = slot['slot']
        slot['inherited'] = i < len(base_slots)
        if slot['inherited']:
            slot['base_symbols'] = base_slots[i]['symbols']
            slot['same_pac_as_base'] = all(slot[k] == base_slots[i][k]
                                          for k in ['diversity', 'address_diversity', 'key'])
            slot['same_target_as_base'] = bool(set(slot['symbols']) & set(base_slots[i]['symbols']))
    result = {'status': 'OFFLINE_BINARY_RECOVERY', 'hardware_access': False,
              'header_qualified': False, 'controller': controller, 'superclass_candidate': base}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'controller_slots': controller['slot_count'],
                      'superclass_slots': base['slot_count'],
                      'new_slots': controller['slot_count'] - base['slot_count']}))


if __name__ == '__main__':
    main()
