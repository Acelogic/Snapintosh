#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the native controller's final AuxKC targets/PAC, with no hardware access.

Failure inventory was recorded before implementation: wrong BootKC/binary/report
pairing; missing/moved/truncated vtable; missing, unauthenticated or wrong-level
chain pointer; changed PAC; wrong resolved symbol address; zero/unresolved native
imports; inputs changing during verification; claiming runtime qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_GUEST = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
VTABLE = '__ZTV17SnapintoshQCC2072'
OWNERS = {'com.apple.kernel', 'com.apple.iokit.IONetworkingFamily',
          'com.apple.iokit.IO80211Family'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def primary_symbols(primary, wanted, addresses=frozenset()):
    """Only read relevant families; never repeatedly slice whole string tables."""
    result = {}
    for owner, _, base in primary.kexts:
        if owner not in OWNERS:
            continue
        require(0 <= base <= len(primary.data) - 32, 'bad primary fileset header')
        count, size = struct.unpack_from('<II', primary.data, base + 16)
        pos, end = base + 32, base + 32 + size
        require(end <= len(primary.data), 'truncated primary command table')
        for _ in range(count):
            require(pos + 8 <= end, 'truncated primary command')
            cmd, length = struct.unpack_from('<II', primary.data, pos)
            require(length >= 8 and pos + length <= end, 'bad primary command')
            if cmd == 2:
                require(length == 24, 'bad primary symtab command')
                symoff, num, stroff, strsize = struct.unpack_from('<4I', primary.data, pos + 8)
                require(symoff + 16 * num <= len(primary.data) and
                        stroff + strsize <= len(primary.data), 'primary symtab outside file')
                strings = primary.data[stroff:stroff + strsize]
                for i in range(num):
                    sx, kind, _, _, va = struct.unpack_from('<IBBHQ', primary.data, symoff + 16 * i)
                    if kind & 0xe0 or kind & 0x0e != 0x0e or not 0 < sx < strsize:
                        continue
                    stop = strings.find(b'\0', sx)
                    require(stop >= 0, 'unterminated primary symbol')
                    name = strings[sx:stop].decode('ascii')
                    if name in wanted or va in addresses:
                        result.setdefault(name, []).append((va, owner))
            pos += length
        require(pos == end, 'primary command count/size mismatch')
    return result


def file_offset(image, address):
    candidates = [offset + address - vmaddr
                  for _, vmaddr, _, offset, size in image.segments
                  if vmaddr <= address < vmaddr + size]
    require(len(candidates) == 1, f'unmapped or ambiguous primary address {address:#x}')
    return candidates[0]


def pac_fields(raw):
    return {'diversity': (raw >> 32) & 0xffff, 'address_diversity': (raw >> 48) & 1,
            'key': ['IA', 'IB', 'DA', 'DB'][(raw >> 49) & 3]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--collection', type=Path, required=True)
    parser.add_argument('--abi-report', type=Path, required=True)
    parser.add_argument('--guest-kc', type=Path,
                        default=ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    require(not args.report.exists(), 'report already exists')
    recovery_path = ROOT / 'drivers/snap-qcc2072/re/recover-controller-abi.py'
    source_paths = [Path(__file__).resolve(), ROOT / 'probes/auxkc.py',
                    ROOT / 'tools/kc-load.py', recovery_path]
    sources = {str(path.relative_to(ROOT)): digest(path.read_bytes())
               for path in source_paths}
    inputs = {str(path.resolve()): digest(path.read_bytes()) for path in
              [args.binary, args.collection, args.abi_report, args.guest_kc]}
    require(inputs[str(args.guest_kc.resolve())] == EXPECTED_GUEST, 'wrong guest collection')
    prelink = json.loads(args.abi_report.read_text())
    require(prelink['status'] == 'CONTROLLER_VTABLE_PAC_MATCH' and
            prelink['slot_count'] == 471 and prelink['implemented_pure_slots'] == 12 and
            prelink['binary_sha256'] == inputs[str(args.binary.resolve())],
            'prelink ABI report does not qualify this binary')
    aux = runpy.run_path(str(ROOT / 'probes/auxkc.py'))
    loader = runpy.run_path(str(ROOT / 'tools/kc-load.py'))
    recover = runpy.run_path(str(recovery_path))
    standalone = recover['inspect'](args.binary.resolve(), 'SnapintoshQCC2072')
    require(standalone['slot_count'] == 471, 'standalone vtable count differs')
    primary = loader['Image'](args.guest_kc.read_bytes())
    collection = aux['Collection'](args.collection.read_bytes())
    aux_symbols = {}
    for va, name in aux['symbols'](collection):
        aux_symbols.setdefault(name, []).append(va)
    starts = aux_symbols.get(VTABLE, [])
    require(len(starts) == 1, 'missing or ambiguous linked controller vtable')
    start = starts[0]
    wanted = {name for row in standalone['slots'] for name in row['symbols']}
    wanted.add('__ZTV17IO80211Controller')
    primary_names = primary_symbols(primary, wanted)
    guest_starts = primary_names.get('__ZTV17IO80211Controller', [])
    require(len(guest_starts) == 1 and
            guest_starts[0][1] == 'com.apple.iokit.IO80211Family',
            'missing or ambiguous guest controller vtable')
    guest_start = guest_starts[0][0]
    guest_offsets = {file_offset(primary, guest_start + 16 + 8 * slot)
                     for slot in range(471)}
    guest_chains = {off: target for off, target in loader['chained_fixups'](primary, 0)
                    if off in guest_offsets}
    require(len(guest_chains) == 471, 'missing guest controller chained pointer')
    primary_names = primary_symbols(primary, wanted, set(guest_chains.values()))
    primary_at = {}
    for name, candidates in primary_names.items():
        for address, owner in candidates:
            primary_at.setdefault(address, []).append((name, owner))
    chains = {off: (level, target, auth)
              for off, level, target, auth in aux['chained_fixups'](collection, primary)}
    rows, origins, patched_inherited = [], {}, []
    for row in standalone['slots']:
        slot = row['slot']
        address = start + 16 + 8 * slot
        off = collection.file_offset(address)
        require(off in chains, f'slot {slot}: no linked chained pointer')
        level, target, auth = chains[off]
        require(auth and row['key'] is not None, f'slot {slot}: authentication missing')
        raw = struct.unpack_from('<Q', collection.data, off)[0]
        pac = pac_fields(raw)
        require(pac == {'diversity': int(row['diversity'], 16),
                        'address_diversity': row['address_diversity'], 'key': row['key']},
                f'slot {slot}: linked PAC changed')
        resolved = primary.vmin + target if level == 0 else target
        guest_off = file_offset(primary, guest_start + 16 + 8 * slot)
        guest_raw = struct.unpack_from('<Q', primary.data, guest_off)[0]
        require(guest_raw >> 63 and pac_fields(guest_raw) == pac,
                f'slot {slot}: linked PAC differs from guest controller')
        own = row['kind'] == 'auth-rebase'
        if own:
            require(level == 3, f'slot {slot}: own implementation not in AuxKC')
            matches = [(name, 'AuxKC') for name in row['symbols']
                       if resolved in aux_symbols.get(name, [])]
        else:
            require(row['kind'] == 'auth-bind' and level == 0,
                    f'slot {slot}: inherited implementation not in BootKC')
            require(resolved == guest_chains[guest_off],
                    f'slot {slot}: inherited target differs from guest controller')
            matches = primary_at.get(resolved, [])
            if not any(name in row['symbols'] for name, _ in matches):
                patched_inherited.append(slot)
        require(matches, f'slot {slot}: no exact resolved target for {row["symbols"]}')
        symbol, owner = matches[0]
        origins[owner] = origins.get(owner, 0) + 1
        rows.append({'slot': slot, 'file_offset': hex(off), 'cache_level': level,
                     'resolved_address': hex(resolved), 'owner': owner,
                     'symbol': symbol, 'standalone_symbols': row['symbols'],
                     'implementation': 'own' if own else 'inherited',
                     'guest_slot_address': hex(guest_start + 16 + 8 * slot),
                     'guest_slot_target': hex(guest_chains[guest_off]), 'pac': pac})
    require(origins.get('com.apple.iokit.IO80211Family', 0) > 0,
            'no resolved native IO80211Family virtual targets')
    for name, expected in inputs.items():
        require(digest(Path(name).read_bytes()) == expected, 'input changed: ' + name)
    for name, expected in sources.items():
        require(digest((ROOT / name).read_bytes()) == expected, 'reader changed: ' + name)
    result = {
        'status': 'NATIVE_CONTROLLER_POSTLINK_TARGETS_PAC_VERIFIED',
        'hardware_access': False, 'runtime_qualified': False, 'slots_checked': len(rows),
        'inputs_sha256': inputs, 'vtable': hex(start), 'origins': origins, 'slots': rows,
        'guest_controller_vtable': hex(guest_start),
        'inherited_slots_patched_by_linker': patched_inherited,
        'verifier_sha256': sources[str(Path(__file__).resolve().relative_to(ROOT))],
        'reader_sources_sha256': sources,
        'limitations': ['Verifies final virtual targets and PAC, not method execution.',
                        'No hardware, firmware, native interface, scan or traffic qualification.'],
    }
    with args.report.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'slots_checked': len(rows),
                      'origins': origins, 'report': str(args.report),
                      'report_sha256': digest(args.report.read_bytes())}))


if __name__ == '__main__':
    main()
