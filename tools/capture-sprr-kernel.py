#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only mapping evidence for the selected kernel's selector2 copy stop.

This reports source selectors and ordinary ARM shadow permissions. It does
not qualify those permissions as correct SPRR behavior or resume the guest.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OA = 0x0000fffffffff000
STOP = 0xfffffe000ba731a8


def leaves(read, root, granule, low, high):
    """Walk the audited 47-bit stage1 regime, retaining raw descriptors."""
    if granule not in (12, 14):
        raise ValueError('unsupported granule')
    bits = granule - 3
    first = 0 if granule == 12 else 1
    tables = set()

    def visit(table, level, base):
        size = 1 << granule
        if table & (size - 1) or not low <= table <= high - size:
            raise ValueError('table outside audited reservation')
        if table in tables:
            raise ValueError('repeated kernel table')
        tables.add(table)
        if len(tables) > 16384:
            raise ValueError('table budget exceeded')
        raw = read(table, size)
        if len(raw) != size:
            raise ValueError('short table read')
        shift = granule + bits * (3 - level)
        for index, (desc,) in enumerate(struct.iter_unpack('<Q', raw)):
            va = base + (index << shift)
            if va >= 1 << 47:
                if desc & 1:
                    raise ValueError('valid entry outside 47-bit regime')
                continue
            if not desc & 1:
                continue
            kind = desc & 3
            if level < 3 and kind == 3:
                yield from visit(desc & OA & ~(size - 1), level + 1, va)
            else:
                if (level == 0 or (level == 3 and kind != 3) or
                        (level < 3 and kind != 1)):
                    raise ValueError('invalid leaf type')
                span = 1 << shift
                pa = desc & OA
                if pa & (span - 1):
                    raise ValueError('misaligned leaf output')
                yield dict(va=va, pa=pa, size=span, descriptor=desc,
                           selector=((desc >> 4) & 12) | ((desc >> 53) & 3))

    return list(visit(root, first, 0))


def resolve(rows, va):
    va &= (1 << 47) - 1
    found = [r for r in rows if r['va'] <= va < r['va'] + r['size']]
    if len(found) != 1:
        raise ValueError('address does not have one valid mapping')
    row = found[0]
    return dict(row, resolved_pa=row['pa'] + va - row['va'])


def ordinary_arm_permissions(desc):
    ap = (desc >> 6) & 3
    return dict(el1_read=True, el1_write=not bool(ap & 2),
                el1_execute=not bool(desc & (1 << 53)),
                el0_read=bool(ap & 1), el0_write=bool(ap & 1) and not bool(ap & 2),
                el0_execute=not bool(desc & (1 << 54)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True)
    parser.add_argument('--prefix', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid artifact prefix')
    base = ROOT / 'build' / args.prefix
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    stop = json.loads(Path(f'{base}-cpu0-stop.json').read_text())
    if stop['cpu'] != 0 or int(stop['pc'], 16) != STOP or stop['snapshot_kind'] != 2:
        raise ValueError('requires the captured CPU0 selector2 write stop')
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != audit['monitor_sha256'] or digest != stop['monitor_sha256']:
        raise ValueError('build differs from the audited snapshot')
    layout = subprocess.run(['clang', '--target=aarch64-unknown-none-elf',
        '-ffreestanding', '-mgeneral-regs-only', '-Ishadow', '-Icompat',
        '-Xclang', '-fdump-record-layouts', '-fsyntax-only', 'probes/xnuboot.c'],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout

    def offset(kind, field):
        block = next(b for b in layout.split('*** Dumping AST Record Layout')
                     if re.search(r'^\s*0 \| struct ' + kind + r'\n', b))
        values = re.findall(r'^\s*(\d+) \|   .+ ' + field + r'$', block, re.M)
        if len(values) != 1:
            raise ValueError('ambiguous layout')
        return int(values[0])

    secondary = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))
    sys.path.insert(0, str(ROOT / 'probes'))
    import run
    proxy = run.connect(args.device, tries=1)
    try:
        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)

        def read(pa, size):
            return b''.join(proxy.readmem(pa + i, min(65536, size - i), live=True)
                            for i in range(0, size, 65536))

        def q(pa):
            return struct.unpack('<Q', read(pa, 8))[0]

        def service():
            return list(struct.unpack('<8Q', read(work + offset('context', 'services'), 64)))

        if read(info['heap_base'] + run.CODE_AT, len(blob)) != blob:
            raise ValueError('resident monitor differs from audited code')
        if service() != audit['service'] or audit['service'][1] != 0x100000001:
            raise ValueError('resident service stop changed')
        cpu = work + secondary['VCPUS_OFFSET']
        registers = [int(stop['registers'][str(i)], 16) for i in range(31)]
        registers += [int(stop[k], 16) for k in ('sp', 'pstate', 'pc', 'esr', 'far')]
        if read(cpu + offset('vcpu', 'async_regs'), 288) != struct.pack('<36Q', *registers):
            raise ValueError('resident CPU0 snapshot changed')
        roots = [q(cpu + i * secondary['VCPU_SIZE'] + offset('vcpu', 'shadow_root'))
                 for i in range(6)]
        g = audit['geometry']
        end = q(work + offset('context', 'next_table'))
        if not work < end <= work + work_size:
            raise ValueError('invalid monitor table reservation')
        guest = leaves(read, g['root'], 14, g['ram_low'], g['ram_high'])
        hardware = leaves(read, roots[0], 12, work, end)

        def va_read(va, size):
            if not 0 < size <= 4096:
                raise ValueError('invalid kernel object read')
            result = bytearray()
            while size:
                mapping = resolve(guest, va)
                pa = mapping['resolved_pa']
                chunk = min(size, 16384 - (va & 16383))
                if not g['ram_low'] <= pa < pa + chunk <= g['ram_high']:
                    raise ValueError('kernel object outside RAM')
                result.extend(read(pa, chunk))
                va += chunk
                size -= chunk
            return bytes(result)

        target = resolve(guest, registers[24])
        if target['resolved_pa'] != registers[21]:
            raise ValueError('saved target VA and PA disagree')
        target_pa = registers[21]
        frame_pa = g['frame_map'] + ((target_pa - g['frame_low']) >> 14) * 16
        if not g['frame_low'] <= target_pa < g['frame_high']:
            raise ValueError('copy target outside frame metadata')
        target_frame = read(frame_pa, 16)
        aliases = [dict(r, target_va=r['va'] + target_pa - r['pa']) for r in guest
                   if r['pa'] <= target_pa < r['pa'] + r['size']]
        for row in aliases:
            shadow = resolve(hardware, row['target_va'])
            if shadow['resolved_pa'] != target_pa:
                raise ValueError('source and shadow output addresses disagree')
            row['shadow'] = shadow
            row['ordinary_arm_shadow'] = ordinary_arm_permissions(shadow['descriptor'])
        # The next shipped call (c22aa40) searches 24-byte physical-to-virtual
        # records through these globals. Read its actual pending destination,
        # which can differ from the original protected virtual address.
        globals_va = 0xfffffe0007ec0238
        globals_raw = va_read(globals_va, 24)
        count_va, table_va = struct.unpack_from('<2Q', globals_raw, 8)
        if not globals_raw[0] & 1:
            raise ValueError('physical translation records not initialized')
        count, = struct.unpack('<I', va_read(count_va, 4))
        if not 1 <= count <= 128:
            raise ValueError('physical translation count outside capture bound')
        records = []
        for index, (pa, va, pages, flags) in enumerate(
                struct.iter_unpack('<QQII', va_read(table_va, count * 24))):
            if pa <= target_pa < pa + (pages << 14):
                destination = va + target_pa - pa
                mapping = resolve(guest, destination)
                shadow = resolve(hardware, destination)
                if mapping['resolved_pa'] != target_pa or shadow['resolved_pa'] != target_pa:
                    raise ValueError('pending copy destination resolves to a different PA')
                records.append(dict(index=index, pa=hex(pa), va=hex(va), pages=pages,
                    flags=hex(flags), copy_destination=hex(destination), source=mapping,
                    shadow=shadow, ordinary_arm_shadow=ordinary_arm_permissions(shadow['descriptor'])))
        if len(records) != 1:
            raise ValueError('pending physical translation is ambiguous or absent')
        if service() != audit['service']:
            raise ValueError('service state changed during capture')
        report = dict(monitor_sha256=digest, pc=hex(STOP), cpu=0,
            kernel_shadow_roots=[hex(r) for r in roots],
            shared_kernel_shadow=len(set(roots)) == 1,
            selector_leaf_counts=dict(sorted(collections.Counter(r['selector'] for r in guest).items())),
            selector_virtual_bytes={str(i): sum(r['size'] for r in guest if r['selector'] == i)
                                    for i in sorted({r['selector'] for r in guest})},
            copy_bytes=registers[19], source_va=hex(registers[20]),
            target_va=hex(registers[24]), target_pa=hex(target_pa),
            target_frame_type=target_frame[2], target_frame_hex=target_frame.hex(),
            source=resolve(guest, registers[20]), target=target, aliases=aliases,
            physical_translation=records[0],
            qualification='mapping evidence only; SPRR permission translation remains unimplemented')
    finally:
        proxy.link.close()
    path = Path(f'{base}-sprr-kernel.json')
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('shared_kernel_shadow', 'selector_leaf_counts',
        'copy_bytes', 'target_va', 'target_pa', 'qualification')}))
    print(path)


if __name__ == '__main__':
    main()
