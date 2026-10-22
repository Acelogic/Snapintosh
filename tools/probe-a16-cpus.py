#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory firmware CPU entries and query PSCI without changing CPU power.

Uses the stopped-probe scratch gap at heap+0x480000..0x490040, preserving
xnuboot code, report and work arena. Run only with no other proxy client.
No guest memory, physical MMIO, CPU start, parking mailbox or disk writes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run


def checked_table(data, signature):
    if (len(data) < 36 or data[:4] != signature or
            struct.unpack_from('<I', data, 4)[0] != len(data) or sum(data) & 255):
        raise ValueError(f'invalid ACPI {signature!r}')
    return data


def cpu_entries(data):
    checked_table(data, b'APIC')
    if len(data) < 44:
        raise ValueError('truncated MADT')
    cpus = []
    offset = 44
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError('truncated MADT entry')
        kind, size = data[offset:offset+2]
        if size < 2 or offset + size > len(data):
            raise ValueError('invalid MADT entry extent')
        if kind == 11:
            if size < 76:
                raise ValueError('truncated GICC')
            uid, flags, parking = struct.unpack_from('<III', data, offset+8)
            parked, = struct.unpack_from('<Q', data, offset+24)
            mpidr, = struct.unpack_from('<Q', data, offset+68)
            redistributor, = struct.unpack_from('<Q', data, offset+60)
            # ACPI 6.0+ GICC byte 76: Processor Power Efficiency Class (higher = more performant tier on Arm systems
            # per Linux's acpi_cpu_get_efficiency_class use; reported raw here, interpreted by the reader).
            efficiency = data[offset+76] if size >= 77 else None
            cpus.append(dict(uid=uid, flags=flags, parking_version=parking,
                             parked_address=hex(parked), mpidr=hex(mpidr),
                             redistributor=hex(redistributor), efficiency_class=efficiency))
        offset += size
    if not cpus or len({c['mpidr'] for c in cpus}) != len(cpus):
        raise ValueError('missing or duplicate GICC affinities')
    return cpus


def gic_entries(data):
    # Reuse the complete geometry/CPU validation before parsing GIC records.
    cpu_entries(data)
    result = dict(distributors=[], redistributors=[])
    offset = 44
    while offset < len(data):
        kind, size = data[offset:offset+2]
        if kind == 12:
            if size < 24:
                raise ValueError('truncated GICD')
            address, = struct.unpack_from('<Q', data, offset+8)
            result['distributors'].append(dict(base=hex(address), version=data[offset+20]))
        elif kind == 14:
            if size < 16:
                raise ValueError('truncated GICR')
            address, span = struct.unpack_from('<QI', data, offset+4)
            if (not address or address % 0x10000 or span < 0x20000 or span > 0x4000000
                    or address+span > 1 << 64):
                raise ValueError('invalid GICR range')
            result['redistributors'].append(dict(base=hex(address), span=span))
        offset += size
    return result


def collect(proxy, blob, query_psci):
    info = proxy.bootinfo()
    stride, size = info['memory_map_stride'], info['memory_map_size']
    if stride < 40 or size == 0 or size % stride or size > 1024*1024:
        raise ValueError('invalid UEFI memory map geometry')
    raw = proxy.readmem(info['memory_map'], size, live=True)
    ranges = []
    for offset in range(0, size, stride):
        kind, pa, _, pages, _ = struct.unpack_from('<I4xQQQQ', raw, offset)
        if kind in (1, 2, 3, 4, 5, 6, 7, 9, 10) and pages:
            ranges.append((pa, pa + pages*4096))

    def read(pa, length):
        if not 0 < length <= 1024*1024 or not any(
                begin <= pa and pa+length <= end for begin, end in ranges):
            raise ValueError(f'ACPI read outside declared RAM: {pa:#x}+{length:#x}')
        return proxy.readmem(pa, length, live=True)

    rsdp = read(info['acpi_rsdp'], 36)
    if (rsdp[:8] != b'RSD PTR ' or rsdp[15] < 2 or sum(rsdp[:20]) & 255 or
            struct.unpack_from('<I', rsdp, 20)[0] != 36 or sum(rsdp) & 255):
        raise ValueError('invalid ACPI 2+ RSDP')

    def table(pa, expected=None):
        head = read(pa, 36)
        length, = struct.unpack_from('<I', head, 4)
        if not 36 <= length <= 1024*1024:
            raise ValueError('invalid table size')
        data = read(pa, length)
        return checked_table(data, expected or head[:4])

    xsdt = table(struct.unpack_from('<Q', rsdp, 24)[0], b'XSDT')
    if (len(xsdt)-36) % 8:
        raise ValueError('invalid XSDT pointer array')
    tables = {}
    for (pa,) in struct.iter_unpack('<Q', xsdt[36:]):
        signature = read(pa, 36)[:4]
        if signature in (b'FACP', b'APIC'):
            if signature in tables:
                raise ValueError('duplicate CPU platform table')
            tables[signature] = table(pa, signature)
    fadt = tables[b'FACP']
    if len(fadt) < 131:
        raise ValueError('FADT has no ARM boot architecture field')
    arm_boot, = struct.unpack_from('<H', fadt, 129)
    report = dict(stage_generation=info['stage_generation'], current_el=info['current_el'],
                  arm_boot_arch=arm_boot, psci_compliant=bool(arm_boot & 1),
                  psci_uses_hvc=bool(arm_boot & 2), cpus=cpu_entries(tables[b'APIC']),
                  gic=gic_entries(tables[b'APIC']),
                  tables={k.decode(): dict(size=len(v), sha256=hashlib.sha256(v).hexdigest())
                          for k, v in tables.items()}, queries=[])
    if not query_psci:
        return report
    if not report['psci_compliant'] or report['psci_uses_hvc']:
        report['query_skipped'] = 'firmware does not declare SMC PSCI'
        return report
    if info['current_el'] != 2 or info['heap_size'] < 0x490040 or not 0 < len(blob) <= 0x10000:
        raise ValueError('probe requires EL2 and reserved scratch geometry')
    code, out = info['heap_base']+0x480000, info['heap_base']+0x490000
    proxy.writemem(code, blob)
    proxy.flush_code(code, len(blob))

    def query(operation, argument=0):
        proxy.writemem(out, bytes(64))
        # Never retry P_CALL, including on timeout.
        proxy.call(code, out, operation, argument, timeout=10)
        words = struct.unpack('<8Q', proxy.readmem(out, 64, live=True))
        if (words[0] != 8 or words[6] != 8 or words[1] != words[7] or
                words[2:4] != (operation, argument) or words[5] != 1):
            raise ValueError('incomplete or mismatched query report')
        boot_mpidr = hex(words[1] & 0xff00ffffff)
        if report.setdefault('boot_mpidr', boot_mpidr) != boot_mpidr:
            raise ValueError('proxy CPU changed during inventory')
        value = words[4] & 0xffffffff
        value = value if value < 0x80000000 else value-0x100000000
        report['queries'].append(dict(operation=operation, argument=hex(argument),
                                      result=value, raw_result=hex(words[4]), mpidr=hex(words[1])))
        return value

    version = query(0)
    report['psci_version_raw'] = version
    features = {}
    if version >= 0x10000:
        features = {hex(fid): query(1, fid) for fid in (0xc4000003, 0x84000002, 0xc4000004)}
    report['features'] = features
    if features.get('0xc4000004', -1) >= 0 or version == 2:
        for cpu in report['cpus']:
            if cpu['flags'] & 1:
                cpu['affinity_state'] = query(2, int(cpu['mpidr'], 16))
    proxy.nop()
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--query-psci', action='store_true', help='read-only SMC queries if FADT permits')
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    blob = run.build('psci-info', ROOT/'build'/'cpu-probe') if args.query_psci else b''
    proxy = run.connect(args.device, tries=1)
    try:
        report = collect(proxy, blob, args.query_psci)
    finally:
        proxy.link.close()
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
