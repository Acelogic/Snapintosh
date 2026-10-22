#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Start one firmware-off CPU, record its EL, then have it power itself off.

With --watchdog, prove EL2 timer preemption of a masked, bounded EL1 loop.
With --warm-entry, execute the resident stock CPU1 entry stub with read-only
guest mappings and trap before its reset handler, then verify OFF and memory.
This is a hardware liveness probe, not an XNU SMP backend. Never run while
another proxy client or a guest is executing. Keeps the CPU scratch reserved
until AFFINITY_INFO confirms it is off; never retries CPU_ON on uncertainty.
"""
import argparse
import json
from pathlib import Path
import runpy
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'probes'))
import run


def validate_target(inventory, mpidr):
    if (type(mpidr) is not int or mpidr < 0 or mpidr & ~0xff00ffffff or
            inventory.get('current_el') != 2 or
            not inventory.get('psci_compliant') or inventory.get('psci_uses_hvc')):
        raise ValueError('target requires an affinity-only MPIDR and EL2 SMC PSCI')
    if 'boot_mpidr' not in inventory:
        raise ValueError('missing current physical CPU identity')
    boot_mpidr = int(inventory['boot_mpidr'], 16)
    if mpidr == boot_mpidr:
        raise ValueError('cannot start the executing proxy CPU')
    # All secondary probes share one scratch region. Do not overwrite it if
    # any previous start is still executing or its power state is uncertain.
    for cpu in inventory['cpus']:
        if cpu['flags'] & 1:
            expected = 0 if int(cpu['mpidr'], 16) == boot_mpidr else 1
            if cpu.get('affinity_state') != expected:
                raise ValueError('CPU state uncertain; preserve shared secondary scratch')
    targets = [c for c in inventory['cpus'] if int(c['mpidr'], 16) == mpidr]
    if (len(targets) != 1 or not targets[0]['flags'] & 1 or
            targets[0].get('affinity_state') != 1 or
            any(inventory.get('features', {}).get(fid) != 0
                for fid in ('0xc4000003', '0x84000002', '0xc4000004'))):
        raise ValueError('target must be declared OFF; start/stop/query must be supported')


def watchdog_target(inventory, mpidr):
    validate_target(inventory, mpidr)
    if inventory.get('gic', {}).get('distributors') != [dict(base='0x17000000', version=4)]:
        raise ValueError('watchdog requires the measured A16 GICv4 distributor')
    cpus = inventory['cpus']
    target = next(c for c in cpus if int(c['mpidr'], 16) == mpidr)
    redist = int(target.get('redistributor', '0x0'), 16)
    if (not 0x17080000 <= redist < 0x17500000 or
            (redist-0x17080000) % 0x40000 or
            sum(int(c.get('redistributor', '0x0'), 16) == redist for c in cpus) != 1):
        raise ValueError('missing, aliased or out-of-range A16 redistributor')
    return redist


def watchdog_passed(state, code):
    return (len(state) == 32 and state[0] == 2 and state[7] == 0 and
            state[14] == 26 and state[15] & 5 == 5 and state[17] & 0x3ff == 0x3c5 and
            code <= state[26] <= state[16] < state[26]+24 and
            state[10] > 0 and state[12]-state[11] == state[10]//10 and
            state[12] <= state[13] < state[11]+state[10] and
            state[27] & 2 == state[19] & 2 and not state[28] & 8 and
            state[30] == 6 and state[31] == 0)


def coherent_passed(state, primary, shared_words, config, shared, iterations):
    return (len(state) == 64 and len(primary) == 8 and iterations > 0 and
            primary[5] == 1 and primary[7] == iterations and
            state[32:36] == state[36:40] == state[48:52] == tuple(config) and
            state[40:43] == (shared,iterations,iterations) and state[43:45] == (0,0) and
            iterations <= primary[6] <= 2*iterations and
            iterations <= state[45] <= 2*iterations and not any(state[46:48]+state[52:]) and
            shared_words == (2*iterations,1,1,1,1,0,0,0))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--mpidr', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--watchdog', action='store_true',
                    help='prove this core\'s EL2 timer interrupts a masked EL1 loop')
    ap.add_argument('--coherent', action='store_true',
                    help='also use shared cached EL2 mappings and two-core atomic increments')
    ap.add_argument('--warm-entry', action='store_true',
                    help='trace the resident stock CPU1 entry to its reset-handler boundary')
    args = ap.parse_args()
    if args.warm_entry:
        args.coherent = True
    if args.coherent:
        args.watchdog = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    info_blob = run.build('psci-info', ROOT/'build/cpu-probe')
    probe = ('psci-warm-entry' if args.warm_entry else 'psci-coherent' if args.coherent
             else 'psci-watchdog' if args.watchdog else 'psci-roundtrip')
    blob = run.build(probe, ROOT/'build/cpu-probe')
    collect = runpy.run_path(str(ROOT/'tools/probe-a16-cpus.py'))['collect']
    proxy = run.connect(args.device, tries=1)
    report = dict(target=hex(args.mpidr), watchdog=args.watchdog,
                  coherent=args.coherent, warm_entry=args.warm_entry,
                  cpu_on_issued=False, cleanup_confirmed=False)
    report_size = 1024 if args.warm_entry else 512 if args.coherent else 256 if args.watchdog else 64

    def save():
        args.output.write_text(json.dumps(report, indent=2)+'\n')

    try:
        if args.coherent:
            memory_probe = run.build('el2-memory', ROOT/'build/cpu-probe')
            memory_api = runpy.run_path(str(ROOT/'tools/probe-el2-memory.py'))
            primary_memory = memory_api['collect'](proxy, memory_probe)
            report['primary_memory'] = primary_memory
            mapping_api = runpy.run_path(str(ROOT/'tools/host-el2-mapping.py'))
            memory_config = mapping_api['validate_regime'](primary_memory)
        # Restores the PSCI query code after the optional memory inventory.
        inventory = collect(proxy, info_blob, True)
        report['inventory'] = inventory
        save()
        validate_target(inventory, args.mpidr)
        secondary_initial = bytearray(report_size)
        if args.watchdog:
            redist = watchdog_target(inventory, args.mpidr)
            typer = proxy.read64(redist+8)
            affinity = (args.mpidr & 0xffffff) | ((args.mpidr >> 32) << 24)
            control = proxy.read32(0x17000000)
            report.update(redistributor=hex(redist), gic_typer=hex(typer),
                          distributor_control=hex(control))
            # With ARE_NS set, Group1A (bit1) is the affinity-routing enable;
            # legacy Group1 (bit0) can read zero on this GICv4 implementation.
            if typer >> 32 != affinity or control & 0x80000012 != 0x12:
                raise ValueError('GIC affinity/routing not ready; no distributor writes allowed')
            gic_before = dict(group=proxy.read32(redist+0x10080),
                priority=proxy.read8(redist+0x1041a), enable=proxy.read32(redist+0x10100),
                pending=proxy.read32(redist+0x10200), active=proxy.read32(redist+0x10300),
                config=proxy.read32(redist+0x10c04), waker=proxy.read32(redist+0x14))
            report['gic_before'] = gic_before
            if proxy.exceptions:
                raise ValueError('proxy fault during GIC admission; CPU start refused')
            if (gic_before['enable'] or (gic_before['pending'] | gic_before['active']) & (1 << 26)
                    or gic_before['config'] & (1 << 21)):
                raise ValueError('secondary interrupt state is not idle/level-triggered')
            report.update(redistributor=hex(redist), gic_typer=hex(typer),
                          distributor_control=hex(control), gic_before=gic_before)
            struct.pack_into('<QQ', secondary_initial, 64, redist, args.mpidr)
        info = proxy.bootinfo()
        needed = 0x4f0000 if args.warm_entry else 0x4b2040 if args.coherent else 0x4b1000+report_size
        if info['current_el'] != 2 or info['heap_size'] < needed or len(blob) > 0x10000:
            raise ValueError('invalid EL or scratch geometry')
        code, out = info['heap_base']+0x4a0000, info['heap_base']+0x4b0000
        secondary = out+4096
        if code % 2048 or secondary % 64:
            raise ValueError('unaligned secondary code or cache-line report')
        report.update(code=hex(code), primary_report=hex(out), secondary_report=hex(secondary))
        if args.warm_entry:
            warm_api=runpy.run_path(str(ROOT/'tools/stock-warm-entry.py'))
            warm_inputs,warm_tables,warm_originals,warm_immutable,warm_witness=warm_api['prepare'](
                proxy,info,info['heap_base']+0x4c0000,info['heap_base']+0x4f0000)
            report['warm_entry_contract']=warm_witness
            struct.pack_into('<16Q',secondary_initial,512,*warm_inputs)
        if args.coherent:
            shared, iterations = out+8192, 100000
            stride, size = info['memory_map_stride'], info['memory_map_size']
            if stride < 40 or not 0 < size <= 1024*1024 or size % stride:
                raise ValueError('invalid firmware RAM map')
            raw = proxy.readmem(info['memory_map'], size, live=True)
            ram = []
            for offset in range(0, size, stride):
                kind, pa, _, pages, _ = struct.unpack_from('<I4xQQQQ', raw, offset)
                if kind in (1,2,3,4,5,6,7,9,10) and pages:
                    ram.append((pa, pa+pages*4096))
            regions = [('code',code,len(blob),False), ('primary report',out,64,False),
                       ('secondary report',secondary,report_size,False),
                       ('shared atomic',shared,64,False), ('GICR',redist,4096,True),
                       ('GICR SGI',redist+0x10000,4096,True)]
            if args.warm_entry:
                regions.extend((f'warm table {pa:x}',pa,4096,False) for pa in warm_tables)
            witness = mapping_api['verify'](
                lambda pa,n:proxy.readmem(pa,n,live=True),primary_memory,regions,ram)
            if proxy.exceptions:
                raise ValueError('proxy fault during shared-map admission')
            report.update(shared=hex(shared),iterations=iterations,host_mapping=witness)
            for page in witness['table_pages']:
                proxy.request(proxy.P_DC_CVAC,int(page,16),4096)
            struct.pack_into('<QQ',secondary_initial,320,shared,iterations)
            struct.pack_into('<4Q',secondary_initial,384,*memory_config)
            proxy.writemem(shared,bytes(64))
            proxy.request(proxy.P_DC_CIVAC,shared,64)
        if args.warm_entry:
            for pa,data in warm_tables.items():
                proxy.writemem(pa,data)
                proxy.request(proxy.P_DC_CVAC,pa,len(data))
                if proxy.readmem(pa,len(data),live=True)!=data:
                    raise ValueError('private warm-entry table readback mismatch')
        proxy.writemem(code, blob)
        proxy.request(proxy.P_DC_CVAC, code, len(blob))
        proxy.ic_ivau(code, len(blob))
        proxy.writemem(out, bytes(64))
        proxy.writemem(secondary, secondary_initial)
        proxy.request(proxy.P_DC_CIVAC, out, 64)
        proxy.request(proxy.P_DC_CIVAC, secondary, report_size)
        report['cpu_on_issued'] = True
        save()  # Keep the reservation and uncertain-call record before P_CALL.
        proxy.call(code, out, args.mpidr, timeout=10)
        primary = struct.unpack('<8Q', proxy.readmem(out, 64, live=True))
        report['primary_words'] = [hex(x) for x in primary]
        if primary[4] != 1 or primary[1] != 8 or primary[2] != args.mpidr:
            raise ValueError('incomplete CPU_ON report')
        if primary[0] != 0:
            raise ValueError(f'CPU_ON refused: {primary[0]:#x}')
        deadline = time.monotonic()+5
        while True:
            # Read-only affinity probe already uploaded by collect().
            qcode, qout = info['heap_base']+0x480000, info['heap_base']+0x490000
            proxy.writemem(qout, bytes(64))
            proxy.call(qcode, qout, 2, args.mpidr, timeout=10)
            query = struct.unpack('<8Q', proxy.readmem(qout, 64, live=True))
            if (query[0] != 8 or query[6] != 8 or query[1] != query[7] or
                    query[2:4] != (2, args.mpidr) or query[5] != 1):
                raise ValueError('invalid cleanup query')
            report['final_affinity_state'] = query[4]
            proxy.request(proxy.P_DC_IVAC, secondary, report_size)
            state = struct.unpack(f'<{report_size//8}Q', proxy.readmem(secondary, report_size, live=True))
            report['secondary_words'] = [hex(x) for x in state]
            if query[4] == 1:
                report['cleanup_confirmed'] = True
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('secondary not confirmed OFF; keep scratch reserved')
            time.sleep(0.02)
        report['entry_el'] = state[1] >> 2
        report['entry_mpidr'] = hex(state[2])
        report['roundtrip_passed'] = (state[0] == 2 and state[1] == 8 and
                                     state[2] & 0xff00ffffff == args.mpidr and state[7] == 0)
        if args.watchdog:
            after = dict(group=proxy.read32(redist+0x10080), priority=proxy.read8(redist+0x1041a),
                         enable=proxy.read32(redist+0x10100), pending=proxy.read32(redist+0x10200),
                         active=proxy.read32(redist+0x10300), config=proxy.read32(redist+0x10c04),
                         waker=proxy.read32(redist+0x14))
            report['gic_after'] = after
            restored=(all(after[k] == gic_before[k] for k in ('group', 'priority', 'enable', 'config')) and
                      not (after['pending'] | after['active']) & (1 << 26))
            report['watchdog_passed'] = watchdog_passed(state[:32], code) and restored
            report['interrupt_state_restored']=restored
            if not args.warm_entry:
                report['roundtrip_passed'] &= report['watchdog_passed']
            else:
                report['warm_entry_passed']=warm_api['passed'](state,warm_inputs,warm_witness)
                report['roundtrip_passed']=(report['warm_entry_passed'] and restored and
                    state[2]&0xff00ffffff==args.mpidr and report['cleanup_confirmed'])
                for collection in (warm_tables,warm_originals,warm_immutable):
                    for pa,data in collection.items():
                        proxy.request(proxy.P_DC_IVAC,pa,len(data))
                        if proxy.readmem(pa,len(data),live=True)!=data:
                            raise ValueError(f'warm-entry immutable memory changed at {pa:#x}')
                report['warm_memory_unchanged']=True
        if args.coherent:
            # Both participants have stopped modifying the shared block.
            proxy.request(proxy.P_DC_CIVAC,shared,64)
            shared_words = struct.unpack('<8Q',proxy.readmem(shared,64,live=True))
            report['shared_words'] = list(shared_words)
            report['coherent_passed'] = coherent_passed(state[:64],primary,shared_words,
                                                       memory_config,shared,iterations)
            report['roundtrip_passed'] &= report['coherent_passed']
        if proxy.exceptions:
            raise ValueError('proxy fault invalidates secondary proof')
        if args.warm_entry:
            after_memory=memory_api['collect'](proxy,memory_probe)
            report['primary_memory_after']=after_memory
            if (mapping_api['validate_regime'](after_memory)!=memory_config or
                    after_memory['hcr']!=primary_memory['hcr']):
                raise ValueError('warm-entry probe changed the primary EL2 regime')
        proxy.nop()
        save()
        print(json.dumps({k: v for k, v in report.items() if k != 'inventory'}, indent=2))
        if not report['roundtrip_passed']:
            raise RuntimeError('secondary returned OFF but entry evidence failed')
    except BaseException as error:
        report['error'] = str(error)
        save()
        raise
    finally:
        proxy.link.close()


if __name__ == '__main__':
    main()
