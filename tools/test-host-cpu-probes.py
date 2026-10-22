#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline malformed-firmware and CPU-start admission checks. No target access."""
import copy
from pathlib import Path
import runpy
import struct
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
info = runpy.run_path(str(ROOT/'tools/probe-a16-cpus.py'))
start = runpy.run_path(str(ROOT/'tools/probe-a16-secondary.py'))
mapping = runpy.run_path(str(ROOT/'tools/host-el2-mapping.py'))


def checksum(data):
    data[9] = 0
    data[9] = -sum(data) & 255
    return bytes(data)


def madt(affinities=(0, 0x100, 0x20000)):
    data = bytearray(44+80*len(affinities))
    data[:4] = b'APIC'
    struct.pack_into('<I', data, 4, len(data))
    for i, affinity in enumerate(affinities):
        offset = 44+i*80
        data[offset:offset+2] = bytes((11, 80))
        struct.pack_into('<III', data, offset+8, i, 1, 0)
        struct.pack_into('<Q', data, offset+68, affinity)
    return checksum(data)


class CpuProbeTests(unittest.TestCase):
    def test_host_mappings_require_identity_cache_and_ram_tables(self):
        memory = dict(sctlr='0x1005',tcr='0x80843514',ttbr0='0x100000',
                      mair='0xffbb4400',hcr='0x80000010')
        pages = {0x100000:0x101003,0x101000:0x102003,
                 0x102000:0x70d,0x102008:0x20070d,0x102010:0x40000000400401}
        ram = [(0x100000,0x103000)]
        ranges = [('code',0x200000,4096,False),('GICR',0x400000,4096,True)]
        def verify(m=memory,p=pages,r=ram):
            return mapping['verify'](lambda pa,n:struct.pack('<Q',p.get(pa,0)),m,ranges,r)
        result = verify()
        self.assertEqual(result['table_pages'],['0x100000','0x101000','0x102000'])
        self.assertEqual([x['pa'] for x in result['mappings']],['0x200000','0x400000'])
        for bit in (0,2,12):
            m = memory.copy(); m['sctlr'] = hex(0x1005 & ~(1 << bit))
            with self.assertRaises(ValueError): verify(m=m)
        for key, value in [('tcr','0x80847514'),('tcr','0x80843518'),
                           ('hcr','0x480000010'),('ttbr0','0x100001')]:
            m = memory.copy();m[key] = value
            with self.assertRaises(ValueError): verify(m=m)
        for desc in (0,0x20070c,0x30070d,0x20078d,0x20030d,0x20040d,
                     0x200701,0x4000000020070d):
            bad = pages.copy();bad[0x102008] = desc
            with self.assertRaises(ValueError): verify(p=bad)
        bad = pages.copy();bad[0x102010] = 0x40070d
        with self.assertRaises(ValueError): verify(p=bad)
        bad = pages.copy();bad[0x102000] = 0x40d
        with self.assertRaises(ValueError): verify(p=bad)
        with self.assertRaises(ValueError): verify(r=[(0x100000,0x102000)])

    def test_coherence_requires_both_counts_matching_regimes_and_publication(self):
        config = (0x1005,0x80843514,0x100000,0xffbb4400)
        state = [0]*64
        for slot in (32,36,48):state[slot:slot+4] = config
        state[40:43] = (0x200000,100000,100000)
        state[45] = 162797
        primary = [0,8,0x100,0,1,1,200000,100000]
        shared = (200000,1,1,1,1,0,0,0)
        def verify(s=state,p=primary,w=shared):
            return start['coherent_passed'](tuple(s),tuple(p),tuple(w),config,0x200000,100000)
        self.assertTrue(verify())
        for slot in list(range(32,45))+list(range(46,64)):
            bad = state.copy();bad[slot] ^= 1
            self.assertFalse(verify(s=bad),slot)
        for value in (0,99999,200001):
            bad = state.copy();bad[45] = value
            self.assertFalse(verify(s=bad))
        for slot in (5,6,7):
            bad = primary.copy();bad[slot] = 0
            self.assertFalse(verify(p=bad))
        for slot in range(8):
            bad = list(shared);bad[slot] ^= 1
            self.assertFalse(verify(w=bad))
        self.assertFalse(verify(s=state[:32]))

    def test_standalone_probe_blobs_have_no_unresolved_relocations(self):
        run = info['run']
        for name in ('el2-memory','psci-info','psci-roundtrip','psci-watchdog','psci-coherent'):
            blob = run.build(name,ROOT/'build/cpu-probe-tests')
            self.assertTrue(0 < len(blob) <= 0x10000)
            reloc = subprocess.check_output([str(run.LLVM/'llvm-readelf'),'-r',
                str(ROOT/'build/cpu-probe-tests'/f'{name}.o')],text=True)
            self.assertIn('There are no relocations in this file.',reloc)

    def test_gic_records_and_watchdog_binding(self):
        data = bytearray(madt((0, 0x100)))
        for i in range(2):
            struct.pack_into('<Q', data, 44+i*80+60, 0x17080000+i*0x40000)
        distributor = bytearray(24)
        distributor[0:2] = bytes((12, 24))
        struct.pack_into('<Q', distributor, 8, 0x17000000)
        distributor[20] = 4
        data += distributor
        struct.pack_into('<I', data, 4, len(data))
        data = checksum(data)
        inv = dict(current_el=2, psci_compliant=True, psci_uses_hvc=False, boot_mpidr='0x0',
                   features={'0xc4000003':0, '0x84000002':0, '0xc4000004':0},
                   cpus=info['cpu_entries'](data), gic=info['gic_entries'](data))
        for i, cpu in enumerate(inv['cpus']): cpu['affinity_state'] = int(i != 0)
        self.assertEqual(start['watchdog_target'](inv, 0x100), 0x170c0000)
        for address in ('0x0', '0x17080000', '0x170c0008', '0x17500000'):
            bad = copy.deepcopy(inv)
            bad['cpus'][1]['redistributor'] = address
            with self.assertRaises(ValueError): start['watchdog_target'](bad, 0x100)
        for key, value in [('base', '0x0'), ('version', 2)]:
            bad = copy.deepcopy(inv)
            bad['gic']['distributors'][0][key] = value
            with self.assertRaises(ValueError): start['watchdog_target'](bad, 0x100)
        truncated = bytearray(data[:-1])
        truncated[44+160+1] = 23
        struct.pack_into('<I', truncated, 4, len(truncated))
        with self.assertRaises(ValueError): info['gic_entries'](checksum(truncated))

    def test_watchdog_evidence_rejects_cooperative_exit_or_wrong_interrupt(self):
        state = [0]*32
        state[0], state[10], state[11], state[12] = 2, 19000000, 100000000, 101900000
        state[13], state[14], state[15], state[16] = 101900020, 26, 5, 0x20000010
        state[17], state[26], state[30] = 0x800003c5, 0x20000000, 6
        self.assertTrue(start['watchdog_passed'](state, 0x20000000))
        for index, value in [(0,4), (0,3), (7,0x58000001), (10,0), (12,101900001),
                             (13,101899999), (13,119000000), (14,27), (14,1023),
                             (15,1), (15,4), (16,0x1fffffff), (16,0x20000018),
                             (17,0x3c9), (17,0x5), (27,2), (28,8), (30,3), (31,1)]:
            bad = state.copy(); bad[index] = value
            self.assertFalse(start['watchdog_passed'](bad, 0x20000000), (index,value))
        self.assertFalse(start['watchdog_passed'](state[:8], 0x20000000))

    def test_madt_affinities_and_bounds(self):
        cpus = info['cpu_entries'](madt())
        self.assertEqual([int(c['mpidr'], 16) for c in cpus], [0, 0x100, 0x20000])
        self.assertEqual([c['uid'] for c in cpus], [0, 1, 2])
        self.assertTrue(all(c['parking_version'] == 0 for c in cpus))
        for offset, value in [(0, ord('Z')), (9, 123), (45, 0), (45, 1), (45, 75), (45, 255)]:
            data = bytearray(madt((0,)))
            data[offset] = value
            if offset not in (0, 9):
                data = checksum(data)
            with self.assertRaises(ValueError):
                info['cpu_entries'](data)
        for bad in (madt(()), madt((0, 0)), madt()[:-1]):
            with self.assertRaises(ValueError):
                info['cpu_entries'](bad)

    def test_only_declared_off_cpu_can_start(self):
        inventory = dict(current_el=2, psci_compliant=True, psci_uses_hvc=False, boot_mpidr='0x0',
                         features={'0xc4000003': 0, '0x84000002': 0, '0xc4000004': 0},
                         cpus=[dict(mpidr='0x0', flags=1, affinity_state=0),
                               dict(mpidr='0x100', flags=1, affinity_state=1)])
        start['validate_target'](inventory, 0x100)
        for mpidr in (0, 0x200, -1, 0x80000100, 1 << 48, True):
            with self.assertRaises(ValueError):
                start['validate_target'](inventory, mpidr)
        for state in (0, 2, -1, -2, None):
            bad = copy.deepcopy(inventory)
            bad['cpus'][1]['affinity_state'] = state
            with self.assertRaises(ValueError):
                start['validate_target'](bad, 0x100)
        for key, value in [('current_el', 1), ('psci_compliant', False), ('psci_uses_hvc', True)]:
            bad = copy.deepcopy(inventory)
            bad[key] = value
            with self.assertRaises(ValueError):
                start['validate_target'](bad, 0x100)
        for fid in inventory['features']:
            bad = copy.deepcopy(inventory)
            bad['features'][fid] = -1
            with self.assertRaises(ValueError):
                start['validate_target'](bad, 0x100)
        for state in (0, 2, -1, None):
            bad = copy.deepcopy(inventory)
            bad['cpus'].append(dict(mpidr='0x200', flags=1, affinity_state=state))
            with self.assertRaises(ValueError):
                start['validate_target'](bad, 0x100)
        bad = copy.deepcopy(inventory)
        del bad['boot_mpidr']
        with self.assertRaises(ValueError):
            start['validate_target'](bad, 0x100)
        for enabled in (False, None):
            bad = copy.deepcopy(inventory)
            if enabled is False:
                bad['cpus'][1]['flags'] = 0
            else:
                bad['cpus'].append(copy.deepcopy(bad['cpus'][1]))
            with self.assertRaises(ValueError):
                start['validate_target'](bad, 0x100)


if __name__ == '__main__':
    unittest.main(verbosity=2)
