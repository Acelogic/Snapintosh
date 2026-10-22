#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Topology reader bounds, aliases and pinned native layout checks."""
from pathlib import Path
import runpy
import struct
import unittest

api = runpy.run_path(str(Path(__file__).with_name('cpu-topology.py')))


class Topology(unittest.TestCase):
    BOOT_VA = 0xfffffe0007d9fdf8
    BOOT_PA = 0x8c0001000
    DATA_VA = 0xfffffe0010000000
    DATA_PA = 0x94e500000
    RESULT = 0xfffffe010ec80000

    def setUp(self):
        self.mem = {}
        self.words = dict(api['WITNESSES'])
        self.mem[api['BOOTARGS']] = struct.pack('<Q', self.BOOT_VA)
        self.mem[api['NUM_CPUS']] = struct.pack('<I', 6)
        self.mem[api['CPU_SIGNAL']] = struct.pack('<I', 0)
        self.mem[api['MACHINE_INIT']] = struct.pack('<Q', 63)
        self.mem[api['PMAP_CPU']] = struct.pack('<Q', self.RESULT)
        self.mem[api['PMAP_CPU']+0x1d28] = b'\0\0'
        line = b'-v debug=0x8 serial=2\0'.ljust(1024, b'\0')
        self.mem[self.BOOT_PA+0x6c] = self.mem[self.BOOT_VA+0x6c] = line
        self.mem[self.BOOT_PA+0x28] = self.mem[self.BOOT_VA+0x28] = struct.pack(
            '<6Q',0xf9a20000,0,11520,2880,1800,32)
        for i, affinity in enumerate([0, 1, 2, 3, 256, 257]):
            va, pa = self.DATA_VA+i*0x4000, self.DATA_PA+i*0x4000
            self.mem[api['CPU_DATA']+16*i] = struct.pack('<QQ', pa, va)
            raw = bytearray(0x1d0)
            struct.pack_into('<I', raw, 0x40, i)
            struct.pack_into('<I', raw, 0x1c8, affinity)
            self.mem[va] = self.mem[pa] = bytes(raw)

    def read(self, at, size):
        for base, raw in self.mem.items():
            if base <= at < at+size <= base+len(raw):
                return raw[at-base:at-base+size]
        raise ValueError('read outside mapped fixture')

    def capture(self):
        return api['collect'](self.read, self.read, self.words.__getitem__,
                              loader_bootargs_pa=self.BOOT_PA, result_area_va=self.RESULT)

    def test_six_cpu_topology(self):
        d = self.capture()
        self.assertEqual(d['num_cpus'], 6)
        self.assertEqual(d['machine_init_completed_mask'], '0x3f')
        self.assertEqual([r['physical_id'] for r in d['cpu_data_entries']], [0, 1, 2, 3, 256, 257])
        self.assertEqual(d['loader_command_line'], d['kernel_command_line'])
        self.assertEqual(d['loader_video'],d['kernel_video'])
        self.assertEqual(d['kernel_video']['display'],0)

    def test_graphics_video_is_reported_not_gui_qualified(self):
        self.mem[self.BOOT_PA+0x28]=self.mem[self.BOOT_VA+0x28]=struct.pack(
            '<6Q',0xf9a20000,1,11520,2880,1800,32)
        d=self.capture();self.assertEqual(d['kernel_video']['display'],1)
        self.assertIn('not proof',d['boundary'])

    def test_native_witness_mutations(self):
        for at, word in api['WITNESSES'].items():
            self.words[at] ^= 1
            with self.subTest(address=hex(at)), self.assertRaisesRegex(ValueError, 'layout differs'):
                self.capture()
            self.words[at] = word

    def test_monitor_binding(self):
        self.mem[api['PMAP_CPU']] = struct.pack('<Q', self.RESULT+0x4000)
        with self.assertRaisesRegex(ValueError, 'monitor result area'):
            self.capture()

    def test_physical_alias_mismatch(self):
        raw = bytearray(self.mem[self.DATA_PA]); raw[0x40] = 5
        self.mem[self.DATA_PA] = bytes(raw)
        with self.assertRaisesRegex(ValueError, 'aliases differ'):
            self.capture()

    def test_pointer_and_count_bounds(self):
        self.mem[api['NUM_CPUS']] = struct.pack('<I', 7)
        with self.assertRaisesRegex(ValueError, 'CPU count'):
            self.capture()
        self.mem[api['NUM_CPUS']] = struct.pack('<I', 6)
        self.mem[api['BOOTARGS']] = struct.pack('<Q', 0x1000)
        with self.assertRaisesRegex(ValueError, 'topology pointer'):
            self.capture()

    def test_unterminated_command_line(self):
        self.mem[self.BOOT_PA+0x6c] = b'x'*1024
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            self.capture()

    def test_absent_and_partial_cpu_pairs(self):
        self.mem[api['CPU_DATA']+80] = bytes(16)
        self.assertNotIn('physical_id', self.capture()['cpu_data_entries'][5])
        self.mem[api['CPU_DATA']+80] = struct.pack('<QQ', self.DATA_PA, 0)
        with self.assertRaisesRegex(ValueError, 'pointer pair'):
            self.capture()


if __name__ == '__main__':
    unittest.main()
