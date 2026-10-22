#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refusal and bounds checks for the read-only native SEP inventory."""
from pathlib import Path
import runpy
import struct
import unittest

s = runpy.run_path(str(Path(__file__).with_name('sep-state.py')))
BASE = 0xfffffe0010000000


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.mem = {}
        self.words = dict(s['WITNESSES'])
        self.put(s['ENDPOINTS'], bytes(256))

    def put(self, address, data):
        self.mem.update({address+i: b for i, b in enumerate(data)})

    def read(self, address, size):
        self.assertGreater(size, 0)
        self.assertLessEqual(size, 2530)
        return bytes(self.mem[address+i] for i in range(size))

    def collect(self):
        return s['collect'](self.read, self.words.__getitem__)

    def ready(self):
        self.put(s['ENDPOINTS'], struct.pack('<Q', BASE))
        endpoint = bytearray(0x78)
        struct.pack_into('<Q', endpoint, 0x70, BASE+0x1000)
        self.put(BASE, endpoint)
        self.put(BASE+0x1000, bytes(0x1c4))
        self.put(BASE+0x10dc, struct.pack('<I', 0))
        self.put(BASE+0x10e0, struct.pack('<3Q', 0, BASE+0x2000, BASE+0x3000))
        self.put(BASE+0x11b4, struct.pack('<I', 1))
        self.put(BASE+0x2070, struct.pack('<Q', BASE+0x1000))
        self.put(BASE+0x20a9, bytes(11))
        self.put(BASE+0x3070, struct.pack('<Q', BASE+0x1000))
        self.put(BASE+0x3a90, struct.pack('<Q', 0))

    def test_uninitialized(self):
        self.assertEqual(self.collect()['endpoints'], [])

    def test_manager_without_advertisements(self):
        self.ready()
        state = self.collect()
        self.assertEqual(state['manager'], hex(BASE+0x1000))
        self.assertEqual(state['firmware'], '0x0')
        self.assertEqual(state['advertisements'], [])

    def test_startup_fields_are_separate(self):
        self.ready()
        self.put(BASE+0x10c8, struct.pack('<I', 2))
        self.put(BASE+0x10dc, struct.pack('<I', 5))
        self.put(BASE+0x10d8, struct.pack('<I', 0x1234))
        self.put(BASE+0x1128, struct.pack('<Q', BASE+0x4000))
        self.put(BASE+0x1180, struct.pack('<2Q', BASE+0x5000, BASE+0x6000))
        self.put(BASE+0x11bc, struct.pack('<2I', 2, 3))
        self.put(BASE+0x20a9, struct.pack('<BQH', 1, 0x12345678006500ff, 2))
        state = self.collect()
        self.assertEqual((state['power_state'], state['send_gate_state']), (2, 5))
        self.assertEqual(state['resume_field'], 0x1234)
        self.assertEqual(state['shared_memory'], hex(BASE+0x4000))
        self.assertEqual(state['firmware_mapper'], hex(BASE+0x5000))
        self.assertEqual(state['auxiliary_mapper'], hex(BASE+0x6000))
        self.assertEqual((state['hibernate_state'], state['hibernate_boot_count']), (2, 3))
        self.assertEqual(state['rom_booter'], dict(waiting=True, phase=2,
                         last_message_hex='12345678006500ff'))

    def test_absent_control_objects(self):
        self.ready()
        self.put(BASE+0x10e8, bytes(16))
        state = self.collect()
        self.assertIsNone(state['rom_booter'])
        self.assertEqual(state['advertisements'], [])

    def test_effective_status_update_completion(self):
        self.ready()
        self.assertFalse(self.collect()['effective_status_properties_updated'])
        self.put(BASE+0x10cf,b'\x01')
        self.assertTrue(self.collect()['effective_status_properties_updated'])
        self.put(BASE+0x10cf,b'\x02')
        with self.assertRaisesRegex(ValueError,'effective-status update flag'):self.collect()

    def test_channel_addresses_are_physical_and_iova(self):
        self.ready()
        self.assertEqual(self.collect()['txm_channel'], dict(pa='0x0', iova='0x0'))
        self.put(BASE+0x1130, struct.pack('<2Q', 0x8ceb00000, 0x10000000000))
        self.assertEqual(self.collect()['txm_channel'],
                         dict(pa='0x8ceb00000', iova='0x10000000000'))

    def test_firmware_object_separates_iova_and_kernel_pointers(self):
        self.ready()
        self.put(BASE+0x10e0, struct.pack('<Q', BASE+0x7000))
        self.put(BASE+0x7088, struct.pack('<11Q', BASE+0x8000, BASE+0x9000,
                 0x180000000, 6144000, BASE+0xa000, BASE+0xb000, 0,
                 0, 0, 0, 0))
        self.put(BASE+0x70e0, b'\x01')
        obj = self.collect()['firmware_object']
        self.assertEqual(obj['iova'], '0x180000000')
        self.assertEqual(obj['bytes'], 6144000)
        self.assertEqual(obj['descriptor'], hex(BASE+0x8000))
        self.assertEqual(obj['mapper'], hex(BASE+0xb000))
        self.assertTrue(obj['preloaded'])
        self.assertEqual(obj['patch_descriptor'], '0x0')

    def test_firmware_object_refuses_corrupt_flag_and_pointer(self):
        self.ready()
        self.put(BASE+0x10e0, struct.pack('<Q', BASE+0x7000))
        self.put(BASE+0x7088, bytes(88))
        self.put(BASE+0x70e0, b'\x02')
        with self.assertRaisesRegex(ValueError, 'preload flag'): self.collect()
        self.put(BASE+0x70e0, b'\x01')
        self.put(BASE+0x7088, struct.pack('<Q', BASE+1))
        with self.assertRaisesRegex(ValueError, 'object pointer'): self.collect()

    def test_refuse_booter_corruption(self):
        for mutation in ('manager', 'waiting', 'mapping'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.ready()
                if mutation == 'manager': self.put(BASE+0x2070, struct.pack('<Q', BASE))
                elif mutation == 'waiting': self.put(BASE+0x20a9, b'\x02')
                else: self.put(BASE+0x1180, struct.pack('<Q', BASE+1))
                with self.assertRaises(ValueError): self.collect()

    def test_packed_record(self):
        self.ready()
        self.put(BASE+0x3a90, struct.pack('<Q', 1))
        self.put(BASE+0x30a9, struct.pack('<BIB4B', 1, 0x706e6f6e, 5, 1, 2, 3, 4))
        row, = self.collect()['advertisements']
        self.assertEqual(row['name_hex'], '706e6f6e')
        self.assertEqual(row['ool_size_fields'], [1, 2, 3, 4])

    def test_refuse_bad_identity_or_alias(self):
        for mutation in ('identity', 'alias', 'pointer'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.ready()
                if mutation == 'identity': self.put(BASE+0x60, b'\x01')
                elif mutation == 'alias': self.put(s['ENDPOINTS']+8, struct.pack('<Q', BASE))
                else: self.put(BASE+0x70, struct.pack('<Q', BASE+1))
                with self.assertRaises(ValueError): self.collect()

    def test_refuse_discovery_corruption(self):
        for mutation in ('count', 'manager', 'duplicate', 'flag'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.ready()
                if mutation == 'count': self.put(BASE+0x3a90, struct.pack('<Q', 254))
                elif mutation == 'manager': self.put(BASE+0x3070, struct.pack('<Q', BASE+0x2000))
                else:
                    self.put(BASE+0x3a90, struct.pack('<Q', 2))
                    record = struct.pack('<BIB4B', 2 if mutation == 'flag' else 1, 7, 5, 0, 0, 0, 0)
                    self.put(BASE+0x30a9, record*2)
                with self.assertRaises(ValueError): self.collect()

    def test_refuse_changed_native_witness(self):
        for address in self.words:
            self.words[address] ^= 1
            with self.assertRaises(ValueError): self.collect()
            self.words[address] ^= 1


if __name__ == '__main__':
    unittest.main()
