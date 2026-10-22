#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reader-only IORegistry graph, type and resource-bound tests."""
from pathlib import Path
import runpy
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('ioreg-state.py')))


class RegistryReaderTests(unittest.TestCase):
    def setUp(self):
        self.mem = {}
        self.next = 0xfffffe1000000000
        self.reads = []
        self.instructions = dict(API['WITNESSES'])
        self.vtables = {0xfffffe0007100010+i*0x100: name for i, name in enumerate(
            ['OSDictionary', 'OSArray', 'OSSymbol', 'IORegistryEntry',
             'IOBootFramebuffer', 'AppleARMIODevice', 'IOPMrootDomain'])}
        self.byname = {n: a for a, n in self.vtables.items()}
        self.name_key = self.string('IOName')
        self.plane_name = self.string('IOServiceName')
        self.child_key = self.string('IOServiceChildLinks')
        self.driver = self.obj('IOBootFramebuffer', 0x50)
        self.put(self.driver+24, struct.pack('<Q', self.dictionary([(self.name_key, self.string('Boot display'))])))
        self.put(self.driver+32, struct.pack('<Q', self.dictionary([])))
        self.put(self.driver+0x48, struct.pack('<I', 6))
        children = self.obj('OSArray', 40)
        slots = self.blob(struct.pack('<Q', self.driver))
        self.put(children+20, struct.pack('<II', 1, 1))
        self.put(children+32, struct.pack('<Q', slots))
        self.root = self.obj('IORegistryEntry', 0x50)
        self.put(self.root+24, struct.pack('<Q', self.dictionary([
            (self.name_key, self.string('Root')), (self.child_key, children)])))
        plane = self.blob(bytes(48))
        self.put(plane+32, struct.pack('<QQ', self.child_key, self.plane_name))
        for address, value in [(API['ROOT_SLOT'], self.root), (API['PLANE_SLOT'], plane),
                               (API['NAME_KEY_SLOT'], self.name_key)]:
            self.put(address, struct.pack('<Q', value))

    def put(self, address, data):
        self.mem.update((address+i, byte) for i, byte in enumerate(data))

    def blob(self, data):
        address = self.next
        self.next += (len(data)+0xff) & ~0xff
        self.put(address, data)
        return address

    def obj(self, name, size):
        address = self.blob(bytes(size))
        self.put(address, struct.pack('<Q', self.byname[name]))
        return address

    def string(self, value):
        raw = value.encode()+b'\0'
        address = self.obj('OSSymbol', 24)
        self.put(address+12, struct.pack('<I', len(raw)<<14))
        self.put(address+16, struct.pack('<Q', self.blob(raw)))
        return address

    def dictionary(self, entries):
        address = self.obj('OSDictionary', 40)
        self.put(address+20, struct.pack('<II', len(entries), len(entries)))
        if entries:
            slots = self.blob(b''.join(struct.pack('<QQ', *pair) for pair in entries))
            self.put(address+32, struct.pack('<Q', slots))
        return address

    def read(self, address, size):
        self.reads.append((address, size))
        self.assertLessEqual(size, 0x4000)
        return bytes(self.mem[address+i] for i in range(size))

    def collect(self, **kwargs):
        return API['collect'](self.read, self.instructions.__getitem__, self.vtables, **kwargs)

    def test_reaches_driver_through_actual_child_edge(self):
        result = self.collect()
        self.assertTrue(result['complete'])
        self.assertEqual(len(result['entries']), 2)
        self.assertEqual(result['edges'], [(hex(self.root), hex(self.driver))])
        driver, = result['display_entries']
        self.assertEqual(driver['class_name'], 'IOBootFramebuffer')
        self.assertEqual(driver['name'], 'Boot display')
        self.assertTrue(driver['registered'] and driver['matched'])

    def test_wrong_instruction_refuses_all_guest_reads(self):
        self.instructions[next(iter(self.instructions))] ^= 1
        with self.assertRaisesRegex(ValueError, 'witness'):
            self.collect()
        self.assertEqual(self.reads, [])

    def test_provider_matching_state_is_not_a_driver_registration(self):
        self.put(self.driver, struct.pack('<Q', self.byname['AppleARMIODevice']))
        self.put(self.driver+24, struct.pack('<Q', self.dictionary([
            (self.name_key, self.string('snapintosh-boot-display'))])))
        for state1, active in [(0, False), (0x80000000, True),
                               (0x20000, True), (0x40000, False)]:
            self.put(self.driver+0x4c, struct.pack('<I', state1))
            result = self.collect()
            self.assertEqual(result['display_entries'], [])
            provider, = result['display_providers']
            self.assertEqual(provider['state1'], hex(state1))
            self.assertEqual(provider['matching_pending_or_running'], active)

    def test_matching_mask_witness_refuses_all_guest_reads(self):
        self.instructions[0xfffffe000c0dcd08] ^= 1
        with self.assertRaisesRegex(ValueError, 'witness'):
            self.collect()
        self.assertEqual(self.reads, [])

    def test_startup_busy_count_excludes_matching_state_bits(self):
        self.put(self.driver, struct.pack('<Q', self.byname['IOPMrootDomain']))
        self.put(self.driver+0x4c, struct.pack('<I', 0x80020005))
        result = self.collect()
        self.assertEqual(result['display_entries'], [])
        service, = result['startup_entries']
        self.assertEqual(service['busy_count'], 5)
        self.assertTrue(service['matching_pending_or_running'])

    def test_node_bound_is_not_reported_as_absence(self):
        with self.assertRaisesRegex(ValueError, 'graph incomplete'):
            self.collect(max_nodes=1)

    def test_wrong_dictionary_type(self):
        self.put(self.root+24, struct.pack('<Q', self.driver))
        with self.assertRaisesRegex(ValueError, 'not an OSDictionary'):
            self.collect()

    def test_name_string_bound(self):
        self.put(self.child_key+12, struct.pack('<I', 2000<<14))
        with self.assertRaisesRegex(ValueError, 'string exceeds'):
            self.collect()

    def test_exact_simple_vtable_symbols(self):
        names = API['vtable_names']([(0x1000, '__ZTV17IOBootFramebuffer'),
                                     (0x2000, '__ZTV18IOBootFramebuffer'),
                                     (0x3000, '__ZTVN17IOBootFramebuffer9MetaClassE')])
        self.assertEqual(names, {0x1010: 'IOBootFramebuffer'})


if __name__ == '__main__':
    unittest.main()
