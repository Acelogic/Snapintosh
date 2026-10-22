#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Task/root binding and bounded native user-page reader tests."""
from pathlib import Path
import runpy
import struct
import unittest
import copy

API = runpy.run_path(str(Path(__file__).with_name('process-user-memory.py')))


class ProcessMemoryTests(unittest.TestCase):
    def setUp(self):
        self.task = 0xfffffe0010000000
        self.map = self.task+0x4000
        self.pmap = self.map+0x4000
        self.root, self.l2, self.l3 = 0x10000, 0x14000, 0x18000
        self.mem = {}
        self.reads = []
        self.instructions = dict(API['WITNESSES'])
        self.q(self.task+0x28, self.map & 0xffffffffffff)
        self.q(self.map+0x58, self.pmap & 0xffffffffffff)
        self.q(self.pmap+8, self.root)
        self.q(self.root, self.l2 | 3)
        self.q(self.l2, self.l3 | 3)
        self.q(self.l3+8, 0x20000 | 3)
        self.q(self.l3+16, 0x30000 | 3)
        self.put(0x20000, b'A'*0x4000)
        self.put(0x30000, b'B'*0x4000)
        self.rows = [dict(root=hex(self.root), format=0, flags='0x2', mappings_equal=True)]

    def put(self, address, raw):
        self.mem.update((address+i, value) for i, value in enumerate(raw))

    def q(self, address, value):
        self.put(address, struct.pack('<Q', value))

    def read(self, address, size):
        self.reads.append((address, size))
        return bytes(self.mem[address+i] for i in range(size))

    def bind(self, **kwargs):
        return API['make_reader'](self.read, self.read, self.instructions.__getitem__,
                                  self.rows, 0x10000, 0x40000, **kwargs)(self.task)

    def ownership(self):
        self.rows = []
        metadata = bytearray(16)
        metadata[2], metadata[4], metadata[8], metadata[10] = 18, 1, 255, 11
        self.put(0x3c000, metadata)
        return dict(runtime_stop_qualified=True, user_mapping_qualified=True,
                    ownership=dict(mismatches=[], audited_tables=3),
                    geometry=dict(ram_low=0x10000, ram_high=0x40000,
                                  alloc_low=0x10000, alloc_high=0x38000,
                                  frame_low=0x10000, frame_high=0x40000,
                                  frame_map=0x3c000, user_roots=[self.root], shared_roots=[]))

    def test_process_binding_and_noncontiguous_page_crossing(self):
        read, meta = self.bind()
        self.assertEqual(meta['root'], hex(self.root))
        self.assertEqual(read(0x7ffc, 8), b'AAAABBBB')

    def test_unadmitted_and_changed_root_refused(self):
        for root in [0, self.root+0x4000, self.root+8]:
            self.q(self.pmap+8, root)
            with self.assertRaisesRegex(ValueError, 'audited'):
                self.bind()

    def test_audited_permission_changes_keep_noncontiguous_16k_geometry(self):
        for flags in ('0x2', '0xa', '0xb'):
            with self.subTest(flags=flags):
                self.rows[0]['flags'] = flags
                read, meta = self.bind()
                self.assertEqual(meta['flags'], flags)
                self.assertEqual(read(0x7ffc, 8), b'AAAABBBB')

    def test_umprr11_root_to_native_initial_arguments_across_pages(self):
        self.initial_arguments_case()

    def test_ownership_root_to_native_initial_arguments_across_pages(self):
        self.initial_arguments_case(ownership_audit=self.ownership())

    def initial_arguments_case(self, **kwargs):
        initial = runpy.run_path(str(Path(__file__).with_name('process-initial-arguments.py')))
        self.instructions.update(initial['WITNESSES'])
        for offset in range(0, len(initial['PREFIX']), 4):
            self.instructions[0xfffffe00070be0b2+offset] = int.from_bytes(initial['PREFIX'][offset:offset+4], 'little')
        proc, pid, begin = self.task+0xc000, 100, 0x7ff0
        block = initial['PREFIX']+b'/usr/libexec/xpcproxy\0\0xpcproxy\0org.snapintosh.metal-probe\0'
        top = (begin+len(block)+128+15)&~15
        self.put(proc+0x60, struct.pack('<I', pid))
        self.put(proc+initial['FIELDS'], struct.pack('<IiQ', top-begin, 2, top))
        self.put(0x23ff0, block[:16])
        self.put(0x30000, block[16:])
        if self.rows:
            self.rows[0]['flags'] = '0xb'
        read, meta = self.bind(**kwargs)
        result = initial['make_reader'](self.read, self.instructions.__getitem__)(proc, pid, read)
        self.assertEqual(meta['flags'], '0xb')
        self.assertEqual(result['argv'], ['xpcproxy', 'org.snapintosh.metal-probe'])
        self.assertEqual(result['executable'], '/usr/libexec/xpcproxy')
        for address, size in self.reads:
            if 0x20000 <= address < 0x38000:
                self.assertTrue(0x23ff0 <= address < address+size <= 0x24000 or
                                0x30000 <= address < address+size <= 0x30000+len(block)-16)

    def test_ownership_admission_records_provenance_and_rejects_changes(self):
        audit = self.ownership()
        read, meta = self.bind(ownership_audit=audit)
        self.assertEqual(meta['admission'], 'ownership-audit')
        self.assertEqual(meta['root_metadata']['raw'], self.read(0x3c000, 16).hex())
        self.assertNotIn('mappings_equal', meta)
        self.assertEqual(read(0x7ffc, 8), b'AAAABBBB')
        self.mem[0x3c004] = 2
        with self.assertRaisesRegex(ValueError, 'changed'):
            read(0x7ffc, 8)
        self.mem[0x3c004] = 1
        self.q(self.pmap+8, self.root+0x4000)
        with self.assertRaisesRegex(ValueError, 'changed'):
            read(0x7ffc, 8)

    def test_ownership_audit_failures_before_physical_reads(self):
        audit = self.ownership()
        cases = [(['runtime_stop_qualified'], False), (['user_mapping_qualified'], False),
                 (['ownership', 'mismatches'], ['bad']), (['ownership', 'audited_tables'], 0),
                 (['geometry', 'ram_high'], 0x50000),
                 (['geometry', 'user_roots'], [self.root, self.root]),
                 (['geometry', 'frame_map'], 0x40000)]
        for keys, value in cases:
            with self.subTest(keys=keys):
                bad = copy.deepcopy(audit)
                target = bad
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = value
                self.reads.clear()
                with self.assertRaises(ValueError): self.bind(ownership_audit=bad)
                self.assertEqual(self.reads, [])
        audit['geometry']['user_roots'] = []
        with self.assertRaisesRegex(ValueError, 'audited'):
            self.bind(ownership_audit=audit)
        self.assertFalse(any(a < self.task for a, _ in self.reads))

    def test_ownership_native_metadata_refusals(self):
        audit = self.ownership()
        original = self.read(0x3c000, 16)
        for offset, value in [(0,1), (2,19), (4,0), (8,0), (9,1),
                              (10,3), (10,6), (12,1), (13,1)]:
            with self.subTest(offset=offset,value=value):
                self.put(0x3c000, original)
                self.mem[0x3c000+offset] = value
                with self.assertRaisesRegex(ValueError, 'metadata|binding'):
                    self.bind(ownership_audit=audit)
        self.put(0x3c000, original)
        self.rows = [dict(root=hex(self.root), format=0, flags='0xb', mappings_equal=False)]
        with self.assertRaisesRegex(ValueError, 'audited'):
            self.bind(ownership_audit=audit)

    def test_ownership_shared_binding_and_short_metadata(self):
        audit = self.ownership()
        self.mem[0x3c008] = 7
        shared = bytearray(16)
        shared[2], shared[4], shared[8] = 19, 1, 7
        self.put(0x3c030, shared)
        audit['geometry']['shared_roots'] = [0x1c000]
        read, meta = self.bind(ownership_audit=audit)
        self.assertEqual(meta['shared_metadata']['root'], '0x1c000')
        self.assertEqual(read(0x7ffc, 8), b'AAAABBBB')
        self.mem[0x3c038] = 8
        with self.assertRaisesRegex(ValueError, 'changed'):
            read(0x7ffc, 8)
        def short(address, size): return self.read(address, size)[:-1]
        with self.assertRaisesRegex(ValueError, 'short'):
            API['make_reader'](self.read, short, self.instructions.__getitem__, [],
                               0x10000, 0x40000, ownership_audit=audit)(self.task)

    def test_wrong_instruction_before_any_memory_read(self):
        self.instructions[0xfffffe000ba69498] ^= 1
        with self.assertRaisesRegex(ValueError, 'witness'):
            self.bind()
        self.assertEqual(self.reads, [])

    def test_non_user_and_unmapped_addresses(self):
        read, _ = self.bind()
        for address, size in [(0, 16), (1 << 47, 16), (0x4000, 0x4001)]:
            with self.assertRaisesRegex(ValueError, 'address or size'):
                read(address, size)
        self.q(self.l3+8, 0)
        with self.assertRaisesRegex(ValueError, 'absent'):
            read(0x4000, 16)

    def test_physical_escape_and_budget(self):
        read, _ = self.bind()
        self.q(self.l3+8, 0x40000 | 3)
        with self.assertRaisesRegex(ValueError, 'outside guest RAM'):
            read(0x4000, 16)
        self.q(self.l3+8, 0x20000 | 3)
        read, _ = self.bind(max_bytes=4096)
        with self.assertRaisesRegex(ValueError, 'budget'):
            read(0x4000, 4096)

    def test_root_format_and_audit_failure(self):
        for key, value in [('format', 1), ('flags', '0x0'), ('flags', '0x6'),
                           ('flags', '0x12'), ('flags', '0x22'), ('flags', '0x3'),
                           ('mappings_equal', False)]:
            previous = self.rows[0][key]
            self.rows[0][key] = value
            with self.assertRaisesRegex(ValueError, 'audited'):
                self.bind()
            self.rows[0][key] = previous


if __name__ == '__main__':
    unittest.main()
