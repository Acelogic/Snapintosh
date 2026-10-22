#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the independent native permission survey's walkers and bounds."""
from pathlib import Path
import runpy
import struct
import unittest

survey = runpy.run_path(str(Path(__file__).with_name('capture-sprr-kernel.py')))


class WalkerTests(unittest.TestCase):
    def setUp(self):
        self.pages = {}
        for pa in (0x100000, 0x104000, 0x108000):
            self.pages[pa] = bytearray(16384)
        for pa in (0x200000, 0x201000, 0x202000, 0x203000):
            self.pages[pa] = bytearray(4096)
        self.put(0x100000, 0, 0x104003)
        self.put(0x104000, 0, 0x108003)
        self.put(0x108000, 1, 0x400003 | (1 << 54))  # selector2
        for pa in (0x200000, 0x201000, 0x202000):
            self.put(pa, 0, pa + 4096 + 3)
        for i in range(4):
            self.put(0x203000, i + 4, 0x400003 + i * 4096 | (1 << 54))

    def put(self, pa, index, value):
        struct.pack_into('<Q', self.pages[pa], index * 8, value)

    def read(self, pa, size):
        return bytes(self.pages[pa][:size])

    def walk(self, granule):
        root, low, high = ((0x100000, 0x100000, 0x10c000) if granule == 14 else
                           (0x200000, 0x200000, 0x204000))
        return survey['leaves'](self.read, root, granule, low, high)

    def test_four_shadow_pages_match_one_guest_page(self):
        guest, shadow = self.walk(14), self.walk(12)
        self.assertEqual((len(guest), len(shadow)), (1, 4))
        self.assertEqual(guest[0]['selector'], 2)
        for offset in (0, 1, 4095, 4096, 8191, 8192, 12288, 16383):
            va = 0xffff800000004000 + offset
            self.assertEqual(survey['resolve'](guest, va)['resolved_pa'], 0x400000 + offset)
            self.assertEqual(survey['resolve'](shadow, va)['resolved_pa'], 0x400000 + offset)
        rights = survey['ordinary_arm_permissions'](shadow[0]['descriptor'])
        self.assertTrue(rights['el1_write'])
        self.assertTrue(rights['el1_execute'])
        self.assertFalse(rights['el0_write'])

    def test_valid_block_and_misaligned_block(self):
        self.put(0x104000, 0, 0x2000001 | (1 << 54))
        row, = self.walk(14)
        self.assertEqual((row['size'], row['pa']), (1 << 25, 1 << 25))
        self.put(0x104000, 0, 0x2001001)
        with self.assertRaisesRegex(ValueError, 'misaligned leaf'):
            self.walk(14)

    def test_out_of_bounds_and_repeated_tables(self):
        self.put(0x100000, 0, 0x300003)
        with self.assertRaisesRegex(ValueError, 'outside audited'):
            self.walk(14)
        self.put(0x100000, 0, 0x100003)
        with self.assertRaisesRegex(ValueError, 'repeated kernel table'):
            self.walk(14)

    def test_invalid_page_short_read_and_root_width(self):
        self.put(0x108000, 1, 0x400001)
        with self.assertRaisesRegex(ValueError, 'invalid leaf type'):
            self.walk(14)
        self.pages[0x108000] = bytearray(16)
        with self.assertRaisesRegex(ValueError, 'short table read'):
            self.walk(14)
        self.put(0x200000, 256, 0x201003)
        with self.assertRaisesRegex(ValueError, 'outside 47-bit'):
            self.walk(12)

    def test_missing_or_overlapping_mapping(self):
        rows = self.walk(14)
        for candidate, va in ((rows, 0), (rows * 2, 0x4000)):
            with self.assertRaisesRegex(ValueError, 'one valid mapping'):
                survey['resolve'](candidate, va)


if __name__ == '__main__':
    unittest.main()
