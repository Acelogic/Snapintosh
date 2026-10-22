#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Service-profile capture under SNAP_NATIVE_TABLES: the per-CPU private user
view machinery must be idle (exactly zero), the table memo still notes every
store without lookups, and native user views carry two variant copies per
source while the kernel view keeps six."""
from pathlib import Path
import runpy
import struct
import unittest

module = runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))
FIELDS = module['TREE_MEMO_FIELDS']


class NativeIdle(unittest.TestCase):
    def test_zero_is_idle(self):
        row = module['native_idle'](bytes(48), 'user publication')
        self.assertTrue(row['native_tables'])
        self.assertEqual(row['raw_hex'], '00' * 48)

    def test_any_advance_is_refused(self):
        for n in (0, 17, 47):
            raw = bytearray(48)
            raw[n] = 1
            with self.subTest(byte=n), self.assertRaisesRegex(ValueError, 'user publication: private'):
                module['native_idle'](bytes(raw), 'user publication')


class NativeTreeMemo(unittest.TestCase):
    VALID = dict.fromkeys(FIELDS, 0) | dict(notes=123456, allocations=789, walk_hits=30, walk_misses=10)

    def pack(self, **change):
        row = dict(self.VALID, **change)
        return struct.pack(f'<{len(FIELDS)}Q', *(row[f] for f in FIELDS))

    def test_notes_without_lookups(self):
        row = module['decode_native_tree_memo'](self.pack())
        self.assertTrue(row['native_tables'])
        self.assertAlmostEqual(row['walk_hit_fraction'], 0.75)
        self.assertIsNone(module['decode_native_tree_memo'](
            self.pack(walk_hits=0, walk_misses=0))['walk_hit_fraction'])

    def test_lookups_or_idle_tracking_refused(self):
        for field in ('calls', 'samples', 'checked', 'mismatches', 'scan_hits', 'scan_misses',
                      'copy_hits', 'copy_misses', 'forced', 'errors'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module['decode_native_tree_memo'](self.pack(**{field: 1}))
        for field in ('notes', 'allocations'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module['decode_native_tree_memo'](self.pack(**{field: 0}))
        with self.assertRaises(ValueError):
            module['decode_native_tree_memo'](self.pack()[:-8])


class NativePrivatePages(unittest.TestCase):
    """decode_private_pages with a six-copy kernel view and a two-variant user view."""
    def setUp(self):
        self.first = 0x40000000
        self.allocated = self.first + 16 * 4096
        self.owners = bytes([0] * 8 + [2] * 8)
        self.views = [dict(owner=0, root=self.first, sources=[self.first],
                           copies=[self.first + i * 4096 for i in range(1, 7)]),
                      dict(owner=2, root=self.first + 8 * 4096, columns=2,
                           sources=[self.first + 8 * 4096, self.first + 11 * 4096],
                           copies=[self.first + i * 4096 for i in (9, 10, 12, 13)])]
        self.canonical = [self.first, self.first + 8 * 4096, self.first + 11 * 4096]
        bits = sum(1 << i for i in [*range(1, 7), 9, 10, 12, 13])
        self.raw = struct.pack('<6Q', 32, 24, 16, 1000, 900, 0) + bits.to_bytes(4096, 'little')

    def check(self, views):
        return module['decode_private_pages'](self.raw, self.first, self.allocated, self.owners,
                                              views, self.canonical)

    def test_two_variant_copies(self):
        row = self.check(self.views)
        self.assertEqual((row['private_pages'], row['canonical_pages']), (10, 3))

    def test_copy_count_follows_columns(self):
        six = [dict(self.views[0]), dict(self.views[1], columns=6)]
        with self.assertRaises(ValueError):
            self.check(six)
        short = [dict(self.views[0]), dict(self.views[1], copies=self.views[1]['copies'][:3])]
        with self.assertRaises(ValueError):
            self.check(short)


if __name__ == '__main__':
    unittest.main()
