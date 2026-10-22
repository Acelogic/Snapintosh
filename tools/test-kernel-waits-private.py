#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""capture-kernel-waits.py's private copy inventory: six CPU copies per source,
or two native permission variants with the other four slots zero. Every copy
must be owned by its cache slot, be no live canonical table and alias nothing;
an unused slot that is not zero, or a zero where a copy belongs, is refused."""
from pathlib import Path
import runpy
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
module = runpy.run_path(str(ROOT / 'tools/capture-kernel-waits.py'), run_name='kernel_waits_under_test')
private_copies = module['private_copies']
BASE = 0x80000000


def owned_index(pa):
    if pa & 4095 or not BASE <= pa < BASE + 64 * 4096:
        raise ValueError('owned table outside monitor arena')
    return (pa - BASE) // 4096


def page(i):
    return BASE + 4096 * i


class PrivateCopies(unittest.TestCase):
    def setUp(self):
        # Slot 3 owns pages 0..39; slot 4 owns 40..63; pages 0..3 are live canonical.
        self.owners = bytes([3] * 40 + [4] * 24)
        self.live = {0, 1, 2, 3}

    def records(self, rows):
        return b''.join(struct.pack('<8Q', *row) for row in rows)

    def check(self, rows, columns, owner=3, pages=None):
        pages = set() if pages is None else pages
        private_copies(self.records(rows), owner, self.owners, owned_index, self.live, pages, columns)
        return pages

    def test_six_cpu_copies(self):
        rows = [(page(0), *map(page, range(4, 10)), 0), (page(1), *map(page, range(10, 16)), 1)]
        self.assertEqual(self.check(rows, 6), set(range(4, 16)))

    def test_two_native_variants(self):
        rows = [(page(0), page(4), page(5), 0, 0, 0, 0, 0), (page(1), page(6), page(7), 0, 0, 0, 0, 3)]
        self.assertEqual(self.check(rows, 2), {4, 5, 6, 7})
        # The same records read as six CPU copies hit the zero slots.
        with self.assertRaisesRegex(ValueError, 'outside monitor arena'):
            self.check(rows, 6)

    def test_refusals(self):
        good = (page(0), page(4), page(5), 0, 0, 0, 0, 0)
        bad = {
            'unused slot': (page(0), page(4), page(5), page(6), 0, 0, 0, 0),
            'missing variant': (page(0), page(4), 0, 0, 0, 0, 0, 0),
            'other slot copy': (page(0), page(4), page(40), 0, 0, 0, 0, 0),
            'canonical copy': (page(0), page(4), page(2), 0, 0, 0, 0, 0),
            'self alias': (page(0), page(4), page(4), 0, 0, 0, 0, 0),
            'foreign source': (page(41), page(4), page(5), 0, 0, 0, 0, 0),
            'bad level': (page(0), page(4), page(5), 0, 0, 0, 0, 4),
            'misaligned copy': (page(0), page(4), page(5) + 8, 0, 0, 0, 0, 0),
        }
        for name, row in bad.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check([row], 2)
        # Aliasing across sources and against pages already counted.
        with self.assertRaises(ValueError):
            self.check([good, (page(1), page(5), page(6), 0, 0, 0, 0, 1)], 2)
        with self.assertRaises(ValueError):
            self.check([good], 2, pages={5})
        with self.assertRaises(ValueError):
            self.check([good], 3)


if __name__ == '__main__':
    unittest.main()
