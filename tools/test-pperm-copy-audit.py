#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

A = runpy.run_path(str(Path(__file__).with_name('audit-pperm-copy.py')))
PP = 0x2020a52a302abae6


class CopyAudit(unittest.TestCase):
    def encode(self, row):
        return struct.pack('<90Q', *([0] * 30 + row + [0] * 45))

    def test_grant_and_restore(self):
        row = [1, 1, 0, PP, PP | (1 << 36), 0xfffffe000ba7ce0c,
               0x944bb4000, 0xbba93000, 9, 108, 0xa080,
               0xba4ce000, 5065, 2525376, 0x80d]
        current = [PP] * 6
        current[2] |= 1 << 36
        self.assertEqual(A['audit'](self.encode(row), current)['grants'], 1)
        for i, value in [(0, 0), (1, 0), (2, 2), (3, 0), (4, PP), (5, 0x1234),
                         (6, 0), (7, 0), (8, 0), (8, 8193), (9, 9000), (10, 0x200),
                         (11, 1), (12, 0), (13, 1 << 36), (14, 0xa0d)]:
            bad = row.copy()
            bad[i] = value
            with self.subTest(i=i, value=value), self.assertRaises(AssertionError):
                A['audit'](self.encode(bad), current)
        with self.assertRaises(AssertionError):
            A['audit'](self.encode(row), [PP] * 6)
        row[0], row[2], row[3], row[4], row[5] = 2, 1, PP | (1 << 36), PP, 0xfffffe000ba7ce58
        self.assertEqual(A['audit'](self.encode(row), [PP] * 6)['restores'], 1)

    def test_no_transaction(self):
        self.assertEqual(A['audit'](bytes(720), [PP] * 6)['transactions'], 0)
        with self.assertRaises(AssertionError):
            A['audit'](bytes(720), [PP | (1 << 36)] * 6)


if __name__ == '__main__':
    unittest.main()
