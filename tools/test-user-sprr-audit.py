#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

A = runpy.run_path(str(Path(__file__).with_name('audit-user-sprr.py')))


class UserSprrAudit(unittest.TestCase):
    def encode(self, row):
        return struct.pack('<48Q', *([0] * 8 + row + [0] * 32))

    def test_fixed_permission_read(self):
        row = [1, 0x1006a5aec, 0xd53ef1a9, 0x2010002030100000,
               0x60000000, 0x16f8bb5e0, 0x94213c000, 0]
        for rt in range(32):
            for umprr in (0, 0x800, 0x40000, 0x40800):
                good = row.copy()
                good[2] = 0xd53ef1a0 | rt
                good[7] = umprr
                self.assertEqual(A['audit'](self.encode(good))['reads'], 1)
        for i, value in [(0, 0), (1, 0), (1, 0x1003), (1, 1 << 47),
                         (2, 0xd51ef1a9), (2, 0xd53ef1c9), (3, 0),
                         (4, 5), (4, 1 << 20), (4, 1 << 32),
                         (5, 0), (5, 1 << 47), (6, 0), (6, 0x94213c001),
                         (7, 0x40001)]:
            bad = row.copy()
            bad[i] = value
            with self.subTest(i=i, value=value), self.assertRaises(AssertionError):
                A['audit'](self.encode(bad))
        row[3] |= 1 << 36
        with self.assertRaises(AssertionError):
            A['audit'](self.encode(row))
        row[7] = 0x40000
        self.assertEqual(A['audit'](self.encode(row))['reads'], 1)

    def test_no_read(self):
        self.assertEqual(A['audit'](bytes(384))['reads'], 0)
        with self.assertRaises(AssertionError):
            A['audit'](bytes(376))


if __name__ == '__main__':
    unittest.main()
