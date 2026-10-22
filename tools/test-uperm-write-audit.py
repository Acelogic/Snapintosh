#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

A = runpy.run_path(str(Path(__file__).with_name('audit-uperm-write.py')))


class UpermWriteAudit(unittest.TestCase):
    def encode(self, row):
        return struct.pack('<84Q', *([0] * 14 + row + [0] * 56))

    def test_transaction(self):
        row = [1, 1, 0x102969bbc, 0xd51ef1a0, 0x2010002030100000,
               0x2010003030100000, 0x60000000, 0x16d6b75e0,
               0x942554000, 0xbba94000, 8, 120, 0x8080, 0x40000]
        self.assertEqual(A['audit'](self.encode(row))['changes'], 1)
        for i, value in [(0, 0), (1, 2), (2, 0), (2, 0x123), (3, 0xd53ef1a0),
                         (3, 0xd51ef1bf), (4, 0), (5, 0), (6, 9), (6, 1 << 20),
                         (8, 0), (8, 0x942554001), (9, 0), (10, 0), (10, 8193),
                         (11, 0), (11, 8192), (12, 0), (12, 0x200), (13, 0)]:
            bad = row.copy()
            bad[i] = value
            with self.subTest(i=i, value=value), self.assertRaises(AssertionError):
                A['audit'](self.encode(bad))
        row[2], row[6] = 0xfffffe000ba693c4, 0x604003c5
        row[4], row[5] = row[5], row[4]
        self.assertEqual(A['audit'](self.encode(row))['writes'], 1)

    def test_kernel_stack_modes(self):
        row = [1, 1, 0xfffffe000ba693c4, 0xd51ef1a8,
               0x2010003030100000, 0x2010002030100000,
               0x604003c4, 0xfffffe74b1b977b0,
               0x942554000, 0xbba94000, 8, 120, 0x8080, 0x40000]
        for mode in range(32):
            row[6] = 0x604003c0 | mode
            if mode in (4, 5):
                self.assertEqual(A['audit'](self.encode(row))['writes'], 1)
            else:
                with self.subTest(mode=mode), self.assertRaises(AssertionError):
                    A['audit'](self.encode(row))
        row[6] = 0x604003c4
        row[2] = 0x10440dbbc
        with self.assertRaises(AssertionError):
            A['audit'](self.encode(row))

    def test_no_write(self):
        self.assertEqual(A['audit'](bytes(672))['writes'], 0)


if __name__ == '__main__':
    unittest.main()
