#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest
A=runpy.run_path(str(Path(__file__).with_name('audit-user-map-conflict.py')))
class ConflictAudit(unittest.TestCase):
    def encode(self,row):return struct.pack('<48Q',*(row+[0]*40))
    def test_reply(self):
        row=[1,0x942100000,0x10052c000,0x60000946b40e43,0,0x60000946b48ec3,0xfffffe0001234000,6]
        self.assertEqual(A['audit'](self.encode(row))['count'],1)
        for i,value in [(0,0),(1,0),(2,0x10052c001),(3,row[3]&~1),(4,2),
                        (5,row[3]),(5,0),(6,0),(7,1)]:
            bad=row.copy();bad[i]=value
            with self.subTest(i=i,value=value),self.assertRaises(AssertionError):A['audit'](self.encode(bad))
    def test_suppressed_output(self):
        row=[1,0x942100000,0x10052c000,0x60000946b40e43,1,0,0,6]
        self.assertEqual(A['audit'](self.encode(row))['count'],1)
if __name__=='__main__':unittest.main()
