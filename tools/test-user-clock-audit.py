#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

A=runpy.run_path(str(Path(__file__).with_name('audit-user-clock.py')))

class UserClockAudit(unittest.TestCase):
    def encode(self,row):return struct.pack('<66Q',*([0]*22+row+[0]*33))
    def test_scaled_sample(self):
        row=[1,0x102d345cc,0xd53cfac8,1250001,0x60000000,0x16d5a7690,
             0x94270c000,0x4f,1000001,19200000,24000000]
        self.assertEqual(A['audit'](self.encode(row))['reads'],1)
        for i,value in [(0,0),(1,0),(1,0x1003),(2,0xd51cfac8),(3,1250000),
                        (4,5),(4,1<<20),(5,1<<47),(6,0x94270c001),(7,0x4d),
                        (8,1000000),(9,0),(10,19200000)]:
            bad=row.copy();bad[i]=value
            with self.subTest(i=i,value=value),self.assertRaises(AssertionError):
                A['audit'](self.encode(bad))
    def test_no_read(self):self.assertEqual(A['audit'](bytes(528))['reads'],0)

if __name__=='__main__':unittest.main()
