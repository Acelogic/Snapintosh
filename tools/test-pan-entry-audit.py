#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

A=runpy.run_path(str(Path(__file__).with_name('audit-pan-entry.py')))

class PanEntryAudit(unittest.TestCase):
    def encode(self,active):
        idle=[1<<20,0x30501805,0,0,0,0,0,0]
        return struct.pack('<48Q',*(idle*2+active+idle*3))

    def test_hardware_transition(self):
        row=[1<<20,0x30501805,3,3,0x400,0,0x4003c5,0x30501805]
        result=A['audit'](self.encode(row))
        self.assertEqual(result['protected_vectors'],3)
        self.assertEqual(result['rows'][2]['saved_spsr'],0)

    def test_reject_broken_entry(self):
        row=[1<<20,0x30501805,3,3,0x400,0,0x4003c5,0x30501805]
        for i,value in [(0,0),(1,row[1]|1<<23),(2,4),(3,4),
                        (4,0x200),(5,5),(6,0x3c5),(6,0x4003c0),
                        (7,row[7]|1<<23)]:
            bad=row.copy();bad[i]=value
            with self.subTest(i=i,value=value),self.assertRaises(AssertionError):
                A['audit'](self.encode(bad))

    def test_native_cache_zero_keeps_pan(self):
        row=[1<<20,0x30505985,3,3,0x400,0,0x4003c5,0x30505985]
        result=A['audit'](struct.pack('<48Q',*(row*6)))
        self.assertTrue(result['user_cache_zero_enabled'])
        self.assertEqual(result['protected_vectors'],18)
        for index in (1,7):
            bad=row.copy();bad[index]^=1<<14
            with self.subTest(index=index),self.assertRaises(AssertionError):
                A['audit'](struct.pack('<48Q',*(bad*6)))

if __name__=='__main__':unittest.main()
