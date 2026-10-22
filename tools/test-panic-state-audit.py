#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest
A=runpy.run_path(str(Path(__file__).with_name('audit-panic-state.py')))
class PanicAudit(unittest.TestCase):
    def test_idle(self):
        state=struct.pack('<11Q',0,0x8000,0xff,0,0,*([0]*6))
        self.assertEqual(A['audit'](bytes(16384),state,0x1000,0x1000)['owner'],0x8000)
    def test_latched(self):
        state=struct.pack('<11Q',1,3,1,3,1,0,1,0,2,0,0)
        result=A['audit'](b'\1'+bytes(16383),state,0x1000,0x1000)
        self.assertEqual((result['triggered'],result['owner'],result['entries']),(1,3,3))
    def test_corruptions(self):
        state=[1,3,1,3,1,0,1,0,2,0,0];page=b'\1'+bytes(16383)
        for i,v in [(0,0),(0,2),(1,6),(1,0),(2,0xff),(3,2),(8,0)]:
            bad=state.copy();bad[i]=v
            with self.subTest(i=i,v=v),self.assertRaises(AssertionError):
                A['audit'](page,struct.pack('<11Q',*bad),0x1000,0x1000)
        for data,pointer in [(bytes(16384),0x1000),(page[:-1]+b'\1',0x1000),(page,0)]:
            with self.assertRaises(AssertionError):A['audit'](data,struct.pack('<11Q',*state),pointer,0x1000)
if __name__=='__main__':unittest.main()
