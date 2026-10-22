#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
import struct
import unittest
from pathlib import Path

decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_root_publish']

class Capture(unittest.TestCase):
    def setUp(self):
        self.first=0xae1400000
        self.args=(self.first,self.first+200*4096,100,self.first+10*4096,self.first+20*4096)
        self.words=[1300,1800,100,100,15000,1100,13900,0,self.args[3],self.args[4]]
        self.bits=1<<199
    def raw(self):
        return struct.pack('<10Q',*self.words)+self.bits.to_bytes(4096,'little')
    def test_valid_pending(self):
        row=decode(self.raw(),*self.args)
        self.assertEqual((row['pending_pages'],row['always_pages']),(1,10))
        self.assertGreater(row['skipped_fraction'],0.9)
    def test_each_counter_and_range(self):
        bad={0:99,1:1299,2:101,3:99,4:14999,5:999,6:0,7:1,8:self.first,9:self.first+21*4096}
        for i,value in bad.items():
            with self.subTest(i=i):
                old=self.words[i];self.words[i]=value
                with self.assertRaises(ValueError):decode(self.raw(),*self.args)
                self.words[i]=old
    def test_range_corruption(self):
        for args in [(self.first+1,*self.args[1:]),
                     (self.first,self.first,*self.args[2:]),
                     (*self.args[:3],self.first-4096,self.args[4]),
                     (*self.args[:4],self.first+201*4096),
                     (*self.args[:4],self.args[3])]:
            with self.assertRaises(ValueError):decode(self.raw(),*args)
        with self.assertRaises(ValueError):decode(self.raw()[:-1],*self.args)
        self.bits=1<<200
        with self.assertRaises(ValueError):decode(self.raw(),*self.args)
    def test_volume_bounds(self):
        for notes,considered,published,skipped in [(1300,21000,1100,19900),
                                                   (1100,15000,1900,13100)]:
            self.words[0]=notes;self.words[4:7]=[considered,published,skipped]
            with self.assertRaises(ValueError):decode(self.raw(),*self.args)
    def test_installed_arena_high_page(self):
        # Publication of the last240MiB page must survive decoding; a bit
        # beyond the actual allocation must still fail before any claim.
        args=(self.first,self.first+61440*4096,*self.args[2:])
        raw=struct.pack('<10Q',*self.words)+(1<<61439).to_bytes(7680,'little')
        self.assertEqual(decode(raw,*args)['pending_pages'],1)
        with self.assertRaises(ValueError):decode(raw,self.first,self.first+61439*4096,*self.args[2:])
        with self.assertRaises(ValueError):decode(raw+b'\0',*args)

if __name__=='__main__':unittest.main()
