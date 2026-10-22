#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject corrupt proof telemetry and mismatches with the independent walk."""
import copy
from pathlib import Path
import runpy
import struct
import unittest

decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_kernel_class_proof']

class ClassProofCapture(unittest.TestCase):
    def setUp(self):
        self.first=0x100000;self.limit=self.first+0x40000;self.allocated=self.first+0x20000
        self.header=[130,128,2,0,0,2,1,1,1,2,1,self.first,512,self.first,self.limit,2,4,4,4,4]
        self.bitmap=15
        self.kernel=dict(canonical_root=hex(self.first),canonical_tables=4,
            canonical_table_pages=[hex(self.first+n*4096) for n in range(4)],
            selector_4k_pages={'2':4})
    def read(self):
        raw=struct.pack('<20Q',*self.header)+self.bitmap.to_bytes(4096,'little')
        return decode(raw,self.kernel,130,self.first,self.limit,self.allocated)
    def test_independent_walk_matches_valid_snapshot(self):
        self.assertTrue(self.read()['current_snapshot_verified'])
    def test_installed_bitmap_shape(self):
        # A wider arena cannot truncate the proof bitmap or skip its audit.
        self.limit=self.first+61440*4096;self.header[14]=self.limit
        raw=struct.pack('<20Q',*self.header)+self.bitmap.to_bytes(7680,'little')
        self.assertTrue(decode(raw,self.kernel,130,self.first,self.limit,self.allocated)['current_snapshot_verified'])
        corrupt=bytearray(raw);corrupt[-1]=128
        with self.assertRaises(ValueError):decode(corrupt,self.kernel,130,self.first,self.limit,self.allocated)
        with self.assertRaises(ValueError):decode(raw[:-1],self.kernel,130,self.first,self.limit,self.allocated)
    def test_invalid_snapshot_does_not_claim_current_coverage(self):
        self.header[10]=0;self.header[15]=1
        self.kernel['canonical_tables']=5
        self.kernel['canonical_table_pages'].append(hex(self.first+0x5000))
        self.assertFalse(self.read()['current_snapshot_verified'])
    def test_corrupt_header_fields_rejected(self):
        mutations={0:129,1:127,2:1,3:1,4:1,5:0,6:3,7:2,8:2,9:3,10:2,
                   11:self.first+4096,12:0,13:self.first+4096,14:self.limit+4096,
                   15:1,16:3,17:5,18:512,19:3}
        for index,value in mutations.items():
            with self.subTest(field=index):
                before=self.header[index];self.header[index]=value
                with self.assertRaises(ValueError):self.read()
                self.header[index]=before
    def test_bitmap_corruption_rejected(self):
        for bits in [14,7,31,23,15|(1<<32),15|(1<<32767)]:
            with self.subTest(bits=bits):
                self.bitmap=bits
                with self.assertRaises(ValueError):self.read()
    def test_independent_coverage_mismatch_rejected(self):
        original=copy.deepcopy(self.kernel)
        for pages in [[hex(self.first)]*4,
                      [hex(self.first+n*4096) for n in (0,1,2,4)],
                      [hex(self.first+n*4096) for n in (0,1,2,32)],
                      [hex(self.first+n) for n in (0,4096,8192,12289)]]:
            self.kernel=copy.deepcopy(original);self.kernel['canonical_table_pages']=pages
            with self.assertRaises(ValueError):self.read()
    def test_independent_leaf_summary_mismatch_rejected(self):
        self.kernel['selector_4k_pages']={'3':4}
        with self.assertRaises(ValueError):self.read()
        self.kernel['selector_4k_pages']={'2':3}
        with self.assertRaises(ValueError):self.read()

if __name__=='__main__':unittest.main()
