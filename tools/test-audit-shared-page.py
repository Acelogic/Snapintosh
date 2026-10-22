#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

ROOT=Path(__file__).resolve().parent
module=runpy.run_path(str(ROOT/'audit-shared-page.py'))

class SharedPageAudit(unittest.TestCase):
    def setUp(self):
        self.ram=bytearray(0x40000);self.work=bytearray(0x10000)
        # Shared and user roots have distinct L2s but the same physical L3.
        for pa,v in [(0x10000,0x14003),(0x14000,0x18003),(0x18008,0x00600000000306c3),
                     (0x1c000,0x20003),(0x20000,0x18003)]:self.put(pa,v)
        for pa,v in [(0x100000,0x101003),(0x101000,0x102003),(0x102000,0x103003)]:self.put(pa,v)
        for i in range(4):self.put(0x103020+i*8,0x00600000000306c3+i*4096)
        self.cache=[dict(valid=1,root=0x1c000,shadow=0x100000,format=0)]
        self.regions=[dict(root='0x10000',page_size=16384,start='0x0',end='0x100000')]
        self.state=dict.fromkeys(module['FIELDS'],0)
        self.state.update(calls=1,inserts=1,alias_updates=1,root=0x10000,va=0x4000,
            next=0x00600000000306c3,requested=0x00600000000306c3,shift=14,mask=1,cpu=3)
    def put(self,pa,v):
        target,off=(self.ram,pa-0x10000) if pa<0x100000 else (self.work,pa-0x100000)
        struct.pack_into('<Q',target,off,v)
    def read(self,pa,size):
        target,off=(self.ram,pa-0x10000) if pa<0x100000 else (self.work,pa-0x100000)
        return target[off:off+size]
    def audit(self):
        return module['audit'](self.read,state=self.state,cache=self.cache,regions=self.regions,
            ram_low=0x10000,ram_high=0x50000,work_low=0x100000,work_high=0x110000)
    def test_shared_source_and_alias(self):
        d=self.audit();self.assertTrue(d['current_source_matches']);self.assertEqual(len(d['current_aliases']),1)
    def test_bad_source_and_each_hardware_part(self):
        for i in range(4):
            for mask in (0x80,0x1000,1<<59,1<<53):
                self.put(0x103020+i*8,(0x00600000000306c3+i*4096)^mask)
                with self.subTest(part=i,mask=mask),self.assertRaises(ValueError):self.audit()
                self.put(0x103020+i*8,0x00600000000306c3+i*4096)
    def test_bad_witness(self):
        for key,value in [('calls',2),('next',0),('options',2),('shift',13),('cpu',6),('requested',0)]:
            old=self.state[key];self.state[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.audit()
            self.state[key]=old
    def test_unmapped_historical_witness(self):
        self.put(0x18008,0)
        for i in range(4):self.put(0x103020+i*8,0)
        self.assertFalse(self.audit()['current_source_matches'])
    def test_update_of_valid_leaf_reports_map_valid(self):
        # A same-PA update of a valid shared leaf is MAP_VALID (1); reporting
        # 0 would make XNU add a second PV entry for the same PTE pointer.
        self.state.update(inserts=0,updates=1,old=0x0060000000030643,result=1)
        self.assertTrue(self.audit()['current_source_matches'])
        self.state['result']=0
        with self.assertRaises(ValueError):self.audit()
    def test_insert_reports_success(self):
        self.state['result']=1
        with self.assertRaises(ValueError):self.audit()
    def test_bound_but_not_nested_root(self):
        self.put(0x20000,0)
        self.assertEqual(self.audit()['current_aliases'],[])
    def test_new_mapping_after_earlier_historical_request(self):
        self.put(0x18008,0x00600000000386c3)
        for i in range(4):self.put(0x103020+i*8,0x00600000000386c3+i*4096)
        self.assertFalse(self.audit()['current_source_matches'])

if __name__=='__main__':unittest.main()
