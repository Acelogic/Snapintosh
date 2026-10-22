#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import copy
from pathlib import Path
import runpy
import struct
import unittest

MOD=runpy.run_path(str(Path(__file__).with_name('audit-shared-region.py')))
class SharedRegionAudit(unittest.TestCase):
    def setUp(self):
        self.base=0x900000000;self.memory=bytearray(0x30000)
        self.root=self.base+0x4000;self.fm=self.base+0x20000;self.va=0x180004000
        self.write(self.root+8*((self.va>>36)&2047),self.base+0x8003)
        self.write(self.base+0x8000+8*((self.va>>25)&2047),self.base+0xc003)
        self.slot=self.base+0xc000+8*((self.va>>14)&2047)
        old=0x00200009000106c3;new=old|0x800;self.write(self.slot,new)
        self.memory[0x20000+16+2]=19
        row=dict(zip(MOD['FIELDS'],[1,64,1,4,0,self.base+0x10000,64,self.root,self.va,
                                 self.slot,old,new,14,0,1,0x800]))
        self.states=[[dict.fromkeys(MOD['FIELDS'],0),dict.fromkeys(MOD['FIELDS'],0)] for _ in range(6)]
        self.states[3]=[row.copy(),row.copy()]
    def write(self,at,value):struct.pack_into('<Q',self.memory,at-self.base,value)
    def read(self,at,n):
        assert 0<=at-self.base<=len(self.memory)-n
        return bytes(self.memory[at-self.base:at-self.base+n])
    def audit(self):
        return MOD['audit'](self.read,states=self.states,ram_low=self.base,
                           ram_high=self.base+0x20000,frame_map=self.fm,frame_low=self.base)
    def test_live_rx_conversion(self):
        r=self.audit();self.assertEqual((r['calls'],r['entries'],r['changed']),(1,64,1))
        self.assertTrue(all(x['current_source_matches'] for x in r['rows']))
    def test_later_empty_preserves_changed_witness(self):
        s=self.states[3][0];s.update(calls=2,entries=128,old=0,next=0,last_changed=0,target=0,
                                     va=self.va+0x4000,slot=self.slot+8)
        self.assertEqual(len(self.audit()['rows']),2)
    def test_historical_source_reported(self):
        self.write(self.slot,0);self.assertFalse(self.audit()['rows'][0]['current_source_matches'])
    def test_no_calls(self):
        self.states=[[dict.fromkeys(MOD['FIELDS'],0),dict.fromkeys(MOD['FIELDS'],0)] for _ in range(6)]
        self.assertEqual(self.audit()['calls'],0)
    def test_reject_corruption(self):
        original=copy.deepcopy(self.states)
        for field,value in [('next',0),('old',0),('requested',0),('target',0),('flags',2),
                            ('options',2),('shift',13),('count',65),('slot',self.slot+8),
                            ('result',5),('last_changed',0),('root',self.root+1)]:
            with self.subTest(field=field):
                self.states=copy.deepcopy(original);self.states[3][1][field]=value
                with self.assertRaises(ValueError):self.audit()
    def test_lost_changed_witness(self):
        self.states[3][1]=dict.fromkeys(MOD['FIELDS'],0)
        with self.assertRaises(ValueError):self.audit()

if __name__=='__main__':unittest.main()
