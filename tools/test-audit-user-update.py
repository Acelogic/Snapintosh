#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
module=runpy.run_path(str(ROOT/'audit-user-update.py'))
Fixture=runpy.run_path(str(ROOT/'test-audit-user-roots.py'))['RootAudit']

class UserUpdateAudit(unittest.TestCase):
    def setUp(self):
        self.fixture=Fixture();self.fixture.setUp()
        self.states=[dict.fromkeys(module['FIELDS'],0) for _ in range(6)]
        self.states[0].update(calls=1,entries=1,changed=1,options=0xc0a,result=0,
            target=0x20000,count=1,root=0x10000,va=0x4000,slot=0x18008,
            old=0x0860000000020ec3,next=0x0060000000020e43,shift=14,flags=2,
            last_changed=1,requested=0x0060000000020e43)
        self.fixture.gput(0x8008,self.states[0]['next'])
    def run_audit(self):
        return module['audit'](self.fixture.read,states=self.states,cache=self.fixture.cache,
                               ram_low=0x10000,ram_high=0x30000)
    def test_measured_fault_repair(self):
        row=self.run_audit()['rows'][0]
        self.assertTrue(row['current_source_matches'] and row['descriptor_policy_verified'])
    def test_bad_witness(self):
        for key,value in [('next',0),('last_changed',0),('options',0x40a),('changed',2),
                          ('count',65),('target',0x20001),('shift',13),('result',5),('slot',0x18010)]:
            old=self.states[0][key];self.states[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_audit()
            self.states[0][key]=old
    def test_stale_history_is_reported_without_claiming_current_match(self):
        self.fixture.gput(0x8008,self.states[0]['old'])
        self.assertFalse(self.run_audit()['rows'][0]['current_source_matches'])
    def test_unused_witness_must_be_empty(self):
        self.states[1]['next']=1
        with self.assertRaises(ValueError):self.run_audit()

class UserRegionAudit(UserUpdateAudit):
    def setUp(self):
        super().setUp();s=self.states[0]
        s.update(options=2,old=0x0060000000020e43,next=0x0060000000020ec3,
                 requested=0x00600000000000c0)
        self.fixture.gput(0x8008,s['next'])
    def run_audit(self):
        return module['audit'](self.fixture.read,states=self.states,cache=self.fixture.cache,
                              ram_low=0x10000,ram_high=0x30000,region=True)
    def test_bad_witness(self):
        for key,value in [('next',0),('last_changed',0),('changed',2),('count',65),
                          ('target',0x24000),('shift',13),('result',5),('slot',0x18010)]:
            old=self.states[0][key];self.states[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_audit()
            self.states[0][key]=old
    def test_absent_leaf_returns_zero(self):
        self.states[0].update(target=0,old=0,next=0,last_changed=0,changed=0)
        self.fixture.gput(0x8008,0)
        self.assertTrue(self.run_audit()['rows'][0]['descriptor_policy_verified'])

class KernelUpdateAudit(UserUpdateAudit):
    def setUp(self):
        super().setUp()
        s=self.states[0]
        s.update(options=0xa,flags=0,old=0x0060000000020603,
                 next=0x0860000000020683,requested=0x0860000000020683)
        self.fixture.gput(0x8008,s['next'])
        for part in range(4):
            self.fixture.hput(0x3020+part*8,(s['next']&~(1<<59))+part*4096)
    def run_audit(self):
        return module['audit_kernel'](self.fixture.read,states=self.states,
            root=0x10000,canonical=0x100000,ram_low=0x10000,ram_high=0x30000)
    def test_bad_witness(self):
        for key,value in [('next',0),('last_changed',0),('changed',2),('count',65),
                          ('target',0x20001),('shift',12),('result',5),('slot',0x18010),
                          ('root',0x14000),('flags',2)]:
            old=self.states[0][key];self.states[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_audit()
            self.states[0][key]=old
    def test_stale_history_is_reported_without_claiming_current_match(self):
        self.fixture.gput(0x8008,self.states[0]['old'])
        for part in range(4):self.fixture.hput(0x3020+part*8,self.states[0]['old']+part*4096)
        self.assertFalse(self.run_audit()['rows'][0]['current_source_matches'])
    def test_each_hardware_leaf_is_verified(self):
        expected=self.states[0]['next']&~(1<<59)
        for part in range(4):
            for change in (1<<59,0x80,1<<53,0x1000):
                self.fixture.hput(0x3020+part*8,(expected+part*4096)^change)
                with self.subTest(part=part,change=change),self.assertRaises(ValueError):self.run_audit()
                self.fixture.hput(0x3020+part*8,expected+part*4096)

if __name__=='__main__':unittest.main()
