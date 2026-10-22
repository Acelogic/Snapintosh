#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import copy
import runpy
import struct
import unittest

decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_private_pages']

class PrivateProvenanceCapture(unittest.TestCase):
    def setUp(self):
        self.first=0x40000000
        self.allocated=self.first+16*4096
        self.owners=bytes([0]*8+[2]*8)
        self.views=[dict(owner=0,root=self.first,sources=[self.first],
                         copies=[self.first+i*4096 for i in range(1,7)]),
                    dict(owner=2,root=self.first+8*4096,sources=[self.first+8*4096],
                         copies=[self.first+i*4096 for i in range(9,15)])]
        self.canonical=[self.first,self.first+8*4096,self.first+7*4096]
        self.stats=[32,24,16,1000,900,0]
        self.bits=sum(1<<i for i in [*range(1,7),*range(9,15)])
    def raw(self,stats=None,bits=None):
        return struct.pack('<6Q',*(self.stats if stats is None else stats))+(self.bits if bits is None else bits).to_bytes(4096,'little')
    def check(self,**kwargs):
        args=dict(raw=self.raw(),first=self.first,allocated=self.allocated,owners=self.owners,
                  views=self.views,canonical=self.canonical)
        args.update(kwargs);return decode(**args)
    def test_independent_bitmap(self):
        r=self.check();self.assertEqual(r['private_pages'],12)
        self.assertEqual(r['canonical_pages'],3);self.assertTrue(r['current_snapshot_verified'])
    def test_installed_bitmap_shape(self):
        # The larger bitmap must retain independent ownership checks.
        raw=self.raw()+bytes(7680-4096)
        self.assertTrue(self.check(raw=raw)['current_snapshot_verified'])
        corrupt=bytearray(raw);corrupt[-1]=128
        with self.assertRaises(ValueError):self.check(raw=corrupt)
        with self.assertRaises(ValueError):self.check(raw=raw[:-1])
    def test_counters(self):
        for i,value in [(0,23),(1,0),(1,11),(2,33),(3,900),(4,0),(5,1)]:
            s=self.stats.copy();s[i]=value
            with self.subTest(i=i,value=value),self.assertRaises(ValueError):self.check(raw=self.raw(stats=s))
    def test_bitmap_and_geometry(self):
        for bits in [self.bits^2,self.bits|1,self.bits|(1<<16),self.bits|(1<<7)]:
            with self.subTest(bits=bits),self.assertRaises(ValueError):self.check(raw=self.raw(bits=bits))
        for args in [dict(raw=bytes(4143)),dict(first=self.first+1),dict(allocated=self.first),
                     dict(allocated=self.allocated+1),dict(owners=self.owners[:-1]),
                     dict(canonical=self.canonical+[self.first+4096]),
                     dict(canonical=self.canonical+[self.allocated])]:
            with self.subTest(args=str(args)[:50]),self.assertRaises(ValueError):self.check(**args)
    def test_metadata_and_lifetime(self):
        owners=bytearray(self.owners);owners[1]=255
        with self.assertRaises(ValueError):self.check(owners=owners)
        owners=bytearray(self.owners);owners[7]=255
        with self.assertRaises(ValueError):self.check(owners=owners)
        for field,value in [('owner',3),('root',self.first+8),('copies',self.views[0]['copies']*2),
                            ('copies',[self.first+4096]*6),('sources',[])]:
            v=copy.deepcopy(self.views);v[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(views=v)

if __name__=='__main__':unittest.main()
