#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind energy baseline pages to the shipped setters and register tables."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import pmgr_power_models,device_model_words

class EnergyRestore(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.windows=xb.device_windows(self.dt,'pmgr','/device-tree/arm-io')

    def test_exact_source_windows_and_configuration(self):
        models=[m for m in self.dt.device_models if m.kind==36]
        expected=[(10,0x210059000),(11,0x210159000),(12,0x210259000),
                  (13,0x210359000),(19,0x211059000),(20,0x211159000),
                  (7,0x210e48000),(16,0x211e48000)]
        self.assertEqual([m.words() for m in models],
            [(36,base,0x1000,0,0,0,0,0) for _,base in expected])
        for m,(index,base) in zip(models,expected):
            start,span=self.windows[index]
            self.assertEqual(base-start,0x8000 if index in (7,16) else 0x9000)
            self.assertLessEqual(base+0x1000,start+span)
            for bad in (replace(m,span=0x2000),*(replace(m,config=tuple(
                    int(i==word) for i in range(5))) for word in range(5))):
                with self.assertRaises(ValueError):device_model_words((bad,))
            changed=list(self.windows);changed[index]=(start+0x1000,span)
            with self.assertRaises(ValueError):
                pmgr_power_models(self.dt,xb.GUEST_PROFILE.pmgr_boot,changed)

    def test_stock_setters_address_the_derived_pairs(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(low,count):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*count,image.data,off+va-base)
        table=words(0x76f4078,24)
        self.assertEqual(table,(14,0x50000,15,0x150000,16,0x250000,17,0x350000,
                               0,0,0,0,26,0x50000,27,0x150000,0,0,0,0,0,0,0,0))
        for low,immediate in ((0x9bec1e4,0x52920008),(0x9bec5b4,0x52920108)):
            self.assertEqual(words(low,5),(immediate,0x72a000a8,0x2a0a5108,
                                          0x29402561,0x4b090102))
        self.assertEqual(words(0x9bec3c0,3),(0x52900002,0x72a01c82,0x52800004))
        self.assertEqual(words(0x9bec67c,3),(0x52900102,0x72a01c82,0x52800004))
        # Logical register mapping: core cluster tables and CPM ACC translator.
        self.assertEqual(words(0x76f4038,2),(10,0xe40000))
        self.assertEqual(words(0x76f4070,2),(22,0xe40000))
        actual=[]
        for cluster,count,first_dt in ((0,4,10),(1,2,19)):
            for cpu in range(count):
                logical,offset=table[12*cluster+2*cpu:12*cluster+2*cpu+2]
                self.assertEqual(logical,(14 if cluster==0 else 26)+cpu)
                start,_=self.windows[first_dt+cpu]
                actual.append(start+((0x59000|(cpu<<20))-offset))
        actual.extend(self.windows[i][0]+0x8000 for i in (7,16))
        self.assertEqual(actual,[m.base for m in self.dt.device_models if m.kind==36])
        # Read-modify-write of the energy configuration word: disable all
        # three bits or enable all three, retaining unrelated readback bits.
        self.assertEqual(words(0x9bec084,3),(0x52802f02,0x72a01ce2,0x52800003))
        self.assertEqual(words(0x9bec0c8,6),(0x92f50008,0x8a080008,0x710002bf,
                                          0xd2f50009,0x9a9f1129,0xaa090103))
        self.assertEqual(words(0x979d654,1),(0x52800022,))

if __name__=='__main__':unittest.main()
