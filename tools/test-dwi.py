#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind DWI startup to the selected DT and actual Apple driver instructions."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import dwi_models, device_model_words


class DWITests(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.spec=xb.GUEST_PROFILE.dwi_startup
        self.windows=xb.device_windows(self.dt,'dwi','/device-tree/arm-io')

    def test_profile_binding_preserves_all_consumers(self):
        before=self.dt.serialize()
        models=dwi_models(self.dt,self.spec,self.windows)
        self.assertEqual([m.words() for m in models],[(42,0x300200000,0x4000,0,0,0,0,0)])
        self.assertEqual([m for m in self.dt.device_models if m.kind==42],list(models))
        self.assertEqual(self.dt.serialize(),before)
        for buck in range(3):self.assertIsNone(self.dt.get(self.spec.node,f'voltages-buck{buck:x}'))
        # Derive the native driver's three configuration values from properties.
        def u32(key):return struct.unpack('<I',self.dt.get(self.spec.node,key))[0]
        divisor=u32('nclk-div')
        self.assertEqual((((divisor-1)<<16)|u32('polarity-config'),
                          24*u32('str-delay')//divisor,24*u32('lockout-us')),
                         (1,192000,120))
        device_model_words(self.dt.device_models)

    def test_changed_unresolved_missing_or_added_metadata_is_atomic_refusal(self):
        for key,prop in list(self.dt.nodes[self.spec.node].items()):
            original=prop.value
            for mode in ('changed','unresolved','missing'):
                if mode=='changed':prop.value=bytes([original[0]^1])+original[1:]
                elif mode=='unresolved':prop.placeholder=True
                else:self.dt.nodes[self.spec.node].pop(key)
                before=self.dt.serialize()
                with self.assertRaises(ValueError):dwi_models(self.dt,self.spec,self.windows)
                self.assertEqual(self.dt.serialize(),before)
                prop.value=original;prop.placeholder=False;self.dt.nodes[self.spec.node][key]=prop
        self.dt.put(self.spec.node,'voltages-buck0',struct.pack('<I',900))
        with self.assertRaises(ValueError):dwi_models(self.dt,self.spec,self.windows)

    def test_power_binding_and_geometry_refusals(self):
        model=dwi_models(self.dt,self.spec,self.windows)[0]
        for bad in (replace(model,base=model.base+0x1000),replace(model,span=0x1000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for windows in ((),((0x300201000,0x4000),),((0x300200000,0x1000),)):
            with self.assertRaises(ValueError):dwi_models(self.dt,self.spec,windows)
        prop=self.dt.nodes['/device-tree/arm-io/pmgr']['devices'];original=prop.value
        for offset in (576,592,602,608):
            prop.value=original[:offset]+bytes([original[offset]^1])+original[offset+1:]
            with self.assertRaises(ValueError):dwi_models(self.dt,self.spec,self.windows)
        prop.value=original;prop.placeholder=True
        with self.assertRaises(ValueError):dwi_models(self.dt,self.spec,self.windows)

    def test_stock_startup_and_optional_buck_instructions(self):
        image=xb.kc_load.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def word(va):
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<I',image.data,off+va-base)[0]
        for va,value in ((0xfffffe00099373b0,0xb9000149),
                         (0xfffffe00099373b8,0xb900d149),
                         (0xfffffe00099373c0,0xb9000549),
                         (0xfffffe00099373c4,0xb900855f),
                         (0xfffffe00099373c8,0xb9008148),
                         (0xfffffe0009937434,0xb4000460),
                         (0xfffffe00099374c4,0xf1000f3f)):
            self.assertEqual(word(va),value)


if __name__=='__main__':unittest.main()
