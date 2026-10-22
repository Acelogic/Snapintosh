#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import i2c_empty_models,device_model_words

class I2CEmptyTests(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.spec=xb.GUEST_PROFILE.i2c_empty
        self.windows=xb.device_windows(self.dt,'i2c2','/device-tree/arm-io')

    def test_binding_preserves_native_consumers(self):
        before=self.dt.serialize()
        models=i2c_empty_models(self.dt,self.spec,self.windows)
        self.assertEqual([m.words() for m in models],[(43,0x385018000,0x4000,2,6,1110,0,0)])
        self.assertEqual([m for m in self.dt.device_models if m.kind==43],list(models))
        self.assertEqual(self.dt.serialize(),before)
        self.assertEqual(self.dt.children[self.spec.node],
            [self.spec.node+'/usb-hub-i2c',self.spec.node+'/usb-repeater-i2c'])

    def test_firmware_drift_refuses_without_mutation(self):
        for node in [self.spec.node,*self.dt.children[self.spec.node]]:
            for key,prop in list(self.dt.nodes[node].items()):
                original=prop.value
                for mode in ('changed','placeholder'):
                    if mode=='changed':prop.value=bytes(original)+b'\0'
                    else:prop.placeholder=True
                    before=self.dt.serialize()
                    with self.assertRaises(ValueError):i2c_empty_models(self.dt,self.spec,self.windows)
                    self.assertEqual(self.dt.serialize(),before)
                    prop.value=original;prop.placeholder=False
        self.dt.put(self.spec.node,'new-device',b'')
        with self.assertRaises(ValueError):i2c_empty_models(self.dt,self.spec,self.windows)

    def test_clock_geometry_and_model_refusals(self):
        m=i2c_empty_models(self.dt,self.spec,self.windows)[0]
        for windows in ((),((0x385014000,0x4000),),((0x385018000,0x1000),)):
            with self.assertRaises(ValueError):i2c_empty_models(self.dt,self.spec,windows)
        for i in range(5):
            c=list(m.config);c[i]+=1
            with self.assertRaises(ValueError):device_model_words((replace(m,config=tuple(c)),))
        p=self.dt.nodes['/device-tree/arm-io/pmgr']['devices'];old=p.value
        for off in (3264,3268,3280,3290,3296):
            p.value=old[:off]+bytes([old[off]^1])+old[off+1:]
            with self.assertRaises(ValueError):i2c_empty_models(self.dt,self.spec,self.windows)
        p.value=old;p.placeholder=True
        with self.assertRaises(ValueError):i2c_empty_models(self.dt,self.spec,self.windows)

    def test_stock_controller_initialization_instructions(self):
        image=xb.kc_load.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def word(va):
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<I',image.data,off+va-base)[0]
        # Control, status, mask, debug lines, revision, and revision-6 enable.
        for va,op in ((0xfffffe000992e22c,0xb9001d09),(0xfffffe000992e230,0xb9401514),
                      (0xfffffe000992e280,0xb9001509),(0xfffffe000992e284,0xb900191f),
                      (0xfffffe000992e28c,0xb9001109),(0xfffffe000992e310,0xb9402908),
                      (0xfffffe000992e318,0x7100191f),(0xfffffe000992e32c,0xb9001d09),
                      (0xfffffe000992f1a4,0xb9004109)):
            self.assertEqual(word(va),op,hex(va))

if __name__=='__main__':unittest.main()
