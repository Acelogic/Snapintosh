#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check QSPI placement against the exact selected guest and reject ABI drift."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import qspi_models, device_model_words


class QSPITests(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.spec=xb.GUEST_PROFILE.qspi_boot
        self.windows=xb.device_windows(self.dt,'qspi','/device-tree/arm-io')

    def test_overlapping_windows_share_one_model_and_keep_flash_consumers(self):
        models=qspi_models(self.dt,self.spec,self.windows)
        self.assertEqual([m.words() for m in models],[(41,0x385110000,0x5000,0,0,0,0,0)])
        self.assertEqual([m for m in self.dt.device_models if m.kind==41],list(models))
        for child,compat in (('spinor',b'nor-flash,spi\0'),
                             ('spinor/anvram',b'nvram,chrp\0'),
                             ('spinor/syscfg',b'diagnostic-data,format1\0')):
            self.assertEqual(self.dt.get(self.spec.node+'/'+child,'compatible'),compat)
        self.assertTrue(self.dt.get('/device-tree/chosen','nvram-proxy-data'))
        device_model_words(self.dt.device_models)

    def test_changed_or_unresolved_controller_metadata_is_atomic_refusal(self):
        for key,prop in list(self.dt.nodes[self.spec.node].items()):
            original=prop.value
            for mode in ('changed','unresolved','missing'):
                if mode=='changed':prop.value=bytes([original[0]^1])+original[1:]
                elif mode=='unresolved':prop.placeholder=True
                else:self.dt.nodes[self.spec.node].pop(key)
                before=self.dt.serialize()
                with self.assertRaises(ValueError):qspi_models(self.dt,self.spec,self.windows)
                self.assertEqual(self.dt.serialize(),before)
                prop.value=original;prop.placeholder=False;self.dt.nodes[self.spec.node][key]=prop

    def test_geometry_and_descriptor_refusals(self):
        model=qspi_models(self.dt,self.spec,self.windows)[0]
        for index in range(2):
            for column in range(2):
                bad=[list(w) for w in self.windows];bad[index][column]+=0x1000
                with self.assertRaises(ValueError):qspi_models(self.dt,self.spec,tuple(map(tuple,bad)))
        for bad in (replace(model,span=0x4000),replace(model,span=0x6000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))

    def test_stock_reset_and_fifo_capacity_read_instructions(self):
        image=xb.kc_load.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def word(va):
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<I',image.data,off+va-base)[0]
        # mov w9,#0x100; str w9,[x8]; ldr w9,[x8]; tbz w9,#8.
        self.assertEqual(word(0xfffffe00098eb478),0x52802009)
        self.assertEqual(word(0xfffffe00098eb47c),0xb9000109)
        self.assertEqual(word(0xfffffe00098eb480),0xb9400109)
        self.assertEqual(word(0xfffffe00098eb484)&0xfff8001f,0x36400009)
        # Common VERSION at +3c; peripheral FIFO depths at +38.
        self.assertEqual(word(0xfffffe00098eb49c),0xb9403d29)
        self.assertEqual(word(0xfffffe00098eb4a4),0xb9403908)


if __name__=='__main__':unittest.main()
