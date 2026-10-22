#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the disabled LLT control to the shipped T8140 method and source DT."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import device_model_words,pmgr_power_models

class LLTTests(unittest.TestCase):
    def test_source_window_and_descriptor_refusals(self):
        dt=xb.build_devicetree();windows=xb.device_windows(dt,'pmgr','/device-tree/arm-io')
        model,=[m for m in dt.device_models if m.kind==38]
        self.assertEqual(windows[24],(0x300730000,0x14000))
        self.assertEqual(model.words(),(38,0x300740000,0x1000,0,0,0,0,0))
        for bad in (replace(model,base=model.base+0x1000),replace(model,span=0x2000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for window in ((0x300734000,0x14000),(0x300730000,0x10000)):
            changed=list(windows);changed[24]=window;before=dt.serialize()
            with self.assertRaisesRegex(ValueError,'LLT'):
                pmgr_power_models(dt,xb.GUEST_PROFILE.pmgr_boot,changed)
            self.assertEqual(dt.serialize(),before)

    def test_stock_control_is_single_bit_rmw_without_completion_poll(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        im=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(low,count):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in im.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*count,im.data,off+va-base)
        self.assertEqual(words(0x9bed738,7),(0x52a00021,0x94000b9f,
            0x121f7808,0x2a140102,0xaa1503e0,0x52a00021,0xaa1303e3))
        self.assertEqual(words(0x9bed770,1),(0x14000ba6,))
        self.assertEqual(words(0x97a43c4,1),(0x52800d21,))
        self.assertEqual(words(0x97a4438,1),(0x52800d21,))
        # The callback's final hardware call clears DDR sleep bit 0, then
        # both the callback and AppleSOCTuner::start take their return paths.
        self.assertEqual(words(0x9bed628,6),(0x52880001,0x97fff3ca,0x121f7808,
            0x2a130102,0xaa1403e0,0x52880001))
        self.assertEqual(words(0x9bed658,1),(0x17fff36d,))
        self.assertEqual(words(0x9b25ef0,3),(0x97fffd9d,0xb9011e74,0xa9497bfd))
        self.assertEqual(words(0x9b25f14,1),(0xd65f0fff,))
        self.assertEqual(words(0x9b25244,1),(0x52800020,))
        self.assertEqual(words(0x9b2525c,1),(0xd65f0fff,))
        fix=dict(module.chained_fixups(im,0))
        for slot,target in ((0x82756c8,0x97a4380),(0x82756f0,0x97a43f0)):
            va=0xfffffe0000000000+slot
            _,base,_,off,_=next(s for s in im.segments if s[1]<=va<s[1]+s[4])
            self.assertEqual(fix[off+va-base],0xfffffe0000000000+target)

if __name__=='__main__':unittest.main()
