#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check opaque ACC startup programming against the shipped binary and DT."""
from dataclasses import replace
import importlib.util
import hashlib
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import device_model_words

class ACCPolicy(unittest.TestCase):
    def test_source_apertures_and_descriptor_validation(self):
        dt=xb.build_devicetree();windows=xb.device_windows(dt,'pmgr','/device-tree/arm-io')
        models=[m for m in dt.device_models if m.kind==37]
        self.assertEqual([m.words() for m in models],[(37,0x210e44000+i*0x1000000,
            0x1000,i,0,0,0,0) for i in range(2)])
        for i,m in enumerate(models):
            start,span=windows[(7,16)[i]]
            self.assertEqual(m.base,start+0x4000);self.assertLessEqual(m.base+m.span,start+span)
            for bad in (replace(m,span=0x2000),replace(m,config=(2,0,0,0,0)),
                        *(replace(m,config=(i,*(int(j==k) for j in range(4)))) for k in range(4))):
                with self.assertRaises(ValueError):device_model_words((bad,))

    def test_stock_wrapper_tail_write_after_generic_restore(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(low,count):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*count,image.data,off+va-base)
        self.assertEqual(words(0x9be95dc,4),(0x52800002,0xaa0903f1,0xf2fd78f1,0xd73f0911))
        self.assertEqual(words(0x9be9624,4),(0x52881f02,0x72a01c82,0x52800023,0x52800004))
        self.assertEqual(words(0x9be9654,1),(0xd71f0a11,))
        self.assertEqual(words(0x76f4038,2),(10,0xe40000))
        self.assertEqual(words(0x76f4070,2),(22,0xe40000))

    def test_native_cluster_sampler_programming(self):
        blob=xb.DEFAULT_KERNELCACHE.read_bytes()
        self.assertEqual(hashlib.sha256(blob).hexdigest(),
            'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62')
        image=xb.kc_load.Image(blob)
        def word(low):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<I',blob,off+va-base)[0]
        # Decode the actual MOVZ payload and source register for every native
        # selector write, including its descriptor field and STR destination.
        constants=((0x9b6e5dc,1,0x8a0f),(0x9b6e5e4,0,0x800f),
                   (0x9b6e5ec,17,0x8c0f),(0x9b6e5f0,16,0x9c0f),
                   (0x9b6e5f4,15,0x9e0f),(0x9b6e5f8,14,0x810f),
                   (0x9b6e5fc,13,0xb90f),(0x9b6e600,12,0xbe0f),
                   (0x9b6e604,11,0xbf0f),(0x9b6e608,10,0xd40f))
        destinations=(2,1,0,17,16,15,14,13,12,8)
        for i,((pc,source,value),dest) in enumerate(zip(constants,destinations)):
            self.assertEqual(word(pc),0x52800000|(value<<5)|source)
            self.assertEqual(word(0x9b6e638+i*12),
                0xb9400000|(((0x4c+i*4)//4)<<10)|(8<<5)|dest)
            self.assertEqual(word(0x9b6e640+i*12),0xf9000000|(dest<<5)|source)
        self.assertEqual(word(0x9b6e5e8),0xf900016a)  # enable-register write1
        self.assertEqual(word(0x9b6e634),0xd2800001)  # disabled first selector is0

if __name__=='__main__':unittest.main()
