#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from dataclasses import replace
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from coresight import coresight_models
from devicemodel import device_model_words

class CoreSightTests(unittest.TestCase):
    def test_source_binding_and_unchanged_tree(self):
        profile=xb.GUEST_PROFILE
        with patch.object(xb,'GUEST_PROFILE',replace(profile,coresight_boot=())):
            original=xb.build_devicetree()
        dt=xb.build_devicetree()
        self.assertEqual(dt.serialize(),original.serialize())
        self.assertEqual(tuple(m for m in dt.device_models if m.kind!=39),original.device_models)
        self.assertEqual(len(dt.device_models),120)
        locks=tuple(m for m in dt.device_models if m.kind==39)
        self.assertEqual(len(locks),6)
        for i,model in enumerate(locks):
            self.assertEqual(model.kind,39)
            self.assertEqual(model.config,(i,0,0,0,0))
            self.assertEqual(model.span,0x1000)
            for bad in (replace(model,base=model.base+0x1000),replace(model,span=0x2000),
                        replace(model,config=(6,0,0,0,0)),
                        *(replace(model,config=tuple(1 if j==k else model.config[j] for j in range(5)))
                          for k in range(1,5))):
                with self.assertRaises(ValueError):device_model_words((bad,))

    def test_refusal_does_not_mutate_tree(self):
        specs=xb.GUEST_PROFILE.coresight_boot
        for changes in (specs[:-1],specs[:-1]+(specs[0],),
                        specs[:-1]+(replace(specs[-1],base=specs[-1].base+0x1000),)):
            dt=xb.build_devicetree();before=dt.serialize()
            with self.assertRaises(ValueError):coresight_models(dt,changes)
            self.assertEqual(dt.serialize(),before)
        for name,value in [('compatible',b'other\0'),('coresight-reg',bytes(16)),
                           ('reg-private',bytes(8)),('coresight-reg',bytes(8))]:
            dt=xb.build_devicetree();dt.put(specs[-1].node,name,value);before=dt.serialize()
            with self.assertRaises(ValueError):coresight_models(dt,specs)
            self.assertEqual(dt.serialize(),before)
        for name in ('compatible','coresight-reg','reg-private'):
            for unresolved in (False,True):
                dt=xb.build_devicetree()
                if unresolved:dt.nodes[specs[-1].node][name].placeholder=True
                else:dt.nodes[specs[-1].node].pop(name)
                before=dt.serialize()
                with self.assertRaises(ValueError):coresight_models(dt,specs)
                self.assertEqual(dt.serialize(),before)

    def test_shipped_access_and_topology_mapping(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        kc=importlib.util.module_from_spec(spec);spec.loader.exec_module(kc)
        im=kc.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(low,n):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in im.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*n,im.data,off+va-base)
        self.assertEqual(words(0xba7d6f8,3),(0x5299caa9,0x72b8b589,0xb90fb109))
        self.assertEqual(words(0xba7d6b0,3),(0xf940e280,0xaa130008,0xb4000ac8))
        # An existing CPU-implementation mapping also maps CoreSight. Merely
        # removing its address while preserving CPU implementation is unsafe.
        self.assertEqual(words(0xba89348,7),(0xf9001ac0,0xa94686c0,0x528000e2,
            0x52800063,0x52800004,0x97ffdc1d,0xf90032c0))
        self.assertEqual(words(0xba7d810,5),(0xa9437bfd,0xa9424ff4,0xa94157f6,
            0x910103ff,0xd65f0fff))

if __name__=='__main__':unittest.main()
