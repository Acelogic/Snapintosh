#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind PMP row votes to native active-state domains and exact DT transport."""
from dataclasses import replace
from pathlib import Path
import struct
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import pmp_active_models,device_model_words

class PMPTests(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.pmp='/device-tree/arm-io/pmp/iop-pmp-nub'
        self.pmgr='/device-tree/arm-io/pmgr'
        self.models=tuple(replace(m,kind=6,config=(*m.config[:4],0)) if m.kind==25 else m
                          for m in self.dt.device_models)

    def test_native_mask_matches_physical_domains_and_excludes_virtual_devices(self):
        binary=ROOT/'build/test-pmp-active'
        self.assertTrue(binary.exists(),'build the native transport test first')
        native=int(subprocess.check_output([str(binary),'--supported-mask'],text=True))
        raw=self.dt.get(self.pmgr,'devices')
        physical={row[3] for row in (raw[i:i+48] for i in range(0,len(raw),48))
                  if not row[0]&16 and row[3]}
        rows=tuple(struct.iter_unpack('<31I',self.dt.get(self.pmp,'soc-device')))
        expected=sum(1<<i for i,row in enumerate(rows) if row[0] in physical)
        self.assertEqual(native,expected)
        self.assertEqual(native.bit_count(),12)
        self.assertFalse(native&((1<<10)|(1<<27)))
        before=self.dt.serialize()
        models=pmp_active_models(self.dt,self.models)
        self.assertEqual(self.dt.serialize(),before)
        self.assertEqual(models,self.dt.device_models)
        self.assertEqual(models[10].words(),(25,0x3003c0000,0x14000,0x10000,0x1a8,0x1b8,8,native))
        self.assertEqual(len(models),len(self.models))

    def test_mutated_missing_or_unresolved_contract_refused(self):
        for path,name in ((self.pmgr,'devices'),(self.pmgr,'reg'),(self.pmgr,'ptd-ranges'),
                          (self.pmgr,'pmp'),(self.pmgr,'pmp-voter-agent-idx'),
                          (self.pmp,'ptd-range'),(self.pmp,'soc-device'),
                          (self.pmp,'ptd-driver-version'),(self.pmp,'soc-device-ps-group')):
            prop=self.dt.nodes[path][name];original=prop.value
            for mode in ('mutated','missing','unresolved'):
                if mode=='mutated':prop.value=bytes([original[0]^1])+original[1:]
                elif mode=='missing':self.dt.nodes[path].pop(name)
                else:prop.placeholder=True
                before=self.dt.serialize()
                with self.assertRaises(ValueError):pmp_active_models(self.dt,self.models)
                self.assertEqual(self.dt.serialize(),before)
                prop.value=original;prop.placeholder=False;self.dt.nodes[path][name]=prop

    def test_power_backend_dependencies_are_required(self):
        for group in (0,1):
            omitted=tuple(m for m in self.models if not (m.kind==18 and m.config[0]==group))
            with self.assertRaises(ValueError):pmp_active_models(self.dt,omitted)
            changed=tuple(replace(m,base=m.base+0x1000) if m.kind==18 and m.config[0]==group else m
                          for m in self.models)
            with self.assertRaises(ValueError):pmp_active_models(self.dt,changed)
        with self.assertRaises(ValueError):device_model_words((self.dt.device_models[10],))

    def test_shared_aperture_and_native_config_are_strict(self):
        for changes in (dict(base=0x400000000),dict(span=0x18000),
                        dict(config=(0x20000,0x1a8,0x1b8,8,0))):
            altered=tuple(replace(m,**changes) if m.kind==6 else m for m in self.models)
            with self.assertRaises(ValueError):pmp_active_models(self.dt,altered)
        for i in range(5):
            m=self.dt.device_models[10];config=list(m.config);config[i]^=1
            altered=list(self.dt.device_models);altered[10]=replace(m,config=tuple(config))
            with self.assertRaises(ValueError):device_model_words(altered)
        with self.assertRaises(ValueError):pmp_active_models(self.dt,tuple(m for m in self.models if m.kind!=6))

if __name__=='__main__':unittest.main()
