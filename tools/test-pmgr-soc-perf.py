#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the restore backend to Apple's table and shipped instruction contract."""
from dataclasses import replace
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import pmgr_power_models,device_model_words

class SOCCounters(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.node='/device-tree/arm-io/pmgr'
        self.models=[m for m in self.dt.device_models if m.kind==34]

    def test_topology_from_primary_and_paired_records(self):
        raw=self.dt.get(self.node,'perf-counters')
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            '0bee9adb92308ec5cad0869c5eabe2b121db31eeb61d558309221ca3be4cc096')
        slots=set()
        for start in range(0,len(raw),64):
            row=raw[start:start+64]
            if row[0]==3:continue  # CPU/DPE records use a separate interface.
            if row[4]<6:slots.add((row[4],struct.unpack_from('<I',row,8)[0]))
            if row[0]==1 and row[1] in (1,2) and row[5]<6:
                slots.add((row[5],struct.unpack_from('<I',row,12)[0]))
        self.assertEqual([sum(g==i for g,_ in slots) for i in range(6)],
                         [137,295,26,26,26,8])
        result=subprocess.run([str(ROOT/'build/test-pmgr-soc-perf'),'--topology'],
                              check=True,capture_output=True,text=True)
        native=[tuple(map(int,line.split())) for line in result.stdout.splitlines()]
        self.assertEqual(len(native),518)
        self.assertEqual(set(native),slots)
        self.assertFalse(any(g==1 and 0x24c0<=off<=0x2dc0 for g,off in native))

    def test_group_geometry_and_descriptor_contract(self):
        groups=self.dt.get(self.node,'perf-groups')
        self.assertEqual(hashlib.sha256(groups).hexdigest(),
            '15b1245f5b613775f5c2b747d1e930414b12dfd49c0cb68875732390c6b702ed')
        windows=xb.device_windows(self.dt,'pmgr','/device-tree/arm-io')
        for g,m in enumerate(self.models):
            index,offset,flags,dataoff,mode,enable,*zeros=struct.unpack_from('<9I',groups,g*36)
            self.assertEqual((flags,dataoff,mode,enable,zeros),(1,16,3,4,[0,0,0]))
            self.assertEqual(m.base,(windows[index][0]+offset)&~0xfff)
            self.assertEqual(m.config,(g,0,0,0,0))
            for bad in (replace(m,span=m.span+0x1000),
                        replace(m,config=(6,0,0,0,0)),
                        *(replace(m,config=(g,*(int(j==k) for j in range(4)))) for k in range(4))):
                with self.assertRaises(ValueError):device_model_words((bad,))
        for key in ('perf-groups','perf-counters'):
            prop=self.dt.nodes[self.node][key];original=prop.value
            prop.value=bytes([original[0]^1])+original[1:]
            with self.assertRaises(ValueError):
                pmgr_power_models(self.dt,xb.GUEST_PROFILE.pmgr_boot,windows)
            prop.value=original

    def test_stock_split_join_enable_and_read_retry(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(low,count):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*count,image.data,off+va-base)
        self.assertEqual(words(0x97a9674,3),(0xd360fc48,0xb9000082,0xb9000068))
        self.assertEqual(words(0x97be930,10),(0x2942254a,0x2a00012b,0x0a290009,
            0x710002df,0x1a891169,0x0a2a0129,0x4b0a03eb,0x0a0b014a,0x710002bf,0x1a8a13ea))
        self.assertEqual(words(0x97bea30,1),(0x121f7808,))
        for va in (0x97beb70,0x97bebbc):self.assertEqual(words(va,1),(0xd73f0931,))
        self.assertEqual(words(0x97b328c,1),(0xd73f0910,))
        self.assertEqual(words(0x97b32d4,1),(0xd73f0931,))
        self.assertEqual(words(0x97b331c,2),(0xd73f0931,0x6b17001f))

if __name__=='__main__':unittest.main()
