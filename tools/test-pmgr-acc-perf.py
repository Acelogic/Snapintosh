#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify exact ACC restore slots against stock DT records and instructions."""
from dataclasses import replace
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

class ACCRestore(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree();self.node='/device-tree/arm-io/pmgr'
        self.windows=xb.device_windows(self.dt,'pmgr','/device-tree/arm-io')

    def test_exact_slots_from_cpu_records_and_bounded_pstates(self):
        raw=self.dt.get(self.node,'perf-counters');telemetry={0:[],1:[]}
        for pos in range(0,len(raw),64):
            row=raw[pos:pos+64]
            if row[0]==3:telemetry[row[16]].append(row[17])
        self.assertEqual(telemetry,{0:[0,44,48,52,56],1:[0,44,48]})
        expected=set()
        for cluster,count in ((0,8),(1,18)):
            expected|={(cluster,base+8*i) for base in (0x400,0x500) for i in range(count)}
            expected|={(cluster,0x680+8*i+event*8) for i in telemetry[cluster] for event in (0,1)}
            expected|={(cluster,0x11e8+8*i) for i in range(count)}
        expected|={(0,0x10e8+8*i) for i in range(8)}
        result=subprocess.run([str(ROOT/'build/test-pmgr-acc-perf'),'--topology'],
            capture_output=True,text=True,check=True)
        native=[tuple(map(int,line.split())) for line in result.stdout.splitlines()]
        self.assertEqual(len(native),102);self.assertEqual(set(native),expected)

    def test_descriptor_geometry_and_binding(self):
        models=[m for m in self.dt.device_models if m.kind==35]
        self.assertEqual([m.words() for m in models],
            [(35,0x210e20000+g*0x1000000,0x2000,g,0,0,0,0) for g in range(2)])
        for g,m in enumerate(models):
            self.assertEqual(self.windows[5+g*9],(m.base,0x2000))
            for bad in (replace(m,span=0x1000),replace(m,config=(2,0,0,0,0)),
                        *(replace(m,config=(g,*(int(i==j) for i in range(4)))) for j in range(4))):
                with self.assertRaises(ValueError):device_model_words((bad,))
        for prop in ('perf-domains','perf-counters'):
            record=self.dt.nodes[self.node][prop];original=record.value
            record.value=bytes([original[0]^1])+original[1:]
            with self.assertRaises(ValueError):
                pmgr_power_models(self.dt,xb.GUEST_PROFILE.pmgr_boot,self.windows)
            record.value=original

    def test_stock_address_mapping_and_setter_bounds(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(low,count):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*count,image.data,off+va-base)
        self.assertEqual(words(0x76f4000,2),(9,0xe20000))
        self.assertEqual(words(0x76f4048,2),(21,0xe20000))
        for va,bound,branch in ((0x9bebf34,0x7100205f,0x54000682),
                               (0x9bebed0,0x7100485f,0x54000962)):
            self.assertEqual(words(va,8),(bound,branch,0x52808008,0x72a01c48,
                0x32180109,0x7100007f,0x1a881128,0x2a020d02))
        for va,branch in ((0x9bebe40,0x54000da2),(0x9bebf80,0x54000442)):
            self.assertEqual(words(va,10),(0x7100e45f,branch,0x52805008,0x52805109,
                0x7100007f,0x1a881128,0x52808009,0x72a01c49,0x2a090108,0x0b020d02))
        # The Apple enableCPUPerfCounters override is a no-op, not a freeze gate.
        self.assertEqual(words(0x9bee004,2),(0xd503245f,0xd65f03c0))
        self.assertEqual(words(0x9bebe84,7),(0x7100205f,0x54000ba2,0x52819d08,
            0x5281bd09,0x7100007f,0x1a881128,0x0b020d08))
        self.assertEqual(words(0x9bebef4,5),(0x7100485f,0x54000862,0x52808008,
            0x72a01c48,0x0b020d08))
        self.assertEqual(words(0x9bebf28,1),(0x1137a102,))
        # cpuComplexIdleEnter reads logical e20020 and waits for BUSY[31]
        # to clear. It does not request a sampled counter or current P-state.
        self.assertEqual(words(0x9bec734,3),(0x52800402,0x72a01c42,0x52800003))
        self.assertEqual(words(0x9bec748,1),(0x37fffe80,))

if __name__=='__main__':unittest.main()
