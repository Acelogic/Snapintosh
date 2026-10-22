#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run
import xnuboot as xb


class StockCPU(unittest.TestCase):
    def test_target_registry_and_disjoint_results(self):
        binary=ROOT/'build/test-cpu'
        subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined',
            '-fno-sanitize-recover=all','-Wall','-Wextra','-Werror',
            str(ROOT/'tools/test-cpu.c'),str(ROOT/'compat/cpu.c'),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)

    def test_selected_shipped_affinity_and_slot_contract(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        kc=importlib.util.module_from_spec(spec);spec.loader.exec_module(kc)
        im=kc.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def word(low):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in im.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<I',im.data,off+va-base)[0]
        self.assertEqual(word(0xba788f4),0xb27e0129)  # topology entry's physical ID at +4
        self.assertEqual(word(0xba7890c),0xb9400140)  # w0 argument to CPU_ID
        self.assertEqual(word(0xba78918),0x793a52a0)  # u16 slot stored
        self.assertEqual(word(0xba78928),0x8b093d00)  # slot * 0x8000
        self.assertEqual(word(0xba78948),0xaa1303e0)  # same slot to OUTPUT_AREA
        dt=xb.build_devicetree()
        self.assertEqual([struct.unpack('<I',dt.nodes[f'/device-tree/cpus/cpu{i}']['reg'].value)[0]
                          for i in range(6)],[0,1,2,3,0x100,0x101])
        self.assertEqual(xb.SCRATCH_COUNT,6)
        self.assertEqual(xb.SCRATCH_STRIDE,0x8000)
        self.assertEqual(xb.SCRATCH_PA,xb.SPTM_DATA_PA+xb.SCRATCH_OFFSET)
        self.assertLessEqual(xb.SCRATCH_OFFSET+xb.SCRATCH_SPAN,xb.SPTM_DATA_SPAN)

    def test_cpu_refusal_classification(self):
        # A terminal refusal stays visible even if the ordinary event log fills.
        event=(38,0xfffffe0001234000,3,0x13,0x101,0)
        result,reason=run.classify(1,0,b'',[],{},0,event)
        self.assertEqual(result,run.EXIT_UNSUPPORTED)
        self.assertIn('CPU not registered',reason)
        self.assertIn('0x101',reason)


if __name__=='__main__':unittest.main(verbosity=2)
