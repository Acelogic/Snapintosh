#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SOC tuner policy binding and the original Apple no-control path."""
from dataclasses import replace
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from appledt import DeviceTree
from soctunerboot import populate_soctuner_boot
import xnuboot as xb
SPEC=xb.GUEST_PROFILE.soctuner_boot


def fixture():
    dt=xb.build_devicetree()
    dt.put(SPEC.node,'mcc-power-gating',struct.pack('<I',1))
    return dt


class SOCTunerBootTests(unittest.TestCase):
    def test_source_binding_and_only_one_policy_changes(self):
        path=ROOT/'downloads/extracted/j700ap/DeviceTree.j700ap'
        original=path.read_bytes();source=DeviceTree(original)
        raw=source.get(SPEC.node,'mcc-power-gating')
        self.assertEqual(raw,struct.pack('<I',1))
        self.assertEqual(hashlib.sha256(raw).hexdigest(),SPEC.mcc_power_gating_sha256)
        dt=fixture();before=dt.serialize()
        populate_soctuner_boot(dt,SPEC)
        self.assertEqual(dt.get(SPEC.node,'mcc-power-gating'),bytes(4))
        self.assertEqual(dt.get(SPEC.node,'soc-tuning'),source.get(SPEC.node,'soc-tuning'))
        self.assertEqual(dt.get(SPEC.node,'fb-caching'),source.get(SPEC.node,'fb-caching'))
        after=dt.serialize();populate_soctuner_boot(dt,SPEC)
        self.assertEqual(dt.serialize(),after)
        dt.put(SPEC.node,'mcc-power-gating',raw)
        self.assertEqual(dt.serialize(),before)
        self.assertEqual(path.read_bytes(),original)

    def assert_refused(self,dt,spec=SPEC):
        before=dt.serialize()
        with self.assertRaises(ValueError):populate_soctuner_boot(dt,spec)
        self.assertEqual(dt.serialize(),before)

    def test_unresolved_or_changed_provider_and_policy_refused(self):
        for name in ('compatible','mcc-power-gating'):
            dt=fixture();del dt.nodes[SPEC.node][name];self.assert_refused(dt)
            dt=fixture();dt.nodes[SPEC.node][name].placeholder=True;self.assert_refused(dt)
        dt=fixture();dt.put(SPEC.node,'compatible',b'soc-tuner,other\0');self.assert_refused(dt)
        for raw in (b'',bytes(3),bytes(8),struct.pack('<I',2),b'\xff'*4):
            dt=fixture();dt.put(SPEC.node,'mcc-power-gating',raw);self.assert_refused(dt)
        for digest in ('','a'*63,'G'*64,True,None,'0'*64):
            self.assert_refused(fixture(),replace(SPEC,mcc_power_gating_sha256=digest))

    def test_profile_integrates_policy_without_changing_device_abi(self):
        dt=xb.build_devicetree();parsed=DeviceTree(dt.serialize())
        self.assertEqual(parsed.get(SPEC.node,'mcc-power-gating'),bytes(4))
        self.assertEqual(len(dt.device_models),120)
        self.assertEqual(len(parsed.get('/device-tree/arm-io/pmgr','reg')),44*16)

    def test_stock_boolean_guard_precedes_mcc_function_call(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        im=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def read(low,length):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in im.segments if s[1]<=va<s[1]+s[4])
            return im.data[off+va-base:off+va-base+length]
        def words(low,count):return struct.unpack('<'+'I'*count,read(low,count*4))
        self.assertEqual(read(0x76d8128,17),b'mcc-power-gating\0')
        self.assertEqual(words(0x9b24d80,2),(0x90fedda1,0x9104a021))
        self.assertEqual(words(0x9b24d98,4),(0xb9400be8,0x7100011f,0x1a9f07e8,0x39026e68))
        self.assertEqual(words(0x9b25684,4),(0x39426c08,0x36000328,0xf9406400,0xb40002e0))
        self.assertEqual(words(0x9b256ec,1),(0xd65f03c0,))


if __name__=='__main__':unittest.main()
