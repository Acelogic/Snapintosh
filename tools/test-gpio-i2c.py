#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import gpio_models,device_model_words

class I2CPads(unittest.TestCase):
    def test_exact_routes_and_preservation(self):
        profile=xb.GUEST_PROFILE;spec=profile.gpio_boot[0]
        with patch.object(xb,'GUEST_PROFILE',replace(profile,gpio_boot=(replace(spec,idle_i2c=()),*profile.gpio_boot[1:]))):
            previous=xb.build_devicetree()
        dt=xb.build_devicetree();self.assertEqual(dt.serialize(),previous.serialize())
        changed=[(a,b) for a,b in zip(previous.device_models,dt.device_models) if a!=b]
        self.assertEqual(len(changed),1);old,model=changed[0]
        self.assertEqual((old.kind,model.kind),(12,40))
        self.assertEqual(model.words(),(40,0x31a000000,0x100000,216,7,127,5096408961622,5878381359781))
        routes=[((v>>(11*i))&511)-1 for v in model.config[3:] for i in range(4)]
        self.assertEqual(routes,[85,169,101,80,164,165,170,171])
        for word in (3,4):
            for bit in range(44,64):
                cfg=list(model.config);cfg[word]|=1<<bit
                with self.assertRaises(ValueError):device_model_words((replace(model,config=tuple(cfg)),))

    def test_provider_and_pin_binding_refusal(self):
        spec=xb.GUEST_PROFILE.gpio_boot[0]
        for bus in spec.idle_i2c:
            for key,raw in [('compatible',b'i2c,other\0'),
                ('gpio-iic_scl',struct.pack('<3I',bus.scl+1,0x10102,0x5041)),
                ('gpio-iic_sda',struct.pack('<3I',bus.sda,0x10103,0x5041)),
                ('gpio-iic_sda',struct.pack('<3I',bus.sda,0x10102,0x5042)),
                ('gpio-iic_sda',bytes(8))]:
                dt=xb.build_devicetree();dt.put(bus.peripheral,key,raw);before=dt.serialize()
                with self.assertRaises(ValueError):gpio_models(dt,spec,[(0x31a000000,0x100000)])
                self.assertEqual(dt.serialize(),before)
        dt=xb.build_devicetree()
        for buses in (spec.idle_i2c*2,(spec.idle_i2c[0],)*2):
            with self.assertRaises(ValueError):gpio_models(dt,replace(spec,idle_i2c=buses),[(0x31a000000,0x100000)])

if __name__=='__main__':unittest.main()
