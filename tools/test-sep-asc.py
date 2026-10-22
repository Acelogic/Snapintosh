#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import sep_asc_models,device_model_words
from guestprofile import J700_26A428_NO_CLPC


class SEPASC(unittest.TestCase):
    def test_exact_subtree_and_model(self):
        dt=xb.build_devicetree();spec=xb.GUEST_PROFILE.sep_asc
        windows=xb.device_windows(dt,'sep','/device-tree/arm-io')
        expected=sep_asc_models(dt,spec,windows)
        self.assertEqual(expected[0].words(),(45,0x282600000,0x9000,8,0,0,0,0))
        self.assertEqual(len(dt.device_models),120)
        self.assertEqual([(i,dt.device_models[i].kind) for i in (117,118,119)],
                         [(117,43),(118,44),(119,45)])
        nodes=[n for n in dt.nodes if n==spec.node or n.startswith(spec.node+'/')]
        for node in nodes:
            for key in list(dt.nodes[node]):
                old=dt.get(node,key)
                dt.nodes[node][key].placeholder=True
                with self.assertRaises(ValueError):sep_asc_models(dt,spec,windows)
                dt.nodes[node][key].placeholder=False
                dt.put(node,key,old+b'\0')
                with self.assertRaises(ValueError):sep_asc_models(dt,spec,windows)
                dt.put(node,key,old)
            dt.put(node,'new-policy',b'')
            with self.assertRaises(ValueError):sep_asc_models(dt,spec,windows)
            del dt.nodes[node]['new-policy']
        for win in (windows[:1],windows[::-1],[(0x282610000,0x88000),windows[1]]):
            with self.assertRaises(ValueError):sep_asc_models(dt,spec,win)
        for i in range(5):
            cfg=list(expected[0].config);cfg[i]^=1
            with self.assertRaises(ValueError):device_model_words((replace(expected[0],config=tuple(cfg)),))
        for change in [dict(base=0x282610000),dict(span=0x88000)]:
            with self.assertRaises(ValueError):device_model_words((replace(expected[0],**change),))
        self.assertEqual(sep_asc_models(dt,spec,windows),expected)

    def test_real_high_memory_placement(self):
        with patch.dict(xb.__dict__,xb.__dict__.copy()):
            xb.place(0x8c0000000,29696<<20,guest_span=8192<<20)
            dt=xb.build_devicetree()
            self.assertEqual(dt.device_models[-1].words(),(45,0x282600000,0x9000,8,0,0,0,0))
            self.assertEqual(xb.PARAMS_WORDS,1154)

    def test_explicit_reply_transport(self):
        dt=xb.build_devicetree();spec=replace(xb.GUEST_PROFILE.sep_asc,reply_transport=True)
        windows=xb.device_windows(dt,'sep','/device-tree/arm-io')
        model,=sep_asc_models(dt,spec,windows)
        self.assertEqual(model.words(),(45,0x282600000,0x9000,8,1,346,343,0))
        self.assertFalse(xb.GUEST_PROFILE.sep_asc.reply_transport)
        self.assertTrue(J700_26A428_NO_CLPC.sep_asc.reply_transport)
        for index in range(5):
            cfg=list(model.config);cfg[index]^=2 if index==4 else 1
            with self.assertRaises(ValueError):device_model_words((replace(model,config=tuple(cfg)),))
        for invalid in (1,None,'true'):
            with self.assertRaises(ValueError):
                sep_asc_models(dt,replace(spec,reply_transport=invalid),windows)

    def test_explicit_rom_status(self):
        dt=xb.build_devicetree();spec=replace(xb.GUEST_PROFILE.sep_asc,reply_transport=True,rom_status=True)
        windows=xb.device_windows(dt,'sep','/device-tree/arm-io')
        model,=sep_asc_models(dt,spec,windows)
        self.assertEqual(model.config,(8,1,346,343,1))
        for changes in [dict(reply_transport=False),dict(rom_status=1),dict(rom_status=None)]:
            with self.assertRaises(ValueError):sep_asc_models(dt,replace(spec,**changes),windows)

    def test_explicit_service_bootstrap(self):
        dt=xb.build_devicetree();windows=xb.device_windows(dt,'sep','/device-tree/arm-io')
        spec=replace(xb.GUEST_PROFILE.sep_asc,reply_transport=True,rom_status=True,service_bootstrap=True)
        model,=sep_asc_models(dt,spec,windows)
        self.assertEqual(model.config,(8,1,346,343,3))
        for changes in [dict(rom_status=False),dict(reply_transport=False),dict(service_bootstrap=1)]:
            with self.assertRaises(ValueError):sep_asc_models(dt,replace(spec,**changes),windows)

    def test_explicit_recovery_endpoint(self):
        dt=xb.build_devicetree();windows=xb.device_windows(dt,'sep','/device-tree/arm-io')
        spec=replace(xb.GUEST_PROFILE.sep_asc,reply_transport=True,rom_status=True,
                     service_bootstrap=True,pnon_recovery=True)
        model,=sep_asc_models(dt,spec,windows)
        self.assertEqual(model.config,(8,1,346,343,7))
        for changes in [dict(service_bootstrap=False),dict(pnon_recovery=1),
                        dict(rom_status=False),dict(reply_transport=False)]:
            with self.assertRaises(ValueError):sep_asc_models(dt,replace(spec,**changes),windows)


if __name__=='__main__':unittest.main()
