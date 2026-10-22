#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import contextlib
from dataclasses import replace
import io
import runpy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import sep_asc_models


class XARSProfile(unittest.TestCase):
    def test_secondary_admission_accepts_explicit_pinned_profile(self):
        validate=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))['validate_guest_profile']
        validate('j700ap-26A428-bootfb-xars')
        validate('j700ap-26A428-bootfb-rtc')
        with self.assertRaises(ValueError):validate('j700ap-26A428-bootfb-xars-unknown')

    def test_explicit_selection_changes_only_backend_mode(self):
        trees=[]
        for name in ('j700ap-26A428-bootfb-rtc','j700ap-26A428-bootfb-xars'):
            xb.configure_guest(name);xb.place(0x8c0000000,guest_span=8192<<20)
            with contextlib.redirect_stdout(io.StringIO()):trees.append(xb.build_devicetree())
        a,b=trees
        changed=[(x,y) for x,y in zip(a.device_models,b.device_models) if x!=y]
        self.assertEqual(len(a.device_models),len(b.device_models))
        self.assertEqual(len(changed),1)
        before,after=changed[0]
        self.assertEqual(before.kind,45)
        self.assertEqual(before.config,(8,1,346,343,7))
        self.assertEqual(after,replace(before,config=(8,1,346,343,15)))
        self.assertEqual(a.serialize(),b.serialize())
        spec=xb.GUEST_PROFILE.sep_asc
        windows=xb.device_windows(b,'sep','/device-tree/arm-io')
        for mutation in (dict(xars_refusal=1),dict(pnon_recovery=False,service_bootstrap=False)):
            with self.assertRaises(ValueError):sep_asc_models(b,replace(spec,**mutation),windows)

    def test_installed_xars_without_recovery_os_type(self):
        # Regression: installed CPSN lookup panics when its xars service is
        # absent. Enabling that service must not select recoveryOS pnon.
        xb.configure_guest('j700ap-26A428-xars-uniform-auxkc-installed')
        xb.place(0x8c0000000,guest_span=8192<<20)
        with contextlib.redirect_stdout(io.StringIO()):tree=xb.build_devicetree()
        spec=xb.GUEST_PROFILE.sep_asc
        self.assertFalse(spec.pnon_recovery)
        self.assertTrue(spec.pnon_refusal)
        self.assertTrue(spec.xars_refusal)
        windows=xb.device_windows(tree,'sep','/device-tree/arm-io')
        selected=sep_asc_models(tree,replace(spec,xars_refusal=True),windows)
        disabled=sep_asc_models(tree,replace(spec,xars_refusal=False),windows)
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0].config,(8,1,346,343,27))
        self.assertEqual(disabled[0].config,(8,1,346,343,19))
        self.assertEqual(selected[0],replace(disabled[0],config=(8,1,346,343,27)))
        for mutation in (dict(pnon_recovery=True),dict(pnon_refusal=1),
                         dict(service_bootstrap=False)):
            with self.assertRaises(ValueError):sep_asc_models(tree,replace(spec,**mutation),windows)


if __name__=='__main__':unittest.main()
