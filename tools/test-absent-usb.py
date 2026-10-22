#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The no-USB board may only withdraw the unbacked USB/Type-C clients."""
from dataclasses import fields
from pathlib import Path
import runpy
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import guestprofile as gp
import xnuboot as xb


class AbsentUSBTests(unittest.TestCase):
    def test_profile_and_resolved_tree_contract(self):
        old,new=gp.J700_26A428_BOOTFB_NUB,gp.J700_26A428_BOOTFB_NO_USB
        validate=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))['validate_guest_profile']
        validate(new.name)
        for f in fields(old):
            if f.name not in ('name','deferred_subtrees'):
                self.assertEqual(getattr(old,f.name),getattr(new,f.name),f.name)
        xb.configure_guest(old.name)
        xb.place(0x8c0000000,29696<<20,guest_span=8192<<20)
        before=xb.build_devicetree()
        xb.configure_guest(new.name)
        xb.place(0x8c0000000,29696<<20,guest_span=8192<<20)
        after=xb.build_devicetree()
        expected={p for p in before.nodes if p in ('/device-tree/arm-io/atc0-dpphy',
                  '/device-tree/arm-io/i2c2/usb-hub-i2c') or
                  p=='/device-tree/arm-io/usb-drd' or p.startswith('/device-tree/arm-io/usb-drd/')}
        self.assertEqual(len(expected),7)
        self.assertEqual(set(before.nodes)-set(after.nodes),expected)
        self.assertEqual(set(after.nodes)-set(before.nodes),set())
        self.assertEqual(len(after.deferred_nodes),28)
        self.assertEqual(after.device_models,before.device_models)
        self.assertEqual(after.monitor_uat_geometry,before.monitor_uat_geometry)
        for node in after.nodes:
            self.assertEqual(set(after.nodes[node]),set(before.nodes[node]))
            for prop in before.nodes[node]:
                self.assertEqual(after.get(node,prop),before.get(node,prop),(node,prop))
        for node in ('dart-usb','atc-phy0','atc0-dpxbar','disp0','pmgr'):
            self.assertIn('/device-tree/arm-io/'+node,after.nodes)
        full=xb.build_devicetree(include_deferred=True)
        self.assertTrue(expected<=set(full.nodes))
        # Firmware drift must refuse the deferral before mutating publication.
        from deferred import defer_subtrees
        # Omitting the hub from the closure leaves its real USB port phandle.
        incomplete=tuple(s for s in new.deferred_subtrees if s.node!='/device-tree/arm-io/i2c2/usb-hub-i2c')
        original_nodes=set(full.nodes)
        with self.assertRaisesRegex(ValueError,'usb-port.*references'):
            defer_subtrees(full,incomplete,new.deferred_functions)
        self.assertEqual(set(full.nodes),original_nodes)
        target='/device-tree/arm-io/usb-drd'
        full.put(target,'compatible',b'unexpected-controller\0')
        nodes=set(full.nodes)
        with self.assertRaisesRegex(ValueError,'hash|digest|changed'):
            defer_subtrees(full,new.deferred_subtrees,new.deferred_functions)
        self.assertEqual(set(full.nodes),nodes)


if __name__=='__main__':unittest.main()
