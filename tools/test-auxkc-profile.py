#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The linked-AuxKC profiles change only what they name; lp-sip0 is exact."""
import contextlib
from dataclasses import fields
import io
from pathlib import Path
import runpy
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
from guestprofile import get_profile, CSR_ALLOW_UNRESTRICTED_FS
from trustcache import AugmentedTrustCacheSpec

BASE = 'j700ap-26A428-bootfb-xars-uniform'
AUXKC = 'j700ap-26A428-bootfb-auxkc'
GPU = 'j700ap-26A428-bootfb-auxkc-gpu'
PLAIN = 'j700ap-26A428-xars-uniform-auxkc'


def tree(name):
    xb.configure_guest(name)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree()


def differing(a, b):
    return {f.name for f in fields(a) if getattr(a, f.name) != getattr(b, f.name)}


class ProfileTests(unittest.TestCase):
    def tearDown(self):
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_fields_that_differ(self):
        base, aux, gpu = map(get_profile, (BASE, AUXKC, GPU))
        self.assertEqual(differing(base, aux), {'name', 'aux_collection_linked'})
        self.assertEqual(differing(aux, gpu), {'name', 'sip_lp_sip0', 'trust_cache'})
        self.assertTrue(aux.boot_framebuffer_aux and aux.boot_framebuffer_nub)
        self.assertEqual(gpu.sip_lp_sip0, CSR_ALLOW_UNRESTRICTED_FS)
        self.assertIsInstance(gpu.trust_cache, AugmentedTrustCacheSpec)
        self.assertEqual(gpu.trust_cache.base, base.trust_cache)
        self.assertFalse(gpu.trust_cache.appended)
        self.assertFalse(base.aux_collection_linked)
        self.assertIsNone(base.sip_lp_sip0)
        plain = get_profile(PLAIN)
        self.assertEqual(differing(base, plain), {'name', 'aux_collection_linked',
                                                  'boot_framebuffer_aux', 'boot_framebuffer_nub'})
        self.assertFalse(plain.boot_framebuffer_aux or plain.boot_framebuffer_nub)

    def test_secondary_admission(self):
        validate = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))['validate_guest_profile']
        for name in (AUXKC, GPU, PLAIN):
            validate(name)

    def test_device_tree_differs_only_in_local_policy(self):
        base, aux, gpu = tree(BASE), tree(AUXKC), tree(GPU)
        self.assertEqual(base.serialize(), aux.serialize())
        self.assertEqual(gpu.get(xb.LOCAL_POLICY_NODE, 'lp-sip0'), struct.pack('<Q', 2))
        gpu.nodes[xb.LOCAL_POLICY_NODE].pop('lp-sip0')
        self.assertEqual(gpu.serialize(), base.serialize())
        self.assertIsNone(base.get(xb.LOCAL_POLICY_NODE, 'lp-sip0'))
        self.assertEqual(set(base.nodes[xb.LOCAL_POLICY_NODE]), {'AAPL,phandle', 'name'})

    def test_local_policy_refusals(self):
        dt = tree(BASE)
        for bad in (0, 1 << 13, CSR_ALLOW_UNRESTRICTED_FS | (1 << 4), True, '2'):
            with self.subTest(bad), self.assertRaises(ValueError):
                xb.local_boot_policy(dt, bad)
        xb.local_boot_policy(dt, CSR_ALLOW_UNRESTRICTED_FS)
        self.assertEqual(len(dt.get(xb.LOCAL_POLICY_NODE, 'lp-sip0')), 8)
        with self.assertRaisesRegex(ValueError, 'already sets lp-sip0'):
            xb.local_boot_policy(dt, CSR_ALLOW_UNRESTRICTED_FS)
        del dt.nodes[xb.LOCAL_POLICY_NODE]
        with self.assertRaisesRegex(ValueError, 'local-policy node'):
            xb.local_boot_policy(dt, CSR_ALLOW_UNRESTRICTED_FS)

    def test_pinned_kernel_reads_lp_sip0_as_u64(self):
        data = xb.DEFAULT_KERNELCACHE.read_bytes()
        for text in (b'lp-sip0\0', b'/chosen/asmb\0', b"unexpected size %xu for uint64 property '%s'"):
            self.assertIn(text, data)

    def test_linked_profile_layout_reserves_after_monitor_data(self):
        xb.configure_guest(AUXKC)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        placed = {name: (off, span) for name, off, span in xb.reservations()}
        self.assertEqual(placed['aux collection'],
                         (placed['sptm data'][0] + placed['sptm data'][1], xb.AUXKC_SPAN))
        xb.validate_layout()
        xb.configure_guest(AUXKC)       # default small layout also fits
        xb.validate_layout()
        xb.configure_guest(PLAIN)       # no boot framebuffer: tree stays at +0x10000
        xb.place(0x8c0000000, guest_span=8192 << 20)
        xb.validate_layout()
        self.assertEqual(xb.DEVICETREE_PA, xb.HANDOFF_PA + 0x10000)
        self.assertIn('aux collection', {name for name, _, _ in xb.reservations()})


if __name__ == '__main__':
    unittest.main()
