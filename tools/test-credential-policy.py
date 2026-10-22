#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the no-SEP profile policy against the actual shipped kernel bytes."""
import hashlib
import importlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'probes'))
import credential
import guestprofile
kc_load = importlib.import_module('kc-load')


class Tree:
    def __init__(self):
        self.values = {key: bytes(4) for key in ('protected-data-access', 'sepfw-load-at-boot')}

    def get(self, node, key):
        assert node == '/device-tree/chosen'
        return self.values.get(key)


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = kc_load.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        cls.sha = hashlib.sha256(cls.image.data).hexdigest()
        assert cls.sha == dict(guestprofile.J700_26A428.firmware)[guestprofile.J700_26A428.kernelcache]

    def test_profile_scope(self):
        self.assertFalse(guestprofile.J700_26A428.acm_software_mode)
        self.assertTrue(guestprofile.J700_26A428_NO_CLPC.acm_software_mode)

    def test_actual_image_without_modification(self):
        self.assertEqual(credential.software_cmdline(self.image, Tree(), '-v rd=md0'),
                         '-v rd=md0 acm_fastsim=1')
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), self.sha)

    def test_requires_both_explicit_no_sep_properties(self):
        for name in Tree().values:
            for bad in (None, b'', b'\0', b'\1\0\0\0'):
                with self.subTest(name=name, bad=bad):
                    tree = Tree(); tree.values[name] = bad
                    with self.assertRaises(ValueError):
                        credential.software_cmdline(self.image, tree, '-v')

    def test_no_duplicate_or_conflicting_mode(self):
        for arg in ('acm_fastsim', 'acm_fastsim=0', 'acm_fastsim=1', 'acm_fastsim=2'):
            with self.assertRaises(ValueError):
                credential.software_cmdline(self.image, Tree(), '-v '+arg)

    def test_all_measured_instructions_and_literal_are_required(self):
        for va in [v for v, _ in credential.WITNESSES]+[0xfffffe00073b0995]:
            data = bytearray(self.image.data)
            for _, base, _, offset, size in self.image.segments:
                if base <= va < base+size:
                    data[offset+va-base] ^= 1
                    break
            altered = SimpleNamespace(data=data, segments=self.image.segments)
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                credential.software_cmdline(altered, Tree(), '-v')

    def test_unbacked_image_is_rejected(self):
        for segments in ([], self.image.segments*2):
            with self.assertRaises(ValueError):
                credential.software_cmdline(SimpleNamespace(data=self.image.data, segments=segments), Tree(), '-v')


if __name__ == '__main__':
    unittest.main()
