#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the shipped-image loader's aperture setup and call interception."""
import contextlib
import io
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'probes'))
import xnuboot as xb

class LoaderSPRR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xb.configure_guest('j700ap-26A428-no-clpc')
        xb.place(0x8c0000000,guest_span=8192<<20)
        with contextlib.redirect_stdout(io.StringIO()):cls.b=xb.build(xb.DEFAULT_KERNELCACHE)
    def test_required_monitor_calls_survive_descriptor_initialization(self):
        image=self.b['image']
        self.assertEqual(self.b['stub_pa'],xb.monitor_pages(image,image.data))
        self.assertEqual(len(self.b['stub_pa']),5)
        self.assertIn((xb.IMAGE_PA+0xfffffe000c2640ac-image.vmin)&~4095,self.b['stub_pa'])
    def test_rozone_descriptor_is_initialized(self):
        pa=self.b['tables'].walk(xb.GUEST_PROFILE.frame_type_info_va+25*144+0x79)
        self.assertEqual(next(d[pa-base] for base,d in self.b['chunks'].items()
                              if base<=pa<base+len(d)),2)
    def test_wrong_or_empty_scan_buffer_refused(self):
        image=self.b['image']
        for data in (image.data[:1024],bytes(len(image.data))):
            with self.assertRaises(ValueError):xb.monitor_pages(image,data)

if __name__=='__main__':unittest.main()
