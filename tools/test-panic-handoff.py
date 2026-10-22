#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb

class PanicHandoff(unittest.TestCase):
    def test_reserved_page(self):
        pa,va,size=xb.panic_state_reservation(xb.SCRATCH_PA-0x4000)
        self.assertEqual((pa+size,size),(xb.SCRATCH_PA,16384))
        self.assertEqual(va,xb.APERTURE_VA+pa-xb.PHYS_BASE)
        self.assertFalse(pa%16384)
        for overrun in (1,4096,16384):
            with self.assertRaises(ValueError):xb.panic_state_reservation(pa+overrun)

    def test_schema_and_abi(self):
        row=next(f for f in xb.handoff_fields() if f[0]=='panic flag ptr')
        self.assertEqual(row[1:3],(0x198,8))
        self.assertFalse(xb.check_handoff_overlap())
        # New field is within the 0x358 bytes copied by the shipped kernel.
        self.assertLessEqual(row[1]+row[2],0x358)
        # 1148 plus the appended struct early_stop_params (compat/early-stop.h).
        self.assertEqual(xb.PARAMS_WORDS,1154)

if __name__=='__main__':unittest.main()
