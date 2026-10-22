#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import unittest
M=runpy.run_path(str(Path(__file__).with_name('inspect-user-exec-contract.py')))
class Contract(unittest.TestCase):
    def test_selected_shipped_contract(self):
        r=M['inspect'](M['ROOT']/'downloads/extracted/j700ap/sptm.t8140.release')
        self.assertEqual(r['types'][14]['selectors'],[11,13,15])
    def test_every_witness_bit_is_required(self):
        original={M['BASE']|p:v for p,v in M['WORDS']}
        for pa,word in original.items():
            for bit in range(32):
                changed=dict(original);changed[pa]=word^(1<<bit)
                with self.subTest(pa=hex(pa),bit=bit):
                    with self.assertRaises(ValueError):M['require_words'](changed.__getitem__)
if __name__=='__main__':unittest.main()
