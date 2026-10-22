#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import unittest
A=runpy.run_path(str(Path(__file__).with_name('inspect-panic-contract.py')))
class PanicContract(unittest.TestCase):
    def test_images(self):self.assertEqual(A['inspect']()['handoff_offset'],'0x198')
    def test_single_bit_mutations(self):
        for label in ('KERNEL_WORDS','SPTM_WORDS'):
            original=A[label]
            for va in original:
                for bit in range(32):
                    changed=original.copy();changed[va]^=1<<bit
                    with self.subTest(va=hex(va),bit=bit),self.assertRaises(ValueError):
                        A['require_words'](changed.__getitem__,original)
if __name__=='__main__':unittest.main()
