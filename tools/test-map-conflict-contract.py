#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import unittest
A=runpy.run_path(str(Path(__file__).with_name('inspect-map-conflict-contract.py')))
class Contract(unittest.TestCase):
    def test_images(self):self.assertEqual(A['inspect']()['guest_result'],6)
    def test_instruction_mutations(self):
        for name,base in [('SPTM_WORDS',0xfffffff000000000),('KERNEL_WORDS',0xfffffe0000000000)]:
            words=A[name];expected={base|pc:word for pc,word in words}
            for pc,word in words:
                for bit in range(32):
                    changed=dict(expected);changed[base|pc]=word^(1<<bit)
                    with self.subTest(pc=pc,bit=bit),self.assertRaises(ValueError):
                        A['require_words'](changed.__getitem__,words,base)
if __name__=='__main__':unittest.main()
