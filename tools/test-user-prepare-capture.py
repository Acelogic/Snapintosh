#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_user_prepare']

class UserPrepareCapture(unittest.TestCase):
    def test_qualified_counters(self):
        r=decode(struct.pack('<7Q',128,128,2,0,0,768,512),128)
        self.assertEqual(r['mean_source_tables'],6)
        self.assertEqual(r['mean_private_tables'],4)
    def test_corruption_and_unexercised_paths(self):
        good=[128,128,2,0,0,768,512]
        for index,value in [(0,127),(1,127),(2,1),(3,1),(4,1),(5,127),
                            (5,8192*128+1),(6,127),(6,128*128+1)]:
            with self.subTest(index=index,value=value):
                bad=good.copy();bad[index]=value
                with self.assertRaises(ValueError):decode(struct.pack('<7Q',*bad),128)
        with self.assertRaises(ValueError):decode(struct.pack('<7Q',*good),127)
        with self.assertRaises(ValueError):decode(struct.pack('<7Q',32,32,0,0,0,192,128),32)
        with self.assertRaises(ValueError):decode(bytes(55),128)

if __name__=='__main__':unittest.main()
