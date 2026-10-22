# SPDX-License-Identifier: MIT
"""Bind the grouped scan counters to complete audited preparations."""
from pathlib import Path
import runpy
import struct
import unittest
decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_user_zero_groups']
class ZeroGroupCapture(unittest.TestCase):
    def test_valid(self):
        row=decode(struct.pack('<2Q',6400,5300),100)
        self.assertEqual(row['empty_fraction'],5300/6400)
    def test_size(self):
        for n in (0,15,17):
            with self.assertRaises(ValueError):decode(bytes(n),100)
    def test_binding(self):
        for groups in (0,6399,6401):
            with self.assertRaises(ValueError):decode(struct.pack('<2Q',groups,5300),100)
        with self.assertRaises(ValueError):decode(struct.pack('<2Q',64,63),0)
    def test_paths(self):
        for empty in (0,6400,6401):
            with self.assertRaises(ValueError):decode(struct.pack('<2Q',6400,empty),100)
if __name__=='__main__':unittest.main()
