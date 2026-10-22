# SPDX-License-Identifier: MIT
"""Bind bounded canonical table reads to the full-walk preparation counters."""
from pathlib import Path
import runpy
import struct
import unittest
decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_user_table_reads']
class TableReadCapture(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(decode(struct.pack('<3Q',1048,1048,0),1048),
                         {'calls':1048,'complete':1048,'errors':0})
    def test_bad_geometry(self):
        for raw in [b'',b'\0'*23,b'\0'*25]:
            with self.assertRaises(ValueError):decode(raw,1048)
    def test_counter_mismatch(self):
        for values in [(1047,1048,0),(1048,1047,0),(1048,1048,1),(0,0,0)]:
            with self.assertRaises(ValueError):decode(struct.pack('<3Q',*values),1048)
    def test_empty(self):
        with self.assertRaises(ValueError):decode(b'\0'*24,0)
if __name__=='__main__':unittest.main()
