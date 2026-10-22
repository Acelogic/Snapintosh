# SPDX-License-Identifier: MIT
"""Reject incomplete or unbound private-sync reader counters."""
from pathlib import Path
import runpy
import struct
import unittest
decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_view_table_reads']
class ViewReaderCapture(unittest.TestCase):
    def test_valid(self):
        row=decode(struct.pack('<6Q',100,100,1700,1700,1700,0),100)
        self.assertEqual(row['tables'],1700)
    def test_bad_size(self):
        for n in (0,47,49):
            with self.assertRaises(ValueError):decode(bytes(n),100)
    def test_bad_counts(self):
        for index in range(6):
            row=[100,100,1700,1700,1700,0];row[index]+=1
            with self.assertRaises(ValueError):decode(struct.pack('<6Q',*row),100)
    def test_bounds(self):
        for tables in (0,99,12801):
            with self.assertRaises(ValueError):decode(struct.pack('<6Q',100,100,tables,tables,tables,0),100)
        with self.assertRaises(ValueError):decode(bytes(48),0)
if __name__=='__main__':unittest.main()
