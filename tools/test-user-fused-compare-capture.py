#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy,struct,unittest
from pathlib import Path
decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_view_store_compare']
class FusedCompareCapture(unittest.TestCase):
    def test_valid_and_maximum(self):
        for tables in (6,24,768):
            words=512*tables
            row=decode(struct.pack('<7Q',1,1,tables,words,words-3,3,0),1,tables,copies=6)
            self.assertEqual(row['tables'],tables)
    def test_corrupt_fields(self):
        original=[2,2,48,24576,24564,12,0]
        for i in range(7):
            data=original[:];data[i]+=1
            with self.assertRaises(ValueError):decode(struct.pack('<7Q',*data),2,48,copies=6)
    def test_bounds(self):
        for tables in (0,1,5,7,769,774):
            words=512*tables
            with self.assertRaises(ValueError):decode(struct.pack('<7Q',1,1,tables,words,max(words-1,0),1,0),1,tables,copies=6)
        for copies in (0,2,7):
            with self.assertRaises(ValueError):decode(struct.pack('<7Q',1,1,24,12288,12285,3,0),1,24,copies=copies)
if __name__=='__main__':unittest.main()
