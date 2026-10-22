# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy,struct,unittest
decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_view_store_compare']
class StoreCompareCapture(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(decode(struct.pack('<7Q',100,100,400,204800,204700,100,0),100,400)['changed'],100)
    def test_corrupt_fields_and_bindings(self):
        good=[100,100,400,204800,204700,100,0]
        for i in range(7):
            bad=good.copy();bad[i]+=1
            with self.subTest(field=i),self.assertRaises(ValueError):decode(struct.pack('<7Q',*bad),100,400)
        for calls,tables in [(99,400),(100,401),(0,0),(100,99),(100,12801)]:
            with self.subTest(calls=calls,tables=tables),self.assertRaises(ValueError):decode(struct.pack('<7Q',*good),calls,tables)
        for i in (4,5):
            bad=good.copy();bad[i]=0;bad[9-i]=204800
            with self.assertRaises(ValueError):decode(struct.pack('<7Q',*bad),100,400)
    def test_short_or_oversized(self):
        for n in (0,55,57):
            with self.assertRaises(ValueError):decode(bytes(n),100,400)
if __name__=='__main__':unittest.main()
