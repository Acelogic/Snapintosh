# SPDX-License-Identifier: MIT
"""Reject inconsistent user-publication observations before claiming qualification."""
from pathlib import Path
import runpy
import struct
import unittest

decode=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))['decode_user_publish']
class PublicationCapture(unittest.TestCase):
    def setUp(self):
        self.values=[100,100,300,120,180,0]
        self.root={'published':200,'pages_noted':400}
    def packed(self):return struct.pack('<6Q',*self.values)
    def test_valid(self):
        self.assertEqual(decode(self.packed(),100,self.root)['skipped_fraction'],0.6)
    def test_bad_shape(self):
        for raw in [b'',self.packed()[:-1],self.packed()+b'\0']:
            with self.assertRaises(ValueError):decode(raw,100,self.root)
    def test_each_counter(self):
        for i in range(6):
            with self.subTest(field=i):
                original=self.values[i];self.values[i]+=1
                with self.assertRaises(ValueError):decode(self.packed(),100,self.root)
                self.values[i]=original
    def test_total_noted_bound(self):
        with self.assertRaises(ValueError):decode(self.packed(),100,dict(self.root,pages_noted=319))
    def test_empty_and_unexercised(self):
        for values,calls in [([0]*6,0),([100,100,100,100,0,0],100),
                             ([100,100,100,0,100,0],100),([100,100,13000,120,12880,0],100),
                             ([100,100,99,20,79,0],100)]:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):decode(struct.pack('<6Q',*values),calls,self.root)
if __name__=='__main__':unittest.main()
