# SPDX-License-Identifier: MIT
from pathlib import Path
import copy
import runpy
import struct
import unittest
collect=runpy.run_path(str(Path(__file__).with_name('table-density.py')))['collect']
BASE=0xae1340000
class DensityTests(unittest.TestCase):
    def setUp(self):
        self.pages={BASE:bytearray(4096),BASE+4096:bytearray(4096)}
        for index,value in [(0,3),(7,2),(8,1),(511,2)]:struct.pack_into('<Q',self.pages[BASE],8*index,value)
        self.processes=[dict(pid=54,name='kernelmanagerd',user_address_space={'root':'0x10000'})]
        self.roots=[dict(root='0x10000',canonical=hex(BASE),canonical_table_pages=[hex(BASE),hex(BASE+4096)],private_table_pages=[hex(BASE+8192)])]
        self.reads=0
    def read(self,pa,size):
        self.assertEqual(size,4096);self.reads+=1;return self.pages[pa]
    def run_capture(self):
        return collect(self.processes,['kernelmanagerd'],self.roots,BASE,BASE+16384,self.read)
    def test_zero_groups_require_all_eight_words_zero(self):
        result=self.run_capture();row=result['processes'][0]
        self.assertEqual((row['words'],row['zero_words'],row['groups_of_eight'],row['zero_groups_of_eight']),(1024,1020,128,125))
        self.assertEqual((self.reads,result['bytes_read']),(2,8192))
    def test_alias_duplicate_and_bounds_refused_before_reads(self):
        for pages in [[BASE,BASE+8192],[BASE,BASE],[BASE,BASE-4096],[BASE,BASE+16384],[BASE,BASE+1],[]]:
            self.roots[0]['canonical_table_pages']=list(map(hex,pages))
            with self.assertRaises(ValueError):self.run_capture()
            self.assertEqual(self.reads,0)
    def test_missing_or_ambiguous_process(self):
        self.processes.append(copy.deepcopy(self.processes[0]))
        with self.assertRaises(ValueError):self.run_capture()
        self.processes=[]
        with self.assertRaises(ValueError):self.run_capture()
    def test_unbound_root(self):
        self.processes[0]['user_address_space']['root']='0x20000'
        with self.assertRaises(ValueError):self.run_capture()
    def test_short_read(self):
        self.pages[BASE]=self.pages[BASE][:-1]
        with self.assertRaisesRegex(ValueError,'short'):self.run_capture()
if __name__=='__main__':unittest.main()
