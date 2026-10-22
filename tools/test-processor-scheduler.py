# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest
api=runpy.run_path(str(Path(__file__).with_name('processor-scheduler.py')))
class ProcessorScheduler(unittest.TestCase):
    def setUp(self):
        self.words=dict(api['WITNESSES']);self.mem={}
        self.topology=dict(num_cpus=6,cpu_data_entries=[])
        self.mem[api['REQUESTED']]=struct.pack('<3Q',0x3f,0x3f,0xffffffffffffffff)
        self.mem[api['EFFECTIVE']]=struct.pack('<Q',0xf)
        for cpu in range(6):
            at=0xfffffe0100000000+cpu*0x1000
            self.topology['cpu_data_entries'].append(dict(index=cpu,data_va=hex(at-api['PROCESSOR_DELTA'])))
            raw=bytearray(0x68);struct.pack_into('<I',raw,0,6 if cpu<4 else 4)
            raw[4]=int(cpu<4);struct.pack_into('<I',raw,0x64,cpu);self.mem[at]=bytes(raw)
    def read(self,at,size):return self.mem[at][:size]
    def collect(self):return api['collect'](self.topology,self.read,self.words.__getitem__)
    def test_requested_and_effective_are_distinct(self):
        r=self.collect();self.assertEqual(r['requested'],'0x3f');self.assertEqual(r['effective'],'0xf')
        self.assertEqual([p['cpu'] for p in r['processors'] if not p['recommended']],[4,5])
    def test_witnesses(self):
        for at,word in api['WITNESSES']:
            self.words[at]=word^1
            with self.assertRaisesRegex(ValueError,'witness'):self.collect()
            self.words[at]=word
    def test_mask_binding(self):
        self.mem[api['EFFECTIVE']]=struct.pack('<Q',0x3f)
        with self.assertRaisesRegex(ValueError,'recommendation'):self.collect()
        self.mem[api['EFFECTIVE']]=struct.pack('<Q',0x40)
        with self.assertRaisesRegex(ValueError,'mask'):self.collect()
        self.mem[api['EFFECTIVE']]=struct.pack('<Q',0xf)
        self.mem[api['REQUESTED']]=struct.pack('<3Q',0x3f,0xf,0x3f)
        with self.assertRaisesRegex(ValueError,'mask'):self.collect()
    def test_identity_and_short_read(self):
        at=0xfffffe0100000000;raw=bytearray(self.mem[at]);struct.pack_into('<I',raw,0x64,5);self.mem[at]=bytes(raw)
        with self.assertRaisesRegex(ValueError,'identity'):self.collect()
        self.mem[at]=b''
        with self.assertRaisesRegex(ValueError,'short'):self.collect()
    def test_duplicate_cpu_and_pointer(self):
        self.topology['cpu_data_entries'][1]['index']=0
        with self.assertRaisesRegex(ValueError,'coverage'):self.collect()
        self.topology['cpu_data_entries'][1]['index']=1
        self.topology['cpu_data_entries'][1]['data_va']=self.topology['cpu_data_entries'][0]['data_va']
        with self.assertRaisesRegex(ValueError,'geometry'):self.collect()
if __name__=='__main__':unittest.main()
