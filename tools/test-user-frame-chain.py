#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
from pathlib import Path
import struct
import unittest

C=runpy.run_path(str(Path(__file__).with_name('user-frame-chain.py')))['collect']


class UserFrames(unittest.TestCase):
    def test_pac_lookup_and_null_parent(self):
        rows={0x1000:struct.pack('<2Q',0x1100,0x1234800180010040),
              0x1100:struct.pack('<2Q',0,0x180010080),
              0x18001003c:bytes.fromhex('01000094e00300aa')+bytes(56),
              0x18001007c:bytes.fromhex('01000094e10300aa')+bytes(56)}
        reads=[]
        def read(address,size):
            reads.append((address,size))
            if address not in rows:raise ValueError('unmapped')
            return rows[address]
        result=C(read,0x1000)
        self.assertEqual(result['end'],'null parent')
        self.assertEqual(result['frames'][0]['lookup_pc'],'0x180010040')
        self.assertFalse(result['frames'][0]['return_address_authenticated'])
        self.assertEqual(reads,[(0x1000,16),(0x18001003c,64),(0x1100,16),(0x18001007c,64)])

    def test_instruction_read_stays_in_page(self):
        reads=[]
        def read(address,size):
            reads.append((address,size))
            return struct.pack('<2Q',0,0x180014000) if address==0x1000 else bytes(size)
        row=C(read,0x1000)['frames'][0]
        self.assertEqual(reads,[(0x1000,16),(0x180013ffc,4)])
        self.assertEqual(row['return_site_va'],'0x180013ffc')

    def test_bad_entries_never_read(self):
        for address in (0,1,0xfffffe0000000000,1<<47):
            self.assertEqual(C(lambda *_:self.fail('unexpected read'),address)['frames'],[])

    def test_cycle_and_distance_bound(self):
        for parent in (0x1000,0xff0,0x6000):
            result=C(lambda address,size:struct.pack('<2Q',parent,0),0x1000)
            self.assertEqual(len(result['frames']),1)
            self.assertEqual(result['end'],'non-monotonic or distant parent')

    def test_missing_memory_and_frame_limit(self):
        def missing(*_):raise ValueError('unmapped frame')
        self.assertEqual(C(missing,0x1000)['end'],'unmapped frame')
        def next_(address,size):return struct.pack('<2Q',address+0x10,0)
        self.assertEqual(len(C(next_,0x1000,3)['frames']),3)
        for bound in (0,33):
            with self.assertRaises(ValueError):C(next_,0x1000,bound)


if __name__=='__main__':unittest.main()
