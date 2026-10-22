#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
api=runpy.run_path(str(ROOT/'tools/stock-warm-entry.py'))


class WarmEntry(unittest.TestCase):
    def tables(self):
        values={0x100000:0x101003,0x101000:(1<<54)|0x7fd,
                0x101008:0x102003,0x102000:(1<<54)|0x2007ff,
                0x102008:0x2017ff}
        return {p:struct.pack('<512Q',*(values.get(p+i*8,0) for i in range(512)))
                for p in (0x100000,0x101000,0x102000)}

    def clone(self,tables=None,limit=0x310000,executable=0x200000):
        tables=self.tables() if tables is None else tables
        return api['clone_readonly_stage2'](lambda pa,n:tables[pa],0x100000,
            0x100000,0x103000,0x300000,limit,executable)

    def test_single_executable_page_and_no_writes(self):
        source=self.tables();before=source.copy()
        root,copies,originals=self.clone(source)
        self.assertEqual(root,0x300000)
        self.assertEqual(originals,before);self.assertEqual(source,before)
        self.assertEqual(len(copies),3)
        words={pa:struct.unpack('<512Q',data) for pa,data in copies.items()}
        self.assertEqual(words[root][0],0x301003)
        self.assertEqual(words[0x301000][1],0x302003)
        leaves=[words[0x301000][0],*words[0x302000][:2]]
        self.assertTrue(all(x&(1<<6) and not x&(1<<7) for x in leaves))
        self.assertEqual([bool(x&(1<<54)) for x in leaves],[True,False,True])

    def test_rejects_unowned_alias_cycle_oversize_and_wide_execution(self):
        for address,value in [(0x100000,0x100003),(0x100008,0x101003),
                              (0x100000,0x104003),(0x102000,0x2027ff),
                              (0x102000,0x20073f),(0x100200,1)]:
            tables=self.tables();page=address&~4095;raw=bytearray(tables[page])
            struct.pack_into('<Q',raw,address&4095,value);tables[page]=bytes(raw)
            with self.assertRaises(ValueError):self.clone(tables)
        with self.assertRaises(ValueError):self.clone(limit=0x301000)
        with self.assertRaises(ValueError):self.clone(executable=0)
        with self.assertRaises(ValueError):self.clone(executable=0x202000)
        with self.assertRaises(ValueError):self.clone(limit=0x300001)

    def test_exact_hardware_boundary_witness(self):
        target=dict(va=0xfffffe03119ba730,intstack=0xfffffe0001000000,
                    excepstack=0xfffffe0001004000)
        reset=api['RESET'];inputs=(api['ENTRY'],1,0x80000001,0x123000,0x456000,
                                  0x400000011,0xff,0x30d01985,7<<48|0x300000,
                                  0x4355c,0xfffffe000b86c000,reset,target['va'],
                                  target['intstack'],target['excepstack'],0x8c8000000)
        witness=dict(reset=hex(reset),reset_pa=hex(0x8c9000f5c),cpu1=target)
        state=[0]*128
        state[0]=4;state[1]=8;state[7]=(0x20<<26)|0xf
        state[16]=reset;state[17]=0x3c4;state[30]=6;state[64:80]=inputs
        state[80:102]=(target['va'],0,reset,reset,6,0x80000001,16,0,target['va'],0,
                       target['intstack'],target['excepstack'],0,0,0,reset,0,
                       inputs[2],inputs[8],inputs[3],inputs[5],inputs[7])
        self.assertTrue(api['passed'](tuple(state),inputs,witness))
        for index in [0,1,6,7,16,17,30,31,*range(64,80),*range(80,89),
                      90,91,92,93,95,97,98,99,100,101]:
            bad=state.copy();bad[index]^=1
            # FSC level is diagnostic; change its class rather than its level.
            if index==7:bad[index]=0x24<<26|0xf
            self.assertFalse(api['passed'](tuple(bad),inputs,witness),index)


if __name__=='__main__':unittest.main()
