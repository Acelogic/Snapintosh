#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
import struct
import unittest
from pathlib import Path

M=runpy.run_path(str(Path(__file__).with_name('process-initial-arguments.py')))

class InitialArguments(unittest.TestCase):
    def setUp(self):
        self.proc=0xfffffe1000000000;self.pid=54;self.top=0x16ffff000
        self.words=dict(M['WITNESSES'])
        for offset in range(0,len(M['PREFIX']),4):
            self.words[0xfffffe00070be0b2+offset]=int.from_bytes(M['PREFIX'][offset:offset+4],'little')
        self.identity=struct.pack('<I',self.pid)
        self.fixture([b'xpcproxy',b'com.apple.kernelmanagerd'])
    def fixture(self,args,padding=3):
        self.block=M['PREFIX']+b'/usr/libexec/xpcproxy\0'+b'\0'*padding+b''.join(a+b'\0' for a in args)
        # Deliberately no environment bytes in the fixture: even one read past
        # the last argument must fail, although the declared stack range extends.
        size=len(self.block)+128;self.begin=self.top-size
        self.fields=struct.pack('<IiQ',size,len(args),self.top)
        self.reads=[]
    def kernel(self,address,size):
        if (address,size)==(self.proc+0x60,4):return self.identity
        if (address,size)==(self.proc+M['FIELDS'],16):return self.fields
        raise ValueError('unexpected kernel read')
    def user(self,address,size):
        self.reads.append((address,size));offset=address-self.begin
        if not 0<=offset<offset+size<=len(self.block):raise ValueError('environment or absent user data')
        return self.block[offset:offset+size]
    def reader(self,kernel=None):return M['make_reader'](kernel or self.kernel,self.words.__getitem__)
    def collect(self):return self.reader()(self.proc,self.pid,self.user)
    def test_early_launcher_and_no_environment_read(self):
        d=self.collect();self.assertEqual(d['argv'],['xpcproxy','com.apple.kernelmanagerd'])
        self.assertEqual(d['executable'],'/usr/libexec/xpcproxy')
        self.assertEqual(d['alignment_padding'],3)
        self.assertEqual(max(a+n for a,n in self.reads),self.begin+len(self.block))
    def test_all_instruction_and_literal_witnesses(self):
        for address in self.words:
            self.words[address]^=1
            with self.subTest(address=hex(address)),self.assertRaises(ValueError):self.reader()
            self.words[address]^=1
    def test_empty_later_argument_and_page_crossing(self):
        self.top=0x1700040c0;self.fixture([b'xpcproxy',b'',b'x'*120],0)
        self.assertNotEqual(self.begin>>14,(self.begin+len(self.block)-1)>>14)
        self.assertEqual(self.collect()['argv'],['xpcproxy','','x'*120])
    def test_counts_sizes_and_stack_bounds(self):
        good=self.fields;size,argc,top=struct.unpack('<IiQ',good)
        for fields in [(size,0,top),(size,65,top),(size,-1,top),(0,argc,top),
                       ((1<<20)+1,argc,top),(size,argc,0),(size,argc,1<<47),(size,argc,top+1)]:
            self.fields=struct.pack('<IiQ',*fields)
            with self.subTest(fields=fields),self.assertRaises(ValueError):self.collect()
        self.fields=good
    def test_identity_and_process_bounds(self):
        for proc in [0,self.proc+1,1<<64]:
            with self.subTest(proc=proc),self.assertRaises(ValueError):self.reader()(proc,self.pid,self.user)
        for pid in [0,257,self.pid+1]:
            with self.subTest(pid=pid),self.assertRaises(ValueError):self.reader()(self.proc,pid,self.user)
    def test_changed_metadata_and_short_reads(self):
        calls=0
        def changed(a,n):
            nonlocal calls
            value=self.kernel(a,n);calls+=1
            return bytes([value[0]^1])+value[1:] if calls==4 else value
        with self.assertRaisesRegex(ValueError,'changed'):self.reader(changed)(self.proc,self.pid,self.user)
        with self.assertRaises(ValueError):self.reader()(self.proc,self.pid,lambda a,n:self.user(a,n)[:-1])
    def test_prefix_padding_path_and_string_limit(self):
        for args,padding in [([b'a'*512],0),([b'xpcproxy'],16)]:
            self.fixture(args,padding)
            with self.assertRaises(ValueError):self.collect()
        self.fixture([b'xpcproxy']);self.block=b'X'+self.block[1:]
        with self.assertRaisesRegex(ValueError,'prefix'):self.collect()
        self.fixture([b'xpcproxy']);self.block=self.block.replace(b'/usr',b'xusr')
        with self.assertRaisesRegex(ValueError,'absolute'):self.collect()
    def test_total_budget_and_utf8(self):
        self.fixture([b'x'*511]*20)
        with self.assertRaisesRegex(ValueError,'budget'):self.collect()
        self.fixture([b'xpcproxy',b'\xff'])
        with self.assertRaises(UnicodeError):self.collect()

if __name__=='__main__':unittest.main()
