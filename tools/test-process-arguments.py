#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import copy
import hashlib
import json
from pathlib import Path
import runpy
import struct
import tempfile
import unittest

M=runpy.run_path(str(Path(__file__).with_name('process-arguments.py')))

class ProcessArguments(unittest.TestCase):
    def setUp(self):
        self.mem={};self.slide=0x4000;self.argc=0x60000000
        self.argvptr=0x60000008;self.vector=0x60010000;self.string=0x60023ff4
        self.put(M['ACCESSOR']+self.slide,M['ACCESSOR_BYTES'])
        self.q(M['ARGC_SLOT']+self.slide,self.argc)
        self.q(M['ARGV_SLOT']+self.slide,self.argvptr)
        self.put(self.argc,struct.pack('<I',2));self.q(self.argvptr,self.vector)
        self.q(self.vector,self.string);self.q(self.vector+8,self.string+0x100)
        self.q(self.vector+16,0)
        self.put(self.string,b'xpcproxy\0')
        self.put(self.string+0x100,b'com.apple.bsd.dirhelper\0')
    def put(self,address,data):self.mem.update({address+i:b for i,b in enumerate(data)})
    def q(self,address,value):self.put(address,struct.pack('<Q',value))
    def read(self,address,size):
        if address<self.vector and any(address+i not in self.mem for i in range(size)):
            raise ValueError('absent fixture data')
        return bytes(self.mem.get(address+i,0) for i in range(size))
    def test_arguments_and_page_boundary(self):
        def read(address,size):
            if address==self.string:self.assertLessEqual(size,12)
            return self.read(address,size)
        d=M['collect'](read,self.slide)
        self.assertEqual(d['argv'],['xpcproxy','com.apple.bsd.dirhelper'])
        self.assertEqual(d['argc'],2);self.assertLess(d['bytes_read'],1024)
    def test_every_accessor_word(self):
        for i in range(6):
            old=dict(self.mem);self.mem[M['ACCESSOR']+self.slide+4*i]^=1
            with self.subTest(word=i),self.assertRaisesRegex(ValueError,'accessor'):
                M['collect'](self.read,self.slide)
            self.mem=old
    def test_invalid_counts_and_pointers(self):
        for n in [0,65,0xffffffff]:
            self.put(self.argc,struct.pack('<I',n))
            with self.subTest(argc=n),self.assertRaises(ValueError):M['collect'](self.read,self.slide)
        self.put(self.argc,struct.pack('<I',2))
        for p in [0,1,(1<<47),0xffff000060010000]:
            self.q(self.argvptr,p)
            with self.subTest(pointer=p),self.assertRaises(ValueError):M['collect'](self.read,self.slide)
    def test_short_read_termination_and_limits(self):
        with self.assertRaises(ValueError):M['collect'](lambda a,n:self.read(a,n)[:-1],self.slide)
        self.q(self.vector+16,self.string)
        with self.assertRaises(ValueError):M['collect'](self.read,self.slide)
        self.q(self.vector+16,0);self.put(self.string,b'a'*512)
        with self.assertRaises(ValueError):M['collect'](self.read,self.slide)
        for slide in [-1,1,1<<32]:
            with self.subTest(slide=slide),self.assertRaises(ValueError):M['collect'](self.read,slide)
    def test_total_budget(self):
        self.put(self.argc,struct.pack('<I',64))
        for i in range(64):
            p=0x60040000+i*512;self.q(self.vector+i*8,p);self.put(p,b'a'*511+b'\0')
        self.q(self.vector+64*8,0)
        with self.assertRaisesRegex(ValueError,'budget'):M['collect'](self.read,self.slide)

class HintBindings(unittest.TestCase):
    def test_capture_and_process_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);origin=dict(pid=77,name='xpcproxy',task='0xfffffe0010000000',
                user_address_space={'root':'0x900000000'},threads=[dict(tid=982,
                saved_user_state=dict(pc='0x190000000',instruction_hex='ab'*64))])
            capture=dict(kernel_sha256='kernel',monitor_sha256='monitor',user_processes=dict(processes=[origin]))
            raw=json.dumps(capture).encode();(root/'capture.json').write_bytes(raw)
            data=dict(capture='capture.json',capture_sha256=hashlib.sha256(raw).hexdigest(),
                kernel_sha256='kernel',monitor_sha256='monitor',processes=[dict(pid=77,name='xpcproxy',
                address_space=origin['user_address_space'],code_match=dict(matched_bytes=64,tid=982,
                    runtime_pc=0x190000000,kind='saved_pc',slide=0x4000))])
            path=root/'sites.json'
            def run(d):
                path.write_text(json.dumps(d));return M['load_hints'](path,root,'kernel','monitor')
            self.assertEqual(run(data)[77]['witness'],b'\xab'*64)
            for key in ['capture_sha256','kernel_sha256','monitor_sha256']:
                bad=copy.deepcopy(data);bad[key]='changed'
                with self.subTest(key=key),self.assertRaises(ValueError):run(bad)
            for key,value in [('name','dirhelper'),('address_space',{}),('pid',76)]:
                bad=copy.deepcopy(data);bad['processes'][0][key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):run(bad)
            for key,value in [('matched_bytes',63),('tid',983),('runtime_pc',0x190000004),('kind','frame_return_site')]:
                bad=copy.deepcopy(data);bad['processes'][0]['code_match'][key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):run(bad)

if __name__=='__main__':unittest.main()
