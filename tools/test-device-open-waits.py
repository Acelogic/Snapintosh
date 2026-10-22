# SPDX-License-Identifier: MIT
import runpy
import struct
import unittest
from pathlib import Path

m=runpy.run_path(str(Path(__file__).with_name('device-open-waits.py')))
HEAD=m['HEAD'];WAIT=m['WAIT_RETURN'];WORDS=m['WITNESSES']
NODE=0xfffffe1f504ab670;OWNER=0xfffffe2412345000;WAITER=OWNER+0x1000

class Queue(unittest.TestCase):
    def setUp(self):
        self.memory={HEAD:struct.pack('<2Q',NODE,NODE),
            NODE:struct.pack('<3Q4I',0,HEAD,OWNER,0x00000000,0x2000,1,0)}
        self.words=dict(WORDS)
        self.processes=[dict(pid=1,name='launchd',threads=[dict(thread=hex(OWNER),tid=11,
            wait_event='0x0',on_cpu=[0],frames=[])]),
            dict(pid=54,name='xpcproxy',threads=[dict(thread=hex(WAITER),tid=914,
                wait_event=hex(NODE),on_cpu=[],frames=[dict(raw_lr=hex(WAIT))])])]
    def run_reader(self,read=None):
        return m['collect'](read or (lambda a,n:self.memory[a][:n]),self.words.__getitem__,[],self.processes)
    def test_owner_and_waiter(self):
        row=self.run_reader()['records'][0]
        self.assertEqual(row['owner']['pid'],1)
        self.assertEqual([x['pid'] for x in row['observed_sleepers']],[54])
        self.assertEqual(row['waiters'],1)
    def test_unknown_and_unqualified(self):
        self.processes[0]['threads']=[]
        self.processes[1]['threads'][0]['frames']=[]
        row=self.run_reader()['records'][0]
        self.assertIsNone(row['owner']);self.assertFalse(row['observed_sleepers'])
        self.assertEqual(len(row['unqualified_event_matches']),1)
    def test_instruction_witnesses(self):
        for address in WORDS:
            self.words[address]^=1
            with self.assertRaisesRegex(ValueError,'instruction witness'):self.run_reader()
            self.words[address]^=1
    def test_empty_and_second_record(self):
        self.memory[HEAD]=struct.pack('<2Q',0,HEAD)
        self.assertEqual(self.run_reader()['records'],[])
        second=NODE+0x1000
        self.memory[HEAD]=struct.pack('<2Q',NODE,second)
        self.memory[NODE]=struct.pack('<3Q4I',second,HEAD,OWNER,0,0x2000,1,0)
        self.memory[second]=struct.pack('<3Q4I',0,NODE,WAITER,1,0x2000,0,0)
        self.assertEqual(len(self.run_reader()['records']),2)
    def test_bad_queue(self):
        original=self.memory[NODE]
        for words in [(NODE,HEAD,OWNER,0,0x2000,1,0),
                      (0,NODE,OWNER,0,0x2000,1,0),
                      (0,HEAD,0,0,0x2000,1,0),
                      (0,HEAD,OWNER+1,0,0x2000,1,0),
                      (0,HEAD,OWNER,0,0x2000,0,0)]:
            self.memory[NODE]=struct.pack('<3Q4I',*words)
            with self.assertRaises(ValueError):self.run_reader()
        self.memory[NODE]=original
        self.memory[HEAD]=struct.pack('<2Q',NODE,HEAD)
        with self.assertRaisesRegex(ValueError,'tail'):self.run_reader()
    def test_short_and_unstable(self):
        with self.assertRaisesRegex(ValueError,'short'):
            self.run_reader(lambda a,n:self.memory[a][:n-1])
        calls={}
        def read(a,n):
            calls[a]=calls.get(a,0)+1;v=self.memory[a]
            if a==NODE and calls[a]>1:v=v[:-1]+bytes([v[-1]^1])
            return v[:n]
        with self.assertRaisesRegex(ValueError,'changed'):self.run_reader(read)
    def test_duplicate_identity(self):
        self.processes.append(self.processes[0])
        with self.assertRaisesRegex(ValueError,'duplicate'):self.run_reader()
    def tty_fixture(self):
        tty=0xfffffe29e5c9ca00;fp=0xfffffe4c27cbb940
        self.words.update(m['TTY_WITNESSES'])
        owner=self.processes[0]['threads'][0]
        owner['wait_event']=hex(tty+8)
        owner['frames']=[dict(fp=hex(fp),raw_lr=hex(m['TTY_RETURN']))]
        self.memory[fp-16]=struct.pack('<2Q',tty,OWNER)
        self.memory[tty]=struct.pack('<2Q',0,0x80000000|123)
        self.memory[tty+0x1e8]=struct.pack('<Q',WAITER)
        self.memory[WAITER+0x518]=struct.pack('<I',123)
        return tty,fp
    def test_tty_owner(self):
        self.tty_fixture();row=self.run_reader()['records'][0]['tty_wait']
        self.assertTrue(row['owner_qualified']);self.assertEqual(row['owner']['pid'],54)
    def test_tty_stale_owner(self):
        self.tty_fixture();self.memory[WAITER+0x518]=struct.pack('<I',124)
        row=self.run_reader()['records'][0]['tty_wait']
        self.assertFalse(row['owner_qualified']);self.assertIsNone(row['owner'])
    def test_tty_argument_mismatch(self):
        tty,fp=self.tty_fixture();self.memory[fp-16]=struct.pack('<2Q',tty+8,OWNER)
        with self.assertRaisesRegex(ValueError,'disagree'):self.run_reader()
    def test_tty_witness(self):
        self.tty_fixture()
        for address in m['TTY_WITNESSES']:
            self.words[address]^=1
            with self.assertRaisesRegex(ValueError,'tty-lock witness'):self.run_reader()
            self.words[address]^=1

if __name__=='__main__':unittest.main()
