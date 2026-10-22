# SPDX-License-Identifier: MIT
"""Fail closed on unqualified native layout, unknown bits and truncated records."""
from pathlib import Path
import runpy
import struct
import unittest
api=runpy.run_path(str(Path(__file__).with_name('thread-scheduler.py')))
class SchedulerState(unittest.TestCase):
    def setUp(self):
        self.words=dict(api['WITNESSES'])
        self.reader=api['make_reader'](self.words.__getitem__)
    def record(self,state):
        raw=bytearray(0x8c0);struct.pack_into('<I',raw,api['STATE_OFFSET'],state)
        return raw
    def test_running_waiting_and_transition(self):
        self.assertEqual(self.reader(self.record(4))['flags'],['run'])
        self.assertEqual(self.reader(self.record(0x49))['flags'],['wait','uninterruptible','wait_report'])
        mixed=self.reader(self.record(0x105))
        self.assertTrue(mixed['run'] and mixed['waiting'] and mixed['waking'])
        self.assertTrue(self.reader(self.record(0x84))['idle'])
    def test_unknown_bits(self):
        for state in (0x200,0x80000000,0xffffffff):
            with self.assertRaisesRegex(ValueError,'unknown'):self.reader(self.record(state))
    def test_runq_assignment_preserves_raw_pointer(self):
        # Assignment and RUN are independent observations, including when a
        # stopped thread was captured in a scheduler transition.
        for state in (0, 1, 4, 0x105):
            for pointer in (0, 0xfffffe000c123450, 0xaabbfe000c123450):
                raw = self.record(state)
                struct.pack_into('<Q', raw, api['RUNQ_OFFSET'], pointer)
                out = self.reader(raw)
                self.assertEqual(int(out['runq_assignment'], 16), pointer)
                self.assertEqual(bytes.fromhex(out['runq_raw_hex']), struct.pack('<Q', pointer))
    def test_truncated(self):
        for n in (0,0x1f8,0x1fb):
            with self.assertRaisesRegex(ValueError,'short'):self.reader(bytes(n))
    def test_every_native_witness(self):
        for address,word in api['WITNESSES']:
            self.words[address]=word^1
            with self.assertRaisesRegex(ValueError,'witness'):api['make_reader'](self.words.__getitem__)
            self.words[address]=word
    def test_process_inventory_binds_existing_thread_bytes(self):
        fixtures=runpy.run_path(str(Path(__file__).with_name('test-process-waits.py')))
        f=fixtures['ProcessWaitTests']();f.setUp()
        f.put(f.THREAD+api['STATE_OFFSET'],4,4)
        collect=runpy.run_path(str(Path(__file__).with_name('process-waits.py')))['collect']
        rows=collect(f.read,lambda _:None,set(),scheduler_state=self.reader)
        thread=rows['processes'][0]['threads'][0]
        self.assertEqual(thread['tid'],123)
        self.assertEqual(thread['scheduler_state']['flags'],['run'])
        f.put(f.THREAD+api['STATE_OFFSET'],0x200,4)
        with self.assertRaisesRegex(ValueError,'unknown'):
            collect(f.read,lambda _:None,set(),scheduler_state=self.reader)
if __name__=='__main__':unittest.main()
