#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import copy
from pathlib import Path
import runpy
import struct
import unittest

api = runpy.run_path(str(Path(__file__).with_name('ipc-send-waits.py')))
collect = api['collect']
FP = 0xfffffecffba8bb70
PORT = 0xfffffe231c330800


class SendWaitTests(unittest.TestCase):
    def setUp(self):
        self.words = dict(api['WITNESSES'])
        self.memory = {FP-16: struct.pack('<4Q', PORT+0x28, PORT, FP+0x80, api['RETURN_PC']),
                       PORT+0x38: struct.pack('<2H', 5, 5)}
        self.processes = [dict(pid=75, name='pmset', threads=[dict(tid=969, on_cpu=False,
            kernel_stack=hex(FP & ~0x3fff),
            wait_event=hex(api['WAIT_EVENT']), frames=[dict(fp=hex(FP), raw_lr=hex(api['RETURN_PC']))])])]

    def run_collect(self):
        def read(address, size):
            raw = self.memory[address]
            if len(raw) != size:
                raise ValueError('test read size mismatch')
            return raw
        return collect(self.processes, read, self.words.__getitem__)['waits']

    def test_full_queue_and_frame(self):
        row = self.run_collect()[0]
        self.assertEqual((row['message_count'], row['queue_limit'], row['port']), (5, 5, hex(PORT)))
        self.assertTrue(row['at_or_above_limit'])

    def test_current_counter_not_inferred_from_wait(self):
        self.memory[PORT+0x38] = struct.pack('<2H', 2, 5)
        self.assertFalse(self.run_collect()[0]['at_or_above_limit'])

    def test_every_native_witness(self):
        for address, word in api['WITNESSES']:
            self.words[address] = word ^ 1
            with self.assertRaisesRegex(ValueError, 'native IPC send witness'):
                self.run_collect()
            self.words[address] = word

    def test_unqualified_thread_skipped(self):
        self.processes[0]['threads'][0]['on_cpu'] = True
        self.assertEqual(self.run_collect(), [])
        self.processes[0]['threads'][0]['on_cpu'] = False
        self.processes[0]['threads'][0]['wait_event'] = '0x0'
        self.assertEqual(self.run_collect(), [])

    def test_register_relationship_refused(self):
        self.memory[FP-16] = struct.pack('<4Q', PORT+0x30, PORT, FP+0x80, api['RETURN_PC'])
        self.assertIn('relationship differs', self.run_collect()[0]['error'])

    def test_duplicate_or_bad_frame_refused(self):
        frame = self.processes[0]['threads'][0]['frames'][0]
        self.processes[0]['threads'][0]['frames'].append(copy.deepcopy(frame))
        self.assertIn('ambiguous', self.run_collect()[0]['error'])
        self.processes[0]['threads'][0]['frames'].pop()
        frame['fp'] = '0x8000'
        self.assertIn('noncanonical', self.run_collect()[0]['error'])

    def test_saved_registers_must_fit_the_captured_stack(self):
        self.processes[0]['threads'][0]['kernel_stack'] = hex(FP)
        self.assertIn('outside captured kernel stack', self.run_collect()[0]['error'])


class ReceiverTests(SendWaitTests):
    SPACE = 0xfffffe2200100000
    TASK = 0xfffffe2300200000

    def setUp(self):
        super().setUp()
        self.words.update(api['RECEIVER_WITNESSES'])
        self.processes.append(dict(pid=57, name='syslogd', task_present=True,
                                   task=hex(self.TASK), threads=[]))
        self.header = bytearray(0x50)
        self.header[1] = 1
        self.header[0x38:0x3c] = struct.pack('<2H', 5, 5)
        # Signed-looking top16 bits must be stripped only for lookup.
        struct.pack_into('<Q', self.header, 0x48, self.SPACE & 0x0000ffffffffffff | 0xabcd000000000000)
        self.memory[PORT] = self.header
        self.memory[self.SPACE+0x50] = struct.pack('<Q', self.TASK & 0x0000ffffffffffff | 0x1234000000000000)
        self.memory[self.TASK+0x318] = struct.pack('<Q', self.SPACE)

    def receiver_rows(self):
        return collect(self.processes, lambda a,n:bytes(self.memory[a]), self.words.__getitem__,
                       receivers=True)['waits']

    def test_receiver_identity_and_reciprocity(self):
        for state in (1, 2):
            self.header[1] = state
            row = self.receiver_rows()[0]['receiver']
            self.assertEqual((row['pid'], row['name'], row['task'], row['space']),
                             (57, 'syslogd', hex(self.TASK), hex(self.SPACE)))

    def test_every_receiver_witness(self):
        for a, w in api['RECEIVER_WITNESSES']:
            self.words[a] = w ^ 1
            with self.assertRaisesRegex(ValueError, 'native IPC send witness'):
                self.receiver_rows()
            self.words[a] = w

    def test_non_receiver_union_states_refused(self):
        for state in (0, 3, 4, 5, 6, 7):
            self.header[1] = state
            self.assertIn('in-space', self.receiver_rows()[0]['receiver_error'])

    def test_null_or_unaligned_receiver(self):
        for value in (0, self.SPACE+1, 0x1000):
            struct.pack_into('<Q', self.header, 0x48, value)
            self.assertIn('noncanonical', self.receiver_rows()[0]['receiver_error'])

    def test_receiver_requires_one_captured_task(self):
        original = self.processes.pop()
        self.assertIn('uniquely', self.receiver_rows()[0]['receiver_error'])
        self.processes.extend([original, dict(original)])
        self.assertIn('uniquely', self.receiver_rows()[0]['receiver_error'])

    def test_reverse_link_required(self):
        self.memory[self.TASK+0x318] = struct.pack('<Q', self.SPACE+4096)
        self.assertIn('reciprocal', self.receiver_rows()[0]['receiver_error'])

    def test_short_read_and_changed_queue_refused(self):
        self.memory[PORT] = self.header[:-1]
        self.assertIn('short', self.receiver_rows()[0]['receiver_error'])
        self.memory[PORT] = self.header;self.header[0x38] = 4
        self.assertIn('counters differ', self.receiver_rows()[0]['receiver_error'])


if __name__ == '__main__':
    unittest.main()
