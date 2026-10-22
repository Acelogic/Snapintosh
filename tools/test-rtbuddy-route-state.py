#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded-read and rejected-layout checks for the stopped route collector."""
from pathlib import Path
import runpy
import struct
import unittest

MODULE = runpy.run_path(str(Path(__file__).with_name('rtbuddy-route-state.py')))
COLLECT = MODULE['collect']
WORDS = dict(MODULE['WITNESSES'])


class RouteCaptureTests(unittest.TestCase):
    def setUp(self):
        self.stack = 0xfffffe0001000000
        self.fp = self.stack+0x200
        self.obj = 0xfffffe0002000000
        self.storage = 0xfffffe0003000000
        self.memory = {}
        self.reads = []
        self.put(self.fp-0x50, bytes(0x50))
        # Saved caller registers in the native wait helper frame.
        for off, value in [(-0x50, 0xfffffe0004000000), (-0x30, 1),
                           (-0x18, self.obj), (-0x8, 0xfffffe0005000000)]:
            self.put(self.fp+off, struct.pack('<Q', value))
        self.put(self.obj+0xc, struct.pack('<I', 8))
        self.put(self.obj+0x18, struct.pack('<Q', self.storage))
        self.put(self.storage, bytes.fromhex('69000000cf000000'))
        self.threads = [dict(tid=613, name="IOConfigThread_'iop-dcp-nub'",
            kernel_stack=hex(self.stack), frames=[dict(fp=hex(self.fp),
            raw_lr=hex(MODULE['RETURN_PC']))])]

    def put(self, address, data):
        self.memory.update((address+i, b) for i, b in enumerate(data))

    def read(self, address, size):
        self.reads.append((address, size))
        return bytes(self.memory[address+i] for i in range(size))

    def collect(self):
        return COLLECT(self.threads, self.read, WORDS.__getitem__)

    def test_reads_selected_record_only(self):
        result = self.collect()
        self.assertEqual(result[0]['route_value'], 0xcf)
        self.assertEqual(result[0]['route_index'], 1)
        self.assertEqual(result[0]['route_bytes'], 'cf000000')
        self.assertEqual(self.reads[-1], (self.storage+4, 4))
        self.assertNotIn((self.storage, 8), self.reads)

    def test_unrelated_frame_never_reads_memory(self):
        self.threads[0]['frames'][0]['raw_lr'] = '0xfffffe000b320a54'
        self.assertEqual(self.collect(), [])
        self.assertEqual(self.reads, [])

    def test_bad_witness_never_reads_memory(self):
        with self.assertRaisesRegex(ValueError, 'witness'):
            COLLECT(self.threads, self.read, lambda va: WORDS[va]^1)
        self.assertEqual(self.reads, [])

    def test_frame_bounds_before_read(self):
        for fp in [self.stack+0x40, self.stack+0x3ff8, self.fp+1]:
            with self.subTest(fp=fp):
                self.threads[0]['frames'][0]['fp'] = hex(fp)
                with self.assertRaisesRegex(ValueError, 'bounded stack'):
                    self.collect()
        self.assertEqual(self.reads, [])

    def test_invalid_lengths_and_index(self):
        for size in [0, 3, 4, 7, 260]:
            with self.subTest(size=size):
                self.reads.clear()
                self.put(self.obj+0xc, struct.pack('<I', size))
                with self.assertRaisesRegex(ValueError, 'length or index'):
                    self.collect()
                self.assertTrue(all(a < self.storage for a, _ in self.reads))

    def test_null_backing_storage(self):
        self.put(self.obj+0x18, bytes(8))
        with self.assertRaisesRegex(ValueError, 'null backing'):
            self.collect()


if __name__ == '__main__':
    unittest.main()
