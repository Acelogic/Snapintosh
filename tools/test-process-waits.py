#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed tests for the stopped-process diagnostic reader."""
from pathlib import Path
import runpy
import struct
import unittest

api = runpy.run_path(str(Path(__file__).with_name('process-waits.py')))
collect, pid_hash = api['collect'], api['pid_hash']


class ProcessWaitTests(unittest.TestCase):
    TABLE = 0xfffffe0010000000
    PROC = 0xfffffe0020000000
    THREAD = 0xfffffe0030000000

    def setUp(self):
        self.mem = {}
        self.put(api['PID_HASH'], (self.TABLE & ((1 << 48)-1)) | (0xfffa << 48))
        for i in range(64):
            self.put(self.TABLE+i*8, 0)
        self.mem[self.PROC] = bytearray(0xea8)
        self.mem[self.THREAD] = bytearray(0x8c0)
        self.put(self.TABLE+8*(pid_hash(7) & 63), self.PROC+0xa0)
        self.put(self.PROC+0x60, 7, 4)
        self.put(self.PROC+0x20, 1, 4)
        self.put(self.PROC+0x458, 2, 1)
        self.put(self.PROC+0xea0, 1, 4)
        self.mem[self.PROC][0x5bc:0x5c2] = b'ditto\0'
        self.head = self.PROC+0x810
        self.put(self.head, self.THREAD)
        self.put(self.head+8, self.THREAD)
        self.put(self.PROC+0x838, 1, 4)
        self.put(self.THREAD+0x410, self.head)
        self.put(self.THREAD+0x418, self.head)
        self.put(self.THREAD+0x510, 123)

    def put(self, at, value, size=8):
        data = value.to_bytes(size, 'little')
        for base, raw in self.mem.items():
            if base <= at and at+size <= base+len(raw):
                raw[at-base:at-base+size] = data
                return
        self.mem[at] = bytearray(data)

    def read(self, at, size):
        for base, raw in self.mem.items():
            if base <= at and at+size <= base+len(raw):
                return bytes(raw[at-base:at-base+size])
        raise ValueError('unmapped fixture address')

    def capture(self, on_cpu=()):
        return collect(self.read, lambda pc: {'va': hex(pc)} if pc else None, set(on_cpu))

    def test_process_and_running_thread(self):
        result = self.capture([self.THREAD])
        self.assertEqual(result['hash_mask'], '0x3f')
        self.assertEqual(len(result['processes']), 1)
        p = result['processes'][0]
        self.assertEqual((p['pid'], p['ppid'], p['name'], p['thread_count']),
                         (7, 1, 'ditto', 1))
        self.assertTrue(p['threads'][0]['on_cpu'])

    def test_parent_pid_is_not_limited_by_capture_pid_bound(self):
        self.put(self.PROC+0x20, 1000, 4)
        self.assertEqual(self.capture()['processes'][0]['ppid'], 1000)
        self.put(self.PROC+0x20, 0xffffffff, 4)
        with self.assertRaisesRegex(ValueError, 'parent process identity'):
            self.capture()

    def test_saved_wait_and_frame(self):
        stack = 0xfffffe0040000000
        self.mem[stack] = bytearray(0x4000)
        self.put(self.THREAD+0xf0, stack)
        self.put(self.THREAD+0x158, stack+0x100)
        self.put(self.THREAD+0x18, 0xfffffe0001234000)
        self.put(stack+0x150, stack+0x200)
        self.put(stack+0x208, 0xfffffe0001234560)
        t = self.capture()['processes'][0]['threads'][0]
        self.assertEqual(t['wait_event'], '0xfffffe0001234000')
        self.assertEqual(t['frames'][0]['return_to']['va'], '0xfffffe0001234560')

    def test_null_task(self):
        self.put(self.PROC+0x458, 0, 1)
        self.assertFalse(self.capture()['processes'][0]['task_present'])

    def test_reverse_task_identity(self):
        self.put(self.PROC+0xea0, 0, 4)
        with self.assertRaisesRegex(ValueError, 'reverse mapping'):
            self.capture()

    def test_bucket_cycle(self):
        self.put(self.PROC+0x60, 999, 4)
        self.put(self.PROC+0xa0, self.PROC+0xa0)
        with self.assertRaisesRegex(ValueError, 'PID bucket'):
            self.capture()

    def test_thread_backlink(self):
        self.put(self.THREAD+0x418, 0)
        with self.assertRaisesRegex(ValueError, 'reciprocity'):
            self.capture()

    def test_thread_count(self):
        self.put(self.PROC+0x838, 2, 4)
        with self.assertRaisesRegex(ValueError, 'count or tail'):
            self.capture()

    def test_geometry_and_limit(self):
        for limit in (0, 257):
            with self.assertRaisesRegex(ValueError, 'PID capture bound'):
                collect(self.read, lambda _: None, set(), limit)
        self.put(api['PID_HASH'], 0)
        with self.assertRaisesRegex(ValueError, 'hash geometry'):
            self.capture()


if __name__ == '__main__':
    unittest.main()
