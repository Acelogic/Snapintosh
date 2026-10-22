#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('msgbuf-state.py')))


class MessageBufferTests(unittest.TestCase):
    def test_ring_order_and_empty_space(self):
        obj, storage = 0xfffffe1000000000, 0xfffffe1000001000
        values = {API['SLOT']: struct.pack('<Q', obj),
                  obj: struct.pack('<4IQ', 0x063061, 8, 3, 0, storage),
                  storage: b'newold\0\0'}
        result = API['collect'](lambda a, n: values[a][:n], dict(API['WITNESSES']).__getitem__)
        self.assertEqual(result['text'], 'oldnew')

    def test_bad_witness_before_reads(self):
        reads = []
        with self.assertRaisesRegex(ValueError, 'witness'):
            API['collect'](lambda a, n: reads.append((a, n)), lambda a: 0)
        self.assertEqual(reads, [])

    def test_invalid_geometry_before_buffer_read(self):
        obj = 0xfffffe1000000000
        def read(address, size):
            if address == API['SLOT']:
                return struct.pack('<Q', obj)
            self.assertEqual(address, obj)
            return struct.pack('<4IQ', 0x063061, 8, 8, 0, 0xfffffe1000001000)
        with self.assertRaisesRegex(ValueError, 'geometry'):
            API['collect'](read, dict(API['WITNESSES']).__getitem__)


if __name__ == '__main__':
    unittest.main()
