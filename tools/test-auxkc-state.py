#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded native AuxKC state reader refusal checks."""
from pathlib import Path
import runpy
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('auxkc-state.py')))


class StateReaderTests(unittest.TestCase):
    def setUp(self):
        self.words = dict(API['WITNESSES'])
        self.memory = {}
        self.reads = []
        self.args = 0xfffffe0008000000
        self.header = 0xfffffe0008100000
        self.put(0xfffffe0007ebf100, struct.pack('<Q', self.args))
        self.put(0xfffffe0007ebf060, bytes(8))
        self.put(0xfffffe000c830890, bytes(8))
        self.put(0xfffffe000c77d6a0, bytes(4))
        self.put(0xfffffe000c77d668, bytes(16))
        self.put(0xfffffe000c6d6e08, b'\1')
        self.put(0xfffffe000c830688, b'\0')
        self.put(self.args+0x2d8, bytes(24))

    def put(self, addr, data):
        self.memory.update((addr+i, b) for i, b in enumerate(data))

    def read(self, addr, size):
        self.assertTrue(0 < size <= 4096)
        self.reads.append((addr, size))
        return bytes(self.memory[addr+i] for i in range(size))

    def test_absent_collection_has_no_indirect_header_read(self):
        result = API['collect'](self.read, self.words.__getitem__)
        self.assertEqual(result['registered_header'], '0x0')
        self.assertNotIn('mach_header', result)

    def test_wrong_native_witness_refused_before_memory_read(self):
        for address, word in API['WITNESSES']:
            self.words[address] = word ^ 1
            with self.assertRaisesRegex(ValueError, 'witness'):
                API['collect'](self.read, self.words.__getitem__)
            self.words[address] = word
        self.assertEqual(self.reads, [])

    def test_loader_controls_are_independent_of_collection_presence(self):
        for enabled in (0, 1):
            for ready in (0, 1):
                self.put(0xfffffe000c6d6e08, bytes([enabled]))
                self.put(0xfffffe000c830688, bytes([ready]))
                result = API['collect'](self.read, self.words.__getitem__)
                self.assertEqual(result['load_enabled'], bool(enabled))
                self.assertEqual(result['daemon_ready'], bool(ready))
                self.assertEqual(result['registered_header'], '0x0')

    def test_corrupt_loader_boolean_refused(self):
        self.put(0xfffffe000c830688, b'\2')
        with self.assertRaisesRegex(ValueError, 'loader boolean'):
            API['collect'](self.read, self.words.__getitem__)

    def test_bad_command_bounds_refused(self):
        self.put(0xfffffe0007ebf060, struct.pack('<Q', self.header))
        self.put(self.header, struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 12, 1, 8, 0, 0))
        self.put(self.header+32, struct.pack('<2I', 0x19, 0xffffffff))
        with self.assertRaisesRegex(ValueError, 'command outside bounds'):
            API['collect'](self.read, self.words.__getitem__)


if __name__ == '__main__':
    unittest.main()
