#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refusal and offset tests for the native saved EL0 state reader."""
from pathlib import Path
import runpy
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('user-state.py')))


class SavedUserStateTests(unittest.TestCase):
    def setUp(self):
        self.address = 0xfffffe1200000000
        self.state = bytearray(0x130)
        self.thread = bytearray(0x118)
        struct.pack_into('<Q', self.thread, 0x110, 0x1234fe1200000000)
        struct.pack_into('<II', self.state, 0, 21, 74)
        struct.pack_into('<Q', self.state, 8, 0x11223344)
        struct.pack_into('<4Q', self.state, 0xf0, 0x16b940020, 0x190000004, 0x16b940000, 0x190000008)
        struct.pack_into('<I', self.state, 0x110, 0x60000000)
        struct.pack_into('<2Q', self.state, 0x118, 0x190008000, 0x92000007)
        self.words = dict(API['WITNESSES'])
        self.reads = []

    def read(self, address, size):
        self.assertEqual(address, self.address)
        self.reads.append(size)
        return bytes(self.state[:size])

    def reader(self):
        return API['make_reader'](self.read, self.words.__getitem__)

    def test_saved_registers_and_pointer_address(self):
        result = self.reader()(0xfffffe1000000000, self.thread)
        self.assertEqual(result['address'], hex(self.address))
        self.assertEqual(result['registers']['0'], '0x11223344')
        self.assertEqual(result['pc'], '0x190000008')
        self.assertEqual(result['far'], '0x190008000')
        self.assertEqual(result['esr'], '0x92000007')
        self.assertEqual(self.reads, [8, 0x130])

    def test_native_witness_mismatch_prevents_reads(self):
        self.words[next(iter(self.words))] ^= 1
        with self.assertRaisesRegex(ValueError, 'native witness'):
            self.reader()
        self.assertEqual(self.reads, [])

    def test_wrong_header_refused_before_full_read(self):
        struct.pack_into('<I', self.state, 0, 23)
        with self.assertRaisesRegex(ValueError, 'header differs'):
            self.reader()(0xfffffe1000000000, self.thread)
        self.assertEqual(self.reads, [8])

    def test_privileged_state_not_labeled_el0(self):
        struct.pack_into('<I', self.state, 0x110, 4)
        with self.assertRaisesRegex(ValueError, 'not EL0'):
            self.reader()(0xfffffe1000000000, self.thread)

    def test_absent_pointer(self):
        struct.pack_into('<Q', self.thread, 0x110, 0)
        self.assertIsNone(self.reader()(0xfffffe1000000000, self.thread))
        self.assertEqual(self.reads, [])


if __name__ == '__main__':
    unittest.main()
