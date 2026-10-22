#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject ambiguous or nonexecutable instruction matches before symbolizing."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('dyld_cache', Path(__file__).with_name('dyld-cache.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CacheCodeMatchTests(unittest.TestCase):
    CODE = bytes(range(64))
    BASE = 0x180000000

    def fixture(self, directory, copies=1, prot=5):
        raw = bytearray(4096)
        raw[:16] = b'dyld_v1  arm64e\0\0'
        struct.pack_into('<II', raw, 16, 32, 1)
        struct.pack_into('<QQQII', raw, 32, self.BASE, len(raw), 0, 5, prot)
        for i in range(copies):
            raw[0x100+i*0x100:0x140+i*0x100] = self.CODE
        (directory/'dyld_shared_cache_arm64e').write_bytes(raw)
        (directory/'dyld_shared_cache_arm64e.map').write_text('')

    def test_exact_match_establishes_slide(self):
        with tempfile.TemporaryDirectory() as folder:
            self.fixture(Path(folder))
            with module.Cache(folder) as cache:
                match = cache.match_code(self.BASE+0x100+0x67e4000, self.CODE)
                self.assertEqual(match['slide'], 0x67e4000)
                self.assertEqual(match['unslid_pc'], self.BASE+0x100)
                self.assertEqual(match['matched_bytes'], 64)

    def test_duplicate_code_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            self.fixture(Path(folder), copies=2)
            with module.Cache(folder) as cache:
                with self.assertRaisesRegex(ValueError, 'multiple executable'):
                    cache.match_code(self.BASE, self.CODE)

    def test_nonexecutable_match_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            self.fixture(Path(folder), prot=1)
            with module.Cache(folder) as cache:
                with self.assertRaisesRegex(ValueError, 'no executable'):
                    cache.match_code(self.BASE, self.CODE)

    def test_short_or_unaligned_input_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            self.fixture(Path(folder))
            with module.Cache(folder) as cache:
                for pc, code in [(self.BASE, self.CODE[:32]), (self.BASE+1, self.CODE)]:
                    with self.assertRaisesRegex(ValueError, 'aligned PC'):
                        cache.match_code(pc, code)

    def pointer_fixture(self, directory, raw):
        self.fixture(directory)
        path = directory/'dyld_shared_cache_arm64e'
        data = bytearray(path.read_bytes())
        struct.pack_into('<II', data, 0x138, 0x180, 1)
        struct.pack_into('<6Q2I', data, 0x180, self.BASE, len(data), 0, 0x300, 26, 0, 5, 5)
        struct.pack_into('<III4xQH', data, 0x300, 5, 4096, 1, self.BASE, 0x500)
        struct.pack_into('<Q', data, 0x500, raw)
        path.write_bytes(data)

    def test_authenticated_target_and_chain_membership(self):
        with tempfile.TemporaryDirectory() as folder:
            self.pointer_fixture(Path(folder), (1 << 63) | 0x1234)
            with module.Cache(folder) as cache:
                self.assertEqual(cache.pointer_target(self.BASE+0x500), self.BASE+0x1234)
                with self.assertRaisesRegex(ValueError, 'not a member'):
                    cache.pointer_target(self.BASE+0x508)

    def test_plain_pointer_high_byte(self):
        with tempfile.TemporaryDirectory() as folder:
            self.pointer_fixture(Path(folder), (0xab << 34) | 0x1234)
            with module.Cache(folder) as cache:
                self.assertEqual(cache.pointer_target(self.BASE+0x500), (0xab << 56) | (self.BASE+0x1234))

    def test_chain_cannot_escape_page(self):
        with tempfile.TemporaryDirectory() as folder:
            self.pointer_fixture(Path(folder), (0x7ff << 52) | 0x1234)
            with module.Cache(folder) as cache:
                with self.assertRaisesRegex(ValueError, 'outside mapped page'):
                    cache.pointer_target(self.BASE+0x508)


if __name__ == '__main__':
    unittest.main()
