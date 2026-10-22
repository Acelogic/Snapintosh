#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression checks for read-only capture at 16 KiB mapping boundaries."""
from pathlib import Path
import runpy
import unittest

read_cstring=runpy.run_path(str(Path(__file__).with_name('capture-clpc-platform.py')))['read_cstring']

class Strings(unittest.TestCase):
    def reader(self,pages):
        calls=[]
        def read(va,n):
            calls.append((va,n))
            page=va&~0x3fff;offset=va&0x3fff
            self.assertIn(page,pages,'reader crossed into an unmapped page')
            self.assertLessEqual(offset+n,0x4000)
            return pages[page][offset:offset+n]
        return read,calls

    def test_terminator_at_last_mapped_byte(self):
        for distance in range(1,130):
            with self.subTest(distance=distance):
                page=b'X'*(0x4000-distance)+b'A'*(distance-1)+b'\0'
                reader,calls=self.reader({0:page})
                self.assertEqual(read_cstring(reader,0x4000-distance,256),'A'*(distance-1))
                self.assertTrue(all(va+n<=0x4000 for va,n in calls))

    def test_string_spans_two_mapped_pages(self):
        reader,calls=self.reader({0:b'X'*(0x4000-3)+b'abc',0x4000:b'def\0'+b'X'*(0x4000-4)})
        self.assertEqual(read_cstring(reader,0x4000-3),'abcdef')
        self.assertEqual(calls,[(0x4000-3,3),(0x4000,64)])

    def test_unterminated_is_bounded(self):
        reader,calls=self.reader({0:b'A'*0x4000})
        with self.assertRaisesRegex(ValueError,'unterminated'):
            read_cstring(reader,0,128)
        self.assertEqual(sum(n for _,n in calls),128)

    def test_invalid_limits_and_short_reads(self):
        for limit in (0,-1,0x4001):
            with self.assertRaisesRegex(ValueError,'limit'):
                read_cstring(lambda *_:self.fail('unexpected read'),0,limit)
        with self.assertRaisesRegex(ValueError,'short'):
            read_cstring(lambda *_:b'\0',0)

    def test_invalid_ascii_is_explicit(self):
        reader,_=self.reader({0:b'\xff\0'+bytes(0x3ffe)})
        with self.assertRaises(UnicodeDecodeError):read_cstring(reader,0)

if __name__=='__main__':unittest.main()
