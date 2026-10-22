#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject corrupt configuration telemetry without conflating history and ownership."""
from pathlib import Path
import runpy
import struct
import unittest

audit=runpy.run_path(str(Path(__file__).with_name('audit-root-configuration.py')))['audit_root_configuration']
ROOT=0x943450000

def blob(**changes):
    values=dict(calls=1,changes=1,root=ROOT,value=8,mask=8,before=2,after=10,reserved=0)
    values.update(changes)
    return struct.pack('<8Q',*values.values())

def metadata(flags=10):
    result=bytearray(16);result[2]=18;result[4]=10;result[8]=255;result[10]=flags
    return {ROOT:bytes(result)}

class ConfigurationAudit(unittest.TestCase):
    def test_unused(self):
        self.assertEqual(audit(bytes(64),{})['calls'],0)
        with self.assertRaises(ValueError):audit(blob(calls=0,changes=0),{})

    def test_valid_transitions(self):
        for before in (0,1,2,3,4,5,6,7,0x20,0x21,0x22,0x23):
            with self.subTest(before=before):
                self.assertTrue(audit(blob(before=before,after=before|8),metadata(before|8))['last_matches_current'])
                self.assertTrue(audit(blob(value=0,before=before|8,after=before),metadata(before))['last_matches_current'])
        self.assertEqual(audit(blob(calls=2,before=10),metadata())['changes'],1)
        self.assertEqual(audit(blob(changes=0,before=10),metadata())['changes'],0)
        for before in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                       0x20,0x21,0x22,0x23,0x28,0x29,0x2a,0x2b):
            for mask in (0,1,2,3,8,9,10,11):
                for value in (0,1,2,3,8,9,10,11):
                    after=(before&~mask)|(value&mask)
                    self.assertTrue(audit(blob(before=before,mask=mask,value=value,after=after),
                                          metadata(after))['last_matches_current'])

    def test_history_is_not_live_ownership(self):
        self.assertFalse(audit(blob(),{})['last_matches_current'])
        self.assertFalse(audit(blob(),metadata(2))['last_matches_current'])
        wrong_type=bytearray(metadata()[ROOT]);wrong_type[2]=19
        self.assertFalse(audit(blob(),{ROOT:bytes(wrong_type)})['last_matches_current'])

    def test_corrupt_records(self):
        invalid=[dict(reserved=1),dict(changes=2),dict(root=ROOT+1),dict(root=0),
                 dict(value=1<<16),dict(mask=1<<16),dict(value=4),dict(mask=16),
                 dict(before=16),dict(before=0x82),dict(after=2),dict(changes=0)]
        for changes in invalid:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):audit(blob(**changes),metadata())
        for size in (0,63,65):
            with self.assertRaises(ValueError):audit(bytes(size),{})

if __name__=='__main__':unittest.main()
