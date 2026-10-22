#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
import struct
import unittest
from pathlib import Path

A=runpy.run_path(str(Path(__file__).with_name('audit-user-execution.py')))

class UserExecutionAudit(unittest.TestCase):
    def record(self,**changes):
        row={name:0 for name in A['FIELDS']}
        row.update(returns=1,executed=1,entry=0x1026f8bf0,stack=0x16d85fd58,
                   root=0x944ba8000,shadow=0xbba91000,ttbr=0x80000bba91000,
                   tcr=0x0108003365112511 & ~0xc000,
                   entry_pa=0x944b68bf0,source_pte=0x0020000944b68ec3,
                   shadow_pte=0x0020000944b68ec3,instruction=0x910003e0,
                   observed_pc=0x1026f8bf4,observed_spsr=0,
                   observed_esr=0xc8000000,observed_x0=0x16d85fd58,
                   observed_sp=0x16d85fd58)
        row.update(changes)
        return struct.pack('<23Q',*(row[n] for n in A['FIELDS']))+bytes(5*23*8)

    def test_native_shaped_witness(self):
        result=A['audit'](self.record())
        self.assertTrue(result['el0_execution_proven'])
        self.assertEqual(result['witnessed_cpus'],[0])

    def test_return_request_is_not_execution(self):
        result=A['audit'](self.record(executed=0,pending=1))
        self.assertFalse(result['el0_execution_proven'])

    def test_invalid_evidence(self):
        for key,value in dict(returns=0,pending=1,interrupted=1,instruction=0x910003e1,
                observed_spsr=4,observed_pc=0x1026f8bf0,observed_esr=0x80000000,
                observed_x0=0,observed_sp=0,shadow_pte=0,ttbr=0,
                source_pte=0x0060000944b68ec3,entry=0).items():
            with self.subTest(key=key), self.assertRaises((ValueError,AssertionError)):
                A['audit'](self.record(**{key:value}))

    def test_empty_and_wrong_size(self):
        self.assertFalse(A['audit'](bytes(6*23*8))['el0_execution_proven'])
        with self.assertRaises(ValueError):A['audit'](bytes(23*8))

if __name__=='__main__':unittest.main()
