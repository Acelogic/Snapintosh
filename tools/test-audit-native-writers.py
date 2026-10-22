# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import unittest

api=runpy.run_path(str(Path(__file__).with_name('audit-native-writers.py')))

class NativeWriters(unittest.TestCase):
    def good(self):
        saved=[0x12345000+i*4 for i in range(6)]+[0x400+i*16 for i in range(6)]
        pc,word=next(iter(api['SITES'].items()))
        return saved+saved+[0xf11f010305719,1,0,1,1,0,64,0,2,pc,word]
    def audit(self,words,**kw):
        return api['audit'](struct.pack('<35Q',*words),enabled=True,prepared=True,**kw)
    def test_restored_bank_and_execution(self):
        out=self.audit(self.good())
        self.assertTrue(out['active']);self.assertEqual(out['traps'],64)
    def test_every_saved_and_observed_register(self):
        for i in range(24):
            words=self.good();words[i]^=4
            with self.assertRaisesRegex(ValueError,'restoration'):self.audit(words)
    def test_lifecycle_failures(self):
        for field,value in [('saved',0),('installed',1),('install_verified',0),
                            ('restores',0),('restores',2),('restore_failed',1),('rejected',1)]:
            words=self.good();words[24+api['FIELDS'].index(field)]=value
            with self.assertRaisesRegex(ValueError,'lifecycle'):self.audit(words)
    def test_capacity_and_counters(self):
        for value in (0,5,0x4009):
            words=self.good();words[24]=value
            with self.assertRaisesRegex(ValueError,'capacity'):self.audit(words)
        words=self.good();words[32]=65
        with self.assertRaisesRegex(ValueError,'accounting'):self.audit(words)
        words=self.good();words[33]+=4
        with self.assertRaisesRegex(ValueError,'instruction'):self.audit(words)
    def test_unused_short_and_early_stop(self):
        for enabled,prepared in [(False,False),(False,True),(True,False)]:
            self.assertFalse(api['audit'](bytes(280),enabled=enabled,prepared=prepared)['active'])
            with self.assertRaisesRegex(ValueError,'unused'):
                api['audit'](struct.pack('<35Q',*self.good()),enabled=enabled,prepared=prepared)
        for size in (0,279,281):
            with self.assertRaises(ValueError):api['audit'](bytes(size),enabled=True,prepared=True)
    def test_prepared_but_no_hit_is_not_execution_proof(self):
        words=self.good();words[30]=words[32]=words[33]=words[34]=0
        self.assertEqual(self.audit(words)['traps'],0)

if __name__=='__main__':unittest.main()
