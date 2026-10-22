#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
from pathlib import Path
import struct
import unittest

audit=runpy.run_path(str(Path(__file__).with_name('audit-user-roots.py')))['audit']

class RootAudit(unittest.TestCase):
    def setUp(self):
        self.ram=bytearray(0x20000);self.work=bytearray(0x10000)
        # Guest16K VA0x4000 ->0x20000; hardware4K splits it into four leaves.
        self.gput(0,0x14003);self.gput(0x4000,0x18003);self.gput(0x8008,0x20000|0x600000000007c3)
        self.hput(0,0x101003);self.hput(0x1000,0x102003);self.hput(0x2000,0x103003)
        for i in range(4):self.hput(0x3020+8*i,0x20000+0x1000*i|0x600000000007c3)
        self.cache=[dict(root=0x10000,shadow=0x100000,leaves=1,asid=6,format=0,flags=2,valid=1)]
    def gput(self,off,value):struct.pack_into('<Q',self.ram,off,value)
    def hput(self,off,value):struct.pack_into('<Q',self.work,off,value)
    def read(self,pa,size):
        if 0x10000<=pa<0x30000:return self.ram[pa-0x10000:pa-0x10000+size]
        if 0x100000<=pa<0x110000:return self.work[pa-0x100000:pa-0x100000+size]
        raise ValueError('out of range')
    def run_audit(self,active=(0x10000,0,0,0x10000,0,0),sprr=None,**kwargs):
        return audit(self.read,cache=self.cache,active=active,ram_low=0x10000,ram_high=0x30000,
                     work_low=0x100000,work_high=0x110000,sprr=sprr,**kwargs)
    def test_diagnostic_mismatches_do_not_qualify_mappings(self):
        self.hput(0x3020,0)
        self.cache[0]['leaves']=2
        with self.assertRaises(ValueError):self.run_audit()
        result=self.run_audit(diagnose_mismatches=True)
        self.assertFalse(result['mappings_equal'])
        self.assertFalse(result['cached_leaf_counts_equal'])
        row=result['roots'][0]
        self.assertEqual(row['mismatch_count'],1)
        self.assertEqual(row['first_mismatches'][0]['va'],'0x4000')
        self.assertIsNone(row['first_mismatches'][0]['actual'])
        self.hput(0,0x100003)
        with self.assertRaisesRegex(ValueError,'invalid or aliased table'):
            self.run_audit(diagnose_mismatches=True)
    def sprr_states(self):
        return [dict(uperm=0x2010002030100000,pperm=0x2020a52a302abae6,
                     umprr=0x40000 if cpu in (0,3) else 0,pmprr=0x40010,
                     resets=1,reads=0,writes=0,rejected=0,last_reg=0,last_value=0)
                for cpu in range(6)]
    def test_match(self):
        result=self.run_audit();self.assertEqual(result['roots'][0]['mapped_4k_pages'],4)
        self.assertEqual(result['roots'][0]['active_cpus'],[0,3])
    def test_address_pauth_flag_is_not_user_privilege(self):
        for flags in (0,1,2,3,8,9,10,11,0x20,0x21,0x22,0x23,0x28,0x29,0x2a,0x2b):
            self.cache[0]['flags']=flags
            sprr=self.sprr_states()
            for cpu in range(6):sprr[cpu]['umprr']=((flags&8)<<15)|((flags&1)<<11) if cpu in (0,3) else 0
            self.assertEqual(self.run_audit(sprr=sprr if flags&9 else None)
                             ['roots'][0]['mapped_4k_pages'],4)
            if flags&9:
                with self.assertRaisesRegex(ValueError,'missing SPRR'):self.run_audit()
        for flags in (4,6,0x10,0x80,0x100,0x10000):
            self.cache[0]['flags']=flags
            with self.assertRaisesRegex(ValueError,'cached root identity'):self.run_audit()
    def test_umprr11_does_not_admit_untranslated_selector5(self):
        self.cache[0]['flags']=1
        self.gput(0x8008,0x20000|0x0020000000000443)
        with self.assertRaisesRegex(ValueError,'SPRR permission translation'):self.run_audit()
    def test_cached_leaf_count_must_match(self):
        self.cache[0]['leaves']=2
        with self.assertRaises(ValueError):self.run_audit()
    def test_history_stays_software_only_and_does_not_weaken_permissions(self):
        pte=0x20000|0x60000000000ec3
        self.gput(0x8008,pte|(1<<59))
        for i in range(4):self.hput(0x3020+8*i,pte+i*4096)
        row=self.run_audit()['roots'][0]
        self.assertEqual(row['was_writable_4k_pages'],4)
        self.assertTrue(row['hardware_history_bits_absent'])
        self.assertEqual(row['was_writable_sample'][0],dict(va='0x4000',pa='0x20000'))
        for i in range(4):
            for changed in ((pte+i*4096)|(1<<59),(pte+i*4096)&~0x80,
                            (pte+i*4096)&~(1<<54)):
                with self.subTest(part=i,pte=hex(changed)):
                    self.hput(0x3020+8*i,changed)
                    with self.assertRaises(ValueError):self.run_audit()
                    self.hput(0x3020+8*i,pte+i*4096)
        self.gput(0x8008,(pte|(1<<59))&~0x40)
        with self.assertRaisesRegex(ValueError,'ordinary NX user'):self.run_audit()
    def test_removed_leaf_and_empty_cache(self):
        self.gput(0x8008,0)
        for i in range(4):self.hput(0x3020+8*i,0)
        with self.assertRaises(ValueError):self.run_audit()
        self.cache[0]['leaves']=0
        self.assertEqual(self.run_audit()['roots'][0]['mapped_guest_pages'],0)
    def test_extra_bootstrap_alias(self):
        self.hput(0x3000,0x20000|0x600000000007c3)
        with self.assertRaises(ValueError):self.run_audit()
    def test_wrong_physical_mapping(self):
        self.hput(0x3020,0x21000|0x600000000007c3)
        with self.assertRaises(ValueError):self.run_audit()
    def test_weaker_permissions(self):
        self.hput(0x3020,0x20000|0x600000000003c3)
        with self.assertRaises(ValueError):self.run_audit()
    def test_missing_cache(self):
        with self.assertRaises(ValueError):self.run_audit((0x14000,))
    def test_private_table_escape(self):
        self.hput(0,0x14003)
        with self.assertRaises(ValueError):self.run_audit()
    def test_reused_table(self):
        self.hput(0x2008,0x103003)
        with self.assertRaises(ValueError):self.run_audit()
    def test_modified_root_requires_and_checks_register_readback(self):
        self.cache[0]['flags']=10
        with self.assertRaisesRegex(ValueError,'missing SPRR'):self.run_audit()
        states=self.sprr_states()
        self.assertEqual(self.run_audit(sprr=states)['sprr'],states)
        for cpu in range(6):
            for field in ('uperm','pperm','umprr','pmprr'):
                bad=[dict(row) for row in states];bad[cpu][field]^=1
                with self.subTest(cpu=cpu,field=field):
                    with self.assertRaisesRegex(ValueError,'SPRR register state'):
                        self.run_audit(sprr=bad)
    def test_modified_root_cpu_state_is_not_shared(self):
        self.cache[0]['flags']=10;states=self.sprr_states();states[1]['umprr']=0x40000
        with self.assertRaisesRegex(ValueError,'SPRR register state'):self.run_audit(sprr=states)
    def test_saved_policy_waits_for_each_cpu_switch(self):
        # Generation38: CONFIGURE_ROOT changes saved flags while a peer CPU
        # still has the old policy installed. Corrupt loaded records must not
        # turn that distinction into an unchecked SPRR-state exception.
        self.cache[0]['flags']=11;states=self.sprr_states()
        loaded=[dict(root=0x10000 if cpu in (0,3) else 0,
                     flags=10 if cpu in (0,3) else 0,resets=1) for cpu in range(6)]
        self.assertEqual(self.run_audit(sprr=states,loaded=loaded)['loaded'],loaded)
        with self.assertRaisesRegex(ValueError,'SPRR register state'):self.run_audit(sprr=states)
        for field in ('root','flags','resets'):
            for cpu in range(6):
                bad=[dict(row) for row in loaded]
                bad[cpu][field]^=2
                with self.subTest(cpu=cpu,field=field),self.assertRaises(ValueError):
                    self.run_audit(sprr=states,loaded=bad)
        for bit in (1,3,5,7,16):
            bad=[dict(row) for row in loaded];bad[0]['flags']^=1<<bit
            with self.assertRaises(ValueError):self.run_audit(sprr=states,loaded=bad)
        for cpu in (0,3):
            loaded[cpu]['flags']=11;loaded[cpu]['resets']+=1
            states[cpu]['umprr']=0x40800;states[cpu]['resets']+=1
            self.assertEqual(self.run_audit(sprr=states,loaded=loaded)['loaded'],loaded)
        bad=[dict(row) for row in loaded];bad[3]['flags']=10
        with self.assertRaisesRegex(ValueError,'SPRR register state'):
            self.run_audit(sprr=states,loaded=bad)
        with self.assertRaises(ValueError):self.run_audit(sprr=states,loaded=loaded[:-1])
    def test_kernel_aperture_grant_does_not_change_user_permissions(self):
        self.cache[0]['flags']=10;states=self.sprr_states();states[2]['pperm']|=0x100
        self.assertEqual(self.run_audit(sprr=states)['sprr'],states)
    def test_tpro_state_change_without_affected_leaves_is_per_cpu(self):
        self.cache[0]['flags']=10;states=self.sprr_states()
        states[0]['uperm']|=1<<36
        self.assertEqual(self.run_audit(sprr=states)['sprr'],states)
        for cpu in (1,2,4,5):
            bad=[dict(row) for row in states];bad[cpu]['uperm']|=1<<36
            with self.subTest(cpu=cpu),self.assertRaisesRegex(ValueError,'enabled root policy'):
                self.run_audit(sprr=bad)
        self.gput(0x8008,0x20000|0x20000000000783)
        for i in range(4):self.hput(0x3020+8*i,0x20000+0x1000*i|0x20000000000783)
        with self.assertRaisesRegex(ValueError,'SPRR permission translation'):
            self.run_audit(sprr=states)
    def test_invalid_register_counters_or_cpu_count(self):
        self.cache[0]['flags']=10
        for bad in ('resets','rejected'):
            states=self.sprr_states();states[0][bad]=0 if bad=='resets' else 1
            with self.assertRaisesRegex(ValueError,'SPRR lifecycle'):self.run_audit(sprr=states)
        with self.assertRaisesRegex(ValueError,'SPRR CPU count'):self.run_audit(sprr=self.sprr_states()[:-1])
    def test_matching_raw_attributes_do_not_qualify_tpro_translation(self):
        self.cache[0]['flags']=10
        self.gput(0x8008,0x20000|0x20000000000783)
        for i in range(4):self.hput(0x3020+8*i,0x20000+0x1000*i|0x20000000000783)
        with self.assertRaisesRegex(ValueError,'SPRR permission translation'):
            self.run_audit(sprr=self.sprr_states())

if __name__=='__main__':unittest.main()
