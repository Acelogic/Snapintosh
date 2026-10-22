#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent auditor must include inactive user mappings and commpage roles."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('audit_refs', Path(__file__).with_name('audit-sptm-refs.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
BASE, SIZE = 0x90000000, 0x40000
ROOT, FM, USER, L2, L3, DATA = (BASE + n for n in (0, 0x4000, 0x10000, 0x14000, 0x18000, 0x1c000))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.ram = bytearray(SIZE)
        self.args = dict(root=ROOT, frame_map=FM, frame_low=BASE, frame_high=BASE+SIZE,
                         alloc_low=USER, alloc_high=BASE+SIZE, aperture_va=0xfffffe0100000000,
                         aperture_size=SIZE, ram_low=BASE, ram_high=BASE+SIZE)
        self.meta(USER, 18, 0)
        struct.pack_into('<H', self.ram, self.meta(USER, 18, 0)+10, 2)
        self.meta(L2, 20, 2)
        self.meta(L3, 23, 3)
        self.meta(DATA, 29, 0)

    def read(self, pa, size):
        self.assertTrue(BASE <= pa < pa + size <= BASE + SIZE)
        return bytes(self.ram[pa-BASE:pa-BASE+size])

    def put(self, pa, value):
        struct.pack_into('<Q', self.ram, pa-BASE, value)

    def meta(self, pa, kind, level):
        off = FM-BASE + ((pa-BASE) >> 14)*16
        self.ram[off+2] = kind
        self.ram[off+4] = level
        if kind==18:self.ram[off+8]=255
        if kind==19:self.ram[off+8]=0
        return off

    def populate(self, va):
        self.put(USER + ((va >> 36) & 2047)*8, L2 | 3)
        self.put(L2 + ((va >> 25) & 2047)*8, L3 | 3)
        self.put(L3 + ((va >> 14) & 2047)*8, DATA | 0x00600000000007c3)
        struct.pack_into('<H', self.ram, self.meta(L3, 23, 3)+8, 1)
        struct.pack_into('<I', self.ram, self.meta(DATA, 29, 0)+8, 1)
        for pa in (USER, L2, L3):
            struct.pack_into('<H', self.ram, FM-BASE+((pa-BASE)>>14)*16+6, 1)
        struct.pack_into('<H', self.ram, self.meta(L2, 20, 2)+8, 1)

    def test_active_cpu_root_references(self):
        self.populate(0xfffffc000)
        struct.pack_into('<H',self.ram,FM-BASE+((USER-BASE)>>14)*16+6,3)
        result=module.audit(self.read,**self.args,user_roots=[USER],active_user_roots=[USER,USER])
        self.assertEqual(result['mismatches'],[])
        missed=module.audit(self.read,**self.args,user_roots=[USER])
        self.assertEqual(len(missed['mismatches']),1)
        with self.assertRaises(ValueError):
            module.audit(self.read,**self.args,user_roots=[USER],active_user_roots=[L2])

    def test_address_pauth_flag_preserves_mapping_ownership(self):
        self.populate(0xfffffc000)
        off=FM-BASE+((USER-BASE)>>14)*16+10
        for flags in (0,1,2,3,8,9,10,11):
            struct.pack_into('<H',self.ram,off,flags)
            self.assertEqual(module.audit(self.read,**self.args,user_roots=[USER])['mismatches'],[])
        for flags in (4,6,0x10,0x80,0x100):
            struct.pack_into('<H',self.ram,off,flags)
            with self.assertRaisesRegex(ValueError,'USER_ROOT'):
                module.audit(self.read,**self.args,user_roots=[USER])

    def test_executable_frame_counts_and_writable_alias_refusal(self):
        va=0x4000;self.populate(va);self.meta(L3,20,3)
        off=self.meta(DATA,14,0);struct.pack_into('<2I',self.ram,off+8,0,1)
        self.put(L3+8,DATA|0x0020000000000ec3)
        self.assertEqual(module.audit(self.read,**self.args,user_roots=[USER])['mismatches'],[])
        self.put(L3+8,DATA|0x0060000000000e43)
        with self.assertRaisesRegex(ValueError,'USER_EXEC frame'):
            module.audit(self.read,**self.args,user_roots=[USER])

    def test_tpro_mixed_aliases_and_permission_refusal(self):
        self.populate(0x4000);self.meta(L3,20,3)
        off=self.meta(DATA,17,0)
        struct.pack_into('<H',self.ram,self.meta(USER,18,0)+10,0xa)
        self.put(L3+8,DATA|0x0020000000000e83)
        self.put(L3+16,DATA|0x0060000000000ec3)
        self.put(L3+24,DATA|0x0060000000000e43)
        struct.pack_into('<H',self.ram,self.meta(L3,20,3)+8,3)
        struct.pack_into('<2I',self.ram,off+8,1,2)
        self.assertEqual(module.audit(self.read,**self.args,user_roots=[USER])['mismatches'],[])
        # WAS_WRITABLE is software history on TPRO leaves (class 9 -> 25):
        # still one non-readonly reference, as the monitor counts it.
        self.put(L3+8,DATA|0x0820000000000e83)
        self.assertEqual(module.audit(self.read,**self.args,user_roots=[USER])['mismatches'],[])
        self.put(L3+8,DATA|0x0020000000000ec3)
        with self.assertRaisesRegex(ValueError,'USER_TPRO frame'):
            module.audit(self.read,**self.args,user_roots=[USER])
        self.put(L3+8,DATA|0x0020000000000e83)
        self.ram[off+3]=1
        with self.assertRaisesRegex(ValueError,'USER_TPRO metadata'):
            module.audit(self.read,**self.args,user_roots=[USER])

    def test_shared_root_inventory_and_child_references(self):
        off=self.meta(USER,19,0)
        self.ram[off+10]=0
        result=module.audit(self.read,**self.args,shared_roots=[USER])
        self.assertEqual(result['mismatches'],[])
        self.assertEqual(result['active_tables'],2)
        self.ram[off+6]=1
        self.assertEqual(len(module.audit(self.read,**self.args,shared_roots=[USER])['mismatches']),1)
        self.put(USER,L2|3)
        self.meta(L2,21,2)
        self.ram[FM-BASE+((L2-BASE)>>14)*16+6]=1
        self.assertEqual(module.audit(self.read,**self.args,shared_roots=[USER])['mismatches'],[])
        self.meta(L2,20,2)
        with self.assertRaises(ValueError):module.audit(self.read,**self.args,shared_roots=[USER])
        self.meta(L2,21,2)
        for field,value in [(4,1),(8,255),(10,2),(12,2)]:
            old=self.ram[off+field];self.ram[off+field]=value
            with self.assertRaises(ValueError):module.audit(self.read,**self.args,shared_roots=[USER])
            self.ram[off+field]=old
        other=BASE+0x20000;self.meta(other,19,0)
        with self.assertRaises(ValueError):module.audit(self.read,**self.args,shared_roots=[USER,other])

    def test_shared_binding_references(self):
        shared=BASE+0x20000
        u=self.meta(USER,18,7);p=self.meta(shared,19,0)
        self.ram[u+8]=0;self.ram[p+4]=1
        result=module.audit(self.read,**self.args,user_roots=[USER],shared_roots=[shared])
        self.assertEqual(result['mismatches'],[])
        for target,offset,value in [(p,4,0),(p,4,2),(p,12,1),(u,8,1),(u,9,1)]:
            old=self.ram[target+offset];self.ram[target+offset]=value
            with self.assertRaises(ValueError):
                module.audit(self.read,**self.args,user_roots=[USER],shared_roots=[shared])
            self.ram[target+offset]=old
        with self.assertRaises(ValueError):module.audit(self.read,**self.args,user_roots=[USER])

    def test_shared_table_hierarchy_both_formats(self):
        for fmt in (0,1):
            self.setUp()
            off=self.meta(USER,19,0);self.ram[off+10]=0;self.ram[off+12]=fmt
            start=0 if fmt else 1
            frames=[USER]+[BASE+0x20000] * fmt+[L2,L3]
            for level in range(start,3):
                parent=frames[level-start];child=frames[level-start+1]
                self.meta(child,21,level+1)
                for n in range(4 if fmt else 1):self.put(parent+8*n,(child+n*0x1000)|3)
                self.ram[FM-BASE+((parent-BASE)>>14)*16+(6 if level==start else 8)]=1
                self.ram[FM-BASE+((child-BASE)>>14)*16+6]=1
            result=module.audit(self.read,**self.args,shared_roots=[USER])
            self.assertEqual(result['mismatches'],[])
            self.assertEqual(result['active_tables'],len(frames)+1)
            self.assertEqual(result['data_mappings'],0)
            self.meta(L3,20,3)
            with self.assertRaises(ValueError):module.audit(self.read,**self.args,shared_roots=[USER])
            self.meta(L3,21,3)
            self.ram[FM-BASE+((L3-BASE)>>14)*16+8]=1
            result=module.audit(self.read,**self.args,shared_roots=[USER])
            self.assertTrue(any(x.get('pa')==hex(L3) for x in result['mismatches']))

    def test_unattached_shared_table_references(self):
        off=self.meta(L2,21,2)
        self.assertEqual(module.audit(self.read,**self.args)['mismatches'],[])
        for field in (6,8):
            self.ram[off+field]=1
            self.assertTrue(module.audit(self.read,**self.args)['mismatches'])
            self.ram[off+field]=0

    def test_condemned_ordinary_tables_retain_leaf_references(self):
        for fmt in (0, 1):
            with self.subTest(format=fmt):
                self.setUp()
                if fmt:
                    self.populate_4k()
                    slots = [L2+0x3000+(508+n)*8 for n in range(4)]
                else:
                    self.populate(0xfffffc000)
                    slots = [L2+((0xfffffc000 >> 25)&2047)*8]
                self.meta(L3, 20, 3)
                for n, slot in enumerate(slots):
                    self.put(slot, (L3+n*0x1000) | 7)
                result = module.audit(self.read, **self.args, user_roots=[USER])
                self.assertEqual(result['mismatches'], [])
                self.assertEqual(result['data_mappings'], 4 if fmt else 1)
                self.meta(L3, 23, 3)
                with self.assertRaises(ValueError):
                    module.audit(self.read, **self.args, user_roots=[USER])
                self.meta(L3, 20, 3)
                if fmt:
                    self.put(slots[-1], (L3+0x3000) | 3)
                    with self.assertRaises(ValueError):
                        module.audit(self.read, **self.args, user_roots=[USER])
                else:
                    self.put(USER, L2 | 7)
                    with self.assertRaises(ValueError):
                        module.audit(self.read, **self.args, user_roots=[USER])

    def test_user_mappings_are_required(self):
        self.populate(0xfffffc000)
        omitted = module.audit(self.read, **self.args)
        self.assertEqual(len(omitted['mismatches']), 2)
        included = module.audit(self.read, **self.args, user_roots=[USER])
        self.assertEqual(included['mismatches'], [])
        self.assertEqual((included['data_mappings'], included['tracked_l3_tables']), (1, 1))
        self.put(L3+((0xfffffc000 >> 14)&2047)*8, 0)
        self.assertEqual(len(module.audit(self.read, **self.args, user_roots=[USER])['mismatches']), 2)

    def test_reclaimed_image_mapping_and_exact_alias(self):
        self.ram=bytearray(SIZE)
        bootva=0xfffffe0008000000
        data=BASE+0x10000;l2=BASE+0x8000;l3=BASE+0xc000
        self.args.update(alloc_low=BASE+0x20000,
            boot_ranges=[(bootva,data,1)],boot_aliases=[(bootva,data,1)])
        self.put(ROOT+((bootva>>36)&2047)*8,l2|3)
        self.put(l2+((bootva>>25)&2047)*8,l3|3)
        self.put(l3,data|0x0060000000000703)
        self.put(l3+8,data|0x0060000000000703)
        off=self.meta(data,11,0);struct.pack_into('<I',self.ram,off+12,1)
        result=module.audit(self.read,**self.args)
        self.assertEqual((result['mismatches'],result['data_mappings']),([],1))
        self.assertEqual((result['boot_frames_audited'],result['boot_cpu_mappings'],
                          result['boot_data_frames']),(1,1,1))
        struct.pack_into('<I',self.ram,off+12,2)
        result=module.audit(self.read,**self.args,
            dma_references=[dict(pa=hex(data),readonly=0,other=1)])
        self.assertEqual((result['mismatches'],result['dma_mappings']),([],1))
        # The exact bootstrap alias is exempt, never every mapping to that PA.
        struct.pack_into('<I',self.ram,off+12,0)
        self.assertEqual(module.audit(self.read,**self.args)['mismatches'],
            [dict(pa=hex(data),type=11,expected=(0,1),actual=(0,0))])
        with self.assertRaises(ValueError):
            module.audit(self.read,**dict(self.args,boot_aliases=[]))
        for boot in [[(bootva,FM,1)],[(bootva,data+1,1)],[(bootva,data,0)],
                     [(bootva,data,1),(bootva+0x4000,data,1)]]:
            with self.assertRaises(ValueError):
                module.audit(self.read,**dict(self.args,boot_ranges=boot))

    def test_iommu_owner_is_not_a_cpu_reference_count(self):
        off = self.meta(DATA, 24, 0)
        self.ram[off+6:off+11] = bytes([5, 0, 21, 1, 0])
        self.assertEqual(module.audit(self.read, **self.args)['mismatches'], [])
        self.populate(0xfffffc000)
        self.ram[off+2] = 24
        self.ram[off+6:off+11] = bytes([5, 0, 21, 1, 0])
        result = module.audit(self.read, **self.args, user_roots=[USER])
        self.assertEqual(result['mismatches'], [dict(pa=hex(DATA), type=24,
                                                   expected=(0, 0), actual=(1, 0))])

    def test_cpu_and_dma_share_counters(self):
        self.populate(0xfffffc000)
        off=self.meta(DATA,11,0)
        struct.pack_into('<2I',self.ram,off+8,3,1) # One CPU RO, two DMA RO, one DMA RW.
        refs=[dict(pa=hex(DATA),readonly=2,other=1)]
        omitted=module.audit(self.read,**self.args,user_roots=[USER])
        self.assertEqual(len(omitted['mismatches']),1)
        result=module.audit(self.read,**self.args,user_roots=[USER],dma_references=refs)
        self.assertEqual(result['mismatches'],[])
        self.assertEqual((result['data_mappings'],result['dma_mappings']), (1,3))
        struct.pack_into('<I',self.ram,off+12,0)
        self.assertEqual(len(module.audit(self.read,**self.args,user_roots=[USER],
                                         dma_references=refs)['mismatches']),1)

    def test_bad_dma_reference_witnesses(self):
        self.meta(DATA,11,0)
        good=dict(pa=hex(DATA),readonly=1,other=0)
        bad=[dict(pa=hex(ROOT),readonly=1,other=0),dict(pa=hex(DATA+1),readonly=1,other=0),
             dict(pa=hex(DATA),readonly=-1,other=2),dict(pa=hex(DATA),readonly=True,other=0),
             dict(pa=hex(DATA),readonly=0,other=0),dict(pa=hex(DATA),readonly=1<<31,other=0)]
        for ref in bad:
            with self.subTest(ref=ref):
                with self.assertRaises(ValueError):module.audit(self.read,**self.args,dma_references=[ref])
        with self.assertRaises(ValueError):module.audit(self.read,**self.args,dma_references=[good,good])
        self.meta(DATA,24,0)
        with self.assertRaises(ValueError):module.audit(self.read,**self.args,dma_references=[good])

    def test_kernel_aperture_exemption_is_not_a_user_exemption(self):
        self.populate(self.args['aperture_va'] & ((1 << 47)-1))
        result = module.audit(self.read, **self.args, user_roots=[USER])
        self.assertEqual(result['mismatches'], [])
        self.assertEqual(result['data_mappings'], 1)

    def test_rejects_unqualified_and_shared_roots(self):
        with self.assertRaises(ValueError):
            module.audit(self.read, **self.args, user_roots=[ROOT])
        with self.assertRaises(ValueError):
            module.audit(self.read, **self.args, user_roots=[USER, USER])
        self.ram[self.meta(USER, 18, 0)+12] = 2
        with self.assertRaises(ValueError):
            module.audit(self.read, **self.args, user_roots=[USER])

    def test_detached_commpage_retains_references(self):
        self.populate(0xfffffc000)
        self.put(L2+((0xfffffc000 >> 25)&2047)*8, 0)
        struct.pack_into('<H', self.ram, self.meta(L2, 20, 2)+8, 0)
        struct.pack_into('<H', self.ram, self.meta(L3, 23, 3)+6, 0)
        result = module.audit(self.read, **self.args, user_roots=[USER], detached_commpages=[L3])
        self.assertEqual(result['mismatches'], [])
        self.assertEqual(result['data_mappings'], 1)
        self.assertEqual((result['active_tables'], result['retained_tables'], result['audited_tables']), (3, 1, 4))
        struct.pack_into('<H', self.ram, self.meta(L3, 23, 3)+6, 1)
        with self.assertRaises(ValueError):
            module.audit(self.read, **self.args, detached_commpages=[L3])

    def populate_4k(self, flags=0x22):
        l1 = BASE+0x20000
        off = self.meta(USER, 18, 4)
        struct.pack_into('<H', self.ram, off+10, flags)
        struct.pack_into('<I', self.ram, off+12, 1)
        self.meta(l1, 20, 1)
        # VA ffffc000 selects the fourth 4K subtable in both L2 and L3.
        for n in range(4):
            self.put(USER+(252*8 if flags == 6 else 0)+n*8, (l1+n*0x1000) | 3)
            self.put(l1+(0x3000+508*8 if flags == 6 else 0)+n*8, (L2+n*0x1000) | 3)
            self.put(L2+0x3000+(508+n)*8, (L3+n*0x1000) | 3)
            self.put(L3+0x3000+(508+n)*8, (DATA+n*0x1000) | 0x00600000000007c3)
        for pa in (USER, l1, L2, L3):
            struct.pack_into('<H', self.ram, FM-BASE+((pa-BASE)>>14)*16+6, 1)
        for pa in (l1, L2):
            struct.pack_into('<H', self.ram, FM-BASE+((pa-BASE)>>14)*16+8, 1)
        struct.pack_into('<H', self.ram, self.meta(L3, 23, 3)+8, 4)
        struct.pack_into('<I', self.ram, self.meta(DATA, 29, 0)+8, 4)
        return l1

    def test_4k_subtables_and_data_offsets_share_frame_counts(self):
        self.populate_4k()
        result = module.audit(self.read, **self.args, user_roots=[USER])
        self.assertEqual(result['mismatches'], [])
        self.assertEqual((result['active_tables'], result['data_mappings'], result['data_frames']), (5, 4, 1))
        struct.pack_into('<H', self.ram, self.meta(USER, 18, 4)+6, 4)
        mismatch = module.audit(self.read, **self.args, user_roots=[USER])['mismatches']
        self.assertEqual(mismatch, [dict(pa=hex(USER), field='table links', expected=1, actual=4)])

    def test_4k_group_and_address_width_refusals(self):
        l1 = self.populate_4k()
        self.put(USER+24, 0)
        with self.assertRaisesRegex(ValueError, 'group'):
            module.audit(self.read, **self.args, user_roots=[USER])
        self.put(USER+24, (l1+0x3000) | 3)
        # The forced L1 quartet covers 2 TiB, but flags 0x22 permit only 4 GiB.
        self.put(l1+32, L2 | 3)
        self.put(l1+40, (L2+0x1000) | 3)
        self.put(l1+48, (L2+0x2000) | 3)
        self.put(l1+56, (L2+0x3000) | 3)
        with self.assertRaisesRegex(ValueError, 'out-of-range'):
            module.audit(self.read, **self.args, user_roots=[USER])

    def test_x86_4k_root_uses_the_last_l0_group(self):
        self.populate_4k(flags=6)
        result = module.audit(self.read, **self.args, user_roots=[USER])
        self.assertEqual(result['mismatches'], [])
        self.assertEqual((result['active_tables'], result['data_mappings']), (5, 4))

    def test_shared_commpage_counts_parent_links_but_not_duplicate_leaves(self):
        for fmt in (0,1):
            with self.subTest(format=fmt):
                self.setUp()
                old_l1=self.populate_4k() if fmt else None
                if not fmt:self.populate(0xfffffc000)
                user2,l22,l12=BASE+0x28000,BASE+0x2c000,BASE+0x30000
                copies=[(USER,user2),(L2,l22)]+([(old_l1,l12)] if fmt else [])
                remap=dict(copies)
                for old,new in copies:
                    self.ram[new-BASE:new-BASE+0x4000]=self.read(old,0x4000)
                    old_meta=FM-BASE+((old-BASE)>>14)*16
                    new_meta=FM-BASE+((new-BASE)>>14)*16
                    self.ram[new_meta:new_meta+16]=self.ram[old_meta:old_meta+16]
                    for i in range(2048):
                        pte=struct.unpack_from('<Q',self.ram,new-BASE+i*8)[0]
                        target=pte&0x0000ffffffffc000
                        if target in remap:self.put(new+i*8,remap[target]|(pte&~0x0000ffffffffc000))
                link=FM-BASE+((L3-BASE)>>14)*16+6
                struct.pack_into('<H',self.ram,link,2)
                result=module.audit(self.read,**self.args,user_roots=[USER,user2])
                self.assertEqual(result['mismatches'],[])
                self.assertEqual(result['data_mappings'],4 if fmt else 1)
                self.assertEqual(result['data_frames'],1)
                struct.pack_into('<H',self.ram,link,1)
                result=module.audit(self.read,**self.args,user_roots=[USER,user2])
                self.assertEqual(result['mismatches'],[dict(pa=hex(L3),field='table links',expected=2,actual=1)])
                struct.pack_into('<H',self.ram,link,2)
                data_count=FM-BASE+((DATA-BASE)>>14)*16+8
                struct.pack_into('<I',self.ram,data_count,8 if fmt else 2)
                result=module.audit(self.read,**self.args,user_roots=[USER,user2])
                self.assertEqual(len(result['mismatches']),1)
                self.assertEqual(result['mismatches'][0]['pa'],hex(DATA))
                self.meta(L3,20,3)
                with self.assertRaisesRegex(ValueError,'shared or cyclic ordinary'):
                    module.audit(self.read,**self.args,user_roots=[USER,user2])

    def test_duplicate_root_inventory_is_not_shared_commpage(self):
        self.populate(0xfffffc000)
        with self.assertRaises(ValueError):
            module.audit(self.read,**self.args,user_roots=[USER,USER])

    def test_detached_4k_commpage_retains_all_subpage_references(self):
        self.populate_4k()
        for n in range(4):
            self.put(L2+0x3000+(508+n)*8, 0)
        struct.pack_into('<H', self.ram, self.meta(L2, 20, 2)+8, 0)
        struct.pack_into('<H', self.ram, self.meta(L3, 23, 3)+6, 0)
        result = module.audit(self.read, **self.args, user_roots=[USER], detached_commpages=[L3])
        self.assertEqual(result['mismatches'], [])
        self.assertEqual((result['active_tables'], result['retained_tables'], result['data_mappings']), (4, 1, 4))


if __name__ == '__main__':
    unittest.main()
