#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location('audit_dart',Path(__file__).with_name('audit-dart-tables.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
BASE=0x8c0000000;SIZE=0x40000;FM=BASE+0x4000
ROOT=BASE+0x10000;MID=BASE+0x14000;LEAF=BASE+0x18000;FREE=BASE+0x1c000


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.ram=bytearray(SIZE)
        for pa,level,refs in ((ROOT,0,2),(MID,1,2),(LEAF,2,1),(FREE,0,0)):
            e=self.offset(pa)
            self.ram[e:e+16]=bytes([0,0,24,0,refs,0,5,0,21,1,level,0,0,0,0,0])
        self.put(ROOT+16*8,(MID>>4)|1)
        self.put(MID+3*8,(LEAF>>4)|1)
        self.args=dict(frame_map=FM,frame_low=BASE,frame_high=BASE+SIZE,
            alloc_low=ROOT,alloc_high=BASE+SIZE,roots=[(21,0,0),(21,1,(ROOT>>12)|1)])

    def offset(self,pa):return FM-BASE+((pa-BASE)>>14)*16
    def put(self,pa,value):struct.pack_into('<Q',self.ram,pa-BASE,value)
    def read(self,pa,size):
        self.assertTrue(BASE<=pa<pa+size<=BASE+SIZE)
        return bytes(self.ram[pa-BASE:pa-BASE+size])
    def audit(self):return module.audit(self.read,**self.args)

    def test_graph_and_unattached_allocation(self):
        before=bytes(self.ram);result=self.audit()
        self.assertEqual(result['mismatches'],[])
        self.assertEqual(result['attached_tables'],3)
        self.assertEqual(result['unattached_frames'],[hex(FREE)])
        self.assertEqual(bytes(self.ram),before)

    def test_sep_two_level_root_and_biased_leaf(self):
        self.ram=bytearray(SIZE)
        for pa,level,refs in ((ROOT,1,2),(LEAF,2,2)):
            e=self.offset(pa)
            self.ram[e:e+16]=bytes([0,0,24,0,refs,0,5,0,20,0,level,0,0,0,0,0])
        self.ram[self.offset(FREE)+2]=11
        self.put(ROOT,(LEAF>>4)|1)
        self.put(LEAF+8,(FREE>>4)|1|(0xfff<<40))
        self.args['roots']=[(20,0,(ROOT>>12)|1,1)]
        result=self.audit()
        self.assertEqual(result['mismatches'],[])
        self.assertEqual(result['attached_tables'],2)
        self.assertEqual(result['leaves'][0]['iova'],'0x10000004000')
        self.assertEqual(result['data_references'],[dict(pa=hex(FREE),readonly=0,other=1)])
        self.put(LEAF+8,0);self.put(LEAF,(FREE>>4)|1|(0xfff<<40))
        self.assertTrue(any(m['field']=='leaf window' for m in self.audit()['mismatches']))
        self.args['roots']=[(20,0,(ROOT>>12)|1,9)]
        with self.assertRaises(ValueError):self.audit()

    def reserved_sep(self):
        self.ram=bytearray(SIZE);firmware=BASE+0x8000
        for pa,level in ((ROOT,1),(LEAF,2)):
            off=self.offset(pa)
            self.ram[off:off+16]=bytes([0,0,24,0,2,0,5,0,20,0,level,0,0,0,0,0])
        self.ram[self.offset(firmware)+2]=11
        struct.pack_into('<I',self.ram,self.offset(firmware)+12,1)
        self.put(ROOT,(LEAF>>4)|1);self.put(LEAF+8,(firmware>>4)|1|(0xfff<<40))
        self.args.update(roots=[(20,0,(ROOT>>12)|1,1)],sep_firmware=(firmware,0x4000))
        return firmware

    def test_reserved_sep_counts_and_no_reclaimable_ownership(self):
        firmware=self.reserved_sep();before=bytes(self.ram)
        result=self.audit();self.assertEqual(result['mismatches'],[])
        self.assertEqual(result['data_references'],[dict(pa=hex(firmware),readonly=0,other=1)])
        spec=importlib.util.spec_from_file_location('audit_cpu',Path(__file__).with_name('audit-sptm-refs.py'))
        cpu=importlib.util.module_from_spec(spec);spec.loader.exec_module(cpu)
        args={k:v for k,v in self.args.items() if k!='roots'}
        args.update(root=BASE,aperture_va=0xfffffe0100000000,aperture_size=SIZE,
                    ram_low=BASE,ram_high=BASE+SIZE,dma_references=result['data_references'])
        combined=cpu.audit(self.read,**args)
        self.assertEqual(combined['mismatches'],[])
        self.assertEqual(combined['sep_firmware_frames_audited'],1)
        self.assertEqual(combined['sep_firmware_dma_mappings'],1)
        self.assertEqual(combined['boot_data_frames'],0)
        self.assertEqual(bytes(self.ram),before)
        struct.pack_into('<I',self.ram,self.offset(firmware)+12,2)
        self.assertEqual(len(cpu.audit(self.read,**args)['mismatches']),1)
        self.ram[self.offset(firmware)+2]=24
        with self.assertRaises(ValueError):cpu.audit(self.read,**args)

    def test_reserved_sep_wrong_stream_and_table_refused(self):
        firmware=self.reserved_sep()
        self.args['roots']=[(20,1,(ROOT>>12)|1,1)]
        self.ram[self.offset(ROOT)+9]=self.ram[self.offset(LEAF)+9]=1
        self.assertTrue(any(x['field']=='leaf descriptor' for x in self.audit()['mismatches']))
        firmware=self.reserved_sep();self.put(ROOT,(firmware>>4)|1)
        self.assertTrue(any(x['field']=='table address' for x in self.audit()['mismatches']))

    def test_released_sep_is_ordinary_managed_memory(self):
        # After the SEP boots XNU frees the extent to the VM: another stream
        # may then map it, even as a table, and it counts like arena memory.
        firmware=self.reserved_sep();self.args['sep_released']=True
        result=self.audit();self.assertEqual(result['mismatches'],[])
        self.assertEqual(result['data_references'],[dict(pa=hex(firmware),readonly=0,other=1)])
        spec=importlib.util.spec_from_file_location('audit_cpu',Path(__file__).with_name('audit-sptm-refs.py'))
        cpu=importlib.util.module_from_spec(spec);spec.loader.exec_module(cpu)
        args={k:v for k,v in self.args.items() if k!='roots'}
        args.update(root=BASE,aperture_va=0xfffffe0100000000,aperture_size=SIZE,
                    ram_low=BASE,ram_high=BASE+SIZE,dma_references=result['data_references'])
        combined=cpu.audit(self.read,**args)
        self.assertEqual(combined['mismatches'],[])
        self.assertTrue(combined['sep_firmware_released'])
        self.assertEqual(combined['sep_firmware_frames_audited'],0)
        # Released frames may take any XNU type: a reserved one could not.
        self.ram[self.offset(firmware)+2]=20;struct.pack_into('<I',self.ram,self.offset(firmware)+12,0)
        args['dma_references']=[]
        self.assertEqual(cpu.audit(self.read,**args)['mismatches'],[])
        args['sep_released']=False
        with self.assertRaises(ValueError):cpu.audit(self.read,**args)
        # A released extent must still be a loader extent below the arena.
        for extent in [(ROOT,0x4000),(FM,0x4000),(firmware+1,0x4000)]:
            with self.subTest(extent=extent),self.assertRaises(ValueError):
                module.ManagedFrames(FM,BASE,BASE+SIZE,ROOT,BASE+SIZE,released=extent)

    def test_reserved_sep_geometry_refused(self):
        firmware=self.reserved_sep()
        for extent in [(0,0x4000),(firmware,0),(firmware+1,0x4000),
                       (FM,0x4000),(ROOT,0x4000),(firmware,0x1004000),
                       (BASE-0x4000,0x4000),(firmware,0x4001)]:
            self.args['sep_firmware']=extent
            with self.subTest(extent=extent),self.assertRaises(ValueError):self.audit()

    def test_reclaimed_table_graph_and_dma_data(self):
        boot=[(0xfffffe0008000000,ROOT,4)]
        self.args.update(alloc_low=FREE+0x4000,boot_ranges=boot,
                         boot_aliases=[(0xfffffe030c000000,ROOT,4)])
        off=self.offset(FREE);self.ram[off:off+16]=bytes([0,0,11,0,0,0,0,0])+bytes(8)
        self.put(LEAF,(FREE>>4)|1|(0xfff<<40));self.ram[self.offset(LEAF)+4]=2
        result=self.audit()
        self.assertEqual(result['mismatches'],[])
        self.assertEqual((result['attached_tables'],result['dma_mappings']),(3,1))
        self.assertEqual(result['data_references'],[dict(pa=hex(FREE),readonly=0,other=1)])
        self.args.update(boot_ranges=[],boot_aliases=[])
        self.assertTrue(any(m['field']=='table address' for m in self.audit()['mismatches']))

    def test_reference_mismatch(self):
        self.ram[self.offset(ROOT)+4]=3
        self.assertEqual(self.audit()['mismatches'],
            [dict(pa=hex(ROOT),field='references',expected=2,actual=3)])

    def test_cross_owner(self):
        self.ram[self.offset(MID)+8]=20
        self.assertTrue(any(m['field']=='ownership' for m in self.audit()['mismatches']))

    def test_shared_and_cyclic_tables(self):
        self.put(ROOT+17*8,(MID>>4)|1);self.ram[self.offset(ROOT)+4]=3
        self.assertTrue(any(m['field']=='attachment' for m in self.audit()['mismatches']))
        self.put(ROOT+17*8,0);self.ram[self.offset(ROOT)+4]=2
        self.put(MID+3*8,(ROOT>>4)|1)
        self.assertTrue(any(m['field']=='attachment' for m in self.audit()['mismatches']))

    def test_malformed_and_outside_owned_memory(self):
        self.put(ROOT+16*8,(MID>>4)|5)
        self.assertTrue(any(m['field']=='table descriptor' for m in self.audit()['mismatches']))
        self.put(ROOT+16*8,((BASE+SIZE)>>4)|1)
        self.assertTrue(any(m['field']=='table address' for m in self.audit()['mismatches']))

    def test_stream_window_and_orphans(self):
        self.put(ROOT+16*8,0);self.put(ROOT+15*8,(MID>>4)|1)
        self.assertTrue(any(m['field']=='root slot' for m in self.audit()['mismatches']))
        self.ram[self.offset(FREE)+4]=1
        self.assertTrue(any(m['field']=='unattached references' for m in self.audit()['mismatches']))

    def test_unsupported_dma_type_and_invalid_roots(self):
        self.put(LEAF,(FREE>>4)|1);self.ram[self.offset(LEAF)+4]=2
        self.assertTrue(any(m['field']=='DMA frame' for m in self.audit()['mismatches']))
        self.args['roots']=[(21,1,2)]
        with self.assertRaises(ValueError):self.audit()
        self.args['roots']=[(21,1,0),(21,1,0)]
        with self.assertRaises(ValueError):self.audit()

    def test_dma_aliases_permissions_and_partial_bounds(self):
        off=self.offset(FREE);self.ram[off:off+16]=bytes([0,0,11,0,0,0,0,0])+bytes(8)
        self.put(LEAF,(FREE>>4)|1|(0xfff<<40))
        self.put(LEAF+8,(FREE>>4)|5|(2<<52)|(3<<40))
        self.ram[self.offset(LEAF)+4]=3
        result=self.audit()
        self.assertEqual(result['mismatches'],[])
        self.assertEqual(result['dma_mappings'],2)
        self.assertEqual(result['data_references'],[dict(pa=hex(FREE),readonly=1,other=1)])
        self.assertEqual(result['leaves'][1],dict(iova=hex((1<<40)+(3<<25)+0x4000),
            pa=hex(FREE),device_id=21,sid=1,readonly=True,no_read=False,begin=8,end=16))

    def test_dma_descriptor_refusal(self):
        off=self.offset(FREE);self.ram[off:off+16]=bytes([0,0,11,0,0,0,0,0])+bytes(8)
        self.ram[self.offset(LEAF)+4]=2
        for pte in [(FREE>>4)|3, (FREE>>4)|1|(4<<52)|(3<<40),
                    ((BASE+SIZE)>>4)|1, (FREE>>4)|1|(1<<39)]:
            with self.subTest(pte=hex(pte)):
                self.put(LEAF,pte)
                self.assertTrue(any(m['field']=='leaf descriptor' for m in self.audit()['mismatches']))

    def test_combined_cpu_and_dart_graphs(self):
        spec=importlib.util.spec_from_file_location('audit_cpu',Path(__file__).with_name('audit-sptm-refs.py'))
        cpu=importlib.util.module_from_spec(spec);spec.loader.exec_module(cpu)
        off=self.offset(FREE);self.ram[off:off+16]=bytes([0,0,11,0,0,0,0,0])+bytes(8)
        self.put(LEAF,(FREE>>4)|1|(0xfff<<40))
        self.put(LEAF+8,(FREE>>4)|5|(0xfff<<40))
        self.ram[self.offset(LEAF)+4]=3
        self.put(BASE,(BASE+0x8000)|3)
        self.put(BASE+0x8000,(BASE+0xc000)|3)
        self.put(BASE+0xc000,FREE|0x0060000000000703)
        struct.pack_into('<2I',self.ram,off+8,1,2) # CPU RW + DMA RO/RW.
        args={k:v for k,v in self.args.items() if k!='roots'}
        args.update(root=BASE,aperture_va=0xfffffe0100000000,aperture_size=SIZE,
                    ram_low=BASE,ram_high=BASE+SIZE)
        dart=self.audit();self.assertEqual(dart['mismatches'],[])
        self.assertEqual(len(cpu.audit(self.read,**args)['mismatches']),1)
        result=cpu.audit(self.read,dma_references=dart['data_references'],**args)
        self.assertEqual(result['mismatches'],[])
        self.assertEqual((result['data_mappings'],result['dma_mappings']),(1,2))
        struct.pack_into('<I',self.ram,off+12,1)
        self.assertEqual(len(cpu.audit(self.read,dma_references=dart['data_references'],
                                      **args)['mismatches']),1)


if __name__=='__main__':unittest.main()
