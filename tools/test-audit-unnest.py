#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent removed/source edges and accounting, with fault injection."""
from pathlib import Path
import runpy,struct,unittest
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'tools/test-audit-nest.py'))
audit=runpy.run_path(str(ROOT/'tools/audit-unnest-region.py'))['audit_unnesting']
BASE,PAGE,USER,SHARED,START=[n[k] for k in ('BASE','PAGE','USER','SHARED','START')]
class UnnestAuditTests(unittest.TestCase):
    def fixture(self,fmt):
        data,read,kwargs,nest_blob=n['NestAuditTests']().fixture(fmt)
        shift=12 if fmt else 14;page=1<<shift;span=1<<(2*shift-3);mask=(1<<48)-page
        def l2(root):
            table=root
            for level in range(0 if fmt else 1,3):
                idx=(START>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1)
                slot=table+8*idx;pte=struct.unpack('<Q',read(slot,8))[0]
                if level==2:return slot,pte
                table=pte&mask
        dst,pte=l2(USER);src,_=l2(SHARED)
        struct.pack_into('<Q',data,dst-BASE,0)
        for frame,field in ((dst&~0x3fff,8),(pte&~0x3fff,6)):
            off=((frame-BASE)>>14)*16+field
            old=struct.unpack_from('<H',data,off)[0];struct.pack_into('<H',data,off,old-1)
        values=[1,1,1,USER,SHARED,START+page,1,0,fmt,START,span,1,1,1,1]+[0]*31
        return data,read,kwargs,nest_blob,values,dst,src,pte
    def test_valid_both_geometries_and_full_references(self):
        for fmt in (0,1):
            data,read,kwargs,nest_blob,words,*_=self.fixture(fmt)
            ownership=n['refs'](read,**kwargs);self.assertEqual(ownership['mismatches'],[])
            report=audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
            self.assertEqual(len(report['current_removed_descriptors']),1)
            result=n['nest'](read,nest_blob,frame_map=BASE,frame_low=BASE,ownership=ownership,removed=1)
            self.assertEqual(result['last_retired_descriptors'],1)
            with self.assertRaises(ValueError):
                n['nest'](read,nest_blob,frame_map=BASE,frame_low=BASE,ownership=ownership)
    def test_stale_alias_lost_source_or_released_child(self):
        for fmt in (0,1):
            for kind in range(3):
                data,read,kwargs,nb,words,dst,src,pte=self.fixture(fmt)
                if kind==0:struct.pack_into('<Q',data,dst-BASE,pte)
                elif kind==1:struct.pack_into('<Q',data,src-BASE,0)
                else:struct.pack_into('<H',data,(((pte&~0x3fff)-BASE)>>14)*16+6,0)
                with self.subTest(fmt=fmt,kind=kind),self.assertRaises(ValueError):
                    audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
    def test_bad_witness(self):
        for fmt in (0,1):
            for field,value in ((0,0),(1,0),(2,0),(5,START+1),(6,0),(7,6),
                (8,2),(9,START+1),(10,1),(11,2049),(12,2),(13,2049),(14,2),(45,1<<63)):
                data,read,kwargs,nb,words,*_=self.fixture(fmt);words[field]=value
                with self.subTest(fmt=fmt,field=field),self.assertRaises(ValueError):
                    audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
    def test_empty(self):
        def forbidden(*args):raise AssertionError('empty witness must not read')
        self.assertEqual(audit(forbidden,bytes(368),frame_map=BASE,frame_low=BASE)['calls'],0)
        with self.assertRaises(ValueError):
            n['nest'](forbidden,bytes(64),frame_map=BASE,frame_low=BASE,
                ownership={'nested_descriptors':0},removed=1)
    def test_private_replacement_requires_distinct_ordinary_l3(self):
        for fmt in (0,1):
            for corruption in (None,'shared','level','links','same_child'):
                data,read,kwargs,nb,words,dst,src,pte=self.fixture(fmt)
                child=BASE+180*PAGE;off=((child-BASE)>>14)*16
                data[child-BASE:child-BASE+PAGE]=bytes(PAGE)
                data[off:off+16]=bytes(16);data[off+2]=20;data[off+4]=3
                struct.pack_into('<H',data,off+6,1)
                struct.pack_into('<Q',data,dst-BASE,child|3)
                parent=(((dst&~0x3fff)-BASE)>>14)*16+8
                struct.pack_into('<H',data,parent,struct.unpack_from('<H',data,parent)[0]+1)
                if fmt:
                    # An ordinary 4K L3 occupies a complete four-descriptor
                    # allocation group. Model the other three removals too.
                    for part in range(1,4):
                        struct.pack_into('<Q',data,dst-BASE+part*8,(child+part*4096)|3)
                    shared_links=(((pte&~0x3fff)-BASE)>>14)*16+6
                    struct.pack_into('<H',data,shared_links,struct.unpack_from('<H',data,shared_links)[0]-3)
                    struct.pack_into('<H',data,parent,struct.unpack_from('<H',data,parent)[0]-3)
                    words[0]=words[1]=words[2]=4
                if corruption=='shared':data[off+2]=21
                if corruption=='level':data[off+4]=2
                if corruption=='links':data[off+6]=2
                if corruption=='same_child':struct.pack_into('<Q',data,dst-BASE,pte)
                with self.subTest(fmt=fmt,corruption=corruption):
                    if corruption:
                        with self.assertRaises(ValueError):
                            audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
                    else:
                        ownership=n['refs'](read,**kwargs);self.assertEqual(ownership['mismatches'],[])
                        report=audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
                        self.assertEqual(report['current_removed_descriptors'][0]['consumer_replacement'],hex(child|3))
    def test_retired_root_requires_zero_metadata_and_descriptors(self):
        for fmt in (0,1):
            for dirty in (False,True):
                data,read,kwargs,nb,words,*_=self.fixture(fmt)
                off=((USER-BASE)>>14)*16;data[off:off+16]=bytes([0,0,11])+bytes(13)
                data[USER-BASE:USER-BASE+PAGE]=bytes(PAGE)
                if dirty:data[USER-BASE+PAGE-1]=1
                if dirty:
                    with self.assertRaises(ValueError):audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
                else:
                    self.assertTrue(audit(read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)['retired_root'])
if __name__=='__main__':unittest.main()
