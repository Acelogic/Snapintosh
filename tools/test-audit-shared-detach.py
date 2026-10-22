#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source retirement must have history plus live empty-table evidence."""
from pathlib import Path
import runpy,struct,unittest
ROOT=Path(__file__).resolve().parents[1]
u=runpy.run_path(str(ROOT/'tools/test-audit-unnest.py'))
d=runpy.run_path(str(ROOT/'tools/audit-shared-detach.py'))
BASE=u['BASE'];SHARED=u['SHARED'];START=u['START']
class SharedDetachAuditTests(unittest.TestCase):
    def fixture(self,fmt=0):
        data,read,kw,nb,words,dst,src,pte=u['UnnestAuditTests']().fixture(fmt)
        group=4 if fmt else 1;page=4096 if fmt else 16384;span=1<<(2*(12 if fmt else 14)-3)
        child=pte&~0x3fff;parent=src&~0x3fff
        old=struct.unpack_from('<H',data,((parent-BASE)>>14)*16+8)[0]
        # Fixture only: remove leaf data before the independently checked
        # source retirement. Full production ownership is audited separately.
        data[child-BASE:child-BASE+0x4000]=bytes(0x4000)
        struct.pack_into('<HH',data,((child-BASE)>>14)*16+6,0,0)
        struct.pack_into('<H',data,((parent-BASE)>>14)*16+8,old-1)
        for i in range(group):
            struct.pack_into('<Q',data,src-BASE+i*8,0)
            struct.pack_into('<Q',data,dst-BASE+i*8,0)
        off=(((dst&~0x3fff)-BASE)>>14)*16+8
        count=struct.unpack_from('<H',data,off)[0];struct.pack_into('<H',data,off,count-(group-1))
        words=[1,group,group,u['USER'],SHARED,START,group*span//page,0,fmt,START,span,group,group,group,(1<<group)-1]+[0]*31
        row=[SHARED,START,src,child,fmt,2,old,1]
        blob=bytearray(8+4096*64);struct.pack_into('<9Q',blob,0,1,*row)
        return data,read,nb,words,blob,row
    def test_source_retirement_is_explicit(self):
        data,read,nb,words,blob,row=self.fixture()
        report=d['audit_shared_detaches'](read,blob,frame_map=BASE,frame_low=BASE)
        # Two bindings at release, one after a later verified unbind.
        struct.pack_into('<Q',blob,8+7*8,2)
        report=d['audit_shared_detaches'](read,blob,frame_map=BASE,frame_low=BASE)
        self.assertEqual(report['current_bindings'],1)
        with self.assertRaises(ValueError):u['audit'](read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE)
        out=u['audit'](read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE,detachments=report['records'])
        self.assertTrue(out['current_removed_descriptors'][0]['source_detached'])
        nest=u['n']['nest'](read,nb,frame_map=BASE,frame_low=BASE,
            ownership={'nested_descriptors':1},removed=1,detachments=report['records'])
        self.assertEqual(nest['last_retired_descriptors'],1)
    def test_reused_child_accepted(self):
        # The monitor refuses a detach unless the table is all zero; after it
        # XNU may re-link the frame or RETYPE it to data and fill it (seen at
        # 25 min on the A16), so neither state is evidence of a bad detach.
        for kind in range(2):
            data,read,nb,words,blob,row=self.fixture();child=row[3]
            if kind==0:struct.pack_into('<H',data,((child-BASE)>>14)*16+6,1)
            else:
                data[((child-BASE)>>14)*16+2]=11;data[child-BASE:child-BASE+0x4000]=b'\xa5'*0x4000
            with self.subTest(kind=kind):
                d['audit_shared_detaches'](read,blob,frame_map=BASE,frame_low=BASE)
    def test_live_corruption_rejected(self):
        for kind in range(6):
            data,read,nb,words,blob,row=self.fixture();child=row[3];src=row[2]
            if kind==0:struct.pack_into('<Q',data,src-BASE,child|3)
            elif kind==1:data[((child-BASE)>>14)*16]=1         # in-flight state
            elif kind==2:data[child-BASE+0x3fff]=1
            elif kind==3:struct.pack_into('<H',data,((SHARED-BASE)>>14)*16+4,0xfffa)
            elif kind==4:blob[-1]=1
            else:struct.pack_into('<Q',blob,8+5*8,3)
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                d['audit_shared_detaches'](read,blob,frame_map=BASE,frame_low=BASE)
    def test_four_k_group_and_ring(self):
        data,read,nb,words,blob,row=self.fixture(1)
        report=d['audit_shared_detaches'](read,blob,frame_map=BASE,frame_low=BASE)
        out=u['audit'](read,struct.pack('<46Q',*words),frame_map=BASE,frame_low=BASE,detachments=report['records'])
        self.assertEqual(len(out['current_removed_descriptors']),4)
        self.assertTrue(all(r['source_detached'] for r in out['current_removed_descriptors']))
        out=u['n']['nest'](read,nb,frame_map=BASE,frame_low=BASE,
            ownership={'nested_descriptors':1},removed=4,detachments=report['records'])
        self.assertEqual(out['last_retired_descriptors'],4)
        record=struct.pack('<8Q',*row)
        wrapped=struct.pack('<Q',4097)+record*4096
        self.assertEqual(d['audit_shared_detaches'](read,wrapped,frame_map=BASE,frame_low=BASE)['retained_records'],4096)
    def test_empty(self):
        def forbidden(*args):raise AssertionError('empty must not read')
        self.assertEqual(d['audit_shared_detaches'](forbidden,bytes(8+4096*64),frame_map=BASE,frame_low=BASE)['calls'],0)
if __name__=='__main__':unittest.main()
