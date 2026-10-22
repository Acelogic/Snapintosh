#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check independent ownership reconstruction against C-produced nest fixtures."""
from pathlib import Path
import runpy
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
refs=runpy.run_path(str(ROOT/'tools/audit-sptm-refs.py'))['audit']
nest=runpy.run_path(str(ROOT/'tools/audit-nest-region.py'))['audit_nesting']
BASE=0x100000
PAGE=0x4000
SHARED=BASE+3*PAGE
USER=SHARED+PAGE
START=0x180000000


class NestAuditTests(unittest.TestCase):
    def fixture(self,fmt):
        data=bytearray((ROOT/'build'/f'nest-fixture-{4 if fmt else 16}k.bin').read_bytes())
        def read(pa,size):
            if not BASE<=pa<=BASE+len(data)-size:raise ValueError('outside fixture')
            return bytes(data[pa-BASE:pa-BASE+size])
        kwargs=dict(root=BASE+249*PAGE,frame_map=BASE,frame_low=BASE,frame_high=BASE+304*PAGE,
            alloc_low=SHARED,alloc_high=BASE+200*PAGE,aperture_va=0,aperture_size=0,
            ram_low=BASE,ram_high=BASE+len(data),user_roots=[USER],shared_roots=[SHARED])
        shift=12 if fmt else 14;group=4 if fmt else 1;span=1<<(2*shift-3)
        blob=struct.pack('<8Q',1,group+1,USER,SHARED,START+(1<<shift),group*span//(1<<shift),START,START+(group+1)*span)
        return data,read,kwargs,blob

    def test_positive_independent_counts(self):
        for fmt in range(2):
            with self.subTest(fmt=fmt):
                data,read,kwargs,blob=self.fixture(fmt)
                result=refs(read,**kwargs)
                self.assertEqual(result['mismatches'],[])
                self.assertEqual(result['nested_descriptors'],5 if fmt else 2)
                self.assertEqual(result['nested_tables'],2)
                self.assertEqual(result['data_mappings'],12 if fmt else 3)
                report=nest(read,blob,frame_map=BASE,frame_low=BASE,ownership=result)
                self.assertEqual(report['last_descriptors'],5 if fmt else 2)

    def test_reject_false_telemetry(self):
        for fmt in range(2):
            for field in range(8):
                data,read,kwargs,blob=self.fixture(fmt);ownership=refs(read,**kwargs)
                values=list(struct.unpack('<8Q',blob));values[field]^=1 if field==4 else 0x10000
                with self.subTest(fmt=fmt,field=field),self.assertRaises(ValueError):
                    nest(read,struct.pack('<8Q',*values),frame_map=BASE,frame_low=BASE,ownership=ownership)

    def test_reject_wrong_source_and_reference_count(self):
        for fmt in range(2):
            data,read,kwargs,blob=self.fixture(fmt)
            shift=12 if fmt else 14;mask=(1<<48)-(1<<shift);table=USER
            for level in range(0 if fmt else 1,3):
                idx=(START>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1)
                slot=table+idx*8;pte=struct.unpack('<Q',read(slot,8))[0];table=pte&mask
            frame=pte&~0x3fff;off=((frame-BASE)>>14)*16+6
            data[off]^=1
            result=refs(read,**kwargs)
            self.assertTrue(any(m['field']=='table links' for m in result['mismatches']))
            data[off]^=1
            struct.pack_into('<Q',data,slot-BASE,pte+PAGE)
            with self.assertRaises(ValueError):refs(read,**kwargs)

    def test_retired_last_root_and_faults(self):
        # Exercise this history reader separately from the full live-owner
        # traversal. Its ownership total is supplied by that prior audit.
        for fmt in range(2):
            for fault in range(19):
                data,read,kwargs,blob=self.fixture(fmt)
                offset=((USER-BASE)>>14)*16
                data[offset:offset+16]=bytes([0,0,11])+bytes(13)
                data[USER-BASE:USER-BASE+PAGE]=bytes(PAGE)
                total=struct.unpack('<8Q',blob)[1]
                removed=total
                if fault<16:data[offset+fault]^=0x80
                elif fault==16:data[USER-BASE]=1
                elif fault==17:removed-=1
                ownership={'nested_descriptors':total-removed}
                with self.subTest(fmt=fmt,fault=fault):
                    if fault<18:
                        with self.assertRaises(ValueError):
                            nest(read,blob,frame_map=BASE,frame_low=BASE,
                                 ownership=ownership,removed=removed)
                    else:
                        report=nest(read,blob,frame_map=BASE,frame_low=BASE,
                                    ownership=ownership,removed=removed)
                        self.assertTrue(report['retired_root'])
                        self.assertEqual(report['last_retired_descriptors'],total)
                        self.assertEqual(report['last_tables'],0)


if __name__=='__main__':unittest.main()
