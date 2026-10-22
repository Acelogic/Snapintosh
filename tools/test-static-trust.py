#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bound the real Apple cache, malformed imports and executable membership."""
from pathlib import Path
import hashlib
import struct
import sys
import unittest
import zipfile
import runpy

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from guestprofile import get_profile
from trustcache import parse_v2, unwrap_component, reserve_size


class StaticTrustTests(unittest.TestCase):
    def setUp(self):
        self.spec=get_profile('j700ap-26A428-no-clpc').trust_cache
        self.payload=self.spec.load(ROOT/'downloads/extracted/j700ap')

    def test_original_executables(self):
        entries=parse_v2(self.payload)['entries']
        for index,digest in [(984,'e388638c5a061155f37fa6977eda6220c5bda33e'),
                             (171,'28ee758ce6926c460d935becc618e6ef15519c57')]:
            self.assertEqual(entries[index],bytes.fromhex(digest+'02000200'))
        self.assertEqual(len(entries),1103)
        self.assertEqual(reserve_size(len(self.payload)),0xc000)

    def test_reject_changed_payload(self):
        for offset in (0,4,20,24,len(self.payload)-1):
            changed=bytearray(self.payload);changed[offset]^=1
            with self.assertRaises(ValueError):self.spec.verify(changed)

    def test_reject_malformed_arrays(self):
        for bad in (b'', self.payload[:23],self.payload[:-1],self.payload+b'\0',
                    b'\x03'+self.payload[1:], self.payload[:20]+struct.pack('<I',0xffffffff)+self.payload[24:]):
            with self.assertRaises(ValueError):parse_v2(bad)
        changed=self.payload[:24]+self.payload[48:72]+self.payload[24:48]+self.payload[72:]
        with self.assertRaises(ValueError):parse_v2(changed)

    def test_component(self):
        with zipfile.ZipFile(ROOT/'downloads/UniversalMac_27.0_26A428_Restore.ipsw') as z:
            component=z.read(self.spec.member)
        self.assertEqual(self.spec.extract(component),self.payload)
        for bad in (component[:-1],component+b'\0',b'\x31'+component[1:],b'\x30\x80',b'\x30\x84\xff'):
            with self.assertRaises(ValueError):unwrap_component(bad)
        changed=bytearray(component);changed[-1]^=1
        with self.assertRaises(ValueError):self.spec.extract(changed)

    def test_readback_rejects_false_evidence(self):
        audit=runpy.run_path(str(ROOT/'tools/audit-static-trust.py'))['audit_static_trust']
        pa,va=0x90000000,0xfffffe1000000000
        runtime=bytearray(0x4000)
        struct.pack_into('<Q',runtime,0x10,va+0x100)
        struct.pack_into('<Q',runtime,0x20,va+0x80)
        struct.pack_into('<QQ',runtime,0x110,len(self.payload),va+0x4000)
        entry=va+0x4000+24+984*24
        digest=bytes.fromhex('e388638c5a061155f37fa6977eda6220c5bda33e')
        state=bytearray(struct.pack('<8Q24s2Q',1,1103,1,1,0,1,32,0x1000000000,
                                    digest,va+0x100,entry)+(1<<984).to_bytes(512,'little'))
        def read(address,size):
            raw=bytes(runtime)+self.payload
            return raw[address-pa:address-pa+size]
        result=audit(read,(pa,va,len(self.payload)),state,self.spec)
        self.assertEqual(result['matched'][0]['cdhash'],digest.hex())
        for offset in (0,8,16,24,32,88,96,104+984//8):
            bad=bytearray(state);bad[offset]^=1
            with self.assertRaises(ValueError):audit(read,(pa,va,len(self.payload)),bad,self.spec)
        runtime[0x118]^=1
        with self.assertRaises(ValueError):audit(read,(pa,va,len(self.payload)),state,self.spec)


if __name__=='__main__':unittest.main()
