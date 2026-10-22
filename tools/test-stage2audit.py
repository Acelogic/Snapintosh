#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject false isolation proofs, including shared descendants and open guards."""
import copy
import struct
import unittest
from stage2audit import audit_private_stage2, XN

LOW, HIGH = 0x100000000, 0x100100000


def fixture():
    pages, banks = {}, []
    for cpu in range(6):
        root = LOW + cpu * 0x3000
        l2, l3 = root+4096, root+8192
        pages[root], pages[l2] = [0]*512, [0]*512
        pages[root][0], pages[l2][1] = l2 | 3, l3 | 3
        pages[l3] = [0x200000+n*4096 | 0x7ff for n in range(512)]
        pages[l3][0] |= XN
        banks.append(dict(root=root, vttbr=root | ((cpu+1) << 48),
                          guards=[(0x200000, l3, 0x2007ff, 0)]))
    return pages, banks


class PrivateStage2Audit(unittest.TestCase):
    def audit(self, pages, banks, ranges=None):
        def read(pa, size):
            self.assertEqual(size, 4096)
            return struct.pack('<512Q', *pages[pa])
        return audit_private_stage2(read, banks, ranges or [(0x200000, 0x400000, 0x7fc, 0)], LOW, HIGH)

    def test_sealed_prefix_and_stale_guard_descriptor(self):
        pages,banks=fixture()
        ranges=[(0x200000,0x210000,0x77c,0),(0x210000,0x400000,0x7fc,0)]
        for b in banks:
            for i in range(16):pages[b['root']+8192][i]&=~0x80
            pa,slot,desc,mode=b['guards'][0]
            b['guards'][0]=(pa,slot,desc&~0x80,mode)
        self.assertTrue(self.audit(pages,banks,ranges)['complete_ranges'])
        for cpu in range(6):
            b=banks[cpu];slot=b['root']+8192
            pages[slot][8]|=0x80
            with self.assertRaises(AssertionError):self.audit(pages,banks,ranges)
            pages[slot][8]&=~0x80
        pa,slot,desc,mode=banks[0]['guards'][0]
        banks[0]['guards'][0]=(pa,slot,desc|0x80,mode)
        with self.assertRaises(AssertionError):self.audit(pages,banks,ranges)

    def test_six_disjoint_complete_maps(self):
        result = self.audit(*fixture())
        self.assertEqual(result['disjoint_table_pages'], 18)
        self.assertEqual([b['vmid'] for b in result['banks']], list(range(1, 7)))
        self.assertTrue(all(b['guards_closed'] == 1 for b in result['banks']))

    def test_each_open_guard_is_rejected(self):
        for cpu in range(6):
            pages, banks = fixture()
            pages[banks[cpu]['guards'][0][1]][0] &= ~XN
            with self.assertRaises(AssertionError): self.audit(pages, banks)

    def test_shared_descendant_is_rejected(self):
        pages, banks = fixture()
        pages[banks[1]['root']][0] = pages[banks[0]['root']][0]
        banks[1]['guards'] = copy.deepcopy(banks[0]['guards'])
        with self.assertRaises(AssertionError): self.audit(pages, banks)

    def test_missing_page_and_wrong_permissions(self):
        for replacement in [0, 0x20177f, 0x2017ff | XN]:
            pages, banks = fixture()
            pages[banks[0]['root']+8192][1] = replacement
            with self.assertRaises(AssertionError): self.audit(pages, banks)

    def test_extra_mapping_is_rejected(self):
        pages, banks = fixture()
        pages[banks[0]['root']+4096][2] = 0x4007fd
        with self.assertRaises(AssertionError): self.audit(pages, banks)

    def test_private_prefix_must_be_unmapped_even_if_readonly(self):
        pages,banks=fixture()
        # Model a private context preceding the visible table arena.
        ranges=[(0x210000,0x400000,0x7fc,0)]
        for bank in banks:
            bank['guards']=[]
            pages[bank['root']+8192][:16]=[0]*16
        self.assertTrue(self.audit(pages,banks,ranges)['complete_ranges'])
        for bank in banks:
            slot=bank['root']+8192
            pages[slot][15]=0x20f000|0x77f|XN
            with self.assertRaises(AssertionError):self.audit(pages,banks,ranges)
            pages[slot][15]=0

    def test_vmid_reuse_is_rejected(self):
        pages, banks = fixture()
        banks[1]['vttbr'] = banks[1]['root'] | (1 << 48)
        with self.assertRaises(AssertionError): self.audit(pages, banks)

    def test_cycle_and_outside_table_are_rejected(self):
        for target in [LOW, HIGH]:
            pages, banks = fixture()
            pages[LOW][0] = target | 3
            with self.assertRaises(AssertionError): self.audit(pages, banks)

    def test_guard_pointer_and_mode_must_match_leaf(self):
        for field, value in [(0, 0x201000), (1, LOW), (2, 0x20077f), (3, 1)]:
            pages, banks = fixture()
            guard = list(banks[0]['guards'][0])
            guard[field] = value
            banks[0]['guards'][0] = tuple(guard)
            with self.assertRaises(AssertionError): self.audit(pages, banks)


if __name__ == '__main__': unittest.main()
