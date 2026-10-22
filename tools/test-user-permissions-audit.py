#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault-injection checks for the independent TPRO hardware-view auditor."""
from pathlib import Path
import runpy
import struct
import unittest

ROOT = Path(__file__).resolve().parent
module = runpy.run_path(str(ROOT / 'audit-user-permissions.py'))
AUDIT = module['audit']
BASE, GUEST, DATA = 0x100000, 0x90000000, 0x94050c000
UP, PP = module['UPERM'], module['PPERM']
NX = 3 << 53


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.pages = {}
        self.records = []
        for level in range(4):
            source = BASE + level * 4096
            copies = [BASE + 0x10000 + (level * 6 + cpu) * 4096 for cpu in range(6)]
            self.records.append([source, *copies, level])
            for p in [source, *copies]:
                self.pages[p] = bytearray(4096)
        for level in range(3):
            self.put(self.records[level][0], 0, self.records[level + 1][0] | 3)
        self.raw = DATA | 0x0020000000000f83
        self.put(self.records[3][0], 0, self.raw)
        self.put(self.records[3][0], 1, DATA | 0x0060000000000f43)  # ordinary RW alias
        self.active = [GUEST, GUEST, 0, 0, 0, 0]
        self.sprr = [dict(uperm=UP | (1 << 36) if cpu == 0 else UP,
                          pperm=PP | (1 << 36) if cpu == 1 else PP,
                          umprr=0x40000) for cpu in range(6)]
        self.modes = [dict(root=GUEST, shadow=self.records[0][cpu + 1], el0=int(cpu == 0),
                           uperm=self.sprr[cpu]['uperm'], pperm=self.sprr[cpu]['pperm'],
                           umprr=0x40000, syncs=1, entries=0, returns=int(cpu == 0))
                      for cpu in range(6)]
        for cpu in range(6):
            for level in range(3):
                self.put(self.records[level][cpu + 1], 0, self.records[level + 1][cpu + 1] | 3)
            wanted = (self.raw & ~((3 << 6) | NX)) | NX | (1 << 6) | (0 if cpu < 2 else 2 << 6)
            self.put(self.records[3][cpu + 1], 0, wanted)
            self.put(self.records[3][cpu + 1], 1, DATA | 0x0060000000000f43)
        self.fm = bytearray(16)
        self.fm[2] = 17
        self.fm[12] = 2
        self.entry = dict(root=GUEST, shadow=BASE, flags=0xa)

    def put(self, page, slot, d):
        struct.pack_into('<Q', self.pages[page], 8 * slot, d)

    def run_audit(self, **kwargs):
        state = bytearray(8256)
        struct.pack_into('<8Q', state, 0, BASE, len(self.records), *([1] * 6))
        for n, r in enumerate(self.records):
            struct.pack_into('<8Q', state, 64 + n * 64, *r)
        return AUDIT(lambda pa, size: bytes(self.pages[pa][:size]), state=state,
                     entry=self.entry, active=self.active, sprr=self.sprr, modes=self.modes,
                     frame_map=self.fm, frame_low=DATA, work_low=BASE, work_high=BASE + 0x80000,
                     **kwargs)

    def test_diagnostic_mismatches_are_bounded_and_unqualified(self):
        for slot in range(2, 34):
            self.put(self.records[3][1], slot, DATA | 0x0060000000000f43)
        with self.assertRaisesRegex(ValueError, 'private user PTE mismatch'):
            self.run_audit()
        result = self.run_audit(diagnose_mismatches=True)
        self.assertFalse(result['private_descriptors_verified'])
        self.assertEqual(result['mismatch_count'], 32)
        self.assertEqual(len(result['first_mismatches']), 16)
        self.assertEqual(result['first_mismatches'][0]['expected'], '0x0')
        self.modes[0]['el0'] = 2
        with self.assertRaises(ValueError):
            self.run_audit(diagnose_mismatches=True)

    def test_independent_cpu_permissions_and_ordinary_alias(self):
        result = self.run_audit()
        self.assertEqual(result['tpro_4k_pages'], 1)
        self.assertEqual([r['tpro_write'] for r in result['cpu_views']], [True, True, False, False, False, False])

    def test_wrong_private_permissions(self):
        for cpu, value in ((0, self.raw), (0, DATA | 0x0060000000000fc3),
                           (2, DATA | 0x0060000000000f43)):
            with self.subTest(cpu=cpu, value=value):
                self.setUp()
                self.put(self.records[3][cpu + 1], 0, value)
                with self.assertRaises(ValueError):
                    self.run_audit()

    def test_saved_modifier_preserves_loaded_private_views(self):
        self.entry['flags']=11
        loaded=[dict(root=GUEST if cpu<2 else 0,flags=10 if cpu<2 else 0,resets=1)
                for cpu in range(6)]
        for row in self.sprr:row['resets']=1
        with self.assertRaises(ValueError):self.run_audit()
        self.assertTrue(self.run_audit(loaded=loaded)['private_descriptors_verified'])
        for field in ('root','flags','resets'):
            bad=[dict(row) for row in loaded];bad[0][field]^=2
            with self.assertRaises(ValueError):self.run_audit(loaded=bad)
        self.sprr[0]['umprr']=0x40800
        with self.assertRaises(ValueError):self.run_audit(loaded=loaded)
        loaded[0]['flags']=11;loaded[0]['resets']=2
        self.sprr[0]['resets']=2;self.modes[0]['umprr']=0x40800
        self.assertTrue(self.run_audit(loaded=loaded)['private_descriptors_verified'])

    def test_wrong_register_or_mode_state(self):
        for field, value in (('el0', 2), ('uperm', UP), ('pperm', PP | 0x100), ('shadow', BASE)):
            with self.subTest(field=field):
                self.setUp()
                self.modes[0][field] = value
                with self.assertRaises(ValueError):
                    self.run_audit()

    def test_stale_unmap_and_shared_or_aliased_storage(self):
        for kind in range(4):
            with self.subTest(kind=kind):
                self.setUp()
                if kind == 0:
                    self.put(self.records[3][0], 0, 0)
                elif kind == 1:
                    self.put(self.records[2][1], 0, self.records[3][0] | 3)
                elif kind == 2:
                    self.records[3][2] = self.records[3][1]
                else:
                    self.put(self.records[2][0], 0, self.records[3][1] | 3)
                with self.assertRaises(ValueError):
                    self.run_audit()

    def test_type_and_root_policy(self):
        for kind in range(3):
            with self.subTest(kind=kind):
                self.setUp()
                if kind == 0:
                    self.fm[2] = 11
                elif kind == 1:
                    self.fm[3] = 1
                else:
                    self.entry['flags'] = 2
                with self.assertRaises(ValueError):
                    self.run_audit()


NATIVE = module['audit_native']
ASID = module['native_asid']


class NativeAuditTests(unittest.TestCase):
    """SNAP_NATIVE_TABLES: two shared variants instead of six CPU views."""
    SLOT = 3

    def setUp(self):
        self.pages = {}
        self.records = []
        for level in range(4):
            source = BASE + level * 4096
            copies = [BASE + 0x10000 + (level * 2 + w) * 4096 for w in range(2)]
            self.records.append([source, *copies, 0, 0, 0, 0, level])
            for p in [source, *copies]:
                self.pages[p] = bytearray(4096)
        for level in range(3):
            self.put(self.records[level][0], 0, self.records[level + 1][0] | 3)
            for w in range(2):
                self.put(self.records[level][w + 1], 0, self.records[level + 1][w + 1] | 3)
        self.raw = DATA | 0x0020000000000f83
        self.put(self.records[3][0], 0, self.raw)
        self.put(self.records[3][0], 1, DATA | 0x0060000000000f43)  # ordinary RW alias
        for w in range(2):
            self.put(self.records[3][w + 1], 0,
                     (self.raw & ~((3 << 6) | NX)) | NX | (1 << 6) | (0 if w else 2 << 6))
            self.put(self.records[3][w + 1], 1, DATA | 0x0060000000000f43)
        # CPU0 runs EL0 with UPERM TPRO write (w=1); CPU1 runs EL1 with the
        # ROZONE PPERM bit (k=1) and no TPRO write (w=0); the rest elsewhere.
        self.active = [GUEST, GUEST, 0, 0, 0, 0]
        self.sprr = [dict(uperm=UP | (1 << 36) if cpu == 0 else UP,
                          pperm=PP | 0x100 if cpu == 1 else PP, umprr=0x40000) for cpu in range(6)]
        self.modes = [dict(root=GUEST, shadow=self.records[0][2 if cpu == 0 else 1], el0=int(cpu == 0),
                           uperm=self.sprr[cpu]['uperm'], pperm=self.sprr[cpu]['pperm'],
                           umprr=0x40000, syncs=1, entries=0, returns=int(cpu == 0)) for cpu in range(6)]
        ttbr0 = [[self.records[0][w + 1] | ASID(self.SLOT, w) << 48] * 2 for w in range(2)]
        self.native = [dict(ttbr0=[list(r) for r in ttbr0], ttbr1=[0, 0], uperm=self.sprr[cpu]['uperm'],
                            pperm=self.sprr[cpu]['pperm'], el0=int(cpu == 0), w=int(cpu == 0),
                            k=int(cpu == 1), installed=1, selects=5, flips=1, errors=0)
                       for cpu in range(6)]
        self.fm = bytearray(16)
        self.fm[2] = 17
        self.fm[12] = 2
        self.entry = dict(root=GUEST, shadow=BASE, flags=0xa, index=self.SLOT)
        self.syncs = [0] * 6

    def put(self, page, slot, d):
        struct.pack_into('<Q', self.pages[page], 8 * slot, d)

    def run_audit(self, **kwargs):
        state = bytearray(8256)
        struct.pack_into('<8Q', state, 0, BASE, len(self.records), *self.syncs)
        for n, r in enumerate(self.records):
            struct.pack_into('<8Q', state, 64 + n * 64, *r)
        return NATIVE(lambda pa, size: bytes(self.pages[pa][:size]), state=state,
                      entry=self.entry, active=self.active, sprr=self.sprr, modes=self.modes,
                      native=self.native, frame_map=self.fm, frame_low=DATA, work_low=BASE,
                      work_high=BASE + 0x80000, **kwargs)

    def test_record_layout(self):
        raw = struct.pack('<6Q', 1, 2, 3, 4, 5, 6) + struct.pack('<2Q', UP, PP) + \
            struct.pack('<4I', 1, 1, 0, 1) + struct.pack('<3Q', 9, 8, 0)
        row = module['native_cpu'](raw)
        self.assertEqual((row['ttbr0'], row['ttbr1'], row['uperm'], row['pperm']),
                         ([[1, 2], [3, 4]], [5, 6], UP, PP))
        self.assertEqual((row['el0'], row['w'], row['k'], row['installed'], row['selects'], row['flips']),
                         (1, 1, 0, 1, 9, 8))
        with self.assertRaises(ValueError):
            module['native_cpu'](raw[:-8])

    def test_shared_variants_and_selection(self):
        result = self.run_audit()
        self.assertTrue(result['private_descriptors_verified'])
        self.assertEqual((result['tpro_4k_pages'], result['private_copy_pages']), (1, 8))
        self.assertEqual([(r['cpu'], r['tpro_write'], r['asid']) for r in result['cpu_views']],
                         [(0, True, ASID(3, 1)), (1, False, ASID(3, 0))])

    def test_wrong_variant_descriptor(self):
        writable = (self.raw & ~((3 << 6) | NX)) | NX | (1 << 6)
        for w, value in ((0, writable), (1, writable | 2 << 6), (0, self.raw), (1, 0)):
            with self.subTest(w=w, value=hex(value)):
                self.setUp()
                self.put(self.records[3][w + 1], 0, value)
                with self.assertRaisesRegex(ValueError, f'variant{w} private user PTE mismatch'):
                    self.run_audit()
                result = self.run_audit(diagnose_mismatches=True)
                self.assertEqual((result['mismatch_count'], result['private_descriptors_verified']), (1, False))

    def test_variant_link_names_its_own_child(self):
        self.put(self.records[2][1], 0, self.records[3][2] | 3)
        with self.assertRaises(ValueError):
            self.run_audit()

    def test_cpu_selection_state(self):
        other = [[self.records[0][w + 1] | ASID(self.SLOT + 1, w) << 48] * 2 for w in range(2)]
        for field, value in (('ttbr0', other), ('ttbr1', [0, 1]), ('installed', 0), ('errors', 1),
                             ('w', 0), ('k', 1), ('el0', 0), ('uperm', UP), ('pperm', PP | 0x100)):
            with self.subTest(field=field):
                self.setUp()
                self.native[0][field] = value
                with self.assertRaisesRegex(ValueError, 'native CPU selection'):
                    self.run_audit()

    def test_mode_state(self):
        for field, value in (('shadow', None), ('el0', 2), ('uperm', UP), ('returns', 2)):
            with self.subTest(field=field):
                self.setUp()
                self.modes[0][field] = self.records[0][1] if value is None else value
                with self.assertRaises(ValueError):
                    self.run_audit()

    def test_unused_copy_slots_and_cpu_syncs_stay_zero(self):
        self.records[2][3] = BASE + 0x40000
        with self.assertRaisesRegex(ValueError, 'unused private copy slots'):
            self.run_audit()
        self.setUp()
        self.syncs[4] = 1
        with self.assertRaisesRegex(ValueError, 'view count differs'):
            self.run_audit()

    def test_raw_tpro_behind_a_shared_table(self):
        # The level-3 table loses its copies: its raw TPRO leaf is reachable
        # through a table both variants share.
        del self.records[3]
        for w in range(2):
            self.put(self.records[2][w + 1], 0, (BASE + 3 * 4096) | 3)
        with self.assertRaisesRegex(ValueError, 'raw TPRO exposed through shared path'):
            self.run_audit()


if __name__ == '__main__':
    unittest.main()
