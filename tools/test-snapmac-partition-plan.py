#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""snapmac-partition-plan: exact numbers for the A16, and every protection check.

  python3 tools/test-snapmac-partition-plan.py

GPTs are built from the final Windows layout record of 2026-09-21 (embedded
below; it matches build/a16-storage-backup-20260921/staging-final.json) and
decoded with q1n1's tools/gpt_survey.py, the same decoder the survey uses.
"""
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import unittest
import uuid
import zlib

HERE = Path(__file__).resolve().parent
Q1N1_TOOLS = Path(os.environ.get('Q1N1_TOOLS', HERE.parents[1] / 'q1n1/tools'))
sys.path.insert(0, str(Q1N1_TOOLS))
import gpt_survey as gs  # noqa: E402

spec = importlib.util.spec_from_file_location('plan', HERE / 'snapmac-partition-plan.py')
plan_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan_mod)

# (slot, GUID, type, offset, size, name) -- Windows' final record, slots in offset order
# for the 16 original entries, 16/17 for SNAPBOOT/SNAPASSETS.
LAYOUT = [
    (0, 'dc0777a3-2209-4316-8970-29eb200511d1', '97745aba-135a-44c3-9adc-05616173c24c', 1048576, 1048576, 'ToolsFv'),
    (1, 'a642d24c-0c1c-4a11-99eb-84737f211431', 'bc0330eb-3410-4951-a617-03898dbe3372', 2097152, 16777216, 'LogFs'),
    (2, 'ff899570-2688-4192-8e02-90cd0c62ea61', 'b7524b2d-0a91-49a2-aa5e-bda266699d49', 18874368, 1048576, 'EnterpriseFV'),
    (3, '5c92f10b-51bd-410b-9a42-48d746a3f775', 'a3381699-350c-465e-bd5d-fa3ab901a39a', 19922944, 1048576, 'ToolsFv_BACKUP'),
    (4, '00c8adb3-028c-451b-9acf-c345b3f723c6', 'c80325ba-7ec2-4a30-b2f7-18f646086185', 20971520, 73400320, 'UpdateCapsule'),
    (5, '9d8159d5-5938-4440-9caf-65c21392d5c2', 'fa4cbe53-31b5-4c23-9c1e-a01feb966856', 94371840, 125829120, 'NHLOS'),
    (6, '4ac52e5f-1aa6-409f-b12c-023520982261', '6690b4ce-70e9-4817-b9f1-25d64d888357', 220200960, 125829120, 'core_nhlos_a'),
    (7, '9c817ddb-0373-4d63-92f7-ed3bce38636d', 'aa9a5c4c-4f1f-7d3a-014a-22bd33bf7191', 346030080, 1048576, 'quantumsdk'),
    (8, 'aea9defe-5f13-4258-9f49-6eb36df1883e', '80c23c26-c3f9-4a19-bb38-1e457daceb09', 347078656, 1048576, 'quantumfv'),
    (9, '5a514971-8e3b-47cf-a12b-fd95dec307f8', 'e12d830b-7f62-4f0b-b48a-8178c5bf3ac1', 348127232, 1048576, 'catecontentfv'),
    (10, '5e3fcd32-6617-4a21-90bd-ed4ba1580b14', '5af80809-aabb-4943-9168-cdfc38742598', 349175808, 536870912, 'logdump'),
    (11, '939a0a66-c61e-42b7-b975-5be3c2b80280', 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 886046720, 471859200, 'EFI system partition'),
    (12, '7723b707-46b5-4404-b74f-4e3dffe17d62', 'e3c9e316-0b5c-4db8-817d-f92df00215ae', 1357905920, 16777216, 'Microsoft reserved partition'),
    (13, '419baed0-542c-4292-a670-caaabe34e2fa', 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', 1374683136, 512104595456, 'Basic data partition'),
    (16, '1b0d0e57-9a6f-498e-a189-264e9107bc36', 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', 513479278592, 17179869184, 'SNAPBOOT'),
    (17, '17cd69a6-eb33-406a-86fd-6d54fac2d2d1', 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', 530659147776, 68719476736, 'SNAPASSETS'),
    (14, '0e71a636-b076-4ab6-9f50-6425f2a618a5', 'de94bba4-06d1-4d40-a16a-bfd50179d6ac', 1022049124352, 1887436800, 'Basic data partition'),
    (15, '4dcd54be-0986-4010-b44c-ae1fa3f853a7', 'de94bba4-06d1-4d40-a16a-bfd50179d6ac', 1023936561152, 272629760, 'Basic data partition'),
]
BLOCKS = plan_mod.DISK_BYTES // 512


def gpt_windows(layout):
    array = bytearray(128 * 128)
    for slot, g, t, off, size, name in layout:
        attrs = 0 if t in ('c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'e3c9e316-0b5c-4db8-817d-f92df00215ae',
                           'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', plan_mod.TYPE) else 0x8000000000000001
        array[slot * 128:(slot + 1) * 128] = (uuid.UUID(t).bytes_le + uuid.UUID(g).bytes_le +
                                              struct.pack('<QQQ', off // 512, (off + size) // 512 - 1, attrs) +
                                              name.encode('utf-16le').ljust(72, b'\0'))
    last = BLOCKS - 1
    first, lastw = bytearray(1 << 20), bytearray(1 << 20)
    first[446:462] = bytes([0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF])
    first[510:512] = b'\x55\xaa'
    crc = zlib.crc32(array)
    for mine, other, entries in ((1, last, 2), (last, 1, last - 32)):
        h = bytearray(struct.pack('<8sIIIIQQQQ16sQIII', b'EFI PART', 0x10000, 92, 0, 0, mine, other, 34, last - 33,
                                  uuid.UUID(plan_mod.DISK_GUID).bytes_le, entries, 128, 128, crc))
        struct.pack_into('<I', h, 16, zlib.crc32(h))
        if mine == 1:
            first[512:604] = h
            first[1024:1024 + len(array)] = array
        else:
            base = plan_mod.DISK_BYTES - (1 << 20)
            lastw[entries * 512 - base:entries * 512 - base + len(array)] = array
            lastw[mine * 512 - base:mine * 512 - base + 92] = h
    return bytes(first), bytes(lastw)


def survey(layout, eui=plan_mod.EUI):
    d = gs.raw_windows(*gpt_windows(layout), plan_mod.DISK_BYTES, 512)
    d['path_info'] = {'nvme_eui_bytes': eui}
    return json.loads(json.dumps({'disks': [d]}))


def applied(layout, p, guid='7b0e9a4e-3f6f-4b8f-9c1d-5a2b6c7d8e9f', slot=18, first=None, last=None, t=None):
    n = p['new']
    f, l = first if first is not None else n['first_lba'], last if last is not None else n['last_lba']
    return layout + [(slot, guid, t or plan_mod.TYPE, f * 512, (l - f + 1) * 512, 'Snapintosh macOS')]


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.before = survey(LAYOUT)
        self.plan = plan_mod.plan(self.before)

    def test_exact_numbers(self):
        n, e = self.plan['new'], self.plan['extent']
        self.assertEqual((e['first_lba'], e['last_lba'], e['offset'], e['bytes']),
                         (1170661376, 1996189695, 599378624512, 422670499840))
        self.assertEqual((n['first_lba'], n['last_lba'], n['offset'], n['bytes'], n['end']),
                         (1170663424, 1996187647, 599379673088, 422668402688, 1022048075776))
        self.assertEqual(n['expected_index'], 18)
        self.assertEqual(len(self.plan['protected']), 18)
        self.assertIn('-Offset 599379673088 -Size 422668402688', self.plan['windows']['new_partition'])
        self.assertIn('offset=585331712 size=403088', self.plan['windows']['diskpart'])

    def test_the_exact_change_verifies(self):
        after = survey(applied(LAYOUT, self.plan))
        self.assertEqual(plan_mod.verify(self.before, after, self.plan), [])

    def test_slot_reorder_is_a_note_not_a_pass_by_silence(self):
        moved = [(3 if s == 16 else 16 if s == 3 else s,) + tuple(rest) for s, *rest in LAYOUT]
        notes = []
        after = survey(applied(moved, self.plan))
        self.assertEqual(plan_mod.verify(self.before, after, self.plan, notes=notes), [])
        self.assertEqual(len(notes), 2)

    def test_refuses_to_plan(self):
        cases = {
            'wrong eui': survey(LAYOUT, eui='0011223344556677'),
            'already planned': survey(applied(LAYOUT, self.plan)),
            'something in the extent': survey(LAYOUT + [(18, str(uuid.uuid4()), 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',
                                                         700000000000, 1 << 30, 'x')]),
            'neighbour moved': survey([r if r[1] != plan_mod.BEFORE_NEIGHBOUR else r[:3] + (r[3], r[4] - (1 << 20), r[5])
                                       for r in LAYOUT]),
            'esp missing': survey([r for r in LAYOUT if r[1] != plan_mod.ESP]),
        }
        for name, s in cases.items():
            with self.subTest(name=name), self.assertRaises(plan_mod.PlanError):
                plan_mod.plan(s)
        bad_crc = survey(LAYOUT)
        bad_crc['disks'][0]['backup']['array_crc_ok'] = False
        with self.assertRaises(plan_mod.PlanError):
            plan_mod.plan(bad_crc)

    def test_verify_catches_every_deviation(self):
        n = self.plan['new']
        c_moved = [r if r[1] != plan_mod.WINDOWS_C else r[:4] + (r[4] - (1 << 20), r[5]) for r in LAYOUT]
        esp_renamed = [r if r[1] != plan_mod.ESP else r[:5] + ('EFI',) for r in LAYOUT]
        cases = {
            'windows C resized': applied(c_moved, self.plan),
            'esp changed': applied(esp_renamed, self.plan),
            'no guard at start': applied(LAYOUT, self.plan, first=n['first_lba'] - 2048),
            'short partition': applied(LAYOUT, self.plan, last=n['last_lba'] - 2048),
            'wrong type': applied(LAYOUT, self.plan, t='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'),
            'two new partitions': applied(LAYOUT, self.plan) + [(19, str(uuid.uuid4()), plan_mod.TYPE, 10 << 20, 1 << 20, 'x')],
            'recovery deleted': applied([r for r in LAYOUT if r[1] != plan_mod.AFTER_NEIGHBOUR], self.plan),
            'nothing applied': LAYOUT,
        }
        for name, layout in cases.items():
            with self.subTest(name=name):
                try:
                    problems = plan_mod.verify(self.before, survey(layout), self.plan)
                except plan_mod.PlanError as e:
                    problems = [str(e)]
                self.assertTrue(problems, name)

    def test_refuses_any_other_partition_set(self):
        # A partition added outside the free extent (e.g. a Windows update carving
        # a new recovery partition out of C:) or a moved one must stop the plan.
        c = next(r for r in LAYOUT if r[1] == plan_mod.WINDOWS_C)
        shrunk = [r if r is not c else (*r[:4], r[4] - (1 << 30), r[5]) for r in LAYOUT]
        extra = shrunk + [(18, '11111111-2222-3333-4444-555555555555', 'de94bba4-06d1-4d40-a16a-bfd50179d6ac',
                           c[3] + c[4] - (1 << 30), 1 << 30, 'new recovery')]
        for name, layout in (('shrunk C:', shrunk), ('extra partition', extra)):
            with self.subTest(name=name), self.assertRaises(plan_mod.PlanError):
                plan_mod.plan(survey(layout))
        self.assertNotIn('noerr', plan_mod.plan(survey(LAYOUT))['windows']['diskpart'])

    def test_undo(self):
        self.assertEqual(plan_mod.verify_undo(self.before, survey(LAYOUT)), [])
        self.assertTrue(plan_mod.verify_undo(self.before, survey(applied(LAYOUT, self.plan))))

    def test_windows_record_agrees(self):
        record = Path(os.environ.get('SNAP_STORAGE_BACKUP', HERE.parent / 'build/a16-storage-backup-20260921')) / 'staging-final.json'
        if not record.exists():
            self.skipTest('staging-final.json not present')
        decoded = self.before['disks'][0]
        self.assertEqual(gs.compare_windows(decoded, json.loads(record.read_text(encoding='utf-8-sig'))), [])


if __name__ == '__main__':
    unittest.main()
