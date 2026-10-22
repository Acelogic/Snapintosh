#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tools/native_shared_audit.py against a synthetic stopped image: groups that
translate their guest tables (pages only where leaves are), own exactly their
allocation domain, are found through the index and match the trees that link
them are accepted; each kind of disagreement is refused."""
from pathlib import Path
import runpy
import struct
import unittest

m = runpy.run_path(str(Path(__file__).with_name('native_shared_audit.py')))
WORK = 0x40000000
CLASSES = (0x0060000000000f43, 0x0020000000000fc3, 0x0060000000000fc3, 0x0060000000000f83)
HEADER = len(m['HEADER']) * 8
GROUP = HEADER
INDEX = GROUP + m['GROUPS'] * m['GROUP_WORDS'] * 8


class Image:
    def __init__(self):
        self.mem, self.owners, self.next = {}, [], WORK

    def page(self, owner, size=4096):
        pa = self.next
        self.next += size
        self.owners += [owner] * (size // 4096)
        for off in range(0, size, 8):
            self.mem[pa + off] = 0
        return pa

    def put(self, pa, v):
        self.mem[pa] = v

    def read(self, pa, n):
        return b''.join(struct.pack('<Q', self.mem.get(pa + off, 0)) for off in range(0, n, 8))


def index_put(raw, guest, g):
    """shadow/native-shared.c index_insert()."""
    i = m['home'](guest)
    while struct.unpack_from('<H', raw, INDEX + 2 * i)[0]:
        i = (i + 1) & (m['INDEX'] - 1)
    struct.pack_into('<H', raw, INDEX + 2 * i, g + 1)
    return i


class NativeSharedAudit(unittest.TestCase):
    def setUp(self):
        img = self.img = Image()
        self.raw = bytearray(INDEX + m['INDEX'] * 2)
        self.guest = img.page(0, 16384)
        # Leaves in every 2 MiB but the last two, which get no page.
        for j in range(0, 14 * 128, 5):
            img.put(self.guest + 8 * j, (0x900000000 + 0x4000 * j) | CLASSES[j % 4])
        self.va = 0x180000000
        pages = [img.page(200) for _ in range(14)] + [0, 0]
        leaves = 0
        for j in range(2048):
            d = img.mem[self.guest + 8 * j]
            leaves += d & 1
            if pages[j // 128]:
                for k, e in enumerate(m['translate'](d)):
                    img.put(pages[j // 128] + 8 * (4 * (j % 128) + k), e)
        # Slot 3 (valid) and slot 7 (an invalid entry keeping its tree) link it.
        self.trees = {}
        for slot in (3, 7):
            root, l1, l2 = img.page(slot + 1), img.page(slot + 1), img.page(slot + 1)
            img.put(root + 8 * ((self.va >> 39) & 511), l1 | 3)
            img.put(l1 + 8 * ((self.va >> 30) & 511), l2 | 3)
            for i in range(16):
                if pages[i]:
                    img.put(l2 + 8 * (((self.va >> 21) & 511) + i), pages[i] | 3)
            self.trees[slot] = root
        # A second, pageless group (an empty guest table) linked by slot 3.
        self.empty = img.page(0, 16384)
        l1 = img.mem[self.trees[3] + 8 * ((self.va >> 39) & 511)] & ~3
        self.empty_va = self.va + (1 << 25)
        struct.pack_into('<9Q', self.raw, 0, 2, 2, 0, 0, 3, 0, 0, 0, 0)
        struct.pack_into('<21Q', self.raw, GROUP + 5 * m['GROUP_WORDS'] * 8, self.guest, 0x8d4ac0000, self.va,
                         leaves, (1 << 3) | (1 << 7), *pages)
        struct.pack_into('<21Q', self.raw, GROUP + 9 * m['GROUP_WORDS'] * 8, self.empty, 0x8d4ac0000,
                         self.empty_va, 0, 1 << 3, *([0] * 16))
        index_put(self.raw, self.guest, 5)
        index_put(self.raw, self.empty, 9)
        self.pages, self.leaves, self.l1 = pages, leaves, l1

    def run_audit(self, trees=None):
        return m['audit'](self.img.read, bytes(self.raw), bytes(self.img.owners), WORK,
                          self.trees if trees is None else trees, group_offset=GROUP, index_offset=INDEX)

    def test_accepts_exact_groups(self):
        r = self.run_audit()
        self.assertEqual((r['groups'], r['leaves'], r['links']), (2, self.leaves, {3: 2, 7: 1}))
        self.assertEqual(r['pages'], {p for p in self.pages if p})

    def l2_table(self, slot):
        l1 = self.img.mem[self.trees[slot] + 8 * ((self.va >> 39) & 511)] & ~3
        return self.img.mem[l1 + 8 * ((self.va >> 30) & 511)] & ~3

    def test_refusals(self):
        cases = {
            'entry differs': lambda t: t.img.put(t.pages[2] + 8, t.img.mem[t.pages[2] + 8] ^ 0x4000),
            'guest leaf changed': lambda t: t.img.put(t.guest + 8 * 7, 0x900100000 | CLASSES[0]),
            'tpro in guest': lambda t: t.img.put(t.guest + 8 * 5, 0x900014000 | 0x0020000000000e83),
            'leaf without a page': lambda t: t.img.put(t.guest + 8 * (15 * 128 + 1), 0x900200000 | CLASSES[0]),
            'foreign owner': lambda t: t.img.owners.__setitem__((t.pages[4] - WORK) // 4096, 9),
            'stray domain page': lambda t: t.img.page(200),
            'lost link': lambda t: t.img.put(t.l2_table(7) + 8 * (((t.va >> 21) & 511) + 3), 0),
            'link to a missing page': lambda t: t.img.put(t.l2_table(3) + 8 * (((t.va >> 21) & 511) + 15),
                                                          t.pages[0] | 3),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                self.setUp()
                change(self)
                with self.assertRaises(ValueError):
                    self.run_audit()

    def test_counters_index_and_slots(self):
        slots = GROUP + 5 * m['GROUP_WORDS'] * 8 + 32
        for name, (off, value, text) in {
                'errors': (48, 1, 'counters disagree'), 'live': (0, 3, 'counters disagree'),
                'full': (56, 1, 'records exhausted'),
                'slot without a tree': (slots, 1 << 4, 'has no tree'),
                'leaves': (GROUP + 5 * m['GROUP_WORDS'] * 8 + 24, 1, 'leaf count')}.items():
            with self.subTest(name=name):
                self.setUp()
                struct.pack_into('<Q', self.raw, off, value)
                with self.assertRaisesRegex(ValueError, text):
                    self.run_audit()
        # The index must find every live group, and only them.
        self.setUp()
        at = m['home'](self.empty)
        while struct.unpack_from('<H', self.raw, INDEX + 2 * at)[0] != 10:
            at = (at + 1) & (m['INDEX'] - 1)
        struct.pack_into('<H', self.raw, INDEX + 2 * at, 0)
        with self.assertRaisesRegex(ValueError, 'index'):
            self.run_audit()
        self.setUp()
        struct.pack_into('<H', self.raw, INDEX + 2 * ((m['home'](self.guest) + 100) & (m['INDEX'] - 1)), 40)
        with self.assertRaisesRegex(ValueError, 'index'):
            self.run_audit()
        # A tree link that no slot bit names.
        self.setUp()
        other = self.img.page(4)
        self.img.put(other + 8 * 1, self.pages[0] | 3)
        self.img.put(self.l1 + 8 * 1, other | 3)
        with self.assertRaisesRegex(ValueError, 'unrecorded or misplaced'):
            self.run_audit()

    def test_known_probe_starts(self):
        # The same known answers tools/test-native-shared.c checks against the monitor.
        for guest, start in ((0x800000000, 1765), (0x8d4edc000, 5967), (0x100004000, 4259), (0x100008000, 1130)):
            self.assertEqual(m['home'](guest), start)

    def test_probe_order_is_the_monitor_hash(self):
        # Two guests with the same probe start: the second sits after the first.
        base = 0x800000000
        seen = {}
        for n in range(1, 200000):
            h = m['home'](base + (n << 14))
            if h in seen:
                a, b = seen[h], base + (n << 14)
                break
            seen[h] = base + (n << 14)
        raw = bytearray(INDEX + m['INDEX'] * 2)
        groups = {0: dict(guest=a), 1: dict(guest=b)}
        ia, ib = index_put(raw, a, 0), index_put(raw, b, 1)
        index = list(struct.unpack_from(f'<{m["INDEX"]}H', raw, INDEX))
        self.assertEqual(ib, (ia + 1) & (m['INDEX'] - 1))
        self.assertEqual((m['find'](groups, index, a), m['find'](groups, index, b)), (0, 1))


if __name__ == '__main__':
    unittest.main()
