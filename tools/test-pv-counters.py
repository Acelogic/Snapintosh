#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""context.pv_audit: target layout (tail append) and the audit decoder."""
from pathlib import Path
import runpy
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
pv = runpy.run_path(str(ROOT / 'tools/pv_counters.py'))


class PvAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()

    def test_tail_append(self):
        l = self.layout
        # Appended after the kernel-root MAP_PAGE conflict record (5 words),
        # which follows the MULTIPAGE counters; every earlier offset stays.
        self.assertEqual(l.offset('context', 'kernel_map_conflict'), l.offset('context', 'multipage_groups') + 8)
        self.assertEqual(l.offset('context', 'pv_audit'), l.offset('context', 'kernel_map_conflict') + 40)
        self.assertEqual(l.size('sptm_pv_audit'), pv['SIZE'])
        for n, field in enumerate(pv['FIELDS']):
            self.assertEqual(l.offset('sptm_pv_audit', field), 8 * n, field)
        end = l.offset('context', 'pv_audit') + pv['SIZE']
        # The linked-AuxKC counters are the next tail append, then the Stage 4 Adreno state.
        self.assertEqual(l.offset('context', 'auxkc_exec'), end)
        self.assertEqual(l.offset('context', 'gpu'), end + l.size('auxkc_exec_state'))
        # Preserve every older context offset when adding retained console data.
        # This fails if the ring is inserted into the existing report ABI.
        tail = l.offset('context', 'gpu') + l.size('adreno_state')
        self.assertEqual(l.offset('context', 'console_tail_bytes'), tail)
        self.assertEqual(l.offset('context', 'console_tail'), tail + 8)
        tail += 8 + 65536
        # Later appends follow the ring directly (endpoint8 kernel removals
        # first); inactive-root mirroring directly follows early stop, and the
        # context ends with the last append, native page tables.
        self.assertEqual(l.offset('context', 'kernel_disjoint_unmaps'), tail)
        end = l.offset('context', 'early_stop') + l.size('early_stop_state')
        self.assertEqual(l.offset('context', 'inactive_mirror'), end)
        end += l.size('inactive_mirror_state')
        self.assertEqual(l.offset('context', 'native_cpu'), end)
        end = l.offset('context', 'native_stats') + l.size('native_table_stats')
        self.assertEqual(l.offset('context', 'native_shared'), end)
        end += l.size('native_shared')
        self.assertTrue(0 <= l.size('context') - end < 64)

    def test_read_context(self):
        l = self.layout
        work = 0x80000000
        base = work + l.offset('context', 'pv_audit')
        values = [7, 1, 3, 0x104000, 0x60000968270e43, 0x60000968274e43, 0x968008000, 0x105568000, 0, 0, 0, 0]
        raw = struct.pack('<12Q', *values)
        conflict = work + l.offset('context', 'kernel_map_conflict')
        def read(pa, n):
            if (pa, n) == (conflict, 40):
                return struct.pack('<5Q', 2, 0xfffffe1000004000, 0x40000968278403, 0x40000968270403, 0xfffffe0106d54000)
            self.assertEqual((pa, n), (base, pv['SIZE']))
            return raw
        got = pv['read_context'](read, work, l.offset, l.records['context'])
        self.assertEqual(got['moved_pointers'], 7)
        self.assertEqual(got['remaps'], 1)
        self.assertEqual(got['duplicate_records'], 3)
        self.assertEqual(got['kernel_map_conflicts'], 2)
        self.assertEqual(got['last_kernel_conflict']['va'], '0xfffffe1000004000')
        self.assertEqual(got['last_remap'], dict(va='0x104000', old='0x60000968270e43', next='0x60000968274e43'))
        self.assertEqual(got['last_duplicate'], dict(root='0x968008000', va='0x105568000'))
        self.assertEqual(got['uncommitted_remaps'], 0)

    def test_zero_and_older_monitor(self):
        got = pv['decode'](bytes(pv['SIZE']))
        self.assertEqual((got['remaps'], got['last_remap'], got['last_duplicate']), (0, None, None))
        self.assertIsNone(pv['read_context'](None, 0, None, '   0 | struct context\n'))
        with self.assertRaises(ValueError):
            pv['decode'](bytes(8))


if __name__ == '__main__':
    unittest.main()
