#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Monitor arena reservation, resident locator and stage2 isolation checks."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'probes'))
import monitor_work as mw
import run
import xnuboot as xb


class WorkRegionTests(unittest.TestCase):
    def setUp(self):
        self.info = dict(heap_base=0xb9e40000, heap_size=64 << 20,
                         image_base=0xb0000000, image_size=0xa0000,
                         stage_base=0xb0000000, stage_size=16 << 20,
                         stage_generation=1, memory_map=0x80000000,
                         memory_map_size=48, memory_map_stride=48)
        self.low = 0x8c0000000
        self.high = self.low + (8192 + 528) * 1024 * 1024
        self.base = self.high
        free_high = (self.high + mw.WORK_SIZE + (32 << 20) - 1) & ~((32 << 20) - 1)
        self.free = [(self.low, free_high)]
        self.map = struct.pack('<IIQQQQQ', 7, 0, self.low, 0,
                               (self.free[0][1] - self.low) // 4096, 0, 0)

    def encode(self):
        return mw.encode_locator(self.base, mw.WORK_SIZE, self.low, self.high,
                                 self.info, self.free)

    def test_external_region_and_resident_identity(self):
        data = self.encode()
        self.assertEqual(mw.decode_locator(data, self.info, self.free),
                         (self.base, mw.WORK_SIZE))
        changed = dict(self.info, stage_generation=2)
        with self.assertRaisesRegex(ValueError, 'resident q1n1'):
            mw.decode_locator(data, changed, self.free)

    def test_installed_capacity_reservation(self):
        # Real installed startup churns in128MiB. Admit240MiB only when the
        # entire new reservation is free; the old bound fails the first call.
        capacity = 240 << 20
        free = [(self.low, self.base + capacity)]
        mw.validate_region(self.base, capacity, self.low, self.high, self.info, free)
        with self.assertRaises(ValueError):
            mw.validate_region(self.base, capacity, self.low, self.high, self.info,
                               [(self.low, self.base + capacity - 4096)])
        with self.assertRaises(ValueError):
            mw.validate_region(self.base, 128 << 20, self.low, self.high, self.info, free)

    def test_every_locator_byte_is_checked(self):
        data = self.encode()
        for offset in range(len(data)):
            corrupted = bytearray(data)
            corrupted[offset] ^= 1
            with self.assertRaises(ValueError):
                mw.decode_locator(bytes(corrupted), self.info, self.free)
        with self.assertRaises(ValueError):
            mw.decode_locator(bytes(mw.LOCATOR_SIZE), self.info, self.free)

    def test_overlaps_bounds_and_insufficient_memory(self):
        for base, size, free in [(self.low, mw.WORK_SIZE, self.free),
                                 (self.info['heap_base'], mw.WORK_SIZE, [(0x80000000, 1 << 32)]),
                                 (self.base + 4096, mw.WORK_SIZE, self.free),
                                 (self.base, mw.WORK_SIZE - 4096, self.free),
                                 (mw.IPA_LIMIT, mw.WORK_SIZE, [(mw.IPA_LIMIT, mw.IPA_LIMIT * 2)]),
                                 (self.base, mw.WORK_SIZE, [(self.base, self.base + mw.WORK_SIZE - 4096)])]:
            with self.assertRaises(ValueError):
                mw.validate_region(base, size, self.low, self.high, self.info, free)

    def test_firmware_reservations_are_carved_out(self):
        blob = struct.pack('<IIQQQQQ', 7, 0, 0x80000000, 0, 0x80000, 0, 0)
        spans = mw.free_spans(blob, 48, self.info)
        for low, high in spans:
            self.assertTrue(all(high <= a or low >= b for a, b in mw.reserved(self.info)))
        with self.assertRaises(ValueError):
            mw.free_spans(blob[:-1], 48, self.info)

    def test_loader_selection_checks_explicit_base_and_total_reserve(self):
        class Proxy:
            def readmem(inner, pa, size):
                self.assertEqual((pa, size), (self.info['memory_map'], 48))
                return self.map
        need = self.high + mw.WORK_SIZE - self.low
        self.assertEqual(run.free_region(Proxy(), self.info, need, required_base=self.low), self.free[0])
        self.assertIsNone(run.free_region(Proxy(), self.info, self.free[0][1] - self.low + 4096))
        self.assertIsNone(run.free_region(Proxy(), self.info, need, required_base=self.low + 4096))

    def test_locator_roundtrip_revalidates_firmware_map(self):
        storage = {self.info['memory_map']: self.map}
        class Proxy:
            def readmem(inner, pa, size, **kwargs):
                return storage[pa][:size]
            def writemem(inner, pa, data):
                storage[pa] = data
        proxy = Proxy()
        mw.publish_work(proxy, self.info, self.base, mw.WORK_SIZE, self.low, self.high)
        self.assertEqual(mw.resident_work(proxy, self.info), (self.base, mw.WORK_SIZE))
        storage[self.info['memory_map']] = bytes(48)
        with self.assertRaisesRegex(ValueError, 'free memory'):
            mw.resident_work(proxy, self.info)

    def test_stage2_excludes_context_and_exposes_tables_readonly(self):
        xb.configure_guest('j700ap-26A428-sep-preload')
        xb.place(self.low, guest_span=8192 << 20)
        context_size = 4 << 20
        table_base = self.base + context_size
        ranges = xb.stage2_ranges(work=(table_base, mw.WORK_SIZE - context_size))
        self.assertIsNone(xb.stage2_where(self.base, ranges))
        region = next(row for row in ranges if row[0] == table_base)
        self.assertEqual(region[2], 'ro')
        self.assertEqual(region[1], self.base + mw.WORK_SIZE)
        self.assertIsNone(xb.stage2_where(mw.locator_address(self.info), ranges))


if __name__ == '__main__':
    unittest.main()
