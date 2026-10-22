#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent CHRP consumer checks and atomic boot-input validation."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree, Property
from guestprofile import J700_26A428
from nvram import empty_bank, populate_boot_nvram

SPEC = J700_26A428.nvram_boot
CHOSEN = '/device-tree/chosen'


def fixture():
    dt = DeviceTree.__new__(DeviceTree)
    dt.nodes = {CHOSEN: {name: Property(name, bytes(size)) for name, size in (
        ('name', 7), ('nvram-proxy-data', SPEC.bank_size),
        ('nvram-bank-size', 4), ('nvram-bank-count', 4), ('nvram-current-bank', 4))}}
    return dt


class NVRAMTests(unittest.TestCase):
    def test_bank_consumer(self):
        b = empty_bank(SPEC)
        self.assertEqual(len(b), 65536)
        # Independently reproduce the kernel's byte-wise checks, not zlib.
        low, high = 1, 0
        for value in b[20:]:
            low = (low + value) % 65521
            high = (high + low) % 65521
        self.assertEqual(struct.unpack_from('<I', b, 16)[0], high << 16 | low)
        self.assertEqual(struct.unpack_from('<I', b, 20)[0], 1)
        offset, parts = 0, []
        while offset < len(b):
            sig, checksum, blocks, name = struct.unpack_from('<BBH12s', b, offset)
            header = b[offset:offset + 16]
            total = sig
            for value in header[2:]:
                total += value
                total = (total & 255) + (total >> 8)
            self.assertEqual(checksum, total)
            size = blocks * 16
            self.assertGreaterEqual(size, 16)
            self.assertLessEqual(offset + size, len(b))
            parts.append((offset, size, name.rstrip(b'\0')))
            if offset:
                self.assertEqual(sig, 0x70)
                self.assertEqual(b[offset + 16:offset + size], bytes(size - 16))
            offset += size
        self.assertEqual(parts, [(0, 32, b'2nvram'),
                                (32, 0x1fe0, b'2common'),
                                (0x2000, 0xe000, b'2system')])

    def test_boot_properties(self):
        dt = fixture()
        populate_boot_nvram(dt, SPEC)
        self.assertEqual(dt.get(CHOSEN, 'nvram-proxy-data'), empty_bank(SPEC))
        for name, expected in [('nvram-bank-size', 65536),
                               ('nvram-bank-count', 2), ('nvram-current-bank', 0)]:
            self.assertEqual(struct.unpack('<I', dt.get(CHOSEN, name))[0], expected)

    def test_invalid_layouts(self):
        for field, values in [('format', ['unknown']), ('bank_size', [0, 32, 65535, 0x100000]),
                              ('common_end', [0, 32, 65, 65536]), ('bank_count', [0, -1, 1 << 32])]:
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    empty_bank(replace(SPEC, **{field: value}))

    def test_bad_input_has_no_partial_changes(self):
        for name, value in [('nvram-proxy-data', b'old data'),
                            ('nvram-proxy-data', b'X' + bytes(65535)),
                            ('nvram-bank-size', b'\0'),
                            ('nvram-bank-count', struct.pack('<I', 2)),
                            ('nvram-current-bank', None)]:
            with self.subTest(name=name, value_length=len(value) if value else 0):
                dt = fixture()
                if value is None:
                    del dt.nodes[CHOSEN][name]
                else:
                    dt.set(CHOSEN, name, value)
                before = {k: bytes(v.value) for k, v in dt.nodes[CHOSEN].items()}
                with self.assertRaises(ValueError):
                    populate_boot_nvram(dt, SPEC)
                self.assertEqual(before, {k: bytes(v.value) for k, v in dt.nodes[CHOSEN].items()})

    def test_real_loader_tree(self):
        import xnuboot
        if not xnuboot.DEFAULT_DEVICETREE.exists():
            self.skipTest('audited firmware is unavailable')
        dt = xnuboot.build_devicetree()
        reparsed = DeviceTree(dt.blob)
        self.assertEqual(reparsed.get(CHOSEN, 'nvram-proxy-data'), empty_bank(SPEC))
        self.assertEqual(reparsed.get(CHOSEN, 'nvram-bank-size'), struct.pack('<I', SPEC.bank_size))


if __name__ == '__main__':
    unittest.main()
