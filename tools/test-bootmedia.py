#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import runpy
import struct
import sys
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import bootmedia


class GPTTests(unittest.TestCase):
    def fixture(self):
        root, isc = b'R' * 0x14000, b'I' * 0x8000
        base = 0x100000000
        chunks, desc = bootmedia.assemble(root, isc, base, base + (256 << 20))
        image = bytearray(desc['bytes'])
        cursor = base
        for pa, blob in sorted(chunks.items()):
            self.assertEqual(pa, cursor, 'uninitialized or overlapping guest media bytes')
            image[pa - base:pa - base + len(blob)] = blob
            cursor += len(blob)
        self.assertEqual(cursor, base + len(image))
        self.assertIs(chunks[base + desc['root'][0]], root)
        self.assertIs(chunks[base + desc['isc'][0]], isc)
        return image, desc

    def test_native_disk_structure_and_unmodified_payloads(self):
        image, desc = self.fixture()
        self.assertEqual(bootmedia.inspect(lambda o, n: image[o:o+n], len(image)), desc)
        self.assertEqual(image[510:512], b'\x55\xaa')
        self.assertEqual(image[450], 0xee)
        for offset in (512, len(image) - 512):
            h = bytearray(image[offset:offset+92])
            expected = struct.unpack_from('<I', h, 16)[0]
            h[16:20] = bytes(4)
            self.assertEqual(zlib.crc32(h), expected)
        self.assertEqual(image[1024:1040], bootmedia.APFS_TYPE.bytes_le)
        self.assertEqual(image[1152:1168], bootmedia.ISC_TYPE.bytes_le)
        for name, fill in [('root', b'R'), ('isc', b'I')]:
            off, size = desc[name]
            self.assertEqual(image[off:off+size], fill * size)
        end = desc['root'][0] + desc['root'][1]
        self.assertFalse(any(image[end:desc['isc'][0]]))

    def test_corrupt_gpt_copies_fail_before_payload_access(self):
        image, _ = self.fixture()
        # Primary/backup headers, both arrays, protective MBR, extra entries.
        for off in [450, 510, 512, 528, 536, 552, 584, 600, 1024, 1152, 1280,
                    len(image)-512, len(image)-496, len(image)-16384]:
            bad = bytearray(image)
            bad[off] ^= 1
            with self.subTest(offset=off), self.assertRaises(ValueError):
                bootmedia.inspect(lambda o, n: bad[o:o+n], len(bad))

    def test_crc_valid_wrong_partitions_are_rejected(self):
        image, _ = self.fixture()
        for field, value in [(32, 1), (40, (len(image)//512)), (48, 1),
                             (128+32, 2048), (128+40, 2047)]:
            bad = bytearray(image)
            struct.pack_into('<Q', bad, 1024 + field, value)
            entries = bad[1024:1024+16384]
            bad[-512-16384:-512] = entries
            for off in [512, len(bad)-512]:
                struct.pack_into('<I', bad, off+88, zlib.crc32(entries))
                struct.pack_into('<I', bad, off+16, 0)
                struct.pack_into('<I', bad, off+16, zlib.crc32(bad[off:off+92]))
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                bootmedia.inspect(lambda o, n: bad[o:o+n], len(bad))

    def test_bounds_and_allocator_headroom(self):
        for sizes in [(0, 16384), (16383, 16384), (16384, 16385)]:
            with self.assertRaises(ValueError):
                bootmedia.layout(*sizes)
        for base, end in [(-16384, 1<<30), (1, 1<<30), (0, 128<<20), (0, (1<<36)+1)]:
            with self.assertRaises(ValueError):
                bootmedia.assemble(bytes(16384), bytes(16384), base, end)

    def test_sparse_upload_replaces_old_ram_exactly(self):
        base = 0x100000000
        source = bytearray((8 << 20) + 0x4000)
        source[3] = 17
        source[0x234567] = 42
        source[-1] = 99
        memory = bytearray(b'\xaa' * len(source))
        calls = []

        class Proxy:
            def memset8(self, address, value, size):
                calls.append(('zero', address, size))
                self_range(address, size)
                memory[address-base:address-base+size] = bytes([value]) * size

            def writemem(self, address, data):
                calls.append(('write', address, len(data)))
                self_range(address, len(data))
                memory[address-base:address-base+len(data)] = data

        def self_range(address, size):
            self.assertLessEqual(size, 8 << 20)
            self.assertGreaterEqual(address, base)
            self.assertLessEqual(address+size, base+len(source))

        sent = bootmedia.upload_auxiliary(Proxy(), base, source)
        self.assertEqual(memory, source)
        self.assertEqual(sent, 2 * (64 << 10) + 0x4000)
        self.assertEqual([c[0] for c in calls], ['zero', 'zero', 'write', 'write', 'write'])
        for address, data in [(base+1, source), (base, bytes(3)), (1<<36, source)]:
            before = list(calls)
            with self.assertRaises(ValueError):
                bootmedia.upload_auxiliary(Proxy(), address, data)
            self.assertEqual(calls, before)


class ScratchTests(unittest.TestCase):
    api = runpy.run_path(str(ROOT / 'tools/make-isc-fixture.py'))

    def test_scratch_size_refused_before_reading(self):
        class Oversized:
            def __len__(self):
                return (2 << 30) + 0x4000
            def __getitem__(self, index):
                raise AssertionError('oversized input must not be read')
        self.assertEqual(self.api['MAX_SCRATCH_BYTES'], 2 << 30)
        with self.assertRaises(ValueError):
            self.api['make_xart'](Oversized())

    def fixture(self):
        image = bytearray(16384)
        image[32:36] = b'NXSB'
        struct.pack_into('<IQ', image, 36, 4096, 4)
        block = bytearray(4096)
        struct.pack_into('<I', block, 24, 13)
        block[32:36] = b'APSB'
        struct.pack_into('<Q', block, 264, 1)
        block[704:719] = b'Snapintosh-xART'
        block[:8] = self.api['checksum'](block)
        image[4096:8192] = block
        image[:8] = self.api['checksum'](image[:4096])
        return image

    def test_only_role_and_checksum_change(self):
        source = self.fixture()
        before = bytes(source)
        result, off = self.api['make_xart'](source)
        self.assertEqual(source, before)
        self.assertEqual(off, 4096)
        changes = {i for i, (a, b) in enumerate(zip(source, result)) if a != b}
        self.assertLessEqual(changes, set(range(off, off+8)) | {off+964, off+965})
        self.assertEqual(struct.unpack_from('<H', result, off+964)[0], 256)
        self.assertEqual(result[off:off+8], self.api['checksum'](result[off:off+4096]))

    def test_refuse_used_or_unrecognized_filesystems(self):
        source = self.fixture()
        for off in [24, 32, 184, 192, 200, 208, 216, 264, 704, 964]:
            bad = bytearray(source)
            bad[4096+off] ^= 1
            bad[4096:4104] = self.api['checksum'](bad[4096:8192])
            with self.subTest(offset=off), self.assertRaises(ValueError):
                self.api['make_xart'](bad)
        for off in [0, 32, 36, 40, 4096]:
            bad = bytearray(source)
            bad[off] ^= 1
            with self.subTest(offset=off), self.assertRaises(ValueError):
                self.api['make_xart'](bad)
        duplicate = bytearray(source)
        duplicate[8192:12288] = duplicate[4096:8192]
        with self.assertRaises(ValueError):
            self.api['make_xart'](duplicate)


if __name__ == '__main__':
    unittest.main()
