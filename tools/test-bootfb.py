#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Codeless AuxKC format, admission, and real loader placement checks."""
import contextlib
import copy
import hashlib
import io
from pathlib import Path
import plistlib
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import bootfb
from appledt import DeviceTree
import xnuboot as xb


class BootFramebufferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xb.configure_guest('j700ap-26A428-bootfb')
        cls.image = xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
        cls.info = plistlib.loads((ROOT / 'drivers/boot-framebuffer/'
                                  'SnapintoshBootFramebuffer.kext/Contents/Info.plist').read_bytes())

    def setUp(self):
        xb.configure_guest('j700ap-26A428-bootfb')
        xb.place(0x8c0000000, guest_span=8192 << 20)

    def tearDown(self):
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_native_collection_geometry_and_identity(self):
        data = bootfb.build_auxkc(self.image, self.info)
        magic, cpu, subtype, kind, count, command_bytes, flags, reserved = struct.unpack_from('<8I', data)
        self.assertEqual((magic, cpu, subtype, kind), (0xfeedfacf, 0x100000c, 2, 12))
        self.assertEqual(len(data), 32768)
        pos = 32
        ranges = []
        metadata = None
        collection_id = None
        for _ in range(count):
            cmd, size = struct.unpack_from('<II', data, pos)
            self.assertGreaterEqual(size, 8)
            self.assertLessEqual(pos + size, 32 + command_bytes)
            if cmd == 0x19:
                name, va, length, off, filesize, maximum, initial, sections, _ = struct.unpack_from('<16sQQQQiiII', data, pos+8)
                name = name.rstrip(b'\0')
                self.assertEqual(va, off)
                self.assertEqual(length, filesize)
                self.assertEqual(maximum, initial)
                self.assertEqual((va | length) & 0x3fff, 0)
                ranges.append((va, va+length, maximum))
                if name == b'__PRELINK_INFO':
                    self.assertEqual(sections, 1)
                    section_name, segment_name, addr, section_size, offset = struct.unpack_from('<16s16sQQI', data, pos+72)
                    self.assertEqual(section_name.rstrip(b'\0'), b'__info')
                    self.assertEqual(segment_name.rstrip(b'\0'), name)
                    self.assertEqual(addr, offset)
                    self.assertEqual(data[offset+section_size-1], 0)
                    metadata = plistlib.loads(data[offset:offset+section_size-1])
            elif cmd == 0x1b:
                collection_id = data[pos+8:pos+24]
            else:
                self.fail(f'unexpected command {cmd:#x}: no executable entries or fixups allowed')
            pos += size
        self.assertEqual(pos, 32+command_bytes)
        self.assertEqual(ranges, [(0, 16384, 5), (16384, 32768, 1)])
        # Native arm_vm_auxkc_init requires RO to include the contiguous RX
        # range and end at the highest non-LINKEDIT address.
        self.assertLessEqual(ranges[0][1], ranges[1][1])
        self.assertEqual(metadata['_PrelinkKCID'], collection_id)
        self.assertIn(b'_BootKCID\0', self.image.data)
        self.assertEqual(metadata['_BootKCID'], bytes.fromhex('0b89bc1e814fa4decdb7bc9940dc7fe5'))
        entry, = metadata['_PrelinkInfoDictionary']
        self.assertNotIn('_PrelinkExecutableLoadAddr', entry)
        self.assertNotIn('CFBundleExecutable', entry)
        self.assertTrue(entry['_PrelinkBundlePath'].endswith('/SnapintoshBootFramebuffer.kext'))
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), bootfb.KERNEL_SHA256)

    def test_deterministic_without_mutating_info(self):
        before = copy.deepcopy(self.info)
        self.assertEqual(bootfb.build_auxkc(self.image, self.info),
                         bootfb.build_auxkc(self.image, self.info))
        self.assertEqual(self.info, before)

    def test_rejects_other_kernel(self):
        with self.assertRaisesRegex(ValueError, 'pinned'):
            bootfb.build_auxkc(SimpleNamespace(data=b'other kernel'), self.info)

    def test_rejects_executable_or_wider_match_before_tree_change(self):
        tree = xb.build_devicetree()
        before = tree.serialize()
        for key, value in [('CFBundleExecutable', 'payload'), ('_PrelinkExecutableLoadAddr', 1)]:
            bad = copy.deepcopy(self.info)
            bad[key] = value
            with self.assertRaises(ValueError):
                bootfb.prepare(tree, self.image, bad)
            self.assertEqual(tree.serialize(), before)
        bad = copy.deepcopy(self.info)
        bad['IOKitPersonalities']['SnapintoshBootFramebuffer']['IONameMatch'] = '*'
        with self.assertRaises(ValueError):
            bootfb.prepare(tree, self.image, bad)
        self.assertEqual(tree.serialize(), before)

    def test_rejects_wrong_provider_or_existing_property(self):
        tree = xb.build_devicetree()
        tree.put(bootfb.NODE, 'compatible', b'different\0')
        with self.assertRaisesRegex(ValueError, 'identity'):
            bootfb.prepare(tree, self.image, self.info)
        tree.put(bootfb.NODE, 'compatible', bootfb.MATCH.encode()+b'\0')
        tree.add(bootfb.NODE, 'AAPL,boot-display', b'')
        with self.assertRaisesRegex(ValueError, 'already'):
            bootfb.prepare(tree, self.image, self.info)

    def test_profile_separation_and_real_loader_placement(self):
        original = xb.build_devicetree()
        before = original.serialize()
        with contextlib.redirect_stdout(io.StringIO()):
            built = xb.build(xb.DEFAULT_KERNELCACHE)
        base, size = built['auxkc_range']
        self.assertEqual((base, size), (xb.HANDOFF_PA+0x10000, 0x8000))
        self.assertEqual(xb.DEVICETREE_PA, base+size)
        self.assertLessEqual(xb.DEVICETREE_PA+built['devicetree_len'], xb.IMAGE_PA)
        self.assertEqual(xb.check_handoff_overlap(), [])
        values = struct.unpack_from('<QQQ', built['chunks'][xb.HANDOFF_PA], 0x2d8)
        self.assertEqual(values[:2], (self.image.vmin-xb.HANDOFF_SPAN+0x10000,)*2)
        self.assertEqual(values[2], self.image.vmax)
        tree = built['dt']
        self.assertEqual(tree.get(bootfb.NODE, 'AAPL,boot-display'), b'')
        tree.nodes[bootfb.NODE].pop('AAPL,boot-display')
        # build() also preloads SEP firmware; compare native display subtree.
        self.assertEqual({k: bytes(v.value) for k, v in tree.nodes[bootfb.NODE].items()},
                         {k: bytes(v.value) for k, v in original.nodes[bootfb.NODE].items()})
        self.assertEqual(original.serialize(), before)
        xb.configure_guest('j700ap-26A428-sep-preload')
        self.assertEqual(xb.DEVICETREE_PA, xb.HANDOFF_PA+0x10000)
        self.assertIsNone(xb.build_devicetree().get(bootfb.NODE, 'AAPL,boot-display'))
        old_handoff = xb.build_handoff(xb.HANDOFF_PA)[0][xb.HANDOFF_PA]
        self.assertEqual(old_handoff[0x2d8:0x2f0], bytes(24))

    def test_bad_virtual_bounds(self):
        for base, end in [(1, 0x40000), (0x10000, 1), (0x10000, 0x20000)]:
            with self.assertRaises(ValueError):
                bootfb.handoff_values(base, end)

    def test_historical_payload_remains_byte_identical(self):
        payload = bootfb.build_auxkc(self.image, self.info)
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         'b474ddbd0d3ec72207b6eea752f6a1d88617dcbbb8fc603fac4f93ffb96db191')

    def test_dedicated_provider_separates_matching_without_changing_disp0(self):
        xb.configure_guest('j700ap-26A428-bootfb-nub')
        xb.place(0x8c0000000, guest_span=8192 << 20)
        original = xb.build_devicetree()
        original_display = original.serialize(bootfb.NODE)
        old_children = original.children[bootfb.NUB_PARENT][:]
        with contextlib.redirect_stdout(io.StringIO()):
            built = xb.build(xb.DEFAULT_KERNELCACHE)
        tree = built['dt']
        self.assertEqual(tree.serialize(bootfb.NODE), original_display)
        self.assertIsNone(tree.get(bootfb.NODE, 'AAPL,boot-display'))
        self.assertEqual(tree.children[bootfb.NUB_PARENT], old_children+[bootfb.NUB_NODE])
        self.assertEqual(tree.get(bootfb.NUB_NODE, 'compatible'), bootfb.NUB_MATCH.encode()+b'\0')
        self.assertEqual(tree.get(bootfb.NUB_NODE, 'AAPL,boot-display'), b'')
        self.assertIsNone(tree.get(bootfb.NUB_NODE, 'reg'))
        self.assertEqual(DeviceTree(tree.serialize()).serialize(), tree.serialize())
        payload = bootfb.build_auxkc(self.image, self.info, dedicated=True)
        metadata = plistlib.loads(payload[bootfb.PAGE:].split(b'\0', 1)[0])
        personality = metadata['_PrelinkInfoDictionary'][0]['IOKitPersonalities']['SnapintoshBootFramebuffer']
        self.assertEqual(personality['IONameMatch'], bootfb.NUB_MATCH)
        self.assertNotEqual(metadata['_PrelinkKCID'], bytes.fromhex('265b6b02906254b8a70eca2906d566d1'))
        self.assertEqual(self.info['IOKitPersonalities']['SnapintoshBootFramebuffer']['IONameMatch'], bootfb.MATCH)
        self.assertEqual(built['auxkc_range'], (xb.HANDOFF_PA+0x10000, 0x8000))
        self.assertEqual(xb.check_handoff_overlap(), [])

    def test_dedicated_provider_collision_is_not_overwritten(self):
        tree = xb.build_devicetree()
        bootfb.prepare(tree, self.image, self.info, dedicated=True)
        before = tree.serialize()
        with self.assertRaisesRegex(ValueError, 'provider already exists'):
            bootfb.prepare(tree, self.image, self.info, dedicated=True)
        self.assertEqual(tree.serialize(), before)


if __name__ == '__main__':
    unittest.main()
