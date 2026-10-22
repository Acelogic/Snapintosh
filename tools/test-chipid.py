#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest chip identity: manifest binding, atomic refusal and serialized ABI."""
from dataclasses import replace
from pathlib import Path
import hashlib
import plistlib
import struct
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree, Property
from chipid import populate_chip_id
from guestprofile import J700_26A428

SPEC = J700_26A428.chip_id_boot
CHOSEN = '/device-tree/chosen'


def fixture():
    dt = DeviceTree.__new__(DeviceTree)
    dt.nodes = {
        '/device-tree': {'compatible': Property('compatible', b'J700AP\0Mac17,5\0AppleARM\0')},
        '/device-tree/arm-io': {'compatible': Property('compatible', b'arm-io,t8140\0')},
        CHOSEN: {'chip-id': Property('chip-id', bytes(4)),
                 'unique-chip-id': Property('unique-chip-id', bytes(8))},
    }
    return dt


def snapshot(dt):
    return {p: {k: (bytes(v.value), v.placeholder) for k, v in props.items()}
            for p, props in dt.nodes.items()}


class ChipIDTests(unittest.TestCase):
    def test_exact_width_value_and_idempotence(self):
        dt = fixture(); before = snapshot(dt)
        self.assertEqual(populate_chip_id(dt, SPEC), 0x8140)
        self.assertEqual(dt.get(CHOSEN, 'chip-id'), b'\x40\x81\0\0')
        after = snapshot(dt)
        populate_chip_id(dt, SPEC)
        self.assertEqual(snapshot(dt), after)
        after[CHOSEN]['chip-id'] = before[CHOSEN]['chip-id']
        self.assertEqual(after, before)

    def test_invalid_profile_refused_atomically(self):
        for value in [False, True, 0, -1, 0x100000000, 33100.0, '0x8140']:
            with self.subTest(value=value):
                dt = fixture(); before = snapshot(dt)
                with self.assertRaises(ValueError):
                    populate_chip_id(dt, replace(SPEC, chip_id=value))
                self.assertEqual(snapshot(dt), before)

    def test_missing_and_malformed_identity_refused_atomically(self):
        for value in [None, b'', bytes(2), bytes(8), struct.pack('<I', 0x8112)]:
            with self.subTest(value=value):
                dt = fixture()
                if value is None: del dt.nodes[CHOSEN]['chip-id']
                else: dt.put(CHOSEN, 'chip-id', value)
                before = snapshot(dt)
                with self.assertRaises(ValueError): populate_chip_id(dt, SPEC)
                self.assertEqual(snapshot(dt), before)
        dt = fixture(); del dt.nodes[CHOSEN]; before = snapshot(dt)
        with self.assertRaises(ValueError): populate_chip_id(dt, SPEC)
        self.assertEqual(snapshot(dt), before)

    def test_bindings_and_placeholders_refused_atomically(self):
        for path, name in [('/device-tree', 'compatible'),
                           ('/device-tree/arm-io', 'compatible'), (CHOSEN, 'chip-id')]:
            dt = fixture(); dt.nodes[path][name].placeholder = True
            before = snapshot(dt)
            with self.assertRaises(ValueError): populate_chip_id(dt, SPEC)
            self.assertEqual(snapshot(dt), before)
        for path in ['/device-tree', '/device-tree/arm-io']:
            for value in [b'other\0', b'J700AP-extra\0arm-io,t8140-extra\0', b'']:
                dt = fixture(); dt.put(path, 'compatible', value); before = snapshot(dt)
                with self.assertRaises(ValueError): populate_chip_id(dt, SPEC)
                self.assertEqual(snapshot(dt), before)
        for key in ['root_compatible', 'arm_io_compatible']:
            for value in [b'', b'J700AP\0']:
                dt = fixture(); before = snapshot(dt)
                with self.assertRaises(ValueError):
                    populate_chip_id(dt, replace(SPEC, **{key: value}))
                self.assertEqual(snapshot(dt), before)

    def test_serialized_real_tree_preserves_unique_identity(self):
        import xnuboot as xb
        original = DeviceTree(Path(xb.DEFAULT_DEVICETREE).read_bytes())
        dt = DeviceTree(xb.build_devicetree().serialize())
        self.assertEqual(dt.get(CHOSEN, 'chip-id'), struct.pack('<I', 0x8140))
        self.assertEqual(dt.get(CHOSEN, 'unique-chip-id'), original.get(CHOSEN, 'unique-chip-id'))
        self.assertEqual(dt.get('/device-tree/arm-io/sep/iop-sep-nub', 'rom-panic-bytes'),
                         struct.pack('<I', 424))

    def test_pinned_restore_manifest_matches_profile(self):
        image = ROOT / 'downloads/UniversalMac_27.0_26A428_Restore.ipsw'
        if not image.exists(): self.skipTest('pinned restore image is not available')
        with zipfile.ZipFile(image) as z: raw = z.read('BuildManifest.plist')
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '22949db91be2ddd0009a0047ceba37336452b76af3ff915f496d842b85cce6a7')
        identities = [i for i in plistlib.loads(raw)['BuildIdentities']
                      if i['Info']['DeviceClass'] == 'j700ap']
        self.assertEqual(len(identities), 3)
        self.assertEqual({int(i['ApChipID'], 16) for i in identities}, {SPEC.chip_id})


if __name__ == '__main__': unittest.main()
