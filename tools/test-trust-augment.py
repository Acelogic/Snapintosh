#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Augmented boot trust cache: row format, pinned base, binding and readback."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
from guestprofile import get_profile
from trustcache import (AugmentedTrustCacheSpec, augment, entry, load_additions, parse_v2,
                        reserve_size, MAX_PAYLOAD)

GPU = 'j700ap-26A428-bootfb-auxkc-gpu'
FIRMWARE = ROOT / 'downloads/extracted/j700ap'
APPLE = bytes.fromhex('e388638c5a061155f37fa6977eda6220c5bda33e')   # index 984
PARAVIRT = bytes.fromhex('ef2b813924d40365b012cedcdd7ebc95448f87fa')
OURS = [hashlib.sha256(b'snapintosh-test-kext').digest(),
        hashlib.sha256(b'snapintosh-test-plugin').digest()]


class TrustAugmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = get_profile(GPU).trust_cache
        cls.base = cls.spec.base.load(FIRMWARE)
        cls.temp = tempfile.TemporaryDirectory()
        cls.additions = Path(cls.temp.name) / 'additions.json'
        cls.additions.write_text(json.dumps(
            [dict(cdhash=h[:20].hex(), category=2, name=f'test{n}') for n, h in enumerate(OURS)]))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_row_trailer_matches_apple(self):
        rows = parse_v2(self.base)['entries']
        paravirt = next(r for r in rows if r[:20] == PARAVIRT)
        self.assertEqual(paravirt[20:], bytes.fromhex('02000200'))
        self.assertEqual(entry(PARAVIRT, category=2), paravirt)
        self.assertEqual(entry(OURS[0])[20:], bytes.fromhex('02000200'))
        # The prototype's '<HBB' 0x0200,2,0 put flags where the hash type goes.
        self.assertNotEqual(entry(OURS[0])[20:], struct.pack('<HBB', 0x0200, 2, 0))
        self.assertEqual(entry(OURS[0])[:20], OURS[0][:20])
        for bad in (dict(hash_type=3), dict(flags=256), dict(category=1 << 16)):
            with self.assertRaises(ValueError):
                entry(OURS[0], **bad)
        with self.assertRaises(ValueError):
            entry(OURS[0][:19])

    def test_augment_preserves_base_and_sorts(self):
        rows = [entry(h) for h in OURS]
        payload = augment(self.base, rows)
        parsed = parse_v2(payload)
        self.assertEqual(parsed['count'], 1105)
        self.assertEqual(payload[4:20], self.base[4:20])
        self.assertEqual(set(parsed['entries']), set(parse_v2(self.base)['entries']) | set(rows))

    def test_collisions_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'collides'):
            augment(self.base, [entry(APPLE, category=9)])
        with self.assertRaisesRegex(ValueError, 'collides'):
            augment(self.base, [entry(OURS[0]), entry(OURS[0], category=3)])
        with self.assertRaises(ValueError):
            augment(self.base, [])
        with self.assertRaises(ValueError):
            augment(self.base, [entry(OURS[0])[:23] + b'\1'])

    def test_spec_binds_verifies_and_refuses(self):
        with self.assertRaisesRegex(ValueError, 'no bound CDHashes'):
            self.spec.load(FIRMWARE)
        bound = self.spec.bind(load_additions(self.additions))
        self.assertEqual(bound.entries, 1105)
        payload = bound.load(FIRMWARE)
        self.assertEqual(bound.verify(payload), payload)
        with self.assertRaises(ValueError):
            bound.verify(self.base)
        for offset in (0, 4, 24, len(payload) - 1):
            changed = bytearray(payload)
            changed[offset] ^= 1
            with self.subTest(offset), self.assertRaises(ValueError):
                bound.verify(bytes(changed))
        other = self.spec.bind([entry(OURS[0])])
        with self.assertRaises(ValueError):
            other.verify(payload)
        with self.assertRaises(ValueError):
            self.spec.bind([])
        with self.assertRaises(ValueError):
            self.spec.bind([entry(hashlib.sha256(bytes([n])).digest()) for n in range(65)])

    def test_capacity(self):
        self.assertTrue(xb.static_trust_fits(len(self.base) + 64 * 24))
        # The window still holds any cache up to the old 64 KiB bound; only a larger one (the
        # installed OS's, ~441 KB) takes the payload-area placement in xnuboot.build().
        self.assertTrue(xb.static_trust_fits(0x10000))
        self.assertFalse(xb.static_trust_fits(MAX_PAYLOAD))
        begin, end = xb.static_trust_window(6)
        self.assertFalse(xb.static_trust_fits(end - begin))
        self.assertEqual(reserve_size(len(self.base) + 2 * 24), 0xc000)

    def test_readback_audit_accepts_an_appended_hit(self):
        audit = runpy.run_path(str(ROOT / 'tools/audit-static-trust.py'))['audit_static_trust']
        bound = self.spec.bind(load_additions(self.additions))
        payload = bound.load(FIRMWARE)
        index = parse_v2(payload)['entries'].index(entry(OURS[1]))
        pa, va = 0x90000000, 0xfffffe1000000000
        runtime = bytearray(0x4000)
        struct.pack_into('<Q', runtime, 0x10, va + 0x100)
        struct.pack_into('<Q', runtime, 0x20, va + 0x80)
        struct.pack_into('<QQ', runtime, 0x110, len(payload), va + 0x4000)
        state = bytearray(struct.pack('<8Q24s2Q', 1, 1105, 1, 1, 0, 1, 32, 0x1000000000,
                                      OURS[1][:20], va + 0x100, va + 0x4000 + 24 + 24 * index) +
                          (1 << index).to_bytes(512, 'little'))
        def read(address, size):
            raw = bytes(runtime) + payload
            return raw[address - pa:address - pa + size]
        result = audit(read, (pa, va, len(payload)), state, bound)
        self.assertEqual(result['matched'], [dict(index=index, cdhash=OURS[1][:20].hex(),
                                                   hash_type=2, flags=0, category=2)])
        with self.assertRaises(ValueError):          # the unbound or plain spec disagrees
            audit(read, (pa, va, len(payload)), state, self.spec.base)

    def test_loader_binds_only_augmented_profiles(self):
        xb.configure_guest(GPU)
        try:
            with self.assertRaisesRegex(ValueError, 'pass --trust-additions'):
                xb.trust_cache_spec()
            self.assertEqual(xb.trust_cache_spec(self.additions).entries, 1105)
            xb.configure_guest('j700ap-26A428-bootfb-auxkc')
            with self.assertRaisesRegex(ValueError, 'unmodified Apple'):
                xb.trust_cache_spec(self.additions)
            self.assertEqual(xb.trust_cache_spec().entries, 1103)
        finally:
            xb.configure_guest('j700ap-26A428-sep-preload')

    def test_tool_writes_the_same_bytes_the_loader_builds(self):
        out = Path(self.temp.name) / 'cache'
        additions = Path(self.temp.name) / 'tool.json'
        result = subprocess.run([sys.executable, str(ROOT / 'tools/augment-trust-cache.py'),
                                 '--additions', str(additions), '--add-cdhash', OURS[0].hex(),
                                 '--output', str(out)], capture_output=True, text=True,
                                env={'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report['entries'], report['appended']), (1104, 1))
        self.assertEqual(report['rows'][0]['trailer'], '02000200')
        self.assertEqual(out.read_bytes(), augment(self.base, [entry(OURS[0])]))
        bad = subprocess.run([sys.executable, str(ROOT / 'tools/augment-trust-cache.py'),
                              '--additions', str(additions), '--add-cdhash', APPLE.hex()],
                             capture_output=True, text=True, env={'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('collides', bad.stderr)


if __name__ == '__main__':
    unittest.main()
