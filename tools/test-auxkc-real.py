#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The two lead-verified kmutil collections through pin, loader and readback.

build/auxkc-20260925/aux-hello.kc and aux-adreno.kc were linked by
`sudo build/kmutil-auxkc.sh` (root-owned staging, -x, KDK). Nothing here
runs kmutil; the tests pin copies in a temporary directory.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import plistlib
import runpy
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'probes'), str(ROOT / 'tools')]
import auxkc
import auxkc_fixture as F
import bootfb
import xnuboot as xb

VERIFIED = ROOT / 'build/auxkc-20260925'
COLLECTIONS = {
    'aux-hello.kc': ('4d23b139739beb1a429f98e479f587ff665feafe92ae0b6b9829fd76a2644b08',
                     'org.snapintosh.driver.SnapHello', 'SnapHello.kext', 0x2c000),
    'aux-adreno.kc': ('7b6da7ddd4c5916e3affa85091f2b8690cd733488b77c4e1f8761fbe4005331c',
                      'org.snapintosh.driver.AdrenoX2', 'AdrenoX2.kext', 0x30000),
}
PLAIN = 'j700ap-26A428-xars-uniform-auxkc'
BOOTFB = 'j700ap-26A428-bootfb-auxkc'
BUILD = runpy.run_path(str(ROOT / 'build/build-auxkc.py'), run_name='build_auxkc')
BUNDLES = runpy.run_path(str(ROOT / 'tools/auxkc-bundles.py'), run_name='auxkc_bundles')
STATE = runpy.run_path(str(ROOT / 'tools/auxkc-state.py'))


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


@unittest.skipUnless(all((VERIFIED / n).is_file() for n in COLLECTIONS), 'verified collections absent')
class RealCollections(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()
        xb.configure_guest('j700ap-26A428-sep-preload')

    def copy(self, name):
        path = self.dir / name
        shutil.copyfile(VERIFIED / name, path)
        return path

    def place(self, profile):
        xb.configure_guest(profile)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        return xb.GUEST_PROFILE

    def test_pinned_hashes_and_bundle_checker(self):
        for name, (sha, bundle, kext, _) in COLLECTIONS.items():
            data = (VERIFIED / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
            self.assertEqual(BUNDLES['check'](data, BUNDLES['requested']([VERIFIED / kext])), [])
        other = VERIFIED / 'AdrenoX2.kext'
        problems = BUNDLES['check']((VERIFIED / 'aux-hello.kc').read_bytes(),
                                    BUNDLES['requested']([other]))
        self.assertIn('MISSING: org.snapintosh.driver.AdrenoX2', problems)
        self.assertIn('UNREQUESTED: org.snapintosh.driver.SnapHello', problems)

    def test_bundle_checker_accepts_a_codeless_bundle_without_fileset_entry(self):
        # The lead's entry_id check would call this MISSING.
        guest = self.place(BOOTFB)
        personality = bootfb.collection_personality(
            plistlib.loads(BUILD['BOOTFB_SOURCE'].read_bytes()), dedicated=guest.boot_framebuffer_nub)
        image = xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
        data = F.build(bootfb._prelink_info(image)['_PrelinkKCID'],
                       [F.code_info(), F.bootfb_info(personality)])
        generated = BUILD['stage'](self.dir / 'stage', guest)
        code = self.dir / 'Code.kext/Contents'
        code.mkdir(parents=True)
        (code / 'Info.plist').write_bytes(plistlib.dumps(F.code_info()))
        self.assertEqual(BUNDLES['check'](data, BUNDLES['requested']([generated, code.parent])), [])
        self.assertNotIn(bootfb.BUNDLE_ID, {e for e, _, _ in auxkc.Collection(data).entries})

    def test_stage_generates_the_profile_personality_and_the_sudo_line(self):
        guest = self.place(BOOTFB)
        kext = BUILD['stage'](self.dir / 'stage', guest)
        info = plistlib.loads((kext / 'Contents/Info.plist').read_bytes())
        self.assertNotIn('CFBundleExecutable', info)
        self.assertEqual(info['IOKitPersonalities']['SnapintoshBootFramebuffer'],
                         bootfb.collection_personality(
                             plistlib.loads(BUILD['BOOTFB_SOURCE'].read_bytes()), dedicated=True))
        command = BUILD['link_command'](self.dir / 'aux.kc', [kext, VERIFIED / 'SnapHello.kext'])
        self.assertEqual(command[:2], ['sudo', str(ROOT / 'build/kmutil-auxkc.sh')])
        self.assertIsNone(BUILD['stage'](self.dir / 'plain', self.place(PLAIN)))

    def test_build_script_never_runs_kmutil_itself(self):
        source = (ROOT / 'build/build-auxkc.py').read_text()
        self.assertNotIn("'kmutil'", source)
        self.assertNotIn('/usr/bin/kmutil', source)
        self.assertIn('kmutil-auxkc.sh', source)

    def test_pin_refusals(self):
        guest = self.place(PLAIN)
        path = self.copy('aux-hello.kc')
        with self.assertRaisesRegex(SystemExit, 'not the expected'):
            quiet(BUILD['pin'], path, guest, ['org.snapintosh.driver.SnapHello'], '0' * 64)
        with self.assertRaisesRegex(ValueError, 'differ from the pinned'):
            quiet(BUILD['pin'], path, guest, ['org.snapintosh.driver.AdrenoX2'])
        self.assertFalse(auxkc.manifest_path(path).exists())
        # The boot-framebuffer profile needs the codeless bundle inside.
        with self.assertRaisesRegex(ValueError, 'differ from the pinned'):
            quiet(BUILD['pin'], path, self.place(BOOTFB), ['org.snapintosh.driver.SnapHello'])
        self.assertFalse(auxkc.manifest_path(path).exists())

    def test_loader_places_maps_and_hands_off_each_collection(self):
        for name, (sha, bundle, _, top) in COLLECTIONS.items():
            with self.subTest(name):
                guest = self.place(PLAIN)
                path = self.copy(name)
                manifest = quiet(BUILD['pin'], path, guest, [bundle], sha)
                self.assertEqual((manifest['sha256'], manifest['bundles']), (sha, [bundle]))
                built = quiet(xb.build, xb.DEFAULT_KERNELCACHE, auxkc=path)
                image, tables, chunks = built['image'], built['tables'], built['chunks']
                base, (pa, span) = image.vmax, built['auxkc_range']
                self.assertEqual((pa, span), (xb.PHYS_BASE + xb.auxkc_offset(), top))
                self.assertEqual(built['auxkc_va_range'], (base, base + top))
                self.assertEqual(struct.unpack_from('<3Q', chunks[xb.HANDOFF_PA], 0x2d8),
                                 (base, base + 0x8000, base + top))
                data = path.read_bytes()
                for seg, va, vmsize, off, filesize, _, initprot in auxkc.Collection(data).segments:
                    self.assertEqual(chunks[pa + va], data[off:off + filesize].ljust(vmsize, b'\0'), seg)
                    for n in range(0, vmsize, 0x4000):
                        self.assertEqual(tables.walk(base + va + n), pa + va + n)
                # No reservation overlaps the collection, physically.
                for rname, off, rspan in xb.reservations():
                    if rname != 'aux collection':
                        lo = xb.PHYS_BASE + off
                        self.assertFalse(lo < pa + xb.AUXKC_SPAN and pa < lo + rspan, rname)
                self.assertGreaterEqual(built['alloc_low'], pa + xb.AUXKC_SPAN)
                # No boot framebuffer experiment: the tree is the plain one.
                self.assertEqual(xb.DEVICETREE_PA, xb.HANDOFF_PA + 0x10000)
                self.assertIsNone(built['dt'].get(bootfb.NUB_NODE, 'compatible'))
                self.assertIsNone(built['dt'].get(bootfb.NODE, 'AAPL,boot-display'))
                words = struct.unpack_from('<4Q', chunks[built['params_pa']], (xb.PARAMS_WORDS - 16 - 4) * 8)
                self.assertEqual(words, (base, base + top, pa, pa + top))
                self.assertIn(('auxkc end', 0x2e8, 8, 'measured'), xb.handoff_fields())

    def test_plain_profile_refuses_a_boot_framebuffer_collection(self):
        guest = self.place(PLAIN)
        image = xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
        personality = bootfb.collection_personality(
            plistlib.loads(BUILD['BOOTFB_SOURCE'].read_bytes()), dedicated=True)
        data = F.build(bootfb._prelink_info(image)['_PrelinkKCID'],
                       [F.code_info(), F.bootfb_info(personality)])
        path = self.dir / 'aux.kc'
        F.write(path, data, xb.PROFILE_FIRMWARE[guest.kernelcache], [F.CODE_BUNDLE, bootfb.BUNDLE_ID])
        with self.assertRaisesRegex(ValueError, 'no boot framebuffer experiment'):
            quiet(xb.build, xb.DEFAULT_KERNELCACHE, auxkc=path)

    def test_readback_after_native_slide_and_structor_signing(self):
        """What arm_auxkc_init leaves: every chain slot rebased (auth ones
        PAC-signed), load-command vmaddrs slid, then
        OSRuntimeSignStructorsInFileset re-signing the plain structor
        pointers kmutil emitted in __mod_init_func/__mod_term_func."""
        xb.configure_guest(PLAIN)
        image = xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
        data = (VERIFIED / 'aux-hello.kc').read_bytes()
        c = auxkc.Collection(data)
        base, pa = image.vmax, 0x8ca700000
        memory = bytearray(c.top)
        for _, va, vmsize, off, filesize, _, _ in c.segments:
            memory[va:va + vmsize] = data[off:off + filesize].ljust(vmsize, b'\0')

        def read(addr, size):
            self.assertTrue(pa <= addr and addr + size <= pa + c.top)
            return bytes(memory[addr - pa:addr - pa + size])

        def at(off):
            seg = next(s for s in c.segments if s[3] <= off < s[3] + s[4])
            return seg[1] + off - seg[3]
        structors = STATE['structor_slots'](c)
        self.assertEqual(len(structors), 2)
        rows = list(auxkc.chained_fixups(c, image))
        self.assertTrue(structors <= {off for off, _, _, _ in rows})
        for off, level, target, auth in rows:
            value = (image.vmin if level == 0 else base) + target
            if auth or off in structors:
                value ^= 0x5a << 48          # PAC bits above the 47-bit VA
            struct.pack_into('<Q', memory, at(off), value)
        pos = c.mh_vmaddr + 32
        for _ in range(struct.unpack_from('<I', data, 16)[0]):
            cmd, length = struct.unpack_from('<II', memory, pos)
            if cmd == 0x19:
                struct.pack_into('<Q', memory, pos + 24, struct.unpack_from('<Q', memory, pos + 24)[0] + base)
            pos += length
        result = STATE['resident'](read, c, base, pa, image.vmin, image.vmax)
        self.assertEqual((result['state'], result['fixups_raw'], result['fixups_rewritten'],
                          result['structors_resigned']), ('slid', 0, 0, 2))
        self.assertEqual(result['fixups_applied'], len(rows))


if __name__ == '__main__':
    unittest.main()
