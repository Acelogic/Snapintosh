#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Linked (kmutil) AuxKC: admission, placement, handoff, audit readback."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import plistlib
import runpy
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

PROFILE = 'j700ap-26A428-bootfb-auxkc'
BASE_PROFILE = 'j700ap-26A428-bootfb-xars-uniform'
KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
LEAD_AUXKC = ROOT / 'build/auxkc-hello-20260925/aux.kc'
STATE = runpy.run_path(str(ROOT / 'tools/auxkc-state.py'))
from monitor_layout import MonitorLayout  # noqa: E402
LAYOUT = MonitorLayout()


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def leaf(tables, va):
    offset = va & ((1 << (64 - xb.T1SZ)) - 1)
    return tables.read(tables._descend(offset), xb.index(3, offset))


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xb.configure_guest(PROFILE)
        cls.image = xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
        cls.primary = bootfb._prelink_info(cls.image)
        info = plistlib.loads((ROOT / 'drivers/boot-framebuffer/SnapintoshBootFramebuffer.kext/'
                               'Contents/Info.plist').read_bytes())
        cls.info = info
        cls.personality = bootfb.collection_personality(info, dedicated=True)
        cls.bundles = [F.CODE_BUNDLE, bootfb.BUNDLE_ID]

    def make(self, **kwargs):
        infos = kwargs.pop('infos', None) or [F.code_info(), F.bootfb_info(self.personality)]
        return F.build(self.primary['_PrelinkKCID'], infos, **kwargs)

    def admit(self, data, bundles=None, personality='default'):
        return auxkc.admit(auxkc.Collection(data), self.image, self.primary,
                           bundles or self.bundles,
                           self.personality if personality == 'default' else personality)


class FormatTests(Fixture):
    def test_fixture_admits_with_native_geometry(self):
        result = self.admit(self.make())
        self.assertEqual(result['executables'], [F.CODE_BUNDLE])
        self.assertEqual(result['fixups'], dict(primary=1, auxiliary=1, authenticated=1))
        self.assertEqual((result['top'], result['mh_vmaddr']), ('0x14000', '0x8000'))

    def test_native_assert_emulation(self):
        c = auxkc.Collection(self.make())
        ranges = auxkc.layout_checks(c)
        self.assertEqual((ranges['highest_ro'], ranges['highest_nle'], ranges['lowest_rx']),
                         (0x14000, 0x10000, 0xc000))
        # A writable segment above LINKEDIT breaks HIGHESTRO == HIGHESTNLE.
        c.segments = c.segments + [('__LATE', 0x14000, 0x4000, 0x14000, 0, 3, 3)]
        with self.assertRaisesRegex(ValueError, 'HIGHESTRO'):
            auxkc.layout_checks(c)

    def test_rejects_unsupported_geometry(self):
        def shift_lowest(data):          # __PRELINK_INFO vmaddr 0 -> 0x40000
            pos = bytes(data).index(b'__PRELINK_INFO\0\0') + 16
            struct.pack_into('<Q', data, pos, 0x40000)
        def writable_text(data):
            pos = bytes(data).index(b'__TEXT_EXEC\0') + 16
            struct.pack_into('<ii', data, pos + 32, 7, 7)
        def overlap(data):
            pos = bytes(data).index(b'__DATA\0\0') + 16
            struct.pack_into('<Q', data, pos, 0x8000)
        for mutate, message in ((shift_lowest, 'lowest vmaddr'), (writable_text, 'writable and exec'),
                                (overlap, 'overlap')):
            with self.subTest(message), self.assertRaisesRegex(ValueError, message):
                auxkc.Collection(self.make(mutate=mutate))
        with self.assertRaisesRegex(ValueError, 'MH_FILESET'):
            auxkc.Collection(self.make(mutate=lambda d: struct.pack_into('<I', d, 12, 11)))

    def test_rejects_chains_the_native_walker_would_abandon(self):
        for kwargs, message in ((dict(levels=(1, 3)), 'absent cache level'),
                                (dict(levels=(0, 2)), 'absent cache level'),
                                (dict(primary_target=0x3fffffff), 'outside the BootKC'),
                                (dict(multi=True), 'multi-start'),
                                (dict(fmt=7), 'kernel-cache format')):
            with self.subTest(**kwargs), self.assertRaisesRegex(ValueError, message):
                self.admit(self.make(**kwargs))

    def test_fixups_may_not_land_in_text(self):
        def into_text(data):
            pos = 0x10000 + 0x20 + 0x20 + 8   # starts_in_segment.segment_offset
            struct.pack_into('<Q', data, pos, 0xc000 - F.MH)
            data[0xc000:0xc008] = struct.pack('<Q', F.fixup(0x1000, 0))
        with self.assertRaisesRegex(ValueError, '__TEXT_EXEC'):
            self.admit(self.make(mutate=into_text))

    def test_bundle_list_identity_and_personality_are_exact(self):
        data = self.make()
        with self.assertRaisesRegex(ValueError, 'differ from the pinned'):
            self.admit(data, bundles=[bootfb.BUNDLE_ID])
        with self.assertRaisesRegex(ValueError, 'differ from the pinned'):
            self.admit(data, bundles=self.bundles + ['com.apple.driver.AppleCentauriManager'])
        other = copy.deepcopy(self.personality)
        other['IONameMatch'] = bootfb.MATCH
        with self.assertRaisesRegex(ValueError, 'personality differs'):
            self.admit(data, personality=other)
        extra = F.bootfb_info(self.personality)
        extra['IOKitPersonalities']['SnapintoshBootFramebuffer']['IOProbeScore'] = 1
        with self.assertRaisesRegex(ValueError, 'personality differs'):
            self.admit(self.make(infos=[F.code_info(), extra]))
        with self.assertRaisesRegex(ValueError, 'boot framebuffer'):
            self.admit(self.make(infos=[F.code_info()]), bundles=[F.CODE_BUNDLE])
        codeless = F.code_info()
        del codeless['CFBundleExecutable']
        with self.assertRaisesRegex(ValueError, 'fileset entries'):
            self.admit(self.make(infos=[codeless, F.bootfb_info(self.personality)]))
        wrong_boot = F.build(bytes(16), [F.code_info(), F.bootfb_info(self.personality)])
        with self.assertRaisesRegex(ValueError, 'pinned BootKC'):
            self.admit(wrong_boot)

    def test_symbols_name_the_code_kexts_vtables(self):
        self.assertEqual(auxkc.symbols(auxkc.Collection(self.make())), [(F.VTABLE, '__ZTV14SnapFixtureCode')])

    def test_handoff_words_cover_both_collections(self):
        c = auxkc.Collection(self.make())
        base = self.image.vmax
        self.assertEqual(auxkc.handoff_values(c, base, self.image.vmax),
                         (base, base + 0x8000, base + 0x14000))
        with self.assertRaises(ValueError):
            auxkc.handoff_values(c, base + 8, self.image.vmax)

    @unittest.skipUnless(LEAD_AUXKC.is_file(), 'lead kmutil output not present')
    def test_real_kmutil_output_parses_and_is_refused_for_its_contents(self):
        # The first kmutil attempt rejected SnapHello (ownership) and linked
        # 16 host kexts instead. The parser must read it; admission must not.
        c = auxkc.Collection(LEAD_AUXKC.read_bytes())
        bundles = [k['CFBundleIdentifier'] for k in c.prelink_info()['_PrelinkInfoDictionary']]
        self.assertNotIn('org.snapintosh.driver.SnapHello', bundles)
        self.assertIn('com.apple.driver.AppleCentauriManager', bundles)
        result = auxkc.admit(c, self.image, self.primary, bundles)
        self.assertEqual(result['fixups'], dict(primary=1176, auxiliary=142, authenticated=1221))
        self.assertEqual((result['top'], result['mh_vmaddr']), ('0x68000', '0x14000'))
        with self.assertRaisesRegex(ValueError, 'boot framebuffer'):
            auxkc.admit(c, self.image, self.primary, bundles, self.personality)
        with self.assertRaisesRegex(ValueError, 'differ from the pinned'):
            auxkc.admit(c, self.image, self.primary,
                        ['org.snapintosh.driver.SnapHello', bootfb.BUNDLE_ID], self.personality)


class LoaderTests(Fixture):
    def setUp(self):
        xb.configure_guest(PROFILE)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'aux.kc'
        self.data = self.make()
        F.write(self.path, self.data, KERNEL_SHA, self.bundles)

    def tearDown(self):
        self.temp.cleanup()
        xb.configure_guest('j700ap-26A428-sep-preload')

    def build(self, **kwargs):
        return quiet(xb.build, xb.DEFAULT_KERNELCACHE, **kwargs)

    def test_profile_requires_a_pinned_collection(self):
        with self.assertRaisesRegex(ValueError, 'requires --auxkc'):
            self.build()
        manifest = json.loads(auxkc.manifest_path(self.path).read_text())
        self.path.write_bytes(self.data[:-1] + b'\1')
        with self.assertRaisesRegex(ValueError, 'pinned sha256'):
            self.build(auxkc=self.path)
        self.path.write_bytes(self.data)
        for key, value, message in (('kernel_sha256', '0' * 64, 'different kernelcache'),
                                    ('bundles', [bootfb.BUNDLE_ID], 'differ from the pinned'),
                                    ('format', 'other', 'unknown format')):
            bad = dict(manifest, **{key: value})
            auxkc.manifest_path(self.path).write_text(json.dumps(bad))
            with self.subTest(key), self.assertRaisesRegex(ValueError, message):
                self.build(auxkc=self.path)
        xb.configure_guest(BASE_PROFILE)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        with self.assertRaisesRegex(ValueError, 'does not take a linked AuxKC'):
            self.build(auxkc=self.path)

    def test_placement_mapping_and_handoff(self):
        built = self.build(auxkc=self.path)
        image, tables, chunks = built['image'], built['tables'], built['chunks']
        pa, span = built['auxkc_range']
        self.assertEqual((pa, span), (xb.PHYS_BASE + xb.auxkc_offset(), 0x14000))
        self.assertIn(('aux collection', xb.auxkc_offset(), xb.AUXKC_SPAN), xb.reservations())
        xb.validate_layout()
        self.assertGreaterEqual(built['alloc_low'], pa + xb.AUXKC_SPAN)
        base = image.vmax
        self.assertEqual(built['auxkc_va_range'], (base, base + span))
        self.assertEqual(struct.unpack_from('<3Q', chunks[xb.HANDOFF_PA], 0x2d8),
                         (base, base + 0x8000, base + 0x14000))
        c = auxkc.Collection(self.data)
        for name, va, vmsize, off, filesize, _, initprot in c.segments:
            for n in range(0, vmsize, 0x4000):
                self.assertEqual(tables.walk(base + va + n), pa + va + n)
                pte = leaf(tables, base + va + n)
                executable = bool(initprot & 4)
                self.assertEqual(not pte & (1 << 53), executable, name)
                self.assertEqual(bool(pte & (1 << 54)), not executable, name)
                self.assertEqual(pte & (3 << 6), 0, name)   # EL1 RW for the native slide
            # Bytes exactly as kmutil wrote them: no fixup applied here.
            self.assertEqual(chunks[pa + va], self.data[off:off + filesize].ljust(vmsize, b'\0'))
        # Nothing below the handoff's codeless slot and the tree did not move.
        self.assertNotIn(xb.HANDOFF_PA + bootfb.OFFSET, chunks)
        self.assertEqual(xb.DEVICETREE_PA, xb.HANDOFF_PA + bootfb.DT_OFFSET)
        # struct params' auxkc field, wherever later fields (gpu, txm_native,
        # early_stop) put it: from the monitor's own layout, not a count from the end.
        words = struct.unpack_from('<4Q', chunks[built['params_pa']], LAYOUT.offset('params', 'auxkc'))
        self.assertEqual(words, (base, base + span, pa, pa + span))
        tree = built['dt']
        self.assertEqual(tree.get(bootfb.NUB_NODE, 'compatible'), bootfb.NUB_MATCH.encode() + b'\0')
        self.assertIsNone(tree.get(bootfb.NODE, 'AAPL,boot-display'))
        self.assertIsNone(tree.get(xb.LOCAL_POLICY_NODE, 'lp-sip0'))
        self.assertEqual(built['auxkc']['sha256'], hashlib.sha256(self.data).hexdigest())

    def test_existing_profile_keeps_codeless_layout(self):
        xb.configure_guest(BASE_PROFILE)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        self.assertFalse(any(name == 'aux collection' for name, _, _ in xb.reservations()))
        built = self.build()
        self.assertEqual(built['auxkc_range'], (xb.HANDOFF_PA + bootfb.OFFSET, bootfb.SPAN))
        self.assertIsNone(built['auxkc_va_range'])
        words = struct.unpack_from('<4Q', built['chunks'][built['params_pa']], (xb.PARAMS_WORDS - 16 - 4) * 8)
        self.assertEqual(words, (0, 0, 0, 0))
        self.assertEqual(struct.unpack_from('<3Q', built['chunks'][xb.HANDOFF_PA], 0x2d8),
                         bootfb.handoff_values(built['image'].vmin - xb.HANDOFF_SPAN, built['image'].vmax))

    def test_resident_readback_before_and_after_the_native_slide(self):
        built = self.build(auxkc=self.path)
        pa, span = built['auxkc_range']
        base = built['image'].vmax
        memory = bytearray(span)
        c = auxkc.Collection(self.data)
        for name, va, vmsize, off, filesize, _, _ in c.segments:
            memory[va:va + vmsize] = self.data[off:off + filesize].ljust(vmsize, b'\0')

        def read(addr, size):
            self.assertTrue(pa <= addr and addr + size <= pa + span)
            return bytes(memory[addr - pa:addr - pa + size])
        vmin, vmax = built['image'].vmin, built['image'].vmax
        result = STATE['resident'](read, c, base, pa, vmin, vmax)
        self.assertEqual((result['state'], result['fixups_raw'], result['fixups_applied']), ('unslid', 2, 0))
        # What arm_auxkc_init does: rebase (PAC bits in the top), slide vmaddrs.
        struct.pack_into('<Q', memory, 0x4000, vmin + 0x1000)
        struct.pack_into('<Q', memory, 0x4008, (base + 0xc000) ^ (0x5a << 48))
        header = 0x8000
        pos = header + 32
        for _ in range(struct.unpack_from('<I', memory, header + 16)[0]):
            cmd, length = struct.unpack_from('<II', memory, pos)
            if cmd == 0x19:
                struct.pack_into('<Q', memory, pos + 24, struct.unpack_from('<Q', memory, pos + 24)[0] + base)
            pos += length
        result = STATE['resident'](read, c, base, pa, vmin, vmax)
        self.assertEqual((result['state'], result['fixups_applied'], result['header_segments_slid']),
                         ('slid', 2, 5))
        # A kext storing to an initialized pointer after the slide is
        # reported, not fatal: the stopped-state audit must finish.
        struct.pack_into('<Q', memory, 0x4000, vmin + 0x2000)
        result = STATE['resident'](read, c, base, pa, vmin, vmax)
        self.assertEqual((result['state'], result['fixups_rewritten']), ('slid', 1))
        self.assertEqual(result['rewritten_examples'][0]['file_offset'], hex(0x8000))
        struct.pack_into('<Q', memory, 0x4000, vmin + 0x1000)
        memory[0xc010] ^= 1
        with self.assertRaisesRegex(ValueError, '__TEXT_EXEC'):
            STATE['resident'](read, c, base, pa, vmin, vmax)


class CounterTests(unittest.TestCase):
    API = runpy.run_path(str(ROOT / 'tools/auxkc_counters.py'))

    def raw(self, **values):
        return struct.pack('<13Q', *(values.get(f, 0) for f in self.API['FIELDS']))

    def test_decode_and_consistency(self):
        va, pa = (0xfffffe000e358000, 0xfffffe000e36c000), (0x8ced00000, 0x8ced14000)
        result = self.API['decode'](self.raw(map_pages=3, map_exec_gained=1, retypes=1,
                                             last_kind=1, last_va=va[0] + 0xc000, last_new=0x40b,
                                             last_retype_pa=pa[0], last_retype_types=(0xb << 32) | 0x10),
                                    va, pa)
        self.assertEqual((result['exec_gained'], result['last_exec']['kind'],
                          result['last_retype']['new_type']), (1, 'MAP_PAGE', 0x10))
        for bad in (dict(map_exec_gained=1), dict(last_kind=1), dict(retype_failed=1),
                    dict(map_pages=1, map_exec_gained=1, last_kind=1, last_va=1),
                    dict(retypes=1, last_retype_pa=1), dict(last_kind=7)):
            with self.subTest(bad), self.assertRaises(ValueError):
                self.API['decode'](self.raw(**bad), va, pa)

    def test_field_order_matches_the_monitor_header(self):
        header = (ROOT / 'compat/auxkc-observe.h').read_text()
        body = header[header.index('struct auxkc_exec_state {'):]
        body = body[:body.index('};')]
        import re
        names = [n for line in body.splitlines()[1:]
                 for n in re.findall(r'\b(\w+)\s*[,;]', line.split('/*')[0])]
        self.assertEqual(tuple(names), self.API['FIELDS'])

    def test_unused_range_reads_as_absent(self):
        layout = ' auxkc_exec\n auxkc\n'
        self.assertIsNone(self.API['read_context'](None, 0, None, layout, lambda n: (0, 0, 0, 0)))
        self.assertIsNone(self.API['read_context'](None, 0, None, '', lambda n: (1, 2, 3, 4)))
        with self.assertRaises(ValueError):
            self.API['read_context'](None, 0, None, layout, lambda n: (0, 0, 1, 0))


if __name__ == '__main__':
    unittest.main()
