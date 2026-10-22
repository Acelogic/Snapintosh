#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acceptance/refusal tests for the guest/host boundary, without hardware."""
from dataclasses import replace
import hashlib
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from bootcontract import Framebuffer, HostRuntime, PhysicalRange, checked_ranges
from guestprofile import J700_26A428, get_profile
import xnuboot as xb
import run


class BootContractTests(unittest.TestCase):
    def test_queue_pointer_reproduces_and_rejects_live_fault(self):
        old_va = 0xfffffed0019ed3c0
        packed = (old_va >> 6) & 0xffffffff
        self.assertEqual(packed, 0x40067b4f)
        self.assertEqual(0xfffffe0000000000 | (packed << 6), 0xfffffe10019ed3c0)
        with self.assertRaisesRegex(ValueError, 'reconstructs'):
            J700_26A428.validate_queue_range(old_va, 64)
        J700_26A428.validate_queue_range(J700_26A428.early_heap_va, xb.VSPACE_WALK_SPAN)

    def test_queue_pointer_range_cannot_cross_its_encoding_limit(self):
        end = J700_26A428.queue_pointer_base + (1 << 38)
        J700_26A428.validate_queue_range(end - 64, 64)
        for base, size in ((end - 64, 65), (end, 64), (end - 63, 64),
                           (J700_26A428.early_heap_va, 1 << 40)):
            with self.subTest(base=base, size=size), self.assertRaises(ValueError):
                J700_26A428.validate_queue_range(base, size)

    def test_queue_pointer_format_is_profile_specific(self):
        narrow = replace(J700_26A428, queue_pointer_bits=24)
        with self.assertRaisesRegex(ValueError, 'reconstructs'):
            narrow.validate_queue_range(J700_26A428.early_heap_va, 64)
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            replace(J700_26A428, queue_pointer_base=J700_26A428.queue_pointer_base + 64).validate_queue_range(0, 64)

    def host_info(self):
        return dict(current_el=2, timer_hz=19200000,
                    heap_base=0x80000000, heap_size=0x4000000,
                    fb_base=0xf9a20000, fb_size=2880 * 1800 * 4,
                    fb_width=2880, fb_height=1800, fb_stride=2880, fb_format=1)

    def test_host_timer_is_live_not_chip_constant(self):
        info = self.host_info()
        for hz in (19200000, 24000000, 62500000):
            info['timer_hz'] = hz
            self.assertEqual(HostRuntime.from_q1n1(info).timer_hz, hz)

    def test_invalid_host_is_rejected(self):
        for changes in (dict(current_el=1), dict(timer_hz=0),
                        dict(heap_size=0x500000), dict(timer_hz=1 << 32)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                HostRuntime.from_q1n1(self.host_info() | changes)

    def test_monitor_arena_does_not_require_heap_storage(self):
        host = HostRuntime.from_q1n1(self.host_info() | dict(heap_size=0x501000))
        self.assertEqual(host.heap.size, 0x501000)

    def test_framebuffer_geometry_is_measured(self):
        host = HostRuntime.from_q1n1(self.host_info(), with_framebuffer=True)
        self.assertEqual(host.framebuffer.physical_range(),
                         PhysicalRange(0xf9a20000, 0x13c8000, 'panel'))
        self.assertEqual(host.framebuffer.stride, 2880 * 4)

    def test_invalid_framebuffer_is_rejected(self):
        for changes in (dict(fb_size=16), dict(fb_stride=10), dict(fb_base=0),
                        dict(fb_format=2), dict(fb_height=0),
                        dict(fb_base=0x80000000), dict(fb_base=1 << 36)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                HostRuntime.from_q1n1(self.host_info() | changes, with_framebuffer=True)

    def test_unaligned_pixel_base_includes_last_page(self):
        fb = Framebuffer(0x10003ffc, 1, 2, 4, 32)
        self.assertEqual(fb.physical_range(), PhysicalRange(0x10000000, 0x8000, 'panel'))

    def test_holes_do_not_become_owned_memory(self):
        ranges = [PhysicalRange(0x10000, 0x4000, 'RAM'),
                  PhysicalRange(0x20000, 0x4000, 'panel')]
        chunks, size = xb.build_framemap(0, 0x10000, 0x24000, 0xb, ranges)
        self.assertEqual(chunks[0][2::16], bytes([0xb, 0, 0, 0, 0xb]))
        self.assertEqual(size, 5 * 16)

    def test_malformed_frame_maps_are_refused(self):
        for low, high, kind in ((0, 1, 11), (0x4000, 0x4000, 11),
                                (0, 0x4000, 256)):
            with self.subTest(low=low, high=high, kind=kind), self.assertRaises(ValueError):
                xb.build_framemap(0, low, high, kind)

    def test_boot_arguments_are_not_silently_truncated(self):
        for line in ('x' * xb.BOOT_LINE_LENGTH, 'serial=2\0serial=3'):
            with self.subTest(line=line[:20]), self.assertRaises(ValueError):
                xb.boot_args(0, 0, 0, 0, 0, 0, line)

    def test_overlapping_and_out_of_range_resources_are_refused(self):
        ram = PhysicalRange(0x10000, 0x8000, 'RAM')
        for region in (PhysicalRange(0x14000, 0x4000, 'panel'),
                       PhysicalRange(1 << 36, 0x4000, 'panel'),
                       PhysicalRange(0x20001, 0x4000, 'panel')):
            with self.subTest(region=region), self.assertRaises(ValueError):
                checked_ranges([ram, region])

    def test_arbitrary_profile_name_is_not_a_fallback(self):
        with self.assertRaisesRegex(ValueError, 'unsupported guest profile'):
            get_profile('mac17j')
        self.assertIs(get_profile('j700ap-26A428'), J700_26A428)

    def test_hashes_follow_the_actual_selected_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = []
            for name, _ in J700_26A428.firmware:
                body = name.encode()
                (root / name).write_bytes(body)
                firmware.append((name, hashlib.sha256(body).hexdigest()))
            profile = replace(J700_26A428, firmware=tuple(firmware))
            self.assertEqual(profile.validate(profile.hashes(root)), [])
            alternate = root / 'other-kernelcache'
            alternate.write_bytes(b'a different binary')
            errors = profile.validate(profile.hashes(root, alternate))
            self.assertEqual(len(errors), 1)
            self.assertIn('kernelcache.release.mac17p: sha256', errors[0])

    def test_build_cannot_bypass_identity_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'kernelcache'
            path.write_bytes(b'not the audited kernel')
            with self.assertRaisesRegex(ValueError, 'firmware does not match'):
                xb.build(path)

    def test_firmware_directory_selection_is_consistent(self):
        try:
            xb.configure_guest(directory='/tmp/audited-bundle')
            self.assertEqual(xb.DEFAULT_KERNELCACHE.parent, xb.FIRMWARE_DIR)
            self.assertEqual(xb.DEFAULT_DEVICETREE.parent, xb.FIRMWARE_DIR)
            self.assertEqual(xb.MONITOR_IMAGES, J700_26A428.monitors)
            self.assertEqual(xb.XNU_VBAR, J700_26A428.vbar)
        finally:
            xb.configure_guest()

    def test_budget_rejects_panel_that_needs_unimplemented_map_table(self):
        old = xb.FRAMEBUFFER
        try:
            dt = xb.build_devicetree()
            xb.FRAMEBUFFER = (0xf9a20000, 2732, 1896, 2732 * 4, 32)
            demand, capacity = xb.early_mapping_budget(dt)
            self.assertLess(demand, capacity)
            self.assertEqual(capacity, 2048)
            xb.FRAMEBUFFER = (0xf9a20000, 4096, 4096, 4096 * 4, 32)
            with self.assertRaisesRegex(ValueError, 'before MAP_TABLE'):
                xb.early_mapping_budget(dt)
        finally:
            xb.FRAMEBUFFER = old

    def test_video_witness_distinguishes_mapping_from_acquisition(self):
        witness = J700_26A428.video_console
        fields = {witness.vinfo: 1800, witness.vinfo + 4: 2880,
                  witness.vinfo + 8: 32, witness.vinfo + 12: 11520,
                  witness.vinfo + 0x10: 0xfffffed000014000,
                  witness.vinfo + 0x40: 0xf9a20000,
                  witness.graphics_mode: 0, witness.acquired: 0}
        built = dict(video_console_witness=witness,
                     framebuffer=(0xf9a20000, 2880, 1800, 11520, 32))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            state = run.video_console_state(lambda va, n=8: fields[va], built)
        self.assertTrue(state['geometry_matches'])
        self.assertEqual(state['acquired'], 0)
        self.assertIn('has not acquired', output.getvalue())
        fields[witness.vinfo + 4] = 1920
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(run.video_console_state(lambda va, n=8: fields[va], built)['geometry_matches'])

    def test_video_witness_never_borrows_another_guests_addresses(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(run.video_console_state(
                lambda *args: self.fail('unprofiled guest memory was read'), {}))
            with self.assertRaisesRegex(RuntimeError, 'unmapped'):
                run.video_console_state(lambda *args: (_ for _ in ()).throw(RuntimeError('unmapped')),
                                        dict(video_console_witness=J700_26A428.video_console))


if __name__ == '__main__':
    unittest.main()
