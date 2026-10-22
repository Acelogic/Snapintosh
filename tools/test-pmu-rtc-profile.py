#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RTC admission and one-time UTC seed checks against the selected firmware."""
import contextlib
from dataclasses import replace
import io
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
from devicemodel import (device_model_words, seed_rtc_models, spmi_models,
                         SPMI_PMU_RTC_V1, PMU_RTC_LIMIT_US)


class RTCProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trees = []
        for profile in ('j700ap-26A428-bootfb-no-usb', 'j700ap-26A428-bootfb-rtc'):
            xb.configure_guest(profile)
            xb.place(0x8c0000000, guest_span=8192 << 20)
            with contextlib.redirect_stdout(io.StringIO()):
                cls.trees.append(xb.build_devicetree())
        cls.models = cls.trees[1].device_models
        cls.index, = [i for i, m in enumerate(cls.models) if m.kind == SPMI_PMU_RTC_V1]

    def test_single_model_change_and_identical_guest_tree(self):
        a, b = self.trees
        self.assertEqual(a.serialize(), b.serialize())
        self.assertEqual(len(a.device_models), 120)
        self.assertEqual([i for i, pair in enumerate(zip(a.device_models, b.device_models))
                          if pair[0] != pair[1]], [self.index])
        old, new = a.device_models[self.index], b.device_models[self.index]
        self.assertEqual((old.node, old.base, old.span, old.config[:3]),
                         (new.node, new.base, new.span, new.config[:3]))

    def test_seed_changes_only_epoch_word(self):
        before = device_model_words(self.models)
        for epoch in (1, 1790208000123456, PMU_RTC_LIMIT_US):
            with self.subTest(epoch=epoch):
                seeded = seed_rtc_models(self.models, epoch)
                after = device_model_words(seeded)
                changed = [i for i, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]
                self.assertEqual(len(changed), 1)
                self.assertEqual(after[changed[0]], epoch)
                self.assertEqual(self.models[self.index].config[3], 0)
                self.assertEqual(struct.unpack(f'<{len(after)}Q', struct.pack(f'<{len(after)}Q', *after)),
                                 tuple(after))
                with self.assertRaises(ValueError):
                    seed_rtc_models(seeded, epoch + 1)

    def test_invalid_seed_and_clock_count(self):
        for epoch in (0, -1, True, 1.5, '123', None, PMU_RTC_LIMIT_US + 1, 1 << 64):
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                seed_rtc_models(self.models, epoch)
        for models in ((), self.trees[0].device_models, self.models + (self.models[self.index],)):
            with self.assertRaises(ValueError):
                seed_rtc_models(models, 1790208000123456)
        model = self.models[self.index]
        for config in (model.config[:4] + (0,), (0x8000,) + model.config[1:]):
            altered = tuple(replace(m, config=config) if i == self.index else m
                            for i, m in enumerate(self.models))
            with self.assertRaises(ValueError):
                seed_rtc_models(altered, 1790208000123456)

    def test_firmware_drift_refused(self):
        dt = xb.DeviceTree(self.trees[1].serialize())
        spec = next(s for s in xb.GUEST_PROFILE.spmi_boot if s.rtc)
        windows = ((0x308714000, 0x4000), (0x308704000, 0x4000), (0x308700000, 0x4000))
        self.assertEqual(spmi_models(dt, spec, windows), (self.models[self.index],))
        pmu = spec.node + '/pmu-main'
        original = dt.get(pmu, 'info-rtc')
        dt.put(pmu, 'info-rtc', bytes(len(original)))
        with self.assertRaisesRegex(ValueError, 'PMU subtree'):
            spmi_models(dt, spec, windows)
        dt.put(pmu, 'info-rtc', original)
        with self.assertRaisesRegex(ValueError, 'must be boolean'):
            spmi_models(dt, replace(spec, rtc=1), windows)
        with self.assertRaises(ValueError):
            spmi_models(dt, spec, tuple((pa + 0x1000, size) for pa, size in windows))


if __name__ == '__main__':
    unittest.main()
