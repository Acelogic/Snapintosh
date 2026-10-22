#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The -sks-quiet profile withdraws exactly the absent devices IOKit waits on.

Builds the real generated guest trees of the -sks board and its -quiet child
and checks: every root that held an IOConfigThread in the generation61 stop
(docs/IOKIT-QUIESCE-20260928.md) is gone or has its blocking declaration
withdrawn; so is the one device those waits used to hide (the PMU's battery-trap
monitor, whose driver panicked generations 64 and 65 once pmu-main's start
returned); nothing else changes except the one virtual display-subsystem entry;
no retained provider reference dangles; the hashes bind the exact subtrees.

    python3 tools/test-quiet-profile.py [--firmware DIR]
DIR defaults to ../Snapintosh/downloads/extracted/j700ap (read only).
"""
import argparse
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
from deferred import defer_subtrees

FIRMWARE = ROOT.parent / 'Snapintosh/downloads/extracted/j700ap'
BASE = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks'
QUIET = BASE + '-quiet'
A = '/device-tree/arm-io/'
SLOT = A + 'adreno-display'
# (withdrawn root, the driver start that waited in generation61)
WAITERS = (
    (A + 'aop', 'RTBuddy::_initRoutes, route 0x65'),
    (A + 'aop2', 'RTBuddy::_initRoutes, route 0x69'),
    (A + 'dcp', 'RTBuddy::_initRoutes, route 0xcf'),
    (A + 'dcp0-expert', 'AppleDCPExpert::start, RTBuddyService role DCP'),
    (A + 'disp0', 'UnifiedPipeline2::start, wait_for_dcp_expert'),
    (A + 'dp-audio0', 'IOAVAudioDMADelegate::start, sio-dma'),
    (A + 'dp-audio1', 'IOAVAudioDMADelegate::start, sio-dma'),
    (A + 'aop-spmi0', 'AppleStockholmControl::start, smc-pmu function-enable'),
    (A + 'i2c0/audio-codec-output', 'AppleEmbeddedAudio::start, AppleARMIISDevice'),
    (A + 'smctempsensor0', 'AppleSMCSensorDispatcher::start, AppleSMCEmbeddedResource'),
    (A + 'ave', 'AVE_HwC::Init, ApplePMGR state change'),
    (A + 'ave1', 'AppleAVE2Driver::start, AVE mutex'),
    ('/device-tree/buttons', 'AppleM68Buttons::handleStart, smc-pmu function-button_hold'),
    ('/device-tree/backlight', 'AppleARMBacklight::start, IONVRAM resource'),
)
PMU = A + 'nub-spmi0/pmu-main'   # AppleDialogSPMIPMU::start, smc-pmu function-external_standby
MTP = A + 'dockchannel-mtp/mtp-transport/multi-touch'
# Unblocking PMU also lets the SPMI controller publish its next child, btm. AppleBTM
# then started and ApplePPMCPMS's AppleBTM arrival handler (initial battery power
# setup, through ppm's function-btm-*) panicked in AppleCotaBTM::configSampling:
# "unable to config PMU" (generations 64 and 65). Before quiet, btm was never published.
BTM = A + 'nub-spmi0/btm'
PPM = A + 'pmgr/ppm'
PPM_BTM_FUNCTIONS = ('function-btm-config', 'function-btm-start', 'function-btm-stop',
                     'function-btm-vthr')
WITHDRAWN_FUNCTIONS = {(PMU, 'function-external_standby'), (MTP, 'function-afe-reset'),
                       (MTP, 'function-ipd-pwr-seq-control')} | {(PPM, n) for n in PPM_BTM_FUNCTIONS}
# Devices a boot needs, and the retained backing providers of withdrawn clients.
RETAINED = (PMU, A + 'nub-spmi0', A + 'sep', A + 'ans', A + 'sart-ans', A + 'adreno', A + 'dart-adreno',
            A + 'wdt', A + 'pmgr', PPM, A + 'aic', A + 'i2c0', A + 'dockchannel-mtp', A + 'smc-gpio',
            A + 'aop-gpio', A + 'dart-disp0', A + 'dart-dcp', A + 'dart-ave', A + 'dart-aop',
            '/device-tree/options')
DISPLAY_TYPES = (b'display-subsystem', b'ext-display-subsystem')


def tree(name, include_deferred=False):
    xb.configure_guest(name, FIRMWARE)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree(include_deferred=include_deferred)


def display_slots(dt):
    return [child for child in dt.children['/device-tree/arm-io']
            if dt.get(child, 'device_type') is not None and
            bytes(dt.get(child, 'device_type')).rstrip(b'\0') in DISPLAY_TYPES]


def provider(name):
    return (name.startswith('function-') or name.endswith('-parent') or name.endswith('-phandle') or
            name in ('msi-parent-controller', 'amfm-managed-port-control', 'usb-port'))


class QuietProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tree(BASE)
        cls.quiet = tree(QUIET)
        cls.full = tree(BASE, include_deferred=True)

    def test_every_waiting_start_is_withdrawn(self):
        for root, why in WAITERS:
            self.assertIn(root, self.base.nodes, why)
            self.assertNotIn(root, self.quiet.nodes, why)
        for node, name in WITHDRAWN_FUNCTIONS:
            self.assertIn(name, self.base.nodes[node])
            self.assertNotIn(name, self.quiet.nodes[node])

    def test_battery_trap_monitor_stays_unpublished(self):
        # The -sks board has btm beside pmu-main; quiet leaves pmu-main alone on the bus.
        self.assertEqual(self.base.children[A + 'nub-spmi0'], [PMU, BTM])
        self.assertEqual(self.quiet.children[A + 'nub-spmi0'], [PMU])
        self.assertEqual(bytes(self.base.nodes[BTM]['compatible'].value), b'btm,phone\0')
        # Every declaration naming btm goes with it; ppm keeps the rest, btm-enabled
        # included (CPMS only arms an AppleBTM arrival notification, as it did before).
        phandle = bytes(self.base.nodes[BTM]['AAPL,phandle'].value)
        named = {(n, k) for n, props in self.base.nodes.items() if n != BTM
                 for k, v in props.items() if k.startswith('function-') and bytes(v.value[:4]) == phandle}
        self.assertEqual(named, {(PPM, n) for n in PPM_BTM_FUNCTIONS})
        base = {k: bytes(v.value) for k, v in self.base.nodes[PPM].items() if k not in PPM_BTM_FUNCTIONS}
        self.assertEqual({k: bytes(v.value) for k, v in self.quiet.nodes[PPM].items()}, base)
        self.assertEqual(base['btm-enabled'], (1).to_bytes(4, 'little'))

    def test_needed_devices_are_retained(self):
        for keep in RETAINED:
            self.assertIn(keep, self.quiet.nodes, keep)
        # The PMU keeps every other property: RTC, fault and LPEM metadata.
        base = {k: bytes(v.value) for k, v in self.base.nodes[PMU].items()}
        del base['function-external_standby']
        self.assertEqual({k: bytes(v.value) for k, v in self.quiet.nodes[PMU].items()}, base)

    def test_exactly_one_display_slot_with_no_hardware(self):
        self.assertEqual(display_slots(self.base), [A + 'disp0'])
        self.assertEqual(display_slots(self.quiet), [SLOT])
        self.assertEqual(set(self.quiet.nodes[SLOT]), {'name', 'compatible', 'device_type'})
        self.assertEqual(self.quiet.children[SLOT], [])

    def test_only_withdrawals_and_the_slot_change(self):
        self.assertEqual(self.base.device_models, self.quiet.device_models)
        self.assertEqual(set(self.quiet.nodes) - set(self.base.nodes), {SLOT})
        self.assertEqual(set(self.base.nodes) - set(self.quiet.nodes),
                         set(self.quiet.deferred_nodes) - set(self.base.deferred_nodes))
        for path, props in self.quiet.nodes.items():
            if path == SLOT:
                continue
            want = {k: bytes(v.value) for k, v in self.base.nodes[path].items()
                    if (path, k) not in WITHDRAWN_FUNCTIONS}
            self.assertEqual({k: bytes(v.value) for k, v in props.items()}, want, path)

    def test_no_retained_provider_reference_dangles(self):
        withdrawn = {bytes(self.full.get(n, 'AAPL,phandle')) for n in self.quiet.deferred_nodes
                     if self.full.get(n, 'AAPL,phandle') is not None}
        self.assertTrue(withdrawn)
        for node, props in self.quiet.nodes.items():
            for name, prop in props.items():
                if provider(name):
                    self.assertNotIn(bytes(prop.value[:4]), withdrawn, (node, name))

    def test_hashes_bind_exact_subtrees(self):
        from guestprofile import get_profile
        profile, base = get_profile(QUIET), get_profile(BASE)
        self.assertEqual(profile.deferred_subtrees[:len(base.deferred_subtrees)], base.deferred_subtrees)
        for spec in profile.deferred_subtrees[len(base.deferred_subtrees):]:
            self.assertEqual(hashlib.sha256(self.full.serialize(spec.node)).hexdigest(), spec.sha256,
                             spec.node)
        dt = tree(BASE, include_deferred=True)
        reg = dt.nodes[A + 'ave1']['reg']
        reg.value = bytes(len(reg.value))
        with self.assertRaises(ValueError):
            defer_subtrees(dt, profile.deferred_subtrees, profile.deferred_functions)

    def test_inherits_the_sks_board(self):
        from dataclasses import fields, replace
        from guestprofile import get_profile
        profile, base = get_profile(QUIET), get_profile(BASE)
        differ = {f.name for f in fields(profile) if getattr(profile, f.name) != getattr(base, f.name)}
        self.assertEqual(differ, {'name', 'adreno', 'deferred_subtrees', 'deferred_functions'})
        self.assertEqual(profile.adreno, replace(base.adreno, display_slot=True))
        self.assertEqual(profile.adreno.flags(), base.adreno.flags())


if __name__ == '__main__':
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--firmware', type=Path)
    known, rest = ap.parse_known_args()
    if known.firmware:
        FIRMWARE = known.firmware
    unittest.main(argv=[sys.argv[0]] + rest)
