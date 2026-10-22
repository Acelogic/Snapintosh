#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The no-audio profile withdraws exactly the audio graph and nothing else.

    python3 tools/test-no-audio-profile.py
"""
import contextlib
import io
import runpy
import struct
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
from deferred import defer_subtrees

BASE = 'j700ap-26A428-bootfb-xars-uniform'
NO_AUDIO = 'j700ap-26A428-bootfb-xars-uniform-no-audio'
AUDIO_ROOTS = ('/device-tree/arm-io/iop-audio-controller',
               '/device-tree/arm-io/iop-voicetrigger-controller',
               '/device-tree/arm-io/admac-base-ns',
               '/device-tree/arm-io/admac-leap-ns',
               '/device-tree/arm-io/admac-leap-s',
               '/device-tree/arm-io/admac-leap-s-rx-0-proxy',
               '/device-tree/arm-io/audio-shared-dart-proxy',
               '/device-tree/arm-io/audio-hp-mic-proxy',
               '/device-tree/arm-io/i2c0/audio-codec-output')


def tree(name, include_deferred=False):
    xb.configure_guest(name)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree(include_deferred=include_deferred)


def windows(dt, path):
    bus, name = path.rsplit('/', 1)
    try:
        return xb.device_windows(dt, name, bus)
    except (SystemExit, KeyError):
        return ()


class NoAudioProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tree(BASE)
        cls.quiet = tree(NO_AUDIO)
        cls.full = tree(BASE, include_deferred=True)

    def test_models_and_other_state_unchanged(self):
        self.assertEqual(self.base.device_models, self.quiet.device_models)
        extra = set(self.quiet.deferred_nodes) - set(self.base.deferred_nodes)
        self.assertTrue(set(self.base.deferred_nodes) <= set(self.quiet.deferred_nodes))
        self.assertEqual(set(self.base.nodes) - set(self.quiet.nodes), extra)
        for path, props in self.quiet.nodes.items():
            self.assertEqual({k: bytes(v.value) for k, v in props.items()},
                             {k: bytes(v.value) for k, v in self.base.nodes[path].items()}, path)

    def test_withdraws_whole_audio_graph_only(self):
        extra = set(self.quiet.deferred_nodes) - set(self.base.deferred_nodes)
        expected = {n for n in self.full.nodes
                    for root in AUDIO_ROOTS if n == root or n.startswith(root + '/')}
        self.assertEqual(extra, expected)
        self.assertEqual(len(extra), 40)
        # The bus and IOPs stay; only their audio clients go.
        for keep in ('/device-tree/arm-io/i2c0', '/device-tree/arm-io/aop',
                     '/device-tree/arm-io/sio', '/device-tree/arm-io/dart-aop',
                     '/device-tree/arm-io/dart-sio', '/device-tree/arm-io/dp-audio0',
                     '/device-tree/arm-io/dp-audio1', '/device-tree/arm-io/pmgr'):
            self.assertIn(keep, self.quiet.nodes)

    def test_no_model_answers_a_withdrawn_window_alone(self):
        # Every withdrawn register window was unbacked, except the shared AOP
        # timebase word, which the retained AOP/timesync owner still uses.
        timebase = [m for m in self.base.device_models if m.kind == 16]
        self.assertEqual(len(timebase), 1)
        for root in AUDIO_ROOTS:
            for pa, size in windows(self.full, root):
                owners = [m for m in self.base.device_models
                          if m.base < pa + size and pa < m.base + m.span]
                self.assertTrue(all(m.kind == 16 for m in owners), (root, hex(pa)))

    def test_no_retained_provider_reference_dangles(self):
        withdrawn = set()
        for node in set(self.quiet.deferred_nodes) - set(self.base.deferred_nodes):
            value = self.full.get(node, 'AAPL,phandle')
            if value is not None:
                withdrawn.add(bytes(value))
        self.assertTrue(withdrawn)
        for node, props in self.quiet.nodes.items():
            for name, prop in props.items():
                provider = (name.startswith('function-') or name.endswith('-parent') or
                            name.endswith('-phandle'))
                if provider:
                    self.assertNotIn(bytes(prop.value[:4]), withdrawn, (node, name))

    def test_hashes_bind_exact_subtrees(self):
        from guestprofile import get_profile
        profile = get_profile(NO_AUDIO)
        roots = [s.node for s in profile.deferred_subtrees]
        for root in AUDIO_ROOTS:
            self.assertEqual(roots.count(root), 1)
        dt = tree(BASE, include_deferred=True)
        codec = '/device-tree/arm-io/i2c0/audio-codec-output'
        dt.nodes[codec]['reg'].value = bytes(16)
        with self.assertRaises(ValueError):
            defer_subtrees(dt, profile.deferred_subtrees)

    def test_secondary_admission_accepts_profile(self):
        validate = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))['validate_guest_profile']
        validate(NO_AUDIO)
        with self.assertRaises(ValueError):
            validate(NO_AUDIO + '-unknown')


if __name__ == '__main__':
    unittest.main()
