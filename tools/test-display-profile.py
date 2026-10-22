#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The display profile leaves exactly one IOMobileFramebuffer slot: AdrenoDisplay's.

Builds the real generated guest device trees of the Stage 7 (adreno-metal) profile
and of its -display child, and checks what IOMobileFramebuffer.framework (26A428)
will count: the /arm-io children whose device_type is display-subsystem or
ext-display-subsystem (iomfb_populate_all_display_infos), plus AppleParavirtGPU
ports only when a child is compatible "paravirtualizedgraphics,gpu".

    python3 tools/test-display-profile.py [--firmware DIR]
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
BASE = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal'
DISPLAY = BASE + '-display'
WITHDRAWN = ('/device-tree/arm-io/dispext0', '/device-tree/arm-io/dcpext',
             '/device-tree/arm-io/dcpext-expert')
RETAINED = ('/device-tree/arm-io/disp0', '/device-tree/arm-io/dcp', '/device-tree/arm-io/dcp0-expert',
            '/device-tree/arm-io/dart-disp0', '/device-tree/arm-io/display-crossbar0',
            '/device-tree/arm-io/exdisplaypipe')


def tree(name, include_deferred=False):
    xb.configure_guest(name, FIRMWARE)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree(include_deferred=include_deferred)


def framebuffer_slots(dt):
    """The framework's reference count of display instances for this tree."""
    slots, paravirt = [], []
    for child in dt.children['/device-tree/arm-io']:
        kind = dt.get(child, 'device_type')
        if kind is not None and bytes(kind).rstrip(b'\0') in (b'display-subsystem', b'ext-display-subsystem'):
            slots.append(child)
        compatible = dt.get(child, 'compatible')
        if compatible is not None and b'paravirtualizedgraphics,gpu' in bytes(compatible).split(b'\0'):
            paravirt.append(child)
    return slots, paravirt


class DisplayProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tree(BASE)
        cls.display = tree(DISPLAY)
        cls.full = tree(BASE, include_deferred=True)

    def test_exactly_one_framebuffer_slot(self):
        self.assertEqual(framebuffer_slots(self.base), (['/device-tree/arm-io/disp0',
                                                         '/device-tree/arm-io/dispext0'], []))
        # One slot, filled by AdrenoDisplay; zero slots would stop the framework enumerating.
        self.assertEqual(framebuffer_slots(self.display), (['/device-tree/arm-io/disp0'], []))

    def test_withdraws_external_display_graph_only(self):
        extra = set(self.display.deferred_nodes) - set(self.base.deferred_nodes)
        expected = {n for n in self.full.nodes for root in WITHDRAWN if n == root or n.startswith(root + '/')}
        self.assertEqual(extra, expected)
        self.assertEqual(set(self.base.nodes) - set(self.display.nodes), extra)
        for keep in RETAINED:
            self.assertIn(keep, self.display.nodes)

    def test_everything_else_unchanged(self):
        self.assertEqual(self.base.device_models, self.display.device_models)
        for path, props in self.display.nodes.items():
            self.assertEqual({k: bytes(v.value) for k, v in props.items()},
                             {k: bytes(v.value) for k, v in self.base.nodes[path].items()}, path)

    def test_no_retained_provider_reference_dangles(self):
        withdrawn = set()
        for node in set(self.display.deferred_nodes) - set(self.base.deferred_nodes):
            value = self.full.get(node, 'AAPL,phandle')
            if value is not None:
                withdrawn.add(bytes(value))
        self.assertTrue(withdrawn)
        for node, props in self.display.nodes.items():
            for name, prop in props.items():
                if name.startswith('function-') or name.endswith('-parent') or name.endswith('-phandle'):
                    self.assertNotIn(bytes(prop.value[:4]), withdrawn, (node, name))

    def test_hashes_bind_exact_subtrees(self):
        from guestprofile import get_profile
        profile = get_profile(DISPLAY)
        base = get_profile(BASE)
        self.assertEqual(profile.deferred_subtrees[:len(base.deferred_subtrees)], base.deferred_subtrees)
        added = profile.deferred_subtrees[len(base.deferred_subtrees):]
        self.assertEqual(tuple(s.node for s in added), WITHDRAWN)
        dt = tree(BASE, include_deferred=True)
        for spec in added:
            self.assertEqual(hashlib.sha256(dt.serialize(spec.node)).hexdigest(), spec.sha256)
        dt.nodes['/device-tree/arm-io/dcpext']['reg'].value = bytes(len(dt.nodes['/device-tree/arm-io/dcpext']['reg'].value))
        with self.assertRaises(ValueError):
            defer_subtrees(dt, profile.deferred_subtrees)

    def test_inherits_the_stage7_board(self):
        from dataclasses import fields
        from guestprofile import get_profile
        profile, base = get_profile(DISPLAY), get_profile(BASE)
        differ = {f.name for f in fields(profile) if getattr(profile, f.name) != getattr(base, f.name)}
        self.assertEqual(differ, {'name', 'deferred_subtrees'})


if __name__ == '__main__':
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--firmware', type=Path)
    known, rest = ap.parse_known_args()
    if known.firmware:
        FIRMWARE = known.firmware
    unittest.main(argv=[sys.argv[0]] + rest)
