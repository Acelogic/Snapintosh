#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tools/audit-device-exposure.py against the pinned tree; no hardware.

    python3 tools/test-device-exposure.py
"""
import json
import runpy
import tempfile
from collections import namedtuple
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
tool = runpy.run_path(str(ROOT / 'tools/audit-device-exposure.py'))
BUS = '/device-tree/arm-io/'
M = namedtuple('M', 'base span')


def capture(nubs):
    """A minimal stopped IOService plane: nub name -> driver classes."""
    entries = [{'address': '0x1', 'class_name': 'IORegistryEntry', 'name': 'Root'}]
    edges, n = [], 2
    for name, drivers in nubs.items():
        nub = hex(n); n += 1
        entries.append({'address': nub, 'class_name': 'AppleARMIODevice', 'name': name})
        edges.append(['0x1', nub])
        for cls in drivers:
            child = hex(n); n += 1
            entries.append({'address': child, 'class_name': cls, 'name': None})
            edges.append([nub, child])
    return {'ioreg_state': {'root': '0x1', 'entries': entries, 'edges': edges}}


class Exposure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dt = tool['build']('j700ap-26A428-bootfb-xars-uniform')
        cls.report = tool['audit'](cls.dt)
        cls.rows = {r['node']: r for r in cls.report['nodes']}

    def test_uncovered(self):
        gaps = tool['uncovered']
        self.assertEqual(gaps(0x1000, 0x1000, ()), [(0x1000, 0x1000)])
        self.assertEqual(gaps(0x1000, 0x1000, (M(0x1000, 0x1000),)), [])
        self.assertEqual(gaps(0x1000, 0x3000, (M(0x2000, 0x1000),)),
                         [(0x1000, 0x1000), (0x3000, 0x1000)])
        self.assertEqual(gaps(0x1000, 0x2000, (M(0, 0x1800), M(0x2800, 0x100))),
                         [(0x1800, 0x1000), (0x2900, 0x700)])

    def test_known_classification(self):
        rows = self.rows
        self.assertEqual(rows[BUS + 'i2c2']['state'], 'modeled')
        self.assertEqual(rows[BUS + 'i2c0']['state'], 'absent')
        self.assertEqual(rows[BUS + 'aic']['state'], 'modeled')
        self.assertEqual(rows[BUS + 'dockchannel-uart']['state'], 'console')
        self.assertEqual(rows[BUS + 'wdt']['state'], 'partial')
        self.assertEqual(rows[BUS + 'wdt']['unmodeled'], [['0x3082bc224', '0x4']])
        self.assertIn('43 I2C_EMPTY_V1', rows[BUS + 'i2c2']['models'])
        # Without a capture nothing can be called a latent stop.
        self.assertEqual(self.report['latent_stops'], [])
        self.assertTrue(all(r['drivers'] is None for r in self.report['nodes']))

    def test_deferred_nodes_are_not_rows(self):
        self.assertIn(BUS + 'sgx', self.report['deferred'])
        for node in self.report['deferred']:
            self.assertNotIn(node, self.rows)

    def test_registry_names_every_kind(self):
        kinds = {entry['kind']: entry['name'] for entry in self.report['registry']}
        self.assertEqual(sum(e['instances'] for e in self.report['registry']),
                         self.report['models'])
        self.assertNotIn('?', kinds.values())
        self.assertEqual(kinds[45], 'SEP_ASC_MAILBOX_V1')
        self.assertEqual(kinds[18], 'PMGR_ACTIVE_BOOT_V1')

    def test_latent_stops_need_a_driver_and_an_unbacked_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'waits.json'
            path.write_text(json.dumps(capture({
                'i2c0': ['AppleS5L8940XI2CController'],
                'i2c2': ['AppleS5L8940XI2CController'],
                'uart0': [],
                'wdt': ['AppleARMWatchdogTimer'],
                'dockchannel-uart': ['AppleSerialShim']})))
            attached = tool['drivers_from_capture'](path)
            report = tool['audit'](self.dt, attached)
            self.assertEqual(sorted(report['latent_stops']),
                             [BUS + 'i2c0', BUS + 'wdt'])
            empty = Path(tmp) / 'empty.json'
            empty.write_text(json.dumps({'threads': []}))
            with self.assertRaises(ValueError):
                tool['drivers_from_capture'](empty)

    def test_no_audio_profile_removes_audio_windows(self):
        dt = tool['build']('j700ap-26A428-bootfb-xars-uniform-no-audio')
        rows = {r['node'] for r in tool['audit'](dt)['nodes']}
        for gone in ('admac-base-ns', 'admac-leap-ns', 'admac-leap-s'):
            self.assertIn(BUS + gone, self.rows)
            self.assertNotIn(BUS + gone, rows)
        self.assertIn(BUS + 'i2c0', rows)


if __name__ == '__main__':
    unittest.main()
