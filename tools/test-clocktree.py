#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Clock inventory binding and fail-before-mutation checks; no hardware."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'probes'))
from clocktree import CounterClockBootSpec, populate_counter_clock


class Tree:
    def __init__(self):
        self.props = {
            ('/io', 'compatible'): b'io,test\0',
            ('/io', 'clock-frequencies'): struct.pack('<6Q', 11, 22, 33, 44, 0, 66),
            ('/io/timer', 'compatible'): b'timer,test\0',
            ('/io/timer', 'clock-ids'): struct.pack('<2I', 1, 4),
            ('/cpus/cpu0', 'state'): b'running\0',
        }

    def get(self, node, key):
        return self.props.get((node, key))

    def put(self, node, key, value):
        self.props[node, key] = value


class ClockTreeTests(unittest.TestCase):
    spec = CounterClockBootSpec('/io', b'io,test', '/cpus/cpu0',
                                '/io/timer', b'timer,test', 1, 4)

    def test_frequency_binding_and_serialization(self):
        for hz in (19200000, 24000000, 100000000, 0xffffffff):
            tree = Tree()
            populate_counter_clock(tree, self.spec, hz)
            self.assertEqual(tree.get('/cpus/cpu0', 'fixed-frequency'), struct.pack('<I', hz))
            self.assertEqual(struct.unpack('<6Q', tree.get('/io', 'clock-frequencies')),
                             (11, 22, 33, 44, 0, 66))
            populate_counter_clock(tree, self.spec, hz)

    def test_invalid_binding_is_atomic(self):
        bad_specs = [replace(self.spec, **{field: value}) for field, value in (
            ('provider', '/wrong'), ('provider_compatible', b'io'),
            ('consumer_compatible', b'timer'), ('source_cpu', '/cpus/absent'),
            ('clock_id', 6), ('clock_id', -1), ('consumer_index', 0),
            ('consumer_index', 2), ('consumer_index', -1))]
        for spec in bad_specs:
            tree = Tree()
            before = tree.props.copy()
            with self.assertRaises(ValueError):
                populate_counter_clock(tree, spec, 19200000)
            self.assertEqual(tree.props, before)

    def test_malformed_and_conflicting_inputs(self):
        for key, value in ((('/cpus/cpu0', 'fixed-frequency'), b'\0' * 3),
                           (('/cpus/cpu0', 'state'), b'waiting\0'),
                           (('/io', 'clock-frequencies-nclk'), b''),
                           (('/io/timer', 'clock-ids'), b'\4'),
                           (('/io/timer', 'clock-ids'), struct.pack('<2I', 1, 5)),
                           (('/cpus/cpu0', 'fixed-frequency'), struct.pack('<Q', 24))):
            tree = Tree()
            tree.props[key] = value
            before = tree.props.copy()
            with self.assertRaises(ValueError):
                populate_counter_clock(tree, self.spec, 19200000)
            self.assertEqual(tree.props, before)
        for hz in (0, -1, 1 << 32, True, 19.2):
            with self.assertRaises(ValueError):
                populate_counter_clock(Tree(), self.spec, hz)


if __name__ == '__main__':
    unittest.main()
