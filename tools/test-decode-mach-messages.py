#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Saved-call admission and packed-argument regression tests; no hardware."""

import copy
from pathlib import Path
import runpy
import unittest

m = runpy.run_path(str(Path(__file__).with_name('decode-mach-messages.py')))


class MachMessages(unittest.TestCase):
    def setUp(self):
        # Captured pmset PID75/TID969 in bootfb-match-live-20260923.
        self.state = dict(pc='0x190ca8c20', cpsr='0x80000000', esr='0x56000080',
                          registers=dict(zip(map(str, range(8)), [
                              '0x16f4b1728', '0x400000001', '0x3880130013',
                              '0xc03', '0x7600001e0f', '0x1', '0x0', '0x0'])))
        self.state['registers']['16'] = '0xffffffffffffffd1'
        self.pc = int(self.state['pc'], 0)

    def test_recorded_send(self):
        d = m['decode_state'](self.state, self.pc)
        self.assertEqual((d['message_id'], d['send_size'], d['descriptor_count']), (118, 56, 1))
        self.assertEqual((d['remote_port'], d['local_port'], d['voucher_port']), ('0xc03', '0x0', '0x1e0f'))
        self.assertEqual(d['destination_policy'], 'message_queue')
        self.assertTrue(d['send'] and d['complex'])
        self.assertFalse(d['receive'] or d['vector'] or d['send_timeout_enabled'])

    def test_other_pc_not_attributed(self):
        self.assertIsNone(m['decode_state'](self.state, self.pc + 4))

    def test_abi_mutations_refused(self):
        for key, value in [('cpsr', '0x5'), ('esr', '0x92000007')]:
            changed = copy.deepcopy(self.state); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m['decode_state'](changed, self.pc)
        for reg, value in [('16', '0x3'), ('2', '-1'), ('4', '0x10000000000000000')]:
            changed = copy.deepcopy(self.state); changed['registers'][reg] = value
            with self.subTest(reg=reg), self.assertRaises(ValueError):
                m['decode_state'](changed, self.pc)

    def test_receive_only_has_no_send_identity(self):
        self.state['registers']['1'] = '0x40700420e'
        d = m['decode_state'](self.state, self.pc)
        self.assertTrue(d['receive']); self.assertFalse(d['send'])
        self.assertNotIn('message_id', d)
        self.assertNotIn('remote_port', d)

    def test_vector_counts_not_bytes(self):
        self.state['registers']['1'] = '0x500000001'
        d = m['decode_state'](self.state, self.pc)
        self.assertTrue(d['vector'])
        self.assertNotIn('send_size', d)
        self.assertEqual(d['send_vector_count'], 56)

    def test_signed_message_id(self):
        self.state['registers']['4'] = '0xffffffff00001e0f'
        self.assertEqual(m['decode_state'](self.state, self.pc)['message_id'], -1)

    def test_unused_descriptor_count_and_mixed_policy(self):
        self.state['registers']['2'] = '0x3800130013'
        self.state['registers']['1'] = '0x600000001'
        d = m['decode_state'](self.state, self.pc)
        self.assertNotIn('descriptor_count', d)
        self.assertEqual(d['destination_policy'], 'other')

    def test_cross_run_and_unqualified_witness_refused(self):
        p = Path('/tmp/run-kernel-waits.json'); s = Path('/tmp/run-cpu0-stop.json')
        capture = dict(monitor_sha256='a' * 64)
        snapshot = dict(monitor_sha256='a' * 64, user_mapping_qualified=True, pstate='0x0')
        m['validate_pair'](p, s, capture, snapshot)
        for changed in [dict(snapshot, monitor_sha256='b' * 64),
                        dict(snapshot, user_mapping_qualified=False),
                        dict(snapshot, pstate='0x5')]:
            with self.assertRaises(ValueError):
                m['validate_pair'](p, s, capture, changed)
        for other in [Path('/tmp/old-cpu0-stop.json'), Path('/tmp/other/run-cpu0-stop.json')]:
            with self.assertRaises(ValueError):
                m['validate_pair'](p, other, capture, snapshot)


if __name__ == '__main__':
    unittest.main()
