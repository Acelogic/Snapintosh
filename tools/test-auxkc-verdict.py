#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tools/auxkc-verdict.py on synthetic stopped-state JSON, plus the run scripts compile."""
import copy
from pathlib import Path
import py_compile
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
V = runpy.run_path(str(ROOT / 'tools/auxkc-verdict.py'), run_name='auxkc_verdict')
BASE = '0xfffffe000e358000'
AUDIT = dict(linked_auxkc=dict(
    resident=dict(state='slid', fixups_applied=318, fixups_raw=0, structors_resigned=2,
                  fixups_rewritten=0, executable_bytes_verified=1441, base=BASE,
                  header_pa='0x8ced08000'),
    monitor_counters=dict(map_pages=0, exec_gained=0)))
WAITS = dict(
    auxkc_state=dict(handoff=dict(base=BASE), uuid_valid=1, daemon_ready=True, load_enabled=True),
    linked_auxkc=dict(base=BASE, bundles=['org.snapintosh.driver.SnapHello'],
                      registry_entries=[dict(class_name='SnapHello', name='SnapHello',
                                             vtable='0xfffffe000e35c010', registered=True)],
                      kernel_messages=['KextLog: Adding kexts from in-memory AuxKC',
                                       'SnapHello: AuxKC kext started']),
    kernel_messages=dict(text='boot\nKextLog: Adding kexts from in-memory AuxKC\n'
                              'SnapHello: AuxKC kext started\nlater\n'))


class Verdict(unittest.TestCase):
    def test_all_stages(self):
        result = V['verdict'](AUDIT, WAITS)
        self.assertEqual((result['reached'], result['first_unmet']), ('started', None))
        self.assertEqual(result['logged'], {'org.snapintosh.driver.SnapHello': True})
        self.assertEqual(result['refusals'], [])

    def test_first_unmet_stage_is_reported(self):
        waits = copy.deepcopy(WAITS)
        waits['auxkc_state']['daemon_ready'] = False
        waits['linked_auxkc']['registry_entries'] = []
        waits['kernel_messages']['text'] = 'boot\n'
        result = V['verdict'](AUDIT, waits)
        self.assertEqual((result['reached'], result['first_unmet']), ('accepted', 'activated'))
        audit = copy.deepcopy(AUDIT)
        audit['linked_auxkc']['resident'].update(state='partial', fixups_raw=12)
        self.assertEqual(V['verdict'](audit, WAITS)['reached'], 'placed')
        waits = copy.deepcopy(WAITS)
        waits['auxkc_state']['handoff']['base'] = '0xfffffe0006f94000'
        self.assertEqual(V['verdict'](AUDIT, waits)['first_unmet'], 'accepted')

    def test_start_needs_registry_or_the_log_line(self):
        waits = copy.deepcopy(WAITS)
        waits['linked_auxkc']['registry_entries'] = []
        self.assertEqual(V['verdict'](AUDIT, waits)['reached'], 'started')
        waits['kernel_messages']['text'] = 'boot\n'
        self.assertEqual(V['verdict'](AUDIT, waits)['first_unmet'], 'started')

    def test_refusals_are_surfaced(self):
        waits = copy.deepcopy(WAITS)
        waits['linked_auxkc']['registry_entries'] = []
        waits['kernel_messages']['text'] = (
            'KextLog: AuxKC bundle org.snapintosh.driver.SnapHello marked as NOT loadable\n'
            'Kext org.snapintosh.driver.SnapHello is not loadable\n')
        result = V['verdict'](AUDIT, waits)
        self.assertEqual(result['first_unmet'], 'started')
        self.assertEqual(len(result['refusals']), 2)

    def test_requires_the_linked_audit(self):
        with self.assertRaisesRegex(ValueError, 'linked_auxkc'):
            V['verdict']({}, WAITS)

    def test_run_scripts_compile(self):
        with tempfile.TemporaryDirectory() as temp:
            for name in ('build/build-auxkc-monitor-20260925.py', 'build/run-auxkc-hello-600s-20260925.py',
                         'build/collect-auxkc-20260925.py', 'build/build-auxkc.py'):
                path = ROOT / name
                if path.is_file():
                    py_compile.compile(str(path), cfile=str(Path(temp) / 'x.pyc'), doraise=True)


if __name__ == '__main__':
    unittest.main()
