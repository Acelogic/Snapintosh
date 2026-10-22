#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for cycle.py installed-fresh --zone-log / --zone-log-records. No A16 access.

The boot-argument addition without the options must be exactly what earlier attempts qualified; with them it
appends zlog1=ZONE (and zrecs=N); anything outside XNU's zone-name alphabet or range is refused.
"""
import argparse
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from cycle_lib import installed_fresh as fresh          # noqa: E402
from cycle_lib.common import Refused                    # noqa: E402

spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

BASE = ' '.join([fresh.TIMESYNC_FLAG, fresh.COMPRESSOR_SW_FLAG])


def ns(**kw):
    return argparse.Namespace(**kw)


class ZoneLog(unittest.TestCase):
    def test_default_unchanged(self):
        self.assertEqual(fresh.boot_addition(ns()), BASE)
        self.assertEqual(fresh.boot_addition(ns(console=True, single_user=True)),
                         ' '.join([BASE, fresh.CONSOLE_FLAG, fresh.SINGLE_USER_FLAG]))
        self.assertEqual(fresh.boot_addition(ns(zone_log=None, zone_log_records=None)), BASE)

    def test_zone(self):
        self.assertEqual(fresh.boot_addition(ns(zone_log='early.kalloc.1024')), BASE + ' zlog1=early.kalloc.1024')
        self.assertEqual(fresh.boot_addition(ns(console=True, zone_log='kalloc.1024', zone_log_records=8192)),
                         ' '.join([BASE, fresh.CONSOLE_FLAG, 'zlog1=kalloc.1024', 'zrecs=8192']))

    def test_refusals(self):
        for bad in ('', 'a b', 'x!y', "q'", 'a=b', 'z' * 65, 'kalloc.1024 zrecs=1'):
            with self.assertRaises(Refused, msg=bad):
                fresh.boot_addition(ns(zone_log=bad))
        with self.assertRaises(Refused):
            fresh.boot_addition(ns(zone_log_records=10))
        for n in (0, 65537, -1):
            with self.assertRaises(Refused, msg=n):
                fresh.boot_addition(ns(zone_log='kalloc.1024', zone_log_records=n))

    def test_cli_reaches_args(self):
        a = cli.parse(['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check', '--zone-log', 'kalloc.1024',
                       '--zone-log-records', '4096'])
        self.assertEqual((a.zone_log, a.zone_log_records), ('kalloc.1024', 4096))


if __name__ == '__main__':
    unittest.main()
