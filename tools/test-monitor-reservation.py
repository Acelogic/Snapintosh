#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The q1n1 heap layout the loader uses (probes/run.py) after the monitor's
code reservation grew to 448 KiB: code, report, SMP configuration page and work
locator stay in that order without overlapping, and only OUT_AT moved. Host
only; the monitor binary itself does not depend on the reservation (the report
address is passed to xnuboot_setup)."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import monitor_work  # noqa: E402
import run  # noqa: E402


class HeapLayout(unittest.TestCase):
    def test_regions_in_order(self):
        self.assertEqual(run.OUT_AT - run.CODE_AT, 448 << 10)
        self.assertLessEqual(run.OUT_AT + run.REPORT_RESERVE, run.SECONDARY_CONFIG_AT)
        self.assertEqual(run.OUT_HEADROOM, run.SECONDARY_CONFIG_AT - run.OUT_AT)
        self.assertLessEqual(run.SECONDARY_CONFIG_AT + 4096, run.WORK_AT)
        # The work locator host tools read from a stopped A16 is at WORK_AT.
        self.assertEqual(monitor_work.LOCATOR_OFFSET, run.WORK_AT)

    def test_only_the_report_moved(self):
        # Where code starts, the SMP page, the work locator and the report's
        # size are protocol with running stages and stopped-state tools.
        self.assertEqual((run.CODE_AT, run.SECONDARY_CONFIG_AT, run.WORK_AT, run.REPORT_RESERVE),
                         (0x400000, 0x4f0000, 0x500000, 0x10000))


if __name__ == '__main__':
    unittest.main()
