#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Catch a stale q1n1 stage before building/uploading a multi-GiB guest."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import importlib.util
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'probes'))
import run
import preload


class Panel:
    def __init__(self, enabled):
        self.enabled = enabled
        self.calls = []

    def fb_console(self, enabled):
        self.calls.append(enabled)
        previous, self.enabled = self.enabled, int(enabled)
        return previous


class PreflightTests(unittest.TestCase):
    def test_preserves_enabled_and_disabled_ownership(self):
        for enabled in (0, 1):
            p = Panel(enabled)
            run.check_panel_control(p)
            self.assertEqual(p.enabled, enabled)
            self.assertEqual(p.calls, [False, True] if enabled else [False])

    def test_rejected_stage_names_recovery(self):
        with patch.object(Panel, 'fb_console', side_effect=run.q1n1.ProxyRemoteError('status -1')):
            with self.assertRaisesRegex(ValueError, 'RAM-chainload the latest q1n1 stage'):
                run.check_panel_control(Panel(1))

    def test_invalid_prior_state(self):
        for state in (-1, 2, None):
            with self.subTest(state=state), patch.object(Panel, 'fb_console', return_value=state):
                with self.assertRaisesRegex(ValueError, 'invalid panel ownership'):
                    run.check_panel_control(Panel(1))

    def test_failed_retention(self):
        with patch.object(Panel, 'fb_console', side_effect=[1, 1]):
            with self.assertRaisesRegex(ValueError, 'did not retain'):
                run.check_panel_control(Panel(1))

    def test_network_failure_is_not_a_stale_stage(self):
        with patch.object(Panel, 'fb_console', side_effect=run.q1n1.ProxyTimeout('link lost')):
            with self.assertRaises(run.q1n1.ProxyTimeout):
                run.check_panel_control(Panel(1))

    def test_boot_refuses_before_layout_or_image_build(self):
        # Stub only profile/cache discovery. Any build, target-memory write,
        # or runtime admission reached on this rejected stage fails the test.
        profile = SimpleNamespace(abi='fixture', sep_asc=None)
        xb = SimpleNamespace(configure_guest=lambda *a: None,
            check_profile=lambda **k: [], DEFAULT_KERNELCACHE='fixture',
            PROFILE_NAME='fixture', PROFILE_TARGET='fixture', PROFILE_BUILD='fixture',
            TIMEBASE_HZ=24000000, GUEST_PROFILE=profile)
        host = SimpleNamespace(framebuffer=True, timer_hz=19200000, adapter='q1n1')
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m: None))
        p = Panel(1)
        with patch.object(preload, 'resident_cache', return_value=[]), \
             patch.object(run.HostRuntime, 'from_q1n1', return_value=host), \
             patch.object(importlib.util, 'spec_from_file_location', return_value=spec), \
             patch.object(importlib.util, 'module_from_spec', return_value=xb), \
             patch.object(Panel, 'fb_console', side_effect=run.q1n1.ProxyRemoteError('status -1')), \
             redirect_stdout(StringIO()) as output:
            self.assertEqual(run.run_xnuboot(p, {}, 0), run.EXIT_LOADER)
        self.assertIn('RAM-chainload', output.getvalue())


if __name__ == '__main__':
    unittest.main()
