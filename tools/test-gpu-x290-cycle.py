#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cycle.py installed-fresh opt-ins of agents/gpu-x290 (FAILURE-MODES.md C1, X6, X8, F6): --gpu-x290, --gpu-x290-survey,
--adreno-fill-br, --adreno-fence-br. Offline: argument parsing, the monitor define list and the q1n1 GPU steps.

  python3 tools/test-gpu-x290-cycle.py [--qualification build/installed-fresh-desktop-20261021-b12v11/qualification.json]
"""
from pathlib import Path
import argparse
import json
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.path.insert(0, str(ROOT / 'tools'))

_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--qualification', default=str(ROOT / 'build/installed-fresh-desktop-20261021-b12v11/qualification.json'))
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
FILL, FENCE = '-DSNAP_ADRENO_FILL_BR=1', '-DSNAP_ADRENO_FENCE_BR=1'


class Cycle(unittest.TestCase):
    def test_parser(self):
        import cycle
        argv = ['installed-fresh', '--prepare', '--gpu-x290', '--gpu-x290-survey', '--adreno-fill-br', '--adreno-fence-br']
        try:
            args = cycle.parse(argv)
        except SystemExit:                      # a parser that needs more arguments: check the names exist at least
            text = (ROOT / 'tools/cycle.py').read_text()
            for flag in argv[2:]:
                self.assertIn(f"'{flag}'", text)
            return
        for name in ('gpu_x290', 'gpu_x290_survey', 'adreno_fill_br', 'adreno_fence_br'):
            self.assertTrue(getattr(args, name), name)
        plain = cycle.parse(['installed-fresh', '--prepare'])
        for name in ('gpu_x290', 'gpu_x290_survey', 'adreno_fill_br', 'adreno_fence_br'):
            self.assertFalse(getattr(plain, name), name)

    def test_defines(self):
        """C1/F6: off by default, appended last (fill before fence), nothing else moves."""
        from cycle_lib import installed_fresh as f
        self.assertEqual((f.ADRENO_FILL_BR_DEFINE, f.ADRENO_FENCE_BR_DEFINE), (FILL, FENCE))
        sets = dict(fast=['-DSNAP_ROOT_CACHE_WIDE=1', '-DX=1'], control=['-DY=1'])
        base = dict(variant='fast', root_cache_wide=True)
        plain = f.variant_flags(sets, types.SimpleNamespace(**base))
        self.assertNotIn(FILL, plain)
        self.assertNotIn(FENCE, plain)
        fill = f.variant_flags(sets, types.SimpleNamespace(adreno_fill_br=True, **base))
        fence = f.variant_flags(sets, types.SimpleNamespace(adreno_fence_br=True, **base))
        both = f.variant_flags(sets, types.SimpleNamespace(adreno_fill_br=True, adreno_fence_br=True, **base))
        self.assertEqual(fill, plain + [FILL])
        self.assertEqual(fence, plain + [FENCE])
        self.assertEqual(both, plain + [FILL, FENCE])

    def test_qualification_has_neither(self):
        """The b12v11 qualification (the default monitor this change must leave byte-identical) has neither define and
        no --x290 / x290-survey step."""
        path = Path(ARGS.qualification)
        if not path.is_file():
            self.skipTest(f'{path} absent')
        q = json.loads(path.read_text())
        self.assertNotIn(FILL, q['flags'])
        self.assertNotIn(FENCE, q['flags'])
        steps = [x for _, a in q['gpu_steps'] for x in a]
        self.assertNotIn('--x290', steps)
        self.assertNotIn('x290-survey', steps)

    def test_gpu_steps(self):
        """X8: --x290 on every cp-fence (after --va-wide when both); the survey last, after llcc-gpu."""
        from cycle_lib import installed_fresh as f
        for extra in ({}, dict(gpu_va_wide=True), dict(llcc=True), dict(gpu_va_wide=True, llcc=True)):
            plain = f.gpu_steps(ROOT, types.SimpleNamespace(**extra))
            x290 = f.gpu_steps(ROOT, types.SimpleNamespace(gpu_x290=True, **extra))
            survey = f.gpu_steps(ROOT, types.SimpleNamespace(gpu_x290_survey=True, **extra))
            self.assertEqual(len(plain), len(x290))
            fences = 0
            for (name, a), (name2, b) in zip(plain, x290):
                self.assertEqual(name, name2)
                if a[0] == 'cp-fence':
                    fences += 1
                    self.assertEqual(b, [*a, '--x290'])
                else:
                    self.assertEqual(a, b)
            self.assertGreaterEqual(fences, 4)       # C3, C3S, C5, fence
            self.assertNotIn('--x290', [x for _, a in plain for x in a])
            self.assertEqual(survey, plain + [('x290_survey', ['x290-survey'])])
            self.assertNotIn('--write', survey[-1][1])
            if extra.get('llcc'):
                self.assertEqual(survey[-2][0], 'llcc_gpu')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST])
