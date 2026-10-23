#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_UPDATE_CHECK_SPARSE: the user-update kernel skip's six-CPU kernel-copy
re-derivation runs 1 in 1024 skips instead of 1 in 64 (opt-in; a weaker audit,
accepted for speed; the skip itself is unchanged).

    python3 tools/test-update-check-sparse.py [--build [--out DIR] [--expect fast=SHA256]]

Offline. Checks that probes/xnuboot.c defaults the define to 0, requires
SNAP_USER_UPDATE_KERNEL_SKIP, changes only the sampling mask (1023 for 63),
and that tools/kernel_ops_perf.py accepts exactly verified == skipped // 1024
with the flag and exactly skipped // 64 without it. --build: absent == =0,
=1 differs, the code budget holds, --expect pins the default build.

Failure inventory: the check silently off (rate 0 or never), the decoder
accepting either rate, a default build that changed.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


class Source(unittest.TestCase):
    def test_default_and_rate(self):
        self.assertIn('#ifndef SNAP_UPDATE_CHECK_SPARSE\n#define SNAP_UPDATE_CHECK_SPARSE 0\n#endif\n'
                      '_Static_assert(!SNAP_UPDATE_CHECK_SPARSE || SNAP_USER_UPDATE_KERNEL_SKIP,', SOURCE)
        skip = between(SOURCE, 'static void user_update_kernel_skip(struct context *c)', '\n}\n')
        self.assertIn('#if SNAP_UPDATE_CHECK_SPARSE\n    if(!(++k->skipped&1023) && c->kernel_views.count) {\n'
                      '#else\n    if(!(++k->skipped&63) && c->kernel_views.count) {\n#endif', skip)
        self.assertEqual(SOURCE.count('SNAP_UPDATE_CHECK_SPARSE'), 5)


def decode(flags, skipped, verified):
    spec = importlib.util.spec_from_file_location('kernel_ops_perf', ROOT / 'tools/kernel_ops_perf.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw = {'user_update_skip': struct.pack('<3Q', skipped, verified, 0)}
    audit = {'root_switch': {}, 'user_updates': {'calls': skipped, 'entries': skipped}}
    return module.decode(raw, flags, audit)


class Decoder(unittest.TestCase):
    def test_each_rate_exactly(self):
        skip = 'SNAP_USER_UPDATE_KERNEL_SKIP'
        for skipped in (64, 1023, 1024, 6734020):
            decode([skip, 'SNAP_UPDATE_CHECK_SPARSE'], skipped, skipped // 1024)
            decode([skip], skipped, skipped // 64)
            if skipped // 1024 != skipped // 64:
                with self.assertRaises(ValueError):
                    decode([skip, 'SNAP_UPDATE_CHECK_SPARSE'], skipped, skipped // 64)
                with self.assertRaises(ValueError):
                    decode([skip], skipped, skipped // 1024)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        spec = importlib.util.spec_from_file_location('root_miss', ROOT / 'tools/test-root-miss.py')
        module = importlib.util.module_from_spec(spec)
        saved_argv = sys.argv
        sys.argv = [saved_argv[0]]
        try:
            spec.loader.exec_module(module)
        finally:
            sys.argv = saved_argv
        sets, _ = module.flag_sets()
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='check-sparse-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name in ('control', 'fast'):
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_UPDATE_CHECK_SPARSE=0']),
                                     ('on', ['-DSNAP_UPDATE_CHECK_SPARSE=1'])):
                    monitor_run.FLAGS[:] = sets[name] + extra
                    blob = monitor_run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name])
        finally:
            monitor_run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
