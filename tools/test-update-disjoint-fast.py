#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_UPDATE_DISJOINT_FAST: bind compat/update-fast.h's TLBI rule and the
one-pass kernel-copy verification to the monitor, its defaults and layout.

    python3 tools/test-update-disjoint-fast.py
    python3 tools/test-update-disjoint-fast.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]

Offline, no hardware and no proxy. It builds and runs (sanitized)
tools/test-update-disjoint-fast.c: sprr_views_verify_all against six
sprr_views_verify_cpu calls on random kernel-shaped views and corruptions, the
AF-clear skip against a TLB model, and the real UPDATE_DISJOINT engine on the
v33 reference/modify pair; then requires a weakened copy of each guard
(A1/A2, V1/V2) to FAIL it. It checks that probes/xnuboot.c defaults the
define to 0, skips exactly one TLBI (user_commit_update, on the OLD leaf),
swaps exactly the two sampled six-CPU verifications at an unchanged rate, and
that struct context keeps its size.

--build compiles xnuboot with the control/fast/fast-wfi flag sets with the
define absent, =0 and =1 (-Werror, the code budget, absent == =0, =1 differs);
--expect NAME=SHA256 pins a default build. It also reports the define-on
SHA-256s of the full fast stack with this define, with SNAP_ROOT_MISS_FAST,
and with both.

Failure inventory: a skipped TLBI while a TLB may hold the old leaf (AF set,
or read from the new leaf); the skip reaching another path; a CPU's copy left
unchecked or decoded with another CPU's PPERM or child; a changed
verification rate; a default build that changed; a layout change.
"""
from pathlib import Path
import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
VIEW_C = (ROOT / 'shadow/sprr-view.c').read_text()
HEADER = (ROOT / 'compat/update-fast.h').read_text()
DEFINE = '-DSNAP_UPDATE_DISJOINT_FAST=1'
CORE = ['compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c', 'compat/sptm-unmap.c',
        'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c', 'compat/sptm-slide.c',
        'compat/sptm-root.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
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


def compile_c(directory, overrides=None):
    exe = Path(directory) / 'test-update-disjoint-fast'
    include, sources = [], list(CORE)
    if overrides:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        (mut / 'update-fast.h').write_text(overrides.get('update-fast.h', HEADER))
        (mut / 'sprr-view.c').write_text(overrides.get('sprr-view.c', VIEW_C))
        include = [f'-I{mut}']
        sources = [str(mut / 'sprr-view.c') if s == 'shadow/sprr-view.c' else s for s in sources]
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', DEFINE, *include,
                    '-Icompat', '-Ishadow', 'tools/test-update-disjoint-fast.c', *sources, '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


def run(exe):
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=900)


MUTANTS = {
    'A1 every valid leaf skips': ('update-fast.h',
        '    return (old&3)==3 && !(old&PT_AF);\n', '    return (old&3)==3;\n'),
    'A1 an AF-set leaf skips': ('update-fast.h',
        '    return (old&3)==3 && !(old&PT_AF);\n', '    return (old&3)==3 && !!(old&PT_AF);\n'),
    'V2 every CPU decoded with CPU 0 PPERM': ('sprr-view.c',
        'if(!entry_decode(v,n,d,i,cpu,pperm[cpu],0,0,&expected) ||',
        'if(!entry_decode(v,n,d,i,cpu,pperm[0],0,0,&expected) ||'),
    'V2 every CPU decoded with CPU 0 children': ('sprr-view.c',
        'if(!entry_decode(v,n,d,i,cpu,pperm[cpu],0,0,&expected) ||',
        'if(!entry_decode(v,n,d,i,0,pperm[cpu],0,0,&expected) ||'),
    'V2 the last CPU unchecked': ('sprr-view.c',
        '            for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {\n                uint64_t expected,actual;',
        '            for(unsigned cpu=0;cpu+1<SPRR_VIEW_CPUS;cpu++) {\n                uint64_t expected,actual;'),
    'V2 a misaligned copy admitted': ('sprr-view.c',
        '            if(!t->copy[cpu] || (t->copy[cpu]&4095))return 0;\n        if(t->level>3',
        '            if(!t->copy[cpu])return 0;\n        if(t->level>3'),
    'V2 only CPU 0 PPERM validated': ('sprr-view.c',
        '        if((pperm[cpu]&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;',
        '        if((pperm[0]&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;'),
    'V1 a copy compared without reading it': ('sprr-view.c',
        "                   s->read(s->ctx,t->copy[cpu]+8UL*i,&actual) || actual!=expected)return 0;",
        "                   s->read(s->ctx,t->copy[cpu]+8UL*i,&actual) || (actual!=expected && cpu==0))return 0;"),
}


class Decision(unittest.TestCase):
    def test_verify_model_engine(self):
        with tempfile.TemporaryDirectory() as d:
            result = run(compile_c(d))
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-3000:])
        self.assertTrue(result.stdout.rstrip().splitlines()[-1].startswith('PASS'))
        for line in result.stdout.strip().splitlines():
            print(line, file=sys.stderr)

    def test_weakened_guards_fail(self):
        for label, (name, old, new) in MUTANTS.items():
            text = HEADER if name == 'update-fast.h' else VIEW_C
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                self.assertEqual(text.count(old), 1, label)
                result = run(compile_c(d, {name: text.replace(old, new)}))
                self.assertNotEqual(result.returncode, 0, f'{label} survived')


class Source(unittest.TestCase):
    def test_default_off(self):
        self.assertIn('#ifndef SNAP_UPDATE_DISJOINT_FAST\n#define SNAP_UPDATE_DISJOINT_FAST 0\n#endif\n'
                      '_Static_assert(!SNAP_UPDATE_DISJOINT_FAST || SNAP_NATIVE_TABLES,', SOURCE)
        self.assertIn('#if SNAP_UPDATE_DISJOINT_FAST\n#include "../compat/update-fast.h"\n#endif', SOURCE)
        self.assertIn('#if SNAP_UPDATE_DISJOINT_FAST\n/* compat/update-fast.h V1/V2', VIEW_C)

    def test_one_skip_on_the_old_leaf(self):
        commit = between(SOURCE, 'static int user_commit_update(void *ctx', '\n}\n')
        self.assertIn('#if SNAP_UPDATE_DISJOINT_FAST\n', commit)
        self.assertIn('    if(update_fast_uncached(old))return !c->user_view_failed;\n#endif\n', commit)
        self.assertTrue(commit.rstrip().endswith('user_tlb_range(c,va,UINT64_C(1)<<shift);return !c->user_view_failed;'))
        # SNAP_FINE_LOCKS mirrors this commit once, as fine_user_commit_update
        # (tools/test-fine-locks.py pins the mirror); the rule has no other use.
        fine = between(SOURCE, 'static int fine_user_commit_update(void *ctx', '\n}\n') \
            if 'static int fine_user_commit_update(void *ctx' in SOURCE else ''
        # SNAP_SPTM_FINE's converted hardware-walk update commit applies the same rule to its by-VA
        # invalidation (tools/test-sptm-fine.py pins that call).
        hw = between(SOURCE, 'static int fine_hw_commit_update(void *ctx', '\n}\n') \
            if '#if SNAP_SPTM_FINE\n' in SOURCE else ''
        self.assertEqual(SOURCE.count('update_fast_uncached('),
                         1 + fine.count('update_fast_uncached(') + hw.count('update_fast_uncached('))
        self.assertLessEqual(fine.count('update_fast_uncached('), 1)
        self.assertLessEqual(hw.count('update_fast_uncached('), 1)
        if hw:
            self.assertIn(',UINT64_C(1)<<shift,!update_fast_uncached(old),&t,&n);', hw)
        # The callback is installed only as the private-root update commit.
        self.assertEqual(SOURCE.count('b->commit_update=user_commit_update'), 1)

    def test_two_verifications_same_rate(self):
        self.assertEqual(SOURCE.count('sprr_views_verify_all(&c->kernel_views,&s,pp)'), 2)
        skip = between(SOURCE, 'static void user_update_kernel_skip(struct context *c)', '\n}\n')
        self.assertIn('if(!(++k->skipped&63) && c->kernel_views.count) {', skip)
        on = between(skip, '#if SNAP_UPDATE_DISJOINT_FAST', '#else')
        off = between(skip, '#else', '#endif', skip.index('#if SNAP_UPDATE_DISJOINT_FAST'))
        self.assertIn('pp[cpu]=c->user_roots.sprr[cpu].pperm;', on)
        self.assertEqual([l.strip() for l in off.splitlines()[1:] if l.strip()],
                         ['for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)',
                          'if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,c->user_roots.sprr[cpu].pperm)) {',
                          'k->mismatches++;c->kernel_view_failed=1;return;', '}'])
        refresh = between(SOURCE, 'static int kernel_refresh_impl(struct context *c)', '\n}\n')
        # compat/audit-sparse.h: 63 by default (1 in 64), 1023 under SNAP_AUDIT_SPARSE.
        self.assertIn('if(!(reuse->hits&AUDIT_SAMPLE_MASK)) {\n#if SNAP_UPDATE_DISJOINT_FAST', refresh)

    def test_header_rule(self):
        self.assertIn('_Static_assert(!(SPTM_ROOT_TCR_16K&(UINT64_C(1)<<39)) && '
                      '!(SPTM_ROOT_TCR_4K&(UINT64_C(1)<<39)),', HEADER)
        off = subprocess.run(['cc', '-E', '-P', '-Icompat', '-Ishadow', 'shadow/sprr-view.c'], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
        self.assertNotIn('sprr_views_verify_all', off)


class Layout(unittest.TestCase):
    def test_context_unchanged(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        perf = importlib.import_module('perf_counters')
        for name, flags in flag_sets().items():
            defines = [f for f in flags if f.startswith('-D')]
            off = perf._records(ROOT / 'probes/xnuboot.c', defines)
            on = perf._records(ROOT / 'probes/xnuboot.c', defines + [DEFINE])
            self.assertEqual(perf._size(off['context']), perf._size(on['context']), name)


def flag_sets():
    spec = importlib.util.spec_from_file_location('root_miss', ROOT / 'tools/test-root-miss.py')
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [saved[0]]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    sets, _ = module.flag_sets()
    return sets


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a few minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        sets = flag_sets()
        stack = ['-DSNAP_WFI_RESUME=1', '-DSNAP_FAST_EL0_SYSREG=1', '-DSNAP_SERVICE_SUBCLASS=1',
                 '-DSNAP_DART_WIREDCNT=1', '-DSNAP_PANIC_SERVE=1']
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        sets['fast-stack'] = sets['fast'] + stack
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='update-fast-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                variants = [('default', []), ('off', ['-DSNAP_UPDATE_DISJOINT_FAST=0']), ('on', [DEFINE])]
                if name == 'fast-stack':
                    variants.append(('both', [DEFINE, '-DSNAP_ROOT_MISS_FAST=1']))
                for label, extra in variants:
                    monitor_run.FLAGS[:] = flags + extra
                    blob = monitor_run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0, f'{name}-{label}')
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name],
                                     f'{name}: the default build changed')
        finally:
            monitor_run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
