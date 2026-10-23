#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_FINE_LOCKS / SNAP_FINE_SWITCH / SNAP_FAIR_TOKEN (docs/FINE-LOCKS-20261017.md).

    python3 tools/test-fine-locks.py [--build [--out DIR] [--expect NAME=SHA256]] [--quick]

Offline, no hardware and no proxy.
Unit: tools/test-fine-locks.c, six pthreads running the real compat engines
under the real gate and root stripes, interleaved with token-path calls,
under ThreadSanitizer and under ASan/UBSan, phase 1 and phase 1b, with the
default compat defines and with the installed-fresh (v41) set, and with four
stripes (roots sharing stripes): every converted call's result, the final
guest RAM, shadow arena and cache equal a single-threaded token-path replay
of the log, the reference and type invariants hold, every cached shadow
equals its guest leaves, no CPU's TLB keeps a stale translation of a changed
page, and every shadow store is published before its TLBI.
Mutants: a missing stripe, unsorted stripes (deadlock), a non-atomic count, a
count delta against a lost snapshot, a token holder that does not drain
readers, a reader that does not publish itself, a commit without its TLBI, a
store without its publication, and (phase 1b) a switch outside its old
root's stripe or with a plain activity store: each must fail the harness.
Source: the define-off text of every changed file is free of the new code;
each converted callback in probes/xnuboot.c repeats its token-path original's
calls (publication, TLBI, commits) except the listed differences; nothing a
converted call reaches allocates, flushes, reclaims, invalidates, retypes,
builds or takes the token; global words it writes are atomic or under aux;
perf_counters.py decodes a fine profile a C writer produced.
Fairness: under an adversarial re-acquire loop a waiter is passed by at most
the five CPUs already queued, for the stripe/aux ticket locks and for the
SNAP_FAIR_TOKEN token; readers cannot enter after a token grant; a
test-and-set stripe lock and a token turn ignoring the queue must fail.
Pauth (SNAP_FAST_PAUTH_CALLS): tools/test-fast-pauth-calls.c compiles the
monitor's own converted pointer calls, the define-on SIGN/AUTH/BATCH_SIGN
cases and the default build's original cases (extracted from
probes/xnuboot.c) against the real pauth engines: for random calls, states and
injected native failures, the default case equals the define-on case, a
converted answer equals the case's, a decline changed nothing and the case
refuses it, a converted failure carries the case's record; weakened sources
must fail it. The source binding: SIGN/AUTH/BATCH_SIGN classified and
dispatched to the converted calls, one signing body for both paths, no stripe,
no pv_audit or view-failure write, nothing token-only reached, per-CPU state
only; weakened bindings must be caught. A source without the conversion fails
both.
Phase-fair gate (SNAP_PHASE_FAIR_GATE, batch6 FAILURES-AND-DESIGN.md G1-G16):
the harness above with the announced wait (bounded, withdrawn at the bound)
under TSan and ASan; mutants for each failure mode; fairness: a reader is
passed by at most the one writer present at its arrival, a token holder's
drain sees at most one entry per other CPU; Mix: installed-fresh-20261020-v5's
load on the real gate, old against new (reader and writer waits, drain,
fairness counts), reported.
--build: control, fast and fast+WFI: absent == =0, SNAP_FAIR_TOKEN=1 differs
(SNAP_FINE_LOCKS=1 and SNAP_FAST_PAUTH_CALLS=1 refuse to build outside the
installed flag set); the installed-fresh (v41) set: absent == =0, =1,
=1+SWITCH, =1+SWITCH+FAIR, =1+SWITCH+FAIR+GATE_WAIT+PHASE_FAIR_GATE and
=1+FAST_PAUTH_CALLS differ, the code budget holds; --expect pins defaults;
SNAP_PHASE_FAIR_GATE refuses to build without SNAP_FAIR_TOKEN or SNAP_GATE_WAIT.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
IMPL = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'compat').glob('sptm*.c'))
IMPL += ['shadow/sprr-view.c', 'shadow/mmu.c', 'shadow/shadow.c', 'compat/service-lock.c']
CC = ['clang', '-std=gnu11', '-O1', '-g', '-pthread', '-ffunction-sections', '-Wl,-dead_strip',
      '-Wall', '-Wextra', '-Werror', '-DSNAP_FINE_LOCKS=1', '-Icompat', '-Ishadow']
SAN = {'tsan': ['-fsanitize=thread'], 'asan': ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']}
CHANGED = ['compat/service-lock.h', 'compat/service-lock.c', 'compat/sptm.h', 'compat/sptm-refs.h',
           'compat/sptm-refs.c', 'compat/sptm-root.h', 'compat/sptm-root.c', 'shadow/root-publish.h',
           'shadow/txn-publish.h', 'shadow/sprr-private-pages.h', 'shadow/sprr-table-memo.h',
           'shadow/sprr-view.h', 'probes/xnuboot.c']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--quick', action='store_true', help='fewer calls per CPU and only the key mutants')
    ap.add_argument('--out')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, quick=False, out=None, expect=[]), [])
WORK = Path(tempfile.mkdtemp(prefix='fine-locks-'))
CALLS = '1500' if ARGS.quick else '3000'


def installed_defines():
    """The installed-fresh (v41) fast flag set's -D words: cycle.py's recipe."""
    spec = importlib.util.spec_from_file_location('wfi_resume', ROOT / 'tools/test-wfi-resume.py')
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [saved[0]]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    sets, _ = module.flag_sets()
    sys.path.insert(0, str(ROOT / 'tools'))
    import cycle_lib.installed_fresh as fresh  # noqa: E402
    args = argparse.Namespace(variant='fast', wfi_resume=True, fast_el0_sysreg=True, service_subclass=True,
                              dart_wiredcnt=True, panic_serve=True, root_miss_fast=True, update_disjoint_fast=True,
                              root_cache_wide=True, update_check_sparse=True, input=True, kernel_pperm_fast=True,
                              ib_budget_1s=True, unmap_mixed=True)
    return fresh.variant_flags(sets, args), sets


def harness(tree, san, extra=(), calls=CALLS, seed='5', timeout=900):
    """Build tools/test-fine-locks.c in tree and run it; (returncode, output)."""
    binary = WORK / f'h-{abs(hash((str(tree), san, tuple(extra))))}'
    build = subprocess.run([*CC, *SAN[san], *extra, 'tools/test-fine-locks.c', *IMPL, '-o', str(binary)],
                           cwd=tree, capture_output=True, text=True)
    if build.returncode:
        return build.returncode, 'build: ' + build.stderr[-3000:]
    env = dict(os.environ, TSAN_OPTIONS='halt_on_error=1')
    try:
        run = subprocess.run([str(binary), calls, seed], capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return -9, 'timeout'
    return run.returncode, run.stdout + run.stderr


class Unit(unittest.TestCase):
    def check(self, san, extra=(), seed='5'):
        rc, out = harness(ROOT, san, extra, seed=seed)
        self.assertEqual(rc, 0, f'{san} {extra}: {out[-3000:]}')
        self.assertIn('replay equal', out)
        label = ' '.join(e for e in extra if 'FINE' in e or 'FAIR' in e) + \
            (' +installed defines' if any(e.startswith('-DSNAP_') and 'FINE' not in e and 'FAIR' not in e
                                          for e in extra) else '')
        print(f'{san} {label or "phase 1"}: ' + [l for l in out.splitlines() if 'calls logged' in l][0],
              file=sys.stderr)

    def test_phase1(self):
        for san in ('tsan', 'asan'):
            self.check(san)

    def test_phase1b(self):
        for san in ('tsan', 'asan'):
            self.check(san, ['-DSNAP_FINE_SWITCH=1'], seed='6')

    def test_shared_stripes(self):
        # Four stripes: roots share stripes, so merged locksets and one root's
        # holder excluding another's calls are exercised.
        for san in ('tsan', 'asan'):
            self.check(san, ['-DSNAP_FINE_SWITCH=1', '-DFINE_STRIPES=4u'], seed='7')

    def test_fair_token(self):
        for san in ('tsan', 'asan'):
            self.check(san, ['-DSNAP_FINE_SWITCH=1', '-DSNAP_FAIR_TOKEN=1'], seed='9')

    def test_phase_fair_gate(self):
        # SNAP_PHASE_FAIR_GATE: announced arrivals, phase entries, withdrawals at the bound.
        for san in ('tsan', 'asan'):
            self.check(san, PHASE_FAIR, seed='10')
        self.check('asan', [*PHASE_FAIR, '-DFINE_STRIPES=4u'], seed='11')

    def test_installed_defines(self):
        flags, _ = installed_defines()
        defines = [f for f in flags if f.startswith('-D') and 'FINE' not in f]
        for san in ('tsan', 'asan'):
            self.check(san, ['-DSNAP_FINE_SWITCH=1', *defines], seed='8')


PHASE_FAIR = ['-DSNAP_FINE_SWITCH=1', '-DSNAP_FAIR_TOKEN=1', '-DSNAP_PHASE_FAIR_GATE=1']
# Each must fail the harness under at least one sanitizer.
MUTANTS = [
    ('missing stripe', 'tools/test-fine-locks.c', '#ifndef MUTANT_NO_STRIPES\n    fine_lockset_acquire(stripes,set);',
     '#ifndef MUTANT_NO_STRIPES\n    (void)set;', []),
    ('unsorted stripes', 'compat/fine-lock.h',
     '    while (i < s->count && s->stripe[i] < k) i++;\n    if (i < s->count && s->stripe[i] == k) return 1;',
     '    for (; i < s->count; i++) if (s->stripe[i] == k) return 1;', []),
    ('non-atomic count', 'compat/sptm-refs.c',
     '            if (!table && ro)\n                __atomic_fetch_add((volatile uint32_t *)(e->entry+8),(uint32_t)ro,__ATOMIC_RELAXED);',
     '            if (!table && ro)\n                store(e->entry+8,(uint32_t)e->ro,4);', []),
    ('lost snapshot', 'compat/sptm-refs.c',
     '            m->fine->ro[e-b->entries]=e->ro;m->fine->other[e-b->entries]=e->other;',
     '            m->fine->ro[e-b->entries]=0;m->fine->other[e-b->entries]=0;', []),
    ('token holder does not drain', 'compat/service-lock.h',
     '    return !__atomic_load_n(&lock->readers, __ATOMIC_ACQUIRE);\n}', '    (void)lock;return 1;\n}', []),
    ('reader not published', 'compat/service-lock.c',
     '    __atomic_fetch_or(&lock->readers,bit,__ATOMIC_SEQ_CST);', '    (void)bit;', []),
    ('reader ignores a token taken meanwhile', 'compat/service-lock.c',
     '    if (__atomic_load_n(&lock->owner,__ATOMIC_SEQ_CST)) {\n        guest_service_leave_shared(lock,cpu);\n        return SERVICE_BUSY;',
     '    if (0) {\n        guest_service_leave_shared(lock,cpu);\n        return SERVICE_BUSY;', []),
    ('a converted call allocates', 'tools/test-fine-locks.c',
     'static uint64_t fine_alloc(void *ctx) {(void)ctx;self->alloc_refused=1;return 0;}',
     'static uint64_t token_alloc(void *ctx);\nstatic uint64_t fine_alloc(void *ctx) {return token_alloc(ctx);}', []),
    ('commit without TLBI', 'tools/test-fine-locks.c', '#ifndef MUTANT_NO_TLBI\n    tlbi_range(va,size);',
     '#ifndef MUTANT_NO_TLBI\n    (void)tlbi_range;(void)va;(void)size;', []),
    ('store without publication', 'tools/test-fine-locks.c', '#ifndef MUTANT_NO_PUBLISH\n',
     '#ifdef MUTANT_NO_PUBLISH\n', []),
    ('switch outside the old root stripe', 'tools/test-fine-locks.c',
     '        if(old && !fine_lockset_add(set,old))return 0;', '        (void)old;', ['-DSNAP_FINE_SWITCH=1']),
    ('plain activity store', 'compat/sptm-root.c',
     '    __atomic_store_n(&s->active[cpu],root,__ATOMIC_RELEASE);\n    __atomic_fetch_add(&s->switches,1,__ATOMIC_RELAXED);\n'
     '    __atomic_fetch_add(&s->user_switches,1,__ATOMIC_RELAXED);',
     '    s->active[cpu]=root;\n    __atomic_fetch_add(&s->switches,1,__ATOMIC_RELAXED);\n'
     '    __atomic_fetch_add(&s->user_switches,1,__ATOMIC_RELAXED);', ['-DSNAP_FINE_SWITCH=1']),
    # SNAP_PHASE_FAIR_GATE (G numbers: batch6 FAILURES-AND-DESIGN.md).
    ('phase-fair: a writer drains only the free bank (G1, G4)', 'compat/service-lock.h',
     '    return !(r & (UINT64_C(0xff) | UINT64_C(0xff) << SERVICE_GATE_BANK_SHIFT(!(r & SERVICE_GATE_PHASE))));',
     '    return !(r & UINT64_C(0xff));', PHASE_FAIR),
    ('phase-fair: an announced reader enters at once (G4)', 'compat/service-lock.c',
     '    return gate&SERVICE_GATE_WRITER ? SERVICE_BUSY : SERVICE_OK;', '    return SERVICE_OK;', PHASE_FAIR),
    ('phase-fair: a reader bank that ignores the phase (G8)', 'compat/service-lock.c',
     'SERVICE_GATE_BANK_SHIFT(!!(gate&SERVICE_GATE_PHASE)) : 0));', 'SERVICE_GATE_BANK_SHIFT(0) : 0));', PHASE_FAIR),
    ('phase-fair: a writer that keeps the phase (G8)', 'compat/service-lock.c',
     '(gate|SERVICE_GATE_WRITER)^SERVICE_GATE_PHASE,1,', '(gate|SERVICE_GATE_WRITER),1,', PHASE_FAIR),
    ('phase-fair: a relaxed phase poll (G9)', 'compat/service-lock.c',
     '    uint64_t gate=__atomic_load_n(&lock->readers,__ATOMIC_ACQUIRE);\n    unsigned phase;',
     '    uint64_t gate=__atomic_load_n(&lock->readers,__ATOMIC_RELAXED);\n    unsigned phase;', PHASE_FAIR),
    ('phase-fair: a relaxed writer clear (G9)', 'compat/service-lock.c',
     '        __atomic_fetch_and(&lock->readers, ~SERVICE_GATE_WRITER, __ATOMIC_RELEASE);',
     '        __atomic_fetch_and(&lock->readers, ~SERVICE_GATE_WRITER, __ATOMIC_RELAXED);', PHASE_FAIR),
    ('phase-fair: the turn passed before the writer bit is cleared (G9)', 'compat/service-lock.c',
     '    if (__atomic_load_n(&lock->readers, __ATOMIC_RELAXED) & SERVICE_GATE_WRITER)\n'
     '        __atomic_fetch_and(&lock->readers, ~SERVICE_GATE_WRITER, __ATOMIC_RELEASE);\n#endif\n'
     '    /* The holder alone writes serving: pass the turn once the word is free. */\n'
     '    if (!__atomic_compare_exchange_n(&lock->owner, &expected, 0, 0,\n'
     '                                     __ATOMIC_RELEASE, __ATOMIC_RELAXED)) return SERVICE_BAD_OWNER;\n'
     '    __atomic_store_n(&lock->serving, __atomic_load_n(&lock->serving, __ATOMIC_RELAXED) + 1,\n'
     '                     __ATOMIC_RELEASE);\n',
     '#endif\n    if (!__atomic_compare_exchange_n(&lock->owner, &expected, 0, 0,\n'
     '                                     __ATOMIC_RELEASE, __ATOMIC_RELAXED)) return SERVICE_BAD_OWNER;\n'
     '    __atomic_store_n(&lock->serving, __atomic_load_n(&lock->serving, __ATOMIC_RELAXED) + 1,\n'
     '                     __ATOMIC_RELEASE);\n'
     '    if (__atomic_load_n(&lock->readers, __ATOMIC_RELAXED) & SERVICE_GATE_WRITER)\n'
     '        __atomic_fetch_and(&lock->readers, ~SERVICE_GATE_WRITER, __ATOMIC_RELEASE);\n', PHASE_FAIR),
    ('phase-fair: an arrival not withdrawn at the bound (G3, G10)', 'tools/test-fine-locks.c',
     '                guest_service_leave_shared(&gate,t->cpu);\n                break;',
     '                break;', PHASE_FAIR),
]
# Each must fail the fairness run (an adversarial re-acquire loop).
FAIR_MUTANTS = [
    ('test-and-set stripe lock', [
        ('compat/fine-lock.h', '    return __atomic_fetch_add(&t->next, 1, __ATOMIC_RELAXED);\n}', '    (void)t;return 0;\n}'),
        ('compat/fine-lock.h',
         '    while (__atomic_load_n(&t->serving, __ATOMIC_ACQUIRE) != me) { waited = 1; FINE_RELAX(); }',
         '    (void)me;while (__atomic_exchange_n(&t->serving, 1, __ATOMIC_ACQUIRE)) { waited = 1; FINE_RELAX(); }'),
        ('compat/fine-lock.h',
         '    uint32_t now = __atomic_load_n(&t->serving, __ATOMIC_RELAXED);\n    __atomic_store_n(&t->serving, now + 1, __ATOMIC_RELEASE);',
         '    __atomic_store_n(&t->serving, 0, __ATOMIC_RELEASE);')]),
    ('a token turn that ignores the queue', [
        ('compat/service-lock.c',
         '    if (__atomic_load_n(&lock->serving, __ATOMIC_ACQUIRE) != ticket) return SERVICE_BUSY;\n', '')]),
]
# Each must fail the phase-fair fairness run.
PHASE_FAIR_MUTANTS = [
    ('phase-fair: a reader that waits for the writer bit, not its phase (G1, G5)', [
        ('compat/service-lock.c', '    if (writer && (unsigned)!!(gate&SERVICE_GATE_PHASE)==phase) return SERVICE_BUSY;',
         '    (void)phase;if (writer) return SERVICE_BUSY;')]),
    ('phase-fair: readers that ignore the writer (G4)', [
        ('compat/service-lock.c', 'SERVICE_GATE_BANK_SHIFT(!!(gate&SERVICE_GATE_PHASE)) : 0));', '0 : 0));'),
        ('compat/service-lock.c', '    return gate&SERVICE_GATE_WRITER ? SERVICE_BUSY : SERVICE_OK;', '    return SERVICE_OK;')]),
]
QUICK_MUTANTS = {'missing stripe', 'unsorted stripes', 'non-atomic count', 'token holder does not drain',
                 'phase-fair: a writer drains only the free bank (G1, G4)'}


class Mutants(unittest.TestCase):
    def test_each_mutant_fails(self):
        for n, (name, rel, old, new, extra) in enumerate(MUTANTS):
            if ARGS.quick and name not in QUICK_MUTANTS:
                continue
            text = read_source(ROOT / rel)
            self.assertEqual(text.count(old), 1, f'mutant {name} anchor')
            tree = WORK / f'mutant-{n}'
            for d in ('compat', 'shadow', 'tools'):
                shutil.copytree(ROOT / d, tree / d)
            (tree / rel).write_text(text.replace(old, new))
            caught = []
            for san in ('tsan', 'asan'):
                rc, out = harness(tree, san, extra, timeout=300)
                self.assertFalse(out.startswith('build:'), f'mutant {name} does not build: {out}')
                if rc:
                    caught.append(san)
            self.assertTrue(caught, f'mutant {name} survived both sanitizers')
            print(f'mutant {name}: caught by {", ".join(caught)}', file=sys.stderr)


class Cycle(unittest.TestCase):
    """cycle.py installed-fresh --fine-locks/--fine-switch/--fair-token."""
    def test_flags(self):
        installed, sets = installed_defines()
        import cycle_lib.installed_fresh as fresh  # noqa: E402  (installed_defines put tools on the path)
        from cycle_lib.common import Refused  # noqa: E402
        base = dict(variant='fast', root_cache_wide=True, update_disjoint_fast=True, service_subclass=True)
        flags = fresh.variant_flags(sets, argparse.Namespace(**base, fine_locks=True, fine_switch=True,
                                                             fair_token=True))
        self.assertEqual(flags[-3:], ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1', '-DSNAP_FAIR_TOKEN=1'])
        self.assertEqual(fresh.variant_flags(sets, argparse.Namespace(variant='control', fair_token=True))[-1],
                         '-DSNAP_FAIR_TOKEN=1')
        for missing in ('root_cache_wide', 'update_disjoint_fast', 'service_subclass'):
            with self.assertRaises(Refused):
                fresh.variant_flags(sets, argparse.Namespace(**dict(base, **{missing: False}), fine_locks=True))
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, argparse.Namespace(**dict(base, variant='control'), fine_switch=True))
        # --fast-pauth-calls: last, after every earlier define; needs --fine-locks.
        flags = fresh.variant_flags(sets, argparse.Namespace(**base, fine_locks=True, gate_wait=True,
                                                             fast_pauth_calls=True))
        self.assertEqual(flags[-2:], ['-DSNAP_GATE_WAIT=1', '-DSNAP_FAST_PAUTH_CALLS=1'])
        self.assertEqual(flags[:-1], fresh.variant_flags(sets, argparse.Namespace(**base, fine_locks=True,
                                                                                  gate_wait=True)))
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, argparse.Namespace(**base, fast_pauth_calls=True))
        spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
        cycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cycle)
        args = cycle.parse(['installed-fresh', '--prefix', 'x', '--check', '--variant', 'fast', '--fine-locks',
                            '--fine-switch', '--fair-token', '--fast-pauth-calls'])
        self.assertTrue(args.fine_locks and args.fine_switch and args.fair_token and args.fast_pauth_calls)
        # --phase-fair-gate: appended last; needs --fine-locks, --fair-token and --gate-wait.
        gate = dict(base, fine_locks=True, fine_switch=True, fair_token=True, gate_wait=True)
        flags = fresh.variant_flags(sets, argparse.Namespace(**gate, phase_fair_gate=True))
        self.assertEqual(flags[-1], '-DSNAP_PHASE_FAIR_GATE=1')
        self.assertEqual(flags[:-1], fresh.variant_flags(sets, argparse.Namespace(**gate)))
        for missing in ('fine_locks', 'fair_token', 'gate_wait'):
            with self.assertRaises(Refused):
                fresh.variant_flags(sets, argparse.Namespace(**dict(gate, **{missing: False}), phase_fair_gate=True))
        args = cycle.parse(['installed-fresh', '--prefix', 'x', '--check', '--variant', 'fast', '--fine-locks',
                            '--fair-token', '--gate-wait', '--phase-fair-gate'])
        self.assertTrue(args.phase_fair_gate)
        args = cycle.parse(['speed-test', '--prefix', 'x', '--check', '--phase-fair-gate'])
        self.assertTrue(args.phase_fair_gate)
        import cycle_lib.speed_test as speed  # noqa: E402
        self.assertEqual(speed.options_of(args), {'phase_fair_gate': True})
        fast = speed.speed_sets(ROOT, {'phase_fair_gate': True})[0]['fast']
        self.assertEqual(fast[-1], '-DSNAP_PHASE_FAIR_GATE=1')
        self.assertEqual(fast[:-1], speed.speed_sets(ROOT)[0]['fast'])


class Fairness(unittest.TestCase):
    """compat/fine-lock.h ticket locks and SNAP_FAIR_TOKEN under an adversarial
    re-acquire loop: a waiter is passed by at most the five CPUs already
    queued; readers cannot enter once a token holder has the word."""
    def fair(self, tree, san, fair_token=True, phase=False):
        extra = ['-DSNAP_FINE_SWITCH=1', f'-DSNAP_FAIR_TOKEN={int(fair_token)}'] + \
            (['-DSNAP_PHASE_FAIR_GATE=1'] if phase else [])
        return harness(tree, san, extra, calls='fair', seed='5000' if ARGS.quick else '20000', timeout=600)

    def test_bounded_waits(self):
        for san in ('tsan', 'asan'):
            rc, out = self.fair(ROOT, san)
            self.assertEqual(rc, 0, out[-2000:])
            self.assertIn('token (fair): at most', out)
            print(f'{san}: ' + '; '.join(l for l in out.splitlines() if 'at most' in l), file=sys.stderr)

    def test_phase_fair_bounds(self):
        # G5: a reader is passed by at most the writer present at its arrival;
        # G4: a token holder's drain sees at most one entry per other CPU.
        for san in ('tsan', 'asan'):
            rc, out = self.fair(ROOT, san, phase=True)
            self.assertEqual(rc, 0, out[-2000:])
            self.assertIn('gate (phase-fair): at most', out)
            print(f'{san} phase-fair: ' + '; '.join(l for l in out.splitlines() if 'at most' in l), file=sys.stderr)

    def test_phase_fair_mutants_fail(self):
        for n, (name, edits) in enumerate(PHASE_FAIR_MUTANTS):
            tree = WORK / f'phase-fair-mutant-{n}'
            for d in ('compat', 'shadow', 'tools'):
                shutil.copytree(ROOT / d, tree / d)
            for rel, old, new in edits:
                text = (tree / rel).read_text()
                self.assertEqual(text.count(old), 1, f'{name}: {old[:50]}')
                (tree / rel).write_text(text.replace(old, new))
            rc, out = self.fair(tree, 'asan', phase=True)
            self.assertFalse(out.startswith('build:'), f'{name} does not build: {out}')
            self.assertNotEqual(rc, 0, f'{name} survived: {out[-1500:]}')
            print(f'fairness mutant {name}: caught', file=sys.stderr)

    def test_default_token_reported(self):
        # Without SNAP_FAIR_TOKEN the token is the CAS word: reported, not bounded.
        rc, out = self.fair(ROOT, 'asan', fair_token=False)
        self.assertEqual(rc, 0, out[-2000:])
        print('default token: ' + [l for l in out.splitlines() if l.startswith('token:')][0], file=sys.stderr)

    def test_unfair_mutants_fail(self):
        for n, (name, edits) in enumerate(FAIR_MUTANTS):
            tree = WORK / f'fair-mutant-{n}'
            for d in ('compat', 'shadow', 'tools'):
                shutil.copytree(ROOT / d, tree / d)
            for rel, old, new in edits:
                text = (tree / rel).read_text()
                self.assertEqual(text.count(old), 1, f'{name}: {old[:50]}')
                (tree / rel).write_text(text.replace(old, new))
            rc, out = self.fair(tree, 'asan')
            self.assertFalse(out.startswith('build:'), f'{name} does not build: {out}')
            self.assertNotEqual(rc, 0, f'{name} survived: {out[-1500:]}')
            print(f'fairness mutant {name}: caught', file=sys.stderr)


class Mix(unittest.TestCase):
    """installed-fresh-20261020-v5's load on the real gate (tools/test-fine-locks.c
    "mix", plain -O2): the old gate against SNAP_PHASE_FAIR_GATE, same seeds. A
    timing model on the host: the waits are reported, only the fairness bound and
    a clean run are asserted."""
    SECONDS = '3' if ARGS.quick else '10'
    SEEDS = ('1',) if ARGS.quick else ('1', '2', '3')

    def run_mix(self, extra, seed, *more):
        binary = WORK / f'mix-{abs(hash(tuple(extra)))}'
        if not binary.exists():
            subprocess.run(['clang', '-std=gnu11', '-O2', '-pthread', '-ffunction-sections', '-Wl,-dead_strip',
                            '-Wall', '-Wextra', '-Werror',
                            '-DSNAP_FINE_LOCKS=1', '-Icompat', '-Ishadow', '-DSNAP_FINE_SWITCH=1',
                            '-DSNAP_FAIR_TOKEN=1', *extra, 'tools/test-fine-locks.c', *IMPL, '-o', str(binary)],
                           cwd=ROOT, check=True)
        out = subprocess.run([str(binary), 'mix', self.SECONDS, seed, *more], capture_output=True, text=True,
                             timeout=600)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        line = [l for l in out.stdout.splitlines() if l.startswith('mix ')][0]
        return json.loads(line[4:])

    def test_old_and_phase_fair(self):
        rows = []
        for seed in self.SEEDS:
            old = self.run_mix([], seed)
            new = self.run_mix(['-DSNAP_PHASE_FAIR_GATE=1'], seed)
            self.assertEqual((old['gate'], new['gate']), ('base', 'phase-fair'))
            self.assertLessEqual(new['passed_max'], 1, 'G5: a reader passed by more than one writer')
            rows += [old, new]
        for r in rows:
            print(f"mix {r['gate']:10} seed {r['seed']}: busy {r['token_busy']:.3f}  converted wait "
                  f"{r['reader_wait']['mean_us']:6.2f} us (p99 {r['reader_wait']['p99_us']:7.1f}, max "
                  f"{r['reader_wait']['max_us']:7.1f})  token wait {r['writer_wait']['mean_us']:6.2f} us (p99 "
                  f"{r['writer_wait']['p99_us']:7.1f})  drain {r['writer_drain']['mean_us']:5.2f} us  passed max "
                  f"{r['passed_max']} hist {r['passed_hist']}  ahead {r['ahead']}  timeouts {r['timeouts']}",
                  file=sys.stderr)
        if os.environ.get('FINE_LOCKS_MIX_JSON'):
            Path(os.environ['FINE_LOCKS_MIX_JSON']).write_text(json.dumps(rows, indent=1) + '\n')


def strip(text):
    """The text with every '#if SNAP_FINE_LOCKS' / '#if SNAP_FINE_SWITCH' /
    '#if SNAP_FAST_PAUTH_CALLS ...' branch removed and its '#else' kept: what a
    define-off build compiles."""
    out, stack = [], []
    for line in text.splitlines(keepends=True):
        s = line.strip()
        if s.startswith('#if'):
            fine = bool(re.fullmatch(r'#if (SNAP_FINE_LOCKS|SNAP_FINE_SWITCH|SNAP_FAIR_TOKEN|SNAP_PHASE_FAIR_GATE)'
                                     r'( \|\| (SNAP_FINE_LOCKS|SNAP_FINE_SWITCH|SNAP_FAIR_TOKEN))*', s) or
                        re.match(r'#if SNAP_FAST_PAUTH_CALLS\b', s) or
                        # agents/sptm-locks: SNAP_SPTM_FINE[_RETYPE|_KERNEL] blocks are fine-lock code too.
                        re.match(r'#if !?SNAP_SPTM_FINE(_RETYPE|_KERNEL)?\b', s))
            stack.append(('fine' if fine else 'other', fine))
            if fine:
                continue
        elif s.startswith('#else') and stack and stack[-1][0] == 'fine':
            stack[-1] = ('fine', False)
            continue
        elif s.startswith('#endif') and stack:
            kind, _ = stack.pop()
            if kind == 'fine':
                continue
        if any(kind == 'fine' and skip for kind, skip in stack):
            continue
        out.append(line)
    return ''.join(out)


def effective(defines):
    """probes/xnuboot.c preprocessed with the monitor's flags (macros expanded)."""
    return subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                           '-E', '-P', '-Ishadow', '-Icompat', f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines,
                           'probes/xnuboot.c'], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def functions(code):
    out = {}
    for m in re.finditer(r'^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w \*]*?\b(\w+)\s*\([^;{}]*\)\s*\{', code, re.M):
        name, i, depth = m[1], m.end() - 1, 0
        start = i
        while i < len(code):
            depth += code[i] == '{'
            depth -= code[i] == '}'
            i += 1
            if not depth:
                break
        out.setdefault(name, code[start:i])
    return out


IGNORED = {'fine_add', 'fine_sat_add', 'sprr_count', 'fine_view_failed', 'fine_failed', 'fine_aux_lock',
           'fine_aux_unlock', 'fine_cpu', 'fine_of', 'detail_begin', 'detail_end', 'sizeof', 'if', 'for',
           'while', 'return', 'switch', 'vcpu_of', '__asm__', '__builtin_ctzll', 'int', 'uint64_t'}
RENAMED = {'sprr_table_memo_note_fine': 'sprr_table_memo_note', 'root_publish_note_fine': 'root_publish_note',
           'txn_publish_observe_fine': 'txn_publish_observe', 'sprr_private_write_fine': 'sprr_private_write',
           'sprr_view_epoch_advance_fine': 'sprr_view_epoch_advance', 'fine_memory': 'sptm_context_memory'}


def calls(body):
    """The ordered calls and asm templates of a function body."""
    seq = []
    for m in re.finditer(r'__asm__\s+volatile\s*\(\s*"([^"]*)"|\b([A-Za-z_]\w*)\s*\(', body):
        if m[1] is not None:
            seq.append('asm:' + ' '.join(m[1].split()))
        elif not m[2].startswith('__atomic') and m[2] not in IGNORED:
            name = RENAMED.get(m[2], m[2])
            seq.append(name[5:] if name.startswith('fine_') else name)
    return seq


# fine copy -> (token-path original, calls only in the original, calls only in the copy)
MIRRORS = {
    'fine_native_tlbi_range': ('native_tlbi_range', [], []),
    'fine_native_store_admit': ('native_store_admit', [], []),
    'fine_user_private_write': ('user_private_write', [], []),
    'fine_kernel_table_write': ('kernel_table_write', ['sprr_publish_note'], ['native_page']),
    'fine_native_copy_write': ('native_copy_write', [], []),
    'fine_native_live_shadow': ('native_live_shadow', [], []),
    'fine_native_store_propagate': ('native_store_propagate', [], []),
    'fine_mem_write': ('mem_write', [], ['sprr_class_proof_tracked']),
    'fine_user_live_write': ('user_live_write', [], []),
    'fine_sptm_publish': ('sptm_publish', [], []),
    'fine_user_refresh_all': ('user_refresh_all', [], []),
    'fine_user_commit_tlb_range': ('user_commit_tlb_range', [], []),
    'fine_user_prepare_leaf': ('user_prepare_leaf', ['native_prepare_tpro'], ['live_shadow']),
    'fine_user_commit_leaf': ('user_commit_leaf', [], ['live_shadow']),
    'fine_user_prepare_unmap': ('user_prepare_unmap', [], ['live_shadow']),
    'fine_user_prepare_update': ('user_prepare_update', ['native_prepare_tpro'], []),
    'fine_user_commit_update': ('user_commit_update', ['user_tlb_range'], ['live_shadow', 'native_tlbi_range']),
    'fine_user_commit_unmap': ('user_commit_unmap', [], ['live_shadow']),
    'fine_user_backend': ('user_backend', [], ['lockset_has']),
    'fine_user_install_view': ('user_install_view', ['user_view_shadow', 'native_umprr', 'native_views_sync',
                                                     'native_mark', 'publish'], []),
    'fine_user_root_install': ('user_root_install', ['kernel_change_pperm_timed', 'root_publish_flush',
                                                     'asm:dsb ish'], ['install_publish']),
    'fine_install_failed': ('install_failed', [], []),
}
# What no converted call may reach: token-path state changes and the token.
FORBIDDEN = {'transaction_publish', 'root_publish_flush', 'txn_publish_flush', 'arena_reclaim', 'arena_reserve',
             'table_alloc_owned', 'table_alloc', 'user_table_alloc', 'private_table_alloc_owned', 'user_root_build',
             'kernel_change_pperm', 'kernel_change_pperm_timed', 'kernel_change_pperm_impl', 'shadow_tlb_sync',
             'kernel_refresh', 'user_install_view', 'native_prepare_tpro', 'root_slot_release',
             'sptm_root_invalidate', 'inactive_map_keep', 'guest_service_try', 'runtime_enter',
             'native_mark', 'native_views_sync', 'sptm_mac_retype', 'sptm_mac_switch_root', 'user_root_install',
             'mem_write', 'user_live_write', 'kernel_table_write', 'user_private_write', 'sptm_publish',
             'native_group_alloc', 'native_shared_create', 'native_root_created'}


def effective_of(text, defines):
    """effective() of a probes/xnuboot.c text, in a scratch tree."""
    tree = WORK / f'src-{hashlib.sha256(text.encode()).hexdigest()[:12]}'
    if not tree.exists():
        (tree / 'probes').mkdir(parents=True)
        for d in ('compat', 'shadow', 'gpu'):
            if (ROOT / d).exists():
                (tree / d).symlink_to(ROOT / d)
        for f in (ROOT / 'probes').iterdir():
            if f.suffix == '.h':
                (tree / 'probes' / f.name).symlink_to(f)
        (tree / 'probes/xnuboot.c').write_text(text)
    return subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                           '-E', '-P', '-Ishadow', '-Icompat', f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines,
                           'probes/xnuboot.c'], cwd=tree, capture_output=True, text=True, check=True).stdout


def source_problems(text):
    """Every reason probes/xnuboot.c's converted calls would differ from the
    token path they repeat, or reach token-path state. Empty means none."""
    p = []
    trap = text[text.index('int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)\n{'):]
    trap = trap[:trap.index('\n}\n')]
    if not trap.find('fast_idle_poll(c, frame, esr, elr)') < trap.find('fine_sptm_call(') < trap.find('runtime_enter('):
        p.append('fine_sptm_call is not between the fast paths and runtime_enter')
    enter = text[text.index('static int runtime_enter(struct context *c'):]
    enter = enter[:enter.index('\n}\n')]
    if 'if (result == SERVICE_OK && !guest_service_drained(&c->services)) {' not in enter or \
            not enter.find('guest_service_drained') < enter.find('service_profile_wait_done'):
        p.append('runtime_enter does not drain converted calls before its wait accounting')
    flags, _ = installed_defines()
    fns = functions(effective_of(text, [f for f in flags if f.startswith('-D')] +
                                 ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1']))
    for fine, (orig, only_orig, only_fine) in MIRRORS.items():
        if fine not in fns or orig not in fns:
            p.append(f'{fine} or {orig} missing')
            continue
        a, b = calls(fns[orig]), calls(fns[fine])
        for name in only_orig:
            if name in a:
                a.remove(name)
            else:
                p.append(f'{orig}: {name} is no longer there')
        for name in only_fine:
            if name in b:
                b.remove(name)
            else:
                p.append(f'{fine}: {name} is no longer there')
        if a != b:
            p.append(f'{fine} does not repeat {orig}: {b} != {a}')
    # Direct calls, and the converted callbacks handed to the engines (a
    # fine_* name used as a value); fine_fatal takes the token only after
    # leaving the gate (checked below).
    seen, todo = set(), ['fine_sptm_call']
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name)
        for m in re.finditer(r'\b([A-Za-z_]\w*)\b(\s*\()?', fns[name]):
            callee = m[1]
            if callee in fns and callee != 'fine_fatal' and (m[2] or callee.startswith('fine_')):
                todo.append(callee)
    if seen & FORBIDDEN:
        p.append(f'converted calls reach {sorted(seen & FORBIDDEN)}')
    for need in ('fine_user_commit_update', 'fine_user_commit_leaf', 'fine_user_commit_unmap',
                 'fine_mem_write', 'fine_user_root_install', 'fine_install_publish'):
        if need not in seen:
            p.append(f'{need} not reached')
    reached = ''.join(fns[n] for n in seen)
    for engine in ('sptm_mac_update_user_disjoint', 'sptm_mac_map_user_page', 'sptm_mac_unmap_user_region',
                   'sptm_mac_switch_root_hit'):
        if engine not in reached:
            p.append(f'{engine} not reached')
    # Every shadow, memory and backend a converted call builds carries the
    # converted writers, allocator and publisher (a token-path callback left
    # in one would be reached through the engines).
    if '.alloc=fine_refuse_alloc,\n        .read=mem_read,.write=fine_user_live_write,' not in \
            text[text.index('static struct shadow fine_live_shadow('):]:
        p.append('fine_live_shadow does not carry the converted writer and allocator')
    if 's.alloc=fine_refuse_alloc;s.write=fine_native_copy_write;return s;' not in text:
        p.append('fine_native_live_shadow does not carry the converted writer and allocator')
    if 'm.publish=fine_sptm_publish;m.refs=&fine_of(c)->refs[vcpu_of(c)->slot];\n' \
            '    m.audit=&f->audit;m.fine=&f->ref_fine;m.clean_frame=0;' not in text:
        p.append('fine_memory does not carry this CPU\'s batch, snapshots, audit and publisher')
    for fn in ('fine_map_page', 'fine_unmap_region', 'fine_update_disjoint', 'fine_user_commit_leaf',
               'fine_user_prepare_unmap', 'fine_user_commit_update', 'fine_switch_root'):
        if 'sptm_context_memory(' in fns.get(fn, ''):
            p.append(f'{fn} builds a token-path memory')
    backend = fns.get('fine_user_backend', '')
    for field in ('prepare_leaf', 'commit_leaf', 'prepare_unmap', 'commit_unmap', 'prepare_update',
                  'commit_update'):
        if f'b->{field}=fine_user_{field};' not in backend:
            p.append(f'fine_user_backend lacks fine_user_{field}')
    if 'shared' in backend.replace('guest_ttbr1', '') or 'lockset_has' not in backend:
        p.append('fine_user_backend admits shared roots or roots outside the lockset')
    call = fns.get('fine_sptm_call', '')
    if not call.rindex('guest_service_leave_shared') < call.index('fine_fatal('):
        p.append('fine_fatal takes the token before the gate is left')
    p += phase_fair_problems(text)
    # A store to a context word is per CPU, per root (under its stripe) or
    # under aux; everything else is atomic.
    block = text[text.index('/* ---- SNAP_FINE_LOCKS: converted user address-space calls'):]
    block = block[:block.index('int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr);')]
    for fn, body in functions(block).items():
        aux = False
        for line in body.splitlines():
            if 'fine_aux_lock(c);' in line:
                aux = True
            for m in re.finditer(r'\bc->((?:\w|\.|->|\[[^\]]*\])+)\s*(\+\+|\+=|-=|(?<![<>!=])=(?!=))', line):
                target = m[1]
                if aux or re.match(r'\w+\[(v->slot|vcpu_of\(c\)->slot|cpu)\]', target) or \
                        target.startswith('root_ext->fine'):
                    continue
                p.append(f'{fn}: plain store c->{target}{m[2]}')
            if 'fine_aux_unlock(c);' in line:
                aux = False
    return p


def phase_fair_problems(text):
    """SNAP_PHASE_FAIR_GATE in probes/xnuboot.c (raw text: the define is off in
    the effective source above): the bounded wait polls the announced arrival
    with guest_service_wait_shared, withdraws it at the bound before declining
    (G3, G10), counts phase entries, and the define refuses to build without
    SNAP_GATE_WAIT."""
    p = []
    call = text[text.index('static int fine_sptm_call(struct context *c'):]
    call = call[:call.index('\n}\n')]
    loop = call[call.index('    for(int waited=0;;waited=1) {'):]
    loop = loop[:loop.index('    if(gate!=SERVICE_OK) {f->profile.declined[FINE_NO_GATE]++;return 0;}')]
    if '#if SNAP_PHASE_FAIR_GATE\n        gate=waited ? guest_service_wait_shared(&c->services,v->slot,&ahead) :\n' \
            '                      guest_service_enter_shared(&c->services,v->slot);\n#else' not in loop:
        p.append('the phase-fair wait does not poll its announced arrival with guest_service_wait_shared')
    bound = loop[loop.index('if((int64_t)(now-t0-c->params->clock_host_hz/200)>=0'):]
    bound = bound[:bound.index('break;')]
    if '#if SNAP_PHASE_FAIR_GATE\n            guest_service_leave_shared(&c->services,v->slot);' not in bound:
        p.append('the phase-fair wait declines at its bound without withdrawing its arrival')
    if 'if(ahead)fine_add(&c->root_ext->gate[4],1);' not in loop:
        p.append('phase entries are not counted')
    if '#if SNAP_PHASE_FAIR_GATE && !SNAP_GATE_WAIT\n#error' not in text:
        p.append('SNAP_PHASE_FAIR_GATE builds without SNAP_GATE_WAIT')
    return p


# Each weakened source must be caught by source_problems.
SOURCE_MUTANTS = {
    'a live store left unpublished': ('    int result=fine_mem_write(ctx,pa,value);\n    if(!result)publish(pa,pa+8);',
                                      '    int result=fine_mem_write(ctx,pa,value);'),
    'an update without its TLBI': ('    fine_native_tlbi_range(c,va,UINT64_C(1)<<shift);return !fine_failed(c);',
                                   '    return !fine_failed(c);'),
    'a store without its dirty note': ('        if(!root_publish_note_fine(&c->root_publish,c->work_base,c->next_table,pa,8))return -1;\n', ''),
    'a converted call flushes globally': ('    (void)p;\n    fine_add(&c->user_update_skip.skipped,1);',
                                          '    (void)p;transaction_publish(c);\n    fine_add(&c->user_update_skip.skipped,1);'),
    'a plain global counter': ('fine_add(&c->update_calls,1);', 'c->update_calls++;'),
    'a token-path writer in a converted shadow': ('.read=mem_read,.write=fine_user_live_write,.ctx=c,',
                                                  '.read=mem_read,.write=user_live_write,.ctx=c,'),
    'a token-path copy writer': ('    return fine_kernel_table_write(c,pa,value);\n}',
                                 '    return kernel_table_write(c,pa,value);\n}'),
    'a token holder that does not drain': ('    if (result == SERVICE_OK && !guest_service_drained(&c->services)) {',
                                           '    if (0) {'),
    'the backend outside the lockset': ('    if(!fine_lockset_has(&fine_cpu(c)->locks,root))return 0;\n', ''),
    'a phase-fair arrival not withdrawn at the bound': (
        '#if SNAP_PHASE_FAIR_GATE\n            guest_service_leave_shared(&c->services,v->slot);   /* withdraw the arrival */\n#endif\n',
        ''),
    'a phase-fair wait that re-arrives': ('        gate=waited ? guest_service_wait_shared(&c->services,v->slot,&ahead) :\n'
                                          '                      guest_service_enter_shared(&c->services,v->slot);',
                                          '        gate=guest_service_enter_shared(&c->services,v->slot);'),
    'a switch that keeps the global flush': ('    if(!fine_install_publish(c,owner)) {fine_install_failed(c,deferred);return;}',
                                             '    if(!root_publish_flush(&c->root_publish,c->work_base,c->next_table,'
                                             'publish_page_lines,c)) {fine_install_failed(c,deferred);return;}'),
}


class Source(unittest.TestCase):
    def test_define_off_text(self):
        for rel in CHANGED:
            off = strip(read_source(ROOT / rel))
            for token in ('SNAP_FINE', 'fine_', 'FINE_', 'fine-lock.h', '_fine', 'SNAP_FAIR', 'try_turn',
                          'guest_service_queue', 'user_pointer_'):
                self.assertNotIn(token, off, f'{rel}: {token} outside the defines')
        self.assertIn('#ifndef SNAP_FINE_LOCKS\n#define SNAP_FINE_LOCKS 0\n#endif', (ROOT / 'compat/fine-lock.h').read_text())

    def test_phase_fair_define_off_text(self):
        # SNAP_PHASE_FAIR_GATE's code only inside its own blocks (checked on its
        # tokens alone: test_define_off_text stops at xnuboot.c's pre-existing
        # '#elif SNAP_FINE_LOCKS' report-offset chains).
        for rel in CHANGED + ['compat/fine-lock.h', 'compat/token-costs.h']:
            off = strip(read_source(ROOT / rel))
            for token in ('wait_shared', 'SERVICE_GATE_', 'drain_from', 'ahead)', 'gate[4]', 'gate[5]', 'gate[6]',
                          'UINT64_C(1) << 5'):
                self.assertNotIn(token, off, f'{rel}: {token} outside SNAP_PHASE_FAIR_GATE')
        self.assertIn('#ifndef SNAP_PHASE_FAIR_GATE\n#define SNAP_PHASE_FAIR_GATE 0\n#endif',
                      (ROOT / 'compat/fine-lock.h').read_text())

    def test_monitor_source(self):
        self.assertEqual(source_problems(SOURCE), [])

    def test_weakened_sources_are_caught(self):
        for name, (old, new) in SOURCE_MUTANTS.items():
            self.assertEqual(SOURCE.count(old), 1, name)
            self.assertNotEqual(source_problems(SOURCE.replace(old, new)), [], name)

    def test_profile_decoder(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        flags, _ = installed_defines()
        defines = [f for f in flags if f.startswith('-D')] + ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1']
        lay = perf['fine_layout'](defines)
        writer = WORK / 'writer.c'
        writer.write_text(r'''
#include <stdio.h>
#include "fine-lock.h"
static struct fine_profile p[6];
int main(int argc,char **argv)
{
    (void)argc;
    for(unsigned cpu=0;cpu<6;cpu++) {
        for(unsigned k=0;k<FINE_CALLS;k++) {
            struct fine_bucket *b=&p[cpu].call[k];
            b->entries=100*cpu+k+1;b->gate_wait=2*b->entries;b->stripe_wait=3*b->entries;
            b->aux_wait=b->entries;b->hold=10*b->entries;b->contended=k;
        }
        for(unsigned d=0;d<FINE_DECLINES;d++)p[cpu].declined[d]=cpu+d;
        p[cpu].aux_entries=50;p[cpu].aux_contended=5;p[cpu].failures=0;
    }
    unsigned long long head[2]={FINE_PROFILE_MAGIC,(unsigned long long)sizeof(struct fine_profile)<<32|BITS};
    FILE *f=fopen(argv[1],"wb");fwrite(head,sizeof head,1,f);fwrite(p,sizeof p,1,f);fclose(f);
    return 0;
}
''')
        def blob_of(name, extra, bits):
            binary, blob = WORK / f'writer-{name}', WORK / f'fine-{name}.bin'
            subprocess.run(['clang', '-std=gnu11', '-DSNAP_FINE_LOCKS=1', f'-DBITS={bits}', *extra, '-Icompat',
                            str(writer), '-o', str(binary)], cwd=ROOT, check=True)
            subprocess.run([str(binary), str(blob)], check=True)
            return blob.read_bytes()
        record = blob_of('switch', [], 1)
        out = perf['decode_fine_profile'](record, lay=lay, hz=19.2e6)
        self.assertTrue(out['switch'])
        self.assertFalse(out['pauth'])
        self.assertEqual(out['calls']['update_disjoint']['entries'], sum(100 * c + 1 for c in range(6)))
        self.assertEqual(out['calls']['switch_kernel']['hold'], sum(10 * (100 * c + 5) for c in range(6)))
        self.assertEqual(out['declined']['switch'], sum(c + 8 for c in range(6)))
        bad = bytearray(record)
        bad[0] ^= 1
        with self.assertRaises(ValueError):
            perf['decode_fine_profile'](bytes(bad), lay=lay)
        with self.assertRaises(ValueError):
            perf['decode_fine_profile'](record[:-8], lay=lay)
        offset, size = perf['fine_profile_spec'](defines)
        exit_offset, exit_size = perf['exit_profile_spec'](defines)
        self.assertEqual((offset, size), (exit_offset + exit_size, 16 + 6 * lay['size']))
        # SNAP_FAST_PAUTH_CALLS: the two pointer buckets after the five, the
        # header's bit 1 set; a bit that disagrees with the layout is refused.
        pauth = defines + ['-DSNAP_FAST_PAUTH_CALLS=1']
        lay7 = perf['fine_layout'](pauth)
        self.assertEqual(lay7['calls'][-2:], ('pauth', 'pauth_batch'))
        self.assertEqual(lay7['declined'] - lay7['call'], lay['declined'] - lay['call'] + 2 * lay['bucket'])
        self.assertEqual((lay7['call'], lay7['bucket']), (lay['call'], lay['bucket']))
        record7 = blob_of('pauth', ['-DSNAP_FAST_PAUTH_CALLS=1'], 3)
        out = perf['decode_fine_profile'](record7, lay=lay7, hz=19.2e6)
        self.assertTrue(out['switch'] and out['pauth'])
        self.assertEqual(out['calls']['pauth']['entries'], sum(100 * c + 6 for c in range(6)))
        self.assertEqual(out['calls']['pauth_batch']['hold'], sum(10 * (100 * c + 7) for c in range(6)))
        self.assertEqual(out['calls']['update_disjoint']['entries'], sum(100 * c + 1 for c in range(6)))
        self.assertEqual(out['declined']['switch'], sum(c + 8 for c in range(6)))
        for wrong, wrong_lay in ((blob_of('pauth-unmarked', ['-DSNAP_FAST_PAUTH_CALLS=1'], 1), lay7),
                                 (blob_of('marked', [], 3), lay)):
            with self.assertRaises(ValueError):
                perf['decode_fine_profile'](wrong, lay=wrong_lay)
        offset7, size7 = perf['fine_profile_spec'](pauth)
        self.assertEqual((offset7, size7), (exit_offset + exit_size, 16 + 6 * lay7['size']))
        self.assertEqual(perf['token_costs_spec'](pauth + ['-DSNAP_GATE_WAIT=1'])[0], offset7 + size7)


# ---- SNAP_FAST_PAUTH_CALLS: the converted pointer calls --------------------
PAUTH_C = 'tools/test-fast-pauth-calls.c'
PAUTH_IMPL = ['compat/pauth-pointer.c', 'compat/pauth-batch.c', 'compat/pauth-domain.c', 'compat/pauth-user.c',
              'compat/aes.c']
PAUTH_TCR = '__asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));'
PAUTH_CASES = ('    case SPTM_FN_SIGN_USER_POINTER:\n    case SPTM_FN_AUTH_USER_POINTER: {',
               '    case SPTM_FN_SWITCH_ROOT: {')
# What the shared signing bodies may name in the context: this CPU's records
# (indexed by its slot) and the boot-fixed domain.
POINTER_STATE = {'pauth_bank', 'user_pauth', 'pauth_derive', 'pauth_pointer', 'pauth_batch'}
POINTER_FIXED = {'pauth_domain', 'aes_hardware'}


def definition(text, name):
    """The whole definition of the static function name in text, signature
    through closing brace; LookupError when there is none."""
    m = re.search(r'^static\b[^;{}()]*?\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{', text, re.M)
    if not m:
        raise LookupError(f'probes/xnuboot.c has no {name}')
    i, depth = m.end() - 1, 0
    while True:
        depth += text[i] == '{'
        depth -= text[i] == '}'
        i += 1
        if not depth:
            return text[m.start():i] + '\n'


def pauth_extract(text):
    """pauth-extract.h for tools/test-fast-pauth-calls.c: the monitor's own code
    for every path -- monitor_call_impl's pointer cases twice (as the default
    build and as the define-on build compile them), the helpers, the native
    sign callbacks and the converted calls -- with TCR_EL1 read from the model.
    LookupError when the source has no converted pointer calls."""
    defines = re.findall(r'^#define SPTM_FN_(?:BATCH_SIGN|SIGN|AUTH)_USER_POINTER \d+\n', text, re.M)
    native = re.search(r'^struct pauth_batch_native \{[^\n]*\};\n', text, re.M)
    state = re.search(r'^enum \{FINE_DECLINE,FINE_DONE,FINE_FATAL\};\nstruct fine_call_state \{.*?\n\};\n', text,
                      re.M | re.S)
    if len(defines) != 3 or not native or not state or text.count(PAUTH_CASES[0]) != 1:
        raise LookupError('the pointer endpoints, their native context, the converted-call state or the cases')
    start = text.index(PAUTH_CASES[0])
    cases = text[start:text.index(PAUTH_CASES[1], start)]

    def locked(name, on):
        return (f'#undef SNAP_FAST_PAUTH_CALLS\n#define SNAP_FAST_PAUTH_CALLS {on}\n'
                f'static int {name}(struct context *c,uint64_t *frame,uint64_t *elr,'
                'struct guest_cpu_buffer cpu_scratch)\n{\n    uint32_t endpoint=(uint32_t)frame[16];\n'
                '    switch (endpoint) {\n' + cases + '    default: return -1;\n    }\n'
                '    c->calls++;\n    *elr += 4;\n    return 1;\n}\n')
    out = (''.join(defines) + native[0] +
           ''.join(definition(text, n) for n in ('pauth_batch_native_sign', 'pauth_pointer_native_sign',
                                                 'user_pointer_call', 'user_pointer_batch')) +
           state[0] + ''.join(definition(text, n) for n in ('fine_pauth_pointer', 'fine_pauth_batch')) +
           locked('locked_off', 0) + locked('locked_on', 1) + '#undef SNAP_FAST_PAUTH_CALLS\n'
           '#define SNAP_FAST_PAUTH_CALLS 1\n')
    if out.count(PAUTH_TCR) != 6:
        raise LookupError(f'{out.count(PAUTH_TCR)} TCR_EL1 reads, not the helpers\' two and the cases\' four')
    return out.replace(PAUTH_TCR, 'tcr=c->tcr;')


def pauth_differential(text, cases='20000', seed='11'):
    """Build tools/test-fast-pauth-calls.c on text's extracted pointer calls
    (ASan/UBSan) and run it: (returncode, output)."""
    try:
        header = pauth_extract(text)
    except LookupError as error:
        return 2, f'extract: {error}'
    d = WORK / f'pauth-{hashlib.sha256(text.encode()).hexdigest()[:12]}'
    d.mkdir(exist_ok=True)
    (d / 'pauth-extract.h').write_text(header)
    binary = d / 'differential'
    build = subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', *SAN['asan'],
                            '-DSNAP_FINE_LOCKS=1', '-DSNAP_FAST_PAUTH_CALLS=1', '-Icompat', '-Ishadow', f'-I{d}',
                            PAUTH_C, *PAUTH_IMPL, '-o', str(binary)], cwd=ROOT, capture_output=True, text=True)
    if build.returncode:
        return build.returncode, 'build: ' + build.stderr[-3000:]
    run = subprocess.run([str(binary), cases, seed], capture_output=True, text=True, timeout=600)
    return run.returncode, run.stdout + run.stderr


def pauth_problems(text):
    """Every reason probes/xnuboot.c's converted pointer calls would not be the
    locked path's, or would reach stripes, shared or token-path state; and the
    default build's cases. Empty means none."""
    p = []
    flags, _ = installed_defines()
    base = [f for f in flags if f.startswith('-D')] + ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1']
    fns = functions(effective_of(text, base + ['-DSNAP_FAST_PAUTH_CALLS=1']))
    off = effective_of(text, base)
    value = dict(re.findall(r'^#define SPTM_FN_(\w+)\s+(\d+)\s*$', text, re.M))
    sign, auth, batch, switch = (value.get(n, 'none') for n in ('SIGN_USER_POINTER', 'AUTH_USER_POINTER',
                                                                'BATCH_SIGN_USER_POINTER', 'SWITCH_ROOT'))
    call = fns.get('fine_sptm_call', '')
    # Classified and dispatched.
    if not re.search(rf'case\s+{sign}\s*:\s*case\s+{auth}\s*:\s*kind\s*=\s*FINE_CALL_PAUTH\s*;', call) or \
            not re.search(rf'case\s+{batch}\s*:\s*kind\s*=\s*FINE_CALL_PAUTH_BATCH\s*;', call):
        p.append('fine_sptm_call does not classify SIGN/AUTH as FINE_CALL_PAUTH and BATCH_SIGN as '
                 'FINE_CALL_PAUTH_BATCH')
    if not re.search(r'kind\s*==\s*FINE_CALL_PAUTH\s*\?\s*fine_pauth_pointer\(c,frame,&s\)', call) or \
            not re.search(r'kind\s*==\s*FINE_CALL_PAUTH_BATCH\s*\?\s*fine_pauth_batch\(c,frame,&cpu_scratch,&s\)',
                          call):
        p.append('fine_sptm_call does not dispatch the pointer kinds to fine_pauth_pointer and fine_pauth_batch')
    # One signing body: the locked cases and the converted calls run the
    # helpers, neither an engine of its own.
    impl = fns.get('monitor_call_impl', '')
    m = re.search(rf'case\s+{sign}\s*:\s*case\s+{auth}\s*:\s*\{{', impl)
    n = re.search(rf'case\s+{switch}\s*:', impl[m.end():]) if m else None
    cases = impl[m.start():m.end() + n.start()] if m and n else ''
    engines = ('pauth_pointer', 'pauth_batch_sign', 'pauth_domain_user_cached')
    for body, name, helpers in ((cases, 'the locked cases', ('user_pointer_call', 'user_pointer_batch')),
                                (fns.get('fine_pauth_pointer', ''), 'fine_pauth_pointer', ('user_pointer_call',)),
                                (fns.get('fine_pauth_batch', ''), 'fine_pauth_batch', ('user_pointer_batch',))):
        seq = calls(body)
        if not body or any(h not in seq for h in helpers) or any(e in seq for e in engines):
            p.append(f'{name}: not the shared signing body ({seq})')
    # The helpers: this CPU's records and the boot-fixed domain, nothing
    # recorded, no reference audit.
    for name in ('user_pointer_call', 'user_pointer_batch'):
        body = fns.get(name, '')
        used = re.findall(r'\bc->(\w+)(\[[^\]]*\])?', body)
        if not body or any(f not in POINTER_STATE | POINTER_FIXED for f, _ in used) or \
                any(f in POINTER_STATE and index != '[v->slot]' for f, index in used):
            p.append(f'{name} reaches more than this CPU\'s signing state and the domain: {used}')
        if 'record(' in body or 'pv_audit' in body:
            p.append(f'{name} records or touches pv_audit')
    # No stripe: the pointer kinds leave fine_lockset_for before any root
    # lookup or stripe.
    lockset = fns.get('fine_lockset_for', '')
    first = min((lockset.find(t) for t in ('hw_root(', 'fine_user_root(', 'fine_lockset_add(') if t in lockset),
                default=len(lockset))
    guard = re.search(r'if\s*\(\s*\(\s*\(s->kind\)\s*==\s*FINE_CALL_PAUTH\s*\|\|\s*\(s->kind\)\s*==\s*'
                      r'FINE_CALL_PAUTH_BATCH\s*\)\s*\)\s*\{\s*fine_lockset_init\(set\);\s*return 1;\s*\}', lockset)
    if not guard or guard.start() > first:
        p.append('a pointer call reaches a root lookup or a stripe in fine_lockset_for')
    # The epilogue leaves pv_audit.pending alone; a failure latches no view.
    pointer = r'\(\s*\({0}\)\s*==\s*FINE_CALL_PAUTH\s*\|\|\s*\({0}\)\s*==\s*FINE_CALL_PAUTH_BATCH\s*\)'
    if not re.search(r'if\s*\(\s*!\s*' + pointer.format('kind') + r'\s*\)\s*pv->pending\s*=\s*0\s*;', call):
        p.append('the converted epilogue clears pv_audit.pending for a pointer call')
    if not re.search(r'if\s*\(\s*!\s*' + pointer.format(r's->kind') + r'\s*\)\s*fine_view_failed\(c\);',
                     fns.get('fine_fatal', '')):
        p.append('a pointer call\'s failure latches a view failure')
    batch_body = fns.get('fine_pauth_batch', '')
    if 'sptm_context_memory(' in batch_body or 'fine_memory(' not in batch_body:
        p.append('fine_pauth_batch builds a token-path memory')
    # Nothing token-only reached from the converted pointer calls.
    seen, todo = set(), ['fine_pauth_pointer', 'fine_pauth_batch']
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name)
        for found in re.finditer(r'\b([A-Za-z_]\w*)\b(\s*\()?', fns[name]):
            if found[1] in fns and (found[2] or found[1].startswith('fine_')):
                todo.append(found[1])
    if seen & FORBIDDEN:
        p.append(f'converted pointer calls reach {sorted(seen & FORBIDDEN)}')
    for need in ('user_pointer_call', 'user_pointer_batch', 'fine_memory', 'fine_sptm_publish'):
        if need not in seen:
            p.append(f'{need} not reached from the converted pointer calls')
    if '(uint64_t)SNAP_FAST_PAUTH_CALLS << 1 |' not in text:
        p.append('the fine profile header does not say which bucket layout follows')
    # The default build: no pointer conversion, its inline cases.
    for token in ('FINE_CALL_PAUTH', 'fine_pauth_', 'user_pointer_call', 'user_pointer_batch'):
        if token in off:
            p.append(f'{token} in a build without SNAP_FAST_PAUTH_CALLS')
    inline = calls(functions(off).get('monitor_call_impl', ''))
    if 'pauth_pointer' not in inline or 'pauth_batch_sign' not in inline:
        p.append('the default build lost its inline signing cases')
    return p


# Each weakened binding must be caught by pauth_problems: (old, new).
PAUTH_SOURCE_MUTANTS = {
    'SIGN/AUTH not converted':
        ('    case SPTM_FN_SIGN_USER_POINTER: case SPTM_FN_AUTH_USER_POINTER: kind=FINE_CALL_PAUTH;break;\n', ''),
    'BATCH_SIGN not dispatched':
        ('               kind==FINE_CALL_PAUTH_BATCH ? fine_pauth_batch(c,frame,&cpu_scratch,&s) :\n', ''),
    'a converted call with its own signing copy':
        ('    enum sptm_result r=user_pointer_call(c,frame,(uint32_t)s->x16,&ran);\n',
         '    enum sptm_result r=pauth_pointer(frame[0],frame[1],frame[2],0,0,0,0,0,'
         '&c->pauth_pointer[vcpu_of(c)->slot]);ran=1;\n'),
    'a locked case with its own signing copy':
        ('        enum sptm_result result=user_pointer_call(c,frame,endpoint,&ran);\n',
         '        enum sptm_result result=pauth_pointer(frame[0],frame[1],frame[2],0,0,0,0,0,'
         '&c->pauth_pointer[v->slot]);(void)ran;\n'),
    'a pointer call takes a stripe': ('    if(FINE_POINTER_CALL(s->kind)) {fine_lockset_init(set);return 1;}\n', ''),
    'the epilogue clears pv_audit.pending for a pointer call':
        ('            if(!FINE_POINTER_CALL(kind))\n#endif\n            pv->pending=0;',
         '#endif\n            pv->pending=0;'),
    'a pointer failure latches a view failure':
        ('    if(!FINE_POINTER_CALL(s->kind))\n#endif\n    fine_view_failed(c);', '#endif\n    fine_view_failed(c);'),
    'the converted batch publishes through the token path':
        ('    struct sptm_memory memory=fine_memory(c);\n    int ran=0;',
         '    struct sptm_memory memory=sptm_context_memory(c);\n    int ran=0;'),
    'a pointer call reclaims the arena':
        ('s->fail_b=(uint32_t)s->x16;return FINE_FATAL;}\n',
         's->fail_b=(uint32_t)s->x16;return FINE_FATAL;}\n    arena_reserve(c,frame);\n'),
    'a helper signs into another CPU\'s record':
        ('        pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);\n    aes_clear(&native,sizeof(native));',
         '        pauth_pointer_native_sign,&native,&c->pauth_pointer[0]);\n    aes_clear(&native,sizeof(native));'),
    'the header does not mark the layout':
        (' | (uint64_t)SNAP_FAST_PAUTH_CALLS << 1 |', ' |'),
}
# Each must fail the differential (not its build or extraction): (old, new).
PAUTH_DIFF_MUTANTS = {
    'a decline after the engine ran':
        ('    if(!ran) {s->reason=FINE_NO_ENGINE;return FINE_DECLINE;}\n    if(r) {s->result=r;s->fail_kind=EV_TABLE_FAILED;'
         's->fail_a=s->a0;s->fail_b=(uint32_t)s->x16;',
         '    if(r) {s->reason=FINE_NO_ENGINE;return FINE_DECLINE;}\n    if(r) {s->result=r;s->fail_kind=EV_TABLE_FAILED;'
         's->fail_a=s->a0;s->fail_b=(uint32_t)s->x16;'),
    'the define-on body inverts the AUTH flag':
        ('        endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,\n'
         '        pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);\n    aes_clear',
         '        endpoint==SPTM_FN_SIGN_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,\n'
         '        pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);\n    aes_clear'),
    'the default case drifts (TBID from the wrong bit)':
        ('            endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,\n            pauth_pointer_native_sign',
         '            endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>52)&1,\n            pauth_pointer_native_sign'),
    'a converted batch failure names the endpoint':
        ('        s->fail_b=c->pauth_batch[vcpu_of(c)->slot].failed_index;return FINE_FATAL;',
         '        s->fail_b=(uint32_t)s->x16;return FINE_FATAL;'),
    'the converted batch publishes through the token path': PAUTH_SOURCE_MUTANTS[
        'the converted batch publishes through the token path'],
    'the converted answer from the wrong field':
        ('    frame[0]=c->pauth_pointer[vcpu_of(c)->slot].result;return FINE_DONE;',
         '    frame[0]=c->pauth_pointer[vcpu_of(c)->slot].computed;return FINE_DONE;'),
}


class Pauth(unittest.TestCase):
    """SNAP_FAST_PAUTH_CALLS: the converted pointer calls against the locked
    path on the monitor's own code, and their source binding."""
    def test_converted_equals_locked(self):
        rc, out = pauth_differential(SOURCE, '6000' if ARGS.quick else '20000')
        self.assertEqual(rc, 0, out[-3000:])
        print([l for l in out.splitlines() if l.startswith('pauth differential:')][0], file=sys.stderr)

    def test_weakened_calls_fail_the_differential(self):
        for name, (old, new) in PAUTH_DIFF_MUTANTS.items():
            with self.subTest(name):
                self.assertEqual(SOURCE.count(old), 1, name)
                rc, out = pauth_differential(SOURCE.replace(old, new), '4000')
                self.assertFalse(out.startswith(('build:', 'extract:')), f'{name}: {out[-1500:]}')
                self.assertNotEqual(rc, 0, f'{name} survived: {out[-800:]}')
                print(f'pauth differential mutant {name}: caught ({out.strip().splitlines()[-1][:110]})',
                      file=sys.stderr)

    def test_binding(self):
        self.assertEqual(pauth_problems(SOURCE), [])

    def test_weakened_bindings_are_caught(self):
        for name, (old, new) in PAUTH_SOURCE_MUTANTS.items():
            with self.subTest(name):
                self.assertEqual(SOURCE.count(old), 1, name)
                self.assertNotEqual(pauth_problems(SOURCE.replace(old, new)), [], name)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        installed, sets = installed_defines()
        sets = {'control': sets['control'], 'fast': sets['fast'],
                'fast-wfi': sets['fast'] + ['-DSNAP_WFI_RESUME=1'], 'installed': installed}
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='fine-locks-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                labels = [('default', []), ('off', ['-DSNAP_FINE_LOCKS=0', '-DSNAP_FINE_SWITCH=0',
                                                    '-DSNAP_FAIR_TOKEN=0', '-DSNAP_FAST_PAUTH_CALLS=0',
                                                    '-DSNAP_PHASE_FAIR_GATE=0'])]
                labels.append(('fair', ['-DSNAP_FAIR_TOKEN=1']))
                if name == 'installed':
                    labels += [('on', ['-DSNAP_FINE_LOCKS=1']),
                               ('on-off', ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FAST_PAUTH_CALLS=0']),
                               ('on-switch', ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1']),
                               ('on-switch-fair', ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1',
                                                   '-DSNAP_FAIR_TOKEN=1']),
                               ('on-pauth', ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FAST_PAUTH_CALLS=1']),
                               ('on-switch-fair-wait', ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1',
                                                        '-DSNAP_FAIR_TOKEN=1', '-DSNAP_GATE_WAIT=1']),
                               ('on-switch-fair-wait-phase', ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1',
                                                              '-DSNAP_FAIR_TOKEN=1', '-DSNAP_GATE_WAIT=1',
                                                              '-DSNAP_PHASE_FAIR_GATE=1'])]
                for label, extra in labels:
                    monitor_run.FLAGS[:] = flags + extra
                    blob = monitor_run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget, len(blob), f'{name}-{label}')
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['fair'], name)
                if name == 'installed':
                    self.assertNotEqual(blobs['default'], blobs['on'])
                    self.assertEqual(blobs['on'], blobs['on-off'])
                    self.assertNotEqual(blobs['on'], blobs['on-switch'])
                    self.assertNotEqual(blobs['on-switch'], blobs['on-switch-fair'])
                    self.assertNotEqual(blobs['on'], blobs['on-pauth'])
                    self.assertNotEqual(blobs['on-switch-fair-wait'], blobs['on-switch-fair-wait-phase'])
                    # SNAP_PHASE_FAIR_GATE needs SNAP_FAIR_TOKEN (writers' FIFO) and SNAP_GATE_WAIT.
                    for refused in (['-DSNAP_FINE_LOCKS=1', '-DSNAP_GATE_WAIT=1', '-DSNAP_PHASE_FAIR_GATE=1'],
                                    ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FAIR_TOKEN=1', '-DSNAP_PHASE_FAIR_GATE=1']):
                        monitor_run.FLAGS[:] = flags + refused
                        with self.assertRaises(subprocess.CalledProcessError):
                            monitor_run.build('xnuboot', out / f'{name}-refused-phase-{len(results)}-{refused[1][7:-2]}')
                else:
                    for refused in ('-DSNAP_FINE_LOCKS=1', '-DSNAP_FAST_PAUTH_CALLS=1'):
                        monitor_run.FLAGS[:] = flags + [refused]
                        with self.assertRaises(subprocess.CalledProcessError):
                            monitor_run.build('xnuboot', out / f'{name}-refused-{refused[7:-2].lower()}')
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name], name)
        finally:
            monitor_run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST])
