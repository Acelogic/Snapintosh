#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_WFI_RESUME: bind compat/wfi-resume.h's decision to the monitor, its
vectors, the context layout and the pinned kernel.

    python3 tools/test-wfi-resume.py
    python3 tools/test-wfi-resume.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256]

Offline, no hardware and no proxy. It builds and runs tools/test-wfi-resume.c
(sanitized; every decline reason, the whole hint space, a differential
oracle), then requires a set of weakened deciders to FAIL it. It checks that
probes/xnuboot.c defaults the define to 0, decides only at the EL2 timer tick
after timer_sync, the EOI, the GPU tick, the host-stop poll and the device-reset
check, under the service lock (runtime_enter/runtime_leave), that the #else path
is the unchanged two lines, that frame[32] is the ELR the async vector restores,
that IPIs are posted only by the locked trap handler, that the next tick is the
1 ms poll, and that the context and the fast-trap line keep their sizes. Against
the pinned kernelcache it lists every executable WFI and checks that each lies
in the const prefix and that no direct branch targets, and no landing pad sits
at, its successor.

--build also compiles xnuboot with cycle.py's installed-fresh/speed-test flag
sets (control and fast) with the define absent, =0 and =1: -Werror, the code
budget, absent == =0, and =1 differs. --expect NAME=SHA256 requires the default
build to equal a pre-change monitor byte for byte.

Failure inventory: a resume path outside the timer tick or before its
bookkeeping; a decision outside the service lock; a default build that changed;
a rewind into the wrong frame slot; a lock-free IPI post; an unbounded sleep;
a layout change visible to host readers; a weakened decider passing the table;
a pinned-kernel WFI whose successor a branch can reach.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
VECTORS = (ROOT / 'probes/xnuboot.S').read_text()
HEADER = (ROOT / 'compat/wfi-resume.h').read_text()
KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
WFI = 0xd503207f


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256',
                    help='control or fast: the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


# Parsed before the classes so that @skipUnless sees --build.
ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def ordered(region, tokens):
    at = 0
    for token in tokens:
        found = region.find(token, at)
        if found < 0:
            raise AssertionError(f'{token!r} missing or out of order')
        at = found + len(token)


def compile_test(directory, header_dir=None):
    exe = Path(directory) / 'test-wfi-resume'
    include = [f'-I{header_dir}'] if header_dir else []
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *include,
                    '-Icompat', 'tools/test-wfi-resume.c', '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=120, capture_output=True)
    return exe


# Each weakening of compat/wfi-resume.h must make the C test fail.
MUTANTS = {
    'BTYPE ignored': ('(WFI_SPSR_BTYPE | WFI_SPSR_IL | WFI_SPSR_SS)', '(WFI_SPSR_IL | WFI_SPSR_SS)'),
    'SS ignored': ('(WFI_SPSR_BTYPE | WFI_SPSR_IL | WFI_SPSR_SS)', '(WFI_SPSR_BTYPE | WFI_SPSR_IL)'),
    'EL0 resumes': ('if (mode == 0) return WFI_DECLINE_BUSY;', 'if (0) return WFI_DECLINE_BUSY;'),
    'monitor ignored': ('if (s->stop || s->monitor)', 'if (s->stop)'),
    'ERET target ignored': ('if (s->elr == s->last_return) return', 'if (0) return'),
    'WFE accepted': ('if (m->fetch(m->ctx, pa) != WFI_RESUME_WORD)',
                     'if ((m->fetch(m->ctx, pa) | 0x20) != WFI_RESUME_WORD)'),
    'any page': ('((s->elr - 4) ^ s->elr) >> 12 ||', ''),
    'any RAM is text': ('pa < m->text_begin || m->text_end < 4 ||', 'm->text_end < 4 ||'),
    'deadline now is future': ('(int64_t)(s->timer_cval - s->guest_now) <= 0',
                               '(int64_t)(s->timer_cval - s->guest_now) < 0'),
    'VSE ignored': ('(UINT64_C(1) << 8)) /* VF VI VSE */', '0) /* VF VI VSE */'),
    'other models ignored': ('s->model_irq_pending || s->models_pending ||', 's->model_irq_pending ||'),
    'device due now ignored': ('(int64_t)(s->device_due - s->physical) <= 0',
                               '(int64_t)(s->device_due - s->physical) < 0'),
    'masked EL2 timer accepted': ('(s->el2_ctl & 3) != 1', '(s->el2_ctl & 1) != 1'),
    'unbounded sleep': ('(int64_t)(s->el2_cval - s->physical) > (int64_t)s->wake_bound', '0'),
    'IPI ignored': ('if (s->ipi_pending) return WFI_DECLINE_IPI;', ''),
}


class Decision(unittest.TestCase):
    def test_table_hint_space_and_differential(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([str(compile_test(d))], capture_output=True, text=True, timeout=600)
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-2000:])
        self.assertTrue(result.stdout.rstrip().endswith('PASS'), result.stdout[-2000:])
        print(result.stdout.strip().splitlines()[-2], file=sys.stderr)

    def test_weakened_deciders_fail(self):
        for name, (old, new) in MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(HEADER.count(old), 1, name)
                (Path(d) / 'wfi-resume.h').write_text(HEADER.replace(old, new))
                result = subprocess.run([str(compile_test(d, d))], capture_output=True, text=True,
                                        timeout=600)
                self.assertNotEqual(result.returncode, 0, name)


class Source(unittest.TestCase):
    def test_default_off_and_included_only_when_on(self):
        self.assertIn('#ifndef SNAP_WFI_RESUME\n#define SNAP_WFI_RESUME 0\n#endif\n'
                      '#if SNAP_WFI_RESUME\n#include "../compat/wfi-resume.h"\n#endif', SOURCE)
        helper = between(SOURCE, '#if SNAP_WFI_RESUME\nstatic uint64_t wfi_resume_pa(', '#endif\n')
        self.assertIn('static void wfi_resume(struct context *c', helper)

    def test_decides_last_in_the_timer_tick(self):
        locked = between(SOURCE, 'static int xnuboot_async_locked(', '\nint xnuboot_async(')
        tick = between(locked, 'if (intid == 26) {', 'if (intid < 1020) timer_eoi(intid);')
        ordered(tick, ['timer_irqs++', 'timer_sync(c);', 'timer_eoi(intid);', 'gpu_tick(c, elr);',
                       '#if SNAP_WFI_RESUME', 'int host_stop = early_stop_host_tick(c, physical);',
                       'if (host_stop) timer_sync(c);', 'int stop = device_reset_stop(c, elr, frame);',
                       'wfi_resume(c, elr, (uint64_t *)frame, stop || host_stop);', 'return stop;',
                       '#else', '#endif'])
        unchanged = between(tick, '#else', '#endif')
        self.assertEqual([l.strip() for l in unchanged.splitlines()[1:] if l.strip()],
                         ['if (early_stop_host_tick(c, physical)) timer_sync(c);',
                          'return device_reset_stop(c, elr, frame);'])
        # The tick is reached only for INTID 26 with ISTATUS and the budget not spent.
        self.assertIn('if (which == ASYNC_IRQ && (ctl & CNTHP_ISTATUS) &&\n'
                      '        (int64_t)(run_deadline(c) - physical) > 0) {', locked)
        self.assertEqual(SOURCE.count('wfi_resume(c, elr,'), 1)
        self.assertEqual(SOURCE.count('frame[32] = elr - 4'), 1)
        helper = between(SOURCE, 'static void wfi_resume(struct context *c', '\n}\n')
        self.assertIn('if (r == WFI_RESUME) frame[32] = elr - 4;', helper)
        self.assertIn('c->perf.fast[v->slot].wfi[r]++;', helper)
        self.assertIn('p->const_begin, p->const_end', helper)
        self.assertIn('guest_ipi_poll_delay(v->clock_rate.host_hz, UINT64_MAX)', helper)
        self.assertIn('.last_return = v->last_kernel_return', helper)

    def test_decision_runs_under_the_service_lock(self):
        entry = between(SOURCE, 'int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame)\n{',
                        '\n}\n')
        ordered(entry, ['runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)',
                        'runtime_leave(c, xnuboot_async_locked(elr, which, frame))'])
        # Every IPI post is the locked trap handler's guest_ipi_route.
        self.assertEqual(SOURCE.count('guest_ipi_route('), 1)
        trap_locked = between(SOURCE, 'static int xnuboot_trap_locked(', '\nint xnuboot_trap(')
        self.assertIn('guest_ipi_route(', trap_locked)
        self.assertIsNone(re.search(r'ipi\.pending\s*=[^=]', SOURCE))
        for name in ('fast-trap.h', 'fast-vector.h', 'fast-mmio.h'):
            self.assertNotIn('guest_ipi_', (ROOT / 'compat' / name).read_text(), name)
        # The next tick: timer_sync re-arms through timer_arm, capped at the IPI poll.
        sync = between(SOURCE, 'static void timer_sync(struct context *c)', '\n}\n')
        self.assertTrue(sync.rstrip().endswith('timer_arm(c, physical, due);'))
        arm = between(SOURCE, 'static void timer_arm(struct context *c', '\n}\n')
        self.assertIn('if (c->host_cpus) delay=guest_ipi_poll_delay(', arm)

    def test_frame_slot_32_is_the_restored_elr(self):
        lower = between(VECTORS, 'async_lower:', 'pauth_failed:')
        ordered(lower, ['mrs x0, elr_el2', 'str x0, [sp, #(32 * 8)]', 'mov x2, sp', 'bl xnuboot_async',
                        'str x0, [sp, #(33 * 8)]', 'b resume_lower'])
        resume = between(VECTORS, 'resume_lower:', 'done:')
        ordered(resume, ['bl xnuboot_pauth_resume', 'ldr x2, [sp, #(32 * 8)]', 'msr elr_el2, x2', 'eret'])
        self.assertNotIn('[sp, #(32 * 8)]', resume.replace('ldr x2, [sp, #(32 * 8)]', ''))
        self.assertEqual(VECTORS.count('bl xnuboot_async'), 1)
        for vector in ('async_irq:', 'async_fiq:', 'async_serror:'):
            self.assertIn('b async_lower', between(VECTORS, vector, '\n\n'))
        self.assertIn('int xnuboot_pauth_resume(const uint64_t *frame)\n{', SOURCE)


class Layout(unittest.TestCase):
    def test_sizes_hold_and_counter_offsets(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        perf = importlib.import_module('perf_counters')
        sets, _ = flag_sets()
        defines = [f for f in sets['fast'] if f.startswith('-D')]
        off = perf._records(ROOT / 'probes/xnuboot.c', defines)
        on = perf._records(ROOT / 'probes/xnuboot.c', defines + ['-DSNAP_WFI_RESUME=1'])
        for records in (off, on):
            line = records['fast_trap_cpu']
            self.assertEqual(perf._size(line), 192)
            self.assertEqual(perf._offset(line, 'reserved'), 152)
            self.assertEqual(perf._offset(line, 'wfi'), 160)
        self.assertEqual(perf._size(off['context']), perf._size(on['context']))
        base = perf._offset(on['context'], 'perf') + perf._offset(on['perf_state'], 'fast') + 160
        print(f'perf.fast[cpu].wfi[8] (uint32 RESUME STATE BUSY TEXT IPI TIMER LINE WAKE) at '
              f'context+{base:#x}+cpu*192; context size {perf._size(on["context"])}', file=sys.stderr)


@unittest.skipUnless(KERNELCACHE.exists(), 'pinned kernelcache not extracted')
class PinnedKernel(unittest.TestCase):
    def test_every_wfi_successor_is_unreachable_by_branch(self):
        try:
            import numpy as np
        except ImportError:
            self.skipTest('numpy not available')
        sys.path.insert(0, str(ROOT / 'tools'))
        data = KERNELCACHE.read_bytes()
        image = importlib.import_module('kc-load').Image(data)
        protections = {va: initprot for _, va, size, _, initprot in image.segment_protections}
        end = image.vmin                       # const_region_contract's prefix, VA form
        for _, va, size, maxprot, initprot in sorted(image.segment_protections, key=lambda s: s[1]):
            if not size:
                continue
            if (maxprot | initprot) & 2:
                break
            end = va + size
        vas, words, data_wfi = [], [], 0
        for _, vmaddr, vmsize, fileoff, filesize in image.segments:
            w = np.frombuffer(data, dtype='<u4', count=min(vmsize, filesize) // 4, offset=fileoff)
            if protections.get(vmaddr, 0) & 4:
                vas.append(vmaddr + 4 * np.arange(len(w), dtype=np.uint64))
                words.append(w)
            elif image.vmin <= vmaddr < end:
                data_wfi += int((w == WFI).sum())
        va, w = np.concatenate(vas), np.concatenate(words)

        def sext(x, bits):
            x = x.astype(np.int64)
            return np.where(x >= 1 << (bits - 1), x - (1 << bits), x)
        targets = []
        for mask, match, shift, bits in ((0x7c000000, 0x14000000, 0, 26),   # B, BL
                                         (0xff000010, 0x54000000, 5, 19),   # B.cond
                                         (0x7e000000, 0x34000000, 5, 19),   # CBZ, CBNZ
                                         (0x7e000000, 0x36000000, 5, 14)):  # TBZ, TBNZ
            m = (w & mask) == match
            targets.append(va[m].astype(np.int64) + 4 * sext((w[m] >> shift) & ((1 << bits) - 1), bits))
        targets = np.unique(np.concatenate(targets).astype(np.uint64))
        pads = {0xd503241f, 0xd503245f, 0xd503249f, 0xd50324df, 0xd503233f, 0xd503237f}  # BTI, PACIxSP
        sites = np.nonzero(w == WFI)[0]
        self.assertGreater(len(sites), 0)
        report = []
        for i in sites:
            site = int(va[i])
            self.assertTrue(image.vmin <= site < end - 4, hex(site))
            self.assertLess(i + 1, len(w))
            self.assertFalse(bool(np.isin(np.uint64(site + 4), targets)), f'{site + 4:#x} is a branch target')
            self.assertNotIn(int(w[i + 1]), pads, hex(site))
            self.assertNotEqual(site & 0xfff, 0xffc, f'{site:#x} ends a page: never resumed')
            report.append(f'{site:#x}')
        self.assertEqual(data_wfi, 0, 'WFI-valued words in non-executable const segments')
        print(f'pinned kernel: {len(sites)} executable WFI sites {report}, all in the const prefix, '
              f'no branch to WFI+4 among {len(targets)} direct targets', file=sys.stderr)


def flag_sets():
    """cycle_lib/speed_test.py flag_sets(): config/monitor-flags.json + ADDED (+FAST) + CENSUS."""
    tree = ast.parse((ROOT / 'tools/build-fast-traps-monitor.py').read_text())
    lists = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name) and t.id in ('ADDED', 'FAST')}
    census = [ast.literal_eval(n.value) for n in ast.parse((ROOT / 'tools/cycle_lib/speed_test.py')
              .read_text()).body if isinstance(n, ast.Assign) and
              any(isinstance(t, ast.Name) and t.id == 'CENSUS' for t in n.targets)][0]
    base = json.loads((ROOT / 'config/monitor-flags.json').read_text())['flags']
    return dict(control=[*base, *lists['ADDED'], census],
                fast=[*base, *lists['ADDED'], *lists['FAST'], census]), lists['FAST']


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (about a minute)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        sets, fast = flag_sets()
        self.assertNotIn('-DSNAP_WFI_RESUME=1', sets['fast'])
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='wfi-resume-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_WFI_RESUME=0']),
                                     ('on', ['-DSNAP_WFI_RESUME=1'])):
                    run.FLAGS[:] = flags + extra
                    blob = run.build('xnuboot', out / f'{name}-{label}')
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
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
