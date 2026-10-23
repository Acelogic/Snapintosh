#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_FAST_TIMER_IRQ: bind compat/fast-timer-irq.h's gate and tick to the
monitor, its locked tick, the layouts, the report record and cycle.py.

    python3 tools/test-fast-timer-irq.py
    python3 tools/test-fast-timer-irq.py --build [--out DIR] [--expect SHA256]

Offline, no hardware and no proxy. It builds and runs tools/test-fast-timer-irq.c
(sanitized: the gate's table and an exhaustive oracle, other INTIDs from IAR, the
lines, a differential against the locked tick's transcription, a 20 s timeline
and the device deadline under watchdog pets), then requires a set of weakened
headers to FAIL it. It binds that transcription to probes/xnuboot.c line by
line, compiles xnuboot_async itself (the source's own text) with stubs to check
the dispatch with the define on and off, and checks that probes/xnuboot.c
defaults the define to 0, that only vCPUs 1-5 can take the fast tick, that
every helper the locked tick runs on vCPU 0 only stays there, that the only
model with a deadline is the watchdog, whose register path re-syncs its CPU,
that the fast path writes no shared state, that define-free layouts and the
context's size hold, that the report record sits where tools/perf_counters.py
reads it (a C-written record decodes, damaged ones are refused), and that
cycle.py installed-fresh admits --fast-timer-irq only with its prerequisites.

--build also builds xnuboot with the latest installed-fresh flag set
(installed-fresh-20261019-v89's, from cycle.py's recipe) with the define absent,
=0 and =1: absent == =0, =1 differs, both within the code budget; --expect
requires the default build to have that SHA-256 (v89's monitor_sha256).

Failure inventory: a fast tick on vCPU 0 or for another interrupt; a swallowed
or still-active foreign INTID; an EOI before the re-arm; a stale or missing
line; a device deadline or reset, a run deadline or a stop overrun; a shared
write without the token; a default build that changed; a layout change visible
to define-free readers; a report record the decoder misreads; a weakened gate or
tick passing the C test; the option admitted without its prerequisites.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HEADER = (ROOT / 'compat/fast-timer-irq.h').read_text()
TEST_C = (ROOT / 'tools/test-fast-timer-irq.c').read_text()
DEFINE = '-DSNAP_FAST_TIMER_IRQ=1'
# cycle.py installed-fresh options of installed-fresh-20261019-v89 (its qualification "flags").
V89 = ('wfi_resume fast_el0_sysreg service_subclass dart_wiredcnt panic_serve root_miss_fast update_disjoint_fast '
       'root_cache_wide update_check_sparse input kernel_pperm_fast ib_budget_1s unmap_mixed prime_secondaries '
       'txm_aspace_wide fine_locks fine_switch fair_token user_hw_walk s2_fault_retry nest_fast detach_fast '
       'root_index other_profile gate_wait').split()


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', metavar='SHA256', help='the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (argparse.Namespace(build=False, out=None, expect=None), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin + len(start))]


def ordered(region, tokens):
    at = 0
    for token in tokens:
        found = region.find(token, at)
        if found < 0:
            raise AssertionError(f'{token!r} missing or out of order')
        at = found + len(token)


def code(text):
    """C text without comments."""
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))


def function(source, signature):
    return runpy.run_path(str(ROOT / 'tools/test-guard-step.py'))['function'](source, signature)


def installed(**extra):
    """cycle_lib.installed_fresh.variant_flags for v89's options (+ extra)."""
    sys.path.insert(0, str(ROOT / 'tools'))
    import cycle_lib.installed_fresh as fresh  # noqa: E402
    import cycle_lib.speed_test as st  # noqa: E402
    sets, _ = st.flag_sets(ROOT)
    args = argparse.Namespace(variant='fast', **{n: True for n in V89})
    for k, v in extra.items():
        setattr(args, k, v)
    return fresh, sets, args


def flags_v89(on=False):
    fresh, sets, args = installed(fast_timer_irq=on)
    return fresh.variant_flags(sets, args)


def compile_test(directory, header_dir=None):
    exe = Path(directory) / 'test-fast-timer-irq'
    include = [f'-I{header_dir}'] if header_dir else []
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *include, '-Icompat',
                    'tools/test-fast-timer-irq.c', 'compat/clock.c', 'compat/ipi.c', 'compat/exception.c',
                    '-o', str(exe)], cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


# Each weakening of compat/fast-timer-irq.h must make the C test fail.
MUTANTS = {
    'vCPU 0 taken': ('    if (!g->slot) return FAST_IRQ_DECLINE_CPU0;\n', ''),
    'ISTATUS ignored': ('if (!(g->ctl & FAST_IRQ_ISTATUS) || g->hppir', 'if (g->hppir'),
    'HPPIR ignored': (' || g->hppir != FAST_IRQ_TIMER_INTID) return', ') return'),
    'not admitted taken': ('if (!g->admitted || !g->watchdog_live)', 'if (!g->watchdog_live)'),
    'watchdog off taken': ('if (!g->admitted || !g->watchdog_live)', 'if (!g->admitted)'),
    'reset ignored': ('if (g->reset_latched || g->physical >= g->device_due)', 'if (g->physical >= g->device_due)'),
    'device due now taken': ('g->physical >= g->device_due', 'g->physical > g->device_due'),
    'deadline now taken': ('(int64_t)(g->deadline - g->physical) <= 0', '(int64_t)(g->deadline - g->physical) < 0'),
    'deadline compared unsigned': ('(int64_t)(g->deadline - g->physical) <= 0', 'g->deadline <= g->physical'),
    'foreign INTID swallowed': ('        if (intid < FAST_IRQ_INTID_LIMIT) hw->complete(hw->ctx, intid);\n', ''),
    'spurious completed': ('if (intid < FAST_IRQ_INTID_LIMIT) hw->complete', 'if (1) hw->complete'),
    'foreign INTID ticked': ('        return FAST_IRQ_OTHER;\n    }\n', '    }\n'),
    'timer_irqs lost': ('    (*v->timer_irqs)++;\n', ''),
    'IRQ pc lost': ('    *v->timer_irq_pc = elr;\n', '    (void)elr;\n'),
    'sample before the count': ('uint64_t now = hw->counter(hw->ctx), physical = hw->physical(hw->ctx);',
                                'uint64_t physical = hw->physical(hw->ctx), now = hw->counter(hw->ctx);'),
    'IPI ignored': ('int fiq = *v->timer_pending || __atomic_load_n(v->ipi_pending, __ATOMIC_RELAXED);',
                    'int fiq = *v->timer_pending != 0;'),
    'timer line ignored': ('int fiq = *v->timer_pending || __atomic_load_n', 'int fiq = __atomic_load_n'),
    'model line ignored': ('int irq = *v->model_irq_pending != 0;', 'int irq = 0;'),
    'other HCR bits dropped': ('uint64_t next = (hcr & ~(FAST_IRQ_HCR_VF | FAST_IRQ_HCR_VI)) |', 'uint64_t next = 0 |'),
    'assert/clear swapped': ('if (fiq) (*v->timer_asserts)++; else (*v->timer_clears)++;',
                             'if (fiq) (*v->timer_clears)++; else (*v->timer_asserts)++;'),
    'HCR always written': ('    if (next != hcr) hw->set_hcr(hw->ctx, next);', '    hw->set_hcr(hw->ctx, next);'),
    'no device deadline': ('hw->arm(hw->ctx, physical, v->device_due);', 'hw->arm(hw->ctx, physical, UINT64_MAX);'),
    'EOI before the re-arm': ('    hw->arm(hw->ctx, physical, v->device_due);\n    hw->complete(hw->ctx, intid);\n',
                              '    hw->complete(hw->ctx, intid);\n    hw->arm(hw->ctx, physical, v->device_due);\n'),
    'stale timer line': ('    *v->timer_pending = (uint64_t)guest_timer_pending(v->timer, now);\n', '    (void)now;\n'),
}


class Decision(unittest.TestCase):
    def test_gate_tick_differential_and_timeline(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([str(compile_test(d))], capture_output=True, text=True, timeout=600)
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-2000:])
        self.assertTrue(result.stdout.rstrip().endswith('PASS'), result.stdout[-2000:])
        print('\n'.join(result.stdout.strip().splitlines()[:-1]), file=sys.stderr)

    def test_weakened_headers_fail(self):
        for name, (old, new) in MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(HEADER.count(old), 1, name)
                (Path(d) / 'fast-timer-irq.h').write_text(HEADER.replace(old, new))
                result = subprocess.run([str(compile_test(d, d))], capture_output=True, text=True, timeout=600)
                self.assertNotEqual(result.returncode, 0, name)


class Transcription(unittest.TestCase):
    """tools/test-fast-timer-irq.c locked() restates the locked tick on vCPUs 1-5."""

    def test_the_locked_tick(self):
        locked = between(SOURCE, 'static int xnuboot_async_locked(', '\nint xnuboot_async(')
        ordered(locked, ['if (which == ASYNC_IRQ && (c->params->gpu.flags & ADRENO_F_ENABLE)) {',
                         'if (pending == ADRENO_INTID) {', 'gpu_irq(c);',
                         'if (which == ASYNC_IRQ && (ctl & CNTHP_ISTATUS) &&\n'
                         '        (int64_t)(run_deadline(c) - physical) > 0) {',
                         'if (pending == 26) {', 'mrs %0, icc_iar1_el1; dsb sy', 'if (intid == 26) {',
                         'vcpu_of(c)->timer_irqs++;', 'vcpu_of(c)->timer_irq_pc = elr;', 'timer_sync(c);',
                         'timer_eoi(intid);', 'int thermal_stop=thermal_tick(c,physical);',
                         'if (!thermal_stop && !vcpu_of(c)->slot && c->params->gpu.flags) gpu_tick(c, elr);',
                         'int host_stop=thermal_stop ? 0 : early_stop_host_tick(c,physical);',
                         'if(host_stop)timer_sync(c);', 'int stop=device_reset_stop(c,elr,frame);',
                         'wfi_resume(c,elr,(uint64_t *)frame,stop || host_stop);', 'return stop;',
                         'if (intid < 1020) timer_eoi(intid);'])
        # Off vCPU 0 the thermal, GPU and host-stop helpers return at once.
        self.assertIn('if(vcpu_of(c)->slot || !c->thermal)return 0;', between(SOURCE, 'static int thermal_tick(', '\n}\n'))
        self.assertIn('if (vcpu_of(c)->slot || !early_stop_host_due(',
                      between(SOURCE, 'static int early_stop_host_tick(', '\n}\n'))
        # The acknowledge the C test models is the locked one's.
        self.assertIn('__asm__ volatile("mrs %0, icc_iar1_el1; dsb sy":"=r"(intid)::"memory");',
                      between(SOURCE, 'static uint64_t fast_irq_acknowledge(', '\n}\n'))

    def test_timer_sync_and_lines(self):
        sync = between(SOURCE, 'static void timer_sync(struct context *c)\n{', '\n}\n')
        ordered(sync, ['now = clock_counter(c);', 'mrs %0, cntpct_el0', 'device_model_wait(', 'device_latch_resets(',
                       'vcpu_of(c)->timer_pending = guest_timer_pending(&vcpu_of(c)->timer, now);',
                       'guest_interrupt_sync(c);', 'd->guest = due;', 'timer_arm(c, physical, due);'])
        lines = between(SOURCE, 'static void guest_interrupt_sync(struct context *c)\n{', '\n}\n')
        for statement in (
                'int fiq = exception_step_fiq(&vcpu_of(c)->stepping, guest_ipi_fiq(&vcpu_of(c)->ipi,vcpu_of(c)->timer_pending));',
                'int irq = exception_step_fiq(&vcpu_of(c)->stepping, vcpu_of(c)->model_irq_pending);',
                'if (fiq) vcpu_of(c)->timer_asserts++; else vcpu_of(c)->timer_clears++;',
                'if (irq) vcpu_of(c)->model_irq_asserts++; else vcpu_of(c)->model_irq_clears++;',
                'uint64_t next = (hcr & ~((1UL << 6) | (1UL << 7))) |',
                '(fiq ? 1UL << 6 : 0) | (irq ? 1UL << 7 : 0);',
                'if (next != hcr) __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(next));'):
            self.assertIn(statement, lines)
        test = between(TEST_C, 'static unsigned locked(', '\n}\n')
        ordered(test, ['hw_acknowledge(h);', 'if (intid == 26) {', 'v->timer_irqs++;', 'v->timer_irq_pc = elr;',
                       'hw_counter(h);', 'hw_physical(h);', 'guest_timer_pending(&v->timer, now);', 'hw_hcr(h);',
                       'guest_ipi_fiq(&v->ipi', 'if (next != hcr) hw_set_hcr(h, next);',
                       'hw_arm(h, physical, v->device_due);', 'hw_complete(h, intid);',
                       'if (intid < 1020) hw_complete(h, intid);'])
        self.assertIn('static void timer_eoi(uint64_t intid)', SOURCE)
        self.assertIn('if (ctl & 2) /* EOImode: priority drop and deactivation are separate. */',
                      between(SOURCE, 'static void timer_eoi(uint64_t intid)', '\n}\n'))

    def test_shared_part_is_the_watchdog_polled_by_locked_ticks(self):
        device = read_source(ROOT / 'compat/device.c')
        wait = between(device, 'uint64_t device_model_wait(', '\n}\n')
        self.assertIn('model->kind == DEVICE_WATCHDOG_WD1_V1', wait)
        self.assertEqual(wait.count('return'), 2)             # the watchdog's wait, else the budget unchanged
        self.assertIn('model->kind == DEVICE_WATCHDOG_WD1_V1 &&\n           state->watchdog.reset;',
                      between(device, 'int device_reset_pending(', '\n}\n'))
        # Every device-model access re-syncs (and re-arms) its own CPU before returning.
        self.assertIn('        timer_sync(c);\n        if (device_reset_stop(c, *elr, frame)) return 1;\n        *elr += 4;',
                      SOURCE)
        # vCPU 0's tick is always locked (the gate's first check) and armed within the poll.
        self.assertIn('if (c->host_cpus) delay=guest_ipi_poll_delay(', between(SOURCE, 'static void timer_arm(struct context *c, uint64_t physical', '\n}\n'))


class Source(unittest.TestCase):
    def test_default_off_and_prerequisites(self):
        self.assertIn('#ifndef SNAP_FAST_TIMER_IRQ\n#define SNAP_FAST_TIMER_IRQ 0\n#endif\n#if SNAP_FAST_TIMER_IRQ\n'
                      '#include "../compat/fast-timer-irq.h"\n', SOURCE)
        self.assertIn('_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE && SNAP_SERVICE_SUBCLASS,', SOURCE)
        self.assertIn('#define WFI_SHARED(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)\n#else\n'
                      '#define WFI_SHARED(x) (x)\n#endif\n', between(SOURCE, '#if SNAP_FAST_TIMER_IRQ\n#include', '/* vCPU 0 on'))
        # tools/test-wfi-resume.py reads the WFI helpers up to the first #endif.
        self.assertIn('static void wfi_resume(struct context *c',
                      between(SOURCE, '#if SNAP_WFI_RESUME\nstatic uint64_t wfi_resume_pa(', '#endif\n'))
        self.assertEqual(len(re.findall(r'\bfast_timer_irq\(', SOURCE)), 3)   # declaration, definition, one call

    def test_dispatch_text(self):
        entry = function(SOURCE, 'int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame)\n{')
        on = between(entry, '#if SNAP_FAST_TIMER_IRQ', '#else')
        ordered(on, ['which == ASYNC_IRQ ? fast_timer_irq(c, elr, (uint64_t *)frame) : FAST_IRQ_LOCKED;',
                     'if (stop < 0) {', 'stop == FAST_IRQ_LOCKED_OTHER ? ASYNC_IRQ_OTHER : which;',
                     'runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)',
                     'runtime_leave(c, xnuboot_async_locked(elr, kind, frame));'])
        off = between(entry, '#else', '#endif')
        self.assertEqual([l.strip() for l in off.splitlines()[1:] if l.strip()],
                         ['if (!runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)) return 1;',
                          'int stop = runtime_leave(c, xnuboot_async_locked(elr, which, frame));'])
        # ASYNC_IRQ_OTHER is no vector's kind and reaches only the locked tail.
        self.assertIn('#define ASYNC_IRQ_OTHER 3', SOURCE)
        self.assertNotIn('ASYNC_IRQ_OTHER', (ROOT / 'probes/xnuboot.S').read_text())
        run = (ROOT / 'probes/run.py').read_text()
        self.assertIn("ASYNC_KINDS = {**ASYNC_VECTORS, 3: ", run)

    def test_fast_tick_order_and_writes(self):
        body = between(SOURCE, 'static int fast_timer_irq(struct context *c,uint64_t elr,uint64_t *frame)\n{', '\n}\n')
        ordered(body, ['struct fast_irq_cpu *f=&c->root_ext->fast_irq[v->slot];', 'if(v->slot) {',
                       'mrs %0, cnthp_ctl_el2; mrs %1, icc_hppir1_el1; mrs %2, cntpct_el0',
                       'g.admitted=(uint64_t)fast_admitted(c,v,0);', 'g.watchdog_live=v->watchdog_live;',
                       'g.device_due=c->fast_timer_due[v->slot].physical;',
                       'g.reset_latched=(uint64_t)fast_reset_latched(c);', 'g.deadline=run_deadline(c);',
                       'unsigned r=fast_timer_irq_gate(&g);', 'if(r==FAST_IRQ_HANDLED) {',
                       'fast_irq_acknowledge,fast_irq_complete,clock_counter,',
                       'fast_irq_physical,fast_irq_hcr,fast_irq_set_hcr,fast_irq_arm};',
                       '&v->ipi.pending,', 'c->fast_timer_due[v->slot].guest};',
                       'r=fast_timer_irq_tick(&hw,&state,elr);', 'f->result[r]++;',
                       'if(r==FAST_IRQ_OTHER)return FAST_IRQ_LOCKED_OTHER;',
                       'if(r!=FAST_IRQ_HANDLED)return FAST_IRQ_LOCKED;',
                       'if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],SERVICE_PROFILE_ASYNC+ASYNC_IRQ);',
                       'step_translation_clear(&c->step_translation[v->slot]);', '#if SNAP_WFI_RESUME',
                       'wfi_resume(c,elr,frame,fast_reset_latched(c));', 'f->ticks+=end-g.physical;',
                       'return guest_service_stopped(&c->services)!=0;'])
        self.assertIn('{(void)ctx;timer_eoi(intid);}', between(SOURCE, 'static void fast_irq_complete(', '\n'))
        self.assertIn('{timer_arm(ctx,physical,due);}', between(SOURCE, 'static void fast_irq_arm(', '\n'))
        # Nothing shared is written: no log, stop, model, reset mask, deadline row or token call.
        for forbidden in ('record(', 'guest_service_stop(', 'model_state', 'device_reset_mask', 'fast_timer_due[v->slot].physical=',
                          'fast_timer_due[v->slot].guest=', 'runtime_enter', 'runtime_leave', 'guest_service_try',
                          'service_profile', 'exit_profile', 'FAST_EXIT_MARK', 'frame[31]', 'timer_sync(', 'ipi.pending='):
            self.assertNotIn(forbidden, code(body), forbidden)
        for forbidden in ('guest_ipi_route', 'device_model', 'device_latch', 'device_irq', 'model_state', 'record(',
                          '*v->ipi_pending =', '*v->model_irq_pending ='):
            self.assertNotIn(forbidden, code(HEADER), forbidden)
        # The counter rows are this CPU's, in the wide cache's arena pages.
        root_ext = between(SOURCE, 'struct root_ext {', '\n};\n')
        self.assertTrue(root_ext.rstrip().endswith('#if SNAP_FAST_TIMER_IRQ\n    struct fast_irq_cpu fast_irq[GUEST_CPU_COUNT];'
                                                   '  /* compat/fast-timer-irq.h, that CPU\'s (OUT_FAST_IRQ) */\n#endif'))
        # The WFI decision reads other CPUs' words through WFI_SHARED only.
        wfi = between(SOURCE, 'static void wfi_resume(struct context *c', '\n}\n')
        for word in ('c->user_view_failed', 'c->root_install_failures', 'c->kernel_view_failed', 'v->ipi.pending'):
            self.assertIn(f'WFI_SHARED({word})', wfi)
            self.assertEqual(wfi.count(word), 1, word)


DISPATCH = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define ASYNC_IRQ 0
#define ASYNC_FIQ 1
#define ASYNC_SERROR 2
#define ASYNC_IRQ_OTHER 3
#define SERVICE_PROFILE_ASYNC 64
#define FAST_IRQ_LOCKED (-1)
#define FAST_IRQ_LOCKED_OTHER (-2)
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static unsigned checks;
struct regs { uint64_t x0, esr, pc, far; };
struct vcpu { uint64_t async_captured; struct regs async_regs; };
struct context { struct vcpu v; };
static struct context context;
static int fast_result, fast_calls, enter_calls, admission, leave_stop, locked_stop;
static unsigned entered;
static uint64_t locked_which;
static struct context *context_of(void) { return &context; }
static struct vcpu *vcpu_of(struct context *c) { return &c->v; }
__attribute__((unused)) static int fast_timer_irq(struct context *c, uint64_t elr, uint64_t *frame)
{ (void)c; (void)elr; (void)frame; fast_calls++; return fast_result; }
static int runtime_enter(struct context *c, const uint64_t *f, uint64_t pc, unsigned cat)
{ (void)c; (void)f; (void)pc; enter_calls++; entered = cat; return admission; }
static int runtime_leave(struct context *c, int stop) { (void)c; return stop || leave_stop; }
static int xnuboot_async_locked(uint64_t elr, uint64_t which, const uint64_t *frame)
{ (void)elr; (void)frame; locked_which = which; return locked_stop; }
static void fill_regs(struct regs *r, const uint64_t *f, uint64_t esr, uint64_t pc, uint64_t far)
{ *r = (struct regs){f[0], esr, pc, far}; }
/* XNUBOOT_ASYNC */
static void reset(int fast) { context = (struct context){0}; fast_result = fast; fast_calls = enter_calls = 0;
    admission = 1; leave_stop = locked_stop = 0; entered = 0; locked_which = 99; }
int main(void)
{
    uint64_t frame[34] = {0x77};
#if SNAP_FAST_TIMER_IRQ
    /* A finished lock-free tick never takes the token. */
    reset(0); CHECK(!xnuboot_async(0x4000, ASYNC_IRQ, frame) && fast_calls == 1 && !enter_calls && locked_which == 99);
    CHECK(!context.v.async_captured);
    /* A peer's stop seen after it: the stop, with the frame captured as the locked return does. */
    reset(1); CHECK(xnuboot_async(0x4000, ASYNC_IRQ, frame) && !enter_calls && context.v.async_captured == 1);
    CHECK(context.v.async_regs.pc == 0x4000 && context.v.async_regs.x0 == 0x77 && !context.v.async_regs.esr);
    /* A decline: the locked tick, profiled as the IRQ vector. */
    reset(FAST_IRQ_LOCKED); CHECK(!xnuboot_async(0x4000, ASYNC_IRQ, frame) && enter_calls == 1);
    CHECK(entered == 64 && locked_which == ASYNC_IRQ);
    /* Another INTID acknowledged: the locked tail as ASYNC_IRQ_OTHER, still profiled as IRQ, and its stop. */
    reset(FAST_IRQ_LOCKED_OTHER); locked_stop = 1;
    CHECK(xnuboot_async(0x4000, ASYNC_IRQ, frame) && entered == 64 && locked_which == ASYNC_IRQ_OTHER);
    /* No admission: stop without the tail. */
    reset(FAST_IRQ_LOCKED); admission = 0;
    CHECK(xnuboot_async(0x4000, ASYNC_IRQ, frame) && locked_which == 99 && !context.v.async_captured);
    /* FIQ and SError never reach the lock-free tick. */
    for (uint64_t which = ASYNC_FIQ; which <= ASYNC_SERROR; which++) {
        reset(0); CHECK(!xnuboot_async(0x4000, which, frame) && !fast_calls && enter_calls == 1);
        CHECK(entered == 64 + which && locked_which == which);
    }
#else
    /* Without the define every vector takes the token, as before. */
    for (uint64_t which = ASYNC_IRQ; which <= ASYNC_SERROR; which++) {
        reset(0); CHECK(!xnuboot_async(0x4000, which, frame) && !fast_calls && enter_calls == 1);
        CHECK(entered == 64 + which && locked_which == which);
    }
#endif
    printf("PASS: %u dispatch checks (SNAP_FAST_TIMER_IRQ=%d)\n", checks, SNAP_FAST_TIMER_IRQ);
    return 0;
}
'''


class Dispatch(unittest.TestCase):
    def test_xnuboot_async_dispatch(self):
        entry = function(SOURCE, 'int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame)\n{')
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'dispatch.c'
            src.write_text(DISPATCH.replace('/* XNUBOOT_ASYNC */', 'int xnuboot_async(uint64_t, uint64_t, const uint64_t *);\n' + entry))
            for on in (1, 0):
                exe = Path(d) / f'dispatch{on}'
                subprocess.run(['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                                f'-DSNAP_FAST_TIMER_IRQ={on}', str(src), '-o', str(exe)], check=True, capture_output=True)
                result = subprocess.run([str(exe)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                print(result.stdout.strip(), file=sys.stderr)


class Layout(unittest.TestCase):
    def test_define_free_layouts_hold(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        off, on = flags_v89(), flags_v89(True)
        self.assertEqual([f for f in on if f != DEFINE], off)
        a = perf['_records'](ROOT / 'probes/xnuboot.c', [f for f in off if f.startswith('-D')])
        b = perf['_records'](ROOT / 'probes/xnuboot.c', [f for f in on if f.startswith('-D')])
        for name in ('context', 'vcpu', 'perf_state', 'fast_trap_cpu', 'exit_profile', 'service_profile', 'fine_cpu'):
            self.assertEqual(a[name].split('\n', 1)[1], b[name].split('\n', 1)[1], name)
        self.assertNotIn('fast_irq_cpu', a)
        self.assertEqual(perf['_size'](b['fast_irq_cpu']), 128)
        grown = perf['_size'](b['root_ext']) - perf['_size'](a['root_ext'])
        self.assertEqual(grown, 6 * 128)
        self.assertEqual(perf['_offset'](b['root_ext'], 'fast_irq'), perf['_size'](a['root_ext']))
        pages = lambda r: (perf['_size'](r['root_ext']) + 4095) // 4096
        print(f'root_ext {perf["_size"](a["root_ext"])} -> {perf["_size"](b["root_ext"])} bytes, '
              f'{pages(a)} -> {pages(b)} pages; context {perf["_size"](b["context"])} bytes either way', file=sys.stderr)

    def test_report_offset_is_the_monitors(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        flags = [f for f in flags_v89(True) if f.startswith('-D')]
        offset, size = perf['fast_irq_spec'](flags)
        token, token_size = perf['token_costs_spec'](flags)
        self.assertEqual(offset, token + token_size)
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / 'probe.c'
            probe.write_text(f'#include "{ROOT}/probes/xnuboot.c"\n'
                             f'_Static_assert(16 + 8*OUT_FAST_IRQ == {offset}, "report offset");\n'
                             f'_Static_assert(8*2 + 8*GUEST_CPU_COUNT*FAST_IRQ_WORDS == {size}, "record size");\n')
            subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                            '-fsyntax-only', f'-I{ROOT / "shadow"}', f'-I{ROOT / "compat"}', *flags, str(probe)],
                           cwd=ROOT, check=True, capture_output=True)


WRITER = r'''
#include <stdio.h>
#include "fast-timer-irq.h"
static struct fast_irq_cpu cpu[6];
int main(int argc, char **argv)
{
    (void)argc;
    uint64_t head[2] = {UINT64_C(0x3151524954534146), 1 | (uint64_t)sizeof *cpu << 32};
    cpu[0].result[FAST_IRQ_DECLINE_CPU0] = 9000;
    for (unsigned n = 1; n < 6; n++) {
        struct fast_irq_cpu *c = &cpu[n];
        c->result[FAST_IRQ_HANDLED] = 1000 * n; c->resumed = 900 * n; c->ticks = 250 * 1000 * n; c->max = 4000;
        c->result[FAST_IRQ_DECLINE_DEVICE] = n; c->result[FAST_IRQ_DECLINE_STATE] = 2;
        c->result[FAST_IRQ_DECLINE_TIMER] = n == 5; c->result[FAST_IRQ_OTHER] = n == 3;
    }
    FILE *f = fopen(argv[1], "wb"); fwrite(head, sizeof head, 1, f); fwrite(cpu, sizeof cpu, 1, f); fclose(f);
    printf("%zu\n", sizeof head + sizeof cpu);
    return 0;
}
'''


class Decoder(unittest.TestCase):
    def test_decode_a_c_written_record(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        flags = [f for f in flags_v89(True) if f.startswith('-D')]
        lay = perf['fast_irq_layout'](flags)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'w.c').write_text(WRITER)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-Icompat', str(Path(d) / 'w.c'), '-o', str(Path(d) / 'w')],
                           cwd=ROOT, check=True)
            size = int(subprocess.run([str(Path(d) / 'w'), str(Path(d) / 'r.bin')], check=True,
                                      capture_output=True, text=True).stdout)
            raw = (Path(d) / 'r.bin').read_bytes()
        self.assertEqual(size, perf['fast_irq_spec'](flags)[1])
        cpus = [dict(slot=0, buckets=[dict(category=64, entries=9000, wait_ticks=1, hold_ticks=1)])] + \
               [dict(slot=n, buckets=[dict(category=64, entries=n + 2 + (n == 5) + (n == 3), wait_ticks=1, hold_ticks=1),
                                      dict(category=0x18, entries=7, wait_ticks=1, hold_ticks=1)]) for n in range(1, 6)]
        out = perf['decode_fast_irq'](raw, lay=lay, hz=19.2e6, cpus=cpus)
        s = out['summary']
        self.assertTrue(out['wfi_resume'])
        self.assertEqual(s['result']['handled'], 15000)
        self.assertEqual(s['result']['cpu0'], 9000)
        self.assertEqual((s['result']['device'], s['result']['state'], s['result']['not_timer'], s['result']['other']),
                         (15, 10, 1, 1))
        self.assertEqual((s['locked'], s['resumed'], s['ticks'], s['max_ticks']), (9027, 13500, 3750000, 4000))
        self.assertAlmostEqual(s['mean_ns'], 250 / 19.2e6 * 1e9)
        # Refusals: magic, size word, an unknown build bit, vCPU 0 handling, cpu0 on a secondary,
        # more resumes than ticks, ticks beyond ticks x max, a reserved word, a short record.
        base1 = 16 + lay['size']
        for at, value in ((0, 0), (8, 1 | (lay['size'] + 8) << 32), (8, 3 | lay['size'] << 32),
                          (16 + lay['result'], 1), (base1 + lay['result'] + 8, 1),
                          (base1 + lay['resumed'], 1001), (base1 + lay['ticks'], 4000 * 1000 + 1),
                          (base1 + lay['reserved'], 1)):
            bad = bytearray(raw)
            struct.pack_into('<Q', bad, at, value)
            with self.assertRaises(ValueError, msg=f'{at}={value}'):
                perf['decode_fast_irq'](bytes(bad), lay=lay)
        with self.assertRaises(ValueError):
            perf['decode_fast_irq'](raw[:-8], lay=lay)
        # The service profile's IRQ entries must be exactly the declined ones.
        cpus[2]['buckets'][0]['entries'] += 1
        with self.assertRaises(ValueError):
            perf['decode_fast_irq'](raw, lay=lay, cpus=cpus)
        # Without SNAP_WFI_RESUME no tick resumes a WFI.
        bad = bytearray(raw)
        struct.pack_into('<Q', bad, 8, lay['size'] << 32)
        with self.assertRaises(ValueError):
            perf['decode_fast_irq'](bytes(bad), lay=lay)
        # The command line finds the record in a whole report.bin.
        offset, length = perf['fast_irq_spec'](flags)
        run = runpy.run_path(str(ROOT / 'probes/run.py'), run_name='fast_irq_cli')
        report = bytearray(run['OUT_HEADROOM'])
        exit_offset, exit_length = perf['exit_profile_spec'](flags)
        lay_exit = perf['exit_layout'](flags)
        struct.pack_into('<2Q', report, exit_offset, perf['EXIT_MAGIC'], 3 | lay_exit['size'] << 32)
        fine_offset, _ = perf['fine_profile_spec'](flags)
        struct.pack_into('<2Q', report, fine_offset, perf['FINE_MAGIC'], 1 | perf['fine_layout'](flags)['size'] << 32)
        token_offset, _ = perf['token_costs_spec'](flags)
        struct.pack_into('<2Q', report, token_offset, perf['TOKEN_MAGIC'], 0x1f | (8 * perf['TOKEN_WORDS']) << 32)
        report[offset:offset + length] = raw
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'report.bin').write_bytes(report)
            text = subprocess.run([sys.executable, str(ROOT / 'tools/perf_counters.py'), '--report',
                                   str(Path(d) / 'report.bin'), '--hz', '19200000', '--defines', *flags],
                                  check=True, capture_output=True, text=True).stdout
        self.assertEqual(json.loads(text)['fast_irq']['summary']['result']['handled'], 15000)


class Cycle(unittest.TestCase):
    def test_option_and_prerequisites(self):
        fresh, sets, args = installed(fast_timer_irq=True)
        flags = fresh.variant_flags(sets, args)
        self.assertEqual(flags.count(DEFINE), 1)
        self.assertEqual(fresh.FAST_TIMER_IRQ_DEFINE, DEFINE)
        self.assertNotIn(DEFINE, fresh.variant_flags(sets, installed(fast_timer_irq=False)[2]))
        for name, change in (('control', dict(variant='control')), ('no wide cache', dict(root_cache_wide=False)),
                             ('no sub-classes', dict(service_subclass=False))):
            with self.subTest(name):
                _, _, bad = installed(fast_timer_irq=True, **change)
                with self.assertRaises(Exception) as caught:
                    fresh.variant_flags(sets, bad)
                self.assertIn('--fast-timer-irq needs', str(caught.exception))
        cycle = (ROOT / 'tools/cycle.py').read_text()
        self.assertIn("p.add_argument('--fast-timer-irq', action='store_true',", cycle)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a minute or two)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='fast-timer-irq-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results, blobs = {}, {}
        base = flags_v89()
        try:
            for label, flags in (('default', base), ('off', base + ['-DSNAP_FAST_TIMER_IRQ=0']), ('on', flags_v89(True))):
                run.FLAGS[:] = flags
                blob = blobs[label] = run.build('xnuboot', out / label)
                results[label] = dict(bytes=len(blob), headroom=budget - len(blob), sha256=hashlib.sha256(blob).hexdigest())
                self.assertGreater(budget - len(blob), 0, label)
        finally:
            run.FLAGS[:] = saved
        self.assertEqual(blobs['default'], blobs['off'])
        self.assertNotEqual(blobs['default'], blobs['on'])
        if ARGS.expect:
            self.assertEqual(results['default']['sha256'], ARGS.expect, 'the default build changed')
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
