#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_ANS_ASYNC / SNAP_ANS_CONVERTED / SNAP_ATTR_CLEAN_DEFER (agents/nvme-async/FAILURE-MODES.md).

    python3 tools/test-nvme-async.py [--base DIR] [--qualification Q.json] [--quick] [--builds] [unittest args]

Offline, no hardware.
Unit: tools/test-ans.c and tools/test-nvme-host.c as they were (no define), with -DSNAP_ANS_ASYNC=1 and with both
defines: the async and converted scenarios (ordering, drains, pinning, refusals, the stop, the differential
against the synchronous path).
Harness: tools/test-ans-converted.c, six vCPU threads and an SSD thread through the real compat/ans.c, ans-window.c,
nvme-host.c, sptm-refs.c, sptm.c (sptm_mac_retype) and service-lock.c, under ThreadSanitizer and ASan/UBSan, two
seeds, and with 64 frame-lock words (collisions); every mutant must fail.
Source: the define-off preprocessed tokens of every changed C file equal the base's (no flags and the
qualification's); the define prerequisites refuse; probes/xnuboot.c's converted ANS bodies keep the lock order and
call nothing token-only; the tick, the stop, the attribute flush and the schedule sit where the failure modes say;
compat/nvme-host.c's submit/reap mirror its synchronous command.
Layout: probes/ansstate.py's async offsets equal the compiled struct's.
Decoder: tools/perf_counters.py decodes FINELCK1 records with header bit 4; the qualification run's report.bin
decodes identically with the base and the patched decoder.
Cycle: the qualification's arguments reproduce its flags; --nvme-async, --nvme-converted, --attr-clean-defer append
theirs and refuse without their prerequisites.
Builds (--builds): xnuboot.bin with the qualification's flags equals its monitor_sha256; each define builds.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(os.environ.get('SNAPINTOSH_OPS', '/nonexistent/set-SNAPINTOSH_OPS'))  # operator/agent tree (baselines, receipts)
LOGS = OPS / 'agents/nvme-async/tests/logs'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base', default=str(OPS / 'sme-batch12/Snapintosh'), help='the unpatched tree (read only)')
    ap.add_argument('--qualification', default=str(
        OPS / 'sme-batch12/Snapintosh/build/installed-fresh-desktop-20261021-b12v6/qualification.json'))
    ap.add_argument('--run-args', default=str(OPS / 'sme-batch12/desktop-run-args-b12v6.json'))
    ap.add_argument('--quick', action='store_true')
    ap.add_argument('--builds', action='store_true', help='also build the monitor (several minutes)')
    return ap.parse_known_args()


ARGS, REST = arguments()
BASE = Path(ARGS.base)
QUAL = json.loads(Path(ARGS.qualification).read_text())
QDEFINES = [f for f in QUAL['flags'] if f.startswith('-D')]
ON = ['-DSNAP_ANS_ASYNC=1', '-DSNAP_ANS_CONVERTED=1', '-DSNAP_ATTR_CLEAN_DEFER=1']
WORK = Path(tempfile.mkdtemp(prefix='nvme-async-'))
OPS_PER_CPU = '300' if ARGS.quick else '600'
CHANGED_C = ['probes/xnuboot.c', 'compat/ans.c', 'compat/ans-window.c', 'compat/nvme-host.c']
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
CC = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow']
IGNORE = WORK / 'tsan-ignore.txt'
IGNORE.write_text('fun:metadata\nfun:data_type\n')    # tools/test-sptm-fine.py's: sptm-user.c's pre-lock reads
SAN = {'tsan': ['-fsanitize=thread', f'-fsanitize-ignorelist={IGNORE}'],
       'asan': ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']}
HARNESS_DEFINES = ['-DANS_HOST', '-DSNAP_ANS_ASYNC=1', '-DSNAP_ANS_CONVERTED=1', '-DSNAP_FINE_LOCKS=1',
                   '-DSNAP_FINE_HW=1', '-DSNAP_SPTM_FINE=1', '-DSNAP_SPTM_FINE_RETYPE=1', '-DSNAP_FAIR_TOKEN=1',
                   '-DSNAP_PHASE_FAIR_GATE=1']
IMPL = ['compat/ans.c', 'compat/ans-window.c', 'compat/nvme-host.c',
        *sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'compat').glob('sptm*.c')),
        'shadow/sprr-view.c', 'shadow/mmu.c', 'shadow/shadow.c', 'compat/service-lock.c']
MUTANTS = {'MUTANT_NO_ANS_LOCK': 'tsan', 'MUTANT_NO_GATE': 'tsan', 'MUTANT_LINES_OUTSIDE_LOCK': 'tsan',
           'MUTANT_PLAIN_ENTRY_READ': 'tsan', 'MUTANT_PER_PAGE_COMMIT': 'asan', 'MUTANT_UNPINNED_RETYPE': 'asan'}


def log(name, text):
    LOGS.mkdir(parents=True, exist_ok=True)
    (LOGS / f'nvme-async-{name}.txt').write_text(text)


def build_run(name, sources, defines, args=(), san=('-fsanitize=address,undefined',), extra_cc=(), timeout=1800,
              cc=CC):
    exe = WORK / name
    b = subprocess.run([*cc, *san, *extra_cc, *defines, *sources, '-o', str(exe)], cwd=ROOT, capture_output=True,
                       text=True, timeout=900)
    if b.returncode:
        return b.returncode, 'build: ' + b.stderr[-3000:]
    try:
        r = subprocess.run([str(exe), *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        return -9, f'timeout: {(e.stdout or b"")[-2000:]!r}'
    return r.returncode, r.stdout + r.stderr


class Unit(unittest.TestCase):
    def test_ans(self):
        rows = []
        for name, defines, want in (('sync', [], None), ('async', ['-DSNAP_ANS_ASYNC=1'], 'test-ans async'),
                                    ('converted', ['-DSNAP_ANS_ASYNC=1', '-DSNAP_ANS_CONVERTED=1'], 'test-ans async')):
            rc, out = build_run(f'test-ans-{name}', ['tools/test-ans.c', 'compat/ans.c'], ['-DANS_HOST', *defines],
                                cc=['clang', '-std=c11', '-g', '-O1', '-Icompat'])   # its header's build line
            rows.append(f'== {name} (rc {rc})\n{out[-4000:]}')
            self.assertEqual(rc, 0, out[-3000:])
            self.assertIn(' 0 failures', out)
            if want:
                self.assertIn(want, out)
        log('test-ans', '\n'.join(rows))

    def test_nvme_host(self):
        rows = []
        for name, defines in (('sync', []), ('async', ['-DSNAP_ANS_ASYNC=1'])):
            rc, out = build_run(f'test-nvme-host-{name}', ['tools/test-nvme-host.c', 'compat/nvme-host.c',
                                                           'compat/ans-window.c'], defines)
            rows.append(f'== {name} (rc {rc})\n{out[-4000:]}')
            self.assertEqual(rc, 0, out[-3000:])
            if defines:
                self.assertIn('async:', out)
                self.assertIn('; 0 failures', out)
        log('test-nvme-host', '\n'.join(rows))


def harness(san, extra=(), ops=OPS_PER_CPU, seed='1'):
    tag = hashlib.sha256(' '.join([san, *extra]).encode()).hexdigest()[:10]
    return build_run(f'harness-{san}-{tag}', ['tools/test-ans-converted.c', *IMPL], [*HARNESS_DEFINES, *extra],
                     args=[ops, seed], san=SAN[san], extra_cc=['-pthread', '-ffunction-sections', '-Wl,-dead_strip'])


class Harness(unittest.TestCase):
    def check(self, name, san, extra=(), seed='1'):
        rc, out = harness(san, extra, seed=seed)
        log(f'harness-{name}', out)
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn('PASS test-ans-converted', out)
        self.assertNotIn('ThreadSanitizer', out)
        print('\n' + next(l for l in out.splitlines() if l.startswith('PASS')), file=sys.stderr)

    def test_tsan(self):
        self.check('tsan-seed1', 'tsan')
        self.check('tsan-seed7', 'tsan', seed='7')

    def test_asan(self):
        self.check('asan-seed1', 'asan')
        self.check('asan-seed7', 'asan', seed='7')

    def test_frame_lock_collisions(self):
        self.check('tsan-64-frame-locks', 'tsan', ['-DSPTM_FRAME_LOCKS=64u'], seed='3')

    def test_each_mutant_fails(self):
        rows = []
        for mutant, san in MUTANTS.items():
            failed = []
            for seed in ('1', '2', '3'):
                rc, out = harness(san, [f'-D{mutant}'], ops='600', seed=seed)
                failed.append(rc != 0)
                if rc:
                    why = next((l for l in out.splitlines() if 'FAIL' in l or 'WARNING: ThreadSanitizer' in l), '')
                    rows.append(f'{mutant} ({san}, seed {seed}): exit {rc}: {why.strip()[:160]}')
                    break
            else:
                rows.append(f'{mutant} ({san}): passed all seeds (NOT CAUGHT)')
            self.assertTrue(any(failed), mutant)
        log('harness-mutants', '\n'.join(rows) + '\n')


# ---- source checks --------------------------------------------------------------------------------------------
def preprocess(tree, rel, defines, target=True):
    args = ['clang', '-E', '-P', '-Ishadow', '-Icompat', f'-I{tree.parent / "q1n1/platform/uefi"}', *defines, rel]
    if target:
        args[1:1] = ['--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only']
    out = subprocess.run(args, cwd=tree, capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f'{tree}/{rel}: {out.stderr[-500:]}')
    return out.stdout


TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_0-9.]+|\S')


def tokens(text):
    return TOKEN.findall(text)


def functions(code):
    out = {}
    for m in re.finditer(r'^(?:static\s+)?(?:inline\s+)?(?:__attribute__\(\([^)]*\)\)\s*)?[A-Za-z_][\w \*]*?\b(\w+)'
                         r'\s*\([^;{}]*\)\s*\{', code, re.M):
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


def order(body, *needles):
    """Each needle found after the previous one."""
    at, i = [], 0
    for n in needles:
        j = body.find(n, i)
        at.append(j)
        if j < 0:
            return False, dict(zip(needles, at))
        i = j + len(n)
    return True, dict(zip(needles, at))


def normalized(body):
    return ' '.join(re.sub(r'/\*.*?\*/', ' ', body, flags=re.S).split())


# What a converted ANS body must never call: the token path's own (beyond test-fine-locks.py's FORBIDDEN).
FORBIDDEN = {'sptm_context_memory', 'ans_frame_ref', 'sptm_publish', 'timer_sync', 'device_models_route_irqs',
             'ans_async_drain', 'ans_async_stop', 'ans_window_read', 'ans_window_write', 'ans_window_flush',
             'nvmeh_read', 'nvmeh_write', 'nvmeh_flush', 'transaction_publish', 'shadow_tlb_sync', 'kernel_refresh',
             'mem_write', 'guest_service_try', 'arena_reserve', 'record', 'fill_regs'}


class Source(unittest.TestCase):
    def test_define_off_tokens_equal_the_base(self):
        rows = []
        for rel in CHANGED_C:
            target = rel == 'probes/xnuboot.c'
            v7 = Path(ARGS.qualification).parents[1] / 'installed-fresh-desktop-20261021-b12v7/qualification.json'
            q7 = [f for f in json.loads(v7.read_text())['flags'] if f.startswith('-D')] if v7.exists() else QDEFINES
            for name, defines in (('none', []), ('qualification', QDEFINES),
                                  ('qualification, =0', QDEFINES + [d.replace('=1', '=0') for d in ON]),
                                  ('b12v7 (sptm-fine, va-wide)', q7)):
                # Whitespace-normalized text (tools/test-sptm-fine.py's rule, stricter than tokens), then tokens.
                pa, pb = preprocess(BASE, rel, defines, target), preprocess(ROOT, rel, defines, target)
                a, b = ' '.join(pa.split()), ' '.join(pb.split())
                rows.append(f'{rel} [{name}]: {"equal" if a == b else "DIFFERENT"} ({len(tokens(pb))} tokens)')
                self.assertEqual(a, b, f'{rel} {name}')
                self.assertEqual(tokens(pa), tokens(pb), f'{rel} {name}')
        log('define-off-tokens', '\n'.join(rows) + '\n')

    def test_prerequisites(self):
        for defines, needle in ((['-DSNAP_ANS_CONVERTED=1'], 'SNAP_ANS_CONVERTED requires SNAP_ANS_ASYNC'),
                                (['-DSNAP_ANS_ASYNC=1'], 'it needs SNAP_ROOT_CACHE_WIDE'),
                                (['-DSNAP_ATTR_CLEAN_DEFER=1'], 'it needs SNAP_ROOT_CACHE_WIDE'),
                                ([*QDEFINES, '-DSNAP_ANS_ASYNC=1', '-DSNAP_ANS_CONVERTED=1', '-DSNAP_FINE_LOCKS=0',
                                  '-DSNAP_FINE_SWITCH=0', '-DSNAP_FINE_HW=0', '-DSNAP_FAST_PAUTH_CALLS=0',
                                  '-DSNAP_PHASE_FAIR_GATE=0', '-DSNAP_DART_CONVERTED=0', '-DSNAP_FINE_SWITCH_HW=0'],
                                 'SNAP_ANS_CONVERTED needs SNAP_FINE_LOCKS')):
            defines = [d for i, d in enumerate(defines)
                       if not any(d.split('=')[0] == e.split('=')[0] for e in defines[i + 1:])]
            out = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                                  '-mgeneral-regs-only', '-fsyntax-only', '-Ishadow', '-Icompat',
                                  f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines, 'probes/xnuboot.c'],
                                 cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(out.returncode, 0)
            self.assertIn(needle, out.stderr)
        h = (ROOT / 'compat/ans.h').read_text()
        for d in ('SNAP_ANS_ASYNC', 'SNAP_ANS_CONVERTED'):
            self.assertIn(f'#ifndef {d}\n#define {d} 0\n#endif', h)

    def test_converted_bodies(self):
        code = preprocess(ROOT, 'probes/xnuboot.c', QDEFINES + ON)
        fns = functions(code)
        problems = []
        mmio = fns['fine_ans_mmio']
        ok, at = order(mmio, 'guest_service_enter_shared', 'fine_state_admits', 'fine_ans_lock(', 'ans_mmio(',
                       'ans_async_schedule(', 'ans_async_lines(', 'fine_ans_unlock(', 'guest_service_leave_shared(',
                       'runtime_enter(')
        if not ok:
            problems.append(f'fine_ans_mmio order {at}')
        raw = functions(SOURCE)['fine_ans_mmio']
        fatal = raw[raw.find('if(r) {'):]
        if 'runtime_enter' in mmio[:mmio.find('if(r) {')]:
            problems.append('fine_ans_mmio takes the token before its fatal path')
        if not ('record(c,EV_ANS' in fatal and 'runtime_leave(c,1)' in fatal):
            problems.append('fine_ans_mmio fatal path is not model_dispatch\'s EV_ANS stop')
        sptm = fns['fine_ans_sptm']
        ok, at = order(sptm, 'fine_ans_lock(', 'ans_sptm_converted(', 'ans_async_schedule(', 'ans_async_lines(',
                       'fine_ans_unlock(')
        if not ok:
            problems.append(f'fine_ans_sptm order {at}')
        ops = fns['fine_ans_ops']
        for need in ('o.frame_ref=fine_ans_frame_ref', 'o.publish=fine_sptm_publish', 'o.frame_refs=fine_ans_frame_refs'):
            if need not in ops.replace(' ', ''):
                problems.append(f'fine_ans_ops lacks {need}')
        refs = fns['fine_ans_frame_refs']
        ok, at = order(refs, 'fine_memory(', 'sptm_refs_begin(', 'fine_ans_dma_frame(', 'sptm_refs_validate(',
                       'sptm_refs_commit(')
        if not ok or refs.count('sptm_refs_commit(') != 1:
            problems.append(f'fine_ans_frame_refs is not one batch, one commit {at}')
        for name in ('fine_ans_mmio', 'fine_ans_sptm', 'fine_ans_frame_refs', 'fine_ans_ops', 'fine_ans_dma_frame'):
            body = fns[name]
            if name == 'fine_ans_mmio':
                body = body[:body.find('if(r) {')]            # its fatal path runs under the token
            called = set(re.findall(r'\b([A-Za-z_]\w*)\s*\(', body))
            bad = called & FORBIDDEN
            if bad:
                problems.append(f'{name} calls {sorted(bad)}')
        call = fns['fine_sptm_call']
        if not order(call.replace(' ', ''), 'kind=FINE_CALL_ANS_SPTM;break;', 'fine_ans_sptm(c,frame,&s)')[0]:
            problems.append('fine_sptm_call does not dispatch the table-6 calls')
        if 'if(kind!=FINE_CALL_ANS_SPTM)' not in call.replace(' ', '') and 'kind!=FINE_CALL_ANS_SPTM' not in call:
            problems.append('fine_sptm_call records EV_MONITOR for MAP/UNMAP_PAGES (call_other does not)')
        trap = fns['xnuboot_trap']
        if not order(trap, 'fine_sptm_call(', 'fine_ans_mmio(', 'runtime_enter(')[0]:
            problems.append('fine_ans_mmio is not between fine_sptm_call and runtime_enter')
        self.assertEqual(problems, [])

    def test_placement(self):
        code = preprocess(ROOT, 'probes/xnuboot.c', QDEFINES + ON)
        fns = functions(code)
        problems = []
        tick = fns['xnuboot_async_locked']
        if not order(tick, 'ans_async_tick(c, elr, frame)', 'timer_sync(c);', 'timer_eoi(intid)', 'if (ans_stop)')[0]:
            problems.append('the locked tick polls after timer_sync')
        report = code[code.find('ans_async_stop(c->root_ext->ans'):]
        if not order(report, 'ans_async_stop(', 'gpu_quiesce(c)', 'ans_window_stop(c)')[0]:
            problems.append('the stop drain is not before the GPU quiesce and ans_window_stop')
        trap = fns['xnuboot_trap']
        if not re.search(r'stop=runtime_leave\(c,stop\);\s*attr_clean_flush\(c\);', trap):
            problems.append('attr_clean_flush does not follow runtime_leave at once')
        fast = fns['fast_timer_irq']
        if not order(fast, 'ans_async_due_of(', 'ans_window_ready(', 'fast_timer_irq_gate(&g)')[0]:
            problems.append('the fast tick peeks after its gate')
        if 'g.device_due=due' not in fast.replace(' ', ''):
            problems.append('the fast tick does not decline at a ready completion')
        arm = fns['timer_arm']
        if not order(arm, 'ans_async_due_of(', 'guest_ipi_poll_delay', 'cnthp_cval_el2')[0]:
            problems.append('timer_arm does not fold the deadline in')
        disp = fns['model_dispatch']
        if not order(disp, 'ans_mmio(', 'ans_async_schedule(c)', 'ans_route(c)', 'timer_sync(c)')[0]:
            problems.append('model_dispatch does not schedule between ans_mmio and the lines')
        impl = fns['monitor_call_impl']
        if not order(impl, 'ans_sptm(s,&o,table,endpoint,frame,&ret)', 'ans_async_schedule(c)', 'ans_async_lines(c)',
                     'timer_sync(c)')[0]:
            problems.append('call_other does not route the lines after an ANS SPTM call')
        finish = fns['attr_clean_finish']
        if not order(finish, 'attr_defer', 'd->pa[d->count++]', 'publish(s->pending_pa[n]', 's->recleans++')[0]:
            problems.append('attr_clean_finish does not defer')
        self.assertEqual(problems, [])

    def test_nvme_host_mirrors_its_command(self):
        """nvmeh_submit is command() up to its SQ doorbell; nvmeh_reap is its wait's pass and its tail."""
        text = (ROOT / 'compat/nvme-host.c').read_text()
        fns = functions(text)
        cmd, sub, reap = normalized(fns['command']), normalized(fns['nvmeh_submit']), normalized(fns['nvmeh_reap'])
        head = cmd[:cmd.index('uint64_t cqe =')]
        sub_body = sub.replace('if (f->active) return NVMEH_E_BUSY; ', '')
        sub_body = sub_body[:sub_body.index('f->op = op;')]
        self.assertEqual(head, sub_body)
        tail = cmd[cmd.index('s->head = (s->head + 1)'):]
        for a, b in (('!= cid', '!= f->cid'), ('= lba;', '= f->lba;'), ('if (op == 2)', 'if (f->op == 2)'),
                     ('CLEAN(o, data, bytes)', 'CLEAN(o, f->data, f->bytes)'), ('+= bytes', '+= f->bytes'),
                     ('else if (op == 1)', 'else if (f->op == 1)')):
            tail = tail.replace(a, b)
        self.assertIn(tail.rstrip('}').strip(), reap)
        win = normalized((ROOT / 'compat/ans-window.c').read_text())
        for need in ('if (op == 2 ? !valid(b, lba, n) || !chunk_blocks(b) : op != 1 || ans_window_prepare_write(b, lba, n, &stage)) return 1;',):
            self.assertIn(need, win)


class Layout(unittest.TestCase):
    def test_ansstate_async_offsets(self):
        ansstate = load('ansstate_patched', ROOT / 'probes/ansstate.py')
        src = WORK / 'layout.c'
        fields = list(ansstate.ASYNC_OFFSETS)
        src.write_text('#include <stdio.h>\n#include <stddef.h>\n#include "ans.h"\nint main(void){\n'
                       'printf("%zu %zu %zu\\n",offsetof(struct ans_state,async),sizeof(struct ans_async),'
                       'sizeof(struct ans_state));\n' +
                       ''.join(f'printf("%zu\\n",offsetof(struct ans_async,{f}));\n' for f in fields) + 'return 0;}\n')
        exe = WORK / 'layout'
        subprocess.run(['clang', '-std=c11', '-DANS_HOST', '-DSNAP_ANS_ASYNC=1', '-Icompat', str(src), '-o', str(exe)],
                       cwd=ROOT, check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout.split()
        at, size, total = map(int, out[:3])
        self.assertEqual(at, ansstate.SIZE)
        self.assertEqual(size, ansstate.ASYNC_SIZE)
        self.assertLessEqual(total, 0x30000)
        self.assertEqual(dict(zip(fields, map(int, out[3:]))), ansstate.ASYNC_OFFSETS)
        raw = bytearray(ansstate.SIZE + ansstate.ASYNC_SIZE)
        struct.pack_into('<3Q', raw, 0, ansstate.MAGIC, ansstate.VERSION, 1 << 30)
        self.assertNotIn('async', ansstate.decode(bytes(raw)))
        struct.pack_into('<Q', raw, ansstate.SIZE, ansstate.ASYNC_MAGIC)
        struct.pack_into('<12Q', raw, ansstate.SIZE + ansstate.ASYNC_OFFSETS['counter'], *range(1, 13))
        d = ansstate.decode(bytes(raw))['async']
        self.assertEqual(d['counters']['queued'], 1)
        self.assertEqual(d['counters']['stops'], 12)
        self.assertEqual(ansstate.decode(bytes(raw[:ansstate.SIZE])).get('async'), None)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [saved[0]]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


class Decoder(unittest.TestCase):
    def record(self, perf, defines, bits):
        lay = perf.fine_layout(defines)
        size = lay['size']
        rec = bytearray(16 + 6 * size)
        struct.pack_into('<2Q', rec, 0, perf.FINE_MAGIC, bits | size << 32)
        for cpu in range(6):
            base = 16 + cpu * size
            for i, _ in enumerate(lay['calls']):
                struct.pack_into('<6Q', rec, base + lay['call'] + i * lay['bucket'], 10 + i, 100, 20, 3, 400, 1)
            struct.pack_into(f'<{len(lay["declines"])}Q', rec, base + lay['declined'],
                             *range(1, len(lay['declines']) + 1))
        return lay, rec

    def test_record_with_bit4(self):
        perf = load('perf_counters_patched', ROOT / 'tools/perf_counters.py')
        for stages, bits in (([], 1 | 2 | 4 | 16),
                             (['-DSNAP_SPTM_FINE=1', '-DSNAP_SPTM_FINE_RETYPE=1'], 1 | 2 | 4 | 8 | 16)):
            defines = QDEFINES + stages + ['-DSNAP_ANS_ASYNC=1', '-DSNAP_ANS_CONVERTED=1']
            lay, rec = self.record(perf, defines, bits)
            self.assertEqual(lay['calls'][-2:], perf.FINE_ANS_CALLS)
            self.assertEqual(lay['declines'][-1:], perf.FINE_ANS_DECLINES)
            out = perf.decode_fine_profile(bytes(rec), lay=lay, hz=19.2e6)
            self.assertTrue(out['ans_converted'])
            self.assertEqual(out['calls']['ans_sptm']['entries'], 6 * (10 + lay['calls'].index('ans_sptm')))
            self.assertEqual(out['declined']['busy'], 6 * len(lay['declines']))
            bad = bytearray(rec)
            struct.pack_into('<Q', bad, 8, (bits & ~16) | lay['size'] << 32)
            with self.assertRaises(ValueError):
                perf.decode_fine_profile(bytes(bad), lay=lay)
        # Without the define, bit 4 is refused.
        lay, rec = self.record(perf, QDEFINES, 1 | 2 | 4)
        struct.pack_into('<Q', rec, 8, 1 | 2 | 4 | 16 | lay['size'] << 32)
        with self.assertRaises(ValueError):
            perf.decode_fine_profile(bytes(rec), lay=lay)

    def test_qualification_report_decodes_identically(self):
        report = Path(ARGS.qualification).parent / 'report.bin'
        if not report.exists():
            self.skipTest(f'{report} absent')
        outs = []
        for tree in (BASE, ROOT):
            run = subprocess.run([sys.executable, '-B', 'tools/perf_counters.py', '--report', str(report),
                                  '--hz', '19200000', '--defines', *QDEFINES], cwd=tree, capture_output=True,
                                 text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            outs.append((run.returncode, run.stdout))
        self.assertEqual(outs[0], outs[1])
        self.assertEqual(outs[0][0], 0, outs[0][1][-500:])


class Cycle(unittest.TestCase):
    def test_flags(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        cycle = load('cycle_cli_nvme', ROOT / 'tools/cycle.py')
        import cycle_lib.installed_fresh as fresh  # noqa: E402
        import cycle_lib.speed_test as st  # noqa: E402
        from cycle_lib.common import Refused  # noqa: E402
        sets = st.flag_sets(ROOT)[0]
        argv = json.loads(Path(ARGS.run_args).read_text())
        base = fresh.variant_flags(sets, cycle.parse([*argv, '--check']))
        self.assertEqual(base, QUAL['flags'])
        for extra, added in ((['--nvme-async'], ON[:1]), (['--nvme-async', '--nvme-converted'], ON[:2]),
                             (['--attr-clean-defer'], ON[2:]), (['--nvme-async', '--nvme-converted',
                                                                 '--attr-clean-defer'], ON)):
            self.assertEqual(fresh.variant_flags(sets, cycle.parse([*argv, '--check', *extra])), base + added)
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, cycle.parse([*argv, '--check', '--nvme-converted']))
        no_wide = [a for a in argv if a != '--root-cache-wide']
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, cycle.parse([*no_wide, '--check', '--nvme-async']))


@unittest.skipUnless(ARGS.builds, '--builds')
class Builds(unittest.TestCase):
    def test_monitor(self):
        script = OPS / 'agents/sptm-locks/tests/build-monitor.py'
        rows = []
        for name, extra in (('off', []), ('async', ON[:1]), ('converted', ON[:2]), ('attr-defer', ON[2:]),
                            ('all', ON)):
            out = WORK / f'build-{name}'
            run = subprocess.run([sys.executable, '-B', str(script), str(ROOT), ARGS.qualification, str(out), *extra],
                                 capture_output=True, text=True, timeout=1800,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(run.returncode, 0, run.stderr[-3000:])
            got = json.loads(run.stdout.strip().splitlines()[-1])
            rows.append(f'{name}: {got["bytes"]} bytes, sha256 {got["sha256"]}, elf {got["elf_sha256"]}')
            if name == 'off':
                self.assertEqual(got['sha256'], QUAL['monitor_sha256'])
                self.assertEqual(got['elf_sha256'], QUAL['elf_sha256'])
        log('builds', '\n'.join(rows) + '\n')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
