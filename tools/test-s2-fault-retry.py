#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_S2_FAULT_RETRY: bind compat/s2-fault-retry.h (a guest stage-2 translation fault whose
hardware IPA, HPFAR's, is mapped guest RAM is snapshotted and retried, bounded, instead of stopping
the run; SNAP_S2_FAULT_RETRY_STAGE1 adds the retry of a fault whose HPFAR IPA is not mapped but
whose stage-1 re-walk's is) to its host test, the monitor's wiring, the cycle flags, the work-dump
decoder and the defaults (docs/USER-HW-WALK-20261017.md "v65").

    python3 tools/test-s2-fault-retry.py
    python3 tools/test-s2-fault-retry.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256 --expect v65=SHA256]

Offline, no hardware and no proxy. It builds and runs (sanitized) tools/test-s2-fault-retry.c: the
fault classes (only translation faults, levels 0-3, from a lower EL), HPFAR's IPA (S1PTW drops FAR's
offset, NS is not address), the register checks (VTTBR exact, VTCR's monitor fields, HCR.VM), the
stage-2 walk (pages, 2M and 1G blocks, holes at each level, a non-identity leaf, a reserved level-3
entry, an IPA beyond T0SZ), the bounds (the same access three times in a row, more than 1000 a
second, the window restarting) and the snapshot ring. A weakened copy of each must make it FAIL.
It replays the v62, v63 and v65 stops against their work dumps (the six-CPU stage-2 tree as it was
at the stop), four ways, built without and with SNAP_S2_FAULT_RETRY_STAGE1: HPFAR naming the
reported IPA is MAPPED and retried by both, with the dump's descriptors; HPFAR naming a hole with
the re-walk's IPA mapped is STAGE1, stopped without the second define and retried only with it;
neither mapped stops; a permission fault stops. Source checks: both defines default to 0 and the
second needs the first (a build with it alone is refused); the retry sits only at the stage-2 stop
(after guards, device windows and models, never for an Adreno block) under the define, passes
SNAP_S2_FAULT_RETRY_STAGE1 to the verdict, invalidates before resuming and resumes only on RESUME;
its expected VTCR is vcpu_arch_prepare's; the stage-2 stop's terminal word carries HPFAR_EL2 under
the define and probes/run.py prints its IPA and strips it before classifying; the snapshot page is
taken at setup with a room check, zeroed, and excluded from the coverage sentinel; the event kind
has its transcript label; cycle.py --s2-fault-retry and --s2-fault-retry-stage1 add exactly their
defines, the second only with the first. Every define-free struct context offset and the context's page count are
unchanged. The decoder (tools/s2-retry-dump.py) reads a synthetic work dump laid out by clang.

--build compiles xnuboot with the control, fast and fast-wfi sets and with v65's qualified flags
(when its record is present) with the define absent, =0, =1 and =1 plus the STAGE1 define (-Werror,
the code budget, absent == =0, each of the others differs) and reports every SHA-256; --expect
NAME=SHA256 pins a default build.

Failure inventory: a permission or access-flag fault retried; an EL2 fault retried; an IPA outside
guest RAM retried; a STAGE1 fault retried without the second define, or a MAPPED one stopped; a wrong VTTBR, VTCR or VM bit retried; unbounded retries; a retry without its
invalidation; HPFAR missing from the snapshot or the re-walk's IPA reported as the hardware's; a
default build that changes; a layout change visible to define-free readers.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
DEFINE = '-DSNAP_S2_FAULT_RETRY=1'
HEADER = (ROOT / 'compat/s2-fault-retry.h').read_text()
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
RUNS = {  # the three stops: work dump, recorded IPA (the re-walk's), ESR, FAR, the dump's level-3 table
    'v62': (0x92fdde030, 0x92000046, 0x75a18a6030, 0xae37e3000),
    'v63': (0x936f0f200, 0x92000046, 0x78d4c9f200, 0xae37f1000),
    'v65': (0x9a5ce3000, 0x92000045, 0x103d08000, 0xae3873000),
}
RUN_DIR = {k: Path(os.environ.get(f'S2_RETRY_{k.upper()}_RUN', ROOT / f'build/installed-fresh-20261018-{k}'))
           for k in RUNS}
V65_QUALIFICATION = RUN_DIR['v65'] / 'qualification.json'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256',
                    help='control, fast, fast-wfi or v65: the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def compile_test(directory, header=None, sanitize=True, defines=(), name='test-s2-fault-retry'):
    exe = Path(directory) / name
    include = []
    if header is not None:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        (mut / 's2-fault-retry.h').write_text(header)
        include = [f'-I{mut}']
    cmd = ['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
           *(['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if sanitize else []),
           *defines, *include, '-Icompat', 'tools/test-s2-fault-retry.c', '-o', str(exe)]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
    return exe if result.returncode == 0 else None, result.stderr


def run(cmd):
    return subprocess.run([str(c) for c in cmd], cwd=ROOT, capture_output=True, text=True, timeout=600)


MUTANTS = {
    'a permission fault retried': ('return (fsc & 0x3c) == 0x04 ? (int)(fsc & 3) : -1;',
                                   'return (fsc & 0x34) == 0x04 ? (int)(fsc & 3) : -1;'),
    'an EL2 abort retried': ('if (ec != 0x24 && ec != 0x20) return -1;',
                             'if (ec != 0x24 && ec != 0x20 && ec != 0x25) return -1;'),
    'FAR offset kept on S1PTW': ('return page | (((esr >> 7) & 1) ? 0 : (far & 0xfff));',
                                 '(void)esr; return page | (far & 0xfff);'),
    'NS taken as address': ('((hpfar & UINT64_C(0x00000ffffffffff0)) >> 4) << 12',
                            '((hpfar & UINT64_C(0xfffffffffffffff0)) >> 4) << 12'),
    'VTTBR not compared': ('return vttbr == vttbr_expected &&', 'return (vttbr != 0 || vttbr_expected != 0) &&'),
    'VTCR RES1 bits compared': ('(vtcr & S2_RETRY_VTCR_FIELDS) == (vtcr_expected & S2_RETRY_VTCR_FIELDS)',
                                'vtcr == vtcr_expected'),
    'VTCR not compared': ('(vtcr & S2_RETRY_VTCR_FIELDS) == (vtcr_expected & S2_RETRY_VTCR_FIELDS)',
                          '((vtcr | vtcr_expected) != 0)'),
    'HCR.VM ignored': ('&& (hcr & 1);', '&& (hcr != 0);'),
    'any leaf accepted': ('return (oa & ~(span - 1)) == (ipa & ~(span - 1) & UINT64_C(0x0000fffffffff000));',
                          'return (oa | span) != 0;'),
    'a reserved level-3 entry accepted': ('            if (level == 3 && !(e & 2)) return 0;    /* reserved at level 3 */\n',
                                          ''),
    'an IPA beyond T0SZ walked': ('if (txsz < 25 || txsz > 33 || (ipa >> (64 - txsz))) return 0;',
                                  'if (txsz < 25 || txsz > 33) return 0;'),
    'the VMID taken as the root': ('uint64_t table = root & UINT64_C(0x0000fffffffff000);',
                                   'uint64_t table = root & ~UINT64_C(0xfff);'),
    'three in a row resumed': ('if (cpu->repeats >= S2_RETRY_REPEAT_MAX) return S2_RETRY_STOP_REPEAT;',
                               'if (cpu->repeats > S2_RETRY_REPEAT_MAX) return S2_RETRY_STOP_REPEAT;'),
    'the access is the PC alone': ('if (cpu->repeats && pc == cpu->last_pc && far == cpu->last_far) cpu->repeats++;',
                                   'if (cpu->repeats && pc == cpu->last_pc) cpu->repeats++;'),
    'the rate bound one late': ('if (++cpu->window_count > S2_RETRY_RATE_MAX) return S2_RETRY_STOP_RATE;',
                                'if (++cpu->window_count > S2_RETRY_RATE_MAX + 1) return S2_RETRY_STOP_RATE;'),
    'the window restarts late': ('now - cpu->window_start >= hz)', 'now - cpu->window_start >= 2 * hz)'),
    'an unmapped fault retried': ('    if (*kind == S2_RETRY_NONE) return S2_RETRY_STOP_UNMAPPED;\n', ''),
    'STAGE1 retried without SNAP_S2_FAULT_RETRY_STAGE1': (
        '    if (*kind == S2_RETRY_STAGE1 && !stage1_retry) return S2_RETRY_STOP_STAGE1;\n',
        '    (void)stage1_retry;\n'),
    'MAPPED stopped without SNAP_S2_FAULT_RETRY_STAGE1': (
        'if (*kind == S2_RETRY_STAGE1 && !stage1_retry)', 'if (*kind != S2_RETRY_NONE && !stage1_retry)'),
    'STAGE1 never retried': ('if (*kind == S2_RETRY_STAGE1 && !stage1_retry)',
                             'if (*kind == S2_RETRY_STAGE1 && stage1_retry >= 0)'),
    'wrong registers retried': ('    if (!registers_ok) return S2_RETRY_STOP_REGISTERS;\n', '    (void)registers_ok;\n'),
    'the re-walk preferred to HPFAR': (
        '*kind = hw_mapped ? S2_RETRY_MAPPED : at_mapped ? S2_RETRY_STAGE1 : S2_RETRY_NONE;',
        '*kind = at_mapped ? S2_RETRY_STAGE1 : hw_mapped ? S2_RETRY_MAPPED : S2_RETRY_NONE;'),
    'the ring unbounded': ('&s->ring[n % S2_RETRY_RING]', '&s->ring[n]'),
    'a fault not counted': ('    __atomic_fetch_add(&s->faults, 1, __ATOMIC_RELAXED);\n', ''),
}


class Host(unittest.TestCase):
    def test_unit(self):
        with tempfile.TemporaryDirectory() as d:
            exe, err = compile_test(d)
            self.assertIsNotNone(exe, err)
            r = run([exe])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertRegex(r.stdout, r'^PASS: \d+ checks')
            print(r.stdout.strip(), file=sys.stderr)

    def test_weakened_copies_fail(self):
        survived, refused = [], []
        for label, (old, new) in MUTANTS.items():
            self.assertEqual(HEADER.count(old), 1, label)
            with tempfile.TemporaryDirectory() as d:
                exe, err = compile_test(d, HEADER.replace(old, new))
                if exe is None:
                    refused.append(f'{label}: {err[-300:]}')
                    continue
                if run([exe]).returncode == 0:
                    survived.append(label)
        self.assertEqual(refused, [], 'every mutant must compile')
        self.assertEqual(survived, [], 'weakened copies passed the host test')


def dump_module():
    spec = importlib.util.spec_from_file_location('hw_walk_dump', ROOT / 'tools/hw-walk-dump.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_geometry(run_dir):
    """(work dump, its base, vCPU 0's stage-2 root, mem_low, mem_high) from a run's records."""
    dump = dump_module()
    qual = json.loads((run_dir / 'qualification.json').read_text())
    defines = [f for f in qual['flags'] if f.startswith('-D')]
    lay = dump.layouts(defines, ROOT)
    work = run_dir / 'work-dump/work.bin'
    base = int(json.loads((work.parent / 'work.json').read_text())['work'], 16)
    with open(work, 'rb') as f:
        f.seek(lay['context']['fields']['vcpus'][0] + lay['vcpu']['fields']['stage2_root'][0])
        root = struct.unpack('<Q', f.read(8))[0]
    pb, pf = (run_dir / 'params.bin').read_bytes(), lay['params']['fields']
    lo, hi = (struct.unpack_from('<Q', pb, pf[k][0])[0] for k in ('mem_low', 'mem_high'))
    return work, base, root, lo, hi


@unittest.skipUnless(any((d / 'work-dump/work.bin').is_file() for d in RUN_DIR.values()),
                     'no v62/v63/v65 work dump (set S2_RETRY_V65_RUN etc.)')
class Replay(unittest.TestCase):
    def test_the_three_stops(self):
        with tempfile.TemporaryDirectory() as d:
            exe, err = compile_test(d, sanitize=False)
            self.assertIsNotNone(exe, err)
            exe1, err = compile_test(d, sanitize=False, defines=['-DSNAP_S2_FAULT_RETRY_STAGE1=1'],
                                     name='test-s2-fault-retry-stage1')
            self.assertIsNotNone(exe1, err)
            for name, (ipa, esr, far, l3) in RUNS.items():
                run_dir = RUN_DIR[name]
                if not (run_dir / 'work-dump/work.bin').is_file():
                    continue
                work, base, root, lo, hi = run_geometry(run_dir)
                self.assertTrue(lo <= ipa < hi, name)

                def judge(hpfar_ipa, at, e=esr, binary=exe):
                    r = run([binary, '--replay', work, hex(base), hex(root), hex(lo), hex(hi), hex(e), hex(far),
                             hex((hpfar_ipa >> 12) << 4), hex(at)])
                    self.assertEqual(r.returncode, 0, r.stderr)
                    w = r.stdout.split()
                    return dict(level=int(w[1]), ipa_hw=int(w[3], 16), verdict=int(w[5]), kind=int(w[7]),
                                hw_mapped=int(w[9]), hw=[int(x, 0) for x in w[10:13]],
                                at_mapped=int(w[14]), at=[int(x, 0) for x in w[15:18]])
                for binary in (exe, exe1):
                    # 1. HPFAR naming the reported IPA: the tree maps it, MAPPED, retried by both builds.
                    j = judge(ipa, ipa, binary=binary)
                    self.assertEqual((j['verdict'], j['kind'], j['hw_mapped']), (0, 1, 1), (name, binary.name, j))
                    self.assertEqual(j['ipa_hw'], ipa, name)
                    self.assertEqual(j['level'], esr & 3, name)
                    self.assertEqual(j['hw'][0] & 3, 3, name)
                    self.assertEqual(j['hw'][1] & ~0xfff & 0x0000fffffffff000, l3, name)
                    self.assertEqual(j['hw'][2], (ipa & ~0xfff) | 0x7ff, name)
                    # 2. HPFAR naming a hole below guest RAM, the re-walk the reported IPA: STAGE1,
                    # stopped (5) by default and retried only with SNAP_S2_FAULT_RETRY_STAGE1.
                    j = judge(0x40001000, ipa, binary=binary)
                    want = 0 if binary is exe1 else 5
                    self.assertEqual((j['verdict'], j['kind'], j['hw_mapped'], j['at_mapped']), (want, 2, 0, 1),
                                     (name, binary.name, j))
                    self.assertEqual(j['at'][2], (ipa & ~0xfff) | 0x7ff, name)
                    # 3. Neither mapped: the stop, as before.
                    j = judge(0x40001000, 0, binary=binary)
                    self.assertEqual((j['verdict'], j['kind']), (2, 0), (name, j))
                    j = judge(hi + 0x1000, hi + 0x2000, binary=binary)
                    self.assertEqual((j['verdict'], j['kind']), (2, 0), (name, j))
                    # 4. A permission fault on the same address stops (an S2RO frame written).
                    j = judge(ipa, ipa, e=(esr & ~0x3f) | 0x0f, binary=binary)
                    self.assertEqual((j['level'], j['verdict']), (-1, 2), (name, j))


def unguarded(text, token):
    """Lines naming token outside every #if SNAP_S2_FAULT_RETRY branch (an #else of one is outside)."""
    stack, bad = [], []
    for n, line in enumerate(text.splitlines(), 1):
        d = line.strip()
        if d.startswith('#if'):
            stack.append(d.startswith('#if SNAP_S2_FAULT_RETRY'))
        elif d.startswith('#endif'):
            stack.pop()
        elif d.startswith('#el'):
            stack[-1] = False
        elif token in line and not any(stack) and not d.startswith(('/*', '*')):
            bad.append(n)
    return bad


def constant(expr, names):
    """Evaluate a C integer expression of |, << and names, e.g. vcpu_arch_prepare's VTCR (no eval)."""
    def value(node):
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            return names[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.BitOr, ast.LShift)):
            a, b = value(node.left), value(node.right)
            return a | b if isinstance(node.op, ast.BitOr) else a << b
        raise ValueError(f'not a constant expression: {ast.dump(node)}')
    return value(ast.parse(expr, mode='eval'))


class Wiring(unittest.TestCase):
    def test_default_off(self):
        self.assertIn('#ifndef SNAP_S2_FAULT_RETRY\n#define SNAP_S2_FAULT_RETRY 0\n#endif', SOURCE)
        self.assertIn('#ifndef SNAP_S2_FAULT_RETRY_STAGE1\n#define SNAP_S2_FAULT_RETRY_STAGE1 0\n#endif', SOURCE)
        self.assertIn('_Static_assert(!SNAP_S2_FAULT_RETRY_STAGE1 || SNAP_S2_FAULT_RETRY,', SOURCE)
        self.assertIn('#if SNAP_S2_FAULT_RETRY\n#include "../compat/s2-fault-retry.h"', SOURCE)
        # Everything the define adds is under it.
        for token in ('s2_fault_retry(', 's2_retry', 'S2_RETRY_', 'EV_S2_RETRY, ', 'c->last.repeats = hpfar'):
            self.assertEqual(unguarded(SOURCE, token), [], token)

    def test_stage1_needs_the_retry(self):
        defines = ['-DSNAP_FAST_VCPU_TRAPS=1']
        def syntax(extra):
            return subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                                   '-mgeneral-regs-only', '-Ishadow', '-Icompat',
                                   f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines, *extra,
                                   '-fsyntax-only', 'probes/xnuboot.c'], cwd=ROOT, capture_output=True, text=True)
        alone = syntax(['-DSNAP_S2_FAULT_RETRY_STAGE1=1'])
        self.assertNotEqual(alone.returncode, 0)
        self.assertIn('the STAGE1 retry is part of the stage-2 fault retry', alone.stderr)
        both = syntax([DEFINE, '-DSNAP_S2_FAULT_RETRY_STAGE1=1'])
        self.assertEqual(both.returncode, 0, both.stderr[-2000:])

    def test_the_stop_names_hpfar(self):
        abort = between(SOURCE, '    if (ec == 0x20 || ec == 0x24) {              /* abort from EL1, insn or data */',
                        '    if (ec == 0x32) {')
        self.assertIn('__asm__ volatile("mrs %0, hpfar_el2" : "=r"(hpfar));', abort)
        self.assertIn('            record(c, EV_S2_FAULT, *elr, ipa, esr, far);\n#if SNAP_S2_FAULT_RETRY\n', abort)
        self.assertIn('            c->last.repeats = hpfar;\n#endif\n        }', abort)
        self.assertEqual(SOURCE.count('record(c, EV_S2_FAULT,'), 1)
        self.assertIn('out[OUT_LAST_EVENT + 5] = c->last.repeats;', SOURCE)
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        # v65's stop with HPFAR naming its reported IPA, and with HPFAR naming a hole.
        event = (2, 0x1924d6388, 0x9a5ce3000, 0x92000045, 0x103d08000)
        for hpfar, ipa in ((0x9a5ce30, 0x9a5ce3000), (0x40001 << 4, 0x40001000)):
            stripped, got = monitor_run.stage2_stop_hpfar((*event, hpfar))
            self.assertEqual((stripped, got), ((*event, 0), hpfar))
            self.assertEqual(monitor_run.hpfar_ipa(got, event[4], event[3]), ipa)
        self.assertEqual(monitor_run.hpfar_ipa(0x9a5ce30, 0x75a18a6030, 0x92000046 | 1 << 7), 0x9a5ce3000)  # S1PTW
        self.assertEqual(monitor_run.stage2_stop_hpfar((*event, 0)), ((*event, 0), None))
        self.assertEqual(monitor_run.stage2_stop_hpfar((5, 1, 2, 3, 4, 9)), ((5, 1, 2, 3, 4, 9), None))
        self.assertEqual(monitor_run.stage2_stop_hpfar(None), (None, None))
        text = (ROOT / 'probes/run.py').read_text()
        at = text.index('        last_event, hpfar = stage2_stop_hpfar(last_event)\n')
        self.assertLess(at, text.index('verdict(*conclude(entered, fault, console, log, tally, dropped,', at))

    def test_only_at_the_stage2_stop(self):
        call = '        if (!(p->gpu.flags && block) && s2_fault_retry(c, esr, *elr, far, hpfar)) return 0;\n'
        self.assertEqual(SOURCE.count('s2_fault_retry('), 2)
        self.assertEqual(SOURCE.count(call), 1)
        at = SOURCE.index(call)
        # After the guards, the CPU-release window, device windows and models; just before the stop.
        self.assertLess(SOURCE.rindex('struct guard *g = guard_find(c, ipa);', 0, at), at)
        self.assertLess(SOURCE.rindex('return mmio_dispatch(c, frame, elr, esr, ipa, window, off);', 0, at), at)
        self.assertLess(SOURCE.rindex('return model_dispatch(c, frame, elr, esr, ipa, (unsigned)model, off);', 0, at), at)
        self.assertLess(SOURCE.rindex('unsigned block = adreno_block(ipa, p->gpu.flags);', 0, at), at)
        stop = SOURCE.index('record(c, EV_S2_FAULT, *elr, ipa, esr, far);', at)
        self.assertNotIn('return', SOURCE[at + len(call):stop].replace('#endif', ''))
        self.assertEqual(SOURCE[at - len('#if SNAP_S2_FAULT_RETRY\n'):at], '#if SNAP_S2_FAULT_RETRY\n')

    def test_the_retry(self):
        body = between(SOURCE, 'static int s2_fault_retry(struct context *c', '\n}\n') + '\n}\n'
        # The registers: this vCPU's VTTBR and the VTCR vcpu_arch_prepare programs.
        self.assertIn('e.vttbr_expected = vcpu_vttbr(v);', body)
        self.assertIn('e.vtcr_expected = s2_retry_vtcr(S2_TXSZ, parange);', body)
        for reg in ('vttbr_el2', 'vtcr_el2', 'hcr_el2', 'spsr_el2', 'ttbr0_el1', 'tcr_el1', 'mpidr_el1', 'cntpct_el0'):
            self.assertRegex(body, rf'mrs %\d, {reg}', reg)
        # HPFAR's IPA and the re-walk's, both walked through the tree VTTBR names.
        self.assertIn('e.ipa_hw = s2_retry_hpfar_ipa(hpfar, far, esr);', body)
        self.assertIn('e.ipa_at = ((esr >> 7) & 1) ? 0 : guest_pa(far);', body)
        self.assertIn('uint64_t root = e.vttbr & UINT64_C(0x0000fffffffffffe);', body)
        self.assertIn('s2_retry_walk(mem_read, c, root, S2_TXSZ, e.ipa_hw, e.d_hw)', body)
        self.assertIn('s2_retry_walk(mem_read, c, root, S2_TXSZ, e.ipa_at, e.d_at)', body)
        self.assertIn('s2_retry_dram(e.ipa_hw, p->mem_low, p->mem_high)', body)
        # Noted before the verdict acts; resumed only on RESUME, after the invalidation.
        note = body.index('s2_retry_note(s, &e,')
        gate = body.index('if (verdict != S2_RETRY_RESUME) return 0;')
        tlbi = body.index('tlbi vmalls12e1')
        self.assertLess(note, gate)
        self.assertLess(gate, tlbi)
        self.assertLess(tlbi, body.rindex('return 1;'))
        self.assertEqual(body.count('return 1;'), 1)
        self.assertIn('record(c, EV_S2_RETRY, elr, e.ipa_hw, esr, far);', body)
        self.assertIn('if (!s || level < 0 || v->slot >= S2_RETRY_CPUS) return 0;', body)
        self.assertIn('hw_mapped, at_mapped, SNAP_S2_FAULT_RETRY_STAGE1, e.counter,', body)

    def test_expected_vtcr_is_the_programmed_one(self):
        prepare = between(SOURCE, 'static int64_t vcpu_arch_prepare(struct context *c)\n{', '\n}\n')
        expr = re.search(r'uint64_t vtcr = (.*?);', prepare, re.S)[1]
        self.assertIn('if (parange > 5) parange = 5;', prepare)
        py = re.sub(r'(\d+)UL\b', r'\1', ' '.join(expr.split()))
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'v.c'
            src.write_text('#include <stdio.h>\n#include "s2-fault-retry.h"\nint main(void){for(unsigned p=0;p<6;p++)'
                           'printf("%llu\\n",(unsigned long long)s2_retry_vtcr(28,p));return 0;}\n')
            exe = Path(d) / 'v'
            subprocess.run(['cc', '-Icompat', str(src), '-o', str(exe)], cwd=ROOT, check=True)
            got = [int(x) for x in run([exe]).stdout.split()]
        want = [constant(py, {'S2_TXSZ': 28, 'parange': p}) for p in range(6)]
        self.assertEqual(got, want)

    def test_snapshot_page(self):
        setup = between(SOURCE, '} else if(c->params->txm_native.work', 'c->table_pool.head=TABLE_POOL_MAX;')
        block = between(setup, '#if SNAP_S2_FAULT_RETRY', '#endif')
        self.assertIn('if (c->next_table + S2_RETRY_PAGES * 4096 > c->work_end) return 1;', block)
        self.assertIn('c->s2_retry = (struct s2_retry_state *)c->next_table;', block)
        self.assertIn('((volatile uint64_t *)c->s2_retry)[n] = 0;', block)
        self.assertIn('c->next_table += S2_RETRY_PAGES * 4096;', block)
        self.assertLess(setup.index(block), setup.index('if(c->work_end<c->work_base'))
        exclude = between(SOURCE, 'static int txn_publish_exclude(void *ctx,uint64_t page)', '\n}\n')
        self.assertIn('if(page>=(uint64_t)c->s2_retry && page-(uint64_t)c->s2_retry<S2_RETRY_PAGES*4096)return 1;',
                      exclude)
        self.assertIn('_Static_assert(S2_RETRY_CPUS==GUEST_CPU_COUNT', SOURCE)

    def test_event_label(self):
        m = re.search(r'^#define EV_S2_RETRY (\d+)', SOURCE, re.M)
        kind = int(m[1])
        others = [int(x) for x in re.findall(r'^#define EV_\w+ +(\d+)', SOURCE, re.M)]
        self.assertEqual(others.count(kind), 1)
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        self.assertEqual(monitor_run.EVENTS[kind], 'stage-2 fault retried')

    def test_cycle_flag(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        fresh = importlib.import_module('cycle_lib.installed_fresh')
        self.assertEqual(fresh.S2_FAULT_RETRY_DEFINE, DEFINE)
        sets = {'fast': ['-DX=1']}
        base = types.SimpleNamespace(variant='fast')
        self.assertNotIn(DEFINE, fresh.variant_flags(sets, base))
        self.assertEqual(fresh.variant_flags(sets, types.SimpleNamespace(variant='fast', s2_fault_retry=True)),
                         ['-DX=1', DEFINE])
        stage1 = '-DSNAP_S2_FAULT_RETRY_STAGE1=1'
        self.assertEqual(fresh.S2_FAULT_RETRY_STAGE1_DEFINE, stage1)
        self.assertEqual(fresh.variant_flags(sets, types.SimpleNamespace(variant='fast', s2_fault_retry=True,
                                                                         s2_fault_retry_stage1=True)),
                         ['-DX=1', DEFINE, stage1])
        common = importlib.import_module('cycle_lib.common')
        with self.assertRaises(common.Refused):
            fresh.variant_flags(sets, types.SimpleNamespace(variant='fast', s2_fault_retry_stage1=True))
        cycle = (ROOT / 'tools/cycle.py').read_text()
        self.assertIn("p.add_argument('--s2-fault-retry', action='store_true',", cycle)
        self.assertIn("p.add_argument('--s2-fault-retry-stage1', action='store_true',", cycle)


def flag_sets():
    """cycle_lib/speed_test.py flag_sets(): config/monitor-flags.json + ADDED (+FAST) + CENSUS."""
    tree = ast.parse((ROOT / 'tools/build-fast-traps-monitor.py').read_text())
    lists = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name) and t.id in ('ADDED', 'FAST')}
    census = [ast.literal_eval(n.value) for n in ast.parse((ROOT / 'tools/cycle_lib/speed_test.py')
              .read_text()).body if isinstance(n, ast.Assign) and
              any(isinstance(t, ast.Name) and t.id == 'CENSUS' for t in n.targets)][0]
    base = json.loads((ROOT / 'config/monitor-flags.json').read_text())['flags']
    sets = dict(control=[*base, *lists['ADDED'], census], fast=[*base, *lists['ADDED'], *lists['FAST'], census])
    if V65_QUALIFICATION.is_file():
        sets['v65'] = json.loads(V65_QUALIFICATION.read_text())['flags']
    return sets


class Layout(unittest.TestCase):
    def test_context_offsets_unchanged(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        perf = importlib.import_module('perf_counters')
        for name, flags in flag_sets().items():
            defines = [f for f in flags if f.startswith('-D')]
            off = perf._records(ROOT / 'probes/xnuboot.c', defines)
            on = perf._records(ROOT / 'probes/xnuboot.c', defines + [DEFINE])

            def fields(block):
                return {m[2]: int(m[1]) for m in re.finditer(r'^\s*(\d+) \|   (?! )\S.* (\w+)$', block, re.M)}
            before, after = fields(off['context']), fields(on['context'])
            self.assertGreater(len(before), 100, name)
            moved = {k for k in before if after.get(k) != before[k]}
            self.assertLessEqual(moved, {'exit_profile'} & set(before), name)
            if 'exit_profile' in before:
                self.assertEqual(max(after, key=after.get), 'exit_profile', name)
            self.assertEqual(set(after) - set(before), {'s2_retry'}, name)
            self.assertEqual((perf._size(on['context']) + 4095) // 4096,
                             (perf._size(off['context']) + 4095) // 4096, name)
            self.assertLessEqual(perf._size(on['s2_retry_state']), 4096, name)
            if name == 'fast':
                both = perf._records(ROOT / 'probes/xnuboot.c', defines + [DEFINE, '-DSNAP_S2_FAULT_RETRY_STAGE1=1'])
                self.assertEqual(fields(both['context']), after, 'the STAGE1 retry adds no state')


@unittest.skipUnless(V65_QUALIFICATION.is_file(), 'no v65 qualification record (its flags lay the dump out)')
class Decoder(unittest.TestCase):
    def test_synthetic_dump(self):
        dump = dump_module()
        flags = json.loads(V65_QUALIFICATION.read_text())['flags']
        defines = [f for f in flags if f.startswith('-D')] + [DEFINE]
        lay = dump.layouts(defines, ROOT)
        base, page = 0x10000000, (lay['context']['size'] + 0xfff) & ~0xfff
        blob = bytearray(page + 4096)
        struct.pack_into('<Q', blob, lay['context']['fields']['s2_retry'][0], base + page)
        sf, ef = lay['s2_retry_state']['fields'], lay['s2_retry_entry']['fields']
        cf, esize = lay['s2_retry_cpu']['fields'], lay['s2_retry_entry']['size']
        for k, v in dict(next=3, faults=3, resumed=1, stopped=2, mapped=0, stage1=1).items():
            struct.pack_into('<Q', blob, page + sf[k][0], v)
        struct.pack_into('<Q', blob, page + sf['cpu'][0] + 3 * lay['s2_retry_cpu']['size'] + cf['resumed'][0], 1)
        vttbr, vtcr = 0xae30ad000 | 4 << 48, 0x4351c

        def entry(i, seq, info, ipa_hw, ipa_at, esr, d_hw, d_at, vtcr_now):
            at = page + sf['ring'][0] + i * esize
            vals = dict(seq=seq, counter=0x1234 + seq, mpidr=0x10300, info=info, esr=esr, far=0x103d08000,
                        hpfar=(ipa_hw >> 12) << 4, elr=0x1924d6388, spsr=0x80000000, vttbr=vttbr,
                        vttbr_expected=vttbr, vtcr=vtcr_now, vtcr_expected=vtcr, hcr=0x2c80000000db,
                        ttbr0=0x4010000123456000, tcr=0x1234, ipa_hw=ipa_hw, ipa_at=ipa_at)
            for k, v in vals.items():
                struct.pack_into('<Q', blob, at + ef[k][0], v)
            for k, ds in (('d_hw', d_hw), ('d_at', d_at)):
                for n, v in enumerate(ds):
                    struct.pack_into('<Q', blob, at + ef[k][0] + 8 * n, v)
        # Written in ring order 5, 1, 9: the decoder sorts by seq.
        entry(5, 2, 3 | 1 << 8 | 0 << 16 | 2 << 24, 0x3fff000, 0, 0x92000045, [0, 0, 0], [0, 0, 0], vtcr)
        entry(9, 3, 4 | 2 << 8 | 2 << 16 | 5 << 24, 0x40002000, 0x936f0f200, 0x92000046, [0, 0, 0],
              [0xae35b5003, 0xae37f1003, 0x936f0f7ff], vtcr)
        entry(1, 1, 3 | 1 << 8 | 2 << 16 | 0 << 24, 0x40001000, 0x9a5ce3000, 0x92000045, [0, 0, 0],
              [0xae35b5003, 0xae3873003, 0x9a5ce37ff], vtcr | 1 << 31)
        with tempfile.TemporaryDirectory() as d:
            run_dir = Path(d)
            (run_dir / 'work-dump').mkdir()
            (run_dir / 'work-dump/work.bin').write_bytes(bytes(blob))
            (run_dir / 'work-dump/work.json').write_text(json.dumps(dict(work=hex(base))))
            (run_dir / 'qualification.json').write_text(json.dumps(dict(flags=[*flags, DEFINE])))
            spec = importlib.util.spec_from_file_location('s2_retry_dump', ROOT / 'tools/s2-retry-dump.py')
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            out = mod.decode(run_dir)
            self.assertEqual(out['counters'], dict(next=3, faults=3, resumed=1, stopped=2, mapped=0, stage1=1))
            self.assertEqual(out['cpus'][3]['resumed'], 1)
            self.assertEqual([e['seq'] for e in out['entries']], [1, 2, 3])
            first, second, third = out['entries']
            self.assertEqual((third['slot'], third['level'], third['kind'], third['verdict']),
                             (4, 2, 'STAGE1', 'stopped: STAGE1 (SNAP_S2_FAULT_RETRY_STAGE1 off)'))
            self.assertEqual((first['slot'], first['level'], first['kind'], first['verdict']),
                             (3, 1, 'STAGE1', 'resumed'))
            self.assertEqual(first['same_page'], False)
            self.assertTrue(first['vttbr_ok'] and first['vtcr_ok'] and first['vm'])   # RES1 bit 31 ignored
            self.assertEqual(first['d_at'], [0xae35b5003, 0xae3873003, 0x9a5ce37ff])
            self.assertEqual(first['ipa_hw'], 0x40001000)
            self.assertEqual(second['verdict'], "stopped: neither IPA is mapped RAM")
            self.assertIsNone(second['same_page'])
            # And the printed form.
            r = run([sys.executable, '-I', ROOT / 'tools/s2-retry-dump.py', run_dir])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('3 stage-2 translation faults at the stop, 1 retried (0 MAPPED, 1 STAGE1), 2 stopped',
                          r.stdout)
            self.assertIn('a DIFFERENT page', r.stdout)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a few minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402  (import only: build() needs no hardware)
        sets = flag_sets()
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        for flags in sets.values():
            self.assertNotIn(DEFINE, flags)
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='s2-fault-retry-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_S2_FAULT_RETRY=0']), ('on', [DEFINE]),
                                     ('on-stage1', [DEFINE, '-DSNAP_S2_FAULT_RETRY_STAGE1=1'])):
                    monitor_run.FLAGS[:] = flags + extra
                    blob = monitor_run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0, f'{name}-{label}')
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                self.assertNotEqual(blobs['on'], blobs['on-stage1'], name)
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
