#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_SPTM_FINE / SNAP_SPTM_FINE_RETYPE / SNAP_SPTM_FINE_KERNEL (agents/sptm-locks/FAILURE-MODES.md).

    python3 tools/test-sptm-fine.py [--base DIR] [--qualification Q.json] [--quick] [unittest args]

Offline, no hardware.
Unit: tools/test-sptm-fine.c, six pthreads running the real compat engines (user MAP/UNMAP/UPDATE_DISJOINT,
UNMAP_DISJOINT, UPDATE_REGION, RETYPE, the kernel's MAP_PAGE/UNMAP_REGION through compat/sptm-fine.h) under the
real gate, stripes, kernel lock and frame locks, interleaved with token-path calls; replay linearizability,
reference/type invariants, TLB model, kernel-view copies, lock quiescence; under ThreadSanitizer and ASan/UBSan,
with four stripes and with 64 frame-lock words (collisions), with and without the phase-fair gate.
Mutants: each failure mode's weakening in the harness must fail under at least one sanitizer.
HwWalk: tools/test-user-hw-walk.c (part 12) with SNAP_SPTM_FINE: replacements and region updates on
hardware-walk roots run through the converted update events and every differential check holds; three
weakened copies of compat/user-hw-walk.h must fail it.
Source: the define-off preprocessed tokens of every changed C file equal the base's (no flags and the
qualification's flags); probes/xnuboot.c's converted SPTM_FINE bodies reach nothing token-only (calls, fine_*
callbacks and the hardware-walk ops they hand to engines), mirror their token-path originals where they repeat
them, keep the lock release order, store to shared words only atomically, per CPU or under aux; weakened
sources must be caught.
Decoder: tools/perf_counters.py decodes a FINELCK1 record with header bit 3, and the qualification run's
report.bin decodes identically with the base and patched decoders.
Cycle: the qualification's arguments reproduce its -D flags; --sptm-fine[-retype|-kernel] append theirs
and refuse without their prerequisites.
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


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base', default=str(OPS / 'sme-batch12/Snapintosh'),
                    help='the unpatched Snapintosh tree (read only)')
    ap.add_argument('--qualification', default=str(
        OPS / 'sme-batch12/Snapintosh/build/installed-fresh-desktop-20261021-b12v5/qualification.json'))
    ap.add_argument('--quick', action='store_true')
    args, rest = ap.parse_known_args()
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(base=str(OPS / 'sme-batch12/Snapintosh'), quick=False, qualification=str(
        OPS / 'sme-batch12/Snapintosh/build/installed-fresh-desktop-20261021-b12v5/qualification.json')), [])
BASE = Path(ARGS.base)
QUAL = json.loads(Path(ARGS.qualification).read_text())
QDEFINES = [f for f in QUAL['flags'] if f.startswith('-D')]
WORK = Path(tempfile.mkdtemp(prefix='sptm-fine-'))
CALLS = '1000' if ARGS.quick else '1500'
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HEADER = (ROOT / 'compat/user-hw-walk.h').read_text()
STAGES = ['-DSNAP_SPTM_FINE=1', '-DSNAP_SPTM_FINE_RETYPE=1', '-DSNAP_SPTM_FINE_KERNEL=1']
IMPL = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'compat').glob('sptm*.c'))
IMPL += ['shadow/sprr-view.c', 'shadow/mmu.c', 'shadow/shadow.c', 'compat/service-lock.c']
HARNESS_DEFINES = ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1', '-DSNAP_FAIR_TOKEN=1', '-DSNAP_PHASE_FAIR_GATE=1',
                   '-DSNAP_FINE_HW=1', *STAGES]
CC = ['clang', '-std=gnu11', '-O1', '-g', '-pthread', '-ffunction-sections', '-Wl,-dead_strip',
      '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow']
# The pre-lock type reads that race with a converted RETYPE by design: every one is re-validated under the
# frame lock (compat/sptm-refs.c delta()). Exactly these two functions of compat/sptm-user.c.
IGNORE = WORK / 'tsan-ignore.txt'
IGNORE.write_text('fun:metadata\nfun:data_type\n')
SAN = {'tsan': ['-fsanitize=thread', f'-fsanitize-ignorelist={IGNORE}'],
       'asan': ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']}
CHANGED_C = ['probes/xnuboot.c', 'compat/sptm-refs.c', 'compat/sptm.c']
CHANGED_H = ['compat/fine-lock.h', 'compat/sptm-refs.h', 'compat/user-hw-walk.h']


def harness(san, extra=(), seed='5', calls=None, timeout=1200):
    binary = WORK / f'h-{hashlib.sha256(repr((san, tuple(extra))).encode()).hexdigest()[:12]}'
    if not binary.exists():
        overridden = {e.split('=')[0] for e in extra}
        defines = [d for d in HARNESS_DEFINES if d.split('=')[0] not in overridden]
        build = subprocess.run([*CC, *SAN[san], *defines, *extra, 'tools/test-sptm-fine.c', *IMPL,
                                '-o', str(binary)], cwd=ROOT, capture_output=True, text=True)
        if build.returncode:
            return build.returncode, 'build: ' + build.stderr[-3000:]
    env = dict(os.environ, TSAN_OPTIONS='halt_on_error=1')
    try:
        run = subprocess.run([str(binary), calls or CALLS, seed], capture_output=True, text=True,
                             timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return -9, 'timeout'
    return run.returncode, run.stdout + run.stderr


def log(name, text):
    out = os.environ.get('SPTM_FINE_LOG')
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / f'{name}.txt').write_text(text)


class Unit(unittest.TestCase):
    def check(self, name, san, extra=(), seed='5'):
        rc, out = harness(san, extra, seed)
        log(f'unit-{name}', out)
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn('replay equal', out)
        self.assertIn('aimed unmap/retype race', out)
        print(f'\n[{name}] ' + ' | '.join(l.strip() for l in out.splitlines()
                                          if 'converted' in l and ('ok' in l or 'logged' in l)), file=sys.stderr)

    def test_tsan(self):
        for seed in ('5', '11'):
            self.check(f'tsan-{seed}', 'tsan', seed=seed)

    def test_asan(self):
        for seed in ('5', '11'):
            self.check(f'asan-{seed}', 'asan', seed=seed)

    def test_four_stripes(self):
        self.check('asan-stripes4', 'asan', ['-DFINE_STRIPES=4'], seed='7')

    def test_frame_lock_collisions(self):
        self.check('tsan-framelocks64', 'tsan', ['-DSPTM_FRAME_LOCKS=64'], seed='7')

    def test_old_gate(self):
        self.check('tsan-oldgate', 'tsan', ['-DSNAP_PHASE_FAIR_GATE=0'], seed='9')


# Each must fail: (name, extra defines). FAILURE-MODES.md numbers in the comment.
MUTANTS = [
    ('a reference touch without its shared frame lock (S3)', ['-DMUTANT_NO_FRAME_SHARE']),
    ('a converted RETYPE without the exclusive frame lock (S3)', ['-DMUTANT_NO_EXCLUSIVE']),
    ('frame locks dropped before the kernel unmap\'s TLBI (S5)', ['-DMUTANT_EARLY_RELEASE']),
    ('converted kernel calls without KL (S16)', ['-DMUTANT_NO_KL']),
    ('a kernel-view copy source written (S8)', ['-DMUTANT_NO_COPIED_CHECK']),
    ('a kernel leaf change without its TLBI (S6)', ['-DMUTANT_KERNEL_NO_TLBI']),
    ('a kernel call on the token path\'s reference batch (S1)', ['-DMUTANT_KERNEL_GLOBAL_REFS']),
    ('user calls without their stripes (S16)', ['-DMUTANT_NO_STRIPES']),
    ('a store left unpublished before its TLBI (S7)', ['-DMUTANT_NO_PUBLISH']),
]


class Mutants(unittest.TestCase):
    def test_each_mutant_fails(self):
        results = []
        for name, extra in MUTANTS:
            caught = None
            for san, seed in (('tsan', '5'), ('asan', '5'), ('asan', '7'), ('tsan', '7')):
                rc, out = harness(san, extra, seed, timeout=900)
                if rc and not out.startswith('build:'):
                    reason = next((l for l in out.splitlines() if re.search(
                        r'FAIL|ThreadSanitizer: data race|AddressSanitizer|runtime error|use after|stale', l)),
                        f'exit {rc}')
                    caught = f'{san} seed {seed}: {reason.strip()[:120]}'
                    break
                self.assertFalse(out.startswith('build:'), out)
            results.append(f'{name}: {caught or "NOT CAUGHT"}')
            self.assertIsNotNone(caught, name)
        log('mutants', '\n'.join(results) + '\n')
        print('\n' + '\n'.join(results), file=sys.stderr)


HW_CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
           'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
           'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c',
           'shadow/native-view.c', 'shadow/stage2.c']
HW_DEFINES = ['-DSNAP_USER_HW_WALK=1', '-DSNAP_SPTM_FINE=1', '-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_HW=1']
HW_MUTANTS = {
    'an update that never invalidates': ('    if(invalidate)t->range(t->ctx,va,size);\n',
                                         '    (void)invalidate;(void)t;\n'),
    'an update whose copies do not follow': (
        'static inline int hw_walk_fine_after_update(const struct hw_walk_ops *o,struct hw_walk_root *r,\n'
        '    uint64_t va,uint64_t size,int invalidate,const struct hw_walk_tlb *t,struct hw_walk_fine_counts *n)\n'
        '{\n    if(!hw_walk_fine_after_add(o,r,va,size,n))return 0;',
        'static inline int hw_walk_fine_after_update(const struct hw_walk_ops *o,struct hw_walk_root *r,\n'
        '    uint64_t va,uint64_t size,int invalidate,const struct hw_walk_tlb *t,struct hw_walk_fine_counts *n)\n'
        '{\n    (void)o;n->refreshes=n->refreshed=0;if(!r)return 0;'),
    'an update into class 9 admitted': ('{return r && shift==12 && (sprr_pte_class(next)!=9 || sprr_pte_class(old)==9);}',
                                        '{(void)old;(void)next;return r && shift==12;}'),
}


def hw_walk(header=None):
    d = Path(tempfile.mkdtemp(dir=WORK))
    include = []
    if header is not None:
        (d / 'mut').mkdir()
        (d / 'mut/user-hw-walk.h').write_text(header)
        include = [f'-I{d / "mut"}']
    exe = d / 'hw'
    build = subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            '-fno-sanitize-recover=all', *HW_DEFINES, *include, '-Icompat', '-Ishadow',
                            'tools/test-user-hw-walk.c', *HW_CORE, '-o', str(exe)],
                           cwd=ROOT, capture_output=True, text=True, timeout=900)
    if build.returncode:
        return build.returncode, 'build: ' + build.stderr[-2000:]
    run = subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=3600)
    return run.returncode, run.stdout + run.stderr


class HwWalk(unittest.TestCase):
    def test_converted_updates(self):
        rc, out = hw_walk()
        log('hw-walk', out)
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn('converted updates (SNAP_SPTM_FINE)', out)
        print('\n' + '\n'.join(l for l in out.splitlines() if 'converted' in l or l.startswith('PASS')), file=sys.stderr)

    def test_weakened_headers_fail(self):
        rows = []
        for name, (old, new) in HW_MUTANTS.items():
            self.assertEqual(HEADER.count(old), 1, name)
            rc, out = hw_walk(HEADER.replace(old, new))
            rows.append(f'{name}: exit {rc}')
            self.assertNotEqual(rc, 0, name)
        log('hw-walk-mutants', '\n'.join(rows) + '\n')


# ---- source checks ------------------------------------------------------------------------------------
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


FL = load('fine_locks_tests', ROOT / 'tools/test-fine-locks.py')


def preprocess(tree, rel, defines, target=True):
    """rel in tree, preprocessed (macros expanded), as one whitespace-normalized token line."""
    args = ['clang', '-E', '-P', '-Ishadow', '-Icompat', f'-I{tree.parent / "q1n1/platform/uefi"}', *defines, rel]
    if target:
        args[1:1] = ['--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only']
    out = subprocess.run(args, cwd=tree, capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f'{tree}/{rel}: {out.stderr[-500:]}')
    return ' '.join(out.stdout.split())


# Beyond test-fine-locks.py's FORBIDDEN: what the new conversions must not reach either.
FORBIDDEN = set(FL.FORBIDDEN) | {'hw_ops', 'hw_copy_write', 'hw_copy_alloc', 'hw_copy_release', 'hw_s2_write',
                                 'hw_s2_frame', 'hw_walk_prepare', 'hw_walk_before_tpro', 'hw_walk_prune',
                                 'hw_walk_attach', 'hw_walk_detach', 'hw_walk_after_add', 'hw_walk_after_change',
                                 'hw_walk_after_unlink', 'hw_prepare_update', 'user_commit_update', 'map_page_failed',
                                 'auxkc_observe_retype'}
# Functions a converted call reaches whose bodies name token-path callbacks as values, each argued: their
# owner overrides them or never calls them on the converted envelope.
VALUE_EXEMPT = {'sptm_context_memory',   # fine_memory replaces publish and clean_frame; fine_retype clears
                                         # retype_user_tpro; sptm_map is a plain bounds check
                'fine_hw_ops',           # the converted ops themselves (checked below)
                'user_shadow', 'user_view_shadow'}   # fine locks' own: fine_native_live_shadow replaces alloc and
                                         # write; fine_user_refresh_all's audit only reads through it
TOKEN_VALUES = {'mem_write', 'hw_copy_write', 'hw_copy_alloc', 'hw_copy_release', 'table_alloc', 'user_live_write',
                'sptm_publish', 'kernel_table_write', 'hw_s2_write', 'user_table_alloc', 'private_kernel_alloc',
                'hw_tlb_range', 'native_tlbi_range'}


def effective(text, extra=()):
    return FL.functions(FL.effective_of(text, [*QDEFINES, *STAGES, *extra]))


def reach(fns, start='fine_sptm_call'):
    seen, todo = set(), [start]
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name)
        for m in re.finditer(r'\b([A-Za-z_]\w*)\b(\s*\()?', fns[name]):
            callee = m[1]
            if callee in fns and callee != 'fine_fatal' and (m[2] or callee.startswith('fine_')):
                todo.append(callee)
    return seen


def source_problems(text):
    p = []
    fns = effective(text)
    seen = reach(fns)
    for need in ('fine_unmap_disjoint', 'fine_update_region', 'fine_retype', 'fine_kernel_map', 'fine_kernel_unmap',
                 'fine_hw_commit_update', 'fine_hw_prepare_update', 'fine_hw_s2_frame', 'fine_input_frames',
                 'fine_hw_ops', 'fine_hw_copy_write', 'fine_kernel_copied'):
        if need not in seen:
            p.append(f'{need} not reached')
    if seen & FORBIDDEN:
        p.append(f'converted calls reach {sorted(seen & FORBIDDEN)}')
    # Every function the new conversions reach (not the earlier converted calls').
    mine = set()
    for start in ('fine_unmap_disjoint', 'fine_update_region', 'fine_retype', 'fine_kernel_map', 'fine_kernel_unmap',
                  'fine_hw_commit_leaf', 'fine_hw_commit_unmap', 'fine_hw_commit_update', 'fine_hw_prepare_update',
                  'fine_input_frames', 'fine_hw_s2_frame'):
        mine |= reach(fns, start)
    for name in sorted(mine - VALUE_EXEMPT):
        named = {m[1] for m in re.finditer(r'\b([A-Za-z_]\w*)\b', fns[name])} & TOKEN_VALUES
        if named:
            p.append(f'{name} names token-path callbacks {sorted(named)}')
    reached = ''.join(fns[n] for n in seen)
    for engine in ('sptm_mac_unmap_user_disjoint', 'sptm_mac_update_user_region', 'sptm_mac_retype',
                   'sptm_fine_kernel_map', 'sptm_fine_kernel_unmap', 'hw_walk_fine_after_update', 'hw_s2_set'):
        if engine not in reached:
            p.append(f'{engine} not reached')
    for fn in ('fine_unmap_disjoint', 'fine_update_region', 'fine_retype', 'fine_kernel_map', 'fine_kernel_unmap'):
        body = fns.get(fn, '')
        if 'sptm_context_memory(' in body or 'fine_memory(c)' not in body:
            p.append(f'{fn} does not run on this CPU\'s fine memory')
    # The converted hardware-walk ops: the converted writer, refusing alloc/release; the events use them.
    ops = fns.get('fine_hw_ops', '')
    if 'hw_table_read,fine_hw_copy_write,fine_hw_refuse_alloc,fine_hw_refuse_release,hw_table_type,c' not in ops:
        p.append('fine_hw_ops is not the converted writer with refusing alloc/release')
    for fn in ('fine_hw_commit_leaf', 'fine_hw_commit_unmap', 'fine_hw_commit_update'):
        if 'fine_hw_ops(c)' not in fns.get(fn, ''):
            p.append(f'{fn} does not use fine_hw_ops')
    copy = fns.get('fine_hw_copy_write', '')
    if 'if((pa&7) || pa<c->work_base || pa>=c->next_table)return -1;' not in copy or \
            'fine_user_live_write(ctx,pa,value)' not in copy:
        p.append('fine_hw_copy_write is not hw_copy_write\'s bounds and a published converted store')
    # fine_hw_commit_update: user_commit_update's hardware-walk prelude and its skip/invalidation.
    upd = fns.get('fine_hw_commit_update', '')
    for need in ('!user_cached(c,root)', 'hw_walk_fine_after_update(', '!update_fast_uncached(old)',
                 'fine_hw_tlb_range', 'fine_view_failed(c)'):
        if need not in upd:
            p.append(f'fine_hw_commit_update lacks {need}')
    if 'hw_walk_fine_prepare_update(' not in fns.get('fine_hw_prepare_update', ''):
        p.append('fine_hw_prepare_update does not refuse class 9')
    # fine_hw_s2_frame repeats hw_s2_frame's calls.
    if 'hw_s2_frame' in fns and 'fine_hw_s2_frame' in fns:
        a = [x for x in FL.calls(fns['hw_s2_frame']) if x != '_Static_assert']
        b = FL.calls(fns['fine_hw_s2_frame'])
        if a != b:
            p.append(f'fine_hw_s2_frame does not repeat hw_s2_frame: {b} != {a}')
    # RETYPE: the envelope, the exclusive frame lock before the engine, the stage-2 action after it.
    rt = fns.get('fine_retype', '')
    if not (0 <= rt.find('sptm_frame_exclusive(') < rt.find('sptm_mac_retype(') < rt.find('hw_s2_retype_action(')):
        p.append('fine_retype: exclusive frame lock, engine, stage 2 out of order')
    if 'memory.retype_user_tpro=0;' not in rt or 'auxkc.pa_end' not in rt:
        p.append('fine_retype keeps a host callback or the AuxKC range')
    # Kernel: the refusing allocator, the converted writer, the copy-source check, by-VA TLBI.
    kof = fns.get('fine_kernel_of', '')
    for need in ('.alloc=fine_refuse_alloc', '.write=fine_user_live_write', '.copied=fine_kernel_copied',
                 '.tlbi=fine_kernel_tlbi', '.guest_write=fine_mem_write'):
        if need not in kof:
            p.append(f'fine_kernel_of lacks {need}')
    if 'fine_native_tlbi_range(' not in fns.get('fine_kernel_tlbi', ''):
        p.append('fine_kernel_tlbi is not the by-VA invalidation in every VMID')
    if 'v->tables[n].source==table' not in fns.get('fine_kernel_copied', ''):
        p.append('fine_kernel_copied does not check the kernel views\' copy sources')
    # The dispatcher: frames set before the input frames and the lockset; released before the stripes and the
    # gate on both paths; KL after the stripes, released before them; fine_fatal after the gate.
    call = fns.get('fine_sptm_call', '')
    if call.count('fine_ticket_unlock(&fine_of(c)->kernel)') != 1:
        p.append('KL not released exactly once in fine_sptm_call')
    try:
        if not call.index('f->ref_fine.held=&f->frames;') < call.index('fine_input_frames(c,&s)') < \
                call.index('fine_lockset_for(c,&s,&f->locks)'):
            p.append('frame locks are not set up before the input frames and the lockset')
        first = call.index('sptm_frame_release(&f->frames);')
        stripes = call.index('fine_lockset_release(fine_of(c)->stripes,&f->locks);')
        if not call.index('fine_lockset_acquire(') < call.index('fine_ticket_lock(&fine_of(c)->kernel)') < \
                first < call.index('fine_ticket_unlock(&fine_of(c)->kernel)') < stripes < \
                call.index('guest_service_leave_shared(&c->services,v->slot);', stripes):
            p.append('lock release order in fine_sptm_call')
        if call.count('sptm_frame_release(&f->frames);') != 2:
            p.append('frame locks not released on both gate exits')
        if not call.rindex('guest_service_leave_shared') < call.index('fine_fatal('):
            p.append('fine_fatal takes the token before the gate is left')
    except ValueError as e:
        p.append(f'fine_sptm_call: {e}')
    # sptm-refs.c: the shared frame lock before the type is read.
    refs = REFS_OVERRIDE.get('text') or (ROOT / 'compat/sptm-refs.c').read_text()
    d = refs[refs.index('static enum sptm_result delta('):]
    if not d.find('sptm_frame_share(m->fine->held,pa)') < d.find('unsigned type=p[2];') or \
            'sptm_frame_share(m->fine->held,pa)' not in d:
        p.append('sptm-refs.c delta(): no shared frame lock before the type read')
    # Plain stores to context words in the new SPTM_FINE functions: per CPU, under aux, or atomic.
    for fn in ('fine_unmap_disjoint', 'fine_update_region', 'fine_retype', 'fine_kernel_map', 'fine_kernel_unmap',
               'fine_hw_commit_update', 'fine_hw_s2_frame', 'fine_input_frames', 'fine_kernel_copied'):
        for m in re.finditer(r'\bc->((?:\w|\.|->|\[[^\]]*\])+)\s*(\+\+|\+=|-=|(?<![<>!=])=(?!=))', fns.get(fn, '')):
            if not re.match(r'\w+\[(v->slot|vcpu_of\(c\)->slot|cpu)\]', m[1]):
                p.append(f'{fn}: plain store c->{m[1]}{m[2]}')
    return p


REFS_OVERRIDE = {}
SOURCE_MUTANTS = {
    'a frame-lock release that misses the decline path':
        ('    else {sptm_frame_release(&f->frames);guest_service_leave_shared(&c->services,v->slot);}',
         '    else {guest_service_leave_shared(&c->services,v->slot);}'),
    'a retype without its exclusive frame lock':
        ('    if(!sptm_frame_exclusive(&fine_cpu(c)->frames,pa&~UINT64_C(0x3fff))) {s->reason=FINE_NO_FRAME;return FINE_DECLINE;}\n',
         ''),
    'a converted event on the token path\'s hardware-walk ops': ('#define FINE_HW_OPS(c) fine_hw_ops(c)',
                                                               '#define FINE_HW_OPS(c) hw_ops(c)'),
    'a kernel shadow that allocates': ('    *s=(struct shadow){.txsz=txsz,.root=vcpu_of(c)->shadow_root,.alloc=fine_refuse_alloc,',
                                       '    *s=(struct shadow){.txsz=txsz,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,'),
    'a kernel call without the copy-source check': ('.copied=fine_kernel_copied,', '.copied=0,'),
    'an update that skips the uncached test': (
        'hw_walk_fine_after_update(&o,hw_root(c,root),va,UINT64_C(1)<<shift,!update_fast_uncached(old),&t,&n);',
        'hw_walk_fine_after_update(&o,hw_root(c,root),va,UINT64_C(1)<<shift,0,&t,&n);'),
    'a retype that refreshes the kernel': ('    memory.retype_user_tpro=0;\n',
                                           '    memory.retype_user_tpro=0;kernel_refresh(c);\n'),
    'a plain counter in a converted body': ('    if(ro)fine_add(&c->hw_walk->stats.s2_protects,1);',
                                            '    if(ro)c->hw_walk->stats.s2_protects++;'),
    'KL never released': ('#if SNAP_SPTM_FINE_KERNEL\n        if(kernel)fine_ticket_unlock(&fine_of(c)->kernel);\n#endif\n', ''),
    'KL released after the gate': (
        '#if SNAP_SPTM_FINE_KERNEL\n        if(kernel)fine_ticket_unlock(&fine_of(c)->kernel);\n#endif\n'
        '        fine_lockset_release(fine_of(c)->stripes,&f->locks);\n'
        '        uint64_t t3=service_profile_clock();\n'
        '        guest_service_leave_shared(&c->services,v->slot);\n',
        '        fine_lockset_release(fine_of(c)->stripes,&f->locks);\n'
        '        uint64_t t3=service_profile_clock();\n'
        '        guest_service_leave_shared(&c->services,v->slot);\n'
        '#if SNAP_SPTM_FINE_KERNEL\n        if(kernel)fine_ticket_unlock(&fine_of(c)->kernel);\n#endif\n'),
    'a converted retype stage 2 on the token writer': ('                                   .read=mem_read,.write=fine_hw_s2_write,.ctx=c};',
                                                        '                                   .read=mem_read,.write=hw_s2_write,.ctx=c};'),
}


class Source(unittest.TestCase):
    def test_define_off_tokens_equal_the_base(self):
        rows = []
        for rel in CHANGED_C:
            for name, defines, target in (('none', [], rel == 'probes/xnuboot.c'),
                                          ('qualification', QDEFINES, rel == 'probes/xnuboot.c'),
                                          ('qualification, =0', QDEFINES + [d.replace('=1', '=0') for d in STAGES],
                                           rel == 'probes/xnuboot.c')):
                a, b = preprocess(BASE, rel, defines, target), preprocess(ROOT, rel, defines, target)
                rows.append(f'{rel} [{name}]: {"equal" if a == b else "DIFFERENT"} ({len(b)} chars)')
                self.assertEqual(a, b, f'{rel} {name}')
        log('define-off-tokens', '\n'.join(rows) + '\n')

    def test_defaults_and_prerequisites(self):
        h = (ROOT / 'compat/fine-lock.h').read_text()
        for d in ('SNAP_SPTM_FINE', 'SNAP_SPTM_FINE_RETYPE', 'SNAP_SPTM_FINE_KERNEL'):
            self.assertIn(f'#ifndef {d}\n#define {d} 0\n#endif', h)
        for extra, needle in (([STAGES[1]], 'require SNAP_SPTM_FINE'), ([STAGES[2]], 'require SNAP_SPTM_FINE'),
                              (['-DSNAP_FINE_HW=0', STAGES[0]], 'requires SNAP_FINE_LOCKS and SNAP_FINE_HW')):
            defines = [d for d in QDEFINES if not d.startswith('-DSNAP_FINE_HW=')] + extra
            out = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                                  '-mgeneral-regs-only', '-fsyntax-only', '-Ishadow', '-Icompat',
                                  f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines, 'probes/xnuboot.c'],
                                 cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(out.returncode, 0)
            self.assertIn(needle, out.stderr)

    def test_monitor_source(self):
        problems = source_problems(SOURCE)
        self.assertEqual(problems, [])

    def test_weakened_sources_are_caught(self):
        rows = []
        for name, (old, new) in SOURCE_MUTANTS.items():
            self.assertEqual(SOURCE.count(old), 1, name)
            found = source_problems(SOURCE.replace(old, new))
            rows.append(f'{name}: {found[:2]}')
            self.assertNotEqual(found, [], name)
        refs = (ROOT / 'compat/sptm-refs.c').read_text()
        old = '        if (m->fine && !sptm_frame_share(m->fine->held,pa)) return SPTM_FRAME_BUSY;\n'
        self.assertEqual(refs.count(old), 1)
        REFS_OVERRIDE['text'] = refs.replace(old, '')
        try:
            found = source_problems(SOURCE)
        finally:
            REFS_OVERRIDE.clear()
        rows.append(f'a reference touch without its frame lock: {found[:2]}')
        self.assertNotEqual(found, [])
        log('source-mutants', '\n'.join(rows) + '\n')

    def test_existing_fine_hw_gap_is_closed(self):
        """Without SNAP_SPTM_FINE the converted MAP_PAGE/UNMAP_REGION events of SNAP_FINE_HW hand hw_ops (whose
        writer is mem_write) to the copy refresh; with it they hand fine_hw_ops."""
        off = FL.functions(FL.effective_of(SOURCE, QDEFINES))
        on = effective(SOURCE)
        self.assertIn('hw_ops(c)', off['fine_hw_commit_leaf'])
        self.assertIn('hw_copy_write', off['hw_ops'])
        self.assertIn('fine_hw_ops(c)', on['fine_hw_commit_leaf'])


class Decoder(unittest.TestCase):
    def test_record_with_bit3(self):
        perf = load('perf_counters_patched', ROOT / 'tools/perf_counters.py')
        defines = QDEFINES + STAGES
        lay = perf.fine_layout(defines)
        names = lay['calls']
        self.assertEqual(names[-5:], perf.FINE_SPTM_CALLS)
        self.assertEqual(lay['declines'][-2:], perf.FINE_SPTM_DECLINES)
        size = lay['size']
        rec = bytearray(16 + 6 * size)
        struct.pack_into('<2Q', rec, 0, perf.FINE_MAGIC, 1 | 2 | 4 | 8 | size << 32)
        for cpu in range(6):
            base = 16 + cpu * size
            for i, _ in enumerate(names):
                struct.pack_into('<6Q', rec, base + lay['call'] + i * lay['bucket'], 10 + i, 100, 20, 3, 400, 1)
            struct.pack_into(f'<{len(lay["declines"])}Q', rec, base + lay['declined'],
                             *range(1, len(lay['declines']) + 1))
        out = perf.decode_fine_profile(bytes(rec), lay=lay, hz=19.2e6)
        self.assertTrue(out['sptm_fine'])
        self.assertEqual(out['calls']['kernel_map']['entries'], 6 * (10 + names.index('kernel_map')))
        self.assertEqual(out['declined']['copied'], 6 * len(lay['declines']))
        bad = bytearray(rec)
        struct.pack_into('<Q', bad, 8, 1 | 2 | 4 | size << 32)
        with self.assertRaises(ValueError):
            perf.decode_fine_profile(bytes(bad), lay=lay)

    def test_qualification_report_decodes_identically(self):
        report = Path(ARGS.qualification).parent / 'report.bin'
        outs = []
        for tree in (BASE, ROOT):
            run = subprocess.run([sys.executable, '-B', 'tools/perf_counters.py', '--report', str(report),
                                  '--hz', '19200000', '--defines', *QDEFINES], cwd=tree, capture_output=True,
                                 text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            outs.append((run.returncode, run.stdout))
        self.assertEqual(outs[0], outs[1])


class Cycle(unittest.TestCase):
    def test_flags(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        cycle = load('cycle_cli_sptm', ROOT / 'tools/cycle.py')
        import cycle_lib.installed_fresh as fresh  # noqa: E402
        from cycle_lib.common import Refused  # noqa: E402
        wfi = load('wfi_resume_sptm', ROOT / 'tools/test-wfi-resume.py')
        sets, _ = wfi.flag_sets()
        argv = json.loads((Path(ARGS.qualification).parents[3] / 'desktop-run-args-b12v5.json').read_text())
        base = cycle.parse([*argv, '--check'])
        self.assertEqual([f for f in fresh.variant_flags(sets, base) if f.startswith('-D')], QDEFINES)
        on = cycle.parse([*argv, '--check', '--sptm-fine', '--sptm-fine-retype', '--sptm-fine-kernel'])
        flags = [f for f in fresh.variant_flags(sets, on) if f.startswith('-D')]
        self.assertEqual(flags, QDEFINES + STAGES)
        one = cycle.parse([*argv, '--check', '--sptm-fine'])
        self.assertEqual([f for f in fresh.variant_flags(sets, one) if f.startswith('-D')], QDEFINES + STAGES[:1])
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, cycle.parse([*argv, '--check', '--sptm-fine-retype']))
        no_hw = [a for a in argv if a != '--fine-hw']
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, cycle.parse([*no_hw, '--check', '--sptm-fine']))


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
