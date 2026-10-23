#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_MULTIPAGE_FAST (agents/sptm-locks/multipage/FAILURE-MODES.md P1-P18), offline.

Unit      tools/test-multipage-fast.c under TSan and ASan (6 threads), and single-threaded against the
          original per-frame path (-DREFERENCE): equal final tables, copies, snapshot and answers.
Mutants   each weakened harness build must fail (MUTANT_UNPATCHED_WORD must pass through P9's full sync).
Source    the harness's copies equal probes/xnuboot.c; define-off preprocessed tokens equal the base's;
          the prerequisites refuse; the ordering of the new paths; source mutants are caught.
Cycle     the reconstructed b12v16 argv reproduces its qualification's flags; --multipage-fast appends the
          define; its refusals.

The monitor's byte identity is checked separately (agents/sptm-locks/tests/build-monitor.py)."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(os.environ.get('SNAPINTOSH_OPS', '/nonexistent/set-SNAPINTOSH_OPS'))  # operator/agent tree (baselines, receipts)


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base', default=str(OPS / 'sme-batch12/Snapintosh'))
    ap.add_argument('--qualification', default=str(
        OPS / 'sme-batch12/Snapintosh/build/installed-fresh-desktop-20261021-b12v16/qualification.json'))
    ap.add_argument('--argv', default=str(OPS / 'agents/sptm-locks/multipage/desktop-run-args-b12v16-reconstructed.json'))
    ap.add_argument('--quick', action='store_true')
    args, rest = ap.parse_known_args()
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (argparse.Namespace(
    base=str(OPS / 'sme-batch12/Snapintosh'), quick=False,
    qualification=str(OPS / 'sme-batch12/Snapintosh/build/installed-fresh-desktop-20261021-b12v16/qualification.json'),
    argv=str(OPS / 'agents/sptm-locks/multipage/desktop-run-args-b12v16-reconstructed.json')), [])
BASE = Path(ARGS.base)
QUAL = json.loads(Path(ARGS.qualification).read_text())
QDEFINES = [f for f in QUAL['flags'] if f.startswith('-D')]
DEFINE = '-DSNAP_MULTIPAGE_FAST=1'
WORK = Path(tempfile.mkdtemp(prefix='multipage-fast-'))
CALLS = '200' if ARGS.quick else '400'
LLVM_CLANG = '/opt/homebrew/opt/llvm/bin/clang'
CC = ['clang', '-std=gnu11', '-O1', '-g', '-pthread', '-ffunction-sections', '-Wl,-dead_strip',
      '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow', DEFINE, '-DSNAP_REUSE_MATCH_MAPPED=1']
SAN = {'tsan': ['-fsanitize=thread'], 'asan': ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'],
       'plain': []}


def impl(root):
    return sorted(str(p.relative_to(root)) for p in (root / 'compat').glob('sptm*.c')) + \
        ['shadow/sprr-view.c', 'shadow/mmu.c', 'shadow/shadow.c']


def log(name, text):
    out = os.environ.get('MP_LOG')
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / f'{name}.txt').write_text(text)


def harness(san, extra=(), root=ROOT):
    binary = WORK / f'h-{hashlib.sha256(repr((san, tuple(extra), str(root))).encode()).hexdigest()[:12]}'
    if not binary.exists():
        build = subprocess.run([*CC, *SAN[san], *extra, 'tools/test-multipage-fast.c', *impl(root), '-o', str(binary)],
                               cwd=root, capture_output=True, text=True)
        if build.returncode:
            return None, build.stderr[-3000:]
    return binary, ''


def run(binary, *argv, timeout=1200):
    env = dict(os.environ, TSAN_OPTIONS='halt_on_error=1')
    try:
        r = subprocess.run([str(binary), *argv], capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return -9, 'timeout'
    return r.returncode, r.stdout + r.stderr


class Unit(unittest.TestCase):
    def check(self, name, san, seed, threads='6'):
        binary, err = harness(san)
        self.assertIsNotNone(binary, err)
        rc, out = run(binary, CALLS, seed, threads)
        log(f'unit-{name}', out)
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn('PASS', out)
        self.assertIn(' 0 proof misses', out)
        print(f'\n[{name}] ' + ' | '.join(l.strip() for l in out.splitlines() if l.startswith(('fast:', 'refresh:'))),
              file=sys.stderr)

    def test_tsan(self):
        for seed in ('5', '11'):
            self.check(f'tsan-{seed}', 'tsan', seed)

    def test_asan(self):
        for seed in ('5', '11'):
            self.check(f'asan-{seed}', 'asan', seed)

    def test_equals_the_original_path(self):
        fast, err = harness('plain')
        self.assertIsNotNone(fast, err)
        ref, err = harness('plain', ['-DREFERENCE', '-Wno-unused-function'])
        self.assertIsNotNone(ref, err)
        rows = []
        for seed in ('5', '11', '23'):
            a, out_a = run(fast, '300', seed, '1')
            b, out_b = run(ref, '300', seed, '1')
            self.assertEqual((a, b), (0, 0), out_a[-2000:] + out_b[-2000:])
            da = re.search(r'digest \w+ answers \w+', out_a)[0]
            db = re.search(r'digest \w+ answers \w+', out_b)[0]
            self.assertEqual(da, db)
            misses = int(re.search(r'(\d+) proof misses', out_b)[1])
            self.assertGreater(misses, 0)
            self.assertIn(' 0 proof misses', out_a)
            rows.append(f'seed {seed}: {da}; original path {misses} full re-syncs, fast 0')
        log('equivalence', '\n'.join(rows) + '\n')


MUTANTS = [
    ('a WRITECOMB<->WRITEBACK change taken as same-class (P5)', 'MUTANT_WC_AS_WB'),
    ('a pre-clean set that outlives its trap (P2, P3)', 'MUTANT_STALE_SET'),
    ('a pre-clean that cleans nothing (P1)', 'MUTANT_NO_PRECLEAN'),
    ('copies left unpatched while the snapshot is patched (P7)', 'MUTANT_COPY_SKIP'),
    ('the second cleans registered before the TLBI (P6, P12)', 'MUTANT_FINISH_FIRST'),
    ('no publication before the TLBI (P10)', 'MUTANT_NO_PUBLISH'),
    ('no TLBI at the close (P12)', 'MUTANT_NO_TLBI'),
    ('no close before a group with records (P6)', 'MUTANT_NO_BARRIER'),
    ('PPERM variant columns left unpatched (P19)', 'MUTANT_NO_VARIANT_PATCH'),
    ('patched copy pages left pending (P20)', 'MUTANT_PENDING_LEFT'),
]


class Mutants(unittest.TestCase):
    def test_each_mutant_fails(self):
        rows = []
        for name, define in MUTANTS:
            caught = []
            for san in ('asan', 'tsan'):
                binary, err = harness(san, [f'-D{define}=1'])
                self.assertIsNotNone(binary, err)
                rc, out = run(binary, '300', '5', '6')
                if rc:
                    caught.append(f'{san}: ' + next((l for l in out.splitlines() if 'FAIL' in l or 'WARNING' in l),
                                                    f'exit {rc}'))
                    break
            self.assertTrue(caught, f'{name} ({define}) not caught')
            rows.append(f'{name}: {caught[0]}')
        log('mutants', '\n'.join(rows) + '\n')

    def test_unpatched_word_is_resynced(self):
        binary, err = harness('asan', ['-DMUTANT_UNPATCHED_WORD=1'])
        self.assertIsNotNone(binary, err)
        rc, out = run(binary, '300', '5', '6')
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn('P9:', out)
        log('mutant-unpatched-word', out)


# ---- source --------------------------------------------------------------------------------------------------
MIRRORED = ['multipage_same_class', 'multipage_preclean', 'multipage_preclean_clear', 'multipage_precleaned',
            'attr_clean_note', 'multipage_view_patch', 'multipage_aperture_fast', 'multipage_close',
            'multipage_fast', 'multipage_aperture']
SUBSTITUTIONS = [('harness_dc_civac(line);', '__asm__ volatile("dc civac, %0" :: "r"(line) : "memory");'),
                 ('harness_dsb();', '__asm__ volatile("dsb ish" ::: "memory");')]


def function(text, name):
    """A function's definition: from its line through its closing brace (prototypes and calls skipped)."""
    m = re.search(r'^[^\n;{}]*\b' + re.escape(name) + r'\([^)]*\)\s*\{', text, re.M)
    if not m:
        return None
    start = m.start()
    brace = m.end() - 1
    depth, i = 0, brace
    while True:
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if not depth:
                return text[start:i + 1]
        i += 1


def drop_mutants(text):
    out, stack = [], []
    for line in text.split('\n'):
        s = line.strip()
        m = re.match(r'#if (!?)MUTANT_\w+$', s)
        if m:
            stack.append('keep' if m.group(1) else 'drop')
            continue
        if stack and s == '#else':
            stack[-1] = 'keep' if stack[-1] == 'drop' else 'drop'
            continue
        if stack and s == '#endif':
            stack.pop()
            continue
        if stack and stack[-1] == 'drop':
            continue
        out.append(line)
    return '\n'.join(out)


def normal(text):
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'#if !SNAP_MULTIPAGE_FAST\n|^#(else|endif)$', '', text, flags=re.M)
    return ''.join(text.split())


def preprocess(root, path, defines):
    flags = [f for f in QUAL['flags'] if not f.startswith('-D') and f not in ('-flto',)]
    r = subprocess.run([LLVM_CLANG, *flags, *defines, f'-I{root / "shadow"}', f'-I{root.parent / "q1n1/platform/uefi"}',
                        '-E', '-P', str(root / path)], capture_output=True, text=True)
    return r.returncode, ' '.join(r.stdout.split()), r.stderr


SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HARNESS = (ROOT / 'tools/test-multipage-fast.c').read_text()
VIEW_C = (ROOT / 'shadow/sprr-view.c').read_text()


def source_problems(source=SOURCE, view=VIEW_C):
    """The ordering the failure modes rest on, read from the sources."""
    p = []

    def order(where, text, *parts):
        try:
            at = [text.index(x) for x in parts]
        except ValueError as e:
            p.append(f'{where}: {e} ({parts})')
            return
        if at != sorted(at):
            p.append(f'{where}: out of order: {parts}')
    trap = function(source, 'xnuboot_trap') or ''
    order('xnuboot_trap', trap, 'multipage_preclean(c, frame, esr);',
          'if (!runtime_enter(c, frame, *elr, (esr >> 26) & 63)) {multipage_preclean_clear(c);return 1;}',
          'stop=runtime_leave(c,stop);', 'attr_clean_flush(c);', 'multipage_preclean_clear(c);   /* P2')
    if trap.count('multipage_preclean(') != 1 or source.count('multipage_preclean(c') != 1:
        p.append('multipage_preclean armed somewhere else than xnuboot_trap')
    if source.count('multipage_precleaned(c,') != 1:
        p.append('the pre-clean set read outside multipage_aperture_fast')
    close = function(source, 'multipage_close') or ''
    order('multipage_close', close, 'transaction_publish(c)', '!kernel_publish_cpu(c,cpu)', 'shadow_tlb_sync(c);',
          'attr_clean_finish(c);')
    fast = function(source, 'multipage_fast') or ''
    order('multipage_fast', fast, 'if(open) {', 'multipage_close(c,elr,grp,1)', 'update_disjoint_call(')
    order('multipage_fast (failure)', fast, 'if(!multipage_aperture_fast(', 'if(open)(void)multipage_close(c,elr,grp,0);')
    ap = function(source, 'multipage_aperture_fast') or ''
    order('multipage_aperture_fast', ap, 'multipage_same_class(', 'multipage_precleaned(c,g->target)',
          'attr_clean_note(c,g->target)', 'sptm_attr_clean(c,g->target,0x4000)', 'kernel_class_proof_forget(c);',
          'sptm_papt_commit(&m,&change);', '*open=1;', 'multipage_view_patch(')
    for bad in ('transaction_publish', 'shadow_tlb_sync', 'attr_clean_finish', 'kernel_refresh'):
        if bad in ap:
            p.append(f'multipage_aperture_fast calls {bad}')
    pre = function(source, 'multipage_preclean') or ''
    if re.search(r'\*\(volatile uint64_t \*\)(h|\(h[^)]*\))\s*=(?!=)', pre):
        p.append('multipage_preclean stores to the ops page')
    for bad in ('record(', 'c->attr_updates', 'kernel_views', 'transaction_publish'):
        if bad in pre:
            p.append(f'multipage_preclean touches {bad} (token state)')
    patch = function(source, 'multipage_view_patch') or ''
    order('multipage_view_patch', patch, 'sprr_views_word_table(', 'r->valid && r->root==s.root',
          'r->pperm[cpu]==pp[cpu]', 'if(!ok) {st->unpatched++;return 1;}', 'v->saves[cpu]==r->saves',
          'v->source[n][cpu]==c->kernel_views.tables[n].source', 'sprr_views_sync_word(', 'r->words[n][index]=')
    case = SOURCE_CASE(source)
    order('MULTIPAGE case', case, '#if SNAP_MULTIPAGE_FAST', 'multipage_fast(c,&plan,*elr,cpu_scratch.pa,&response)',
          '#else', 'multipage_aperture(c,&plan.group[g],*elr,&one)', '#endif', 'c->multipage_calls++')
    table = function(view, 'sprr_views_word_table') or ''
    if 'v->tables[n].level!=3 ? -2 : n' not in table:
        p.append('sprr_views_word_table does not set level 0-2 copies apart')
    sync = function(view, 'sprr_views_sync_word') or ''
    order('sprr_views_sync_word', sync, 'v->tables[n].level!=3)return 0;', '!entry(v,s,n,index,cpu,pperm[cpu],0,0,&d[cpu])',
          '!entry(v,s,n,index,cpu,extra_pperm[cpu],0,0,&e[cpu])', 's->write(s->ctx,t->copy[cpu]+8UL*index,d[cpu])',
          's->write(s->ctx,extra[cpu]+8UL*index,e[cpu])')
    first_store = sync.find('s->write(')
    if first_store < 0 or first_store < sync.rfind('!entry('):
        p.append('sprr_views_sync_word stores before every CPU is preflighted')
    return p


def SOURCE_CASE(source):
    at = source.index('case SPTM_FN_UPDATE_DISJOINT_MULTIPAGE: {')
    return source[at:source.index('case SPTM_FN_UNMAP_DISJOINT: {', at)]


SOURCE_MUTANTS = {
    'the pre-clean set not cleared after the trap': ('    multipage_preclean_clear(c);   /* P2: no pre-clean outlives its trap */\n', ''),
    'the second cleans before the TLBI': (
        '    shadow_tlb_sync(c);\n    if(c->kernel_view_failed) {\n        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;\n    }\n    attr_clean_finish(c);\n',
        '    attr_clean_finish(c);\n    shadow_tlb_sync(c);\n    if(c->kernel_view_failed) {\n        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;\n    }\n'),
    'no close before records': ('        if(open) {\n            if(!multipage_close(c,elr,grp,1))return 0;\n            open=0;\n        }\n', ''),
    'a refresh per aperture step': ('            c->attr_updates.apertures+=change.count;\n        }\n        c->attr_updates.last_pa=g->target;\n        c->attr_updates.last_before=before;c->attr_updates.last_after=after;\n    }\n    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;\n    return 1;\nfailed:\n    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);\n    return 0;\n}\n/* P10/P12',
                                    '            c->attr_updates.apertures+=change.count;shadow_tlb_sync(c);\n        }\n        c->attr_updates.last_pa=g->target;\n        c->attr_updates.last_before=before;c->attr_updates.last_after=after;\n    }\n    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;\n    return 1;\nfailed:\n    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);\n    return 0;\n}\n/* P10/P12'),
    'the snapshot patched without its validity test': ('    int ok=n>=0 && r->valid && r->root==s.root && r->count==c->kernel_views.count;\n',
                                                       '    int ok=n>=0 && r->root==s.root && r->count==c->kernel_views.count;\n'),
    'variant columns not patched': ('        if(v->count[cpu]==c->kernel_views.count && v->saves[cpu] && v->saves[cpu]==r->saves &&\n',
                                    '        if(0 &&\n'),
    'the copy pages left pending': ('           !kernel_publish_cpu(c,cpu)) {\n            record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;\n',
                                    '           0) {\n            record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;\n'),
}
VIEW_MUTANTS = {
    'every copy translated under CPU 0\'s PPERM': ('!entry(v,s,n,index,cpu,pperm[cpu],0,0,&d[cpu])',
                                                    '!entry(v,s,n,index,cpu,pperm[0],0,0,&d[cpu])'),
    'a variant column translated under the live PPERM': ('!entry(v,s,n,index,cpu,extra_pperm[cpu],0,0,&e[cpu])',
                                                          '!entry(v,s,n,index,cpu,pperm[cpu],0,0,&e[cpu])'),
    'a level 0-2 copy word taken as patchable': ('v->tables[n].level!=3 ? -2 : n', 'n'),
}


class Source(unittest.TestCase):
    def test_harness_copies_equal_the_monitor(self):
        rows = []
        for name in MIRRORED:
            mine = function(drop_mutants(HARNESS), name)
            theirs = function(SOURCE, name)
            self.assertIsNotNone(mine, name)
            self.assertIsNotNone(theirs, name)
            for a, b in SUBSTITUTIONS:
                mine = mine.replace(a, b)
            self.assertEqual(normal(mine), normal(theirs), name)
            rows.append(f'{name}: equal ({len(normal(theirs))} chars)')
        self.assertIn('_Static_assert(SPTM_MULTIPAGE_MAX<=SPTM_DISJOINT_MAX,', SOURCE)
        log('mirror', '\n'.join(rows) + '\n')

    def test_define_off_tokens_equal_the_base(self):
        rows = []
        for path in ('probes/xnuboot.c', 'shadow/sprr-view.c'):
            for label, defines in (('none', []), ('b12v16', QDEFINES),
                                   ('b12v16, =0', QDEFINES + ['-DSNAP_MULTIPAGE_FAST=0'])):
                a, mine, err_a = preprocess(ROOT, path, defines)
                b, base, err_b = preprocess(BASE, path, defines)
                self.assertEqual((a, b), (0, 0), (path, label, err_a[-1500:], err_b[-1500:]))
                self.assertEqual(mine, base, f'{path} [{label}]')
                rows.append(f'{path} [{label}]: equal ({len(base)} chars)')
        log('define-off-tokens', '\n'.join(rows) + '\n')

    def test_prerequisites(self):
        on = QDEFINES + [DEFINE]
        rc, _, err = preprocess(ROOT, 'probes/xnuboot.c', on)
        self.assertEqual(rc, 0, err[-1500:])
        for drop in ('-DSNAP_ATTR_CLEAN_DEFER=1', '-DSNAP_KERNEL_VIEW_REUSE=1'):
            rc, _, err = preprocess(ROOT, 'probes/xnuboot.c', [d for d in on if d != drop])
            self.assertNotEqual(rc, 0, drop)
            self.assertTrue('SNAP_MULTIPAGE_FAST needs' in err or 'error' in err, drop)
        rc, _, err = preprocess(ROOT, 'probes/xnuboot.c', on + ['-DSNAP_TOKEN_TRIM=1'])
        self.assertNotEqual(rc, 0)

    def test_orders(self):
        self.assertEqual(source_problems(), [])

    def test_weakened_sources_are_caught(self):
        rows = []
        for name, (old, new) in SOURCE_MUTANTS.items():
            self.assertEqual(SOURCE.count(old), 1, name)
            found = source_problems(SOURCE.replace(old, new))
            self.assertTrue(found, name)
            rows.append(f'{name}: {found}')
        for name, (old, new) in VIEW_MUTANTS.items():
            self.assertEqual(VIEW_C.count(old), 1, name)
            tree = WORK / f'view-{hashlib.sha256(name.encode()).hexdigest()[:8]}'
            shutil.copytree(ROOT / 'compat', tree / 'compat')
            shutil.copytree(ROOT / 'shadow', tree / 'shadow')
            (tree / 'tools').mkdir()
            shutil.copy(ROOT / 'tools/test-multipage-fast.c', tree / 'tools')
            (tree / 'shadow/sprr-view.c').write_text(VIEW_C.replace(old, new))
            binary, err = harness('asan', root=tree)
            self.assertIsNotNone(binary, err)
            rc, out = run(binary, '200', '5', '1')
            self.assertNotEqual(rc, 0, name)
            rows.append(f'{name}: ' + next((l for l in out.splitlines() if 'FAIL' in l), f'exit {rc}'))
        log('source-mutants', '\n'.join(rows) + '\n')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Cycle(unittest.TestCase):
    def test_flags(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        cycle = load('cycle_cli_multipage', ROOT / 'tools/cycle.py')
        import cycle_lib.installed_fresh as fresh  # noqa: E402
        from cycle_lib.common import Refused  # noqa: E402
        wfi = load('wfi_resume_multipage', ROOT / 'tools/test-wfi-resume.py')
        sets, _ = wfi.flag_sets()
        argv = json.loads(Path(ARGS.argv).read_text())
        self.assertEqual(fresh.variant_flags(sets, cycle.parse([*argv, '--check'])), QUAL['flags'])
        on = fresh.variant_flags(sets, cycle.parse([*argv, '--check', '--multipage-fast']))
        self.assertEqual(on, QUAL['flags'] + [DEFINE])
        for drop in ('--attr-clean-defer', '--root-cache-wide'):
            with self.assertRaises(Refused):
                fresh.variant_flags(sets, cycle.parse([*[a for a in argv if a != drop], '--check', '--multipage-fast']))


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
