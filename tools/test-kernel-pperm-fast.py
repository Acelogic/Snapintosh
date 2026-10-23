#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_KERNEL_PPERM_FAST: the TPRO preflight's kernel class proof made
incremental (shadow/sprr-class-fast.h: measurement and failure modes).

    python3 tools/test-kernel-pperm-fast.py
    python3 tools/test-kernel-pperm-fast.py --bench
    python3 tools/test-kernel-pperm-fast.py --build [--out DIR] [--stack QUALIFICATION.json]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]

Offline, no hardware and no proxy. It builds and runs tools/test-kernel-pperm-fast.c
(ASan/UBSan): the incremental proof against the production proof (mapped
misses, word-verified hits) and the original word proof under random
kernel-table mutations made through models of every monitor write path,
exact state after every proof; then the faults (a missed table-memo note
found by the first sampled rescan and poisoned for good; stores missed by
both witnesses and a coverage-only swap refused at the same 64th hit as
production). Every guard has a weakened version here that must FAIL: the
header's, the leaf memo's it relies on, and the monitor source's write
witness and call graph (a proof may run only at the top of a PPERM write or
SWITCH_ROOT's install, never inside an SPTM transaction). It checks that the
define defaults to 0 and adds no context field.

--bench times the walks on a ~5,200-table tree shaped like v33's kernel tree.
--build compiles xnuboot with the control and fast flag sets of
tools/test-wfi-resume.py (and fast + -DSNAP_WFI_RESUME=1) with the define
absent, =0 and =1, and the full stack of --stack (default: v34's
qualification.json, when present) with it absent and =1; --expect NAME=SHA256
pins a default build byte for byte.

Failure inventory: a stale summary accepted (a write path that skips the
note, or a proof between a note and its store); a summary trusted at the
wrong level, for carved storage or across a restarted clock; a structure
change hidden; incomplete coverage; a weaker hit verification; drift from
the production proof; a refusal that leaves output or a summary behind; a
layout change; a default build that changed.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
FAST_H = (ROOT / 'shadow/sprr-class-fast.h').read_text()
LEAF_H = (ROOT / 'shadow/sprr-class-leaf-memo.h').read_text()
TEST_C = 'tools/test-kernel-pperm-fast.c'
LINKED = ['shadow/sprr-view.c', 'shadow/shadow.c', 'shadow/mmu.c']
V34 = ROOT / 'build/installed-fresh-20261017-v34/qualification.json'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--bench', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--stack', help='a qualification.json whose flags are the full stack (default: v34)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, bench=False, out=None, stack=None, expect=[]), [])


def compile_test(directory, shadow_dir=None, sanitize=True):
    exe = Path(directory) / 'test-kernel-pperm-fast'
    flags = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if sanitize else ['-O2']
    include = [f'-I{shadow_dir}'] if shadow_dir else []
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *flags, *include, '-Icompat',
                    '-Ishadow', TEST_C, *LINKED, '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


def mutated_shadow(directory, name, *pairs):
    """A copy of shadow/ (headers resolve each other by their own directory)
    with replacements in one header, beside a compat link for ../compat."""
    d = Path(directory)
    shutil.copytree(ROOT / 'shadow', d / 'shadow')
    (d / 'compat').symlink_to(ROOT / 'compat')
    path = d / 'shadow' / name
    text = path.read_text()
    for old, new in zip(pairs[::2], pairs[1::2]):
        if text.count(old) != 1:
            raise AssertionError(f'{name}: mutation anchor not unique: {old!r}')
        text = text.replace(old, new)
    path.write_text(text)
    return d / 'shadow'


# Weakened guards: each must make the replay FAIL.
MUTANTS = {
    # shadow/sprr-class-fast.h
    'verification marks instead of refusing': ('sprr-class-fast.h',
        'if(page>=SPRR_CLASS_PROOF_PAGES || !(p->bitmap[page/64]&(1UL<<(page%64))))return 0;',
        'if(page>=SPRR_CLASS_PROOF_PAGES)return 0;'),
    'verification range unchecked': ('sprr-class-fast.h',
        'if((pa&4095) || pa<p->first || pa>=p->limit || p->limit-pa<4096)return 0;\n    uint64_t page=(pa-p->first)>>12;\n    if(page>=SPRR_CLASS_PROOF_PAGES || !(',
        'if((pa&4095))return 0;\n    uint64_t page=(pa-p->first)>>12;\n    if(page>=SPRR_CLASS_PROOF_PAGES) return r->base(r->base_ctx,pa);\n    if(!('),
    'no hit verification': ('sprr-class-fast.h',
        'if(hit && (p->hits&AUDIT_SAMPLE_MASK)) {*out=p->result;return 1;}', 'if(hit) {*out=p->result;return 1;}'),
    'hit cadence halved': ('sprr-class-fast.h', 'if(hit && (p->hits&AUDIT_SAMPLE_MASK))', 'if(hit && (p->hits&127))'),
    'verification through the summaries': ('sprr-class-fast.h',
        'sprr_views_check_classes_mapped(&direct,forbidden,&full,sprr_class_proof_map_verify,&audit)',
        'sprr_class_leaf_check(leaf,&direct,forbidden,generations,&full,sprr_class_proof_map_verify,&audit)'),
    'classes not compared': ('sprr-class-fast.h',
        'full.pages!=p->result.pages ||\n                full.classes!=p->result.classes)', 'full.pages!=p->result.pages)'),
    'coverage kept across a miss': ('sprr-class-fast.h',
        'for(unsigned i=0;i<SPRR_CLASS_PROOF_PAGES/64;i++)bits[i]=0;', '(void)bits;'),
    'miss walk refuses unmarked pages': ('sprr-class-fast.h',
        'sprr_class_leaf_check(leaf,&direct,forbidden,generations,&full,sprr_class_proof_map,walk)',
        'sprr_class_leaf_check(leaf,&direct,forbidden,generations,&full,sprr_class_proof_map_verify,walk)'),
    'miss leaves coverage unmarked': ('sprr-class-fast.h',
        '/* sprr_class_proof_check_leaf with leaf summaries on a miss',
        'static inline const volatile uint64_t *nomark(void *ctx,uint64_t pa)\n'
        '{struct sprr_class_proof_map_reader *r=ctx;return r->base(r->base_ctx,pa);}\n'
        '/* sprr_class_proof_check_leaf with leaf summaries on a miss',
        '&full,sprr_class_proof_map,walk)', '&full,nomark,walk)'),
    'verification writes a table': ('sprr-class-fast.h',
        '    return r->base(r->base_ctx,pa);\n}',
        '    const volatile uint64_t *w=r->base(r->base_ctx,pa);\n'
        '    if(w)((volatile uint64_t *)w)[511]^=1;\n    return w;\n}'),
    'poisoned cache answers': ('sprr-class-fast.h',
        'if(!leaf || !generations || !map || !walk || leaf->stats.poisoned) {',
        'if(!leaf || !generations || !map || !walk) {'),
    'output on refusal': ('sprr-class-fast.h',
        '        if(hit)p->mismatches++;\n        p->errors++;p->valid=0;return 0;',
        '        if(hit)p->mismatches++;\n        *out=full;p->errors++;p->valid=0;return 0;'),
    # shadow/sprr-class-leaf-memo.h (the summaries this relies on)
    'generation ignored': ('sprr-class-leaf-memo.h',
        'int hit=saved && saved->generation==generation;', 'int hit=saved && saved->generation;'),
    'no sampled rescan': ('sprr-class-leaf-memo.h',
        '(cache->stats.calls%SPRR_TABLE_MEMO_SAMPLE)==0 || !!source->force', '0'),
    'mismatch not poisoned': ('sprr-class-leaf-memo.h',
        'r->cache->stats.mismatches++;r->cache->stats.poisoned=1;return 0;',
        'r->cache->stats.mismatches++;return 0;'),
    'carved storage summarized': ('sprr-class-leaf-memo.h',
        'if((token&SPRR_TABLE_MEMO_POOL) && (token>>16)) {', 'if(token>>16) {'),
    'summaries above level 3': ('sprr-class-leaf-memo.h', '    if(level==3) {\n', '    if(level>=2) {\n'),
    'invalid scan saved': ('sprr-class-leaf-memo.h',
        'if(!valid)return 0;\n            if(saved) {result.generation=generation;*saved=result;}',
        'if(saved) {result.generation=generation;*saved=result;}\n            if(!valid)return 0;'),
    'mask not rechecked': ('sprr-class-leaf-memo.h', '        if(forbidden&result.classes)return 0;\n', ''),
    'restart not detected': ('sprr-class-leaf-memo.h',
        ' || cache->stats.clock>source->clock) {', ') {'),
}


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def blank(text):
    """text with comments, strings, character literals and every #elif/#else
    branch blanked (same offsets), so braces balance per function."""
    def spaces(m):
        return re.sub(r'[^\n]', ' ', m[0])
    code = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', spaces, text, flags=re.S)
    out, stack = [], []
    for line in code.split('\n'):
        directive = re.match(r'\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b', line)
        if directive:
            kind = directive[1]
            if kind.startswith('if'):
                stack.append(True)
            elif kind in ('elif', 'else') and stack:
                stack[-1] = False
            elif kind == 'endif' and stack:
                stack.pop()
            out.append(' ' * len(line))
        else:
            out.append(line if all(stack) else ' ' * len(line))
    return '\n'.join(out)


def functions(text):
    """Top-level C function bodies by name (column-0 definitions)."""
    out, code = {}, blank(text)
    for m in re.finditer(r'^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w \*]*?\b(\w+)\s*\([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*\)\s*\{',
                         code, re.M):
        name, start, depth, i = m[1], m.end() - 1, 0, m.end() - 1
        while i < len(code):
            depth += code[i] == '{'
            depth -= code[i] == '}'
            i += 1
            if not depth:
                break
        out.setdefault(name, text[start:i])
    return out


# Functions of probes/xnuboot.c reviewed to store directly through a computed
# address. Only mem_write and table_alloc_owned store to a table page (both
# note first); xnuboot_setup zeroes the carved root_ext pages and
# xnuboot_prepare the arena before any table exists (carved pages are never
# allocator-issued, so never summarized); the others store to stage-2 guards,
# context records, device registers or guest scratch pages. A new one must be
# reviewed and added here. boot_relay_call (SNAP_BOOT_RELOCATE) copies the early-stop
# host-poll latch record between the monitor's own caller buffer and the relay buffer.
DIRECT_STORES = {'mem_write', 'table_alloc_owned', 'guard_write', 'root_slot_release', 'gpu_wr',
                 'xnuboot_setup', 'xnuboot_prepare', 'user_commit_unnest', 'update_disjoint_call',
                 'monitor_call_impl', 'boot_relay_call'}
# SNAP_FINE_LOCKS: mem_write's mirror for converted calls, reviewed like it
# (the memo note comes first and precedes the store; source_problems checks).
if 'static int fine_mem_write(void *ctx,uint64_t pa,uint64_t value)\n{' in SOURCE:
    DIRECT_STORES = DIRECT_STORES | {'fine_mem_write'}
STORE = re.compile(r'\*\s*\(\s*volatile\s+uint(?:8|16|32|64)_t\s*\*\s*\)\s*\(?[\w\->\.\+\s\*\(\)]*\)?\s*=[^=]'
                   r'|\(\s*\(\s*volatile\s+uint(?:8|16|32|64)_t\s*\*\s*\)[^;]*?\)\s*\[[^\]]*\]\s*=[^=]'
                   r'|\bvolatile\s+uint64_t\s*\*\s*\w+\s*=')


def callers(fns, name):
    return sorted(f for f, body in fns.items() if f != name and re.search(r'\b' + name + r'\b', body))


def source_problems(text):
    """Every reason the monitor source would let the fast proof trust a stale
    summary or differ from the define-off build. Empty means none."""
    p = []
    if text.count('#ifndef SNAP_KERNEL_PPERM_FAST\n#define SNAP_KERNEL_PPERM_FAST 0\n#endif') != 1:
        p.append('define does not default to 0')
    if not re.search(r'_Static_assert\(!SNAP_KERNEL_PPERM_FAST \|\|\s*\(SNAP_CLASS_PROOF_MAPPED && '
                     r'SNAP_KERNEL_CLASS_PROOF && SNAP_USER_TREE_MEMO &&\s*!SNAP_CLASS_LEAF_MEMO\)', text):
        p.append('prerequisite assertion missing')
    if text.count('#if SNAP_KERNEL_PPERM_FAST\n#include "sprr-class-fast.h"\n#endif') != 1:
        p.append('header not included under the define')
    fns = functions(text)
    pre = fns.get('pperm_tpro_preflight', '')
    branch = between(pre, '#elif SNAP_KERNEL_PPERM_FAST', '#else') if '#elif SNAP_KERNEL_PPERM_FAST' in pre else ''
    if not re.search(r'int proved=sprr_class_proof_check_fast\(&c->kernel_class_proof,&k,1UL<<9,\s*'
                     r'c->work_base,c->work_end,&kernel,class_table_read,c,&walk,\s*'
                     r'&c->class_leaf,&c->table_memo\);', branch):
        p.append('preflight does not call the fast proof with the table memo')
    if len(re.findall(r'\bsprr_class_proof_check_fast\b', text)) != 1:
        p.append('fast proof used outside the preflight')
    # The write witness: every arena write path notes the page first.
    mw = fns.get('mem_write', '')
    guard = 'if(pa>=c->work_base && pa<c->next_table && c->next_table-pa>=8 &&\n       *(volatile uint64_t *)pa!=value) {'
    note = '#if SNAP_USER_TREE_MEMO'
    if guard not in mw:
        p.append('mem_write change test moved')
    else:
        block = mw[mw.index(guard) + len(guard):]
        first = [l.strip() for l in block.splitlines() if l.strip() and not l.strip().startswith(('/*', '*'))][:2]
        if first != [note, 'sprr_table_memo_note(&c->table_memo,pa);']:
            p.append('mem_write does not note the table memo first')
        if mw.find('sprr_table_memo_note(&c->table_memo,pa);') > mw.find('*(volatile uint64_t *)pa = value;'):
            p.append('mem_write stores before noting')
    fine = fns.get('fine_mem_write', '')
    if fine and not (0 <= fine.find('sprr_table_memo_note_fine(&c->table_memo,pa);') <
                     fine.find('*(volatile uint64_t *)pa = value;')):
        p.append('fine_mem_write stores before noting')
    al = fns.get('table_alloc_owned', '')
    zero = 'for (unsigned n = 0; n < 0x1000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;'
    if not (0 <= al.find('sprr_table_memo_alloc(&c->table_memo,table);') < al.find(zero)):
        p.append('table_alloc_owned zeroes before noting')
    sm = fns.get('sptm_shadow_map', '')
    loop = ('for(uint64_t page=pa&~4095UL;size && page<pa+size;page+=4096)\n'
            '        sprr_table_memo_note(&c->table_memo,page);')
    if not (0 <= sm.find(loop) < sm.find('return (volatile uint8_t *)pa;')) or \
            not re.search(r'#if SNAP_USER_TREE_MEMO[^#]*' + re.escape(loop), sm):
        p.append('sptm_shadow_map does not note every mapped page')
    backends = re.findall(r'\.map_shadow=(\w+)', text)
    if not backends or set(backends) != {'sptm_shadow_map'}:
        p.append('an SPTM backend maps tables without the note')
    stores = {f for f, body in fns.items() if STORE.search(body)}
    if stores != DIRECT_STORES:
        p.append(f'unreviewed direct stores: {sorted(stores ^ DIRECT_STORES)}')
    # Call graph: a proof runs only at the top of a PPERM write or a root install.
    expect = {'pperm_tpro_preflight': ['kernel_change_pperm_impl'],
              'kernel_change_pperm_impl': ['kernel_change_pperm_timed'],
              'kernel_change_pperm_timed': ['kernel_change_pperm', 'user_root_install'],
              'kernel_change_pperm': ['xnuboot_trap_locked'],
              'user_root_install': ['monitor_call_impl']}
    for callee, want in expect.items():
        got = callers(fns, callee)
        if got != want:
            p.append(f'{callee} reached from {got}, not only {want}')
    mc = fns.get('monitor_call_impl', '')
    switch_root = mc.find('case SPTM_FN_SWITCH_ROOT:')
    switch_end = mc.find('case ', switch_root + 1) if switch_root >= 0 else -1
    if len(re.findall(r'\buser_root_install\b', mc)) != 1 or switch_root < 0 or \
            '.install=user_root_install' not in mc[switch_root:switch_end]:
        p.append('user_root_install is not only the SWITCH_ROOT installer')
    sa = fns.get('xnuboot_trap_locked', '')
    if len(re.findall(r'\bkernel_change_pperm\b', sa)) != 1 or \
            'sprr_access_with(sprr,reg,is_read,&value,kernel_change_pperm,c)' not in sa:
        p.append('kernel_change_pperm is not only the PPERM write callback')
    return p


def source_problems_compat():
    """SPTM transactions map whole table pages, so the per-page note covers
    every store made through the pointer."""
    p = []
    for path in sorted((ROOT / 'compat').glob('*.c')):
        for size in re.findall(r'map_shadow\(\s*b->ctx\s*,\s*\w+\s*,\s*([^)]+)\)', read_source(path)):
            if size.strip() not in ('4096', '0x1000'):
                p.append(f'{path.name}: map_shadow of {size.strip()}')
    return p


SOURCE_MUTANTS = {
    'map without the note': ('#if SNAP_USER_TREE_MEMO\n    /* The caller may store through this pointer without mem_write.',
                             '#if 0\n    /* The caller may store through this pointer without mem_write.'),
    'store before the note': ('#if SNAP_USER_TREE_MEMO\n        /* First, so even a store refused below cannot leave a stale claim.\n'
                              '         * Canonical and private pages alike: both are memo inputs. */\n'
                              '        sprr_table_memo_note(&c->table_memo,pa);\n#endif\n',
                              ''),
    'zero before the note': ('    sprr_table_memo_alloc(&c->table_memo,table);\n#endif\n'
                             '    for (unsigned n = 0; n < 0x1000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;',
                             '#endif\n    for (unsigned n = 0; n < 0x1000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;\n'
                             '#if SNAP_USER_TREE_MEMO\n    sprr_table_memo_alloc(&c->table_memo,table);\n#endif'),
    'a proof inside a transaction': ('    c->attr_updates.pending=0;\n    if(user && kernel && ((p->tcr>>16)&63)==17) {',
                                     '    c->attr_updates.pending=0;\n    kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,1);\n'
                                     '    if(user && kernel && ((p->tcr>>16)&63)==17) {'),
    'a new direct store': ('#if SNAP_KERNEL_CLASS_PROOF\n    sprr_class_proof_forget(&c->kernel_class_proof);',
                           '#if SNAP_KERNEL_CLASS_PROOF\n    *(volatile uint64_t *)c->next_table=0;\n'
                           '    sprr_class_proof_forget(&c->kernel_class_proof);'),
    'a new indexed store': ('#if SNAP_KERNEL_CLASS_PROOF\n    sprr_class_proof_forget(&c->kernel_class_proof);',
                            '#if SNAP_KERNEL_CLASS_PROOF\n    ((volatile uint64_t *)c->next_table)[3]=0;\n'
                            '    sprr_class_proof_forget(&c->kernel_class_proof);'),
    'default on': ('#define SNAP_KERNEL_PPERM_FAST 0', '#define SNAP_KERNEL_PPERM_FAST 1'),
    'another map_shadow': ('vcpu_of(c)->guest_tcr};\n    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,\n'
                           '        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,',
                           'vcpu_of(c)->guest_tcr};\n    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,\n'
                           '        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_map,'),
    'the old proof under the define': ('int proved=sprr_class_proof_check_fast(', 'int proved=sprr_class_proof_check_leaf('),
    'no prerequisites': ('(SNAP_CLASS_PROOF_MAPPED && SNAP_KERNEL_CLASS_PROOF && SNAP_USER_TREE_MEMO &&\n     !SNAP_CLASS_LEAF_MEMO)',
                         '(SNAP_CLASS_PROOF_MAPPED && SNAP_KERNEL_CLASS_PROOF)'),
}


class Replay(unittest.TestCase):
    def test_differential_and_faults(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([str(compile_test(d))], capture_output=True, text=True, timeout=600)
            self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-2000:])
            lines = result.stdout.strip().splitlines()
            self.assertTrue(lines[-1].startswith('PASS:'), result.stdout[-2000:])
            print('\n'.join(lines[-2:]), file=sys.stderr)

    def test_weakened_guards_fail(self):
        for name, (header, *pairs) in MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                shadow = mutated_shadow(d, header, *pairs)
                exe = compile_test(d, shadow_dir=shadow)
                result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120)
                self.assertNotEqual(result.returncode, 0, f'{name}: the weakened guard passed')


class Source(unittest.TestCase):
    def test_monitor_source(self):
        self.assertEqual(source_problems(SOURCE), [])
        self.assertEqual(source_problems_compat(), [])

    def test_weakened_sources_are_caught(self):
        for name, (old, new) in SOURCE_MUTANTS.items():
            with self.subTest(name):
                self.assertEqual(SOURCE.count(old), 1, name)
                self.assertNotEqual(source_problems(SOURCE.replace(old, new)), [], name)

    def test_header_failure_modes_come_first(self):
        head = FAST_H[:FAST_H.index('static inline')]
        self.assertIn('Failure modes, written before the code', head)
        self.assertEqual(re.findall(r'^ \* (\d)\. ', head, re.M), [str(n) for n in range(1, 10)])

    def test_no_context_field(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        import perf_counters  # noqa: E402
        sets, _ = flag_sets()
        defines = [f for f in sets['fast'] if f.startswith('-D')]
        off = perf_counters._records(ROOT / 'probes/xnuboot.c', defines)['context']
        on = perf_counters._records(ROOT / 'probes/xnuboot.c', defines + ['-DSNAP_KERNEL_PPERM_FAST=1'])['context']
        self.assertEqual(off, on)


@unittest.skipUnless(ARGS.bench, 'pass --bench to time the walks')
class Bench(unittest.TestCase):
    def test_bench(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([str(compile_test(d, sanitize=False)), '--bench'],
                                    capture_output=True, text=True, timeout=600)
            self.assertEqual(result.returncode, 0, result.stdout)
            print(result.stdout, file=sys.stderr)


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


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (about two minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        sets, _ = flag_sets()
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        stack = Path(ARGS.stack) if ARGS.stack else V34
        qualified = None
        if stack.exists():
            record = json.loads(stack.read_text())
            sets['stack'] = record['flags']
            qualified = record.get('monitor_sha256')
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='kernel-pperm-fast-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                self.assertNotIn('-DSNAP_KERNEL_PPERM_FAST=1', flags)
                blobs = {}
                labels = (('default', []), ('on', ['-DSNAP_KERNEL_PPERM_FAST=1'])) if name == 'stack' else \
                    (('default', []), ('off', ['-DSNAP_KERNEL_PPERM_FAST=0']), ('on', ['-DSNAP_KERNEL_PPERM_FAST=1']))
                for label, extra in labels:
                    run.FLAGS[:] = flags + extra
                    blob = blobs[label] = run.build('xnuboot', out / f'{name}-{label}')
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0, f'{name}-{label}')
                if 'off' in blobs:
                    self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name], name)
            if qualified:
                self.assertEqual(results['stack-default']['sha256'], qualified, 'stack: not its qualified monitor')
        finally:
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
