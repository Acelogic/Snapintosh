#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_EL0_MEMO (batch 6): the EL0 read's fetch memo and the user return's second-level PAC derivation cache.

    python3 tools/test-el0-memo.py
    python3 tools/test-el0-memo.py --build [--out DIR] [--expect SHA256]

Offline: no hardware, no proxy, nothing written under build/.

  native   tools/test-el0-memo.c (written before the implementation; its header lists the failure modes it covers)
           under ASan/UBSan, with the bitsliced AES and without: compat/el0-memo.h against random 4K/16K source and
           4K hardware trees with a mutation campaign, fast_el0_sysreg with FAST_CROSS_EL0_MEMO, and
           pauth_domain_user_cached_wide against a renamed define-free pauth-domain.c on every call.
  mutants  every listed source mutant of the deciders must make that test fail.
  hooks    probes/xnuboot.c under the define: the prerequisites, the install bump first in both root installers,
           fast_el0_word/fast_el0_note/user_instruction_read/user_return_root, the user return's derivation, the
           epoch bump, root_ext's state; each define-off text is the original.
  --build  installed-fresh-20261020-v4's flags with the define absent, =0 and =1: -Werror, the code budget,
           absent == =0, =1 differs; --expect requires the default build's SHA-256 (v4: d2480a9a...).
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
VECTOR = (ROOT / 'compat/fast-vector.h').read_text()
MEMO = (ROOT / 'compat/el0-memo.h').read_text()
DOMAIN = (ROOT / 'compat/pauth-domain.c').read_text()
DEFINE = '-DSNAP_EL0_MEMO=1'
SANITIZE = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all']
RENAME = ['-Dpauth_domain_init=ref_pauth_domain_init', '-Dpauth_domain_user=ref_pauth_domain_user',
          '-Dpauth_domain_user_with=ref_pauth_domain_user_with',
          '-Dpauth_domain_user_cached=ref_pauth_domain_user_cached',
          '-Dpauth_root_enables=ref_pauth_root_enables']
V4 = ROOT / 'build/installed-fresh-20261020-v4/launch.json'


def arguments():
    ap = argparse.ArgumentParser(add_help=False)
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
    return True


def build_test(directory, include=(), bitslice=True):
    directory = Path(directory)
    common = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *SANITIZE]
    aes = ['-DSNAP_AES_BITSLICE=1'] if bitslice else []
    inc = [f'-I{p}' for p in include]
    ref = directory / 'ref.o'
    subprocess.run([*common, *aes, '-Icompat', '-c', 'compat/pauth-domain.c', '-o', str(ref), *RENAME],
                   cwd=ROOT, check=True, capture_output=True)
    exe = directory / 'test-el0-memo'
    sources = ['tools/test-el0-memo.c', 'compat/pauth-domain.c', 'compat/aes.c', 'shadow/mmu.c',
               'compat/exception.c', 'compat/clock.c']
    if include:
        # A mutant's tree carries its own pauth-domain.c.
        sources = [str(Path(include[0]) / 'pauth-domain.c') if s == 'compat/pauth-domain.c' else s for s in sources]
    subprocess.run([*common, DEFINE, *aes, '-DFAST_CROSS_EL0_SYSREG=1', '-DFAST_CROSS_EL0_MEMO=1', *inc,
                    '-Icompat', '-Ishadow', *sources, str(ref), '-o', str(exe)],
                   cwd=ROOT, check=True, capture_output=True)
    return exe


class Native(unittest.TestCase):
    def test_sanitized(self):
        for bitslice in (True, False):
            with tempfile.TemporaryDirectory() as d:
                exe = build_test(d, bitslice=bitslice)
                r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=600)
                self.assertEqual(r.returncode, 0, r.stderr[-2000:])
                self.assertIn('PASS:', r.stdout)
                print(('bitsliced: ' if bitslice else 'byte AES: ') + r.stdout.strip().splitlines()[-1],
                      file=sys.stderr)


# (file, original, mutant): each must make the C test fail.
MUTANTS = [
    ('el0-memo.h', 'if(read(ctx,w->at[i],&value) || value!=w->value[i])return 0;',
                   'if(read(ctx,w->at[i],&value))return 0;'),
    ('el0-memo.h', 'if(w->overflow || !w->reads || w->reads>EL0_MEMO_READS)return 0;', ''),
    ('el0-memo.h', '{return w->installs==m->installs && w->active==active;}', '{return w->active==active;}'),
    ('el0-memo.h', '{return w->installs==m->installs && w->active==active;}', '{return w->installs==m->installs;}'),
    ('el0-memo.h', '    m->pending.valid=0;\n    for(unsigned n=0;n<EL0_MEMO_WAYS;n++)', '    for(unsigned n=0;n<EL0_MEMO_WAYS;n++)'),
    ('el0-memo.h', 'el0_memo_replay(&w->walk[0],source_read,source_ctx) &&\n', ''),
    ('el0-memo.h', '&&\n        el0_memo_replay(&w->walk[1],hardware_read,hardware_ctx)', ''),
    ('el0-memo.h', 'w->hardware_root==hardware_root && w->hardware_kind==hardware_kind &&', ''),
    ('el0-memo.h', 'p->valid=p->walk[0].reads && !p->walk[0].overflow && p->walk[1].reads && !p->walk[1].overflow;',
                   'p->valid=1;'),
    ('el0-memo.h', 'if(!read)m->pending.valid=0;', ''),
    ('el0-memo.h', "p->page!=(pc&~UINT64_C(0xfff)) || ", ''),
    ('el0-memo.h', 'p->source_root!=root || ', ''),
    ('el0-memo.h', ' || p->installs!=m->installs', ''),
    ('el0-memo.h', 'for(unsigned n=0;n<EL0_MEMO_WAYS && !w;n++)if(m->way[n].valid && m->way[n].page==p->page)w=&m->way[n];', ''),
    ('el0-memo.h', 'else w->overflow=1;', ''),
    ('fast-vector.h', '                fetched!=FAST_EL0_FETCH_PROVEN &&\n', ''),
    ('fast-vector.h', '                fetched!=FAST_EL0_FETCH_PROVEN &&\n', '                0 &&\n'),
    ('pauth-domain.c', '    if(wide->epoch!=epoch) {', '    if(0) {'),
    ('pauth-domain.c', '        for(unsigned n=0;n<PAUTH_DERIVE_CACHE;n++)cache->entry[n].valid=0;\n', ''),
    ('pauth-domain.c', 'for(unsigned w=0;w<PAUTH_DERIVE_WIDE_WAYS;w++)if(same_inputs(&wide->entry[set][w],s)) {',
                       'for(unsigned w=0;w<PAUTH_DERIVE_WIDE_WAYS;w++)if(wide->entry[set][w].valid) {'),
    ('pauth-domain.c', '            block[i]=first[k][i]^(uint8_t)(word>>((i&7)*8));',
                       '            block[i]=first[0][i]^(uint8_t)(word>>((i&7)*8));'),
    ('pauth-domain.c', '    if(!wide->first_ready || wide->first_hardware!=(uint64_t)hardware) {',
                       '    if(!wide->first_ready && wide->epoch==2) {'),
    ('pauth-domain.c', '        cache->hits++;wide->hits++;return 1;', '        cache->hits++;return 1;'),
    ('pauth-domain.c', '    if(!cache || !wide || !epoch || !d ||', '    if(!cache || !wide || !d ||'),
]


class Mutants(unittest.TestCase):
    def test_mutants_fail(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            survived = []
            for n, (name, original, mutant) in enumerate(MUTANTS):
                text = (ROOT / 'compat' / name).read_text()
                self.assertEqual(text.count(original), 1, (name, original))
                tree = d / f'm{n}'
                tree.mkdir()
                for f in list((ROOT / 'compat').glob('*.h')) + [ROOT / 'compat/pauth-domain.c']:
                    (tree / f.name).write_bytes(f.read_bytes())
                (tree / name).write_text(text.replace(original, mutant))
                (tree / 'out').mkdir()
                try:
                    exe = build_test(tree / 'out', include=[tree])
                except subprocess.CalledProcessError:
                    continue
                r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=600)
                if r.returncode == 0:
                    survived.append((name, original[:70]))
            self.assertEqual(survived, [])
            print(f'{len(MUTANTS)} mutants, all killed', file=sys.stderr)


class Hooks(unittest.TestCase):
    def test_prerequisites(self):
        self.assertIn('#ifndef SNAP_EL0_MEMO\n#define SNAP_EL0_MEMO 0\n#endif\n'
                      '#if SNAP_EL0_MEMO && !(SNAP_PAUTH_EL0_LIVE && SNAP_ROOT_CACHE_WIDE)\n#error', SOURCE)
        self.assertIn('#define FAST_CROSS_EL0_MEMO SNAP_EL0_MEMO', SOURCE)
        self.assertLess(SOURCE.index('#define FAST_CROSS_EL0_MEMO SNAP_EL0_MEMO'),
                        SOURCE.index('#include "../compat/fast-vector.h"'))
        self.assertIn('#ifndef FAST_CROSS_EL0_MEMO\n#define FAST_CROSS_EL0_MEMO 0\n#endif', VECTOR)
        ext = between(SOURCE, 'struct root_ext {\n', '\n};\n')
        self.assertTrue(ordered(ext, ['#if SNAP_EL0_MEMO', 'struct el0_memo_cpu el0_memo[GUEST_CPU_COUNT];',
                                      'struct pauth_derive_wide derive_wide[GUEST_CPU_COUNT];',
                                      'uint64_t pauth_epoch;', '#endif']))
        self.assertTrue(ext.rstrip().endswith('#endif'))   # appended last

    def test_install_bump_first(self):
        for name in ('static void user_root_install(void *ctx', 'static void fine_user_root_install(void *ctx'):
            body = between(SOURCE, name, '\n}\n')
            first = body.index('{\n') + 2
            self.assertTrue(body[first:].startswith(
                '    struct context *c=ctx;struct vcpu *v=vcpu_of(c);\n#if SNAP_EL0_MEMO\n'
                '    /* Before anything changes: this vCPU\'s EL0 fetch memo is stale. */\n'
                '    el0_memo_installed(&EL0M(c)[v->slot]);\n#endif\n'), name)
        # The only installers, and the only writers of a CPU's active root call install first.
        self.assertEqual(SOURCE.count('.install='), 2)
        self.assertIn('.install=user_root_install,.ctx=c,', SOURCE)
        self.assertIn('.install=fine_user_root_install,.ctx=c,', SOURCE)
        root = read_source(ROOT / 'compat/sptm-root.c')
        stores = [i for i in range(len(root)) if root.startswith('s->active[cpu]=', i) or
                  root.startswith('__atomic_store_n(&s->active[cpu],', i)]
        self.assertEqual(len(stores), 4)
        for at in stores:
            self.assertIn('b->install(', root[max(0, at - 1600):at])

    def test_fetch_and_note(self):
        word = between(SOURCE, 'static int fast_el0_word(', '\n}\n')
        self.assertTrue(ordered(word, [
            '#if SNAP_EL0_MEMO', 'if(el0_memo_answer(c,pc,out))return FAST_EL0_FETCH_PROVEN;',
            'el0_memo_begin(&EL0M(c)[cpu],pc,c->user_roots.active[cpu]);', '#endif',
            'struct sptm_root_cached *root=user_return_root(c);', '#if SNAP_EL0_MEMO',
            'int read=root && user_instruction_read(c,root,pc,&source,&hardware,&word);',
            'el0_memo_end(&EL0M(c)[cpu],read);', 'if(!read)return 0;', '#else',
            'if(!root || !user_instruction_read(c,root,pc,&source,&hardware,&word))return 0;', '#endif',
            '(struct fast_el0_fetch){source.descriptor,hardware.descriptor,source.pa,root->root,word}']))
        answer = between(SOURCE, 'static int el0_memo_answer(', '\n}\n')
        self.assertTrue(ordered(answer, [
            'el0_memo_find(m,pc)', 'if(!w)return 0;', 'c->user_roots.active[cpu]',
            '!el0_memo_current(m,w,active) || !e->valid || e->root!=active || user_return_check(c,e)!=e',
            'el0_memo_drop(w);m->stats.stale++;return 0;',
            'hw_walk_of_entry(c->hw_walk,e)!=0', 'hardware_kind ? hw_table_read : kernel_table_read',
            'el0_memo_check(w,e,e->root,e->format ? 12u : 14u,user_hw_root(c,e,cpu),hardware_kind,',
            'user_source_read,c,hardware_read,c) || !user_code_word(c,pa,&word)',
            'el0_memo_drop(w);m->stats.changed++;return 0;',
            '(struct fast_el0_fetch){w->source_leaf,w->hardware_leaf,pa,e->root,word}', 'm->stats.hits++;']))
        note = between(SOURCE, 'static void fast_el0_note(', '\n}\n')
        self.assertTrue(note.rstrip().endswith('#if SNAP_EL0_MEMO\n    /* Both reads agreed and the word was emulated: '
                                               'keep that read\'s record. */\n    el0_memo_keep(&EL0M(c)[v->slot],pc,root);\n#endif'))

    def test_instruction_read(self):
        fn = between(SOURCE, 'static int user_instruction_read(', '\n}\n')
        # The walk reads through the recording reader only while fast_el0_word records.
        self.assertTrue(ordered(fn, [
            '#if SNAP_EL0_MEMO', 'struct el0_memo_cpu *memo=el0_memo_recording(c);',
            'hardware_kind ? hw_table_read : kernel_table_read;',
            'mmu_walk(&source,target,memo ? el0_memo_read : user_source_read,memo ? (void *)&rs : c,&a)',
            'mmu_walk(&hardware,target,memo ? el0_memo_read : hardware_read,memo ? (void *)&rh : c,&b)',
            '#else\n#if SNAP_USER_HW_WALK', 'mmu_walk(&source,target,user_source_read,c,&a)',
            'mmu_walk(&hardware,target,hardware_read,c,&b)', '#else',
            'mmu_walk(&hardware,target,kernel_table_read,c,&b)', '#endif\n#endif', 'a.pa!=b.pa',
            '#if SNAP_EL0_MEMO', 'if(!user_code_word(c,a.pa,&code_word))return 0;',
            '*source_leaf=a;*hardware_leaf=b;*word=code_word;',
            'if(memo)el0_memo_recorded(memo,e,source.root,source.granule_shift,hardware.root,hardware_kind,',
            '#else', 'struct sptm_memory m=sptm_context_memory(c);', '#endif']))
        # user_code_word is the define-off tail, statement for statement.
        code = between(SOURCE, 'static int user_code_word(', '\n}\n')
        tail = between(fn, '#else\n    struct sptm_memory m=sptm_context_memory(c);', '#endif')[len('#else\n'):]
        norm = lambda t: [s.strip() for s in t.replace('a.pa', 'pa').split(';') if s.strip()]
        self.assertEqual(norm(between(code, 'struct sptm_memory m', 'return 1')),
                         norm(tail.split('*source_leaf=a;*hardware_leaf=b;')[0] + '*word=*(volatile uint32_t *)code;'))
        self.assertIn('return m->recording ? m : 0;', between(SOURCE, 'static struct el0_memo_cpu *el0_memo_recording(', '\n}\n'))

    def test_root_split(self):
        on = between(SOURCE, '#if SNAP_EL0_MEMO\n/* The lookup, then every other check', '#else\n')
        self.assertIn('return user_return_check(c,e);', on)
        off = between(SOURCE, '#else\nstatic struct sptm_root_cached *user_return_root(struct context *c)\n{',
                      'static int user_source_read(')
        self.assertTrue(ordered(off, ['struct sptm_root_cached *e=user_cached(c,c->user_roots.active[v->slot]);',
                                      'if(!e)e=hw_record_entry(c,c->user_roots.active[v->slot]);', '#endif\n#endif',
                                      'if(!e || !e->asid', 'return e;\n}']))

    def test_derivation_and_epoch(self):
        resume = between(SOURCE, 'int xnuboot_pauth_resume(const uint64_t *frame)\n{', '\n}\n')
        self.assertTrue(ordered(resume, [
            'c->pauth_key_version[v->slot]!=state->writes', '#if SNAP_EL0_MEMO',
            'pauth_domain_user_cached_wide(&c->pauth_domain,state,&c->pauth_derive[v->slot],',
            '&c->root_ext->derive_wide[v->slot],c->root_ext->pauth_epoch,', 'bank->guest,(int)c->aes_hardware))',
            '#else', 'pauth_domain_user_cached(&c->pauth_domain,state,&c->pauth_derive[v->slot],', '#endif',
            'return xnuboot_pauth_failed(frame);', 'pauth_switch_enter(bank)']))
        prepare = between(SOURCE, 'int64_t xnuboot_prepare(void)\n{', '\n}\n')
        self.assertTrue(ordered(prepare, ['if(!pauth_domain_prepare(c))return -24;', '#if SNAP_EL0_MEMO',
                                          'c->root_ext->pauth_epoch++;', '#endif']))
        self.assertEqual(SOURCE.count('pauth_epoch++'), 1)
        self.assertEqual(SOURCE.count('pauth_domain_init('), 1)
        # The pointer-signing helpers keep the first level only (their converted-call audit).
        for name in ('static enum sptm_result user_pointer_call(', 'static enum sptm_result user_pointer_batch('):
            self.assertNotIn('derive_wide', between(SOURCE, name, '\n}\n'))
        # pauth-domain.c: the wide path's derivation skips only the constant first block.
        self.assertIn('uint8_t block[16]="SnapintoshPACv1";\n        block[15]=(uint8_t)k;\n'
                      '        if(!encrypt(&d->master,block,first[k],hardware))return 0;', DOMAIN)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a few minutes)')
class Build(unittest.TestCase):
    def test_default_identity(self):
        flags = json.loads(V4.read_text())['flags']
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(ARGS.out) if ARGS.out else Path(tmp)
            res = {}
            for name, extra in (('absent', []), ('zero', ['-DSNAP_EL0_MEMO=0']), ('on', [DEFINE])):
                runner = runpy.run_path(str(ROOT / 'probes/run.py'))
                runner['FLAGS'][:] = [f for f in flags if 'SNAP_EL0_MEMO' not in f] + extra
                blob = runner['build']('xnuboot', out / name)
                self.assertLessEqual(len(blob), runner['OUT_AT'] - runner['CODE_AT'])
                res[name] = hashlib.sha256((out / name / 'xnuboot.bin').read_bytes()).hexdigest()
            print(json.dumps(res), file=sys.stderr)
            self.assertEqual(res['absent'], res['zero'])
            self.assertNotEqual(res['absent'], res['on'])
            if ARGS.expect:
                self.assertEqual(res['absent'], ARGS.expect)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST])
