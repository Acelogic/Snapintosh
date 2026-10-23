#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_USER_HW_WALK: bind compat/user-hw-walk.h's hardware walk of macOS's
own 4K user tables to its differential host test, the SWITCH_ROOT hook, the
monitor's wiring and its defaults (docs/USER-HW-WALK-20261017.md).

    python3 tools/test-user-hw-walk.py
    python3 tools/test-user-hw-walk.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]

Offline, no hardware and no proxy. It builds and runs (sanitized)
tools/test-user-hw-walk.c: randomized format-1 trees changed only through the
real SPTM model, walked through the hardware-walk TTBR0 of both TPRO variants
and through the shadow path SWITCH_ROOT installs today (a fresh build plus
native views), after every call; the TLB discipline across each call; the
copy pages; the record index and ASIDs; stage-2 protection of page-table
frames; the SWITCH_ROOT hook; and deliberately corrupted inputs the audit must
refuse. Then a weakened copy of each guard (the failure modes F1-F16 in the
header) must make it FAIL. The root, memo, nest and linked-nest suites must
print the same results with the define as without it. Source checks: the
define defaults to 0 everywhere, its prerequisites are asserted, the monitor
wiring exists only under it, and the define-free layout readers keep every
offset; the state pages follow root_ext and the TXM registry and the coverage
sentinel never arms them. Fine locks (SNAP_FINE_LOCKS, docs/FINE-LOCKS-20261017.md): with the
installed-fresh set, fine locks, fine switch and the define, nothing a
converted call reaches touches hardware-walk state beyond the read-only
record lookup (with the v51 set), every call naming a root with a record declines before its
stripes (MAP_PAGE, UNMAP_REGION, every UPDATE_DISJOINT record, a SWITCH_ROOT
target) and again in its backend, and the converted switch has no hardware-
walk hook; a weakened copy of each of these must be caught. SNAP_FINE_SWITCH_HW
(FineSwitchHw): with the define as well, the converted switch to a root whose
record exists reaches the record lookup, the loaded-policy note and the
record's TTBR0 values only (never the attach, the token path's install, the
whole-arena flush or the PPERM transaction), its install repeats
hw_install_user's calls with the converted publication, its shared counters
are atomic, the compat hit keeps the token path's bounds and declines a
mismatched record, the lockset admits only that switch; weakened copies must
be caught, and the cycle wiring needs --fine-switch and --user-hw-walk.

--build compiles xnuboot with cycle.py's control and fast flag sets (and fast
with SNAP_WFI_RESUME=1) with the define absent, =0 and =1: -Werror, the code
budget, absent == =0, =1 differs. --expect NAME=SHA256 requires the default
build to equal a pre-change monitor byte for byte. It also builds the v40/v50
installed-route stack with the define (and with SNAP_USER_HW_WALK_S2RO=0, and
SNAP_IDREG_MMFR3=1), the stack with fine locks, fine switch and the FIFO token,
and that with the define; the v51 set (that plus the Prime boot relocation and
the wide TXM registry) without and with the define, and with the define but the
TXM registry narrow; and reports every SHA-256.

Failure inventory: raw or misread class 9 reachable by hardware; TPRO
writable or executable when it must not be; a path linked without its
walk-cache invalidation; a changed or removed translation without
invalidation; a stale copy entry; a copy released while linked, or leaked; a
UMPRR18 root's existing class 9 leaves not discovered; a raw root holding
class 9; shared or slot-colliding hardware ASIDs; a contiguous leaf or a
hierarchical table attribute reaching hardware; stage 2 changed on one tree
only, left read-only after release, missing a table type, accepting a
non-RAM range or changing a tree before refusing; the record index losing a
root; the SWITCH_ROOT hook skipping its reference bounds or its bookkeeping;
a default build that changed; a layout change visible to host readers.
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
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
ROOT_C = read_source(ROOT / 'compat/sptm-root.c')
HEADER = (ROOT / 'compat/user-hw-walk.h').read_text()
DEFINE = '-DSNAP_USER_HW_WALK=1'
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']
TEST_EXTRA = ('shadow/native-view.c', 'shadow/stage2.c')
STACK = ['-DSNAP_WFI_RESUME=1', '-DSNAP_FAST_EL0_SYSREG=1', '-DSNAP_SERVICE_SUBCLASS=1',
         '-DSNAP_DART_WIREDCNT=1', '-DSNAP_PANIC_SERVE=1', '-DSNAP_ROOT_MISS_FAST=1',
         '-DSNAP_UPDATE_DISJOINT_FAST=1', '-DSNAP_ROOT_CACHE_WIDE=1', '-DSNAP_UPDATE_CHECK_SPARSE=1',
         '-DSNAP_I2C_INPUT=1', '-DSNAP_KERNEL_PPERM_FAST=1', '-DADRENO_IB_POLL_DIVISOR=1u',
         '-DSNAP_UNMAP_MIXED=1']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256',
                    help='control, fast or fast-wfi: the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def compile_c(directory, test, defines, overrides=None, werror=True, extra=TEST_EXTRA, opt='-O1', sanitize=True):
    """Build tools/<test>; overrides maps 'user-hw-walk.h' or 'sptm-root.c' to a
    mutated copy placed in a private directory searched first."""
    exe = Path(directory) / Path(test).stem
    include, sources = [], [*CORE, *extra]
    if overrides:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        for name, text in overrides.items():
            (mut / name).write_text(text)
        include = [f'-I{mut}']
        if 'sptm-root.c' in overrides:
            sources = [str(mut / 'sptm-root.c') if s == 'compat/sptm-root.c' else s for s in sources]
    flags = ['cc', '-std=gnu11', opt, '-g', '-Wall', '-Wextra', *(['-Werror'] if werror else []),
             *(['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if sanitize else []), *defines, *include,
             '-Icompat', '-Ishadow', f'tools/{test}', *sources, '-o', str(exe)]
    result = subprocess.run(flags, cwd=ROOT, timeout=600, capture_output=True, text=True)
    return exe if result.returncode == 0 else None, result.stderr


def run(exe):
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=1800)


# hw_walk_prune's compaction store, and the one v55 ran (a uint64_t view of
# the struct: at -Os the remapped parent was lost).
COMPACTION_FIXED = ('        volatile struct hw_walk_table *to=&r->t[kept++];\n'
                    '        to->source=t.source;to->va=t.va;to->copy[0]=t.copy[0];to->copy[1]=t.copy[1];\n'
                    '        to->level=t.level;to->parent=t.parent;to->slot=t.slot;to->pad=t.pad;')
COMPACTION_V55 = ('        volatile uint64_t *to=(volatile uint64_t *)&r->t[kept++];\n'
                  '        const uint64_t *from=(const uint64_t *)&t;\n'
                  '        for(unsigned w=0;w<sizeof(t)/8;w++)to[w]=from[w];')

# Each weakening must make tools/test-user-hw-walk.c FAIL (or not compile):
# (file, old, new). The labels name the failure mode they reintroduce.
MUTANTS = {
    'F1 raw class 9 in the copies': ('user-hw-walk.h',
        '        d=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(UINT64_C(1)<<6);\n'
        '        if(!(w&1u))d|=UINT64_C(2)<<6;\n', ''),
    'F1 TPRO writable in the read-only variant': ('user-hw-walk.h',
        '        if(!(w&1u))d|=UINT64_C(2)<<6;\n', ''),
    'F1 TPRO executable': ('user-hw-walk.h',
        'd=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(UINT64_C(1)<<6);',
        'd=(d&~(PT_AP|PT_PXN|PT_UXN))|(UINT64_C(1)<<6);'),
    'F1 a new path is never linked': ('user-hw-walk.h',
        '        if(!hw_walk_translate(o,r,r->t[n].parent,r->t[n].slot,r->t[n].slot,0))return 0;\n'
        '        break;', '        break;'),
    'F1 existing class 9 not discovered at attach': ('user-hw-walk.h',
        '{(void)arg;return hw_walk_prepare(o,r,va)!=0;}',
        '{(void)o;(void)r;(void)va;(void)arg;return 1;}'),
    'F1 a raw root is not scanned for class 9': ('user-hw-walk.h',
        '       !hw_walk_scan(o,r,root,0,0,&tables,tpro ? hw_walk_mark_prepare : 0,0)) {',
        '       (tpro && !hw_walk_scan(o,r,root,0,0,&tables,hw_walk_mark_prepare,0))) {'),
    'F2 a linked path is not invalidated': ('user-hw-walk.h',
        'if(p==2) {t->range(t->ctx,va+off,4096);', 'if(p==2) {'),
    'F2 an unlink is not invalidated': ('user-hw-walk.h',
        '    t->range(t->ctx,0,0);\n    for(int i=0;i<dropped;i++)', '    (void)t;\n    for(int i=0;i<dropped;i++)'),
    'F3 a removed translation is not invalidated': ('user-hw-walk.h',
        '    t->range(t->ctx,va,size);return 1;', '    (void)t;return 1;'),
    'F9 copies do not follow stores': ('user-hw-walk.h',
        '    return hw_walk_refresh(o,r,va,size,&s->refreshed);', '    (void)va;(void)size;return 1;'),
    'F9 refresh misses the first entry': ('user-hw-walk.h',
        '            if(va>lo)i0=(unsigned)((va-lo)/span);', '            if(va>lo)i0=(unsigned)((va-lo)/span)+1;'),
    'F9 refresh covers only the first entry': ('user-hw-walk.h',
        '            if(end<hi)i1=(unsigned)((end-1-lo)/span);', '            i1=i0;(void)hi;'),
    'F9 unlinked copies are kept': ('user-hw-walk.h',
        '        alive[n]=(d&1) && hw_walk_table_ok(r->t[t->parent].level,d) && (d&PT_OA_MASK)==t->source;',
        '        alive[n]=1;(void)d;'),
    'F14 dropped copies released before the invalidation': ('user-hw-walk.h',
        '    t->range(t->ctx,0,0);\n    for(int i=0;i<dropped;i++)o->release(o->ctx,pages[i]);',
        '    for(int i=0;i<dropped;i++)o->release(o->ctx,pages[i]);\n    t->range(t->ctx,0,0);'),
    'F16 a refused path keeps its pages': ('user-hw-walk.h',
        '        for(unsigned n=first;n<r->count;n++)\n'
        '            for(unsigned w=0;w<2;w++)o->release(o->ctx,r->t[n].copy[w]);\n'
        '        r->count=first;return 0;', '        r->count=first;return 0;'),
    'F5 both variants share an ASID': ('user-hw-walk.h', '(r->count ? (w&1u) : 0u)', '0u'),
    'F5 hardware ASIDs in the slot range': ('user-hw-walk.h',
        '#define HW_WALK_ASID_BASE 0x400u', '#define HW_WALK_ASID_BASE 0x200u'),
    'F10 contiguous leaves admitted': ('user-hw-walk.h',
        '#define HW_WALK_LEAF_BITS (PT_OA_MASK|PT_LEAF_ATTRS|PT_LEAF_UPPER|3UL|(3UL<<58))',
        '#define HW_WALK_LEAF_BITS (PT_OA_MASK|PT_LEAF_ATTRS|PT_LEAF_UPPER|3UL|(3UL<<58)|PT_CONTIG)'),
    'F11 hierarchical table attributes admitted': ('user-hw-walk.h',
        '    return (d&PT_OA_MASK) && (attrs==3 || (level==2 && attrs==7));',
        '    return (d&PT_OA_MASK) && ((attrs&~(UINT64_C(0x1f)<<59))==3 || (level==2 && attrs==7));'),
    'F16 the record index loses a root': ('user-hw-walk.h',
        '            if(i<=j ? (home<=i || home>j) : (home<=i && home>j))break;',
        '            if(i<=j ? (home<i || home>j) : (home<i && home>j))break;'),
    'F8 stage 2 changes the first tree only': ('user-hw-walk.h',
        '    for(unsigned pass=0;pass<2;pass++)for(unsigned k=0;k<count;k++) {',
        '    for(unsigned pass=0;pass<2;pass++)for(unsigned k=0;k<1;k++) {'),
    'F8 stage 2 never RW again': ('user-hw-walk.h', '(ro ? S2_AP_RO : S2_AP_RW)', '((void)ro,S2_AP_RO)'),
    'F19 a RETYPE splits a live 1G block (v62)': ('user-hw-walk.h',
        '        if(!split)return 0;\n', '        (void)split;\n'),
    'F19 the pre-split leaves blocks': ('user-hw-walk.h',
        '            ram[k]=(d2[k]&3)==1 && hw_s2_ram_leaf(d2[k],region);',
        '            ram[k]=0;(void)region;'),
    'F19 the pre-split loses a read-only block': ('user-hw-walk.h',
        '                if(trees[0].write(trees[0].ctx,table+8UL*n,(region+((uint64_t)n<<12))|attrs))return -1;',
        '                if(trees[0].write(trees[0].ctx,table+8UL*n,(region+((uint64_t)n<<12))|(attrs&~PT_AP)|S2_AP_RW))'
        'return -1;'),
    'F19 the pre-split shares a table across differing trees': ('user-hw-walk.h',
        '        for(unsigned k=0;k<count;k++)same&=ram[k] && d2[k]==d2[0];',
        '        for(unsigned k=0;k<count;k++)same&=ram[k];'),
    'F18 the compaction keeps the old parent (v55, written out)': ('user-hw-walk.h',
        '        to->level=t.level;to->parent=t.parent;to->slot=t.slot;to->pad=t.pad;',
        '        to->level=t.level;to->parent=r->t[n].parent;to->slot=t.slot;to->pad=t.pad;'),
    'F17 the loaded-root audit reads the cache only (v53)': ('user-hw-walk.h',
        '    const struct sptm_root_cached *e=sptm_root_policy_cache(s,root);\n    if(e)return e;\n'
        '    struct hw_walk_root *r=hw_walk_find(st,root);',
        '    const struct sptm_root_cached *e=sptm_root_policy_cache(s,root);\n    return e;\n'
        '    struct hw_walk_root *r=hw_walk_find(st,root);'),
    'F17 a record beside a valid cache entry admitted': ('user-hw-walk.h',
        '    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root && s->cache[i].valid)return 0;\n', ''),
    'F17 an invalidated cache slot hides the record': ('user-hw-walk.h',
        'if(s->cache[i].root==root && s->cache[i].valid)return 0;', 'if(s->cache[i].root==root)return 0;'),
    'F17 the record noted under a UMPRR its flags do not give': ('user-hw-walk.h',
        '        flags=e->flags;\n    }\n    if(s->sprr[cpu].umprr!=sptm_root_policy_umprr(flags))return 0;\n'
        '    loaded[cpu]=(struct sptm_loaded_root){root,flags,s->sprr[cpu].resets};\n    return 1;\n}\n'
        'static inline int hw_walk_loaded_valid',
        '        flags=e->flags;\n    }\n'
        '    loaded[cpu]=(struct sptm_loaded_root){root,flags,s->sprr[cpu].resets};\n    return 1;\n}\n'
        'static inline int hw_walk_loaded_valid'),
    'F17 CONFIGURE_ROOT checks the other CPUs by cache only': ('user-hw-walk.h',
        '        if(!hw_walk_loaded_valid(s,st,loaded,cpu))return 0;\n        active+=s->active[cpu]==root;',
        '        (void)st;if(!sptm_root_loaded_valid(s,loaded,cpu))return 0;\n        active+=s->active[cpu]==root;'),
    'F17 the shared alias snapshot refuses hardware-walk roots': ('sptm-root.c',
        '        if(found!=1 && !(found==0 && walked(ctx,s->active[cpu])))return 0;',
        '        (void)walked;(void)ctx;if(found!=1)return 0;'),
    'F17 the shared alias snapshot admits any uncached active root': ('sptm-root.c',
        '        if(found!=1 && !(found==0 && walked(ctx,s->active[cpu])))return 0;',
        '        (void)walked;(void)ctx;if(found>1)return 0;'),
    'F7 PAGE_TABLE frames unprotected': ('user-hw-walk.h',
        '           type==SPTM_MAC_PAGE_TABLE || type==SPTM_MAC_PAGE_TABLE_SHARED ||',
        '           type==SPTM_MAC_PAGE_TABLE_SHARED ||'),
    'F7 a non-RAM (XN) range accepted': ('user-hw-walk.h',
        '        (d&~(PT_OA_MASK|PT_AP|3UL))==S2_ATTRS;', '        (d&~(PT_OA_MASK|PT_AP|S2_XN|3UL))==S2_ATTRS;'),
    'F20 a converted UNMAP_REGION is not invalidated (SNAP_FINE_HW)': ('user-hw-walk.h',
        '    t->range(t->ctx,va,size);\n    return 1;', '    (void)t;\n    return 1;'),
    'F20 converted copies do not follow stores (SNAP_FINE_HW)': ('user-hw-walk.h',
        '    return hw_walk_refresh(o,r,va,size,&n->refreshed);', '    (void)va;(void)size;return 1;'),
    'F20 a converted class-9 leaf (SNAP_FINE_HW)': ('user-hw-walk.h',
        '{return r && shift==12 && sprr_pte_class(pte)!=9;}', '{(void)pte;return r && shift==12;}'),
    'SWITCH_ROOT hook skips the reference bounds': ('sptm-root.c',
        '            if(get(meta+6,2)<cpus || get(meta+6,2)>g.root_groups+cpus)return SPTM_BAD_REFERENCE;',
        '            (void)cpus;'),
    'SWITCH_ROOT hook falls into the shadow path': ('sptm-root.c',
        '            b->install(b->ctx,0,root,asid,format);\n            goto installed;',
        '            (void)0;'),
}


class Decision(unittest.TestCase):
    def test_differential(self):
        with tempfile.TemporaryDirectory() as d:
            exe, err = compile_c(d, 'test-user-hw-walk.c', [DEFINE])
            self.assertIsNotNone(exe, err[-3000:])
            result = run(exe)
            self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-3000:])
            self.assertTrue(result.stdout.rstrip().splitlines()[-1].startswith('PASS'), result.stdout)
            print(result.stdout.strip().splitlines()[-1], file=sys.stderr)

    def test_weakened_guards_fail(self):
        texts = {'user-hw-walk.h': HEADER, 'sptm-root.c': ROOT_C}
        for label, (name, old, new) in MUTANTS.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                self.assertEqual(texts[name].count(old), 1, label)
                exe, _ = compile_c(d, 'test-user-hw-walk.c', [DEFINE],
                                   {name: texts[name].replace(old, new)})
                if exe is None:
                    continue                                      # refused at compile time
                result = run(exe)
                self.assertNotEqual(result.returncode, 0, f'{label} survived')

    def test_at_the_monitor_optimization_level(self):
        # The monitor is built -Os (strict aliasing on): v55's lost parent
        # remap only showed there. The differential program must pass at -Os
        # and -O2 unsanitized too, and the old uint64_t-view compaction must
        # fail it at -Os (installed-fresh-20261018-v55).
        for opt in ('-Os', '-O2'):
            with self.subTest(opt), tempfile.TemporaryDirectory() as d:
                exe, err = compile_c(d, 'test-user-hw-walk.c', [DEFINE], opt=opt, sanitize=False)
                self.assertIsNotNone(exe, err[-3000:])
                result = run(exe)
                self.assertEqual(result.returncode, 0, opt + result.stdout[-2000:])
                self.assertTrue(result.stdout.rstrip().splitlines()[-1].startswith('PASS'), opt)
        old = HEADER.replace(COMPACTION_FIXED, COMPACTION_V55)
        self.assertNotEqual(old, HEADER)
        with tempfile.TemporaryDirectory() as d:
            exe, err = compile_c(d, 'test-user-hw-walk.c', [DEFINE], {'user-hw-walk.h': old}, opt='-Os', sanitize=False)
            self.assertIsNotNone(exe, err[-3000:])
            self.assertNotEqual(run(exe).returncode, 0, 'the v55 compaction survived at -Os')

    def test_existing_suites_unchanged_by_the_define(self):
        suites = {'test-sptm-root.c': (), 'test-root-validate-memo.c': (),
                  'test-sptm-nest.c': (), 'test-sptm-unnest.c': (),
                  'test-native-shared-nest.c': ('shadow/native-shared.c',)}
        with tempfile.TemporaryDirectory() as d:
            for suite, extra in suites.items():
                outs = []
                for define in ([], [DEFINE]):
                    sub = Path(d) / (suite + ('-on' if define else '-off'))
                    sub.mkdir()
                    exe, err = compile_c(sub, suite, define, werror=False, extra=extra)
                    self.assertIsNotNone(exe, suite + err[-2000:])
                    result = run(exe)
                    self.assertEqual(result.returncode, 0, suite + result.stdout[-2000:] + result.stderr[-2000:])
                    outs.append(result.stdout)
                self.assertEqual(outs[0], outs[1], suite)


def arena_problems(text):
    """Where the hardware-walk state pages sit in the monitor arena, and that
    the coverage sentinel never arms them (they are stored without a dirty
    note, like root_ext's: compat/root-wide.h W6, compat/txm.h A4)."""
    p = []
    setup = between(text, 'int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,\n'
                    '                  const struct secondary_config *host_cpus)\n{', '\n}\n')
    place = setup.find('    c->hw_walk = (struct hw_walk_state *)c->next_table;')
    if place < 0:
        return ['xnuboot_setup does not place the hardware-walk state']
    # After root_ext and after the TXM registry, whose fixed offset
    # (TXM_EXT_OFFSET) assumes it follows root_ext directly.
    for after in ('    c->next_table += ROOT_EXT_PAGES * 4096;\n#endif\n',
                  '    if (c->next_table != (uint64_t)TXM_REG(c)) return 1;\n'
                  '    c->next_table += TXM_EXT_PAGES * 4096;\n#endif\n'):
        at = setup.find(after)
        if at < 0 or at > place:
            p.append(f'the hardware-walk state is not placed after {after.strip().splitlines()[-2]!r}')
    if '    c->next_table += HW_WALK_PAGES * 4096;\n#endif\n    c->work_end = work + size;' not in setup:
        p.append('the hardware-walk pages are not the last fixed arena pages before work_end')
    if 'if (c->next_table + HW_WALK_PAGES * 4096 > work + size) return 1;' not in setup:
        p.append('xnuboot_setup does not refuse a work area without room for the state')
    exclude = between(text, 'static int txn_publish_exclude(void *ctx,uint64_t page)\n{', '\n}\n')
    if '#if SNAP_USER_HW_WALK\n' not in exclude or \
            'if(page>=(uint64_t)c->hw_walk && page-(uint64_t)c->hw_walk<HW_WALK_PAGES*4096)return 1;' not in exclude:
        p.append('the coverage sentinel can arm a hardware-walk state page')
    return p


ARENA_MUTANTS = {
    'the sentinel arms a state page': (
        '    if(page>=(uint64_t)c->hw_walk && page-(uint64_t)c->hw_walk<HW_WALK_PAGES*4096)return 1;\n', ''),
    'no room check': ('    if (c->next_table + HW_WALK_PAGES * 4096 > work + size) return 1;\n', ''),
}


# compat/sptm-root-policy.h and sptm_root_shared_aliases take an active root's
# identity from its shadow-cache entry; a hardware-walk root has none (v53).
CACHE_ONLY = ('sptm_root_note_loaded', 'sptm_root_loaded_valid', 'sptm_root_configure_active',
              'sptm_root_shared_aliases')
# Where the monitor may still call them with the define: setup (every CPU on
# the kernel root), and the converted switch (fine locks), whose new root is
# the kernel's or a cached one (FINE_HW_ROOT declines a hardware-walk target).
CACHE_ONLY_ALLOWED = {'xnuboot_setup': {'sptm_root_note_loaded'}, 'fine_switch_root': {'sptm_root_note_loaded'}}


def identity_problems(text):
    fns = functions(preprocess(text, installed_defines() + V51 + [DEFINE]))
    p = []
    for name, body in fns.items():
        if name in CACHE_ONLY or name.startswith('hw_walk_'):
            continue
        for helper in CACHE_ONLY:
            if re.search(r'\b' + helper + r'\s*\(', body) and helper not in CACHE_ONLY_ALLOWED.get(name, ()):
                p.append(f'{name} asks {helper}, which cannot see a hardware-walk root')
    for name, need in (('sptm_configure_user_root', 'hw_walk_configure_active'),
                       ('user_shared_mask', 'sptm_root_shared_aliases_hw')):
        if need not in fns.get(name, ''):
            p.append(f'{name} does not use {need}')
    if not any('hw_walk_note_loaded(' in body for body in fns.values()):
        p.append('SWITCH_ROOT does not note a hardware-walk root')
    return p


class Source(unittest.TestCase):
    def test_no_cache_only_identity_for_an_active_root(self):
        self.assertEqual(identity_problems(SOURCE), [])
        reverted = {
            'SWITCH_ROOT notes by cache (v53)': (
                '        if(!hw_walk_note_loaded(&c->user_roots,c->hw_walk,c->root_loaded,(unsigned)vcpu_of(c)->slot)) {',
                '        if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,(unsigned)vcpu_of(c)->slot)) {'),
            'CONFIGURE_ROOT by cache': (
                '        return hw_walk_configure_active(&c->user_roots,c->hw_walk,c->root_loaded,root,before,after);',
                '        return sptm_root_configure_active(&c->user_roots,c->root_loaded,root,before,after);'),
            'the shared alias snapshot by cache': (
                '    return sptm_root_shared_aliases_hw(&m,&c->user_roots,root,va,shift,mask,hw_walk_recorded,c->hw_walk);',
                '    return sptm_root_shared_aliases(&m,&c->user_roots,root,va,shift,mask);'),
        }
        for label, (old, new) in reverted.items():
            with self.subTest(label):
                self.assertEqual(SOURCE.count(old), 1, label)
                self.assertNotEqual(identity_problems(SOURCE.replace(old, new)), [], f'{label} survived')

    def test_arena_pages_after_the_txm_registry_and_never_a_sentinel(self):
        self.assertEqual(arena_problems(SOURCE), [])
        # The state placed between root_ext and the TXM registry (TXM_REG(c)
        # would then point into it): the two blocks swapped.
        txm = ('#if SNAP_TXM_ASPACE_WIDE\n    if (c->next_table != (uint64_t)TXM_REG(c)) return 1;\n'
               '    c->next_table += TXM_EXT_PAGES * 4096;\n#endif\n')
        hw = between(SOURCE, '#if SNAP_USER_HW_WALK\n    /* The records follow root_ext',
                     '    c->work_end = work + size;')
        mutants = dict(ARENA_MUTANTS, **{'the state placed before the TXM registry': (txm + hw, hw + txm)})
        for label, (old, new) in mutants.items():
            with self.subTest(label):
                self.assertEqual(SOURCE.count(old), 1, label)
                self.assertNotEqual(arena_problems(SOURCE.replace(old, new)), [], f'{label} survived')

    def test_default_off_and_prerequisites(self):
        self.assertIn('#ifndef SNAP_USER_HW_WALK\n#define SNAP_USER_HW_WALK 0\n#endif\n'
                      '#ifndef SNAP_USER_HW_WALK_S2RO\n#define SNAP_USER_HW_WALK_S2RO SNAP_USER_HW_WALK\n#endif\n'
                      '_Static_assert(!SNAP_USER_HW_WALK || (SNAP_NATIVE_TABLES && SNAP_ROOT_DIRTY_PUBLISH),', SOURCE)
        self.assertIn('_Static_assert(!SNAP_USER_HW_WALK_S2RO || SNAP_USER_HW_WALK,', SOURCE)
        self.assertIn('#ifndef SNAP_IDREG_MMFR3\n#define SNAP_IDREG_MMFR3 0\n#endif', SOURCE)
        header = (ROOT / 'compat/sptm-root.h').read_text()
        self.assertIn('#ifndef SNAP_USER_HW_WALK\n#define SNAP_USER_HW_WALK 0\n#endif', header)
        self.assertIn('#if SNAP_USER_HW_WALK\n#include "../compat/user-hw-walk.h"', SOURCE)

    def test_compat_changes_are_define_guarded(self):
        for path in ('compat/sptm-root.c', 'compat/sptm-root.h'):
            off = subprocess.run(['cc', '-E', '-P', '-DSNAP_USER_HW_WALK=0', '-Icompat', '-Ishadow', path],
                                 cwd=ROOT, capture_output=True, text=True, check=True).stdout
            on = subprocess.run(['cc', '-E', '-P', DEFINE, '-Icompat', '-Ishadow', path],
                                cwd=ROOT, capture_output=True, text=True, check=True).stdout
            self.assertNotIn('hw_eligible', off, path)
            self.assertIn('hw_eligible', on, path)

    def test_monitor_wiring_only_under_the_define(self):
        # Every use of the hardware-walk API lies inside an SNAP_USER_HW_WALK block.
        names = re.compile(r'(?<![A-Za-z0-9_])(hw_walk_|hw_switch_|hw_root\(|hw_ops\(|hw_s2_|'
                           r'hw_entry_proof|hw_after_table|hw_table_read|hw_record_entry|'
                           r'hw_prepare_|hw_commit_|hw_copy_|hw_fail|hw_install_user)')
        depth, guarded = [], []
        for number, line in enumerate(SOURCE.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('#if'):
                depth.append('SNAP_USER_HW_WALK' in stripped and not stripped.startswith('#if !'))
            elif stripped.startswith('#else') and depth:
                depth[-1] = False
            elif stripped.startswith('#endif') and depth:
                depth.pop()
            elif names.search(line):
                guarded.append((number, any(depth)))
        self.assertGreater(len(guarded), 40)
        self.assertEqual([n for n, ok in guarded if not ok], [], 'hardware-walk code outside its define')
        # The SWITCH_ROOT backend, user_backend, RETYPE, MAP_TABLE and CONDEMN hooks are present.
        backend = between(SOURCE, 'case SPTM_FN_SWITCH_ROOT: {', 'enum sptm_result r=')
        self.assertIn('#if SNAP_USER_HW_WALK\n            ,.hw_eligible=hw_switch_eligible\n#endif', backend)
        self.assertIn('.install=user_root_install', backend)
        install = between(SOURCE, 'static void user_root_install(void *ctx', '\n}\n')
        self.assertIn('#if SNAP_USER_HW_WALK\n', install)
        self.assertIn('    if(asid && !shadow) {hw_install_user(c,guest_root,asid,format);return;}\n#endif', install)
        # After the PPERM reset, before the shadow view.
        self.assertLess(install.index('kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,1)'),
                        install.index('hw_install_user(c,guest_root,asid,format)'))
        self.assertLess(install.index('hw_install_user(c,guest_root,asid,format)'),
                        install.index('shadow=user_install_view(c,guest_root,shadow,0);'))
        user = between(SOURCE, 'static int user_backend(struct context *c,uint64_t root,', '\n}\n')
        self.assertIn('b->mirror=!b->active_refs;', user)
        self.assertNotIn('b->commit_update=hw', user)
        update = between(SOURCE, 'static int user_commit_update(void *ctx', '\n}\n')
        self.assertIn('if(e || !hw_walk_after_add(&o,hr,va,UINT64_C(1)<<shift,&c->hw_walk->stats))return hw_fail(c);',
                      update)
        self.assertLess(update.index('hw_walk_after_add'), update.index('update_fast_uncached(old)'))
        self.assertIn('hw_s2_retype_action((unsigned)frame[1],(unsigned)frame[2])', SOURCE)
        # Stage 2 (v62): every RETYPE without split, and the setup pre-split after
        # every vCPU's tree, before anything runs.
        frame = between(SOURCE, 'static int hw_s2_frame(struct context *c,uint64_t frame,int ro)\n{', '\n}\n')
        self.assertIn('    if(hw_s2_set(trees,GUEST_CPU_COUNT,frame,ro)<0) {c->hw_walk->stats.s2_failures++;return 0;}', frame)
        self.assertNotIn('stage2_split', between(HEADER, 'static inline int hw_s2_set(', '\n}\n'))
        # agents/sptm-locks SNAP_SPTM_FINE_RETYPE: a converted RETYPE's twin
        # (fine_hw_s2_frame) makes the same leaf-only call.
        twin = 'static int fine_hw_s2_frame(' in SOURCE
        self.assertEqual(SOURCE.count('hw_s2_set('), 2 if twin else 1)
        if twin:
            self.assertIn('    if(hw_s2_set(trees,GUEST_CPU_COUNT,frame,ro)<0) {fine_add(&c->hw_walk->stats.s2_failures,1);return 0;}',
                          between(SOURCE, 'static int fine_hw_s2_frame(struct context *c,uint64_t frame,int ro)\n{', '\n}\n'))
        prepare = between(SOURCE, 'int64_t xnuboot_prepare(void)\n{', '\n}\n')
        loop = prepare.index('int built = vcpu_stage2_prepare(c, &c->vcpus[n]);')
        split = prepare.index('#if SNAP_USER_HW_WALK_S2RO\n')
        self.assertLess(loop, split)
        self.assertIn('    if (hw_s2_presplit_all(c)) return -27;\n#endif\n', prepare[split:])
        self.assertLess(prepare.index('hw_s2_presplit_all(c)'), prepare.index('guest_cpu_storage_plan('))
        self.assertIn('!hw_after_table(c,frame[0],frame[1],(unsigned)frame[2])', SOURCE)
        self.assertIn('!hw_after_table(c,frame[0],frame[1],2)', SOURCE)
        # Retirement, sharing and inactive configuration drop the record after their flush.
        for fn in ('static int sptm_retire_user_root', 'static int sptm_share_user_root',
                   'static int sptm_configure_user_root'):
            body = between(SOURCE, fn, '\n}\n')
            flush = body.rindex('shadow_tlb_sync(c);')
            self.assertGreater(body.index('hw_walk_detach'), flush, fn)

    def test_default_monitor_preprocesses_without_the_feature(self):
        flags = json.loads((ROOT / 'config/monitor-flags.json').read_text())['flags']
        defines = [f for f in flags if f.startswith('-D')]
        off = subprocess.run(['cc', '-E', '-P', '-ffreestanding', *defines, '-DSNAP_NATIVE_TABLES=1',
                              '-Ishadow', 'probes/xnuboot.c'], cwd=ROOT, capture_output=True, text=True)
        if off.returncode:
            self.skipTest('host preprocessor cannot read the monitor source: ' + off.stderr[-200:])
        for name in ('hw_walk_', 'hw_s2_', 'user_active_entry', 'HW_WALK'):
            self.assertNotIn(name, off.stdout, name)


FINE = ['-DSNAP_FINE_LOCKS=1', '-DSNAP_FINE_SWITCH=1', '-DSNAP_FAIR_TOKEN=1']
# v51 = v50 + --prime-secondaries --txm-aspace-wide --fine-locks --fine-switch --fair-token.
V51 = ['-DSNAP_BOOT_RELOCATE=1', '-DSNAP_TXM_ASPACE_WIDE=1', *FINE]
V51_QUALIFICATION = ROOT / 'build/installed-fresh-20261018-v51/qualification.json'
# What a converted call may reach of the hardware walk: the record lookup.
FINE_READS = {'hw_root', 'hw_walk_find', 'hw_walk_hash'}


def installed_defines():
    """The installed-fresh (v50) fast set's -D words: cycle_lib.installed_fresh.variant_flags."""
    for path in (ROOT / 'tools', ROOT / 'probes', ROOT.parent / 'q1n1' / 'tools'):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    speed = importlib.import_module('cycle_lib.speed_test')
    fresh = importlib.import_module('cycle_lib.installed_fresh')
    sets, _ = speed.flag_sets(ROOT)
    args = argparse.Namespace(variant='fast', wfi_resume=True, fast_el0_sysreg=True, service_subclass=True,
                              dart_wiredcnt=True, panic_serve=True, root_miss_fast=True, update_disjoint_fast=True,
                              root_cache_wide=True, update_check_sparse=True, input=True, kernel_pperm_fast=True,
                              ib_budget_1s=True, unmap_mixed=True)
    return [f for f in fresh.variant_flags(sets, args) if f.startswith('-D')]


def preprocess(text, defines, rel='probes/xnuboot.c'):
    """rel, replaced by text, preprocessed for the monitor in a scratch tree."""
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d)
        for sub in ('compat', 'shadow', 'gpu', 'probes'):
            if (ROOT / sub).exists():
                (tree / sub).mkdir()
                for f in (ROOT / sub).iterdir():
                    (tree / sub / f.name).symlink_to(f)
        (tree / rel).unlink()
        (tree / rel).write_text(text)
        return subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                               '-mgeneral-regs-only', '-E', '-P', '-Ishadow', '-Icompat',
                               f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines, rel],
                              cwd=tree, capture_output=True, text=True, check=True).stdout


def functions(code):
    out = {}
    for m in re.finditer(r'^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w \*]*?\b(\w+)\s*\([^;{}]*\)\s*\{', code, re.M):
        i, depth = m.end() - 1, 0
        start = i
        while i < len(code):
            depth += code[i] == '{'
            depth -= code[i] == '}'
            i += 1
            if not depth:
                break
        out.setdefault(m[1], code[start:i])
    return out


def fine_problems(text, root_c=ROOT_C):
    """Every way the converted calls could reach hardware-walk state or run on
    a hardware-walk root. Empty means none."""
    p = []
    defines = installed_defines() + V51 + [DEFINE]
    fns = functions(preprocess(text, defines))
    seen, todo = set(), ['fine_sptm_call']
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name)
        for m in re.finditer(r'\b([A-Za-z_]\w*)\b(\s*\()?', fns[name]):
            callee = m[1]
            # Calls, and callbacks handed to the engines; fine_fatal runs after the gate is left.
            if callee in fns and callee != 'fine_fatal' and (m[2] or callee.startswith(('fine_', 'hw_'))):
                todo.append(callee)
    for need in ('fine_lockset_for', 'fine_user_backend', 'fine_switch_root', 'fine_map_page', 'hw_root'):
        if need not in seen:
            p.append(f'{need} not reached')
    if seen - FINE_READS & {n for n in seen if n.startswith('hw_')}:
        p.append(f'converted calls reach {sorted(n for n in seen - FINE_READS if n.startswith("hw_"))}')
    for name in sorted(seen - FINE_READS):
        if 'hw_walk' in fns[name] or 'HW_WALK' in fns[name]:
            p.append(f'{name} touches hardware-walk state')
    lockset = fns.get('fine_lockset_for', '')
    first = lockset.find('fine_lockset_add')
    named = lockset.find('kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && '
                         '(hw_root((c),(s->a0))!=0))return 0;')
    if named < 0 or named > first:
        p.append('fine_lockset_for does not decline a named hardware-walk root before its stripes')
    loop = lockset[lockset.find('FINE_CALL_UPDATE_DISJOINT) {'):]
    if 'if((hw_root((c),(root))!=0))return 0;' not in loop[:loop.find('return 1;')]:
        p.append('fine_lockset_for does not decline an UPDATE_DISJOINT record on a hardware-walk root')
    backend = fns.get('fine_user_backend', '')
    check = backend.find('if((hw_root((c),(root))!=0))return 0;')
    if check < 0 or check > backend.find('b->prepare_leaf='):
        p.append('fine_user_backend admits a hardware-walk root')
    switch = fns.get('fine_switch_root', '')
    if 'hw_eligible' in switch:
        p.append('the converted switch carries a hardware-walk hook')
    hit = functions(subprocess.run(['cc', '-E', '-P', *FINE, DEFINE, '-Icompat', '-Ishadow', '-x', 'c', '-'],
                                   input=root_c, cwd=ROOT / 'compat', capture_output=True, text=True,
                                   check=True).stdout).get('sptm_mac_switch_root_hit', '')
    if not hit or 'hw_' in hit:
        p.append('sptm_mac_switch_root_hit is missing or runs hardware-walk code')
    return p


# Each weakened source must be caught by fine_problems: (file, old, new).
FINE_MUTANTS = {
    'MAP_PAGE/UNMAP_REGION/a switch target on a hardware-walk root converted':
        ('xnuboot.c', '    if(s->kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && '
                      'FINE_HW_ROOT(c,s->a0))return 0;\n', ''),
    'an UPDATE_DISJOINT record on a hardware-walk root converted':
        ('xnuboot.c', '                return 0;\n#if SNAP_USER_HW_WALK\n            if(FINE_HW_ROOT(c,root))return 0;\n',
         '                return 0;\n#if SNAP_USER_HW_WALK\n'),
    'the converted backend admits a hardware-walk root':
        ('xnuboot.c', '     * checked here again (FINE_HW_ROOT). */\n    if(FINE_HW_ROOT(c,root))return 0;\n',
         '     * checked here again (FINE_HW_ROOT). */\n'),
    'a converted commit refreshes copies':
        ('xnuboot.c', '    fine_add(&c->user_live_pages,1);return 1;',
         '    fine_add(&c->user_live_pages,1);hw_after_table(c,root,va,3);return 1;'),
    'a converted call counts into the hardware-walk stats':
        ('xnuboot.c', '    fine_add(&c->map_pages,1);frame[0]=result;return FINE_DONE;',
         '    fine_add(&c->map_pages,1);c->hw_walk->stats.installs++;frame[0]=result;return FINE_DONE;'),
    'the converted switch attaches records':
        ('xnuboot.c', '.install=fine_user_root_install,.ctx=c,.skip_hit_validation=fine_skip_hit};',
         '.install=fine_user_root_install,.ctx=c,.skip_hit_validation=fine_skip_hit,'
         '.hw_eligible=hw_switch_eligible};'),
    'the converted switch hit consults hw_eligible':
        ('sptm-root.c', '    if(get(meta+6,2)>=0x80b)return 0;\n    struct sptm_root_cached *entry=0;',
         '    if(get(meta+6,2)>=0x80b)return 0;\n    if(b->hw_eligible && b->hw_eligible(b->ctx,m,root,asid,format,flags))'
         'return 0;\n    struct sptm_root_cached *entry=0;'),
}


class FineLocks(unittest.TestCase):
    def test_converted_calls_leave_the_hardware_walk_alone(self):
        self.assertEqual(fine_problems(SOURCE), [])

    def test_weakened_declines_are_caught(self):
        for label, (name, old, new) in FINE_MUTANTS.items():
            with self.subTest(label):
                text = SOURCE if name == 'xnuboot.c' else ROOT_C
                self.assertEqual(text.count(old), 1, label)
                mutated = text.replace(old, new)
                problems = fine_problems(mutated) if name == 'xnuboot.c' else fine_problems(SOURCE, mutated)
                self.assertNotEqual(problems, [], f'{label} survived')

    def test_stack_is_the_installed_set(self):
        # --build's 'stack' monitor is the installed-fresh (v50) one.
        self.assertEqual([f for f in flag_sets()[0]['fast'] + STACK if f.startswith('-D')], installed_defines())

    @unittest.skipUnless(V51_QUALIFICATION.is_file(), 'no v51 qualification record in this tree')
    def test_v51_is_the_qualified_set(self):
        # --build's 'v51' monitor is the one v51 booted.
        flags = json.loads(V51_QUALIFICATION.read_text())['flags']
        self.assertEqual([f for f in flags if f.startswith('-D')], installed_defines() + V51)

    def test_declines_only_under_both_defines(self):
        # Every FINE_HW_ROOT line lies inside an SNAP_FINE_LOCKS block and an
        # SNAP_USER_HW_WALK block (tools/test-fine-locks.py's define-off text
        # check covers the first, the wiring check above the second).
        stack, lines = [], []
        for number, line in enumerate(SOURCE.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('#if'):
                stack.append(stripped)
            elif stripped.startswith('#else') and stack:
                stack[-1] = '#else'
            elif stripped.startswith('#endif') and stack:
                stack.pop()
            elif 'FINE_HW_ROOT' in line:
                lines.append((number, '#if SNAP_FINE_LOCKS' in stack, '#if SNAP_USER_HW_WALK' in stack))
        # The definition, fine_lockset_for's named-root decline (with SNAP_FINE_HW, and
        # without it), its UPDATE_DISJOINT record decline, and fine_user_backend's
        # check (SNAP_FINE_HW's converted backend, and the decline).
        self.assertEqual(sum('FINE_HW_ROOT(' in l for l in SOURCE.splitlines()), 6)
        self.assertEqual([n for n, fine, hw in lines if not (fine and hw)], [])


# SNAP_FINE_HW (docs/FINE-HW-WALK-20261019.md): converted MAP_PAGE and UNMAP_REGION on hardware-walk roots.
FINE_HW = '-DSNAP_FINE_HW=1'
# What a converted call may reach of the hardware walk with SNAP_FINE_HW: the record lookup, the ops it builds (reads
# and copy stores; its alloc and release callbacks are invoked only by path preparation and prune, which must stay
# unreached), and the refresh, which rewrites existing copy entries only.
FINE_HW_READS = FINE_READS | {'hw_ops', 'hw_table_read', 'hw_copy_write', 'hw_table_type', 'hw_copy_alloc',
                              'hw_copy_release', 'hw_walk_fine_prepare_leaf', 'hw_walk_fine_prepare_unmap',
                              'hw_walk_fine_after_add', 'hw_walk_fine_after_change', 'hw_walk_refresh',
                              'hw_walk_translate', 'hw_walk_decode', 'hw_walk_copied', 'hw_walk_span',
                              'hw_walk_table_ok', 'hw_walk_leaf_bits_ok'}
# Never reached by a converted call: path preparation and linking, prune and release, attach and detach, the audit,
# stage 2, and the token path's events with their plain counters.
FINE_HW_FORBIDDEN = {'hw_walk_before_tpro', 'hw_walk_prepare', 'hw_walk_add', 'hw_walk_path', 'hw_walk_prune',
                     'hw_walk_release', 'hw_walk_attach', 'hw_walk_detach', 'hw_walk_after_add',
                     'hw_walk_after_change', 'hw_walk_after_unlink', 'hw_walk_verify', 'hw_fail', 'hw_prepare_leaf',
                     'hw_commit_leaf', 'hw_prepare_unmap', 'hw_commit_unmap', 'hw_prepare_update',
                     'hw_commit_detach', 'hw_commit_attach', 'hw_commit_nest', 'hw_commit_unnest', 'hw_after_table',
                     'hw_s2_frame', 'hw_install_user', 'hw_entry_proof'}


def preprocess_tree(overrides, defines, rel='probes/xnuboot.c'):
    """rel preprocessed for the monitor in a scratch tree where overrides (path -> text) replace those files."""
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d)
        for sub in ('compat', 'shadow', 'gpu', 'probes'):
            if (ROOT / sub).exists():
                (tree / sub).mkdir()
                for f in (ROOT / sub).iterdir():
                    (tree / sub / f.name).symlink_to(f)
        for path, text in overrides.items():
            (tree / path).unlink()
            (tree / path).write_text(text)
        return subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                               '-mgeneral-regs-only', '-E', '-P', '-Ishadow', '-Icompat',
                               f'-I{ROOT.parent / "q1n1/platform/uefi"}', *defines, rel],
                              cwd=tree, capture_output=True, text=True, check=True).stdout


def fine_hw_problems(text=SOURCE, header=HEADER):
    """With SNAP_FINE_HW, every way a converted call on a hardware-walk root could reach token-path state, miss an
    event, or update a shared counter non-atomically. Empty means none."""
    p = []
    fns = functions(preprocess_tree({'probes/xnuboot.c': text, 'compat/user-hw-walk.h': header},
                                    installed_defines() + V51 + [DEFINE, FINE_HW]))
    seen, todo = set(), ['fine_sptm_call']
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name)
        for m in re.finditer(r'\b([A-Za-z_]\w*)\b(\s*\()?', fns[name]):
            callee = m[1]
            if callee in fns and callee != 'fine_fatal' and (m[2] or callee.startswith(('fine_', 'hw_'))):
                todo.append(callee)
    for need in ('fine_hw_backend', 'fine_hw_commit_leaf', 'fine_hw_commit_unmap', 'hw_walk_fine_after_add',
                 'hw_walk_fine_after_change', 'fine_hw_prepare_update', 'fine_hw_commit_update'):
        if need not in seen:
            p.append(f'{need} not reached')
    if seen & FINE_HW_FORBIDDEN:
        p.append(f'converted calls reach {sorted(seen & FINE_HW_FORBIDDEN)}')
    extra = sorted(n for n in seen if n.startswith('hw_') and n not in FINE_HW_READS)
    if extra:
        p.append(f'converted calls reach unlisted hardware-walk code {extra}')
    for name in sorted(n for n in seen if n.startswith('fine_hw_')):
        if re.search(r'c->[\w\[\].>-]+\s*(\+\+|\+=)', fns[name]):
            p.append(f'{name} updates a shared counter non-atomically')
    squeeze = lambda t: re.sub(r'\s+', '', t)
    lockset = squeeze(fns.get('fine_lockset_for', ''))
    decline = lockset.find(squeeze('s->kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && '
                                   's->kind!=FINE_CALL_MAP_PAGE && s->kind!=FINE_CALL_UNMAP_REGION && '
                                   '(hw_root((c),(s->a0))!=0))return 0;'))
    if decline < 0 or decline > lockset.find('fine_lockset_add'):
        p.append('fine_lockset_for admits a hardware-walk root for a kind other than MAP_PAGE and UNMAP_REGION')
    loop = lockset[lockset.find('FINE_CALL_UPDATE_DISJOINT){'):]
    if 'if((hw_root((c),(root))!=0))return0;' not in loop[:loop.find('return1;')]:
        p.append('fine_lockset_for admits an UPDATE_DISJOINT record on a hardware-walk root')
    backend = fns.get('fine_user_backend', '')
    at = backend.find('if((hw_root((c),(root))!=0))return fine_hw_backend(c,root,b);')
    if at < 0 or at > backend.find('b->prepare_leaf=fine_user_prepare_leaf'):
        p.append('fine_user_backend does not give a hardware-walk root the converted events')
    hw = fns.get('fine_hw_backend', '')
    for needed in ('b->mirror=!b->active_refs;', 'b->prepare_update=fine_hw_prepare_update;',
                   'b->commit_update=fine_hw_commit_update;', 'b->prepare_leaf=fine_hw_prepare_leaf;',
                   'b->commit_leaf=fine_hw_commit_leaf;', 'b->prepare_unmap=fine_hw_prepare_unmap;',
                   'b->commit_unmap=fine_hw_commit_unmap;'):
        if squeeze(needed) not in squeeze(hw):
            p.append(f'fine_hw_backend lacks {needed}')
    if hw.count('__atomic_load_n(&') < 2:
        p.append('fine_hw_backend reads the activity words without atomic loads')
    if 'shared' in hw or 'detach' in hw or 'nest' in hw or 'attach' in hw:
        p.append('fine_hw_backend hands the engine shared-root, detach, attach or nest callbacks')
    if 'return 0;' not in fns.get('fine_hw_prepare_update', ''):
        p.append('fine_hw_prepare_update does not decline')
    unmap = fns.get('fine_hw_commit_unmap', '')
    if 'struct hw_walk_tlb t={fine_hw_tlb_range,c};' not in unmap or 'hw_walk_fine_after_change(' not in unmap:
        p.append('fine_hw_commit_unmap does not invalidate through the converted TLBI')
    if 'fine_native_tlbi_range(' not in fns.get('fine_hw_tlb_range', ''):
        p.append('fine_hw_tlb_range is not fine_native_tlbi_range')
    if 't->range(t->ctx,va,size);' not in fns.get('hw_walk_fine_after_change', ''):
        p.append('hw_walk_fine_after_change does not invalidate the range')
    if 'sprr_pte_class(pte)!=9' not in fns.get('hw_walk_fine_prepare_leaf', ''):
        p.append('hw_walk_fine_prepare_leaf admits a class-9 leaf')
    if '(new_pte&1) && sprr_pte_class(new_pte)==9' not in fns.get('fine_map_page', ''):
        p.append('fine_map_page admits a class-9 leaf')
    return p


# Each weakened source must be caught by fine_hw_problems: (file, old, new).
FINE_HW_MUTANTS = {
    'every converted kind admitted on a hardware-walk root':
        ('xnuboot.c', ' && s->kind!=FINE_CALL_MAP_PAGE &&\n       s->kind!=FINE_CALL_UNMAP_REGION && FINE_HW_ROOT(c,s->a0))',
         ' &&\n       FINE_HW_ROOT(c,s->a0))'),
    'an UPDATE_DISJOINT record on a hardware-walk root converted':
        ('xnuboot.c', '                return 0;\n#if SNAP_USER_HW_WALK\n            if(FINE_HW_ROOT(c,root))return 0;\n',
         '                return 0;\n#if SNAP_USER_HW_WALK\n'),
    'a converted commit counts with a plain store':
        ('xnuboot.c', '    fine_add(&c->user_live_pages,1);\n    return 1;', '    c->user_live_pages++;\n    return 1;'),
    'the token path\'s leaf event in the converted backend':
        ('xnuboot.c', 'b->commit_leaf=fine_hw_commit_leaf;', 'b->commit_leaf=hw_commit_leaf;'),
    'an inactive root without events':
        ('xnuboot.c', '    b->mirror=!b->active_refs;\n    return 1;\n}\n#endif', '    return 1;\n}\n#endif'),
    'a replacing MAP_PAGE without events':
        ('xnuboot.c', '    b->prepare_update=fine_hw_prepare_update;b->commit_update=fine_hw_commit_update;\n', ''),
    'an UNMAP_REGION without invalidation':
        ('user-hw-walk.h', '    if(!hw_walk_fine_after_add(o,r,va,size,n))return 0;\n    t->range(t->ctx,va,size);\n    return 1;',
         '    (void)t;return hw_walk_fine_after_add(o,r,va,size,n);'),
    'a class-9 leaf converted':
        ('user-hw-walk.h', '{return r && shift==12 && sprr_pte_class(pte)!=9;}', '{(void)pte;return r && shift==12;}'),
    'the converted refresh uses the token path\'s event':
        ('xnuboot.c', 'int ok=hw_walk_fine_after_add(&o,hw_root(c,root),va,UINT64_C(1)<<shift,&n);',
         'int ok=hw_walk_after_add(&o,hw_root(c,root),va,UINT64_C(1)<<shift,&c->hw_walk->stats);(void)n;'),
}


class FineHw(unittest.TestCase):
    def test_converted_calls_on_hardware_walk_roots(self):
        self.assertEqual(fine_hw_problems(), [])

    def test_weakened_conversions_are_caught(self):
        for label, (name, old, new) in FINE_HW_MUTANTS.items():
            with self.subTest(label):
                text = SOURCE if name == 'xnuboot.c' else HEADER
                self.assertEqual(text.count(old), 1, label)
                mutated = text.replace(old, new)
                problems = fine_hw_problems(mutated) if name == 'xnuboot.c' else fine_hw_problems(SOURCE, mutated)
                self.assertNotEqual(problems, [], f'{label} survived')

    def test_off_by_default_and_prerequisites(self):
        fine = (ROOT / 'compat/fine-lock.h').read_text()
        self.assertIn('#ifndef SNAP_FINE_HW\n#define SNAP_FINE_HW 0\n#endif', fine)
        self.assertIn('#if SNAP_FINE_HW && !SNAP_FINE_LOCKS\n#error', fine)
        self.assertIn('#if SNAP_FINE_HW && !SNAP_USER_HW_WALK\n#error', SOURCE)
        # Without the define the converted calls are exactly the v51 ones (fine_problems' analysis).
        self.assertEqual(fine_problems(SOURCE), [])


# SNAP_FINE_SWITCH_HW (batch8 switch FAILURES-AND-DESIGN.md S1-S14): a SWITCH_ROOT to a hardware-walk root whose record
# already exists runs as a converted call under the old root's and the target's stripes (installed-fresh-20261020-v8:
# 15.6M such switches held the token 126.8 s and waited 243.6 s; 31 user switches were converted).
SWITCH_HW = '-DSNAP_FINE_SWITCH_HW=1'
# What the converted switch may reach of the hardware walk besides FINE_HW_READS: the loaded-policy note and the
# record's TTBR0 values.
SWITCH_HW_READS = FINE_HW_READS | {'hw_walk_note_loaded', 'hw_walk_policy_entry', 'hw_walk_ttbr0', 'hw_walk_asid'}
# Never reached: the token path's eligibility (it attaches), its install (plain counters, the whole-arena flush), the
# whole-arena flush itself and the PPERM transaction.
SWITCH_HW_FORBIDDEN = FINE_HW_FORBIDDEN | {'hw_switch_eligible', 'root_publish_flush', 'kernel_change_pperm_timed',
                                           'kernel_change_pperm', 'user_root_install', 'transaction_publish'}
SWITCH_HW_IGNORED = {'fine_add', 'fine_view_failed', 'sizeof', 'if', 'for', 'while', 'return', 'switch', 'vcpu_of',
                     '__asm__', 'int', 'uint64_t'}


def call_sequence(body):
    """The ordered calls and asm templates of a body (tools/test-fine-locks.py calls(): fine_ prefixes dropped,
    atomics and fine_add ignored)."""
    seq = []
    for m in re.finditer(r'__asm__\s+volatile\s*\(\s*"([^"]*)"|\b([A-Za-z_]\w*)\s*\(', body):
        if m[1] is not None:
            seq.append('asm:' + ' '.join(m[1].split()))
        elif not m[2].startswith('__atomic') and m[2] not in SWITCH_HW_IGNORED:
            seq.append(m[2][5:] if m[2].startswith('fine_') else m[2])
    return seq


def switch_hw_problems(text=SOURCE, root_c=ROOT_C):
    """With SNAP_FINE_SWITCH_HW, every way the converted switch to a hardware-walk root could attach, reach token-path
    state, differ from the token path's install, count non-atomically, or skip a check. Empty means none."""
    p = []
    squeeze = lambda t: re.sub(r'\s+', '', t)
    fns = functions(preprocess_tree({'probes/xnuboot.c': text},
                                    installed_defines() + V51 + [DEFINE, FINE_HW, SWITCH_HW]))
    seen, todo = set(), ['fine_sptm_call']
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name)
        for m in re.finditer(r'\b([A-Za-z_]\w*)\b(\s*\()?', fns[name]):
            callee = m[1]
            if callee in fns and callee != 'fine_fatal' and (m[2] or callee.startswith(('fine_', 'hw_'))):
                todo.append(callee)
    for need in ('fine_switch_root', 'fine_hw_switch_eligible', 'fine_hw_install_user', 'hw_walk_note_loaded',
                 'fine_install_publish', 'fine_user_root_install'):
        if need not in seen:
            p.append(f'{need} not reached')
    if seen & SWITCH_HW_FORBIDDEN:
        p.append(f'converted calls reach {sorted(seen & SWITCH_HW_FORBIDDEN)}')
    extra = sorted(n for n in seen if n.startswith('hw_') and n not in SWITCH_HW_READS)
    if extra:
        p.append(f'converted calls reach unlisted hardware-walk code {extra}')
    # S6: shared counters by atomic add; per-CPU words (indexed by this vCPU) may be plain.
    for name in ('fine_hw_switch_eligible', 'fine_hw_install_user', 'fine_switch_root'):
        for m in re.finditer(r'\bc->((?:\w|\.|->|\[[^\]]*\])+)\s*(\+\+|\+=|-=|(?<![<>!=])=(?!=))', fns.get(name, '')):
            if not re.match(r'\w+\[(v->slot|vcpu_of\(c\)->slot)\]', m[1]):
                p.append(f'{name}: plain store c->{m[1]}{m[2]}')
    # S3/S4: the token path's eligibility without the attach.
    eligible = squeeze(fns.get('fine_hw_switch_eligible', ''))
    for needed in ('if(format!=1)return0;', 'returnr->entry.asid==asid&&r->entry.flags==flags?1:-1;'):
        if needed not in eligible:
            p.append(f'fine_hw_switch_eligible lacks {needed}')
    if 'attach' in eligible or 'alloc' in eligible or not eligible.endswith('return0;}'):
        p.append('fine_hw_switch_eligible attaches or does not end in the shadow-path answer')
    # The install repeats hw_install_user, the converted publication in place of the whole-arena flush (S7).
    a, b = call_sequence(fns.get('hw_install_user', '')), call_sequence(fns.get('fine_hw_install_user', ''))
    for name, seq in (('root_publish_flush', a), ('asm:dsb ish', a), ('install_publish', b)):
        if name in seq:
            seq.remove(name)
        else:
            p.append(f'{name} missing from the install it belongs to')
    if not a or a != b:
        p.append(f'fine_hw_install_user does not repeat hw_install_user: {b} != {a}')
    install = squeeze(fns.get('fine_hw_install_user', ''))
    if not re.search(r'fine_install_publish\(c,201u?\)', install):
        p.append('fine_hw_install_user does not publish the copy domain with the converted publisher')
    if '__atomic_store_n(&v->guest_ttbr0,' not in install:
        p.append('fine_hw_install_user stores guest_ttbr0 without release')
    root_install = squeeze(fns.get('fine_user_root_install', ''))
    branch = root_install.find('if(asid&&!shadow){fine_hw_install_user(c,guest_root,asid,format);return;}')
    if branch < 0 or not root_install.find('deferred=defer;') < branch < \
            root_install.find('shadow=fine_user_install_view(c,guest_root,shadow);'):
        p.append('fine_user_root_install does not hand a hardware-walk root to fine_hw_install_user after its '
                 'accounting and before the cached view')
    # S8/S9: the converted switch.
    switch = squeeze(fns.get('fine_switch_root', ''))
    for needed in ('backend.hw_eligible=fine_hw_switch_eligible;', 'inthw=!kernel&&hw_root(c,root)!=0;',
                   'if(!kernel&&!hw){structsptm_root_cached*e=user_cached(c,root);',
                   # c->user_roots expands to the wide cache's c->root_ext->roots.
                   ',c->hw_walk,c->root_loaded,(unsigned)v->slot)){', 'if(!hw_walk_note_loaded(&c->',
                   'if(!kernel&&!hw){fine_add(&c->native_stats.hit_asks,1);'):
        if needed not in switch:
            p.append(f'fine_switch_root lacks {needed}')
    if 'sptm_root_note_loaded(' in switch:
        p.append('fine_switch_root notes a hardware-walk root by cache only')
    # S1/S12: the lockset admits a switch target with a record (its stripes below); every other decline stays.
    lockset = squeeze(fns.get('fine_lockset_for', ''))
    if 'if(s->kind!=FINE_CALL_SWITCH_HIT)if(s->kind!=FINE_CALL_UPDATE_DISJOINT&&s->kind!=FINE_CALL_SWITCH_KERNEL&&' \
            's->kind!=FINE_CALL_MAP_PAGE&&s->kind!=FINE_CALL_UNMAP_REGION&&(hw_root((c),(s->a0))!=0))return0;' \
            not in lockset:
        p.append('fine_lockset_for still declines a switch to a hardware-walk root, or no longer declines the rest')
    loop = lockset[lockset.find('FINE_CALL_UPDATE_DISJOINT){'):]
    if 'if((hw_root((c),(root))!=0))return0;' not in loop[:loop.find('return1;')]:
        p.append('fine_lockset_for admits an UPDATE_DISJOINT record on a hardware-walk root')
    # S4/S5: the compat hit's hardware-walk branch.
    hit = squeeze(functions(subprocess.run(['cc', '-E', '-P', *FINE, DEFINE, SWITCH_HW, '-Icompat', '-Ishadow', '-x', 'c',
                                            '-'], input=root_c, cwd=ROOT / 'compat', capture_output=True, text=True,
                                           check=True).stdout).get('sptm_mac_switch_root_hit', ''))
    order = ['inthw=b->hw_eligible(b->ctx,m,root,asid,format,flags);', 'if(hw<0)return0;', 'if(hw){',
             'unsignedcpus=active_count_fine(s,root);',
             'if(get(meta+6,2)<cpus||get(meta+6,2)>g.root_groups+cpus)return0;',
             'b->install(b->ctx,0,root,asid,format);', 'gotoinstalled;', 'if(!cache_hit(s,root,asid,format,flags)',
             'installed:sprr_root_reset(&s->sprr[cpu],flags);', '__atomic_store_n(&s->active[cpu],root,']
    at = [hit.find(o) for o in order]
    if -1 in at or at != sorted(at):
        p.append(f'sptm_mac_switch_root_hit lacks or misorders {[o for o, i in zip(order, at) if i < 0] or order}')
    return p


# Each weakened source must be caught by switch_hw_problems: (file, old, new).
SWITCH_HW_MUTANTS = {
    'the converted switch attaches records':
        ('xnuboot.c', '    backend.hw_eligible=fine_hw_switch_eligible;', '    backend.hw_eligible=hw_switch_eligible;'),
    'the converted install keeps the whole-arena flush':
        ('xnuboot.c', 'if(!fine_install_publish(c,HW_WALK_OWNER)) {',
         'if(!root_publish_flush(&c->root_publish,c->work_base,c->next_table,publish_page_lines,c)) {'),
    'the copy domain left out of the publication':
        ('xnuboot.c', 'if(!fine_install_publish(c,HW_WALK_OWNER)) {', 'if(!fine_install_publish(c,0)) {'),
    'a plain hardware-walk counter':
        ('xnuboot.c', 'fine_add(&c->hw_walk->stats.installs,1);', 'c->hw_walk->stats.installs++;'),
    'guest_ttbr0 without release':
        ('xnuboot.c', '    __atomic_store_n(&v->guest_ttbr0,root|(asid<<48),__ATOMIC_RELEASE);',
         '    v->guest_ttbr0=root|(asid<<48);'),
    'hit asks counted for a hardware-walk install':
        ('xnuboot.c', '    if(!kernel && !hw) {fine_add(&c->native_stats.hit_asks,1);',
         '    if(!kernel) {fine_add(&c->native_stats.hit_asks,1);'),
    'a hardware-walk root noted by cache':
        ('xnuboot.c', '    if(!hw_walk_note_loaded(&c->user_roots,c->hw_walk,c->root_loaded,(unsigned)v->slot)) {\n#else',
         '    if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,(unsigned)v->slot)) {\n#else'),
    'switch targets with a record still declined':
        ('xnuboot.c', '    if(s->kind!=FINE_CALL_SWITCH_HIT)\n', ''),
    'the eligibility attaches':
        ('xnuboot.c', '    return 0;     /* no record: the token path attaches (or keeps the shadow) */',
         '    return hw_walk_attach(c->hw_walk,&o,root,asid,flags)!=0;'),
    'a mismatched record installed':
        ('sptm-root.c', '        if(hw<0)return 0;\n', ''),
    'the hit without its reference bounds':
        ('sptm-root.c', '            if(get(meta+6,2)<cpus || get(meta+6,2)>g.root_groups+cpus)return 0;\n', ''),
}


class FineSwitchHw(unittest.TestCase):
    def test_converted_switch_to_hardware_walk_roots(self):
        self.assertEqual(switch_hw_problems(), [])

    def test_weakened_switches_are_caught(self):
        for label, (name, old, new) in SWITCH_HW_MUTANTS.items():
            with self.subTest(label):
                text = SOURCE if name == 'xnuboot.c' else ROOT_C
                self.assertEqual(text.count(old), 1, label)
                mutated = text.replace(old, new)
                problems = switch_hw_problems(mutated) if name == 'xnuboot.c' else switch_hw_problems(SOURCE, mutated)
                self.assertNotEqual(problems, [], f'{label} survived')

    def test_off_by_default_and_prerequisites(self):
        fine = (ROOT / 'compat/fine-lock.h').read_text()
        self.assertIn('#ifndef SNAP_FINE_SWITCH_HW\n#define SNAP_FINE_SWITCH_HW 0\n#endif', fine)
        self.assertIn('#if SNAP_FINE_SWITCH_HW && !SNAP_FINE_SWITCH\n#error', fine)
        self.assertIn('#if SNAP_FINE_SWITCH_HW && !SNAP_USER_HW_WALK\n#error', SOURCE)
        self.assertIn('#if SNAP_FINE_SWITCH_HW && !SNAP_USER_HW_WALK\n#error', ROOT_C)
        # Without the define the converted calls are exactly the earlier ones (both analyses unchanged), and none
        # of the new code is compiled.
        self.assertEqual(fine_problems(SOURCE), [])
        self.assertEqual(fine_hw_problems(), [])
        off = preprocess_tree({}, installed_defines() + V51 + [DEFINE, FINE_HW])
        for name in ('fine_hw_switch_eligible', 'fine_hw_install_user', 'backend.hw_eligible'):
            self.assertNotIn(name, off, name)

    def test_cycle_wiring(self):
        for path in (ROOT / 'tools', ROOT / 'probes', ROOT.parent / 'q1n1' / 'tools'):
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
        speed = importlib.import_module('cycle_lib.speed_test')
        fresh = importlib.import_module('cycle_lib.installed_fresh')
        refused = importlib.import_module('cycle_lib.common').Refused
        sets, _ = speed.flag_sets(ROOT)
        base = dict(variant='fast', root_cache_wide=True, update_disjoint_fast=True, service_subclass=True,
                    fine_locks=True, fine_switch=True, user_hw_walk=True)
        flags = fresh.variant_flags(sets, argparse.Namespace(**base, fine_switch_hw=True))
        self.assertEqual(flags[-1], SWITCH_HW)
        self.assertEqual(flags[:-1], fresh.variant_flags(sets, argparse.Namespace(**base)))
        for missing in ('fine_switch', 'user_hw_walk'):
            with self.subTest(missing), self.assertRaises(refused):
                fresh.variant_flags(sets, argparse.Namespace(**dict(base, **{missing: False}), fine_switch_hw=True))
        spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
        cycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cycle)
        args = cycle.parse(['installed-fresh', '--prefix', 'x', '--check', '--variant', 'fast', '--fine-locks',
                            '--fine-switch', '--user-hw-walk', '--fine-switch-hw'])
        self.assertTrue(args.fine_switch_hw)
        # The speed test boots the stock kernel without --kernel-user-4k, so --user-hw-walk stays out of it.
        self.assertNotIn('fine_switch_hw', speed.OPT_IN)
        self.assertNotIn('user_hw_walk', speed.FAST_OPTIONS)


V53 = Path(os.environ.get('HW_WALK_V53_RUN', ROOT / 'build/installed-fresh-20261018-v53'))


@unittest.skipUnless((V53 / 'work-dump/work.bin').is_file(), 'no v53 work dump (set HW_WALK_V53_RUN)')
class V53Dump(unittest.TestCase):
    def test_the_refusal_and_its_fix(self):
        spec = importlib.util.spec_from_file_location('hw_walk_dump', ROOT / 'tools/hw-walk-dump.py')
        dump = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dump)
        out = dump.decode(V53)
        cpu = [c for c in out['cpus'] if c['active'] == '0x8d592c000']
        self.assertEqual(len(cpu), 1)
        self.assertEqual(cpu[0]['hw_record'], 0)
        self.assertEqual(cpu[0]['cache_slots'], [])
        self.assertTrue(cpu[0]['note_loaded'].startswith('NO cache entry'))     # what stopped v53
        self.assertTrue(cpu[0]['note_loaded_hw'])                             # what the fix notes
        self.assertTrue(all(c['note_loaded_hw'] for c in out['cpus']))
        self.assertEqual(out['index_problems'], [])
        self.assertEqual((out['used'], out['stats']['attached'], out['stats']['installs']), (1, 1, 1))
        self.assertEqual(out['failures'], dict(root_install_failures=0, user_view_failed=0))


V55 = Path(os.environ.get('HW_WALK_V55_RUN', ROOT / 'build/installed-fresh-20261018-v55'))


@unittest.skipUnless((V55 / 'work-dump/work.bin').is_file(), 'no v55 work dump (set HW_WALK_V55_RUN)')
class V55Dump(unittest.TestCase):
    def test_the_lost_parents(self):
        # v55's stop: record 1's level-3 copies at index 4 and 6 name themselves
        # as parent (the compaction lost the remap), which the next prune refused.
        spec = importlib.util.spec_from_file_location('hw_walk_dump', ROOT / 'tools/hw-walk-dump.py')
        dump = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dump)
        out = dump.decode(V55)
        record = out['records']['0x8e4b48000']
        self.assertEqual([t['parent'] for t in record['tables']], [0xffff, 0, 1, 1, 4, 1, 6])
        self.assertEqual(len(out['index_problems']), 2)
        self.assertTrue(all('table 4' in p or 'table 6' in p for p in out['index_problems']))
        self.assertEqual(out['stats']['pruned'], 1)
        self.assertEqual(out['failures'], dict(root_install_failures=0, user_view_failed=1))
        self.assertTrue(all(c['note_loaded_hw'] for c in out['cpus']))


V62 = Path(os.environ.get('HW_WALK_V62_RUN', ROOT / 'build/installed-fresh-20261018-v62'))
V63 = Path(os.environ.get('HW_WALK_V63_RUN', ROOT / 'build/installed-fresh-20261018-v63'))


@unittest.skipUnless(any((r / 'work-dump/work.bin').is_file() for r in (V62, V63)),
                     'no v62 or v63 work dump (set HW_WALK_V62_RUN, HW_WALK_V63_RUN)')
class V62Dump(unittest.TestCase):
    # v62's and v63's stops (a transient stage-2 level-2 translation fault on
    # guest RAM, user write; v63 is v56's stack without the token-cost
    # defines): every tree still maps all guest RAM to itself, the fault IPA
    # included, but RETYPE had split blocks under the running CPUs, and 445 or
    # 442 2M blocks per tree were still waiting for theirs. The setup
    # pre-split leaves none.
    RUNS = {V62: (0x92fdde030, 445, 3909, 0xae37e3000),
            V63: (0x936f0f200, 442, 3912, 0xae37f1000)}

    def test_live_splits_and_a_complete_map(self):
        spec = importlib.util.spec_from_file_location('hw_walk_dump', ROOT / 'tools/hw-walk-dump.py')
        dump = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dump)
        for run, (ipa, blocks, tables, l3) in self.RUNS.items():
            if not (run / 'work-dump/work.bin').is_file():
                continue
            out = dump.decode(run, ipas=[ipa])
            self.assertEqual(len(out['stage2']), 6, run)
            for row in out['stage2']:
                self.assertEqual((row['unmapped'], row['blocks_1g']), (0, 0), row)
                self.assertEqual(row['blocks_2m'], blocks, row)
            self.assertEqual(out['stats']['s2_tables'], tables, run)
            self.assertEqual(out['stats']['s2_failures'], 0, run)
            self.assertEqual(out['index_problems'], [], run)
            # The fault IPA: L1 -> a per-tree L2 -> one shared L3 -> a RW identity leaf.
            paths = out['walks'][hex(ipa)]
            self.assertEqual(len(paths), 6, run)
            for path in paths:
                self.assertEqual([lv for lv, _, _ in path], [1, 2, 3], path)
                self.assertTrue(all(int(e, 16) & 3 == 3 for _, _, e in path), path)
                self.assertEqual(int(path[2][1], 16), l3, path)
                leaf = int(path[2][2], 16)
                self.assertEqual(leaf & 0x0000fffffffff000, ipa & ~0xfff, path)
                self.assertEqual((leaf >> 6) & 3, 3, path)      # S2AP read-write


class Layout(unittest.TestCase):
    def test_context_offsets_unchanged(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        perf = importlib.import_module('perf_counters')
        sets, _ = flag_sets()
        sets['v51'] = installed_defines() + V51       # root_ext, the TXM registry, fine locks
        for name, flags in sets.items():
            defines = [f for f in flags if f.startswith('-D')]
            off = perf._records(ROOT / 'probes/xnuboot.c', defines)
            on = perf._records(ROOT / 'probes/xnuboot.c', defines + [DEFINE])
            ctx_off, ctx_on = off['context'], on['context']
            # Every define-free field keeps its offset; the pointer is the one
            # new field, within the context's last page (the arena base, and so
            # root_ext's and the TXM registry's fixed offsets, stay).
            def fields(block):
                return {m[2]: int(m[1]) for m in re.finditer(r'^\s*(\d+) \|   (?! )\S.* (\w+)$', block, re.M)}
            before, after = fields(ctx_off), fields(ctx_on)
            self.assertGreater(len(before), 100, name)
            # Except exit_profile (SNAP_SERVICE_SUBCLASS), which stays the
            # context's last field; its readers take its offset from the run's
            # own defines (tools/perf_counters.py exit_profile_spec).
            moved = {k for k in before if after.get(k) != before[k]}
            self.assertEqual(moved, {'exit_profile'} & set(before), name)
            if 'exit_profile' in before:
                self.assertEqual(max(after, key=after.get), 'exit_profile', name)
            self.assertEqual(set(after) - set(before), {'hw_walk'}, name)
            self.assertEqual((perf._size(ctx_on) + 4095) // 4096, (perf._size(ctx_off) + 4095) // 4096, name)


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


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a few minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402  (import only: build() needs no hardware)
        sets, _ = flag_sets()
        self.assertNotIn(DEFINE, sets['fast'])
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='user-hw-walk-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_USER_HW_WALK=0']), ('on', [DEFINE])):
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
            for label, extra in (('stack', []), ('stack-on', [DEFINE, '-DSNAP_IDREG_MMFR3=1']),
                                 ('stack-on-nos2', [DEFINE, '-DSNAP_USER_HW_WALK_S2RO=0']),
                                 ('stack-fine', FINE), ('stack-fine-on', FINE + [DEFINE]),
                                 ('v51', V51), ('v51-on', V51 + [DEFINE]),
                                 ('v51-notxm-on', [d for d in V51 if 'TXM' not in d] + [DEFINE])):
                monitor_run.FLAGS[:] = sets['fast'] + STACK + extra
                blob = monitor_run.build('xnuboot', out / label)
                results[label] = dict(bytes=len(blob), headroom=budget - len(blob),
                                      sha256=hashlib.sha256(blob).hexdigest())
                self.assertGreater(budget - len(blob), 0, label)
        finally:
            monitor_run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
