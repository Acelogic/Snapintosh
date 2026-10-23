#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline tests of the token-cost defines (docs/TOKEN-COSTS-20261018.md):
SNAP_NEST_FAST, SNAP_DETACH_FAST (compat/nest-fast.h), SNAP_ROOT_INDEX
(compat/root-index.h), SNAP_OTHER_PROFILE and SNAP_GATE_WAIT
(compat/token-costs.h).

  Unit     the seeded harnesses (tools/test-token-costs-nest.c, -index.c)
           with and without the defines must print identical step lines; the
           existing NEST/UNNEST/detach/root/TXM fixture suites pass unchanged
           with the defines on.
  Mutants  each guard of the failure-mode lists, weakened, must fail a harness.
  Profile  the other-call classes and the TOKCOST1 record round-trip through
           tools/perf_counters.py; corrupt records are refused.
  Source   define-off token identity of every changed C file and header.
  Build    (--build) monitor hashes: defaults unchanged, each define on top of
           a flag set (--qualification, default v54's), refused combinations.
Nothing here touches hardware."""
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
from pathlib import Path
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']
NEST_ON = ['-DSNAP_ROOT_VALIDATE_MEMO=1', '-DSNAP_NEST_FAST=1', '-DSNAP_DETACH_FAST=1']
NEST_OFF = ['-DSNAP_ROOT_VALIDATE_MEMO=1']
CHANGED_C = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/txm.c', 'shadow/shadow.c',
             'probes/xnuboot.c']
CHANGED_H = ['compat/sptm.h', 'compat/sptm-root-memo.h', 'shadow/shadow.h']
DEFINES = ['-DSNAP_NEST_FAST=1', '-DSNAP_DETACH_FAST=1', '-DSNAP_ROOT_INDEX=1', '-DSNAP_OTHER_PROFILE=1',
           '-DSNAP_GATE_WAIT=1']
ARGS = argparse.Namespace(build=False, out=None, qualification=None, base=None, expect=[])


def compile_c(directory, test, defines, overrides=None, extra=('shadow/native-shared.c',), werror=True):
    """tools/<test> with CORE; overrides maps a repo path to replacement text,
    written to a private tree whose files shadow the originals."""
    directory = Path(directory)
    exe = directory / (Path(test).stem + '-' + hashlib.sha1(' '.join(defines).encode()).hexdigest()[:8])
    include, sources = [], [*CORE, *extra]
    if overrides:
        # A private copy of compat/ and shadow/ with the mutated files: quoted
        # includes resolve beside the including file first, so a mutated
        # header must sit next to every file that includes it.
        mut = directory / 'mut'
        for sub in ('compat', 'shadow'):
            for f in (ROOT / sub).iterdir():
                if f.suffix in ('.c', '.h', '.S'):
                    (mut / sub).mkdir(parents=True, exist_ok=True)
                    (mut / sub / f.name).write_text(read_source(f))
        for rel, text in overrides.items():
            (mut / rel).write_text(text)
        include = [f'-I{mut}/compat', f'-I{mut}/shadow']
        sources = [str(mut / s) for s in sources]
    cmd = ['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', *(['-Werror'] if werror else []),
           '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *defines, *include,
           '-Icompat', '-Ishadow', f'tools/{test}', *sources, '-o', str(exe)]
    subprocess.run(cmd, cwd=ROOT, check=True, timeout=600, capture_output=True)
    return exe


def run(exe):
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=1200)


def steps(result):
    return [line for line in result.stdout.splitlines() if line.startswith('step ')]


class Unit(unittest.TestCase):
    def differential(self, test, off, ons, extra=('shadow/native-shared.c',)):
        with tempfile.TemporaryDirectory() as d:
            base = run(compile_c(d, test, off, extra=extra))
            self.assertEqual(base.returncode, 0, base.stdout[-2000:] + base.stderr[-2000:])
            ref = steps(base)
            self.assertGreater(len(ref), 1000)
            for on in ons:
                got = run(compile_c(d, test, on, extra=extra))
                self.assertEqual(got.returncode, 0, ' '.join(on) + got.stdout[-2000:] + got.stderr[-2000:])
                self.assertEqual(steps(got), ref, ' '.join(on))
                print(f'{test} {" ".join(on)}: {len(ref)} steps equal; ' +
                      '; '.join(l[2:] for l in got.stdout.splitlines() if l.startswith('# ') and
                                'nest memo' not in l), file=sys.stderr)

    def test_nest_and_detach(self):
        self.differential('test-token-costs-nest.c', NEST_OFF,
                          [NEST_ON, NEST_ON + ['-DSPTM_NEST_FAST_SAMPLE=0'],
                           NEST_ON + ['-DSNAP_ROOT_MISS_FAST=1']])

    def test_root_index(self):
        self.differential('test-token-costs-index.c', [],
                          [['-DSNAP_ROOT_INDEX=1'], ['-DSNAP_ROOT_INDEX=1', '-DSPTM_ROOT_INDEX_AUDIT=0'],
                           ['-DSNAP_ROOT_INDEX=1', '-DSPTM_ROOT_INDEX_SLOTS=64u']], extra=())

    def test_existing_suites_unchanged(self):
        suites = {'test-native-shared-nest.c': ('shadow/native-shared.c',), 'test-sptm-nest.c': (),
                  'test-sptm-unnest.c': (), 'test-sptm-user-detach.c': (), 'test-sptm-root.c': (),
                  'test-sptm-shared-root.c': (), 'test-sptm-shared-binding.c': (), 'test-txm.c': (),
                  'test-txm-shared-region.c': (), 'test-root-validate-memo.c': (),
                  'test-sptm-shared-detach.c': (), 'test-sptm-shared-table.c': ()}
        on = ['-DSNAP_NEST_FAST=1', '-DSNAP_DETACH_FAST=1', '-DSNAP_ROOT_INDEX=1']
        with tempfile.TemporaryDirectory() as d:
            for suite, extra in suites.items():
                outs = []
                for defines in ([], on):
                    sub = Path(d) / ('on' if defines else 'off')
                    sub.mkdir(exist_ok=True)
                    r = run(compile_c(sub, suite, defines, extra=extra, werror=False))
                    self.assertEqual(r.returncode, 0, suite + ' ' + ' '.join(defines) + r.stdout[-2000:] +
                                     r.stderr[-2000:])
                    outs.append(r.stdout)
                self.assertEqual(outs[0], outs[1], suite)
            # The miss-verdict suite needs SNAP_ROOT_MISS_FAST.
            outs = []
            for defines in (['-DSNAP_ROOT_MISS_FAST=1'], ['-DSNAP_ROOT_MISS_FAST=1', *on]):
                sub = Path(d) / ('m-on' if len(defines) > 1 else 'm-off')
                sub.mkdir(exist_ok=True)
                r = run(compile_c(sub, 'test-root-miss-build.c', defines, werror=False))
                self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
                outs.append(r.stdout)
            self.assertEqual(outs[0], outs[1])


# (label, file, old, new, harness, defines): each must make its harness fail
# (the C test exits nonzero, or its steps differ from the define-free build).
_P = 'compat/sptm-root.c'
MUTANTS = [
    ('N2 a verdict recorded without validate_table', _P,
     '    if(!shared_validates(m,g,table,base,flags))return 0;\n    memo->stats.misses++;',
     '    memo->stats.misses++;', 'nest', NEST_ON),
    ('N3 the per-entry scan skips policy', _P,
     '           sptm_mac_user_leaf_policy(flags,21,data[2],addr,pte,g) ||\n           !m->map(m->ctx,pte&MASK,g->page_size))return 0;',
     '           !m->map(m->ctx,pte&MASK,g->page_size))return 0;', 'nest', NEST_ON),
    ('N3 the per-entry scan checks invalid descriptors', _P,
     '        if((pte&3)!=3)continue;\n        uint64_t addr=base+i*g->page_size;',
     '        if(!(pte&1))continue;\n        uint64_t addr=base+i*g->page_size;', 'nest', NEST_ON),
    ('N4 UNNEST counts compressed markers as mapped leaves', 'compat/sptm-user.c',
     '            if(!(pte&~0xe000000000000000UL))continue;\n            if((pte&3)!=3)proved=0;',
     '            if(!(pte&~0xe000000000000000UL)){nonzero+=pte!=0;continue;}\n            if((pte&3)!=3)proved=0;', 'nest', NEST_ON),
    ('N4 UNNEST counts empty slots as mapped leaves', 'compat/sptm-user.c',
     '            if(!(pte&~0xe000000000000000UL))continue;\n            if((pte&3)!=3)proved=0;',
     '            if(!(pte&~0xe000000000000000UL)){nonzero+=pte==0;continue;}\n            if((pte&3)!=3)proved=0;', 'nest', NEST_ON),
    ('N1 a verdict survives the retype epoch', 'compat/sptm-root-memo.h',
     '           e->record==record && e->epoch==(uint32_t)memo->epoch)return 1;',
     '           e->record==record)return 1;', 'nest', NEST_ON),
    ('N5 a failed rescan is not fatal', _P,
     '{if(st)st->mismatches++;return -1;}', '{if(st)st->mismatches++;return 1;}', 'nest',
     NEST_ON + ['-DSPTM_NEST_FAST_SAMPLE=0']),
    ('N5 the sampled rescan never runs', _P,
     '        if(!(n&SPTM_NEST_FAST_SAMPLE)) {', '        if(0) {', 'nest', NEST_ON + ['-DSPTM_NEST_FAST_SAMPLE=0']),
    ('N6 a recorded miss is not counted', _P,
     '    memo->stats.misses++;\n    sptm_root_memo_store', '    sptm_root_memo_store', 'nest', NEST_ON),
    ('N6 a hit is not counted', _P, '        memo->stats.hits++;\n', '', 'nest', NEST_ON),
    ('N2 a verdict stored under another base', _P,
     '    sptm_root_memo_store(memo,table,base,flags,g->shift,record);',
     '    sptm_root_memo_store(memo,table,base+0x4000,flags,g->shift,record);', 'nest', NEST_ON),
    ('N2 a verdict stored under other flags', _P,
     '    sptm_root_memo_store(memo,table,base,flags,g->shift,record);',
     '    sptm_root_memo_store(memo,table,base,flags^0x20,g->shift,record);', 'nest', NEST_ON),
    ('D1 shadow_range_empty ignores level-3 leaves', 'shadow/shadow.c',
     '                if ((e & 3) == 3) return 0;\n', '', 'nest', NEST_ON),
    ('D2 a block is read as a table', 'shadow/shadow.c',
     '            if (!(d & PT_TABLE) || level >= 3) return -1;', '            if (level >= 3) return -1;',
     'nest', NEST_ON),
    ('D2 a removed leaf takes the fast path', _P,
     '    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2)) {',
     '    if(level==2 && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2)) {', 'nest', NEST_ON),
    ('D1 the guest table is not read', _P,
     '            if((*(volatile uint64_t *)(void *)(page+8UL*i)&3)==3)return 0;\n',
     '            if((*(volatile uint64_t *)(void *)(page+8UL*i)&3)==3)(void)0;\n', 'nest', NEST_ON),
    ('D3 shadow_unmap\'s alignment refusal is lost', 'shadow/shadow.c',
     '    if (!s || s->txsz < 16 || s->txsz > 39 || !s->read || !s->write ||\n        ((va | size) & 0xfff) || va >= (1UL << (64-s->txsz)) ||\n        size > (1UL << (64-s->txsz)) - va) return -1;\n    int start = mmu_start_level(G, s->txsz);\n    if (start < 0) return -1;\n    uint64_t at = va, end = va + size;\n    while (at < end) {\n        uint64_t table = s->root & PT_OA_MASK, d = 0;',
     '    if (!s || s->txsz < 16 || s->txsz > 39 || !s->read || !s->write ||\n        va >= (1UL << (64-s->txsz)) ||\n        size > (1UL << (64-s->txsz)) - va) return -1;\n    int start = mmu_start_level(G, s->txsz);\n    if (start < 0) return -1;\n    uint64_t at = va, end = va + size;\n    while (at < end) {\n        uint64_t table = s->root & PT_OA_MASK, d = 0;',
     'nest', NEST_ON),
    ('D1 a commit skips without its proof', _P,
     '    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2) &&\n       shadow_range_empty(&commit,base,end-base)==1)return 1;',
     '    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2))return 1;',
     'nest', NEST_ON),
    ('D3 the word-wise emptiness check skips words', 'compat/sptm-user.c',
     'for(unsigned i=0;i<PAGE_SIZE;i+=8) if(*(volatile uint64_t *)(void *)(page+i)) return SPTM_FRAME_BUSY;',
     'for(unsigned i=0;i<PAGE_SIZE;i+=16) if(*(volatile uint64_t *)(void *)(page+i)) return SPTM_FRAME_BUSY;',
     'nest', NEST_ON),
    ('R1 a constructor is not noted', 'compat/sptm.c',
     '        new_root ? SPTM_ROOT_KEY_USER(asid) : share_root ? SPTM_ROOT_KEY_SHARED(shared_slot) : 0);',
     '        share_root ? SPTM_ROOT_KEY_SHARED(shared_slot) : 0);', 'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R2 a share is not noted', 'compat/sptm.c',
     '        new_root ? SPTM_ROOT_KEY_USER(asid) : share_root ? SPTM_ROOT_KEY_SHARED(shared_slot) : 0);',
     '        new_root ? SPTM_ROOT_KEY_USER(asid) : 0);', 'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R2 a release is not noted', 'compat/root-index.h',
     '    if(removed)sptm_root_index_remove(x,pa,removed);\n', '', 'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R1 a build skips the map\'s last half', 'compat/root-index.h',
     '    for(uint64_t off=0;off<map_size;off+=16) {\n        uint32_t key=sptm_root_index_key(all+off);',
     '    for(uint64_t off=0;off<map_size/2;off+=16) {\n        uint32_t key=sptm_root_index_key(all+off);',
     'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R3 matches in hash order', 'compat/root-index.h',
     '        while(k && out[k-1]>pa) {out[k]=out[k-1];k--;}\n        out[k]=pa;\n    }\n    if(!((x->stats',
     '        out[k]=pa;\n    }\n    if(!((x->stats', 'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R4 TXM visits frames outside its range', 'compat/root-index.h',
     '        if(x->slot[i].key!=key || (txm && (pa>=m->alloc_high || sptm_next_frame(m,pa)!=pa)))continue;',
     '        if(x->slot[i].key!=key)continue;', 'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R5 a full table answers partially', 'compat/root-index.h',
     '    if(x->stats.live>=SPTM_ROOT_INDEX_SLOTS/2) {x->stats.full++;x->stats.built=0;return 0;}',
     '    if(x->stats.live>=SPTM_ROOT_INDEX_SLOTS/2) {x->stats.full++;return 1;}', 'index',
     ['-DSNAP_ROOT_INDEX=1', '-DSPTM_ROOT_INDEX_SLOTS=16u']),
    ('R6 an audit mismatch keeps the index', 'compat/root-index.h',
     '            x->stats.mismatches++;x->stats.built=0;', '            x->stats.mismatches++;', 'index',
     ['-DSNAP_ROOT_INDEX=1', '-DSPTM_ROOT_INDEX_AUDIT=0']),
    ('R6 an audit answers with the index', 'compat/root-index.h',
     '            for(int k=0;k<s;k++)out[k]=found[k];\n            return s;',
     '            return (int)n;', 'index', ['-DSNAP_ROOT_INDEX=1', '-DSPTM_ROOT_INDEX_AUDIT=0']),
    ('R2 the constructor trusts a stale entry', 'compat/sptm.c',
     '            if (f[2] == SPTM_MAC_USER_ROOT_TABLE && ((uint64_t)f[4] | ((uint64_t)f[5] << 8)) == asid)\n                return SPTM_FRAME_BUSY;',
     '            return SPTM_FRAME_BUSY;', 'index', ['-DSNAP_ROOT_INDEX=1']),
    ('R2 a stale entry is not re-read', 'compat/txm.c',
     '        if(shared) {\n            if(f[2]!=SPTM_MAC_SHARED_ROOT_TABLE || f[8]!=asid)continue;',
     '        if(shared) {\n            if(0)continue;', 'index', ['-DSNAP_ROOT_INDEX=1']),
]


class Mutants(unittest.TestCase):
    def test_each_mutant_fails(self):
        harness = {'nest': ('test-token-costs-nest.c', NEST_OFF, ('shadow/native-shared.c',)),
                   'index': ('test-token-costs-index.c', [], ())}
        refs = {}
        with tempfile.TemporaryDirectory() as d:
            for name, (test, off, extra) in harness.items():
                r = run(compile_c(d, test, off, extra=extra))
                self.assertEqual(r.returncode, 0)
                refs[name] = steps(r)
            for label, path, old, new, which, defines in MUTANTS:
                with self.subTest(label):
                    text = read_source(ROOT / path)
                    self.assertEqual(text.count(old), 1, label)
                    test, _, extra = harness[which]
                    sub = Path(d) / hashlib.sha1(label.encode()).hexdigest()[:10]
                    sub.mkdir()
                    # Warnings a weakening leaves behind (an unused variable) are not refusals.
                    exe = compile_c(sub, test, defines, {path: text.replace(old, new)}, extra=extra, werror=False)
                    r = run(exe)
                    failed = r.returncode != 0 or steps(r) != refs[which]
                    self.assertTrue(failed, f'{label} survived')
                    print(f'mutant {label}: caught', file=sys.stderr)


class Profile(unittest.TestCase):
    WRITER = r'''
#include <stdio.h>
#include <string.h>
#include "token-costs.h"
int main(void)
{
    static const unsigned long long calls[]={
        0x0002000000000023ULL,0x0002000000000024ULL,0x0002000000000025ULL,0x000200000000000eULL,
        0x0000000300000000ULL,0x0000000300000002ULL,0x0000000300000003ULL,0x0000000300000008ULL,
        0x0000000300000005ULL,0x0000000500000001ULL,0x0000000600000002ULL,0x000000070000000cULL,
        0x0000000900000001ULL,0x0000000000000021ULL,0x0400000000000000ULL,0x0001000000000000ULL};
    struct other_profile o={0};struct service_profile p={0};
    for(unsigned i=0;i<16;i++) {
        printf("%u ",other_profile_class(calls[i]));
        other_profile_tag(&o,i%6,calls[i]);
        p.category=SERVICE_SUB_CATEGORY;p.stage=0;p.enter_tick=100*i;p.acquire_tick=100*i+7*i+1;p.last_tick=p.acquire_tick+10+i;
        other_profile_charge(&o,i%6,&p,1,SERVICE_SUB_CALL_OTHER);
    }
    other_profile_tag(&o,1,calls[0]);other_profile_charge(&o,1,&p,1,SERVICE_SUB_VECTOR);   /* not call_other */
    printf("\n");
    struct token_costs_report r;memset(&r,0,sizeof(r));
    for(unsigned i=0;i<16;i++)r.other[i]=o.buckets[i];
    r.nest[0]=10;r.nest[1]=6;r.nest[2]=4;r.nest[3]=4;r.index[0]=1;r.index[3]=99;r.gate[0]=3;r.gate[1]=300;
    unsigned long long head[2]={TOKEN_COSTS_MAGIC,0x1fULL|(unsigned long long)sizeof(r)<<32};
    fwrite(head,8,2,stdout);fwrite(&r,sizeof(r),1,stdout);
    return 0;
}
'''

    def test_classes_and_record(self):
        spec = importlib.util.spec_from_file_location('perf_counters', ROOT / 'tools/perf_counters.py')
        pc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pc)
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'w.c'
            src.write_text(self.WRITER)
            exe = Path(d) / 'w'
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Icompat', str(src), '-o', str(exe)],
                           cwd=ROOT, check=True, capture_output=True)
            out = subprocess.run([str(exe)], capture_output=True, check=True).stdout
        line, record = out.split(b'\n', 1)
        self.assertEqual([int(x) for x in line.split()], list(range(16)))
        call_other = dict(entries=16, wait_ticks=sum(7 * i + 1 for i in range(16)),
                          hold_ticks=sum(10 + i for i in range(16)))
        got = pc.decode_token_costs(record, hz=100.0, call_other=call_other)
        self.assertEqual(sorted(got['other']), sorted(pc.OTHER_CLASSES))
        self.assertEqual(got['other']['txm36']['entries'], 1)
        self.assertEqual(got['nest']['nest_hits'], 6)
        self.assertEqual(got['root_index']['lookups'], 99)
        self.assertEqual(got['gate']['waited'], 3)
        with self.assertRaises(ValueError):           # the classes must sum to call_other
            pc.decode_token_costs(record, call_other=dict(call_other, entries=15))
        bad = bytearray(record); bad[0] ^= 1
        with self.assertRaises(ValueError):
            pc.decode_token_costs(bytes(bad))
        bad = bytearray(record); struct.pack_into('<Q', bad, 16 + 8 * 11, 1)   # a nest mismatch
        with self.assertRaises(ValueError):
            pc.decode_token_costs(bytes(bad))
        with self.assertRaises(ValueError):
            pc.decode_token_costs(record[:-8])
        self.assertNotIn('phase_fair_gate', got['defines'])
        self.assertNotIn('phase_entries', got['gate'])

    def test_phase_fair_gate_record(self):
        # SNAP_PHASE_FAIR_GATE (compat/service-lock.h): header bit 5, only with bit 4 (gate_wait), and
        # gate[4..6]: entries ahead of a queued writer (at most the waited entries), drains, drain ticks.
        spec = importlib.util.spec_from_file_location('perf_counters', ROOT / 'tools/perf_counters.py')
        pc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pc)
        def record(bits, gate):
            words = [0] * 96
            words[80:80 + len(gate)] = gate
            return struct.pack('<2Q', pc.TOKEN_MAGIC, bits | 768 << 32) + struct.pack('<96Q', *words)
        got = pc.decode_token_costs(record(0x30, [9, 900, 1, 0, 4, 7, 70]), hz=10.0)
        self.assertTrue(got['defines']['gate_wait'] and got['defines']['phase_fair_gate'])
        self.assertEqual(got['gate'], dict(waited=9, wait_ticks=900, timeouts=1, stopped=0, phase_entries=4, drains=7,
                                           drain_ticks=70, wait_seconds=90.0, drain_seconds=7.0))
        self.assertEqual(pc.decode_token_costs(record(0x10, [9, 900, 1, 0, 4, 7, 70]))['gate'],
                         dict(waited=9, wait_ticks=900, timeouts=1, stopped=0))   # bit 5 clear: as before
        for bits, gate in ((0x20, [9, 900, 1, 0, 4, 7, 70]),        # bit 5 without gate_wait
                           (0x30, [3, 300, 0, 0, 4, 7, 70]),        # more phase entries than waited
                           (0x30, [3, 300, 0, 0, 1, 0, 70]),        # drain time without drains
                           (0x70, [3, 300, 0, 0, 1, 1, 1])):        # an unknown bit
            with self.assertRaises(ValueError):
                pc.decode_token_costs(record(bits, gate))


def strip_defines(text, names):
    """Drop every #if block on `names` (and the #else of those), keeping the rest."""
    out, stack = [], []
    pat = re.compile(r'#if (?:(?:SNAP_\w+)(?: \|\| )?)+$')
    for line in text.splitlines(keepends=True):
        s = line.strip()
        if s.startswith('#if'):
            ours = bool(pat.fullmatch(s)) and all(n in names for n in re.findall(r'SNAP_\w+', s))
            stack.append(['ours' if ours else 'other', ours])
            if ours:
                continue
        elif s.startswith('#else') and stack and stack[-1][0] == 'ours':
            stack[-1][1] = False
            continue
        elif s.startswith('#endif') and stack:
            kind, _ = stack.pop()
            if kind == 'ours':
                continue
        if any(k == 'ours' and skip for k, skip in stack):
            continue
        out.append(line)
    return ''.join(out)


OURS = ('SNAP_NEST_FAST', 'SNAP_DETACH_FAST', 'SNAP_ROOT_INDEX', 'SNAP_OTHER_PROFILE', 'SNAP_GATE_WAIT',
        'SNAP_TOKEN_COSTS')


class Source(unittest.TestCase):
    def preprocess(self, tree, rel, flags):
        inc = ['-Icompat', '-Ishadow', f'-I{tree.parent / "q1n1" / "platform" / "uefi"}']
        target = ['--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only'] \
            if rel == 'probes/xnuboot.c' else []
        r = subprocess.run(['clang', *target, '-E', '-P', *flags, *inc, rel], cwd=tree, capture_output=True,
                           text=True)
        self.assertEqual(r.returncode, 0, rel + r.stderr[-2000:])
        return re.findall(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\w+|[^\w\s]', r.stdout)

    def test_define_off_tokens(self):
        """Every changed translation unit preprocesses to the same tokens without the defines,
        under no flags and under the qualification's flag set."""
        base = Path(ARGS.base) if ARGS.base else None
        if not base:
            self.skipTest('no --base tree')
        qual = ARGS.qualification or str(ROOT / 'build' / \
                                     'installed-fresh-20261018-v54/qualification.json')
        installed = [f for f in json.load(open(qual))['flags'] if f.startswith('-D')]
        for flags in ([], installed):
            for rel in CHANGED_C:
                self.assertEqual(self.preprocess(ROOT, rel, flags), self.preprocess(base, rel, flags),
                                 f'{rel} {"installed" if flags else "no"} flags')

    def test_new_headers_default_off(self):
        for rel, names in (('compat/nest-fast.h', ('SNAP_NEST_FAST', 'SNAP_DETACH_FAST')),
                           ('compat/root-index.h', ('SNAP_ROOT_INDEX',)),
                           ('compat/token-costs.h', ('SNAP_OTHER_PROFILE',))):
            text = (ROOT / rel).read_text()
            for n in names:
                self.assertIn(f'#ifndef {n}\n#define {n} 0\n#endif', text, rel)
        src = read_source(ROOT / 'probes/xnuboot.c')
        for n in OURS[:-1]:
            self.assertIn(f'#ifndef {n}\n#define {n} 0\n#endif', src)
        self.assertIn('"nest verdicts are the SWITCH_ROOT memo\'s: its write witness, its sampled walk, linked groups"',
                      src)

    def test_index_noted_at_the_only_key_writer(self):
        sptm = (ROOT / 'compat/sptm.c').read_text()
        # Byte 2 is written in two places: the TXM-only retype and sptm_mac_retype, whose commit notes the index.
        self.assertEqual(len(re.findall(r'entry\[2\]\s*=\s*\(uint8_t\)new_type;', sptm)), 2)
        commit = sptm[sptm.index('enum sptm_result sptm_mac_retype('):]
        commit = commit[:commit.index('\n}\n')]
        self.assertLess(commit.index('sptm_root_index_retype('), commit.index('entry[2] = (uint8_t)new_type;'))
        self.assertLess(commit.index('sptm_root_index_retype('), commit.index('entry[i] = 0;'))
        txm_retype = sptm[sptm.index('enum sptm_result sptm_txm_retype('):]
        txm_retype = txm_retype[:txm_retype.index('\n}\n')]
        self.assertNotIn('USER_ROOT', txm_retype)
        check = sptm[sptm.index('enum sptm_result sptm_txm_retype_check('):]
        check = check[:check.index('\n}\n')]
        self.assertIn('old_type==SPTM_MAC_TXM_DEFAULT && new_type==SPTM_MAC_TXM_OWNED', check)


def build_variants(out, qual, root):
    sys.path.insert(0, str(root / 'probes'))
    sys.path.insert(0, str(root.parent / 'q1n1' / 'tools'))
    cwd = os.getcwd()
    os.chdir(root)
    try:
        import run as monitor_run
        spec = importlib.util.spec_from_file_location('wfi', root / 'tools/test-wfi-resume.py')
        m = importlib.util.module_from_spec(spec)
        saved = sys.argv
        sys.argv = [saved[0]]
        spec.loader.exec_module(m)
        sys.argv = saved
        sets, _ = m.flag_sets()
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        flags = list(json.load(open(qual))['flags'])
        res = {}
        plans = [('control', sets['control']), ('fast', sets['fast']), ('fast-wfi', sets['fast-wfi']),
                 ('installed', flags)]
        for define in DEFINES:
            plans.append(('installed+' + define[7:-2].lower(), flags + [define]))
        plans.append(('installed+all', flags + DEFINES))
        for name, f in plans:
            monitor_run.FLAGS[:] = f
            blob = monitor_run.build('xnuboot', Path(out) / name)
            res[name] = dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                             headroom=monitor_run.OUT_AT - monitor_run.CODE_AT - len(blob))
        refused = {}
        for name, f in (('nest-fast without the memo', [x for x in flags if 'SNAP_ROOT_VALIDATE_MEMO' not in x] +
                         ['-DSNAP_ROOT_VALIDATE_MEMO=0', '-DSNAP_NEST_FAST=1']),
                        ('gate-wait without fine locks', [x for x in flags if 'FINE' not in x] +
                         ['-DSNAP_GATE_WAIT=1'])):
            monitor_run.FLAGS[:] = f
            try:
                monitor_run.build('xnuboot', Path(out) / ('refused-' + name.replace(' ', '-')))
                refused[name] = False
            except Exception:
                refused[name] = True
        return res, refused
    finally:
        os.chdir(cwd)


class Build(unittest.TestCase):
    def test_hashes(self):
        if not ARGS.build:
            self.skipTest('--build not given')
        qual = ARGS.qualification or str(ROOT / 'build' / \
                                     'installed-fresh-20261018-v54/qualification.json')
        out = Path(ARGS.out or tempfile.mkdtemp())
        res, refused = build_variants(out, qual, ROOT)
        print(json.dumps(dict(builds=res, refused=refused), indent=1), file=sys.stderr)
        for name, sha in (e.split('=', 1) for e in ARGS.expect):
            self.assertEqual(res[name]['sha256'], sha, name)
        self.assertTrue(all(refused.values()), refused)
        for name, row in res.items():
            if name.startswith('installed+'):
                self.assertNotEqual(row['sha256'], res['installed']['sha256'], name)
                self.assertGreater(row['headroom'], 64 * 1024, name)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--qualification')
    ap.add_argument('--base', help='the tree without the patch, for the define-off text check')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    ARGS, rest = ap.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest])
