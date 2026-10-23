#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline tests of SNAP_UNNEST_4K_FAST (compat/nest-fast.h, docs/UNNEST-4K-FAST-20261020.md): UNNEST_REGION
on 4K user roots answers nested shared tables and their leaf counts from the SWITCH_ROOT memo.

  Unit     tools/test-unnest-4k-fast.c built without the define and with it (also nest-fast alone, every hit
           sampled, with SNAP_ROOT_MISS_FAST) must print identical step lines; the existing NEST/UNNEST/memo
           suites print the same with the define on.
  Mutants  each guard of the failure modes U1-U9, weakened, must fail the harness.
  Source   define-off token identity of every changed file against --base, under no flags and under the
           qualification's flags; the header defaults the define to 0.
  Build    (--build) monitor hashes: define-off builds equal --base's, the define on top of the
           qualification's flags differs and fits, and a build without SNAP_NEST_FAST is refused.
Nothing here touches hardware."""
import argparse
import hashlib
import json
import os
import re
import runpy
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
MEMO = ['-DSNAP_ROOT_VALIDATE_MEMO=1']
NEST = MEMO + ['-DSNAP_NEST_FAST=1', '-DSNAP_DETACH_FAST=1']
ON = NEST + ['-DSNAP_UNNEST_4K_FAST=1']
ON2K = ON + ['-DSPTM_ROOT_MEMO_ENTRIES=2048u', '-DTEST_MEMO_CAPACITY_OVERRIDDEN=1']   # v6's capacity: large witness paths
DEFINE = '-DSNAP_UNNEST_4K_FAST=1'
CHANGED_C = ['compat/sptm-root.c', 'compat/sptm-user.c', 'probes/xnuboot.c']   # and, through them, the headers
V5 = str(ROOT / 'build/installed-fresh-20261020-v5/qualification.json')
ARGS = argparse.Namespace(build=False, out=None, qualification=None, base=None)


def flags_of(qual):
    with open(qual) as f:
        return json.load(f)['flags']


def compile_c(directory, test, defines, overrides=None, extra=('shadow/native-shared.c',), werror=True):
    """tools/<test> with CORE; overrides maps a repo path to replacement text in a private tree."""
    directory = Path(directory)
    exe = directory / (Path(test).stem + '-' + hashlib.sha1(' '.join(defines).encode()).hexdigest()[:8])
    include, sources = [], [*CORE, *extra]
    if overrides:
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
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=1800)


def steps(result):
    return [line for line in result.stdout.splitlines() if line.startswith('step ')]


def notes(result):
    return [line[2:] for line in result.stdout.splitlines() if line.startswith('# ')]


class Unit(unittest.TestCase):
    def test_differential(self):
        with tempfile.TemporaryDirectory() as d:
            base = run(compile_c(d, 'test-unnest-4k-fast.c', MEMO))
            self.assertEqual(base.returncode, 0, base.stdout[-2000:] + base.stderr[-2000:])
            ref = steps(base)
            self.assertGreater(len(ref), 2000)
            for on in (NEST, ON, ON2K, ON + ['-DSPTM_NEST_FAST_SAMPLE=0'], ON + ['-DSNAP_ROOT_MISS_FAST=1']):
                got = run(compile_c(d, 'test-unnest-4k-fast.c', on))
                self.assertEqual(got.returncode, 0, ' '.join(on) + got.stdout[-3000:] + got.stderr[-3000:])
                self.assertEqual(steps(got), ref, ' '.join(on))
                n = notes(got)
                summary = [l for l in n if l.startswith(('counted hits', 'stale', 'crowding round 2', 'capacity'))]
                last = [l for l in n if l.startswith('scenario memo')][-1:]
                print(f'{" ".join(on)}: {len(ref)} steps equal; ' + '; '.join(summary + last), file=sys.stderr)

    def test_existing_suites_unchanged(self):
        suites = {'test-native-shared-nest.c': ('shadow/native-shared.c',), 'test-sptm-nest.c': (),
                  'test-sptm-unnest.c': (), 'test-sptm-user-detach.c': (), 'test-sptm-root.c': (),
                  'test-sptm-shared-root.c': (), 'test-sptm-shared-binding.c': (),
                  'test-root-validate-memo.c': (), 'test-sptm-shared-detach.c': (),
                  'test-sptm-shared-table.c': ()}
        with tempfile.TemporaryDirectory() as d:
            for suite, extra in suites.items():
                outs = []
                for name, defines in (('off', []), ('nest', NEST), ('on', ON), ('on2k', ON2K)):
                    sub = Path(d) / name
                    sub.mkdir(exist_ok=True)
                    r = run(compile_c(sub, suite, defines, extra=extra, werror=False))
                    self.assertEqual(r.returncode, 0, suite + ' ' + ' '.join(defines) + r.stdout[-2000:] +
                                     r.stderr[-2000:])
                    outs.append(r.stdout)
                self.assertEqual(outs[0], outs[1], suite)
                self.assertEqual(outs[0], outs[2], suite)
                self.assertEqual(outs[0], outs[3], suite)
            # The 16K nest-fast harness: its steps are the same with the 4K define on (16K paths unchanged).
            ref = steps(run(compile_c(d, 'test-token-costs-nest.c', MEMO)))
            self.assertGreater(len(ref), 1000)
            for on in (NEST, ON, ON2K, ON + ['-DSPTM_NEST_FAST_SAMPLE=0']):
                r = run(compile_c(d, 'test-token-costs-nest.c', on))
                self.assertEqual(r.returncode, 0, ' '.join(on) + r.stdout[-2000:] + r.stderr[-2000:])
                self.assertEqual(steps(r), ref, ' '.join(on))
            outs = []
            for defines in (['-DSNAP_ROOT_MISS_FAST=1'], ['-DSNAP_ROOT_MISS_FAST=1', *ON]):
                sub = Path(d) / ('m-on' if len(defines) > 1 else 'm-off')
                sub.mkdir(exist_ok=True)
                r = run(compile_c(sub, 'test-root-miss-build.c', defines, werror=False))
                self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
                outs.append(r.stdout)
            self.assertEqual(outs[0], outs[1])


# (label, file, old, new, defines): each must make the harness fail (it exits nonzero, or its steps differ
# from the define-free build's). From the guards of docs/UNNEST-4K-FAST-20261020.md section 3. U4 (the
# per-descriptor checks before the proof) is the differential's locked, unmappable, unmanaged and bad-leaf steps.
_M, _R, _U = 'compat/sptm-root-memo.h', 'compat/sptm-root.c', 'compat/sptm-user.c'
S0 = ON + ['-DSPTM_NEST_FAST_SAMPLE=0']
_PROOF = '    if(r==1 && st && st->unnest_hits!=hits && st->sampled==sampled) {'
_MISS = ('    if(!shared_validates(m,g,table,base,flags))return 0;\n    memo->stats.misses++;\n'
         '    sptm_root_memo_store(memo,table,base,flags,g->shift,record);')
MUTANTS = [
    ('U1 the witness drops only a frame\'s first window', _M,
     '    if(!memo->frame_live[h])return;            /* no entry of this frame */\n'
     '    for(unsigned w=0;w<SPTM_ROOT_MEMO_FRAME_WAYS;w++) {\n#else',
     '    if(!memo->frame_live[h])return;            /* no entry of this frame */\n'
     '    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {\n#else', ON),
    ('U1 the record check covers only a frame\'s first window', _M,
     '    for(unsigned w=0;w<SPTM_ROOT_MEMO_FRAME_WAYS;w++) {\n        struct sptm_root_memo_entry *e=&memo->entry'
     '[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];\n        if(e->table && (e->table&~UINT64_C(0x3fff))==frame && '
     'SPTM_ROOT_MEMO_RECORD(e->record)!=now)',
     '    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {\n        struct sptm_root_memo_entry *e=&memo->entry'
     '[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];\n        if(e->table && (e->table&~UINT64_C(0x3fff))==frame && '
     'SPTM_ROOT_MEMO_RECORD(e->record)!=now)', ON),
    ('U6 a record change keeps the verdict (small path)', _M,
     'SPTM_ROOT_MEMO_RECORD(e->record)!=now)\n            sptm_root_memo_drop(memo,e);',
     '0)\n            sptm_root_memo_drop(memo,e);', ON),
    ('U6 a record change keeps the verdict (large path)', _M,
     'if(!record || sptm_root_memo_record_bytes(record)!=SPTM_ROOT_MEMO_RECORD(e->record))\n',
     'if(!record)\n', ON2K),
    ('U6 the record check compares the count too', _M,
     'SPTM_ROOT_MEMO_RECORD(e->record)!=now)\n', 'e->record!=now)\n', ON),
    ('U6 a counted verdict stops answering', _M,
     '           SPTM_ROOT_MEMO_RECORD(e->record)==record && e->epoch==(uint32_t)memo->epoch)return 1;',
     '           e->record==record && e->epoch==(uint32_t)memo->epoch)return 1;', ON),
    ('U6 a counted verdict\'s count is not found', _M,
     '           SPTM_ROOT_MEMO_RECORD(e->record)==record && e->epoch==(uint32_t)memo->epoch)return e;',
     '           e->record==record && e->epoch==(uint32_t)memo->epoch)return e;', ON),
    ('U9 a verdict survives the retype epoch', _M,
     '           SPTM_ROOT_MEMO_RECORD(e->record)==record && e->epoch==(uint32_t)memo->epoch)return 1;',
     '           SPTM_ROOT_MEMO_RECORD(e->record)==record)return 1;', ON),
    ('U7 a store lands in the frame\'s first window', _M,
     '    unsigned h=sptm_root_memo_window(table);\n#else\n    unsigned h=sptm_root_memo_index(table&~UINT64_C(0x3fff));'
     '\n#endif\n    struct sptm_root_memo_entry *slot=0,*free=0;',
     '    unsigned h=sptm_root_memo_index(table&~UINT64_C(0x3fff));\n#else\n    unsigned h=sptm_root_memo_index(table&~UINT64_C(0x3fff));'
     '\n#endif\n    struct sptm_root_memo_entry *slot=0,*free=0;', ON),
    ('U7 a frame\'s four tables share one window', _M,
     '+SPTM_ROOT_MEMO_WAYS*(unsigned)((table>>12)&3);', ';', ON),
    ('U3 a count off by one', _M, '(leaves+1)<<48;}', '(leaves+2)<<48;}', ON),
    ('U2 a verdict recorded without validate_table', _R, _MISS,
     _MISS.replace('    if(!shared_validates(m,g,table,base,flags))return 0;\n', ''), ON),
    ('U2 a verdict stored under another base', _R, _MISS,
     _MISS.replace('store(memo,table,base,', 'store(memo,table,base+0x1000,'), ON),
    ('U2 a verdict stored under other flags', _R, _MISS,
     _MISS.replace('store(memo,table,base,flags,', 'store(memo,table,base,flags^0x20,'), ON),
    ('U2 a 4K table proved in 16K geometry', _R,
     '    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g) || g.shift!=12)return 0;\n'
     '    struct sptm_nest_fast_stats *st=m->nest_fast;',
     '    if(!m || !m->map || !sptm_mac_user_geometry(0,flags,&g) || g.shift!=12)return 0;\n'
     '    struct sptm_nest_fast_stats *st=m->nest_fast;', ON),
    ('U5 a sampled hit is answered with its count', _R, _PROOF,
     _PROOF.replace(' && st->sampled==sampled', ''), S0),
    ('U5 a failed rescan is not fatal', _R, '{if(st)st->mismatches++;return -1;}',
     '{if(st)st->mismatches++;return 1;}', S0),
    ('U5 the sampled rescan never runs', _R, '        if(!(n&SPTM_NEST_FAST_SAMPLE)) {', '        if(0) {', S0),
    ('U5 a recount mismatch is not fatal', _R,
     '{if(m->nest_fast)m->nest_fast->mismatches++;return -1;}',
     '{if(m->nest_fast)m->nest_fast->mismatches++;return 1;}', S0),
    ('U8 a hit is not counted', _R, '        memo->stats.hits++;\n', '', ON),
    ('U8 a recorded miss is not counted', _R, _MISS, _MISS.replace('    memo->stats.misses++;\n', ''), ON),
    ('U8 a counted hit is not counted', _R, '        if(*known!=UINT64_MAX)st->unnest_counted++;\n', '', ON),
    ('U3 the count recorded before the scan', _U, 'u[12],(unsigned)get(u+10,2),nonzero)<0)',
     'u[12],(unsigned)get(u+10,2),0)<0)', ON),
    ('U3 the count recorded for another verdict', _U,
     'sptm_root_shared_count_4k(m,tte&g.pa_mask,plan.base+i*span,', 'sptm_root_shared_count_4k(m,tte&g.pa_mask,plan.base,',
     ON),
    # Batch 7 (FAILURES-AND-DESIGN.md C1, C5, C8): the capacity and the frame filter.
    ('C8 the define keeps v6\'s capacity', _M, '#define SPTM_ROOT_MEMO_ENTRIES 32768u', '#define SPTM_ROOT_MEMO_ENTRIES 2048u', ON),
    ('C1 a store does not release the overwritten entry\'s count', _M,
     '    else (*sptm_root_memo_frame_live(memo,slot->table))--;   /* evicted, stale or the same key */\n', '', ON),
    ('C1 a store does not count its entry', _M, '    if(table)(*sptm_root_memo_frame_live(memo,table))++;\n', '', ON),
    ('C1 a drop does not release its count', _M,
     '    (*sptm_root_memo_frame_live(memo,e->table))--;\n#endif\n    *e=(struct sptm_root_memo_entry){0};', '#endif\n    *e=(struct sptm_root_memo_entry){0};', ON),
    ('C1 the epoch-wrap flush keeps the counts', _M,
     '        for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++)memo->frame_live[i]=0;\n', '', ON),
    ('C1 counts kept at the table\'s window', _M,
     '    return &memo->frame_live[sptm_root_memo_index(table&~UINT64_C(0x3fff))];',
     '    return &memo->frame_live[sptm_root_memo_window(table)&(SPTM_ROOT_MEMO_ENTRIES-1)];', ON),
    ('C1 the frame drop filters on another index', _M,
     '    if(!memo->frame_live[h])return;            /* no entry of this frame */\n    for(unsigned w=0;w<SPTM_ROOT_MEMO_FRAME_WAYS',
     '    if(!memo->frame_live[(h+1)&(SPTM_ROOT_MEMO_ENTRIES-1)])return;\n    for(unsigned w=0;w<SPTM_ROOT_MEMO_FRAME_WAYS', ON),
    ('C1 the record check filters on another index', _M,
     '    if(!memo->frame_live[h])return;            /* no entry of this frame */\n#endif\n    uint64_t now=',
     '    if(!memo->frame_live[(h+1)&(SPTM_ROOT_MEMO_ENTRIES-1)])return;\n#endif\n    uint64_t now=', ON),
    ('C1 the small path skips every record check', _M,
     '            if(memo->frame_live[sptm_root_memo_index(frame_low+(r<<14))])   /* else nothing to check */\n',
     '            if(0)\n', ON),
    ('C1 the small path\'s record skip on another index', _M,
     '            if(memo->frame_live[sptm_root_memo_index(frame_low+(r<<14))])   /* else nothing to check */\n',
     '            if(memo->frame_live[sptm_root_memo_index(frame_low+((r+1)<<14))])\n', ON),
]


class Mutants(unittest.TestCase):
    def test_each_mutant_fails(self):
        self.assertGreaterEqual(len(MUTANTS), 12)
        with tempfile.TemporaryDirectory() as d:
            r = run(compile_c(d, 'test-unnest-4k-fast.c', MEMO))
            self.assertEqual(r.returncode, 0)
            ref = steps(r)
            for label, path, old, new, defines in MUTANTS:
                with self.subTest(label):
                    text = read_source(ROOT / path)
                    self.assertEqual(text.count(old), 1, label)
                    sub = Path(d) / hashlib.sha1(label.encode()).hexdigest()[:10]
                    sub.mkdir()
                    exe = compile_c(sub, 'test-unnest-4k-fast.c', defines, {path: text.replace(old, new)},
                                    werror=False)
                    r = run(exe)
                    self.assertTrue(r.returncode != 0 or steps(r) != ref, f'{label} survived')
                    print(f'mutant {label}: caught', file=sys.stderr)


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
        if not ARGS.base:
            self.skipTest('no --base tree')
        base = Path(ARGS.base)
        installed = [f for f in flags_of(ARGS.qualification or V5) if f.startswith('-D')]
        for flags in ([], NEST, installed):
            for rel in CHANGED_C:
                self.assertEqual(self.preprocess(ROOT, rel, flags), self.preprocess(base, rel, flags),
                                 f'{rel} {len(flags)} flags')

    def test_header_default_off(self):
        text = (ROOT / 'compat/nest-fast.h').read_text()
        self.assertIn('#ifndef SNAP_UNNEST_4K_FAST\n#define SNAP_UNNEST_4K_FAST 0\n#endif', text)
        self.assertIn('#if SNAP_UNNEST_4K_FAST && !SNAP_NEST_FAST', text)
        memo = (ROOT / 'compat/sptm-root-memo.h').read_text()      # C4: v6's capacity without the define
        self.assertIn('#else\n#define SPTM_ROOT_MEMO_ENTRIES 2048u\n#endif', memo)


def build_all(out, qual, trees):
    """{name: sha256/bytes/headroom} for each (name, tree, flags), or refused."""
    sys.dont_write_bytecode = True
    res, cwd = {}, os.getcwd()
    for name, tree, flags in trees:
        target = Path(out) / name
        os.chdir(tree)
        try:
            runner = runpy.run_path(str(Path(tree) / 'probes/run.py'))
            runner['FLAGS'][:] = flags
            try:
                blob = runner['build']('xnuboot', target)
            except Exception as e:  # noqa: BLE001
                res[name] = dict(refused=True, error=str(e)[-300:])
                continue
            res[name] = dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                             headroom=runner['OUT_AT'] - runner['CODE_AT'] - len(blob))
        finally:
            os.chdir(cwd)
    return res


class Build(unittest.TestCase):
    def test_hashes(self):
        if not ARGS.build or not ARGS.base:
            self.skipTest('--build and --base not given')
        qual = ARGS.qualification or V5
        flags = list(flags_of(qual))
        out = Path(ARGS.out or tempfile.mkdtemp())
        sys.path.insert(0, str(ROOT / 'tools'))
        import cycle_lib.speed_test as speed
        sets, _ = speed.flag_sets(ROOT)
        base = Path(ARGS.base)
        plans = [('base-v5', base, flags), ('new-v5', ROOT, flags),
                 ('base-control', base, sets['control']), ('new-control', ROOT, sets['control']),
                 ('base-fast', base, sets['fast']), ('new-fast', ROOT, sets['fast']),
                 ('new-v5-explicit-0', ROOT, flags + ['-DSNAP_UNNEST_4K_FAST=0']),
                 ('new-v5-unnest4k', ROOT, flags + [DEFINE]),
                 ('new-v5-unnest4k-no-nest-fast', ROOT, [f for f in flags if f != '-DSNAP_NEST_FAST=1'] + [DEFINE])]
        res = build_all(out, qual, plans)
        print(json.dumps(res, indent=1), file=sys.stderr)
        for name in ('v5', 'control', 'fast'):
            self.assertEqual(res['base-' + name]['sha256'], res['new-' + name]['sha256'], name)
        self.assertEqual(res['new-v5-explicit-0']['sha256'], res['new-v5']['sha256'])
        self.assertNotEqual(res['new-v5-unnest4k']['sha256'], res['new-v5']['sha256'])
        self.assertGreater(res['new-v5-unnest4k']['headroom'], 32 * 1024)     # v5 itself leaves 54,057 bytes
        self.assertLess(res['new-v5-unnest4k']['bytes'] - res['new-v5']['bytes'], 4096)
        self.assertTrue(res['new-v5-unnest4k-no-nest-fast'].get('refused'))
        with open(qual) as f:
            monitor = json.load(f).get('monitor_sha256')
        if monitor:
            print(f'qualification monitor_sha256 {monitor}: base-v5 {"matches" if monitor == res["base-v5"]["sha256"] else "differs"}',
                  file=sys.stderr)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--qualification')
    ap.add_argument('--base', help='the tree without the patch')
    ARGS, rest = ap.parse_known_args()
    for name in ('base', 'out', 'qualification'):     # the Build test changes directory
        if getattr(ARGS, name):
            setattr(ARGS, name, str(Path(getattr(ARGS, name)).resolve()))
    unittest.main(argv=[sys.argv[0], *rest])
