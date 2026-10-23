#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_ROOT_CACHE_WIDE: 192 cached user roots (compat/root-wide.h W1-W10).

    python3 tools/test-root-wide.py
    python3 tools/test-root-wide.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]

Offline, no hardware and no proxy. It builds and runs (sanitized)
tools/test-root-wide.c (192-slot masks, reclaim exclusion above slot 63,
native-shared link bits of high slots) and tools/test-root-miss-cache.c built
wide (480 roots, a hot set of 100: the real SWITCH_ROOT against an
independent model after every step, round robin and least recently
installed, beside the same trace on 64 slots) and tools/test-root-miss-build.c
wide; then requires weakened copies of the mask and link-bit helpers to FAIL.
It checks the monitor wiring (state in arena pages taken first at setup and
excluded from the coverage sentinel, the stop-time mirror, no define-free
per-slot field left in use), that every define-free struct context offset and
the arena base are unchanged, and that the twins match the default records.

--build compiles xnuboot with the control/fast/fast-wfi flag sets with the
define absent, =0 and =1 (-Werror, code budget, absent == =0, =1 differs),
the full fast stack with it alone and with SNAP_ROOT_MISS_FAST and
SNAP_UPDATE_DISJOINT_FAST; --expect pins a default build.
"""
from pathlib import Path
import argparse
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
ROOT_H = (ROOT / 'compat/sptm-root.h').read_text()
NS_H = (ROOT / 'shadow/native-shared.h').read_text()
WIDE = '-DSNAP_ROOT_CACHE_WIDE=1'
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c',
        'shadow/native-shared.c']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def compile_c(directory, test, defines, overrides=None, name=None):
    """overrides: {header file name: text} placed in a directory searched
    before compat/ and shadow/ (and the .c files that include them by quote
    are compiled from copies beside them)."""
    exe = Path(directory) / (name or Path(test).stem)
    include, sources = [], list(CORE)
    if overrides:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        for hdr in ('sptm-root.h', 'native-shared.h'):
            (mut / hdr).write_text(overrides.get(hdr, (ROOT / ('compat' if hdr == 'sptm-root.h' else 'shadow') / hdr).read_text()))
        for src in ('compat/sptm-root.c', 'shadow/native-shared.c'):
            (mut / Path(src).name).write_text(read_source(ROOT / src))
        include = [f'-I{mut}']
        sources = [str(mut / Path(s).name) if s in ('compat/sptm-root.c', 'shadow/native-shared.c') else s
                   for s in sources]
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *defines, *include,
                    '-Icompat', '-Ishadow', f'tools/{test}', *sources, '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


def run(exe):
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=1800)


CHURN = ['-DROOTS=480u', '-DHOT=100u']
MUTANTS = {
    'W1 mask test reads word 0': ('sptm-root.h',
        '#define SPTM_ROOT_MASK_HAS(m,i) ((((m).w[(i)>>6])>>((i)&63u))&1u)',
        '#define SPTM_ROOT_MASK_HAS(m,i) ((((m).w[0])>>((i)&63u))&1u)'),
    'W1 mask set writes word 0': ('sptm-root.h',
        '#define SPTM_ROOT_MASK_SET(m,i) ((m).w[(i)>>6]|=UINT64_C(1)<<((i)&63u))',
        '#define SPTM_ROOT_MASK_SET(m,i) ((m).w[0]|=UINT64_C(1)<<((i)&63u))'),
    'W1 mask compare sees word 0': ('sptm-root.h',
        '{uint64_t d=0;for(unsigned i=0;i<SPTM_ROOT_MASK_WORDS;i++)d|=a.w[i]^b.w[i];return d!=0;}',
        '{return (a.w[0]^b.w[0])!=0;}'),
    'W1 mask emptiness sees word 0': ('sptm-root.h',
        '{uint64_t d=0;for(unsigned i=0;i<SPTM_ROOT_MASK_WORDS;i++)d|=m.w[i];return d!=0;}',
        '{return m.w[0]!=0;}'),
    'W1 one-slot mask below 64 only': ('sptm-root.h',
        'if(i<SPTM_ROOT_CACHE)SPTM_ROOT_MASK_SET(m,i);', 'if(i<64u)SPTM_ROOT_MASK_SET(m,i);'),
    'W9 link test reads word 0': ('native-shared.h',
        '#define NATIVE_SHARED_SLOT_HAS(m,s) ((((m).w[(s)>>6])>>((s)&63u))&1u)',
        '#define NATIVE_SHARED_SLOT_HAS(m,s) ((((m).w[0])>>((s)&63u))&1u)'),
    'W9 link set writes word 0': ('native-shared.h',
        '#define NATIVE_SHARED_SLOT_SET(m,s) ((m).w[(s)>>6]|=UINT64_C(1)<<((s)&63u))',
        '#define NATIVE_SHARED_SLOT_SET(m,s) ((m).w[0]|=UINT64_C(1)<<((s)&63u))'),
    'W9 link clear clears word 0': ('native-shared.h',
        '#define NATIVE_SHARED_SLOT_CLEAR(m,s) ((m).w[(s)>>6]&=~(UINT64_C(1)<<((s)&63u)))',
        '#define NATIVE_SHARED_SLOT_CLEAR(m,s) ((m).w[0]&=~(UINT64_C(1)<<((s)&63u)))'),
    'W9 a high-linked group looks free': ('native-shared.h',
        '{uint64_t d=0;for(unsigned i=0;i<NATIVE_SHARED_SLOT_WORDS;i++)d|=m.w[i];return d!=0;}',
        '{return m.w[0]!=0;}'),
}


class Decision(unittest.TestCase):
    def test_masks_reclaim_links(self):
        with tempfile.TemporaryDirectory() as d:
            result = run(compile_c(d, 'test-root-wide.c', [WIDE]))
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-3000:])
        for line in result.stdout.strip().splitlines():
            print(line, file=sys.stderr)

    def test_churn_192_against_model(self):
        rates = {}
        with tempfile.TemporaryDirectory() as d:
            for label, defines in (('64', ['-DSNAP_ROOT_MISS_FAST=1']), ('192', [WIDE]),
                                   ('192-lru', [WIDE, '-DSNAP_ROOT_MISS_FAST=1'])):
                result = run(compile_c(d, 'test-root-miss-cache.c', defines + CHURN, name=f'churn-{label}'))
                self.assertEqual(result.returncode, 0, label + result.stdout[-2000:] + result.stderr[-2000:])
                rates[label] = [l for l in result.stdout.splitlines() if 'hits' in l]
        for label, lines in rates.items():
            for line in lines:
                print(f'{label} slots: {line}', file=sys.stderr)

    def test_miss_build_wide(self):
        with tempfile.TemporaryDirectory() as d:
            result = run(compile_c(d, 'test-root-miss-build.c', [WIDE, '-DSNAP_ROOT_MISS_FAST=1']))
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])

    def test_weakened_helpers_fail(self):
        for label, (name, old, new) in MUTANTS.items():
            text = ROOT_H if name == 'sptm-root.h' else NS_H
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                self.assertEqual(text.count(old), 1, label)
                failed = False
                for test, defines in (('test-root-wide.c', [WIDE]),
                                      ('test-root-miss-cache.c', [WIDE, '-DSNAP_ROOT_MISS_FAST=1', *CHURN])):
                    try:
                        exe = compile_c(d, test, defines, {name: text.replace(old, new)}, name=Path(test).stem)
                    except subprocess.CalledProcessError:
                        failed = True
                        break
                    if run(exe).returncode:
                        failed = True
                        break
                self.assertTrue(failed, f'{label} survived')


class Source(unittest.TestCase):
    def test_default_off_and_prerequisites(self):
        self.assertIn('#ifndef SNAP_ROOT_CACHE_WIDE\n#define SNAP_ROOT_CACHE_WIDE 0\n#endif\n'
                      '_Static_assert(!SNAP_ROOT_CACHE_WIDE || SNAP_NATIVE_SHARED,', SOURCE)
        self.assertIn('#if SNAP_ROOT_CACHE_WIDE\n#define SPTM_ROOT_CACHE 192u\n#else\n#define SPTM_ROOT_CACHE 64u\n#endif',
                      ROOT_H)
        header = (ROOT / 'compat/root-wide.h').read_text()
        for assertion in ('SPTM_ROOT_CACHE%64u==0 && SPTM_ROOT_CACHE<=NATIVE_SHARED_SLOTS',
                          '0x100u+4u*SPTM_ROOT_CACHE<=0x10000u', '((SPTM_ROOT_TCR_16K&SPTM_ROOT_TCR_4K)>>36)&1'):
            self.assertIn(assertion, header)
        self.assertIn('_Static_assert(NATIVE_SHARED_OWNER>SPTM_ROOT_CACHE && NATIVE_SHARED_OWNER<TABLE_POOL_FREE,',
                      SOURCE)
        self.assertIn('static uint64_t native_asid(unsigned slot,unsigned w,unsigned k)\n'
                      '{return 0x100UL+4UL*slot+2UL*w+k;}', SOURCE)

    def test_state_in_arena_pages_first(self):
        setup = between(SOURCE, 'int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,\n'
                        '                  const struct secondary_config *host_cpus)\n{', '\n}\n')
        on = between(setup, '#if SNAP_ROOT_CACHE_WIDE', '#endif')
        self.assertIn('c->root_ext = (struct root_ext *)((work + sizeof(*c) + 0xfff) & ~0xfffUL);', on)
        self.assertIn('if (size < sizeof(*c) + 4096 + ROOT_EXT_PAGES * 4096) return 1;', on)
        # Allocated before the first use of the live state.
        self.assertLess(setup.index('c->root_ext = '), setup.index('c->user_roots.sprr[n]'))
        self.assertIn('    c->work_base = c->next_table;\n#if SNAP_ROOT_CACHE_WIDE\n'
                      '    c->next_table += ROOT_EXT_PAGES * 4096;\n#endif\n', setup)
        exclude = between(SOURCE, 'static int txn_publish_exclude(void *ctx,uint64_t page)\n{', '\n}\n')
        self.assertIn('if(page>=(uint64_t)c->root_ext && page-(uint64_t)c->root_ext<ROOT_EXT_PAGES*4096)return 1;',
                      exclude)

    def test_mirror_at_the_stop(self):
        report = between(SOURCE, 'uint64_t xnuboot_report(uint64_t *out)\n{', '\n}\n')
        self.assertLess(report.index('Every executor has quiesced'), report.index('root_ext_mirror(c);'))
        self.assertEqual(SOURCE.count('root_ext_mirror(c);'), 1)
        mirror = between(SOURCE, 'static void root_ext_mirror(struct context *c)\n{', '\n}\n')
        for field in ('h->switches=s->switches', 'h->builds=s->builds', 'h->invalidations=s->invalidations',
                      'h->cache[i]=s->cache[i]', 'h->active[n]=s->active[n]', 'h->sprr[n]=s->sprr[n]',
                      'nh->live=ns->live', 'b->slots=a->slots.w[0]', 'nh->index[i]=ns->index[i]',
                      'c->user_views[i]=UVIEWS(c)[i]', 'c->root_stamp[i]=USTAMPS(c)[i]'):
            self.assertIn(field, mirror)

    def test_no_define_free_slot_field_in_use(self):
        body = SOURCE[SOURCE.index('#define ROOT_PLAN_MASK(c) ((c)->shared_plan_mask)\n#endif\n'):]
        mirror = between(body, 'static void root_ext_mirror(struct context *c)\n{', '\n}\n')
        body = body.replace(mirror, '')
        for field in ('->user_views', '->user_table_owner', '->user_view_proofs', '->user_view_memo',
                      '->root_stamp', 'inactive_mirror.budget', '->native_shared', '->user_roots_host',
                      '->native_shared_host', 'm->budget['):
            self.assertNotIn(field, body, field)
        for mask in ('uint64_t mask;', 'uint64_t exclude', 'mask&(1UL<<i)', 'mask&(UINT64_C(1)<<i)'):
            self.assertNotIn(mask, body, mask)


def records(defines):
    sys.path.insert(0, str(ROOT / 'tools'))
    perf = importlib.import_module('perf_counters')
    return perf, perf._records(ROOT / 'probes/xnuboot.c', [d for d in defines if d.startswith('-D')])


def fields(block):
    return [(int(o), t, n) for o, t, n in re.findall(r'^\s*(\d+) \|   (\S.*) (\w+)$', block, re.M)]


def flag_sets():
    spec = importlib.util.spec_from_file_location('root_miss', ROOT / 'tools/test-root-miss.py')
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [saved[0]]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    sets, _ = module.flag_sets()
    sets['fast-stack'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1', '-DSNAP_FAST_EL0_SYSREG=1',
                                         '-DSNAP_SERVICE_SUBCLASS=1', '-DSNAP_DART_WIREDCNT=1', '-DSNAP_PANIC_SERVE=1']
    return sets


class Layout(unittest.TestCase):
    def test_define_free_offsets_and_arena_base(self):
        renamed = {'user_roots_host': 'user_roots', 'native_shared_host': 'native_shared'}
        for name, flags in flag_sets().items():
            perf, off = records(flags)
            _, on = records(flags + [WIDE])
            a = {n: (o, t) for o, t, n in fields(off['context'])}
            b = {renamed.get(n, n): (o, t) for o, t, n in fields(on['context'])}
            extra = set(b) - set(a)
            self.assertEqual(extra, {'root_ext'}, name)
            for field, (offset, _) in a.items():
                self.assertEqual(b[field][0], offset, f'{name}: {field}')
            size_off, size_on = perf._size(off['context']), perf._size(on['context'])
            self.assertEqual((size_off + 4095) // 4096, (size_on + 4095) // 4096, name)
            for twin, real in (('sptm_root_state_compat', 'sptm_root_state'),
                               ('native_shared_compat', 'native_shared'),
                               ('native_shared_group_compat', 'native_shared_group')):
                self.assertEqual([(o, n) for o, _, n in fields(on[twin])],
                                 [(o, n) for o, _, n in fields(off[real])], f'{name}: {twin}')
                self.assertEqual(perf._size(on[twin]), perf._size(off[real]), twin)
            ext = perf._size(on['root_ext'])
            print(f'{name}: context {size_off} -> {size_on} bytes (same {(size_on + 4095) // 4096} pages); '
                  f'root_ext {ext} bytes = {(ext + 4095) // 4096} arena pages', file=sys.stderr)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (several minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        sets = flag_sets()
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='root-wide-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                variants = [('default', []), ('off', ['-DSNAP_ROOT_CACHE_WIDE=0']), ('on', [WIDE])]
                if name == 'fast-stack':
                    variants += [('on-miss', [WIDE, '-DSNAP_ROOT_MISS_FAST=1']),
                                 ('on-miss-update', [WIDE, '-DSNAP_ROOT_MISS_FAST=1',
                                                     '-DSNAP_UPDATE_DISJOINT_FAST=1'])]
                for label, extra in variants:
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
        finally:
            monitor_run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
