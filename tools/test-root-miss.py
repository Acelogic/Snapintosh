#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_ROOT_MISS_FAST: bind compat/root-miss.h's victim choice and miss-path
verdicts to SWITCH_ROOT, the linked build, the monitor and its defaults.

    python3 tools/test-root-miss.py
    python3 tools/test-root-miss.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]

Offline, no hardware and no proxy. It builds and runs (sanitized)
tools/test-root-miss-cache.c (the victim oracle and a 160-root churn against
an independent model of the cache: round robin without stamps, least recently
installed with them; also built without the define) and
tools/test-root-miss-build.c (memo-assisted misses and linked builds through
the real SWITCH_ROOT/NEST/MAP_PAGE fixtures), then requires a weakened copy of
each guard (compat/root-miss.h failure modes E1-E5, M1, M4, M5) to FAIL them.
The existing root, memo, word-walk and linked-nest suites must print the same
results with the define as without it. It checks that probes/xnuboot.c
defaults the define to 0, asserts its prerequisites, passes stamps, linked
builds and the read-only group probe only under it, and that struct context
keeps its size.

--build also compiles xnuboot with cycle.py's installed-fresh/speed-test flag
sets (control and fast) with the define absent, =0 and =1, and fast with
SNAP_WFI_RESUME=1 absent/=1 for the define: -Werror, the code budget, absent ==
=0, =1 differs. --expect NAME=SHA256 (control, fast, fast-wfi) requires the
default build to equal a pre-change monitor byte for byte. It reports the
define-on SHA-256 of the full fast stack (census, WFI resume, EL0 sysreg, service
subclass, DART wiredcnt, panic serve).

Failure inventory: an active root evicted; a valid shadow evicted before an
invalidated slot; no victim though one exists; eviction counters changed; a
retained verdict standing in for a table whose leaves are copied (private,
commpage, 4K-format, or a shared child whose group the build creates); memo
calls counting misses; the sampled reference walk using the memo; a default
build that changed; a layout change visible to host readers.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib
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
ROOT_C = read_source(ROOT / 'compat/sptm-root.c')
HEADER = (ROOT / 'compat/root-miss.h').read_text()
DEFINE = '-DSNAP_ROOT_MISS_FAST=1'
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']
FULL_STACK = ['-DSNAP_WFI_RESUME=1', '-DSNAP_FAST_EL0_SYSREG=1', '-DSNAP_SERVICE_SUBCLASS=1',
              '-DSNAP_DART_WIREDCNT=1', '-DSNAP_PANIC_SERVE=1']


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


def compile_c(directory, test, defines, overrides=None, werror=True, extra=()):
    """Build tools/<test> with CORE; overrides maps a compat file name to a
    mutated copy placed (with root-miss.h) in a private directory first."""
    exe = Path(directory) / Path(test).stem
    include, sources = [], [*CORE, *extra]
    if overrides:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        for name in ('root-miss.h', 'sptm-root.c'):
            (mut / name).write_text(overrides.get(name, read_source(ROOT / 'compat' / name)))
        include = [f'-I{mut}']
        sources = [str(mut / 'sptm-root.c') if s == 'compat/sptm-root.c' else s for s in sources]
    flags = ['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', *(['-Werror'] if werror else []),
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *defines, *include,
             '-Icompat', '-Ishadow', f'tools/{test}', *sources, '-o', str(exe)]
    subprocess.run(flags, cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


def run(exe):
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=900)


TESTS = {
    'cache': ('test-root-miss-cache.c', ()),
    'build': ('test-root-miss-build.c', ('shadow/native-shared.c',)),
}

# Each weakening must make the named C test fail: (file, old, new, test).
MUTANTS = {
    'E1 an active root is evicted': ('root-miss.h',
        '    unsigned i=sptm_root_reclaim_pick(s,stamp,SPTM_ROOT_MASK_NONE);\n',
        '    unsigned i=SPTM_ROOT_CACHE;\n    for(unsigned k=0;k<SPTM_ROOT_CACHE;k++)\n'
        '        if(s->cache[k].root && (i==SPTM_ROOT_CACHE || stamp[k]<stamp[i]))i=k;\n', 'cache'),
    'E3 a valid shadow before an invalid slot': ('root-miss.h',
        '    unsigned i=sptm_root_reclaim_pick(s,stamp,SPTM_ROOT_MASK_NONE);\n',
        '    unsigned i=SPTM_ROOT_CACHE;\n    for(unsigned k=0;k<SPTM_ROOT_CACHE;k++) {\n'
        '        int a=0;for(unsigned c=0;c<SPTM_ROOT_CPUS;c++)a|=s->active[c]==s->cache[k].root;\n'
        '        if(s->cache[k].root && !a && (i==SPTM_ROOT_CACHE || stamp[k]<stamp[i]))i=k;\n    }\n',
        'cache'),
    'E4 an eligible slot is skipped': ('root-miss.h',
        'sptm_root_reclaim_pick(s,stamp,SPTM_ROOT_MASK_NONE)', 'sptm_root_reclaim_pick(s,stamp,1)', 'cache'),
    'E5 eviction not counted': ('sptm-root.c',
        'b->stamp,root)))return SPTM_MEMORY_UNAVAILABLE;\n        entry->valid=0;entry->root=0;'
        's->invalidations++;\n        if(b->evictions)(*b->evictions)++;\n',
        'b->stamp,root)))return SPTM_MEMORY_UNAVAILABLE;\n        entry->valid=0;entry->root=0;'
        's->invalidations++;\n', 'cache'),
    'E5 eviction not an invalidation': ('sptm-root.c',
        'b->stamp,root)))return SPTM_MEMORY_UNAVAILABLE;\n        entry->valid=0;entry->root=0;'
        's->invalidations++;\n',
        'b->stamp,root)))return SPTM_MEMORY_UNAVAILABLE;\n        entry->valid=0;entry->root=0;\n',
        'cache'),
    'M1 a miss answers any level-3 table': ('root-miss.h',
        '    return !shared_only || type==SPTM_MAC_PAGE_TABLE_SHARED;\n',
        '    return ((void)shared_only,(void)type,1);\n', 'build'),
    'M1 a created group is not scanned': ('root-miss.h',
        '    return grouped!=0;\n', '    return ((void)grouped,1);\n', 'build'),
    'M1 the linked build answers copied tables': ('sptm-root.c',
        'struct validation v={m,&g,flags,0,0,root,0,memo,1};',
        'struct validation v={m,&g,flags,0,0,root,0,memo,0};', 'build'),
    'M1 a 4K-format miss uses verdicts': ('sptm-root.c',
        'int shared_only=!hit && b->linked_builds && !format;',
        'int shared_only=!hit && b->linked_builds;', 'build'),
    'M4 misses counted as memo calls': ('sptm-root.c',
        'if(walk && memo && hit)memo->stats.calls++;', 'if(walk && memo)memo->stats.calls++;', 'build'),
    'M5 the reference walk uses the memo': ('sptm-root.c',
        'struct validation bytes={m,&g,flags,0,0,root,0,0,0};',
        'struct validation bytes={m,&g,flags,0,0,root,0,memo,shared_only};', 'build'),
}


class Decision(unittest.TestCase):
    def test_cache_and_build(self):
        with tempfile.TemporaryDirectory() as d:
            for name, (test, extra) in TESTS.items():
                for define in ([DEFINE], ['-DSNAP_ROOT_MISS_FAST=0']) if name == 'cache' else ([DEFINE],):
                    result = run(compile_c(d, test, define, extra=extra))
                    self.assertEqual(result.returncode, 0, f'{name} {define}: ' +
                                     result.stdout[-3000:] + result.stderr[-3000:])
                    self.assertTrue(result.stdout.rstrip().splitlines()[-1].startswith('PASS'), name)
                    for line in result.stdout.strip().splitlines():
                        if not line.startswith('PASS: 7489') and not line.startswith('PASS: 43497'):
                            print(f'{name} {define[0]}: {line}', file=sys.stderr)

    def test_weakened_guards_fail(self):
        for label, (name, old, new, test) in MUTANTS.items():
            text = HEADER if name == 'root-miss.h' else ROOT_C
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                self.assertEqual(text.count(old), 1, label)
                source, extra = TESTS[test]
                result = run(compile_c(d, source, [DEFINE], {name: text.replace(old, new)}, extra=extra))
                self.assertNotEqual(result.returncode, 0, f'{label} survived')

    def test_existing_suites_unchanged_by_the_define(self):
        suites = {'test-sptm-root.c': (), 'test-root-validate-memo.c': (),
                  'test-native-shared-nest.c': ('shadow/native-shared.c',)}
        with tempfile.TemporaryDirectory() as d:
            for suite, extra in suites.items():
                outs = []
                for define in ([], [DEFINE]):
                    sub = Path(d) / ('on' if define else 'off')
                    sub.mkdir(exist_ok=True)
                    result = run(compile_c(sub, suite, define, werror=False, extra=extra))
                    self.assertEqual(result.returncode, 0, suite + result.stdout[-2000:] + result.stderr[-2000:])
                    outs.append(result.stdout)
                self.assertEqual(outs[0], outs[1], suite)
            words = []
            for define in ([], [DEFINE]):
                sub = Path(d) / ('w-on' if define else 'w-off')
                sub.mkdir(exist_ok=True)
                result = run(compile_c(sub, 'test-root-validate-words.c',
                                       ['-DSPTM_ROOT_VALIDATE_SAMPLE=0', *define], werror=False))
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
                words.append(result.stdout)
            self.assertEqual(words[0], words[1])


class Source(unittest.TestCase):
    def test_default_off_and_prerequisites(self):
        self.assertIn('#ifndef SNAP_ROOT_MISS_FAST\n#define SNAP_ROOT_MISS_FAST 0\n#endif\n'
                      '_Static_assert(!SNAP_ROOT_MISS_FAST || (SNAP_ROOT_VALIDATE_MEMO && '
                      'SNAP_ROOT_VALIDATE_WORDS &&\n               SNAP_NATIVE_SHARED),', SOURCE)
        header = (ROOT / 'compat/sptm-root.h').read_text()
        self.assertIn('#ifndef SNAP_ROOT_MISS_FAST\n#define SNAP_ROOT_MISS_FAST 0\n#endif', header)
        self.assertIn('#if SNAP_ROOT_MISS_FAST\n#include "root-miss.h"\n#endif', ROOT_C)

    def test_monitor_wiring_only_under_the_define(self):
        backend = between(SOURCE, 'case SPTM_FN_SWITCH_ROOT: {', 'enum sptm_result r=')
        self.assertIn('#if SNAP_ROOT_MISS_FAST\n            ,.stamp=USTAMPS(c),.linked_builds=1\n#endif', backend)
        build = between(SOURCE, 'static int user_root_build(void *ctx', '\n}\n')
        on = between(build, '#if SNAP_ROOT_MISS_FAST', '#else')
        self.assertIn('sptm_root_build_linked_memo(memory,&s,root,format,flags,leaves,&links,\n'
                      '                                                         &c->root_memo,nl_grouped)', on)
        off = between(build, '#else', '#endif', build.index('#if SNAP_ROOT_MISS_FAST'))
        self.assertEqual([l.strip() for l in off.splitlines()[1:] if l.strip()],
                         ['sptm_root_build_linked(memory,&s,root,format,flags,leaves,&links));'])
        # As before: the 4K-format copy and the !SNAP_NATIVE_SHARED copy, nothing added.
        self.assertEqual(build.count('sptm_root_build_shadow('), 2)
        grouped = between(SOURCE, 'static int nl_grouped(void *ctx,uint64_t child,uint64_t va)\n{', '\n}\n')
        self.assertEqual([l.strip() for l in grouped.splitlines()[2:]],
                         ['struct native_links *l=ctx;(void)va;',
                          'return native_shared_find(&UNS(l->c),child)>=0;'])
        # The stamps are the ones every installation writes and reclaim reads.
        # USTAMPS(c): root_stamp, or the wide cache's 192 (compat/root-wide.h).
        self.assertEqual(SOURCE.count('USTAMPS(c)[entry-c->user_roots.cache]=++c->arena_reclaim.clock;'), 1)
        self.assertEqual(SOURCE.count('.stamp=USTAMPS(c)'), 1)

    def test_compat_changes_are_define_guarded(self):
        # Every SNAP_ROOT_MISS_FAST block in compat/sptm-root.c has an #else
        # that restores the original line, or adds code only when on.
        blocks = re.findall(r'#if SNAP_ROOT_MISS_FAST\n(.*?)#endif', ROOT_C, re.S)
        self.assertGreaterEqual(len(blocks), 8)
        off = subprocess.run(['cc', '-E', '-P', '-DSNAP_ROOT_MISS_FAST=0', '-Icompat', '-Ishadow',
                              'compat/sptm-root.c'], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertNotIn('root_miss_', off)
        self.assertNotIn('shared_only', off)
        self.assertNotIn('build_linked_memo', off)


class Layout(unittest.TestCase):
    def test_context_unchanged(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        perf = importlib.import_module('perf_counters')
        sets, _ = flag_sets()
        for name, flags in sets.items():
            defines = [f for f in flags if f.startswith('-D')]
            off = perf._records(ROOT / 'probes/xnuboot.c', defines)
            on = perf._records(ROOT / 'probes/xnuboot.c', defines + [DEFINE])
            self.assertEqual(perf._size(off['context']), perf._size(on['context']), name)
            self.assertEqual(perf._size(off['sptm_root_state']), perf._size(on['sptm_root_state']), name)
            self.assertEqual(perf._offset(on['context'], 'root_stamp'), perf._offset(off['context'], 'root_stamp'))


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
        sets['fast-stack'] = sets['fast'] + FULL_STACK
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='root-miss-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_ROOT_MISS_FAST=0']), ('on', [DEFINE])):
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
