#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_DART_MEMO (docs/DART-MEMO-20261019.md): DART table verdicts in compat/sptm-dart.c,
the monitor's write witness, the report record and cycle.py's option.

    python3 tools/test-dart-memo.py
    python3 tools/test-dart-memo.py --build [--out DIR] [--expect SHA256]

Offline, no hardware. It builds and runs tools/test-dart-memo.c:
- under ASan/UBSan, a differential of every DART service with the memo against
  sptm-dart.c as it was, on the Adreno DART and on a three-level one, with published
  corruption, reference-count changes, repairs and configuration changes, plus the
  bound for an unpublished corruption;
- without sanitizers, the speed check (at least 4x).
It requires weakened header and source copies to fail.

Source checks:
- without the define, sptm-dart.c and sptm.h preprocess to their original text;
- the monitor's sptm_publish drops entries before it publishes;
- the token path's memory carries the memo and the converted calls' does not.

The report record sits below the FASTIPI1 slot and decodes; damaged ones are refused.
cycle.py installed-fresh admits --dart-memo only with --root-cache-wide.

--build builds xnuboot with installed-fresh-20261019-v90's options with the define
absent, =0 and =1: absent == =0, =1 differs, all within the code budget; --expect
requires the default build to have that SHA-256.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HEADER = (ROOT / 'compat/sptm-dart-memo.h').read_text()
DART_C = (ROOT / 'compat/sptm-dart.c').read_text()
SPTM_H = (ROOT / 'compat/sptm.h').read_text()
DEFINE = '-DSNAP_DART_MEMO=1'
EXPORTS = ('sptm_dart_map_table', 'sptm_dart_map', 'sptm_dart_unmap', 'sptm_dart_enable', 'sptm_dart_leaf',
           'sptm_dart_dma_translate', 'sptm_sep_rom_buffer', 'sptm_sep_service_buffers',
           'sptm_sep_endpoint_buffers', 'sptm_sep_all_buffers')
RENAME = [f'-D{name}=ref_{name}' for name in EXPORTS]
LINKED = ['compat/sptm-refs.c', 'compat/sptm.c', 'compat/dart.c', 'compat/sep-pnon.c', 'compat/sep-xars.c',
          'compat/aes.c']
SANITIZE = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all']


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


def without_define(text, define='SNAP_DART_MEMO'):
    """text with every #if <define> block resolved to its #else branch (or removed)."""
    text = text.replace(f'#ifndef {define}\n#define {define} 0\n#endif\n', '')
    pattern = re.compile(rf'#if {define}\n(.*?)(?:#else\n(.*?))?#endif\n', re.S)
    while True:
        new = pattern.sub(lambda m: m.group(2) or '', text)
        if new == text:
            return text
        text = new


def compile_test(directory, header=None, source=None, speed=False):
    """Build the C test in directory; header/source replace the memo header and sptm-dart.c."""
    d = Path(directory)
    opts = ['-O2'] if speed else SANITIZE
    common = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *opts]
    reference = d / 'ref-sptm-dart.c'
    reference.write_text(without_define(DART_C))
    subprocess.run([*common, f'-I{ROOT / "compat"}', f'-I{ROOT / "shadow"}', '-c', str(reference),
                    '-o', str(d / 'ref.o'), *RENAME], cwd=ROOT, check=True)
    # sptm-dart.c includes the memo header with quotes, which searches its own
    # directory first: a weakened header needs its own copy of the source beside it.
    include = []
    dart = 'compat/sptm-dart.c'
    if header is not None or source is not None:
        (d / 'inc').mkdir(exist_ok=True)
        (d / 'inc/sptm-dart-memo.h').write_text(header if header is not None else HEADER)
        (d / 'inc/sptm-dart.c').write_text(source if source is not None else DART_C)
        include = [f'-I{d / "inc"}']
        dart = str(d / 'inc/sptm-dart.c')
    exe = d / 'test-dart-memo'
    r = subprocess.run([*common, DEFINE, *include, '-Icompat', '-Ishadow', 'tools/test-dart-memo.c', dart,
                        *LINKED, str(d / 'ref.o'), '-o', str(exe)], cwd=ROOT, capture_output=True, text=True)
    return exe if r.returncode == 0 else None


def run_test(exe, *argv):
    r = subprocess.run([str(exe), *argv], capture_output=True, text=True, timeout=900)
    return r.returncode, r.stdout + r.stderr


HEADER_MUTANTS = {
    'a published table store keeps the entry': ('{sptm_dart_memo_drop(memo,f);if (f==last) break;}',
                                                '{if (f==last) break;}'),
    'a published frame-record store keeps the entry': (
        'if (i1-i0<64) {for (uint64_t i=i0;i<=i1;i++) sptm_dart_memo_drop(memo,c->frame_low+(i<<14));}',
        'if (i1-i0<64) {(void)i0;}'),
    'refs not compared': (' && e->refs==refs)', ' && (e->refs==refs || refs!=e->refs))'),
    'a configuration change unnoticed': ('if (x[i]!=y[i]) return 0;', '(void)x;(void)y;'),
    'a re-record resets the hit count': ('(uint8_t)level,1,hits,0};', '(uint8_t)level,1,0*hits,0};'),
    'never sampled': ('#define SPTM_DART_MEMO_SAMPLE 64u', '#define SPTM_DART_MEMO_SAMPLE 0xffffffffu'),
}
SOURCE_MUTANTS = {
    'a failing scan recorded': ('    if (!r) sptm_dart_memo_record(memo,t->pa,(unsigned)id,(unsigned)sid,level,t->refs,0);',
                                '    sptm_dart_memo_record(memo,t->pa,(unsigned)id,(unsigned)sid,level,t->refs,0);'),
    'a sampled refusal ignored': ('        if (r) {memo->stats.mismatches++;sptm_dart_memo_forget(memo,t->pa);}\n        return r;',
                                  '        if (r) {memo->stats.mismatches++;sptm_dart_memo_forget(memo,t->pa);}\n'
                                  '        return SPTM_OK;'),
    'MAP re-records a stale reference count': ('table_committed(m,&table,id,sid,table.refs+added,memo_hits);',
                                               'table_committed(m,&table,id,sid,table.refs,memo_hits);'),
}


class Decision(unittest.TestCase):
    def test_differential(self):
        with tempfile.TemporaryDirectory() as d:
            exe = compile_test(d)
            self.assertIsNotNone(exe, 'the C test does not build')
            rc, out = run_test(exe)
            self.assertEqual(rc, 0, out)
            self.assertIn('PASS', out)

    def test_speed(self):
        with tempfile.TemporaryDirectory() as d:
            exe = compile_test(d, speed=True)
            self.assertIsNotNone(exe)
            rc, out = run_test(exe, '--speed')
            self.assertEqual(rc, 0, out)
            print(out.strip(), file=sys.stderr)

    def test_weakened_code_fails(self):
        survivors = []
        for kind, mutants, text in (('header', HEADER_MUTANTS, HEADER), ('source', SOURCE_MUTANTS, DART_C)):
            for name, (old, new) in mutants.items():
                self.assertEqual(text.count(old), 1, f'{name}: {old!r} is not unique')
                with tempfile.TemporaryDirectory() as d:
                    mutated = text.replace(old, new, 1)
                    exe = compile_test(d, header=mutated if kind == 'header' else None,
                                       source=mutated if kind == 'source' else None)
                    if exe is None:
                        survivors.append(f'{name} (does not build)')
                        continue
                    rc, _ = run_test(exe, '20000')
                    if rc == 0:
                        # A mutant that only loses hits must at least lose the speed.
                        exe = compile_test(d, header=mutated if kind == 'header' else None,
                                           source=mutated if kind == 'source' else None, speed=True)
                        rc, _ = run_test(exe, '--speed') if exe else (1, '')
                        if rc == 0:
                            survivors.append(name)
        self.assertEqual(survivors, [], 'weakened code passed')


def body(text, signature):
    start = text.index(signature)
    depth, i = 0, text.index('{', start)
    for j in range(i, len(text)):
        depth += {'{': 1, '}': -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise ValueError(signature)


class Source(unittest.TestCase):
    def preprocess(self, path, *flags, first=None):
        include = [f'-I{first}'] if first else []
        out = subprocess.run(['cc', '-E', '-P', *include, f'-I{ROOT / "compat"}', f'-I{ROOT / "shadow"}', *flags,
                              str(path)], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return re.sub(r'\s+', ' ', out)

    def test_defaults_and_original_text(self):
        self.assertIn('#ifndef SNAP_DART_MEMO\n#define SNAP_DART_MEMO 0\n#endif', DART_C)
        self.assertIn('#ifndef SNAP_DART_MEMO\n#define SNAP_DART_MEMO 0\n#endif', SOURCE)
        with tempfile.TemporaryDirectory() as d:
            orig = Path(d) / 'orig'
            orig.mkdir()
            for name, text in (('sptm-dart.c', DART_C), ('sptm.h', SPTM_H)):
                (orig / name).write_text(without_define(text))
                self.assertNotIn('SNAP_DART_MEMO', (orig / name).read_text(), name)
            # sptm.h through a translation unit that includes it, kept apart from
            # both copies so its quoted include follows the -I order.
            unit = Path(d) / 'unit'
            unit.mkdir()
            (unit / 'unit.c').write_text('#include "sptm.h"\n')
            for flags in ((), ('-DSNAP_DART_MEMO=0',)):
                self.assertEqual(self.preprocess(ROOT / 'compat/sptm-dart.c', *flags),
                                 self.preprocess(orig / 'sptm-dart.c', *flags, first=orig))
                self.assertEqual(self.preprocess(unit / 'unit.c', *flags),
                                 self.preprocess(unit / 'unit.c', *flags, first=orig))
            self.assertNotEqual(self.preprocess(ROOT / 'compat/sptm-dart.c', DEFINE),
                                self.preprocess(orig / 'sptm-dart.c', DEFINE, first=orig))
            self.assertNotEqual(self.preprocess(unit / 'unit.c', DEFINE),
                                self.preprocess(unit / 'unit.c', DEFINE, first=orig))
        self.assertTrue(SPTM_H.rstrip().count('struct sptm_dart_memo *dart_memo;') == 1)
        # The field is the struct's last, so callers built without it see the same prefix.
        tail = SPTM_H[SPTM_H.index('struct sptm_dart_memo *dart_memo;'):]
        self.assertTrue(tail.split('};', 1)[0].strip().endswith('#endif'))

    def test_four_sites_and_commits(self):
        code = DART_C
        self.assertEqual(code.count('table_verdict(m,&'), 4)
        for fn in ('sptm_dart_map_table(', 'enum sptm_result sptm_dart_map(', 'enum sptm_result sptm_dart_unmap(',
                   'enum sptm_result sptm_dart_dma_translate('):
            self.assertIn('table_verdict(m,&', body(code, fn), fn)
        self.assertIn('table_committed(m,&table,id,sid,table.refs+added,memo_hits);',
                      body(code, 'enum sptm_result sptm_dart_map('))
        self.assertIn('table_committed(m,&table,id,sid,table.refs-removed,memo_hits);',
                      body(code, 'enum sptm_result sptm_dart_unmap('))
        self.assertNotIn('table_committed', body(code, 'sptm_dart_map_table('))
        # Commits re-record only after every store and reference publication.
        unmap = body(code, 'enum sptm_result sptm_dart_unmap(')
        self.assertLess(unmap.index('publish_refs(m,&table,table.refs-removed)'), unmap.index('table_committed('))

    def test_monitor_hooks(self):
        publish = body(SOURCE, 'static void sptm_publish(void *ctx, uint64_t pa, uint64_t size)')
        self.assertIn('sptm_dart_memo_publish(&((struct context *)ctx)->root_ext->dart_memo, pa, size);', publish)
        self.assertLess(publish.index('sptm_dart_memo_publish('), publish.index('publish(pa, pa + size);'))
        memory = body(SOURCE, 'static struct sptm_memory sptm_context_memory(struct context *c)')
        self.assertIn('#if SNAP_DART_MEMO\n        ,.dart_memo=&c->root_ext->dart_memo\n#endif', memory)
        self.assertIn('m.dart_memo=0;   /* the memo is the token path\'s */', SOURCE)
        self.assertIn('_Static_assert(SNAP_ROOT_CACHE_WIDE, "the DART memo lives in the wide cache\'s arena pages");',
                      SOURCE)
        # Only two publish callbacks exist: the witness and the converted calls'
        # (which never store to DART tables and never run beside a token holder).
        # SNAP_TOKEN_TRIM (compat/token-trim.h) or SNAP_DART_CONVERTED (compat/dart-converted.h,
        # batch 9: the same block on its own) adds a third, the converted Adreno
        # DART calls': it must feed this memo's witness before the converted publish.
        self.assertEqual(set(re.findall(r'\.publish\s*=\s*(\w+)', SOURCE)) - {'fine_dart_publish'},
                         {'sptm_publish', 'fine_sptm_publish'})
        if 'fine_dart_publish' in SOURCE:
            dart = body(SOURCE, 'static void fine_dart_publish(void *ctx,uint64_t pa,uint64_t size)')
            self.assertLess(dart.index('sptm_dart_memo_publish('), dart.index('fine_sptm_publish(ctx,pa,size);'))
            # Defined, and handed to an engine, only inside the define's part-B block.
            start = SOURCE.index('#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED\n'
                                 '/* ---- The Adreno DART\'s MAP and UNMAP as converted calls')
            end = SOURCE.index('\n}\n#endif\n', SOURCE.index('static int fine_dart_call(', start))
            self.assertTrue(all(start < m.start() < end for m in re.finditer(r'fine_dart_publish', SOURCE)))


def record(stats=(10, 8, 2, 3, 1, 0, 1, 0), live=2, damage=None):
    data = bytearray(struct.pack('<11Q', 0x314d454d54524144, 64 << 32, *stats, live))
    if damage:
        damage(data)
    return bytes(data)


class Report(unittest.TestCase):
    def test_place_and_decode(self):
        pc = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        offset, size = pc['dart_memo_spec']()
        thermal = runpy.run_path(str(ROOT / 'tools/a16_thermal.py'))['REPORT_OFFSET']
        self.assertEqual(size, 88)
        self.assertEqual(offset + size + 8 * 98, thermal)
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / 'probe.c'
            probe.write_text('#include <stdio.h>\n#include "a16-thermal.h"\n#include "sptm-dart-memo.h"\n'
                             'int main(void){printf("%lu\\n",(unsigned long)(16+8*(A16_THERMAL_REPORT_OFFSET/8-98-3-'
                             'sizeof(struct sptm_dart_memo_stats)/8)));return 0;}\n')
            subprocess.run(['cc', '-std=gnu11', f'-I{ROOT / "compat"}', f'-I{ROOT / "shadow"}', str(probe),
                            '-o', f'{d}/probe'], check=True)
            self.assertEqual(int(subprocess.run([f'{d}/probe'], capture_output=True, text=True).stdout), offset)
        self.assertIn('#define OUT_DART_MEMO (OUT_THERMAL - 98 - 3 - DART_MEMO_STATS_WORDS)', SOURCE)
        out = pc['decode_dart_memo'](record())
        self.assertEqual((out['lookups'], out['hits'], out['live']), (10, 8, 2))
        for name, damage in (('magic', lambda b: b.__setitem__(0, 0)),
                             ('size word', lambda b: struct.pack_into('<Q', b, 8, 72 << 32))):
            with self.subTest(damage=name), self.assertRaises(ValueError):
                pc['decode_dart_memo'](record(damage=damage))
        with self.assertRaises(ValueError):   # hits + misses != lookups
            pc['decode_dart_memo'](record(stats=(10, 8, 3, 3, 1, 0, 1, 0)))


def installed(**extra):
    sys.path.insert(0, str(ROOT / 'tools'))
    import cycle_lib.installed_fresh as fresh  # noqa: E402
    import cycle_lib.speed_test as st  # noqa: E402
    sets, _ = st.flag_sets(ROOT)
    v90 = runpy.run_path(str(ROOT / 'tools/test-aes-bitslice.py'))['V90']
    args = argparse.Namespace(variant='fast', **{n: True for n in v90})
    for k, v in extra.items():
        setattr(args, k, v)
    return fresh, sets, args


def flags_v90(on=False):
    fresh, sets, args = installed(dart_memo=on)
    return fresh.variant_flags(sets, args)


class Cycle(unittest.TestCase):
    def test_option_and_prerequisite(self):
        off, on = flags_v90(), flags_v90(True)
        self.assertNotIn(DEFINE, off)
        self.assertEqual([f for f in on if f != DEFINE], off)
        fresh, sets, _ = installed()
        from cycle_lib.common import Refused  # noqa: E402
        with self.assertRaises(Refused) as caught:
            fresh.variant_flags(sets, argparse.Namespace(variant='fast', dart_memo=True, root_cache_wide=False))
        self.assertIn('--dart-memo needs', str(caught.exception))
        self.assertIn("p.add_argument('--dart-memo', action='store_true',", (ROOT / 'tools/cycle.py').read_text())


@unittest.skipUnless(ARGS.build, 'needs --build')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        import run  # noqa: E402
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='dart-memo-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results, blobs = {}, {}
        base = flags_v90()
        try:
            for label, flags in (('default', base), ('off', base + ['-DSNAP_DART_MEMO=0']), ('on', flags_v90(True))):
                run.FLAGS[:] = flags
                blob = blobs[label] = run.build('xnuboot', out / label)
                results[label] = dict(bytes=len(blob), headroom=budget - len(blob),
                                      sha256=hashlib.sha256(blob).hexdigest())
                self.assertGreater(budget - len(blob), 0, label)
        finally:
            run.FLAGS[:] = saved
        self.assertEqual(blobs['default'], blobs['off'])
        self.assertNotEqual(blobs['default'], blobs['on'])
        if ARGS.expect:
            self.assertEqual(results['default']['sha256'], ARGS.expect, 'the default build changed')
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
