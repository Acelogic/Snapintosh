#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_AUDIT_SPARSE (compat/audit-sparse.h): four token-held sampled audits
(the TPRO class-proof hit verification, the kernel refresh's reuse-hit
verification, the exact kernel-variant swap verification and the PPERM-reuse
skip verification) run 1 in 1024 events instead of 1 in 64. Opt-in; a weaker
audit accepted for speed; every audited mechanism is unchanged.

    python3 tools/test-audit-sparse.py [--build --flags RUN/launch.json [--out DIR] [--expect SHA256]]

Offline. Checks that the define defaults to 0 and requires the audited paths,
that each of the four sites changes only its sampling constant, that
tools/kernel_ops_perf.py and tools/capture-service-profile.py accept exactly
hits // 1024 with the flag and exactly hits // 64 without, and that the host
class-proof suite still passes with the default. --build: absent == =0 (and
--expect pins it), =1 differs from the default in exactly the four sampling
instructions (disassembly diff: tst #0x3f -> tst #0x3ff) and keeps its size.

Failure inventory: compat/audit-sparse.h modes 1-7.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
FAST = (ROOT / 'shadow/sprr-class-fast.h').read_text()
HEADER = (ROOT / 'compat/audit-sparse.h').read_text()
OBJDUMP = '/opt/homebrew/opt/llvm/bin/llvm-objdump'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--flags', help='a run launch.json (its "flags") or a JSON list of compile flags')
    ap.add_argument('--out')
    ap.add_argument('--expect', help='SHA-256 the default monitor must have')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    if args.build and not args.flags:
        ap.error('--build needs --flags')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, flags=None, out=None, expect=None), [])


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


class Source(unittest.TestCase):
    def test_header(self):
        self.assertIn('#ifndef SNAP_AUDIT_SPARSE\n#define SNAP_AUDIT_SPARSE 0\n#endif\n#if SNAP_AUDIT_SPARSE\n'
                      '#define AUDIT_SAMPLE_MASK 1023\n#else\n#define AUDIT_SAMPLE_MASK 63\n#endif\n', HEADER)

    def test_sites(self):
        self.assertIn('    if(hit)p->hits++;\n    if(hit && (p->hits&AUDIT_SAMPLE_MASK)) {*out=p->result;return 1;}\n'
                      '    if(hit)p->verified++;', between(FAST, 'static inline int sprr_class_proof_check_fast(', '\n}\n'))
        self.assertIn('#include "../compat/audit-sparse.h"', FAST)
        refresh = between(SOURCE, 'static int kernel_refresh_impl(struct context *c)', '\n}\n')
        self.assertIn('        if(!(reuse->hits&AUDIT_SAMPLE_MASK)) {\n#if SNAP_UPDATE_DISJOINT_FAST\n'
                      '            if(!sprr_views_verify_all(&c->kernel_views,&s,pp)) {', refresh)
        swap = between(SOURCE, 'static int kernel_variant_swap(struct context *c,', '\n}\n')
        self.assertIn('    if(!(a->exact++&AUDIT_SAMPLE_MASK)) {\n'
                      '        if(!sprr_views_verify_cpu(&c->kernel_views,s,cpu,pperm)) {', swap)
        change = between(SOURCE, 'static int kernel_change_pperm_impl(struct context *c,uint64_t pperm,int invalidate)',
                         '\n}\n')
        self.assertIn('        if(!(++kr->skipped&AUDIT_SAMPLE_MASK)) {\n'
                      '            if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pperm)) {', change)
        # Exactly these four uses; the leaf-memo rescan and every other sample keep their rate.
        self.assertEqual(SOURCE.count('&AUDIT_SAMPLE_MASK)'), 3)
        self.assertEqual(FAST.count('&AUDIT_SAMPLE_MASK)'), 1)
        self.assertIn('_Static_assert(!SNAP_AUDIT_SPARSE ||\n    (SNAP_KERNEL_PPERM_FAST && SNAP_KERNEL_VIEW_REUSE && '
                      'SNAP_KERNEL_PPERM_REUSE &&\n     SNAP_KERNEL_PPERM_VARIANTS),', SOURCE)
        leaf = (ROOT / 'shadow/sprr-class-leaf-memo.h').read_text()
        self.assertNotIn('AUDIT_SAMPLE_MASK', leaf)


def kernel_ops():
    spec = importlib.util.spec_from_file_location('kernel_ops_perf', ROOT / 'tools/kernel_ops_perf.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Decoders(unittest.TestCase):
    def test_kernel_ops_rate(self):
        ops = kernel_ops()
        fields = ops.RECORDS['kernel_pperm_reuse'][1]
        for skipped in (64, 1023, 1024, 434574):
            for flag, rate in (('SNAP_AUDIT_SPARSE', 1024), (None, 64)):
                flags = {'SNAP_KERNEL_PPERM_REUSE'} | ({flag} if flag else set())
                for verified, ok in ((skipped // rate, True), (skipped // (1088 - rate), skipped // 64 == skipped // 1024)):
                    row = dict.fromkeys(fields, 0)
                    row.update(calls=skipped, current=skipped, skipped=skipped, repinned=skipped, verified=verified)
                    raw = {'kernel_pperm_reuse': struct.pack(f'<{len(fields)}Q', *(row[f] for f in fields))}
                    audit = {'root_switch': {}}
                    if ok:
                        ops.decode(raw, flags, audit)
                    else:
                        with self.assertRaises(ValueError):
                            ops.decode(raw, flags, audit)

    def test_capture_rates(self):
        profile = runpy.run_path(str(ROOT / 'tools/capture-service-profile.py'), run_name='audit_sparse_test')
        root = 0x9000000000
        first = root - 16 * 4096
        kernel = {'canonical_root': hex(root), 'private_source_tables': 117, 'pperm': ['0x0'] * 6}
        for hits in (64, 1024, 392691):
            for rate in (64, 1024):
                for verified in (hits // 64, hits // 1024):
                    good = verified == hits // rate
                    reuse = struct.pack('<16Q', hits + 1, hits, verified, 0, 0, 1, 0, 0, root, 117, *[0] * 6)
                    class_raw = bytearray(struct.pack('<20Q', hits + 3, hits, verified, 0, 0, 3, 3, 3, 0, 3, 0,
                                                      root, 1 << 9, first, first + 61440 * 4096, 2,
                                                      100, 1000, 0b1000, 1))
                    bits = 1 << ((root - first) // 4096)
                    class_raw += bits.to_bytes(61440 // 8, 'little')
                    calls = [lambda: profile['decode_kernel_reuse'](reuse, kernel, rate),
                             lambda: profile['decode_kernel_class_proof'](bytes(class_raw), kernel, hits + 3, first,
                                                                          first + 61440 * 4096, root + 4096, rate)]
                    for call in calls:
                        if good or hits // 64 == hits // 1024:
                            call()
                        else:
                            with self.assertRaises(ValueError):
                                call()


class HostSuite(unittest.TestCase):
    """The suites whose anchors this change touched, with the default mask. Not
    Source.test_monitor_source of test-kernel-pperm-fast.py: it fails on the
    unmodified tree too (user_root_install reached from fine_user_root_install)."""
    def run_suite(self, script, *names):
        result = subprocess.run([sys.executable, script, *names], cwd=ROOT, capture_output=True, text=True,
                                timeout=1800, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])

    def test_class_proof_suite_default(self):
        self.run_suite('tools/test-kernel-pperm-fast.py', 'Replay', 'Source.test_weakened_sources_are_caught',
                       'Source.test_header_failure_modes_come_first', 'Source.test_no_context_field')

    def test_update_disjoint_suite(self):
        self.run_suite('tools/test-update-disjoint-fast.py', 'Decision', 'Source')


def disassembly(elf):
    text = subprocess.run([OBJDUMP, '-d', '--no-show-raw-insn', str(elf)], capture_output=True, text=True,
                          check=True).stdout
    return [line for line in text.splitlines()[3:]]


@unittest.skipUnless(ARGS.build, 'pass --build --flags RUN/launch.json to compile the monitor')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        import monitor_build_offline as mb  # noqa: E402
        data = json.loads(Path(ARGS.flags).read_text())
        flags = list(data['flags'] if isinstance(data, dict) else data)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='audit-sparse-build-'))
        results = {label: mb.build(ROOT, out / label, flags + extra)
                   for label, extra in (('default', []), ('off', ['-DSNAP_AUDIT_SPARSE=0']),
                                        ('on', ['-DSNAP_AUDIT_SPARSE=1']))}
        self.assertEqual(results['default'], results['off'])
        self.assertNotEqual(results['default']['sha256'], results['on']['sha256'])
        self.assertEqual(results['default']['bytes'], results['on']['bytes'])
        if ARGS.expect:
            self.assertEqual(results['default']['sha256'], ARGS.expect)
        a, b = disassembly(out / 'default/xnuboot.elf'), disassembly(out / 'on/xnuboot.elf')
        self.assertEqual(len(a), len(b))
        changed = [(x.strip(), y.strip()) for x, y in zip(a, b) if x != y]
        self.assertEqual(len(changed), 4, changed)
        for x, y in changed:
            self.assertTrue(x.endswith('#0x3f') and y.endswith('#0x3ff') and x[:-5] == y[:-6], (x, y))
            self.assertIn('tst\t', x)
        results['changed_instructions'] = [list(c) for c in changed]
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
