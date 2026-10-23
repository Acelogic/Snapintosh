#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_UNMAP_MIXED: an endpoint8 UNMAP_DISJOINT list naming user roots and the
kernel root for one frame (installed-fresh-20261017-v39's stop: BAD_CONFIG on a
user-first two-record list) runs as one transaction (compat/sptm-user.h M1-M7).

    python3 tools/test-unmap-mixed.py [--build [--out DIR] [--expect NAME=SHA256]]

Offline. Unit: tools/test-unmap-mixed.c under ASan/UBSan reproduces the old
dispatch's refusal of both orders and checks the mixed engine; the existing
user and kernel UNMAP_DISJOINT suites pass with the define. Mutants: each
guard removed must fail the C test. Source: the monitor's dispatch scans every
record, sends a mixed list to the mixed engine and publishes it as a kernel
one; the define-off text is unchanged. --build: absent == =0, =1 differs, the
code budget holds, --expect pins the default builds.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
ENGINE = read_source(ROOT / 'compat/sptm-user.c')
KERNEL = (ROOT / 'compat/sptm-unmap.c').read_text()
IMPL = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'compat').glob('sptm*.c'))
IMPL += ['shadow/sprr-view.c', 'shadow/mmu.c', 'shadow/shadow.c']
# The existing user suites also link TXM sharing and native-shared groups.
SUITE_IMPL = IMPL + sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'compat').glob('txm*.c'))
SUITE_IMPL += ['shadow/native-shared.c']
CC = ['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
      '-ffunction-sections', '-Wl,-dead_strip', '-Icompat', '-Ishadow']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])
WORK = Path(tempfile.mkdtemp(prefix='unmap-mixed-'))


def compile_run(test, flags, args=(), impl=IMPL):
    """Build tools/<test>.c with the given defines under ASan/UBSan; return (returncode, output)."""
    binary = WORK / f'{test}{"-mixed" if flags else ""}'
    build = subprocess.run([*CC, *flags, f'tools/{test}.c', *impl, '-o', str(binary)],
                           cwd=ROOT, capture_output=True, text=True)
    if build.returncode:
        return build.returncode, build.stderr[-2000:]
    run = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=600)
    return run.returncode, run.stdout + run.stderr


class Unit(unittest.TestCase):
    def test_mixed_engine(self):
        rc, out = compile_run('test-unmap-mixed', ['-DSNAP_UNMAP_MIXED=1'])
        self.assertEqual(rc, 0, out)
        self.assertIn('before fix: user-first -> status 1', out)     # v39: SPTM_BAD_CONFIG
        self.assertIn('before fix: kernel-first -> status 2', out)
        self.assertIn('mixed engine: user-first -> status 0', out)
        self.assertIn('mixed engine: kernel-first -> status 0', out)
        print(out.strip().splitlines()[-1], file=sys.stderr)

    def test_existing_suites_with_define(self):
        for test, args in (('test-unmap-disjoint', ()), ('test-unmap-disjoint-shared', ()),
                           ('replay-kernel-unmap', ('0x0060000000000603',))):
            for flags in ([], ['-DSNAP_UNMAP_MIXED=1']):
                rc, out = compile_run(test, flags, args=args, impl=SUITE_IMPL)
                self.assertEqual(rc, 0, f'{test} {flags}: {out}')


class Audit(unittest.TestCase):
    """M8: the witnesses a mixed call leaves pass the end-of-boot auditor."""
    def test_end_of_boot_audit_admits_both_witnesses(self):
        import runpy
        import struct
        dump = WORK / 'mixed.dump'
        rc, out = compile_run('test-unmap-mixed', ['-DSNAP_UNMAP_MIXED=1'], args=(str(dump),))
        self.assertEqual(rc, 0, out)
        raw = dump.read_bytes()
        base, size = 0x90000000, 0x100000
        ram, user, kernel = raw[:size], raw[size:size + 256], raw[size + 256:size + 512]
        self.assertEqual(len(raw), size + 512)

        def read(pa, n):
            self.assertTrue(base <= pa and pa + n <= base + size, hex(pa))
            return ram[pa - base:pa - base + n]
        auditor = runpy.run_path(str(ROOT / 'tools/audit-unmap-disjoint.py'))
        empty = dict.fromkeys(auditor['FIELDS'], 0)
        for blob, kernel_root, root in ((user, None, base + 0x24000), (kernel, base, base)):
            pair = [dict(zip(auditor['FIELDS'], struct.unpack_from('<16Q', blob, h))) for h in (0, 128)]
            self.assertEqual(pair[0]['root'], root)
            result = auditor['audit'](read, states=[pair] + [[empty, empty]] * 5, ram_low=base,
                                      ram_high=base + size, frame_map=base + 0x4000, frame_low=base,
                                      kernel_root=kernel_root)
            self.assertEqual((result['calls'], result['changed']), (1, 1))
            self.assertTrue(all(r['descriptor_policy_verified'] for r in result['rows']))
        # The same records in one witness, as a single-domain engine would never write: refused.
        pair = [dict(zip(auditor['FIELDS'], struct.unpack_from('<16Q', kernel, h))) for h in (0, 128)]
        with self.assertRaises(ValueError):
            auditor['audit'](read, states=[pair] + [[empty, empty]] * 5, ram_low=base,
                             ram_high=base + size, frame_map=base + 0x4000, frame_low=base)


# Each guard of the mixed engine, removed: the C test must fail.
MUTANTS = [
    ('compat/sptm-user.c', 'kernel_record[i]=kernel && plan[i].root==kernel->root;', 'kernel_record[i]=0;'),
    ('compat/sptm-user.c', 'r=sptm_kernel_unmap_check(kernel->shadow,plan[i].va,target,plan[i].old);if(r)return r;', ''),
    ('compat/sptm-user.c', 'if(!sptm_kernel_unmap_commit(kernel->shadow,plan[i].va))return SPTM_SHADOW_FAILED;', ''),
    ('compat/sptm-user.c', '            r=sptm_refs_leaf(m,plan[i].pa&PA_MASK,plan[i].va,plan[i].old,plan[i].next);if(r)return r;\n'
                           '            plan[i].remove=1;changed++;last_changed=i;continue;',
                           '            plan[i].remove=1;changed++;last_changed=i;continue;'),
    ('compat/sptm-user.c', 'if(plan[j].remove)plan[i].old=plan[j].next|0x80;', ''),
    ('compat/sptm-user.c', '        if(kernel_record[i] && (plan[i].va<0xffff800000000000UL || (plan[i].va&0x3fff)))\n'
                           '            return SPTM_BAD_ADDRESS;\n', ''),
    ('compat/sptm-user.c', 'if(kernel && ((list&7) || scratch==(list&~UINT64_C(0x3fff))))return SPTM_BAD_ADDRESS;', ''),
    ('compat/sptm-user.c', 'for(uint64_t i=0;i<count;i++)if(kernel_record[i]==domain) {',
                           'for(uint64_t i=0;i<count;i++)if(!domain) {'),
    ('compat/sptm-user.c', 'struct sptm_shared_update_state *w=domain ? (kernel ? kernel->state:0) : state;',
                           'struct sptm_shared_update_state *w=domain ? 0 : state;'),
    ('compat/sptm-user.c', '            plan[i].remove=1;changed++;last_changed=i;continue;',
                           '            put(plan[i].slot,plan[i].next,8);plan[i].remove=1;changed++;last_changed=i;continue;'),
    ('compat/sptm-user.c', '            put(plan[i].slot,plan[i].next,8);m->publish(m->ctx,plan[i].pa,8);\n            continue;',
                           '            continue;'),
]
# Not listed: dropping sptm_kernel_unmap_check's shadow_unmap dry run is an
# equivalent mutant (four valid level-3 leaves always unmap), as in the kernel
# engine it mirrors.


class Mutants(unittest.TestCase):
    def test_each_mutant_fails(self):
        for n, (rel, old, new) in enumerate(MUTANTS):
            text = read_source(ROOT / rel)
            self.assertEqual(text.count(old), 1, f'mutant {n} anchor: {old[:60]}')
            tree = WORK / f'mutant-{n}'
            subprocess.run(['mkdir', '-p', str(tree)], check=True)
            for d in ('compat', 'shadow', 'tools'):
                subprocess.run(['cp', '-R', str(ROOT / d), str(tree)], check=True)
            (tree / rel).write_text(text.replace(old, new))
            binary = tree / 'test'
            build = subprocess.run([*CC, '-DSNAP_UNMAP_MIXED=1', 'tools/test-unmap-mixed.c', *IMPL, '-o', str(binary)],
                                   cwd=tree, capture_output=True, text=True)
            if build.returncode == 0:
                build = subprocess.run([str(binary)], capture_output=True, text=True, timeout=600)
            self.assertNotEqual(build.returncode, 0, f'mutant {n} survived: {rel}: {old[:70]}')


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


class Source(unittest.TestCase):
    def test_dispatch(self):
        case = between(SOURCE, '    case SPTM_FN_UNMAP_DISJOINT: {', '    case SPTM_FN_UNMAP_REGION: {')
        self.assertIn('        int kernel=records && *(volatile uint64_t *)records==p->ttbr1_root;\n#if SNAP_UNMAP_MIXED\n', case)
        self.assertIn('        if(records)for(uint64_t n=1;n<count;n++)\n'
                      '            mixed|=(((volatile uint64_t *)records)[n*3]==p->ttbr1_root)!=kernel;\n'
                      '        if(mixed)kernel=1;\n#endif\n', case)
        mixed = between(case, '        if(mixed) {', '        } else\n#endif\n')
        for need in ('((p->tcr>>16)&63)==17', 'const struct sptm_unmap_kernel k={p->ttbr1_root,&shadow,\n                    &c->kernel_disjoint_unmaps[vcpu_of(c)->slot]};',
                     'kernel_class_proof_forget(c);', 'sptm_mac_unmap_mixed_disjoint(&memory,user_update_backend,c,&k,',
                     '&c->user_disjoint_unmaps[vcpu_of(c)->slot]', '.root=vcpu_of(c)->shadow_root'):
            self.assertIn(need, mixed)
        # The mixed list publishes as a kernel one (M6): one post-success block, gated by kernel.
        self.assertEqual(case.count('        if(kernel) {\n            if(!transaction_publish(c)) {'), 1)
        self.assertIn('shadow_tlb_sync(c);', case)

    def test_define_off_text(self):
        for name, text in (('xnuboot.c', SOURCE), ('sptm-user.c', ENGINE), ('sptm-unmap.c', KERNEL)):
            off = strip(text)
            self.assertNotIn('SNAP_UNMAP_MIXED', off, name)
        case = between(strip(SOURCE), '    case SPTM_FN_UNMAP_DISJOINT: {', '    case SPTM_FN_UNMAP_REGION: {')
        self.assertIn('        enum sptm_result result=SPTM_BAD_CONFIG;\n        if(kernel && ((p->tcr>>16)&63)==17) {', case)
        self.assertIn('enum sptm_result sptm_mac_unmap_user_disjoint(const struct sptm_memory *m,', strip(ENGINE))
        self.assertNotIn('sptm_mac_unmap_mixed_disjoint', strip(ENGINE))
        self.assertIn('#ifndef SNAP_UNMAP_MIXED\n#define SNAP_UNMAP_MIXED 0\n#endif\n',
                      (ROOT / 'compat/sptm-user.h').read_text())


def strip(text):
    """The text with every '#if SNAP_UNMAP_MIXED' branch removed and its '#else' kept."""
    out, stack = [], []
    for line in text.splitlines(keepends=True):
        s = line.strip()
        if s.startswith('#if'):
            stack.append(('mixed' if s == '#if SNAP_UNMAP_MIXED' else 'other', s == '#if SNAP_UNMAP_MIXED'))
            if stack[-1][0] == 'mixed':
                continue
        elif s.startswith('#else') and stack and stack[-1][0] == 'mixed':
            stack[-1] = ('mixed', False)
            continue
        elif s.startswith('#endif') and stack:
            kind, _ = stack.pop()
            if kind == 'mixed':
                continue
        if any(kind == 'mixed' and skip for kind, skip in stack):
            continue
        out.append(line)
    return ''.join(out)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        spec = importlib.util.spec_from_file_location('wfi_resume', ROOT / 'tools/test-wfi-resume.py')
        module = importlib.util.module_from_spec(spec)
        saved_argv = sys.argv
        sys.argv = [saved_argv[0]]
        try:
            spec.loader.exec_module(module)
        finally:
            sys.argv = saved_argv
        sets, _ = module.flag_sets()
        sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='unmap-mixed-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name in ('control', 'fast', 'fast-wfi'):
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_UNMAP_MIXED=0']),
                                     ('on', ['-DSNAP_UNMAP_MIXED=1'])):
                    monitor_run.FLAGS[:] = sets[name] + extra
                    blob = monitor_run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                self.assertGreater(budget, len(blobs['on']), name)
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name], name)
        finally:
            monitor_run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
