#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MAP_PAGE over XNU's compressed marker on a shared-region root (installed-fresh-20261018-v69).

    python3 tools/test-shared-compressed.py

Offline, no hardware and no proxy. v69 stopped with exit 7, "mapping references rejected ... table
is already present" (SPTM_TABLE_EXISTS) on MAP_PAGE root 0x902b4c000 VA 0x3555a4000 PTE
0x0060000a33e0c6c3. The root is a shared-region root (the work dump's shared_regions.slots[2]),
and for a shared root that answer has one source: sptm_mac_shared_map_pte refusing an invalid
nonzero old leaf. The only such leaf the model stores is XNU's compressed marker (UNMAP_DISJOINT's
template bits 63:61, sent by pmap_disconnect_options(PMAP_OPTIONS_COMPRESSOR) to every alias,
the shared region's included), and Apple's MAP_PAGE installs over it on root type 19 as on 18
(tools/replay-map-page-status.py, "compressed" rows: status 0). An intermittent stop: it needs
a compressed shared-region page faulted back in.

It checks:
  - tools/test-shared-compressed.c (sanitized): the compress/refault lifecycle on the shared root,
    both geometries, zero to two nested cached aliases, four marker forms, v69's VA and PTE
    attributes, and a bit-7 (FLUSH_PENDING) slot still refused with nothing changed;
  - weakened copies of compat/sptm-user.c (the v69 refusal, bit 7 admitted, the marker passed to
    the alias backends as a prior leaf, the marker kept in the new leaf) must each fail it;
  - the v69 record: its terminal event is MAP_PAGE's TABLE_EXISTS on a shared-region root of the
    work dump; the fixed selection installs its PTE over a marker (status 0) and the v69 copy
    answers TABLE_EXISTS (10), the recorded result;
  - the neighbouring suites (shared pages, compressed PTEs on ordinary roots, the SPTM oracle, the
    user map-replace rules) still pass.

Failure inventory: a compressed shared page that cannot be faulted back in; FLUSH_PENDING admitted;
a refault that leaves a cached alias without the leaf, double-counts a reference or the table, or
loses the prior-PTE output XNU reads.
"""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
USER_C = read_source(ROOT / 'compat/sptm-user.c')
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']
V69 = Path(os.environ.get('SHARED_COMPRESSED_V69_RUN', ROOT / 'build/installed-fresh-20261018-v69'))
FIX = ('''    if(old && (old&3)!=3) {
        if(old&0x80)return SPTM_TABLE_EXISTS;
        old=0;
    }''')
MUTANTS = {
    'the v69 refusal': (FIX, '    if(old && (old&3)!=3)return SPTM_TABLE_EXISTS;'),
    'FLUSH_PENDING admitted': ('        if(old&0x80)return SPTM_TABLE_EXISTS;\n', ''),
    'the marker kept in the new leaf': ('        if(old&0x80)return SPTM_TABLE_EXISTS;\n        old=0;\n',
                                        '        if(old&0x80)return SPTM_TABLE_EXISTS;\n'),
    'the marker passed as a prior leaf': ('        uint64_t prior=(old&3)==3 ? old:0;',
                                          '        uint64_t prior=old;'),
}


def build(directory, test, user_c=None, sanitize=True, werror=True):
    """tools/<test> against compat/, with compat/sptm-user.c replaced by user_c when given (a copy
    next to its own headers: a quoted include finds the includer's directory first)."""
    exe = Path(directory) / Path(test).stem
    sources = list(CORE)
    if user_c is not None:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        path = mut / 'sptm-user.c'
        path.write_text(user_c.replace('#include "', f'#include "{ROOT / "compat"}/'))
        sources = [str(path) if s == 'compat/sptm-user.c' else s for s in sources]
    cmd = ['cc', '-std=gnu11', '-O1', '-g', *(['-Wall', '-Wextra', '-Werror'] if werror else ['-w']),
           *(['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if sanitize else []),
           '-Icompat', '-Ishadow', '-Itools', f'tools/{test}', *sources, '-o', str(exe)]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
    return exe if r.returncode == 0 else None, r.stderr


def run(cmd):
    return subprocess.run([str(c) for c in cmd], cwd=ROOT, capture_output=True, text=True, timeout=900)


class Lifecycle(unittest.TestCase):
    def test_host(self):
        with tempfile.TemporaryDirectory() as d:
            exe, err = build(d, 'test-shared-compressed.c')
            self.assertIsNotNone(exe, err)
            r = run([exe])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertRegex(r.stdout, r'^PASS: \d+ checks \(120 compress/refault cycles')
            print(r.stdout.strip(), file=sys.stderr)

    def test_weakened_copies_fail(self):
        self.assertEqual(USER_C.count(FIX), 1)
        survived = []
        for label, (old, new) in MUTANTS.items():
            self.assertEqual(USER_C.count(old), 1, label)
            with tempfile.TemporaryDirectory() as d:
                exe, err = build(d, 'test-shared-compressed.c', USER_C.replace(old, new))
                self.assertIsNotNone(exe, f'{label}: {err[-400:]}')
                if run([exe]).returncode == 0:
                    survived.append(label)
        self.assertEqual(survived, [])


def last_event(run_dir):
    text = (run_dir / 'boot.log').read_text(errors='replace')
    m = re.search(r'last event \(outside the log, never dropped\):\n\s+(.+?)\s+pc (0x[0-9a-f]+)\s+'
                  r'(0x[0-9a-f]+) (0x[0-9a-f]+) (0x[0-9a-f]+)', text)
    return m[1], int(m[2], 16), int(m[3], 16), int(m[4], 16), int(m[5], 16)


def stop_root(run_dir):
    m = re.search(r'monitor stop PC 0x[0-9a-f]+.*\n\s+x0\s+(0x[0-9a-f]+)', (run_dir / 'boot.log').read_text())
    return int(m[1], 16)


def shared_roots(run_dir):
    spec = __import__('importlib.util').util.spec_from_file_location('hw_walk_dump', ROOT / 'tools/hw-walk-dump.py')
    dump = __import__('importlib.util').util.module_from_spec(spec)
    spec.loader.exec_module(dump)
    qual = json.loads((run_dir / 'qualification.json').read_text())
    lay = dump.layouts([f for f in qual['flags'] if f.startswith('-D')], ROOT)
    base = int(json.loads((run_dir / 'work-dump/work.json').read_text())['work'], 16)
    mem = dump.Memory((run_dir / 'work-dump/work.bin').read_bytes(), base)
    reg = base + lay['context']['fields']['shared_regions'][0]
    sf, size = lay['sptm_shared_slot']['fields'], lay['sptm_shared_slot']['size']
    count = int(re.search(r'\[(\d+)\]', lay['sptm_shared_registry']['fields']['slots'][1])[1])
    out = {}
    for i in range(count):
        at = reg + lay['sptm_shared_registry']['fields']['slots'][0] + i * size
        if mem.u(at + sf['state'][0], 1 if 'int8' in sf['state'][1] else 8):
            out[mem.u(at + sf['root'][0])] = dict(slot=i, start=mem.u(at + sf['start'][0]),
                                                  size=mem.u(at + sf['size'][0]))
    return out


@unittest.skipUnless((V69 / 'work-dump/work.bin').is_file(), 'no v69 record (set SHARED_COMPRESSED_V69_RUN)')
class V69Record(unittest.TestCase):
    def test_the_stop(self):
        kind, pc, result, va, pte = last_event(V69)
        self.assertEqual(kind, 'mapping references rejected')
        self.assertEqual((pc, result, va, pte), (0xfffffe000c22b404, 10, 0x3555a4000, 0x0060000a33e0c6c3))
        root = stop_root(V69)
        regions = shared_roots(V69)
        self.assertIn(root, regions, 'the MAP_PAGE root is a shared-region root of the dump')
        r = regions[root]
        self.assertTrue(r['start'] <= va < r['start'] + r['size'])
        with tempfile.TemporaryDirectory() as d:
            fixed, err = build(d, 'test-shared-compressed.c', sanitize=False)
            self.assertIsNotNone(fixed, err)
            old, new = MUTANTS['the v69 refusal']
            (Path(d) / 'v69').mkdir()
            v69, err = build(Path(d) / 'v69', 'test-shared-compressed.c', USER_C.replace(old, new), sanitize=False)
            self.assertIsNotNone(v69, err)
            for marker in (1 << 63, 1 << 62, (1 << 63) | (1 << 62)):
                got = run([fixed, '--pte', f'{marker:x}', f'{pte:x}']).stdout.split()
                self.assertEqual(got, ['0', '0', f'{pte:016x}'], marker)
                was = run([v69, '--pte', f'{marker:x}', f'{pte:x}']).stdout.split()
                self.assertEqual(int(was[0]), result, 'the v69 copy gives the recorded answer')
            self.assertEqual(run([fixed, '--pte', '80', f'{pte:x}']).stdout.split()[0], str(result))


class Neighbours(unittest.TestCase):
    def test_related_suites(self):
        for test in ('test-shared-page.c', 'test-compressed-pte.c', 'test-sptm-oracle.c', 'test-user-map-replace.c'):
            with tempfile.TemporaryDirectory() as d:
                exe, err = build(d, test, werror=False)    # their own warning baselines
                self.assertIsNotNone(exe, f'{test}: {err[-400:]}')
                r = run([exe])
                self.assertEqual(r.returncode, 0, f'{test}: {r.stdout[-400:]}{r.stderr[-400:]}')
                out = r.stdout + r.stderr
                self.assertTrue('PASS' in out or re.search(r'\b0 failures\b', out), f'{test}: {out[-300:]}')
                self.assertNotIn('FAIL', out.replace('0 failures', ''), test)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *sys.argv[1:]])
