#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Torn descriptors: every 8-byte store the SPTM model makes into guest memory is one single-copy-
atomic access (compat/sptm-access.h; docs/USER-HW-WALK-20261017.md "v67").

    python3 tools/test-descriptor-stores.py
    python3 tools/test-descriptor-stores.py --elf build/installed-fresh-20261018-v67/xnuboot.elf

Offline, no hardware and no proxy. v67 (SNAP_USER_HW_WALK with --s2-fault-retry) recorded HPFAR IPA
0x60e3f030 for a user store whose leaf maps 0x960e3f000: the hardware walked XNU's own table while
the model was storing the leaf one byte at a time, lowest first, and saw the low four bytes new and
the high four still zero. Every stage-2 stop since v62 is its reported IPA with OA[47:32] cleared.

It checks, in order:
  - the stress (tools/test-descriptor-stores.c): a reader thread doing single 64-bit loads of a slot
    another thread rewrites. Through the v67 helper (eight volatile byte stores) it must see torn
    values, which proves this host exposes tearing; through sptm_put64 it must see none, and the
    misaligned fallback must still write the whole value;
  - the real model (tools/test-descriptor-stores-model.c): sptm_mac_map_user_page and
    sptm_mac_unmap_user_region on the live format-1 fixture, a reader on the 64 level-3 slots. It
    must see no torn value, and with sptm_put64 weakened back to the byte copy it must see some;
  - the sources: every model file's 8-byte helpers (compat/sptm*.c, txm.c, txm-copy.c) go through
    sptm_get64/sptm_put64, and no eight-iteration byte loop is left in them;
  - the monitor itself: xnuboot built at its own -Os/LTO with v67's flags (v65's plus
    --s2-fault-retry; the fast set when no record is present) and disassembled. No function may
    store a 64-bit value in pieces, as a byte or halfword loop that shifts a register until 64 or as
    narrow stores to eight consecutive bytes cut from one register, except sptm_put_bytes (the
    misaligned fallback) and q1n1's SHA-256 digest writer. The table writers must be present, so the
    scan is not vacuous, and the build with sptm_put64 weakened back to the byte copy must make the
    scan flag them. --elf scans that file instead (no negative build).

Failure inventory: a descriptor store split into bytes, halfwords or words (any SPTM model writer:
MAP_PAGE, UNMAP, UPDATE, NEST/UNNEST, MAP_TABLE, condemn, the physical aperture, slides, DART); a
helper that skips the single access for aligned fields; a scan that passes because it looked at
nothing; a host that cannot show tearing taken as proof.
"""
from pathlib import Path
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import collections
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
ACCESS = (ROOT / 'compat/sptm-access.h').read_text()
MODEL_FILES = ['compat/sptm.c', 'compat/sptm-user.c', 'compat/sptm-unmap.c', 'compat/sptm-update.c',
               'compat/sptm-papt.c', 'compat/sptm-slide.c', 'compat/sptm-dart.c', 'compat/sptm-root.c',
               'compat/txm.c', 'compat/txm-copy.c']
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']
# sptm_put64 as every model file had it until v67: the byte copy, inline.
WEAK = ('    if (!((uintptr_t)p & 7)) {*(volatile uint64_t *)(volatile void *)p = v; return;}\n'
        '    sptm_put_bytes(p, v, 8);\n',
        '    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));\n')
ALLOWED = re.compile(r'^(sptm_put_bytes(\.\d+)?|q1n1_sha256)$')
# Model functions that store descriptors; each must exist in the monitor build.
WRITERS = ['sptm_mac_map_user_page', 'sptm_mac_unmap_user_region', 'sptm_mac_update_user_region',
           'sptm_mac_unmap_kernel_disjoint', 'sptm_mac_unmap_mixed_disjoint', 'sptm_mac_update_mixed_disjoint',
           'sptm_mac_update_shared_region', 'sptm_mac_nest_region', 'sptm_mac_unnest_region',
           'sptm_mac_map_table', 'sptm_mac_map_user_table_live', 'sptm_mac_condemn_user_table',
           'sptm_mac_slide_region', 'sptm_papt_commit', 'sptm_kernel_update_commit', 'sptm_dart_map_table']
RECORDS = [ROOT / 'build/installed-fresh-20261018-v67/qualification.json',
           ROOT / 'build/installed-fresh-20261018-v65/qualification.json']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--elf', help='scan this monitor ELF instead of building one')
    args, rest = ap.parse_known_args()
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (argparse.Namespace(elf=None), [])


def cc(directory, sources, out, tree=ROOT):
    """Build tools/<sources> against tree's compat/ and shadow/ (ROOT, or weak_tree's copy)."""
    exe = Path(directory) / out
    sources = [str(ROOT / s) if s.startswith('tools/') else str(Path(tree) / s) for s in sources]
    cmd = ['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
           f'-I{Path(tree) / "compat"}', f'-I{Path(tree) / "shadow"}', f'-I{ROOT / "tools"}', *sources, '-o', str(exe)]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
    return exe if r.returncode == 0 else None, r.stderr


def weak_tree(directory):
    """A private copy of the monitor sources with sptm_put64 back to the byte copy (a quoted include
    finds the includer's own directory first, so the header is replaced in a copy of compat/)."""
    tree = Path(directory) / 'weak' / 'Snapintosh'
    tree.mkdir(parents=True)
    for d in ('compat', 'shadow', 'probes', 'config'):
        shutil.copytree(ROOT / d, tree / d, ignore=shutil.ignore_patterns('__pycache__'))
    for d in ('tools', 'gpu', 'drivers', 'candidates', 'downloads'):
        if (ROOT / d).exists():
            (tree / d).symlink_to((ROOT / d).resolve())
    (tree.parent / 'q1n1').symlink_to(ROOT.parent / 'q1n1')
    assert ACCESS.count(WEAK[0]) == 1
    (tree / 'compat/sptm-access.h').write_text(ACCESS.replace(WEAK[0], WEAK[1]))
    return tree


def torn(output):
    m = re.search(r'^torn (\d+) of (\d+) reads', output, re.M)
    return int(m[1]), int(m[2])


class Stress(unittest.TestCase):
    def test_helper(self):
        with tempfile.TemporaryDirectory() as d:
            exe, err = cc(d, ['tools/test-descriptor-stores.c'], 'stress')
            self.assertIsNotNone(exe, err)
            old = subprocess.run([str(exe), 'bytes', '20'], capture_output=True, text=True, timeout=600)
            self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
            seen, reads = torn(old.stdout)
            self.assertGreater(reads, 0)
            self.assertGreater(seen, 0, 'this host shows no tearing for byte stores: the stress proves nothing')
            new = subprocess.run([str(exe), 'put64', '20'], capture_output=True, text=True, timeout=600)
            self.assertEqual(new.returncode, 0, new.stdout + new.stderr)
            self.assertEqual(torn(new.stdout)[0], 0, new.stdout)
            self.assertIn('fallback ok', new.stdout)
            print(f'bytes: {old.stdout.strip()}\nput64: {new.stdout.strip()}', file=sys.stderr)

    def test_model(self):
        with tempfile.TemporaryDirectory() as d:
            src = ['tools/test-descriptor-stores-model.c', *CORE]
            exe, err = cc(d, src, 'model')
            self.assertIsNotNone(exe, err)
            weak, err = cc(d, src, 'model-weak', tree=weak_tree(d))
            self.assertIsNotNone(weak, err)
            r = subprocess.run([str(exe), '3000'], capture_output=True, text=True, timeout=900)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(torn(r.stdout)[0], 0, r.stdout)
            w = subprocess.run([str(weak), '3000'], capture_output=True, text=True, timeout=900)
            self.assertEqual(w.returncode, 0, w.stdout + w.stderr)
            self.assertGreater(torn(w.stdout)[0], 0, 'the byte copy must tear under the model stress')
            print(f'model: {r.stdout.strip()}\nweak:  {w.stdout.strip()}', file=sys.stderr)


class Sources(unittest.TestCase):
    def test_model_helpers(self):
        # Through the helpers' guest-memory pointer (p); a local copy (txm.c's input[]) is not shared.
        byte_loop = re.compile(r'for *\( *unsigned +(\w+) *= *0 *; *\1 *< *8 *;[^)]*\)\s*p\[\1\] *= *\(uint8_t\)'
                               r'|for *\( *unsigned +(\w+) *= *0 *; *\2 *< *8 *;[^)]*\)\s*\w+ *\|= *\(uint64_t\)p\[\2\]')
        for f in MODEL_FILES:
            text = read_source(ROOT / f)
            self.assertIn('#include "sptm-access.h"', text, f)
            self.assertEqual(byte_loop.findall(text), [], f'{f}: an eight-iteration byte loop')
            self.assertTrue('sptm_put64(' in text or 'sptm_get64(' in text, f)
        # Generic helpers take the single access for 8 bytes before any byte loop.
        for f in ('compat/sptm-user.c', 'compat/sptm-slide.c'):
            text = read_source(ROOT / f)
            self.assertRegex(text, r'static uint64_t get\(volatile uint8_t \*p,unsigned n\)\s*\{\s*if\(n==8\)return sptm_get64\(p\);', f)
            self.assertRegex(text, r'static void put\(volatile uint8_t \*p,uint64_t v,unsigned n\)\s*\{\s*if\(n==8\) \{sptm_put64\(p,v\);return;\}', f)
        self.assertRegex(read_source(ROOT / 'compat/sptm-root.c'),
                         r'static uint64_t get\(volatile uint8_t \*p,unsigned n\)\s*\{if\(n==8\)return sptm_get64\(p\);')
        # The helpers themselves: aligned is one volatile 64-bit access; bytes only out of line.
        self.assertIn('if (!((uintptr_t)p & 7)) {*(volatile uint64_t *)(volatile void *)p = v; return;}', ACCESS)
        self.assertIn('if (!((uintptr_t)p & 7)) return *(const volatile uint64_t *)(const volatile void *)p;', ACCESS)
        self.assertEqual(len(re.findall(r'__attribute__\(\(noinline\)\) static inline', ACCESS)), 2)


NARROW = {'strb': 1, 'sturb': 1, 'strh': 2, 'sturh': 2}


def parse(text):
    func, ins = None, []
    for line in text.splitlines():
        m = re.match(r'^[0-9a-f]+ <(.+)>:', line)
        if m:
            func = m[1]
            continue
        m = re.match(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$', line)
        if m:
            ins.append((func, int(m[1], 16), m[2], m[3].strip()))
    return ins


def width(op, args):
    if op in NARROW:
        return NARROW[op]
    if op in ('str', 'stur') and re.match(r'w(\d+|zr),', args):
        return 4
    return 0


def split_stores(ins):
    """function -> sites where a 64-bit value is stored in pieces: (a) a backward loop of at most 24
    instructions storing a byte or halfword of a register shifted by a variable, ending at shift 64
    (cmp #0x40); (b) narrow stores to eight consecutive bytes at an 8-aligned offset of one base, at
    least two of whose values are constant right shifts (by multiples of 8) of one register."""
    out = collections.defaultdict(list)
    by_addr = {a: i for i, (f, a, op, args) in enumerate(ins)}
    target = re.compile(r'0x([0-9a-f]+) <')
    for i, (f, a, op, args) in enumerate(ins):
        if not (op.startswith('b.') or op in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz')):
            continue
        m = target.search(args)
        if not m:
            continue
        t = int(m[1], 16)
        if t > a or t not in by_addr or i - by_addr[t] > 24 or ins[by_addr[t]][0] != f:
            continue
        body = ins[by_addr[t]:i + 1]
        if (any(x[2] in NARROW for x in body) and
                any(x[2] in ('lsr', 'asr') and re.match(r'[xw]\d+, [xw]\d+, [xw]\d+$', x[3]) for x in body) and
                any(x[2] == 'cmp' and re.search(r', #(0x40|64)$', x[3]) for x in body)):
            out[f].append(f'loop@{a:#x}')
    store = re.compile(r'([wx](?:\d+|zr)), \[(x\d+|sp)(?:, #(-?(?:0x)?[0-9a-f]+))?\]$')
    for i, (f, a, op, args) in enumerate(ins):
        w = width(op, args)
        m = store.match(args) if w else None
        if not m:
            continue
        base, k = m[2], int(m[3] or '0', 0)
        if k % 8:
            continue
        stores = [(k, w, m[1])]
        for x in ins[i + 1:i + 40]:
            if x[0] != f:
                break
            w2 = width(x[2], x[3])
            m2 = store.match(x[3]) if w2 else None
            if m2 and m2[2] == base and k <= int(m2[3] or '0', 0) < k + 8:
                stores.append((int(m2[3] or '0', 0), w2, m2[1]))
        cover = set()
        for k2, w2, _ in stores:
            cover |= set(range(k2, k2 + w2))
        if not all(k + n in cover for n in range(8)):
            continue
        regs = {r[1:] for _, _, r in stores}
        shifts = collections.Counter()
        for x in ins[max(0, i - 40):i + 40]:
            mm = re.match(r'([xw])(\d+), ([xw])(\d+), #(\d+|0x[0-9a-f]+)$', x[3]) if (
                x[0] == f and x[2] in ('lsr', 'ubfx')) else None
            if mm and mm[2] in regs and int(mm[5], 0) and int(mm[5], 0) % 8 == 0:
                shifts[mm[4]] += 1
        if shifts and max(shifts.values()) >= 2:
            out[f].append(f'run@{a:#x}')
    return out


def objdump():
    for name in ('llvm-objdump',):
        if shutil.which(name):
            return shutil.which(name)
    r = subprocess.run(['xcrun', '--find', 'llvm-objdump'], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def disassemble(elf):
    tool = objdump()
    if not tool:
        raise unittest.SkipTest('no llvm-objdump')
    return subprocess.run([tool, '-d', '--no-show-raw-insn', str(elf)], capture_output=True, text=True,
                          check=True).stdout


def monitor_flags():
    for record in RECORDS:
        if record.is_file():
            flags = json.loads(record.read_text())['flags']
            if 'v65' in str(record) and '-DSNAP_S2_FAULT_RETRY=1' not in flags:
                flags = [*flags, '-DSNAP_S2_FAULT_RETRY=1']
            return flags, record.parent.name
    sys.path.insert(0, str(ROOT / 'tools'))
    import ast
    tree = ast.parse((ROOT / 'tools/build-fast-traps-monitor.py').read_text())
    lists = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name) and t.id in ('ADDED', 'FAST')}
    base = json.loads((ROOT / 'config/monitor-flags.json').read_text())['flags']
    return [*base, *lists['ADDED'], *lists['FAST']], 'fast set'


def build_monitor(out, tree=ROOT):
    """xnuboot from tree (probes/run.py build(), in a subprocess so a weak tree's run.py is its own)."""
    flags, _ = monitor_flags()
    code = ('import json,sys; from pathlib import Path; sys.path.insert(0, "probes"); '
            'sys.path.insert(0, "../q1n1/tools"); import run; '
            f'run.FLAGS[:] = json.loads({json.dumps(json.dumps(flags))}); '
            f'run.build("xnuboot", Path({json.dumps(str(out))}))')
    r = subprocess.run([sys.executable, '-c', code], cwd=tree, capture_output=True, text=True, timeout=1800)
    if r.returncode:
        raise AssertionError(f'monitor build failed in {tree}: {r.stderr[-2000:]}')
    return Path(out) / 'xnuboot.elf'


class Monitor(unittest.TestCase):
    def test_no_split_descriptor_stores(self):
        with tempfile.TemporaryDirectory() as d:
            elf = Path(ARGS.elf) if ARGS.elf else build_monitor(Path(d) / 'fixed')
            ins = parse(disassemble(elf))
            names = {f for f, *_ in ins}
            missing = [w for w in WRITERS if w not in names]
            self.assertEqual(missing, [], 'table writers not found: the scan would look at nothing')
            found = split_stores(ins)
            bad = {f: v for f, v in found.items() if not ALLOWED.match(f)}
            self.assertEqual(bad, {}, 'a 64-bit value stored in pieces')
            print(f'{elf}: {len(ins)} instructions, split stores only in {sorted(found)}', file=sys.stderr)
            if ARGS.elf:
                return
            # The scan catches the v67 helper in the real build.
            weak = build_monitor(Path(d) / 'weak-build', tree=weak_tree(d))
            flagged = split_stores(parse(disassemble(weak)))
            caught = [w for w in WRITERS if w in flagged]
            self.assertIn('sptm_mac_map_user_page', caught)
            self.assertGreaterEqual(len(caught), len(WRITERS) // 2, caught)
            print(f'weakened helper: {len(caught)} of {len(WRITERS)} writers flagged', file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
