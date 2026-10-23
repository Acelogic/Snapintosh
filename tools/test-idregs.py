#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""probes/idregs.h: the guest's TID3 ID-register reads never become an MRS of an
unallocated encoding at EL2.

    python3 tools/test-idregs.py
    python3 tools/test-idregs.py --build [--out DIR]
        [--expect-before NAME=SHA256 ...] [--expect NAME=SHA256 ...]

The Oryon traps an EL2 MRS of an unallocated ID-space encoding (FEAT_IDST;
installed-fresh-20261018-v48 faulted on S3_0_C0_C0_1). The trap handler in
probes/xnuboot.c answers every op0=3, op1=0, CRn=0, CRm=0..7 read with
id_forge(crm, op2, id_register(crm, op2)), so id_register reads only the 45
architecturally allocated encodings and returns zero (the architectural RAZ)
for the 19 unallocated or reserved ones, without an MRS.

Offline, no hardware. Without --build it checks the header's cases against
the Arm ARM allocation list below, that list against LLVM's own system
register table (an allocated encoding disassembles to a name, an unallocated
one to S3_0_C0_Cm_n), that every case's MRS names its own encoding, and that
the handler and id_forge are unchanged and touch only allocated encodings.

--build compiles xnuboot with cycle.py's control, fast and fast+WFI flag sets
twice: from this tree, and from a copy whose idregs.h is the previous 64-case
header (regenerated here, so the baseline needs no saved tree;
--expect-before binds it to the pre-change monitor hash). Then (a) no
built monitor, the SNAP_BOOT_RELOCATE=1 builds included, contains an MRS of
an unallocated ID encoding anywhere in its image, while the baseline contains
all 19; (b) function by function, with PC-relative fields resolved to their
target symbol or the bytes they point at, the default build differs from the
baseline only in id_register: every other function, the trap handler's
caller xnuboot_trap included, is identical, and none is added or removed.

Failure inventory: an MRS of an unallocated or reserved encoding anywhere in
the monitor; an allocated register dropped (its value would change from the
hardware's to zero); a case whose MRS names another encoding; id_forge
forging an unallocated encoding into something nonzero; the change leaking
into any other function of the default monitor.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / 'probes/idregs.h').read_text()
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
_LLVM_BIN = os.environ.get('LLVM_BIN')
if _LLVM_BIN:
    LLVM = Path(_LLVM_BIN)
elif Path('/opt/homebrew/opt/llvm/bin/llvm-mc').exists():
    LLVM = Path('/opt/homebrew/opt/llvm/bin')
else:
    _mc = shutil.which('llvm-mc')
    LLVM = Path(_mc).parent if _mc else Path('/usr/bin')

# The allocated AArch64 ID registers of op0=3, op1=0, CRn=0, by (CRm, op2): Arm ARM (DDI 0487), the AArch64
# System register index. Everything else in CRm 0-7 is unallocated (CRm=0) or reserved (CRm 1-7).
ALLOCATED = {
    (0, 0): 'MIDR_EL1', (0, 5): 'MPIDR_EL1', (0, 6): 'REVIDR_EL1',
    (1, 0): 'ID_PFR0_EL1', (1, 1): 'ID_PFR1_EL1', (1, 2): 'ID_DFR0_EL1', (1, 3): 'ID_AFR0_EL1',
    (1, 4): 'ID_MMFR0_EL1', (1, 5): 'ID_MMFR1_EL1', (1, 6): 'ID_MMFR2_EL1', (1, 7): 'ID_MMFR3_EL1',
    (2, 0): 'ID_ISAR0_EL1', (2, 1): 'ID_ISAR1_EL1', (2, 2): 'ID_ISAR2_EL1', (2, 3): 'ID_ISAR3_EL1',
    (2, 4): 'ID_ISAR4_EL1', (2, 5): 'ID_ISAR5_EL1', (2, 6): 'ID_MMFR4_EL1', (2, 7): 'ID_ISAR6_EL1',
    (3, 0): 'MVFR0_EL1', (3, 1): 'MVFR1_EL1', (3, 2): 'MVFR2_EL1', (3, 4): 'ID_PFR2_EL1',
    (3, 5): 'ID_DFR1_EL1', (3, 6): 'ID_MMFR5_EL1',
    (4, 0): 'ID_AA64PFR0_EL1', (4, 1): 'ID_AA64PFR1_EL1', (4, 2): 'ID_AA64PFR2_EL1',
    (4, 4): 'ID_AA64ZFR0_EL1', (4, 5): 'ID_AA64SMFR0_EL1', (4, 7): 'ID_AA64FPFR0_EL1',
    (5, 0): 'ID_AA64DFR0_EL1', (5, 1): 'ID_AA64DFR1_EL1', (5, 2): 'ID_AA64DFR2_EL1',
    (5, 4): 'ID_AA64AFR0_EL1', (5, 5): 'ID_AA64AFR1_EL1',
    (6, 0): 'ID_AA64ISAR0_EL1', (6, 1): 'ID_AA64ISAR1_EL1', (6, 2): 'ID_AA64ISAR2_EL1', (6, 3): 'ID_AA64ISAR3_EL1',
    (7, 0): 'ID_AA64MMFR0_EL1', (7, 1): 'ID_AA64MMFR1_EL1', (7, 2): 'ID_AA64MMFR2_EL1',
    (7, 3): 'ID_AA64MMFR3_EL1', (7, 4): 'ID_AA64MMFR4_EL1',
}
UNALLOCATED = {(crm, op2) for crm in range(8) for op2 in range(8)} - set(ALLOCATED)
CASE = re.compile(r'^\s*case 0x([0-9a-f]{2}): __asm__ volatile\("mrs %0, s3_0_c0_c(\d)_(\d)" : "=r"\(v\)\); break;',
                  re.M)
HANDLER = 'if (rt != 31) frame[rt] = id_forge(crm, op2, id_register(crm, op2));'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the builds (default: a temporary one)')
    ap.add_argument('--expect-before', action='append', default=[], metavar='NAME=SHA256',
                    help='control, fast or fast-wfi: the regenerated baseline must have this SHA-256')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256',
                    help='control, fast or fast-wfi: this tree\'s default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect_before=[], expect=[]), [])


def previous_header():
    """The 64-case idregs.h this change replaced: one MRS per encoding of CRm 0-7."""
    cases = ''.join(f'    case 0x{(crm << 3) | op2:02x}: __asm__ volatile("mrs %0, s3_0_c0_c{crm}_{op2}" : "=r"(v)); break;\n'
                    for crm in range(8) for op2 in range(8))
    return ('#ifndef IDREGS_H\n#define IDREGS_H\n\nstatic uint64_t id_register(uint32_t crm, uint32_t op2)\n{\n'
            '    uint64_t v = 0;\n    switch ((crm << 3) | op2) {\n' + cases +
            '    default: break;\n    }\n    return v;\n}\n\n#endif\n')


def id_moves(blob):
    """{(CRm, op2)} of every MRS of op0=3, op1=0, CRn=0, CRm 0-7 found anywhere in the image."""
    found = set()
    for at in range(0, len(blob) - 3, 4):
        w = int.from_bytes(blob[at:at + 4], 'little')
        if w & 0xfffff000 == 0xd5380000 and (w >> 8) & 15 < 8:
            found.add(((w >> 8) & 15, (w >> 5) & 7))
    return found


def sext(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def symbols(elf):
    """(named, mapping): [(addr, size, type, name)] of FUNC, OBJECT and named NOTYPE symbols, and the sorted
    $x/$d mapping symbols that say where code and data-in-code (literal pools, jump tables) start."""
    named, mapping = [], []
    for line in subprocess.run([str(LLVM / 'llvm-readelf'), '-s', '--wide', str(elf)],
                               capture_output=True, text=True, check=True).stdout.splitlines():
        parts = line.split()
        if len(parts) < 8 or not parts[0].rstrip(':').isdigit() or parts[6] == 'UND':
            continue
        addr, size, kind, name = int(parts[1], 16), int(parts[2]), parts[3], parts[7]
        if name.startswith('$x') or name.startswith('$d'):
            mapping.append((addr, name[1]))
        elif kind in ('FUNC', 'OBJECT', 'NOTYPE') and name:
            named.append((addr, size, kind, name))
    named.sort()
    table = []
    for n, (addr, size, kind, name) in enumerate(named):
        if not size:   # an assembly label: up to the next symbol
            size = (named[n + 1][0] if n + 1 < len(named) else addr) - addr
        table.append((addr, size, kind, name))
    return table, sorted(mapping)


def normalized_functions(elf, blob):
    """{name: tuple}: each symbol's contents. Code words have their PC-relative fields replaced by what they
    reach (a symbol and offset, or the 16 bytes they point at); data (OBJECT symbols and $d ranges) is raw."""
    import bisect
    table, mapping = symbols(elf)
    starts = [a for a, _, _, _ in table]
    marks = [a for a, _ in mapping]

    def where(target):
        i = bisect.bisect_right(starts, target) - 1
        if i >= 0 and table[i][0] <= target < table[i][0] + table[i][1]:
            return (table[i][3], target - table[i][0])
        return ('data', bytes(blob[target:target + 16]).hex())

    def is_data(pc):
        i = bisect.bisect_right(marks, pc) - 1
        return i >= 0 and mapping[i][1] == 'd'

    out = {}
    for addr, size, kind, name in table:
        tokens = []
        for pc in range(addr, addr + size - 3, 4):
            w = int.from_bytes(blob[pc:pc + 4], 'little')
            if kind == 'OBJECT' or is_data(pc):
                tokens.append(('raw', w))
            elif w & 0x7c000000 == 0x14000000:                     # B, BL
                tokens.append((w & 0xfc000000, where(pc + sext(w & 0x3ffffff, 26) * 4)))
            elif w & 0xff000010 == 0x54000000 or w & 0x7e000000 == 0x34000000 or w & 0x3b000000 == 0x18000000:
                tokens.append((w & 0xff00001f, where(pc + sext((w >> 5) & 0x7ffff, 19) * 4)))   # B.cond, CBZ, LDR literal
            elif w & 0x7e000000 == 0x36000000:                     # TBZ, TBNZ
                tokens.append((w & 0xfff8001f, where(pc + sext((w >> 5) & 0x3fff, 14) * 4)))
            elif w & 0x9f000000 == 0x10000000:                     # ADR
                tokens.append((w & 0x9f00001f, where(pc + sext(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21))))
            elif w & 0x9f000000 == 0x90000000:                     # ADRP
                page = (pc & ~0xfff) + (sext(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21) << 12)
                tokens.append((w & 0x9f00001f, where(page)))
            else:
                tokens.append(w)
        if size % 4:
            tokens.append(('tail', bytes(blob[addr + size - size % 4:addr + size]).hex()))
        out.setdefault(name, tuple(tokens))
    return out


class Source(unittest.TestCase):
    def test_header_reads_exactly_the_allocated_encodings(self):
        cases = CASE.findall(HEADER)
        self.assertEqual(len(cases), len(ALLOCATED))
        seen = set()
        for index, crm, op2 in cases:
            crm, op2 = int(crm), int(op2)
            self.assertEqual(int(index, 16), (crm << 3) | op2, f'case {index} reads another encoding')
            seen.add((crm, op2))
        self.assertEqual(seen, set(ALLOCATED))
        self.assertEqual(len(UNALLOCATED), 19)
        body = HEADER[HEADER.index('static uint64_t id_register'):]
        self.assertEqual(body.count('mrs'), len(ALLOCATED))
        self.assertIn('uint64_t v = 0;', body)
        self.assertIn('default: break;', body)
        self.assertIn('return v;', body)

    def test_allocation_list_matches_llvm(self):
        words = ''.join(' '.join(f'0x{b:02x}' for b in (0xd5380000 | crm << 8 | op2 << 5).to_bytes(4, 'little')) + '\n'
                        for crm in range(8) for op2 in range(8))
        out = subprocess.run([str(LLVM / 'llvm-mc'), '--disassemble', '--triple=aarch64', '-mattr=+v9.6a,+sve,+sme'],
                             input=words, capture_output=True, text=True, check=True).stdout
        names = re.findall(r'mrs\s+x0, (\S+)', out)
        self.assertEqual(len(names), 64, out)
        for n, name in enumerate(names):
            crm, op2 = divmod(n, 8)
            if (crm, op2) in ALLOCATED:
                self.assertEqual(name, ALLOCATED[(crm, op2)], (crm, op2))
            else:
                self.assertEqual(name, f'S3_0_C0_C{crm}_{op2}', f'LLVM names {(crm, op2)} {name}')

    def test_handler_and_forge_unchanged(self):
        self.assertEqual(SOURCE.count(HANDLER), 1)
        branch = SOURCE[SOURCE.index('if (op0 == 3 && op1 == 0 && crn == 0 && crm < 8 && (iss & 1)) {'):]
        self.assertTrue(branch[:200].split('\n')[1].strip() == HANDLER)
        forge_src = HEADER if 'static uint64_t id_forge(' in HEADER else SOURCE
        forge = forge_src[forge_src.index('static uint64_t id_forge(uint32_t crm, uint32_t op2, uint64_t value)\n{'):]
        forge = forge[:forge.index('\n}\n')]
        pairs = {(int(a), int(b)) for a, b in re.findall(r'crm == (\d) && op2 == (\d)', forge)}
        self.assertEqual(pairs, {(4, 0), (4, 1), (4, 4), (4, 5)})
        self.assertLessEqual(pairs, set(ALLOCATED))   # an unallocated read stays the zero id_register returns
        # Every constant id_register call names an allocated register.
        calls = [(int(a), int(b)) for a, b in re.findall(r'id_register\((\d),\s*(\d)\)', SOURCE)]
        self.assertGreaterEqual(len(calls), 10)
        for call in calls:
            self.assertIn(call, ALLOCATED)

    def test_previous_header_regenerates_the_old_cases(self):
        old = previous_header()
        self.assertEqual(len(CASE.findall(old)), 64)
        self.assertEqual(id_cases(old), {(crm, op2) for crm in range(8) for op2 in range(8)})


def id_cases(text):
    return {(int(crm), int(op2)) for _, crm, op2 in CASE.findall(text)}


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitors (about two minutes)')
class Build(unittest.TestCase):
    def test_monitors(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        sets, _ = runpy.run_path(str(ROOT / 'tools/test-wfi-resume.py'), run_name='flag_sets')['flag_sets']()
        sets = {'control': sets['control'], 'fast': sets['fast'], 'fast-wfi': sets['fast'] + ['-DSNAP_WFI_RESUME=1']}
        expect_before = dict(e.split('=', 1) for e in ARGS.expect_before)
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='idregs-build-'))
        out.mkdir(parents=True, exist_ok=True)
        # The baseline tree: this one with the previous header, built by its own copy of run.py.
        base = out / 'baseline-tree' / 'Snapintosh'
        for folder in ('probes', 'compat', 'shadow', 'tools', 'config'):
            shutil.copytree(ROOT / folder, base / folder, ignore=shutil.ignore_patterns('__pycache__'))
        (base / 'gpu').symlink_to((ROOT / 'gpu').resolve())
        (base.parent / 'q1n1').symlink_to((ROOT.parent / 'q1n1').resolve())
        (base / 'probes/idregs.h').write_text(previous_header())
        import importlib.util
        spec = importlib.util.spec_from_file_location('run_baseline', base / 'probes/run.py')
        baseline_run = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(base / 'probes'))
        spec.loader.exec_module(baseline_run)
        sys.path.remove(str(base / 'probes'))
        results = {}
        saved = list(run.FLAGS)
        try:
            for name, flags in sets.items():
                built = {}
                for label, runner, extra in (('before', baseline_run, []), ('after', run, []),
                                             ('after-relocate', run, ['-DSNAP_BOOT_RELOCATE=1'])):
                    if label == 'after-relocate' and name == 'fast-wfi':
                        continue
                    runner.FLAGS[:] = flags + extra
                    built[label] = (runner.build('xnuboot', out / f'{name}-{label}'),
                                    out / f'{name}-{label}' / 'xnuboot.elf')
                rows = {label: dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                                    unallocated_mrs=sorted(id_moves(blob) & UNALLOCATED))
                        for label, (blob, _) in built.items()}
                # (a) no MRS of an unallocated or reserved ID encoding anywhere; the baseline had all 19.
                self.assertEqual(rows['before']['unallocated_mrs'], sorted(UNALLOCATED), name)
                for label, (blob, _) in built.items():
                    if label != 'before':
                        self.assertEqual(rows[label]['unallocated_mrs'], [], f'{name}-{label}')
                    # Every allocated register is still read from the hardware.
                    self.assertEqual(id_moves(blob) & set(ALLOCATED), set(ALLOCATED), f'{name}-{label}')
                # (b) only id_register differs between the baseline and this tree's default build.
                before = normalized_functions(built['before'][1], built['before'][0])
                after = normalized_functions(built['after'][1], built['after'][0])
                self.assertEqual(set(before), set(after), f'{name}: functions added or removed')
                changed = sorted(f for f in after if after[f] != before[f])
                rows['changed_functions'] = changed
                self.assertEqual(changed, ['id_register'], name)
                if name in expect_before:
                    self.assertEqual(rows['before']['sha256'], expect_before[name], f'{name} baseline')
                if name in expect:
                    self.assertEqual(rows['after']['sha256'], expect[name], name)
                results[name] = rows
        finally:
            run.FLAGS[:] = saved
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
