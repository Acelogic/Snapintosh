#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_AES_BITSLICE (docs/AES-BITSLICE-20261019.md): the bitsliced PAC-derivation
cipher, its wiring into compat/pauth-domain.c, cycle.py's option and the monitor builds.

    python3 tools/test-aes-bitslice.py
    python3 tools/test-aes-bitslice.py --build [--out DIR] [--expect SHA256]

Offline, no hardware. It builds and runs tools/test-aes-bitslice.c sanitized (FIPS-197,
the S-box circuit exhaustively, ShiftRows/MixColumns, random blocks against aes_block,
the refusals, and the derivation with the define against the derivation without it),
then its speed mode without sanitizers (at least 10x faster), then requires weakened
headers to FAIL it. Source checks: the define defaults to 0, only pauth-domain.c
includes the header and only under the define, the define-off encrypt is the original
line, and the header has no tables, no data-dependent branch or index, and clears every
local array. cycle.py installed-fresh --aes-bitslice adds the define and nothing else.

--build builds xnuboot with installed-fresh-20261019-v90's options (cycle.py's recipe)
with the define absent, =0 and =1: absent == =0, =1 differs, both within the code
budget; --expect requires the default build to have that SHA-256 (v90's monitor_sha256).

Failure inventory: a wrong cipher or derivation; a changed refusal; no speedup; a table
or secret-dependent branch; key material left in a local array; a default build that
changed; the option adding other flags.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / 'compat/aes-bitslice.h').read_text()
DOMAIN = (ROOT / 'compat/pauth-domain.c').read_text()
DEFINE = '-DSNAP_AES_BITSLICE=1'
ORIGINAL_ENCRYPT = '{return hardware ? aes_encrypt_hardware(key,in,out) : aes_block(key,in,out,0);}'
# cycle.py installed-fresh options of installed-fresh-20261019-v90 (its qualification "flags").
V90 = ('wfi_resume fast_el0_sysreg service_subclass dart_wiredcnt panic_serve root_miss_fast update_disjoint_fast '
       'root_cache_wide update_check_sparse input kernel_pperm_fast ib_budget_1s unmap_mixed prime_secondaries '
       'txm_aspace_wide fine_locks fine_switch fair_token user_hw_walk s2_fault_retry nest_fast detach_fast '
       'root_index other_profile gate_wait fine_hw fast_timer_irq').split()
RENAME = ['-Dpauth_domain_init=ref_pauth_domain_init', '-Dpauth_domain_user=ref_pauth_domain_user',
          '-Dpauth_domain_user_with=ref_pauth_domain_user_with',
          '-Dpauth_domain_user_cached=ref_pauth_domain_user_cached',
          '-Dpauth_root_enables=ref_pauth_root_enables']
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


def compile_test(directory, header_dir=None, speed=False):
    """Build the C test in directory; header_dir's aes-bitslice.h shadows compat's."""
    directory = Path(directory)
    opts = ['-O2'] if speed else SANITIZE
    include = [f'-I{header_dir}'] if header_dir else []
    common = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *opts]
    ref = directory / 'ref.o'
    subprocess.run([*common, '-Icompat', '-c', 'compat/pauth-domain.c', '-o', str(ref), *RENAME],
                   cwd=ROOT, check=True)
    exe = directory / 'test-aes-bitslice'
    r = subprocess.run([*common, DEFINE, *include, '-Icompat', 'tools/test-aes-bitslice.c',
                        'compat/pauth-domain.c', 'compat/aes.c', str(ref), '-o', str(exe)],
                       cwd=ROOT, capture_output=True, text=True)
    return exe if r.returncode == 0 else None


def run_test(exe, *argv):
    r = subprocess.run([str(exe), *argv], capture_output=True, text=True, timeout=600)
    return r.returncode, r.stdout + r.stderr


# Each mutant replaces exactly one occurrence in compat/aes-bitslice.h.
MUTANTS = {
    'no final ShiftRows': ('aes_bs_sbox(q);aes_bs_shift_rows(q);', 'aes_bs_sbox(q);if(round<key->rounds)aes_bs_shift_rows(q);'),
    'MixColumns in the last round': ('if(round<key->rounds)aes_bs_mix_columns(q);', 'aes_bs_mix_columns(q);'),
    'row1 for row3': ('rest[b]=r1^aes_bs_row2(q[b])^aes_bs_row3(q[b]);', 'rest[b]=r1^aes_bs_row2(q[b])^aes_bs_row1(q[b]);'),
    'doubling without the x^3 term': ('q[3]=t[2]^t[7]^rest[3];', 'q[3]=t[2]^rest[3];'),
    'one S-box gate': ('t2=y12&y15', 't2=y12|y15'),
    'an S-box output unmasked': ('q[6]=s1&0xffff;', 'q[6]=s1;'),
    'ShiftRows row 3 by one column': ('(aes_bs_rotr16(w,12)&0x8888)', '(aes_bs_rotr16(w,4)&0x8888)'),
    'gather off by one': ('x=(x|(x>>14))&UINT64_C(0x0000000f0000000f);', 'x=(x|(x>>15))&UINT64_C(0x0000000f0000000f);'),
    'a skipped round key': ('aes_bs_add_key(q,key->round_key);\n', '\n'),
    'AES-192 refused': ('key->rounds!=12 && ', ''),
    'AES-128 with 9 rounds accepted': ('key->rounds!=10 && ', 'key->rounds!=10 && key->rounds!=9 && '),
    'overlap accepted': ('(out<k+sizeof(*key) && k<out+16)', '(out<k && k<out+16)'),
}


class Decision(unittest.TestCase):
    def test_cipher_and_derivation(self):
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

    def test_weakened_headers_fail(self):
        survivors = []
        for name, (old, new) in MUTANTS.items():
            self.assertEqual(HEADER.count(old), 1, f'{name}: {old!r} is not unique')
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / 'aes-bitslice.h').write_text(HEADER.replace(old, new, 1))
                exe = compile_test(d, header_dir=d)
                if exe is None:
                    continue            # a mutant that does not build cannot pass
                rc, out = run_test(exe, '3000')
                if rc == 0:
                    survivors.append(name)
        self.assertEqual(survivors, [], 'weakened headers passed the C test')


def body(text, signature):
    start = text.index(signature)
    depth, i = 0, text.index('{', start)
    for j in range(i, len(text)):
        depth += {'{': 1, '}': -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise ValueError(signature)


class Source(unittest.TestCase):
    def test_default_off_and_wiring(self):
        self.assertIn('#ifndef SNAP_AES_BITSLICE\n#define SNAP_AES_BITSLICE 0\n#endif', DOMAIN)
        self.assertIn('#if SNAP_AES_BITSLICE\n#include "aes-bitslice.h"\n#endif', DOMAIN)
        # The define-off encrypt is the original line, in the #else branch.
        other = DOMAIN.split('#if SNAP_AES_BITSLICE\n/*', 1)[1]
        self.assertIn('#else\n' + ORIGINAL_ENCRYPT + '\n#endif', other)
        self.assertEqual(DOMAIN.count('aes_encrypt_bitsliced('), 1)
        users = [p for p in (ROOT / 'compat').glob('*') if p.suffix in ('.c', '.h', '.S') and
                 'aes-bitslice.h' in p.read_text(errors='replace') and p.name != 'aes-bitslice.h']
        users += [p for p in (ROOT / 'probes').glob('*.[chS]') if 'aes-bitslice.h' in p.read_text(errors='replace')]
        self.assertEqual(sorted(p.name for p in users), ['pauth-domain.c'])

    def test_preprocessed_off_matches_original(self):
        """Without the define, pauth-domain.c preprocesses to the original file's text."""
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'pauth-domain.c'
            text = DOMAIN.replace('#ifndef SNAP_AES_BITSLICE\n#define SNAP_AES_BITSLICE 0\n#endif\n'
                                  '#if SNAP_AES_BITSLICE\n#include "aes-bitslice.h"\n#endif\n', '')
            text = re.sub(r'#if SNAP_AES_BITSLICE\n/\*.*?\*/\n\{[^\n]*\}\n#else\n(\{[^\n]*\})\n#endif',
                          r'\1', text, flags=re.S)
            original.write_text(text)

            def pre(path, *flags):
                out = subprocess.run(['cc', '-E', '-P', '-Icompat', *flags, str(path)], cwd=ROOT,
                                     capture_output=True, text=True, check=True).stdout
                return re.sub(r'\s+', ' ', out)
            self.assertNotIn('SNAP_AES_BITSLICE', text)
            self.assertEqual(pre(ROOT / 'compat/pauth-domain.c'), pre(original))
            self.assertEqual(pre(ROOT / 'compat/pauth-domain.c', '-DSNAP_AES_BITSLICE=0'), pre(original))
            self.assertNotEqual(pre(ROOT / 'compat/pauth-domain.c', DEFINE), pre(original))

    def test_constant_time_shape(self):
        code = re.sub(r'/\*.*?\*/', '', HEADER, flags=re.S)
        self.assertNotRegex(code, r'static\s+const', 'a table')
        self.assertNotIn('?', code, 'a conditional expression')
        # Indexes: loop counters, constants, or the public round number.
        for index in re.findall(r'\[([^\]]*)\]', code):
            self.assertRegex(index.strip(), r'^(\d+|b|i|8\+i|8|16)$', f'index [{index}]')
        self.assertEqual(code.count('round*16'), 1)
        # Branches: the refusals and the public round count only.
        ifs = re.findall(r'\bif\s*\((.*?)\)\s*(?:return|aes_bs_)', code)
        self.assertEqual(len(re.findall(r'\bif\s*\(', code)), 3, ifs)
        self.assertTrue(any('round<key->rounds' in i for i in ifs))
        self.assertTrue(all('key->rounds' in i or 'out' in i or 'round<' in i for i in ifs), ifs)
        # Every local array is cleared before its function returns.
        for fn, arrays in (('aes_bs_add_key', ['k']), ('aes_bs_mix_columns', ['t', 'rest']),
                           ('aes_encrypt_bitsliced', ['q'])):
            text = body(code, 'static inline ' + ('int ' if fn == 'aes_encrypt_bitsliced' else 'void ') + fn)
            for a in arrays:
                self.assertIn(f'aes_clear({a},sizeof({a}));', text, f'{fn} leaves {a}')


def installed(**extra):
    sys.path.insert(0, str(ROOT / 'tools'))
    import cycle_lib.installed_fresh as fresh  # noqa: E402
    import cycle_lib.speed_test as st  # noqa: E402
    sets, _ = st.flag_sets(ROOT)
    args = argparse.Namespace(variant='fast', **{n: True for n in V90})
    for k, v in extra.items():
        setattr(args, k, v)
    return fresh, sets, args


def flags_v90(on=False):
    fresh, sets, args = installed(aes_bitslice=on)
    return fresh.variant_flags(sets, args)


class Cycle(unittest.TestCase):
    def test_option(self):
        off, on = flags_v90(), flags_v90(True)
        self.assertNotIn(DEFINE, off)
        self.assertEqual(on.count(DEFINE), 1)
        self.assertEqual([f for f in on if f != DEFINE], off)
        text = (ROOT / 'tools/cycle.py').read_text()
        self.assertIn("p.add_argument('--aes-bitslice', action='store_true',", text)


@unittest.skipUnless(ARGS.build, 'needs --build')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='aes-bitslice-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results, blobs = {}, {}
        base = flags_v90()
        try:
            for label, flags in (('default', base), ('off', base + ['-DSNAP_AES_BITSLICE=0']),
                                 ('on', flags_v90(True))):
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
