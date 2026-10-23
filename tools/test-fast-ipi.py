#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_FAST_IPI (docs/FAST-IPI-20261019.md): the lock-free Apple IPI registers, their
wiring into probes/xnuboot.c and compat/ipi.c, the report record and cycle.py's option.

    python3 tools/test-fast-ipi.py
    python3 tools/test-fast-ipi.py --build [--out DIR] [--expect SHA256]

Offline, no hardware. It builds and runs tools/test-fast-ipi.c under ASan/UBSan and under
TSan: a differential against compat/ipi.c as it was, the define's locked path against it,
and six threads posting, reading and acknowledging lock-free and under a mutex with
conservation checks. It requires weakened headers to fail that test. Source checks:
- the define defaults to 0 in both files, and compat/ipi.c without it preprocesses to
  its original text;
- the fast handler repeats the locked IPI case's runnable mask and tail, and is reached
  only for the three IPI registers, after the fast-trap admission;
- the header changes shared words only atomically.
The report record sits just below the thermal block, after every chained record, and
decodes (damaged ones are refused). cycle.py installed-fresh admits --fast-ipi only with
its prerequisites.

--build builds xnuboot with installed-fresh-20261019-v90's options with the define
absent, =0 and =1: absent == =0, =1 differs, all within the code budget; --expect
requires the default build to have that SHA-256.

Failure inventory: divergence from guest_ipi_route; a lost or torn IPI; a changed
refusal; a lock-free path without the admission; a changed locked path or default build;
a report record that overlaps or misdecodes; the option without its prerequisites.
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
HEADER = (ROOT / 'compat/fast-ipi.h').read_text()
IPI_C = (ROOT / 'compat/ipi.c').read_text()
DEFINE = '-DSNAP_FAST_IPI=1'
RENAME = ['-Dguest_ipi_access=ref_guest_ipi_access', '-Dguest_ipi_route=ref_guest_ipi_route',
          '-Dguest_ipi_poll_delay=ref_guest_ipi_poll_delay', '-Dguest_ipi_fiq=ref_guest_ipi_fiq']
SANITIZERS = {'asan': ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'], 'tsan': ['-fsanitize=thread']}


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


def original_ipi_c(text=IPI_C):
    """compat/ipi.c with every SNAP_FAST_IPI block resolved to its #else branch."""
    text = text.replace('#ifndef SNAP_FAST_IPI\n#define SNAP_FAST_IPI 0\n#endif\n', '')
    text = re.sub(r'#if SNAP_FAST_IPI\n.*?#else\n(.*?)#endif\n', r'\1', text, flags=re.S)
    return text


def compile_test(directory, sanitizer='asan', header_dir=None):
    directory = Path(directory)
    opts = ['-O1', '-g', *SANITIZERS[sanitizer]]
    common = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *opts]
    reference = directory / 'ipi-reference.c'
    reference.write_text(original_ipi_c())
    ref = directory / 'ref.o'
    subprocess.run([*common, f'-I{ROOT / "compat"}', '-c', str(reference), '-o', str(ref), *RENAME],
                   cwd=ROOT, check=True)
    include = [f'-I{header_dir}'] if header_dir else []
    exe = directory / 'test-fast-ipi'
    r = subprocess.run([*common, DEFINE, *include, '-Icompat', 'tools/test-fast-ipi.c', 'compat/ipi.c',
                        str(ref), '-lpthread', '-o', str(exe)], cwd=ROOT, capture_output=True, text=True)
    return exe if r.returncode == 0 else None


def run_test(exe, *argv):
    r = subprocess.run([str(exe), *argv], capture_output=True, text=True, timeout=900)
    return r.returncode, r.stdout + r.stderr


# Each replaces exactly one occurrence in compat/fast-ipi.h.
MUTANTS = {
    'a post that is not one exchange': (
        'uint64_t old = __atomic_exchange_n(&ipi->pending, 1, __ATOMIC_ACQ_REL);',
        'uint64_t old = __atomic_load_n(&ipi->pending, __ATOMIC_RELAXED); '
        '__atomic_store_n(&ipi->pending, 1, __ATOMIC_RELAXED);'),
    'requests counted with a plain add': ('__atomic_fetch_add(&ipi->requests, 1, __ATOMIC_RELAXED);', 'ipi->requests++;'),
    'coalesced not counted': ('__atomic_fetch_add(&ipi->coalesced, old, __ATOMIC_RELAXED);', '(void)old;'),
    'an acknowledgement that always counts': (
        'if (__atomic_exchange_n(&ipi->pending, 0, __ATOMIC_ACQ_REL)) ipi->acks++;',
        '__atomic_store_n(&ipi->pending, 0, __ATOMIC_RELAXED); ipi->acks++;'),
    'IPI_SR reads not counted': ('self->reads++;', '(void)self;'),
    'IPI_SR accepts other bits': ('if (*value & ~UINT64_C(1)) return FAST_IPI_DECLINE_REFUSED;', ''),
    'RR read accepted': ('    if (read) return FAST_IPI_DECLINE_REFUSED;\n    uint64_t allowed', '    uint64_t allowed'),
    'RR_LOCAL takes the cluster from the value': (
        '(reg == IPI_RR_LOCAL ? (affinities[source] & 0xff00) : ((*value >> 8) & 0xff00))',
        '((*value >> 8) & 0xff00)'),
    'a non-runnable target posted': ('if (!(runnable & (UINT64_C(1) << i))) return FAST_IPI_DECLINE_TARGET;\n', ''),
    'duplicate affinities accepted': ('if (states[i] == states[j] || (affinities[i] & 0xffff) == (affinities[j] & 0xffff))',
                                      'if (states[i] == states[j])'),
    'a non-runnable source accepted': ('!(runnable & (UINT64_C(1) << source)) ||', ''),
    'pending of 2 accepted': ('__atomic_load_n(&states[i]->pending, __ATOMIC_RELAXED) > 1 ||', ''),
    'the wrong kind for RR_LOCAL': ('return reg == IPI_RR_LOCAL ? FAST_IPI_REQUEST_LOCAL : FAST_IPI_REQUEST_GLOBAL;',
                                    'return FAST_IPI_REQUEST_GLOBAL;'),
    'an unknown target refused instead of declined as a target': (
        '        }\n    return FAST_IPI_DECLINE_TARGET;', '        }\n    return FAST_IPI_DECLINE_REFUSED;'),
}


class Decision(unittest.TestCase):
    def test_differential_and_concurrency(self):
        for sanitizer in SANITIZERS:
            with self.subTest(sanitizer=sanitizer), tempfile.TemporaryDirectory() as d:
                exe = compile_test(d, sanitizer)
                self.assertIsNotNone(exe, 'the C test does not build')
                rc, out = run_test(exe)
                self.assertEqual(rc, 0, out)
                self.assertIn('PASS', out)
                self.assertNotIn('WARNING: ThreadSanitizer', out)
                print(out.strip().splitlines()[-1], f'({sanitizer})', file=sys.stderr)

    def test_weakened_headers_fail(self):
        survivors = []
        for name, (old, new) in MUTANTS.items():
            self.assertEqual(HEADER.count(old), 1, f'{name}: {old!r} is not unique')
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / 'fast-ipi.h').write_text(HEADER.replace(old, new, 1))
                exe = compile_test(d, 'asan', header_dir=d)
                if exe is None:
                    survivors.append(name + ' (does not build)')
                    continue
                rc, out = run_test(exe, '60000', '200000')
                if rc == 0:
                    survivors.append(name)
        self.assertEqual(survivors, [], 'weakened headers passed (or did not build)')


def body(text, signature):
    start = text.index(signature)
    depth, i = 0, text.index('{', start)
    for j in range(i, len(text)):
        depth += {'{': 1, '}': -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise ValueError(signature)


def squeeze(text):
    return re.sub(r'\s+', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))


class Source(unittest.TestCase):
    def test_defaults_and_ipi_c_text(self):
        self.assertIn('#ifndef SNAP_FAST_IPI\n#define SNAP_FAST_IPI 0\n#endif', SOURCE)
        self.assertIn('#ifndef SNAP_FAST_IPI\n#define SNAP_FAST_IPI 0\n#endif', IPI_C)
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'ipi.c'
            original.write_text(original_ipi_c())
            self.assertNotIn('SNAP_FAST_IPI', original.read_text())

            def pre(path, *flags):
                out = subprocess.run(['cc', '-E', '-P', f'-I{ROOT / "compat"}', *flags, str(path)], cwd=ROOT,
                                     capture_output=True, text=True, check=True).stdout
                return re.sub(r'\s+', ' ', out)
            self.assertEqual(pre(ROOT / 'compat/ipi.c'), pre(original))
            self.assertEqual(pre(ROOT / 'compat/ipi.c', '-DSNAP_FAST_IPI=0'), pre(original))
            self.assertNotEqual(pre(ROOT / 'compat/ipi.c', DEFINE), pre(original))

    def test_fast_handler_repeats_the_locked_case(self):
        fast = squeeze(body(SOURCE, 'static int fast_ipi_trap('))
        locked = squeeze(SOURCE[SOURCE.index('enum ipi_result ipi_status=IPI_UNHANDLED;'):
                                SOURCE.index('if (reg == CLOCK_ARCH_CNTP_CTL)')])
        runnable = squeeze('''if(!(life&SERVICE_ADMISSION_CLOSED) && c->vcpus[i].prepared &&
               ((life>>(i*3))&7)==EXECUTOR_RUNNING) runnable|=UINT64_C(1)<<i;''')
        self.assertIn(runnable, locked)
        self.assertIn(runnable, fast)
        self.assertIn('uint64_tlife=guest_service_lifecycle(&c->services);', locked)
        self.assertIn('life=guest_service_lifecycle(&c->services);', fast)
        # The locked case's tail, in order, after a handled result.
        order = ['if(!fast_admitted(c,v,esr))', 'fast_ipi_access(states,affinities,GUEST_CPU_COUNT,runnable,',
                 'if(r>=FAST_IPI_DECLINES)return0;', 'if(reg==IPI_SR&&value)v->ipi_ack_pc=*elr;',
                 'elseif(reg!=IPI_SR)v->ipi_request_pc=*elr;', 'guest_interrupt_sync(c);',
                 'if(is_read&&rt!=31)frame[rt]=value;', '*elr+=4;', 'c->perf.fast[v->slot].sysreg++;']
        at = -1
        for token in order:
            self.assertIn(token, fast[at + 1:], token)
            at = fast.index(token, at + 1)
        for token in ('vcpu_of(c)->ipi_ack_pc=*elr;', 'guest_interrupt_sync(c);', 'if(is_read&&rt!=31)frame[rt]=value;'):
            self.assertIn(token, locked)
        # Nothing else shared: no record, no c->traps, no other vCPU's fields.
        for forbidden in ('record(', 'c->traps', 'guest_ipi_route(', 'timer_arm(', 'step_arm('):
            self.assertNotIn(forbidden, fast, forbidden)

    def test_dispatch(self):
        trap = squeeze(body(SOURCE, 'static int fast_vcpu_trap('))
        hook = ('#ifSNAP_FAST_IPIif(reg==IPI_RR_LOCAL||reg==IPI_RR_GLOBAL||reg==IPI_SR)'
                'returnfast_ipi_trap(c,v,frame,esr,elr);#endif')
        self.assertIn(hook, trap)
        self.assertLess(trap.index(hook), trap.index('cls=fast_trap_sysreg_class('))
        self.assertEqual(SOURCE.count('fast_ipi_trap('), 2)
        self.assertIn('_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE,', SOURCE)

    def test_header_writes_shared_words_atomically(self):
        code = re.sub(r'/\*.*?\*/', '', HEADER, flags=re.S)
        for field in ('pending', 'requests', 'coalesced', 'last_request'):
            plain = re.findall(rf'->{field}\s*(?:[-+]?=(?!=)|\+\+|--)', code)
            self.assertEqual(plain, [], f'a plain write of {field}')
        # Only this vCPU's own counters change with plain increments.
        self.assertEqual(sorted(re.findall(r'(\w+)->(\w+)\+\+', code)), [('ipi', 'acks'), ('self', 'reads')])


def record(lay_size=128, results=None, ticks=0, longest=0, damage=None):
    words = [0x3149504954534146, lay_size << 32]
    for cpu in range(6):
        r = results[cpu] if results else [0] * 7
        cpu_words = list(r) + [ticks, longest] + [0] * 7
        words += cpu_words
    data = bytearray(struct.pack(f'<{len(words)}Q', *words))
    if damage:
        damage(data)
    return bytes(data)


class Report(unittest.TestCase):
    def test_place_and_decode(self):
        pc = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        offset, size = pc['fast_ipi_spec']([f for f in flags_v90(True) if f.startswith('-D')])
        thermal = runpy.run_path(str(ROOT / 'tools/a16_thermal.py'))['REPORT_OFFSET']
        self.assertEqual(size, 16 + 6 * 128)
        self.assertEqual(offset + size, thermal)
        # The C side's OUT_FAST_IPI, from the same headers.
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / 'probe.c'
            probe.write_text('#include <stdio.h>\n#include "a16-thermal.h"\n#include "fast-ipi.h"\n'
                             'int main(void){printf("%lu\\n",(unsigned long)(16+8*(A16_THERMAL_REPORT_OFFSET/8-2-'
                             '6*(sizeof(struct fast_ipi_cpu)/8))));return 0;}\n')
            subprocess.run(['cc', '-std=gnu11', f'-I{ROOT / "compat"}', str(probe), '-o', f'{d}/probe'], check=True)
            self.assertEqual(int(subprocess.run([f'{d}/probe'], capture_output=True, text=True).stdout), offset)
        self.assertIn('#define OUT_FAST_IPI (OUT_THERMAL - 2 - GUEST_CPU_COUNT*FAST_IPI_WORDS)', SOURCE)
        lay = dict(size=128, result=0, ticks=56, max=64, reserved=72)
        results = [[3, 4, 5, 6, 1, 0, 2]] * 6
        out = pc['decode_fast_ipi'](record(results=results, ticks=100, longest=10), lay=lay, hz=19.2e6)
        self.assertEqual(out['summary']['handled'], 6 * 18)
        self.assertEqual(out['summary']['declined'], 6 * 3)
        self.assertEqual(out['cpus'][0]['result']['request_global'], 6)
        for name, damage in (('magic', lambda b: b.__setitem__(0, 0)),
                             ('size word', lambda b: struct.pack_into('<Q', b, 8, 64 << 32)),
                             ('reserved', lambda b: struct.pack_into('<Q', b, 16 + 72, 1))):
            with self.subTest(damage=name), self.assertRaises(ValueError):
                pc['decode_fast_ipi'](record(results=results, ticks=100, longest=10, damage=damage), lay=lay)
        with self.assertRaises(ValueError):   # time without a handled access
            pc['decode_fast_ipi'](record(ticks=5, longest=5), lay=lay)


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


def flags_v90(on=False, **extra):
    fresh, sets, args = installed(fast_ipi=on, **extra)
    return fresh.variant_flags(sets, args)


class Cycle(unittest.TestCase):
    def test_option_and_prerequisites(self):
        off, on = flags_v90(), flags_v90(True)
        self.assertNotIn(DEFINE, off)
        self.assertEqual([f for f in on if f != DEFINE], off)
        self.assertEqual(on.count(DEFINE), 1)
        fresh, sets, _ = installed()
        from cycle_lib.common import Refused  # noqa: E402
        for variant, wide in (('fast', False), ('control', True)):
            args = argparse.Namespace(variant=variant, fast_ipi=True, root_cache_wide=wide)
            with self.subTest(variant=variant, root_cache_wide=wide), self.assertRaises(Refused) as caught:
                fresh.variant_flags(sets, args)
            self.assertIn('--fast-ipi needs', str(caught.exception))
        self.assertIn("p.add_argument('--fast-ipi', action='store_true',", (ROOT / 'tools/cycle.py').read_text())


@unittest.skipUnless(ARGS.build, 'needs --build')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        import run  # noqa: E402
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='fast-ipi-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results, blobs = {}, {}
        base = flags_v90()
        try:
            for label, flags in (('default', base), ('off', base + ['-DSNAP_FAST_IPI=0']), ('on', flags_v90(True))):
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
