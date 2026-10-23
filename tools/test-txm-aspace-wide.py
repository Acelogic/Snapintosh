#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_TXM_ASPACE_WIDE: 4096 TXM address spaces instead of 512 (compat/txm.h A1-A9).

    python3 tools/test-txm-aspace-wide.py
    python3 tools/test-txm-aspace-wide.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]
    python3 tools/test-txm-aspace-wide.py --v47 build/installed-fresh-20261017-v47

Offline, no hardware and no proxy. Run v47 stopped on TXM35 (ASID 0x1552,
SPTM_MEMORY_UNAVAILABLE) with all 512 slots live. This builds and runs
tools/test-txm-aspace-churn.c (sanitized) with the 8-page arena, where the
v47-like lifecycle of 5,457 address spaces through the real SPTM retype and
binding paths must end in exactly that refusal with nothing changed, and with
-DSNAP_TXM_ASPACE_WIDE=1, where the same request is admitted and the arena
fills to exactly 4096 and drains back to zero; then requires mutants of
compat/txm.c (a release that keeps the slot, no slot reuse, a kept binding, a
kept shared count, an early or late limit) and of compat/txm.h (the define
ignored) to FAIL it. Every other TXM/SPTM host suite runs at both widths.

It checks the monitor wiring (the live registry in arena pages after the
context and root_ext, zeroed at setup and excluded from the coverage
sentinel, the stop-time mirror, the prepare-time layout refusal, no direct
struct context registry use), that every define-free struct context offset
and its page count are unchanged, that the twin matches the default record,
the loader's 64-page layout (image built both ways when the local firmware is
present) against the monitor's prepare rules, and cycle.py's wiring of the
define and the launch parameter together.

--build compiles xnuboot with the control/fast/fast-wfi flag sets with the
define absent, =0 and =1 (-Werror, code budget, absent == =0, =1 differs),
and v47's flag set with it; --expect pins a default build.
--v47 DIR decodes that run's context.bin registry and checks its consistency
(skipped when absent).
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
TXM_C = read_source(ROOT / 'compat/txm.c')
TXM_H = (ROOT / 'compat/txm.h').read_text()
WIDE = '-DSNAP_TXM_ASPACE_WIDE=1'
CORE = ['compat/txm.c', 'compat/txm-copy.c', 'compat/sptm.c', 'compat/sptm-root.c', 'compat/sptm-user.c',
        'compat/sptm-refs.c', 'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/sptm-dart.c',
        'compat/dart.c', 'shadow/mmu.c', 'shadow/shadow.c']
SUITES = ['test-txm.c', 'test-sptm-shared-root.c', 'test-sptm-shared-binding.c', 'test-txm-shared-region.c',
          'test-sptm-shared-region.c', 'test-sptm-root-config.c', 'test-sptm-reclaim.c', 'test-static-trust.c',
          'test-txm-trust-query.c', 'test-txm-image4.c', 'test-txm-local-key.c', 'test-txm-nonce.c',
          'test-txm-nonce-digest.c', 'test-txm-release-type.c', 'test-txm-sep-channel.c']
V47_DEFAULT = ROOT / 'build/installed-fresh-20261017-v47'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    ap.add_argument('--v47', default=str(V47_DEFAULT), help='a preserved run directory holding context.bin')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[], v47=str(V47_DEFAULT)), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def compile_c(directory, test, defines, txm_c=None, txm_h=None, name=None):
    """txm_c/txm_h: mutated texts, compiled from copies searched before compat/."""
    exe = Path(directory) / (name or Path(test).stem)
    include, sources = [], list(CORE)
    if txm_c is not None or txm_h is not None:
        mut = Path(directory) / 'mut'
        mut.mkdir(exist_ok=True)
        (mut / 'txm.h').write_text(TXM_H if txm_h is None else txm_h)
        (mut / 'txm.c').write_text(TXM_C if txm_c is None else txm_c)
        include = [f'-I{mut}']
        sources = [str(mut / 'txm.c') if s == 'compat/txm.c' else s for s in sources]
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *defines, *include,
                    '-Icompat', '-Ishadow', f'tools/{test}', *sources, '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


def run(exe):
    return subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=1800)


# Each must make tools/test-txm-aspace-churn.c fail at run time (they compile).
MUTANTS = {
    'TXM36 keeps the slot': ('txm.c', 'r->root[slot] = selector == 35 ? root : 0;',
                             'r->root[slot] = selector == 35 ? root : r->root[slot];', ['', WIDE]),
    'TXM35 never reuses a slot': ('txm.c', 'if (!r->root[n] && slot == r->count) slot = n;',
                                  'if (0 && !r->root[n] && slot == r->count) slot = n;', ['', WIDE]),
    'TXM36 keeps the binding': ('txm.c', '    r->bound_shared[slot]=0;\n    if (slot == r->count) r->count++;',
                                '    if (slot == r->count) r->count++;', ['', WIDE]),
    'unbind keeps the shared count': ('txm.c',
        'store32(parent_object+TXM_SHARED_REFS,load32(parent_object+TXM_SHARED_REFS)-1);',
        'store32(parent_object+TXM_SHARED_REFS,load32(parent_object+TXM_SHARED_REFS));', ['', WIDE]),
    'limit one early': ('txm.c', 'if (slot == TXM_ASPACE_LIMIT) return SPTM_MEMORY_UNAVAILABLE;',
                        'if (slot + 1 >= TXM_ASPACE_LIMIT) return SPTM_MEMORY_UNAVAILABLE;', ['', WIDE]),
    'limit one late': ('txm.c', 'if (slot == TXM_ASPACE_LIMIT) return SPTM_MEMORY_UNAVAILABLE;',
                       'if (slot > TXM_ASPACE_LIMIT) return SPTM_MEMORY_UNAVAILABLE;', ['', WIDE]),
    'wide define ignored': ('txm.h', '#if SNAP_TXM_ASPACE_WIDE\n#define TXM_ASPACE_PAGES 64u\n',
                            '#if SNAP_TXM_ASPACE_WIDE\n#define TXM_ASPACE_PAGES 8u\n', [WIDE]),
}


class Churn(unittest.TestCase):
    def test_narrow_reproduces_the_v47_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            result = run(compile_c(d, 'test-txm-aspace-churn.c', []))
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-3000:])
        self.assertIn('narrow arena: TXM35 ASID 0x1552 refused (SPTM_MEMORY_UNAVAILABLE), state unchanged',
                      result.stdout)
        self.assertIn('full arena: 512 slots', result.stdout)
        for line in result.stdout.strip().splitlines():
            print('narrow: ' + line, file=sys.stderr)

    def test_wide_admits_it_and_fills_to_4096(self):
        with tempfile.TemporaryDirectory() as d:
            result = run(compile_c(d, 'test-txm-aspace-churn.c', [WIDE]))
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-3000:])
        self.assertIn('wide arena: TXM35 ASID 0x1552 admitted in slot 512', result.stdout)
        self.assertIn('full arena: 4096 slots', result.stdout)
        for line in result.stdout.strip().splitlines():
            print('wide: ' + line, file=sys.stderr)

    def test_mutants_fail(self):
        for label, (name, old, new, widths) in MUTANTS.items():
            text = TXM_C if name == 'txm.c' else TXM_H
            self.assertEqual(text.count(old), 1, label)
            mutated = text.replace(old, new)
            for width in widths:
                with self.subTest(label, width=width or 'narrow'), tempfile.TemporaryDirectory() as d:
                    exe = compile_c(d, 'test-txm-aspace-churn.c', [width] if width else [],
                                    txm_c=mutated if name == 'txm.c' else None,
                                    txm_h=mutated if name == 'txm.h' else None)
                    self.assertNotEqual(run(exe).returncode, 0, f'{label} ({width or "narrow"}) survived')


class Suites(unittest.TestCase):
    def test_existing_suites_both_widths(self):
        with tempfile.TemporaryDirectory() as d:
            for test in SUITES:
                for width in ('', WIDE):
                    with self.subTest(test, width=width or 'narrow'):
                        exe = compile_c(d, test, [width] if width else [],
                                        name=Path(test).stem + ('-wide' if width else ''))
                        result = run(exe)
                        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
                        last = result.stdout.strip().splitlines()[-1]
                        print(f'{test} {"wide" if width else "narrow"}: {last}', file=sys.stderr)


class Source(unittest.TestCase):
    def test_default_off(self):
        self.assertIn('#ifndef SNAP_TXM_ASPACE_WIDE\n#define SNAP_TXM_ASPACE_WIDE 0\n#endif\n'
                      '#if SNAP_TXM_ASPACE_WIDE\n#define TXM_ASPACE_PAGES 64u\n#else\n#define TXM_ASPACE_PAGES 8u\n'
                      '#endif\n', TXM_H)
        self.assertIn('#else\n#define TXM_REG(c) (&(c)->txm_registry)\n#endif\n', SOURCE)
        self.assertIn('#if SNAP_TXM_ASPACE_WIDE\n    /* Define-free 512-slot twin', SOURCE)
        self.assertIn('#else\n    struct txm_registry txm_registry;\n#endif\n', SOURCE)

    def test_every_registry_use_goes_through_txm_reg(self):
        # Only the default TXM_REG and the stop-time mirror's twin name the context field.
        self.assertEqual(re.findall(r'c\)?->txm_registry\w*', SOURCE), ['c)->txm_registry', 'c->txm_registry_host'])
        self.assertGreaterEqual(len(re.findall(r'TXM_REG\(c\)', SOURCE)), 14)
        dispatch = between(SOURCE, 'endpoint == 35 || endpoint == 36 || endpoint == 37 ?', ':\n')
        self.assertIn('txm_aspace(&memory, &service, &arena, TXM_REG(c), endpoint, frame)', dispatch)
        for fn, token in (('static int sptm_retire_user_root(', 'TXM_REG(c)->count'),
                          ('static int sptm_share_user_root(', 'txm_share_prepare(&memory,&arena,TXM_REG(c),'),
                          ('static int sptm_retire_shared_root(', 'TXM_REG(c)->count'),
                          ('static int sptm_bind_shared_root(', 'txm_bind_shared(&memory,&arena,TXM_REG(c),')):
            self.assertIn(token, between(SOURCE, fn, '\n}\n'), fn)

    def test_arena_pages_after_context_and_root_ext(self):
        self.assertIn('#define TXM_EXT_PAGES ((sizeof(struct txm_registry)+4095)/4096)', SOURCE)
        self.assertIn('#if SNAP_ROOT_CACHE_WIDE\n#define TXM_EXT_AFTER_ROOT (ROOT_EXT_PAGES*4096)\n#else\n'
                      '#define TXM_EXT_AFTER_ROOT 0\n#endif\n', SOURCE)
        self.assertIn('#define TXM_EXT_OFFSET ((((uint64_t)sizeof(struct context)+0xfffUL)&~0xfffUL)'
                      '+(uint64_t)TXM_EXT_AFTER_ROOT)', SOURCE)
        setup = between(SOURCE, 'int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,\n'
                        '                  const struct secondary_config *host_cpus)\n{', '\n}\n')
        carve = between(setup, '#if SNAP_TXM_ASPACE_WIDE\n    /* The TXM registry follows', '#endif')
        self.assertIn('if ((work & 0xfff) || size < TXM_EXT_OFFSET + TXM_EXT_PAGES * 4096 + 4096) return 1;', carve)
        self.assertIn('((volatile uint64_t *)TXM_REG(c))[n] = 0;', carve)
        # Zeroed before the first use and after root_ext is placed; bumped after root_ext.
        self.assertLess(setup.index('c->root_ext = '), setup.index('/* The TXM registry follows'))
        self.assertLess(setup.index('/* The TXM registry follows'), setup.index('c->params = '))
        self.assertIn('    c->work_base = c->next_table;\n#if SNAP_ROOT_CACHE_WIDE\n'
                      '    c->next_table += ROOT_EXT_PAGES * 4096;\n#endif\n#if SNAP_TXM_ASPACE_WIDE\n'
                      '    if (c->next_table != (uint64_t)TXM_REG(c)) return 1;\n'
                      '    c->next_table += TXM_EXT_PAGES * 4096;\n#endif\n', setup)
        exclude = between(SOURCE, 'static int txn_publish_exclude(void *ctx,uint64_t page)\n{', '\n}\n')
        self.assertIn('if(page>=(uint64_t)TXM_REG(c) && page-(uint64_t)TXM_REG(c)<TXM_EXT_PAGES*4096)return 1;',
                      exclude)

    def test_prepare_refuses_the_narrow_layout(self):
        prepare = between(SOURCE, 'int64_t xnuboot_prepare(void)\n{', '\n}\n')
        ordered = [prepare.index('panic_page<p->txm_aspace_pa+TXM_ASPACE_SIZE+3*0x4000'),
                   prepare.index('#if SNAP_TXM_ASPACE_WIDE\n'),
                   prepare.index('if(p->uat.reserved_pa!=p->txm_aspace_pa+TXM_ASPACE_SIZE)return -22;'),
                   prepare.index('sptm_panic_init(&c->panic_state);')]
        self.assertEqual(ordered, sorted(ordered))

    def test_mirror_at_the_stop(self):
        report = between(SOURCE, 'uint64_t xnuboot_report(uint64_t *out)\n{', '\n}\n')
        self.assertLess(report.index('Every executor has quiesced'), report.index('txm_ext_mirror(c);'))
        self.assertLess(report.index('txm_ext_mirror(c);'), report.index('gpu_quiesce(c);'))
        self.assertEqual(SOURCE.count('txm_ext_mirror(c);'), 1)
        mirror = between(SOURCE, 'static void txm_ext_mirror(struct context *c)\n{', '\n}\n')
        for field in ('h->root[i]=r->root[i]', 'h->asid[i]=r->asid[i]', 'h->shared[i]=r->shared[i]',
                      'h->region_start[i]=r->region_start[i]', 'h->region_end[i]=r->region_end[i]',
                      'h->bound_shared[i]=r->bound_shared[i]', 'h->count=r->count', 'h->region_sets=r->region_sets',
                      'h->bindings=r->bindings', 'h->unbindings=r->unbindings', 'i<TXM_ASPACE_LIMIT_COMPAT'):
            self.assertIn(field, mirror)


def records(defines):
    sys.path.insert(0, str(ROOT / 'tools'))
    perf = importlib.import_module('perf_counters')
    return perf, perf._records(ROOT / 'probes/xnuboot.c', [d for d in defines if d.startswith('-D')])


def fields(block):
    return [(int(o), t, n) for o, t, n in re.findall(r'^\s*(\d+) \|   (\S.*) (\w+)$', block, re.M)]


def flag_sets():
    spec = importlib.util.spec_from_file_location('wfi_resume', ROOT / 'tools/test-wfi-resume.py')
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [saved[0]]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    sets, _ = module.flag_sets()
    sets['fast-wfi'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1']
    # The v47 launch's opt-in stack (cycle.py installed-fresh --variant fast with its options).
    sets['fast-stack'] = sets['fast'] + ['-DSNAP_WFI_RESUME=1', '-DSNAP_FAST_EL0_SYSREG=1', '-DSNAP_SERVICE_SUBCLASS=1',
                                         '-DSNAP_DART_WIREDCNT=1', '-DSNAP_PANIC_SERVE=1', '-DSNAP_ROOT_MISS_FAST=1',
                                         '-DSNAP_UPDATE_DISJOINT_FAST=1', '-DSNAP_ROOT_CACHE_WIDE=1',
                                         '-DSNAP_UPDATE_CHECK_SPARSE=1', '-DSNAP_I2C_INPUT=1',
                                         '-DSNAP_KERNEL_PPERM_FAST=1', '-DADRENO_IB_POLL_DIVISOR=1u',
                                         '-DSNAP_UNMAP_MIXED=1']
    return sets


class Layout(unittest.TestCase):
    def test_define_free_offsets_and_arena_base(self):
        renamed = {'txm_registry_host': 'txm_registry'}
        for name, flags in flag_sets().items():
            perf, off = records(flags)
            _, on = records(flags + [WIDE])
            a = {n: (o, t) for o, t, n in fields(off['context'])}
            b = {renamed.get(n, n): (o, t) for o, t, n in fields(on['context'])}
            self.assertEqual(set(a), set(b), name)
            for field, (offset, _) in a.items():
                self.assertEqual(b[field][0], offset, f'{name}: {field}')
            self.assertEqual(perf._size(off['context']), perf._size(on['context']), name)
            self.assertEqual(a['txm_registry'][0], 8, name)
            self.assertEqual([(o, n) for o, _, n in fields(on['txm_registry_compat'])],
                             [(o, n) for o, _, n in fields(off['txm_registry'])], name)
            self.assertEqual(perf._size(on['txm_registry_compat']), perf._size(off['txm_registry']), name)
            wide = perf._size(on['txm_registry'])
            self.assertEqual(wide, 35 * 4096 + 32, name)
            self.assertEqual(re.findall(r'(\d+) \|   uint64_t\[(\d+)\] root$', on['txm_registry'], re.M), [('0', '4096')])
            size = perf._size(on['context'])
            print(f'{name}: context {size} bytes ({(size + 4095) // 4096} pages) unchanged; live registry '
                  f'{wide} bytes = {(wide + 4095) // 4096} arena pages', file=sys.stderr)


def load_loader():
    sys.path[:0] = [str(ROOT / 'probes'), str(ROOT / 'tools')]
    spec = importlib.util.spec_from_file_location('xnuboot_txm_wide', ROOT / 'probes/xnuboot.py')
    xb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(xb)
    return xb


def monitor_prepare_rules(built, panic_page, size, wide):
    """xnuboot_prepare's arena rules, in Python: the panic page above the arena and
    three UAT pages, and (wide builds) UAT directly after the whole arena."""
    ok = panic_page >= built['txm_aspace_pa'] + size + 3 * 0x4000
    if wide:
        ok = ok and built['uat_pa'] == built['txm_aspace_pa'] + size
    return ok


class Loader(unittest.TestCase):
    def test_configure_arithmetic_and_restore(self):
        xb = load_loader()
        defaults = (xb.TXM_ASPACE_PAGES, xb.SCRATCH_OFFSET, xb.SPTM_DATA_SPAN, xb.SCRATCH_PA)
        self.assertEqual(defaults[:3], (8, 0x480000, 0x500000))
        self.assertEqual(xb.configure_txm_arena(True), 64)
        self.assertEqual((xb.SCRATCH_OFFSET, xb.SPTM_DATA_SPAN), (0x480000 + 56 * 0x4000, 0x600000))
        self.assertEqual(xb.SCRATCH_PA, xb.SPTM_DATA_PA + xb.SCRATCH_OFFSET)
        self.assertLessEqual(xb.SCRATCH_OFFSET + xb.SCRATCH_SPAN, xb.SPTM_DATA_SPAN)
        begin, end = xb.static_trust_window(xb.SCRATCH_COUNT)
        self.assertEqual(end - begin, 10 * 0x4000)
        self.assertEqual(xb.configure_txm_arena(False), 8)
        self.assertEqual((xb.TXM_ASPACE_PAGES, xb.SCRATCH_OFFSET, xb.SPTM_DATA_SPAN, xb.SCRATCH_PA), defaults)
        saved = os.environ.get(xb.TXM_ASPACE_WIDE_ENV)
        try:
            for value, pages in (('1', 64), ('0', 8)):
                os.environ[xb.TXM_ASPACE_WIDE_ENV] = value
                self.assertEqual(xb.configure_txm_arena(), pages)
            os.environ.pop(xb.TXM_ASPACE_WIDE_ENV)
            self.assertEqual(xb.configure_txm_arena(), 8)
            for bad in ('2', 'yes', ''):
                os.environ[xb.TXM_ASPACE_WIDE_ENV] = bad
                with self.assertRaises(ValueError):
                    xb.configure_txm_arena()
        finally:
            os.environ.pop(xb.TXM_ASPACE_WIDE_ENV, None)
            if saved is not None:
                os.environ[xb.TXM_ASPACE_WIDE_ENV] = saved
        # The installed route's placement (8 GiB at 0x8c0000000) validates both ways.
        import monitor_work
        for wide in (False, True):
            xb.configure_txm_arena(wide)
            span = 8192 << 20
            xb.place(0x8c0000000, span + xb.bootstrap_reserve(span) + monitor_work.WORK_SIZE, guest_span=span)
            self.assertEqual(xb.SCRATCH_PA, xb.SPTM_DATA_PA + (0x480000 + (56 * 0x4000 if wide else 0)))
        xb.configure_txm_arena(False)

    def test_image_both_ways(self):
        probe = load_loader()
        if not probe.DEFAULT_KERNELCACHE.is_file():
            self.skipTest(f'no local firmware at {probe.DEFAULT_KERNELCACHE}')
        layouts = {}
        for wide in (False, True):
            xb = load_loader()
            xb.configure_txm_arena(wide)
            with contextlib.redirect_stdout(io.StringIO()):
                built = xb.build(str(xb.DEFAULT_KERNELCACHE))
            size = xb.TXM_ASPACE_PAGES * 0x4000
            panic_page = xb.panic_state_reservation()[0]
            arena = (built['txm_aspace_pa'], built['txm_aspace_pa'] + size)
            # Zero, owned, contiguous, below the allocator, inside the guest's aperture and stage-2 DRAM.
            for pa in range(arena[0], arena[1], 0x4000):
                self.assertEqual(built['chunks'].get(pa), bytes(0x4000), hex(pa))
            self.assertLessEqual(arena[1], built['alloc_low'])
            self.assertTrue(xb.PHYS_BASE <= arena[0] < arena[1] <= xb.REGION_END)
            ranges = xb.stage2_ranges()
            self.assertTrue(any(lo <= arena[0] and arena[1] <= hi and access == 'rw' for lo, hi, access, _ in ranges))
            self.assertEqual(built['uat_pa'], arena[1])
            self.assertEqual(xb.static_trust_window(xb.SCRATCH_COUNT), (arena[1] + 3 * 0x4000, panic_page))
            self.assertEqual(panic_page + 0x4000, xb.SCRATCH_PA)
            data = (xb.SPTM_DATA_PA, xb.SPTM_DATA_PA + xb.SPTM_DATA_SPAN)
            spans = sorted((pa, pa + len(blob)) for pa, blob in built['chunks'].items()
                           if data[0] <= pa < data[1])
            for (a0, a1), (b0, _) in zip(spans, spans[1:]):
                self.assertLessEqual(a1, b0, f'monitor-data chunks {a0:#x}..{a1:#x} and {b0:#x} overlap')
            self.assertLessEqual(spans[-1][1], data[1])
            self.assertLessEqual(data[1], built['alloc_low'])
            # The monitor built for this layout accepts it; the other build refuses
            # the narrow layout (and runs the wide one on its first 8 pages).
            self.assertTrue(monitor_prepare_rules(built, panic_page, size, wide))
            other = (8 if wide else 64) * 0x4000
            self.assertEqual(monitor_prepare_rules(built, panic_page, other, not wide), wide)
            layouts[wide] = dict(arena=arena, uat=built['uat_pa'], panic=panic_page, scratch=xb.SCRATCH_PA,
                                 alloc_low=built['alloc_low'], handles=(xb.APERTURE_VA + arena[0] - xb.PHYS_BASE,
                                                                        xb.APERTURE_VA + arena[1] - xb.PHYS_BASE))
        self.assertEqual(layouts[True]['arena'][0], layouts[False]['arena'][0])
        self.assertEqual(layouts[True]['scratch'] - layouts[False]['scratch'], 56 * 0x4000)
        self.assertEqual(layouts[True]['alloc_low'] - layouts[False]['alloc_low'], 1 << 20)
        for wide, l in layouts.items():
            print(f'{"wide" if wide else "narrow"}: arena {l["arena"][0]:#x}..{l["arena"][1]:#x} (handles '
                  f'{l["handles"][0]:#x}..{l["handles"][1]:#x}), UAT {l["uat"]:#x}, panic {l["panic"]:#x}, '
                  f'scratch {l["scratch"]:#x}, avail_start {l["alloc_low"]:#x}', file=sys.stderr)


class Cycle(unittest.TestCase):
    def test_define_and_launch_parameter_together(self):
        sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'probes')]
        module = importlib.import_module('cycle_lib.installed_fresh')
        sets = {'fast': ['-DX=1'], 'control': ['-DX=1']}
        on = types.SimpleNamespace(variant='fast', txm_aspace_wide=True)
        off = types.SimpleNamespace(variant='fast', txm_aspace_wide=False)
        self.assertIn(WIDE, module.variant_flags(sets, on))
        self.assertNotIn(WIDE, module.variant_flags(sets, off))
        self.assertEqual(module.environment(on).get('SNAP_TXM_ASPACE_WIDE'), '1')
        self.assertNotIn('SNAP_TXM_ASPACE_WIDE', module.environment(off))
        self.assertEqual(module.environment(off), module.ENV)
        text = (ROOT / 'tools/cycle_lib/installed_fresh.py').read_text()
        self.assertIn("    xb.configure_guest(profile_name, root / FIRMWARE)\n"
                      "    xb.configure_txm_arena(bool(getattr(args, 'txm_aspace_wide', False)))\n", text)
        self.assertIn("p.add_argument('--txm-aspace-wide', action='store_true',", (ROOT / 'tools/cycle.py').read_text())
        run_py = (ROOT / 'probes/run.py').read_text()
        self.assertLess(run_py.index('xb.configure_txm_arena()'), run_py.index('xb.place(start, end - start'))


@unittest.skipUnless(Path(ARGS.v47, 'context.bin').is_file(), 'no preserved v47 context.bin')
class V47(unittest.TestCase):
    def test_registry_is_full_and_consistent(self):
        raw = (Path(ARGS.v47) / 'context.bin').read_bytes()
        _, off = records([])
        reg = off['txm_registry']
        base = 8
        o = {n: int(x) for x, _, n in fields(reg)}
        L = 512
        root = struct.unpack_from(f'<{L}Q', raw, base + o['root'])
        asid = struct.unpack_from(f'<{L}H', raw, base + o['asid'])
        count = struct.unpack_from('<I', raw, base + o['count'])[0]
        shared = raw[base + o['shared']:base + o['shared'] + L]
        bound = struct.unpack_from(f'<{L}Q', raw, base + o['bound_shared'])
        bindings, unbindings = struct.unpack_from('<2Q', raw, base + o['bindings'])
        live = [i for i in range(L) if root[i]]
        ids = [asid[i] for i in live if not shared[i]]
        self.assertEqual((count, len(live)), (512, 512))
        self.assertEqual(sorted(asid[i] for i in live if shared[i]), [0, 1, 2, 3])
        self.assertEqual((len(ids), len(set(ids)), len(set(root[i] for i in live))), (508, 508, 512))
        bound_live = sum(1 for i in live if bound[i])
        self.assertEqual(bindings - unbindings, bound_live)
        self.assertEqual(max(ids), 0x1551)
        newest = next(i for i in live if not shared[i] and asid[i] == 0x1551)
        self.assertEqual(bound[newest], 0)
        print(f'v47: {count} slots, {len(live)} live (4 shared, {len(ids)} address spaces, {bound_live} bound), '
              f'{bindings} bindings, {unbindings} unbindings, ASIDs up to {max(ids):#x}, none live in 9..815',
              file=sys.stderr)
        self.assertFalse([a for a in ids if 9 <= a <= 815])


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a few minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run as monitor_run  # noqa: E402
        sets = flag_sets()
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='txm-aspace-wide-build-'))
        budget = monitor_run.OUT_AT - monitor_run.CODE_AT
        saved = list(monitor_run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                labels = (('default', []), ('off', ['-DSNAP_TXM_ASPACE_WIDE=0']), ('on', [WIDE]))
                for label, extra in labels:
                    if name == 'fast-stack' and label == 'off':
                        continue
                    monitor_run.FLAGS[:] = flags + extra
                    blob = monitor_run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0, f'{name}-{label}')
                if 'off' in blobs:
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
