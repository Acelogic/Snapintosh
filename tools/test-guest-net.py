#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_GUEST_NET: bind compat/guest-net-link.h to the monitor, the loader and cycle.py
(docs/GUEST-NETWORK-20261019.md).

    python3 tools/test-guest-net.py
    python3 tools/test-guest-net.py --build [--out DIR] [--expect SHA256]

Offline, no hardware and no proxy. It builds and runs tools/test-guest-net.c
(sanitized: ATTACH refusals and references, hostile indices and headers, the
commit's clamps, and an end-to-end run against a model q1n1 and guest), then
requires each weakened header to FAIL it. It checks that probes/xnuboot.c
defaults the define to 0 and keeps every guest-network statement under it;
that ADRENO_GUEST_NET is admitted only with the launch's net and host flags
and the AuxKC-origin check; that POLL2 falls back to POLL on Q1N1_CALL_E_OP;
that the poll floor drops below 20 ms only in a SNAP_GUEST_NET build; that the
define-free layouts hold and the report record sits where
tools/guest_net_report.py reads it (a C-written record decodes, damaged ones
are refused); that the loader advertises the property only for the net launch
word; and that cycle.py admits --guest-net only with --input.

--build also builds xnuboot with v90's flag set from cycle.py's recipe, with
the define absent, =0 and =1: absent == =0, =1 differs, all within the code
budget; --expect requires the default build to have that SHA-256 (v90's
monitor_sha256, e8e85aec...).
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
LINK = (ROOT / 'compat/guest-net-link.h').read_text()
NET = (ROOT / 'compat/guest-net.h').read_text()
DEFINE = '-DSNAP_GUEST_NET=1'
# cycle.py installed-fresh options of installed-fresh-20261019-v90 that change monitor flags.
V90 = ('wfi_resume fast_el0_sysreg service_subclass dart_wiredcnt panic_serve root_miss_fast update_disjoint_fast '
       'root_cache_wide update_check_sparse kernel_pperm_fast ib_budget_1s unmap_mixed prime_secondaries '
       'txm_aspace_wide fine_locks fine_switch fair_token user_hw_walk s2_fault_retry nest_fast detach_fast '
       'root_index other_profile gate_wait fine_hw fast_timer_irq input').split()


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', metavar='SHA256', help='the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (argparse.Namespace(build=False, out=None, expect=None), [])


def code(text):
    """C text without comments."""
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))


def code_lines(text):
    """C text without comments, line numbers kept (a comment leaves its newlines)."""
    text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def function(source, signature):
    return runpy.run_path(str(ROOT / 'tools/test-guard-step.py'))['function'](source, signature)


def installed(**extra):
    """cycle_lib.installed_fresh.variant_flags for v90's options (+ extra)."""
    sys.path.insert(0, str(ROOT / 'tools'))
    import cycle_lib.installed_fresh as fresh  # noqa: E402
    import cycle_lib.speed_test as st  # noqa: E402
    sets, _ = st.flag_sets(ROOT)
    args = argparse.Namespace(variant='fast', **{n: True for n in V90})
    for k, v in extra.items():
        setattr(args, k, v)
    return fresh, sets, args


def flags_v90(on=False):
    fresh, sets, args = installed(guest_net=on)
    return fresh.variant_flags(sets, args)


def compile_test(directory, header_dir=None):
    exe = Path(directory) / 'test-guest-net'
    include = [f'-I{header_dir}'] if header_dir else []
    # A mutant must build and then fail at run time: warnings stay warnings there.
    warnings = ['-w'] if header_dir else ['-Wall', '-Wextra', '-Werror']
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', *warnings,
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *include, '-Icompat',
                    'tools/test-guest-net.c', '-o', str(exe)], cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


# Each weakening of the headers must make the C test fail: (file, old, new).
MUTANTS = {
    'window: tx bound dropped': ('net', 'if (tx > GUEST_NET_SLOTS || rx > GUEST_NET_SLOTS) return GUEST_NET_E_HEADER;',
                                 'if (rx > GUEST_NET_SLOTS) return GUEST_NET_E_HEADER;'),
    'window: rx bound dropped': ('net', 'if (tx > GUEST_NET_SLOTS || rx > GUEST_NET_SLOTS) return GUEST_NET_E_HEADER;',
                                 'if (tx > GUEST_NET_SLOTS) return GUEST_NET_E_HEADER;'),
    'commit: taken unclamped': ('link', 'if (taken > v->tx_avail) {taken = v->tx_avail; l->taken_clamped++;}', ''),
    'commit: filled unclamped': ('link', 'if (filled > v->rx_room) {filled = v->rx_room; l->filled_clamped++;}', ''),
    'attach: references leak on refusal': ('link', '            guest_net_release(o, pa, n);\n', ''),
    'attach: references leak on a bad header': (
        'link', '        guest_net_release(o, pa, GUEST_NET_PAGES);\n        return guest_net_refuse(l, GUEST_NET_E_HEADER);',
        '        return guest_net_refuse(l, GUEST_NET_E_HEADER);'),
    'attach: monitor pages admitted': (
        'link', '        if (o->monitor_page(o->ctx, pa + n * GUEST_NET_ALIGN)) return guest_net_refuse(l, GUEST_NET_E_RANGE);', ''),
    'detach: references kept': ('link', '    guest_net_release(o, l->ring_pa, GUEST_NET_PAGES);\n    l->attached = 0;',
                                '    l->attached = 0;'),
    'prepare: trusts the ring copies': (
        'link', 'if (guest_net_window(tx_head, l->tx_tail, l->rx_head, rx_tail, &w)) {',
        'if (guest_net_window(tx_head, r->tx_tail, r->rx_head, rx_tail, &w)) {'),
    'attach: a second attach keeps the first': ('link', '    guest_net_detach(l, o);\n    if (bytes', '    if (bytes'),
    'attach: straddling the end': ('link', 'pa > o->mem_high - GUEST_NET_RING_BYTES)', 'pa > o->mem_high)'),
    'prepare: a scribbled header stays attached': (
        'link', '        l->ring_lost++;\n        guest_net_detach(l, o);\n        return 0;\n    }\n    uint64_t tx_head',
        '        l->ring_lost++;\n        return 0;\n    }\n    uint64_t tx_head'),
}


class Decision(unittest.TestCase):
    def test_link_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([str(compile_test(d))], capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertIn('PASS:', r.stdout)
        print(r.stdout.strip().splitlines()[-2], file=sys.stderr)

    def test_weakened_headers_fail(self):
        survived = []
        for name, (which, old, new) in MUTANTS.items():
            with tempfile.TemporaryDirectory() as d:
                texts = {'link': LINK, 'net': NET}
                self.assertEqual(texts[which].count(old), 1, name)
                texts[which] = texts[which].replace(old, new)
                (Path(d) / 'guest-net-link.h').write_text(texts['link'])
                (Path(d) / 'guest-net.h').write_text(texts['net'])
                exe = compile_test(d, d)
                if subprocess.run([str(exe)], capture_output=True, timeout=600).returncode == 0:
                    survived.append(name)
        self.assertEqual(survived, [])
        print(f'{len(MUTANTS)} weakened headers, each fails the C test', file=sys.stderr)


class Source(unittest.TestCase):
    def test_default_off_and_gated(self):
        es = (ROOT / 'compat/early-stop.h').read_text()
        self.assertIn('#ifndef SNAP_GUEST_NET\n#define SNAP_GUEST_NET 0\n#endif', es)
        self.assertRegex(es, r'#define EARLY_STOP_F_ALL\s+\(EARLY_STOP_F_GUEST \| EARLY_STOP_F_HOST\)')
        self.assertIn('#define EARLY_STOP_F_NET 16u', es)
        # The floor drops only in a SNAP_GUEST_NET build, only with F_NET; early_stop_host_due uses it.
        self.assertIn('#if SNAP_GUEST_NET\n#define EARLY_STOP_POLL_FLOOR(p) (((p)->flags & EARLY_STOP_F_NET) ? '
                      'EARLY_STOP_POLL_MIN_NET_MS : EARLY_STOP_POLL_MIN_MS)\n#else\n#define EARLY_STOP_POLL_FLOOR(p) '
                      'EARLY_STOP_POLL_MIN_MS\n#endif', es)
        self.assertIn('p->host_poll_ms < EARLY_STOP_POLL_FLOOR(p)', (ROOT / 'compat/early-stop.c').read_text())
        # Every guest-network token in the monitor sits inside #if SNAP_GUEST_NET.
        depth, inside, lines = [], 0, code_lines(SOURCE).split('\n')
        for n, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith('#if'):
                # OUT_GUEST_NET is defined only under SNAP_GUEST_NET, so #ifdef OUT_GUEST_NET gates the same way.
                depth.append(('SNAP_GUEST_NET' in s and not s.startswith('#ifndef')) or s == '#ifdef OUT_GUEST_NET')
            elif s.startswith('#endif'):
                depth.pop()
            elif re.search(r'\b(guest_net\w*|GUEST_NET_\w+|ADRENO_GUEST_NET|EV_GUEST_NET|OUT_GUEST_NET)\b',
                           line) and not s.startswith('#define EV_GUEST_NET'):
                self.assertTrue(any(depth), f'probes/xnuboot.c:{n} outside #if SNAP_GUEST_NET: {s}')
                inside += 1
        self.assertGreater(inside, 40)

    def test_hvc_admission(self):
        body = code(function(SOURCE, 'static void guest_net_hvc('))
        for token in ('EARLY_STOP_F_NET', 'EARLY_STOP_F_HOST', 'early_stop_guest_caller(&p->auxkc, hvc, pa, word, spsr)',
                      'GUEST_NET_E_DISABLED', 'GUEST_NET_E_ORIGIN', 'GUEST_NET_E_OP',
                      'guest_net_attach(l, &o, frame[2], frame[3], &generation)', 'guest_net_detach(l, &o)',
                      'record(c, EV_GUEST_NET'):
            self.assertIn(token, body)
        # The admission checks come before any attach or detach.
        self.assertLess(body.index('early_stop_guest_caller'), body.index('guest_net_attach'))
        self.assertLess(body.index('EARLY_STOP_F_NET'), body.index('early_stop_guest_caller'))
        dispatch = code(SOURCE[SOURCE.index('if (frame[0] == ADRENO_GUEST_STOP) {'):][:600])
        self.assertIn('if (frame[0] == ADRENO_GUEST_NET) {\n                guest_net_hvc(c, frame, *elr, physical_spsr);',
                      dispatch)
        # The ring is held under the virtual ANS's DMA rule, writable.
        self.assertIn('return ans_frame_ref(ctx, pa, 1, release);', SOURCE)

    def test_poll2_and_fallback(self):
        tick = code(function(SOURCE, 'static int early_stop_host_tick('))
        net = tick[tick.index('#if SNAP_GUEST_NET'):tick.index('#else')]
        order = ['guest_net_prepare(&net->link, &o, &net->view)',
                 'early_stop_host_call(c, GUEST_NET_POLL2, (uintptr_t)&r, sizeof r, (uintptr_t)&net->views)',
                 'if (latched == GUEST_NET_CALL_E_OP) {', 'net->link.poll2_unsupported = 1;', 'net_view = 0;',
                 'early_stop_host_call(c, EARLY_STOP_HOST_POLL', 'if (net_view) guest_net_commit(&net->link, &o, &net->view);']
        at = 0
        for token in order:
            found = net.find(token, at)
            self.assertGreaterEqual(found, 0, token)
            at = found + len(token)
        self.assertIn('int net_on = (p->flags & EARLY_STOP_F_NET) && !net->link.poll2_unsupported;', net)
        self.assertIn('#define GUEST_NET_POLL2 4u', SOURCE)
        self.assertIn('#define GUEST_NET_CALL_E_OP UINT64_C(0xffffffffffffffff)', SOURCE)
        # Without the define the poll is byte-for-byte the old call.
        old = tick[tick.index('#else'):tick.index('#endif', tick.index('#else'))]
        self.assertIn('uint64_t latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,\n'
                      '                                            console ? (uintptr_t)&link->view : 0);', old)

    def test_magics_and_layouts_agree(self):
        def le(text):
            return int.from_bytes(text.encode().ljust(8, b'\0'), 'little')
        self.assertIn(f'GUEST_NET_VIEW_MAGIC UINT64_C({le("Q1NETV1"):#018x})', NET)
        self.assertIn(f'GUEST_NET_VIEWS_MAGIC UINT64_C({le("Q1VIEWS1"):#018x})', NET)
        self.assertIn(f'GUEST_NET_REPORT_MAGIC UINT64_C({le("GUESTNT1"):#018x})', SOURCE)
        self.assertIn(f'GUEST_NET_RING_MAGIC {int.from_bytes(b"SNR1", "little"):#x}u', NET)
        rep = runpy.run_path(str(ROOT / 'tools/guest_net_report.py'), run_name='guest_net_report')
        self.assertEqual(rep['MAGIC'], le('GUESTNT1'))
        self.assertEqual(len(rep['LINK']), int(re.search(r'#define GUEST_NET_LINK_WORDS (\d+)', LINK).group(1)))
        self.assertEqual(len(rep['VIEW']), int(re.search(r'#define GUEST_NET_VIEW_WORDS (\d+)', NET).group(1)))

    def test_loader(self):
        ad = (ROOT / 'probes/adreno.py').read_text()
        self.assertIn("NET_ABI_PROPERTY = 'snapintosh,guest-net-abi'", ad)
        self.assertIn('#define GUEST_NET_PROPERTY "snapintosh,guest-net-abi"', NET)
        xb = (ROOT / 'probes/xnuboot.py').read_text()
        self.assertIn('        if EARLY_STOP is not None and EARLY_STOP.net:\n            adreno.advertise_guest_net(dt)\n', xb)
        sys.path.insert(0, str(ROOT / 'tools'))
        import early_stop  # noqa: E402
        s = early_stop.settings({'SNAP_EARLY_STOP': 'guest,console,net'})
        self.assertTrue(s.net and s.host and s.console)
        self.assertEqual((s.flags, s.poll_ms), (1 | 2 | 4 | 16, 5))
        self.assertEqual(early_stop.settings({'SNAP_EARLY_STOP': 'net', 'SNAP_EARLY_STOP_POLL_MS': '2'}).poll_ms, 2)
        for env in ({'SNAP_EARLY_STOP': 'net', 'SNAP_EARLY_STOP_POLL_MS': '1'},
                    {'SNAP_EARLY_STOP': 'console', 'SNAP_EARLY_STOP_POLL_MS': '5'}):
            with self.assertRaises(ValueError):
                early_stop.settings(env)
        self.assertFalse(early_stop.settings({'SNAP_EARLY_STOP': 'guest,console'}).net)


class Layout(unittest.TestCase):
    def test_define_free_layouts_hold(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        off, on = flags_v90(), flags_v90(True)
        self.assertEqual([f for f in on if f != DEFINE], off)
        a = perf['_records'](ROOT / 'probes/xnuboot.c', [f for f in off if f.startswith('-D')])
        b = perf['_records'](ROOT / 'probes/xnuboot.c', [f for f in on if f.startswith('-D')])
        for name in ('vcpu', 'perf_state', 'fast_trap_cpu', 'service_profile', 'root_ext', 'early_stop_state'):
            if name in a:
                self.assertEqual(a[name].split('\n', 1)[1], b[name].split('\n', 1)[1], name)
        # The context gains one pointer: every earlier field keeps its offset, the page count holds.
        fields = re.findall(r'^\s*(\d+) \|   \S.* (\w+)$', a['context'], re.M)
        self.assertGreater(len(fields), 100)
        for at, name in fields:
            if name != 'exit_profile':
                self.assertEqual(perf['_offset'](b['context'], name), int(at), name)
        self.assertLessEqual(perf['_offset'](b['context'], 'guest_net') + 8, perf['_offset'](b['context'], 'exit_profile'))
        self.assertEqual((perf['_size'](a['context']) + 4095) // 4096, (perf['_size'](b['context']) + 4095) // 4096)
        self.assertNotIn('guest_net_state', a)
        self.assertIn('guest_net_state', b)

    def test_report_offset_is_the_monitors(self):
        rep = runpy.run_path(str(ROOT / 'tools/guest_net_report.py'), run_name='guest_net_report')
        flags = [f for f in flags_v90(True) if f.startswith('-D')]
        offset = rep['offset'](flags)
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / 'probe.c'
            probe.write_text(f'#include "{ROOT}/probes/xnuboot.c"\n'
                             f'_Static_assert(16 + 8*OUT_GUEST_NET == {offset}, "report offset");\n'
                             f'_Static_assert(8*GUEST_NET_LINK_WORDS == {8 * len(rep["LINK"])}, "link size");\n')
            r = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                                '-fsyntax-only', f'-I{ROOT / "shadow"}', f'-I{ROOT / "compat"}', *flags, str(probe)],
                               cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-1500:])


WRITER = r'''
#include <stdio.h>
#include "guest-net-link.h"
int main(int argc, char **argv)
{
    (void)argc;
    struct guest_net_link l = {0}; struct guest_net_view v = {0};
    uint64_t head[2] = {UINT64_C(0x31544e5453455547), 1 | (uint64_t)sizeof l << 32};
    l.attached = 1; l.ring_pa = 0x812340000; l.generation = 2; l.tx_tail = 1000; l.rx_head = 2000;
    l.attaches = 2; l.detaches = 1; l.refusals = 3; l.last_refusal = (uint64_t)(int64_t)GUEST_NET_E_FRAME;
    l.polls = 50000; l.views = 49000; l.frames_out = 1000; l.frames_in = 2000; l.poll2_unsupported = 0;
    v.magic = GUEST_NET_VIEW_MAGIC; v.version = 1; v.slots = 32; v.slot_bytes = 2048; v.frame_max = 1294;
    v.requests = 7000; v.frames_in = 2000; v.frames_out = 1000; v.owner = 0x1234; v.polls_seen = 49000;
    FILE *f = fopen(argv[1], "wb"); fwrite(head, sizeof head, 1, f); fwrite(&l, sizeof l, 1, f);
    fwrite(&v, sizeof v, 1, f); fclose(f);
    printf("%zu\n", sizeof head + sizeof l + sizeof v);
    return 0;
}
'''


class Decoder(unittest.TestCase):
    def test_decode_a_c_written_record(self):
        rep = runpy.run_path(str(ROOT / 'tools/guest_net_report.py'), run_name='guest_net_report')
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'w.c').write_text(WRITER)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-Icompat', str(Path(d) / 'w.c'), '-o', str(Path(d) / 'w')],
                           cwd=ROOT, check=True)
            size = int(subprocess.run([str(Path(d) / 'w'), str(Path(d) / 'r.bin')], check=True,
                                      capture_output=True, text=True).stdout)
            raw = (Path(d) / 'r.bin').read_bytes()
        self.assertEqual(size, 16 + 8 * (len(rep['LINK']) + len(rep['VIEW'])))
        out = rep['decode'](raw)
        self.assertTrue(out['enabled'])
        self.assertEqual((out['link']['frames_out'], out['link']['frames_in'], out['link']['ring_pa'],
                          out['link']['last_refusal']), (1000, 2000, '0x812340000', 'frame'))
        self.assertEqual((out['view']['requests'], out['view']['owner'], out['view']['frame_max']), (7000, 0x1234, 1294))
        for at, value in ((0, 0), (8, 1 | 200 << 32), (8, 3 | 192 << 32), (16 + 8 * 19, 1)):
            bad = bytearray(raw)
            struct.pack_into('<Q', bad, at, value)
            with self.assertRaises(ValueError, msg=f'{at}={value}'):
                rep['decode'](bytes(bad))
        with self.assertRaises(ValueError):
            rep['decode'](raw[:-8])


class Cycle(unittest.TestCase):
    def test_option_and_prerequisites(self):
        fresh, sets, args = installed(guest_net=True)
        flags = fresh.variant_flags(sets, args)
        self.assertEqual(flags.count(DEFINE), 1)
        self.assertEqual(flags[-1], DEFINE)
        fresh, sets, args = installed(guest_net=True, input=False)
        from cycle_lib.common import Refused  # noqa: E402
        with self.assertRaises(Refused):
            fresh.variant_flags(sets, args)
        fresh, sets, args = installed(guest_net=True, console=True)
        env = fresh.environment(args)
        self.assertEqual(env['SNAP_EARLY_STOP'].split(','), ['guest', 'console', 'net'])
        fresh, sets, args = installed(console=True)
        self.assertNotIn('net', fresh.environment(args)['SNAP_EARLY_STOP'])
        help_text = subprocess.run([sys.executable, 'tools/cycle.py', 'installed-fresh', '--help'], cwd=ROOT,
                                   capture_output=True, text=True).stdout
        self.assertIn('--guest-net', help_text)


class Build(unittest.TestCase):
    @unittest.skipUnless(ARGS.build, 'needs --build')
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='guest-net-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results, blobs = {}, {}
        base = flags_v90()
        try:
            for label, flags in (('default', base), ('off', base + ['-DSNAP_GUEST_NET=0']), ('on', flags_v90(True))):
                run.FLAGS[:] = flags
                blob = blobs[label] = run.build('xnuboot', out / label)
                results[label] = dict(bytes=len(blob), headroom=budget - len(blob), sha256=hashlib.sha256(blob).hexdigest())
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
