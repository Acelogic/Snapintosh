#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_DART_WIREDCNT: bind compat/dart-wiredcnt.h to the monitor, the kext
and the pinned 26A428 kernel.

    python3 tools/test-dart-wiredcnt.py
    python3 tools/test-dart-wiredcnt.py --build [--out DIR]
                        [--expect control=SHA256 --expect fast=SHA256]

Offline, no hardware and no proxy. It builds and runs tools/test-dart-wiredcnt.c
(sanitized: 200 unwire/rewire cycles through the real SPTM DART model and
adreno_guest_unmap with the leaf table in vm_pages and below it, the first
clear of a fresh table, mixed XNU/HVC clears, the held table reference, radix
trees of 0..4 levels, every refusal, the templates), checks
that the v29 monitor's behaviour (-DDWC_PRE_CHANGE=1) overflows the count, and
requires weakened deciders to FAIL. Against the pinned kernelcache it finds the
template exactly once, at pmap_ref_iommu_table, and decodes vm_first_phys,
vm_last_phys, vm_pages_first_pnum, vm_pages_count and vm_pages inside the const
prefix, and through the function's own call site below vm_pages the radix
lookup vm_page_find_canonical_radix with pmap_first_pnum and
vm_pages_radix_root. The v46 decider (no radix path) and the v40 bound
(n + 1) are among the weakened deciders that must fail. It checks that the kext still inserts through iovmInsert and clears
through ADRENO_GUEST_UNMAP (the leak's two halves), that probes/xnuboot.c
defaults the define to 0 with the #else clear unchanged, and that the state
words sit in an alignment hole (no offset or size moves).

--build compiles xnuboot with cycle.py's installed-fresh/speed-test flag sets
(control and fast) with the define absent, =0 and =1; --expect NAME=SHA256
requires the default build to equal a pre-change monitor byte for byte.

Failure inventory: a fix that leaves the leak; a decider that writes XNU memory
on a refusal; a template that matches the wrong code or nothing; a layout
change visible to host readers; a default build that changed; a kext that no
longer has the leak's shape (the fix would then be wrong, not merely unused).
"""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HEADER = (ROOT / 'compat/dart-wiredcnt.h').read_text()
TEST_C = (ROOT / 'tools/test-dart-wiredcnt.c').read_text()
KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
AUXKC = ROOT / 'build/current-assets/auxkc-srgb-20261017/adreno.kc'
KEXT = ROOT / 'gpu/adreno-kext/kext/src/AdrenoMemoryMap.cpp'
FUNCTION_VA = 0xfffffe000ba755d4          # pmap_ref_iommu_table (kc-symbolicate)
GLOBALS = {0xfffffe0007e2c1f0: 'vm_first_phys', 0xfffffe0007e2c1f8: 'vm_last_phys',
           0xfffffe0007e2c000: 'vm_pages_first_pnum', 0xfffffe0007d9d270: 'vm_pages_count',
           0xfffffe0007e2c010: 'vm_pages'}
RADIX_VA = 0xfffffe000ba12bec             # vm_page_find_canonical_radix (vm_resident.c:3183)
RADIX_GLOBALS = {0xfffffe0007da05f0: 'pmap_first_pnum', 0xfffffe0007d9d300: 'vm_pages_radix_root'}
SOURCES = ['compat/sptm-dart.c', 'compat/sptm-refs.c', 'compat/sptm.c', 'compat/dart.c',
           'compat/device.c', 'compat/adreno.c', 'compat/irq-forward.c', 'compat/aes.c',
           'compat/aic.c', 'compat/sep-pnon.c', 'compat/sep-xars.c', 'compat/sep-sks-endpoint.c',
           'compat/sep-sks.c', 'compat/watchdog.c', '../q1n1/platform/uefi/sha256.c']


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def c_array(text, name):
    body = between(text, name, '};')
    return [int(x, 16) for x in re.findall(r'0x[0-9a-fA-F]+', body.split('=', 1)[1])]


def compile_test(directory, extra=(), header_dir=None):
    exe = Path(directory) / 'test-dart-wiredcnt'
    include = [f'-I{header_dir}'] if header_dir else []
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *extra, *include,
                    '-Icompat', '-Ishadow', '-I../q1n1/platform/uefi', 'tools/test-dart-wiredcnt.c',
                    *SOURCES, '-o', str(exe)], cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


MUTANTS = {
    'the v46 decider (no radix)': ('        unsigned r = dwc_radix(o, w, va, index, pnum, &page);\n        if (r) return r;',
                                   '        return DWC_R_UNMANAGED;'),
    'the v40 bound (n + 1)': ('(unsigned)count < n + pinned)) reason = DWC_R_LOW',
                              '(unsigned)count < n + 1 + pinned)) reason = DWC_R_LOW'),
    'below zero accepted': ('(unsigned)count < n + pinned)) reason = DWC_R_LOW',
                            '(unsigned)count + 1 < n + pinned)) reason = DWC_R_LOW'),
    'stale pin accepted': ('(unsigned)count < n + pinned)) reason = DWC_R_LOW',
                           '(unsigned)count < n)) reason = DWC_R_LOW'),
    'no held reference': ('(uint16_t)(now - n + !pinned)', '(uint16_t)(now - n)'),
    'a reference per clear': ('(uint16_t)(now - n + !pinned)', '(uint16_t)(now - n + 1)'),
    'any pvh type': ('(pvh & DWC_PVH_TYPE_MASK) != DWC_PVH_TYPE_PTD) return DWC_R_PVH', '0) return DWC_R_PVH'),
    'any DART': ('(uint32_t)(word0 >> 11) != (uint32_t)o->dart_id) return DWC_R_PTD', '0) return DWC_R_PTD'),
    'any table': ('if (table_pa < first || table_pa >= last || (table_pa & 0x3fff)) return DWC_R_UNMANAGED;', ''),
    'above vm_pages accepted': ('        if (pnum - base >= pages_count) return DWC_R_UNMANAGED;\n',
                                '        (void)pages_count;\n'),
    'trust the walk': ('if (v != o->leaf(o->ctx, at)) reason = DWC_R_WALK;\n            else n += (unsigned)(v & 1);',
                       'n += (unsigned)(v & 1);'),
    'ignore a failed unmap': ('int r = o->unmap(o->ctx, iova, size);\n    if (r) return r;',
                              'int r = o->unmap(o->ctx, iova, size);\n    (void)r;'),
    'off by one': ('(uint16_t)(now - n + !pinned)', '(uint16_t)(now - n + 1 + !pinned)'),
    'no alias check': ('if (!dwc_match(w) || o->kva(o->ctx, va) != located) return DWC_R_ALIAS;',
                       'if (!dwc_match(w)) return DWC_R_ALIAS;'),
    'no commit recheck': ('if ((int16_t)now < 0 || (unsigned)now < n + pinned) { reason = DWC_R_RACE; break; }', ''),
    'first match wins': ('if (found >= 0) return -1;', ''),
    'no subtraction': ('if (o->cas16(o->ctx, counter, now, (uint16_t)(now - n + !pinned))) {',
                       'if (o->cas16(o->ctx, counter, now, now)) {'),
    'radix call site unchecked': ('        if ((w[DWC_CALL_AT + i] & dwc_call_mask[i]) != dwc_call_value[i]) return DWC_R_RADIX;\n',
                                  '        (void)i;\n'),
    'radix min unchecked': ('!dwc_load(o, root_va, 8, &root) || pnum < min)', '!dwc_load(o, root_va, 8, &root))'),
    'radix 64-bit shift': ('(key >> ((8 * level) & 31))', '((uint64_t)key >> (8 * level))'),
    'radix leaf as node': ('    if (!dwc_load(o, node + 4 * (key & 0xff), 4, &word) || !word) return DWC_R_RADIX;\n    *page = DWC_PACKED_BASE | word << 6;',
                           '    *page = node;'),
    'radix one level short': ('for (unsigned level = (unsigned)(root & DWC_RADIX_LEVEL_MASK); level; level--) {',
                              'for (unsigned level = (unsigned)(root & DWC_RADIX_LEVEL_MASK); level > 1; level--) {'),
}


class Decision(unittest.TestCase):
    def test_simulation(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([str(compile_test(d))], capture_output=True, text=True, timeout=600)
            self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-2000:])
            self.assertTrue(result.stdout.strip().splitlines()[-1].startswith('PASS:'), result.stdout[-2000:])
            print(result.stdout.strip().splitlines()[-1], file=sys.stderr)
            pre = subprocess.run([str(compile_test(d, ['-DDWC_PRE_CHANGE=1']))], capture_output=True,
                                 text=True, timeout=600)
            self.assertNotEqual(pre.returncode, 0)
            self.assertIn('!overflowed', pre.stdout)            # the v29 panic, reproduced

    def test_weakened_deciders_fail(self):
        for name, (old, new) in MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(HEADER.count(old), 1, name)
                (Path(d) / 'dart-wiredcnt.h').write_text(HEADER.replace(old, new))
                result = subprocess.run([str(compile_test(d, header_dir=d))], capture_output=True,
                                        text=True, timeout=600)
                self.assertNotEqual(result.returncode, 0, name)


class Source(unittest.TestCase):
    def test_default_off_and_unchanged_clear(self):
        self.assertIn('#ifndef SNAP_DART_WIREDCNT\n#define SNAP_DART_WIREDCNT 0\n#endif\n'
                      '#if SNAP_DART_WIREDCNT\n#include "../compat/dart-wiredcnt.h"\n#endif', SOURCE)
        unmap = between(SOURCE, 'static int gpu_unmap(void *ctx,uint64_t iova,uint64_t size)\n{', '\n}\n')
        unchanged = between(unmap, '#else', '#endif')
        self.assertEqual([l.strip() for l in unchanged.splitlines()[1:] if l.strip()], [
            '/* Permit holes when rolling back a partially inserted resource. This is',
            '* native table-3 endpoint3/option2, with its ownership/reference checks. */',
            'return sptm_dart_unmap(l->memory,l->dart,SPTM_DART_ADRENO,0,iova,size,2);'])
        self.assertIn('return dwc_unmap(&o,c->dart_wiredcnt,c->dart_wiredcnt_pins,iova,size);', unmap)
        self.assertIn('p->const_begin', unmap)
        self.assertIn('p->vbar_va-p->vbar', unmap)
        # ADRENO_GUEST_UNMAP is served only through gpu_unmap.
        self.assertEqual(SOURCE.count('adreno_guest_unmap(&o, &p->gpu, &c->gpu, r, gpu_leaf, gpu_unmap, &leaf,'), 1)
        self.assertEqual(len(re.findall(r'\bgpu_unmap\b', SOURCE)), 2)
        helpers = between(SOURCE, '#if SNAP_DART_WIREDCNT\n_Static_assert', '#endif\nstatic int gpu_unmap')
        self.assertIn('return sptm_dart_unmap(l->memory,l->dart,SPTM_DART_ADRENO,0,iova,size,2);', helpers)
        self.assertIn('__atomic_compare_exchange_n((uint16_t *)pa', helpers)

    def test_state_words_fill_a_hole(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        perf = importlib.import_module('perf_counters')
        sets, _ = flag_sets()
        defines = [f for f in sets['fast'] if f.startswith('-D')]
        off = perf._records(ROOT / 'probes/xnuboot.c', defines)['context']
        on = perf._records(ROOT / 'probes/xnuboot.c', defines + ['-DSNAP_DART_WIREDCNT=1'])['context']
        bare = perf._records(ROOT / 'probes/xnuboot.c', [])['context']   # tools/monitor_layout.py
        for layout in (off, on, bare):
            self.assertEqual(perf._size(layout), perf._size(off))
            self.assertEqual(perf._offset(layout, 'dart_wiredcnt'), perf._offset(layout, 'root_busy_refusals') + 8)
            self.assertEqual(perf._offset(layout, 'services'), perf._offset(layout, 'dart_wiredcnt') + 40)
            self.assertEqual(perf._offset(layout, 'dart_wiredcnt_pins'), perf._offset(layout, 'root_loaded') + 6 * 24)
            self.assertEqual(perf._offset(layout, 'perf'), perf._offset(layout, 'dart_wiredcnt_pins') + 16)
        self.assertEqual(perf._offset(off, 'services') % 64, 0)
        self.assertEqual(perf._offset(off, 'perf') % 64, 0)

    def test_the_kext_still_has_the_leaks_shape(self):
        kext = KEXT.read_text()
        insert = between(kext, 'int AdrenoMemoryMap::insertPage(', '\n}\n')
        clear = between(kext, 'int AdrenoMemoryMap::clearPages(', '\n}\n')
        self.assertIn('fMapper->iovmInsert(', insert)
        self.assertIn('ADRENO_GUEST_UNMAP', clear)
        self.assertNotIn('iovmUnmapMemory', clear)
        if AUXKC.exists():                                   # the pinned binary: x0 = 0x10002, hvc #0xad16
            data = AUXKC.read_bytes()
            words = struct.unpack_from(f'<{len(data) // 4}I', data)
            hvc = 0xd4000002 | (0xad16 << 5)
            found = False
            for i, x in enumerate(words):
                if x != hvc:
                    continue
                value = None
                for y in words[max(0, i - 16):i]:
                    if y & 31:
                        continue
                    if (y & 0x7f800000) == 0x52800000:
                        value = ((y >> 5) & 0xffff) << (16 * ((y >> 21) & 3))
                    elif (y & 0x7f800000) == 0x72800000 and value is not None:
                        hw = (y >> 21) & 3
                        value = (value & ~(0xffff << 16 * hw)) | (((y >> 5) & 0xffff) << 16 * hw)
                found |= value == 0x10002
            self.assertTrue(found, 'pinned AuxKC has no ADRENO_GUEST_UNMAP call')


@unittest.skipUnless(KERNELCACHE.exists(), 'pinned kernelcache not extracted')
class PinnedKernel(unittest.TestCase):
    def test_template_finds_pmap_ref_iommu_table_once(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        data = KERNELCACHE.read_bytes()
        image = importlib.import_module('kc-load').Image(data)
        end = image.vmin                                    # const_region_contract's prefix
        for _, va, size, maxprot, initprot in sorted(image.segment_protections, key=lambda s: s[1]):
            if not size:
                continue
            if (maxprot | initprot) & 2:
                break
            end = va + size
        value = c_array(HEADER, 'dwc_value[DWC_TEMPLATE_WORDS]')
        adrp = {int(a) for a, _, _ in re.findall(r'\{(\d+), (\d+), (\d+)\}', between(HEADER, 'dwc_globals_at', '};'))}
        mask = [0x9f00001f if i in adrp else 0xffffffff for i in range(len(value))]
        self.assertEqual(len(value), 49)
        matches = []
        for _, vmaddr, vmsize, fileoff, filesize in image.segments:
            if not (image.vmin <= vmaddr < end):
                continue
            n = min(vmsize, filesize, end - vmaddr) // 4
            words = struct.unpack_from(f'<{n}I', data, fileoff)
            anchor = value[43]
            for i in range(43, n - 5):
                if words[i] == anchor and all((words[i - 43 + k] & mask[k]) == value[k] for k in range(49)):
                    matches.append((vmaddr + 4 * (i - 43), words[i - 43:i + 6]))
        self.assertEqual([m[0] for m in matches], [FUNCTION_VA])
        real = c_array(TEST_C, 'real[DWC_TEMPLATE_WORDS]')
        self.assertEqual(list(matches[0][1]), real)
        decoded = []
        for a, l, size in re.findall(r'\{(\d+), (\d+), (\d+)\}', between(HEADER, 'dwc_globals_at', '};')):
            a, l, size = int(a), int(l), int(size)
            x = real[a]
            imm = ((x >> 29) & 3) | (((x >> 5) & 0x7ffff) << 2)
            imm -= (1 << 21) if imm & (1 << 20) else 0
            target = ((FUNCTION_VA + 4 * a) & ~0xfff) + (imm << 12) + ((real[l] >> 10) & 0xfff) * size
            decoded.append(target)
            segment = [s[0] for s in image.segments if s[1] <= target < s[1] + s[2]]
            self.assertEqual(segment, ['__DATA_CONST'], hex(target))
            self.assertTrue(image.vmin <= target < end)
        self.assertEqual(decoded, list(GLOBALS))
        # Below vm_pages: the call site, its BL target and vm_page_find_canonical_radix.
        def word_at(va):
            for _, vmaddr, vmsize, fileoff, filesize in image.segments:
                if vmaddr <= va < vmaddr + min(vmsize, filesize):
                    return struct.unpack_from('<I', data, fileoff + va - vmaddr)[0]
            raise ValueError(hex(va))
        call_value = c_array(HEADER, 'dwc_call_value[4]')
        call_mask = c_array(HEADER, 'dwc_call_mask[4]')
        call = [word_at(FUNCTION_VA + 4 * (66 + i)) for i in range(4)]
        self.assertEqual([c & m for c, m in zip(call, call_mask)], call_value)
        self.assertEqual(call, c_array(TEST_C, 'real_call[4]'))
        offset = call[1] & 0x3ffffff
        offset -= (1 << 26) if offset & (1 << 25) else 0
        radix_va = FUNCTION_VA + 4 * 67 + 4 * offset
        self.assertEqual(radix_va, RADIX_VA)
        radix = c_array(HEADER, 'dwc_radix_value[DWC_RADIX_WORDS]')
        self.assertEqual(len(radix), 107)
        words = [word_at(radix_va + 4 * i) for i in range(107)]
        for i, (x, v) in enumerate(zip(words, radix)):
            self.assertEqual(x & (0x9f00001f if i in (1, 5) else 0xffffffff), v, i)
        self.assertEqual([words[1], words[2], words[5], words[6]], c_array(TEST_C, 'real_radix_adrp[4]'))
        radix_globals = []
        for a, l, size in ((1, 2, 4), (5, 6, 8)):
            x = words[a]
            imm = ((x >> 29) & 3) | (((x >> 5) & 0x7ffff) << 2)
            imm -= (1 << 21) if imm & (1 << 20) else 0
            target = ((radix_va + 4 * a) & ~0xfff) + (imm << 12) + ((words[l] >> 10) & 0xfff) * size
            self.assertEqual([s[0] for s in image.segments if s[1] <= target < s[1] + s[2]], ['__DATA_CONST'])
            self.assertTrue(image.vmin <= target < end)
            radix_globals.append(target)
        self.assertEqual(radix_globals, list(RADIX_GLOBALS))
        print(f'pinned kernel: template at {FUNCTION_VA:#x} (pmap_ref_iommu_table) only; globals '
              + ', '.join(f'{GLOBALS[v]}={v:#x}' for v in decoded)
              + f'; below vm_pages via vm_page_find_canonical_radix {RADIX_VA:#x}: '
              + ', '.join(f'{RADIX_GLOBALS[v]}={v:#x}' for v in radix_globals), file=sys.stderr)


def flag_sets():
    """cycle_lib/speed_test.py flag_sets(): config/monitor-flags.json + ADDED (+FAST) + CENSUS."""
    tree = ast.parse((ROOT / 'tools/build-fast-traps-monitor.py').read_text())
    lists = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name) and t.id in ('ADDED', 'FAST')}
    census = [ast.literal_eval(n.value) for n in ast.parse((ROOT / 'tools/cycle_lib/speed_test.py')
              .read_text()).body if isinstance(n, ast.Assign) and
              any(isinstance(t, ast.Name) and t.id == 'CENSUS' for t in n.targets)][0]
    base = json.loads((ROOT / 'config/monitor-flags.json').read_text())['flags']
    return dict(control=[*base, *lists['ADDED'], census],
                fast=[*base, *lists['ADDED'], *lists['FAST'], census]), lists['FAST']


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (about a minute)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        sets, _ = flag_sets()
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='dart-wiredcnt-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for name, flags in sets.items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_DART_WIREDCNT=0']),
                                     ('on', ['-DSNAP_DART_WIREDCNT=1'])):
                    run.FLAGS[:] = flags + extra
                    blob = blobs[label] = run.build('xnuboot', out / f'{name}-{label}')
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0)
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name], name)
        finally:
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
