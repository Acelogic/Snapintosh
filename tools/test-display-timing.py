#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cycle.py installed-fresh --present-beam, offline: monitor allow-list, loader, selection, image, build.

    python3 tools/test-display-timing.py                       # header, source, loader, selection (seconds)
    python3 tools/test-display-timing.py --image               # + both guest images (about a minute)
    python3 tools/test-display-timing.py --build --qualification QUAL.json   # + monitors, define absent/0/1

No hardware. agents/tear-free/FAILURE-MODES.md A1-A5, D3, E1, E3.

Monitor: tools/test-display-timing.c runs compat/display-timing.h and must PASS; weakened copies of the header must
FAIL it. Constants: probes/displaytiming.py, compat/dpu-intf.h and compat/display-timing.h agree, and the page is the
glymur intf_5 derivation. probes/xnuboot.c defaults the define to 0 and touches struct-params-free code only under it.

--image: the --present-resident image and the --present-beam image differ only in the params chunk (exactly the four
appended words), the device tree (exactly the two GPU-node properties) and the boot-arguments page that records the
tree's size; image_checks(--present-beam) passes.

--build: xnuboot with each --qualification's flags, define absent, =0 and =1: absent == =0 == the qualification's
monitor_sha256; =1 differs and fits the code budget.
"""
from pathlib import Path
import argparse
import hashlib
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
sys.path.insert(0, str(ROOT / 'probes'))
sys.path.insert(0, str(ROOT / 'tools'))
import displaytiming as d  # noqa: E402

_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--image', action='store_true')
_ap.add_argument('--build', action='store_true')
_ap.add_argument('--out')
_ap.add_argument('--qualification', action='append', default=[])
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
HEADER = ROOT / 'compat/display-timing.h'
RESIDENT = dict(input=True, input_touchpad=True, input_ptp=True, present_dartpool=True, present_resident=True)
MUTATIONS = (
    ('no magic check', 'p->magic != DISPLAY_TIMING_MAGIC || ', ''),
    ('no flags check', ' || p->flags != DISPLAY_TIMING_F_INTF', ''),
    ('page widened', 'p->intf_end != DPU_INTF_PA + DPU_INTF_PAGE', 'p->intf_end < DPU_INTF_PA + DPU_INTF_PAGE'),
    ('read-write', 'S2_AP_RO | S2_ATTRS_DEVICE', 'S2_AP_RW | S2_ATTRS_DEVICE'),
    ('executable', 'S2_ATTRS_DEVICE, S2_XN}', 'S2_ATTRS_DEVICE, 0}'),
)


def compile_c(work, header_dir=None):
    out = work / 'test-display-timing'
    include = [f'-I{header_dir}'] if header_dir else []
    result = subprocess.run(['cc', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
                             *include, '-Ishadow', '-Icompat', 'tools/test-display-timing.c', '-o', str(out)], cwd=ROOT,
                            capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return subprocess.run([str(out)], capture_output=True, text=True)


class Monitor(unittest.TestCase):
    def test_host_model(self):
        with tempfile.TemporaryDirectory() as work:
            run = compile_c(Path(work))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('"display_timing_failures":0', run.stdout)

    def test_weakened_header_fails(self):
        text = HEADER.read_text()
        for name, old, new in MUTATIONS:
            with self.subTest(name), tempfile.TemporaryDirectory() as work:
                self.assertIn(old, text, name)
                (Path(work) / 'display-timing.h').write_text(text.replace(old, new, 1))
                (Path(work) / 'dpu-intf.h').write_text((ROOT / 'compat/dpu-intf.h').read_text())
                self.assertNotEqual(compile_c(Path(work), work).returncode, 0, name)

    def test_constants_match_the_loader(self):
        c = d.header_constants(ROOT)
        self.assertEqual(c['mdp'] + c['first'] + c['stride'] * c['index'], d.INTF_PA)
        self.assertEqual((c['abi_property'], c['pa_property']), (d.ABI_PROPERTY, d.PA_PROPERTY))
        text = HEADER.read_text()
        self.assertIn(f'#define DISPLAY_TIMING_PARAMS_WORDS {d.PARAMS_WORDS}', text)
        self.assertEqual(int(re.search(r'#define DISPLAY_TIMING_MAGIC\s+0x([0-9a-f]+)ULL', text).group(1), 16), d.MAGIC)
        self.assertEqual(d.INTF_PA, 0x0AE3A000)
        self.assertEqual(d.S2_DEVICE_RO, 0x40 | 0x4 | 0x300 | 0x400)

    def test_monitor_source(self):
        src = read_source(ROOT / 'probes/xnuboot.c')
        self.assertIn('#ifndef SNAP_DISPLAY_TIMING\n#define SNAP_DISPLAY_TIMING 0\n#endif', src)
        self.assertEqual(src.count('#include "../compat/display-timing.h"'), 1)
        self.assertIn('if (rows < 0) return -43;', src)
        self.assertIn('#define PARAMS_WORDS 1154', src)                # struct params unchanged
        for use in ('display_timing_rows(', 'display_timing_window(', 'display_timing_block('):
            for at in [m.start() for m in re.finditer(re.escape(use), src)]:
                # the closest preprocessor block opened before the use is SNAP_DISPLAY_TIMING's, still open
                self.assertLess(src.rfind('#endif', 0, at), src.rfind('#if SNAP_DISPLAY_TIMING', 0, at), use)


class Loader(unittest.TestCase):
    def test_rows_and_audit(self):
        words = d.params_words(d.SPEC)
        self.assertEqual(words, [d.MAGIC, 1, 0x0AE3A000, 0x0AE3B000])
        self.assertEqual(d.rows(words), [(0x0AE3A000, 0x0AE3B000)])
        self.assertEqual(d.stage2_audit_ranges(words), [(0x0AE3A000, 0x0AE3B000, 0x744, 1 << 54)])
        for bad in ([0] * 4, [d.MAGIC, 3, 0x0AE3A000, 0x0AE3B000], [d.MAGIC, 1, 0x0AE3B000, 0x0AE3C000],
                    [d.MAGIC, 1, 0x0AE3A000, 0x0AE3C000], words[:3]):
            self.assertIsNone(d.rows(bad))
            self.assertEqual(d.stage2_audit_ranges(bad), [])
        self.assertEqual(d.stage2_ranges(None), [])
        self.assertEqual(d.stage2_ranges(d.SPEC), [(0x0AE3A000, 0x0AE3B000, 'ro',
                                                    'DPU INTF_5 timing page (Device-nGnRE, read-only)')])

    def test_advertise(self):
        import adreno

        class Tree:
            def __init__(self):
                self.nodes = {adreno.GPU_NODE: {}}

            def add(self, path, key, value):
                self.nodes[path][key] = value
        t = Tree()
        d.advertise(t, d.SPEC, [(0x80000000, 1 << 30)])
        self.assertEqual(t.nodes[adreno.GPU_NODE], {d.ABI_PROPERTY: struct.pack('<I', 1),
                                                    d.PA_PROPERTY: struct.pack('<Q', 0x0AE3A000)})
        with self.assertRaises(ValueError):
            d.advertise(t, d.SPEC)                                     # twice
        with self.assertRaises(ValueError):
            d.advertise(Tree(), d.SPEC, [(0x0AE00000, 0x100000)])      # overlapping owned memory
        t2 = Tree(); t2.nodes = {}
        with self.assertRaises(ValueError):
            d.advertise(t2, d.SPEC)                                    # no GPU node
        for name in (d.ABI_PROPERTY, d.PA_PROPERTY):
            self.assertLess(len(name), 32)                             # Apple's property-name field

    def test_xnuboot_hooks(self):
        src = (ROOT / 'probes/xnuboot.py').read_text()
        self.assertIn('DISPLAY_TIMING = None', src)
        self.assertIn('ranges += displaytiming.stage2_ranges(DISPLAY_TIMING)', src)
        self.assertIn('words += displaytiming.params_words(DISPLAY_TIMING)', src)
        self.assertIn('(PARAMS_WORDS + 6 + 12 + 4) * 8', src)
        self.assertIn("xb.DISPLAY_TIMING = displaytiming.SPEC", (ROOT / 'probes/run.py').read_text())

    def test_installed_fresh_selection(self):
        from cycle_lib import installed_fresh as f
        sets = dict(fast=['-DX=1'], control=['-DX=1'])
        beam = types.SimpleNamespace(variant='fast', present_beam=True, **RESIDENT)
        plain = types.SimpleNamespace(variant='fast', **RESIDENT)
        self.assertEqual(f.variant_flags(sets, beam)[-1], d.DEFINE)
        self.assertNotIn(d.DEFINE, f.variant_flags(sets, plain))
        self.assertEqual(f.DISPLAY_TIMING_DEFINE, d.DEFINE)
        self.assertEqual(f.environment(beam)[d.ENV], '1')
        self.assertNotIn(d.ENV, f.environment(plain))
        with self.assertRaisesRegex(BaseException, 'not pinned'):   # refused until its AuxKC is linked and pinned
            f.selected(beam)
        with self.assertRaisesRegex(BaseException, 'needs --present-resident'):
            f.selected(types.SimpleNamespace(variant='fast', present_beam=True, input=True, input_ptp=True,
                                             present_dartpool=True, input_touchpad=True))
        saved = f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA
        try:
            f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA = '0' * 64
            self.assertEqual(f.selected(beam)[1:3], (f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM, '0' * 64))
            self.assertNotEqual(f.selected(plain)[1], f.selected(beam)[1])
        finally:
            f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA = saved


@unittest.skipUnless(ARGS.image, 'pass --image to build the guest images')
class Image(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SNAP_SEED'] = 'test-display-timing'
        from cycle_lib import installed_fresh as f
        from cycle_lib.bootstrap_smoke import load
        cls.f = f
        cls.layout = load('dt_layout', ROOT / 'tools/monitor_layout.py').MonitorLayout()
        cls.work = Path(ARGS.out) / 'images' if ARGS.out else Path(tempfile.mkdtemp(prefix='display-timing-image-'))
        cls.work.mkdir(parents=True, exist_ok=True)
        _, payload = f.root_hash_payload(ROOT)
        (cls.work / 'root-hash.payload').write_bytes(payload)

    def image(self, name, **kwargs):
        dest = self.work / name
        dest.mkdir()
        args = types.SimpleNamespace(**kwargs)
        saved = self.f.selected
        resident = self.f.route_selected(types.SimpleNamespace(**RESIDENT))
        self.f.selected = lambda a: resident             # the resident collection for both images
        try:
            record = self.f.image_checks(ROOT, dest, self.layout, self.work / 'root-hash.payload', args=args)
        finally:
            self.f.selected = saved
        (dest / 'image.json').write_text(json.dumps(record, indent=1, default=str) + '\n')
        return record, (dest / 'device-tree.bin').read_bytes()

    def test_images(self):
        from appledt import DeviceTree
        import adreno
        base, tree0 = self.image('resident', **RESIDENT)
        self.assertNotIn('display_timing', base)
        beam, tree1 = self.image('resident-beam', present_beam=True, **RESIDENT)
        self.assertEqual(beam['display_timing']['stage2'], ['0xae3a000', '0xae3b000', 'ro'])
        chunks0 = {c['address']: c for c in base['chunks']}
        chunks1 = {c['address']: c for c in beam['chunks']}
        self.assertEqual(set(chunks0), set(chunks1))
        differing = sorted(a for a in chunks0 if chunks0[a] != chunks1[a])
        params = [a for a in differing if chunks1[a]['bytes'] == chunks0[a]['bytes'] + 8 * d.PARAMS_WORDS]
        self.assertEqual(len(params), 1, differing)
        self.assertLessEqual(len(differing), 3, differing)               # params, device tree, boot-arguments page
        dt0, dt1 = DeviceTree(tree0), DeviceTree(tree1)
        self.assertEqual(set(dt0.nodes), set(dt1.nodes))
        for path, props in dt0.nodes.items():
            extra = set(dt1.nodes[path]) - set(props)
            self.assertEqual(extra, {d.ABI_PROPERTY, d.PA_PROPERTY} if path == adreno.GPU_NODE else set(), path)
            for key, prop in props.items():
                self.assertEqual(bytes(dt1.nodes[path][key].value), bytes(prop.value), f'{path} {key}')
        (self.work / 'result.json').write_text(json.dumps(dict(differing_chunks=differing, params_chunk=params,
                                                               display_timing=beam['display_timing']), indent=1) + '\n')


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run
        out = Path(ARGS.out) / 'builds' if ARGS.out else Path(tempfile.mkdtemp(prefix='display-timing-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for path in ARGS.qualification:
                record = json.loads(Path(path).read_text())
                name, blobs = Path(path).parent.name, {}
                for label, extra in (('default', []), ('off', ['-DSNAP_DISPLAY_TIMING=0']), ('on', [d.DEFINE])):
                    run.FLAGS[:] = record['flags'] + extra
                    blob = blobs[label] = run.build('xnuboot', out / f'{name}-{label}')
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0)
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                self.assertEqual(results[f'{name}-default']['sha256'], record['monitor_sha256'], name)
        finally:
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
