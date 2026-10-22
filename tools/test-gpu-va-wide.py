#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""--gpu-va-wide (agents/gpu-va-wide FAILURE-MODES.md): the installed-fresh wiring of the wide GPU VA window, offline.

    python3 tools/test-gpu-va-wide.py                       # selection, flags, environment, GPU steps, loader hooks
    python3 tools/test-gpu-va-wide.py --image [--out DIR]   # + both guest images (minutes): only the params block,
                                                            #   the device tree (dart-adreno vm-size, GPU node
                                                            #   gpu-va-bits) and the boot-arguments page differ
    python3 tools/test-gpu-va-wide.py --build --qualification Q.json [--base-tree DIR] [--out DIR]
                                                            # + the monitor with Q's flags: define absent == =0 (and
                                                            #   == DIR/build.json, a build of the unchanged tree);
                                                            #   =1 differs and fits the code budget

The C side is tools/test-adreno-va-wide.c (the mirror, 4 GiB boundary and top of window), tools/test-adreno.c,
tools/test-sptm-dart-adreno.c and tools/test-dart-wiredcnt.c built with -DADRENO_VA_WIDE=1; the q1n1 side is
q1n1 tools/test-a16gpu-adopt.py (cp-fence/adopt --va-wide).
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.path.insert(0, str(ROOT / 'tools'))
import adreno  # noqa: E402

_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--image', action='store_true')
_ap.add_argument('--build', action='store_true')
_ap.add_argument('--out')
_ap.add_argument('--base-tree')
_ap.add_argument('--qualification', action='append', default=[])
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
RESIDENT = dict(input=True, input_touchpad=True, input_ptp=True, present_dartpool=True, present_resident=True)
RECLAIM = dict(RESIDENT, present_beam=True, present_va_reclaim=True)
DEFINE, ENV = '-DADRENO_VA_WIDE=1', 'SNAP_ADRENO_VA_WIDE'


class Wiring(unittest.TestCase):
    def test_installed_fresh_selection(self):
        from cycle_lib import installed_fresh as f
        sets = dict(fast=['-DSNAP_ROOT_CACHE_WIDE=1', '-DSNAP_DART_WIREDCNT=1'], control=['-DX=1'])
        wide = types.SimpleNamespace(variant='fast', gpu_va_wide=True, **RECLAIM)
        plain = types.SimpleNamespace(variant='fast', **RECLAIM)
        self.assertEqual(f.GPU_VA_WIDE_DEFINE, DEFINE)
        self.assertEqual(f.variant_flags(sets, wide)[-1], DEFINE)
        self.assertNotIn(DEFINE, f.variant_flags(sets, plain))
        with self.assertRaisesRegex(BaseException, 'root-cache-wide'):     # V15: the wide pin bitmap's home
            f.variant_flags(dict(fast=['-DSNAP_DART_WIREDCNT=1']), wide)
        self.assertEqual(f.environment(wide)[ENV], '1')
        self.assertNotIn(ENV, f.environment(plain))
        with self.assertRaisesRegex(BaseException, 'not pinned'):          # refused until linked and pinned
            f.selected(wide)
        with self.assertRaisesRegex(BaseException, 'needs --present-va-reclaim'):
            f.selected(types.SimpleNamespace(variant='fast', gpu_va_wide=True, present_beam=True, **RESIDENT))
        saved = f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE, f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA
        try:
            f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE, f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA = \
                'build/x/wide.kc', '0' * 64
            self.assertEqual(f.selected(wide)[1:3], ('build/x/wide.kc', '0' * 64))
            self.assertNotEqual(f.selected(plain)[1], f.selected(wide)[1])
        finally:
            f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE, f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA = saved

    def test_gpu_steps(self):
        from cycle_lib import installed_fresh as f
        plain = f.gpu_steps(ROOT, types.SimpleNamespace(**RECLAIM))
        wide = f.gpu_steps(ROOT, types.SimpleNamespace(gpu_va_wide=True, **RECLAIM))
        self.assertEqual(len(plain), len(wide))
        fences = 0
        for (name, a), (name2, b) in zip(plain, wide):
            self.assertEqual(name, name2)
            if a[0] == 'cp-fence':
                fences += 1
                self.assertEqual(b, [*a, '--va-wide'])
            else:
                self.assertEqual(a, b)
        self.assertGreaterEqual(fences, 1)
        self.assertNotIn('--va-wide', [x for _, a in plain for x in a])

    def test_loader_hooks(self):
        run_src = (ROOT / 'probes/run.py').read_text()
        self.assertIn('xb.configure_adreno_va_wide()', run_src)
        self.assertIn('monitor_work.validate_gpu_pool(*gpu_pool, monitor_end, info, [region])', run_src)
        self.assertIn('adreno.load_adoption(path, info, xb.ADRENO_VA_WIDE)', run_src)
        fresh = (ROOT / 'tools/cycle_lib/installed_fresh.py').read_text()
        self.assertIn("['adopt', '--record', str(adoption), *(['--va-wide'] if va_wide else [])]", fresh)
        self.assertIn('adreno.load_adoption(json.loads(adoption.read_text()), info, va_wide)', fresh)
        self.assertIn("'--gpu-va-wide'", (ROOT / 'tools/cycle.py').read_text())

    def test_loader_refuses_mixed_halves(self):
        """V12: a wide record with a default launch and the reverse; a wide launch without its reservation."""
        info = {'gpu_arena_base': 0xFCC00000, 'gpu_arena_size': 32 << 20, 'gpu_arena_flags': 2,
                'gic_distributor': adreno.GICD_A16, 'stage_generation': 6}
        with self.assertRaises(ValueError):
            adreno.load_adoption(adreno.fixture_record(wide=True), info)
        with self.assertRaises(ValueError):
            adreno.load_adoption(adreno.fixture_record(), info, True)
        with self.assertRaises(ValueError):
            adreno.params_words(adreno.AdrenoSpec(va_wide=True), adreno.fixture_record(wide=True))


@unittest.skipUnless(ARGS.image, 'pass --image to build the guest images')
class Image(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SNAP_SEED'] = 'test-gpu-va-wide'
        from cycle_lib import installed_fresh as f
        from cycle_lib.bootstrap_smoke import load
        cls.f = f
        cls.layout = load('va_layout', ROOT / 'tools/monitor_layout.py').MonitorLayout()
        cls.work = Path(ARGS.out) / 'images' if ARGS.out else Path(tempfile.mkdtemp(prefix='gpu-va-wide-image-'))
        cls.work.mkdir(parents=True, exist_ok=True)
        _, payload = f.root_hash_payload(ROOT)
        (cls.work / 'root-hash.payload').write_bytes(payload)

    def image(self, name, **kwargs):
        dest = self.work / name
        dest.mkdir()
        args = types.SimpleNamespace(**kwargs)
        saved = self.f.selected
        stand_in = self.f.route_selected(types.SimpleNamespace(**RECLAIM))   # the va-reclaim collection for both
        self.f.selected = lambda a: stand_in
        try:
            record = self.f.image_checks(ROOT, dest, self.layout, self.work / 'root-hash.payload', args=args)
        finally:
            self.f.selected = saved
        (dest / 'image.json').write_text(json.dumps(record, indent=1, default=str) + '\n')
        return record, (dest / 'device-tree.bin').read_bytes()

    def test_images(self):
        from appledt import DeviceTree
        base, tree0 = self.image('reclaim', **RECLAIM)
        wide, tree1 = self.image('reclaim-wide', gpu_va_wide=True, **RECLAIM)
        self.assertNotIn('gpu_va_wide', base)
        pool = [int(x, 16) for x in wide['gpu_va_wide']['pool']]
        self.assertEqual(pool[1], adreno.pool_reservation_bytes())
        chunks0 = {c['address']: c for c in base['chunks']}
        chunks1 = {c['address']: c for c in wide['chunks']}
        self.assertEqual(set(chunks0), set(chunks1))                     # the pool is reserved, never uploaded
        differing = sorted(a for a in chunks0 if chunks0[a] != chunks1[a])
        self.assertLessEqual(len(differing), 3, differing)               # params, device tree, boot-arguments page
        dt0, dt1 = DeviceTree(tree0), DeviceTree(tree1)
        self.assertEqual(set(dt0.nodes), set(dt1.nodes))
        changed = []
        for path, props in dt0.nodes.items():
            extra = set(dt1.nodes[path]) - set(props)
            self.assertEqual(extra, {adreno.GPU_VA_BITS_PROPERTY} if path == adreno.GPU_NODE else set(), path)
            for key, prop in props.items():
                if bytes(dt1.nodes[path][key].value) != bytes(prop.value):
                    changed.append((path, key))
        self.assertEqual(changed, [(adreno.DART_NODE, 'vm-size')])
        self.assertEqual(struct.unpack('<Q', bytes(dt1.nodes[adreno.DART_NODE]['vm-size'].value))[0], 0x3C0000000)
        (self.work / 'result.json').write_text(json.dumps(dict(differing_chunks=differing, gpu_va_wide=wide['gpu_va_wide'],
                                                               dt_changed=changed), indent=1) + '\n')


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        import run
        out = Path(ARGS.out) / 'builds' if ARGS.out else Path(tempfile.mkdtemp(prefix='gpu-va-wide-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for path in ARGS.qualification:
                record = json.loads(Path(path).read_text())
                name, blobs = Path(path).parent.name, {}
                for label, extra in (('default', []), ('off', ['-DADRENO_VA_WIDE=0']), ('on', [DEFINE])):
                    run.FLAGS[:] = record['flags'] + extra
                    blob = blobs[label] = run.build('xnuboot', out / f'{name}-{label}')
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0)
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                if ARGS.base_tree:
                    base = json.loads((Path(ARGS.base_tree) / 'build.json').read_text())
                    self.assertEqual(results[f'{name}-default']['sha256'], base['monitor_sha256'], name)
        finally:
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
