#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage 4 offline: the Adreno node in the built image, the params the loader
hands the monitor, and the adoption record's refusals.

    python3 tools/test-adreno-image.py

No target: the tree is the pinned J700 firmware tree built by
probes/xnuboot.build_devicetree; the adoption record is adreno.fixture_record()
(the shape q1n1's `a16gpu.py adopt` writes).
"""
import contextlib
import copy
import functools
import io
import re
import runpy
import struct
import sys
import unittest
from pathlib import Path
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.dont_write_bytecode = True
import xnuboot as xb           # noqa: E402
import adreno                  # noqa: E402
import monitor_work            # noqa: E402
import run                     # noqa: E402
from appledt import DeviceTree  # noqa: E402

FULL = 'j700ap-26A428-xars-uniform-auxkc-adreno'
NODART = FULL + '-nodart'
PLAIN = 'j700ap-26A428-xars-uniform-auxkc'
INSTALLED = PLAIN + '-installed-adreno'
HEADER = (ROOT / 'compat/adreno.h').read_text()


def header_define(name):
    m = re.search(rf'^#define {name}\s+\(?(0x[0-9a-fA-F]+|\d+)U?L?', HEADER, re.M)
    return int(m.group(1), 0)


def struct_fields(name):
    body = re.search(rf'struct {name} \{{(.*?)\n\}};', HEADER, re.S).group(1)
    names = []
    for line in body.splitlines():
        line = line.split('/*')[0].strip()
        if not line.startswith('uint64_t'):
            continue
        for part in line[len('uint64_t'):].rstrip(';').split(','):
            part = part.strip()
            m = re.fullmatch(r'(\w+)\[(\d+)\]', part)
            names += [f'{m.group(1)}{i}' for i in range(int(m.group(2)))] if m else [part]
    return names


def tree(profile):
    xb.configure_guest(profile)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree()


@functools.lru_cache(maxsize=1)
def compiled_params_layout():
    """The monitor's C offsets, independently of Python's serialized fields."""
    import shutil
    import subprocess
    if not shutil.which('clang'):
        raise unittest.SkipTest('clang not present')
    layout = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                             '-mgeneral-regs-only', '-Ishadow', '-Icompat', '-Xclang',
                             '-fdump-record-layouts', '-fsyntax-only', 'probes/xnuboot.c'],
                            cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return next(b for b in layout.split('*** Dumping AST Record Layout')
                if re.search(r'^\s*0 \| struct params\n', b))


class HeaderAgreement(unittest.TestCase):
    """probes/adreno.py and tools/adreno_counters.py against compat/adreno.h."""

    def test_constants(self):
        pairs = {'ADRENO_PA': adreno.GPU_PA, 'ADRENO_PASS0_END': adreno.PASS0_END,
                 'ADRENO_PASS1_PA': adreno.PASS1_PA, 'ADRENO_PASS1_END': adreno.PASS1_END,
                 'ADRENO_CX_MISC_PA': adreno.CX_MISC_PA, 'ADRENO_CX_MISC_END': adreno.CX_MISC_END,
                 'ADRENO_WINDOW_BASE': adreno.WINDOW_BASE, 'ADRENO_WINDOW_END': adreno.WINDOW_END,
                 'ADRENO_DART_ID': adreno.DART_ID, 'ADRENO_AIC_IRQ': adreno.GPU_IRQ,
                 'ADRENO_INTID': adreno.INTID, 'ADRENO_PARAMS_WORDS': adreno.PARAMS_WORDS,
                 'ADRENO_F_ENABLE': adreno.F_ENABLE, 'ADRENO_F_CX_MISC': adreno.F_CX_MISC,
                 'ADRENO_F_DART': adreno.F_DART, 'ADRENO_F_RING': adreno.F_RING,
                 'ADRENO_F_TZ_DONE': adreno.F_TZ_DONE, 'ADRENO_F_SELF_IRQ': adreno.F_SELF_IRQ}
        for name, value in pairs.items():
            self.assertEqual(header_define(name), value, name)
        self.assertEqual(adreno.POOL_BYTES, 0x603000)
        dart_h = (ROOT / 'compat/sptm-dart.h').read_text()
        self.assertIn('#define SPTM_DART_ADRENO 31U', dart_h)
        self.assertIn(f'#define SPTM_DART_ADRENO_BASE {adreno.WINDOW_BASE:#x}UL', dart_h)

    def test_struct_orders(self):
        params = struct_fields('adreno_params')
        self.assertEqual(len(params), adreno.PARAMS_WORDS)
        self.assertEqual(params[:3], ['flags', 'gicd', 'affinity'])
        self.assertEqual(params[-2:], ['ring_at_seconds', 'reserved'])
        state = struct_fields('adreno_state')
        counters = runpy.run_path(str(ROOT / 'tools/adreno_counters.py'))
        self.assertEqual(len(state), header_define('ADRENO_STATE_WORDS'))
        self.assertEqual([f.replace('gic_saved', 'gic') for f in state], counters['FIELDS'])

    def test_counters_decode(self):
        counters = runpy.run_path(str(ROOT / 'tools/adreno_counters.py'))
        values = dict.fromkeys(counters['FIELDS'], 0)
        values.update(status=1 | 2 | 8 | 16, fences=2, fence_last=0x534e0002, map_pages=12,
                      unmap_pages=4, live_pages=8, traps=1, trap_ipa=0x03d7dfa0, trap_block=9,
                      quiesce=1 | 8 | 32, prepare=(1 << 64) - 62)
        raw = struct.pack(f'<{len(counters["FIELDS"])}Q', *(values[k] for k in counters['FIELDS']))
        d = counters['decode'](raw)
        self.assertEqual(d['prepare'], -62)
        self.assertEqual(d['prepare_name'], 'GX off')
        self.assertEqual(d['trap_block_name'], 'GMU')
        self.assertEqual(d['status_names'], ['adopted', 'attached', 'run_fence', 'quiesced'])
        self.assertTrue(any('GX-side GBIF halted' in line for line in counters['summary'](d)))
        values['live_pages'] = 9
        raw = struct.pack(f'<{len(counters["FIELDS"])}Q', *(values[k] for k in counters['FIELDS']))
        with self.assertRaises(ValueError):
            counters['decode'](raw)


class Tree(unittest.TestCase):
    def tearDown(self):
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_full_profile(self):
        for profile in (FULL, INSTALLED):
            with self.subTest(profile=profile):
                self.check_full_tree(profile)

    def check_full_tree(self, profile):
        dt = tree(profile)
        gpu = dt.nodes[adreno.GPU_NODE]
        self.assertEqual(dt.get(adreno.GPU_NODE, 'compatible'), b'snapintosh,adreno-x2\0')
        self.assertEqual(xb.device_windows(dt, 'adreno'),
                         [(0x03D00000, 0x37000), (0x03D3C000, 0x4000), (0x03D9E000, 0x2000)])
        self.assertEqual(struct.unpack('<I', gpu['interrupts'].value)[0], 975)
        self.assertEqual(gpu['interrupt-parent'].value, dt.nodes['/device-tree/arm-io/aic']['AAPL,phandle'].value)
        mapper = dt.nodes[adreno.MAPPER_NODE]
        self.assertEqual(gpu['iommu-parent'].value, mapper['AAPL,phandle'].value)
        self.assertEqual(struct.unpack('<I', gpu['chip-id'].value)[0], 0x44070041)
        if profile == INSTALLED:
            self.assertEqual(gpu['snapintosh,guest-fence-abi'].value, struct.pack('<I', 1))
            self.assertEqual(gpu['snapintosh,guest-unmap-abi'].value, struct.pack('<I', 1))
        else:
            self.assertNotIn('snapintosh,guest-fence-abi', gpu)
            self.assertNotIn('snapintosh,guest-unmap-abi', gpu)
        # The plan's range, and the virtual DART's identity window.
        ranges = list(struct.iter_unpack('<3Q', dt.get('/device-tree/arm-io', 'ranges')))
        self.assertIn((0x7_03D0_0000, 0x03D00000, 0xA0000), ranges)
        self.assertIn((0x7_1000_0000, 0x7_1000_0000, 0x20000), ranges)
        # dart-adreno: dart-sio's property set, its own id and window; the
        # other DARTs keep the ids their audited policies pin.
        ids = {d.path.rsplit('/', 1)[1]: d.device_id for d in dt.dart_devices}
        self.assertEqual((ids['dart-adreno'], ids['dart-sep'], ids['dart-ane'], ids['dart-sio']), (31, 20, 0, 21))
        model = [m for m in dt.device_models if m.node == adreno.DART_NODE]
        self.assertEqual(len(model), 1)
        self.assertEqual((model[0].base, model[0].span, model[0].config),
                         (0x7_1000_0000, 0x20000, (16, 44 | 4 << 8, 976, 36, 1 << 31)))
        self.assertEqual(struct.unpack('<Q', dt.get(adreno.DART_NODE, 'vm-base'))[0], 0x40000000)
        self.assertEqual(struct.unpack('<Q', dt.get(adreno.DART_NODE, 'vm-size'))[0], 0xC0000000)
        # AIC 975/976 were /arm-io/sgx's; sgx is withdrawn and nobody else uses them.
        self.assertNotIn('/device-tree/arm-io/sgx', dt.nodes)
        users = [p for p, props in dt.nodes.items() if 'interrupts' in props and
                 {975, 976} & {v for (v,) in struct.iter_unpack('<I', props['interrupts'].value[:len(props['interrupts'].value) // 4 * 4])}]
        self.assertEqual(sorted(users), sorted([adreno.GPU_NODE, adreno.DART_NODE]))
        # Nothing in the tree names the q1n1 GPU arena.
        blob = dt.serialize()
        arena = adreno.fixture_record()['arena']['base']
        self.assertNotIn(struct.pack('<Q', arena), blob)
        self.assertEqual(DeviceTree(blob).serialize(), blob)

    def test_nodart_and_plain(self):
        dt = tree(NODART)
        self.assertIn(adreno.GPU_NODE, dt.nodes)
        self.assertNotIn(adreno.DART_NODE, dt.nodes)
        self.assertNotIn('iommu-parent', dt.nodes[adreno.GPU_NODE])
        plain = tree(PLAIN)
        self.assertNotIn(adreno.GPU_NODE, plain.nodes)
        # The Adreno profile changes nothing else about the board.
        full = tree(FULL)
        for path in plain.nodes:
            if path != '/device-tree/arm-io':
                self.assertIn(path, full.nodes)

    def test_refusals(self):
        xb.configure_guest(FULL)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        dt = DeviceTree(xb.DeviceTree(Path(xb.DEFAULT_DEVICETREE).read_bytes()).serialize())
        dt.resolve_placeholders()
        before = dt.serialize()
        with self.assertRaises(ValueError):
            adreno.prepare_tree(dt, adreno.AdrenoSpec(), [(0x7_1000_0000, 0x1000)])
        self.assertEqual(dt.serialize(), before)
        dt.put('/device-tree/arm-io/dart-sio', 'interrupts', struct.pack('<I', 975))
        with self.assertRaises(ValueError):
            adreno.prepare_tree(dt, adreno.AdrenoSpec(), [])

    def test_stage2(self):
        xb.configure_guest(FULL)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        ranges = xb.stage2_ranges()
        dev = [(lo, hi, a) for lo, hi, a, what in ranges if 'Adreno' in what]
        self.assertEqual(dev, [(0x03D00000, 0x03D37000, 'rw'), (0x03D3C000, 0x03D40000, 'rw'),
                               (0x03D9E000, 0x03DA0000, 'ro')])
        self.assertIsNone(xb.stage2_where(0x03D37000, ranges))     # GMU_GX stays absent
        self.assertIsNone(xb.stage2_where(0x03D7DFA0, ranges))     # GMU
        self.assertIsNone(xb.stage2_where(0x03DC0000, ranges))     # SMMU
        self.assertIsNone(xb.stage2_where(0xFCC00000, ranges))     # the arena


class Adoption(unittest.TestCase):
    def info(self, record):
        return {'gpu_arena_base': record['arena']['base'], 'gpu_arena_size': record['arena']['size'],
                'gpu_arena_flags': 2, 'gic_distributor': record['gicd'],
                'stage_generation': record['stage_generation']}

    def test_accepts_fixture(self):
        record = adreno.fixture_record()
        self.assertEqual(adreno.load_adoption(record, self.info(record)), record)
        words = adreno.params_words(adreno.AdrenoSpec(), record)
        self.assertEqual(len(words), adreno.PARAMS_WORDS)
        self.assertEqual(words[0], 1 | 2 | 4 | 8 | 16 | 32)
        self.assertEqual(words[2], 0)                 # affinity: the monitor's
        self.assertEqual(words[12] - record['memptrs']['pa'], adreno.FENCE_OFF)
        self.assertEqual(adreno.params_words(None, None), [0] * adreno.PARAMS_WORDS)
        with self.assertRaises(ValueError):
            adreno.params_words(adreno.AdrenoSpec(), None)
        no_tz = dict(record, tz_init_done=False)
        self.assertEqual(adreno.params_words(adreno.AdrenoSpec(dart=False, cx_misc=False), no_tz)[0],
                         1 | 8 | 32)

    def test_refusals(self):
        base = adreno.fixture_record()
        info = self.info(base)
        spoil = [
            lambda r: r.update(schema='x'),
            lambda r: r['arena'].update(base=r['arena']['base'] + 0x200000),
            lambda r: r.update(gicd=0x17100000),
            lambda r: r.update(stage_generation=7),
            lambda r: r.update(ready=False),
            lambda r: r['pool'].update(pa=r['arena']['base'] + r['arena']['size'] - 0x1000),
            lambda r: r['pool'].update(pa=r['ring']['pa']),
            lambda r: r['ring'].update(wptr=8192),
            lambda r: r['fence'].update(pa=r['memptrs']['pa'] + 0x81),
            lambda r: r['cb0'].update(ttbr0=r['pool']['pa'] + 0x2000),
            lambda r: r['cb0'].update(sctlr=0),
            lambda r: r['fence'].update(va=0x50000080, pa=r['memptrs']['pa'] + 0x80),
        ]
        for n, fn in enumerate(spoil):
            record = copy.deepcopy(base)
            fn(record)
            with self.assertRaises((ValueError, KeyError), msg=str(n)):
                adreno.load_adoption(record, info)

    def test_arena_is_reserved(self):
        self.assertIn(('gpu_arena_base', 'gpu_arena_size'), monitor_work.RESERVED_FIELDS)
        record = adreno.fixture_record()
        adreno.check_disjoint(record, [(0x8c0000000, 8 << 30)])
        with self.assertRaises(ValueError):
            adreno.check_disjoint(record, [(0xfd000000, 0x1000)])
        # Placement carves it out of firmware-free memory like q1n1's own regions.
        blob = struct.pack('<IIQQQQ', 7, 0, 0xf0000000, 0, 0x10000, 0)
        spans = monitor_work.free_spans(blob, 40, {'gpu_arena_base': 0xfcc00000,
                                                   'gpu_arena_size': 32 << 20})
        self.assertEqual(spans, [(0xf0000000, 0xfcc00000), (0xfec00000, 0x100000000)])


class Params(unittest.TestCase):
    def tearDown(self):
        xb.ADRENO_RECORD = None
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_image_carries_params(self):
        xb.configure_guest(FULL)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        record = adreno.fixture_record()
        xb.ADRENO_RECORD = record
        kc = ROOT / 'build/auxkc-20260925/aux-hello.kc'
        if not kc.exists():
            self.skipTest('pinned aux-hello.kc not present')
        with contextlib.redirect_stdout(io.StringIO()):
            built = xb.build(str(xb.DEFAULT_KERNELCACHE), auxkc=str(kc))
        blob = built['chunks'][xb.PARAMS_PA]
        self.assertEqual(len(blob), xb.PARAMS_WORDS * 8)
        # TXM fields follow gpu. Decode at the compiled monitor offset so this
        # catches a C/Python field-order mismatch, including fields appended later.
        offset = int(re.findall(r'^\s*(\d+) \|   struct adreno_params gpu$',
                                compiled_params_layout(), re.M)[0])
        gpu = list(struct.unpack_from(f'<{adreno.PARAMS_WORDS}Q', blob, offset))
        self.assertEqual(gpu, adreno.params_words(xb.GUEST_PROFILE.adreno, record))
        self.assertIn(adreno.GPU_NODE.encode().split(b'/')[-1] + b'\0', built['chunks'][xb.DEVICETREE_PA])

    def test_plain_profile_params_are_zero(self):
        xb.configure_guest(PLAIN)
        self.assertIsNone(xb.GUEST_PROFILE.adreno)
        self.assertEqual(adreno.params_words(xb.GUEST_PROFILE.adreno, None), [0] * adreno.PARAMS_WORDS)
        src = read_source(ROOT / 'probes/xnuboot.c')
        self.assertIn(f'#define PARAMS_WORDS {xb.PARAMS_WORDS}', src)


class WideWindow(unittest.TestCase):
    """ADRENO_VA_WIDE (agents/gpu-va-wide FAILURE-MODES.md V1, V5, V8, V9, V12): the header's wide branch, the
    tree, the adoption record's T0SZ, the monitor-private table reservation and the params pool word."""

    def tearDown(self):
        xb.ADRENO_RECORD = None
        xb.configure_adreno_va_wide(False)
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_header_wide_branch(self):
        wide = HEADER.split('#if !ADRENO_VA_WIDE', 1)[1].split('#else', 1)[1].split('#endif', 1)[0]
        self.assertEqual(int(re.search(r'#define ADRENO_WINDOW_END\s+(0x[0-9a-f]+)', wide).group(1), 0),
                         adreno.window_end(True))
        self.assertEqual(int(re.search(r'#define ADRENO_CB0_T0SZ\s+(\d+)', wide).group(1)), adreno.CB0_T0SZ_WIDE)
        self.assertEqual(header_define('ADRENO_CB0_T0SZ'), adreno.CB0_T0SZ)
        self.assertEqual((adreno.pool_bytes(), adreno.pool_bytes(True)), (0x603000, 0x1E0F000))
        self.assertEqual(adreno.pool_reservation_bytes(), 0x1E10000)
        dart_h = (ROOT / 'compat/sptm-dart.h').read_text()
        self.assertIn(f'#define SPTM_DART_ADRENO_END {adreno.window_end(True):#x}UL', dart_h)
        self.assertIn(f'#define SPTM_DART_ADRENO_END {adreno.WINDOW_END:#x}UL', dart_h)

    def test_tree(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                xb.configure_adreno_va_wide(wide)
                dt = tree(INSTALLED)
                size = struct.unpack('<Q', dt.get(adreno.DART_NODE, 'vm-size'))[0]
                self.assertEqual(struct.unpack('<Q', dt.get(adreno.DART_NODE, 'vm-base'))[0], 0x40000000)
                self.assertEqual(size, 0x3C0000000 if wide else 0xC0000000)
                gpu = dt.nodes[adreno.GPU_NODE]
                if wide:
                    self.assertEqual(gpu[adreno.GPU_VA_BITS_PROPERTY].value, struct.pack('<I', 34))
                else:
                    self.assertNotIn(adreno.GPU_VA_BITS_PROPERTY, gpu)

    def test_record_t0sz(self):
        info = Adoption().info(adreno.fixture_record())
        narrow, wide = adreno.fixture_record(), adreno.fixture_record(wide=True)
        self.assertEqual((narrow['cb0']['tcr'], wide['cb0']['tcr']), (0x802020, 0x80201E))
        adreno.load_adoption(narrow, info)
        adreno.load_adoption(wide, info, True)
        for record, flag in ((narrow, True), (wide, False), (dict(wide, cb0=dict(wide['cb0'], tcr=0x80601E)), True)):
            with self.assertRaises(ValueError):
                adreno.load_adoption(record, info, flag)

    def test_params_pool(self):
        spec, record = adreno.AdrenoSpec(va_wide=True), adreno.fixture_record(wide=True)
        pool = 0x9D0000000
        words = adreno.params_words(spec, record, pool_pa=pool)
        self.assertEqual(words[8], pool)
        self.assertEqual(words[6], 0x80201E)
        self.assertEqual(adreno.params_words(adreno.AdrenoSpec(), adreno.fixture_record())[8],
                         adreno.fixture_record()['pool']['pa'])
        a0 = record['arena']['base']
        for bad in (None, pool + 1, a0, a0 + (32 << 20) - 0x1000, record['cb0']['ttbr0'] - 0x1000, 1 << 40):
            with self.assertRaises(ValueError, msg=str(bad)):
                adreno.params_words(spec, record, pool_pa=bad)
        with self.assertRaises(ValueError):
            adreno.params_words(adreno.AdrenoSpec(), adreno.fixture_record(), pool_pa=pool)
        with self.assertRaises(ValueError):
            adreno.check_pool_reservation(record, pool, [(0x8C0000000, 0x110001000)])

    def test_reservation_placement(self):
        xb.configure_guest(INSTALLED)
        span = 8192 << 20
        xb.place(0x8c0000000, span + xb.bootstrap_reserve(span) + monitor_work.WORK_SIZE, guest_span=span)
        self.assertIsNone(xb.gpu_pool_reservation())
        xb.configure_adreno_va_wide(True)
        base, size = xb.gpu_pool_reservation()
        ans = xb.ans_reservation()
        self.assertEqual(size, adreno.pool_reservation_bytes())
        self.assertEqual(base, (ans[0] + ans[1] + 0xFFFF) & ~0xFFFF)
        work = (xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN + 65535) & ~65535
        self.assertGreaterEqual(base, work + monitor_work.WORK_SIZE)
        free = [(0x8c0000000, base + size)]
        info = {'gpu_arena_base': 0xFCC00000, 'gpu_arena_size': 32 << 20}
        monitor_work.validate_gpu_pool(base, size, ans[0] + ans[1], info, free)
        for args in ((base + 0x10000, size, ans[0] + ans[1], info, free),
                     (base, size - 0x1000, ans[0] + ans[1], info, free),
                     (base, size, ans[0] + ans[1], info, [(0x8c0000000, base + size - 0x1000)]),
                     (base, size, ans[0] + ans[1], {'gpu_arena_base': base, 'gpu_arena_size': 32 << 20}, free)):
            with self.assertRaises(ValueError):
                monitor_work.validate_gpu_pool(*args)
        self.assertNotIn(base, [lo for lo, _, _, _ in xb.stage2_ranges()])
        for lo, hi, _, what in xb.stage2_ranges():
            self.assertFalse(lo < base + size and base < hi, what)

    def test_image_carries_wide_params(self):
        xb.configure_guest(FULL)
        xb.configure_adreno_va_wide(True)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        record = adreno.fixture_record(wide=True)
        xb.ADRENO_RECORD = record
        kc = ROOT / 'build/auxkc-20260925/aux-hello.kc'
        if not kc.exists():
            self.skipTest('pinned aux-hello.kc not present')
        with contextlib.redirect_stdout(io.StringIO()):
            built = xb.build(str(xb.DEFAULT_KERNELCACHE), auxkc=str(kc))
        offset = int(re.findall(r'^\s*(\d+) \|   struct adreno_params gpu$', compiled_params_layout(), re.M)[0])
        gpu = list(struct.unpack_from(f'<{adreno.PARAMS_WORDS}Q', built['chunks'][xb.PARAMS_PA], offset))
        pool = xb.gpu_pool_reservation()
        self.assertEqual(gpu[8], pool[0])
        self.assertEqual(gpu, adreno.params_words(xb.adreno_spec(), record, pool_pa=pool[0]))


class StoppedStateAudit(unittest.TestCase):
    """review: tools/audit-secondary-runtime.py audits the stopped monitor's stage 2 against an
    exact range list; an Adreno profile's passthrough must be in it, with the monitor's own bits."""

    @staticmethod
    def build(ranges, work):
        """A 4 KiB-granule, 36-bit stage 2 over `ranges` (2 MiB blocks where aligned)."""
        mem, nxt = {}, [work]

        def alloc():
            nxt[0] += 4096
            mem[nxt[0] - 4096] = [0] * 512
            return nxt[0] - 4096
        root = alloc()

        def table(ipa, target):
            t = root
            for level in range(1, target):
                i = (ipa >> (12 + 9 * (3 - level))) & 511
                if not mem[t][i]:
                    mem[t][i] = alloc() | 3
                t = mem[t][i] & 0x0000fffffffff000
            return t
        for lo, hi, low, upper in ranges:
            ipa = lo
            while ipa < hi:
                if not ipa & 0x1FFFFF and ipa + 0x200000 <= hi:
                    mem[table(ipa, 2)][(ipa >> 21) & 511] = ipa | low | upper | 1
                    ipa += 0x200000
                else:
                    mem[table(ipa, 3)][(ipa >> 12) & 511] = ipa | low | upper | 3
                    ipa += 0x1000
        return root, lambda pa, n: struct.pack('<512Q', *mem[pa])

    def test_bits_match_stage2_h(self):
        h = (ROOT / 'shadow/stage2.h').read_text()
        bit = lambda name: eval(re.search(rf'#define {name}\s+\((.*?)\)', h).group(1).replace('UL', ''))
        device = bit('S2_MEMATTR_DEVICE_nGnRE') | bit('S2_SH_INNER') | bit('S2_AF')
        self.assertEqual(adreno.S2_DEVICE_RW, bit('S2_AP_RW') | device)
        self.assertEqual(adreno.S2_DEVICE_RO, bit('S2_AP_RO') | device)
        self.assertEqual(adreno.S2_XN, bit('S2_XN'))

    def test_audit_accepts_the_passthrough(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        from stage2audit import audit_private_stage2
        work = 0x9c0000000
        memory = [(0x8c0000000, 0x8c0400000, 0x7fc, 0)]
        for flags in (adreno.F_ENABLE, adreno.F_ENABLE | adreno.F_CX_MISC, adreno.AdrenoSpec().flags()):
            gpu = adreno.stage2_audit_ranges(flags)
            root, read = self.build(memory + gpu, work)
            banks = [dict(root=root, vttbr=root | 1 << 48, guards=[])]
            audit_private_stage2(read, banks, memory + gpu, work, work + (1 << 20))
            with self.assertRaises(AssertionError):     # the audit as it was: the windows unexplained
                audit_private_stage2(read, banks, memory, work, work + (1 << 20))
        self.assertEqual(adreno.stage2_audit_ranges(0), [])

    def test_audit_finds_params_gpu(self):
        """The audit's own layout lookup (clang record dump of probes/xnuboot.c) names params.gpu."""
        block = compiled_params_layout()
        offset = int(re.findall(r'^\s*(\d+) \|   \S.* gpu$', block, re.M)[0])
        txm_offset = int(re.findall(r'^\s*(\d+) \|   struct txm_native_params txm_native$', block, re.M)[0])
        size = int(re.findall(r'\[sizeof=(\d+),', block)[0])
        self.assertEqual(offset + 8 * adreno.PARAMS_WORDS, txm_offset)
        self.assertEqual(size, 8 * xb.PARAMS_WORDS)


class Classifier(unittest.TestCase):
    def test_stops(self):
        call = (1, 0, 0, 0, 0, 0)
        code, why = run.classify(1, 0, '', [call, (46, 0xfffffe0010000000, 0x03D7DFA0, 0x93800046, 9, 0)])
        self.assertEqual(code, run.EXIT_UNSUPPORTED)
        self.assertIn('trapped Adreno block', why)
        self.assertIn('GMU', why)
        code, why = run.classify(1, 0, '', [call, (48, 0x1000, 0xc4000003, 0, (1 << 64) - 1, 0)])
        self.assertEqual(code, run.EXIT_UNSUPPORTED)
        self.assertIn('HVC', why)
        self.assertEqual(run.PREPARE_FAILURES[-62][:17], 'Adreno GX is off ')
        self.assertEqual(run.GPU_FLOW_OFFSET, run.RUNTIME_STORAGE_OFFSET + 31 * 8)


class SecondaryAdmission(unittest.TestCase):
    """The secondary PMGR binding admits the recovery and installed Adreno profiles (A16 launches stopped with
    'secondary PMGR binding requires the selected J700 26A428 profile' before this list had them)."""
    def test_adreno_profiles_admitted(self):
        validate = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))['validate_guest_profile']
        for name in ('j700ap-26A428-xars-uniform-auxkc-adreno', 'j700ap-26A428-xars-uniform-auxkc-adreno-nodart', INSTALLED):
            validate(name)


if __name__ == '__main__':
    unittest.main()
