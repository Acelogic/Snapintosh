#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cycle.py installed-fresh --input, offline: monitor, loader and image for the built-in keyboard.

    python3 tools/test-i2c-input.py                       # header, source, layout, loader (seconds)
    python3 tools/test-i2c-input.py --image               # + the complete guest images (about a minute)
    python3 tools/test-i2c-input.py --build [--out DIR] [--expect control=SHA256 --expect fast=SHA256]

No hardware. docs/A16-INPUT-INSTALLED-20261017.md.

Monitor: tools/test-i2c-input.c runs compat/i2c-input.h against the real stage-2 builder
(sanitized) and must PASS; weakened copies of the header must FAIL it. The header's constants equal
probes/i2cinput.py's; probes/xnuboot.c defaults the define to 0, includes the header and grows
struct params, the range array and MAP_PAGE's device test only under it, keeps the literal
`#define PARAMS_WORDS 1154` the other tests read, and refuses a bad block with -41. Clang's record
layout with and without the define: only the six appended words differ.

Loader: the -input profile is the quiet profile plus i2c_input and nothing else; the spec refuses
the unsurveyed touchpad, interrupts and odd poll periods; probes/i2cinput.py's rows() agrees with
the header on the same corpus; every node property name fits Apple's 32-byte name field.

--image: SNAP_SEED fixes the handoff seed so images compare byte for byte. The default profile's
image is checked by cycle_lib/installed_fresh.image_checks as before and carries no input node; the
-input profile with the default AuxKC differs from it only in the device tree (one appended ranges
triple and the keyboard node, nothing else), the params (exactly the six appended words) and the
boot-arguments page that records the tree's size; and the -input profile with the combined AuxKC passes
image_checks(--input), the AuxKC admitted by the loader.

--build: xnuboot with cycle.py's control and fast flag sets, define absent, =0 and =1. Absent and =0
are the same bytes; =1 differs and fits the code budget; --expect NAME=SHA256 requires the default
build to equal a monitor built from the sources before this change.
"""
from pathlib import Path
import argparse
import ast
import copy
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
from dataclasses import fields, replace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.path.insert(0, str(ROOT / 'tools'))
import i2cinput  # noqa: E402
from source_text import read_source  # noqa: E402

HEADER = ROOT / 'compat/i2c-input.h'
SOURCE = ROOT / 'probes/xnuboot.c'
QUIET = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet'
INPUT = QUIET + '-input'
_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--image', action='store_true')
_ap.add_argument('--build', action='store_true')
_ap.add_argument('--out')
_ap.add_argument('--expect', action='append', default=[])
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
MUTATIONS = (
    ('no magic check', 'p->magic != I2C_INPUT_MAGIC || ', ''),
    ('unknown flags accepted', ' || (p->flags & ~(uint64_t)I2C_INPUT_F_ALL)', ''),
    ('a 16 KiB window accepted', 'hi[i] != pa[i] + I2C_INPUT_PAGE', 'hi[i] < pa[i] + I2C_INPUT_PAGE'),
    ('a disabled device\'s address ignored', '} else if (lo[i] || hi[i]) {\n            return -1;\n        }', '}'),
    ('read-only', 'S2_AP_RW | S2_ATTRS_DEVICE', 'S2_AP_RO | S2_ATTRS_DEVICE'),
    ('executable', 'S2_AP_RW | S2_ATTRS_DEVICE, S2_XN}', 'S2_AP_RW | S2_ATTRS_DEVICE, 0}'),
    ('the whole QUP window mapped', 'out[n++] = (struct stage2_range){pa[i], pa[i] + I2C_INPUT_PAGE,',
     'out[n++] = (struct stage2_range){pa[i], pa[i] + 0x4000,'),
    ('rows written before the checks', '    for (unsigned i = 0; i < 2; i++) {\n        if (p->flags & (1u << i)) {\n            if',
     '    out[0] = (struct stage2_range){0};\n    for (unsigned i = 0; i < 2; i++) {\n        if (p->flags & (1u << i)) {\n            if'),
)


def compile_c(work, header_dir=None):
    out = work / 'test-i2c-input'
    include = [f'-I{header_dir}'] if header_dir else []
    result = subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
                             '-Werror', *include, '-Ishadow', '-Icompat', 'tools/test-i2c-input.c', 'shadow/mmu.c',
                             'shadow/shadow.c', 'shadow/stage2.c', '-o', str(out)], cwd=ROOT,
                            capture_output=True, text=True)
    return out if result.returncode == 0 else None


def layout(defines=()):
    text = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                           '-Ishadow', '-Icompat', *defines, '-Xclang', '-fdump-record-layouts', '-fsyntax-only',
                           'probes/xnuboot.c'], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for block in text.split('*** Dumping AST Record Layout'):
        if re.search(r'^\s*0 \| struct params\n', block, re.M):
            fields_ = {m[2]: int(m[1]) for m in re.finditer(r'^\s*(\d+) \|   \S.* (\w+)$', block, re.M)}
            return fields_, int(re.search(r'\[sizeof=(\d+),', block)[1])
    raise AssertionError('no struct params layout')


def defines(text):
    return {n: int(v.rstrip('ULu'), 0) for n, v in re.findall(r'#define (I2C_INPUT_\w+)\s+(0x[0-9A-Fa-f]+U?L*L?|\d+)u?\b', text)}


class Monitor(unittest.TestCase):
    def test_host_model(self):
        with tempfile.TemporaryDirectory() as work:
            binary = compile_c(Path(work))
            self.assertIsNotNone(binary)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stdout, r'PASS: \d+ checks, 0 failures')

    def test_weakened_header_fails(self):
        text = HEADER.read_text()
        survivors = []
        with tempfile.TemporaryDirectory() as work:
            for n, (what, old, new) in enumerate(MUTATIONS):
                self.assertEqual(text.count(old), 1, what)
                folder = Path(work) / str(n)
                folder.mkdir()
                (folder / 'i2c-input.h').write_text(text.replace(old, new))
                binary = compile_c(folder, folder)
                if binary and subprocess.run([str(binary)], capture_output=True).returncode == 0:
                    survivors.append(what)
        self.assertEqual(survivors, [])

    def test_constants_match_the_loader(self):
        d = defines(HEADER.read_text())
        self.assertEqual(d['I2C_INPUT_MAGIC'], i2cinput.MAGIC)
        self.assertEqual(d['I2C_INPUT_KEYBOARD_PA'], i2cinput.KEYBOARD.pa)
        self.assertEqual(d['I2C_INPUT_TOUCHPAD_PA'], i2cinput.TOUCHPAD.pa)
        self.assertEqual(d['I2C_INPUT_PAGE'], i2cinput.PAGE)
        self.assertEqual(d['I2C_INPUT_PARAMS_WORDS'], i2cinput.PARAMS_WORDS)
        self.assertEqual((d['I2C_INPUT_F_KEYBOARD'], d['I2C_INPUT_F_TOUCHPAD']),
                         (i2cinput.F_KEYBOARD, i2cinput.F_TOUCHPAD))
        s2 = (ROOT / 'shadow/stage2.h').read_text()
        def bit(name):   # each is "(N UL << S)" in shadow/stage2.h
            value, shift = re.search(r'#define %s\s+\((\w+)UL << (\d+)\)' % name, s2).groups()
            return int(value, 0) << int(shift)
        self.assertEqual(bit('S2_AP_RW') | bit('S2_MEMATTR_DEVICE_nGnRE') | bit('S2_SH_INNER') | bit('S2_AF'),
                         i2cinput.S2_DEVICE_RW)
        self.assertEqual(bit('S2_XN'), i2cinput.S2_XN)

    def test_monitor_source(self):
        src = read_source(SOURCE)
        self.assertIn('#ifndef SNAP_I2C_INPUT\n#define SNAP_I2C_INPUT 0\n#endif\n'
                      '#if SNAP_I2C_INPUT\n#include "../compat/i2c-input.h"\n#endif\n', src)
        self.assertEqual(src.count('i2c-input.h"'), 1)
        self.assertEqual(re.search(r'#define PARAMS_WORDS (\d+)', src)[1], '1154')
        self.assertIn('#define PARAMS_WORDS 1154\n#if SNAP_I2C_INPUT\n#undef PARAMS_WORDS\n'
                      '#define PARAMS_WORDS (1154 + I2C_INPUT_PARAMS_WORDS)\n#endif\n_Static_assert(', src)
        struct_params = src[src.index('struct params {'):src.index('};', src.index('struct params {'))]
        self.assertTrue(struct_params.rstrip().endswith('struct i2c_input_params i2c_input;\n#endif'))
        # Every use of the new names sits inside an #if SNAP_I2C_INPUT block.
        depth, inside = [], []
        code = re.sub(r'/\*.*?\*/', lambda m: '\n' * m[0].count('\n'), src, flags=re.S)
        for line in code.splitlines():
            if line.startswith('#if'):
                depth.append('SNAP_I2C_INPUT' in line)
            elif line.startswith('#endif'):
                depth.pop()
            elif re.search(r'i2c_input|I2C_INPUT_', line):
                inside.append(any(depth))
        self.assertTrue(inside and all(inside), 'an i2c_input use outside #if SNAP_I2C_INPUT')
        self.assertIn('if (rows < 0) return -41;', src)
        self.assertEqual(len(re.findall(r'return -41;', src)), 1)

    def test_layout_only_appends(self):
        base, base_size = layout()
        on, on_size = layout(['-DSNAP_I2C_INPUT=1'])
        self.assertEqual(base_size, 1154 * 8)
        self.assertEqual(on_size, (1154 + i2cinput.PARAMS_WORDS) * 8)
        self.assertNotIn('i2c_input', base)
        self.assertEqual(on.pop('i2c_input'), 1154 * 8)
        for name in ('magic', 'flags', 'keyboard_pa', 'keyboard_end', 'touchpad_pa', 'touchpad_end'):
            on.pop(name, None)
        self.assertEqual(on, base)


class Loader(unittest.TestCase):
    def test_profile_is_quiet_plus_input(self):
        from guestprofile import get_profile
        quiet, input_ = get_profile(QUIET), get_profile(INPUT)
        self.assertIsNone(quiet.i2c_input)
        self.assertEqual(input_.i2c_input, i2cinput.I2CInputSpec())
        self.assertEqual(replace(quiet, name=INPUT, i2c_input=input_.i2c_input), input_)
        changed = [f.name for f in fields(quiet) if getattr(quiet, f.name) != getattr(input_, f.name)]
        self.assertEqual(sorted(changed), ['i2c_input', 'name'])
        touchpad = get_profile(INPUT + '-touchpad')
        self.assertEqual(touchpad.i2c_input, i2cinput.I2CInputSpec(keyboard=True, touchpad=True))
        self.assertEqual(replace(input_, name=touchpad.name, i2c_input=touchpad.i2c_input), touchpad)
        import runpy
        validate = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))['validate_guest_profile']
        validate(INPUT)
        validate(INPUT + '-touchpad')

    def test_spec_refusals(self):
        for kwargs in (dict(keyboard=False, touchpad=False), dict(poll_us=500),
                       dict(poll_us=200000), dict(irq_policy=0)):
            with self.assertRaises(ValueError, msg=kwargs):
                i2cinput.I2CInputSpec(**kwargs)
        # The touchpad is described, and refused at every use while its controller is unqualified
        # (qualified on generation 33: tools/qualify-a16-touchpad.py, v47).
        both = i2cinput.I2CInputSpec(touchpad=True)
        saved = i2cinput.TOUCHPAD_QUALIFIED
        try:
            i2cinput.TOUCHPAD_QUALIFIED = False
            for use in (both.require_qualified, lambda: i2cinput.stage2_ranges(both),
                        lambda: i2cinput.params_words(both), lambda: i2cinput.prepare_tree(None, both)):
                with self.assertRaisesRegex(ValueError, 'unqualified'):
                    use()
            i2cinput.I2CInputSpec().require_qualified()
            i2cinput.TOUCHPAD_QUALIFIED = True
            self.assertEqual(i2cinput.params_words(both),
                             [i2cinput.MAGIC, 3, 0x0088C000, 0x0088D000, 0x00B80000, 0x00B81000])
            self.assertEqual([r[:2] for r in i2cinput.stage2_ranges(both)],
                             [(0x0088C000, 0x0088D000), (0x00B80000, 0x00B81000)])
        finally:
            i2cinput.TOUCHPAD_QUALIFIED = saved

    def test_rows_agree_with_the_header(self):
        spec = i2cinput.I2CInputSpec()
        words = i2cinput.params_words(spec)
        self.assertEqual(words, [i2cinput.MAGIC, 1, 0x0088C000, 0x0088D000, 0, 0])
        self.assertEqual(i2cinput.rows(words), [(0x0088C000, 0x0088D000)])
        self.assertEqual(i2cinput.stage2_ranges(spec),
                         [(0x0088C000, 0x0088D000, 'rw', 'i2c-hid-kbd GENI I2C page (Device-nGnRE)')])
        bad = [[0] * 6, [i2cinput.MAGIC ^ 1, *words[1:]], [i2cinput.MAGIC, 0, *words[2:]],
               [i2cinput.MAGIC, 5, *words[2:]], [*words[:3], 0x0088C000 + 0x4000, 0, 0],
               [*words[:2], 0x0088D000, 0x0088E000, 0, 0], [*words[:4], 0x00B80000, 0], words[:5]]
        for block in bad:
            self.assertIsNone(i2cinput.rows(block), block)
            self.assertEqual(i2cinput.stage2_audit_ranges(block), [])
        both = [i2cinput.MAGIC, 3, 0x0088C000, 0x0088D000, 0x00B80000, 0x00B81000]
        self.assertEqual(i2cinput.rows(both), [(0x0088C000, 0x0088D000), (0x00B80000, 0x00B81000)])
        self.assertEqual(i2cinput.stage2_audit_ranges(words), [(0x0088C000, 0x0088D000, 0x7C4, 1 << 54)])

    def test_property_names_fit(self):
        names = set(re.findall(r"'(snapintosh,[\w-]+)'", (ROOT / 'probes/i2cinput.py').read_text()))
        self.assertTrue(names)
        self.assertTrue(all(len(n) <= 31 for n in names), [n for n in names if len(n) > 31])
        driver = ROOT / 'drivers/snap-i2c-hid/src/SnapI2CHID.cpp'
        read = set(re.findall(r'"(snapintosh,[\w-]+)"', read_source(driver)))
        self.assertLessEqual(names - {'snapintosh,hid-product'}, read, 'a node property the kext does not read')
        self.assertTrue(all(len(n) <= 31 for n in read))

    def test_installed_fresh_selection(self):
        from cycle_lib import installed_fresh as f
        default = types.SimpleNamespace(variant='fast')
        on = types.SimpleNamespace(variant='fast', input=True)
        self.assertEqual(f.selected(default), (f.PROFILE, f.AUXKC, f.AUXKC_SHA, [f.KEXT_BUNDLE]))
        self.assertEqual(f.selected(on)[0], INPUT)
        self.assertEqual(f.selected(types.SimpleNamespace(input=True, input_touchpad=True))[0], INPUT + '-touchpad')
        with self.assertRaises(BaseException):
            f.selected(types.SimpleNamespace(input_touchpad=True))
        sets = dict(fast=['-DX=1'], control=['-DX=1'])
        self.assertEqual(f.variant_flags(sets, default), ['-DX=1'])
        self.assertEqual(f.variant_flags(sets, on), ['-DX=1', i2cinput.DEFINE])
        self.assertEqual(f.INPUT_DEFINE, i2cinput.DEFINE)
        self.assertEqual(f.INPUT_BUNDLES, sorted(['org.snapintosh.driver.AdrenoX2', i2cinput.BUNDLE]))


@unittest.skipUnless(ARGS.image, 'pass --image to build the guest images')
class Image(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SNAP_SEED'] = 'test-i2c-input'
        from cycle_lib import installed_fresh as f
        from cycle_lib.bootstrap_smoke import load
        cls.f = f
        cls.layout = load('i2c_layout', ROOT / 'tools/monitor_layout.py').MonitorLayout()
        cls.work = Path(tempfile.mkdtemp(prefix='i2c-input-image-'))
        _, payload = f.root_hash_payload(ROOT)
        (cls.work / 'root-hash.payload').write_bytes(payload)

    def image(self, name, input_, aux=None, touchpad=False):
        dest = self.work / name
        dest.mkdir()
        saved = self.f.INPUT_AUXKC, self.f.INPUT_AUXKC_SHA
        if aux:
            self.f.INPUT_AUXKC, self.f.INPUT_AUXKC_SHA = aux
        try:
            record = self.f.image_checks(ROOT, dest, self.layout, self.work / 'root-hash.payload',
                                         args=types.SimpleNamespace(input=input_, input_touchpad=touchpad))
        finally:
            self.f.INPUT_AUXKC, self.f.INPUT_AUXKC_SHA = saved
        return record, (dest / 'device-tree.bin').read_bytes()

    def test_images(self):
        from appledt import DeviceTree
        f = self.f
        default, tree0 = self.image('default', False)
        self.assertNotIn('input', default)
        same_aux, tree1 = self.image('input-default-auxkc', True, (f.AUXKC, f.AUXKC_SHA))
        chunks0 = {c['address']: c for c in default['chunks']}
        chunks1 = {c['address']: c for c in same_aux['chunks']}
        self.assertEqual(set(chunks0), set(chunks1))
        differing = sorted(a for a in chunks0 if chunks0[a] != chunks1[a])
        # the boot arguments page (the device tree's size), the params, the device tree
        self.assertEqual(differing, ['0x8c0001000', '0x8c000c000', '0x8c0010000'], differing)
        self.assertEqual(chunks1['0x8c000c000']['bytes'], chunks0['0x8c000c000']['bytes'] + 8 * i2cinput.PARAMS_WORDS)
        dt0, dt1 = DeviceTree(tree0), DeviceTree(tree1)
        node = i2cinput.KEYBOARD.node
        self.assertEqual(set(dt1.nodes) - set(dt0.nodes), {node})
        self.assertEqual(set(dt0.nodes) - set(dt1.nodes), set())
        for path, props in dt0.nodes.items():
            other = dt1.nodes[path]
            self.assertEqual(set(props), set(other), path)
            for key, prop in props.items():
                if path == '/device-tree/arm-io' and key == 'ranges':
                    self.assertEqual(bytes(other[key].value), bytes(prop.value) + struct.pack(
                        '<3Q', i2cinput.CHILD_OFFSET + 0x0088C000, 0x0088C000, i2cinput.QUP_SPAN))
                else:
                    self.assertEqual(bytes(other[key].value), bytes(prop.value), f'{path} {key}')
        self.assertEqual([c for c in dt1.children['/device-tree/arm-io'] if c != node],
                         dt0.children['/device-tree/arm-io'])
        self.assertEqual({k: v for k, v in dt1.children.items() if k != node}, dt0.children | {
            '/device-tree/arm-io': dt1.children['/device-tree/arm-io']})
        self.assertEqual({k: bytes(v.value) for k, v in dt1.nodes[node].items()}, {
            'name': b'i2c-hid-kbd\0', 'compatible': b'snapintosh,geni-i2c-hid\0', 'device_type': b'i2c-hid\0',
            'reg': struct.pack('<QQ', 0x7_0088_C000, 0x1000),
            'snapintosh,hid-address': struct.pack('<I', 0x15),
            'snapintosh,hid-descriptor-reg': struct.pack('<I', 1),
            'snapintosh,hid-vendor-product': struct.pack('<2I', 0x0B05, 0x4B42),
            'snapintosh,poll-us': struct.pack('<I', 8000), 'snapintosh,irq-policy': struct.pack('<I', 1),
            'snapintosh,hid-product': b'ASUS Zenbook A16 Keyboard\0'})
        combined, _ = self.image('input', True)
        self.assertEqual(combined['input']['stage2'], [['0x88c000', '0x88d000']])
        # The touchpad profile: refused while unqualified; with the flag set, both nodes, both pages.
        saved = i2cinput.TOUCHPAD_QUALIFIED
        try:
            i2cinput.TOUCHPAD_QUALIFIED = False
            with self.assertRaisesRegex(BaseException, 'unqualified'):
                self.image('input-touchpad-refused', True, touchpad=True)
            i2cinput.TOUCHPAD_QUALIFIED = True
            both, tree = self.image('input-touchpad', True, touchpad=True)
        finally:
            i2cinput.TOUCHPAD_QUALIFIED = saved
        self.assertEqual(both['input']['stage2'], [['0x88c000', '0x88d000'], ['0xb80000', '0xb81000']])
        self.assertEqual(both['input']['nodes'], [i2cinput.KEYBOARD.node, i2cinput.TOUCHPAD.node])
        node = DeviceTree(tree).nodes[i2cinput.TOUCHPAD.node]
        self.assertEqual(bytes(node['snapintosh,hid-vendor-product'].value), struct.pack('<2I', 0x2808, 0x0219))
        self.assertEqual(bytes(node['reg'].value), struct.pack('<QQ', 0x7_00B8_0000, 0x1000))
        self.assertEqual(combined['profile'], INPUT)
        self.assertNotEqual(combined['auxkc_range'], default['auxkc_range'])


def flag_sets():
    from cycle_lib import speed_test
    return speed_test.flag_sets(ROOT)[0]


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='i2c-input-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for name, flags in flag_sets().items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_I2C_INPUT=0']), ('on', [i2cinput.DEFINE])):
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
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
