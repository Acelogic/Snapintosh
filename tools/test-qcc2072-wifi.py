#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cycle.py installed-fresh --qcc2072-wifi, offline: monitor, loader, live-path replay, images and builds.

    python3 tools/test-qcc2072-wifi.py                      # header, source, layout, loader, replay (seconds)
    python3 tools/test-qcc2072-wifi.py --image              # + the complete guest images (minutes)
    python3 tools/test-qcc2072-wifi.py --build [--out DIR] [--expect NAME=SHA256 ...] [--qualification JSON ...]

No hardware. Failure inventories: compat/qcc2072-wifi.h (monitor), probes/qcc2072wifi.py (loader),
tools/test-qcc2072-wifi.c (the host model's).

Monitor: tools/test-qcc2072-wifi.c runs compat/qcc2072-wifi.h against the real stage-2 builder (sanitized)
and must PASS; weakened copies of the header must FAIL it. The header's constants equal
probes/qcc2072wifi.py's; probes/xnuboot.c defaults the define to 0 and uses every new name only under it;
struct params is the same with and without the define (the block is read after it); -42 is unique.

Loader: rows() agrees with the header; the record is re/host-proxy/run.py make_record's word list; the node's
property names fit Apple's 31 characters; installed-fresh's flag, environment and collection selection.

Replay: the live admission, upload and stop against a register and memory model of the A16 that serves the
PCIe SMMU tables captured on hardware (--s2-walk, default operator-20261021-wifi/s2-a16): the arena's 32
blocks identity read/write, command 0 -> 2 after every check, every arena byte rewritten, cleaned to PoC and
read back, bus mastering off at the stop; each refusal leaves the command register untouched.

--image: SNAP_SEED fixes the handoff seed. The neon route (--input --input-touchpad --input-ptp
--present-dartpool) with and without --qcc2072-wifi, both on the route's own collection (the node, params and
stage 2 do not depend on it; the Wi-Fi collection is the boot's): only the boot-arguments page, the params
(exactly twelve words appended) and the device tree (five ranges triples appended, one node) differ, and the
Wi-Fi image passes installed_fresh.image_checks(--qcc2072-wifi).

--build: xnuboot with cycle.py's control and fast flag sets and each --qualification's flags, define absent,
=0 and =1. Absent and =0 are the same bytes; =1 differs and fits the code budget; --expect NAME=SHA256 (or the
qualification's monitor_sha256) requires the default build to equal a monitor built from the base sources.
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
import qcc2072wifi as q  # noqa: E402

HEADER = ROOT / 'compat/qcc2072-wifi.h'
SOURCE = ROOT / 'probes/xnuboot.c'
OPS = Path(os.environ.get('SNAPINTOSH_OPS', '/nonexistent/set-SNAPINTOSH_OPS'))  # operator/agent tree (baselines, receipts)
_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--image', action='store_true')
_ap.add_argument('--build', action='store_true')
_ap.add_argument('--out')
_ap.add_argument('--expect', action='append', default=[])
_ap.add_argument('--qualification', action='append', default=[])
_ap.add_argument('--s2-walk', default=str(OPS / 'operator-20261021-wifi/s2-a16'))
_ap.add_argument('--inputs', help='a directory holding the three inputs (default: probes/qcc2072wifi.SOURCES)')
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
MUTATIONS = (
    ('no magic check', 'p->magic == QCC2072_WIFI_MAGIC && ', ''),
    ('no flags check', ' && p->flags == QCC2072_WIFI_F_ENABLE', ''),
    ('BAR2 widened', 'p->bar2_end == QCC2072_WIFI_BAR2_PA + QCC2072_WIFI_BAR2_BYTES',
     'p->bar2_end >= QCC2072_WIFI_BAR2_PA + QCC2072_WIFI_BAR2_BYTES'),
    ('ECAM read-write', 'S2_AP_RO | S2_ATTRS_DEVICE', 'S2_AP_RW | S2_ATTRS_DEVICE'),
    ('control read-write', 'S2_AP_RO | QCC2072_WIFI_S2_ATTRS_NC', 'S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC'),
    ('arena cacheable', '(5UL << 2)', '(0xfUL << 2)'),
    ('arena executable', 'S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC, S2_XN}', 'S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC, 0}'),
    ('record unchecked', ' || !qcc2072_wifi_record_valid(record)', ''),
    ('generation and cookie unchecked', 'return r[4] && r[5];', 'return 1;'),
    ('rows written before the checks', '    if (!qcc2072_wifi_valid(p) || !record',
     '    out[0] = (struct stage2_range){0};\n    if (!qcc2072_wifi_valid(p) || !record'),
    ('any configuration offset written', ' || ipa != p->ecam_pa + QCC2072_WIFI_COMMAND', ''),
    ('byte stores written', 'if (size == 2)\n', 'if (size == 2 || size == 1)\n'),
    ('bus master without memory decode', 'v != (QCC2072_WIFI_CMD_MEMORY | QCC2072_WIFI_CMD_MASTER))',
     'v != (QCC2072_WIFI_CMD_MEMORY | QCC2072_WIFI_CMD_MASTER) && v != QCC2072_WIFI_CMD_MASTER)'),
)
NEON = dict(input=True, input_touchpad=True, input_ptp=True, present_dartpool=True)


def compile_c(work, header_dir=None):
    out = work / 'test-qcc2072-wifi'
    include = [f'-I{header_dir}'] if header_dir else []
    result = subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
                             '-Werror', *include, '-Ishadow', '-Icompat', 'tools/test-qcc2072-wifi.c', 'shadow/mmu.c',
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
    return {n: int(v.rstrip('ULu'), 0) for n, v in
            re.findall(r'#define (QCC2072_WIFI_\w+)\s+\(?(0x[0-9A-Fa-f]+U?L*L?|\d+)u?L*\b', text)}


def inputs():
    if ARGS.inputs:
        return q.load_inputs(ARGS.inputs)
    return {n: Path(q.SOURCES[n]).read_bytes() for n in q.INPUTS}


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
                (folder / 'qcc2072-wifi.h').write_text(text.replace(old, new))
                binary = compile_c(folder, folder)
                if binary and subprocess.run([str(binary)], capture_output=True).returncode == 0:
                    survivors.append(what)
        self.assertEqual(survivors, [])

    def test_constants_match_the_loader(self):
        d = defines(HEADER.read_text())
        self.assertEqual(d['QCC2072_WIFI_MAGIC'], q.MAGIC)
        self.assertEqual(d['QCC2072_WIFI_PARAMS_WORDS'], q.PARAMS_WORDS)
        self.assertEqual(d['QCC2072_WIFI_F_ENABLE'], q.F_ENABLE)
        self.assertEqual(d['QCC2072_WIFI_STAGE2_MAX'], len(q.WINDOWS))
        for name, pa, size, *_ in q.WINDOWS:
            self.assertEqual((d[f'QCC2072_WIFI_{name.upper()}_PA'], d[f'QCC2072_WIFI_{name.upper()}_BYTES']),
                             (pa, size), name)
        self.assertEqual(d['QCC2072_WIFI_RECORD_MAGIC'], q.RECORD_MAGIC)
        self.assertEqual(d['QCC2072_WIFI_COMMAND'], q.COMMAND)
        self.assertEqual((d['QCC2072_WIFI_CMD_MEMORY'], d['QCC2072_WIFI_CMD_MASTER']), (q.CMD_MEMORY, q.CMD_MASTER))
        s2 = (ROOT / 'shadow/stage2.h').read_text()

        def bit(name):   # each is "(N UL << S)" in shadow/stage2.h
            value, shift = re.search(r'#define %s\s+\((\w+)UL << (\d+)\)' % name, s2).groups()
            return int(value, 0) << int(shift)
        common = bit('S2_SH_INNER') | bit('S2_AF')
        self.assertEqual(bit('S2_AP_RW') | bit('S2_MEMATTR_DEVICE_nGnRE') | common, q.S2_DEVICE_RW)
        self.assertEqual(bit('S2_AP_RO') | bit('S2_MEMATTR_DEVICE_nGnRE') | common, q.S2_DEVICE_RO)
        self.assertEqual(bit('S2_AP_RW') | (5 << 2) | common, q.S2_NC_RW)
        self.assertEqual(bit('S2_AP_RO') | (5 << 2) | common, q.S2_NC_RO)
        self.assertEqual(bit('S2_XN'), q.S2_XN)

    def test_monitor_source(self):
        src = read_source(SOURCE)
        self.assertIn('#ifndef SNAP_QCC2072_WIFI\n#define SNAP_QCC2072_WIFI 0\n#endif\n'
                      '#if SNAP_QCC2072_WIFI\n#include "../compat/qcc2072-wifi.h"\n#endif\n', src)
        self.assertEqual(src.count('qcc2072-wifi.h"'), 1)
        self.assertEqual(re.search(r'#define PARAMS_WORDS (\d+)', src)[1], '1154')
        struct_params = src[src.index('struct params {'):src.index('};', src.index('struct params {'))]
        self.assertNotIn('qcc2072', struct_params)
        depth, inside = [], []
        code = re.sub(r'/\*.*?\*/', lambda m: '\n' * m[0].count('\n'), src, flags=re.S)
        for line in code.splitlines():
            if line.startswith('#if'):
                depth.append('SNAP_QCC2072_WIFI' in line)
            elif line.startswith('#endif'):
                depth.pop()
            elif re.search(r'qcc2072|QCC2072', line) and not line.startswith(('#ifndef SNAP_QCC2072_WIFI',
                                                                                 '#define SNAP_QCC2072_WIFI 0')):
                inside.append(any(depth))
        self.assertTrue(inside and all(inside), 'a qcc2072 use outside #if SNAP_QCC2072_WIFI')
        self.assertIn('if (rows < 0) return -42;', src)
        self.assertEqual(len(re.findall(r'return -42;', src)), 1)
        self.assertEqual(len(re.findall(r'#define EV_\w+\s+57\b', src)), 1)

    def test_struct_params_unchanged(self):
        base, base_size = layout()
        on, on_size = layout(['-DSNAP_QCC2072_WIFI=1'])
        self.assertEqual((base, base_size), (on, on_size))
        both, both_size = layout(['-DSNAP_QCC2072_WIFI=1', '-DSNAP_I2C_INPUT=1'])
        i2c, i2c_size = layout(['-DSNAP_I2C_INPUT=1'])
        self.assertEqual((both, both_size), (i2c, i2c_size))


class Loader(unittest.TestCase):
    def test_rows_agree_with_the_header(self):
        grant = q.grant(q.fixture_spec(0x8c0000000), inputs())
        words = q.params_words(grant)
        self.assertEqual(len(words), q.PARAMS_WORDS)
        self.assertEqual(q.rows(words), [(0x78000000, 0x78100000), (0xdc000000, 0xe0000000),
                                         (0x78200000, 0x78201000), (0x780100000, 0x780101000),
                                         (0xe0000000, 0xe0001000)])
        self.assertEqual([r[:3] for r in q.stage2_ranges(grant)],
                         [(0x78000000, 0x78100000, 'rw'), (0xdc000000, 0xe0000000, 'rw'),
                          (0x78200000, 0x78201000, 'rw'), (0x780100000, 0x780101000, 'ro'),
                          (0xe0000000, 0xe0001000, 'ro')])
        self.assertEqual(q.stage2_audit_ranges(words)[1], (0xdc000000, 0xe0000000, 0x7D4, 1 << 54))
        self.assertEqual(q.params_words(None), [])
        self.assertEqual(q.stage2_ranges(None), [])
        bad = [[0] * 12, [q.MAGIC ^ 1, *words[1:]], [q.MAGIC, 0, *words[2:]], [*words[:3], words[3] + 0x1000, *words[4:]],
               words[:11], [*words, 0]]
        for block in bad:
            self.assertIsNone(q.rows(block), block)
            self.assertEqual(q.stage2_audit_ranges(block), [])

    def test_record_is_the_host_harness_record(self):
        data = inputs()
        fw, bd, rg = (data[n] for n in q.INPUTS)
        up = lambda x: (x + 4095) & ~4095
        board_off = up(len(fw)); regdb_off = up(board_off + len(bd)); alloc = up(regdb_off + len(rg))
        # re/host-proxy/run.py make_record, word for word, with its generation, cookie and guest range.
        words = [0x31304e574f434351, 1, 256, 1, 7, 0x123457, 0x111217cb, 0xe14f105b, 0x40100, 31,
                 0x78000000, 0x100000, 0x78200000, 0x1000, 0x780100000,
                 0xdc000000, 0xdc000000, 0x4000000, 0xe0000000,
                 0, len(fw), board_off, len(bd), regdb_off, len(rg),
                 alloc, 0x8c0000000, 0x740000000, 64, 0, 0, 0]
        self.assertEqual(q.record(q.Spec(7, 0x123457, 0x8c0000000, 0x740000000), data), struct.pack('<32Q', *words))
        self.assertEqual(q.fixture_spec(0x8c0000000).guest_bytes, 0x740000000)
        arena = q.arena_payload(data)
        self.assertEqual(len(arena), q.DMA_BYTES)
        self.assertEqual(arena[:len(fw)], fw)
        self.assertEqual(arena[board_off:board_off + len(bd)], bd)
        self.assertEqual(arena[regdb_off:regdb_off + len(rg)], rg)
        self.assertEqual(arena[alloc:], bytes(q.DMA_BYTES - alloc))
        for name, digest in q.INPUTS.items():
            self.assertEqual(hashlib.sha256(data[name]).hexdigest(), digest, name)

    def test_spec_refusals(self):
        for args in ((0, 1, 0x8c0000000, 1 << 30), (1, 2, 0x8c0000000, 1 << 30), (1, 0, 0x8c0000000, 1 << 30),
                     (1, 1 << 63 | 1, 0x8c0000000, 1 << 30), (1, 1, 0xd0000000, 1 << 30),
                     (1, 1, 0x8c0000000, 1 << 36), (1, 1, 0x8c0000800, 1 << 30)):
            with self.assertRaises(ValueError, msg=args):
                q.Spec(*args)

    def test_property_names_fit(self):
        names = [q.ADMISSION, 'name', 'compatible', 'reg']
        self.assertTrue(all(len(n) <= 31 for n in names))
        kext = ROOT / 'drivers/snap-qcc2072'
        if kext.is_dir():
            provider = (kext / 'src/qcc2072-provider.cpp').read_text()
            self.assertIn(f'"{q.ADMISSION}"', provider)
            plist = (kext / 'Info.plist').read_text()
            self.assertIn(f'<key>IONameMatch</key><string>{q.MATCH}</string>', plist)
            self.assertIn('<key>IOProviderClass</key><string>AppleARMIODevice</string>', plist)
            header = (kext / 'src/qcc2072-provider-record.h').read_text()
            self.assertIn(f'{q.RECORD_MAGIC:#x}'.upper().replace('0X', '0x'), header.upper().replace('0X', '0x'))

    def test_tree_refusals(self):
        from appledt import Property

        class Tree:
            def __init__(self, ranges):
                self.nodes = {'/device-tree/arm-io': {'ranges': Property('ranges', b''.join(
                    struct.pack('<3Q', *r) for r in ranges))}}
                self.children = {'/device-tree/arm-io': []}

            def put(self, path, prop, value):
                self.nodes[path][prop] = Property(prop, value)
        grant = q.grant(q.fixture_spec(0x8c0000000), inputs())
        ok = Tree([(0, 0x2_0000_0000, 0x1_0000_0000)])
        made = q.prepare_tree(ok, grant)
        self.assertEqual(made['ranges'], q.triples())
        self.assertEqual(bytes(ok.nodes[q.NODE][q.ADMISSION].value), grant.record)
        with self.assertRaisesRegex(ValueError, 'overlaps|already exists'):
            q.prepare_tree(ok, grant)
        for ranges, why in (([(0x7_7800_0000, 0x1000_0000, 0x1000)], 'child'),
                            ([(0x1_0000_0000, 0xdc00_0000, 0x10_0000)], 'parent')):
            with self.assertRaisesRegex(ValueError, why):
                q.prepare_tree(Tree(ranges), grant)
        with self.assertRaisesRegex(ValueError, 'guest or monitor'):
            q.prepare_tree(Tree([]), grant, owned=[(0xd000_0000, 0x1000_0000)])
        with self.assertRaisesRegex(ValueError, 'admission record'):
            q.prepare_tree(Tree([]), None)

    def test_free_region_exclusion(self):
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run
        spans = [(0xd9dc0000, 0xf9a20000), (0x8c0000000, 0xac0000000)]
        saved = run.monitor_work.firmware_free
        run.monitor_work.firmware_free = lambda proxy, info: list(spans)
        try:
            # A span below 4 GiB is preferred: without the reservation carved out, a 256 MiB request would
            # land on the arena; with it, above the control page. A required base above 4 GiB is unaffected.
            self.assertEqual(run.free_region(None, {}, 0x10000000), (0xda000000, 0xf8000000))
            self.assertEqual(run.free_region(None, {}, 0x10000000, exclude=[q.RESERVATION]), (0xe2000000, 0xf8000000))
            self.assertEqual(run.free_region(None, {}, 0x10000000, required_base=0x8c0000000, exclude=[q.RESERVATION]),
                             (0x8c0000000, 0xac0000000))
            spans[:] = [(0xd9dc0000, 0xf9a20000)]
            self.assertEqual(run.free_region(None, {}, 0x2000000), (0xda000000, 0xf8000000))
            self.assertEqual(run.free_region(None, {}, 0x2000000, exclude=[q.RESERVATION]), (0xe2000000, 0xf8000000))
            self.assertIsNone(run.free_region(None, {}, 0x2000000, required_base=0xdc000000, exclude=[q.RESERVATION]))
        finally:
            run.monitor_work.firmware_free = saved

    def test_installed_fresh_selection(self):
        from cycle_lib import installed_fresh as f
        default = types.SimpleNamespace(variant='fast')
        wifi = types.SimpleNamespace(variant='fast', qcc2072_wifi=True, **NEON)
        sets = dict(fast=['-DX=1'], control=['-DX=1'])
        self.assertEqual(f.selected(default), f.route_selected(default))
        self.assertEqual(f.variant_flags(sets, wifi)[-1], q.DEFINE)
        self.assertNotIn(q.DEFINE, f.variant_flags(sets, types.SimpleNamespace(variant='fast', **NEON)))
        self.assertEqual(f.QCC2072_WIFI_DEFINE, q.DEFINE)
        self.assertEqual(f.QCC2072_BUNDLE, q.BUNDLE)
        self.assertEqual(f.environment(wifi)[q.ENV], '1')
        self.assertNotIn(q.ENV, f.environment(types.SimpleNamespace(**NEON)))
        with self.assertRaises(BaseException):           # no collection named
            f.selected(wifi)
        with self.assertRaises(BaseException):           # --qcc2072-wifi needs --input
            f.selected(types.SimpleNamespace(qcc2072_wifi=True, qcc2072_auxkc='x', qcc2072_auxkc_sha256='y'))
        with self.assertRaises(BaseException):           # a collection without the flag
            f.selected(types.SimpleNamespace(qcc2072_auxkc='x', **NEON))
        with tempfile.TemporaryDirectory() as work:
            folder = Path(work)
            _, aux, aux_sha, bundles = f.route_selected(wifi)
            (folder / 'native-wifi.kc').write_bytes(b'kc')
            kc_sha = hashlib.sha256(b'kc').hexdigest()
            receipt = dict(status=f.QCC2072_AUXKC_STATUS, baseline_collection_sha256=aux_sha,
                           bundle_identifiers=sorted([*bundles, q.BUNDLE]), outputs={'native-wifi.kc': kc_sha})
            (folder / 'build.json').write_text(json.dumps(receipt))
            args = types.SimpleNamespace(qcc2072_wifi=True, qcc2072_auxkc=str(folder), qcc2072_auxkc_sha256=kc_sha,
                                         **NEON)
            self.assertEqual(f.selected(args), (f.route_selected(args)[0], str((folder / 'native-wifi.kc').resolve()),
                                                kc_sha, sorted([*bundles, q.BUNDLE])))
            for key, value in (('baseline_collection_sha256', '0' * 64), ('status', 'FAILED'),
                               ('bundle_identifiers', bundles)):
                (folder / 'build.json').write_text(json.dumps(dict(receipt, **{key: value})))
                with self.assertRaises(BaseException, msg=key):
                    f.selected(args)
            (folder / 'build.json').write_text(json.dumps(receipt))
            with self.assertRaises(BaseException):
                f.selected(types.SimpleNamespace(**dict(vars(args), qcc2072_auxkc_sha256='0' * 64)))


# ---------------------------------------------------------------------------------------- live replay
class FakeA16:
    """The q1n1 proxy calls probes/qcc2072wifi.py makes, against a model of the A16: the endpoint's
    configuration and MHI registers, the PCIe SMMU's registers and its stage-2 tables as captured on hardware
    (walk-s2-low.py), and RAM for the arena and the control page, pre-filled with stale bytes."""
    P_DC_CIVAC = 0x30A

    def __init__(self, walk):
        receipt = json.loads((walk / 'receipt.json').read_text())
        self.tables = {int(p.stem[2:], 16): p.read_bytes() for p in walk.glob('t-*.bin')}
        self.ste_pa, self.ste = receipt['ste']['pa'], receipt['ste']['words']
        self.strtab = 0xcb050000
        self.l1d = ((self.ste_pa - (q.SID & 255) * 64) & 0xfffffffffffc0) | 9
        self.cfg = receipt['strtab_cfg']
        self.config = {0: q.PCI_ID, 0x2c: q.PCI_SUBSYSTEM, 0x10: q.BAR0_PA | 4, 0x14: 0, 0x18: q.BAR2_PA | 4, 0x1c: 0}
        self.command = 0
        self.mhi = {0: 0x1000, 8: 0x01000000, 0x28: 0x100, 0x38: 0, 0x48: 0, 0x128: 0}   # BHI EE at BHIOFF + 0x28
        self.arena = bytearray(b'\xa5' * q.DMA_BYTES)
        self.control = bytearray(b'\x5a' * q.SLOT)
        self.log = []

    def _ram(self, address, size):
        for base, store in ((q.DMA_PA, self.arena), (q.CONTROL_PA, self.control)):
            if base <= address and address + size <= base + len(store):
                return store, address - base
        raise AssertionError(f'RAM access outside the model: {address:#x}+{size:#x}')

    def read32(self, address):
        self.log.append(('read32', address))
        if address == q.SMMU + 32 or address == q.SMMU + 36:
            return 13
        if address == q.SMMU + 0x88:
            return self.cfg
        if q.ECAM_PA <= address < q.ECAM_PA + 0x1000:
            off = address - q.ECAM_PA
            return self.command if off == 4 else self.config[off]
        if q.BAR0_PA <= address < q.BAR0_PA + q.BAR0_BYTES:
            return self.mhi[address - q.BAR0_PA]
        raise AssertionError(f'read32 outside the model: {address:#x}')

    def read64(self, address):
        self.log.append(('read64', address))
        assert address == q.SMMU + 0x80
        return self.strtab | 0x13

    def write16(self, address, value):
        self.log.append(('write16', address, value))
        assert address == q.ECAM_PA + 4, hex(address)
        self.command = value

    def readmem(self, address, size):
        self.log.append(('readmem', address, size))
        if address == self.strtab + (q.SID >> 8) * 8 and size == 8:
            return struct.pack('<Q', self.l1d)
        if address == self.ste_pa and size == 64:
            return struct.pack('<8Q', *self.ste)
        for base, data in self.tables.items():
            if base <= address and address + size <= base + len(data):
                return data[address - base:address - base + size]
        store, at = self._ram(address, size)
        return bytes(store[at:at + size])

    def writemem(self, address, data):
        self.log.append(('writemem', address, len(data)))
        store, at = self._ram(address, len(data))
        store[at:at + len(data)] = data

    def memset8(self, address, value, size):
        self.log.append(('memset8', address, size))
        store, at = self._ram(address, size)
        store[at:at + size] = bytes([value]) * size

    def request(self, opcode, address, size):
        self.log.append(('request', opcode, address, size))
        assert opcode == self.P_DC_CIVAC
        self._ram(address, size)


@unittest.skipUnless(Path(ARGS.s2_walk, 'receipt.json').is_file(), 'no captured S2 walk (--s2-walk)')
class Replay(unittest.TestCase):
    FREE = [(0xd9dc0000, 0xf9a20000), (0x8c0000000, 0x1000000000)]

    def test_admit_upload_stop(self):
        import bootmedia
        a16 = FakeA16(Path(ARGS.s2_walk))
        data = inputs()
        out = q.admit(a16, dict(stage_generation=3), self.FREE, [(0x8c0000000, 0x240000000)])
        self.assertEqual(len(out['smmu']['blocks']), 32)
        self.assertEqual(out['command_before'], '0x0')
        self.assertEqual(out['command_after'], '0x2')
        writes = [e for e in a16.log if e[0] == 'write16']
        self.assertEqual(writes, [('write16', q.ECAM_PA + 4, 2)])
        # The command is written only after every identity, BAR and SMMU check.
        first_write = a16.log.index(writes[0])
        self.assertTrue(all(e[0] != 'readmem' or e[1] < q.DMA_PA for e in a16.log[first_write:]))
        self.assertTrue(any(e[0] == 'readmem' and e[1] == a16.ste_pa for e in a16.log[:first_write]))
        grant = q.grant(q.Spec(3, 0x77, 0x8c0000000, (1 << 36) - 0x8c0000000), data)
        up = q.upload(a16, grant, data, bootmedia.upload_auxiliary)
        self.assertEqual(bytes(a16.arena), q.arena_payload(data))
        self.assertEqual(bytes(a16.control), grant.record + bytes(q.SLOT - 256))
        cleans = [e for e in a16.log if e[0] == 'request']
        self.assertEqual(cleans, [('request', a16.P_DC_CIVAC, q.DMA_PA, q.DMA_BYTES),
                                  ('request', a16.P_DC_CIVAC, q.CONTROL_PA, q.SLOT)])
        last_write = max(i for i, e in enumerate(a16.log) if e[0] in ('writemem', 'memset8'))
        self.assertLess(last_write, a16.log.index(cleans[0]))
        arena = q.arena_payload(data)       # only nonzero 64 KiB blocks cross the link; the rest is memset
        nonzero = sum(1 for o in range(0, q.DMA_BYTES, 1 << 16) if any(arena[o:o + (1 << 16)]))
        self.assertEqual(up['sent_bytes'], (nonzero << 16) + q.SLOT)
        self.assertEqual(q.stop(a16), dict(command_before='0x2', command_after='0x2', bus_master_off=True))
        a16.command = 6
        self.assertEqual(q.stop(a16), dict(command_before='0x6', command_after='0x2', bus_master_off=True))

    def test_refusals_leave_the_command(self):
        cases = {
            'bus mastering is already on': lambda a: setattr(a, 'command', 6),
            'not the ASUS': lambda a: a.config.__setitem__(0x2c, 0xe15a105b),
            'BAR layout changed': lambda a: a.config.__setitem__(0x10, 0x78100004),
            'not in PBL/EDL': lambda a: a.mhi.__setitem__(0x128, 2),
            'link down': lambda a: a.mhi.__setitem__(0, 0xffffffff),
            'stage-2-only': lambda a: a.ste.__setitem__(0, 1),
            'not one 2 MiB block': lambda a: a.tables.__setitem__(0x85634000, bytes(4096)),
            'not identity read/write': lambda a: a.tables.__setitem__(0x85634000, a.tables[0x85634000][:224 * 8] +
                struct.pack('<Q', 0xd0000000 | 0x4fd) + a.tables[0x85634000][225 * 8:]),
            'free span': lambda a: None,
            'overlaps': lambda a: None,
        }
        for why, mutate in cases.items():
            a16 = FakeA16(Path(ARGS.s2_walk))
            mutate(a16)
            before = a16.command
            free = [(0xe0000000, 0xf9a20000)] if why == 'free span' else self.FREE
            occupied = [(0xdf000000, 0x1000)] if why == 'overlaps' else []
            with self.assertRaisesRegex(ValueError, why):
                q.admit(a16, dict(stage_generation=1), free, occupied)
            if why not in ('not in PBL/EDL', 'link down'):
                self.assertEqual(a16.command, before, why)
                self.assertFalse(any(e[0] == 'write16' for e in a16.log), why)

    def test_upload_detects_a_bad_readback(self):
        import bootmedia
        a16 = FakeA16(Path(ARGS.s2_walk))
        data = inputs()
        grant = q.grant(q.Spec(1, 1, 0x8c0000000, 1 << 30), data)
        original = a16.writemem

        def lossy(address, payload):
            original(address, payload)
            if address == q.CONTROL_PA:
                a16.control[8] ^= 1
        a16.writemem = lossy
        with self.assertRaisesRegex(ValueError, 'did not verify'):
            q.upload(a16, grant, data, bootmedia.upload_auxiliary)


# ---------------------------------------------------------------------------------------------- images
@unittest.skipUnless(ARGS.image, 'pass --image to build the guest images')
class Image(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SNAP_SEED'] = 'test-qcc2072-wifi'
        from cycle_lib import installed_fresh as f
        from cycle_lib.bootstrap_smoke import load
        cls.f = f
        cls.layout = load('qcc_layout', ROOT / 'tools/monitor_layout.py').MonitorLayout()
        cls.work = Path(ARGS.out) / 'images' if ARGS.out else Path(tempfile.mkdtemp(prefix='qcc2072-image-'))
        cls.work.mkdir(parents=True, exist_ok=True)
        _, payload = f.root_hash_payload(ROOT)
        (cls.work / 'root-hash.payload').write_bytes(payload)

    def image(self, name, **kwargs):
        dest = self.work / name
        dest.mkdir()
        args = types.SimpleNamespace(**kwargs)
        if getattr(args, 'qcc2072_wifi', False):
            q.stage_inputs(dest / self.f.QCC2072_INPUTS, sources=(
                {n: Path(ARGS.inputs) / n for n in q.INPUTS} if ARGS.inputs else None))
        saved = self.f.selected
        self.f.selected = self.f.route_selected     # the route's own collection for both images
        try:
            record = self.f.image_checks(ROOT, dest, self.layout, self.work / 'root-hash.payload', args=args)
        finally:
            self.f.selected = saved
        (dest / 'image.json').write_text(json.dumps(record, indent=1, default=str) + '\n')
        return record, (dest / 'device-tree.bin').read_bytes()

    def test_images(self):
        from appledt import DeviceTree
        base, tree0 = self.image('neon', **NEON)
        self.assertNotIn('qcc2072_wifi', base)
        wifi, tree1 = self.image('neon-qcc2072-wifi', qcc2072_wifi=True, **NEON)
        chunks0 = {c['address']: c for c in base['chunks']}
        chunks1 = {c['address']: c for c in wifi['chunks']}
        self.assertEqual(set(chunks0), set(chunks1))
        differing = sorted(a for a in chunks0 if chunks0[a] != chunks1[a])
        self.assertEqual(differing, ['0x8c0001000', '0x8c000c000', '0x8c0010000'], differing)
        self.assertEqual(chunks1['0x8c000c000']['bytes'], chunks0['0x8c000c000']['bytes'] + 8 * q.PARAMS_WORDS)
        dt0, dt1 = DeviceTree(tree0), DeviceTree(tree1)
        self.assertEqual(set(dt1.nodes) - set(dt0.nodes), {q.NODE})
        self.assertEqual(set(dt0.nodes) - set(dt1.nodes), set())
        for path, props in dt0.nodes.items():
            other = dt1.nodes[path]
            self.assertEqual(set(props), set(other), path)
            for key, prop in props.items():
                if path == '/device-tree/arm-io' and key == 'ranges':
                    self.assertEqual(bytes(other[key].value), bytes(prop.value) + b''.join(
                        struct.pack('<3Q', *t) for t in q.triples()))
                else:
                    self.assertEqual(bytes(other[key].value), bytes(prop.value), f'{path} {key}')
        self.assertEqual([c for c in dt1.children['/device-tree/arm-io'] if c != q.NODE],
                         dt0.children['/device-tree/arm-io'])
        node = {k: bytes(v.value) for k, v in dt1.nodes[q.NODE].items()}
        grant = q.grant(q.fixture_spec(0x8c0000000), inputs())
        self.assertEqual(node, {'name': b'snap-qcc2072\0', 'compatible': b'snapintosh,qcc2072\0',
                                'reg': struct.pack('<10Q', 0x7_7800_0000, 0x100000, 0x7_dc00_0000, 0x4000000,
                                                   0x7_7820_0000, 0x1000, 0xe_8010_0000, 0x1000,
                                                   0x7_e000_0000, 0x1000),
                                q.ADMISSION: grant.record})
        self.assertEqual(wifi['qcc2072_wifi']['stage2'],
                         [['0x78000000', '0x78100000', 'rw'], ['0xdc000000', '0xe0000000', 'rw'],
                          ['0x78200000', '0x78201000', 'rw'], ['0x780100000', '0x780101000', 'ro'],
                          ['0xe0000000', '0xe0001000', 'ro']])
        self.assertEqual(wifi['input'], base['input'])
        (self.work / 'result.json').write_text(json.dumps(dict(
            differing_chunks=differing, node=node[q.ADMISSION].hex(), stage2=wifi['qcc2072_wifi']['stage2'],
            ranges=wifi['qcc2072_wifi']['ranges'], device_tree_sha256=[base['device_tree_sha256'],
                                                                       wifi['device_tree_sha256']]), indent=1) + '\n')


# ---------------------------------------------------------------------------------------------- builds
def flag_sets():
    from cycle_lib import speed_test
    sets = dict(speed_test.flag_sets(ROOT)[0])
    for path in ARGS.qualification:
        record = json.loads(Path(path).read_text())
        sets[Path(path).parent.name] = record['flags']
    return sets


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        for path in ARGS.qualification:
            expect.setdefault(Path(path).parent.name, json.loads(Path(path).read_text())['monitor_sha256'])
        out = Path(ARGS.out) / 'builds' if ARGS.out else Path(tempfile.mkdtemp(prefix='qcc2072-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        try:
            for name, flags in flag_sets().items():
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_QCC2072_WIFI=0']), ('on', [q.DEFINE])):
                    run.FLAGS[:] = flags + extra
                    blob = blobs[label] = run.build('xnuboot', out / f'{name}-{label}')
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest())
                    self.assertGreater(budget - len(blob), 0)
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name], name)
                    results[f'{name}-default']['expected'] = expect[name]
        finally:
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
