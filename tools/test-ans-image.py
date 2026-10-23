#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full-install M2 loader side: the virtual ANS2 profile, its device models,
reservation, test disk and state decoder (docs/ANS2-M2-20260925.md).

    python3 tools/test-ans-image.py

The monitor side is tools/test-ans.c (build line in its header)."""
import contextlib
from dataclasses import fields, replace
import hashlib
import io
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import xnuboot as xb
import ansdisk
import ansstate
import monitor_work
from devicemodel import (ANS_ASC_V1, ANS_NVME_V1, ANS_DISK_OFFSET, ANS_FW_OFFSET, ANS_FW_BYTES,
                         ANS_FIRMWARE_PROPERTIES, ans_firmware_state, ans_models,
                         ans_reservation_span, device_model_words, populate_ans_firmware,
                         DeviceModel)
from guestprofile import get_profile, PROFILES, ANS2_M2_DISK_SHA256

PLAIN = 'j700ap-26A428-xars-uniform-auxkc'
ANS = 'j700ap-26A428-xars-uniform-auxkc-ans'
INSTALLED = 'j700ap-26A428-xars-uniform-auxkc-installed'   # full-install M6: the SSD window
DISK = ROOT / 'build/ans-m2-disk-20260925/test-disk.img'


def tree(name):
    xb.configure_guest(name)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree()


def container(size):
    """A stand-in APFS container: only the superblock geometry is inspected."""
    data = bytearray(size)
    data[32:36] = b'NXSB'
    struct.pack_into('<IQ', data, 36, 4096, size // 4096)
    data[size // 2] = 0x5a
    return bytes(data)


class ProfileTests(unittest.TestCase):
    def tearDown(self):
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_profile_changes_only_what_it_names(self):
        plain, ans = get_profile(PLAIN), get_profile(ANS)
        self.assertEqual({f.name for f in fields(plain) if getattr(plain, f.name) != getattr(ans, f.name)},
                         {'name', 'ans_boot'})
        self.assertIn(ANS, PROFILES)
        self.assertEqual(ans.ans_boot.disk_sha256, ANS2_M2_DISK_SHA256)
        self.assertEqual(ans.ans_boot.disk_bytes, 64 << 20)
        installed = get_profile(INSTALLED)
        self.assertEqual({f.name for f in fields(plain) if getattr(plain, f.name) != getattr(installed, f.name)},
                         {'name', 'ans_boot', 'root_hash', 'trust_cache', 'installed_root', 'sep_asc',
                          'chip_id_boot', 'apfs_without_sep'})
        self.assertTrue(installed.ans_boot.window and not installed.ans_boot.disk_sha256)
        for other in PROFILES.values():
            if other.name not in (ANS, INSTALLED):
                self.assertIsNone(other.ans_boot)

    def test_every_allow_list_admits_the_profile(self):
        secondary = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))
        secondary['validate_guest_profile'](ANS)
        self.assertIn(f"'{ANS}'", (ROOT / 'build/collect-auxkc-20260925.py').read_text())

    def test_models_bind_the_stock_nodes(self):
        dt = tree(ANS)
        base, span = xb.ans_reservation()
        work = (xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN + 65535) & ~65535
        self.assertEqual(base, work + monitor_work.WORK_SIZE)
        self.assertEqual(span, 0x4040000)
        models = [m for m in dt.device_models if m.kind in (ANS_ASC_V1, ANS_NVME_V1)]
        self.assertEqual([m.words() for m in models],
                         [(49, 0x389600000, 0x9000, base, 1010, 1007, 0, 0),
                          (50, 0x38dcc0000, 0x60000, base, 64 << 20, 1039, 0, 0)])
        # The plain AuxKC board's tree plus exactly the IOP nub's firmware state:
        # no other node, property or deferral changes.
        plain = tree(PLAIN)
        nub = '/device-tree/arm-io/ans/iop-ans-nub'
        self.assertEqual(set(plain.nodes), set(dt.nodes))
        for node in dt.nodes:
            if node != nub:
                self.assertEqual(plain.serialize(node) if not plain.children[node] else
                                 [(k, bytes(v.value), v.placeholder) for k, v in plain.nodes[node].items()],
                                 dt.serialize(node) if not dt.children[node] else
                                 [(k, bytes(v.value), v.placeholder) for k, v in dt.nodes[node].items()])
        extra = [(k, bytes(v.value)) for k, v in dt.nodes[nub].items() if k not in plain.nodes[nub]]
        self.assertEqual(tuple(extra), ans_firmware_state(base))
        self.assertEqual([(k, bytes(v.value)) for k, v in dt.nodes[nub].items() if k in plain.nodes[nub]],
                         [(k, bytes(v.value)) for k, v in plain.nodes[nub].items()])
        self.assertEqual(len(dt.device_models), len(plain.device_models) + 2)
        self.assertLessEqual(len(dt.device_models), 128)

    def test_firmware_drift_refuses(self):
        dt = tree(ANS)
        spec = xb.GUEST_PROFILE.ans_boot
        windows, sart = xb.ans_windows(dt), xb.device_windows(dt, 'sart-ans')
        base = xb.ans_reservation()[0]
        ans_models(dt, spec, windows, sart, base)
        for node in (spec.node, spec.sart_node):
            for key, prop in list(dt.nodes[node].items()):
                original = prop.value
                prop.value = bytes(original) + b'\0'
                with self.assertRaises(ValueError):
                    ans_models(dt, spec, windows, sart, base)
                prop.value = original
                prop.placeholder = True
                with self.assertRaises(ValueError):
                    ans_models(dt, spec, windows, sart, base)
                prop.placeholder = False
        for bad in (windows[1:], windows[:-1] + [(0x38db00000, 0x10000)]):
            with self.assertRaises(ValueError):
                ans_models(dt, spec, bad, sart, base)
        with self.assertRaises(ValueError):
            ans_models(dt, spec, windows, sart[:2], base)
        for bad in (0, base + 0x4000, -0x10000):
            with self.assertRaises(ValueError):
                ans_models(dt, spec, windows, sart, bad)
        for bad in (replace(spec, disk_bytes=0), replace(spec, disk_bytes=(1 << 30) + 4096),
                    replace(spec, disk_bytes=4097), replace(spec, disk_sha256='00')):
            with self.assertRaises(ValueError):
                ans_models(dt, bad, windows, sart, base)

    def test_firmware_state_is_the_iboot_contract(self):
        """RTBuddy reads it as iBoot's pre-loaded, running, quiesced IOP with one
        restricted segment on the monitor's reserved zero page."""
        dt = tree(ANS)
        base = xb.ans_reservation()[0]
        nub = '/device-tree/arm-io/ans/iop-ans-nub'
        self.assertEqual(list(dt.nodes[nub])[-4:], list(ANS_FIRMWARE_PROPERTIES))
        # _initConfigEDT: presence, not value, sets pre-loaded (0x2230) and
        # running (0x2231, which also skips the firmware-service wait, 0x2232).
        self.assertEqual(dt.get(nub, 'pre-loaded'), struct.pack('<I', 1))
        self.assertEqual(dt.get(nub, 'running'), struct.pack('<I', 1))
        self.assertEqual(dt.get(nub, 'quiesced'), b'')
        self.assertEqual(dt.get(nub, 'power-managed'), struct.pack('<I', 1))
        for absent in ('user-power-managed', 'no-firmware-service', 'dont-power-on',
                       'reconfig-firmware'):
            self.assertIsNone(dt.get(nub, absent))
        ranges = dt.get(nub, 'segment-ranges')
        self.assertEqual(len(ranges) % 32, 0)
        records = [struct.unpack_from('<QQQII', ranges, off) for off in range(0, len(ranges), 32)]
        # getSegmentMap tokenizes segment-names on ';' once per record and
        # panics if bytes remain.
        names = dt.get(nub, 'segment-names')
        self.assertEqual(names.count(b';') + 1, len(records))
        self.assertEqual(records, [(base + ANS_FW_OFFSET, 0, base + ANS_FW_OFFSET, ANS_FW_BYTES, 0x11)])
        pa, iop, alias, size, flags = records[0]
        # getSegmentMap 0xfffffe000b328a88: ((f>>2)&1 | (f&1)<<1 | (f>>1)&0xc) ^ 2;
        # RTBuddySegment needsBackup bit0, writable bit1, kernel bit2, restricted bit3.
        segflags = (((flags >> 2) & 1) | ((flags & 1) << 1) | ((flags >> 1) & 0xc)) ^ 2
        self.assertEqual(segflags, 0x8)
        # The reserved page: after the state, before the disk, 16 KiB aligned.
        self.assertTrue(0x10000 <= ANS_FW_OFFSET and ANS_FW_OFFSET + ANS_FW_BYTES <= ANS_DISK_OFFSET)
        self.assertFalse(pa % 0x4000)
        # compat/ans.h agrees on the reserved page's offset.
        self.assertIn(f'#define ANS_FW_OFFSET {ANS_FW_OFFSET:#x}', (ROOT / 'compat/ans.h').read_text())
        # The plain board publishes none of it.
        plain = tree(PLAIN)
        for name in ANS_FIRMWARE_PROPERTIES:
            self.assertIsNone(plain.get(nub, name))

    def test_firmware_state_refusals(self):
        spec = get_profile(ANS).ans_boot
        dt = tree(PLAIN)                          # the stock nub, no state yet
        xb.configure_guest(ANS)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        base = xb.ans_reservation()[0]
        windows, sart = xb.ans_windows(dt), xb.device_windows(dt, 'sart-ans')
        nub = spec.node + '/iop-ans-nub'
        with self.assertRaises(ValueError):       # models need the state
            ans_models(dt, spec, windows, sart, base)
        for bad in (0, base + 0x4000, -0x10000, str(base)):
            with self.assertRaises(ValueError):
                populate_ans_firmware(dt, spec, bad)
        self.assertFalse(any(dt.get(nub, k) is not None for k in ANS_FIRMWARE_PROPERTIES))
        for key, value in (('quiesced', None), ('power-managed', struct.pack('<I', 0)),
                           ('region-base', struct.pack('<Q', 0x1000)),
                           ('no-firmware-service', b''), ('user-power-managed', struct.pack('<I', 1)),
                           ('uuid', b'0\0')):
            probe = tree(PLAIN)
            if value is None:
                del probe.nodes[nub][key]
            else:
                probe.put(nub, key, value)
            with self.assertRaises(ValueError):
                populate_ans_firmware(probe, spec, base)
        populate_ans_firmware(dt, spec, base)
        models = ans_models(dt, spec, windows, sart, base)
        self.assertEqual([m.kind for m in models], [ANS_ASC_V1, ANS_NVME_V1])
        with self.assertRaises(ValueError):       # never twice
            populate_ans_firmware(dt, spec, base)
        with self.assertRaises(ValueError):       # state for another reservation
            ans_models(dt, spec, windows, sart, base + 0x10000)
        for name in ANS_FIRMWARE_PROPERTIES:
            original = bytes(dt.nodes[nub][name].value)
            for value in (original + b'\0', original[:-1], b''):
                if value == original:
                    continue
                dt.nodes[nub][name].value = bytearray(value)
                with self.assertRaises(ValueError):
                    ans_models(dt, spec, windows, sart, base)
            dt.nodes[nub][name].value = bytearray(original)
            saved = dict(dt.nodes[nub])
            del dt.nodes[nub][name]
            with self.assertRaises(ValueError):   # missing
                ans_models(dt, spec, windows, sart, base)
            dt.nodes[nub].clear(); dt.nodes[nub].update(saved)
        # Reordered or followed by anything else.
        saved = dict(dt.nodes[nub])
        items = list(saved.items())
        dt.nodes[nub].clear(); dt.nodes[nub].update(items[:-2] + [items[-1], items[-2]])
        with self.assertRaises(ValueError):
            ans_models(dt, spec, windows, sart, base)
        dt.nodes[nub].clear(); dt.nodes[nub].update(saved)
        dt.add(nub, 'uuid', b'00000000-0000-0000-0000-000000000000\0')
        with self.assertRaises(ValueError):
            ans_models(dt, spec, windows, sart, base)
        dt.nodes[nub].clear(); dt.nodes[nub].update(saved)
        ans_models(dt, spec, windows, sart, base)

    def test_descriptor_refusals(self):
        base = 0x9c4000000
        asc = DeviceModel('/device-tree/arm-io/ans', 49, 0x389600000, 0x9000, (base, 1010, 1007, 0, 0))
        nvme = DeviceModel('/device-tree/arm-io/ans', 50, 0x38dcc0000, 0x60000, (base, 64 << 20, 1039, 0, 0))
        device_model_words((asc, nvme))
        for model in (asc, nvme):
            for i in range(5):
                c = list(model.config)
                c[i] += 0x1000 if i == 0 else 1   # misaligned reservation; any other field
                other = nvme if model is asc else asc
                with self.assertRaises(ValueError):
                    device_model_words((replace(model, config=tuple(c)), other))
            for field, value in (('base', model.base + 0x1000), ('span', model.span + 0x1000)):
                with self.assertRaises(ValueError):
                    device_model_words((replace(model, **{field: value}), nvme if model is asc else asc))
        with self.assertRaises(ValueError):                       # half a pair
            device_model_words((nvme,))
        with self.assertRaises(ValueError):                       # two reservations
            device_model_words((asc, replace(nvme, config=(base + 0x10000,) + nvme.config[1:])))
        with self.assertRaises(ValueError):                       # disk over the guest
            device_model_words((asc, nvme), excluded=[(base + 0x100000, 0x1000)])
        device_model_words((asc, nvme), excluded=[(base + ANS_DISK_OFFSET + (64 << 20), 0x1000)])

    def test_reservation_geometry(self):
        info = dict(heap_base=0x9f0000000, heap_size=64 << 20, image_base=0x9e0000000, image_size=1 << 20)
        work = 0x9b0000000
        base, size = work + monitor_work.WORK_SIZE, ans_reservation_span(64 << 20)
        free = [(0x8c0000000, 0x9e0000000)]
        monitor_work.validate_ans(base, size, work, monitor_work.WORK_SIZE, info, free)
        for args in ((base + 0x10000, size, work), (base, size + 0x8000, work), (base, 0, work),
                     (base, size, work + 0x10000)):
            with self.assertRaises(ValueError):
                monitor_work.validate_ans(*args, monitor_work.WORK_SIZE, info, free)
        with self.assertRaises(ValueError):
            monitor_work.validate_ans(base, size, work, monitor_work.WORK_SIZE, info, [(0x8c0000000, base + size - 1)])
        crowded = dict(info, fb_base=base + 0x10000, fb_size=0x1000)
        with self.assertRaises(ValueError):
            monitor_work.validate_ans(base, size, work, monitor_work.WORK_SIZE, crowded, free)
        for bad in (0, 4097, (1 << 30) + 4096):
            with self.assertRaises(ValueError):
                ans_reservation_span(bad)


class ParamsTests(unittest.TestCase):
    def tearDown(self):
        xb.configure_guest('j700ap-26A428-sep-preload')

    def test_image_carries_the_pair(self):
        """The whole loader path offline: build, params, the registry the monitor validates."""
        kc = ROOT / 'build/auxkc-20260925/aux-hello.kc'
        if not kc.exists():
            self.skipTest('pinned aux-hello.kc not present')
        xb.configure_guest(ANS)
        xb.place(0x8c0000000, guest_span=8192 << 20)
        with contextlib.redirect_stdout(io.StringIO()):
            built = xb.build(str(xb.DEFAULT_KERNELCACHE), auxkc=str(kc))
        blob = xb.params_blob(built)
        self.assertEqual(len(blob), xb.PARAMS_WORDS * 8)
        self.assertIn(f'#define PARAMS_WORDS {xb.PARAMS_WORDS}', read_source(ROOT / 'probes/xnuboot.c'))
        words = struct.unpack(f'<{xb.PARAMS_WORDS}Q', blob)
        count = words[90]
        models = [words[91 + 8 * i:99 + 8 * i] for i in range(count)]
        base = xb.ans_reservation()[0]
        self.assertEqual([m for m in models if m[0] in (49, 50)],
                         [(49, 0x389600000, 0x9000, base, 1010, 1007, 0, 0),
                          (50, 0x38dcc0000, 0x60000, base, 64 << 20, 1039, 0, 0)])
        # Outside every stage-2 range the guest can reach, including the
        # firmware segment the IOP nub names.
        for lo, hi, _, _ in xb.stage2_ranges():
            self.assertFalse(lo < base + 0x4040000 and base < hi)
            fw = base + ANS_FW_OFFSET
            self.assertFalse(lo < fw + ANS_FW_BYTES and fw < hi)


class DiskTests(unittest.TestCase):
    def test_round_trip_and_gpt(self):
        layout = ansdisk.layout()
        image = ansdisk.assemble(container(layout['container'][1]))
        desc = ansdisk.inspect(image)
        self.assertEqual((desc['blocks'], desc['last_usable'], desc['container']),
                         (16384, 16378, (1 << 20, 62 << 20)))
        header = image[4096:4096 + 92]
        self.assertEqual(header[:8], b'EFI PART')
        crc = struct.unpack_from('<I', header, 16)[0]
        self.assertEqual(crc, zlib.crc32(header[:16] + b'\0' * 4 + header[20:92]))
        first, last = struct.unpack_from('<QQ', image, 2 * 4096 + 32)
        self.assertEqual((first, last), (256, 256 + (62 << 20) // 4096 - 1))
        self.assertEqual(image[:4096][510:512], b'\x55\xaa')

    def test_corruption_refuses(self):
        layout = ansdisk.layout()
        good = ansdisk.assemble(container(layout['container'][1]))
        for offset in (511, 4096 + 16, 4096 + 40, 2 * 4096 + 1, 5 * 4096 + 7, 6 * 4096,
                       (1 << 20) + 33, (1 << 20) + 40, (63 << 20) + 5, (64 << 20) - 5 * 4096,
                       (64 << 20) - 100):
            bad = bytearray(good)
            bad[offset] ^= 1
            with self.assertRaises(ValueError, msg=hex(offset)):
                ansdisk.inspect(bytes(bad))
        with self.assertRaises(ValueError):
            ansdisk.inspect(good[:-4096])
        with self.assertRaises(ValueError):
            ansdisk.assemble(container(layout['container'][1] - 4096))
        with self.assertRaises(ValueError):
            ansdisk.assemble(bytes(layout['container'][1]))

    @unittest.skipUnless(DISK.exists(), 'build/build-ans-test-disk-20260925.py has not run here')
    def test_pinned_disk(self):
        data = DISK.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), ANS2_M2_DISK_SHA256)
        desc = ansdisk.inspect(data)
        record = __import__('json').loads((DISK.parent / 'disk.json').read_text())
        self.assertEqual(record['sha256'], desc['sha256'])
        self.assertEqual(record['container_sha256'], desc['container_sha256'])


class StateTests(unittest.TestCase):
    def test_offsets_match_the_c_layout(self):
        cc = shutil.which('clang') or shutil.which('cc')
        if not cc:
            self.skipTest('no host C compiler')
        fields_ = sorted(ansstate.OFFSETS)
        source = '#include <stdio.h>\n#include <stddef.h>\n#include "ans.h"\nint main(void){\n'
        source += 'printf("%zu\\n",sizeof(struct ans_state));\n'
        source += ''.join(f'printf("%zu\\n",offsetof(struct ans_state,{f}));\n' for f in fields_)
        source += 'printf("%d %d %d\\n",ANS_C_COUNT,ANS_E_BACKEND,ANS_IOP_RUNNING);'
        source += ('printf("%zu %d %zu %d %zu %zu %d %u %u %u\\n",sizeof(struct ans_cid),ANS_CIDS,'
                   'offsetof(struct ans_cid,prp),ANS_PRPS,sizeof(struct ans_sart),'
                   'sizeof(((struct ans_state *)0)->bad_opcode),ANS_SART_REGIONS,'
                   'ANS_IOQ_CQ,ANS_IOQ_SQ,ANS_IOQ_IEN);return 0;}\n')
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / 'offsets.c'
            path.write_text(source)
            subprocess.run([cc, '-I', str(ROOT / 'compat'), str(path), '-o', str(Path(scratch) / 'offsets')],
                           check=True)
            out = subprocess.run([str(Path(scratch) / 'offsets')], check=True,
                                 capture_output=True, text=True).stdout.split('\n')
        self.assertEqual(int(out[0]), ansstate.SIZE)
        self.assertEqual([int(v) for v in out[1:1 + len(fields_)]], [ansstate.OFFSETS[f] for f in fields_])
        self.assertEqual(out[1 + len(fields_)], f'{len(ansstate.COUNTERS)} {len(ansstate.ERRORS) - 1} '
                                               f'{len(ansstate.IOP) - 1}')
        self.assertEqual(out[2 + len(fields_)],
                         f'{ansstate.CID_SIZE} {ansstate.CIDS} {ansstate.PRP_OFFSET} {ansstate.PRPS} '
                         f'{ansstate.SART_SIZE} 64 {ansstate.SART_REGIONS} 1 2 4')
        self.assertEqual(ansstate.IOQ, ('cq', 'sq', 'ien'))

    def test_decode(self):
        raw = bytearray(ansstate.SIZE)
        with self.assertRaises(ValueError):
            ansstate.decode(bytes(raw))
        struct.pack_into('<3Q', raw, 0, ansstate.MAGIC, ansstate.VERSION, 64 << 20)
        struct.pack_into('<4I', raw, ansstate.OFFSETS['out_count'], 0, 1, 1, 3)
        struct.pack_into('<Q', raw, ansstate.OFFSETS['counter'] + 8 * ansstate.COUNTERS.index('reads'), 7)
        struct.pack_into('<3Q', raw, ansstate.OFFSETS['refusal'], 14, 0x1234, 5)
        struct.pack_into('<Q', raw, ansstate.OFFSETS['counter'] + 8 * ansstate.COUNTERS.index('refusals'), 1)
        state = ansstate.decode(bytes(raw))
        self.assertEqual((state['iop'], state['counters']['reads'], state['refusal']['reason']),
                         ('running', 7, 'sqe'))
        self.assertIn('first: sqe 0x1234', ansstate.describe(state))
        with self.assertRaises(ValueError):
            ansstate.decode(bytes(raw[:-1]))


    def test_references(self):
        # The A16 run's stop (ans-m2-fw-300s-20260925): ASQ, I/O CQ and ACQ registered,
        # no command mapped. Its audit found exactly these three frames one reference
        # over the DART's count; the model's state names them.
        raw = bytearray(ansstate.SIZE)
        struct.pack_into('<3Q', raw, 0, ansstate.MAGIC, ansstate.VERSION, 64 << 20)
        struct.pack_into('<4Q', raw, ansstate.OFFSETS['asq'], 0x9a36f0000, 0x9a3700000, 0, 0x9a36fc000)
        refs = ansstate.references(bytes(raw))
        self.assertEqual(refs, [dict(pa=hex(pa), readonly=0, other=1)
                                for pa in (0x9a36f0000, 0x9a36fc000, 0x9a3700000)])
        dart = [dict(pa='0x9a36f0000', readonly=0, other=0), dict(pa='0x1000', readonly=1, other=0)]
        self.assertEqual(ansstate.merge_references(dart, refs)[:2],
                         [dict(pa='0x1000', readonly=1, other=0),
                          dict(pa='0x9a36f0000', readonly=0, other=1)])
        # A mapped read (TCB 0x100: device writes) with an unaligned head, a mapped write,
        # and a 32 KiB SART region with perm 0: per 16 KiB frame, writable or read-only.
        cid = ansstate.OFFSETS['cid']
        struct.pack_into('<BBHHH3Q', raw, cid, 3, 1, 0x100, 1, 3, 0x9b0000800, 0x9b0001000, 0x9b0004000)
        struct.pack_into('<BBHHH1Q', raw, cid + ansstate.CID_SIZE * 5, 3, 1, 0x200, 0, 1, 0x9b0008000)
        struct.pack_into('<2Q2I', raw, ansstate.OFFSETS['sart'] + ansstate.SART_SIZE, 0x9c0000000, 0x8000, 0, 0)
        refs = {r['pa']: (r['readonly'], r['other']) for r in ansstate.references(bytes(raw))}
        self.assertEqual(refs['0x9b0000000'], (0, 2))
        self.assertEqual(refs['0x9b0004000'], (0, 1))
        self.assertEqual(refs['0x9b0008000'], (1, 0))
        self.assertEqual((refs['0x9c0000000'], refs['0x9c0004000']), ((1, 0), (1, 0)))
        struct.pack_into('<H', raw, cid + 6, ansstate.PRPS + 1)
        with self.assertRaises(ValueError):
            ansstate.references(bytes(raw))

    def test_queue_and_opcode_diagnostics(self):
        raw = bytearray(ansstate.SIZE)
        struct.pack_into('<3Q', raw, 0, ansstate.MAGIC, ansstate.VERSION, 64 << 20)
        struct.pack_into('<I', raw, ansstate.OFFSETS['ioq'], 3)
        struct.pack_into('<Q', raw, ansstate.OFFSETS['bad_opcode'] + 8 * 3, 1 << 2 | 1 << 10)
        struct.pack_into('<Q', raw, ansstate.OFFSETS['bad_opcode'] + 32, 1 << 5)
        struct.pack_into('<Q', raw, ansstate.OFFSETS['last_status'], 1 << 48 | 0xca << 32 | 0x10000)
        state = ansstate.decode(bytes(raw))
        self.assertEqual(state['io_queue'], ['cq', 'sq'])
        self.assertEqual(state['invalid_opcodes'], dict(admin=[0xc2, 0xca], io=[5]))
        self.assertEqual(state['last_status'], dict(status=1, qid=0, opcode=0xca, cdw10=0x10000))
        self.assertIn("invalid opcodes admin ['0xc2', '0xca'] io ['0x5']", ansstate.describe(state))


class VerdictTests(unittest.TestCase):
    def test_stages(self):
        tool = runpy.run_path(str(ROOT / 'tools/ans-verdict.py'))
        counters = {name: 0 for name in ansstate.COUNTERS}
        state = dict(iop='quiesced', epmap_acked=0, cc=0, csts=0, counters=counters,
                     refusal=dict(reason='ok', a=0, b=0, c=0))
        launch = dict(exit_code=9)
        result = tool['verdict'](launch, dict(state=state), None, {})
        self.assertIsNone(result['reached'])
        counters.update(mmio=5, msg_in=3, msg_out=3, startep=1, admin=4, reads=9)
        state.update(iop='running', epmap_acked=1, cc=1, csts=1)
        entries = [dict(class_name='AppleANS3CGv2Controller', name=None, children=1),
                   dict(class_name='IOEmbeddedNVMeBlockDevice', name='NS_01', children=1),
                   dict(class_name='IOGUIDPartitionScheme', name=None, children=1),
                   dict(class_name='IOGUIDPartitionScheme', name=None, children=1),
                   dict(class_name='IOMedia', name=ansdisk.NAME, children=1),
                   dict(class_name='AppleAPFSContainerScheme', name=None, children=1)]
        waits = dict(ioreg_state=dict(complete=True, entries=entries))
        result = tool['verdict'](launch, dict(state=state), None, waits)
        self.assertEqual(result['reached'], 'gpt')
        entries.append(dict(class_name='AppleAPFSVolume', name='SnapM2', children=1))
        result = tool['verdict'](launch, dict(state=state), None, waits)
        self.assertEqual(result['reached'], 'apfs')
        self.assertTrue(all(result['clean'].values()))
        counters['refusals'] = 1
        self.assertFalse(tool['verdict'](launch, dict(state=state), None, waits)['clean']['refusals'])
        # ans-m2-fw-300s-20260925: the IOP woke and the controller came ready with no STARTEP.
        counters.update(refusals=0, startep=0)
        self.assertEqual(tool['verdict'](launch, dict(state=state), None, waits)['reached'], 'apfs')

    def test_firmware_state_diagnostics(self):
        tool = runpy.run_path(str(ROOT / 'tools/ans-verdict.py'))
        counters = {name: 0 for name in ansstate.COUNTERS}
        state = dict(iop='quiesced', epmap_acked=0, cc=0, csts=0, counters=counters,
                     iop_power=0, ap_power=0, refusal=dict(reason='ok', a=0, b=0, c=0))
        result = tool['verdict'](dict(exit_code=9), dict(state=state), None, {})
        self.assertEqual(result['diagnostics'], dict(firmware_state_published=None,
                         endpoint_published=False, iop_power=0, ap_power=0, startep=0))
        audit = dict(ans=[dict(state=state, firmware_state_published=True)])
        waits = dict(ioreg_state=dict(complete=True, entries=[
            dict(class_name='RTBuddyEndpoint', name='ANS2Endpoint1', children=0)]))
        state.update(iop_power=0x20)
        result = tool['verdict'](dict(exit_code=9), dict(state=state), audit, waits)
        self.assertEqual(result['diagnostics'], dict(firmware_state_published=True,
                         endpoint_published=True, iop_power=0x20, ap_power=0, startep=0))
        self.assertIsNone(result['reached'])     # diagnostics never advance a stage
        state.update(io_queue=['cq', 'sq', 'ien'], invalid_opcodes=dict(admin=[0xca], io=[]),
                     last_status=dict(status=1, qid=0, opcode=0xca, cdw10=0))
        result = tool['verdict'](dict(exit_code=9), dict(state=state), audit, waits)
        self.assertEqual(result['diagnostics']['io_queue'], ['cq', 'sq', 'ien'])
        self.assertEqual(result['diagnostics']['invalid_opcodes'], dict(admin=[0xca], io=[]))
        self.assertIsNone(result['reached'])


if __name__ == '__main__':
    unittest.main()
