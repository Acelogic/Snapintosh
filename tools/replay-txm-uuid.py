#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the pinned TXM16 wrapper with real installed-cache/captured UUID bytes.

PAC return mechanics are modeled; UUID traversal and result packing execute
the shipped instructions. Optional C comparison exercises the actual service.
Failure analysis and hardware qualification plan: docs/TXM-UUID-20260925.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'probes'), str(ROOT / 'build/test-python-deps')]
from guestprofile import get_profile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--c-binary', type=Path)
    args = ap.parse_args()
    assert not args.output.exists(), 'preserve prior evidence'
    sha = lambda b: hashlib.sha256(b).hexdigest()
    raw = (ROOT / 'downloads/extracted/j700ap/txm.macosx.release').read_bytes()
    assert sha(raw) == 'b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
    helpers = runpy.run_path(str(ROOT / 'tools/kc-disas.py'))
    segments = helpers['segments'](raw)
    off = lambda va: helpers['locate'](segments, va)[1]
    assert struct.unpack_from('<i', raw, off(0xfffffff01703f510 + 15 * 4))[0] == 0xb8
    assert struct.unpack_from('<I', raw, off(0xfffffff01703f154))[0] == 0x940002a4
    kernel = (ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes()
    assert sha(kernel) == 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
    ks = helpers['segments'](kernel)
    for va, word in [(0xfffffe000bef9ec8, 0x52800208), (0xfffffe000bef9ef4, 0x7100913f),
                     (0xfffffe000bef9ef8, 0x7a430900), (0xfffffe000bef9efc, 0x52800708)]:
        assert struct.unpack_from('<I', kernel, helpers['locate'](ks, va)[1])[0] == word
    tc = get_profile('j700ap-26A428-xars-uniform-auxkc-installed').trust_cache
    payload_path = ROOT / 'downloads/extracted/j700ap' / tc.filename
    payload = tc.load(payload_path.parent)
    capture_path = ROOT / 'build/installed-cryptex-board-300s-20260925-txm16-input.json'
    capture = json.loads(capture_path.read_text())
    assert capture['source_bound'] and capture['selector'] == 16
    observed = bytes.fromhex(capture['uuid_hex'])
    cache_uuid = payload[4:20]
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
    u.mem_map(0xfffffff017000000, 0x200000)
    for _, va, _, fileoff, size in segments:
        u.mem_write(va, raw[fileoff:fileoff + size])
    u.mem_map(0x1000000, 0x200000)
    runtime, dynamic, module = 0xfffffff017020400, 0x1010000, 0x1020000
    payload_va, query, stack, stop = 0x1040000, 0x10c0000, 0x11e0000, 0x11f0000
    u.mem_write(payload_va, payload)
    u.mem_write(0xfffffff017020391, b'\1')
    pac = 0
    def hook(uc, address, size, context):
        nonlocal pac
        word, = struct.unpack('<I', uc.mem_read(address, 4))
        if word in (0xd503237f, 0xd50323ff):
            pac += 1
            uc.reg_write(reg.UC_ARM64_REG_PC, address + 4)
        elif word == 0xd65f0fff:
            pac += 1
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
    u.hook_add(UC_HOOK_CODE, hook)
    u.reg_write(reg.UC_ARM64_REG_CPACR_EL1, 3 << 20)
    def q(at, value):
        u.mem_write(at, struct.pack('<Q', value))
    def invoke(value, list_index):
        u.mem_write(runtime, bytes(0x30)); u.mem_write(dynamic, bytes(16))
        u.mem_write(module, bytes(32)); q(runtime + 0x20, dynamic)
        if list_index >= 0:
            q([runtime + 0x10, runtime + 0x18, dynamic, dynamic + 8][list_index], module)
            q(module + 16, len(payload)); q(module + 24, payload_va)
        u.mem_write(query, value)
        u.reg_write(reg.UC_ARM64_REG_SP, stack)
        u.reg_write(reg.UC_ARM64_REG_X0, query)
        u.reg_write(reg.UC_ARM64_REG_X30, stop)
        u.emu_start(0xfffffff01703fbe4, stop, count=20000)
        assert u.reg_read(reg.UC_ARM64_REG_PC) == stop
        return u.reg_read(reg.UC_ARM64_REG_X0)
    cases = [('captured', observed, 0), ('loaded-static', cache_uuid, 0),
             ('empty', cache_uuid, -1)]
    for index in range(16):
        altered = bytearray(cache_uuid); altered[index] ^= 1
        cases.append((f'mismatch-byte-{index}', bytes(altered), 0))
    cases += [(f'native-list-{n}', cache_uuid, n) for n in (1, 2, 3)]
    rows = []
    for name, value, index in cases:
        status = invoke(value, index)
        expected = (5 << 32) if index >= 0 and value == cache_uuid else (0x32405 << 32) | 3
        assert status == expected, (name, hex(status), hex(expected))
        row = dict(name=name, uuid=value.hex(), native_status=hex(status), native_list=index)
        if args.c_binary and index in (0, -1):
            c = json.loads(subprocess.check_output([str(args.c_binary.resolve()), str(payload_path),
                           value.hex(), 'empty' if index < 0 else 'normal'], text=True))
            assert c['result'] == 0 and int(c['status'], 16) == status
            assert c['reply_count'] == 0 and c['reply_status'] == c['status']
            row['c'] = c
        rows.append(row)
    refusals = []
    if args.c_binary:
        for mode in ['null-input', 'wrap-input', 'bad-stack', 'extra-argument', 'copy-failure', 'corrupt-view']:
            c = json.loads(subprocess.check_output([str(args.c_binary.resolve()), str(payload_path),
                           observed.hex(), mode], text=True))
            assert c['result'] != 0 and c['status'] == '0x123' and c['unchanged'] and c['publishes'] == 0
            refusals.append(dict(mode=mode, **c))
    record = dict(result='PASS', txm_sha256=sha(raw), payload_sha256=sha(payload),
                  capture_sha256=sha(capture_path.read_bytes()), cache_uuid=cache_uuid.hex(),
                  cases=rows, refusals=refusals, modeled_pac_operations=pac,
                  c_sha256=sha(args.c_binary.read_bytes()) if args.c_binary else None,
                  boundary='Shipped instruction replay with modeled PAC and memory fixture; physical boot is separate')
    with args.output.open('x') as f:
        json.dump(record, f, indent=2); f.write('\n')
    print(json.dumps(dict(result='PASS', cases=len(rows), c_refusals=len(refusals), output=str(args.output))))


if __name__ == '__main__':
    main()
