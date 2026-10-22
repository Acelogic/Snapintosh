#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise native PA helper control flow with modeled privileged operations.

Runs the built AArch64 instructions. System registers, TLB maintenance and
PAC/AUT are modeled; this verifies guards, key selection and restoration, not
the hardware PAC algorithm or translation behavior.
"""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'build/test-python-deps'), str(ROOT / 'probes')]
import run
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

BASE = 0x1000000
BUFFER = BASE + 0x10000
STACK = BASE + 0x18000
RETURN = BASE + 0x1f000
KEYS = ('apia', 'apib', 'apda', 'apdb')
FIELDS = ('currentel', 'id_aa64isar1_el1', 'id_aa64isar2_el1',
          'sctlr_el2', 'tcr_el2', 'hcr_el2', 'sctlr_el1', 'tcr_el1',
          'id_aa64mmfr0_el1', 'id_aa64isar0_el1')
CFG = dict(zip(FIELDS, (8, 0x110111100311002, 0x11005112,
                       0x10003000100d, 0x80843514, 0x88000010,
                       0x100030800180, 0, 0x2100122100001024, 0x1221111110212120)))
CFG['daif'] = 0x80
for n, key in enumerate(KEYS):
    CFG[key + 'keylo_el1'] = 0x11110000 + n
    CFG[key + 'keyhi_el1'] = 0x22220000 + n


def test_case(blob, request, override=None, rejected=False, inspect=False,
              corrupt_read=None, raw_sign=False):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(BASE, 0x20000)
    uc.mem_write(BASE, blob)
    uc.mem_write(BUFFER, b'\xa5' * 0x200)
    packed = struct.pack('<7Q', *request)
    uc.mem_write(BUFFER + 0x100, packed)
    initial = dict(CFG, **(override or {}))
    registers = initial.copy()
    code = {i.address: i for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(blob, BASE)}
    writes, events, signed = [], [], []
    counts = {}

    def get(name):
        return uc.reg_read(getattr(reg, 'UC_ARM64_REG_' + name.upper()))

    def put(name, value):
        uc.reg_write(getattr(reg, 'UC_ARM64_REG_' + name.upper()), value)

    def hook(u, address, size, _):
        insn = code[address]
        op, operands = insn.mnemonic, insn.op_str.split(', ')
        if op == 'mrs':
            dst, src = operands
            value = registers[src]
            # Corrupt only a restoration readback, after the restore write.
            if src == corrupt_read and counts.get(src, 0) >= 2:
                value ^= 1
            put(dst, value)
        elif op == 'msr':
            dst, src = operands
            if dst == 'daifset':
                registers['daif'] |= int(src[1:], 0) << 6
            else:
                value = get(src)
                if dst != 'daif':
                    assert registers['daif'] & 0x3c0 == 0x3c0
                registers[dst] = value
                counts[dst] = counts.get(dst, 0) + 1
                writes.append((dst, value))
            events.append(op + ':' + dst)
        elif op == 'tlbi':
            assert insn.op_str == 'alle2'
            assert registers['daif'] & 0x3c0 == 0x3c0
            events.append('tlbi')
        elif op.startswith(('pac', 'aut')):
            selector = {'ia': 0, 'ib': 1, 'da': 2, 'db': 3}[op[3:]]
            assert selector == request[4]
            dst, src = operands
            key = KEYS[selector]
            assert registers[key + 'keylo_el1'] == request[2]
            assert registers[key + 'keyhi_el1'] == request[3]
            mask = 63 | (1 << 20) | (1 << 29)
            expected_tcr = ((initial['tcr_el2'] & ~mask) | 17 |
                            (request[5] << 20) | (request[6] << 29))
            assert registers['tcr_el2'] == expected_tcr
            assert registers['sctlr_el2'] == initial['sctlr_el2'] | 0xc8002000
            assert registers['daif'] & 0x3c0 == 0x3c0
            assert get(src) == request[1]
            if op.startswith('pac'):
                assert get(dst) == request[0]
                value = request[0] ^ (0x35 << 48)
                signed.append(value)
                put(dst, value)
            else:
                assert not raw_sign, 'sign-only entry executed authentication'
                assert get(dst) == signed[-1]
                put(dst, request[0])
            events.append(op)
        else:
            return
        put('pc', address + size)

    uc.hook_add(UC_HOOK_CODE, hook)
    saved = {n: 0x31415000 + n for n in range(19, 30)}
    for n, value in saved.items():
        put('x' + str(n), value)
    put('sp', STACK)
    put('x30', RETURN)
    put('x0', BUFFER)
    put('x1', 0 if inspect else 1)
    uc.emu_start(BASE, RETURN, count=500)
    assert get('pc') == RETURN
    assert get('sp') == STACK and get('x30') == RETURN
    assert all(get('x' + str(n)) == v for n, v in saved.items())
    assert registers == initial
    after = bytes(uc.mem_read(BUFFER, 0x200))
    expected = bytearray(b'\xa5' * 0x200)
    expected[:80] = struct.pack('<10Q', *(initial[k] for k in FIELDS))
    expected[0x100:0x138] = packed
    if rejected or inspect:
        assert get('x0') == int(rejected)
        assert not writes and not signed
    else:
        restored = 15
        if corrupt_read:
            restored &= ~({'tcr_el2': 2, 'sctlr_el2': 4}.get(corrupt_read, 1))
        assert get('x0') == int(bool(corrupt_read))
        expected[0x180:0x198] = struct.pack('<3Q', signed[0], 0 if raw_sign else request[0], restored)
        assert len(signed) == 1
        if raw_sign:
            assert not any(event.startswith('aut') for event in events)
        assert events.count('tlbi') == 2
        assert events[0] == 'msr:daifset' and events[-1] == 'msr:daif'
        selected = KEYS[request[4]]
        assert {n for n, _ in writes if 'key' in n} == {
            selected + 'keylo_el1', selected + 'keyhi_el1'}
    assert after == expected, 'unexpected output or buffer clobber'


def main():
    blob = run.build('pauth-address', ROOT / 'build/pauth-address-probe')
    cases = 0
    default = [0x1cf5382f0, 0x9abf0001cf5382a8,
               0x0123456789abcdef, 0xfedcba9876543210, 0, 0, 0]
    for key, tbi, tbid, pointer, t0sz in itertools.product(
            range(4), range(2), range(2),
            (0, 0x1cf5382f0, (1 << 47) - 1, 0xab000001cf5382f0),
            (17, 20, 24)):
        req = default.copy()
        req[0], req[4], req[5], req[6] = pointer, key, tbi, tbid
        tagged = bool(pointer >> 56)
        rejected = tagged and not (tbi and (key >= 2 or not tbid))
        tcr = (CFG['tcr_el2'] & ~63) | t0sz
        test_case(blob, req, {'tcr_el2': tcr}, rejected=rejected)
        cases += 1
    for override in (
            {'currentel': 4}, {'hcr_el2': 1 << 34}, {'sctlr_el2': 0},
            {'tcr_el2': 0x14 | (1 << 14)}, {'tcr_el2': 16}, {'tcr_el2': 25},
            {'id_aa64isar1_el1': 0, 'id_aa64isar2_el1': 0}):
        test_case(blob, default, override, rejected=True)
        cases += 1
    for index, value in ((0, 1 << 47), (0, 1 << 55), (4, 4), (4, 1 << 63),
                         (5, 2), (6, 2), (5, 1 << 63), (6, 1 << 63)):
        req = default.copy()
        req[index] = value
        test_case(blob, req, rejected=True)
        cases += 1
    for field in ('tcr_el2', 'sctlr_el2', 'apiakeylo_el1', 'apiakeyhi_el1'):
        test_case(blob, default, corrupt_read=field)
        cases += 1
    test_case(blob, default, inspect=True)
    cases += 1
    print(json.dumps(dict(cases=cases, probe_bytes=len(blob),
                          probe_sha256=hashlib.sha256(blob).hexdigest(),
                          boundary='control flow with modeled system registers and PAC/AUT'),
                     indent=2))


if __name__ == '__main__':
    main()
