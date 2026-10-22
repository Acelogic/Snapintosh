#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay installed 26A428 nonce queries using the production pnon producer.

The failure inventory is in docs/INSTALLED-PNON-POLICY-20260926.md. Original
library instructions run under Unicorn; allocation, logging and transport are
explicit fixtures, PAC is omitted. Unknown calls and unmapped reads fail. This
proves a consumer contract, not physical delivery or a policy decision.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ
import unicorn.arm64_const as reg

LIB_SHA = 'a2df9c6efd25a310df3e0d905468a85e30d7a6dab4473b2a666a0676a303b002'
UUID = '528b381c8756328fbe208b9573a7ec3a'
IMAGE = '/usr/lib/libbootpolicy.dylib'
DIGEST = 0x1b31ef8a8
BLESSED = 0x1b31ef308
SECURITY = 0x1b31f2f44
SEND = 0x1b31f1108
DATA, OUT, RETURN, HEAP = 0x1000000, 0x1003000, 0x1004000, 0x1008000
LOGGER = 0x1e50925c8
IMPORTS = {
    0x1b81c66f0: (0x1e7ff50b8, '_malloc_type_calloc'),
    0x1b81c6670: (0x1e7ff5018, '_free'),
    0x1b81c67b0: (0x1e7ff5fb8, '_os_log_create'),
    0x1b81c67c0: (0x1e7ff6010, '_os_log_type_enabled'),
    0x1b81c65b0: (0x1e7ff5e00, '__os_log_impl'),
    0x1b81cead0: (0x1e7ff18e0, '_syslog$DARWIN_EXTSN'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Native:
    def __init__(self, path, cache):
        assert sha(path) == LIB_SHA, 'unexpected installed library'
        data = path.read_bytes()
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mapped, self.instructions, self.bindings = set(), {}, []
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        offset = 32
        image_uuid = None
        for _ in range(struct.unpack_from('<I', data, 16)[0]):
            cmd, size = struct.unpack_from('<II', data, offset)
            if cmd == 0x1b:
                image_uuid = data[offset + 8:offset + 24].hex()
            if cmd == 0x19:
                va, vmsize, fo, fs = struct.unpack_from('<4Q', data, offset + 24)
                if vmsize:
                    self.map(va, vmsize)
                if fs:
                    self.u.mem_write(va, data[fo:fo + fs])
                for n in range(struct.unpack_from('<I', data, offset + 64)[0]):
                    sec = offset + 72 + n * 80
                    if data[sec:sec + 16].rstrip(b'\0') == b'__text':
                        address, length = struct.unpack_from('<QQ', data, sec + 32)
                        raw = data[fo + address - va:fo + address - va + length]
                        assert raw == cache.read(address, length), 'native text differs from cache'
                        self.instructions.update((i.address, i) for i in md.disasm(raw, address))
                        self.bindings.append(dict(address=hex(address), length=length,
                                                  sha256=hashlib.sha256(raw).hexdigest()))
            offset += size
        assert image_uuid == UUID
        for stub, (pointer, name) in IMPORTS.items():
            code = list(md.disasm(cache.read(stub, 16), stub))
            assert [i.mnemonic for i in code] == ['adrp', 'add', 'ldr', 'braa']
            page = int(code[0].op_str.split('#')[1], 16)
            delta = int(code[1].op_str.split('#')[1], 16)
            assert page + delta == pointer
            target = cache.pointer_target(pointer)
            assert any(any(a == target and s == name for a, s, *_ in cache.symbols(owner))
                       for owner, _ in cache.owner(target)), (name, hex(target))
            self.bindings.append(dict(stub=hex(stub), target=hex(target), symbol=name,
                                      bytes=cache.read(stub, 16).hex()))
        self.map(DATA, 0x40000)
        self.external_ranges = []
        external_pages = set()
        for pointer, symbol in [(0x1e0220d20, '__os_log_default'),
                                (0x1e02205c0, '___stack_chk_guard')]:
            target = cache.pointer_target(pointer)
            assert any(any(a == target and name == symbol
                           for a, name, *_ in cache.symbols(owner))
                       for owner, _ in cache.owner(target))
            self.map(pointer, 8)
            self.u.mem_write(pointer, struct.pack('<Q', target))
            self.external_ranges.append((pointer, 8))
            external_pages.add(pointer & ~0xfff)
            self.bindings.append(dict(pointer=hex(pointer), target=hex(target), symbol=symbol))
            if symbol == '___stack_chk_guard':
                # A constant canary is sufficient for the original save/compare
                # path; it is explicitly a fixture, not a runtime secret.
                self.map(target, 8)
                self.u.mem_write(target, struct.pack('<Q', 0x5152535455565758))
                self.external_ranges.append((target, 8))
                external_pages.add(target & ~0xfff)
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.u.hook_add(UC_HOOK_MEM_INVALID, self.invalid_memory)
        for page in external_pages:
            self.u.hook_add(UC_HOOK_MEM_READ, self.external_read, begin=page, end=page + 0xfff)

    def external_read(self, u, access, address, size, value, unused):
        assert any(start <= address and address + size <= start + length
                   for start, length in self.external_ranges)

    def invalid_memory(self, u, access, address, size, value, unused):
        self.invalid_access = (access, hex(address), size,
                               hex(u.reg_read(reg.UC_ARM64_REG_PC)))
        return False

    def map(self, va, size):
        for page in range(va & ~0xfff, (va + size + 0xfff) & ~0xfff, 0x1000):
            if page not in self.mapped:
                self.u.mem_map(page, 0x1000)
                self.mapped.add(page)

    def ret(self, pc, value=0, tail=False):
        self.u.reg_write(reg.UC_ARM64_REG_X0, value)
        self.u.reg_write(reg.UC_ARM64_REG_PC,
                         self.u.reg_read(reg.UC_ARM64_REG_X30) if tail else pc + 4)

    def hook(self, u, pc, size, unused):
        ins = self.instructions.get(pc)
        assert ins is not None, f'unmodeled native exit {pc:x}'
        self.executed.add(pc)
        if ins.mnemonic in ('pacibsp', 'autibsp', 'autda', 'xpacd', 'pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
            return
        if ins.mnemonic == 'retab':
            u.reg_write(reg.UC_ARM64_REG_PC, u.reg_read(reg.UC_ARM64_REG_X30))
            return
        if pc == SEND:
            assert ins.mnemonic == 'bl' and ins.op_str == '#0x1b31e4374'
            assert u.reg_read(reg.UC_ARM64_REG_X1) == 32
            self.sent.append(bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X0), 32)))
            length_at = u.reg_read(reg.UC_ARM64_REG_X3)
            capacity = struct.unpack('<Q', u.mem_read(length_at, 8))[0]
            self.capacities.append(capacity)
            assert len(self.payload) <= capacity
            if not self.transport_status:
                u.mem_write(u.reg_read(reg.UC_ARM64_REG_X2), self.payload)
                u.mem_write(length_at, struct.pack('<Q', len(self.payload)))
            self.ret(pc, self.transport_status)
            return
        if ins.mnemonic in ('bl', 'b', 'blr', 'blraa', 'blraaz', 'braa', 'braaz'):
            target = int(ins.op_str[1:], 16) if ins.op_str.startswith('#') else None
            if target in self.instructions:
                return
            assert target in IMPORTS, f'unmodeled call {pc:x}: {ins.mnemonic} {ins.op_str}'
            name = IMPORTS[target][1]
            self.calls.append(name)
            result = 0
            if name == '_malloc_type_calloc':
                length = u.reg_read(reg.UC_ARM64_REG_X0) * u.reg_read(reg.UC_ARM64_REG_X1)
                assert 0 < length <= 0x5000
                self.allocations.append(length)
                result = HEAP + 0x8000 * len(self.allocations)
                assert result + length < DATA + 0x38000
                self.live.add(result)
                u.mem_write(result, bytes(length))
            elif name == '_free':
                pointer = u.reg_read(reg.UC_ARM64_REG_X0)
                if pointer:
                    assert pointer in self.live, 'free of unknown or already freed pointer'
                    self.live.remove(pointer)
                    self.frees += 1
            self.ret(pc, result, ins.mnemonic == 'b')
        if ins.mnemonic == 'brk':
            raise AssertionError(f'native trap at {pc:x}')

    def run(self, command, payload, public=False, transport_status=0, security=False):
        self.payload, self.transport_status = payload, transport_status
        self.sent, self.capacities, self.allocations, self.calls = [], [], [], []
        self.live, self.executed, self.frees = set(), set(), 0
        self.invalid_access = None
        self.u.mem_write(DATA, bytes(0x40000))
        self.u.mem_write(LOGGER, bytes(8))
        self.u.mem_write(OUT, b'\xdd' * 48)
        for n in range(31):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), 0)
        self.u.reg_write(reg.UC_ARM64_REG_X0, OUT if public else command)
        self.u.reg_write(reg.UC_ARM64_REG_X1, 0 if public else OUT)
        if security:
            # Two non-default UUID argument buffers. The reached error path
            # returns before reading a policy file or using either UUID.
            self.u.reg_write(reg.UC_ARM64_REG_X0, DATA + 0x5000)
            self.u.reg_write(reg.UC_ARM64_REG_X1, DATA + 0x6000)
            self.u.reg_write(reg.UC_ARM64_REG_X2, OUT)
        self.u.reg_write(reg.UC_ARM64_REG_X30, RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP, DATA + 0x3f000)
        self.u.reg_write(reg.UC_ARM64_REG_CPACR_EL1, 3 << 20)
        try:
            entry = SECURITY if security else BLESSED if public else DIGEST
            self.u.emu_start(entry, RETURN, count=20000)
        except Exception as error:
            raise AssertionError(f'native replay failed: {error}; '
                                 f'invalid_access={self.invalid_access}') from error
        assert self.u.reg_read(reg.UC_ARM64_REG_PC) == RETURN, 'did not return'
        expected = [0x4028, 36, 32, 80] if security else [32, 80]
        assert not self.live and self.frees == len(expected) and self.allocations == expected
        if security:
            assert {SECURITY, 0x1b31f3170, 0x1b31e3350, BLESSED, DIGEST,
                    0x1b31e4968, 0x1b31f10b4}.issubset(self.executed)
        return dict(status=self.u.reg_read(reg.UC_ARM64_REG_W0),
                    output=bytes(self.u.mem_read(OUT, 48)).hex(),
                    sent=[x.hex() for x in self.sent], capacities=self.capacities,
                    allocations=self.allocations, frees=self.frees,
                    fixture_calls=self.calls, instructions=len(self.executed),
                    security_command_11_reached=0x1b31f32cc in self.executed)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--artifacts', type=Path, required=True)
    ap.add_argument('--library', type=Path, default=ROOT / 'build/installed-pnon-20260926/native/libbootpolicy.dylib')
    ap.add_argument('--cache', type=Path, default=Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld'))
    ap.add_argument('--capture', type=Path, default=ROOT / 'build/installed-adreno-cache-v2-600s-20260926-bootpolicy-caller-v2.json')
    args = ap.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=False)
    producer_path = args.artifacts / 'pnon-producer.dylib'
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    str(ROOT / 'compat/sep-pnon.c'), '-o', str(producer_path)], check=True)
    producer = ctypes.CDLL(str(producer_path))
    producer.sep_pnon_refuse_sized.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    producer.sep_pnon_refuse_sized.restype = ctypes.c_int
    capture = json.loads(args.capture.read_text())
    waits = [w for w in capture['bootpolicy_waits'] if w['pid'] == 201 and w['tid'] == 1536]
    assert len(waits) == 1 and waits[0]['size'] == 32 and not waits[0]['header_truncated']
    request = bytes.fromhex(waits[0]['header_hex'])
    assert request == struct.pack('<8I', 0x42506368, 0xe, 0, 0, 0, 0, 0, 0)
    raw = ctypes.create_string_buffer(36)
    assert producer.sep_pnon_refuse_sized(request, len(request), raw) == 32
    reply = raw.raw[:32]
    assert reply == struct.pack('<8I', 0x42507268, 0xff, 0, 0, 0, 0, 0, 0)
    Cache = runpy.run_path(str(ROOT / 'tools/dyld-cache.py'))['Cache']
    cases = []
    with Cache(args.cache) as cache:
        native = Native(args.library, cache)
        for command in range(0xb, 0x11):
            result = native.run(command, reply)
            assert result['status'] == 255 and result['output'] == 'dd' * 48
            assert result['sent'] == [struct.pack('<8I', 0x42506368, command, 0, 0, 0, 0, 0, 0).hex()]
            assert result['capacities'] == [80]
            cases.append(dict(name=f'nonce-{command:02x}', **result))
        result = native.run(0xe, reply, public=True)
        assert result['status'] == 255 and result['output'] == 'dd' * 48
        assert result['sent'] == [request.hex()]
        cases.append(dict(name='public-blessed-nonce', **result))
        good = struct.pack('<8I', 0x42507268, 0, 0, 0, 0, 0, 0, 0) + bytes(range(48))
        result = native.run(0xe, good, public=True)
        assert result['status'] == 0 and result['output'] == bytes(range(48)).hex()
        cases.append(dict(name='synthetic-success-control', **result))
        for name, body, transport in [('short-header', reply[:31], 0),
                                      ('short-success', good[:32], 0),
                                      ('wrong-magic', bytes(4) + reply[4:], 0),
                                      ('transport-error', b'', 5)]:
            result = native.run(0xe, body, public=True, transport_status=transport)
            assert result['status'] != 0 and result['output'] == 'dd' * 48
            cases.append(dict(name=name, **result))
        result = native.run(0xe, reply, security=True)
        assert result['status'] == 255 and result['output'] == 'dd' * 48
        assert result['sent'] == [request.hex()] and not result['security_command_11_reached']
        cases.append(dict(name='security-mode-refusal', **result))
    source_names = ['compat/sep-pnon.c', 'compat/sep-pnon.h',
                    'tools/replay-installed-pnon.py', 'tools/dyld-cache.py']
    report = dict(scope='offline installed nonce consumer; no hardware/policy-success claim',
                  library_sha256=LIB_SHA, library_uuid=UUID, capture_sha256=sha(args.capture),
                  source_sha256={name: sha(ROOT / name) for name in source_names},
                  producer_sha256=sha(producer_path), producer_api='sep_pnon_refuse_sized',
                  request=request.hex(), reply=reply.hex(),
                  native_bindings=native.bindings, cases=cases)
    output = args.artifacts / 'replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(output=str(output), cases=len(cases), status='passed')))


if __name__ == '__main__':
    main()
