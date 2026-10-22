#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run native SKS wrapper/serialization instructions before implementing a model.

Failure inventory and fixture boundary: docs/SKS-NATIVE-REPLAY-20260928.md.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ
import unicorn.arm64_const as reg

IMAGE = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/AppleSEPKeyStore.kext/Contents/MacOS/AppleSEPKeyStore')
IMAGE_SHA = '07f7754966625c1642891ee4be9e12cba9f83ce593a11644c479d10eba594e9d'
IMAGE_UUID = 'f0a296ee2d503d56a383289d9f2c382f'
LLVM = Path('/opt/homebrew/opt/llvm/bin')
DATA, AREA = 0x1000000, 0x100000
CTX, ARGS, DECODE = DATA+0x2000, DATA+0x4000, DATA+0x5000
BUF, REPLY, PAYLOAD, OUT = DATA+0x8000, DATA+0xc000, DATA+0x10000, DATA+0x14000
OUTPTR, OUTLEN, GUARD, DI = DATA+0x18000, DATA+0x18008, DATA+0x18100, DATA+0x18200
PROC, CRED, POSIX_CRED, CDHASH = DATA+0x18400, DATA+0x18500, DATA+0x18600, DATA+0x18700
PROCESS_ID, USER_ID = 0x876543210fedcba9, 0x24681357
RETURN, CALLBACK, FINAL, PROBE = DATA+0x20000, DATA+0x20100, DATA+0x20200, DATA+0x20300
STACK = DATA+AREA-0x100
ENTRY, CODE = 0x45224, 0x2c118
CLOCK_TICKS = 0x13579bdf2468ace0
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


class Native:
    def __init__(self):
        assert sha(IMAGE) == IMAGE_SHA
        fat = IMAGE.read_bytes()
        assert struct.unpack_from('>I', fat)[0] == 0xcafebabe
        arches = [struct.unpack_from('>IIIII', fat, 8+i*20) for i in range(struct.unpack_from('>I', fat, 4)[0])]
        matches = [a for a in arches if a[:2] == (0x100000c, 0xc0000002)]
        assert len(matches) == 1
        _, _, offset, size, _ = matches[0]
        raw = fat[offset:offset+size]
        assert struct.unpack_from('<I', raw)[0] == 0xfeedfacf
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.pages, self.instructions = set(), {}
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.skipdata = True
        pos, uuid = 32, None
        for _ in range(struct.unpack_from('<I', raw, 16)[0]):
            cmd, length = struct.unpack_from('<II', raw, pos)
            if cmd == 0x1b:
                uuid = raw[pos+8:pos+24].hex()
            if cmd == 0x19:
                name = raw[pos+8:pos+24].rstrip(b'\0').decode()
                va, vmbytes, fo, fs = struct.unpack_from('<QQQQ', raw, pos+24)
                if name != '__LINKEDIT':
                    self.map(va, vmbytes)
                    if fs:
                        self.u.mem_write(va, raw[fo:fo+fs])
                    if name == '__TEXT_EXEC':
                        self.instructions.update((i.address, i) for i in md.disasm(raw[fo:fo+fs], va))
            pos += length
        assert uuid == IMAGE_UUID
        symbols = subprocess.check_output([str(LLVM/'llvm-nm'), '--arch=arm64e', '-n', str(IMAGE)], text=True)
        assert f'{ENTRY:016x} t __ipc_get_device_state' in symbols
        assert f'{CODE:016x} t _code_ipc_get_device_state' in symbols
        assembly = subprocess.check_output([str(LLVM/'llvm-objdump'), '--macho', '--arch=arm64e', '-d', str(IMAGE)], text=True)
        self.imports = {}
        for line in assembly.splitlines():
            match = re.search(r'\b(?:bl|b)\s+0x([0-9a-f]+)\s*; symbol stub for: (\S+)', line)
            if match:
                self.imports[int(match[1], 16)] = match[2]
        self.map(DATA, AREA)
        self.put(0x5a428, '<Q', GUARD)  # Native ___stack_chk_guard import.
        self.put(GUARD, '<Q', 0xa183ea7155cc9922)
        self.put(0x5a480, '<Q', PROBE)  # Native dynamic stack probe import.
        self.put(DI, '<QQQ', 32, 32, 64)
        self.put(DI+0x38, '<Q', FINAL)
        self.put(CRED+0x80, '<Q', POSIX_CRED)
        self.put(POSIX_CRED+0x24, '<I', USER_ID)
        self.u.mem_write(CDHASH, bytes(range(0xa1, 0xb5)))
        self.events, self.callbacks, self.executed, self.digests = [], [], set(), {}
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.u.hook_add(UC_HOOK_MEM_INVALID, self.invalid)
        self.u.hook_add(UC_HOOK_MEM_READ, self.memory_read)

    def map(self, address, size):
        for page in range(address & ~0xfff, (address+size+0xfff) & ~0xfff, 0x1000):
            if page not in self.pages:
                self.u.mem_map(page, 0x1000)
                self.pages.add(page)

    def put(self, address, fmt, *values):
        self.u.mem_write(address, struct.pack(fmt, *values))

    def x(self, n):
        return self.u.reg_read(getattr(reg, f'UC_ARM64_REG_X{n}'))

    def result(self, value=0, preserve=False):
        if not preserve:
            self.u.reg_write(reg.UC_ARM64_REG_X0, value & 0xffffffffffffffff)
        self.u.reg_write(reg.UC_ARM64_REG_PC, self.x(30))

    def memory_read(self, u, access, address, size, value, unused):
        assert address >= 0x100, f'native null/near-null read {address:#x}'

    def invalid(self, u, access, address, size, value, unused):
        raise AssertionError(f'unmapped native access type={access} address={address:#x} size={size} pc={self.u.reg_read(reg.UC_ARM64_REG_PC):#x}')

    def hook(self, u, pc, size, unused):
        if pc == CALLBACK:
            assert self.x(0) == CTX and self.x(1) == 0x19
            self.callbacks.append(dict(context=hex(self.x(0)), command=self.x(1),
                args_hex=bytes(u.mem_read(self.x(2), 0xf8)).hex()))
            self.result(0x1234)
            return
        if pc == PROBE:
            assert self.x(9) < 0x4000
            self.events.append(dict(name='stack-probe', bytes=self.x(9)))
            self.result(preserve=True)
            return
        if pc == FINAL:
            assert self.x(0) == DI and self.x(1) in self.digests
            u.mem_write(self.x(2), self.digests[self.x(1)].digest())
            self.events.append(dict(name='SHA256-final', context=hex(self.x(1))))
            self.result()
            return
        if pc in self.imports:
            name = self.imports[pc]
            x0, x1, x2, x3 = [self.x(n) for n in range(4)]
            self.events.append(dict(name=name, args=[hex(v) for v in [x0,x1,x2,x3]]))
            value = 0
            if name == '_bzero':
                assert x1 <= 0x10000
                u.mem_write(x0, bytes(x1))
            elif name == '_mach_continuous_time':
                value = CLOCK_TICKS
                self.events[-1]['result'] = hex(value)
            elif name == '_absolutetime_to_nanoseconds':
                assert x0 == CLOCK_TICKS and DATA <= x1 <= DATA+AREA-8
                self.put(x1, '<Q', x0)  # Explicit synthetic 1 GHz timebase.
                self.events[-1]['nanoseconds'] = hex(x0)
            elif name == '_clock_get_calendar_microtime':
                assert DATA <= x0 <= DATA+AREA-8 and DATA <= x1 <= DATA+AREA-4
                self.put(x0, '<Q', 0x12345678)
                self.put(x1, '<I', 654321)
            elif name == '_proc_self':
                value = PROC
            elif name == '_kauth_cred_proc_ref':
                assert x0 == PROC
                value = CRED
            elif name == '_proc_uniqueid':
                assert x0 == PROC
                value = PROCESS_ID
            elif name == '_kauth_cred_unref':
                assert bytes(u.mem_read(x0,8)) == struct.pack('<Q', CRED)
                self.put(x0, '<Q', 0)
            elif name == '_proc_rele':
                assert x0 == PROC
            elif name == '_cs_get_cdhash':
                assert x0 == PROC
                value = CDHASH
            elif name == '_memset_s':
                assert x3 <= x1 <= 0x10000
                u.mem_write(x0, bytes([x2 & 255])*x3)
            elif name in ('_memcpy', '_memmove'):
                assert x2 <= 0x10000
                u.mem_write(x0, bytes(u.mem_read(x1, x2)))
                value = x0
            elif name == '_memcmp':
                assert x2 <= 0x10000
                a, b = bytes(u.mem_read(x0,x2)), bytes(u.mem_read(x1,x2))
                value = (a > b) - (a < b)
            elif name == '_ccsha256_di':
                value = DI
            elif name == '_ccdigest_init':
                assert x0 == DI
                self.digests[x1] = hashlib.sha256()
            elif name == '_ccdigest_update':
                assert x0 == DI and x1 in self.digests and x2 <= 0x10000
                self.digests[x1].update(bytes(u.mem_read(x3, x2)))
            elif name == '_cc_clear':
                assert x0 <= 0x10000
                u.mem_write(x1, bytes(x0))
            else:
                raise AssertionError(f'unmodeled native import {name} at {pc:#x}')
            self.result(value)
            return
        ins = self.instructions.get(pc)
        assert ins is not None, f'outside native instruction image {pc:#x}'
        self.executed.add(pc)
        if ins.mnemonic in ('pacibsp','paciasp','autibsp','autiasp','autda','autia','xpacd','pacia','pacda'):
            u.reg_write(reg.UC_ARM64_REG_PC, pc+4)
        elif ins.mnemonic in ('retab','retaa'):
            u.reg_write(reg.UC_ARM64_REG_PC, self.x(30))
        elif ins.mnemonic in ('blraa','blraaz','braa','braaz'):
            target = self.x(int(ins.op_str.split(',')[0].strip()[1:]))
            assert target in self.instructions or target in self.imports or target in (CALLBACK, FINAL, PROBE), (hex(pc),hex(target))
            if ins.mnemonic.startswith('bl'):
                u.reg_write(reg.UC_ARM64_REG_X30, pc+4)
            u.reg_write(reg.UC_ARM64_REG_PC, target)
        elif ins.mnemonic == 'brk':
            raise AssertionError(f'native trap {pc:#x}')

    def invoke(self, entry, *args):
        for n in range(31):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), 0)
        self.u.reg_write(reg.UC_ARM64_REG_SP, STACK)
        self.u.reg_write(reg.UC_ARM64_REG_X30, RETURN)
        for n, value in enumerate(args):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        self.u.emu_start(entry, RETURN, count=200000)
        assert self.u.reg_read(reg.UC_ARM64_REG_PC) == RETURN, 'native instruction budget exhausted'
        return self.x(0) & 0xffffffff


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    record = dict(status='RUNNING', hardware_access=False, image_sha256=sha(IMAGE), image_uuid=IMAGE_UUID,
        inputs_sha256={str(p):sha(p) for p in [Path(__file__), ROOT/'docs/SKS-NATIVE-REPLAY-20260928.md']},
        cases=[], boundary='Native serialization consumer replay. Explicit memory, SHA256, stack, synthetic process identity, deterministic clock and callback fixtures; no endpoint/device-state or physical delivery proof.')
    try:
        for version in [1, 2]:
            native = Native()
            native.put(CTX+0x10, '<I', version)
            native.put(OUTPTR, '<Q', OUT)
            native.put(OUTLEN, '<I', 0x100)
            result = native.invoke(ENTRY, CALLBACK, CTX, 0x1122334455667788, 0x99aabbcc, 0x10203040, OUTPTR, OUTLEN)
            assert result == 0x1234 and len(native.callbacks) == 1
            block = bytes.fromhex(native.callbacks[0]['args_hex'])
            native.u.mem_write(ARGS, block)
            length = native.invoke(CODE, 1, 0, BUF, 0x1000, ARGS)
            assert 0 < length <= 0x1000, f'encode failed {length:#x}'
            request = bytes(native.u.mem_read(BUF, length))
            decoded = native.invoke(CODE, 0, 1, BUF, length, DECODE)
            assert decoded == length
            assert bytes(native.u.mem_read(DECODE+0x58, 16)) == block[0x58:0x68]
            record['cases'].append(dict(version=version, wrapper_result=result,
                callback=native.callbacks[0], request_hex=request.hex(), request_bytes=length,
                decoded_bytes=decoded, native_arguments_hex=bytes(native.u.mem_read(DECODE,0xf8)).hex(),
                executed_pcs=[hex(x) for x in sorted(native.executed)], fixture_calls=native.events))
        record['status'] = 'NATIVE_SKS_REQUEST_ROUNDTRIP_QUALIFIED'
    except Exception as error:
        record.update(status='FAILED', error=repr(error))
        if 'native' in locals():
            record['last_fixture_calls'] = native.events[-20:]
            record['last_callbacks'] = native.callbacks
            record['last_pc'] = hex(native.u.reg_read(reg.UC_ARM64_REG_PC))
        raise
    finally:
        with args.output.open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
    print(json.dumps(dict(output=str(args.output), status=record['status'], sha256=sha(args.output))))


if __name__ == '__main__':
    main()
