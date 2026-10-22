#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the shipped SEP discovery parser up to service publication.

Runs the original instruction bytes offline. Models the work-loop gate and
logging, omits pointer authentication, and stops at _exposeNub or a native
refusal. This does not qualify ASC delivery, IRQs, SEP boot or live services.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

START = 0xfffffe00099b0ee0
END = 0xfffffe00099b11fc
DATA = 0x1000000
KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'


class Parser:
    def __init__(self, image):
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        code = START & ~0xfff
        self.u.mem_map(code, 0x2000)
        off = image.va2off(code)
        self.u.mem_write(code, image.data[off:off+0x2000])
        self.u.mem_map(DATA, 0x10000)
        self.u.mem_write(DATA, struct.pack('<Q', DATA+0x4000))
        self.u.mem_write(DATA+0x5000, struct.pack('<Q', DATA+0x4000))
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.stop = None
        self.publications = []

    def hook(self, u, pc, size, _):
        if pc in (0xfffffe00099b0ee4, 0xfffffe00099b0f10,
                  0xfffffe00099b0f34, 0xfffffe00099b1174):
            u.reg_write(reg.UC_ARM64_REG_PC, pc+4)  # PAC omitted in this replay
        elif pc in (0xfffffe00099b0f24, 0xfffffe00099b0f48):
            u.reg_write(reg.UC_ARM64_REG_X0,
                        DATA+0x5000 if pc == 0xfffffe00099b0f24 else 1)
            u.reg_write(reg.UC_ARM64_REG_PC, pc+4)  # work loop; inGate=true
        elif pc == 0xfffffe00099b1130:
            u.reg_write(reg.UC_ARM64_REG_PC, pc+4)  # duplicate/unknown log
        elif pc == 0xfffffe00099b1184:
            address = u.reg_read(reg.UC_ARM64_REG_X1)
            if not DATA+0xaa <= address <= DATA+0xaa+2520 or (address-DATA-0xaa) % 10:
                raise AssertionError('native publication points outside records')
            # _exposeNub receives the nine-byte info after the ready flag.
            self.publications.append(bytes(u.mem_read(address, 9)).hex())
            self.stop = 'publish'
            u.emu_stop()
        elif pc == 0xfffffe00099b11cc:
            self.stop = 'return'
            u.emu_stop()
        elif pc == 0xfffffe00099b10a0 or 0xfffffe00099b11d0 <= pc < END:
            self.stop = f'refuse:{pc:x}'
            u.emu_stop()
        elif not START <= pc < END:
            raise AssertionError(f'unmodeled native exit {pc:x}')

    def send(self, message):
        assert len(message) == 8
        self.u.mem_write(DATA+0x2000, message)
        self.u.reg_write(reg.UC_ARM64_REG_X0, DATA)
        self.u.reg_write(reg.UC_ARM64_REG_X1, 0)
        self.u.reg_write(reg.UC_ARM64_REG_X2, DATA+0x2000)
        self.u.reg_write(reg.UC_ARM64_REG_X30, DATA+0x7000)
        self.u.reg_write(reg.UC_ARM64_REG_SP, DATA+0xf000)
        self.stop = None
        self.u.emu_start(START, END, count=20000)
        assert self.stop is not None, 'native parser did not reach a known exit'
        return self.stop

    def records(self):
        count, = struct.unpack('<Q', self.u.mem_read(DATA+0xa90, 8))
        assert count <= 253
        return bytes(self.u.mem_read(DATA+0xa9, count*10)) if count else b''


def advertisement(endpoint, name):
    return struct.pack('<4BI', 0xfd, 0, 0, endpoint, name)


def ool(endpoint, *sizes):
    return bytes((0xfd, 0, 1, endpoint, *sizes))


def main():
    image = runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    sha = hashlib.sha256(image.data).hexdigest()
    assert sha == KERNEL_SHA
    calls = 0
    # The endpoint number is allocated by virtual firmware; the name is the
    # stock pnon service's FourCC. OOL sizes here are parser test data only.
    for endpoint in (1, 5, 31):
        p = Parser(image)
        first = advertisement(endpoint, 0x706e6f6e)
        assert p.send(first) == 'return'; calls += 1
        assert not p.publications
        expected = struct.pack('<BIB4B', 0, 0x706e6f6e, endpoint, 0, 0, 0, 0)
        assert p.records() == expected
        assert p.send(first) == 'return'; calls += 1
        assert p.records() == expected
        second = ool(endpoint, 1, 7, 1, 5)
        assert p.send(second) == 'publish'; calls += 1
        expected = struct.pack('<BIB4B', 1, 0x706e6f6e, endpoint, 1, 7, 1, 5)
        assert p.records() == expected and p.publications == [expected[1:].hex()]
        assert p.send(second) == 'return'; calls += 1
        assert p.records() == expected and len(p.publications) == 1
        for malformed in (advertisement(endpoint, 0x61626364),
                          advertisement(endpoint+1, 0x706e6f6e),
                          ool(endpoint, 2, 7, 1, 5),
                          ool(endpoint, 1, 8, 1, 5),
                          ool(endpoint, 1, 7, 2, 5),
                          ool(endpoint, 1, 7, 1, 6)):
            assert p.send(malformed).startswith('refuse:'); calls += 1
            assert p.records() == expected and len(p.publications) == 1
    p = Parser(image)
    assert p.send(ool(1, 1, 7, 1, 5)).startswith('refuse:'); calls += 1
    assert not p.records() and not p.publications
    assert p.send(bytes((0xfc, 0, 0, 1, 0, 0, 0, 0))).startswith('refuse:'); calls += 1
    assert not p.records()
    # Native capacity: 253 unique records; the next one must be refused
    # before it changes the array or count.
    p = Parser(image)
    for endpoint in range(253):
        assert p.send(advertisement(endpoint, endpoint+1)) == 'return'; calls += 1
    before = p.records()
    assert p.send(advertisement(253, 254)).startswith('refuse:'); calls += 1
    assert p.records() == before and len(before) == 2530
    print(json.dumps(dict(kernel_sha256=sha, calls=calls,
        normal_advertisement_hex=advertisement(5, 0x706e6f6e).hex(),
        sample_ool_advertisement_hex=ool(5, 1, 7, 1, 5).hex(),
        boundary='original discovery parser through publication call; modeled work-loop gate, logging and PAC; no live SEP or ASC proof')))


if __name__ == '__main__':
    main()
