#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native selector23 -> compiled display -> Legacy request-path replay.

Failure inventory and qualification boundary: docs/PANEL-MODE-REPLAY-20260928.md.
No hardware access. Kernel objects/dispatch are fixtures; native instructions run.
PAC is stripped for emulation and is not qualified by this replay.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

FAMILY = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/IOMobileGraphicsFamily.kext/Contents/MacOS/IOMobileGraphicsFamily')
KERNEL = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
DEFAULT_KEXT = ROOT / 'build/virtual-ethernet-clock-20260927/native-link-v3/AdrenoX2.kext/Contents/MacOS/AdrenoX2'
SETTER = '__ZN13AdrenoDisplay20set_digital_out_modeEjj'
BASE_SETTER = '__ZN25IOMobileFramebufferLegacy20set_digital_out_modeEjj'
HANDLER = '__ZN29IOMobileFramebufferUserClient22s_set_digital_out_modeEPS_PvP25IOExternalMethodArguments'
OBJECT, CLIENT, ARGS, SCALARS, VTABLE, STACK, RETURN = (0x40000000, 0x40010000, 0x40011000, 0x40012000, 0x40013000, 0x40100000, 0x40200000)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Image:
    def __init__(self, path, base):
        self.path, self.base = path, base
        raw = path.read_bytes()
        if raw[:4] == bytes.fromhex('cafebabe'):
            count, = struct.unpack_from('>I', raw, 4)
            slices = [struct.unpack_from('>5I', raw, 8 + i * 20) for i in range(count)]
            cpu, sub, off, size, _ = next(x for x in slices if x[0] == 0x100000c and (x[1] & 0xffffff) == 2)
            raw = raw[off:off + size]
        assert struct.unpack_from('<I', raw)[0] == 0xfeedfacf, 'expected Mach-O64'
        assert struct.unpack_from('<I', raw, 4)[0] == 0x100000c, 'expected arm64'
        self.raw, self.segments, self.symbols = raw, [], {}
        count, = struct.unpack_from('<I', raw, 16)
        at = 32
        for _ in range(count):
            cmd, size = struct.unpack_from('<II', raw, at)
            assert size >= 8 and at + size <= len(raw)
            if cmd == 0x19:
                name, va, vs, fo, fs = struct.unpack_from('<16sQQQQ', raw, at + 8)
                self.segments.append((name.rstrip(b'\0').decode(), va, vs, fo, fs))
            elif cmd == 2:
                so, ns, st, ss = struct.unpack_from('<4I', raw, at + 8)
                for i in range(ns):
                    name, typ, sect, desc, value = struct.unpack_from('<IBBHQ', raw, so + 16 * i)
                    if value and name < ss:
                        end = raw.index(b'\0', st + name, st + ss)
                        self.symbols[raw[st + name:end].decode()] = base + value
            at += size

    def read(self, address, size):
        va = address - self.base
        for _, lo, _, off, length in self.segments:
            if lo <= va and va + size <= lo + length:
                return self.raw[off + va - lo:off + va - lo + size]
        raise ValueError(f'unbacked address {address:#x}')

    def load(self, uc):
        pages = set()
        for _, va, vs, off, fs in self.segments:
            if not vs:
                continue
            for page in range((self.base + va) & ~4095, (self.base + va + vs + 4095) & ~4095, 4096):
                if page not in pages:
                    uc.mem_map(page, 4096)
                    pages.add(page)
            if fs:
                uc.mem_write(self.base + va, self.raw[off:off + fs])


def replay(family, driver, timing, color, layout=None, unavailable=None, fail_property=None):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    family.load(uc)
    driver.load(uc)
    uc.mem_map(OBJECT, 0x20000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(RETURN, 4096)
    q = lambda at, value: uc.mem_write(at, struct.pack('<Q', value))
    q(CLIENT + 0xd8, OBJECT)
    q(ARGS + 0x20, SCALARS)
    q(SCALARS, timing)
    q(SCALARS + 8, color)
    q(OBJECT, VTABLE)
    q(VTABLE + 0x918, driver.symbols[SETTER])
    metadata, gate_calls = {}, []
    if layout:
        for name, offset in layout.items():
            if name == 'fAttributesPublished':
                uc.mem_write(OBJECT + offset, bytes([int(unavailable != name)]))
            else:
                q(OBJECT + offset, 0 if unavailable == name else OBJECT + 0x8000)
        q(VTABLE + 0x2a0, RETURN + 0x200)
    # Bind the driver's imported Legacy vtable to the real native setter.
    fixes = subprocess.check_output(['dyld_info', '-fixups', str(driver.path)], text=True)
    slots = []
    for line in fixes.splitlines():
        if layout and '__ZN13IOCommandGate14runActionBlockEU13block_pointerFivE' in line:
            m = re.search(r'(0x[0-9A-Fa-f]+)\s+(?:auth-)?bind', line)
            assert m, line
            q(driver.base + int(m[1], 16), RETURN + 0x100)
        if '__ZTV25IOMobileFramebufferLegacy' in line:
            m = re.search(r'(0x[0-9A-Fa-f]+)\s+(?:auth-)?bind', line)
            if m:
                slot = driver.base + int(m[1], 16)
                q(slot, VTABLE + 0x2000)
                slots.append(slot)
    assert slots, 'missing native Legacy vtable binding'
    q(VTABLE + 0x2000 + 0x928, family.symbols[BASE_SETTER])
    uc.reg_write(reg.UC_ARM64_REG_X0, CLIENT)
    uc.reg_write(reg.UC_ARM64_REG_X2, ARGS)
    uc.reg_write(reg.UC_ARM64_REG_SP, STACK + 0xf000)
    uc.reg_write(reg.UC_ARM64_REG_X30, RETURN)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    visited, count = [], 0
    entries = {family.symbols[HANDLER]: 'native_selector23_handler', driver.symbols[SETTER]: 'compiled_AdrenoDisplay', family.symbols[BASE_SETTER]: 'native_Legacy_fallback'}

    def hook(u, pc, size, _):
        nonlocal count
        count += 1
        if pc == RETURN + 0x100:
            block = u.reg_read(reg.UC_ARM64_REG_X1)
            invoke, = struct.unpack('<Q', bytes(u.mem_read(block + 0x10, 8)))
            gate_calls.append(dict(block=hex(block), invoke=hex(invoke)))
            u.reg_write(reg.UC_ARM64_REG_X0, block)
            u.reg_write(reg.UC_ARM64_REG_PC, invoke)
            return
        if pc == RETURN + 0x200:
            address = u.reg_read(reg.UC_ARM64_REG_X1)
            name = bytes(u.mem_read(address, 128)).split(b'\0', 1)[0].decode()
            value = u.reg_read(reg.UC_ARM64_REG_X2)
            bits = u.reg_read(reg.UC_ARM64_REG_X3)
            if name != fail_property:
                metadata[name] = dict(value=value, bits=bits)
            u.reg_write(reg.UC_ARM64_REG_X0, int(name != fail_property))
            u.reg_write(reg.UC_ARM64_REG_PC, u.reg_read(reg.UC_ARM64_REG_X30))
            return
        if pc in entries:
            visited.append(entries[pc])
        ins = next(decoder.disasm(bytes(u.mem_read(pc, 4)), pc))
        if ins.mnemonic in ('pacibsp', 'autibsp', 'autda', 'pacda', 'pacia', 'autia', 'xpacd'):
            u.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
        elif ins.mnemonic in ('braa', 'brab', 'braaz', 'brabz', 'blraa', 'blrab', 'blraaz'):
            n = int(ins.op_str.split(',')[0].strip()[1:])
            target = u.reg_read(getattr(reg, f'UC_ARM64_REG_X{n}'))
            if ins.mnemonic.startswith('bl'):
                u.reg_write(reg.UC_ARM64_REG_X30, pc + 4)
            u.reg_write(reg.UC_ARM64_REG_PC, target)
        elif ins.mnemonic == 'retab':
            u.reg_write(reg.UC_ARM64_REG_PC, u.reg_read(reg.UC_ARM64_REG_X30))
        elif ins.mnemonic == 'brk':
            raise AssertionError(f'native trap at {pc:#x}')

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(family.symbols[HANDLER], RETURN, count=2000)
    assert uc.reg_read(reg.UC_ARM64_REG_PC) == RETURN, 'bounded request did not return'
    return dict(timing=timing, color=color, result=hex(uc.reg_read(reg.UC_ARM64_REG_X0) & 0xffffffff),
                geometry=struct.unpack('<II', bytes(uc.mem_read(OBJECT + 0x1bf0, 8))),
                visited=visited, instructions=count, metadata=metadata, gate_calls=gate_calls,
                unavailable=unavailable, fail_property=fail_property)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--kext', type=Path, default=DEFAULT_KEXT)
    p.add_argument('--candidate-qualification', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert not a.output.exists(), 'preserve existing evidence'
    layout, extra_inputs = None, []
    if a.candidate_qualification:
        qualification = json.loads(a.candidate_qualification.read_text())
        folder = a.candidate_qualification.parent
        a.kext = folder / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'
        obj = folder / 'obj/AdrenoDisplay.o'
        assert sha(a.kext) == qualification['kext_sha256']
        assert sha(obj) == qualification['new_object_sha256']
        dwarf = subprocess.check_output(['xcrun', 'dwarfdump', '--debug-info', str(obj)], text=True)
        layout = {}
        for name in ['fLegacyCommandGate', 'fAttributesPublished', 'fTimingElements', 'fColorElements']:
            matches = re.findall(r'DW_AT_name\s+\("' + name + r'"\)[\s\S]*?DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', dwarf)
            assert len(matches) == 1, (name, matches)
            layout[name] = int(matches[0], 16)
        extra_inputs = [a.candidate_qualification, obj]
    family, driver = Image(FAMILY, 0x10000000), Image(a.kext, 0x20000000)
    native = family.read(family.symbols[BASE_SETTER], 16)
    assert native.hex() == '5f2403d5e05880520000bc72c0035fd6'
    kernel = KERNEL.read_bytes()
    handler_bytes = family.read(family.symbols[HANDLER], 0x44)
    assert kernel.count(handler_bytes) == 1, 'native selector handler must match guest kernel uniquely'
    hits, at = [], 0
    while (at := kernel.find(native, at)) >= 0:
        hits.append(at)
        at += 4
    assert hits, 'native unsupported fallback bytes absent from guest kernel'
    cases = [replay(family, driver, t, c, layout) for t, c in [(1000, 100), (1000, 102), (1000, 103), (999, 100), (1000, 101)]]
    for row in cases:
        valid = row['timing'] == 1000 and row['color'] in (100, 102, 103)
        assert row['result'] == (('0x0' if layout else '0xe00002c7') if valid else '0xe00002f0'), row
        assert row['geometry'] == ((2880, 1800) if valid else (0, 0)), row
        assert ('native_Legacy_fallback' in row['visited']) == (valid and not layout)
        if layout:
            assert len(row['gate_calls']) == 1
            assert row['metadata'] == (dict(DisplayWidth=dict(value=2880, bits=32),
                DisplayHeight=dict(value=1800, bits=32), DPTimingModeId=dict(value=1000, bits=64)) if valid else {})
    if layout:
        for name in layout:
            row = replay(family, driver, 1000, 100, layout, unavailable=name)
            assert row['result'] == '0xe00002d8' and row['geometry'] == (0, 0) and not row['metadata'], row
            assert len(row['gate_calls']) == (0 if name == 'fLegacyCommandGate' else 1)
            cases.append(row)
        for name in ['DisplayWidth', 'DisplayHeight', 'DPTimingModeId']:
            row = replay(family, driver, 1000, 100, layout, fail_property=name)
            assert row['result'] == '0xe00002bd' and row['geometry'] == (0, 0), row
            assert name not in row['metadata'] and 'native_Legacy_fallback' not in row['visited'], row
            cases.append(row)
    result = dict(status='CANDIDATE_PANEL_MODE_NATIVE_PATH_PASSED' if layout else 'INSTALLED_PANEL_MODE_FAILURE_REPRODUCED', hardware_access=False,
        cases=cases, layout=layout, inputs_sha256={str(p): sha(p) for p in [FAMILY, a.kext, KERNEL, Path(__file__), *extra_inputs]},
        native_fallback_hex=native.hex(), guest_byte_matches=hits,
        native_handler_hex=handler_bytes.hex(), guest_handler_offset=kernel.index(handler_bytes),
        boundary=['Native selector handler and compiled driver/base instructions executed',
                  'User-space RPC and kernel dispatch/object lifecycle are fixtures',
                  'Guest byte match is not unique symbol identity',
                  'PAC instructions are stripped; no PAC or hardware qualification',
                  'Command gate executes the real compiled block synchronously; no concurrency proof',
                  'IORegistry numeric property storage and allocation failures are fixtures',
                  'Observed failing WindowServer arguments remain unknown'])
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], output=str(a.output), sha256=sha(a.output), cases=len(cases))))


if __name__ == '__main__':
    main()
