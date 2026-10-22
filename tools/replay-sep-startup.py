#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the pinned SEP manager's startup gates without touching hardware.

The original power-state, OS-active and preload instruction bytes run in Unicorn.
IOKit properties, vtable calls, timers and logging are explicit call-site
fixtures; PAC is omitted. Power replay stops before _bootSEP or after its
null-firmware branch; preload replay stops before DMA preparation. This proves
branching and input requirements, not firmware execution, mailbox
delivery, service publication, or completion of a boot task.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'build/test-python-deps'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
import unicorn.arm64_const as reg

KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
POWER = 0xfffffe00099b8584
ACTIVE = 0xfffffe00099b786c
PRELOAD = 0xfffffe00099c36f0
DATA = 0x1000000
OBJECT = DATA+0x4000
VTABLE = DATA+0x8000
ARG = DATA+0xa000
RETURN = DATA+0xb000
GLOBALS = 0xfffffe00081e8000
SEPGLOBALS = 0xfffffe000c8f7000


class Startup:
    def __init__(self, image):
        if hashlib.sha256(image.data).hexdigest() != KERNEL_SHA:
            raise ValueError('startup replay requires the pinned J700 26A428 kernel')
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        base, size = POWER & ~0xffff, 0x15000
        code = image.data[image.va2off(base):image.va2off(base)+size]
        self.u.mem_map(base, size, UC_PROT_READ | UC_PROT_EXEC)
        self.u.mem_write(base, code)
        self.instructions = {i.address: i for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, base)}
        self.u.mem_map(DATA, 0x20000)
        self.u.mem_map(GLOBALS, 0x1000)
        self.u.mem_map(SEPGLOBALS, 0x1000)
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.stop = None
        self.events = []
        self.mode = None
        self.preload_inputs = {}

    def put(self, address, fmt, *values):
        self.u.mem_write(address, struct.pack(fmt, *values))

    def field(self, offset):
        return struct.unpack('<I', self.u.mem_read(DATA+offset, 4))[0]

    def finish(self, result):
        self.stop = result
        self.u.emu_stop()

    def call(self, pc, name, value=0):
        self.events.append(name)
        self.u.reg_write(reg.UC_ARM64_REG_X0, value)
        self.u.reg_write(reg.UC_ARM64_REG_PC, pc+4)

    def hook(self, u, pc, size, _):
        if pc == RETURN:
            self.finish('return')
            return
        ins = self.instructions.get(pc)
        if ins is None:
            raise AssertionError(f'unmodeled native exit {pc:x}')
        if ins.mnemonic in ('pacibsp', 'autibsp', 'autda', 'xpacd', 'pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC, pc+4)
            return
        if ins.mnemonic == 'retab':
            if self.mode == 'preload' and pc in (0xfffffe00099c3cb8, 0xfffffe00099c3d30):
                u.reg_write(reg.UC_ARM64_REG_PC, u.reg_read(reg.UC_ARM64_REG_X30))
            else:
                self.finish('return')
            return
        if self.mode == 'power':
            calls = {
                0xfffffe00099b85bc: ('root-domain', OBJECT),
                0xfffffe00099b85e8: ('absent-hibernate-property', 0),
                0xfffffe00099b85f8: ('cast-absent-property', 0),
                0xfffffe00099b8688: ('power-transition-log', 0),
                0xfffffe00099b8948: ('power-request', 0),
                0xfffffe00099b8988: ('provider-enable', 0),
            }
            if pc == 0xfffffe00099b8c88:
                assert u.reg_read(reg.UC_ARM64_REG_X0) == DATA
                assert u.reg_read(reg.UC_ARM64_REG_X1) == 1
                assert u.reg_read(reg.UC_ARM64_REG_X2) == 0
                self.finish('boot-required')
                return
            if pc == 0xfffffe00099b89d4:
                self.finish('no-firmware-boot')
                return
        elif self.mode == 'active':
            calls = {
                0xfffffe00099b78ec: ('unexpected-state-log', 0),
                0xfffffe00099b79d0: ('active-state-log', 0),
                0xfffffe00099b7a0c: ('cancel-startup-timer', 0),
                0xfffffe00099b7a44: ('set-booted-property', 0),
                0xfffffe00099b7aac: ('notify-active', 0),
                0xfffffe00099b7b94: ('get-workloop', OBJECT),
                0xfffffe00099b7bb8: ('get-command-gate', OBJECT),
                0xfffffe00099b7bf0: ('in-gate', 1),
                0xfffffe00099b7c1c: ('get-workloop', OBJECT),
            }
            if pc in (0xfffffe00099b7c7c, 0xfffffe00099b7c80, 0xfffffe00099b7c84):
                self.finish('refused-power-state')
                return
            if pc == 0xfffffe00099b7c74:
                assert u.reg_read(reg.UC_ARM64_REG_X1) == DATA+0xdc
                self.events.append('wake-state-waiters')
                self.finish('wake')
                return
        else:
            calls = {
                0xfffffe00099c3714: ('chosen-memory-map', self.preload_inputs['node']),
                0xfffffe00099c3c98: ('SEPFW-descriptor', self.preload_inputs['firmware']),
                0xfffffe00099c3ca4: ('SEPFW-mapping', self.preload_inputs['mapping']),
                0xfffffe00099c3cf0: ('SEPPatches-descriptor', self.preload_inputs['patches']),
                0xfffffe00099c3d04: ('uStuff-descriptor', self.preload_inputs['ustuff']),
                0xfffffe00099c3754: ('SEPFW-length', 0x5dc000),
            }
            refusals = {
                0xfffffe00099c3780: 'missing-memory-map',
                0xfffffe00099c3cbc: 'missing-memory-map',
                0xfffffe00099c3cc0: 'missing-SEPFW',
                0xfffffe00099c3cc4: 'unmapped-SEPFW',
                0xfffffe00099c3d34: 'missing-memory-map',
                0xfffffe00099c3d38: 'unpaired-patches',
            }
            if pc in refusals:
                self.finish(refusals[pc])
                return
            if pc == 0xfffffe00099c377c:
                self.finish('dma-preparation-required')
                return
            if pc in (0xfffffe00099c3724, 0xfffffe00099c372c):
                # Execute the nested native preload helpers.
                return
        if pc in calls:
            self.call(pc, *calls[pc])
        elif ins.mnemonic in ('bl', 'blr', 'blraa', 'braa', 'br', 'brk'):
            raise AssertionError(f'unmodeled call/refusal {pc:x}: {ins.mnemonic} {ins.op_str}')

    def run(self, mode, state=0, power=0, firmware=False, desired=2, preload=None):
        if mode not in ('power', 'active', 'preload'):
            raise ValueError('unknown replay mode')
        self.mode = mode
        self.stop, self.events = None, []
        self.u.mem_write(DATA, bytes(0x20000))
        self.u.mem_write(SEPGLOBALS, bytes(0x1000))
        for address in (DATA, OBJECT, OBJECT+0x1000, OBJECT+0x2000, OBJECT+0x3000):
            self.put(address, '<Q', VTABLE)
        self.put(DATA+0x88, '<Q', OBJECT)
        self.put(DATA+0xf8, '<Q', OBJECT)
        self.put(DATA+0xc8, '<I', power)
        self.put(DATA+0xdc, '<I', state)
        self.put(DATA+0xe0, '<Q', OBJECT if firmware else 0)
        self.put(ARG, '<Q', desired)
        self.put(GLOBALS+0x950, '<Q', ARG+0x100)
        self.put(GLOBALS+0xa00, '<Q', ARG+0x100)  # tracing disabled
        if mode == 'preload':
            self.preload_inputs = dict(zip(('node', 'firmware', 'mapping', 'patches', 'ustuff'),
                (OBJECT if flag else 0 for flag in preload)))
        for n in range(31):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), 0)
        self.u.reg_write(reg.UC_ARM64_REG_X0, DATA)
        self.u.reg_write(reg.UC_ARM64_REG_X1, ARG)
        self.u.reg_write(reg.UC_ARM64_REG_X30, RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP, DATA+0x1f000)
        self.u.emu_start(dict(power=POWER, active=ACTIVE, preload=PRELOAD)[mode], RETURN, count=10000)
        if self.stop is None:
            raise AssertionError('startup replay exhausted its instruction budget')
        return dict(stop=self.stop, state=self.field(0xdc), power=self.field(0xc8),
                    events=self.events.copy())


def main():
    image = runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    replay = Startup(image)
    cases = []
    # Cold power-up reaches state 2; only the non-null firmware branch invokes
    # _bootSEP. A desired power of 1 is included to distinguish power from state.
    for desired in (1, 2):
        for firmware in (False, True):
            out = replay.run('power', 0, 0, firmware=firmware, desired=desired)
            assert out['state'] == 2 and out['power'] == desired
            assert out['stop'] == ('boot-required' if firmware else 'no-firmware-boot')
            cases.append(dict(mode='cold-power', firmware=firmware, desired=desired, **out))
    for power in range(3):
        for state in range(12):
            out = replay.run('active', state, power)
            if (state == 5 and power != 2) or (state == 6 and power == 0) or (state == 7 and power != 2):
                assert out['stop'] == 'refused-power-state' and out['state'] == state
            elif state in (5, 6, 7, 9):
                assert out['stop'] == 'wake'
                assert out['state'] == (7 if state == 6 and power == 1 else 8)
                assert 'unexpected-state-log' not in out['events']
            elif state == 8:
                assert out['stop'] == 'return' and out['state'] == 8 and not out['events']
            else:
                assert out['stop'] == 'wake' and out['state'] == state
                assert 'unexpected-state-log' in out['events']
                assert 'notify-active' not in out['events']
            cases.append(dict(mode='os-active', initial_state=state, initial_power=power, **out))
    # Descriptor fixtures stand in for the IOKit property/mapping APIs only.
    # No payload is accepted, decrypted, authenticated, or DMA-mapped here.
    for mask in range(32):
        inputs = tuple(bool(mask & (1 << bit)) for bit in range(5))
        node, firmware, mapping, patches, ustuff = inputs
        expected = ('missing-memory-map' if not node else
                    'missing-SEPFW' if not firmware else
                    'unmapped-SEPFW' if not mapping else
                    'unpaired-patches' if patches != ustuff else
                    'dma-preparation-required')
        out = replay.run('preload', preload=inputs)
        assert out['stop'] == expected, (inputs, out)
        cases.append(dict(mode='preload', inputs=inputs, **out))
    print(json.dumps(dict(kernel_sha256=KERNEL_SHA, cases=len(cases), results=cases,
        boundary='original power/OS-active/preload branches with explicit IOKit fixtures and PAC omission; no firmware execution, DMA, IRQ, endpoint, or native continuation proof')))


if __name__ == '__main__':
    main()
