#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay original SEP ROM boot/request and reply-parser instructions offline.

Uses the pinned kernel and explicit IOKit, KCV, work-loop and wait fixtures.
Replies are injected at the wait boundary through the original _bootAction.
No firmware authentication, payload execution, DMA or native IRQ is modeled.
"""
from pathlib import Path
import json
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
s = runpy.run_path(str(Path(__file__).with_name('replay-sep-startup.py')))
reg = s['reg']
DATA, OBJECT, VTABLE, ARG, RETURN = (s[n] for n in
                                     ('DATA', 'OBJECT', 'VTABLE', 'ARG', 'RETURN'))
BOOT = 0xfffffe00099bfdb4
REPLY = 0xfffffe00099bf188
SHARED = DATA + 0x6000


class ROM(s['Startup']):
    def init(self, mode):
        self.mode = mode
        self.stop = None
        self.events = []
        self.u.mem_write(DATA, bytes(0x20000))
        for obj in (DATA, OBJECT, SHARED):
            self.put(obj, '<Q', VTABLE)
        for n in range(31):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), 0)
        self.u.reg_write(reg.UC_ARM64_REG_SP, DATA+0x1f000)
        self.u.reg_write(reg.UC_ARM64_REG_X30, RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_X0, DATA)

    def x(self, n):
        return self.u.reg_read(getattr(reg, f'UC_ARM64_REG_X{n}'))

    def execute(self, address):
        self.u.emu_start(address, RETURN, count=10000)
        if self.stop is None:
            raise AssertionError('native replay did not reach a modeled boundary')

    def reply(self, opcode, value=0, endpoint=0xff, phase=0, waiting=True, tag=0):
        self.init('reply')
        word = endpoint | (tag << 8) | (opcode << 16) | (value << 32)
        self.put(ARG, '<Q', word)
        self.put(DATA+0xa9, '<B', int(waiting))
        self.put(DATA+0xb2, '<H', phase)
        self.u.reg_write(reg.UC_ARM64_REG_X2, ARG)
        self.execute(REPLY)
        return dict(stop=self.stop, phase=struct.unpack('<H', self.u.mem_read(DATA+0xb2, 2))[0],
                    waiting=bool(self.u.mem_read(DATA+0xa9, 1)[0]),
                    last=struct.unpack('<Q', self.u.mem_read(DATA+0xaa, 8))[0])

    def boot(self, replies, *, firmware=0x180000000, shared_size=0x20000,
             shared_address=0x190000000, tbm=False, patches=0x1a0000000,
             ustuff=0x1b0000000, fail_wait=None, slot_selection=False, selected_slot=2):
        self.init('boot')
        self.answers = iter(replies)
        self.firmware, self.shared_address = firmware, shared_address
        self.tbm, self.patches, self.ustuff = tbm, patches, ustuff
        assert 0 <= selected_slot < 16
        self.slot_selection, self.selected_slot = slot_selection, selected_slot
        self.wait_count, self.fail_wait = 0, fail_wait
        self.messages = []
        self.put(DATA+0x70, '<Q', OBJECT)
        self.put(DATA+0x1c8, '<I', 14)
        self.put(SHARED+0x40, '<Q', shared_size)
        # Suppress the optional monitor notification after ROM boot submission.
        self.put(s['GLOBALS']+0xa00, '<Q', ARG+0x100)
        self.put(ARG+0x100, '<I', 0)
        self.u.reg_write(reg.UC_ARM64_REG_X1, OBJECT)
        self.u.reg_write(reg.UC_ARM64_REG_X3, SHARED)
        self.execute(BOOT)
        return dict(stop=self.stop, return_value=self.x(0), messages=self.messages,
                    waits=self.wait_count, phase=struct.unpack('<H', self.u.mem_read(DATA+0xb2, 2))[0])

    def hook(self, u, pc, size, unused):
        ins = self.instructions.get(pc)
        if ins is None:
            raise AssertionError(f'unmodeled instruction {pc:x}')
        if ins.mnemonic in ('pacibsp', 'autibsp', 'autda', 'xpacd', 'pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC, pc+4)
            return
        if ins.mnemonic == 'retab':
            self.finish('return')
            return
        if self.mode == 'reply':
            if pc == 0xfffffe00099bf484:
                # All reply state writes precede the work-loop wakeup tail.
                self.finish('wake')
                return
            failures = {0xfffffe00099bf550: 'wrong-endpoint',
                        0xfffffe00099bf554: 'terminal-phase',
                        0xfffffe00099bf574: 'bad-version',
                        0xfffffe00099bf578: 'diagnostic-overflow'}
            if pc in failures:
                self.finish(failures[pc])
                return
            if ins.mnemonic == 'bl' and ins.op_str == '#0xfffffe00099ddbac':
                self.call(pc, 'log')
                return
        elif self.mode == 'boot':
            failures = {0xfffffe00099c0440: 'status-timeout',
                        0xfffffe00099c0460: 'expected-phase-1',
                        0xfffffe00099c0468: 'boot-tz0-timeout',
                        0xfffffe00099c0488: 'second-status-timeout',
                        0xfffffe00099c04a8: 'expected-phase-2',
                        0xfffffe00099c04bc: 'unaligned-firmware',
                        0xfffffe00099c043c: 'shared-size-overflow',
                        0xfffffe00099c03f8: 'boot-timeout',
                        0xfffffe00099c04c8: 'unaligned-ustuff',
                        0xfffffe00099c04ec: 'unaligned-patches',
                        0xfffffe00099c04cc: 'ustuff-timeout',
                        0xfffffe00099c04f0: 'patches-timeout'}
            if pc in failures:
                self.finish(failures[pc])
                return
            fixtures = {
                0xfffffe00099bfe18: ('work-loop', OBJECT),
                0xfffffe00099bfe44: ('command-gate', OBJECT),
                0xfffffe00099bfe6c: ('work-loop', OBJECT),
                0xfffffe00099bfea4: ('in-gate', 1),
                0xfffffe00099bff60: ('boot-timeout', 50000),
                0xfffffe00099bff84: ('firmware-type', 0),
                0xfffffe00099bff94: ('slot-selection-capability', int(self.slot_selection)),
                0xfffffe00099c0000: ('KCV-capture-omitted', 0),
                0xfffffe00099c0008: ('TBM-v2', int(self.tbm)),
                0xfffffe00099c0014: ('ustuff-address', self.ustuff),
                0xfffffe00099c0084: ('patches-address', self.patches),
                0xfffffe00099c0154: ('firmware-type', 0),
                0xfffffe00099c0208: ('firmware-address', self.firmware),
                0xfffffe00099c02f4: ('shared-address', self.shared_address),
                0xfffffe00099c0384: ('shared-address', self.shared_address),
                0xfffffe00099c0280: ('log', 0),
                0xfffffe00099c039c: ('log', 0),
            }
            if pc in fixtures:
                self.call(pc, *fixtures[pc])
                return
            if pc == 0xfffffe00099bffb4:
                # Fixture for the selected-slot query; the original subsequent
                # packing instructions still construct the complete ROM word.
                self.u.mem_write(self.x(1), bytes([self.selected_slot]))
                self.call(pc, 'selected-slot-query', 1)
                return
            if pc in (0xfffffe00099c006c, 0xfffffe00099c00e0,
                      0xfffffe00099c0128, 0xfffffe00099c019c,
                      0xfffffe00099c01e0, 0xfffffe00099c026c,
                      0xfffffe00099c0348):
                shared = pc == 0xfffffe00099c0348
                address = self.x(2 if shared else 1)
                word = struct.unpack('<Q', u.mem_read(address, 8))[0]
                self.messages.append(dict(endpoint=self.x(1) if shared else word & 0xff,
                                          word=f'{word:016x}'))
                self.call(pc, 'send-fixture')
                return
            if ins.mnemonic == 'bl' and ins.op_str == '#0xfffffe00099bf84c':
                self.wait_count += 1
                if self.wait_count == self.fail_wait:
                    self.call(pc, 'timeout-fixture', 0xe00002d6)
                    return
                opcode, value = next(self.answers)
                phase = struct.unpack('<H', u.mem_read(DATA+0xb2, 2))[0]
                out = self.receiver.reply(opcode, value, phase=phase)
                assert out['stop'] == 'wake' and not out['waiting'], out
                u.mem_write(DATA+0xa9, bytes(self.receiver.u.mem_read(DATA+0xa9, 11)))
                self.call(pc, 'native-reply-at-wait-fixture')
                return
        if ins.mnemonic in ('bl', 'blr', 'blraa', 'braa', 'brk'):
            raise AssertionError(f'unmodeled call {pc:x}: {ins.mnemonic} {ins.op_str}')


def main():
    image = runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    reply = ROM(image)
    checks = 0
    # Exercise all opcodes with a bounded diagnostic byte count and ROM version.
    phases = {0x66: 30, 0x69: 100, 0x6a: 101, 0x6b: 200,
              0x6c: 3, 0xd2: 30, 0xff: 202}
    clears = {0, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
              0x6c, 0x82, 0x83, 0x88, 0x89, 0xc7}
    saves = {0, 0x67, 0x68, 0x82, 0x83, 0xc7}
    for opcode in range(256):
        out = reply.reply(opcode, 30, phase=7)
        assert out['stop'] == 'wake', (opcode, out)
        assert out['phase'] == phases.get(opcode, 7), (opcode, out)
        assert out['waiting'] == (opcode not in clears), (opcode, out)
        assert out['last'] == ((30 << 32) | (opcode << 16) | 0xff if opcode in saves else 0), (opcode, out)
        checks += 1
    for args, expected in [({'opcode': 0x66, 'endpoint': 0}, 'wrong-endpoint'),
                           ({'opcode': 0x66, 'phase': 202}, 'terminal-phase'),
                           ({'opcode': 0, 'value': 29}, 'bad-version'),
                           ({'opcode': 0xc7, 'value': 31}, 'bad-version')]:
        assert reply.reply(**args)['stop'] == expected
        checks += 1
    boot = ROM(image)
    boot.receiver = reply
    answers = [(0x66, 1), (0x69, 0), (0x66, 2), (0x6a, 0)]
    traces = []
    for tbm in (False, True):
        responses = ([(0x88, 0), (0x89, 0)] if tbm else []) + answers
        out = boot.boot(responses, tbm=tbm)
        assert out['stop'] == 'return' and out['return_value'] == 0 and out['phase'] == 101, out
        expected = ([0x24, 0x25] if tbm else []) + [2, 5, 2, 6]
        assert [int(m['word'], 16) >> 16 & 255 for m in out['messages'][:-1]] == expected, out
        assert out['messages'][-1] == {'endpoint': 254, 'word': '0019000000200000'}, out
        assert out['messages'][-2]['word'] == '0018000000060100', out
        if tbm:
            assert [m['word'] for m in out['messages'][:2]] == [
                '0006c00000240100', '0006800000250100'], out
        traces.append(dict(tbm=tbm, **out))
        checks += 1
    for slot in range(16):
        out = boot.boot(answers, slot_selection=True, selected_slot=slot,
                        firmware=0x10000004000)
        assert out['stop']=='return' and out['return_value']==0 and out['phase']==101
        assert int(out['messages'][-2]['word'],16)==0x1000000400060100|(slot<<28)
        if slot==2:traces.append(dict(selected_slot=slot, **out))
        checks += 1
    for wait, expected in enumerate(['status-timeout', 'boot-tz0-timeout', 'second-status-timeout', 'boot-timeout'], 1):
        assert boot.boot(answers, fail_wait=wait)['stop'] == expected
        checks += 1
    for responses, options, expected in [
        ([(0x66, 0)], {}, 'expected-phase-1'),
        ([(0x66, 1), (0x69, 0), (0x66, 1)], {}, 'expected-phase-2'),
        (answers, {'firmware': 0x180000001}, 'unaligned-firmware'),
        (answers, {'shared_size': 0x10000000}, 'shared-size-overflow'),
        ([], {'tbm': True, 'ustuff': 0x1b0000001}, 'unaligned-ustuff'),
        ([(0x88, 0)], {'tbm': True, 'patches': 0x1a0000001}, 'unaligned-patches'),
        ([], {'tbm': True, 'fail_wait': 1}, 'ustuff-timeout'),
        ([(0x88, 0)], {'tbm': True, 'fail_wait': 2}, 'patches-timeout'),
    ]:
        out = boot.boot(responses, **options)
        assert out['stop'] == expected, (expected, out)
        checks += 1
    print(json.dumps(dict(kernel_sha256=s['KERNEL_SHA'], checks=checks, traces=traces,
                         boundary='native ROM request and reply branches with IOKit, KCV, work-loop and synchronous wait fixtures; no authentication, firmware execution, DMA, IRQ or native boot proof'), indent=2))


if __name__ == '__main__':
    main()
