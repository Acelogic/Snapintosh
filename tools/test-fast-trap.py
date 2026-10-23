#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_FAST_VCPU_TRAPS: bind the lock-free classes to the actual locked chain.

tools/test-fast-trap.c runs compat/fast-trap.h against a transcription of
xnuboot_trap_locked's EC 0x18 chain. This test reads probes/xnuboot.c and
fails if that transcription no longer matches: a new switch case, a new
`reg ==` handler, or a reordered handler chain means the fast classes must be
re-derived before the fast path may stay enabled. It also builds and runs the
C test (sanitized, thread-sanitized) and checks that the pre-change trap
entry model fails the lock regression.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HEADER = (ROOT / 'compat/fast-trap.h').read_text()
ORACLE = (ROOT / 'tools/test-fast-trap.c').read_text()


def sysreg(op0, op1, crn, crm, op2):
    return (op0 << 20) | (op2 << 17) | (op1 << 14) | (crn << 10) | (crm << 1)


def chain():
    start = SOURCE.index('static int xnuboot_trap_locked(')
    body = SOURCE[start:SOURCE.index('\nint xnuboot_trap(', start)]
    traps = body.index('c->traps++;')
    switch = body.index('switch (reg) {', traps)
    end = body.index('default:', switch)
    return body, traps, switch, end


class FastTrapSource(unittest.TestCase):
    def test_switch_cases_match_the_oracle(self):
        body, traps, switch, end = chain()
        cases = re.findall(r'case (SR_\w+):', body[switch:end])
        defined = {name: sysreg(*map(int, args)) for name, *args in re.findall(
            r'#define (SR_\w+)\s+SYSREG\((\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)', SOURCE)}
        oracle = {name: sysreg(*map(int, args)) for name, *args in re.findall(
            r'#define (SR_\w+) SR\((\d+),(\d+),(\d+),(\d+),(\d+)\)', ORACLE)}
        self.assertEqual(sorted(cases), sorted(oracle))
        for name in cases:
            self.assertEqual(defined[name], oracle[name], name)
        # ESR/FAR reads are hardware register reads in the locked path.
        for name, reg in (('SR_ESR_EL1', 'esr_el1'), ('SR_FAR_EL1', 'far_el1')):
            case = body[body.index(f'case {name}:', switch):]
            case = case[:case.index('break;')]
            self.assertIn(f'mrs %0, {reg}', case)

    def test_handler_chain_order(self):
        body, traps, switch, end = chain()
        region = body[traps:switch]
        order = ['id_forge(', 'pauth_user_reg(', 'guest_ipi_route(', 'guest_timer_idle_access(',
                 'CLOCK_TIMER_UNSUPPORTED', 'arch_counter_reads', 'guest_timer_access(',
                 'guest_clock_access(', 'sprr_access_with(']
        positions = [region.index(token) for token in order]
        self.assertEqual(positions, sorted(positions))
        # Every register the chain claims before the switch is a known one.
        claimed = set(re.findall(r'reg\s*==\s*(\w+)', region))
        self.assertEqual(claimed, {'IPI_RR_LOCAL', 'IPI_RR_GLOBAL', 'IPI_SR', 'CLOCK_ARCH_CNTP_CTL',
                                   'CLOCK_ARCH_CNTVCT', 'CLOCK_ARCH_CNTVCTSS', 'CLOCK_CNTV_CTL',
                                   'CLOCK_CNTV_TVAL', 'SPRR_UPERM'})
        # PACGA: the locked EC 0x09 branch precedes the EC 0x18 chain and has
        # exactly the operations fast_trap_emulate performs.
        pacga = body[body.index('if (ec == 0x09 && generic_pauth_supported())'):traps]
        for token in ('guest_pa(*elr)', 'pa >= p->mem_low && pa <= p->mem_high - 4',
                      'sp_el1', 'sp_el0', 'pauth_pacga(word, frame, sp, generic_sign, c)',
                      'pacga_calls++', '*elr += 4'):
            self.assertIn(token, pacga)

    def test_ignored_registers_are_unclaimed(self):
        block = HEADER[HEADER.index('fast_trap_ignored[FAST_TRAP_IGNORED] = {'):]
        block = block[:block.index('};')]
        ignored = [sysreg(*map(int, args)) for args in
                   re.findall(r'FAST_TRAP_SYSREG\((\d+),(\d+),(\d+),(\d+),(\d+)\)', block)]
        self.assertEqual(len(ignored), 20)
        claimed = set()
        for header in ('compat/clock.h', 'compat/ipi.h', 'compat/sprr.h'):
            text = (ROOT / header).read_text()
            for args in re.findall(r'_SYSREG\((\d+),(\d+),(\d+),(\d+),(\d+)\)', text):
                claimed.add(sysreg(*map(int, args)))
        sprr = (ROOT / 'compat/sprr.h').read_text()
        for op2, crm in re.findall(r'SPRR_ISS\((\d+)u,(\d+)u\)', sprr):
            claimed.add(sysreg(3, 6, 15, int(crm), int(op2)))
        claimed |= {sysreg(*map(int, args)) for _, *args in re.findall(
            r'#define (SR_\w+)\s+SYSREG\((\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)', SOURCE)}
        for reg in ignored:
            self.assertNotIn(reg, claimed, hex(reg))
            # Not in the TID3 ID group (Op1=0, CRn=0, CRm<8), which answers first.
            self.assertFalse(((reg >> 14) & 7) == 0 and ((reg >> 10) & 15) == 0 and
                             ((reg >> 1) & 15) < 8, hex(reg))

    def test_zero_class_cases_are_constant_zero(self):
        # docs/FAST-TRAP-BATCH-20261016.md failure mode 2: a register is answered
        # zero without the lock only where xnuboot_trap_locked's switch case is
        # exactly "reads zero" with no record or other effect.
        block = HEADER[HEADER.index('static inline int fast_trap_zero_reg('):]
        block = block[:block.index('\n}')]
        regs = [sysreg(*map(int, a)) for a in
                re.findall(r'FAST_TRAP_SYSREG\((\d+),(\d+),(\d+),(\d+),(\d+)\)', block)]
        self.assertEqual(len(regs), 1)
        names = {sysreg(*map(int, a)): n for n, *a in re.findall(
            r'#define (SR_\w+)\s+SYSREG\((\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)', SOURCE)}
        body, traps, switch, end = chain()
        for reg in regs:
            case = body[body.index(f'case {names[reg]}:', switch):]
            case = case[len(f'case {names[reg]}:'):case.index('break;')]
            case = re.sub(r'/\*.*?\*/', '', case, flags=re.S)
            self.assertEqual(' '.join(case.split()), 'if (is_read) value = 0;', names[reg])

    def test_native_behaviour(self):
        flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Icompat', '-Ishadow']
        sources = ['tools/test-fast-trap.c', 'compat/pauth.c', 'compat/pauth-user.c',
                   'compat/clock.c', 'compat/service-lock.c']
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            builds = {'asan': ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'],
                      'tsan': ['-fsanitize=thread', '-pthread', '-DFAST_TRAP_THREADS=1'],
                      'pre': ['-fsanitize=address,undefined', '-DFAST_TRAP_PRE_CHANGE=1']}
            for name, extra in builds.items():
                subprocess.run(['cc', *flags, *extra, *sources, '-o', str(d / name)],
                               cwd=ROOT, check=True, timeout=120)
            env = dict(os.environ, TSAN_OPTIONS='halt_on_error=1:exitcode=66')
            for name in ('asan', 'tsan'):
                result = subprocess.run([str(d / name)], capture_output=True, text=True,
                                        timeout=600, env=env)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                self.assertIn('PASS:', result.stdout)
            pre = subprocess.run([str(d / 'pre')], capture_output=True, text=True, timeout=600)
            self.assertNotEqual(pre.returncode, 0)
            self.assertIn('e.acquisitions<=5', pre.stderr)


if __name__ == '__main__':
    unittest.main()
