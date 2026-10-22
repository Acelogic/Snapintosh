#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the MAIR_EL1 the loader publishes to the one SPTM leaves XNU with.

sptm.t8140.release has exactly two `msr MAIR_EL1` instructions (the kernel
cache has none: XNU inherits SPTM's table and indexes it from its PTEs).

  +0xa01ec  ...270a41ec  0x00000000010000ff  inside the physically entered
            stub at ...270a4000, whose PA SPTM stores at ...2709c520
            (...270bee94) and copies into the exclave kernel's boot record
            beside 'CL4-entry' (...270e76a0). It runs one call with that
            table, turns the MMU off and ends in `b ...270af400`.
  +0xab5c8  ...270af5c8  0x0c0d00ff01a040ff  in the common start
            ...270af51c that the cold boot (...270af3e0) and the warm/
            secondary entries (...270af400/...408, via ...270af504/50c)
            all reach, straight-line, before the MMU is enabled and SPTM's
            C continuation runs. Nothing writes MAIR after it.

So the second value is live whenever XNU runs, on every CPU. It is XNU's own
CACHE_ATTRINDX table in FEAT_XS encodings: 0 WRITEBACK ff, 1 WRITECOMB 40
(Normal NC), 2 WRITETHRU a0, 3 DISABLE 01, 4 INNERWRITEBACK ff, 5 POSTED 00,
6 POSTED_REORDERED 0d, 7 POSTED_COMBINED_REORDERED 0c (Device-GRE). The first
one made indices 1, 2, 4, 6 and 7 Device-nGnRnE. The Snapdragon implements
FEAT_XS (ID_AA64ISAR1_EL1.XS = 1: ../Snapintosh/build/
pauth-state-live-20260922-pauth-config.json, isar1 0x0110111100311002).

Every value here is decoded from the pinned image (sha256 below); nothing is
emulated and the host needs no disassembler.
"""
import hashlib
import runpy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
SPTM = ROOT / 'downloads/extracted/j700ap/sptm.t8140.release'
SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'

STUB, STUB_TAIL = 0xfffffff0270a4000, 0xfffffff0270a42c4
STUB_WRITE, LIVE_WRITE = 0xfffffff0270a41ec, 0xfffffff0270af5c8
WARM_ENTRY, SECONDARY_ENTRY = 0xfffffff0270af400, 0xfffffff0270af408
COLD_BRANCH, COMMON_START = 0xfffffff0270af3e0, 0xfffffff0270af51c
STUB_VALUE, LIVE_VALUE = 0x00000000010000ff, 0x0c0d00ff01a040ff
MSR_MAIR_EL1 = 0xd518a200
WFE = 0xd503205f


def sign(value, bits):
    return value - ((value >> (bits - 1)) << bits)


def branch_target(address, word):
    """Direct branch target, or None. (kind, target)."""
    if word >> 26 in (0b000101, 0b100101):
        return ('bl' if word >> 31 else 'b'), address + 4 * sign(word & 0x3ffffff, 26)
    if word & 0xff000010 == 0x54000000:
        return 'b.cond', address + 4 * sign((word >> 5) & 0x7ffff, 19)
    if word & 0x7e000000 == 0x34000000:
        return 'cb', address + 4 * sign((word >> 5) & 0x7ffff, 19)
    if word & 0x7e000000 == 0x36000000:
        return 'tb', address + 4 * sign((word >> 5) & 0x3fff, 14)
    return None


def branch_register(word):
    """Opcode of an unconditional branch (register), any PAC form, or None:
    0 BR, 1 BLR (a call), 2 RET, 4 ERET."""
    return (word >> 21) & 0xf if word & 0xfe000000 == 0xd6000000 else None


def indirect(word):
    """br/ret/eret: control leaves the listing (blr is a call that returns)."""
    return branch_register(word) in (0, 2, 4)


def constant(read, start, end, register):
    """Value of `register` at `end`, from the straight-line words [start, end).

    Accepts MOVZ/MOVN/MOVK (64-bit) and ORR (shifted register, 64-bit, LSL).
    System instructions with L=0 (MSR, SYS/TLBI, barriers, hints) write no
    general register. Anything else forgets every register. A halfword never
    written in the listing is an unobserved input and refuses the result."""
    value, known = [0] * 32, [0] * 32
    value[31], known[31] = 0, (1 << 64) - 1          # XZR as ORR operand
    full = (1 << 64) - 1
    for address in range(start, end, 4):
        w = read(address)
        rd = w & 31
        if w & 0xff800000 in (0xd2800000, 0x92800000, 0xf2800000):
            shift = 16 * ((w >> 21) & 3)
            imm = ((w >> 5) & 0xffff) << shift
            if w & 0xff800000 == 0xd2800000:
                value[rd], known[rd] = imm, full
            elif w & 0xff800000 == 0x92800000:
                value[rd], known[rd] = ~imm & full, full
            else:
                value[rd] = (value[rd] & ~(0xffff << shift) & full) | imm
                known[rd] |= 0xffff << shift
        elif w & 0xffe00000 == 0xaa000000:            # ORR Xd, Xn, Xm, LSL #amount
            rn, rm, amount = (w >> 5) & 31, (w >> 16) & 31, (w >> 10) & 63
            if known[rn] != full or known[rm] != full:
                raise ValueError(f'{address:#x}: unobserved incoming operand')
            value[rd], known[rd] = (value[rn] | (value[rm] << amount)) & full, full
        elif w & 0xffe00000 == 0xd5000000:            # system, L=0
            continue
        else:
            value, known = [0] * 32, [0] * 32
            value[31], known[31] = 0, full
        if rd == 31:
            value[31], known[31] = 0, full
    if known[register] != full:
        raise ValueError(f'{end:#x}: unobserved incoming halfword in x{register}')
    return value[register]


class Image:
    def __init__(self):
        im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](SPTM)
        if hashlib.sha256(im.data).hexdigest() != SPTM_SHA:
            raise ValueError('SPTM differs from the selected 26A428 image')
        self.im = im
        name, self.base, _, self.off, self.size = next(s for s in im.segs
                                                      if s[0] == '__TEXT_EXEC')

    def word(self, va):
        o = self.im.locate(va)[1]
        return int.from_bytes(self.im.data[o:o + 4], 'little')

    def text(self):
        for n in range(0, self.size, 4):
            va = self.base + n
            yield va, int.from_bytes(self.im.data[self.off + n:self.off + n + 4], 'little')

    def region(self, end, targets):
        """Start of the straight-line block ending at `end`: after the last
        branch or call, or at the last instruction a branch can land on."""
        at = end
        while at > self.base:
            w = self.word(at - 4)
            if branch_target(at - 4, w) or branch_register(w) is not None:
                return at
            if at in targets:
                return at
            at -= 4
        return at


class MairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sptm = Image()
        cls.targets = {}
        cls.writes = []
        for va, word in cls.sptm.text():
            b = branch_target(va, word)
            if b:
                cls.targets.setdefault(b[1], []).append((va, b[0]))
            if word & ~31 == MSR_MAIR_EL1:
                cls.writes.append((va, word & 31))

    def value(self, va, register):
        start = self.sptm.region(va, self.targets)
        return constant(self.sptm.word, start, va, register)

    def test_exactly_two_writes_and_their_values(self):
        self.assertEqual([va for va, _ in self.writes], [STUB_WRITE, LIVE_WRITE])
        self.assertEqual(self.value(STUB_WRITE, dict(self.writes)[STUB_WRITE]), STUB_VALUE)
        self.assertEqual(self.value(LIVE_WRITE, dict(self.writes)[LIVE_WRITE]), LIVE_VALUE)

    def test_stub_value_is_transient(self):
        # The stub runs with the first table only until its tail branch into
        # the warm entry; nothing after STUB_WRITE leaves the stub another way
        # (its blr/bl are calls into SPTM C code that return).
        self.assertEqual(branch_target(STUB_TAIL, self.sptm.word(STUB_TAIL)), ('b', WARM_ENTRY))
        calls = []
        for va in range(STUB_WRITE, STUB_TAIL, 4):
            w = self.sptm.word(va)
            b = branch_target(va, w)
            self.assertFalse(indirect(w), f'{va:#x}')
            if b and b[0] != 'bl':
                self.assertTrue(STUB_WRITE <= b[1] < STUB_TAIL, f'{va:#x} leaves the stub')
            if (b and b[0] == 'bl') or branch_register(w) == 1:
                calls.append(va)
        self.assertEqual(calls, [0xfffffff0270a4270, 0xfffffff0270a42bc])
        # The stub is exported only as a physical entry for the exclave kernel.
        self.assertNotIn(STUB, self.targets)

    def test_every_entry_reaches_common_start_before_the_live_write(self):
        # Cold boot and both warm entries converge; common start is straight
        # line to the live write (no branch, and no join point inside).
        self.assertEqual(branch_target(COLD_BRANCH, self.sptm.word(COLD_BRANCH)),
                         ('b', COMMON_START))
        self.assertEqual(sorted(va for va, _ in self.targets[COMMON_START]),
                         [COLD_BRANCH, 0xfffffff0270af504, 0xfffffff0270af50c])
        self.assertEqual(self.sptm.region(LIVE_WRITE, self.targets), COMMON_START)
        # Every path from the warm and secondary entries ends at common start or
        # parks the CPU in its own WFE loop; none leaves or writes MAIR.
        for entry in (WARM_ENTRY, SECONDARY_ENTRY):
            seen, work, ends = set(), [entry], set()
            while work:
                va = work.pop()
                if va in seen:
                    continue
                seen.add(va)
                if va == COMMON_START:
                    ends.add('common')
                    continue
                w = self.sptm.word(va)
                self.assertFalse(indirect(w) or w & ~31 == MSR_MAIR_EL1, f'{va:#x}')
                if w == WFE:
                    ends.add('park')
                b = branch_target(va, w)
                if b:
                    self.assertNotEqual(b[0], 'bl', f'{va:#x}')
                    work.append(b[1])
                    if b[0] == 'b':
                        continue
                work.append(va + 4)
            self.assertEqual(ends, {'common', 'park'}, f'{entry:#x}')

    def test_profile_publishes_the_live_value(self):
        profile = runpy.run_path(str(ROOT / 'probes/guestprofile.py'))['J700_26A428']
        self.assertEqual(profile.mair, LIVE_VALUE)
        live = [(LIVE_VALUE >> 8 * i) & 0xff for i in range(8)]
        stub = [(STUB_VALUE >> 8 * i) & 0xff for i in range(8)]
        # XNU's CACHE_ATTRINDX order, FEAT_XS XS=0 forms where the byte ends 0x?1/0x?0.
        self.assertEqual(live, [0xff, 0x40, 0xa0, 0x01, 0xff, 0x00, 0x0d, 0x0c])
        self.assertEqual([i for i in range(8) if live[i] != stub[i]], [1, 2, 4, 6, 7])
        # Index 0, the only one a loader PTE uses (tools/test-profile.py walks
        # them), and the device indices 3 and 5 keep their meaning.
        self.assertEqual([live[i] for i in (0, 3, 5)], [stub[i] for i in (0, 3, 5)])

    def test_decoder_refuses_what_it_cannot_see(self):
        words = {0: 0xf2800028, 4: MSR_MAIR_EL1 | 8}          # movk x8,#1 only
        with self.assertRaisesRegex(ValueError, 'unobserved'):
            constant(words.__getitem__, 0, 4, 8)
        words = {0: 0xaa010000}                               # orr x0,x0,x1 unknown
        with self.assertRaisesRegex(ValueError, 'unobserved'):
            constant(words.__getitem__, 0, 4, 0)
        words = {0: 0xd2800020, 4: 0x8b000000, 8: 0xd503201f}  # movz; add forgets; nop
        with self.assertRaisesRegex(ValueError, 'unobserved'):
            constant(words.__getitem__, 0, 12, 1)
        # Clearing any set immediate bit of the live sequence, or moving any
        # immediate to another halfword, changes the decoded constant: every
        # byte of the pin comes from these words.
        start = self.sptm.region(LIVE_WRITE, self.targets)
        base = {va: self.sptm.word(va) for va in range(start, LIVE_WRITE, 4)}
        mutated = 0
        for va, w in base.items():
            if w & 0xff800000 != 0xd2800000 or w & 31 != 1 or not (w >> 5) & 0xffff:
                continue
            for bit in [b for b in range(5, 21) if w >> b & 1] + [21, 22]:
                bad = dict(base)
                bad[va] = w & ~(1 << bit) if bit < 21 else w ^ (1 << bit)
                self.assertNotEqual(constant(bad.__getitem__, start, LIVE_WRITE, 0), LIVE_VALUE,
                                    f'{va:#x} bit {bit}')
                mutated += 1
        self.assertGreater(mutated, 20)


if __name__ == '__main__':
    unittest.main()
