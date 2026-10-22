#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SCMI performance-domain values transcribed from Linux arch/arm64/boot/dts/qcom/glymur.dtsi:
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries. BSD-3-Clause
# (LICENSES/BSD-3-Clause.txt, THIRD_PARTY_NOTICES.md).
"""Ask the X2E's power firmware for full CPU performance over SCMI, from an idle q1n1.

Mechanism (X2 Elite "Glymur", the A16's SoC). The OS requests CPU performance
with SCMI Performance (protocol 0x13) messages to the PDP power firmware over
the qcom-cpucp mailbox "pdp0"; there is no OS-visible EPSS/cpufreq-hw block.
  * Linux glymur.dtsi (Qualcomm-authored): firmware/scmi { mboxes = <&pdp0_mbox 0>,
    <&pdp0_mbox 1>; shmem = <&cpu_scp_lpri1>, <&cpu_scp_lpri0>; protocol@13 },
    every CPU node power-domains = <&cpu_pdN>, <&scmi_perf D>: D=0 for
    0x0-0x500, 1 for 0x10000-0x10500, 2 for 0x20000-0x20500. No cpufreq-hw node.
    pdp0_mbox@17610000, compatible qcom,glymur-cpucp-mbox: reg 0x17610000 (rx),
    0x19980000 (tx), GIC SPI 34. imem@81e08600: lpri0 +0 and lpri1 +0x180, 0x180
    bytes each. With two mailboxes and two shmems the SCMI mailbox transport
    uses channel 0 both ways for commands (a2p, shmem[0] = lpri1 = 0x81e08780)
    and channel 1 for notifications (p2a, lpri0 = 0x81e08600).
  * drivers/mailbox/qcom-cpucp-mbox.c: doorbell = 32-bit write at
    tx + 0x100 + 8*ch + 4; rx MAP 0x4000, STAT 0x4400, CLEAR 0x4800, EN 0x4c00
    (64-bit); the interrupt handler writes BIT(ch) to CLEAR.
  * This A16's Windows PEP (evidence/drivers/qcpep.wd8480.../qcpep8480.sys) holds
    the same mailbox: "pdp0" tx 0x19980000, rx 0x17610000, rx/tx command offsets
    0x100, MAP/STAT/CLEAR/EN 0x4000/0x4400/0x4800/0x4c00, interrupt 66 (SPI 34),
    channel table 'scmi_apss_agent' tx 0, 'scmi_apss_plat' rx 0 (plus
    dpm_crazy_mode tx 1, debug_log, pcc_core0-5 tx 3-8, ncc_limits); strings
    "scmi_apss_agent", "SCMI error", "Perf Lvl set: ...". The DSDT has no
    _CPC/_PSS: Windows goes through the PEP, which uses this channel. The same
    table also lists "cpucp" (tx 0x18830000, rx 0x17620000, interrupt 60,
    'scmi_apss_agent' tx 0, 'scmi_apss_plat' rx 2) next to SRAM 0x18b4e000+0x400:
    the X1E80100 layout (hamoa.dtsi: cpucp_mbox tx 0x18830000, shmem
    0x18b4e000/+0x200). That is --channel cpucp, opt-in, for when the survey
    shows pdp0 unused and CPUCP in use.
  * The shared-memory addresses are the values not found in a captured A16
    table, which is why `survey` reads them passively before anything is sent.

Modes, each writing a new JSON record and refusing to overwrite one:
  survey   read-only, both transports: EL2 page-table attributes of every
           address used, UEFI memory types of the shared memory, both SCMI
           shmem headers, mailbox rx MAP/STAT/EN and the mailbox interrupt's
           GIC enable/pending. No doorbell.
  query    SCMI BASE and PERF read commands over --channel: vendor, protocols,
           domains (names, flags, levels, limits, current level). Needs a
           survey of this generation that found that channel usable.
  set-max  PERF_LEVEL_SET to the highest level the current limits allow, for
           --domains (default 0,1: what the guest uses), then PERF_LEVEL_GET.
           Needs a query of this generation. Records the previous levels.
  restore  PERF_LEVEL_SET back to the levels a set-max record found, except a
           level that was never set by this agent (LEVEL_GET 0 with limits 0/0:
           writing it back would request index 0, 355 MHz); the rollback for
           those is a cold boot.
  fc-read  read-only: the current value of every described fastchannel
           (LEVEL_GET, LIMITS_GET) from a query record of this q1n1 boot. No
           doorbell; usable after a guest run.
  prime-hold  the Prime-level experiment: keep one Prime CPU (--cpu, default
           0x10000) busy in the stub's hold mode, then PERF_LEVEL_SET by message
           while its cluster is active; only if that does not raise the clock
           (or --always-fc), write the domain's LEVEL_SET fastchannel and ring
           its doorbell as Linux does; with --try-limits and still no change,
           PERF_LIMITS_SET (max = level, min = 0) and LEVEL_SET again. The CPU
           measures every 20 ms window throughout, so the record shows which
           step moved the clock; then the CPU powers off and is measured again
           through a plain CPU_ON to see whether the request survives. With
           --channel pdp1/pdp2 the message goes to the cluster's own PDP (its
           only domain, or the one named PDPn); if that server describes no
           fastchannel, --fc-query takes the cluster's from another query of
           this q1n1 boot (PDP0's describes them).
The scratch memory used (stub, EL2 regime probe, reports) is saved and restored.

Hardware findings, A16 generation 1 after the 2026-10-18 04:34Z cold boot
(build/cpu-clock-records/, docs/A16-CPU-CLOCKS-20261018.md):
  * BASE 2.0 Qualcomm/PDP0, one agent, protocols 0x13 and 0x80;
    BASE_DISCOVER_IMPLEMENTATION_VERSION answers DENIED (Linux ignores that).
  * PERF 4.0, three domains PDP0/PDP1/PDP2, flags 0xea000000: set limits,
    set level, limit notify, fastchannels, level indexing; PDP0 index 0-20
    (355-3610 MHz, sustained 20), PDP1/PDP2 index 0-21 (355-5011, sustained 19,
    20 and 21 boost). Every LEVEL_GET 0 and LIMITS_GET 0/0 before any request,
    while the cores ran PDP0 at index 16 and PDP1/2 at 13: 0 means "no request
    from this agent".
  * LEVEL_SET 20 on PDP0 read back 20 and the Performance cores measured
    3.610 GHz. LEVEL_SET 19 on PDP1/PDP2 answered SUCCESS, read back 0, and the
    Prime cores still measured 3.437 GHz; no Prime core was on when it was sent.
  * Linux (perf.c __scmi_perf_level_set) writes a level through the domain's
    fastchannel whenever PERF_DESCRIBE_FASTCHANNEL describes one, and only
    otherwise sends the message: the message path is not the one Linux uses here.
  * The A16's Windows PEP lists separate SCMI agent/platform channels for pdp0,
    pdp1 and pdp2 (tx 0x19980000, 0x1a980000, 0x1b980000; 0x60-byte shared
    memories at 0x81e08000/060/0c0 and 0x81e08120/180/1e0): each PDP may serve
    its own cluster. The survey reads those headers passively.

After v50's guest run (gen1-v50-survey/-query/-prime-hold.json):
  * The PEP table's second set, 0x81e08120/180/1e0, reads as initialised idle
    SCMI channels (status FREE, all else zero); the first set, 0x81e08000/060/0c0,
    is unrelated data. The table lists them by index after 'cpucp', 'pdp0',
    'pdp1', 'pdp2' (index 0 the CPUCP SRAM 0x18b4e000), so pdp1's agent channel
    is 0x81e08180 and pdp2's 0x81e081e0: --channel pdp1 / pdp2, doorbell
    channel 0 of their own transmit blocks (scmi_apss_agent tx 0). The receive
    block 0x17610000 is shared by all three PDPs, so these channels never write
    its CLEAR register.
  * PDP0's server describes each domain's fastchannels in that domain's own
    PDP mailbox: LEVEL_SET at tx+0x118 (channel 3's data word) with doorbell
    tx+0x11c (channel 3's command word, set 0xf); LIMITS_SET at tx+0x120/0x124
    (channel 4); LEVEL_GET/LIMITS_GET in the shared receive block (PDP0 0x17610148,
    PDP1 0x17610150, PDP2 0x17610158; limits 0x17610160/168/170). Channels 3-8
    are the PEP's pcc_core0-5, the performance channels; channel 1 is
    dpm_crazy_mode and 2 debug_log. The limits fastchannels are 4 bytes; Linux
    (scmi_common_fastchannel_init, valid_size 8 for limits) refuses them and
    uses messages, and so does this tool.
  * PDP0 held index 20 through the whole guest run. PDP1/PDP2 now answer
    LEVEL_GET 21 and LIMITS_GET max 22 / min 0, and their LEVEL_GET fastchannel
    reads 255 even while a Prime CPU is held on. 22 is the domain's level count
    (indices 0-21), so 0-22 is an unrestricted range and 21 its top: defaults
    that appeared only after the Prime cluster had run (cold boot: 0 and 0/0),
    not anything this agent asked for (it asked 19, and LIMITS_SET 19/0 left
    22/0). The cluster nevertheless ran index 13 throughout. PDP0's server
    reports these domains but does not act on this agent's requests for them,
    and nothing publishes their level fastchannel (255): the cluster's own PDP
    is the next route, by its own channel or by the fastchannel in its own
    mailbox.

Failure modes, and what the tool does about each:
 1. Wrong mechanism or firmware (no SCMI on pdp0 here, different shmem): the
    survey requires a plausible a2p header (FREE, sane length/flags) and query
    starts with BASE PROTOCOL_VERSION; a timeout or error stops before PERF.
 2. Channel busy (status not FREE): refused; never written over.
 3. Wrong doorbell (pdp0 channel 1 is dpm_crazy_mode on Windows): the only
    doorbell is the selected transport's tx + 0x104 (channel 0), which the host
    test checks; the only other MMIO write is that rx CLEAR bit 0, made only
    when EN bit 0 and STAT bit 0 are both set (what Linux's handler does;
    otherwise the level interrupt stays asserted).
 4. Unmapped, read-only or unexpectedly cached addresses at EL2: the survey
    walks q1n1's EL2 tables; Device/Normal-NC is used directly, Normal
    cacheable gets clean before the doorbell and clean+invalidate before reads.
    If the shmem is not mapped at all, nothing is sent (see the report for the
    MMU-off secondary fallback).
 5. Ordering: a DSB SY (stub sync entry) separates shmem writes and doorbell.
 6. Bus errors (XPU/NoC): SError strict mode for every access; exception count
    checked after each access; first error stops.
 7. No completion: polled for a bounded time; the channel is then left as it
    is and recorded uncertain; a later run refuses until it reads FREE.
 8. Mismatched response (token, protocol, message, type): refused.
 9. SCMI errors (NOT_SUPPORTED, DENIED, OUT_OF_RANGE, ...): refused at the
    first; set-max never continues to the next domain after a failure.
10. Domain mapping or level semantics differ (indexing mode, kHz vs abstract
    levels, boost levels outside the agent's limits): levels, limits and names
    are recorded; set-max targets the highest described level within the
    current limits (never raises limits) and verifies with LEVEL_GET.
11. Thermal and power: only performance levels are requested; voltage is never
    written; the firmware's LMH/thermal limits still apply. Use AC power.
12. Persistence: a cold boot resets the request; chainloads keep it. The
    request is ineffective if measure-a16-cpu-clock.py shows no change.
13. Levels: set-max never requests boost (above the sustained level) unless
    --allow-boost; limits 0/0 mean unset, so the target is the sustained level.
14. Fastchannel writes (prime-hold): only a described LEVEL_SET fastchannel
    of size 4 at an aligned address that q1n1's EL2 tables map identity and
    writable, outside every RAM type of the UEFI map and outside q1n1's own
    image, heap and stage; its doorbell, if any, only inside the selected
    mailbox's transmit block, rung as Linux does (read & preserve mask | set).
15. Hold CPU (prime-hold): the hold stub stops itself after 240 windows; an
    uncertain power state keeps the scratch reserved (measure-a16-cpu-clock.py
    rules); a CPU_ON of the Prime cluster only when every non-boot CPU is OFF.
16. Per-PDP channels (pdp1, pdp2): used only after a survey of this
    generation found their shared memory FREE and sane; their receive block is
    PDP0's, so its CLEAR register is never written. A first message that times
    out means nothing serves that channel; it then stays busy until a cold boot
    (the tool refuses it from then on) and nothing else is affected.
"""
import argparse
import fcntl
import json
from pathlib import Path
import runpy
import statistics
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
clock_tool = runpy.run_path(str(ROOT / 'tools' / 'measure-a16-cpu-clock.py'), run_name='cpu_clock')
run = clock_tool['run']
Refused, need, Workspace = clock_tool['Refused'], clock_tool['need'], clock_tool['Workspace']
serror_clear = clock_tool['serror_clear']

TRANSPORTS = dict(
    pdp0=dict(tx=0x19980000, rx=0x17610000, shmem=0x81e08780, notify=0x81e08600, size=0x180, channel=0,
              intid=32 + 34, rx_clear=True),
    cpucp=dict(tx=0x18830000, rx=0x17620000, shmem=0x18b4e000, notify=0x18b4e200, size=0x200, channel=0,
               intid=32 + 28, rx_clear=True),
    # The PEP's own per-PDP agent channels (qcpep8480 table, survey gen1-v50): 0x60 bytes, shared rx block.
    pdp1=dict(tx=0x1a980000, rx=0x17610000, shmem=0x81e08180, notify=None, size=0x60, channel=0,
              intid=32 + 34, rx_clear=False),
    pdp2=dict(tx=0x1b980000, rx=0x17610000, shmem=0x81e081e0, notify=None, size=0x60, channel=0,
              intid=32 + 34, rx_clear=False))
PDP_TX = {0: 0x19980000, 1: 0x1a980000, 2: 0x1b980000}
# Transmit channels the PEP names (pdp0 and pdp1/pdp2 tables): only the pcc_core ones carry a fastchannel.
PEP_TX_CHANNELS = {0: 'scmi_apss_agent', 1: 'dpm_crazy_mode', 2: 'debug_log',
                   **{3 + i: f'pcc_core{i}' for i in range(6)}}
FC_DOORBELL_CHANNELS = range(3, 9)


def doorbell(t):
    return t['tx'] + 0x100 + 8 * t['channel'] + 4


def rx(t, name):
    return t['rx'] + dict(map=0x4000, stat=0x4400, clear=0x4800, enable=0x4c00)[name]


PDP0 = TRANSPORTS['pdp0']
DOORBELL, RX_MAP, RX_STAT, RX_CLEAR, RX_EN = (doorbell(PDP0), rx(PDP0, 'map'), rx(PDP0, 'stat'),
                                              rx(PDP0, 'clear'), rx(PDP0, 'enable'))
A2P_SHMEM, P2A_SHMEM, PDP0_TX, MAILBOX_INTID = PDP0['shmem'], PDP0['notify'], PDP0['tx'], PDP0['intid']
GICD = 0x17000000
PAGES = dict(gicd=GICD, pdp1_tx=0x1a980000, pdp2_tx=0x1b980000)
for _name, _t in TRANSPORTS.items():
    PAGES.update({f'{_name}_tx': _t['tx'], f'{_name}_rx': _t['rx'], f'{_name}_rx_status': rx(_t, 'map'),
                  f'{_name}_shmem': _t['shmem'] & ~0xfff})
BASE, PERF = 0x10, 0x13
STATUS = {0: 'SUCCESS', -1: 'NOT_SUPPORTED', -2: 'INVALID_PARAMETERS', -3: 'DENIED', -4: 'NOT_FOUND',
          -5: 'OUT_OF_RANGE', -6: 'BUSY', -7: 'COMMS_ERROR', -8: 'GENERIC_ERROR', -9: 'HARDWARE_ERROR',
          -10: 'PROTOCOL_ERROR', -11: 'IN_USE'}
SET_LIMITS, SET_LEVEL, FASTCHANNELS, LEVEL_INDEXING = 1 << 31, 1 << 30, 1 << 27, 1 << 25
DEFAULT_DOMAINS = (0, 1)        # the boot cluster and SNAP_SMP_PRIME's cluster 1
PROTOCOL_MESSAGE_ATTRIBUTES, LIMITS_SET, LIMITS_GET, LEVEL_SET, LEVEL_GET, DESCRIBE_FASTCHANNEL = 2, 5, 6, 7, 8, 11
FC_MESSAGES = dict(level_set=LEVEL_SET, level_get=LEVEL_GET, limits_set=LIMITS_SET, limits_get=LIMITS_GET)
FC_SIZES = dict(level_set=4, level_get=4, limits_set=8, limits_get=8)
RAM_TYPES = {1, 2, 3, 4, 5, 6, 7, 9, 10}          # UEFI loader/boot/runtime/conventional/ACPI memory
PEP_SHMEMS = (0x81e08000, 0x81e08060, 0x81e080c0, 0x81e08120, 0x81e08180, 0x81e081e0)   # qcpep8480 table
BASELINE_WINDOWS, SETTLE_WINDOWS = 5, 8
REGIME_CODE, REGIME_OUT = 0x480000, 0x490000      # tools/probe-el2-memory.py collect()
SYNC_BARRIER, SYNC_CLEAN, SYNC_CLEAN_INVALIDATE = 0, 1, 2


def signed32(value):
    value &= 0xffffffff
    return value - (1 << 32) if value & 0x80000000 else value


def mair_kind(attr):
    if attr & 0xf0 == 0:
        return 'device'
    if attr == 0x44:
        return 'normal-nc'
    return 'normal-cached'


def walk(read64, regime, va):
    """q1n1's EL2 stage-1 translation of VA (4 KiB granule), or None if unmapped."""
    sctlr, tcr, ttbr, mair = (int(regime[k], 16) for k in ('sctlr', 'tcr', 'ttbr0', 'mair'))
    if not sctlr & 1:
        return dict(pa=hex(va), kind='device', attr='0x0', mmu='off', writable=True, xn=True)
    t0sz = tcr & 63
    need((tcr >> 14) & 3 == 0 and 16 <= t0sz <= 39, 'unsupported EL2 TCR (not a 4 KiB granule)')
    if va >> (64 - t0sz):
        return None
    level = 0 if t0sz < 25 else 1 if t0sz < 34 else 2
    table = ttbr & 0x0000fffffffff000
    for shift in (39, 30, 21, 12)[level:]:
        desc = read64(table + ((va >> shift) & 511) * 8)
        form = desc & 3
        if not desc & 1 or (shift == 12 and form != 3):
            return None
        if form == 1 or shift == 12:
            if shift == 39:
                return None
            mask = (1 << shift) - 1
            attr = (mair >> (((desc >> 2) & 7) * 8)) & 255
            return dict(pa=hex((desc & 0x0000fffffffff000 & ~mask) | (va & mask)), desc=hex(desc), leaf_shift=shift,
                        attr=hex(attr), kind=mair_kind(attr), writable=not desc & (1 << 7),
                        accessed=bool(desc & (1 << 10)), xn=bool(desc & (1 << 54)))
        table = desc & 0x0000fffffffff000
    return None


def uefi_type(proxy, info, pa):
    stride, size = info['memory_map_stride'], info['memory_map_size']
    need(stride >= 40 and 0 < size <= 1 << 20 and not size % stride, 'invalid UEFI memory map geometry')
    raw = proxy.readmem(info['memory_map'], size, live=True)
    for offset in range(0, size, stride):
        kind, start, _, pages, attribute = struct.unpack_from('<I4xQQQQ', raw, offset)
        if start <= pa < start + pages * 4096:
            return dict(type=kind, start=hex(start), pages=pages, attribute=hex(attribute))
    return None


def shmem_header(words, size):
    """SCMI shared memory: reserved, channel_status, reserved[2], flags, length, msg_header, payload..."""
    status, flags, length, header = words[1], words[4], words[5], words[6]
    decoded = dict(channel_status=hex(status), free=bool(status & 1), error=bool(status & 2), flags=hex(flags),
                   length=length, msg_header=hex(header), message=header & 0xff, type=(header >> 8) & 3,
                   protocol=hex((header >> 10) & 0xff), token=(header >> 18) & 0x3ff,
                   payload=[hex(w) for w in words[7:]])
    problems = []
    if status & ~3:
        problems.append('reserved channel_status bits set')
    if not status & 1:
        problems.append('channel not FREE')
    if flags & ~1:
        problems.append('reserved flags set')
    if length > size - 24:
        problems.append('length beyond the shared memory')
    decoded['problems'] = problems
    return decoded


class Access:
    """Guarded 32/64-bit accesses with the cache handling the EL2 mapping needs."""

    def __init__(self, proxy, kinds, sync=None, transport=None):
        self.proxy, self.kinds, self.sync = proxy, kinds, sync
        self.allowed = ((doorbell(transport),) + ((rx(transport, 'clear'),) if transport.get('rx_clear', True)
                                                   else ())) if transport else ()
        self.mmio_writes = []

    def check(self, what):
        count = self.proxy.get_exc_count()
        need(not count and not self.proxy.exceptions, f'fault during {what} ({count} skipped/marked)')

    def cached(self, address):
        return self.kinds.get(address & ~0xfff) == 'normal-cached'

    def read32(self, address):
        if self.cached(address):
            self.proxy.request(self.proxy.P_DC_CIVAC, address & ~63, 64)
        value = self.proxy.read32(address)
        self.check(f'read32 {address:#x}')
        return value

    def read64(self, address):
        value = self.proxy.read64(address)
        self.check(f'read64 {address:#x}')
        return value

    def write32(self, address, value):
        self.proxy.write32(address, value)
        self.check(f'write32 {address:#x}')

    def mmio_write(self, address, value, width):
        need(address in self.allowed, f'MMIO write to {address:#x} is not the channel 0 doorbell or clear')
        self.mmio_writes.append((hex(address), hex(value), width))
        (self.proxy.write32 if width == 32 else self.proxy.write64)(address, value)
        self.check(f'MMIO write {address:#x}')

    def permit(self, address, kind):
        """A fastchannel or fastchannel doorbell address fc_check() admitted."""
        self.fc_allowed = getattr(self, 'fc_allowed', set()) | {address}
        self.kinds.setdefault(address & ~0xfff, kind)

    def fc_write(self, address, value, width=32):
        need(address in getattr(self, 'fc_allowed', ()), f'{address:#x} is not an admitted fastchannel')
        self.mmio_writes.append((hex(address), hex(value), width))
        getattr(self.proxy, f'write{width}')(address, value)
        self.check(f'fastchannel write {address:#x}')
        if self.cached(address):
            self.sync(address & ~63, 64, SYNC_CLEAN)

    def fc_read(self, address, width=32):
        if self.cached(address):
            self.proxy.request(self.proxy.P_DC_CIVAC, address & ~63, 64)
        value = getattr(self.proxy, f'read{width}')(address)
        self.check(f'fastchannel read {address:#x}')
        return value


class Channel:
    """SCMI over a qcom-cpucp mailbox, channel 0, polled (flags = 0, no interrupt)."""

    def __init__(self, access, transport, token=None, timeout=0.5, clock=time.monotonic, sleep=time.sleep):
        self.a, self.t, self.timeout, self.clock, self.sleep = access, transport, timeout, clock, sleep
        self.shmem, self.size = transport['shmem'], transport['size']
        self.token = (int(time.time() * 1000) if token is None else token) & 0x3ff
        self.sequence = 0
        self.log = []
        self.uncertain = None

    def header(self):
        return [self.a.read32(self.shmem + 4 * i) for i in range(7)]

    def xfer(self, protocol, message, payload=(), rx_words=0):
        need(self.uncertain is None, f'channel uncertain: {self.uncertain}')
        a, shm, t = self.a, self.shmem, self.t
        status = a.read32(shm + 4)
        need(status & 1 and not status & ~3, f'SCMI channel not FREE (status {status:#x})')
        need(4 * len(payload) <= self.size - 28, 'payload too long')
        self.token = (self.token + 1) & 0x3ff
        self.sequence += 1
        header = message | protocol << 10 | self.token << 18
        a.write32(shm + 4, 0)                          # busy, error cleared
        a.write32(shm + 16, 0)                         # polled completion
        a.write32(shm + 20, 4 + 4 * len(payload))
        a.write32(shm + 24, header)
        for i, word in enumerate(payload):
            a.write32(shm + 28 + 4 * i, word)
        a.sync(shm, self.size, SYNC_CLEAN if a.cached(shm) else SYNC_BARRIER)
        stat_before = a.read64(rx(t, 'stat'))
        a.mmio_write(doorbell(t), self.sequence, 32)
        deadline = self.clock() + self.timeout
        polls = 0
        while True:
            polls += 1
            status = a.read32(shm + 4)
            if status & 3:
                break
            if self.clock() >= deadline:
                self.uncertain = f'no completion of protocol {protocol:#x} message {message} after {polls} polls'
                raise Refused(self.uncertain)
            self.sleep(0.001)
        reply = a.read32(shm + 24)
        length = a.read32(shm + 20)
        need(not status & 2, f'SCMI channel error (status {status:#x})')
        need(reply == header, f'response header {reply:#x} for request {header:#x}')
        need(8 <= length <= self.size - 24, f'response length {length}')
        count = min(rx_words, (length - 8) // 4)
        result = signed32(a.read32(shm + 28))
        words = [a.read32(shm + 32 + 4 * i) for i in range(count)]
        stat, enable = a.read64(rx(t, 'stat')), a.read64(rx(t, 'enable'))
        cleared = False
        if t.get('rx_clear', True) and stat & 1 and enable & 1:
            a.mmio_write(rx(t, 'clear'), 1, 64)        # as qcom_cpucp_mbox_irq_fn does
            cleared = True
        self.log.append(dict(protocol=hex(protocol), message=message, token=self.token, polls=polls,
                             status=STATUS.get(result, result), rx_stat_before=hex(stat_before),
                             rx_stat=hex(stat), rx_enable=hex(enable), rx_cleared=cleared))
        need(result == 0, f'SCMI protocol {protocol:#x} message {message}: {STATUS.get(result, result)}')
        return words


def text(words, count=4):
    return b''.join(struct.pack('<I', w) for w in words[:count]).split(b'\0', 1)[0].decode('ascii', 'replace')


class Scmi:
    def __init__(self, channel):
        self.c = channel

    def base(self):
        version = self.c.xfer(BASE, 0, rx_words=1)[0]
        attributes = self.c.xfer(BASE, 1, rx_words=1)[0]
        vendor = text(self.c.xfer(BASE, 3, rx_words=4))
        result = dict(version=hex(version), protocols=attributes & 0xff, agents=(attributes >> 8) & 0xff,
                      vendor=vendor)
        try:
            result['sub_vendor'] = text(self.c.xfer(BASE, 4, rx_words=4))
        except Refused as error:
            if self.c.uncertain:
                raise
            result['sub_vendor_error'] = str(error)
        # Linux's base protocol init ignores both of these failing; the A16's PDP0
        # answers BASE_DISCOVER_IMPLEMENTATION_VERSION with DENIED (gen1 query).
        words, error = self.optional(BASE, 5, rx_words=1)
        result['implementation' if words else 'implementation_error'] = hex(words[0]) if words else error
        words, error = self.optional(BASE, 6, [0], rx_words=1 + (result['protocols'] + 3) // 4)
        if words:
            ids = b''.join(struct.pack('<I', w) for w in words[1:])[:words[0]]
            result['protocol_ids'] = [hex(b) for b in ids]
        else:
            result['protocol_list_error'] = error
        return result

    def optional(self, protocol, message, payload=(), rx_words=0):
        """A command whose failure is a finding, not an error (unless the channel is lost)."""
        try:
            return self.c.xfer(protocol, message, payload, rx_words=rx_words), None
        except Refused as error:
            if self.c.uncertain:
                raise
            return None, str(error).rsplit(': ', 1)[-1]

    def message_attributes(self, messages):
        out = {}
        for m in messages:
            words, error = self.optional(PERF, PROTOCOL_MESSAGE_ATTRIBUTES, [m], rx_words=1)
            out[str(m)] = hex(words[0]) if words else error
        return out

    def describe_fc(self, d, name):
        words, error = self.optional(PERF, DESCRIBE_FASTCHANNEL, [d, FC_MESSAGES[name]], rx_words=11)
        if not words:
            return dict(error=error)
        need(len(words) >= 11, 'short DESCRIBE_FASTCHANNEL reply')
        attr = words[0]
        return dict(attr=hex(attr), doorbell=bool(attr & 1), db_width=1 << ((attr >> 1) & 3),
                    rate_limit_us=words[1] & 0xfffff, addr=hex(words[2] | words[3] << 32), size=words[4],
                    db_addr=hex(words[5] | words[6] << 32), db_set=hex(words[7] | words[8] << 32),
                    db_preserve=hex(words[9] | words[10] << 32))

    def level_get(self, d):
        return self.c.xfer(PERF, LEVEL_GET, [d], rx_words=1)[0]

    def limits_set(self, d, top, bottom):
        self.c.xfer(PERF, LIMITS_SET, [d, top, bottom])
        return dict(zip(('max', 'min'), self.c.xfer(PERF, LIMITS_GET, [d], rx_words=2)))

    def perf(self):
        version = self.c.xfer(PERF, 0, rx_words=1)[0]
        attributes = self.c.xfer(PERF, 1, rx_words=4)
        return dict(version=hex(version), v4=version >> 16 >= 4, domains=attributes[0] & 0xffff,
                    power_flags=hex(attributes[0] >> 16))

    def domain(self, d, v4):
        attr = self.c.xfer(PERF, 3, [d], rx_words=8)
        flags = attr[0]
        info = dict(domain=d, name=text(attr[4:8]), flags=hex(flags), set_limits=bool(flags & SET_LIMITS),
                    set_level=bool(flags & SET_LEVEL), fastchannels=bool(flags & FASTCHANNELS),
                    level_indexing=bool(v4 and flags & LEVEL_INDEXING), rate_limit_us=attr[1] & 0xfffff,
                    sustained_khz=attr[2], sustained_level=attr[3])
        entry = 5 if v4 else 3
        levels = []
        for _ in range(32):
            words = self.c.xfer(PERF, 4, [d, len(levels)], rx_words=1 + 16 * entry)
            returned, remaining = words[0] & 0xffff, words[0] >> 16
            need(not returned or 1 + returned * entry <= len(words), 'short DESCRIBE_LEVELS reply')
            for i in range(returned):
                e = words[1 + i * entry:1 + (i + 1) * entry]
                level = dict(perf=e[0], power=e[1], latency_us=e[2] & 0xffff)
                if v4:
                    level.update(indicative_khz=e[3], index=e[4])
                levels.append(level)
            if not remaining or not returned or len(levels) >= 128:
                break
        need(levels, f'domain {d} describes no levels')
        info['levels'] = levels
        info['limits'] = dict(zip(('max', 'min'), self.c.xfer(PERF, 6, [d], rx_words=2)))
        info['level'] = self.c.xfer(PERF, 8, [d], rx_words=1)[0]
        for level in levels:
            level['mhz'] = mhz(info, level)
        return info

    def level_set(self, d, level):
        self.c.xfer(PERF, 7, [d, level])
        return self.c.xfer(PERF, 8, [d], rx_words=1)[0]


def mhz(info, level):
    if info['level_indexing'] or level.get('indicative_khz'):
        return round(level.get('indicative_khz', 0) / 1000, 1)
    if info['sustained_level']:
        return round(level['perf'] * info['sustained_khz'] / info['sustained_level'] / 1000, 1)
    return None


def limits_unset(info):
    return info['limits'] == dict(max=0, min=0)


def target_level(info, allow_boost=False):
    """The level set-max requests, in the domain's own level units.

    Limits 0/0 are unset on the A16 (it runs PDP0 at index 16 and PDP1/2 at 13
    while reporting them): taken literally they allow only index 0, 355 MHz.
    Then the target is the sustained level. Otherwise the highest described
    level within the limits. Either way never above the sustained level
    (boost) unless allow_boost."""
    key = 'index' if info['level_indexing'] else 'perf'
    described = sorted(lv[key] for lv in info['levels'])
    sustained = info['sustained_level']
    need(sustained in described, f'domain {info["domain"]}: sustained level {sustained} is not a described level')
    if limits_unset(info):
        return described[-1] if allow_boost else sustained
    allowed = [lv for lv in described if info['limits']['min'] <= lv <= info['limits']['max']]
    if not allow_boost:
        allowed = [lv for lv in allowed if lv <= sustained]
    need(allowed, f'domain {info["domain"]}: no described level within limits {info["limits"]}')
    return max(allowed)


def level_mhz(info, level):
    key = 'index' if info['level_indexing'] else 'perf'
    return next((lv['mhz'] for lv in info['levels'] if lv[key] == level), None)


def uefi_type_of(info, pa):
    for kind, start, pages in info.get('_uefi_map', ()):
        if start <= pa < start + pages * 4096:
            return kind
    return None


def uefi_map(proxy, info):
    stride, size = info['memory_map_stride'], info['memory_map_size']
    need(stride >= 40 and 0 < size <= 1 << 20 and not size % stride, 'invalid UEFI memory map geometry')
    raw = proxy.readmem(info['memory_map'], size, live=True)
    rows = [struct.unpack_from('<I4xQQQ', raw, o) for o in range(0, size, stride)]
    return [(kind, start, pages) for kind, start, _, pages in rows]


def pdp_of(dom):
    """The PDP that owns a domain: its name 'PDPn', else (PDP0's server) its index."""
    name = (dom or {}).get('name', '')
    if name.startswith('PDP') and name[3:].isdigit():
        return int(name[3:])
    return (dom or {}).get('domain')


def fc_check(read64, regime, info, desc, transport, name, dom=None):
    """Whether a described fastchannel may be read (and, for a *_set, written).

    A doorbell must be a command word (tx + 0x100 + 8*ch + 4) of the domain's own
    PDP transmit block, on one of the PEP's performance channels (pcc_core0-5,
    3-8), never channel 0 (the SCMI agent), 1 (dpm_crazy_mode) or 2 (debug_log);
    a set fastchannel inside a PDP transmit block must be that channel's data word."""
    if desc.get('error'):
        return dict(ok=False, problems=[f'not described: {desc["error"]}'])
    problems = []
    address, size = int(desc['addr'], 16), desc['size']
    if size != FC_SIZES[name]:
        problems.append(f'size {size}, expected {FC_SIZES[name]}' + (
            ' (Linux refuses a limits fastchannel that is not 8 bytes and sends messages)'
            if name.startswith('limits') else ''))
    if not address or address % 4:
        problems.append('null or unaligned address')
    page = walk(read64, regime, address) if address and not address % 4 else None
    if not page or int(page['pa'], 16) != address:
        problems.append('not identity-mapped at EL2')
    elif name.endswith('_set') and not page['writable']:
        problems.append('read-only at EL2')
    uefi = uefi_type_of(info, address)
    if uefi in RAM_TYPES:
        problems.append(f'in UEFI memory type {uefi}')
    for begin, length in ((info.get('image_base', 0), info.get('image_size', 0)),
                          (info['heap_base'], info.get('heap_size', 0)),
                          (info.get('stage_base', 0), info.get('stage_size', 0))):
        if begin <= address < begin + length:
            problems.append('inside q1n1')
    result = dict(kind=page['kind'] if page else None, uefi_type=uefi)
    pdp = pdp_of(dom) if dom else None
    tx = PDP_TX.get(pdp, transport['tx'] if dom is None else None)
    in_block = next((n for n, base in PDP_TX.items() if base <= address < base + 0x8000), None)
    if in_block is not None and PDP_TX[in_block] != tx:
        problems.append(f'{address:#x} is in PDP{in_block}\'s mailbox, not the domain\'s own')
    if name.endswith('_set') and desc['doorbell']:
        db, width = int(desc['db_addr'], 16), desc['db_width']
        offset = db - tx - 0x100 if tx is not None else -1
        channel = offset // 8 if offset >= 0 else None
        db_page = walk(read64, regime, db) if db and not db % width else None
        if tx is None or not tx <= db < tx + 0x8000:
            problems.append(f'doorbell {db:#x} outside the domain\'s own PDP transmit block')
        elif offset % 8 != 4 or width != 4:
            problems.append(f'doorbell {db:#x} is not a 32-bit channel command word')
        elif channel not in FC_DOORBELL_CHANNELS:
            problems.append(f'doorbell {db:#x} is channel {channel} '
                            f'({PEP_TX_CHANNELS.get(channel, "unnamed")}), not a pcc_core performance channel')
        elif in_block is not None and address != tx + 0x100 + 8 * channel:
            problems.append(f'{address:#x} is not channel {channel}\'s data word')
        elif not db_page or db_page['kind'] != 'device' or not db_page['writable']:
            problems.append('doorbell not writable Device memory at EL2')
        result.update(doorbell=hex(db), db_width=width, doorbell_channel=channel,
                      doorbell_name=PEP_TX_CHANNELS.get(channel))
    result.update(ok=not problems, problems=problems)
    return result


def regime_and_kinds(proxy, info, memory_blob, collect):
    regime = collect(proxy, memory_blob)
    read64 = lambda pa: struct.unpack('<Q', proxy.readmem(pa, 8, live=True))[0]   # noqa: E731
    pages = {name: walk(read64, regime, va) for name, va in PAGES.items()}
    kinds = {PAGES[n]: p['kind'] for n, p in pages.items() if p}
    return regime, pages, kinds, read64


def survey(proxy, info, memory_blob, collect):
    """Passive reads only. Judges each transport usable or lists why not."""
    regime, pages, kinds, _ = regime_and_kinds(proxy, info, memory_blob, collect)
    record = dict(regime={k: regime[k] for k in ('sctlr', 'tcr', 'ttbr0', 'mair', 'hcr')}, pages=pages,
                  uefi={name: uefi_type(proxy, info, t['shmem']) for name, t in TRANSPORTS.items()},
                  reads={}, verdict={})
    access = Access(proxy, kinds)
    gic = pages['gicd'] and pages['gicd']['kind'] == 'device'
    for name, t in TRANSPORTS.items():
        reads = record['reads'][name] = {}
        problems = []
        shmem = pages[f'{name}_shmem']
        if shmem:
            for role in ('shmem', 'notify'):
                if t.get(role):
                    reads[role] = shmem_header([access.read32(t[role] + 4 * i) for i in range(15)], t['size'])
        status_page = pages[f'{name}_rx_status']
        if status_page and status_page['kind'] == 'device':
            reads['rx'] = dict(map=hex(access.read64(rx(t, 'map'))), stat=hex(access.read64(rx(t, 'stat'))),
                               enable=hex(access.read64(rx(t, 'enable'))))
        if gic:
            word, bit = 4 * (t['intid'] // 32), 1 << (t['intid'] % 32)
            reads['interrupt'] = dict(intid=t['intid'], enabled=bool(access.read32(GICD + 0x100 + word) & bit),
                                      pending=bool(access.read32(GICD + 0x200 + word) & bit))
        for page in (f'{name}_tx', f'{name}_rx_status'):
            p = pages[page]
            if not p or p['kind'] != 'device' or not p['writable'] or int(p['pa'], 16) != PAGES[page]:
                problems.append(f'{page} is not identity-mapped writable Device memory at EL2')
        if not shmem or not shmem['writable'] or int(shmem['pa'], 16) != PAGES[f'{name}_shmem']:
            problems.append('the SCMI shared memory is not identity-mapped writable memory at EL2')
        elif reads['shmem']['problems']:
            problems.append('a2p shmem header: ' + ', '.join(reads['shmem']['problems']))
        record['verdict'][name] = dict(usable=not problems, problems=problems)
    # The Windows PEP's per-PDP channels share the pdp0 shared-memory page.
    if pages['pdp0_shmem'] and int(pages['pdp0_shmem']['pa'], 16) == PAGES['pdp0_shmem']:
        record['reads']['pep_channels'] = {hex(a): shmem_header([access.read32(a + 4 * i) for i in range(15)], 0x60)
                                           for a in PEP_SHMEMS}
    return record


def same_boot(record, info, kind, channel, generation=True):
    need(record.get('kind') == kind and record.get('status') == 'DONE', f'not a completed {kind} record')
    need(record['bootinfo']['heap_base'] == info['heap_base'] and
         (not generation or record['bootinfo']['stage_generation'] == info['stage_generation']),
         f'the {kind} record is from another generation')
    if kind != 'survey':
        need(record.get('channel') == channel, f'the {kind} record used channel {record.get("channel")}')


def domain_of(mpidr):
    """Linux glymur.dtsi: cluster 0 (0x0-0x500) is domain 0, 0x1xxxx domain 1, 0x2xxxx domain 2."""
    return (mpidr >> 16) & 0xff


def fc_values(access, dom, checks):
    """Passive reads of the domain's GET fastchannels that fc_check admitted."""
    values = {}
    for name in ('level_get', 'limits_get'):
        if not checks.get(name, {}).get('ok'):
            continue
        address = int(dom['fastchannels_described'][name]['addr'], 16)
        access.kinds.setdefault(address & ~0xfff, checks[name]['kind'])
        values[name] = (access.fc_read(address) if name == 'level_get' else
                        dict(max=access.fc_read(address), min=access.fc_read(address + 4)))
    return values


def segments(ghz, steps, target_mhz):
    """Median clock before the first step and between steps; whether each step raised it.

    A step's own window (the one running while the host acted) is skipped:
    ghz[i] is the window that completed i+1 windows."""
    out = []
    start = 0
    names = [s for s in steps if s['step'] not in ('baseline', 'end')]
    first = names[0]['before_window'] if names else len(ghz)
    base = ghz[start:first]
    baseline = statistics.median(base) if base else None
    out.append(dict(step='baseline', windows=len(base), ghz=baseline))
    following = steps[steps.index(names[0]) + 1:] if names else []
    for step, nxt in zip(names, following):
        window = ghz[step['after_window'] + 1:nxt['before_window']]
        median = statistics.median(window) if window else None
        out.append(dict(step=step['step'], windows=len(window), ghz=median,
                        raised=bool(median and baseline and median >= baseline * 1.03),
                        reached=bool(median and target_mhz and abs(median * 1000 - target_mhz) <= 0.03 * target_mhz)))
    return out


def conclusion(parts, after_ghz, baseline_ghz, target_mhz, channel='pdp0'):
    moved = next((p for p in parts if p.get('raised')), None)
    if not moved and channel in ('pdp0', 'cpucp'):
        what = ('no step moved the clock while the cluster was active; next: the cluster\'s own PDP channel '
                '(--channel pdp1 or pdp2: tx 0x1a980000/0x1b980000, shared memory 0x81e08180/0x81e081e0), '
                'after a survey that finds it FREE')
    elif not moved:
        what = (f'no step moved the clock while the cluster was active, on {channel}\'s own channel either: '
                'the Prime clock is not set by this agent\'s SCMI requests')
    else:
        what = dict(message='message PERF_LEVEL_SET applies while the cluster is active',
                    fastchannel='the LEVEL_SET fastchannel applies; the message is ignored for this domain',
                    **{'limits+message': 'LEVEL_SET applies after PERF_LIMITS_SET'})[moved['step']]
    kept = None
    if moved and after_ghz is not None:
        kept = abs(after_ghz * 1000 - target_mhz) <= 0.03 * target_mhz
        what += ('; kept after the cluster powered off' if kept else
                 '; dropped when the cluster powered off: re-assert after each power-up')
    return dict(effective_step=moved['step'] if moved else None, kept_after_power_off=kept, summary=what,
                baseline_ghz=baseline_ghz, after_power_off_ghz=after_ghz)


def prime_hold(args, proxy, info, prior, scmi, access, t, regime, read64, record, save, cpu):
    known = {d['domain']: d for d in prior['domains']}
    cluster = domain_of(args.cpu)
    named = [x['domain'] for x in prior['domains'] if x['name'] == f'PDP{cluster}']
    d = named[0] if len(named) == 1 else (prior['domains'][0]['domain'] if len(prior['domains']) == 1 else cluster)
    need(d in known, f'{args.cpu:#x} is in cluster {cluster}, which the query did not describe')
    dom = scmi.domain(d, prior['perf']['v4'])
    need(dom['name'] == known[d]['name'], f'domain {d} changed name since the query')
    key = 'index' if dom['level_indexing'] else 'perf'
    level = dom['sustained_level'] if args.level is None else args.level
    need(level in [lv[key] for lv in dom['levels']], f'level {level} is not described for domain {d}')
    need(level <= dom['sustained_level'] or args.allow_boost, f'level {level} is a boost level (use --allow-boost)')
    target_mhz = level_mhz(dom, level)
    fc = {name: scmi.describe_fc(d, name) for name in ('level_set', 'level_get')}
    fc_source = getattr(args, 'channel', 'pdp0')
    other = getattr(args, 'fc_record', None)
    if fc['level_set'].get('error') and other:
        # This server describes none: take the cluster's fastchannels from another query of this q1n1 boot.
        need(other.get('kind') == 'query' and other.get('status') == 'DONE' and
             other['bootinfo']['heap_base'] == info['heap_base'], '--fc-query is not a completed query of this boot')
        match = [x for x in other['domains'] if x['name'] == dom['name'] or x['name'] == f'PDP{cluster}']
        need(len(match) == 1, f'--fc-query has no single domain named {dom["name"]} or PDP{cluster}')
        fc = {name: match[0]['fastchannels_described'][name] for name in ('level_set', 'level_get')}
        fc_source = f'{other.get("channel")} query, domain {match[0]["name"]}'
        dom_for_check = match[0]
    else:
        dom_for_check = dict(dom, name=dom['name'] if pdp_of(dom) == cluster else f'PDP{cluster}')
    checks = {name: fc_check(read64, regime, info, fc[name], t, name, dom_for_check) for name in fc}
    exp = record['experiment'] = dict(cpu=hex(args.cpu), cluster=cluster, domain=d, name=dom['name'], level=level,
                                      target_mhz=target_mhz, settle_windows=args.settle, domain_before=dom,
                                      channel=getattr(args, 'channel', 'pdp0'),
                                      fastchannel_source=fc_source, fastchannels=fc, checks=checks, steps=[])

    def fc_level():
        if not checks['level_get']['ok']:
            return None
        address = int(fc['level_get']['addr'], 16)
        access.kinds.setdefault(address & ~0xfff, checks['level_get']['kind'])
        return access.fc_read(address)

    def fc_set():
        desc = fc['level_set']
        address = int(desc['addr'], 16)
        access.permit(address, checks['level_set']['kind'])
        access.fc_write(address, level)
        access.sync(address & ~63, 64, SYNC_BARRIER)          # the level before the doorbell
        if desc['doorbell']:
            db, width = int(desc['db_addr'], 16), 8 * desc['db_width']
            access.permit(db, 'device')
            preserve, value = int(desc['db_preserve'], 16), int(desc['db_set'], 16)
            current = access.fc_read(db, width) & preserve if preserve else 0
            access.fc_write(db, value | current, width)

    inventory = cpu['inventory'](proxy)
    ticks = round(cpu['timer_hz'] * 0.02)
    hold = clock_tool['Hold'](proxy, inventory, args.cpu, ticks, cpu['scratch'], exp, save,
                              timer_hz=cpu['timer_hz'], **cpu.get('hold', {}))

    def step(name, action=None):
        before = hold.progress()
        extra = action() if action else {}
        exp['steps'].append(dict(step=name, before_window=before, after_window=hold.progress(), at=time.time(),
                                 fc_level_get=fc_level(), **extra))
        save()
        return exp['steps'][-1]

    def settle():
        hold.wait(exp['steps'][-1]['after_window'] + 1 + args.settle)
        return segments(hold.samples(), exp['steps'] + [dict(step='end', before_window=hold.progress())],
                        target_mhz)[-1]

    exp['fc_level_get_before'] = fc_level()
    hold.start()
    try:
        hold.wait(BASELINE_WINDOWS)
        step('baseline')
        step('message', lambda: dict(level_get=scmi.level_set(d, level)))
        moved = settle()['raised']
        if checks['level_set']['ok'] and (not moved or args.always_fc):
            step('fastchannel', lambda: (fc_set(), dict(level_get=scmi.level_get(d)))[1])
            moved = settle()['raised'] or moved
        elif not checks['level_set']['ok']:
            exp['fastchannel_skipped'] = checks['level_set']['problems']
        if args.try_limits and not moved:
            step('limits+message', lambda: dict(limits=scmi.limits_set(d, level, 0), level_get=scmi.level_set(d, level)))
            settle()
        step('end')
    finally:
        if hold.running:
            exp['hold'] = hold.stop()
    parts = exp['segments'] = segments([s['ghz'] for s in exp['hold']['samples']], exp['steps'], target_mhz)
    clock_tool['measure_secondaries'](proxy, inventory, [args.cpu], 8, ticks, exp, save, cpu['scratch'],
                                      timer_hz=cpu['timer_hz'], **cpu.get('measure', {}))
    after = exp['cpus'][-1].get('ghz_median')
    exp['level_get_after'] = scmi.level_get(d)
    exp['fc_level_get_after'] = fc_level()
    exp['verdict'] = conclusion(parts, after, parts[0]['ghz'], target_mhz, getattr(args, 'channel', 'pdp0'))
    save()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', choices=('survey', 'query', 'set-max', 'restore', 'fc-read', 'prime-hold'))
    ap.add_argument('--device', required=True)
    ap.add_argument('--generation', type=int, required=True)
    ap.add_argument('--after', help='preserved stop this follows: build/PREFIX/launch.json')
    ap.add_argument('--idle', action='store_true', help='no guest ran in this generation')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--channel', choices=sorted(TRANSPORTS), default='pdp0')
    ap.add_argument('--survey', type=Path, help='query: the survey record')
    ap.add_argument('--query', type=Path, help='set-max, fc-read, prime-hold: the query record')
    ap.add_argument('--from', dest='source', type=Path, help='restore: the set-max record')
    ap.add_argument('--domains', default=','.join(map(str, DEFAULT_DOMAINS)))
    ap.add_argument('--allow-boost', action='store_true', help='allow levels above the sustained level')
    ap.add_argument('--cpu', type=lambda v: int(v, 0), default=0x10000, help='prime-hold: the CPU to hold')
    ap.add_argument('--level', type=int, help='prime-hold: level (index) to request; default sustained')
    ap.add_argument('--settle', type=int, default=SETTLE_WINDOWS, help='prime-hold: 20 ms windows per step')
    ap.add_argument('--always-fc', action='store_true', help='prime-hold: try the fastchannel even if the '
                                                              'message already raised the clock')
    ap.add_argument('--try-limits', action='store_true', help='prime-hold: PERF_LIMITS_SET if nothing else did')
    ap.add_argument('--fc-query', type=Path, help='prime-hold: take the cluster\'s fastchannels from this query '
                                                   'record (same q1n1 boot) when the channel describes none')
    args = ap.parse_args(argv)
    args.fc_record = json.loads(args.fc_query.read_text()) if args.fc_query else None
    need(bool(args.after) != bool(args.idle), 'give exactly one of --after PREFIX or --idle')
    need(1 <= args.settle <= 40, '--settle must be 1..40 windows')
    prior = None
    needed = {'query': ('survey', '--survey'), 'set-max': ('query', '--query'), 'restore': ('source', '--from'),
              'fc-read': ('query', '--query'), 'prime-hold': ('query', '--query')}
    if args.mode in needed:
        attribute, flag = needed[args.mode]
        need(getattr(args, attribute), f'{args.mode} needs {flag} RECORD')
        prior = json.loads(getattr(args, attribute).read_text())
    domains = [int(x) for x in args.domains.split(',') if x.strip()]
    ws = Workspace(ROOT)
    admission = clock_tool['admit'](args, ws)
    memory_blob = run.build('el2-memory', ROOT / 'build' / 'cpu-probe')
    psci_blob = run.build('psci-info', ROOT / 'build' / 'cpu-probe')
    collect = runpy.run_path(str(ROOT / 'tools' / 'probe-el2-memory.py'))['collect']
    cpu_collect = runpy.run_path(str(ROOT / 'tools' / 'probe-a16-cpus.py'))['collect']
    stub = clock_tool['build_stub']()
    t = TRANSPORTS[args.channel]
    record = dict(schema='snapintosh-cpu-perf-v2', kind=args.mode, channel=args.channel, admission=admission,
                  started=time.time(), mechanism=dict(protocol='SCMI performance 0x13', mailbox=args.channel,
                                                      doorbell=hex(doorbell(t)), shmem=hex(t['shmem']),
                                                      rx=hex(t['rx']), mailbox_channel=t['channel']))

    def save():
        args.output.write_text(json.dumps(record, indent=2) + '\n')

    with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        proxy = run.connect(args.device, tries=1)
        try:
            info, record['serror_before'] = clock_tool['check_resident'](proxy, args, admission)
            record['bootinfo'] = {k: info[k] for k in ('stage_generation', 'heap_base', 'image_base')}
            scratch = clock_tool['Scratch'](proxy, clock_tool['scratch_ranges'](
                info['heap_base'], stub, max(len(memory_blob), len(psci_blob))))
            cpu = dict(scratch=scratch, timer_hz=info['timer_hz'],
                       inventory=lambda p: cpu_collect(p, psci_blob, True))
            proxy.serror_strict(True)
            try:
                record['status'] = 'FAILED'
                execute(args, proxy, info, prior, domains, memory_blob, collect, stub, record, save, cpu=cpu)
                record['status'] = 'DONE'
            finally:
                proxy.serror_strict(False)
                record['scratch'] = scratch.restore()
                record['serror_after'] = proxy.serror_state()
                save()
            need(serror_clear(record['serror_after']), 'SError recorded during the run')
        except BaseException as error:
            record['error'] = f'{type(error).__name__}: {error}'
            save()
            raise
        finally:
            proxy.link.close()
    shown = ('kind', 'channel', 'status', 'verdict', 'changes', 'fastchannels')
    summary = {k: record.get(k) for k in shown}
    if 'experiment' in record:
        summary['experiment'] = {k: record['experiment'].get(k) for k in ('cpu', 'domain', 'level', 'target_mhz',
                                                                          'segments', 'verdict')}
    print(json.dumps(summary, indent=2))
    return 0


def execute(args, proxy, info, prior, domains, memory_blob, collect, stub, record, save, clock_kw=None, cpu=None):
    channel_name = getattr(args, 'channel', 'pdp0')
    t = TRANSPORTS[channel_name]
    record['channel'] = channel_name
    save()
    if args.mode == 'survey':
        result = survey(proxy, info, memory_blob, collect)
        record.update(result)
        record['kinds'] = {hex(PAGES[n]): p['kind'] for n, p in result['pages'].items() if p}
        return
    kind = {'query': 'survey', 'restore': 'set-max'}.get(args.mode, 'query')
    same_boot(prior, info, kind, channel_name, generation=args.mode != 'fc-read')
    if args.mode == 'query':
        verdict = prior.get('verdict', {}).get(channel_name, {})
        need(verdict.get('usable'), f'survey found {channel_name} unusable: {verdict.get("problems")}')
    info = dict(info, _uefi_map=uefi_map(proxy, info))
    # Re-establish the regime: the channel's cache handling depends on it.
    regime, _, kinds, read64 = regime_and_kinds(proxy, info, memory_blob, collect)
    need({hex(k): v for k, v in kinds.items()} == prior['kinds'], 'EL2 attributes changed since the prior record')
    record['kinds'] = prior['kinds']
    if args.mode == 'fc-read':
        access = Access(proxy, kinds)
        record['fastchannels'] = {}
        for dom in prior['domains']:
            checks = {n: fc_check(read64, regime, info, dom['fastchannels_described'][n], t, n, dom)
                      for n in ('level_get', 'limits_get') if n in dom.get('fastchannels_described', {})}
            record['fastchannels'][dom['name']] = dict(checks=checks, values=fc_values(access, dom, checks))
        return
    code = info['heap_base'] + clock_tool['CODE_AT']
    clock_tool['upload'](proxy, code, stub)      # to PoC: a hold CPU fetches it with its caches off

    def sync(address, length, op):
        need(proxy.call(code + clock_tool['ENTRY_SYNC'], address, length, op, timeout=10) == 0x5c,
             'sync stub did not run')

    access = Access(proxy, kinds, sync, t)
    channel = Channel(access, t, **(clock_kw or {}))
    scmi = Scmi(channel)
    try:
        record['shmem_before'] = shmem_header(channel.header() + [0] * 8, t['size'])
        if args.mode == 'query':
            record['base'] = scmi.base()
            need(record['base']['vendor'].lower().startswith('qualcomm'),
                 f'SCMI vendor {record["base"]["vendor"]!r}')
            if 'protocol_ids' in record['base']:
                need('0x13' in record['base']['protocol_ids'], 'the platform lists no SCMI performance protocol')
            record['perf'] = scmi.perf()
            need(1 <= record['perf']['domains'] <= 16, f'{record["perf"]["domains"]} performance domains')
            record['domains'] = [scmi.domain(d, record['perf']['v4']) for d in range(record['perf']['domains'])]
            record['perf_message_attributes'] = scmi.message_attributes((LIMITS_SET, LIMITS_GET, LEVEL_SET, LEVEL_GET,
                                                                         DESCRIBE_FASTCHANNEL))
            for dom in record['domains']:
                dom['fastchannels_described'] = {n: scmi.describe_fc(dom['domain'], n) for n in FC_MESSAGES}
                dom['fastchannel_checks'] = {n: fc_check(read64, regime, info, dom['fastchannels_described'][n],
                                                         t, n, dom) for n in FC_MESSAGES}
                dom['fastchannel_values'] = fc_values(access, dom, dom['fastchannel_checks'])
            return
        if args.mode == 'set-max':
            v4 = prior['perf']['v4']
            known = {d['domain']: d for d in prior['domains']}
            need(domains and all(d in known for d in domains), f'unknown domains {domains}')
            record['changes'] = []
            for d in domains:
                info_d = scmi.domain(d, v4)
                need(info_d['set_level'], f'domain {d} does not accept PERF_LEVEL_SET')
                need(info_d['name'] == known[d]['name'], f'domain {d} changed name since the query')
                target = target_level(info_d, getattr(args, 'allow_boost', False))
                change = dict(domain=d, name=info_d['name'], before=info_d['level'], target=target,
                              limits=info_d['limits'], target_mhz=level_mhz(info_d, target),
                              before_unset=info_d['level'] == 0 and limits_unset(info_d))
                record['changes'].append(change)
                save()
                change['after'] = scmi.level_set(d, target)
                change['verified'] = change['after'] == target
                save()
            record['unverified'] = [c['name'] for c in record['changes'] if not c['verified']]
            return
        if args.mode == 'prime-hold':
            need(cpu, 'prime-hold needs the CPU context')
            prime_hold(args, proxy, info, prior, scmi, access, t, regime, read64, record, save, cpu)
            return
        changes = prior.get('changes') or []
        need(changes and all('before' in c for c in changes), 'the set-max record has no previous levels')
        unset = [c['name'] for c in changes if c.get('before_unset', c['before'] == 0 and
                                                       c.get('limits') == dict(max=0, min=0))]
        settable = [c for c in changes if c['name'] not in unset]
        record['not_restored'] = dict(domains=unset, reason='no previous request by this agent (LEVEL_GET 0, limits '
                                      '0/0): writing 0 would request index 0, 355 MHz; the rollback is a cold boot')
        need(settable, f'nothing to restore: {", ".join(unset)} had no previous request; the rollback is a cold boot')
        record['changes'] = []
        for c in settable:
            entry = dict(domain=c['domain'], target=c['before'])
            record['changes'].append(entry)
            save()
            entry['after'] = scmi.level_set(c['domain'], c['before'])
            entry['verified'] = entry['after'] == c['before']
            save()
    finally:
        record['transactions'] = channel.log
        record['mmio_writes'] = access.mmio_writes
        record['channel_uncertain'] = channel.uncertain
        try:
            record['shmem_after'] = shmem_header(channel.header() + [0] * 8, t['size'])
        except Refused as error:
            record['shmem_after_error'] = str(error)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as refusal:
        print(f'refused: {refusal}', file=sys.stderr)
        sys.exit(2)
