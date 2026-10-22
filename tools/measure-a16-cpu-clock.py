#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure the clock the A16's CPU cores actually run at, from a stopped, idle q1n1.

Each tested CPU enables its PMU cycle counter at EL2, then counts PMCCNTR_EL0
against CNTPCT_EL0 over fixed windows (default 8 x 20 ms) and restores every
PMU register it touched. GHz = cycles / (ticks / CNTFRQ). The boot CPU runs
tools/a16-cpu-stub.S through P_CALL. q1n1 has no SMP call (its UEFI payload
never starts secondaries), so other CPUs run the same code through PSCI CPU_ON,
the route tools/probe-a16-secondary.py qualified: a CPU is started only if
PSCI AFFINITY_INFO says it is OFF, it measures with its MMU off, writes its
report and calls CPU_OFF, and the tool waits for AFFINITY_INFO to say OFF.

Writes, all restored: PMCR_EL0 (E on, D and DP off), PMCNTENSET_EL0 bit 31,
PMCCFILTR_EL0.NSH, and MDCR_EL2.HCCD/HPMD (cleared only if set). Scratch
memory: the stopped-probe gap heap+0x480000..0x490040 (PSCI inventory) and
heap+0x4a0000..0x4b3040 (stub, reports, hold report), saved first and written back and
verified at the end. Never MMIO, guest memory, the GIC, or SCMI.

Admission (hardware): /tmp/snapintosh-hardware.lock, no other hardware client,
--generation equal to the resident stage generation, and either --after PREFIX
(build/PREFIX/launch.json STOPPED_PRESERVED, launcher exited, same q1n1 boot)
or --idle (the operator states no guest ran in this generation). A copy run from
elsewhere finds build/PREFIX under $SNAP_TREE when that is set. --qemu runs
the same code on q1n1 in QEMU (two CPUs, no A16 access) as the E2E control.

Failure modes, each with what the tool does about it:
 1. No PMUv3 (ID_AA64DFR0_EL1.PMUVer 0 or 0xF): the stub stops before any PMU
    access, status 2.
 2. EL3 traps PMU registers (MDCR_EL3.TPM): the access faults to q1n1, which
    skips it and reports an exception; the all-ones sentinels show it in the
    report. Any proxy exception invalidates the CPU's result and stops the run
    before a secondary is started.
 3. PMCCNTR not counting at EL2: PMCCFILTR_EL0.NSH is 0 at reset (no EL2
    counting), MDCR_EL2.HCCD prohibits it, HPMD+PMCR.DP prohibits it, PMCR.E
    off. The stub sets each and records the running values; zero cycles in a
    window refuses the result.
 4. PMCR_EL0.D (count every 64 cycles) left set: cleared while measuring,
    checked in the running PMCR.
 4b. PMU overflow interrupts enabled (PMINTENSET_EL1 non-zero, e.g. left by a
    guest): enabling PMCR_EL0.E could start interrupting counters, so the stub
    refuses with status 4 before writing anything.
 5. Restoration incomplete: every touched register is read back and compared
    with the value read before; a difference fails the CPU's result loudly.
    PMCCNTR_EL0 is not reset; it advances by the cycles counted.
 6. Clock changes during the measurement (firmware DCVS ramping or a
    thermal/LMH clamp): several windows, reported individually with median,
    min, max and spread; a spread above 2% is flagged, not averaged away.
 7. Interrupts on the boot CPU: not masked (q1n1's tick services USB); both
    counters run through an EL2 handler, so the ratio is unaffected; a window
    more than twice its nominal length is refused.
 8. CNTFRQ zero or not the 19.2 MHz bootinfo timer_hz on the A16: zero is
    refused; any difference from timer_hz is refused on hardware.
 8b. Hold (a CPU kept busy for a host experiment, see Hold): the CPU stops on
    its own after its window budget; the stop word has its own cache line,
    written and cleaned by the host only; progress and samples are read after
    invalidating, while the CPU keeps writing them non-cacheably.
 9. A secondary CPU not OFF, CPU_ON refused/ALREADY_ON/ON_PENDING, or OFF not
    confirmed within its deadline: no CPU_ON is ever retried; an uncertain
    state stops the run and keeps the scratch reserved (not restored), because
    that CPU may still be executing from it.
10. Secondary faults: its own vector records ESR_EL2, marks status 0xEE and
    powers off; CPU_OFF returning is recorded (done word 3).
11. Secondary report invisible (its writes are non-cacheable, ours cacheable):
    the report is cleaned to PoC before CPU_ON and invalidated before reading.
12. P_CALL timeout or lost link: never retried; the record written before
    each call says what was in flight.
13. Another client, wrong generation, a running launcher, or a guest stop not
    preserved: refused before connecting to anything but the proxy.
14. The output path exists: refused; captures are never overwritten.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.path.insert(0, str(ROOT / 'tools'))
import run                                                      # noqa: E402
from cycle_lib.common import (Workspace, Refused, need, require_exclusive,  # noqa: E402
                              host_absent, serror_clear)

STUB_SOURCE = ROOT / 'tools' / 'a16-cpu-stub.S'
STUB_BUILD = ROOT / 'build' / 'cpu-clock'
INVENTORY_CODE, INVENTORY_OUT = 0x480000, 0x490000     # tools/probe-a16-cpus.py collect()
CODE_AT = 0x4a0000
RESULT_AT = 0x4b0000            # boot CPU report, 512 bytes
START_AT = 0x4b0200             # CPU_ON result, 64 bytes
QUERY_AT = 0x4b0300             # AFFINITY_INFO result, 64 bytes
SECONDARY_AT = 0x4b1000         # secondary report, 512 bytes
HOLD_AT = 0x4b2000              # hold report, 4096 bytes, then its stop word (own cache line)
REPORT_BYTES, HOLD_BYTES, HOLD_WINDOWS = 512, 4096, 240
HOLD_STOP = HOLD_AT + HOLD_BYTES
SCRATCH_TOP = HOLD_STOP + 64
ENTRY_MEASURE, ENTRY_START, ENTRY_AFFINITY, ENTRY_SYNC, ENTRY_HOLD = 0, 4, 8, 12, 16
MAGIC = int.from_bytes(b'CPUCLK01', 'little')
MAX_WINDOWS = 16
AFFINITY_MASK = 0xff00ffffff
FIELDS = ('magic status current_el mpidr midr cntfrq id_aa64dfr0 pmcr_before pmcntenset_before '
          'pmccfiltr_before mdcr_before pmcr_run mdcr_run pmcr_after pmcntenset_after '
          'pmccfiltr_after mdcr_after windows ticks esr off_result done pmccfiltr_run pmintenset '
          'progress wdone').split()
STATUS = {0: 'ok', 1: 'not at EL2', 2: 'no PMUv3', 3: 'bad arguments', 4: 'PMU overflow interrupts enabled',
          0xee: 'secondary fault'}
PSCI = {0: 'SUCCESS', -1: 'NOT_SUPPORTED', -2: 'INVALID_PARAMETERS', -3: 'DENIED', -4: 'ALREADY_ON',
        -5: 'ON_PENDING', -6: 'INTERNAL_FAILURE', -7: 'NOT_PRESENT', -8: 'DISABLED', -9: 'INVALID_ADDRESS'}
# CPU_ON returns after which the target certainly never started.
CPU_ON_NOT_STARTED = (-1, -2, -3, -7, -8, -9)
# Qualcomm's figures for the X2E-96-100 (docs/CPU-MAPPING-20260921.md); MADT
# efficiency class 0 is cluster 0 (Performance), class 1 clusters 1-2 (Prime).
NOMINAL = {0: dict(tier='Performance', max_ghz=3.6),
           1: dict(tier='Prime', max_ghz=4.4, boost_ghz=5.0, boost_note='1-2 active cores')}
SPREAD_LIMIT = 0.02


def sha(data):
    return hashlib.sha256(data).hexdigest()


def signed32(value):
    value &= 0xffffffff
    return value - (1 << 32) if value & 0x80000000 else value


def build_stub(out_dir=STUB_BUILD):
    """Assemble the stub to a flat .text blob, as probes/run.py builds probes."""
    out_dir.mkdir(parents=True, exist_ok=True)
    obj, binary = out_dir / 'a16-cpu-stub.o', out_dir / 'a16-cpu-stub.bin'
    subprocess.run([str(run.LLVM / 'clang'), *run.FLAGS, '-c', str(STUB_SOURCE), '-o', str(obj)], check=True)
    subprocess.run([str(run.LLVM / 'llvm-objcopy'), '-O', 'binary', '--only-section=.text',
                    str(obj), str(binary)], check=True)
    blob = binary.read_bytes()
    need(0x800 < len(blob) <= 0x10000, f'stub size {len(blob)} outside its scratch slot')
    return blob


def decode(words, windows, ticks, timer_hz=None, hold=False):
    """A stub report as a result, or Refused with the reason. A hold report may
    end before `windows` (its stop word); a plain one must have them all."""
    need(len(words) == (HOLD_BYTES if hold else REPORT_BYTES) // 8, 'truncated report')
    raw = dict(zip(FIELDS, words))
    need(raw['magic'] == MAGIC, f'report magic {raw["magic"]:#x}: the stub did not finish')
    need(raw['status'] == 0, f'stub status {raw["status"]:#x} ({STATUS.get(raw["status"], "unknown")}), '
         f'ESR {raw["esr"]:#x}, PMINTENSET {raw["pmintenset"]:#x}')
    need(raw['current_el'] == 8, 'not measured at EL2')
    need(raw['windows'] == windows and raw['ticks'] == ticks, 'report parameters differ from the request')
    need(raw['cntfrq'] > 0, 'CNTFRQ_EL0 is zero')
    if timer_hz is not None:
        need(raw['cntfrq'] == timer_hz, f'CNTFRQ {raw["cntfrq"]} differs from bootinfo timer_hz {timer_hz}')
    need(raw['id_aa64dfr0'] >> 8 & 15 not in (0, 15), 'no PMUv3')
    need(raw['pmcr_before'] != 2**64 - 1 and raw['mdcr_before'] != 2**64 - 1,
         'a PMU register read was skipped (trapped): all-ones sentinel in the report')
    need(raw['pmcr_run'] & 1 and not raw['pmcr_run'] & 0x28, 'PMCR_EL0 not counting every cycle while measuring')
    need(raw['pmccfiltr_run'] & (1 << 27), 'PMCCFILTR_EL0.NSH not set while measuring')
    need(not raw['mdcr_run'] & ((1 << 23) | (1 << 17)), 'MDCR_EL2 still prohibits EL2 cycle counting')
    restored = dict(pmcr=raw['pmcr_after'] == raw['pmcr_before'],
                    pmcntenset=raw['pmcntenset_after'] == raw['pmcntenset_before'],
                    pmccfiltr=raw['pmccfiltr_after'] == raw['pmccfiltr_before'],
                    mdcr=raw['mdcr_after'] == raw['mdcr_before'])
    need(all(restored.values()), f'PMU state not restored: {restored}')
    count = raw['wdone']
    need(1 <= count <= windows if hold else count == windows, f'{count} windows completed of {windows}')
    samples = []
    for i in range(count):
        dt, dc = words[32 + 2 * i], words[33 + 2 * i]
        need(ticks <= dt <= 2 * ticks, f'window {i}: {dt} ticks for a {ticks}-tick window')
        need(0 < dc < 1 << 40, f'window {i}: {dc} cycles')
        samples.append(dict(ticks=dt, cycles=dc, ghz=round(dc * raw['cntfrq'] / dt / 1e9, 4)))
    ghz = [s['ghz'] for s in samples]
    median = statistics.median(ghz)
    result = dict(mpidr=hex(raw['mpidr']), affinity=hex(raw['mpidr'] & AFFINITY_MASK), midr=hex(raw['midr']),
                  cntfrq=raw['cntfrq'], ghz_median=median, ghz_min=min(ghz), ghz_max=max(ghz),
                  spread=round((max(ghz) - min(ghz)) / median, 4), samples=samples,
                  pmu=dict(id_aa64dfr0=hex(raw['id_aa64dfr0']), pmuver=raw['id_aa64dfr0'] >> 8 & 15,
                           pmcr=hex(raw['pmcr_before']), pmcntenset=hex(raw['pmcntenset_before']),
                           pmccfiltr=hex(raw['pmccfiltr_before']), mdcr_el2=hex(raw['mdcr_before']),
                           pmcr_running=hex(raw['pmcr_run']), pmccfiltr_running=hex(raw['pmccfiltr_run']),
                           mdcr_running=hex(raw['mdcr_run']), pmintenset=hex(raw['pmintenset']),
                           restored=restored))
    result['stable'] = result['spread'] <= SPREAD_LIMIT
    return result


def label(result, inventory):
    """Tier and nominal clock from the MADT efficiency class of the measured CPU."""
    cpu = next((c for c in inventory.get('cpus', []) if int(c['mpidr'], 16) == int(result['affinity'], 16)), None)
    klass = cpu.get('efficiency_class') if cpu else None
    result['efficiency_class'] = klass
    nominal = NOMINAL.get(klass) if inventory.get('a16') else None
    if nominal:
        result.update(tier=nominal['tier'], nominal_max_ghz=nominal['max_ghz'],
                      fraction_of_nominal=round(result['ghz_median'] / nominal['max_ghz'], 3))
        if 'boost_ghz' in nominal:
            result.update(nominal_boost_ghz=nominal['boost_ghz'], boost_note=nominal['boost_note'])
    return result


class Scratch:
    """Save scratch ranges first; write them back unless a CPU may still use them."""

    def __init__(self, proxy, ranges):
        self.proxy = proxy
        self.saved = [(a, proxy.readmem(a, n)) for a, n in ranges]
        self.reserved = None

    def keep(self, reason):
        self.reserved = reason

    def release(self):
        self.reserved = None

    def restore(self):
        if self.reserved:
            return dict(restored=False, reserved_because=self.reserved,
                        ranges=[[hex(a), len(d)] for a, d in self.saved])
        for address, data in self.saved:
            self.proxy.writemem(address, data)
            self.proxy.request(self.proxy.P_DC_CVAC, address, len(data))
            need(self.proxy.readmem(address, len(data)) == data, f'scratch at {address:#x} did not restore')
        return dict(restored=True, ranges=[[hex(a), len(d), sha(d)] for a, d in self.saved])


def words_at(proxy, address, size):
    return struct.unpack(f'<{size // 8}Q', proxy.readmem(address, size, live=True))


def affinity_state(proxy, code, query, mpidr):
    proxy.writemem(query, bytes(64))
    proxy.call(code + ENTRY_AFFINITY, query, mpidr, timeout=10)      # never retried
    q = words_at(proxy, query, 64)
    need(q[5] == 1 and q[2] == mpidr, 'incomplete AFFINITY_INFO result')
    return signed32(q[0])


def psci_ready(inventory):
    need(inventory.get('psci_compliant', True) and not inventory.get('psci_uses_hvc'),
         'firmware does not declare SMC PSCI')
    need(all(inventory.get('features', {}).get(f) == 0 for f in ('0xc4000003', '0x84000002', '0xc4000004')),
         f'PSCI CPU_ON/CPU_OFF/AFFINITY_INFO not all supported: {inventory.get("features")}')


def cpu_states(inventory):
    return {int(c['mpidr'], 16): c.get('affinity_state') for c in inventory['cpus'] if c['flags'] & 1}


def only_boot_on(states, boot_affinity, mpidr):
    need(mpidr != boot_affinity, 'the boot CPU is measured through P_CALL, not CPU_ON')
    need(mpidr in states, f'{mpidr:#x} is not an enabled CPU in the MADT')
    for other, state in states.items():
        need(state == (0 if other == boot_affinity else 1),
             f'CPU {other:#x} AFFINITY_INFO {state}; every non-boot CPU must be OFF')


def cpu_on(proxy, code, entry, start_at, mpidr, report_at, scratch, record, save):
    """One CPU_ON, never retried. Returns the PSCI result; the scratch stays
    reserved unless the CPU certainly did not start."""
    proxy.writemem(start_at, bytes(64))
    proxy.request(proxy.P_DC_CIVAC, start_at, 64)
    record['in_flight'] = dict(cpu=hex(mpidr), call='CPU_ON', entry=entry)
    scratch.keep(f'CPU_ON {mpidr:#x} issued; OFF not yet confirmed')
    save()
    proxy.call(code + entry, start_at, mpidr, report_at, timeout=10)
    st = words_at(proxy, start_at, 64)
    if not (st[5] == 1 and st[2] == mpidr and st[3] == report_at and st[1] == 8):
        scratch.keep(f'incomplete CPU_ON result for {mpidr:#x}')
        raise Refused(scratch.reserved)
    returned = signed32(st[0])
    if returned in CPU_ON_NOT_STARTED:
        scratch.release()
        record.pop('in_flight')
        return returned, st
    if returned != 0:
        scratch.keep(f'CPU_ON {mpidr:#x} returned {PSCI.get(returned, returned)}; power state uncertain')
        raise Refused(scratch.reserved)
    return 0, st


def wait_off(proxy, code, query_at, mpidr, deadline, scratch, record, *, clock, sleep, poll):
    while True:
        state = affinity_state(proxy, code, query_at, mpidr)
        if state == 1:
            break
        if state not in (0, 2) or clock() >= deadline:
            scratch.keep(f'{mpidr:#x} not confirmed OFF (AFFINITY_INFO {state})')
            raise Refused(scratch.reserved)
        sleep(poll)
    scratch.release()
    record.pop('in_flight', None)


def upload(proxy, code, blob):
    proxy.writemem(code, blob)
    proxy.request(proxy.P_DC_CVAC, code, len(blob))      # fetched with caches off on a secondary
    proxy.ic_ivau(code, len(blob))
    need(proxy.readmem(code, len(blob)) == blob, 'stub upload did not verify')


def measure(proxy, blob, inventory, targets, windows, ticks, record, save, scratch, *, timer_hz,
            off_seconds=5.0, poll=0.02, clock=time.monotonic, sleep=time.sleep, uploaded=False):
    """Boot CPU first, then each target in order. Appends to record['cpus'].
    Marks the scratch reserved whenever a started CPU's state is uncertain."""
    info = proxy.bootinfo()
    base = info['heap_base']
    need(info['current_el'] == 2, 'q1n1 is not at EL2')
    need(info['heap_size'] >= SCRATCH_TOP, 'heap too small for the scratch layout')
    code, result_at = base + CODE_AT, base + RESULT_AT
    secondary_at = base + SECONDARY_AT
    need(code % 2048 == 0 and secondary_at % 64 == 0, 'unaligned stub or secondary report')
    need(len(blob) <= RESULT_AT - CODE_AT, 'stub overlaps its reports')
    need(not proxy.exceptions, 'proxy exceptions before measuring')
    windows_seconds = windows * ticks / timer_hz
    record.setdefault('cpus', [])
    if not uploaded:
        upload(proxy, code, blob)
    proxy.writemem(result_at, bytes(REPORT_BYTES))
    record['in_flight'] = dict(cpu='boot', call='measure')
    scratch.keep('boot CPU measure call in flight')
    save()
    proxy.call(code + ENTRY_MEASURE, result_at, windows, ticks, timeout=10 + 2 * windows_seconds)
    scratch.release()
    record.pop('in_flight')
    need(not proxy.exceptions, f'proxy exception while measuring the boot CPU: {proxy.exceptions}')
    boot = decode(words_at(proxy, result_at, REPORT_BYTES), windows, ticks, timer_hz)
    boot.update(role='boot', route='P_CALL')
    record['cpus'].append(label(boot, inventory))
    save()
    need(int(boot['affinity'], 16) == int(inventory['boot_mpidr'], 16), 'boot CPU differs from the inventory')
    return measure_secondaries(proxy, inventory, targets, windows, ticks, record, save, scratch, timer_hz=timer_hz,
                               off_seconds=off_seconds, poll=poll, clock=clock, sleep=sleep)


def measure_secondaries(proxy, inventory, targets, windows, ticks, record, save, scratch, *, timer_hz,
                        off_seconds=5.0, poll=0.02, clock=time.monotonic, sleep=time.sleep):
    """Each target through CPU_ON into secondary_entry; the stub must already be uploaded."""
    base = proxy.bootinfo()['heap_base']
    code, start_at, query_at, secondary_at = (base + CODE_AT, base + START_AT, base + QUERY_AT,
                                              base + SECONDARY_AT)
    windows_seconds = windows * ticks / timer_hz
    boot_affinity = int(inventory['boot_mpidr'], 16)
    states = inventory.setdefault('_states', cpu_states(inventory))
    record.setdefault('cpus', [])
    if targets:
        psci_ready(inventory)
    for mpidr in targets:
        only_boot_on(states, boot_affinity, mpidr)
        initial = bytearray(REPORT_BYTES)
        struct.pack_into('<QQ', initial, 136, windows, ticks)
        proxy.writemem(secondary_at, bytes(initial))
        proxy.request(proxy.P_DC_CIVAC, secondary_at, REPORT_BYTES)
        returned, st = cpu_on(proxy, code, ENTRY_START, start_at, mpidr, secondary_at, scratch, record, save)
        if returned:
            record['cpus'].append(dict(affinity=hex(mpidr), role='secondary', route='PSCI CPU_ON',
                                       refused=PSCI.get(returned, returned)))
            save()
            continue
        wait_off(proxy, code, query_at, mpidr, clock() + off_seconds + 2 * windows_seconds, scratch, record,
                 clock=clock, sleep=sleep, poll=poll)
        states[mpidr] = 1
        proxy.request(proxy.P_DC_IVAC, secondary_at, REPORT_BYTES)
        words = words_at(proxy, secondary_at, REPORT_BYTES)
        need(not proxy.exceptions, f'proxy exception during the {mpidr:#x} measurement')
        need(words[21] == 1, f'{mpidr:#x} done word {words[21]} (3: CPU_OFF returned {words[20]:#x})')
        result = decode(words, windows, ticks, timer_hz)
        need(int(result['affinity'], 16) == mpidr, f'{mpidr:#x} report came from {result["affinity"]}')
        result.update(role='secondary', route='PSCI CPU_ON', entry=hex(st[4]))
        record['cpus'].append(label(result, inventory))
        save()
    return record


class Hold:
    """One CPU kept busy in hold_entry while the host does something else.

    start() issues CPU_ON (only if every non-boot CPU is OFF); progress() is the
    number of 20 ms windows it has completed; samples() what it measured so far;
    stop() sets the stop word, waits for AFFINITY_INFO OFF and returns the
    decoded report. The CPU stops on its own after `windows` windows, so a host
    that dies leaves it OFF within windows x ticks."""

    def __init__(self, proxy, inventory, mpidr, ticks, scratch, record, save, *, timer_hz, windows=HOLD_WINDOWS,
                 off_seconds=5.0, poll=0.02, clock=time.monotonic, sleep=time.sleep):
        base = proxy.bootinfo()['heap_base']
        need(1 <= windows <= HOLD_WINDOWS, f'hold windows must be 1..{HOLD_WINDOWS}')
        self.proxy, self.inventory, self.mpidr, self.ticks, self.windows = proxy, inventory, mpidr, ticks, windows
        self.scratch, self.record, self.save, self.timer_hz = scratch, record, save, timer_hz
        self.code, self.start_at, self.query_at = base + CODE_AT, base + START_AT, base + QUERY_AT
        self.report, self.stop_at = base + HOLD_AT, base + HOLD_STOP
        self.off_seconds, self.poll, self.clock, self.sleep = off_seconds, poll, clock, sleep
        self.running = False

    def start(self):
        psci_ready(self.inventory)
        states = self.inventory.setdefault('_states', cpu_states(self.inventory))
        only_boot_on(states, int(self.inventory['boot_mpidr'], 16), self.mpidr)
        initial = bytearray(HOLD_BYTES)
        struct.pack_into('<QQ', initial, 136, self.windows, self.ticks)
        self.proxy.writemem(self.report, bytes(initial))
        self.proxy.writemem(self.stop_at, bytes(64))
        self.proxy.request(self.proxy.P_DC_CIVAC, self.report, HOLD_BYTES + 64)
        returned, st = cpu_on(self.proxy, self.code, ENTRY_HOLD, self.start_at, self.mpidr, self.report,
                              self.scratch, self.record, self.save)
        need(returned == 0, f'hold CPU_ON {self.mpidr:#x} refused: {PSCI.get(returned, returned)}')
        states[self.mpidr] = None          # ON until stop() confirms OFF
        self.started = self.clock()
        self.running = True

    def header(self):
        self.proxy.request(self.proxy.P_DC_IVAC, self.report, 256)
        return words_at(self.proxy, self.report, 256)

    def progress(self):
        words = self.header()
        need(words[1] == 0 or words[0] != MAGIC, f'hold stub status {words[1]:#x} ({STATUS.get(words[1])})')
        return words[24]

    def samples(self):
        """Windows completed so far, as GHz, without stopping."""
        count = self.progress()
        self.proxy.request(self.proxy.P_DC_IVAC, self.report + 256, 16 * count)
        raw = struct.unpack(f'<{2 * count}Q', self.proxy.readmem(self.report + 256, 16 * count, live=True)) \
            if count else ()
        cntfrq = self.header()[5] or self.timer_hz
        return [round(raw[2 * i + 1] * cntfrq / raw[2 * i] / 1e9, 4) for i in range(count) if raw[2 * i]]

    def wait(self, count, timeout=None):
        deadline = self.clock() + (timeout if timeout is not None else
                                   2 * count * self.ticks / self.timer_hz + self.off_seconds)
        while True:
            done = self.progress()
            if done >= count:
                return done
            need(done < self.windows, f'hold ended after {done} windows, before {count}')
            need(self.clock() < deadline, f'hold reached {done} of {count} windows before its deadline')
            self.sleep(self.poll)

    def stop(self):
        self.proxy.writemem(self.stop_at, struct.pack('<Q', 1))
        self.proxy.request(self.proxy.P_DC_CVAC, self.stop_at, 64)
        wait_off(self.proxy, self.code, self.query_at, self.mpidr,
                 self.clock() + self.off_seconds + 2 * self.ticks / self.timer_hz, self.scratch, self.record,
                 clock=self.clock, sleep=self.sleep, poll=self.poll)
        self.inventory['_states'][self.mpidr] = 1
        self.running = False
        self.proxy.request(self.proxy.P_DC_IVAC, self.report, HOLD_BYTES)
        words = words_at(self.proxy, self.report, HOLD_BYTES)
        need(not self.proxy.exceptions, f'proxy exception during the {self.mpidr:#x} hold')
        need(words[21] == 1, f'{self.mpidr:#x} done word {words[21]} (3: CPU_OFF returned {words[20]:#x})')
        result = decode(words, self.windows, self.ticks, self.timer_hz, hold=True)
        need(int(result['affinity'], 16) == self.mpidr, f'hold report came from {result["affinity"]}')
        result.update(role='hold', route='PSCI CPU_ON (hold)', windows_done=len(result['samples']))
        return label(result, self.inventory)


def scratch_ranges(base, blob, probe_bytes):
    """Every scratch byte a session may touch: the inventory/regime probes, the
    stub, the reports and the hold report with its stop word."""
    return [(base + INVENTORY_CODE, probe_bytes), (base + INVENTORY_OUT, 128), (base + CODE_AT, len(blob)),
            (base + RESULT_AT, 0x400), (base + SECONDARY_AT, REPORT_BYTES), (base + HOLD_AT, HOLD_BYTES + 64)]


def session(proxy, blob, psci_blob, collect, targets, windows, window_ms, record, save, *, a16, timer_hz=None,
            **options):
    """Inventory, then measure, with the scratch saved first and restored last."""
    info = proxy.bootinfo()
    base = info['heap_base']
    need(info['current_el'] == 2 and info['heap_size'] >= SCRATCH_TOP,
         'q1n1 is not at EL2 or its heap is too small')
    record['bootinfo'] = {k: info.get(k) for k in ('stage_generation', 'heap_base', 'heap_size',
                                                   'image_base', 'timer_hz', 'current_el')}
    scratch = Scratch(proxy, scratch_ranges(base, blob, len(psci_blob)))
    try:
        inventory = collect(proxy, psci_blob, True)
        inventory['a16'] = a16
        record['inventory'] = dict(boot_mpidr=inventory.get('boot_mpidr'),
                                   psci_version=inventory.get('psci_version_raw'),
                                   features=inventory.get('features'),
                                   cpus=[dict(mpidr=c['mpidr'], flags=c['flags'],
                                              efficiency_class=c.get('efficiency_class'),
                                              affinity_state=c.get('affinity_state'))
                                         for c in inventory['cpus']])
        if timer_hz is None:
            timer_hz = probe_cntfrq(proxy, blob, base)
        ticks = round(timer_hz * window_ms / 1000)
        need(0 < ticks < 1 << 32, 'window length out of range')
        record['ticks'] = ticks
        save()
        measure(proxy, blob, inventory, targets, windows, ticks, record, save, scratch,
                timer_hz=timer_hz, **options)
    finally:
        record['scratch'] = scratch.restore()
        save()
    return record


def admit(args, ws):
    """Offline checks before the proxy is opened."""
    need(not args.output.exists(), f'{args.output} exists; captures are never overwritten')
    require_exclusive(ws)
    if args.after:
        # SNAP_TREE: a scratch copy of these tools reads the run records of the real checkout.
        records = Path(os.environ['SNAP_TREE']) / 'build' if os.environ.get('SNAP_TREE') else ws.build
        path = records / args.after / 'launch.json'
        need(path.is_file(), f'no launch record {path}')
        launch = json.loads(path.read_text())
        need(launch.get('status') == 'STOPPED_PRESERVED' and launch.get('preservation_sha256'),
             f'{args.after} is {launch.get("status")}, not a preserved stop')
        host_absent(ws, launch)
        need(launch['bootinfo'].get('stage_generation') == args.generation,
             f'{args.after} ran in generation {launch["bootinfo"].get("stage_generation")}')
        return dict(after=args.after, launch=str(path), preservation_sha256=launch['preservation_sha256'],
                    heap_base=launch['bootinfo']['heap_base'])
    need(args.idle, 'name the preserved stop with --after PREFIX, or state --idle (no guest ran)')
    return dict(idle=True)


def check_resident(proxy, args, admission):
    info = proxy.bootinfo()
    need(info['stage_generation'] == args.generation,
         f'resident generation {info["stage_generation"]}, expected {args.generation}')
    if 'heap_base' in admission:
        need(info['heap_base'] == admission['heap_base'], f'{args.after} ran in another q1n1 boot')
    state = proxy.serror_state()
    need(serror_clear(state), f'SError recorded before measuring: {state}')
    return info, state


class QemuSmp:
    """q1n1 under QEMU with two CPUs (PSCI over SMC at EL2), isolated in DEST."""

    def __init__(self, dest, cpus=2):
        self.esp = dest / 'qemu-esp'
        self.esp.mkdir(parents=True)
        payload = ROOT.parent / 'q1n1' / 'build' / 'uefi' / 'q1n1.efi'
        need(payload.exists(), f'build q1n1 first: make -C {ROOT.parent / "q1n1"} uefi')
        shutil.copyfile(payload, self.esp / 'q1n1.efi')
        (self.esp / 'startup.nsh').write_text('fs0:\nq1n1.efi --uart-proxy\n')
        self.sock = f'/tmp/snapintosh-clock-{os.getpid()}.sock'
        self.log = dest / 'qemu.log'
        self.cpus = cpus
        self.proc = None

    def __enter__(self):
        Path(self.sock).unlink(missing_ok=True)
        self.log_file = open(self.log, 'w')
        self.proc = subprocess.Popen(
            ['qemu-system-aarch64', '-machine', 'virt,virtualization=on,gic-version=3',
             '-accel', 'tcg', '-cpu', 'max', '-smp', str(self.cpus), '-m', '4G',
             '-bios', run.FIRMWARE, '-drive', f'format=raw,file=fat:rw:{self.esp}',
             '-device', 'ramfb', '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
             '-chardev', f'socket,id=s,path={self.sock},server=on,wait=off', '-serial', 'chardev:s'],
            stdout=subprocess.DEVNULL, stderr=self.log_file)
        return self.sock

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.log_file.close()
        Path(self.sock).unlink(missing_ok=True)


def summary(record):
    rows = []
    for cpu in record.get('cpus', []):
        if 'ghz_median' in cpu:
            rows.append(dict(cpu=cpu['affinity'], role=cpu['role'], tier=cpu.get('tier'),
                             ghz=cpu['ghz_median'], min=cpu['ghz_min'], max=cpu['ghz_max'],
                             stable=cpu['stable'], nominal=cpu.get('nominal_max_ghz'),
                             fraction=cpu.get('fraction_of_nominal')))
        else:
            rows.append(dict(cpu=cpu['affinity'], role=cpu['role'], refused=cpu.get('refused')))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--device', help='q1n1 proxy link, e.g. udp://en5')
    ap.add_argument('--output', type=Path, required=True, help='new JSON record (never overwritten)')
    ap.add_argument('--generation', type=int, help='resident q1n1 stage generation (bootinfo)')
    ap.add_argument('--after', help='preserved stop this follows: build/PREFIX/launch.json')
    ap.add_argument('--idle', action='store_true', help='no guest ran in this generation')
    ap.add_argument('--cpus', default='0x100,0x10000',
                    help='non-boot MPIDRs to start through CPU_ON, comma separated; "" for the boot CPU only')
    ap.add_argument('--windows', type=int, default=8)
    ap.add_argument('--window-ms', type=float, default=20.0)
    ap.add_argument('--qemu', action='store_true', help='E2E control on q1n1 in QEMU; no A16 access')
    args = ap.parse_args(argv)
    need(1 <= args.windows <= MAX_WINDOWS, f'--windows must be 1..{MAX_WINDOWS}')
    need(1.0 <= args.window_ms <= 200.0, '--window-ms must be 1..200')
    targets = [int(x, 0) for x in args.cpus.split(',') if x.strip()]
    need(all(0 <= t and not t & ~AFFINITY_MASK for t in targets) and len(set(targets)) == len(targets),
         'targets must be distinct affinity-only MPIDRs')
    if args.qemu:
        need(not args.output.exists(), f'{args.output} exists; captures are never overwritten')
        targets = targets if args.cpus != ap.get_default('cpus') else [0x1]
        lock_path, admission = Path('/tmp/snapintosh-clock-qemu.lock'), dict(qemu=True)
    else:
        need(args.device and args.generation is not None, '--device and --generation are required on hardware')
        need(bool(args.after) != bool(args.idle), 'give exactly one of --after PREFIX or --idle')
        ws = Workspace(ROOT)
        admission = admit(args, ws)
        lock_path = Path('/tmp/snapintosh-hardware.lock')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    blob = build_stub()
    psci_blob = run.build('psci-info', ROOT / 'build' / 'cpu-probe')
    collect = runpy.run_path(str(ROOT / 'tools' / 'probe-a16-cpus.py'))['collect']
    record = dict(schema='snapintosh-cpu-clock-v1', admission=admission, targets=[hex(t) for t in targets],
                  windows=args.windows, window_ms=args.window_ms, started=time.time(),
                  stub=dict(source=str(STUB_SOURCE), source_sha256=sha(STUB_SOURCE.read_bytes()),
                            sha256=sha(blob), bytes=len(blob)),
                  qualification='EL2 PMU cycle counter against CNTPCT on a stopped, idle q1n1; '
                                'not a guest-load or sustained-thermal measurement')

    def save():
        args.output.write_text(json.dumps({k: v for k, v in record.items() if not k.startswith('_')},
                                          indent=2) + '\n')

    with lock_path.open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        dest = args.output.parent / (args.output.stem + '-qemu')
        context = QemuSmp(dest) if args.qemu else None
        sock = context.__enter__() if context else None
        try:
            proxy = run.connect(sock if args.qemu else args.device, tries=90 if args.qemu else 1)
            try:
                if args.qemu:
                    timer_hz = None
                else:
                    info, record['serror_before'] = check_resident(proxy, args, admission)
                    timer_hz = info['timer_hz']
                session(proxy, blob, psci_blob, collect, targets, args.windows, args.window_ms, record, save,
                        a16=not args.qemu, timer_hz=timer_hz)
                if not args.qemu:
                    record['serror_after'] = proxy.serror_state()
                    need(serror_clear(record['serror_after']), 'SError recorded during the measurement')
                record['finished'] = time.time()
                record['status'] = 'MEASURED'
                save()
                proxy.nop()
            finally:
                proxy.link.close()
        except BaseException as error:
            record['status'] = 'FAILED'
            record['error'] = f'{type(error).__name__}: {error}'
            save()
            raise
        finally:
            if context:
                context.__exit__(None, None, None)
    print(json.dumps(dict(output=str(args.output), status=record['status'], cpus=summary(record)), indent=2))
    return 0


def probe_cntfrq(proxy, blob, base):
    """QEMU only: CNTFRQ_EL0 from a one-window run (the A16 path uses bootinfo timer_hz)."""
    code, out = base + CODE_AT, base + RESULT_AT
    proxy.writemem(code, blob)
    proxy.flush_code(code, len(blob))
    proxy.writemem(out, bytes(REPORT_BYTES))
    proxy.call(code + ENTRY_MEASURE, out, 1, 1000, timeout=10)
    words = words_at(proxy, out, REPORT_BYTES)
    need(words[0] == MAGIC and words[5] > 0, 'QEMU CNTFRQ probe failed')
    return words[5]


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as refusal:
        print(f'refused: {refusal}', file=sys.stderr)
        sys.exit(2)
