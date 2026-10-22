# SPDX-License-Identifier: MIT
"""IC10 fan read protocol and bounded, preconfigured GPI ring transport.

This module has no hardware connector. A platform must supply an exclusively
owned, started channel pair, qualified DMA mappings and cache operations.
No such A16 lease is qualified yet. See docs/A16-FAN-GPI-20261018.md.
"""
from dataclasses import dataclass, asdict
import struct

GPI_MMIO = 0x00A00000
GPI_EE = GPI_MMIO - 0x10000
APPS_MASK = 0x3F
SE_BASE = 0x00A84000
STREAM_ID = 0xCB6
SEID = 1
I2C_PROTOCOL = 3
EC_ADDRESS = 0x76
FAN_HIGH = 0x0603
FAN_LOW = 0x0602
TRE_SIZE = 16


class Refused(RuntimeError):
    pass


def require(condition, why):
    if not condition:
        raise Refused(why)


def context(instance, channel=None):
    require(0 <= instance < 6, 'instance outside documented apps mask')
    if channel is None:
        return GPI_EE + 0x21000 + 0x4000 * instance
    require(channel in (0, 1), 'bad channel')
    return GPI_EE + 0x20000 + 0x4000 * instance + 0x80 * channel


def register(instance, offset):
    require(0 <= instance < 6, 'instance outside documented apps mask')
    return GPI_EE + 0x4000 * instance + offset


def survey_plan():
    """Only side-effect-free context/status reads; no doorbell/FIFO reads."""
    result = []
    se = {'status': 0x40, 'master_clock': 0x48, 'clock_control': 0x60,
          'fifo_disabled': 0x64, 'firmware_revision': 0x68, 'clock_select': 0x7c,
          'dma_mode': 0x258, 'scl_counters': 0x278, 'io_status': 0x908}
    for name, offset in se.items():
        result.append((f'ic10.{name}', SE_BASE + offset))
    ring = {'config': 0, 'length': 4, 'base_low': 8, 'base_high': 12,
            'rp_low': 16, 'rp_high': 20, 'wp_low': 24, 'wp_high': 28}
    for instance in range(6):
        for channel in (0, 1, None):
            tag = 'event' if channel is None else f'ch{channel}'
            for name, offset in ring.items():
                result.append((f'gpi{instance}.{tag}.{name}', context(instance, channel) + offset))
            if channel is not None:
                for index in range(4):
                    result.append((f'gpi{instance}.{tag}.scratch{index}',
                                   context(instance, channel) + 0x60 + index * 4))
        for name, offset in {'irq_type': 0x23080, 'irq_mask': 0x23088,
                             'ch_irq': 0x23090, 'event_irq': 0x23094,
                             'global_irq': 0x23100, 'general_irq': 0x23118,
                             'error_log': 0x23200}.items():
            result.append((f'gpi{instance}.{name}', register(instance, offset)))
    require(all(SE_BASE <= a < SE_BASE + 0x4000 or 0xA04000 <= a < 0xA5C000
                for _, a in result), 'survey exceeds ACPI resource')
    return result


def decode_survey(reads):
    expected = dict(survey_plan())
    seen = {}
    for row in reads:
        name, address, value = row['name'], int(row['address'], 0), row['value']
        require(name in expected and address == expected[name], 'unplanned register in capture')
        require(name not in seen, 'duplicate register in capture')
        require(type(value) is int and 0 <= value <= 0xffffffff, 'bad register value')
        seen[name] = value
    require(seen.keys() == expected.keys(), 'incomplete ownership survey')
    instances = []
    for instance in range(6):
        prefix = f'gpi{instance}.'
        channels = []
        for channel in (0, 1):
            c = prefix + f'ch{channel}.'
            state = (seen[c + 'config'] >> 20) & 15
            scratch = seen[c + 'scratch0']
            channels.append(dict(channel=channel, state=state, seid=scratch & 7,
                                 protocol=(scratch >> 4) & 15, pair=(scratch >> 16) & 31,
                                 ring_base=seen[c + 'base_low'] | seen[c + 'base_high'] << 32,
                                 ring_bytes=seen[c + 'length']))
        event_state = (seen[prefix + 'event.config'] >> 20) & 15
        instances.append(dict(instance=instance, channels=channels, event_state=event_state,
                              appears_unallocated=event_state == 0 and all(c['state'] == 0 for c in channels),
                              routes_ic10=any(c['state'] != 0 and c['seid'] == SEID and
                                             c['protocol'] == I2C_PROTOCOL for c in channels)))
    return dict(instances=instances, dma_launch_admitted=False,
                remaining=['exclusive ownership grant', 'stream 0xcb6 DMA translation',
                           'cache maintenance and DMA arena', 'bounded allocation/restore qualification'])


def tre(*words):
    require(len(words) == 4 and all(0 <= w <= 0xffffffff for w in words), 'bad TRE words')
    return struct.pack('<4I', *words)


@dataclass(frozen=True)
class Timing:
    low: int
    high: int
    cycle: int
    divider: int

    @classmethod
    def observed(cls, master_clock, scl_counters):
        require(master_clock & 1, 'serial engine clock disabled')
        timing = cls((scl_counters >> 10) & 1023, (scl_counters >> 20) & 1023,
                     scl_counters & 1023, (master_clock >> 4) & 4095)
        timing.config()
        return timing

    def config(self):
        require(all(0 < v < 256 for v in (self.low, self.high, self.cycle)), 'bad SCL counters')
        require(0 < self.divider < 4096, 'bad clock divider')
        return tre(self.low | self.high << 8 | self.cycle << 16 | 3 << 24,
                   0, self.divider, 0x00220001)


def dma(address, length):
    require(0 <= address < 1 << 64 and 0 < length < 1 << 24, 'bad DMA range')
    require(address + length <= 1 << 64, 'DMA overflow')
    return tre(address & 0xffffffff, address >> 32, length, 0x00100200)


def go(read=False, stretch=False, length=1):
    # Linux I2C_WRITE=1 / I2C_READ=2. Read GO links to the RX channel;
    # it has no TX DMA TRE, which would produce an unintended write cycle.
    return tre((2 if read else 1) | EC_ADDRESS << 8 | int(stretch) << 26,
               0, length, 0x00200800 if read else 0x00200001)


def request_bytes(ec_register):
    require(ec_register in (FAN_HIGH, FAN_LOW), 'only ACPI fan RPM bytes allowed')
    return bytes((0x52, ec_register >> 8, ec_register & 255, 1, 0, 0))


@dataclass(frozen=True)
class Arena:
    """IOVAs, never inferred from CPU physical addresses. All rings are 4 KiB-local."""
    tx: int
    rx: int
    event: int
    request: int
    selector: int
    result: int
    ring_bytes: int = 256
    event_bytes: int = 1024

    def validate(self):
        ranges = []
        for name, length in [('tx', self.ring_bytes), ('rx', self.ring_bytes),
                             ('event', self.event_bytes), ('request', 6), ('selector', 1), ('result', 1)]:
            address = getattr(self, name)
            require(type(address) is int and 0 < address < 1 << 64, 'invalid IOVA')
            require(address + length <= 1 << 64, 'IOVA overflow')
            if name in ('tx', 'rx', 'event'):
                require(length >= 128 and length & (length - 1) == 0 and
                        address % length == 0, 'ring size/alignment')
                require(address >> 32 == (address + length - 1) >> 32, 'doorbell 4 GiB crossing')
            for begin, end in ranges:
                require(address + length <= begin or address >= end, 'overlapping DMA resources')
            ranges.append((address, address + length))


class RingReader:
    """Bounded transfer engine for an already-owned, started, empty GPI pair.

    Backend contract: time_us/read32/write32/read_dma/write_dma/clean/invalidate/
    barrier/stop_requested. MMIO and DMA hooks must themselves have finite
    bounds. The reader stops both channels but never frees the arena.
    This implementation deliberately does not allocate a firmware GPI instance.
    """
    def __init__(self, backend, instance, arena, timing, *, max_us=50000, max_polls=10000):
        arena.validate()
        require(0 < max_us <= 250000 and 0 < max_polls <= 100000, 'unbounded transfer')
        self.b, self.instance, self.a, self.timing = backend, instance, arena, timing
        context(instance)
        self.max_us, self.max_polls = max_us, max_polls
        self.tx_pos = self.rx_pos = self.ev_pos = 0
        self.submitted = False
        self.pinned = True
        self.events = []
        self.stop_evidence = None

    def admit(self):
        proof = self.b.lease_evidence()
        require(proof.get('exclusive') is True and proof.get('dma_mapping_qualified') is True and
                proof.get('cache_maintenance_qualified') is True and proof.get('stream_id') == STREAM_ID,
                'missing exclusive DMA/cache lease')
        require(proof.get('instance') == self.instance and proof.get('arena') == asdict(self.a),
                'lease does not cover this instance and DMA arena')
        for ch, base in ((0, self.a.tx), (1, self.a.rx)):
            c = context(self.instance, ch)
            cfg = self.b.read32(c)
            require((cfg >> 20) & 15 == 2 and cfg >> 24 == 16 and cfg & 7 == 2,
                    'channel is not started GPI TRE16')
            require((cfg >> 3) & 1 == (1 if ch == 0 else 0), 'channel direction mismatch')
            require((cfg >> 14) & 31 == 0, 'wrong event-ring index')
            require(self.b.read32(c + 0x60) == ((1 - ch) << 16 | I2C_PROTOCOL << 4 | SEID),
                    'channel route mismatch')
            require(self.b.read32(c + 4) == self.a.ring_bytes, 'channel ring length mismatch')
            for low in (8, 16, 24):
                require(self.b.read32(c + low) | self.b.read32(c + low + 4) << 32 == base,
                        'channel ring not empty at admitted base')
        c = context(self.instance)
        cfg = self.b.read32(c)
        require((cfg >> 20) & 15 == 1 and cfg >> 24 == 16 and cfg & 15 == 2,
                'event ring not allocated GPI TRE16')
        require(self.b.read32(c + 4) == self.a.event_bytes, 'event ring length mismatch')
        for low in (8, 16):
            require(self.b.read32(c + low) | self.b.read32(c + low + 4) << 32 == self.a.event,
                    'event ring not empty at admitted base')
        require(self.b.read32(SE_BASE + 0x40) == 0, 'IC10 busy')
        require(self.b.read32(SE_BASE + 0x64) & 1 and self.b.read32(SE_BASE + 0x258) & 1,
                'IC10 not in observed GPI mode')
        require(self.timing == Timing.observed(self.b.read32(SE_BASE + 0x48),
                                              self.b.read32(SE_BASE + 0x278)),
                'timing differs from current firmware configuration')
        require(self.b.read32(register(self.instance, 0x23090)) == 0 and
                self.b.read32(register(self.instance, 0x23094)) == 0, 'pending control command IRQ')
        self._errors()

    def _errors(self):
        require(not self.b.stop_requested(), 'operator stop')
        for offset in (0x23100, 0x23118):
            require(self.b.read32(register(self.instance, offset)) == 0, 'GPI error IRQ')

    def _queue(self, channel, entries):
        position = self.tx_pos if channel == 0 else self.rx_pos
        base = self.a.tx if channel == 0 else self.a.rx
        require(len(entries) < self.a.ring_bytes // 16, 'ring would overrun')
        terminal = None
        for entry in entries:
            require(len(entry) == 16, 'malformed TRE')
            terminal = base + position
            self.b.write_dma(terminal, entry)
            self.b.clean(terminal, 16)
            position = (position + 16) % self.a.ring_bytes
        self.b.barrier()
        if channel == 0:
            self.tx_pos = position
        else:
            self.rx_pos = position
        self.submitted = True  # uncertain MMIO return still pins the arena
        self.b.write32(register(self.instance, 0x22000 + 8 * channel), (base + position) & 0xffffffff)
        return terminal

    def _wait(self, expected):
        deadline = self.b.time_us() + self.max_us
        pending = dict(expected)
        for _ in range(self.max_polls):
            self._errors()
            require(self.b.time_us() < deadline, 'transfer deadline')
            c = context(self.instance)
            rp = self.b.read32(c + 16) | self.b.read32(c + 20) << 32
            require(self.a.event <= rp < self.a.event + self.a.event_bytes and rp % 16 == 0,
                    'invalid event producer pointer')
            while self.a.event + self.ev_pos != rp:
                self._errors()
                require(self.b.time_us() < deadline, 'event-drain deadline')
                address = self.a.event + self.ev_pos
                self.b.invalidate(address, 16)
                self.b.barrier()
                raw = self.b.read_dma(address, 16)
                require(len(raw) == 16, 'short event DMA read')
                pointer, length_code, status, kind, channel = struct.unpack('<QIHBB', raw)
                length, code = length_code & 0xffffff, length_code >> 24
                self.events.append(dict(pointer=pointer, length=length, code=code,
                                        status=status, kind=kind, channel=channel))
                require(kind == 0x22 and code == 2 and status == 0, 'unexpected completion/event status')
                require(channel in pending, 'stale or duplicate completion')
                require(pending[channel] == (pointer, length), 'completion pointer/length mismatch')
                del pending[channel]
                self.ev_pos = (self.ev_pos + 16) % self.a.event_bytes
                # Return the element just consumed, not the next unread one.
                self.b.barrier()
                self.b.write32(register(self.instance, 0x22100), address & 0xffffffff)
            self.b.write32(register(self.instance, 0x230c0), 1)
            if not pending:
                # RX completion alone cannot prove the linked TX GO retired.
                for channel, base, position in ((0, self.a.tx, self.tx_pos), (1, self.a.rx, self.rx_pos)):
                    c = context(self.instance, channel)
                    pointer = self.b.read32(c + 16) | self.b.read32(c + 20) << 32
                    require(pointer == base + position, 'channel has unretired TREs')
                return
        raise Refused('poll budget exhausted')

    def _byte(self, ec_register):
        payload = request_bytes(ec_register)
        self.b.write_dma(self.a.request, payload)
        self.b.clean(self.a.request, len(payload))
        start = self.tx_pos
        self._queue(0, [self.timing.config(), go(length=6), dma(self.a.request, 6)])
        self._wait({0: (self.a.tx + (start + 32) % self.a.ring_bytes, 6)})
        # The preceding completion must have retired the STOP-terminated write.
        require(self.b.read32(SE_BASE + 0x40) == 0, 'request transaction did not become idle')
        self.b.write_dma(self.a.selector, b'\x52')
        self.b.write_dma(self.a.result, b'\xa5')
        self.b.clean(self.a.selector, 1)
        self.b.clean(self.a.result, 1)
        rx_start, tx_start = self.rx_pos, self.tx_pos
        self._queue(1, [dma(self.a.result, 1)])  # arm RX before read GO
        self._queue(0, [go(stretch=True), dma(self.a.selector, 1), go(read=True)])
        self._wait({0: (self.a.tx + (tx_start + 16) % self.a.ring_bytes, 1),
                    1: (self.a.rx + rx_start, 1)})
        require(self.b.read32(SE_BASE + 0x40) == 0, 'response transaction did not become idle')
        self.b.invalidate(self.a.result, 1)
        self.b.barrier()
        raw = self.b.read_dma(self.a.result, 1)
        require(len(raw) == 1, 'short fan response')
        return raw[0]

    def _stop_pair(self):
        evidence = dict(command_completions=[False, False], states=[None, None], ic10_idle=False)
        deadline = self.b.time_us() + 250000
        try:
            for channel in (0, 1):
                require(self.b.time_us() < deadline, 'pair stop deadline')
                require(self.b.read32(register(self.instance, 0x23090)) == 0, 'ambiguous prior control command')
                self.b.write32(register(self.instance, 0x23008), 2 << 24 | channel)
                for _ in range(self.max_polls):
                    if self.b.time_us() >= deadline:
                        break
                    irq = self.b.read32(register(self.instance, 0x23090))
                    state = (self.b.read32(context(self.instance, channel)) >> 20) & 15
                    evidence['states'][channel] = state
                    require(irq & ~(1 << channel) == 0, 'unowned control completion')
                    if irq & (1 << channel):
                        require(state == 3, 'STOP completion has wrong state')
                        self.b.write32(register(self.instance, 0x230a0), 1 << channel)
                        evidence['command_completions'][channel] = True
                        break
                require(evidence['command_completions'][channel], 'STOP command uncertain; do not retry')
            evidence['ic10_idle'] = self.b.read32(SE_BASE + 0x40) == 0
        except Exception as exc:
            evidence['error'] = str(exc)
        return evidence

    def read_rpm(self):
        self.admit()
        try:
            hi = self._byte(FAN_HIGH)
            lo = self._byte(FAN_LOW)
            hi_again = self._byte(FAN_HIGH)
            require(hi == hi_again, 'torn RPM sample')
            return dict(rpm=hi << 8 | lo, bytes=[hi, lo, hi_again],
                        cooling_qualified=False, hardware_qualified=False)
        finally:
            # Owned pair only; a command timeout is never retried. The caller
            # must retain the lease and memory when stop proof is incomplete.
            if self.submitted:
                evidence = self._stop_pair()
                self.stop_evidence = evidence
                self.pinned = not (evidence.get('command_completions') == [True, True] and
                                   evidence.get('states') == [3, 3] and evidence.get('ic10_idle') is True)
                require(not self.pinned, 'pair stop unqualified; retain DMA arena and ownership')
