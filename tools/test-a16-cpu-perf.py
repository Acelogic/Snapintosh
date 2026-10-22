#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests for tools/a16-cpu-perf.py against a modelled SCMI platform. No A16 access.

  python3 tools/test-a16-cpu-perf.py

The fake proxy holds q1n1's EL2 page tables, the UEFI memory map, the pdp0
mailbox registers and an SCMI platform that answers on the channel 0 shared
memory when the doorbell is written, as the PDP firmware would. A16Platform
answers as the A16's PDP0 did on 2026-10-18 (gen1-query-2.json: BASE 2.0
Qualcomm/PDP0, message 5 DENIED, PERF 4.0, the real level tables, limits and
LEVEL_GET 0 until set, flags 0xea000000), plus fastchannels with a doorbell, and
one of four hypotheses for why a Prime request does not stick. The CPU model
runs CPU_ON targets and hold CPUs whose clock follows the domain's level.
"""
import copy
import json
from pathlib import Path
import runpy
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
perf = runpy.run_path(str(ROOT / 'tools' / 'a16-cpu-perf.py'), run_name='cpu_perf')
Refused = perf['Refused']
HEAP = 0xb9e00000
DOORBELL, RX_STAT, RX_CLEAR, RX_EN = perf['DOORBELL'], perf['RX_STAT'], perf['RX_CLEAR'], perf['RX_EN']
SHM, P2A = perf['A2P_SHMEM'], perf['P2A_SHMEM']
T = perf['TRANSPORTS']
CPUCP = T['cpucp']
rx = perf['rx']
MAIR = 0x00000000ff440400          # attr0 Device-nGnRnE, attr1 Device-nGnRE, attr2 Normal-NC, attr3 WB
ATTR = dict(device=0, normal_nc=2, cached=3)
KHZ = {0: [384000, 1209600, 2208000, 3110400, 3609600],
       1: [384000, 1209600, 2400000, 3600000, 4416000, 4992000],
       2: [384000, 1209600, 2400000, 3600000, 4416000, 4992000]}
LIMITS = {0: (3609600, 384000), 1: (4416000, 384000), 2: (4416000, 384000)}
# The A16's tables (gen1-query-2.json), kHz by index.
A16_KHZ = {0: [355200, 902400, 1056000, 1209600, 1363200, 1516800, 1651200, 1785600, 1939200, 2073600, 2208000,
               2342400, 2496000, 2630400, 2764800, 2918400, 3072000, 3225600, 3398400, 3552000, 3609600],
           1: [355200, 883200, 1132800, 1382400, 1593600, 1785600, 1996800, 2188800, 2400000, 2611200, 2822400,
               3033600, 3225600, 3436800, 3628800, 3801600, 3955200, 4128000, 4281600, 4454400, 4800000, 5011200]}
A16_KHZ[2] = list(A16_KHZ[1])
A16_SUSTAINED = {0: 20, 1: 19, 2: 19}
A16_BOOT = {0: 16, 1: 13, 2: 13}          # what the cores ran at before any request
PDP_TX = perf['PDP_TX']
# As PDP0 described them after v50 (gen1-v50-query.json): sets in the domain's own PDP mailbox, channel 3
# (level) and 4 (limits), data word then command word; gets in the shared receive block.
def fc_level_set(d): return PDP_TX[d] + 0x118                       # noqa: E302,E704
def fc_level_db(d): return PDP_TX[d] + 0x11c                        # noqa: E302,E704
def fc_level_get(d): return 0x17610148 + 8 * d                      # noqa: E302,E704
FC_DOORBELL = fc_level_db(1)


class FakeLink:
    def close(self):
        pass


class Platform:
    """The PDP side of SCMI: BASE and PERF on one a2p channel."""

    def __init__(self, v4=False, indexing=False, vendor=b'Qualcomm', protocols=(0x10, 0x11, 0x13, 0x19),
                 fail=None):
        self.v4, self.indexing, self.vendor, self.protocols = v4, indexing, vendor, protocols
        self.fail = fail or {}
        self.level = {d: (1 if indexing else KHZ[d][1]) for d in KHZ}
        self.sets = []

    def answer(self, protocol, message, payload):
        key = (protocol, message)
        if key in self.fail:
            return self.fail[key], []
        d = payload[0] if payload else None
        if protocol == 0x10:
            if message == 0:
                return 0, [0x20000]
            if message == 1:
                return 0, [len(self.protocols) - 1 | 1 << 8]
            if message == 3:
                return 0, list(struct.unpack('<4I', self.vendor.ljust(16, b'\0')))
            if message == 4:
                return -1, []
            if message == 5:
                return 0, [0x20002]
            if message == 6:
                ids = bytes(p for p in self.protocols if p != 0x10)
                return 0, [len(ids)] + list(struct.unpack(f'<{(len(ids) + 3) // 4}I', ids.ljust(4 * ((len(ids) + 3) // 4), b'\0')))
        if protocol == 0x13:
            if message == 0:
                return 0, [0x40000 if self.v4 else 0x30000]
            if message == 1:
                return 0, [3, 0, 0, 0]
            if d not in KHZ:
                return -4, []
            if message == 3:
                flags = (1 << 31) | (1 << 30) | ((1 << 25) if self.indexing else 0)
                name = struct.unpack('<4I', f'cpu-cl{d}'.encode().ljust(16, b'\0'))
                return 0, [flags, 1000, KHZ[d][-2], KHZ[d][-2] if not self.indexing else len(KHZ[d]) - 2, *name]
            if message == 4:
                start = payload[1]
                levels = KHZ[d][start:start + 4]
                entries = []
                for i, khz in enumerate(levels):
                    index = start + i
                    entries += [index if self.indexing else khz, 1000 + i, 30]
                    if self.v4:
                        entries += [khz, index]
                return 0, [len(levels) | (len(KHZ[d]) - start - len(levels)) << 16] + entries
            if message == 6:
                top, bottom = LIMITS[d]
                if self.indexing:
                    top, bottom = KHZ[d].index(top), KHZ[d].index(bottom)
                return 0, [top, bottom]
            if message == 7:
                self.sets.append((d, payload[1]))
                self.level[d] = payload[1]
                return 0, []
            if message == 8:
                return 0, [self.level[d]]
        return -1, []


class A16Platform:
    """The A16's PDP firmware as measured, with switches for what is not yet known.

    PDP0's server (protocol answers below) reports domains PDP0-PDP2 and acts on
    PDP0 requests. For PDP1/PDP2:
      pdp0_msg  'ignored' (what the hardware did), 'active' (applies while the
                cluster has a CPU on) or 'limits' (applies while active, after
                LIMITS_SET);
      pdp_fc    the LEVEL_SET fastchannel in the cluster's own PDP mailbox applies
                (Linux's route);
      own       the cluster's own PDP channel (--channel pdp1/pdp2) applies a
                LEVEL_SET; own_fc: that server describes fastchannels too.
    The cluster's LEVEL_GET fastchannel reads 255 until something applies a
    level to it. after_v50: LEVEL_GET 21 and limits 22/0 on PDP1/PDP2."""

    def __init__(self, pdp0_msg='ignored', pdp_fc=False, own=False, own_fc=False, drop_on_idle=False,
                 after_v50=False, fc=True, doorbell=None):
        self.pdp0_msg, self.pdp_fc, self.own, self.own_fc = pdp0_msg, pdp_fc, own, own_fc
        self.drop_on_idle, self.fc, self.doorbell = drop_on_idle, fc, doorbell
        self.requested = {d: 21 if after_v50 and d else 0 for d in A16_KHZ}
        self.limits = {d: (22, 0) if after_v50 and d else (0, 0) for d in A16_KHZ}
        self.applied = dict(A16_BOOT)
        self.published = {0}
        self.active = set()
        self.sets = []
        self.own_sets = []
        self.proxy = None

    def mhz(self, d):
        return A16_KHZ[d][self.applied[d]] / 1000

    def publish(self):
        for d in A16_KHZ:
            self.proxy.put32(fc_level_get(d), self.applied[d] if d in self.published else 255)

    def apply(self, d, level):
        self.applied[d] = level
        self.published.add(d)
        if self.proxy:
            self.publish()

    def idle(self, d):
        self.active.discard(d)
        if self.drop_on_idle and d:
            self.apply(d, A16_BOOT[d])

    def mmio_write(self, address, value):
        """A write inside a PDP transmit block other than the SCMI doorbells."""
        for d, tx in PDP_TX.items():
            if address == tx + 0x11c:
                level = self.proxy.get32(tx + 0x118)
                if value == 0xf and (d == 0 or self.pdp_fc):
                    self.requested[d] = level
                    self.apply(d, level)
                return True
            if address in (tx + 0x118, tx + 0x120, tx + 0x124):
                self.proxy.put32(address, value)
                return True
        return False

    def domain_attributes(self, d, name):
        return [0xea000000, 0, A16_KHZ[d][A16_SUSTAINED[d]], A16_SUSTAINED[d],
                *struct.unpack('<4I', name.encode().ljust(16, b'\0'))]

    def describe_levels(self, d, start):
        entries = []
        for i, khz in enumerate(A16_KHZ[d][start:start + 3]):         # three fit in a 0x60-byte channel
            entries += [khz, 1000 * (start + i + 1), 30, khz, start + i]
        n = len(entries) // 5
        return [n | (len(A16_KHZ[d]) - start - n) << 16] + entries

    def describe_fc(self, d, message):
        tx = PDP_TX[d]
        if message == 7:
            return 0, [5, 0, tx + 0x118, 0, 4, self.doorbell or tx + 0x11c, 0, 0xf, 0, 0, 0]
        if message == 5:
            return 0, [5, 0, tx + 0x120, 0, 4, tx + 0x124, 0, 0xf, 0, 0, 0]
        if message == 8:
            return 0, [0, 0, fc_level_get(d), 0, 4, 0, 0, 0, 0, 0, 0]
        if message == 6:
            return 0, [0, 0, 0x17610160 + 8 * d, 0, 4, 0, 0, 0, 0, 0, 0]
        return -1, []

    def answer(self, protocol, message, payload):
        """PDP0's server."""
        d = payload[0] if payload else None
        if protocol == 0x10:
            return {0: (0, [0x20000]), 1: (0, [2 | 1 << 8]),
                    3: (0, list(struct.unpack('<4I', b'Qualcomm'.ljust(16, b'\0')))),
                    4: (0, list(struct.unpack('<4I', b'PDP0'.ljust(16, b'\0')))), 5: (-3, []),
                    6: (0, [2, 0x8013])}.get(message, (-1, []))
        if protocol != 0x13:
            return -1, []
        if message == 0:
            return 0, [0x40000]
        if message == 1:
            return 0, [3 | 2 << 16, 0, 0, 0]
        if message == 2:
            return (0, [1]) if d in (5, 6, 7, 8) else (-4, [])
        if d not in A16_KHZ:
            return -4, []
        if message == 3:
            return 0, self.domain_attributes(d, f'PDP{d}')
        if message == 4:
            return 0, self.describe_levels(d, payload[1])
        if message == 5:
            if d == 0:
                self.limits[d] = (payload[1], payload[2])
            elif self.pdp0_msg == 'limits':
                self.limits[d] = (payload[1], payload[2])
            return 0, []                              # PDP1/PDP2 left 22/0 after LIMITS_SET 19/0
        if message == 6:
            return 0, list(self.limits[d])
        if message == 7:
            self.sets.append((d, payload[1]))
            active = d in self.active
            if d == 0 or (self.pdp0_msg == 'active' and active) or \
                    (self.pdp0_msg == 'limits' and active and self.limits[d] != (0, 0)):
                self.requested[d] = payload[1]
                self.apply(d, payload[1])
            return 0, []                              # accepted either way, as PDP1/PDP2 were
        if message == 8:
            return 0, [self.requested[d]]
        if message == 11:
            return self.describe_fc(d, payload[1]) if self.fc else (-1, [])
        return -1, []

    def own_answer(self, cluster):
        """The cluster's own PDP server, on its own channel: one domain, named after it."""
        def answer(protocol, message, payload):
            if protocol == 0x10:
                return {0: (0, [0x20000]), 1: (0, [1 | 1 << 8]),
                        3: (0, list(struct.unpack('<4I', b'Qualcomm'.ljust(16, b'\0')))),
                        4: (0, list(struct.unpack('<4I', f'PDP{cluster}'.encode().ljust(16, b'\0')))),
                        5: (-3, []), 6: (0, [1, 0x13])}.get(message, (-1, []))
            if protocol != 0x13:
                return -1, []
            if message == 0:
                return 0, [0x40000]
            if message == 1:
                return 0, [1 | 2 << 16, 0, 0, 0]
            if message == 2:
                return (0, [1]) if payload[0] in (5, 6, 7, 8) else (-4, [])
            if payload[0] != 0:
                return -4, []
            if message == 3:
                return 0, self.domain_attributes(cluster, f'PDP{cluster}')
            if message == 4:
                return 0, self.describe_levels(cluster, payload[1])
            if message == 6:
                return 0, list(self.limits[cluster])
            if message == 7:
                self.own_sets.append((cluster, payload[1]))
                if self.own:
                    self.requested[cluster] = payload[1]
                    self.apply(cluster, payload[1])
                return 0, []
            if message == 8:
                return 0, [self.requested[cluster]]
            if message == 11:
                return self.describe_fc(cluster, payload[1]) if self.own_fc else (-1, [])
            return -1, []
        return answer


def stub_words(mpidr, windows, ticks, ghz, hold, final):
    """A report as tools/a16-cpu-stub.S writes it."""
    words = [0] * (512 if hold else 64)
    words[:26] = [0x3130_4b4c_4355_5043 if final else 0, 0, 8, mpidr, 0x512f0010, 19200000, 0x1030560a,
                  0x41013000, 0, 0, 6, 0x41013001, 6, 0x41013000, 0, 0, 6, windows, ticks, 0, 0, int(final),
                  1 << 27, 0, len(ghz), len(ghz)]
    for i, g in enumerate(ghz):
        dt = ticks + 3
        words[32 + 2 * i:34 + 2 * i] = [dt, round(g * 1e9 * dt / 19200000)]
    return words


class FakeProxy:
    P_DC_CVAC, P_DC_CIVAC, P_DC_IVAC = 0x308, 0x30A, 0x303

    def __init__(self, platform=None, shm_kind='normal_nc', unmap=(), read_only=(), behaviour=None,
                 rx_enable=1, status=1, cpucp_status=0, pdp_status=1):
        self.ram = {}
        self.link = FakeLink()
        self.exceptions = []
        self.platform = platform or Platform()
        self.b = dict(behaviour or {})
        self.mmio = {perf['GICD'] + 0x100 + 4 * (i // 32): 0 for i in (60, 66)}
        self.mmio.update({perf['GICD'] + 0x200 + 4 * (i // 32): 0 for i in (60, 66)})
        for t in T.values():
            self.mmio.update({rx(t, 'stat'): 0, rx(t, 'enable'): rx_enable, rx(t, 'map'): 2**64 - 1})
        self.bells = {perf['doorbell'](t): t for t in T.values()}
        own = getattr(self.platform, 'own_answer', None)
        self.servers = {name: own(int(name[3])) if own and name in ('pdp1', 'pdp2') else self.platform.answer
                        for name in T}
        self.writes, self.ops, self.syncs, self.calls = [], [], [], []
        self.strict = []
        self.tables = 0x90000000
        self.next_table = self.tables + 0x1000
        for va in sorted(set(perf['PAGES'].values())):
            aliases = {n for n, v in perf['PAGES'].items() if v == va}     # pdp0/pdp1/pdp2 shmem share a page
            if aliases & set(unmap):
                continue
            kind = shm_kind if 'pdp0_shmem' in aliases else 'device'
            self.map(va, ATTR[kind], not aliases & set(read_only))
        self.put32(SHM + 4, status)
        self.put32(P2A + 4, 1)
        self.put32(CPUCP['shmem'] + 4, cpucp_status)
        for name in ('pdp1', 'pdp2'):
            if pdp_status == 'garbage':
                for i in range(7):
                    self.put32(T[name]['shmem'] + 4 * i, 0x9e3779b9 * (i + 1))
            else:
                self.put32(T[name]['shmem'] + 4, pdp_status)
        self.cpus = {}
        if hasattr(self.platform, 'proxy'):
            self.platform.proxy = self
            self.platform.publish()
        self.memory_map = 0x91000000
        entries = [(0, 0x81e00000, 0x200), (7, 0x80000000, 0x1e00), (11, 0x17000000, 0x10000)]
        raw = b''.join(struct.pack('<I4xQQQQ', k, start, start, pages, 0x8000000000000001) for k, start, pages in entries)
        self.writemem(self.memory_map, raw)
        self.map_size = len(raw)

    # Page tables, the way q1n1 inherits them from UEFI: 4 KiB granule, T0SZ 20.
    def map(self, va, attr, writable):
        table = self.tables
        for shift in (39, 30, 21):
            slot = table + ((va >> shift) & 511) * 8
            desc = self.get64(slot)
            if not desc:
                desc = self.next_table | 3
                self.next_table += 0x1000
                self.put64(slot, desc)
            table = desc & 0x0000fffffffff000
        self.put64(table + ((va >> 12) & 511) * 8, va | 3 | attr << 2 | 1 << 10 | (0 if writable else 1 << 7))

    def regime(self, proxy, blob):
        return dict(sctlr='0x30c5183d', tcr='0x80803514', ttbr0=hex(self.tables), mair=hex(MAIR), hcr='0x80000000')

    def get64(self, a):
        return int.from_bytes(bytes(self.ram.get(a + i, 0) for i in range(8)), 'little')

    def put64(self, a, v):
        self.writemem(a, struct.pack('<Q', v))

    def get32(self, a):
        return int.from_bytes(bytes(self.ram.get(a + i, 0) for i in range(4)), 'little')

    def put32(self, a, v):
        self.writemem(a, struct.pack('<I', v & 0xffffffff))

    def bootinfo(self):
        return dict(current_el=2, heap_base=HEAP, heap_size=64 << 20, stage_generation=1, image_base=0xb0000000,
                    image_size=16 << 20, stage_base=0xb0000000, stage_size=16 << 20,
                    timer_hz=19200000, memory_map=self.memory_map, memory_map_size=self.map_size,
                    memory_map_stride=40)

    def readmem(self, address, size, live=False):
        return bytes(self.ram.get(address + i, 0) for i in range(size))

    def writemem(self, address, data):
        for i, byte in enumerate(data):
            self.ram[address + i] = byte

    def flush_code(self, address, size):
        self.ops.append(('flush', address, size))

    def ic_ivau(self, address, size):
        self.ops.append(('ic_ivau', address, size))

    def nop(self):
        pass

    def request(self, op, address, size):
        self.ops.append((op, address, size))
        if op == self.P_DC_IVAC:
            for mpidr, cpu in self.cpus.items():
                if cpu['hold'] and address == cpu['report'] and not cpu['final']:
                    self.window(mpidr, cpu)

    # CPUs started through the stub's CPU_ON entries; their clock follows the domain.
    def window(self, mpidr, cpu):
        stop = self.get64(cpu['report'] + 4096)
        if not stop and len(cpu['ghz']) < cpu['windows']:
            cpu['ghz'].append(self.platform.mhz(mpidr >> 16 & 0xff) / 1000)
        if stop or len(cpu['ghz']) >= cpu['windows']:
            self.finish(mpidr, cpu)
        else:
            self.put_words(cpu['report'], stub_words(mpidr, cpu['windows'], cpu['ticks'], cpu['ghz'], True, False))

    def finish(self, mpidr, cpu):
        if not cpu['hold']:
            cpu['ghz'] = [self.platform.mhz(mpidr >> 16 & 0xff) / 1000] * cpu['windows']
        cpu['final'] = True
        self.put_words(cpu['report'], stub_words(mpidr, cpu['windows'], cpu['ticks'], cpu['ghz'], cpu['hold'], True))
        self.platform.idle(mpidr >> 16 & 0xff)

    def put_words(self, address, words):
        self.writemem(address, struct.pack(f'<{len(words)}Q', *words))

    def get_exc_count(self):
        return self.b.get('exc_count', 0)

    def serror_strict(self, on):
        self.strict.append(on)

    def read32(self, address):
        if address in self.mmio:
            return self.mmio[address] & 0xffffffff
        return self.get32(address)

    def read8(self, address):
        return self.ram.get(address, 0)

    def read16(self, address):
        return self.get32(address) & 0xffff

    def read64(self, address):
        if address in self.mmio:
            return self.mmio[address]
        return self.get64(address)

    def write32(self, address, value):
        self.writes.append((address, value, 32))
        if address in self.bells:
            self.doorbell(self.bells[address])
        elif hasattr(self.platform, 'mmio_write') and self.platform.mmio_write(address, value):
            pass
        elif 0x17000000 <= address < 0x20000000 and not any(
                t['shmem'] <= address < t['shmem'] + t['size'] for t in T.values()):
            raise AssertionError(f'unexpected MMIO write {address:#x}')
        else:
            self.put32(address, value)

    def write64(self, address, value):
        self.writes.append((address, value, 64))
        for t in T.values():
            if address == rx(t, 'clear'):
                self.mmio[rx(t, 'stat')] &= ~value
                return
        raise AssertionError(f'unexpected 64-bit write {address:#x}')

    def call(self, address, *args, timeout=None):
        self.calls.append((address,) + args)
        entry = address - (HEAP + perf['clock_tool']['CODE_AT'])
        if entry == 12:
            self.syncs.append(args)
            return 0x5c
        if entry in (4, 16):
            out, mpidr, report = args
            windows, ticks = struct.unpack('<QQ', self.readmem(report + 136, 16))
            self.cpus[mpidr] = dict(hold=entry == 16, report=report, windows=windows, ticks=ticks, ghz=[],
                                    final=False)
            self.platform.active.add(mpidr >> 16 & 0xff)
            self.put_words(out, [0, 8, mpidr, report, address + 0x300, 1, 0, 0])
            return 0
        if entry == 8:
            out, mpidr = args
            cpu = self.cpus.get(mpidr)
            if cpu and not cpu['final']:
                if cpu['hold']:
                    self.window(mpidr, cpu)
                else:
                    self.finish(mpidr, cpu)
            state = 0 if cpu and not cpu['final'] else 1
            self.put_words(out, [state, 0, mpidr, 0, 0, 1, 0, 0])
            return 0
        raise AssertionError(f'unexpected call {address:#x}')

    def doorbell(self, t):
        if self.b.get('silent'):
            return
        name = next(n for n, x in T.items() if x is t)
        SHM = t['shmem']
        header = self.get32(SHM + 24)
        length = self.get32(SHM + 20)
        payload = [self.get32(SHM + 28 + 4 * i) for i in range((length - 4) // 4)]
        status, words = self.servers[name]((header >> 10) & 0xff, header & 0xff, payload)
        if self.b.get('token_mismatch'):
            header ^= 1 << 18
        self.put32(SHM + 24, header)
        self.put32(SHM + 20, 8 + 4 * len(words))
        self.put32(SHM + 28, status)
        for i, w in enumerate(words):
            self.put32(SHM + 32 + 4 * i, w)
        self.put32(SHM + 4, 1 | (2 if self.b.get('channel_error') else 0))
        self.mmio[rx(t, 'stat')] |= 1


class Args:
    def __init__(self, mode, channel='pdp0', **kw):
        self.mode, self.channel = mode, channel
        self.allow_boost, self.cpu, self.level, self.settle, self.fc_record = False, 0x10000, None, 8, None
        self.always_fc = self.try_limits = False
        self.__dict__.update(kw)


def inventory():
    cpus = [dict(mpidr=hex(m), flags=1, efficiency_class=int(m >= 0x10000), affinity_state=int(m != 0))
            for m in (0x0, 0x100, 0x10000, 0x20000)]
    return dict(boot_mpidr='0x0', cpus=cpus, features={'0xc4000003': 0, '0x84000002': 0, '0xc4000004': 0})


def cpu_context(proxy):
    clock = perf['clock_tool']
    scratch = clock['Scratch'](proxy, clock['scratch_ranges'](HEAP, b'\0' * 64, 0x200))
    quiet = dict(sleep=lambda s: None, poll=0)
    return dict(scratch=scratch, timer_hz=19200000, inventory=lambda p: copy.deepcopy(inventory()),
                hold=quiet, measure=quiet)


def survey_record(proxy):
    record = dict(kind='survey', status='DONE', bootinfo=dict(stage_generation=1, heap_base=HEAP))
    result = perf['survey'](proxy, proxy.bootinfo(), b'', proxy.regime)
    record.update(result)
    record['kinds'] = {hex(perf['PAGES'][n]): p['kind'] for n, p in result['pages'].items() if p}
    return record


def execute(proxy, mode, prior, domains=(0, 1), channel='pdp0', cpu=None, fc_record=None, **kw):
    record = {}
    try:
        perf['execute'](Args(mode, channel, fc_record=fc_record, **kw), proxy, proxy.bootinfo(), prior, list(domains), b'', proxy.regime,
                        b'\0' * 64, record, lambda: None, clock_kw=dict(timeout=0.05, sleep=lambda s: None),
                        cpu=cpu)
    except Refused:
        record['status'] = 'FAILED'
        raise
    record.update(kind=mode, status='DONE', channel=channel, bootinfo=dict(stage_generation=1, heap_base=HEAP))
    return record


class Survey(unittest.TestCase):
    def test_survey_is_read_only_and_finds_the_channel_usable(self):
        proxy = FakeProxy()
        record = survey_record(proxy)
        self.assertEqual(proxy.writes, [])
        self.assertEqual(proxy.calls, [])
        self.assertTrue(record['verdict']['pdp0']['usable'], record['verdict'])
        self.assertEqual(record['verdict']['cpucp'], dict(usable=False, problems=['a2p shmem header: channel not FREE']))
        self.assertTrue(record['reads']['pdp0']['shmem']['free'])
        self.assertEqual(record['pages']['pdp0_tx']['kind'], 'device')
        self.assertEqual(record['pages']['pdp0_shmem']['kind'], 'normal-nc')
        self.assertEqual(record['uefi']['pdp0']['type'], 0)
        self.assertEqual(record['reads']['pdp0']['interrupt'], dict(intid=66, enabled=False, pending=False))
        self.assertEqual(record['reads']['cpucp']['interrupt']['intid'], 60)
        self.assertEqual(record['reads']['pdp0']['rx']['enable'], '0x1')

    def test_survey_problems(self):
        for kw, reason in [(dict(status=0), 'not FREE'), (dict(status=5), 'reserved'),
                           (dict(unmap=('pdp0_tx',)), 'pdp0_tx'), (dict(read_only=('pdp0_shmem',)), 'shared memory'),
                           (dict(unmap=('pdp0_shmem',)), 'shared memory'),
                           (dict(read_only=('pdp0_rx_status',)), 'pdp0_rx_status')]:
            record = survey_record(FakeProxy(**kw))
            self.assertFalse(record['verdict']['pdp0']['usable'], kw)
            self.assertIn(reason, ' '.join(record['verdict']['pdp0']['problems']), kw)

    def test_faulting_read_stops(self):
        with self.assertRaisesRegex(Refused, 'fault'):
            survey_record(FakeProxy(behaviour=dict(exc_count=1)))

    def test_walk_decodes_blocks_and_attributes(self):
        proxy = FakeProxy()
        regime = proxy.regime(None, None)
        got = perf['walk'](proxy.get64, regime, perf['DOORBELL'])
        self.assertEqual((got['pa'], got['kind'], got['writable']), (hex(perf['DOORBELL']), 'device', True))
        self.assertIsNone(perf['walk'](proxy.get64, regime, 0x40000000))
        self.assertEqual(perf['mair_kind'](0xff), 'normal-cached')


class Channel(unittest.TestCase):
    def setUp(self):
        self.proxy = FakeProxy()
        self.survey = survey_record(self.proxy)

    def test_constants_are_channel_zero_of_pdp0(self):
        self.assertEqual(DOORBELL, 0x19980104)
        self.assertEqual((SHM, P2A), (0x81e08780, 0x81e08600))
        self.assertEqual((perf['RX_STAT'], RX_CLEAR, RX_EN), (0x17614400, 0x17614800, 0x17614c00))
        self.assertEqual(perf['MAILBOX_INTID'], 66)

    def test_query_reads_base_and_every_domain(self):
        record = execute(self.proxy, 'query', self.survey)
        self.assertEqual(record['base']['vendor'], 'Qualcomm')
        self.assertIn('0x13', record['base']['protocol_ids'])
        self.assertEqual(record['perf']['domains'], 3)
        self.assertEqual([len(d['levels']) for d in record['domains']], [5, 6, 6])
        self.assertEqual(record['domains'][1]['limits'], dict(max=4416000, min=384000))
        self.assertEqual(record['domains'][1]['levels'][-1]['mhz'], 4992.0)
        self.assertEqual(record['domains'][0]['level'], 1209600)
        self.assertEqual(self.proxy.platform.sets, [])
        # Header encoding: message, protocol in 17:10, token in 27:18; type 0.
        first = next(w for a, w, _ in self.proxy.writes if a == SHM + 24)
        self.assertEqual(first & 0x3ffff, 0x10 << 10)
        self.assertEqual(record['transactions'][0]['status'], 'SUCCESS')

    def test_only_doorbell_and_rx_clear_are_mmio_writes(self):
        execute(self.proxy, 'query', self.survey)
        mmio = {a for a, _, _ in self.proxy.writes if not SHM <= a < SHM + 0x180}
        self.assertEqual(mmio, {DOORBELL, RX_CLEAR})
        self.assertTrue(all(v == 1 for a, v, w in self.proxy.writes if a == RX_CLEAR and w == 64))
        # The shmem is written only while FREE, and the doorbell follows a DSB SY.
        order = [('sync', s[2]) for s in self.proxy.syncs]
        self.assertTrue(order and all(op == 0 for _, op in order))

    def test_rx_clear_only_when_the_interrupt_is_enabled(self):
        proxy = FakeProxy(rx_enable=0)
        execute(proxy, 'query', survey_record(proxy))
        self.assertNotIn(RX_CLEAR, {a for a, _, _ in proxy.writes})

    def test_cached_shared_memory_is_cleaned_then_invalidated(self):
        proxy = FakeProxy(shm_kind='cached')
        record = survey_record(proxy)
        self.assertEqual(record['pages']['pdp0_shmem']['kind'], 'normal-cached')
        proxy.ops.clear()
        execute(proxy, 'query', record)
        self.assertTrue(proxy.syncs and all(op == 1 for _, _, op in proxy.syncs))
        self.assertIn((proxy.P_DC_CIVAC, SHM, 64), proxy.ops)

    def test_set_max_requests_the_highest_level_within_limits(self):
        query = execute(self.proxy, 'query', self.survey)
        record = execute(self.proxy, 'set-max', query)
        # 3110400 is d0's sustained level: 3609600 above it is boost; d1's limit and sustained are 4416000.
        self.assertEqual(self.proxy.platform.sets, [(0, 3110400), (1, 4416000)])
        self.assertEqual([c['before'] for c in record['changes']], [1209600, 1209600])
        self.assertFalse(any(c['before_unset'] for c in record['changes']))
        self.assertTrue(all(c['verified'] for c in record['changes']))
        self.assertEqual(record['changes'][1]['target_mhz'], 4416.0)
        restore = execute(self.proxy, 'restore', record)
        self.assertEqual(self.proxy.platform.sets[-2:], [(0, 1209600), (1, 1209600)])
        self.assertTrue(all(c['verified'] for c in restore['changes']))

    def test_level_indexing_mode_sets_indices(self):
        proxy = FakeProxy(platform=Platform(v4=True, indexing=True))
        query = execute(proxy, 'query', survey_record(proxy))
        self.assertTrue(query['domains'][0]['level_indexing'])
        self.assertEqual(query['domains'][1]['levels'][4]['mhz'], 4416.0)
        execute(proxy, 'set-max', query, domains=(0, 1, 2))
        self.assertEqual(proxy.platform.sets, [(0, 3), (1, 4), (2, 4)])        # d0 sustained index 3

    def test_no_completion_leaves_the_channel_uncertain_and_busy(self):
        query = execute(self.proxy, 'query', self.survey)
        self.proxy.b['silent'] = True
        with self.assertRaisesRegex(Refused, 'no completion'):
            execute(self.proxy, 'set-max', query)
        self.assertEqual(self.proxy.get32(SHM + 4), 0)
        self.proxy.b['silent'] = False
        with self.assertRaisesRegex(Refused, 'not FREE'):
            execute(self.proxy, 'set-max', query)

    def test_mismatched_or_failed_responses_stop(self):
        for behaviour, reason in [(dict(token_mismatch=True), 'response header'),
                                  (dict(channel_error=True), 'channel error')]:
            proxy = FakeProxy(behaviour=behaviour)
            with self.assertRaisesRegex(Refused, reason):
                execute(proxy, 'query', survey_record(proxy))

    def test_first_scmi_error_stops_set_max(self):
        query = execute(self.proxy, 'query', self.survey)
        self.proxy.platform.fail[(0x13, 7)] = -3
        with self.assertRaisesRegex(Refused, 'DENIED'):
            execute(self.proxy, 'set-max', query)
        self.assertEqual(self.proxy.platform.sets, [])

    def test_vendor_protocol_and_domain_checks(self):
        for platform, reason in [(Platform(vendor=b'ARM'), 'vendor'), (Platform(protocols=(0x10, 0x11)), 'performance')]:
            proxy = FakeProxy(platform=platform)
            with self.assertRaisesRegex(Refused, reason):
                execute(proxy, 'query', survey_record(proxy))
        query = execute(self.proxy, 'query', self.survey)
        with self.assertRaisesRegex(Refused, 'unknown domains'):
            execute(self.proxy, 'set-max', query, domains=(5,))

    def test_records_from_another_boot_or_kind_refused(self):
        other = json.loads(json.dumps(self.survey))
        other['bootinfo']['stage_generation'] = 2
        with self.assertRaisesRegex(Refused, 'another generation'):
            execute(self.proxy, 'query', other)
        with self.assertRaisesRegex(Refused, 'completed query'):
            execute(self.proxy, 'set-max', self.survey)

    def test_attribute_change_since_survey_refused(self):
        survey = json.loads(json.dumps(self.survey))
        survey['kinds'][hex(perf['PAGES']['pdp0_shmem'])] = 'normal-cached'
        with self.assertRaisesRegex(Refused, 'attributes changed'):
            execute(self.proxy, 'query', survey)

    def test_mmio_guard(self):
        access = perf['Access'](self.proxy, {}, transport=T['pdp0'])
        for address in (perf['PDP0_TX'] + 0x10c, perf['doorbell'](CPUCP), rx(CPUCP, 'clear'), RX_EN):
            with self.assertRaisesRegex(Refused, 'not the channel 0'):
                access.mmio_write(address, 1, 32)          # 0x1998010c: channel 1, dpm_crazy_mode on Windows
        self.assertEqual(self.proxy.writes, [])

    def test_cpucp_channel_is_opt_in_and_uses_only_its_own_registers(self):
        proxy = FakeProxy(cpucp_status=1)
        record = survey_record(proxy)
        self.assertTrue(record['verdict']['cpucp']['usable'])
        query = execute(proxy, 'query', record, channel='cpucp')
        self.assertEqual(query['perf']['domains'], 3)
        mmio = {a for a, _, _ in proxy.writes if not CPUCP['shmem'] <= a < CPUCP['shmem'] + CPUCP['size']}
        self.assertEqual(mmio, {perf['doorbell'](CPUCP), rx(CPUCP, 'clear')})
        self.assertEqual(perf['doorbell'](CPUCP), 0x18830104)
        with self.assertRaisesRegex(Refused, 'used channel cpucp'):
            execute(proxy, 'set-max', query, channel='pdp0')
        with self.assertRaisesRegex(Refused, 'cpucp unusable'):
            execute(FakeProxy(), 'query', survey_record(FakeProxy()), channel='cpucp')


class Rules(unittest.TestCase):
    def test_boost_only_when_allowed(self):
        proxy = FakeProxy()
        query = execute(proxy, 'query', survey_record(proxy))
        execute(proxy, 'set-max', query, allow_boost=True)
        self.assertEqual(proxy.platform.sets, [(0, 3609600), (1, 4416000)])     # d1 still capped by its limit

    def test_target_level_rules(self):
        info = dict(domain=1, level_indexing=True, sustained_level=19, limits=dict(max=0, min=0),
                    levels=[dict(index=i, perf=k) for i, k in enumerate(A16_KHZ[1])])
        self.assertEqual(perf['target_level'](info), 19)                     # unset limits: sustained, not 0
        self.assertEqual(perf['target_level'](info, allow_boost=True), 21)
        info['limits'] = dict(max=21, min=0)
        self.assertEqual(perf['target_level'](info), 19)
        info['limits'] = dict(max=15, min=2)
        self.assertEqual(perf['target_level'](info), 15)
        info['limits'] = dict(max=0, min=0)
        info['sustained_level'] = 40
        with self.assertRaisesRegex(Refused, 'sustained level 40'):
            perf['target_level'](info)


class A16(unittest.TestCase):
    """The A16's PDP firmware as it answered (gen1 and after v50), with the routes still open."""

    def setUp(self):
        self.proxy = FakeProxy(platform=A16Platform())
        self.query = execute(self.proxy, 'query', survey_record(self.proxy))

    def test_query_tolerates_denied_message_5_and_records_fastchannels(self):
        base = self.query['base']
        self.assertEqual((base['vendor'], base['sub_vendor']), ('Qualcomm', 'PDP0'))
        self.assertEqual(base['implementation_error'], 'DENIED')
        self.assertEqual(base['protocol_ids'], ['0x13', '0x80'])
        self.assertEqual(self.query['perf_message_attributes']['8'], '0x1')
        d1 = self.query['domains'][1]
        self.assertEqual((d1['name'], d1['sustained_level'], d1['level'], d1['limits']), ('PDP1', 19, 0,
                                                                                         dict(max=0, min=0)))
        self.assertEqual(d1['levels'][19]['mhz'], 4454.4)
        fc = d1['fastchannels_described']['level_set']
        self.assertEqual((fc['addr'], fc['size'], fc['doorbell'], fc['db_addr'], fc['db_set']),
                         ('0x1a980118', 4, True, '0x1a98011c', '0xf'))
        checks = d1['fastchannel_checks']
        self.assertTrue(checks['level_set']['ok'] and checks['level_get']['ok'], checks)
        self.assertEqual((checks['level_set']['doorbell_channel'], checks['level_set']['doorbell_name']),
                         (3, 'pcc_core0'))
        for name in ('limits_set', 'limits_get'):
            self.assertFalse(checks[name]['ok'])
            self.assertIn('Linux refuses', ' '.join(checks[name]['problems']))
        self.assertEqual(d1['fastchannel_values']['level_get'], 255)                # nothing publishes PDP1
        self.assertEqual(self.query['domains'][0]['fastchannel_values']['level_get'], 16)
        self.assertEqual(self.proxy.platform.sets, [])

    def test_set_max_requests_sustained_and_reports_what_did_not_stick(self):
        record = execute(self.proxy, 'set-max', self.query, domains=(0, 1, 2))
        self.assertEqual(self.proxy.platform.sets, [(0, 20), (1, 19), (2, 19)])    # not 0 (355 MHz), not boost
        self.assertEqual([c['after'] for c in record['changes']], [20, 0, 0])
        self.assertEqual(record['unverified'], ['PDP1', 'PDP2'])
        self.assertTrue(all(c['before_unset'] for c in record['changes']))
        with self.assertRaisesRegex(Refused, 'rollback is a cold boot'):
            execute(self.proxy, 'restore', record)
        self.assertEqual(len(self.proxy.platform.sets), 3)                         # nothing written back

    def test_after_v50_defaults_give_the_sustained_target(self):
        proxy = FakeProxy(platform=A16Platform(after_v50=True))
        query = execute(proxy, 'query', survey_record(proxy))
        d1 = query['domains'][1]
        self.assertEqual((d1['level'], d1['limits']), (21, dict(max=22, min=0)))
        self.assertEqual(perf['target_level'](d1), 19)                 # 0-22 is unrestricted: sustained, not boost
        self.assertEqual(perf['target_level'](d1, allow_boost=True), 21)

    def test_fc_read_is_passive(self):
        self.proxy.writes.clear()
        self.proxy.calls.clear()
        record = execute(self.proxy, 'fc-read', self.query)
        self.assertEqual(self.proxy.writes, [])          # no shmem, doorbell or fastchannel write
        self.assertEqual(self.proxy.calls, [])           # and no stub call
        values = {name: v['values']['level_get'] for name, v in record['fastchannels'].items()}
        self.assertEqual(values, dict(PDP0=16, PDP1=255, PDP2=255))

    def run_hold(self, platform, channel='pdp0', fc_record=None, **kw):
        proxy = FakeProxy(platform=platform)
        survey = survey_record(proxy)
        query = execute(proxy, 'query', survey, channel=channel)
        record = execute(proxy, 'prime-hold', query, channel=channel, cpu=cpu_context(proxy),
                         fc_record=fc_record(proxy, survey) if fc_record else None, **kw)
        proxy.record = record
        return proxy, record['experiment']

    def test_route_pdp0_message_while_active(self):
        proxy, exp = self.run_hold(A16Platform(pdp0_msg='active'))
        self.assertEqual([s['step'] for s in exp['steps']], ['baseline', 'message', 'end'])
        parts = {p['step']: p for p in exp['segments']}
        self.assertAlmostEqual(parts['baseline']['ghz'], 3.4368, places=3)
        self.assertTrue(parts['message']['raised'] and parts['message']['reached'])
        self.assertEqual(exp['verdict']['effective_step'], 'message')
        self.assertTrue(exp['verdict']['kept_after_power_off'])
        self.assertEqual({w[0] for w in proxy.record['mmio_writes']}, {hex(DOORBELL), hex(RX_CLEAR)})
        self.assertEqual(exp['steps'][1]['fc_level_get'], 19)                      # published once applied

    def test_route_dropped_when_the_cluster_powers_off(self):
        _, exp = self.run_hold(A16Platform(pdp0_msg='active', drop_on_idle=True))
        self.assertEqual(exp['verdict']['effective_step'], 'message')
        self.assertFalse(exp['verdict']['kept_after_power_off'])
        self.assertIn('re-assert after each power-up', exp['verdict']['summary'])

    def test_route_linux_fastchannel_in_the_clusters_own_mailbox(self):
        proxy, exp = self.run_hold(A16Platform(pdp_fc=True))
        self.assertEqual([s['step'] for s in exp['steps']], ['baseline', 'message', 'fastchannel', 'end'])
        parts = {p['step']: p for p in exp['segments']}
        self.assertFalse(parts['message']['raised'])
        self.assertTrue(parts['fastchannel']['raised'] and parts['fastchannel']['reached'])
        self.assertEqual(exp['verdict']['effective_step'], 'fastchannel')
        written = [(a, v) for a, v, w in proxy.writes if PDP_TX[1] <= a < PDP_TX[1] + 0x8000]
        self.assertEqual(written, [(0x1a980118, 19), (0x1a98011c, 0xf)])          # level, then doorbell
        self.assertEqual([s['fc_level_get'] for s in exp['steps']], [255, 255, 19, 19])
        self.assertTrue(exp['verdict']['kept_after_power_off'])

    def test_route_pdp0_limits_then_message(self):
        _, exp = self.run_hold(A16Platform(pdp0_msg='limits', fc=False), try_limits=True)
        self.assertEqual(exp['fastchannel_skipped'], ['not described: NOT_SUPPORTED'])
        self.assertEqual(exp['verdict']['effective_step'], 'limits+message')

    def test_v50_result_nothing_on_pdp0_points_at_the_clusters_own_channel(self):
        proxy, exp = self.run_hold(A16Platform(after_v50=True), try_limits=True)
        self.assertEqual([s['step'] for s in exp['steps']],
                         ['baseline', 'message', 'fastchannel', 'limits+message', 'end'])
        self.assertIsNone(exp['verdict']['effective_step'])
        self.assertIn('--channel pdp1', exp['verdict']['summary'])
        self.assertTrue(all(abs(s['ghz'] - 3.4368) < 0.001 for s in exp['hold']['samples']))
        self.assertEqual(exp['steps'][-2]['limits'], dict(max=22, min=0))           # LIMITS_SET ignored, as seen

    def test_route_own_pdp_channel(self):
        proxy, exp = self.run_hold(A16Platform(own=True), channel='pdp1')
        self.assertEqual((exp['domain'], exp['name']), (0, 'PDP1'))                # its only domain
        self.assertEqual(exp['verdict']['effective_step'], 'message')
        self.assertEqual(proxy.platform.own_sets, [(1, 19)])
        self.assertEqual(proxy.platform.sets, [])                                  # PDP0's server untouched
        self.assertEqual({w[0] for w in proxy.record['mmio_writes']}, {hex(perf['doorbell'](T['pdp1']))})
        self.assertNotIn(RX_CLEAR, {a for a, _, _ in proxy.writes})                # shared rx block: never cleared
        self.assertTrue(exp['verdict']['kept_after_power_off'])

    def test_route_own_channel_with_pdp0s_fastchannel_description(self):
        def pdp0_query(proxy, survey):
            return execute(proxy, 'query', survey)
        proxy, exp = self.run_hold(A16Platform(pdp_fc=True), channel='pdp1', fc_record=pdp0_query)
        self.assertEqual(exp['fastchannel_source'], 'pdp0 query, domain PDP1')
        self.assertEqual(exp['verdict']['effective_step'], 'fastchannel')
        self.assertIn((0x1a98011c, 0xf, 32), proxy.writes)

    def test_own_channel_refused_unless_the_survey_finds_it_free(self):
        proxy = FakeProxy(platform=A16Platform(own=True), pdp_status='garbage')
        survey = survey_record(proxy)
        self.assertFalse(survey['verdict']['pdp1']['usable'])
        self.assertIn('a2p shmem header', ' '.join(survey['verdict']['pdp1']['problems']))
        with self.assertRaisesRegex(Refused, 'pdp1 unusable'):
            execute(proxy, 'query', survey, channel='pdp1')
        self.assertFalse([a for a, _, _ in proxy.writes if a == perf['doorbell'](T['pdp1'])])

    def test_fastchannel_doorbells_only_on_the_clusters_own_performance_channels(self):
        cases = [(PDP_TX[0] + 0x11c, "outside the domain's own PDP transmit block"),     # PDP0's mailbox
                 (PDP_TX[1] + 0x10c, 'dpm_crazy_mode'), (PDP_TX[1] + 0x114, 'debug_log'),
                 (PDP_TX[1] + 0x104, 'scmi_apss_agent'), (PDP_TX[1] + 0x124, "not channel 4's data word"),
                 (PDP_TX[1] + 0x118, 'not a 32-bit channel command word'), (0x17000000, 'outside')]
        for doorbell, reason in cases:
            proxy, exp = self.run_hold(A16Platform(pdp_fc=True, doorbell=doorbell))
            self.assertIn(reason, ' '.join(exp['fastchannel_skipped']), hex(doorbell))
            self.assertFalse([a for a, _, _ in proxy.writes if PDP_TX[1] <= a < PDP_TX[1] + 0x8000], hex(doorbell))
            self.assertIsNone(exp['verdict']['effective_step'])

    def test_boost_and_undescribed_levels_refused(self):
        with self.assertRaisesRegex(Refused, 'boost level'):
            execute(self.proxy, 'prime-hold', self.query, cpu=cpu_context(self.proxy), level=20)
        with self.assertRaisesRegex(Refused, 'not described'):
            execute(self.proxy, 'prime-hold', self.query, cpu=cpu_context(self.proxy), level=30)
        self.assertEqual(self.proxy.cpus, {})

    def test_segments_skip_the_window_a_step_ran_in(self):
        ghz = [3.4] * 6 + [3.9] + [4.45] * 8
        steps = [dict(step='baseline', before_window=5, after_window=5),
                 dict(step='message', before_window=6, after_window=6), dict(step='end', before_window=15)]
        parts = perf['segments'](ghz, steps, 4454.4)
        self.assertEqual(parts[0], dict(step='baseline', windows=6, ghz=3.4))
        self.assertEqual((parts[1]['windows'], parts[1]['ghz'], parts[1]['raised'], parts[1]['reached']),
                         (8, 4.45, True, True))


if __name__ == '__main__':
    unittest.main()
