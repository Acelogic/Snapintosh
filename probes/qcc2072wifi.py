# SPDX-License-Identifier: MIT
"""Opt-in QCC2072 Wi-Fi passthrough for the SnapintoshQCC2072 kext: reservation, admission record,
tree node, stage 2, params, live admission and the stop.

The monitor side is compat/qcc2072-wifi.h, compiled only with -DSNAP_QCC2072_WIFI=1; a launch
without SNAP_QCC2072_WIFI changes nothing here or there (cycle.py installed-fresh --qcc2072-wifi).

Guest-visible layout (IPA == PA, the monitor's identity stage 2), in the node's reg order, which is
the provider's mapDeviceMemoryWithIndex order (drivers/snap-qcc2072/src/qcc2072-provider.cpp):
  0 BAR0           0x7800_0000 + 1 MiB   Device-nGnRE, RW, XN
  1 DMA arena      0xdc00_0000 + 64 MiB  Normal non-cacheable, RW, XN (IOVA == PA, below 4 GiB)
  2 BAR2           0x7820_0000 + 4 KiB   Device-nGnRE, RW, XN
  3 endpoint ECAM  0x7_8010_0000 + 4 KiB Device-nGnRE, read-only; the monitor performs command
                                         register stores of 2 and 6 (compat/qcc2072-wifi.h)
  4 control page   0xe000_0000 + 4 KiB   Normal non-cacheable, read-only: the 256-byte provider record
Everything else stays absent at stage 2. The reservation [0xdc00_0000, 0xe000_4000) (the arena and the
control page's 16 KiB guest page) is excluded from every other placement.

Failure modes, written before the code (the monitor's are in compat/qcc2072-wifi.h):
  L1. A default launch changes: nothing here runs, and nothing is appended, without the flag.
  L2. Inputs: the firmware container, the exact ASUS board ELF or the regulatory database differ
      from what the provider verifies (prepare_image's SHA-256s). Refused before anything is built.
  L3. The reservation is not Conventional in this boot's UEFI map, or overlaps q1n1 (image, heap,
      DMA, stage, panel, GPU arena), the guest/monitor/ANS region or the EFI asset cache.
  L4. The arena is not identity-mapped read/write by this boot's PCIe SMMU stage 2 for SID 0x40100
      (the firmware's table can differ per boot): a bounded read-only walk, refused otherwise.
  L5. The endpoint is not the ASUS QCC2072, its BARs moved, bus mastering is already on, its link is
      down, or it is not in PBL/EDL (a previous run left firmware running): refused; cold boot.
  L6. The command register write (memory decode only) does not read back.
  L7. The arena or control page keeps stale lines or old bytes: every byte is written (zero, then the
      assets), cleaned and invalidated to PoC, and the record and asset edges read back.
  L8. Generation/cookie reuse: the cookie is fresh per launch; the record is bound to q1n1's stage
      generation; the offline fixture is used only for image checks.
  L9. After the guest stops, the card keeps DMA into memory nobody reserves any more: the launcher
      turns bus mastering off (stop()) once the stopped state is preserved, never before (a proxy
      fault would freeze the capture), and --quiesce confirms it; the next attempt needs a cold boot.
  L10. The tree: a child or parent range overlapping arm-io's, a second node claiming the match, a
      property name past Apple's 31 characters. Refused, all or nothing.
Not provided: DMA isolation. The card translates through the firmware's shared stage-2 table, which
maps all low Conventional RAM and guest RAM; the record's proof bits are the host harness's.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct

PARAMS_WORDS = 12                        # compat/qcc2072-wifi.h QCC2072_WIFI_PARAMS_WORDS
MAGIC = int.from_bytes(b'SNAPQCC1', 'little')
F_ENABLE = 1
DEFINE = '-DSNAP_QCC2072_WIFI=1'
ENV = 'SNAP_QCC2072_WIFI'                # the loader half of DEFINE (both or neither)
INPUTS_ENV = 'SNAP_QCC2072_INPUTS'       # directory holding the three staged inputs
BUNDLE = 'org.snapintosh.driver.SnapintoshQCC2072'
MATCH = 'snapintosh,qcc2072'             # the kext's IONameMatch
NODE = '/device-tree/arm-io/snap-qcc2072'
ADMISSION = 'snapintosh,qcc2072-admission'
CHILD_OFFSET = 0x7_0000_0000             # arm-io child space, as probes/i2cinput.py
SLOT = 0x4000                            # the guest's page: one arm-io ranges triple per window

PCI_ID, PCI_SUBSYSTEM, SID = 0x111217cb, 0xe14f105b, 0x40100
ECAM_PA, ECAM_BYTES = 0x7_8010_0000, 0x1000
BAR0_PA, BAR0_BYTES = 0x7800_0000, 0x10_0000
BAR2_PA, BAR2_BYTES = 0x7820_0000, 0x1000
DMA_PA, DMA_BYTES = 0xdc00_0000, 0x400_0000
CONTROL_PA, CONTROL_BYTES = 0xe000_0000, 0x1000
RESERVATION = (DMA_PA, CONTROL_PA + SLOT)
COMMAND, CMD_MEMORY, CMD_MASTER = 4, 0x2, 0x4
# drivers/snap-qcc2072/src/qcc2072-provider-record.h and qcc2072-dma.h
RECORD_MAGIC, RECORD_BYTES, PROOFS, CACHE_LINE = 0x31304e574f434351, 256, 31, 64
IPA_LIMIT = 1 << 36
# shadow/stage2.h: S2AP | MemAttr | SH inner | AF, and S2_XN.
S2_DEVICE_RW, S2_DEVICE_RO, S2_NC_RW, S2_NC_RO, S2_XN = 0x7C4, 0x744, 0x7D4, 0x754, 1 << 54
# (name, pa, bytes, access, stage-2 low attributes, description), in reg order.
WINDOWS = (('bar0', BAR0_PA, BAR0_BYTES, 'rw', S2_DEVICE_RW, 'QCC2072 BAR0 (Device-nGnRE)'),
           ('dma', DMA_PA, DMA_BYTES, 'rw', S2_NC_RW, 'QCC2072 DMA arena (Normal-NC)'),
           ('bar2', BAR2_PA, BAR2_BYTES, 'rw', S2_DEVICE_RW, 'QCC2072 BAR2 (Device-nGnRE)'),
           ('ecam', ECAM_PA, ECAM_BYTES, 'ro', S2_DEVICE_RO,
            'QCC2072 ECAM page (Device-nGnRE; command stores by the monitor)'),
           ('control', CONTROL_PA, CONTROL_BYTES, 'ro', S2_NC_RO, 'QCC2072 control page (Normal-NC)'))
# The provider's prepare_image hashes; names are the staged files' names.
INPUTS = {'firmware-2.bin': '4c6a1be1f5bfad76319755ff76904abb21c4c7ece5293cc5f33a20b1f4c35254',
          'board.elf': 'eeb1311ec3e4955323f1b62247d4caeaad1f292938e2077dfdc466d6a4d3be86',
          'regdb.bin': '9752107372bdefcd2dd11a394459f8eaec0166a3ca1e680f10ad9a243ac2d360'}
# Where they were verified on 2026-10-21 (re/host-proxy/run.py); prepare copies them, hash-checked.
_REPO = Path(__file__).resolve().parents[1]   # board and regdb: this checkout's build/ outputs
SOURCES = {'firmware-2.bin': str(Path(os.environ.get('QCC2072_FIRMWARE_DIR', _REPO / 'build/fw-qcc2072'))
                                 / 'firmware-2.bin'),                     # linux-firmware ath12k/WCN7850/hw2.0
           'board.elf': str(_REPO / 'build/qcc2072-board-provenance-20261019/board-verified.elf'),
           'regdb.bin': str(_REPO / 'build/qcc2072-runtime-20261021/final-v2/regdb-reconstructed.bin')}
FIXTURE_COOKIE = 0x5143435746495845      # offline image checks only; a launch draws a fresh one
SMMU = 0x15480000                        # pcie_smmu (GUEST-WIFI-20261019.md)
DDR = (0x8000_0000, 0x8b_9100_0000)      # table reads stay in DRAM (walk-s2-low.py)
SHA = lambda b: hashlib.sha256(b).hexdigest()


@dataclass(frozen=True)
class Spec:
    """One admission: the record's generation and cookie, and the guest range it excludes."""
    generation: int
    cookie: int
    guest_pa: int
    guest_bytes: int

    def __post_init__(self):
        if not 1 <= self.generation < 1 << 32:
            raise ValueError('QCC2072 admission needs a q1n1 stage generation >= 1')
        if not (self.cookie & 1) or not 0 < self.cookie < 1 << 63:
            raise ValueError('QCC2072 cookie must be odd, nonzero and below 2**63')
        lo, hi = self.guest_pa, self.guest_pa + self.guest_bytes
        if self.guest_bytes <= 0 or lo & 0xfff or hi > IPA_LIMIT or (lo < RESERVATION[1] and RESERVATION[0] < hi):
            raise ValueError('QCC2072 guest exclusion range is invalid or overlaps the reservation')


def fixture_spec(phys_base):
    """The offline image's admission: generation 1, a fixed cookie, the guest from PHYS_BASE up."""
    return Spec(1, FIXTURE_COOKIE, phys_base, IPA_LIMIT - phys_base)


def load_inputs(directory):
    """The three staged inputs, each exactly the bytes the provider verifies."""
    out = {}
    for name, digest in INPUTS.items():
        data = (Path(directory) / name).read_bytes()
        if SHA(data) != digest:
            raise ValueError(f'QCC2072 input {name} differs from the provider\'s pin')
        out[name] = data
    return out


def stage_inputs(dest, sources=None):
    """Copy the pinned inputs into dest (prepare), hash-checked before and after; never overwrites."""
    dest = Path(dest)
    dest.mkdir()
    for name, digest in INPUTS.items():
        data = Path((sources or SOURCES)[name]).read_bytes()
        if SHA(data) != digest:
            raise ValueError(f'QCC2072 input {name} differs from the provider\'s pin')
        with (dest / name).open('xb') as stream:
            stream.write(data)
    return {name: SHA((dest / name).read_bytes()) for name in INPUTS}


def offsets(inputs):
    """make_record's layout: the container at 0, then board and regdb, each 4 KiB aligned."""
    up = lambda x: (x + 4095) & ~4095
    fw, bd, rg = (len(inputs[n]) for n in INPUTS)
    board = up(fw)
    regdb = up(board + bd)
    allocate = up(regdb + rg)
    if allocate >= DMA_BYTES:
        raise ValueError('QCC2072 inputs do not fit the arena')
    return dict(firmware=(0, fw), board=(board, bd), regdb=(regdb, rg), allocate=allocate)


def record(spec, inputs):
    """The 256-byte provider record (re/host-proxy/run.py make_record), the control page's bytes."""
    o = offsets(inputs)
    words = [RECORD_MAGIC, 1, RECORD_BYTES, 1, spec.generation, spec.cookie, PCI_ID, PCI_SUBSYSTEM, SID, PROOFS,
             BAR0_PA, BAR0_BYTES, BAR2_PA, BAR2_BYTES, ECAM_PA,
             DMA_PA, DMA_PA, DMA_BYTES, CONTROL_PA,
             *o['firmware'], *o['board'], *o['regdb'],
             o['allocate'], spec.guest_pa, spec.guest_bytes, CACHE_LINE, 0, 0, 0]
    assert len(words) == 32
    return struct.pack('<32Q', *words)


def arena_payload(inputs):
    """Every byte of the 64 MiB arena: the assets at their offsets, zero elsewhere."""
    o = offsets(inputs)
    payload = bytearray(DMA_BYTES)
    for name, key in zip(INPUTS, ('firmware', 'board', 'regdb')):
        at, n = o[key]
        payload[at:at + n] = inputs[name]
    return bytes(payload)


def control_payload(record_bytes):
    """The control page's 16 KiB guest page: the record, then zero."""
    if len(record_bytes) != RECORD_BYTES:
        raise ValueError('QCC2072 record is 256 bytes')
    return record_bytes + bytes(SLOT - RECORD_BYTES)


@dataclass(frozen=True)
class Grant:
    """What the image build needs: the admission and the record built from it."""
    spec: Spec
    record: bytes


def grant(spec, inputs):
    return Grant(spec, record(spec, inputs))


def params_words(grant_):
    """struct qcc2072_wifi_params, in field order (appended after struct params and any i2c block)."""
    if grant_ is None:
        return []
    words = [MAGIC, F_ENABLE]
    for _, pa, size, *_ in WINDOWS:
        words += [pa, pa + size]
    assert len(words) == PARAMS_WORDS
    return words


def rows(words):
    """compat/qcc2072-wifi.h qcc2072_wifi_valid: [(lo, hi)] of a valid block, or None."""
    if len(words) != PARAMS_WORDS or words[0] != MAGIC or words[1] != F_ENABLE:
        return None
    pairs = list(zip(words[2::2], words[3::2]))
    expected = [(pa, pa + size) for _, pa, size, *_ in WINDOWS]
    return pairs if pairs == expected else None


def stage2_ranges(grant_):
    """The monitor's passthrough, as probes/xnuboot.stage2_ranges lists ranges."""
    if grant_ is None:
        return []
    return [(pa, pa + size, access, what) for _, pa, size, access, _, what in WINDOWS]


def stage2_audit_ranges(words):
    """The windows as tools/audit-secondary-runtime.py audits a stopped monitor's stage 2:
    [(lo, hi, low attributes, upper attributes)] of the appended words (none if invalid)."""
    if rows(words) is None:
        return []
    return [(pa, pa + size, low, S2_XN) for _, pa, size, _, low, _ in WINDOWS]


def triples():
    """The arm-io ranges triples appended for the node: one 16 KiB-rounded span per window."""
    return [(CHILD_OFFSET + pa, pa, (size + SLOT - 1) & ~(SLOT - 1)) for _, pa, size, *_ in WINDOWS]


def prepare_tree(dt, grant_, owned=()):
    """Add the ranges and the node, all or nothing. `owned` is [(base, size)] of the guest's memory and
    the monitor's: no window may touch it."""
    from appledt import Property
    if grant_ is None or len(grant_.record) != RECORD_BYTES:
        raise ValueError('QCC2072 node needs an admission record')
    bus = '/device-tree/arm-io'
    raw = dt.nodes[bus]['ranges']
    if raw.placeholder or len(raw.value) % 24:
        raise ValueError('arm-io ranges are not resolved (child, parent, span) triples')
    ranges = list(struct.iter_unpack('<3Q', raw.value))
    add = triples()
    for child, parent, span in add:
        for c, p, s in ranges:
            if child < c + s and c < child + span:
                raise ValueError(f'arm-io child range {child:#x} overlaps {c:#x}')
            if parent < p + s and p < parent + span:
                raise ValueError(f'arm-io parent range {parent:#x} overlaps {p:#x}')
        for base, size in owned:
            if parent < base + size and base < parent + span:
                raise ValueError('a QCC2072 window overlaps guest or monitor memory')
    if NODE in dt.nodes:
        raise ValueError(f'{NODE} already exists')
    for path, props in dt.nodes.items():
        compatible = props.get('compatible')
        if compatible is not None and MATCH.encode() in bytes(compatible.value).split(b'\0'):
            raise ValueError(f'{path} already claims {MATCH}')
    dt.put(bus, 'ranges', raw.value + b''.join(struct.pack('<3Q', *r) for r in add))
    props = {
        'name': NODE.rsplit('/', 1)[1].encode() + b'\0',
        'compatible': MATCH.encode() + b'\0',
        'reg': b''.join(struct.pack('<QQ', CHILD_OFFSET + pa, size) for _, pa, size, *_ in WINDOWS),
        ADMISSION: bytes(grant_.record),
    }
    dt.nodes[NODE] = {k: Property(k, v) for k, v in props.items()}
    dt.children[NODE] = []
    dt.children[bus].append(NODE)
    return dict(node=NODE, ranges=add, record_sha256=SHA(grant_.record))


# ---------------------------------------------------------------------------------------------- live
def _disjoint(lo, hi, ranges, what):
    for base, size in ranges:
        if size and lo < base + size and base < hi:
            raise ValueError(f'QCC2072 reservation overlaps {what} {base:#x}+{size:#x}')


def check_reservation(free_spans, occupied):
    """L3: the reservation inside one firmware-free span (Conventional minus q1n1's reservations) and
    clear of every other placement (guest/monitor/ANS region, EFI cache, panel, GPU arena)."""
    lo, hi = RESERVATION
    if not any(a <= lo and hi <= b for a, b in free_spans):
        raise ValueError('QCC2072 reservation is not inside one firmware-reported free span')
    _disjoint(lo, hi, occupied, 'an occupied range')


def mhi_snapshot(proxy):
    """MHI and BHI registers through BAR0 (memory decode on), as the host harness reads them."""
    names = dict(MHIREGLEN=0, MHIVER=8, BHIOFF=0x28, MHICTRL=0x38, MHISTATUS=0x48)
    s = {k: proxy.read32(BAR0_PA + o) for k, o in names.items()}
    if 0 < s['BHIOFF'] < 0x1000:
        s['BHI_EXECENV'] = proxy.read32(BAR0_PA + s['BHIOFF'] + 0x28)
    return s


def walk_smmu(proxy):
    """L4: a bounded read-only walk of SID 0x40100's stage 2 over the arena (walk-s2-low.py's rules)."""
    def read_table(at, size):
        if not (DDR[0] <= at and at + size <= DDR[1] and at % size == 0):
            raise ValueError(f'SMMU table pointer {at:#x} is outside DRAM')
        data = proxy.readmem(at, size)
        if len(data) != size:
            raise ValueError('short SMMU table read')
        return struct.unpack(f'<{size // 8}Q', data)
    if proxy.read32(SMMU + 32) != 13 or proxy.read32(SMMU + 36) != 13:
        raise ValueError('PCIe SMMU is not enabled with its queues')
    cfg = proxy.read32(SMMU + 0x88)
    if (cfg >> 16) & 3 != 1 or (cfg >> 6) & 31 != 8:
        raise ValueError('PCIe SMMU stream table is not two-level split 8')
    strtab = proxy.read64(SMMU + 0x80) & 0xfffffffffffc0
    l1d, = struct.unpack('<Q', proxy.readmem(strtab + (SID >> 8) * 8, 8))
    if not l1d & 31:
        raise ValueError('no stream-table L2 for SID 0x40100')
    ste_pa = (l1d & 0xfffffffffffc0) + (SID & 255) * 64
    ste = struct.unpack('<8Q', proxy.readmem(ste_pa, 64))
    if not ste[0] & 1 or (ste[0] >> 1) & 7 != 6:
        raise ValueError('SID 0x40100 STE is not valid stage-2-only')
    s2ttb = ste[3] & 0xffffffffff000
    l1 = read_table(s2ttb, 0x2000)
    blocks = []
    for ipa in range(DMA_PA, DMA_PA + DMA_BYTES, 1 << 21):
        d = l1[ipa >> 30]
        if not d & 1:
            raise ValueError(f'arena {ipa:#x}: level-1 entry invalid')
        if not d & 2:
            pa, attrs = (d & 0xfffffc0000000) | (ipa & ((1 << 30) - 1)), d & 0xfff0000000000fff
        else:
            e = read_table(d & 0xffffffffff000, 0x1000)[(ipa >> 21) & 511]
            if e & 3 != 1:
                raise ValueError(f'arena {ipa:#x}: not one 2 MiB block ({e:#x})')
            pa, attrs = e & 0xfffffffe00000, e & 0xfff0000000000fff
        if pa != ipa or attrs & 0xc0 != 0xc0 or not attrs & 0x400:
            raise ValueError(f'arena {ipa:#x}: not identity read/write ({pa:#x}, attrs {attrs:#x})')
        blocks.append(dict(ipa=hex(ipa), attrs=hex(attrs)))
    return dict(ste_pa=hex(ste_pa), ste=[hex(w) for w in ste], s2ttb=hex(s2ttb), blocks=blocks)


def admit(proxy, info, free_spans, occupied):
    """The live admission, before the image is built: reservation, SMMU, endpoint, command = memory
    decode only. Returns the record of what was observed; raises ValueError on any refusal."""
    out = dict(stage_generation=info['stage_generation'])
    check_reservation(free_spans, occupied)
    out['reservation'] = [hex(RESERVATION[0]), hex(RESERVATION[1])]
    ident = proxy.read32(ECAM_PA), proxy.read32(ECAM_PA + 0x2c)
    if ident != (PCI_ID, PCI_SUBSYSTEM):
        raise ValueError(f'not the ASUS QCC2072 module: {ident[0]:#x} {ident[1]:#x}')
    bars = [proxy.read32(ECAM_PA + o) for o in (0x10, 0x14, 0x18, 0x1c)]
    if bars != [BAR0_PA | 4, 0, BAR2_PA | 4, 0]:
        raise ValueError('QCC2072 BAR layout changed: ' + ' '.join(hex(b) for b in bars))
    before = proxy.read32(ECAM_PA + COMMAND) & 0xffff
    out['command_before'] = hex(before)
    if before & CMD_MASTER:
        raise ValueError('QCC2072 bus mastering is already on')
    out['smmu'] = walk_smmu(proxy)
    proxy.write16(ECAM_PA + COMMAND, CMD_MEMORY)
    after = proxy.read32(ECAM_PA + COMMAND) & 0xffff
    out['command_after'] = hex(after)
    if after != CMD_MEMORY:
        raise ValueError(f'QCC2072 command register reads {after:#x} after writing memory decode only')
    mhi = mhi_snapshot(proxy)
    out['mhi'] = {k: hex(v) for k, v in mhi.items()}
    if mhi['MHIREGLEN'] == 0xffffffff:
        raise ValueError('QCC2072 BAR0 reads all-ones: link down')
    if mhi.get('BHI_EXECENV') not in (0, 6) or mhi['MHISTATUS'] & 4:
        raise ValueError('QCC2072 is not in PBL/EDL (firmware already ran?): cold boot the A16')
    return out


def upload(proxy, grant_, inputs, writer):
    """L7: write every byte of the arena and the control page (writer = bootmedia.upload_auxiliary),
    clean and invalidate both to PoC, and read back the record and the assets' edges."""
    arena = arena_payload(inputs)
    control = control_payload(grant_.record)
    sent = writer(proxy, DMA_PA, arena) + writer(proxy, CONTROL_PA, control)
    proxy.request(proxy.P_DC_CIVAC, DMA_PA, DMA_BYTES)
    proxy.request(proxy.P_DC_CIVAC, CONTROL_PA, SLOT)
    o = offsets(inputs)
    checks = [(CONTROL_PA, control[:RECORD_BYTES]), (CONTROL_PA + SLOT - 4096, bytes(4096))]
    for at, n in (o['firmware'], o['board'], o['regdb']):
        checks += [(DMA_PA + at, arena[at:at + 4096]), (DMA_PA + at + n - 4096, arena[at + n - 4096:at + n])]
    checks += [(DMA_PA + o['allocate'], bytes(4096)), (DMA_PA + DMA_BYTES - 4096, bytes(4096))]
    for at, data in checks:
        if proxy.readmem(at, len(data)) != data:
            raise ValueError(f'QCC2072 upload did not verify at {at:#x}')
    return dict(sent_bytes=sent, record_sha256=SHA(grant_.record), arena_sha256=SHA(arena),
                verified=[hex(at) for at, _ in checks])


def stop(proxy):
    """L9: after the stopped state is preserved, bus mastering off (memory decode stays on), read back."""
    before = proxy.read32(ECAM_PA + COMMAND) & 0xffff
    proxy.write16(ECAM_PA + COMMAND, (before & ~CMD_MASTER) | CMD_MEMORY)
    after = proxy.read32(ECAM_PA + COMMAND) & 0xffff
    return dict(command_before=hex(before), command_after=hex(after), bus_master_off=not after & CMD_MASTER)
