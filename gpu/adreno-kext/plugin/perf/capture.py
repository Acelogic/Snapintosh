#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reading desktop-scenes adreno captures: kernel commands, ADRENO_KCMD_IB packages, relocations, resources.

Pure Python, no q1n1 import. compat/adreno-submit.h layout:
  kernel command: u32 type, u32 size; FENCE 0x1000, FILL32 0x1001, IB 0x1002
  IB: 48-byte header (type,size,version,flags,ib_dwords,data_bytes,reloc_count,reserved0,reserved1[2]),
      package [IB dwords | zero pad to 64 | data_bytes], relocations (32 bytes each).
"""
import json
import struct
from pathlib import Path

KCMD_FENCE, KCMD_FILL32, KCMD_IB = 0x1000, 0x1001, 0x1002
RELOC_RESOURCE, RELOC_PACKAGE, RELOC_ZERO = 1, 2, 3
ACCESS_READ, ACCESS_WRITE = 1, 2
NO_HI = 0xFFFFFFFF
ZERO_BYTES = 0x4000


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def kernel_commands(blob):
    out, at = [], 0
    while at < len(blob):
        kind, size = struct.unpack_from('<II', blob, at)
        if size < 8 or size % 4 or at + size > len(blob):
            raise ValueError(f'kernel command {kind:#x} size {size} at {at}')
        out.append((kind, blob[at:at + size]))
        at += size
    return out


def parse_package(cmd):
    kind, size, version, flags, ib_dwords, data_bytes, nrel, _r0, _r1a, _r1b = struct.unpack_from('<IIIIIIIIQQ', cmd, 0)
    if kind != KCMD_IB or size != len(cmd) or version != 1:
        raise ValueError('not an ADRENO_KCMD_IB v1 command')
    data_off = align(4 * ib_dwords, 64)
    pbytes = data_off + data_bytes
    package = bytearray(cmd[48:48 + pbytes])
    relocs = []
    for i in range(nrel):
        lo, hi, rkind, access, al, hi_bits, rid, offset, length = struct.unpack_from('<IIBBBBIQQ', cmd, 48 + pbytes + 32 * i)
        relocs.append(dict(lo=lo, hi=hi, kind=rkind, access=access, align=al, hi_bits=hi_bits, rid=rid,
                           offset=offset, length=length))
    return dict(ib_dwords=ib_dwords, data_bytes=data_bytes, data_offset=data_off, package=package, relocs=relocs)


def fill32(cmd):
    """FILL32 request (compat/adreno-fill-command.c adreno_fill32_decode: u32 resource_id, u32 pattern, u64 offset,
    u64 bytes after the 8-byte header; 32 bytes in all)."""
    rid, pattern, offset, nbytes = struct.unpack_from('<IIQQ', cmd, 8)
    return dict(rid=rid, offset=offset, bytes=nbytes, pattern=pattern)


def apply_relocs(pkg, base_of):
    """Patch every relocation: base_of(kind, rid, offset, length, access) -> GPU address of offset."""
    p = pkg['package']
    for r in pkg['relocs']:
        va = base_of(r)
        lo = struct.unpack_from('<I', p, r['lo'])[0]
        struct.pack_into('<I', p, r['lo'], (lo | (va & 0xFFFFFFFF)) & 0xFFFFFFFF)
        if r['hi'] != NO_HI:
            hi = struct.unpack_from('<I', p, r['hi'])[0]
            mask = (1 << r['hi_bits']) - 1
            struct.pack_into('<I', p, r['hi'], (hi & ~mask) | ((va >> 32) & mask))
    return p


class Capture:
    """A desktop-scenes adreno run directory."""

    def __init__(self, path):
        self.dir = Path(path)
        self.report = json.loads((self.dir / 'report.json').read_text())
        self.commits = self.report['commits']
        self.scenes = {s['scene']: s for s in self.report['scenes']}

    def scene_commits(self, scene):
        return [c for c in self.commits if c['scene'] == scene]

    def commands(self, commit):
        f = self.dir / commit['dir'] / 'commands.bin'
        return f.read_bytes() if f.is_file() else b''

    def packages(self, commit):
        out = []
        for kind, cmd in kernel_commands(self.commands(commit)):
            if kind == KCMD_IB:
                out.append(('ib', parse_package(cmd)))
            elif kind == KCMD_FILL32:
                out.append(('fill', cmd))
        return out

    def resource_rows(self, commit):
        return {r['id']: r for r in commit.get('resources', [])}

    def snapshot(self, commit, rid):
        row = self.resource_rows(commit).get(rid)
        if not row or 'file' not in row:
            return None
        return (self.dir / commit['dir'] / row['file']).read_bytes()


# ---- registers and PM4 (AdrenoA8xxRegs.h, generated from Mesa's XML; no q1n1 import) ----------------------------
HEADER = Path(__file__).resolve().parents[2] / 'include/AdrenoA8xxRegs.h'
_REGS = None


def regs():
    """{'REG': {offset, stride, count, fields: {F: (shift, width, shr)}}, 'E': {enum: value}, 'OPS': {name: opcode}}"""
    global _REGS
    if _REGS:
        return _REGS
    import re
    reg, enums, fields = {}, {}, {}
    for line in HEADER.read_text().splitlines():
        m = re.match(r'#define A8XX_REG_([A-Z0-9_]+?) (0x[0-9a-f]+)u$', line)
        if m and '__' not in m.group(1):
            reg.setdefault(m.group(1), {})['offset'] = int(m.group(2), 16)
            continue
        m = re.match(r'#define A8XX_REG_([A-Z0-9_]+?)__(ARRAY_STRIDE|ARRAY_COUNT|BIT_SIZE) (0x[0-9a-f]+|\d+)u$', line)
        if m:
            reg.setdefault(m.group(1), {})[m.group(2).lower()] = int(m.group(3), 0)
            continue
        m = re.match(r'#define A8XX_REG_([A-Z0-9_]+?)__([A-Z0-9_]+?)__(SHIFT|WIDTH|SHR) (\d+)u$', line)
        if m:
            fields.setdefault(m.group(1), {}).setdefault(m.group(2), {})[m.group(3)] = int(m.group(4))
            continue
        m = re.match(r'#define A8XX_E_([A-Z0-9_]+) (0x[0-9a-f]+)u$', line)
        if m:
            enums[m.group(1)] = int(m.group(2), 16)
    for name, f in fields.items():
        if name in reg:
            reg[name]['fields'] = {k: (v.get('SHIFT', 0), v.get('WIDTH', 32), v.get('SHR', 0)) for k, v in f.items()}
    by_offset = {}
    for name, r in reg.items():
        if 'offset' not in r:
            continue
        stride, count = r.get('array_stride', 0) or 1, r.get('array_count', 1)
        halves = 2 if r.get('bit_size') == 64 else 1
        for i in range(count):
            for h in range(halves):
                by_offset.setdefault(r['offset'] + i * stride + h, (name, i, h))
    _REGS = dict(REG=reg, E=enums, BY_OFFSET=by_offset)
    return _REGS


def field(name, word, fname):
    sh, w, shr = regs()['REG'][name]['fields'][fname]
    return ((word >> sh) & ((1 << w) - 1)) << shr


def walk(words):
    """[('reg', dword index, offset, value)] and [('pkt', header index, opcode, payload list)] in stream order."""
    E = regs()['E']
    crb, ncrb = E['CP_CONTEXT_REG_BUNCH'], E['CP_NON_CONTEXT_REG_BUNCH']
    out, i = [], 0
    while i < len(words):
        h = words[i]
        if h >> 28 == 4:
            cnt, off = h & 0x7F, (h >> 8) & 0x3FFFF
            for k in range(cnt):
                out.append(('reg', i + 1 + k, off + k, words[i + 1 + k]))
            i += 1 + cnt
            continue
        if h >> 28 != 7:
            raise ValueError(f'bad packet header {h:#x} at {i}')
        cnt, op = h & 0x3FFF, (h >> 16) & 0x7F
        body = words[i + 1:i + 1 + cnt]
        if op == crb:
            for k in range(cnt // 2):
                out.append(('reg', i + 2 + 2 * k, body[2 * k], body[2 * k + 1]))
        elif op == ncrb:
            for k in range(cnt // 2 - 1):
                out.append(('reg', i + 4 + 2 * k, body[2 + 2 * k], body[3 + 2 * k]))
        out.append(('pkt', i, op, body))
        i += 1 + cnt
    return out


def ib_words(pkg):
    return list(struct.unpack_from(f'<{pkg["ib_dwords"]}I', pkg['package'], 0))


def reloc_at(pkg, dword):
    """The relocation whose lo half patches IB dword `dword`, or None."""
    for r in pkg['relocs']:
        if r['lo'] == 4 * dword:
            return r
    return None
