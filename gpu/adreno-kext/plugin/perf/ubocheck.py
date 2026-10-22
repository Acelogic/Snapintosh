#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""What every draw's constant buffers hold when the GPU reads them (agents/gpu-perf FAILURE-MODES.md U13).

    ubocheck.py CAPTURE                      -> per-scene draw signatures (summary)
    ubocheck.py BEFORE_CAPTURE AFTER_CAPTURE -> compare: every draw must read the same constant bytes in both
    ubocheck.py --prefix N BEFORE AFTER      -> hash only each descriptor's first N bytes

CAPTURE is a desktop-scenes adreno run with resource snapshots (run-suite.py's adreno/ directory). The command stream is
executed symbolically in order over a byte model of the resources:
  - memory starts as each resource's snapshot (contents at commit, as the CPU left them);
  - FILL32 commands and CP_MEMCPY packets are applied where they stand, between and inside passes;
  - at each CP_DRAW_INDX_OFFSET, every UBO descriptor loaded for the vertex and fragment stage
    (CP_LOAD_STATE6 ST6_UBO SS6_DIRECT) is resolved through its relocation and its SIZE bytes are hashed.
A draw's signature is the sorted list of (stage, slot, size, sha1) over resource-backed descriptors. Package-backed
descriptors (setBytes copies, driver tables full of relocated addresses) are listed by size only. Unaligned constant
buffers are read from a staging slice in the old build and from a mirror region in the new one: equal signatures
mean the GPU reads the same bytes. A resource without a snapshot makes its descriptor 'nosnap'.
"""
import collections
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C  # noqa: E402

E = C.regs()['E']
NOSNAP = 'nosnap'
PREFIX = None     # --prefix N: hash only each descriptor's first N bytes


class Memory:
    """Resource bytes as the GPU sees them: the snapshot where there is one, else unknown until a copy or fill writes
    them (the plug-in's staging arenas and mirror regions). A read that touches an unknown byte is None."""

    def __init__(self, cdir, rows):
        self.dir, self.rows, self.mem = cdir, rows, {}

    def get(self, rid):
        if rid not in self.mem:
            row = self.rows.get(rid)
            if row and 'file' in row and (self.dir / row['file']).is_file():
                data = bytearray((self.dir / row['file']).read_bytes())
                self.mem[rid] = [data, bytearray(b'\x01') * len(data)]
            else:
                self.mem[rid] = [bytearray(), bytearray()]
        return self.mem[rid]

    def read(self, rid, off, n):
        data, known = self.get(rid)
        if off + n > len(data) or known.find(0, off, off + n) >= 0:
            return None
        return bytes(data[off:off + n])

    def write(self, rid, off, src):
        data, known = self.get(rid)
        n = len(src) if src is not None else 0
        if src is None:
            return
        if off + n > len(data):
            grow = off + n - len(data)
            data.extend(b'\x00' * grow); known.extend(b'\x00' * grow)
        data[off:off + n] = src
        known[off:off + n] = b'\x01' * n

    def unknown(self, rid, off, n):
        data, known = self.get(rid)
        if off < len(known):
            e = min(len(known), off + n)
            known[off:e] = b'\x00' * (e - off)


def commit_draws(cap_dir, commit):
    cdir = cap_dir / commit['dir']
    f = cdir / 'commands.bin'
    if not f.is_file():
        return []
    rows = {r['id']: r for r in commit.get('resources', [])}
    mem = Memory(cdir, rows)
    draws = []
    for kind, cmd in C.kernel_commands(f.read_bytes()):
        if kind == C.KCMD_FILL32:
            fl = C.fill32(cmd)
            mem.write(fl['rid'], fl['offset'], struct.pack('<I', fl['pattern']) * (fl['bytes'] // 4))
            continue
        if kind != C.KCMD_IB:
            continue
        pkg = C.parse_package(cmd)
        relocs = {r['lo']: r for r in pkg['relocs']}
        words = C.ib_words(pkg)
        ubo = {}   # (stage, slot) -> (desc kind, rid/offset, size)
        for ev in C.walk(words):
            if ev[0] != 'pkt':
                continue
            _, at, op, body = ev
            if op == E['CP_MEMCPY']:
                s, d = relocs.get(4 * (at + 2)), relocs.get(4 * (at + 4))
                n = 4 * body[0]
                if s and d:
                    data = mem.read(s['rid'], s['offset'], n)
                    if data is None:
                        mem.unknown(d['rid'], d['offset'], n)
                    else:
                        mem.write(d['rid'], d['offset'], data)
            elif op in (E['CP_LOAD_STATE6_GEOM'], E['CP_LOAD_STATE6_FRAG']):
                w0 = body[0]
                st, src, sb, dst = (w0 >> 14) & 3, (w0 >> 16) & 3, (w0 >> 18) & 0xf, w0 & 0x3fff
                n = (w0 >> 22) & 0x3ff
                if st != E['ST6_UBO'] or src != E['SS6_DIRECT']:
                    continue
                stage = 'vs' if op == E['CP_LOAD_STATE6_GEOM'] else 'fs'
                for k in range(n):
                    lo = 4 * (at + 4 + 2 * k)
                    size = ((body[4 + 2 * k] >> 17) & 0x7fff) * 16
                    r = relocs.get(lo)
                    slot = dst + k
                    if not r:
                        ubo[(stage, slot)] = ('none', 0)
                    elif r['kind'] == C.RELOC_RESOURCE:
                        ubo[(stage, slot)] = ('res', r['rid'], r['offset'], size)
                    else:
                        ubo[(stage, slot)] = ('pkg', size)
            elif op == E['CP_DRAW_INDX_OFFSET']:
                sig = []
                for (stage, slot), d in sorted(ubo.items()):
                    if d[0] == 'res':
                        data = mem.read(d[1], d[2], min(d[3], PREFIX) if PREFIX else d[3])
                        sig.append((stage, slot, d[3], hashlib.sha1(data).hexdigest()[:16] if data is not None else NOSNAP))
                    elif d[0] == 'pkg':
                        sig.append((stage, slot, d[1], 'pkg'))
                draws.append(tuple(sig))
    return draws


def load(path):
    p = Path(path)
    if (p / 'adreno/report.json').is_file():
        p = p / 'adreno'
    report = json.loads((p / 'report.json').read_text())
    out = collections.OrderedDict()
    for c in report['commits']:
        if not c.get('has_commands'):
            continue
        out.setdefault((c['scene'], c['frame']), []).extend(commit_draws(p, c))
    return out


def main():
    global PREFIX
    if len(sys.argv) > 2 and sys.argv[1] == '--prefix':
        PREFIX = int(sys.argv[2]); del sys.argv[1:3]
    a = load(sys.argv[1])
    if len(sys.argv) == 2:
        n = sum(len(v) for v in a.values())
        nos = sum(1 for v in a.values() for d in v for x in d if x[3] == NOSNAP)
        print(f'{len(a)} frames, {n} draws, {nos} descriptors without snapshot')
        return
    b = load(sys.argv[2])
    total = same = multiset_same = 0
    bad = []
    for key in a:
        if key not in b:
            bad.append((key, 'frame missing in AFTER'))
            continue
        da, db = a[key], b[key]
        total += len(da)
        if len(da) == len(db):
            same += sum(1 for x, y in zip(da, db) if x == y)
        if collections.Counter(da) == collections.Counter(db):
            multiset_same += len(da)
        else:
            diff = (collections.Counter(da) - collections.Counter(db)) + (collections.Counter(db) - collections.Counter(da))
            bad.append((key, f'{len(da)} vs {len(db)} draws, {sum(diff.values())} signatures differ'))
    nos = sum(1 for v in b.values() for d in v for x in d if x[3] == NOSNAP)
    print(f'frames {len(a)}, draws {total}: in-order equal {same}, as multisets equal {multiset_same}; '
          f'AFTER descriptors without snapshot {nos}')
    for key, why in bad[:20]:
        print('  DIFF', key, why)
    print('PASS' if not bad else 'FAIL')
    sys.exit(0 if not bad else 1)


if __name__ == '__main__':
    main()
