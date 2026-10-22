#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation check of tools/ubo-mirror-check.py (it must FAIL on broken streams): copies a passing ubo-mirror run and
  m1: shifts the source offset of the second prelude's first CP_MEMCPY by 64 bytes (a mapping error);
  m2: drops the FILL32 (an ordering/invalidation error: draw 7 must then read stale bytes);
  m3: turns the second prelude's copies into copies of 4 bytes (a region the draws read beyond).
    ubo-mirror-mutate.py PASSING_RUN OUTDIR"""
import shutil, struct, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C  # noqa: E402
src, out = Path(sys.argv[1]), Path(sys.argv[2])
E = C.regs()['E']
def mutate(name, fn):
    d = out / name
    if d.exists(): shutil.rmtree(d)
    shutil.copytree(src, d)
    f = d / 'commit-0000/commands.bin'
    f.write_bytes(fn(bytearray(f.read_bytes())))
    r = subprocess.run([sys.executable, str(Path(__file__).parent / 'ubo-mirror-check.py'), str(d)], capture_output=True, text=True)
    print(f'{name}: checker exit {r.returncode} ({"caught" if r.returncode else "MISSED"}): {r.stdout.strip().splitlines()[-1]}')
    return r.returncode != 0
def memcpys(blob):
    out, at = [], 0
    for kind, cmd in C.kernel_commands(bytes(blob)):
        if kind == C.KCMD_IB:
            pkg = C.parse_package(cmd)
            relocs = {r['lo']: (i, r) for i, r in enumerate(pkg['relocs'])}
            base = at + 48
            reloc_at = base + pkg['data_offset'] + pkg['data_bytes']
            for ev in C.walk(C.ib_words(pkg)):
                if ev[0] == 'pkt' and ev[2] == E['CP_MEMCPY']:
                    out.append((base + 4 * ev[1], relocs[4 * (ev[1] + 2)][0], reloc_at))
        at += len(cmd)
    return out
def m1(b):
    pk, ri, reloc_at = memcpys(b)[4]          # copies 0-2: prelude A, 3: the blit, 4: prelude B's first
    off = reloc_at + 32 * ri + 16              # adreno_ib_reloc: lo, hi, kind, access, align, hi_bits, rid, offset
    struct.pack_into('<Q', b, off, struct.unpack_from('<Q', b, off)[0] + 64)
    return b
def m2(b):
    out, at = bytearray(), 0
    for kind, cmd in C.kernel_commands(bytes(b)):
        if kind != C.KCMD_FILL32: out += cmd
    return out
def m3(b):
    for pk, ri, reloc_at in memcpys(b)[4:7]:
        struct.pack_into('<I', b, pk + 4, 1)
    return b
ok = all([mutate('m1-mapping', m1), mutate('m2-no-fill', m2), mutate('m3-short-copy', m3)])
print('PASS: every mutation caught' if ok else 'FAIL: a mutation went unnoticed')
sys.exit(0 if ok else 1)
