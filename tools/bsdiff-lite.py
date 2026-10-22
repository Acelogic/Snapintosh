#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A BSDIFF40 patch for /usr/bin/bspatch, from block matches (no suffix sort).

    python3 tools/bsdiff-lite.py OLD NEW PATCH

The format is bsdiff 4.3's (header, then bzip2'd control, diff and extra blocks), so any bspatch applies it. Matches
are found only on 16-byte-aligned 32-byte blocks of OLD and extended both ways, so the patch is small only when NEW
is mostly OLD's bytes, possibly shifted: a rebuilt binary with an unchanged data payload. The patch is applied with
/usr/bin/bspatch before it is written, and must reproduce NEW exactly; otherwise nothing is written.
"""
import bz2
from pathlib import Path
import subprocess
import sys
import tempfile

BLOCK, STEP = 32, 16


def offtout(x):
    """bsdiff's int64: sign-magnitude, little-endian, sign in bit 63."""
    return (abs(x) | (1 << 63 if x < 0 else 0)).to_bytes(8, 'little')


def segments(old, new):
    """NEW as ('copy', old offset, length) and ('lit', bytes) runs, in order."""
    index = {}
    for i in range(0, len(old) - BLOCK + 1, STEP):
        index.setdefault(old[i:i + BLOCK], i)
    out, lit_start, p = [], 0, 0
    while p + BLOCK <= len(new):
        o = index.get(new[p:p + BLOCK])
        if o is None:
            p += 1
            continue
        start, ostart = p, o
        while start > lit_start and ostart > 0 and new[start - 1] == old[ostart - 1]:
            start, ostart = start - 1, ostart - 1
        end, oend = p + BLOCK, o + BLOCK
        while end < len(new) and oend < len(old) and new[end] == old[oend]:
            end, oend = end + 1, oend + 1
        if start > lit_start:
            out.append(('lit', new[lit_start:start]))
        out.append(('copy', ostart, end - start))
        lit_start = p = end
    if lit_start < len(new):
        out.append(('lit', new[lit_start:]))
    return out


def patch(old, new):
    """bspatch reads (x, y, z): x bytes of old+diff at oldpos, y bytes of extra, then oldpos += x + z."""
    segs = segments(old, new)
    ctrl, diff, extra = bytearray(), bytearray(), bytearray()
    oldpos = newpos = i = 0
    if segs and segs[0][0] == 'copy' and segs[0][1]:
        ctrl += offtout(0) + offtout(0) + offtout(segs[0][1])     # seek old to the first copy
        oldpos = segs[0][1]
    while i < len(segs):
        x = 0
        if segs[i][0] == 'copy':
            _, at, x = segs[i]
            assert at == oldpos, (at, oldpos)
            diff += bytes((a - b) & 0xFF for a, b in zip(new[newpos:newpos + x], old[at:at + x]))
            newpos, oldpos, i = newpos + x, oldpos + x, i + 1
        y = b''
        if i < len(segs) and segs[i][0] == 'lit':
            y = segs[i][1]
            newpos, i = newpos + len(y), i + 1
        nxt = segs[i][1] if i < len(segs) and segs[i][0] == 'copy' else oldpos
        ctrl += offtout(x) + offtout(len(y)) + offtout(nxt - oldpos)
        extra += y
        oldpos = nxt
    assert newpos == len(new)
    c, d, e = (bz2.compress(bytes(b), 9) for b in (ctrl, diff, extra))
    return b'BSDIFF40' + offtout(len(c)) + offtout(len(d)) + offtout(len(new)) + c + d + e


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 64
    old, new, out = Path(sys.argv[1]).read_bytes(), Path(sys.argv[2]).read_bytes(), Path(sys.argv[3])
    if out.exists():
        print(f'{out} exists')
        return 64
    data = patch(old, new)
    with tempfile.TemporaryDirectory() as tmp:
        p, r = Path(tmp) / 'patch', Path(tmp) / 'result'
        p.write_bytes(data)
        subprocess.run(['/usr/bin/bspatch', sys.argv[1], str(r), str(p)], check=True)
        if r.read_bytes() != new:
            print('FAIL: bspatch did not reproduce NEW')
            return 1
    out.write_bytes(data)
    print(f'patch {len(data)} bytes for {len(new)} new bytes; /usr/bin/bspatch reproduces NEW exactly')
    return 0


if __name__ == '__main__':
    sys.exit(main())
