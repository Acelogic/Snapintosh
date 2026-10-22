#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract unique PTE-level ground-truth rows from a qemu-sptm SPTM trace.

Row format (one per line, hex without 0x):
  <op> <root_type> <old> <requested> <options> <result_pte> <status>
op: D = UPDATE_DISJOINT record, R = UPDATE_REGION template, M = MAP_PAGE over a
valid leaf, N = MAP_PAGE into an empty slot. root_type: the SPTM frame type
of the root at the time of the call from the RETYPE log (18 user, 19 shared
region), or 0 for the kernel root (never retyped at runtime).
<status> is x0 at gexit (MAP_PAGE/UPDATE_*: a status)."""
import sys

def leaves(s):
    return [tuple(int(x, 16) if i != 1 else int(x) for i, x in enumerate(item.split(':')))
            for item in s.split(';')]

def main(trace, out):
    pend = {}
    rows = set()
    types = {}
    rt = lambda root: types.get(root & 0x0000ffffffffc000, 0)
    for line in open(trace, errors='replace'):
        f = line.split()
        if len(f) < 3:
            continue
        try:
            if f[0] == 'G':
                kv = dict(x.split('=', 1) for x in f[2:])
                x16 = int(kv['x16'], 16)
                if x16 == 1:
                    a = [int(v, 16) for v in kv['a'].split(',')]
                    types[a[0] & 0x0000ffffffffc000] = a[2]
                if x16 in (2, 5, 6):
                    pend[int(f[1])] = (x16, [int(v, 16) for v in kv['a'].split(',')], kv)
            elif f[0] == 'X':
                seq = int(f[1])
                if seq not in pend:
                    continue
                x16, a, g = pend.pop(seq)
                kv = dict(x.split('=', 1) for x in f[2:])
                r, r1 = (int(v, 16) for v in kv['r'].split(',')[:2])
                if r == 5 and r1 == 1:
                    continue  # preempted: SPTM resumes it through dispatch cmd 4
                old = leaves(g['old']) if 'old' in g else []
                new = leaves(kv['new']) if 'new' in kv else []
                if x16 == 2 and old and new and old[0][1] == 3 and new[0][1] == 3:
                    o, n = old[0][2], new[0][2]
                    op = 'M' if (o & 3) == 3 else 'N'
                    rows.add((op, rt(a[0]), o, a[2], a[3], n, r))
                elif x16 == 6 and 'rec' in g:
                    recs = [tuple(int(v, 16) for v in rr.split(',')) for rr in g['rec'].split(';')]
                    for i, (root, va, req) in enumerate(recs):
                        if i < len(old) and i < len(new) and old[i][1] == 3 == new[i][1]:
                            rows.add(('D', rt(root), old[i][2], req, a[3], new[i][2], r))
                elif x16 == 5 and 'tpl' in g:
                    tpl = [int(v, 16) for v in g['tpl'].split(',')]
                    for i, t in enumerate(tpl):
                        if i < len(old) and i < len(new) and old[i][1] == 3 == new[i][1]:
                            rows.add(('R', rt(a[0]), old[i][2], t, a[4], new[i][2], r))
        except (ValueError, KeyError, IndexError):
            continue
    # Canonicalise output addresses so the fixture keeps every distinct
    # attribute/option/status pattern but not every physical page: the
    # requested PTE's page becomes A, any other page becomes B.
    PA = 0x0000fffffffff000
    A, B = 0x947a0c000, 0x947a10000
    def canon(v, ref):
        if not v:
            return 0
        pa = v & PA
        return (v & ~PA) | (A if pa == ref else B)
    uniq = set()
    for op, user, old, req, opts, new, r in rows:
        ref = (req if op in 'MND' and (req & 3) else old) & PA
        uniq.add((op, user, canon(old, ref), canon(req, ref) if op != 'R' or req & 1 else req,
                  opts, canon(new, ref), r))
    with open(out, 'w') as o:
        o.write('# op root_type old requested options result_pte status\n')
        o.write('# qemu-sptm oracle: real SPTM/TXM + kernelcache 26A428 J700 (T8140)\n')
        o.write('# D=UPDATE_DISJOINT record R=UPDATE_REGION template M=MAP_PAGE over a\n')
        o.write('# valid leaf N=MAP_PAGE into an empty slot; pages canonicalised to A/B\n')
        for row in sorted(uniq):
            o.write('%s %d %x %x %x %x %x\n' % row)
    print(len(rows), 'rows,', len(uniq), 'patterns')

if __name__ == '__main__':
    main(*sys.argv[1:3])
