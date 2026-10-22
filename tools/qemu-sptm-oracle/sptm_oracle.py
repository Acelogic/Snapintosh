#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarise a qemu-sptm SPTM trace (QEMU_SPTM_TRACE) into Apple's real
operation x frame-type x options matrix, for diffing against Snapintosh.

    sptm_oracle.py <sptm-trace.txt> [--json out.json] [--pairs N]

Frame types: every runtime type change goes through RETYPE(pa, prev, new,
params) (XNU->SPTM endpoint 1, or TXM->SPTM endpoint 2 via svc). The type of
a frame before its first logged retype is that retype's `prev` (backfilled),
so the map is exact for every frame that is ever retyped; frames never
retyped are reported as 'init' (SPTM bootstrap typing: XNU_DEFAULT for free
RAM, or a boot-image type).
"""
import argparse, collections, json, re, sys

FN = {0: 'LOCKDOWN', 1: 'RETYPE', 2: 'MAP_PAGE', 3: 'MAP_TABLE', 4: 'UNMAP_TABLE',
      5: 'UPDATE_REGION', 6: 'UPDATE_DISJOINT', 7: 'UNMAP_REGION', 8: 'UNMAP_DISJOINT',
      9: 'CONFIGURE_SHAREDREGION', 10: 'NEST_REGION', 11: 'UNNEST_REGION',
      12: 'CONFIGURE_ROOT', 13: 'SWITCH_ROOT', 14: 'REGISTER_CPU', 15: 'FIXUPS_COMPLETE',
      16: 'SIGN_USER_POINTER', 17: 'AUTH_USER_POINTER', 18: 'REGISTER_EXC_RETURN',
      19: 'CPU_ID', 20: 'SLIDE_REGION', 21: 'UPDATE_DISJOINT_MULTIPAGE',
      24: 'GUEST_VA_TO_IPA', 25: 'GUEST_STAGE1_TLBOP', 26: 'GUEST_STAGE2_TLBOP',
      27: 'GUEST_DISPATCH', 28: 'GUEST_EXIT', 30: 'HIB_BEGIN',
      31: 'HIB_VERIFY_HASH_NON_WIRED', 32: 'HIB_FINALIZE_NON_WIRED',
      33: 'IOFILTER_PROTECTED_WRITE', 39: 'SET_SHARED_REGION',
      40: 'BATCH_SIGN_USER_POINTER', 41: 'SURT_ALLOC', 42: 'SURT_FREE',
      43: 'CONDEMN_LEAF_TABLE', 44: 'UNCONDEMN_LEAF_TABLE', 45: 'SERIAL_PUTC',
      46: 'SERIAL_DISABLE', 50: 'OUTPUT_AREA'}
TXM2SPTM = {0: 'TXM_FIXUPS_COMPLETE', 1: 'TXM_REGISTER_DISPATCH_TABLE',
            2: 'TXM_RETYPE', 3: 'TXM_USER_ASID'}
TYPES = {42: 'TXM_DEFAULT', 49: 'TXM_FREE_LIST', 11: 'XNU_DEFAULT', 14: 'USER_EXEC', 17: 'USER_TPRO', 18: 'USER_ROOT_TABLE',
         19: 'SHARED_ROOT_TABLE', 20: 'PAGE_TABLE', 21: 'PAGE_TABLE_SHARED',
         22: 'PAGE_TABLE_ROZONE', 23: 'PAGE_TABLE_COMMPAGE', 24: 'IOMMU', 25: 'ROZONE',
         29: 'COMMPAGE_RW', 30: 'COMMPAGE_RO', 31: 'COMMPAGE_RX', 35: 'KERNEL_RESTRICTED'}
PA_MASK = 0x0000ffffffffc000


def tname(t):
    if t is None:
        return 'init'
    return f'{t}:{TYPES.get(t, "?")}'


STATUS_EPS = {'MAP_PAGE', 'MAP_TABLE', 'UNMAP_TABLE', 'UPDATE_REGION', 'UPDATE_DISJOINT',
              'UNMAP_REGION', 'UNMAP_DISJOINT', 'CONDEMN_LEAF_TABLE', 'UNCONDEMN_LEAF_TABLE',
              'SWITCH_ROOT', 'SET_SHARED_REGION', 'UNNEST_REGION', 'SLIDE_REGION'}


def rstr(name, c):
    if 'r' not in c:
        return 'noexit'
    r = c['r']
    if r == 5 and c.get('r1') == 1:
        return 'preempted'   # x0=5,x1=1: resumed by dispatch cmd 4 (a0 = stub pc)
    if name in STATUS_EPS or r < 0x100:
        return hex(r)
    return 'value'


def call_name(x16):
    cmd, dom, tab, ep = x16 >> 56, (x16 >> 48) & 0xff, (x16 >> 32) & 0xffff, x16 & 0xffffffff
    if cmd:
        return {4: 'cmd4_RESUME', 2: 'cmd2_PANIC'}.get(cmd, f'cmd{cmd}')
    if dom == 0 and tab == 0:
        return FN.get(ep, f'sptm_ep{ep}')
    if x16 >> 32 == 1:
        return TXM2SPTM.get(ep, f'txm2sptm_ep{ep}')
    return f'd{dom}.t{tab}.e{ep}'


def sclass(pte):
    """SPRR selector: AP[2:1] -> bits 3:2, UXN,PXN -> bits 1:0 (as sprr_pte_class)."""
    return ((pte >> 4) & 12) | ((pte >> 53) & 3)


def pte_delta(old, new):
    """Describe which architectural fields change between two leaf PTEs."""
    if not (old & 1) and not (new & 1):
        return 'inv->inv'
    if not (old & 1):
        return 'inv->valid'
    if not (new & 1):
        return 'valid->inv'
    d = old ^ new
    parts = []
    if d & PA_MASK:
        parts.append('OA')
    if d & (1 << 10):
        parts.append('AF' + ('+' if new & (1 << 10) else '-'))
    if d & (3 << 6):
        parts.append('AP')
    if d & (1 << 53):
        parts.append('PXN')
    if d & (1 << 54):
        parts.append('UXN')
    if d & (7 << 2):
        parts.append('ATTR')
    if d & (1 << 11):
        parts.append('nG')
    if d & (3 << 8):
        parts.append('SH')
    if d & (1 << 51):
        parts.append('DBM')
    if d & (1 << 52):
        parts.append('CONT')
    if d & (0xf << 55):
        parts.append('SW')
    rest = d & ~(PA_MASK | (1 << 10) | (3 << 6) | (3 << 53) | (7 << 2) | (1 << 11) |
                 (3 << 8) | (1 << 51) | (1 << 52) | (0xf << 55))
    if rest:
        parts.append(f'other{rest:#x}')
    return '+'.join(parts) or 'same'


def parse_leaves(s):
    out = []
    for item in s.split(';'):
        va, lvl, pte = item.split(':')
        out.append((int(va, 16), int(lvl), int(pte, 16)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('trace')
    ap.add_argument('--json')
    ap.add_argument('--top', type=int, default=40)
    args = ap.parse_args()

    calls = {}
    order = []
    faults = collections.Counter()
    txm_calls = collections.Counter()
    sysreg_writes = collections.OrderedDict()
    sprr_states = []
    txm_retypes = collections.Counter()
    def parse_line(line):
            tag = line[:2]
            if tag == 'G ':
                f = line.split()
                seq = int(f[1])
                kv = dict(x.split('=', 1) for x in f[2:])
                c = {'seq': seq, 'pc': int(kv['pc'], 16), 'x16': int(kv['x16'], 16),
                     'a': [int(v, 16) for v in kv['a'].split(',')]}
                if 'rec' in kv:
                    c['rec'] = [tuple(int(v, 16) for v in r.split(',')) for r in kv['rec'].split(';')]
                if 'tpl' in kv:
                    c['tpl'] = [int(v, 16) for v in kv['tpl'].split(',')]
                if 'old' in kv:
                    c['old'] = parse_leaves(kv['old'])
                calls[seq] = c
                order.append(seq)
            elif tag == 'X ':
                f = line.split()
                seq = int(f[1])
                kv = dict(x.split('=', 1) for x in f[2:])
                c = calls.get(seq)
                if c is None:
                    return
                r = kv['r'].split(',')
                c['r'] = int(r[0], 16)
                c['r1'] = int(r[1], 16)
                if 'new' in kv:
                    c['new'] = parse_leaves(kv['new'])
                if 'sprr' in kv:
                    sprr_states.append((seq, call_name(c['x16']), kv['sprr']))
            elif tag == 'F ':
                f = line.split()
                kv = dict(x.split('=', 1) for x in f[2:] if '=' in x)
                esr = int(kv['esr'], 16)
                ec = esr >> 26
                if ec == 0x15:
                    x16 = int(kv['x16'], 16)
                    if x16 == 0x100000003 and 'a' in kv:
                        # TXM -> SPTM frame retype (pa, old, new, params), e.g.
                        # TXM_DEFAULT(42) -> TXM_FREE_LIST(49) after XNU donates.
                        a = [int(v, 16) for v in kv['a'].split(',')]
                        txm_retypes[(tname(a[1]), tname(a[2]), hex(a[3]))] += 1
                    txm_calls[TXM2SPTM.get(x16 & 0xffffffff, hex(x16)) if (x16 >> 32) == 1 else hex(x16)] += 1
                else:
                    faults[(kv['el'], hex(ec), kv['pc'])] += 1
            elif tag == 'R ':
                f = line.split()
                if f[2] == 'w':
                    key = (f[1], f[4])
                    sysreg_writes.setdefault(key, [])
                    if len(sysreg_writes[key]) < 6 and f[3] not in sysreg_writes[key]:
                        sysreg_writes[key].append(f[3])


    bad = 0
    for line in open(args.trace, errors='replace'):
        try:
            parse_line(line)
        except (ValueError, IndexError, KeyError):
            bad += 1  # truncated final line of a killed run

    # ---- frame types from the retype log (with backfill) ----
    first_prev = {}
    types = {}
    retype = collections.Counter()
    retype_fail = collections.Counter()
    for seq in order:
        c = calls[seq]
        if call_name(c['x16']) != 'RETYPE':
            continue
        pa, prev, new, params = c['a'][0] & PA_MASK, c['a'][1], c['a'][2], c['a'][3]
        # RETYPE returns void (x0 on gexit is not a status; SPTM panics on
        # a bad request), so every completed call is a real transition.
        ok = 'r' in c
        (retype if ok else retype_fail)[(tname(prev), tname(new), hex(params))] += 1
        if ok:
            first_prev.setdefault(pa, prev)

    def frame_type_at(pa, seq, cache={}):
        return types.get(pa & PA_MASK, first_prev.get(pa & PA_MASK))

    # ---- walk calls in order, keeping the live type map ----
    ep_count = collections.Counter()
    ep_result = collections.Counter()
    matrix = collections.Counter()
    examples = {}
    kernel_roots = collections.Counter()
    for seq in order:
        c = calls[seq]
        name = call_name(c['x16'])
        ep_count[name] += 1
        ep_result[(name, rstr(name, c))] += 1
        a = c['a']
        ok = 'r' in c
        if name == 'RETYPE':
            if ok:
                types[a[0] & PA_MASK] = a[2]
            continue
        if name == 'MAP_PAGE':
            root, va, pte = a[0], a[1], a[2]
            user = va < (1 << 47)
            old = c.get('old', [(va, -1, 0)])[0][2]
            new = c.get('new', [(va, -1, 0)])[0][2]
            key = (name, 'user' if user else 'kernel', 'frame=' + tname(frame_type_at(pte, seq)),
                   f'cls{sclass(old)}->{sclass(pte)}' if old & 1 else f'cls-->{sclass(pte)}',
                   pte_delta(old, pte), 'r=' + rstr(name, c))
            if not user:
                kernel_roots[hex(root)] += 1
        elif name in ('UPDATE_DISJOINT', 'UNMAP_DISJOINT'):
            target = a[0]
            opts = hex(a[3]) if name == 'UPDATE_DISJOINT' else '-'
            recs = c.get('rec', [])
            olds = c.get('old', [])
            news = c.get('new', [])
            for i, (root, va, req) in enumerate(recs):
                old = olds[i][2] if i < len(olds) else 0
                new = news[i][2] if i < len(news) else 0
                user = va < (1 << 47)
                if name == 'UPDATE_DISJOINT':
                    key = (name, 'user' if user else 'kernel', 'frame=' + tname(frame_type_at(target, seq)),
                           'opts=' + opts, f'cls{sclass(old)}->{sclass(req)}',
                           'req:' + pte_delta(old, req), 'res:' + pte_delta(old, new),
                           'r=' + rstr(name, c))
                else:
                    key = (name, 'user' if user else 'kernel', 'frame=' + tname(frame_type_at(target, seq)),
                           f'cls{sclass(old)}', 'res:' + pte_delta(old, new), 'r=' + rstr(name, c))
                matrix[key] += 1
                examples.setdefault(key, (seq, hex(target), hex(root), hex(va), hex(old), hex(req), hex(new)))
            continue
        elif name == 'UPDATE_REGION':
            root, va, n, tpl, opts = a[0], a[1], a[2], a[3], a[4]
            olds = c.get('old', [])
            news = c.get('new', [])
            for i, t in enumerate(c.get('tpl', [])):
                old = olds[i][2] if i < len(olds) else 0
                new = news[i][2] if i < len(news) else 0
                user = va < (1 << 47)
                key = (name, 'user' if user else 'kernel', 'frame=' + tname(frame_type_at(old if old & 1 else t, seq)),
                       'opts=' + hex(opts), f'cls{sclass(old)}->{sclass(t)}',
                       'req:' + pte_delta(old, t), 'res:' + pte_delta(old, new),
                       'r=' + rstr(name, c))
                matrix[key] += 1
                examples.setdefault(key, (seq, hex(root), hex(va + i * 0x4000), hex(old), hex(t), hex(new)))
            continue
        elif name == 'UNMAP_REGION':
            key = (name, 'user' if a[1] < (1 << 47) else 'kernel', f'count={a[2]}',
                   'opts=' + hex(a[3]), 'r=' + rstr(name, c))
        elif name in ('MAP_TABLE', 'UNMAP_TABLE'):
            key = (name, 'user' if a[1] < (1 << 47) else 'kernel', f'level={a[2]}',
                   'r=' + rstr(name, c))
        elif name in ('CONFIGURE_ROOT', 'SWITCH_ROOT', 'SET_SHARED_REGION',
                      'CONFIGURE_SHAREDREGION', 'NEST_REGION', 'UNNEST_REGION'):
            key = (name, 'root=' + tname(frame_type_at(a[0], seq)),
                   'x1=' + hex(a[1]) if name in ('CONFIGURE_ROOT', 'SWITCH_ROOT') else '',
                   'x2=' + hex(a[2]) if name in ('CONFIGURE_ROOT', 'SWITCH_ROOT') else '',
                   'r=' + rstr(name, c))
        else:
            key = (name, 'r=' + rstr(name, c) if 'r' in c else 'noexit')
        matrix[key] += 1
        examples.setdefault(key, (seq, hex(c['pc']), [hex(v) for v in a[:5]]))

    out = sys.stdout
    print(f'# calls: {len(order)}  (unmatched gexit: {sum(1 for s in order if "r" not in calls[s])})', file=out)
    print('\n## endpoint counts', file=out)
    for k, v in ep_count.most_common():
        print(f'{v:9d}  {k}', file=out)
    print('\n## non-zero / missing return codes', file=out)
    for (k, r), v in sorted(ep_result.items()):
        if r != '0x0':
            print(f'{v:9d}  {k} r={r}', file=out)
    print('\n## RETYPE (prev -> new, params): successful', file=out)
    for k, v in sorted(retype.items(), key=lambda kv: -kv[1]):
        print(f'{v:9d}  {k[0]:26s} -> {k[1]:26s} params={k[2]}', file=out)
    if retype_fail:
        print('\n## RETYPE failures', file=out)
        for k, v in retype_fail.items():
            print(f'{v:9d}  {k}', file=out)
    print('\n## operation x frame type x options x PTE change matrix', file=out)
    for k, v in sorted(matrix.items(), key=lambda kv: (kv[0][0], -kv[1])):
        print(f'{v:9d}  ' + '  '.join(x for x in k if x), file=out)
        if args.top and k[0] in ('UPDATE_DISJOINT', 'UPDATE_REGION', 'UNMAP_DISJOINT'):
            print(f'             e.g. {examples[k]}', file=out)
    print('\n## TXM -> SPTM (svc from GL0)', file=out)
    for k, v in txm_calls.most_common():
        print(f'{v:9d}  {k}', file=out)
    print('\n## TXM -> SPTM retypes (x16=0x100000003: pa, old, new, params)', file=out)
    for k, v in txm_retypes.most_common():
        print(f'{v:9d}  {k[0]} -> {k[1]} params={k[2]}', file=out)
    print('\n## other exceptions taken in GL', file=out)
    for k, v in faults.most_common(args.top):
        print(f'{v:9d}  {k}', file=out)
    print('\n## SPRR state changes observed at gexit (first 40)', file=out)
    for s in sprr_states[:40]:
        print(f'  seq {s[0]} after {s[1]}: {s[2]}', file=out)
    print(f'  ({len(sprr_states)} changes total)', file=out)
    print('\n## Apple sysreg writes (name, gl) -> distinct values (first 6)', file=out)
    for (n, gl), vals in sysreg_writes.items():
        print(f'  {n:24s} {gl}  {" ".join(vals)}', file=out)
    if args.json:
        json.dump({'endpoints': ep_count, 'retype': {' | '.join(k): v for k, v in retype.items()},
                   'matrix': {' | '.join(x for x in k if x): v for k, v in matrix.items()},
                   'examples': {' | '.join(x for x in k if x): examples.get(k) for k in matrix},
                   'txm_to_sptm': txm_calls,
                   'sysreg_writes': {f'{n} {gl}': v for (n, gl), v in sysreg_writes.items()}},
                  open(args.json, 'w'), indent=1, default=str)


if __name__ == '__main__':
    main()
