#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Where the service token's hold goes, from a stopped run's retained bytes.

    python3 tools/token-detail-report.py RUN_DIR [--output NEW.json]

Offline: reads RUN_DIR/launch.json (the ordered compile flags), context.bin,
summary.json and decoded.json; nothing else. The context layout comes from
clang's record layout of probes/xnuboot.c under the run's own -D flags (struct
context depends on them), so decode a run only with the sources it was built
from (launch.json source_sha256 is checked for probes/xnuboot.c and the
shadow/compat headers this reads).

Reports:
  - SNAP_SERVICE_DETAIL buckets (kernel PPERM change, kernel refresh, each
    SPTM endpoint), summed over vCPUs: calls, inclusive/self seconds, max;
  - the PPERM split: per-vCPU least squares of the PPERM bucket's seconds on
    (TPRO transactions, other changes), i.e. the cost of one of each;
  - the sampled audits and their observed rate (SNAP_AUDIT_SPARSE: 1024,
    else 64): class-proof hit verifications, kernel refresh reuse-hit
    verifications, exact variant-swap verifications, PPERM-reuse skip
    verifications; the leaf-memo rescans;
  - the token, gate and wait totals from summary.json/decoded.json.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CLANG = '/opt/homebrew/opt/llvm/bin/clang'
DETAIL = {0: 'kernel refresh, all CPUs', 1: 'kernel PPERM change', 2: 'user refresh, all CPUs',
          3: 'user sync, one CPU', 4: 'other monitor call', 5: 'canonical user view proof'}
ENDPOINTS = {0x0: 'LOCKDOWN', 0x1: 'RETYPE', 0x2: 'MAP_PAGE', 0x3: 'MAP_TABLE', 0x4: 'UNMAP_TABLE',
             0x5: 'UPDATE_REGION', 0x6: 'UPDATE_DISJOINT', 0x7: 'UNMAP_REGION', 0x8: 'UNMAP_DISJOINT',
             0x9: 'CONFIGURE_SHAREDREGION', 0xa: 'NEST_REGION', 0xb: 'UNNEST_REGION', 0xc: 'CONFIGURE_ROOT',
             0xd: 'SWITCH_ROOT', 0xe: 'REGISTER_CPU', 0xf: 'FIXUPS_COMPLETE', 0x10: 'SIGN_USER_POINTER',
             0x11: 'AUTH_USER_POINTER', 0x12: 'REGISTER_EXC_RETURN', 0x13: 'CPU_ID', 0x14: 'SLIDE_REGION',
             0x15: 'UPDATE_DISJOINT_MULTIPAGE'}


class Layout:
    def __init__(self, flags, root=ROOT):
        defines = [f for f in flags if f.startswith('-D')]
        text = subprocess.run([CLANG, '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                               '-mcmodel=tiny', *defines, f'-I{root}/shadow', f'-I{root}/compat',
                               f'-I{root.parent}/q1n1/platform/uefi', '-Xclang', '-fdump-record-layouts',
                               '-fsyntax-only', 'probes/xnuboot.c'],
                              cwd=root, capture_output=True, text=True, check=True).stdout
        self.records = {}
        for block in text.split('*** Dumping AST Record Layout'):
            m = re.search(r'^\s*0 \| struct (\w+)\n', block, re.M)
            if m and m[1] not in self.records:
                self.records[m[1]] = block

    def offset(self, kind, field):
        found = re.findall(r'^\s*(\d+) \|   \S.* ' + re.escape(field) + r'$', self.records[kind], re.M)
        if len(found) != 1:
            raise ValueError(f'ambiguous field {kind}.{field}')
        return int(found[0])

    def size(self, kind):
        return int(re.findall(r'\[sizeof=(\d+),', self.records[kind])[0])

    def struct_of(self, field):
        m = re.search(r'^\s*\d+ \|   struct (\w+) ' + re.escape(field) + r'$', self.records['context'], re.M)
        return m[1] if m else None

    def scalars(self, kind):
        return [(int(m[1]), m[2]) for m in
                re.finditer(r'^\s*(\d+) \|   uint64_t (\w+)$', self.records[kind], re.M)]


def record(layout, raw, field):
    kind = layout.struct_of(field)
    base = layout.offset('context', field)
    return {name: struct.unpack_from('<Q', raw, base + off)[0] for off, name in layout.scalars(kind)}


def lstsq2(rows):
    """Least squares y = a*x1 + b*x2 (no intercept), closed form."""
    s11 = sum(x1 * x1 for x1, _, _ in rows); s22 = sum(x2 * x2 for _, x2, _ in rows)
    s12 = sum(x1 * x2 for x1, x2, _ in rows)
    s1y = sum(x1 * y for x1, _, y in rows); s2y = sum(x2 * y for _, x2, y in rows)
    det = s11 * s22 - s12 * s12
    if not det:
        return None, None
    return (s1y * s22 - s2y * s12) / det, (s2y * s11 - s1y * s12) / det


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run')
    ap.add_argument('--tree', type=Path, default=ROOT,
                    help='the Snapintosh checkout the run was built from (default: this one)')
    ap.add_argument('--output')
    args = ap.parse_args()
    tree = args.tree.resolve()
    run = Path(args.run)
    if args.output and Path(args.output).exists():
        sys.exit(f'{args.output} exists: give a new path')
    launch = json.loads((run / 'launch.json').read_text())
    flags = launch['flags']
    for path, digest in launch.get('source_sha256', {}).items():
        rel = path.split('/Snapintosh/')[-1]
        if rel.startswith(('probes/xnuboot.c', 'probes/xnuboot/', 'shadow/', 'compat/')):
            if not (tree / rel).exists() or hashlib.sha256((tree / rel).read_bytes()).hexdigest() != digest:
                sys.exit(f'{tree / rel} differs from the run\'s build: give --tree with the sources it was built from')
    layout = Layout(flags, tree)
    raw = (run / 'context.bin').read_bytes()
    summary = json.loads((run / 'summary.json').read_text())
    hz = 19.2e6
    decoded = json.loads((run / 'decoded.json').read_text()) if (run / 'decoded.json').exists() else {}
    hz = decoded.get('host_hz', hz)
    cpus = summary['cpus_active']

    sd, ss = layout.offset('context', 'service_detail'), layout.size('service_detail')
    buckets, per_cpu = {}, []
    for cpu in range(cpus):
        base = sd + cpu * ss
        row = {}
        for i in range(144):
            calls, inc, own, mx, failed = struct.unpack_from('<5Q', raw, base + 240 + i * 40)
            if not calls:
                continue
            name = DETAIL.get(i) or f'endpoint {i - 16:#x} {ENDPOINTS.get(i - 16, "")}'.strip()
            b = buckets.setdefault(name, dict(calls=0, inclusive_seconds=0.0, self_seconds=0.0, max_us=0.0))
            b['calls'] += calls; b['inclusive_seconds'] += inc / hz; b['self_seconds'] += own / hz
            b['max_us'] = max(b['max_us'], mx / hz * 1e6)
            row[i] = (calls, inc / hz)
        per_cpu.append(row)
    for b in buckets.values():
        b['inclusive_us_each'] = b['inclusive_seconds'] / b['calls'] * 1e6

    pu, pus = layout.offset('context', 'sprr_pperm_update'), layout.size('sprr_pperm_update_state')
    tro = layout.offset('sprr_pperm_update_state', 'transactions')
    split = []
    for cpu in range(cpus):
        tpro = struct.unpack_from('<Q', raw, pu + cpu * pus + tro)[0]
        calls, seconds = per_cpu[cpu].get(1, (0, 0.0))
        split.append((tpro, calls - tpro, seconds))
    a, b = lstsq2(split)

    sparse = '-DSNAP_AUDIT_SPARSE=1' in flags
    rate = 1024 if sparse else 64
    proof = record(layout, raw, 'kernel_class_proof')
    reuse = record(layout, raw, 'kernel_reuse_state')
    pperm = record(layout, raw, 'kernel_pperm_reuse')
    variants = record(layout, raw, 'kernel_variants')
    # The leaf memo's own stats lead struct sprr_class_leaf_cache (calls, hits, scans, verified, ...).
    leaf_base = layout.offset('context', 'class_leaf')
    leaf = dict(zip(('calls', 'hits', 'scans', 'verified'), struct.unpack_from('<4Q', raw, leaf_base)))
    audits = dict(
        rate_expected=rate,
        class_proof=dict(hits=proof['hits'], verified=proof['verified'], walks=proof['walks'],
                         invalidations=proof['invalidations'], rate_ok=proof['verified'] == proof['hits'] // rate),
        refresh=dict(calls=reuse['calls'], hits=reuse['hits'], verified=reuse['verified'], saves=reuse['saves'],
                     rate_ok=reuse['verified'] == reuse['hits'] // rate),
        variant_swap=dict(swaps=variants.get('swaps'), exact=variants.get('exact'), verified=variants.get('verified'),
                          rate_ok=variants.get('verified') == (variants.get('exact', 0) + rate - 1) // rate),
        pperm_skip=dict(skipped=pperm['skipped'], verified=pperm['verified'],
                        rate_ok=pperm['verified'] == pperm['skipped'] // rate),
        leaf=dict(walks=leaf['calls'], rescanned_tables=leaf['verified'], scans=leaf['scans']))
    gate = decoded.get('exits', {}).get('token_costs', {}).get('gate', {})
    result = dict(
        run=str(run), monitor_sha256=launch.get('monitor_sha256'), audit_sparse=sparse,
        reuse_match_mapped='-DSNAP_REUSE_MATCH_MAPPED=1' in flags,
        wall_seconds=summary['wall_seconds'], cpus=cpus,
        guest_share_estimate=summary.get('guest_share_estimate'), monitor_cpu_seconds=summary.get('monitor_cpu_seconds'),
        lock=dict(busy=summary['lock_busy_fraction'], wait=summary['lock_wait_cpu_seconds'],
                  hold=summary['lock_hold_cpu_seconds']),
        converted=dict(wait=summary.get('converted_wait_cpu_seconds'), hold=summary.get('converted_hold_cpu_seconds')),
        gate=dict(waited=gate.get('waited'), wait_seconds=gate.get('wait_seconds'), timeouts=gate.get('timeouts')),
        fast_exit_cpu_seconds=summary.get('fast_exit_cpu_seconds'),
        detail=dict(sorted(buckets.items(), key=lambda kv: -kv[1]['inclusive_seconds'])),
        pperm_split=dict(per_cpu=[dict(tpro=t, other=o, seconds=s) for t, o, s in split],
                         us_per_tpro_change=a * 1e6 if a is not None else None,
                         us_per_other_change=b * 1e6 if b is not None else None),
        audits=audits)
    text = json.dumps(result, indent=1)
    if args.output:
        Path(args.output).write_text(text + '\n')
    p = buckets.get('kernel PPERM change', {}); r = buckets.get('kernel refresh, all CPUs', {})
    print(f"{run.name}: guest share {result['guest_share_estimate']:.3f}, monitor {result['monitor_cpu_seconds']:.0f} "
          f"CPU-s; token busy {result['lock']['busy']:.3f}, wait {result['lock']['wait']:.1f} s, hold "
          f"{result['lock']['hold']:.1f} s; gate wait {gate.get('wait_seconds', 0):.1f} s, timeouts {gate.get('timeouts')}")
    print(f"  kernel PPERM change: {p.get('calls')} calls, {p.get('inclusive_seconds', 0):.2f} s, max "
          f"{p.get('max_us', 0):.0f} us; per TPRO change {result['pperm_split']['us_per_tpro_change']:.1f} us, per other "
          f"{result['pperm_split']['us_per_other_change']:.1f} us")
    print(f"  kernel refresh: {r.get('calls')} calls, {r.get('inclusive_seconds', 0):.2f} s "
          f"({r.get('inclusive_us_each', 0):.1f} us each), max {r.get('max_us', 0):.0f} us")
    for k, v in audits.items():
        if isinstance(v, dict):
            print(f'  audit {k}: {v}')
    print(f"  audit rate expected 1 in {rate} (the leaf-memo rescan stays 1 in 64 walks)")


if __name__ == '__main__':
    main()
