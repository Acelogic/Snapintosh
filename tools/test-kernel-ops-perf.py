#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""kernel-ops-perf records: append-only target layout, the reader's sentinel
hash against the C implementation, and refusal of every broken relation."""
from pathlib import Path
import os
import random
import runpy
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ops = runpy.run_path(str(ROOT / 'tools/kernel_ops_perf.py'))
RECORDS = ops['RECORDS']


def layout_checks():
    layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()
    last = layout.offset('context', 'user_mode_skip')
    previous = last
    for name, (kind, fields, _) in RECORDS.items():
        offset = layout.offset('context', name)
        assert offset > previous, f'{name} is not appended after the existing context'
        assert layout.size(kind) == 8 * len(fields), f'{kind} size'
        for n, field in enumerate(fields):
            assert layout.offset(kind, field) == 8 * n, f'{kind}.{field} offset'
        previous = offset
    end = layout.offset('context', 'root_validate') + layout.size(RECORDS['root_validate'][0])
    # Later appends (EL0 signal counters, then the user-tree memo) follow these
    # records in the agreed order; nothing is interleaved with them.
    later = [layout.offset('context', n) for n in ('guest_user_signal', 'table_memo', 'user_view_memo')]
    assert later == sorted(later) and 0 <= later[0] - end < 64, 'records precede the later appends'
    assert layout.offset('context', 'class_leaf') >= layout.offset('context', 'txm_load') + layout.size('txm_load_state')
    assert layout.offset('sprr_class_leaf_cache', 'stats') == 0
    assert layout.offset('sprr_class_leaf_cache', 'entry') == layout.size('sprr_class_leaf_stats')
    # The SWITCH_ROOT memo follows every earlier field (sep_sks_request stays put).
    assert layout.offset('context', 'root_memo') >= layout.offset('context', 'sep_sks_request') + 16384
    assert layout.offset('sptm_root_memo', 'stats') == 0
    assert layout.offset('sptm_root_memo', 'entry') == layout.size('sptm_root_memo_stats') + 16
    return layout.size('context')


def hash_checks():
    with tempfile.TemporaryDirectory(prefix='kops-hash-') as d:
        src = Path(d) / 'h.c'
        src.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include "txn-publish.h"\n'
                       'int main(int c,char **v){(void)c;static _Alignas(4096) unsigned char p[4096];'
                       'FILE *f=fopen(v[1],"rb");if(!f||fread(p,1,4096,f)!=4096)return 2;fclose(f);'
                       'printf("%llu\\n",(unsigned long long)txn_publish_hash((uint64_t)(uintptr_t)p));return 0;}\n')
        exe = Path(d) / 'h'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(ROOT / 'shadow'), str(src), '-o', str(exe)], check=True)
        rng = random.Random(7)
        for n in range(24):
            page = bytes(rng.getrandbits(8) for _ in range(4096)) if n % 3 else bytes(4096)
            (Path(d) / 'page').write_bytes(page)
            out = subprocess.run([str(exe), str(Path(d) / 'page')], check=True,
                                 capture_output=True, text=True).stdout
            assert int(out) == ops['sentinel_hash'](page), 'reader hash differs from C'


def pack(name, row):
    return struct.pack(f'<{len(RECORDS[name][1])}Q', *(row[f] for f in RECORDS[name][1]))


def decoder_checks():
    # The per-call copy/flush records first; native page tables change the
    # SWITCH_ROOT relations and are checked separately (native_checks).
    flags = {flag for _, _, flag in RECORDS.values()} - {'SNAP_NATIVE_TABLES'}
    audit = dict(root_switch=dict(switches=75372, user_switches=55699, builds=2699, invalidations=2713),
                 user_updates=dict(calls=63777, entries=63777), user_mapping=dict(live_pages=103805))
    proof = dict(walks=1238, verified=128, mismatches=0)
    arena = dict(first=0xae1347000, limit=0xae1347000 + 61440 * 4096,
                 allocated=0xae1347000 + 22482 * 4096,
                 runtime_first=0xae261d000, runtime_end=0xae261d000 + 97 * 4096)
    page = bytes(range(256)) * 16
    good = {
        'txn_publish': dict(calls=80000, complete=80000, considered=80000 * 22000, published=300000,
                            runtime=80000 * 97, errors=0, armed=80000, checked=60000, noted=19999,
                            retired=0, mismatches=0, sentinel=0xae1347000 + 5 * 4096,
                            hash=ops['sentinel_hash'](page), observed=0, cursor=80000),
        'kernel_pperm_reuse': dict(calls=119592, current=110000, skipped=80000, synced=30000,
                                   repinned=110000, verified=80000 // 64, mismatches=0, errors=0),
        'user_update_skip': dict(skipped=63777, verified=63777 // 64, mismatches=0),
        'install_tlbi': dict(installs=75372, pperm_folded=75372, view_folded=55699, failure_flushes=0),
        'class_proof_mapped': dict(walks=1238, tables=1238 * 5109, groups=64 * (1238 * 5109 - 984000),
                                   empty_groups=1000, compared=128, errors=0),
        'root_validate': dict(validations=55699, sampled=55699 // 64, mismatches=0, tables=55699 * 58),
        'class_leaf': dict(calls=1238, hits=1000000, scans=400000, verified=16000,
                           mismatches=0, resets=1, poisoned=0, base=arena['first'], pages=61440, clock=100000),
        'root_memo': dict(calls=53000, hits=53000 * 225, misses=5000, records=5000, evictions=10,
                          invalidations=4000, epoch_bumps=30, flushes=0, sampled=820, mismatches=0),
        'inactive_mirror': dict(leaves=20000, present=3000, tables=900, tpro=12, budget=40, arena=1,
                                configured=660),
        'native_stats': dict.fromkeys(RECORDS['native_stats'][1], 0),
    }
    raw = {k: pack(k, v) for k, v in good.items()}
    rows = ops['decode'](raw, flags, audit, proof, arena, page)
    assert all(rows[k]['enabled'] for k in good if k != 'native_stats')
    assert not rows['native_stats']['enabled']
    # The disabled control retains the original full mapped-walk accounting.
    control_mapped = dict(good['class_proof_mapped'])
    control_mapped['groups'] = 64 * control_mapped['tables']
    control = dict(raw, class_leaf=bytes(80), class_proof_mapped=pack('class_proof_mapped', control_mapped))
    control_rows = ops['decode'](control, flags - {'SNAP_CLASS_LEAF_MEMO'}, audit, proof, arena, page)
    assert not control_rows['class_leaf']['enabled'] and control_rows['class_proof_mapped']['enabled']
    for missing in ('record', 'flag'):
        bad_raw = {k: v for k, v in raw.items() if missing != 'record' or k != 'class_leaf'}
        bad_flags = flags if missing == 'record' else flags - {'SNAP_CLASS_PROOF_MAPPED'}
        try:
            ops['decode'](bad_raw, bad_flags, audit, proof, arena, page)
        except ValueError:
            continue
        raise AssertionError(f'missing leaf prerequisite {missing} accepted')
    # Retained root verdicts are only meaningful beside the sampled word walk.
    try:
        ops['decode'](dict(raw, root_validate=bytes(32)), flags - {'SNAP_ROOT_VALIDATE_WORDS'},
                      audit, proof, arena, page)
    except ValueError:
        pass
    else:
        raise AssertionError('root memo without sampled word validation accepted')
    # Disabled flags: zero records accepted, nonzero refused.
    zero = {k: bytes(len(v)) for k, v in raw.items()}
    assert not any(r['enabled'] for r in ops['decode'](zero, set(), audit, proof, arena).values())
    corruptions = [
        ('txn_publish', 'mismatches', 1), ('txn_publish', 'errors', 1), ('txn_publish', 'complete', 79999),
        ('txn_publish', 'runtime', 1), ('txn_publish', 'published', 80000 * 22000 + 1),
        ('txn_publish', 'checked', 0), ('txn_publish', 'armed', 80002), ('txn_publish', 'sentinel', 0),
        ('txn_publish', 'sentinel', 0xae261d000), ('txn_publish', 'hash', 1), ('txn_publish', 'observed', 2),
        ('kernel_pperm_reuse', 'mismatches', 1), ('kernel_pperm_reuse', 'repinned', 109999),
        ('kernel_pperm_reuse', 'synced', 30001), ('kernel_pperm_reuse', 'verified', 0),
        ('kernel_pperm_reuse', 'errors', 1),
        ('user_update_skip', 'skipped', 63776), ('user_update_skip', 'verified', 1),
        ('user_update_skip', 'mismatches', 1),
        ('install_tlbi', 'installs', 1), ('install_tlbi', 'view_folded', 1), ('install_tlbi', 'failure_flushes', 1),
        ('class_proof_mapped', 'walks', 1), ('class_proof_mapped', 'compared', 1),
        ('class_proof_mapped', 'groups', 1), ('class_proof_mapped', 'errors', 1),
        ('root_validate', 'validations', 55698), ('root_validate', 'sampled', 0), ('root_validate', 'mismatches', 1),
        ('class_leaf', 'calls', 1237), ('class_leaf', 'hits', 1), ('class_leaf', 'scans', 1),
        ('class_leaf', 'verified', 0), ('class_leaf', 'mismatches', 1), ('class_leaf', 'poisoned', 1),
        ('class_leaf', 'resets', 0), ('class_leaf', 'resets', 1239), ('class_leaf', 'base', 0),
        ('class_leaf', 'pages', 61439), ('class_leaf', 'clock', (1 << 48) - 1),
        ('root_memo', 'mismatches', 1), ('root_memo', 'calls', 52999), ('root_memo', 'calls', 55699),
        ('root_memo', 'hits', 0), ('root_memo', 'records', 4999), ('root_memo', 'sampled', 0),
        ('root_memo', 'sampled', 55699 // 64 + 1), ('root_memo', 'evictions', 5001),
        ('root_memo', 'invalidations', 5001), ('root_memo', 'flushes', 31),
        ('inactive_mirror', 'leaves', 103806), ('inactive_mirror', 'configured', 2713 - 53 + 1),
    ]
    for name, field, value in corruptions:
        bad = dict(good[name]); bad[field] = value
        broken = dict(raw); broken[name] = pack(name, bad)
        try:
            ops['decode'](broken, flags, audit, proof, arena, page)
        except ValueError:
            continue
        raise AssertionError(f'corrupt {name}.{field} accepted')
    # Mixed user+kernel UPDATE_DISJOINT calls are audited user updates that
    # refresh the kernel views instead of skipping (generation71: 373371 calls
    # carrying 373626 records). Each has at least two records, so at most
    # 255 calls there can go unskipped. Above, single-record calls allow none.
    mixed_rows = [(373371, 373626, 373116, 255), (373371, 373626, 373371, 0),
                  (373371, 373626, 373115, None), (373371, 373626, 373372, None), (63, 63, 63, None)]
    for calls, entries, skipped, mixed in mixed_rows:
        row = dict(skipped=skipped, verified=skipped // 64, mismatches=0)
        updates = dict(audit, user_updates=dict(calls=calls, entries=entries))
        try:
            got = ops['decode'](dict(raw, user_update_skip=pack('user_update_skip', row)), flags, updates,
                                proof, arena, page)['user_update_skip']['mixed_calls']
        except ValueError as e:
            assert str(e).startswith('user_update_skip:'), e
            got = None
        assert got == mixed, f'{skipped} skips of {calls} calls, {entries} records: mixed {got}'
    # A changed pending sentinel page is refused; an observed one is not re-hashed.
    try:
        ops['decode'](raw, flags, audit, proof, arena, page[:-1] + b'\x01')
    except ValueError:
        pass
    else:
        raise AssertionError('changed sentinel page accepted')
    observed = dict(good['txn_publish'], observed=1, hash=0)
    ops['decode'](dict(raw, txn_publish=pack('txn_publish', observed)), flags, audit, proof, arena, None)
    nonzero = dict(zero); nonzero['install_tlbi'] = pack('install_tlbi', good['install_tlbi'])
    try:
        ops['decode'](nonzero, set(), audit, proof, arena)
    except ValueError:
        pass
    else:
        raise AssertionError('counters without their flag accepted')
    return len(corruptions) + 6 + sum(m is None for *_, m in mixed_rows) + native_checks(good, audit, proof,
                                                                                       arena, page)


def native_checks(good, audit, proof, arena, page):
    """SNAP_NATIVE_TABLES: 53000 cache-hit switches of which the default
    1-in-64 sample (829) are walked; installs fold nothing."""
    flags = {flag for _, _, flag in RECORDS.values()}
    hits = audit['root_switch']['user_switches'] - audit['root_switch']['builds']
    due = lambda asks, shift=6: (asks + (1 << shift) - 1) >> shift
    native = dict(propagated=400000, refused=0, paths=300, syncs=2699, installs=55699, local_flushes=30000,
                  flips=90000, tlbi_calls=120000, tlbi_pages=460000, tlbi_full=5000,
                  audit_asks=100000, audits=due(100000), audit_failures=0,
                  hit_asks=hits, hit_skips=hits - due(hits), proof_asks=200000,
                  proof_skips=200000 - due(200000), pperm_skips=70000,
                  reuse_asks=119000, reuse_checks=due(119000), reuse_failures=0,
                  pperm_flushes=119592 - 80000, created=0, uncreated=0, coverages=due(due(100000)))
    walked = audit['root_switch']['user_switches'] - native['hit_skips']
    rows = dict(good, native_stats=native,
                install_tlbi=dict(installs=75372, pperm_folded=0, view_folded=0, failure_flushes=0),
                root_validate=dict(validations=walked, sampled=walked // 64, mismatches=0, tables=walked * 58),
                root_memo=dict(good['root_memo'], calls=due(hits), sampled=13))
    raw = {k: pack(k, v) for k, v in rows.items()}
    got = ops['decode'](raw, flags, audit, proof, arena, page)
    assert got['native_stats']['enabled'] and got['native_stats']['audit_shift'] == 6
    # Any one rate fits: every audit run (shift 0) walks every switch.
    every = dict(native, hit_skips=0, audits=100000, proof_skips=0, reuse_checks=119000,
                 coverages=due(100000))
    full = dict(raw, native_stats=pack('native_stats', every),
                root_validate=pack('root_validate', good['root_validate']),
                root_memo=pack('root_memo', good['root_memo']))
    assert ops['decode'](full, flags, audit, proof, arena, page)['native_stats']['audit_shift'] == 0
    # Roots cached at their constructor (SNAP_NATIVE_LIVE) derive their
    # variants at a first install that needed no build.
    live = dict(raw, native_stats=pack('native_stats', dict(native, created=100, syncs=2699 + 60)))
    assert ops['decode'](live, flags, audit, proof, arena, page)['native_stats']['created'] == 100
    try:
        ops['decode'](dict(raw, native_stats=pack('native_stats', dict(native, created=100, syncs=2699 + 101))),
                      flags, audit, proof, arena, page)
    except ValueError:
        pass
    else:
        raise AssertionError('native: more syncs than builds and constructed roots accepted')
    corruptions = [
        ('native_stats', 'refused', 1), ('native_stats', 'audit_failures', 1),
        ('native_stats', 'installs', 55698), ('native_stats', 'syncs', 2698),
        ('native_stats', 'hit_asks', hits + 1), ('native_stats', 'hit_skips', native['hit_skips'] + 1),
        ('native_stats', 'audits', native['audits'] - 1), ('native_stats', 'audits', 0),
        ('native_stats', 'proof_skips', native['proof_skips'] + 1),
        ('native_stats', 'local_flushes', 75373), ('native_stats', 'pperm_skips', 75373),
        ('native_stats', 'tlbi_full', 120001), ('native_stats', 'paths', 120001),
        ('native_stats', 'tlbi_pages', 64 * 115000 + 1),
        ('native_stats', 'reuse_failures', 1), ('native_stats', 'reuse_checks', due(119000) + 1),
        ('native_stats', 'reuse_asks', 119593), ('native_stats', 'pperm_flushes', 39591),
        ('native_stats', 'pperm_flushes', 39593),
        ('native_stats', 'coverages', due(due(100000)) + 1), ('native_stats', 'syncs', 2700),
        # The non-native relations no longer hold.
        ('root_validate', 'validations', 55699), ('root_memo', 'calls', hits),
        ('install_tlbi', 'pperm_folded', 75372), ('install_tlbi', 'view_folded', 55699),
    ]
    for name, field, value in corruptions:
        bad = dict(rows[name]); bad[field] = value
        try:
            ops['decode'](dict(raw, **{name: pack(name, bad)}), flags, audit, proof, arena, page)
        except ValueError:
            continue
        raise AssertionError(f'native: corrupt {name}.{field} accepted')
    try:
        ops['decode']({k: v for k, v in raw.items() if k != 'native_stats'}, flags, audit, proof, arena, page)
    except ValueError:
        pass
    else:
        raise AssertionError('native: enabled record not read accepted')
    return len(corruptions) + 1


def main():
    size = layout_checks()
    hash_checks()
    refused = decoder_checks()
    print(f'PASS: kernel-ops-perf records appended (context {size} bytes), reader hash matches C, '
          f'{refused} corruptions refused')


if __name__ == '__main__':
    main()
