#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read per-CPU lock wait/handler timing from an audited stopped monitor."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
import monitor_work

# Live captures require the current target layout. Offline decoders retain
# the exact old bitmap shape so historical128MiB evidence remains replayable.
ARENA_BITMAP_BYTES = monitor_work.WORK_PAGES // 8
ROOT_PUBLISH_BYTES = 80 + ARENA_BITMAP_BYTES
PRIVATE_PAGES_BYTES = 48 + ARENA_BITMAP_BYTES
CLASS_PROOF_BYTES = 160 + ARENA_BITMAP_BYTES

def bitmap_capacity(raw,header):
    pages=(len(raw)-header)*8
    if pages not in (32768,monitor_work.WORK_PAGES):
        raise ValueError('invalid arena bitmap shape')
    return pages

FIELDS = ('attempts', 'acquired', 'cancelled', 'contended', 'wait_ticks', 'hold_ticks',
          'max_wait_ticks', 'max_hold_ticks', 'first_tick', 'last_tick', 'enter_tick',
          'acquire_tick', 'category', 'stage', 'errors')
LABELS = {1: 'WFE', 0x18: 'sysreg', 0x20: 'instruction abort',
          0x24: 'data abort', 0x32: 'single step', 64: 'IRQ', 65: 'FIQ',
          66: 'SError', 67: 'secondary bootstrap'}
DETAIL_LABELS={0:'kernel refresh, all CPUs',1:'kernel PPERM change',
               2:'user refresh, all CPUs',3:'user sync, one CPU',4:'other monitor call',
               5:'canonical user view proof'}

def decode_view_store_compare(raw,expected_calls,expected_tables,copies=1):
    if len(raw)!=56:raise ValueError('invalid private store comparison stats size')
    row=dict(zip(('calls','complete','tables','compared','skipped','changed','failures'),struct.unpack('<7Q',raw)))
    if (copies not in (1,6) or not expected_calls or row['calls']!=expected_calls or row['complete']!=expected_calls or
            not copies*expected_calls<=expected_tables<=128*copies*expected_calls or
            expected_tables%copies or
            row['tables']!=expected_tables or row['compared']!=512*expected_tables or
            row['skipped']+row['changed']!=row['compared'] or
            not row['skipped'] or not row['changed'] or row['failures']):
        raise ValueError('private store comparison differs from audited syncs')
    return row

def decode_view_table_reads(raw,expected_calls):
    if len(raw)!=48:raise ValueError('invalid private-sync reader stats size')
    row=dict(zip(('calls','complete','tables','map_calls','map_complete','errors'),struct.unpack('<6Q',raw)))
    if (not expected_calls or row['calls']!=expected_calls or row['complete']!=expected_calls or
            row['errors'] or not expected_calls<=row['tables']<=128*expected_calls or
            row['map_calls']!=row['tables'] or row['map_complete']!=row['tables']):
        raise ValueError('private-sync table reader differs from completed syncs')
    return row

def decode_user_zero_groups(raw,source_tables):
    if len(raw)!=16:raise ValueError('invalid zero-group stats size')
    groups,empty=struct.unpack('<2Q',raw)
    if not source_tables or groups!=64*source_tables or not 0<empty<groups:
        raise ValueError('zero groups differ from full preparation or paths were not exercised')
    return dict(groups=groups,empty_groups=empty,empty_fraction=empty/groups)

def decode_user_table_reads(raw,source_tables):
    if len(raw)!=24:raise ValueError('invalid bounded table-reader stats size')
    row=dict(zip(('calls','complete','errors'),struct.unpack('<3Q',raw)))
    if not source_tables or row['calls']!=source_tables or row['complete']!=source_tables or row['errors']:
        raise ValueError('table reader differs from full preparation walk count')
    return row

def decode_user_publish(raw,expected_calls,root):
    if len(raw)!=48:raise ValueError('invalid user publication stats size')
    row=dict(zip(('calls','complete','considered','published','skipped','errors'),struct.unpack('<6Q',raw)))
    if (not expected_calls or row['calls']!=expected_calls or row['complete']!=expected_calls or
            row['errors'] or not row['published'] or not row['skipped'] or
            row['considered']!=row['published']+row['skipped'] or
            not expected_calls<=row['considered']<=expected_calls*128 or
            row['published']+root['published']>root['pages_noted']):
        raise ValueError('invalid or unexercised user publication counters')
    row['skipped_fraction']=row['skipped']/row['considered']
    return row

def decode_root_publish(raw,first,allocated,switches,runtime_first,runtime_end):
    capacity=bitmap_capacity(raw,80)
    if ((first|allocated|runtime_first|runtime_end)&4095 or
            not 0<allocated-first<=capacity*4096 or
            not first<=runtime_first<runtime_end<=allocated):
        raise ValueError('invalid root publication geometry')
    fields=('notes','pages_noted','calls','complete','considered','published','skipped',
            'errors','always_first','always_end')
    row=dict(zip(fields,struct.unpack_from('<10Q',raw)))
    pages=(allocated-first)//4096;always=(runtime_end-runtime_first)//4096
    bits=int.from_bytes(raw[80:],'little')
    if (row['errors'] or row['calls']!=switches or row['complete']!=switches or
            not switches or row['always_first']!=runtime_first or row['always_end']!=runtime_end or
            row['notes']<switches or row['pages_noted']<row['notes'] or
            row['considered']!=row['published']+row['skipped'] or
            not switches*always<=row['published']<=row['pages_noted'] or
            not row['published']<=row['considered']<=switches*pages or
            not row['skipped'] or bits>>pages):
        raise ValueError('invalid or unexercised root publication counters')
    row.update(allocated_pages=pages,always_pages=always,pending_pages=bits.bit_count(),
               bitmap_sha256=hashlib.sha256(raw[80:]).hexdigest(),
               skipped_fraction=row['skipped']/row['considered'])
    for key in ('always_first','always_end'):row[key]=hex(row[key])
    return row

def decode_private_pages(raw,first,allocated,owners,views,canonical):
    capacity=bitmap_capacity(raw,48)
    if ((first|allocated)&4095 or
            not 0<allocated-first<=capacity*4096 or len(owners)!=(allocated-first)//4096):
        raise ValueError('invalid private provenance geometry')
    row=dict(zip(('allocations','private_allocations','retired','writes','private_writes','errors'),
                 struct.unpack_from('<6Q',raw)))
    bits=int.from_bytes(raw[48:],'little')
    if (row['errors'] or not 0<row['private_allocations']<=row['allocations'] or
            row['retired']>row['allocations'] or
            not 0<row['private_writes']<row['writes'] or
            bits>>len(owners) or bits.bit_count()>row['private_allocations']):
        raise ValueError('invalid or unexercised private provenance counters')
    expected=set();sources=set(canonical)
    def page(pa):
        if pa&4095 or not first<=pa<allocated:
            raise ValueError('private provenance page outside allocated arena')
        return (pa-first)//4096
    for view in views:
        if not 0<=view['owner']<=64 or not 1<=len(view['sources'])<=128:
            raise ValueError('invalid private view owner or count')
        if (view['root']!=view['sources'][0] or len(set(view['sources']))!=len(view['sources']) or
                len(view['copies'])!=view.get('columns',6)*len(view['sources'])):
            raise ValueError('invalid private view source/copy records')
        sources.update(view['sources'])
        for pa in view['copies']:
            i=page(pa)
            if pa in expected or owners[i]!=view['owner']:
                raise ValueError('private copy alias or allocation owner mismatch')
            expected.add(pa)
    if not expected or sources&expected:
        raise ValueError('canonical source marked as private copy')
    for pa in sources:
        if owners[page(pa)]==255:raise ValueError('canonical source uses retired storage')
    wanted=sum(1<<page(pa) for pa in expected)
    if wanted!=bits:raise ValueError('allocation bitmap differs from independent private metadata')
    row.update(private_pages=len(expected),canonical_pages=len(sources),views=len(views),
               bitmap_sha256=hashlib.sha256(raw[48:]).hexdigest(),current_snapshot_verified=True)
    return row

def decode_user_prepare(raw,refresh_calls):
    if len(raw)!=56:raise ValueError('invalid fused preparation stats size')
    row=dict(zip(('calls','successes','verified','mismatches','failures','source_tables',
                  'private_tables'),struct.unpack('<7Q',raw)))
    if (row['calls']!=refresh_calls or row['successes']!=row['calls'] or
            row['calls']<64 or row['verified']!=row['calls']//64 or
            row['mismatches'] or row['failures'] or
            not row['calls']<=row['source_tables']<=8192*row['calls'] or
            not row['calls']<=row['private_tables']<=128*row['calls']):
        raise ValueError('invalid or unexercised fused preparation stats')
    row['mean_source_tables']=row['source_tables']/row['calls']
    row['mean_private_tables']=row['private_tables']/row['calls']
    return row


TREE_MEMO_FIELDS=('calls','samples','checked','mismatches','scan_hits','scan_misses','copy_hits',
                  'copy_misses','notes','allocations','errors','walk_hits','walk_misses','forced')
def decode_user_tree_memo(raw,refresh_calls,sync_calls,source_tables,destination_tables):
    """SNAP_USER_TREE_MEMO counters, bound to the audited refresh/sync counts.

    Every memo transaction is one all-CPU refresh or one cached one-CPU sync;
    every 64th recomputes everything and checks every claim it would have used.
    Refresh level3 scans are a subset of the recorded source tables; destination
    pages (hits+misses) equal the six-CPU plus one-CPU compared table counts."""
    if len(raw)!=8*len(TREE_MEMO_FIELDS):raise ValueError('invalid user tree memo stats size')
    row=dict(zip(TREE_MEMO_FIELDS,struct.unpack(f'<{len(TREE_MEMO_FIELDS)}Q',raw)))
    scans=row['scan_hits']+row['scan_misses'];copies=row['copy_hits']+row['copy_misses']
    if (not refresh_calls or row['calls']!=refresh_calls+sync_calls or
            row['samples']!=row['calls']//64 or not row['samples'] or not row['checked'] or
            row['forced']>row['calls']-row['samples'] or
            row['mismatches'] or row['errors'] or not row['notes'] or not row['allocations'] or
            not 0<scans<=source_tables or not row['scan_hits'] or
            copies!=destination_tables or not row['copy_hits']):
        raise ValueError('user tree memo differs from audited transactions or was not exercised')
    row['scan_hit_fraction']=row['scan_hits']/scans
    row['copy_hit_fraction']=row['copy_hits']/copies
    walks=row['walk_hits']+row['walk_misses']
    row['walk_hit_fraction']=row['walk_hits']/walks if walks else None
    return row

def native_idle(raw,what):
    """SNAP_NATIVE_TABLES: user roots run on two shared permission variants kept
    exact per canonical store (shadow/native-view.h), so the per-CPU private
    user-view machinery never runs. Its counters must be exactly zero."""
    if any(raw):raise ValueError(f'{what}: private user-view counters advanced under native page tables')
    return dict(native_tables=True,raw_hex=raw.hex(),
                boundary='Native page tables: no per-CPU private user view exists; this machinery never ran.')

def decode_native_tree_memo(raw):
    """The table memo still notes every arena store and allocation (write
    generations stay exact for its other users) but no refresh or sync looks
    anything up under native page tables."""
    if len(raw)!=8*len(TREE_MEMO_FIELDS):raise ValueError('invalid user tree memo stats size')
    row=dict(zip(TREE_MEMO_FIELDS,struct.unpack(f'<{len(TREE_MEMO_FIELDS)}Q',raw)))
    idle=('calls','samples','checked','mismatches','scan_hits','scan_misses','copy_hits','copy_misses',
          'forced','errors')
    if any(row[k] for k in idle) or not row['notes'] or not row['allocations']:
        raise ValueError('user tree memo lookups under native page tables, or notes not exercised')
    walks=row['walk_hits']+row['walk_misses']
    row['walk_hit_fraction']=row['walk_hits']/walks if walks else None
    return dict(row,native_tables=True)

def decode_kernel_class_proof(raw,kernel,transactions,first,limit,allocated,rate=64):
    # rate: the hit verification cadence, 1024 under SNAP_AUDIT_SPARSE (compat/audit-sparse.h).
    capacity=bitmap_capacity(raw,160)
    fields=('calls','hits','verified','mismatches','errors','walks','invalidations',
            'tracked_writes','wide_invalidations','epoch','valid','root','forbidden',
            'first','limit','saved_epoch','tables','pages','classes','tracked_pages')
    row=dict(zip(fields,struct.unpack_from('<20Q',raw)))
    if (row['errors'] or row['mismatches'] or row['valid'] not in (0,1) or
            row['calls']!=transactions or row['calls']!=row['hits']+row['walks'] or
            not row['walks'] or row['hits']<64 or row['verified']!=row['hits']//rate or
            row['epoch']!=row['tracked_writes']+row['wide_invalidations'] or
            row['epoch']==2**64-1 or row['invalidations']>row['epoch'] or
            row['saved_epoch']>row['epoch'] or
            (row['valid'] and row['saved_epoch']!=row['epoch']) or
            row['root']!=int(kernel['canonical_root'],16) or row['forbidden']!=1<<9 or
            row['first']!=first or row['limit']!=limit or
            not first<=row['root']<allocated<=limit or
            not 0<limit-first<=capacity*4096 or (first|limit|allocated)&4095 or
            not 1<=row['tracked_pages']<=row['tables']<=8192 or
            row['classes']&~0xffff or row['classes']&row['forbidden']):
        raise ValueError('invalid or unexercised kernel class proof')
    bits=int.from_bytes(raw[160:],'little')
    if (bits.bit_count()!=row['tracked_pages'] or bits>>((allocated-first)//4096) or
            not bits&(1<<((row['root']-first)//4096))):
        raise ValueError('invalid canonical proof bitmap')
    if row['valid']:
        pages=[int(p,16) for p in kernel['canonical_table_pages']]
        if (len(pages)!=len(set(pages)) or len(pages)!=kernel['canonical_tables'] or
                any(p&4095 or not first<=p<allocated for p in pages)):
            raise ValueError('invalid independently audited canonical pages')
        expected=sum(1<<((p-first)//4096) for p in pages)
        classes=sum(1<<int(k) for k,v in kernel['selector_4k_pages'].items() if v)
        if (bits!=expected or row['tables']!=len(pages) or row['classes']!=classes or
                row['pages']!=sum(kernel['selector_4k_pages'].values())):
            raise ValueError('cached class proof differs from independent full tree audit')
    row['current_snapshot_verified']=bool(row['valid'])
    row['bitmap_sha256']=hashlib.sha256(raw[160:]).hexdigest()
    for key in ('root','first','limit','classes','forbidden'):row[key]=hex(row[key])
    return row


def decode_kernel_reuse(raw,kernel,rate=64):
    # rate: the reuse-hit verification cadence, 1024 under SNAP_AUDIT_SPARSE.
    if len(raw)!=128:raise ValueError('invalid kernel reuse header size')
    values=struct.unpack('<16Q',raw)
    row=dict(zip(('calls','hits','verified','mismatches','errors','saves','invalidations',
                  'valid','root','count'),values[:10]))
    if (row['errors'] or row['mismatches'] or row['valid'] not in (0,1) or
            row['root']!=int(kernel['canonical_root'],16) or
            not 1<=row['count']<=kernel['private_source_tables']<=128 or
            not row['saves'] or row['hits']<64 or row['verified']!=row['hits']//rate or
            row['calls']!=row['hits']+row['saves'] or
            (row['valid'] and (row['count']!=kernel['private_source_tables'] or
                              list(values[10:])!=[int(x,16) for x in kernel['pperm']]))):
        raise ValueError('invalid or unexercised kernel reuse proof')
    row['pperm']=[hex(x) for x in values[10:]]
    row['root']=hex(row['root']);return row


def decode_detail(raw,layout,hz,hold_ticks):
    if (len(raw)!=layout.size('service_detail') or layout.size('service_detail_bucket')!=40
            or layout.size('service_detail_frame')!=24 or not 0<hz<10**10):
        raise ValueError('invalid detailed timing layout or frequency')
    fields=('errors','depth','max_depth','begins','ends','outer_ticks')
    row={k:struct.unpack_from('<Q',raw,layout.offset('service_detail',k))[0] for k in fields}
    if (row['errors'] or row['depth'] or row['begins']!=row['ends'] or
            row['outer_ticks']>hold_ticks or row['max_depth']>8 or
            bool(row['max_depth'])!=bool(row['begins'])):
        raise ValueError('incomplete or out-of-budget detailed intervals')
    buckets=[]
    start=layout.offset('service_detail','buckets')
    for i in range(144):
        calls,inclusive,own,maximum,failed=struct.unpack_from('<5Q',raw,start+i*40)
        if (own>inclusive or maximum>inclusive or failed>calls or
                (not calls and (inclusive or own or maximum or failed)) or
                (i not in DETAIL_LABELS and i<16 and calls)):
            raise ValueError('invalid detailed bucket totals')
        if calls:
            label=DETAIL_LABELS.get(i)
            if label is None:
                endpoint=i-16
                label=f'monitor {endpoint:#x}: '+run.SPTM_ENDPOINTS.get(endpoint,'unnamed endpoint')
            buckets.append(dict(bucket=i,name=label,calls=calls,inclusive_ticks=inclusive,
                self_ticks=own,max_ticks=maximum,failed=failed,inclusive_seconds=inclusive/hz,
                self_seconds=own/hz,max_seconds=maximum/hz))
    if (sum(b['calls'] for b in buckets)!=row['begins'] or
            sum(b['self_ticks'] for b in buckets)!=row['outer_ticks']):
        raise ValueError('detailed self-time/call conservation failed')
    row.update(outer_seconds=row['outer_ticks']/hz,buckets=buckets)
    return row


def decode(raw, layout, hz, acquired):
    if len(raw) != layout.size('service_profile') or not 0 < hz < 10**10:
        raise ValueError('invalid profile size or host frequency')
    row = {name: struct.unpack_from('<Q', raw, layout.offset('service_profile', name))[0]
           for name in FIELDS}
    if (not row['attempts'] or row['stage'] or row['errors'] or
            row['attempts'] != row['acquired'] + row['cancelled'] or
            row['acquired'] != acquired or row['contended'] > row['attempts']):
        raise ValueError('incomplete profile or acquisition count mismatch')
    start = layout.offset('service_profile', 'buckets')
    stride = layout.size('service_profile_bucket')
    if stride != 24:
        raise ValueError('unexpected profile bucket layout')
    buckets = []
    for category in range(68):
        entries, wait, hold = struct.unpack_from('<3Q', raw, start + category * stride)
        if not entries and (wait or hold):
            raise ValueError('time attributed to an empty bucket')
        if entries:
            buckets.append(dict(category=category, name=LABELS.get(category, f'EC {category:#x}'),
                                entries=entries, wait_ticks=wait, hold_ticks=hold,
                                wait_seconds=wait / hz, hold_seconds=hold / hz))
    if (sum(b['entries'] for b in buckets) != row['attempts'] or
            sum(b['wait_ticks'] for b in buckets) != row['wait_ticks'] or
            sum(b['hold_ticks'] for b in buckets) != row['hold_ticks']):
        raise ValueError('bucket totals do not match profile totals')
    elapsed = (row['last_tick'] - row['first_tick']) & ((1 << 64) - 1)
    measured = row['wait_ticks'] + row['hold_ticks']
    if (measured > elapsed or row['max_wait_ticks'] > row['wait_ticks'] or
            row['max_hold_ticks'] > row['hold_ticks']):
        raise ValueError('profile time exceeds observed interval')
    row.update(elapsed_seconds=elapsed / hz, wait_seconds=row['wait_ticks'] / hz,
               hold_seconds=row['hold_ticks'] / hz,
               outside_instrumented_seconds=(elapsed - measured) / hz,
               buckets=sorted(buckets, key=lambda b: b['hold_ticks'], reverse=True))
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--step-translation', action='store_true')
    ap.add_argument('--user-view-cache', action='store_true')
    ap.add_argument('--user-only-tlbi', action='store_true')
    ap.add_argument('--service-detail', action='store_true')
    ap.add_argument('--kernel-publish', action='store_true')
    ap.add_argument('--kernel-reuse', action='store_true')
    ap.add_argument('--user-fused', action='store_true')
    ap.add_argument('--kernel-class-proof', action='store_true')
    ap.add_argument('--user-prepare', action='store_true')
    ap.add_argument('--private-view-epoch', action='store_true')
    ap.add_argument('--root-publish', action='store_true')
    ap.add_argument('--user-publish', action='store_true')
    ap.add_argument('--user-table-read', action='store_true')
    ap.add_argument('--view-table-read', action='store_true')
    ap.add_argument('--view-store-compare', action='store_true')
    ap.add_argument('--user-fused-compare', action='store_true')
    ap.add_argument('--user-zero-group', action='store_true')
    ap.add_argument('--kernel-ops-perf', default='',
                    help='comma-separated SNAP_* kernel-ops-perf flags built into the monitor')
    ap.add_argument('--user-tree-memo', action='store_true')
    args = ap.parse_args()
    ops_flags = {f for f in args.kernel_ops_perf.split(',') if f}
    # SNAP_AUDIT_SPARSE (compat/audit-sparse.h): sampled audits 1 in 1024 instead of 1 in 64.
    audit_rate = 1024 if 'SNAP_AUDIT_SPARSE' in ops_flags else 64
    if 'SNAP_CLASS_PROOF_MAPPED' in ops_flags and not args.kernel_class_proof:
        raise ValueError('mapped class-walk capture requires the class proof record')
    if args.user_fused and not args.service_detail:
        raise ValueError('fused user-view capture requires detailed service counters')
    if args.user_prepare and not args.service_detail:
        raise ValueError('fused preparation capture requires detailed service counters')
    if args.user_publish and not (args.root_publish and args.private_view_epoch and args.service_detail):
        raise ValueError('user publication capture requires root, private ownership and service audits')
    if args.user_table_read and not args.user_prepare:
        raise ValueError('bounded table reader capture requires full user preparation counters')
    if args.view_table_read and not (args.user_view_cache and args.service_detail):
        raise ValueError('private-sync reader capture requires user proofs and detailed service counters')
    if args.view_store_compare and not (args.view_table_read and args.private_view_epoch):
        raise ValueError('store comparison capture requires source reader and private provenance audits')
    if args.user_fused_compare and not (args.view_store_compare and args.user_zero_group and args.user_fused):
        raise ValueError('fused comparison capture requires private comparison and full fused preparation audits')
    if args.user_tree_memo and not (args.user_fused_compare and args.view_store_compare):
        raise ValueError('user tree memo capture requires both compared user-view audits')
    if args.user_zero_group and not (args.user_table_read and args.user_prepare):
        raise ValueError('zero-group capture requires source-reader and full preparation counters')
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid capture prefix')
    base = ROOT / 'build' / args.prefix
    audit_raw = Path(f'{base}-audit.json').read_bytes()
    audit = json.loads(audit_raw)
    if not audit['runtime_stop_qualified'] or not audit['user_mapping_qualified']:
        raise ValueError('requires an audited clean stopped runtime')
    # SNAP_NATIVE_TABLES, from this runtime root's audit of the same stop. The
    # kernel-ops-perf flags (the launch's build defines) must agree.
    native = bool(audit.get('native_tables', {}).get('enabled'))
    if ops_flags and native != ('SNAP_NATIVE_TABLES' in ops_flags):
        raise ValueError('native page tables differ between the audit and the kernel-ops-perf flags')
    layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest() != audit['monitor_sha256']:
        raise ValueError('built monitor differs from audit')
    proxy = run.connect(args.device, tries=1)
    try:
        info = proxy.bootinfo()
        work, size = run.resident_work(proxy, info)
        table_limit=work+size
        if audit.get('txm_native',{}).get('enabled'):
            table_limit=int(audit['txm_native']['params'][1],16)
            if table_limit+0x300000!=work+size or struct.unpack('<Q',proxy.readmem(
                    work+layout.offset('context','work_end'),8,live=True))[0]!=table_limit:
                raise ValueError('native Image4/table reservation differs from audit')
        if proxy.readmem(info['heap_base'] + run.CODE_AT, len(blob), live=True) != blob:
            raise ValueError('resident monitor differs from audited build')
        services = work + layout.offset('context', 'services')
        expected = struct.pack('<8Q', *audit['service'])
        if proxy.readmem(services, len(expected), live=True) != expected:
            raise ValueError('service state changed since audit')
        params, = struct.unpack('<Q', proxy.readmem(work, 8, live=True))
        hz, = struct.unpack('<Q', proxy.readmem(params + layout.offset('params','clock_host_hz'), 8, live=True))
        address = work + layout.offset('context', 'service_profile')
        stride = layout.size('service_profile')
        if not work <= address <= work + size - 6 * stride:
            raise ValueError('profile outside monitor work area')
        raw = proxy.readmem(address, 6 * stride, live=True)
        if raw != proxy.readmem(address, len(raw), live=True):
            raise ValueError('profile changed while stopped')
        cpus = []
        for slot in range(6):
            acquired = next(r['service_acquires'] for r in audit['cpu_rows'] if r['slot'] == slot)
            cpus.append(dict(slot=slot, **decode(raw[slot*stride:(slot+1)*stride], layout, hz, acquired)))
        result = dict(monitor_sha256=audit['monitor_sha256'],
                      audit_sha256=hashlib.sha256(audit_raw).hexdigest(), host_hz=hz,
                      raw_hex=raw.hex(), cpus=cpus,
                      boundary='Instrumented host-counter intervals include measurement overhead. '
                               'Wait time overlaps across CPUs. Outside time includes guest execution, '
                               'assembly entry/exit and unmeasured monitor work; it is not guest-only time.')
        if args.step_translation:
            start = work + layout.offset('context', 'step_translation')
            stride = layout.size('step_translation')
            if stride != 80 or not work <= start <= work + size - 6 * stride:
                raise ValueError('invalid step translation layout')
            raw = proxy.readmem(start, 6 * stride, live=True)
            if raw != proxy.readmem(start, len(raw), live=True):
                raise ValueError('step translation state changed while stopped')
            fields = ('valid','va_page','pa_page','generation','guard','hits','misses',
                      'invalidations','verified','mismatches')
            rows = [dict(slot=n, **dict(zip(fields, struct.unpack_from('<10Q',raw,n*stride))))
                    for n in range(6)]
            if any(r['mismatches'] or r['verified'] > r['hits'] // 1024 or
                   r['valid'] > 1 for r in rows):
                raise ValueError('step translation verification failed')
            result['step_translation'] = dict(raw_hex=raw.hex(), cpus=rows)
        if args.user_view_cache:
            start=work+layout.offset('context','user_view_epoch')
            proof_start=work+layout.offset('context','user_view_proofs')
            stats_start=work+layout.offset('context','user_view_proof_stats')
            if (layout.size('sprr_view_proof')!=32 or layout.size('sprr_view_proof_stats')!=32 or
                    proof_start!=start+8 or stats_start!=proof_start+64*32 or
                    not work<=start<stats_start+6*32<=work+size):
                raise ValueError('unexpected user-view proof layout')
            raw=proxy.readmem(start,stats_start+6*32-start,live=True)
            if raw!=proxy.readmem(start,len(raw),live=True):
                raise ValueError('user-view proof state changed while stopped')
            epoch,=struct.unpack_from('<Q',raw)
            rows=[dict(slot=n,**dict(zip(('calls','hits','verified','mismatches'),
                  struct.unpack_from('<4Q',raw,8+64*32+n*32)))) for n in range(6)]
            if native:
                # No private view is ever proved or reused: every counter and
                # every retained proof stays zero.
                if not epoch or any(raw[8:]):
                    raise ValueError('user-view proof cache used under native page tables')
                result['user_view_cache']=dict(native_tables=True,epoch=epoch,raw_hex=raw.hex(),cpus=rows,
                    proofs=[],calls=0,hits=0,verified=0,mismatches=0,
                    boundary='Native page tables: no per-CPU user view exists to prove; the shared '
                             'variants are kept exact per store and audited by sampling.')
            else:
                if not epoch or any(r['hits']>r['calls'] or r['mismatches'] or
                        r['verified']!=(r['hits']+63)//64 for r in rows):
                    raise ValueError('user-view proof sampling failed')
                if not sum(r['hits'] for r in rows):
                    raise ValueError('user-view proof reuse was not exercised')
                proofs=[]
                shadows={int(r['shadow'],16) for r in audit['root_switch']['roots']}
                for slot in range(64):
                    root,count,generation,valid=struct.unpack_from('<4Q',raw,8+slot*32)
                    if valid>1 or generation>epoch or (valid and (not root or root&4095 or not 0<count<=128)):
                        raise ValueError('invalid retained user-view proof')
                    reusable=bool(valid and generation==epoch and epoch!=(1<<64)-1)
                    if reusable:
                        address=work+layout.offset('context','user_views')+slot*layout.size('sprr_views')
                        identity=struct.unpack('<2Q',proxy.readmem(address,16,live=True))
                        if identity!=(root,count) or root not in shadows:
                            raise ValueError('reusable proof differs from the audited cached root')
                    if root or valid:
                        proofs.append(dict(slot=slot,root=hex(root),count=count,epoch=generation,
                                           valid=valid,reusable=reusable))
                result['user_view_cache']=dict(epoch=epoch,raw_hex=raw.hex(),cpus=rows,proofs=proofs,
                    calls=sum(r['calls'] for r in rows),hits=sum(r['hits'] for r in rows),
                    verified=sum(r['verified'] for r in rows),mismatches=0,
                    boundary='Canonical-coverage proof reuse only; every CPU descriptor is still preflighted. '
                             'One full coverage check on the first hit and every 64 hits per CPU.')
        if args.user_only_tlbi:
            start=work+layout.offset('context','user_only_tlbi')
            if not work<=start<=work+size-32:
                raise ValueError('invalid user-only invalidation counter layout')
            raw=proxy.readmem(start,32,live=True)
            if raw!=proxy.readmem(start,32,live=True):
                raise ValueError('user-only invalidation counters changed while stopped')
            values=struct.unpack('<4Q',raw)
            mapping=audit['user_mapping']
            if (not sum(values) or values[0]!=mapping['live_pages'] or
                    values[1]!=mapping['unmap_calls'] or
                    values[2]<mapping['comm_attach_calls'] or
                    values[3]!=audit['nesting']['calls']):
                raise ValueError('user-only invalidations disagree with audited transactions')
            result['user_only_tlbi']=dict(zip(('leaf','unmap','comm_attach','nest'),values))
            result['user_only_tlbi'].update(total=sum(values),raw_hex=raw.hex(),
                boundary='Same all-VMID hardware invalidation after four user-only commits; '
                         'unchanged kernel private tables are not refreshed.')
        if args.service_detail:
            start=work+layout.offset('context','service_detail');stride=layout.size('service_detail')
            if stride!=6000 or not work<=start<=work+size-6*stride:
                raise ValueError('invalid detail record bounds')
            raw=proxy.readmem(start,6*stride,live=True)
            if raw!=proxy.readmem(start,len(raw),live=True):
                raise ValueError('detailed intervals changed while stopped')
            rows=[dict(slot=n,**decode_detail(raw[n*stride:(n+1)*stride],layout,hz,
                                             cpus[n]['hold_ticks'])) for n in range(6)]
            count=run.ENDPOINT_BUCKETS
            address=work+layout.offset('context','endpoint_calls')
            if count!=64 or layout.offset('context','endpoint_other')!=address-work+8*count:
                raise ValueError('unexpected endpoint counter layout')
            endpoint_raw=proxy.readmem(address,8*(count+1),live=True)
            if endpoint_raw!=proxy.readmem(address,len(endpoint_raw),live=True):
                raise ValueError('endpoint counters changed while stopped')
            totals=[0]*144
            for row in rows:
                for b in row['buckets']:totals[b['bucket']]+=b['calls']
            observed=totals[16:16+count]+[totals[4]+sum(totals[16+count:])]
            if not sum(observed) or observed!=list(struct.unpack('<65Q',endpoint_raw)):
                raise ValueError('detail calls disagree with independent dispatcher counters')
            result['service_detail']=dict(raw_hex=raw.hex(),cpus=rows,
                endpoint_raw_hex=endpoint_raw.hex(),
                boundary='Only intervals inside acquired runtime service ownership. '
                         'Inclusive times overlap; self time excludes instrumented children. '
                         'Instrumentation adds overhead. Initial table construction is excluded.')
        if args.kernel_publish:
            start=work+layout.offset('context','kernel_publish_state')
            if layout.size('sprr_publish_state')!=160 or not work<=start<=work+size-160:
                raise ValueError('invalid kernel publication layout')
            raw=proxy.readmem(start,160,live=True)
            if raw!=proxy.readmem(start,160,live=True):
                raise ValueError('kernel publication state changed while stopped')
            values=struct.unpack('<20Q',raw);root,count=values[:2]
            stats=dict(zip(('writes','publishes','pages','flushed','skipped','errors'),values[14:]))
            kernel=audit['kernel_permissions']
            if (root!=int(kernel['canonical_root'],16) or count!=kernel['private_source_tables'] or
                    any(values[2:14]) or stats['errors'] or not stats['writes'] or
                    stats['publishes']!=sum(kernel['syncs']) or not stats['flushed'] or
                    not stats['skipped'] or stats['pages']!=stats['flushed']+stats['skipped'] or
                    not stats['publishes']<=stats['pages']<=stats['publishes']*count):
                raise ValueError('kernel publication counters disagree with audited views')
            result['kernel_publish']=dict(root=hex(root),count=count,raw_hex=raw.hex(),**stats,
                boundary='Every changed and newly allocated private copy page is published '
                         'children before parents; unchanged published pages skip cache maintenance. '
                         'Descriptor validation and all-VMID TLBI remain.')
        if args.kernel_reuse:
            start=work+layout.offset('context','kernel_reuse_state')
            if (layout.size('sprr_reuse_state')!=532608 or
                    layout.offset('sprr_reuse_state','tables')!=128 or
                    layout.offset('sprr_reuse_state','words')!=8320 or
                    not work<=start<=work+size-532608):
                raise ValueError('invalid kernel reuse layout')
            raw=proxy.readmem(start,128,live=True)
            if raw!=proxy.readmem(start,128,live=True):
                raise ValueError('kernel reuse state changed while stopped')
            row=decode_kernel_reuse(raw,audit['kernel_permissions'],audit_rate)
            row['raw_hex']=raw.hex()
            if row['valid']:
                count=row['count'];saved=proxy.readmem(start+128,count*64,live=True)
                current=work+layout.offset('context','kernel_views')+layout.offset('sprr_views','tables')
                if saved!=proxy.readmem(current,len(saved),live=True):
                    raise ValueError('cached kernel view identities differ from current views')
                for n in range(count):
                    source,=struct.unpack_from('<Q',saved,n*64)
                    if (source&4095) or not work<=source<=work+size-4096:
                        raise ValueError('cached kernel source outside work arena')
                    expected=proxy.readmem(start+8320+n*4096,4096,live=True)
                    if expected!=proxy.readmem(source,4096,live=True):
                        raise ValueError('cached source descriptors differ from current tables')
                row['current_snapshot_verified']=True
            else:row['current_snapshot_verified']=False
            row['boundary']='Exact source words, metadata and all six PPERMs gate reuse. '
            row['boundary']+='Independent PPERM writes invalidate; sampled hits verify every private descriptor without repair. Hardware TLBI remains.'
            result['kernel_reuse']=row
        if args.private_view_epoch:
            start=work+layout.offset('context','private_pages')
            if layout.size('sprr_private_pages')!=PRIVATE_PAGES_BYTES or not work<=start<=work+size-PRIVATE_PAGES_BYTES:
                raise ValueError('invalid private provenance layout')
            raw=proxy.readmem(start,PRIVATE_PAGES_BYTES,live=True)
            if raw!=proxy.readmem(start,PRIVATE_PAGES_BYTES,live=True):
                raise ValueError('private provenance changed while stopped')
            first,allocated=struct.unpack('<2Q',proxy.readmem(
                work+layout.offset('context','work_base'),8,live=True)+proxy.readmem(
                work+layout.offset('context','next_table'),8,live=True))
            if not work<=first<allocated<=work+size or (first|allocated)&4095:
                raise ValueError('invalid private provenance arena')
            owners=proxy.readmem(work+layout.offset('context','table_pool')+
                layout.offset('table_pool','owner'),(allocated-first)//4096,live=True)
            views=[]
            canonical=[int(x,16) for x in audit['kernel_permissions']['canonical_table_pages']]
            audited={0:(int(audit['kernel_permissions']['canonical_root'],16),
                set(int(x,16) for x in audit['kernel_permissions']['private_table_pages']))}
            for a in audit['user_permissions']['roots']:
                canonical.extend(int(x,16) for x in a['canonical_table_pages'])
                audited[int(a['canonical'],16)]=set(int(x,16) for x in a['private_table_pages'])
            for owner in range(65):
                address=work+(layout.offset('context','kernel_views') if not owner else
                    layout.offset('context','user_views')+(owner-1)*layout.size('sprr_views'))
                root,count=struct.unpack('<2Q',proxy.readmem(address,16,live=True))
                if not count:
                    if root:raise ValueError('empty view has nonzero canonical root')
                    continue
                if not root or count>128:raise ValueError('invalid private metadata count')
                records=proxy.readmem(address+layout.offset('sprr_views','tables'),count*64,live=True)
                records=list(struct.iter_unpack('<8Q',records))
                # Native user views: copy[0..1] are the shared variants and
                # copy[2..5] stay zero; the kernel view keeps six CPU copies.
                columns=2 if native and owner else 6
                if any(p for r in records for p in r[1+columns:7]):
                    raise ValueError('nonzero unused private copy slots')
                view=dict(owner=owner,root=root,sources=[r[0] for r in records],columns=columns,
                          copies=[p for r in records for p in r[1:1+columns]])
                if any(r[7]>3 for r in records) or records[0][7]:
                    raise ValueError('invalid private metadata levels')
                if not owner:
                    if (root,set(view['copies']))!=audited.pop(0):
                        raise ValueError('kernel private identities changed since audit')
                elif root in audited and set(view['copies'])!=audited.pop(root):
                    raise ValueError('user private identities changed since audit')
                views.append(view)
            if audited:raise ValueError('audited private view missing from stopped metadata')
            row=decode_private_pages(raw,first,allocated,owners,views,canonical)
            row['raw_hex']=raw.hex()
            row['boundary']='Only allocation-proven private stores preserve the user coverage epoch. Canonical stores, allocation and recycling still invalidate; metadata, ownership and all reachable canonical pages independently qualify the stopped bitmap.'
            result['private_view_epoch']=row
        if args.root_publish:
            start=work+layout.offset('context','root_publish')
            if (layout.size('root_publish_state')!=ROOT_PUBLISH_BYTES or
                    layout.offset('root_publish_state','bitmap')!=80 or
                    not work<=start<=work+size-ROOT_PUBLISH_BYTES):
                raise ValueError('invalid root publication layout')
            raw=proxy.readmem(start,ROOT_PUBLISH_BYTES,live=True)
            if raw!=proxy.readmem(start,ROOT_PUBLISH_BYTES,live=True):
                raise ValueError('root publication changed while stopped')
            def field(kind,address,name):
                return struct.unpack('<Q',proxy.readmem(address+layout.offset(kind,name),8,live=True))[0]
            first=field('context',work,'work_base');allocated=field('context',work,'next_table')
            if first!=((work+layout.size('context')+4095)&~4095):
                raise ValueError('root publication arena differs from context boundary')
            cpu0=work+layout.offset('context','vcpus');stride=layout.size('vcpu')
            runtime_first=field('vcpu',cpu0,'vncr_va')
            secondary=field('context',work,'secondary_base')
            # Independently bind the whole forced range to the actual six-CPU
            # storage recipe: six VNCRs, five output+16-page stacks, six records.
            cursor=runtime_first
            for n in range(6):
                cpu=cpu0+n*stride
                if field('vcpu',cpu,'vncr_va')!=cursor:
                    raise ValueError('root publication runtime VNCR layout differs')
                cursor+=4096
                if n:
                    if field('vcpu',cpu,'out_ptr')!=cursor:
                        raise ValueError('root publication runtime output layout differs')
                    cursor+=4096+16*4096
                    if field('vcpu',cpu,'el2_sp')!=cursor:
                        raise ValueError('root publication runtime stack layout differs')
            if secondary!=cursor:raise ValueError('root publication secondary record layout differs')
            row=decode_root_publish(raw,first,allocated,audit['root_switch']['switches'],
                                    runtime_first,secondary+6*4096)
            row['raw_hex']=raw.hex()
            row['boundary']='Root installation publishes noted allocations, changed stores and conservatively mapped ranges. CPU runtime memory is always published; existing direct guard publication, other publishers, validation and hardware TLBI remain. Counters qualify tracking geometry and volume, not independent bus-memory cache contents.'
            result['root_publish']=row
        if args.user_publish:
            start=work+layout.offset('context','user_publish')
            if (layout.size('user_publish_stats')!=48 or
                    layout.offset('user_publish_stats','errors')!=40 or
                    not work<=start<=work+size-48):
                raise ValueError('invalid user publication layout')
            raw=proxy.readmem(start,48,live=True)
            if raw!=proxy.readmem(start,48,live=True):
                raise ValueError('user publication changed while stopped')
            if native:
                result['user_publish']=native_idle(raw,'user publication')
            else:
                expected=sum(b['calls']*(6 if b['bucket']==2 else 1)
                             for cpu in result['service_detail']['cpus']
                             for b in cpu['buckets'] if b['bucket'] in (2,3))
                row=decode_user_publish(raw,expected,result['root_publish']);row['raw_hex']=raw.hex()
                row['boundary']='Allocation-proven private user copies share the root dirty bitmap. Each all-CPU refresh publishes six views and each one-CPU sync one view; only selected changed pages are cleaned. Mapping proofs, direct guard publication and hardware TLBI remain. Counters are not an independent bus-cache-content audit.'
                result['user_publish']=row
        if args.user_prepare:
            start=work+layout.offset('context','user_prepare_stats')
            if layout.size('sprr_user_prepare_stats')!=56 or not work<=start<=work+size-56:
                raise ValueError('invalid fused preparation stats layout')
            raw=proxy.readmem(start,56,live=True)
            if raw!=proxy.readmem(start,56,live=True):
                raise ValueError('fused preparation stats changed while stopped')
            if native:
                result['user_prepare']=dict(native_idle(raw,'fused preparation'),calls=0,
                                            source_tables=0,private_tables=0)
            else:
                observed=sum(b['calls'] for cpu in result['service_detail']['cpus']
                             for b in cpu['buckets'] if b['bucket']==2)
                row=decode_user_prepare(raw,observed);row['raw_hex']=raw.hex()
                row['boundary']='One complete source-validation/coverage-plan walk per transaction; every 64th call independently checks full coverage before all-CPU descriptor preflight and ordered commit. No plan is reused across transactions.'
                result['user_prepare']=row
        if args.user_table_read:
            start=work+layout.offset('context','user_table_reads')
            if not work<=start<=work+size-24:raise ValueError('invalid table-reader counter layout')
            raw=proxy.readmem(start,24,live=True)
            if raw!=proxy.readmem(start,24,live=True):
                raise ValueError('bounded table reader changed while stopped')
            if native:
                result['user_table_read']=native_idle(raw,'bounded table reader')
            else:
                row=decode_user_table_reads(raw,result['user_prepare']['source_tables']);row['raw_hex']=raw.hex()
                row['boundary']='One checked allocation-span mapping per visited source table. Every descriptor is still loaded and validated; every64th preparation independently repeats coverage through the original word callback. Mapped pointers are transaction-local and no proof is reused.'
                result['user_table_read']=row
        if args.user_zero_group:
            start=work+layout.offset('context','user_zero_groups')
            if (layout.size('sprr_user_zero_stats')!=16 or
                    layout.offset('sprr_user_zero_stats','empty_groups')!=8 or
                    not work<=start<=work+size-16):
                raise ValueError('invalid zero-group counter layout')
            raw=proxy.readmem(start,16,live=True)
            if raw!=proxy.readmem(start,16,live=True):
                raise ValueError('zero-group counters changed while stopped')
            if native:
                result['user_zero_group']=native_idle(raw,'zero groups')
            else:
                row=decode_user_zero_groups(raw,result['user_prepare']['source_tables'])
                row['raw_hex']=raw.hex()
                row['boundary']='Every eight-word group loads all eight volatile descriptors. Only a zero bitwise OR skips individual empty-entry checks. Nonzero groups retain full checks and the sampled independent callback walk is unchanged.'
                result['user_zero_group']=row
        if args.view_table_read:
            start=work+layout.offset('context','view_table_reads')
            if (layout.size('view_table_read_stats')!=48 or
                    layout.offset('view_table_read_stats','errors')!=40 or
                    not work<=start<=work+size-96):
                raise ValueError('invalid private-sync reader layout')
            raw=proxy.readmem(start,96,live=True)
            if raw!=proxy.readmem(start,96,live=True):
                raise ValueError('private-sync reader changed while stopped')
            user_calls=sum(b['calls'] for cpu in result['service_detail']['cpus']
                           for b in cpu['buckets'] if b['bucket']==3)
            if user_calls!=result['user_view_cache']['calls']:
                raise ValueError('user sync detail and proof counts differ')
            counts=(sum(audit['kernel_permissions']['syncs']),user_calls)
            result['view_table_read']={name:(native_idle(raw[48:],'user private-sync reader')
                                             if native and i else
                                             decode_view_table_reads(raw[48*i:48*i+48],counts[i]))
                for i,name in enumerate(('kernel','user'))}
            if native:result['view_table_read']['user'].update(calls=0,tables=0)
            result['view_table_read']['raw_hex']=raw.hex()
            result['view_table_read']['boundary']='One full allocation-span mapping per private source table and sync. All descriptor preflight and child-before-parent writes retained; canonical coverage and installed kernel checks still use independent word callbacks. No pointer or decoded value survives a transaction.'
        if args.view_store_compare:
            start=work+layout.offset('context','view_store_compare')
            if (layout.size('sprr_store_compare_stats')!=56 or
                    layout.offset('sprr_store_compare_stats','failures')!=48 or
                    not work<=start<=work+size-112):
                raise ValueError('invalid private store comparison layout')
            raw=proxy.readmem(start,112,live=True)
            if raw!=proxy.readmem(start,112,live=True):
                raise ValueError('private store comparison changed while stopped')
            result['view_store_compare']={name:(native_idle(raw[56:],'user private store comparison')
                                                if native and i else
                                                decode_view_store_compare(raw[56*i:56*i+56],
                result['view_table_read'][name]['calls'],result['view_table_read'][name]['tables']))
                for i,name in enumerate(('kernel','user'))}
            if native:result['view_store_compare']['user'].update(tables=0)
            result['view_store_compare']['raw_hex']=raw.hex()
            result['view_store_compare']['boundary']='Every private destination word is compared during commit. Only equal-value idempotent callbacks are skipped; changed descriptors retain normal stores, publication and TLBI. No cross-transaction cache or shortened source preflight.'
        if args.user_fused_compare:
            start=work+layout.offset('context','user_fused_compare')
            if (layout.size('sprr_store_compare_stats')!=56 or
                    layout.offset('sprr_store_compare_stats','failures')!=48 or
                    not work<=start<=work+size-56):
                raise ValueError('invalid fused store comparison layout')
            raw=proxy.readmem(start,56,live=True)
            if raw!=proxy.readmem(start,56,live=True):
                raise ValueError('fused store comparison changed while stopped')
            if native:
                row=dict(native_idle(raw,'fused store comparison'),tables=0)
            else:
                row=decode_view_store_compare(raw,result['user_prepare']['calls'],
                    6*result['user_prepare']['private_tables'],copies=6)
                row['raw_hex']=raw.hex()
            row['boundary']='Full source walk and sampled coverage retained; all six CPU descriptors preflighted before writes. Every private destination compared, only equal-value idempotent callbacks skipped. Changed stores, publication and TLBI unchanged; tables count six copies per private source table.'
            result['user_fused_compare']=row
        if args.user_tree_memo:
            size_stats=8*len(TREE_MEMO_FIELDS)
            start=(work+layout.offset('context','table_memo')+
                   layout.offset('sprr_table_memo','stats'))
            if (layout.size('sprr_table_memo_stats')!=size_stats or
                    layout.offset('sprr_table_memo_stats','forced')!=size_stats-8 or
                    not work<=start<=work+size-size_stats):
                raise ValueError('invalid user tree memo layout')
            raw=proxy.readmem(start,size_stats,live=True)
            if raw!=proxy.readmem(start,size_stats,live=True):
                raise ValueError('user tree memo changed while stopped')
            if native:
                row=decode_native_tree_memo(raw)
            else:
                row=decode_user_tree_memo(raw,result['user_prepare']['calls'],
                    result['user_view_cache']['calls'],result['user_prepare']['source_tables'],
                    result['user_fused_compare']['tables']+result['view_store_compare']['user']['tables'])
            row['raw_hex']=raw.hex()
            row['boundary']='Per-page write generations over the table arena. Current level3 summaries replace rescans in refresh and proof-miss walks; private copies whose source/copy pages and class9 key are unchanged skip preflight and compare. Every 64th transaction recomputes and checks every claim without repair; independent coverage samples never use claims.'
            result['user_tree_memo']=row
        if args.kernel_class_proof:
            start=work+layout.offset('context','kernel_class_proof')
            if (layout.size('sprr_class_proof')!=CLASS_PROOF_BYTES or
                    layout.offset('sprr_class_proof','bitmap')!=160 or
                    not work<=start<=work+size-CLASS_PROOF_BYTES):
                raise ValueError('invalid kernel class proof layout')
            raw=proxy.readmem(start,CLASS_PROOF_BYTES,live=True)
            if raw!=proxy.readmem(start,CLASS_PROOF_BYTES,live=True):
                raise ValueError('kernel class proof changed while stopped')
            allocated,=struct.unpack('<Q',proxy.readmem(
                work+layout.offset('context','next_table'),8,live=True))
            row=decode_kernel_class_proof(raw,audit['kernel_permissions'],
                audit['pperm_copy']['transactions'],(work+layout.size('context')+4095)&~4095,
                table_limit,allocated,audit_rate)
            row['raw_hex']=raw.hex()
            row['boundary']=f'Full canonical class proof reused only before tracked-source or pointer-transaction invalidation. Every {audit_rate}th hit walks the tree without repair; private synchronization, publication and TLBI remain.'
            result['kernel_class_proof']=row
        if args.user_fused:
            start=work+layout.offset('context','user_fused_syncs')
            if not work<=start<=work+size-8:raise ValueError('invalid user fused counter bounds')
            raw=proxy.readmem(start,8,live=True)
            if raw!=proxy.readmem(start,8,live=True):
                raise ValueError('fused user-view count changed while stopped')
            calls,=struct.unpack('<Q',raw)
            observed=sum(b['calls'] for cpu in result['service_detail']['cpus']
                         for b in cpu['buckets'] if b['bucket']==2)
            if native:
                # The refresh bucket times the sampled native audits instead.
                if calls or observed!=audit['native_tables']['stats']['audits']:
                    raise ValueError('refresh count differs from the sampled native audits')
            elif not calls or calls!=observed:
                raise ValueError('fused user-view calls disagree with detailed refresh count')
            result['user_fused']=dict(syncs=calls,profiled_refresh_calls=observed,raw_hex=raw.hex(),
                boundary='All six CPU outputs retain separate control/descriptor checks and publication; common source decoding is shared.')
        if ops_flags:
            ops=runpy.run_path(str(ROOT/'tools/kernel_ops_perf.py'))
            unknown=ops_flags-{flag for _,_,flag in ops['RECORDS'].values()}-{'SNAP_AUDIT_SPARSE'}
            if unknown:raise ValueError('unknown kernel-ops-perf flags: '+','.join(sorted(unknown)))
            raw={}
            for name,(kind,fields,flag) in ops['RECORDS'].items():
                start=work+layout.offset('context',name);length=layout.size(kind)
                if length!=8*len(fields) or not work<=start<=work+size-length:
                    raise ValueError(f'invalid {name} layout')
                raw[name]=proxy.readmem(start,length,live=True)
                if raw[name]!=proxy.readmem(start,length,live=True):
                    raise ValueError(f'{name} changed while stopped')
            def word(offset):
                return struct.unpack('<Q',proxy.readmem(work+offset,8,live=True))[0]
            rp=layout.offset('context','root_publish')
            arena=dict(first=word(layout.offset('context','work_base')),
                       limit=word(layout.offset('context','work_end')),
                       allocated=word(layout.offset('context','next_table')),
                       runtime_first=word(rp+layout.offset('root_publish_state','always_first')),
                       runtime_end=word(rp+layout.offset('root_publish_state','always_end')))
            txn=ops['unpack']('txn_publish',raw['txn_publish']);page=None
            if txn['sentinel'] and not txn['observed']:
                if not arena['first']<=txn['sentinel']<arena['allocated']:
                    raise ValueError('txn_publish sentinel outside arena')
                page=proxy.readmem(txn['sentinel'],4096,live=True)
            rows=ops['decode'](raw,ops_flags,audit,result.get('kernel_class_proof'),arena,page)
            for name,row in rows.items():row['raw_hex']=raw[name].hex()
            memo=rows['root_memo']
            if memo['enabled']:
                lookups=memo['hits']+memo['misses']
                memo['hit_fraction']=memo['hits']/lookups if lookups else None
                memo['lookups_per_call']=lookups/memo['calls']
            rows['boundary']=('Transaction publication (sentinel-checked coverage), PPERM snapshot '
                'reuse (sampled read-only view checks), user-update kernel refresh skip (sampled '
                'all-CPU checks), folded installation TLBIs, mapped class walks (sampled original '
                'walks), optional generation-bound L3 class summaries, word-load root '
                'validation (sampled byte walks) and optional cache-hit L3 verdict reuse '
                '(retired by published stores and mapped-frame retypes; the sampled byte walk '
                'never uses it). All mismatch counters zero.')
            result['kernel_ops_perf']=rows
        Path(f'{base}-service-profile.json').write_text(json.dumps(result, indent=2) + '\n')
        summary = dict(output=f'{base}-service-profile.json', cpus=[
            dict(slot=c['slot'], wait_seconds=c['wait_seconds'], hold_seconds=c['hold_seconds'],
                 outside_seconds=c['outside_instrumented_seconds']) for c in cpus])
        memo = result.get('kernel_ops_perf', {}).get('root_memo')
        if memo and memo['enabled']:
            summary['root_memo'] = {k: memo[k] for k in ('calls', 'hits', 'misses', 'hit_fraction',
                'invalidations', 'epoch_bumps', 'flushes', 'evictions', 'sampled', 'mismatches')}
        print(json.dumps(summary))
    finally:
        proxy.link.close()


if __name__ == '__main__':
    main()
