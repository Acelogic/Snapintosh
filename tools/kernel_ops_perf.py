# SPDX-License-Identifier: MIT
"""Stopped-state rules for the kernel-ops-perf self-check records.

Each record is appended to struct context by probes/xnuboot.c and is only
meaningful when its SNAP_* flag was built in. decode() receives the raw record
bytes (read twice by the caller while the guest is stopped), the enabled flag
names, the independent runtime audit and the decoded class-proof record, and
raises ValueError when a counter relation that a never-diverging run must
satisfy is violated. It never repairs or reinterprets a record.
"""
import struct

RECORDS = {
    # context field: (struct name, fields, flag)
    'txn_publish': ('txn_publish_stats',
        ('calls','complete','considered','published','runtime','errors','armed','checked',
         'noted','retired','mismatches','sentinel','hash','observed','cursor'),
        'SNAP_TXN_DIRTY_PUBLISH'),
    'kernel_pperm_reuse': ('kernel_pperm_reuse_stats',
        ('calls','current','skipped','synced','repinned','verified','mismatches','errors'),
        'SNAP_KERNEL_PPERM_REUSE'),
    'user_update_skip': ('user_update_skip_stats',('skipped','verified','mismatches'),
        'SNAP_USER_UPDATE_KERNEL_SKIP'),
    'install_tlbi': ('install_tlbi_stats',('installs','pperm_folded','view_folded','failure_flushes'),
        'SNAP_INSTALL_TLBI_DEFER'),
    'class_proof_mapped': ('class_proof_mapped_stats',
        ('walks','tables','groups','empty_groups','compared','errors'),'SNAP_CLASS_PROOF_MAPPED'),
    'root_validate': ('sptm_root_validate_stats',('validations','sampled','mismatches','tables'),
        'SNAP_ROOT_VALIDATE_WORDS'),
    'class_leaf': ('sprr_class_leaf_stats',
        ('calls','hits','scans','verified','mismatches','resets','poisoned','base','pages','clock'),
        'SNAP_CLASS_LEAF_MEMO'),
    'root_memo': ('sptm_root_memo_stats',
        ('calls','hits','misses','records','evictions','invalidations','epoch_bumps','flushes',
         'sampled','mismatches'),
        'SNAP_ROOT_VALIDATE_MEMO'),
    'inactive_mirror': ('inactive_mirror_stats',
        ('leaves','present','tables','tpro','budget','arena','configured'),
        'SNAP_INACTIVE_MIRROR'),
    'native_stats': ('native_table_stats',
        ('propagated','refused','paths','syncs','installs','local_flushes','flips',
         'tlbi_calls','tlbi_pages','tlbi_full',
         'audit_asks','audits','audit_failures','hit_asks','hit_skips','proof_asks','proof_skips',
         'pperm_skips','reuse_asks','reuse_checks','reuse_failures','pperm_flushes',
         'created','uncreated','coverages'),
        'SNAP_NATIVE_TABLES'),
}
# probes/xnuboot.c NATIVE_TLBI_PAGES: larger ranges drop each VMID's entries.
NATIVE_TLBI_PAGES = 64
MASK = (1 << 64) - 1


def sentinel_hash(page):
    """shadow/txn-publish.h txn_publish_hash over 4096 stopped bytes."""
    if len(page) != 4096:
        raise ValueError('sentinel page must be 4096 bytes')
    h = 0xcbf29ce484222325
    for i, (w,) in enumerate(struct.iter_unpack('<Q', page)):
        h ^= (w + 0x9e3779b97f4a7c15 * (i + 1)) & MASK
        h = (h * 0x100000001b3) & MASK
        h ^= h >> 29
    return h


def unpack(name, raw):
    fields = RECORDS[name][1]
    if len(raw) != 8 * len(fields):
        raise ValueError(f'{name}: record size {len(raw)} differs from {8*len(fields)}')
    return dict(zip(fields, struct.unpack(f'<{len(fields)}Q', raw)))


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def _due(asks, shift):
    """native_due: the first ask and then every 2**shift-th is due."""
    return (asks + (1 << shift) - 1) >> shift


def native_audit_shift(row):
    """The SNAP_NATIVE_AUDIT_SHIFT that every sampled native counter agrees
    on, or None. With no asks at all any shift fits; 6 is the default."""
    fits = [k for k in range(32)
            if row['hit_asks'] - row['hit_skips'] == _due(row['hit_asks'], k) and
            row['audits'] == _due(row['audit_asks'], k) and
            row['proof_asks'] - row['proof_skips'] == _due(row['proof_asks'], k) and
            row['reuse_checks'] == _due(row['reuse_asks'], k)]
    return 6 if 6 in fits else (fits[0] if fits else None)


def decode(raw, flags, audit, class_proof=None, arena=None, sentinel_page=None):
    """raw: {record: bytes}. arena: dict(first, allocated, runtime_first, runtime_end).
    sentinel_page: stopped bytes of the armed txn sentinel page, if any."""
    out = {}
    _require('SNAP_CLASS_LEAF_MEMO' not in flags or 'SNAP_CLASS_PROOF_MAPPED' in flags,
             'class_leaf: mapped class proof flag required')
    _require('SNAP_ROOT_VALIDATE_MEMO' not in flags or 'SNAP_ROOT_VALIDATE_WORDS' in flags,
             'root_memo: sampled word validation flag required')
    # Native page tables skip the walk on sampled SWITCH_ROOT cache hits and
    # count them; root_validate and root_memo count only the walked ones.
    native = None
    if 'SNAP_NATIVE_TABLES' in flags:
        _require('native_stats' in raw, 'native_stats: enabled record was not read')
        native = unpack('native_stats', raw['native_stats'])
    hit_skips = native['hit_skips'] if native else 0
    for name, (_, _, flag) in RECORDS.items():
        if name not in raw:
            _require(flag not in flags, f'{name}: enabled record was not read')
            continue
        row = unpack(name, raw[name])
        if flag not in flags:
            _require(not any(row.values()), f'{name}: counters present without {flag}')
            out[name] = dict(row, enabled=False)
            continue
        switches = audit['root_switch']
        if name == 'txn_publish':
            _require(arena is not None, 'txn_publish: arena geometry required')
            pages = (arena['allocated'] - arena['first']) // 4096
            runtime = (arena['runtime_end'] - arena['runtime_first']) // 4096
            _require(not row['errors'] and not row['mismatches'], 'txn_publish: error or sentinel mismatch')
            _require(row['calls'] == row['complete'] and row['complete'] > 0, 'txn_publish: incomplete or unexercised')
            _require(row['runtime'] == row['complete'] * runtime, 'txn_publish: runtime pages not always published')
            _require(row['published'] <= row['considered'] <= row['complete'] * pages,
                     'txn_publish: publication volume exceeds considered pages')
            done = row['checked'] + row['noted'] + row['retired']
            _require(row['checked'] > 0 and row['armed'] - done in (0, 1) and row['armed'] <= row['complete'],
                     'txn_publish: sentinel accounting disagrees or was never checked')
            _require(row['observed'] in (0, 1), 'txn_publish: invalid observed flag')
            s = row['sentinel']
            _require((s == 0) == (row['armed'] == done), 'txn_publish: pending sentinel disagrees with arming')
            if s:
                _require(not s & 4095 and arena['first'] <= s < arena['allocated'] and
                         not arena['runtime_first'] <= s < arena['runtime_end'],
                         'txn_publish: sentinel outside eligible arena')
                if not row['observed']:
                    _require(sentinel_page is not None, 'txn_publish: pending sentinel page not read')
                    _require(sentinel_hash(sentinel_page) == row['hash'],
                             'txn_publish: unnoted change to the pending sentinel page')
        elif name == 'kernel_pperm_reuse':
            _require(not row['mismatches'] and not row['errors'], 'kernel_pperm_reuse: mismatch or error')
            _require(row['repinned'] == row['current'] <= row['calls'], 'kernel_pperm_reuse: unrepinned current transaction')
            _require(row['skipped'] + row['synced'] == row['repinned'], 'kernel_pperm_reuse: skip/sync split disagrees')
            # SNAP_AUDIT_SPARSE (compat/audit-sparse.h) samples 1 in 1024 skips instead of 1 in 64.
            rate = 1024 if 'SNAP_AUDIT_SPARSE' in flags else 64
            _require(row['verified'] == row['skipped'] // rate and row['skipped'] >= 64,
                     'kernel_pperm_reuse: sampled verification missing or unexercised')
        elif name == 'user_update_skip':
            # The audited user updates are every UPDATE_DISJOINT that names a
            # user root. Only user-only calls skip the kernel refresh; a mixed
            # call also names the kernel root, changes kernel leaves and keeps
            # the refresh (update_disjoint_call: user && !kernel, since 87cdda3).
            # No mixed count is kept, but each mixed call carries a user and a
            # kernel record, so the calls not skipped are at most the audited
            # records beyond one per call.
            calls, entries = audit['user_updates']['calls'], audit['user_updates']['entries']
            mixed = calls - row['skipped']
            _require(not row['mismatches'], 'user_update_skip: stale kernel view observed')
            _require(row['skipped'] >= 64 and 0 <= mixed <= entries - calls,
                     'user_update_skip: skips differ from audited user-only updates')
            # SNAP_UPDATE_CHECK_SPARSE samples 1 in 1024 skips instead of 1 in 64.
            rate = 1024 if 'SNAP_UPDATE_CHECK_SPARSE' in flags else 64
            _require(row['verified'] == row['skipped'] // rate, 'user_update_skip: sampled verification missing')
            row = dict(row, mixed_calls=mixed)
        elif name == 'install_tlbi':
            _require(row['installs'] == switches['switches'] and row['installs'] > 0,
                     'install_tlbi: installations differ from audited root switches')
            # Native installs fold nothing: the PPERM reset carries its own
            # invalidation and a variant needs none.
            folded = (0, 0) if native else (row['installs'], switches['user_switches'])
            _require((row['pperm_folded'], row['view_folded']) == folded,
                     'install_tlbi: folded invalidations differ from switches')
            _require(not row['failure_flushes'], 'install_tlbi: failure path taken')
        elif name == 'class_proof_mapped':
            _require(class_proof is not None, 'class_proof_mapped: class proof record required')
            _require(not row['errors'], 'class_proof_mapped: refused walk')
            _require(row['walks'] == class_proof['walks'] and row['compared'] == class_proof['verified'],
                     'class_proof_mapped: walks/verifications differ from the class proof')
            skipped = 0
            if 'SNAP_CLASS_LEAF_MEMO' in flags:
                _require('class_leaf' in raw, 'class_leaf: enabled record was not read')
                leaf = unpack('class_leaf', raw['class_leaf'])
                skipped = leaf['hits'] - leaf['verified']
            _require(0 <= skipped <= row['tables'] and
                     row['groups'] == 64 * (row['tables'] - skipped) and row['empty_groups'] <= row['groups'] and
                     row['tables'] >= row['walks'], 'class_proof_mapped: group accounting disagrees')
            # SNAP_AUDIT_SPARSE verifies 1 in 1024 hits: a run with fewer hits has compared none.
            sparse_unreached = 'SNAP_AUDIT_SPARSE' in flags and class_proof['hits'] < 1024
            _require((row['compared'] > 0 or sparse_unreached) and not class_proof['mismatches'],
                     'class_proof_mapped: never cross-checked or mismatched')
        elif name == 'root_validate':
            _require(not row['mismatches'], 'root_validate: word and byte walks disagreed')
            _require(row['validations'] == switches['user_switches'] - hit_skips and row['validations'] >= 64,
                     'root_validate: validations differ from audited user switches')
            _require(row['sampled'] == row['validations'] // 64 and row['tables'] >= row['validations'],
                     'root_validate: sampled byte walks missing')
        elif name == 'class_leaf':
            _require(class_proof is not None and arena is not None and 'limit' in arena,
                     'class_leaf: class proof and arena bounds required')
            _require(not row['mismatches'] and not row['poisoned'], 'class_leaf: stale summary or poisoned cache')
            _require(row['calls'] == class_proof['walks'] and row['calls'] > 0,
                     'class_leaf: calls differ from successful whole-proof walks')
            _require(0 < row['verified'] <= min(row['hits'], row['scans']),
                     'class_leaf: absent or inconsistent sampled claims')
            _require(0 < row['resets'] <= row['calls'], 'class_leaf: invalid reset accounting')
            _require(row['base'] == arena['first'] and
                     row['pages'] * 4096 == arena['limit'] - arena['first'],
                     'class_leaf: generation arena differs from monitor arena')
            _require(0 < row['clock'] < (1 << 48) - 1, 'class_leaf: unusable generation clock')
        elif name == 'root_memo':
            _require('root_validate' in raw, 'root_memo: root_validate record required')
            validate = unpack('root_validate', raw['root_validate'])
            _require(not row['mismatches'], 'root_memo: retained verdict disagreed with the reference walk')
            # Every successful user switch either installs a valid cached
            # shadow (memo-assisted) or builds one; a miss is rescanned and
            # recorded, or the switch fails and the guest stops.
            _require(row['calls'] == switches['user_switches'] - switches['builds'] - hit_skips and
                     row['calls'] >= 64,
                     'root_memo: assisted validations differ from audited cache-hit switches')
            _require(row['hits'] > 0 and row['records'] == row['misses'],
                     'root_memo: unexercised, or a missed table was not recorded')
            _require(0 < row['sampled'] <= validate['sampled'],
                     'root_memo: sampled reference walks missing or exceed root_validate')
            _require(row['evictions'] <= row['records'] and row['invalidations'] <= row['records'] and
                     row['flushes'] <= row['epoch_bumps'], 'root_memo: inconsistent retirement accounting')
        elif name == 'inactive_mirror':
            # A mirrored leaf is committed by the live-leaf path, which counts
            # every committed leaf; each discarded valid shadow went through
            # sptm_root_invalidate, which counts every cached slot it names.
            # Whether the kept shadows equal their guest trees is the audit's
            # own full comparison of every cached root (mappings_equal).
            _require(row['leaves'] <= audit['user_mapping']['live_pages'],
                     'inactive_mirror: more mirrored leaves than committed leaves')
            _require(row['tpro'] + row['budget'] + row['arena'] + row['configured'] <= switches['invalidations'],
                     'inactive_mirror: discarded shadows exceed audited invalidations')
        elif name == 'native_stats':
            # Every user switch installs variants (built roots derive them
            # once), every cache hit asks whether to walk, and the three
            # sampled audits share one rate. A refused store or a failed
            # audit is terminal.
            _require(not row['refused'] and not row['audit_failures'] and not row['reuse_failures'],
                     'native_stats: refused store or failed audit')
            # A root's variants are derived at its first install after a
            # build, or after its constructor cached it (SNAP_NATIVE_LIVE).
            _require(row['installs'] == switches['user_switches'] > 0 and
                     switches['builds'] <= row['syncs'] <= switches['builds'] + row['created'],
                     'native_stats: installs or syncs differ from audited switches and builds')
            _require(row['coverages'] == _due(row['audits'], 6),
                     'native_stats: coverage audits are not every 64th audit')
            _require(row['hit_asks'] == switches['user_switches'] - switches['builds'],
                     'native_stats: walk decisions differ from audited cache-hit switches')
            shift = native_audit_shift(row)
            _require(shift is not None and row['audits'] > 0,
                     'native_stats: sampled audits disagree on one rate, or never ran')
            _require(row['local_flushes'] <= switches['switches'] and
                     row['pperm_skips'] <= switches['switches'],
                     'native_stats: more flushes or PPERM skips than switches')
            _require(row['tlbi_full'] <= row['tlbi_calls'] and row['paths'] <= row['tlbi_calls'] and
                     row['tlbi_pages'] <= NATIVE_TLBI_PAGES * (row['tlbi_calls'] - row['tlbi_full']),
                     'native_stats: invalidation accounting disagrees')
            # A PPERM transaction invalidates this CPU's TLB exactly when its
            # kernel copy was not provably unchanged (not skipped).
            if 'SNAP_KERNEL_PPERM_REUSE' in flags:
                _require('kernel_pperm_reuse' in raw, 'kernel_pperm_reuse: enabled record was not read')
                reuse = unpack('kernel_pperm_reuse', raw['kernel_pperm_reuse'])
                _require(row['pperm_flushes'] + reuse['skipped'] == reuse['calls'] and
                         row['reuse_asks'] <= reuse['calls'],
                         'native_stats: PPERM invalidations differ from unskipped transactions')
            row = dict(row, audit_shift=shift)
        out[name] = dict(row, enabled=True)
    return out
