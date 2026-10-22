# SPDX-License-Identifier: MIT
"""Decode the monitor's PV self-check counters (struct sptm_pv_audit).

context.pv_audit counts MAP_PAGE PTE pointers returned through a SLIDE_REGION
alias (moved_pointers), committed valid->valid leaf changes to a different PA
(remaps, with the last one as a witness) and UPDATE/UNMAP_DISJOINT records
repeating an earlier (root, VA) in one call (duplicate_records, with the last
one). Monitors built before the counters decode as None.

remaps is the one expected to stay zero: Apple's MAP_PAGE refuses a
different-PA replacement with CONFLICT 6, and XNU only keeps its PV list right
if it sees that refusal. moved_pointers and duplicate_records are normal and
are reported for correlation with pmap panics.
"""
import re
import struct

FIELDS = ('moved_pointers', 'remaps', 'duplicate_records',
          'remap_va', 'remap_old', 'remap_next', 'duplicate_root', 'duplicate_va',
          'pending', 'pending_va', 'pending_old', 'pending_next')
SIZE = 8 * len(FIELDS)


def decode(raw):
    if len(raw) != SIZE:
        raise ValueError(f'pv_audit is {SIZE} bytes, got {len(raw)}')
    v = dict(zip(FIELDS, struct.unpack(f'<{len(FIELDS)}Q', raw)))
    result = {k: v[k] for k in ('moved_pointers', 'remaps', 'duplicate_records')}
    result['last_remap'] = (dict(va=hex(v['remap_va']), old=hex(v['remap_old']),
                                 next=hex(v['remap_next'])) if v['remaps'] else None)
    result['last_duplicate'] = (dict(root=hex(v['duplicate_root']), va=hex(v['duplicate_va']))
                                if v['duplicate_records'] else None)
    # Reset at every call entry and consumed by the call's commit; nonzero
    # only in a monitor stopped inside a refused reference transaction.
    result['uncommitted_remaps'] = v['pending']
    return result


def read_context(read, work, offset, layout):
    """context.pv_audit from a stopped monitor, or None for an older layout.
    offset(kind, field) and layout come from clang, as for user_crash_ring."""
    if not re.search(r' pv_audit$', layout, re.M):
        return None
    result = decode(read(work + offset('context', 'pv_audit'), SIZE))
    # Kernel-root MAP_PAGE answered CONFLICT(6): count and the last case.
    if re.search(r' kernel_map_conflict$', layout, re.M):
        count, va, wanted, old, pointer = struct.unpack(
            '<5Q', read(work + offset('context', 'kernel_map_conflict'), 40))
        result['kernel_map_conflicts'] = count
        result['last_kernel_conflict'] = (dict(va=hex(va), wanted=hex(wanted), old=hex(old),
                                               pointer=hex(pointer)) if count else None)
    return result
