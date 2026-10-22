# SPDX-License-Identifier: MIT
"""Decode the monitor's linked-AuxKC observation counters (context.auxkc_exec).

The monitor counts kernel-root MAP_PAGE and UPDATE_REGION/UPDATE_DISJOINT
leaves inside the linked AuxKC's VA range, and RETYPEs of its physical
frames. `*_exec_gained` counts leaves whose PXN went from set (or invalid) to
clear on a valid page: XNU asking the monitor to make AuxKC memory
executable at EL1. Nothing is gated on these; a zero means the kext text ran
only through the loader's initial RX mapping. Monitors built before the
counters, and profiles without a linked AuxKC (params range zero), decode as
None.
"""
import re
import struct

FIELDS = ('map_pages', 'map_exec_gained', 'update_entries', 'update_exec_gained',
          'retypes', 'retype_failed', 'last_kind', 'last_va', 'last_old', 'last_new',
          'last_elr', 'last_retype_pa', 'last_retype_types')
SIZE = 8 * len(FIELDS)
KINDS = {0: None, 1: 'MAP_PAGE', 2: 'UPDATE'}


def decode(raw, va_range, pa_range):
    if len(raw) != SIZE:
        raise ValueError(f'auxkc_exec is {SIZE} bytes, got {len(raw)}')
    v = dict(zip(FIELDS, struct.unpack(f'<{len(FIELDS)}Q', raw)))
    gained = v['map_exec_gained'] + v['update_exec_gained']
    if (v['map_exec_gained'] > v['map_pages'] or v['update_exec_gained'] > v['update_entries'] or
            v['retype_failed'] > v['retypes'] or v['last_kind'] not in KINDS or
            bool(gained) != bool(v['last_kind'])):
        raise ValueError('inconsistent linked-AuxKC counters')
    if gained and not va_range[0] <= v['last_va'] < va_range[1]:
        raise ValueError('last AuxKC execute transition lies outside its VA range')
    if v['retypes'] and not pa_range[0] <= v['last_retype_pa'] < pa_range[1]:
        raise ValueError('last AuxKC retype lies outside its physical range')
    result = {k: v[k] for k in FIELDS[:6]}
    result['exec_gained'] = gained
    result['last_exec'] = (dict(kind=KINDS[v['last_kind']], va=hex(v['last_va']),
                                old=hex(v['last_old']), new=hex(v['last_new']),
                                elr=hex(v['last_elr'])) if gained else None)
    result['last_retype'] = (dict(pa=hex(v['last_retype_pa']),
                                  old_type=v['last_retype_types'] >> 32,
                                  new_type=v['last_retype_types'] & 0xffffffff)
                             if v['retypes'] else None)
    result['va_range'] = [hex(x) for x in va_range]
    result['pa_range'] = [hex(x) for x in pa_range]
    result['boundary'] = ('Kernel-root SPTM calls observed for the linked AuxKC; '
                          'no gate. Zero exec_gained means only the loader mapped it RX.')
    return result


def read_context(read, work, offset, layout, param):
    """context.auxkc_exec, or None for an older layout or an unused range.
    offset(kind, field) and layout come from clang; param('auxkc') returns
    the four resident params.auxkc words (va_base, va_end, pa_base, pa_end)."""
    if not re.search(r' auxkc_exec$', layout, re.M) or not re.search(r' auxkc$', layout, re.M):
        return None
    va_range, pa_range = param('auxkc')[:2], param('auxkc')[2:]
    if not va_range[1]:
        if any(va_range + pa_range):
            raise ValueError('partial linked-AuxKC range in resident params')
        return None
    if not (va_range[0] < va_range[1] and pa_range[0] < pa_range[1] and
            va_range[1] - va_range[0] == pa_range[1] - pa_range[0] and
            not (va_range[0] | va_range[1] | pa_range[0] | pa_range[1]) & 0x3fff):
        raise ValueError('invalid linked-AuxKC range in resident params')
    return decode(read(work + offset('context', 'auxkc_exec'), SIZE), va_range, pa_range)
