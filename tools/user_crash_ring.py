# SPDX-License-Identifier: MIT
"""Decode the monitor's EL0 crash evidence (compat/user-crash.h).

Reads context.user_crashes (per-vCPU rings, SNAP_USER_CRASH_RING) together
with the older per-vCPU counters guest_user_signal and guest_brk, from a
stopped monitor through an injected read(pa, n). Each field is optional so
older monitors decode as None instead of failing. PAC is stripped for
display only; the raw values are kept.
"""
import re
import struct

GUEST_CPUS = 6
ROWS = 8
FRAMES = 4
TEXT_WORDS = 8
RECORD_WORDS = 29
HEADER = ('recorded', 'walk_reads', 'walk_refusals', 'text_refusals')
FIELDS = ('seq', 'guest_count', 'raw_count', 'meta', 'esr', 'elr', 'far', 'x0', 'x1', 'x2',
          'x16', 'fp', 'lr', 'sp', 'ttbr0', 'tpidr_el1', 'tpidrro_el0')
RING_BYTES = 8 * len(HEADER) + ROWS * RECORD_WORDS * 8
KINDS = {1: 'self_signal', 2: 'kill', 3: 'abort_with_payload', 4: 'terminate_with_payload',
         5: 'os_fault_with_payload', 6: 'fatal_exception', 7: 'wild_address_abort',
         8: 'el0_trap'}
SIGNALS = {3: 'SIGQUIT', 4: 'SIGILL', 5: 'SIGTRAP', 6: 'SIGABRT', 7: 'SIGEMT', 8: 'SIGFPE',
           10: 'SIGBUS', 11: 'SIGSEGV', 12: 'SIGSYS'}
EXCEPTIONS = {0x00: 'unknown', 0x0e: 'illegal state', 0x1c: 'FPAC', 0x22: 'PC alignment',
              0x26: 'SP alignment', 0x3c: 'BRK', 0x20: 'instruction abort', 0x24: 'data abort',
              0x15: 'SVC', 0x01: 'WFI/WFE', 0x07: 'SIMD/FP access', 0x09: 'PAC instruction trap',
              0x0d: 'BTI', 0x18: 'MSR/MRS/SYS', 0x19: 'SVE', 0x1d: 'SME', 0x2c: 'FP exception'}
# What 26A428's sleh_synchronous does with each EL0 class (kernel.release.t8140 disassembly, jump table at
# sleh_synchronous+3424; docs in compat/user-crash.h): the signal the process gets, or a kernel panic.
XNU_OUTCOME = {0x00: 'SIGILL', 0x01: 'SIGILL', 0x07: 'SIGILL', 0x09: 'SIGILL', 0x18: 'SIGILL', 0x19: 'SIGILL',
               0x1d: 'SIGILL unless SME state is allocated', 0x0d: 'kernel panic', 0x0e: 'kernel panic',
               0x1c: 'SIGSEGV/SIGBUS (EXC_BAD_ACCESS|EXC_PTRAUTH)', 0x22: 'SIGBUS', 0x26: 'SIGBUS',
               0x2c: 'SIGFPE', 0x3c: 'SIGTRAP'}
GUEST_HZ = 24_000_000


def strip(value):
    """User VA without PAC/TBI bits (display only)."""
    return value & ((1 << 47) - 1)


def decode_record(raw):
    words = struct.unpack(f'<{RECORD_WORDS}Q', raw)
    row = dict(zip(FIELDS, words[:len(FIELDS)]))
    frames = list(words[len(FIELDS):len(FIELDS) + FRAMES])
    text_words = words[len(FIELDS) + FRAMES:]
    meta = row['meta']
    kind, cpu, ec = meta & 0xff, (meta >> 8) & 0xff, (meta >> 16) & 63
    nframes, ntext, offset = (meta >> 24) & 7, (meta >> 28) & 15, (meta >> 32) & 7
    if nframes > FRAMES or ntext > TEXT_WORDS:
        raise ValueError(f'crash record meta {meta:#x} outside the ring ABI')
    text = b''.join(struct.pack('<Q', w) for w in text_words[:ntext])[offset:]
    # Exception rows (SNAP_USER_CRASH_WIDE) keep the faulting instruction, not a reason string.
    insn = struct.unpack_from('<I', text)[0] if kind in (6, 8) and ntext and len(text) >= 4 else None
    row.update(kind=KINDS.get(kind, f'unknown:{kind}'), cpu=cpu, ec=ec,
               exception=EXCEPTIONS.get(ec, hex(ec)), frames=frames[:nframes],
               reason=text.split(b'\0', 1)[0].decode('utf-8', 'replace') if ntext and insn is None else None,
               insn=insn, xnu_outcome=XNU_OUTCOME.get(ec) if kind in (6, 8) else None,
               guest_s=row['guest_count'] / GUEST_HZ if row['guest_count'] else None,
               root=row['ttbr0'] & ((1 << 48) - 1), asid=row['ttbr0'] >> 48)
    if kind in (1, 2):
        row['signal'] = SIGNALS.get(row['x1'], row['x1'])
    if ec == 0x3c:
        row['brk_immediate'] = row['esr'] & 0xffff
        row['pac_trap'] = 0xc470 <= row['brk_immediate'] <= 0xc473
    if kind == 7:
        row['pac_poisoned'] = strip(row['far'] & ((1 << 56) - 1)) != (row['far'] & ((1 << 56) - 1))
    return row


def decode_ring(raw, cpu=None):
    if len(raw) != RING_BYTES:
        raise ValueError(f'crash ring is {len(raw)} bytes, not {RING_BYTES}')
    header = dict(zip(HEADER, struct.unpack_from('<4Q', raw, 0)))
    rows = []
    for n in range(ROWS):
        base = 32 + n * RECORD_WORDS * 8
        row = decode_record(raw[base:base + RECORD_WORDS * 8])
        if not row['seq']:
            continue
        if (row['seq'] - 1) % ROWS != n or row['seq'] > header['recorded']:
            raise ValueError(f'crash ring slot {n} holds sequence {row["seq"]}')
        if cpu is not None and row['cpu'] != cpu:
            raise ValueError(f'crash ring {cpu} holds a record from CPU {row["cpu"]}')
        rows.append(row)
    rows.sort(key=lambda r: r['seq'])
    header['lost'] = max(0, header['recorded'] - ROWS)
    return dict(header, rows=rows)


def read_context(read, work, offset, layout):
    """EL0 crash evidence from a stopped monitor; fields absent in older
    layouts are None. offset(kind, field) and layout come from clang."""
    def present(field):
        return re.search(r' ' + field + r'(\[\d+\])?$', layout, re.M) is not None
    result = dict(guest_user_signal=None, guest_brk=None, user_crashes=None)
    if present('guest_user_signal'):
        result['guest_user_signal'] = list(struct.unpack(
            f'<{GUEST_CPUS}Q', read(work + offset('context', 'guest_user_signal'), 8 * GUEST_CPUS)))
    if present('guest_brk'):
        raw = read(work + offset('context', 'guest_brk'), 40 * GUEST_CPUS)
        result['guest_brk'] = [dict(zip(('el0', 'el1', 'last_pc', 'last_esr', 'last_spsr'), row))
                               for row in struct.iter_unpack('<5Q', raw)]
    if present('user_crashes'):
        raw = read(work + offset('context', 'user_crashes'), RING_BYTES * GUEST_CPUS)
        rings = [decode_ring(raw[n * RING_BYTES:(n + 1) * RING_BYTES], n) for n in range(GUEST_CPUS)]
        merged = sorted((row for ring in rings for row in ring['rows']),
                        key=lambda r: (r['guest_count'] or r['raw_count'], r['cpu'], r['seq']))
        result['user_crashes'] = dict(
            recorded=[ring['recorded'] for ring in rings], lost=[ring['lost'] for ring in rings],
            walk_refusals=[ring['walk_refusals'] for ring in rings],
            text_refusals=[ring['text_refusals'] for ring in rings], rows=merged)
    return result


def attribute(rows, processes):
    """Name each record's process from a kernel-waits capture's live roots."""
    roots = {}
    for process in processes:
        space = process.get('user_address_space') or {}
        if space.get('root'):
            roots[int(space['root'], 16)] = (process['pid'], process['name'])
    for row in rows:
        row['process'] = roots.get(row['root'])
    return rows
