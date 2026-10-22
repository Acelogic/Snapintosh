#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay Apple's shared disjoint engine (...270fdc44) on duplicate records.

UPDATE_DISJOINT (endpoint6, callbacks fd544/fdab4) and UNMAP_DISJOINT
(endpoint8, callbacks fd244/fd478) both run the one loop at ...270fdc44. This
executes that loop, its CAS, both callbacks and the release/unlock pass as
shipped, with the frame-table/walk/TLBI helpers replaced by a small model:

  de490  copy the caller's records into CPU scratch +0x200
  ec314  target metadata, reader lock +2      f9ab8  root metadata, lock +2
  f9cd8  VA check (returns VA)                ec4e8  walk: slot pointer, lock +2
  ec194  metadata without lock                dfea4  TLBI (recorded)
  ecb8c  reference transfer/release (recorded)
  102cc8/102d08  panic (the replay fails)

The question answered is whether the shipped engine treats two records naming
the same (root, VA) as an error. It does not look for them: each record is
walked, CAS'd and released on its own, so a later duplicate observes the
earlier record's result. No instruction is patched.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
BASE = 0xfffffff027000000
RAM, RAMSZ = 0x1000000, 0x100000
PERCPU, SCRATCH, META, TABLE, LIST, STACK = (RAM+0x1000, RAM+0x10000, RAM+0x20000,
                                             RAM+0x30000, RAM+0x40000, RAM+0xf0000)
TARGET, OTHER, USER_ROOT = 0x968270000, 0x968274000, 0x968008000
TABLE_PA = 0x9683cc000
VA = 0x105568000
ENGINE = BASE+0xfdc44
UPDATE_CB, UPDATE_RELEASE = BASE+0xfd544, BASE+0xfdab4
UNMAP_CB, UNMAP_RELEASE = BASE+0xfd244, BASE+0xfd478
PACIBSP, AUTIBSP, RETAB = 0xd503237f, 0xd50323ff, 0xd65f0fff


def meta_of(pa):
    return {TARGET: META, OTHER: META+0x10, USER_ROOT: META+0x20, TABLE_PA: META+0x30}[pa]


def replay(im, records, slots, options, update):
    """records: [(root, va, template)]; slots: {(root, va): initial PTE}.
    Returns the per-record old values, final slot values and helper calls."""
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)       # LSE CAS/LDADD
    u.mem_map(BASE, 0x200000); u.mem_map(RAM, RAMSZ)
    for _, va, _, off, size in im.segs:
        u.mem_write(va, im.data[off:off+size])
    get = lambda i: u.reg_read(getattr(reg, f'UC_ARM64_REG_X{i}'))
    put = lambda i, v: u.reg_write(getattr(reg, f'UC_ARM64_REG_X{i}'), v)
    q = lambda a: struct.unpack('<Q', u.mem_read(a, 8))[0]
    h = lambda a: struct.unpack('<H', u.mem_read(a, 2))[0]
    u.mem_write(PERCPU+0x1680, struct.pack('<Q', SCRATCH))
    # Managed physical range [...9e1f8, ...9e200): the target and list checks
    # at fdc9c..fdcbc. Records are copied through the de490 model.
    u.mem_write(BASE+0x9e1f8, struct.pack('<2Q', 0, 1 << 40))
    # Metadata {u16 lock, u8 type}: DEFAULT targets, USER_ROOT, PAGE_TABLE.
    for pa, kind in ((TARGET, 11), (OTHER, 11), (USER_ROOT, 18), (TABLE_PA, 20)):
        u.mem_write(meta_of(pa), struct.pack('<HB', 0, kind))
    slot_va = {}
    for n, (key, pte) in enumerate(slots.items()):
        slot_va[key] = TABLE+8*n
        u.mem_write(TABLE+8*n, struct.pack('<Q', pte))
    for n, r in enumerate(records):
        u.mem_write(LIST+24*n, struct.pack('<3Q', *r))
    calls = dict(tlbi=0, release=[], walks=0)

    def lock(meta, delta):
        u.mem_write(meta, struct.pack('<H', (h(meta)+delta) & 0xffff))

    def ret(value=None):
        if value is not None: put(0, value)
        u.reg_write(reg.UC_ARM64_REG_PC, get(30))

    def hook(uc, a, size, _):
        word = struct.unpack('<I', u.mem_read(a, 4))[0]
        off = a-BASE
        if off in (0xfdf94, 0xfe158):                   # dsb ishnxs (FEAT_XS)
            u.reg_write(reg.UC_ARM64_REG_PC, a+4)
        elif off == 0xfdcc8:                            # mrs s3_6_c15_c8_0
            put(8, 1); u.reg_write(reg.UC_ARM64_REG_PC, a+4)
        elif off == 0xfdcd0:                            # mrs s3_6_c15_c11_1
            put(8, PERCPU); u.reg_write(reg.UC_ARM64_REG_PC, a+4)
        elif off == 0xde490:
            u.mem_write(SCRATCH+0x200, bytes(u.mem_read(get(0), get(1)*get(2)))); ret()
        elif off == 0xec314:
            lock(meta_of(get(0)), 2); ret(meta_of(get(0)))
        elif off == 0xf9ab8:
            lock(meta_of(get(0)), 2); ret(meta_of(get(0)))
        elif off == 0xf9cd8:
            ret(get(0))
        elif off == 0xec4e8:
            calls['walks'] += 1
            root = next(pa for pa in (USER_ROOT,) if meta_of(pa) == get(0))
            key = (root, get(1))
            if key not in slot_va:
                u.mem_write(get(4), struct.pack('<Q', 0)); ret(0); return
            u.mem_write(get(4), struct.pack('<Q', slot_va[key]))
            lock(meta_of(TABLE_PA), 2); ret(meta_of(TABLE_PA))
        elif off == 0xec194:
            ret(meta_of(get(0)))
        elif off == 0xdfea4:
            calls['tlbi'] += 1; ret()
        elif off == 0xecb8c:
            calls['release'].append([hex(get(i)) for i in range(4)]); ret()
        elif off == 0x102998:
            raise AssertionError(f'unmodeled 102998 from {get(30)-4:x}')
        elif off in (0x102cc8, 0x102d08):
            raise AssertionError(f'Apple SPTM panicked from {get(30)-4:x}')
        elif word in (PACIBSP, AUTIBSP):
            u.reg_write(reg.UC_ARM64_REG_PC, a+4)
        elif word == RETAB:
            if a == BASE+0xfe1d4: u.emu_stop(); return
            ret()
        elif word & 0xfffffc1f == 0xd73f081f:           # BLRAA xN, x17
            put(30, a+4); u.reg_write(reg.UC_ARM64_REG_PC, get((word >> 5) & 31))

    u.hook_add(UC_HOOK_CODE, hook)
    u.reg_write(reg.UC_ARM64_REG_SP, STACK)
    put(0, TARGET); put(1, LIST); put(2, len(records)); put(3, options)
    put(4, UPDATE_CB if update else UNMAP_CB)
    put(5, UPDATE_RELEASE if update else UNMAP_RELEASE)
    put(30, 0)
    try:
        u.emu_start(ENGINE, 0, count=200000)
    except Exception as exc:
        raise AssertionError(f'stopped at {u.reg_read(reg.UC_ARM64_REG_PC):x}: {exc}') from exc
    assert u.reg_read(reg.UC_ARM64_REG_PC) == BASE+0xfe1d4, hex(u.reg_read(reg.UC_ARM64_REG_PC))
    # Every reader lock the walk and metadata lookups took has been dropped.
    for pa in (TARGET, USER_ROOT, TABLE_PA):
        assert h(meta_of(pa)) == 0, (hex(pa), h(meta_of(pa)))
    return dict(result=get(0), old=[hex(q(SCRATCH+8*n)) for n in range(len(records))],
                slots={f'{k[0]:x}/{k[1]:x}': hex(q(v)) for k, v in slot_va.items()},
                walks=calls['walks'], tlbi=calls['tlbi'], releases=calls['release'])


def main():
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(im.data).hexdigest() == SHA
    rw = 0x0060000968270e43                 # captured user RW leaf on TARGET
    ro = rw | 0x80                           # its write revocation (AP[2])
    other_va = VA+0x4000
    cases = {}
    # UNMAP_DISJOINT: an identical pair, and a pair split by another record.
    cases['unmap_identical'] = r = replay(im, [(USER_ROOT, VA, 0)]*2,
                                          {(USER_ROOT, VA): rw}, 0, False)
    assert r['old'] == [hex(rw), '0x80'] and r['slots'][f'{USER_ROOT:x}/{VA:x}'] == '0x0'
    assert len(r['releases']) == 1 and r['walks'] == 2 and r['result'] == 0
    cases['unmap_interleaved'] = r = replay(
        im, [(USER_ROOT, VA, 0), (USER_ROOT, other_va, 0), (USER_ROOT, VA, 0)],
        {(USER_ROOT, VA): rw, (USER_ROOT, other_va): rw}, 0, False)
    assert r['old'] == [hex(rw), hex(rw), '0x80'] and len(r['releases']) == 2
    # UPDATE_DISJOINT: identical revocation, identical satisfied request and
    # two different requests for one slot (applied in order, not refused).
    cases['update_identical_revoke'] = r = replay(im, [(USER_ROOT, VA, ro)]*2,
                                                  {(USER_ROOT, VA): rw}, 2, True)
    assert r['old'] == [hex(rw), hex(ro)] and r['slots'][f'{USER_ROOT:x}/{VA:x}'] == hex(ro)
    cases['update_identical_satisfied'] = r = replay(im, [(USER_ROOT, VA, ro)]*2,
                                                     {(USER_ROOT, VA): ro}, 2, True)
    assert r['old'] == [hex(ro)]*2 and r['slots'][f'{USER_ROOT:x}/{VA:x}'] == hex(ro)
    aged = rw & ~0x400
    cases['update_conflicting'] = r = replay(im, [(USER_ROOT, VA, ro), (USER_ROOT, VA, aged)],
                                             {(USER_ROOT, VA): rw}, 0xa, True)
    assert r['old'][0] == hex(rw) and r['old'][1] == hex(ro), r
    assert r['slots'][f'{USER_ROOT:x}/{VA:x}'] == hex(ro & ~0x400), r
    print(json.dumps(dict(sptm_sha256=SHA, engine=hex(ENGINE), cases=cases,
        verdict='duplicate (root, VA) records are accepted and applied in order; '
                'the later record observes the earlier one\'s CAS result',
        boundary='engine loop, CAS and callbacks executed; frame table, walk, '
                 'TLBI and reference helpers modeled'), indent=2))


if __name__ == '__main__':
    main()
