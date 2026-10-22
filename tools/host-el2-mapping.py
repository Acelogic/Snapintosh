# SPDX-License-Identifier: MIT
"""Admit a secondary's shared EL2 regime using actual firmware page tables.

Only the measured non-VHE, 4 KiB, 44-bit A16 EL2 regime is supported. This
does not create or edit tables. Call while the primary regime is stable.
"""
import struct


def validate_regime(memory):
    sctlr, tcr, ttbr, mair, hcr = (int(memory[k], 16) for k in ('sctlr', 'tcr', 'ttbr0', 'mair', 'hcr'))
    if (sctlr & 0x1005 != 0x1005 or hcr & (1 << 34) or
            tcr & 63 != 20 or (tcr >> 14) & 3 or (tcr >> 8) & 63 != 0x35 or
            (tcr >> 16) & 7 != 4 or ttbr & ~0x00000ffffffff000 or not ttbr):
        raise ValueError('unsupported primary EL2 memory regime')
    return sctlr, tcr, ttbr, mair


def verify(read, memory, ranges, ram_ranges):
    _, _, root, mair = validate_regime(memory)
    tables = set()

    def descriptor(table, slot):
        if not any(lo <= table and table+4096 <= hi for lo, hi in ram_ranges):
            raise ValueError('host table outside declared RAM')
        tables.add(table)
        return struct.unpack('<Q', read(table+slot*8, 8))[0]

    def walk(va):
        if not 0 <= va < 1 << 44:
            raise ValueError('host VA outside admitted TCR range')
        table = root
        for level, shift in enumerate((39, 30, 21, 12)):
            desc = descriptor(table, (va >> shift) & 511)
            form = desc & 3
            if (level == 3 and form == 3) or (level in (1, 2) and form == 1):
                mask = (1 << shift)-1
                if desc & 0x00000ffffffff000 & mask:
                    raise ValueError('misaligned host block descriptor')
                pa = (desc & 0x00000ffffffff000 & ~mask) | (va & mask)
                return pa, desc, shift
            if form != 3 or level == 3:
                raise ValueError('invalid host translation descriptor')
            table = desc & 0x00000ffffffff000
        raise ValueError('missing host translation')

    witnesses = []
    for name, base, size, device in ranges:
        if size <= 0 or base % 4096:
            raise ValueError('invalid mapping request')
        for offset in range(0, size, 4096):
            va = base+offset
            pa, desc, shift = walk(va)
            attr = (mair >> (((desc >> 2) & 7)*8)) & 255
            if pa != va or not desc & (1 << 10) or desc & (1 << 7):
                raise ValueError('host range must be identity mapped, accessed and writable')
            if (device and attr != 0) or (not device and
                    (attr != 255 or (desc >> 8) & 3 != 3)):
                raise ValueError('incompatible shared RAM or Device memory attributes')
            if name == 'code' and desc & (1 << 54):
                raise ValueError('secondary code is not executable')
            witnesses.append(dict(name=name, va=hex(va), pa=hex(pa), desc=hex(desc),
                                  leaf_shift=shift, memory_attribute=hex(attr)))
    # These table pages are read through the primary's identity map. Check
    # that assumption as well; newly encountered intermediate tables follow.
    checked = set()
    while tables-checked:
        table = next(iter(tables-checked))
        pa, desc, _ = walk(table)
        if (pa != table or ((mair >> (((desc >> 2) & 7)*8)) & 255) != 255
                or (desc >> 8) & 3 != 3 or not desc & (1 << 10)):
            raise ValueError('host table is not identity-mapped normal WB memory')
        checked.add(table)
    return dict(mappings=witnesses, table_pages=[hex(p) for p in sorted(tables)])
