# SPDX-License-Identifier: MIT
"""Validate a stopped CPU's breakpoint-bank lifecycle, not merely build flags."""
import struct

SIZE=280
SITES={
    0xfffffe000b86eae8:0xd5184033,0xfffffe000b86eb08:0xd5184032,
    0xfffffe000b86f9f4:0xd5184002,0xfffffe000b86fc14:0xd5184002,
    0xfffffe000b86fc70:0xd518402c,0xfffffe000b86fe88:0xd5184002,
}
FIELDS=('dfr0','saved','installed','install_verified','restores','restore_failed',
        'traps','rejected','stepped','last_pc','last_word')

def audit(raw,*,enabled,prepared):
    if len(raw)!=SIZE or type(enabled) is not bool or type(prepared) is not bool:
        raise ValueError('invalid native writer audit input')
    words=struct.unpack('<35Q',raw)
    if not enabled or not prepared:
        if any(words):raise ValueError('unused native writer bank changed')
        return dict(active=False,traps=0,stepped=0,raw_hex=raw.hex())
    row=dict(zip(FIELDS,words[24:]))
    if not 6<=row['dfr0']&15<=11 or (row['dfr0']>>12)&15<5:
        raise ValueError('native writer debug capacity differs')
    if (row['saved'],row['installed'],row['install_verified'],row['restores'],
            row['restore_failed'],row['rejected'])!=(1,0,1,1,0,0):
        raise ValueError('native writer bank lifecycle is not restored and qualified')
    if words[:12]!=words[12:24]:
        raise ValueError('native writer debug register restoration differs')
    if row['stepped']>row['traps']:
        raise ValueError('native writer step accounting differs')
    if row['traps']:
        if SITES.get(row['last_pc'])!=row['last_word']:
            raise ValueError('native writer terminal instruction differs')
    elif row['last_pc'] or row['last_word']:
        raise ValueError('unobserved native writer has a last instruction')
    return dict(row,active=True,raw_hex=raw.hex(),
                boundary='Recorded per-CPU install/readback and restoration; register bits alone do not prove every comparator executed.')
