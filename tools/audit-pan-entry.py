#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit physical PAN exception-entry evidence, without modifying PSTATE."""
import struct

FIELDS='mmfr1 installed_sctlr user_vectors protected_vectors vector saved_spsr entry_spsr entry_sctlr'.split()

def audit(raw):
    assert len(raw)==6*8*8
    rows=[]
    for cpu,values in enumerate(struct.iter_unpack('<8Q',raw)):
        row=dict(zip(FIELDS,values),cpu=cpu)
        assert (row['mmfr1']>>20)&15, f'CPU{cpu}: PAN not implemented'
        assert not row['installed_sctlr']&(1<<23), f'CPU{cpu}: SPAN preserves PAN'
        row['user_cache_zero_enabled']=bool(row['installed_sctlr']&(1<<14))
        # SNAP_EL0_WFE / SNAP_EL0_CACHE_MAINT: EL0 WFE (nTWE) and EL0 cache maintenance (UCI) run
        # instead of trapping to XNU as SIGILL; reported, and held to the installed policy below.
        row['user_wfe_enabled']=bool(row['installed_sctlr']&(1<<18))
        row['user_cache_maint_enabled']=bool(row['installed_sctlr']&(1<<26))
        assert row['user_vectors']==row['protected_vectors'], f'CPU{cpu}: unprotected user vector'
        if row['user_vectors']:
            assert row['vector'] in (0x400,0x480,0x500,0x580)
            assert not row['saved_spsr']&31
            assert row['entry_spsr']&(1<<22)
            assert row['entry_spsr']&31 in (4,5)
            assert not row['entry_sctlr']&(1<<23)
            assert bool(row['entry_sctlr']&(1<<14))==row['user_cache_zero_enabled'], \
                f'CPU{cpu}: cache-zero policy changed after installation'
            assert (row['entry_sctlr']&((1<<18)|(1<<26)))==(row['installed_sctlr']&((1<<18)|(1<<26))), \
                f'CPU{cpu}: EL0 WFE/cache-maintenance policy changed after installation'
        else:
            assert not any(values[4:])
        rows.append(row)
    return dict(user_cache_zero_enabled=all(r['user_cache_zero_enabled'] for r in rows),
                user_wfe_enabled=all(r['user_wfe_enabled'] for r in rows),
                user_cache_maint_enabled=all(r['user_cache_maint_enabled'] for r in rows),
                user_vectors=sum(r['user_vectors'] for r in rows),
                protected_vectors=sum(r['protected_vectors'] for r in rows),rows=rows)
