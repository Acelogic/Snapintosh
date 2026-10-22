#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent check of the monitor's historical first-EL0-step witnesses.

These snapshots belong to the time of entry; the current root may have changed
since then. A dispatch count does not imply that an instruction executed.
"""
import struct

FIELDS=('returns','pending','executed','interrupted','faults','svcs',
        'entry','stack','initial_spsr','root','shadow','ttbr','tcr',
        'entry_pa','source_pte','shadow_pte','instruction','initial_x0',
        'observed_pc','observed_spsr','observed_esr','observed_x0','observed_sp')

def audit(data):
    if len(data)!=6*len(FIELDS)*8:
        raise ValueError('wrong userspace witness size')
    rows=[]
    for cpu,words in enumerate(struct.iter_unpack('<'+'Q'*len(FIELDS),data)):
        row=dict(zip(FIELDS,words));row['cpu']=cpu
        if row['pending'] not in (0,1) or row['executed'] not in (0,1) or row['interrupted'] not in (0,1):
            raise ValueError('invalid one-instruction probe state')
        if row['executed'] or row['pending']:
            assert row['returns'] and not row['interrupted']
            assert row['instruction']==0x910003e0
            assert 0<row['entry']<(1<<47)-4 and row['entry']%4==0
            assert 0<row['stack']<1<<47 and row['initial_spsr']&31==0
            assert row['root']%16384==0 and row['shadow']%4096==0
            assert row['ttbr']&((1<<48)-1)==row['shadow'] and row['ttbr']>>48
            assert row['tcr']&0xc0bf==17  # 4K, T0SZ=17, EPD0 clear
            a,b=row['source_pte'],row['shadow_pte']
            attrs=0xfff|(3<<53)
            assert a&attrs==b&attrs
            assert a&3==3 and a&(3<<6)==3<<6 and a&(1<<10)
            assert a&(1<<53) and not a&(1<<54)
            assert b&0x0000fffffffff000==row['entry_pa']&~4095
        if row['executed']:
            assert not row['pending']
            assert row['observed_esr']>>26==0x32
            assert row['observed_spsr']&31==0
            assert row['observed_pc']==row['entry']+4
            assert row['observed_x0']==row['observed_sp']==row['stack']
        row['el0_execution_proven']=bool(row['executed'])
        rows.append(row)
    return dict(returns=sum(r['returns'] for r in rows),
                el0_execution_proven=any(r['el0_execution_proven'] for r in rows),
                witnessed_cpus=[r['cpu'] for r in rows if r['el0_execution_proven']],
                faults=sum(r['faults'] for r in rows),svcs=sum(r['svcs'] for r in rows),rows=rows)
