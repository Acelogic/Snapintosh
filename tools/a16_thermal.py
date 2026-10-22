# SPDX-License-Identifier: MIT
"""Read-only ABI decoder for compat/a16-thermal.h; no target I/O."""
import struct
MAGIC=0x314d524548543641
SIZE=320*8
REPORT_OFFSET=16+0xf000
FIELDS=('magic abi bytes polls reads started last_poll next_poll last_change trip_ticks reason location '
        'current_mc peak_mc valid_count missing_count max_gap_ticks invalid_samples read_failures '
        'poll_ticks max_poll_ticks ready unchanged_ticks read_inflight').split()
REASONS={0:'okay',1:'temperature ceiling',2:'sensor configuration',3:'sensor invalid for one second',
         4:'sample gap of one second',5:'sensor read failure',6:'temperature outside plausible range',
         7:'hardware critical status',8:'all temperatures unchanged for ten seconds',
         9:'sample consumed a polling interval',10:'invalid counter frequency'}

def admit_target(info):
    # Fail closed before accessing the Glymur-specific MMIO map. This is the
    # surveyed platform fingerprint, not authentication or arbitrary-v3 support.
    expected=dict(current_el=2,timer_hz=19200000,gic_distributor=0x17000000,
                  gic_redistributor=0x17080000,fb_width=2880,fb_height=1800)
    if any(info.get(k)!=v for k,v in expected.items()):
        raise ValueError('thermal guard requires the surveyed A16/Glymur EL2 platform')

def decode(raw):
    if len(raw)!=SIZE:raise ValueError(f'thermal report requires {SIZE} bytes')
    w=struct.unpack('<320Q',raw)
    if not any(w):return None
    if w[:3]!=(MAGIC,1,SIZE):raise ValueError('unrecognized thermal report ABI')
    r=dict(zip(FIELDS,w));cursor=len(FIELDS)
    for key,count in [('version',8),('control',8),('trdy',8),('valid_mask',8),('seen_mask',8),('last_valid',128),('raw',128)]:
        r[key]=list(w[cursor:cursor+count]);cursor+=count
    for key in ('current_mc','peak_mc'):
        if r[key]>>63:r[key]-=1<<64
        if r[key]==-(1<<63):r[key]=None
    r['reason_name']=REASONS.get(r['reason'],f'unknown reason {r["reason"]}')
    return r

def summary(r,hz):
    if r is None:return 'thermal guard disabled'
    peak='none' if r['peak_mc'] is None else f'{r["peak_mc"]/1000:.1f} C'
    return (f'thermal guard: {r["reason_name"]}, {r["valid_count"]}/92 valid, peak {peak}, '
            f'{r["polls"]} samples, max sample {r["max_poll_ticks"]/hz*1000:.3f} ms, '
            f'max gap {r["max_gap_ticks"]/hz*1000:.3f} ms')
