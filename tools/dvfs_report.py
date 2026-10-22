#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the agents/dvfs record DVFSREP1 from a run's report.bin (probes/xnuboot.c OUT_DVFS: the words right after
the thermal report, byte 16 + 8 * (0xf000 / 8 + 320)): struct cpu_dvfs_state (compat/cpu-dvfs.h) and struct
gpu_dvfs_state (compat/gpu-dvfs.h), as the stop left them. Each block's ABI word picks the layout: CPU ABI 1
(b12v4) counted requested levels, ABI 2 counts LEVEL_GET's; GPU ABI 2 adds the race-to-idle counters, ABI 3
the first-IB kick, the hold and the two thermal readings.

  python3 tools/dvfs_report.py build/PREFIX/report.bin
  python3 tools/dvfs_report.py --raw BLOCK.bin        # a block that starts at the magic (tools/test-dvfs.c)
"""
import argparse
import json
import struct
import sys
from pathlib import Path

MAGIC = 0x3150455253465644                       # "DVFSREP1"
OFFSET = 16 + 8 * (0xF000 // 8 + 320)
CPU_LEVELS_KHZ = {
    0: [355200, 902400, 1056000, 1209600, 1363200, 1516800, 1651200, 1785600, 1939200, 2073600, 2208000, 2342400,
        2496000, 2630400, 2764800, 2918400, 3072000, 3225600, 3398400, 3552000, 3609600, 0],
    1: [355200, 883200, 1132800, 1382400, 1593600, 1785600, 1996800, 2188800, 2400000, 2611200, 2822400, 3033600,
        3225600, 3436800, 3628800, 3801600, 3955200, 4128000, 4281600, 4454400, 4800000, 5011200]}
CPU_LEVELS_KHZ[2] = CPU_LEVELS_KHZ[1]
GPU_MHZ = [0, 310, 410, 572, 760, 820, 915, 1070, 1185, 1350, 1550, 1700]   # ABI <= 3 used 1..6
CPU_STATUS = {0: 'off', 1: 'running', 2: 'stopped (restored)'}
GPU_STATUS = {0: 'off', 1: 'running', 2: 'latched (no more votes)', 3: 'stopped (restored)'}
GPU_ERRORS = {0: 'ok', 1: 'range', 2: 'host record', 3: 'queue corrupt', 4: 'queue busy', 5: 'timeout',
              6: 'nack', 7: 'response queue', 8: 'address refused'}
OFF_REASON = {0: '', 1: 'no thermal guard', 2: 'no counter frequency / arena', 3: 'no governed domain'}


def signed(v):
    return v - (1 << 64) if v >> 63 else v


def u32s(words):
    out = []
    for w in words:
        out += [w & 0xffffffff, w >> 32]
    return out


def cpu_v1(words, head, out):
    """ABI 1 (b12v4 and before): its residency counted the REQUESTED level, not LEVEL_GET."""
    if len(words) < 106:
        raise ValueError(f'CPU ABI 1 block has {len(words)} words, expected 106')
    at = 13
    for d in range(3):
        f = dict(zip('slots level floor ceiling restore initial_get writes mismatches latched verify below '
                     'below_target clamped_windows last_demand_pct'.split(), words[at:at + 14]))
        res = u32s(words[at + 14:at + 25])
        at += 25
        if not f['slots']:
            continue
        khz = CPU_LEVELS_KHZ[d]
        latched_get = f['latched'] & 0xffffffff if f['latched'] else None
        out['domains'][f'PDP{d}'] = dict(
            vcpu_slots=[n for n in range(6) if f['slots'] >> n & 1], requested_level=f['level'], floor=f['floor'],
            ceiling=f['ceiling'], restore_level=f['restore'], level_get_at_start=f['initial_get'],
            fastchannel_writes=f['writes'], verify_mismatches=f['mismatches'],
            latched=hex(f['latched']) if f['latched'] else None, level_get_at_latch=latched_get,
            clamped_windows=f['clamped_windows'], last_demand_pct=f['last_demand_pct'],
            seconds_at_requested_level={f'{l} ({khz[l] / 1e6:.3f} GHz)': round(n * 0.02, 1)
                                        for l, n in enumerate(res) if n},
            warning='ABI 1 counted the requested level; what the firmware ran is LEVEL_GET: '
                    f'{f["initial_get"]} at the start' + (f', {latched_get} at the latch' if latched_get is not None
                                                          else '') + '; no granted residency was recorded')
    out['seconds_note'] = ('ABI 1 counted windows x 20 ms; a window ends at the first vCPU 0 tick past 20 ms, so '
                           'this is a lower bound (b12v4: 195.5 s counted, 246.7 s wall)')
    return out


CPU_DOMAIN_U32 = ('level requested floor ceiling restore initial_get cap walk writes refusals mismatches latched '
                  'verify settled below below_target clamped_windows last_demand_pct limits_start limits_last '
                  'limits_changes refused_mask granted_max unknown_ms reprobes accepted').split()


def cpu(words):
    if len(words) < 13:
        raise ValueError(f'CPU block has {len(words)} words')
    head = dict(zip('magic abi status reason hz window_ticks next_window windows thermal_mc thermal_clamp hispeed '
                    'restores thermal_eff_mc'.split(), words[:13]))
    out = dict(abi=head['abi'], status=CPU_STATUS.get(head['status'], head['status']),
               off_reason=OFF_REASON.get(head['reason']), windows=head['windows'],
               seconds=round(head['windows'] * 0.02, 1),
               last_thermal_c=round(signed(head['thermal_mc']) / 1000, 1) if head['thermal_mc'] != 1 << 63 else None,
               thermal_clamp_streak=head['thermal_clamp'], hispeed_jumps=head['hispeed'], restores=head['restores'],
               domains={})
    if head['abi'] == 1:
        return cpu_v1(words, head, out)
    need = 19 + 3 * 25
    if len(words) < need:
        raise ValueError(f'CPU ABI {head["abi"]} block has {len(words)} words, expected {need}')
    hz = head['hz'] or 19200000
    started, last_window = words[13], words[14]
    out['seconds'] = round((last_window - started) / hz, 1)
    meas_count, meas_sum = words[15], words[16]
    lo, hi = u32s(words[17:19])[0:2], u32s(words[17:19])[2:4]
    out['measured_clock'] = dict(
        samples=meas_count, mean_ghz=round(meas_sum / meas_count / 1e3, 3) if meas_count else None,
        min_ghz=round(lo[0] / 1e6, 3) if meas_count else None, max_ghz=round(lo[1] / 1e6, 3) if meas_count else None,
        last_ghz=round(hi[0] / 1e6, 3) if meas_count else None, level_get_at_last=hi[1] if meas_count else None,
        note="vCPU 0's core, a dependent-ADD chain timed by CNTPCT once a second (independent of LEVEL_GET)")
    at = 19
    for d in range(3):
        slots = words[at]
        f = dict(zip(CPU_DOMAIN_U32, u32s(words[at + 1:at + 14])))
        res = u32s(words[at + 14:at + 25])
        at += 25
        if not slots:
            continue
        khz = CPU_LEVELS_KHZ[d]
        total = sum(res)
        out['domains'][f'PDP{d}'] = dict(
            vcpu_slots=[n for n in range(6) if slots >> n & 1], granted_level=f['level'],
            last_requested=f['requested'], floor=f['floor'], ceiling=f['ceiling'], firmware_cap=f['cap'],
            walking=bool(f['walk']), restore_level=f['restore'], level_get_at_start=f['initial_get'],
            granted_max=f['granted_max'], fastchannel_writes=f['writes'], accepted=f['accepted'],
            refusals=f['refusals'], refused_levels=[l for l in range(22) if f['refused_mask'] >> l & 1],
            reprobes=f['reprobes'], latched=hex(f['latched']) if f['latched'] else None,
            limits_get_start=hex(f['limits_start']), limits_get_last=hex(f['limits_last']),
            limits_get_changes=f['limits_changes'], clamped_windows=f['clamped_windows'],
            last_demand_pct=f['last_demand_pct'], unpublished_seconds=round(f['unknown_ms'] / 1e3, 1),
            seconds_at_granted_level={f'{l} ({khz[l] / 1e6:.3f} GHz)': round(n / 1e3, 1)
                                      for l, n in enumerate(res) if n},
            mean_granted_ghz=round(sum(n * khz[l] for l, n in enumerate(res)) / total / 1e6, 3) if total else None)
    return out


GPU_V1 = ('magic abi status reason hz arena window_ticks next_window windows opp ceiling below below_target '
          'busy_ticks last_busy_pct submissions window_submissions votes acks errors last_error last_seq '
          'skipped_messages send_ticks_max send_ticks_total thermal_clamp hispeed restores pending deferred '
          'flight_ticks_seen thermal_eff_mc').split()
GPU_V2 = ('top hot_until race_long race_burst midflight_votes hot_ms idle_downs flights_seen ended_seen '
          'long_flights flight_max_seen started').split()
GPU_V3 = 'race_first kicks hold_ms die_mc spot_mc die_eff_mc clamp_die_ms clamp_spot_ms'.split()


def celsius(v):
    v = signed(v)
    return None if v == -(1 << 63) else round(v / 1000, 1)


def gpu(words):
    need = 39
    if len(words) < need:
        raise ValueError(f'GPU block has {len(words)} words, expected {need}')
    f = dict(zip(GPU_V1, words[:32]))
    nres = 12 if f['abi'] >= 4 else 7          # residency words: OPP 0..11 (ABI 4) or 0..6
    res = list(words[32:32 + nres])
    base = 32 + nres
    hz = f['hz'] or 19200000
    total = sum(res[1:]) or 1
    unit = 1e-3 if f['abi'] >= 2 else 0.05          # ABI 2: ms; ABI 1: 50 ms windows (each at least 50 ms)
    out = dict(abi=f['abi'], status=GPU_STATUS.get(f['status'], f['status']), off_reason=OFF_REASON.get(f['reason']),
               arena=hex(f['arena']), opp=f['opp'], mhz=GPU_MHZ[f['opp']] if f['opp'] < nres else None,
               ceiling_mhz=GPU_MHZ[f['ceiling']] if f['ceiling'] < nres else None, windows=f['windows'],
               submissions=f['submissions'], votes=f['votes'], acks=f['acks'], errors=f['errors'],
               last_error=GPU_ERRORS.get(f['last_error'], f['last_error']), last_seq=f['last_seq'],
               skipped_messages=f['skipped_messages'], deferred_while_in_flight=f['deferred'],
               send_ms_max=round(f['send_ticks_max'] / hz * 1e3, 3),
               send_ms_mean=round(f['send_ticks_total'] / max(f['acks'], 1) / hz * 1e3, 3),
               hispeed_jumps=f['hispeed'], restores=f['restores'],
               seconds_at_mhz={GPU_MHZ[o]: round(res[o] * unit, 1) for o in range(1, nres) if res[o]},
               mean_mhz=round(sum(res[o] * GPU_MHZ[o] for o in range(1, nres)) / total))
    if f['abi'] >= 2 and len(words) >= base + len(GPU_V2):
        r = dict(zip(GPU_V2, words[base:base + len(GPU_V2)]))
        out.update(race_to_idle=dict(
            raises_long_ib=r['race_long'], raises_burst=r['race_burst'], midflight_votes=r['midflight_votes'],
            hot_seconds=round(r['hot_ms'] / 1e3, 1), idle_downs=r['idle_downs'],
            long_ibs=r['long_flights'], longest_flight_ms=round(r['flight_max_seen'] / hz * 1e3, 1),
            flights=r['flights_seen'], flights_ended=r['ended_seen'],
            last_top_mhz=GPU_MHZ[r['top']] if r['top'] < nres else None))
    at = base + len(GPU_V2)
    if f['abi'] >= 3 and len(words) >= at + len(GPU_V3):
        r = dict(zip(GPU_V3, words[at:at + len(GPU_V3)]))
        out['race_to_idle'].update(raises_before_doorbell=r['race_first'], kicks=r['kicks'], hold_ms=r['hold_ms'],
                                   note='ABI 3: raises_long_ib counts every raise the tick made on activity; '
                                        'raises_burst stays 0 (the per-IB kick replaced it)')
        out['thermal'] = dict(last_die_c=celsius(r['die_mc']), last_hotspot_c=celsius(r['spot_mc']),
                              die_as_clamped_c=celsius(r['die_eff_mc']),
                              hotspot_as_clamped_c=celsius(f['thermal_eff_mc']),
                              clamped_by_die_s=round(r['clamp_die_ms'] / 1e3, 1),
                              clamped_by_hotspot_s=round(r['clamp_spot_ms'] / 1e3, 1),
                              limits='die 75->85 C, hotspot 88->93 C')
    at += len(GPU_V3)
    if f['abi'] >= 4 and len(words) >= at + 2 + 12:
        hfi_opps, bw_rows = words[at], words[at + 1]
        flights = words[at + 2:at + 14]
        per = {}
        for o in range(1, 12):
            n, us = flights[o] >> 32, flights[o] & 0xffffffff
            if n:
                per[GPU_MHZ[o]] = dict(flights=n, mean_ms=round(us / n / 1e3, 2))
        out['table'] = dict(hfi_opps=hfi_opps, legacy_record=hfi_opps == 0, bw_rows=bw_rows,
                            top_mhz=GPU_MHZ[min(hfi_opps or 6, 11)],
                            note='hfi_opps: the OPPs in the perf TABLE q1n1 sent (host record word 21); 0: an older '
                                 'q1n1, read as 6')
        out['flights_by_mhz'] = dict(per, note='flights that started and ended at one OPP with no vote between '
                                               '(FAILURE-MODES O10): the effective clock check')
    return out


def decode_block(raw):
    words = struct.unpack(f'<{len(raw) // 8}Q', raw[:len(raw) // 8 * 8])
    if not words or words[0] != MAGIC:
        return None
    header = words[1]
    cpu_words, gpu_words = header >> 16 & 0xffff, header >> 32 & 0xffff
    out = dict(cpu_dvfs=bool(header & 1), gpu_dvfs=bool(header & 2))
    if header & 1:
        out['cpu'] = cpu(words[2:2 + cpu_words])
    if header & 2:
        out['gpu'] = gpu(words[2 + cpu_words:2 + cpu_words + gpu_words])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('report', type=Path)
    ap.add_argument('--raw', action='store_true', help='the file starts at the magic')
    args = ap.parse_args()
    data = args.report.read_bytes()
    block = data if args.raw else data[OFFSET:OFFSET + 8 * 190]
    out = decode_block(block)
    if out is None:
        print('no DVFSREP1 record (a build without SNAP_CPU_DVFS/SNAP_GPU_DVFS, or a stop before the record)')
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
