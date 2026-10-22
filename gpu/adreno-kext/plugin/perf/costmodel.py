#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A first-order GPU time model for one AdrenoMetal pass (agents/gpu-perf). Parameters are guesses for the X2-90 (a8xx,
4 slices) until the A16 timing run (tools/a16-gpu-timing) calibrates them; every number in the report that comes from
here says "model". Components (seconds):
  cp      the CP parses every IB dword (CP_CYC_PER_DW cycles each)
  fill    each draw's bounding box: max(ROP rate, DRAM bytes / BW); bytes = bpp x (1 + blend) + 4 B x textures
  clear   2D-engine clears and scaled blits: pixels / 2D rate, or bytes / BW
  memcpy  CP_MEMCPY: fixed cycles + bytes / (MEMCPY_B_PER_CYC x f)
  sync    each WFI drains the pipeline (WFI_CYC + DRAW_LAT_CYC: no overlap between the draws around it); each cache
          event and CCHE invalidate costs EVENT_CYC
  refetch a UCHE invalidate (CACHE_INVALIDATE7) inside a render pass makes the next draw fetch its textures and blend
          destination again: REFETCH_FRACTION of that draw's bytes, approximated by the pass's mean draw
  compute a dispatch: groups x GROUP_CYC
total = cp + fill + clear + memcpy + sync + refetch + compute (no overlap credited: an upper bound for a serialised
stream; the WFI-free stream would overlap cp with fill).
"""
P = dict(CP_CYC_PER_DW=1.0, DRAW_LAT_CYC=700.0, WFI_CYC=150.0, EVENT_CYC=60.0, MEMCPY_B_PER_CYC=4.0,
         MEMCPY_FIXED_CYC=300.0, BW=50e9, PPC=64.0, PPC_2D=32.0, REFETCH_FRACTION=0.5, GROUP_CYC=200.0)


def pass_time(p, f, params=None):
    q = dict(P, **(params or {}))
    cp = p.dwords * q['CP_CYC_PER_DW'] / f
    blend = p.blend_px
    bytes_ = p.draw_px * p.bpp + blend * p.bpp + p.tex_px * 4
    fill = max(p.draw_px / (q['PPC'] * f), bytes_ / q['BW'])
    clear = max((p.clear_px + p.blit2d_px) / (q['PPC_2D'] * f), (p.clear_px + 2 * p.blit2d_px) * p.bpp / q['BW'])
    memcpy = p.memcpy * q['MEMCPY_FIXED_CYC'] / f + p.memcpy_bytes / (q['MEMCPY_B_PER_CYC'] * f)
    nev = sum(p.events.values()) + p.cche + p.wait_mem
    sync = p.wfi * (q['WFI_CYC'] + q['DRAW_LAT_CYC']) / f + nev * q['EVENT_CYC'] / f
    inv = p.events.get('CACHE_INVALIDATE7', 0)
    refetch = 0.0
    if p.kind == 'render' and p.draws and inv > 1:
        # the restore's invalidate is free (the pass starts cold anyway); later ones hit a draw's working set
        per_draw = bytes_ / p.draws
        refetch = min(inv - 1, p.draws) * per_draw * q['REFETCH_FRACTION'] / q['BW']
    compute = p.groups * q['GROUP_CYC'] / f
    d = dict(cp=cp, fill=fill, clear=clear, memcpy=memcpy, sync=sync, refetch=refetch, compute=compute)
    d['total'] = sum(d.values())
    return d
