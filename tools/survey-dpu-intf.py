#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only survey of the eDP interface's timing engine (DPU INTF_5) from q1n1, before any --present-beam boot.

agents/tear-free/FAILURE-MODES.md A2 (an unclocked MDSS read is an SError, a cold reboot) and B1-B3. Reads only, and in
this order, stopping at the first failed check:
  1. DISP_CC_MDSS_AHB_CBCR, DISP_CC_MDSS_MDP_CBCR: CLK_OFF (bit 31) clear; MDSS_CORE_GDSC: PWR_ON (bit 31) set;
  2. the MDSS HW version (0x0ae00000) and the MDP top's (0x0ae01000);
  3. INTF_5's registers (compat/dpu-intf.h, the same list the kext reads), decoded as AdrenoDisplayBeam.h decodes them;
  4. LINE_COUNT and FRAME_COUNT sampled for --seconds: the frame rate from FRAME_COUNT against host time, and the
     largest and smallest line seen (the counter's modulus);
  5. with --pipe only: the SSPP source addresses, layer mixer and CTL registers a page flip (option b) would need.
Nothing is written to the A16.

    python3 tools/survey-dpu-intf.py --plan                     # the read list, offline
    python3 tools/survey-dpu-intf.py --check SURVEY.json        # decode a saved survey, offline
    python3 tools/survey-dpu-intf.py --survey --device udp://enN --output NEW.json [--seconds 2] [--pipe]
"""
from pathlib import Path
import argparse
import json
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / 'compat/dpu-intf.h'


def constants():
    text = HEADER.read_text()
    out = {}
    for name, value in re.findall(r'#define (DPU_\w+)\s+(0x[0-9A-Fa-f]+|\d+)(?:ULL|u)?\b', text):
        out[name] = int(value, 0)
    for name, shift in re.findall(r'#define (DPU_\w+)\s+\(1u << (\d+)\)', text):
        out[name] = 1 << int(shift)
    out['DPU_INTF_PA'] = out['DPU_MDP_PA'] + out['DPU_INTF_FIRST'] + out['DPU_INTF_STRIDE'] * out['DPU_INTF_INDEX']
    return out


C = constants()
INTF_REGS = ('TIMING_ENGINE_EN', 'CONFIG', 'HSYNC_CTL', 'VSYNC_PERIOD_F0', 'DISPLAY_V_START_F0', 'DISPLAY_V_END_F0',
             'ACTIVE_V_START_F0', 'ACTIVE_V_END_F0', 'DISPLAY_HCTL', 'ACTIVE_HCTL', 'CONFIG2', 'FRAME_LINE_COUNT_EN',
             'FRAME_COUNT', 'LINE_COUNT', 'STATUS', 'AVR_CONTROL')
CLOCKS = (('DISP_CC_MDSS_AHB_CBCR', C['DPU_DISPCC_PA'] + C['DPU_DISPCC_MDSS_AHB_CBCR'], 'clock'),
          ('DISP_CC_MDSS_MDP_CBCR', C['DPU_DISPCC_PA'] + C['DPU_DISPCC_MDSS_MDP_CBCR'], 'clock'),
          ('MDSS_CORE_GDSCR', C['DPU_DISPCC_PA'] + C['DPU_DISPCC_MDSS_CORE_GDSCR'], 'gdsc'))
# --pipe (option b's survey): dpu_12_2_glymur.h block bases from the "mdp" region; register offsets from Linux
# dpu_hw_sspp.c (SRC_SIZE 0x00, SRC_XY 0x08, OUT_SIZE 0x0c, SRC0_ADDR 0x14, SRC_YSTRIDE0 0x24, SRC_FORMAT 0x30) and
# dpu_hw_ctl.c (CTL_LAYER(lm) 0x00 + 4 * lm, CTL_TOP 0x14, CTL_FLUSH 0x18, CTL_INTF_ACTIVE 0xf4).
SSPP = (('VIG0', 0x4000), ('VIG1', 0x6000), ('VIG2', 0x8000), ('VIG3', 0xa000), ('DMA0', 0x24000), ('DMA1', 0x26000),
        ('DMA2', 0x28000), ('DMA3', 0x2a000), ('DMA4', 0x2c000), ('DMA5', 0x2e000))
SSPP_REGS = (('SRC_SIZE', 0x00), ('SRC_XY', 0x08), ('OUT_SIZE', 0x0c), ('SRC0_ADDR', 0x14), ('SRC_YSTRIDE0', 0x24),
             ('SRC_FORMAT', 0x30))
CTL = tuple((f'CTL{i}', 0x15000 + 0x1000 * i) for i in range(8))
CTL_REGS = tuple((f'LAYER{lm}', 4 * lm) for lm in range(6)) + (('TOP', 0x14), ('FLUSH', 0x18), ('INTF_ACTIVE', 0xf4))


def plan(pipe=False):
    reads = [(name, pa, kind) for name, pa, kind in CLOCKS]
    reads += [('MDSS_HW_VERSION', C['DPU_MDSS_PA'], 'id'), ('MDP_HW_REV', C['DPU_MDP_PA'], 'id')]
    reads += [(f'INTF5_{r}', C['DPU_INTF_PA'] + C[f'DPU_INTF_{r}'], 'intf') for r in INTF_REGS]
    if pipe:
        reads += [(f'{b}_{r}', C['DPU_MDP_PA'] + base + off, 'pipe') for b, base in SSPP for r, off in SSPP_REGS]
        reads += [(f'{b}_{r}', C['DPU_MDP_PA'] + base + off, 'pipe') for b, base in CTL for r, off in CTL_REGS]
    for _, pa, kind in reads:
        assert kind != 'intf' or C['DPU_INTF_PA'] <= pa < C['DPU_INTF_PA'] + C['DPU_INTF_PAGE']
    return reads


def decode(regs, width=2880, height=1800):
    """AdrenoDisplayBeam.h adreno_beam_decode, register for register."""
    r = lambda n: regs[f'INTF5_{n}']
    if not (r('STATUS') & 1) and not (r('TIMING_ENGINE_EN') & 1):
        return dict(reason='engine off')
    if r('AVR_CONTROL'):
        return dict(reason='adaptive refresh on')
    ht = r('HSYNC_CTL') >> 16
    if ht < 16:
        return dict(reason='htotal')
    vt = r('VSYNC_PERIOD_F0') // ht
    if r('VSYNC_PERIOD_F0') % ht or vt <= height or vt > 8 * height:   # whole lines, no CVT range (the A16: 3840)
        return dict(reason='vtotal', vtotal=vt)
    vs, ve = r('DISPLAY_V_START_F0'), r('DISPLAY_V_END_F0')
    if (r('CONFIG') & C['DPU_INTF_CFG_ACTIVE_V_EN']) and r('ACTIVE_V_END_F0') > r('ACTIVE_V_START_F0'):
        vs, ve = r('ACTIVE_V_START_F0'), r('ACTIVE_V_END_F0')
    if ve < vs:
        return dict(reason='height')
    a0, lines = vs // ht, (ve - vs + ht) // ht
    if lines != height or a0 + lines - 1 >= vt:
        return dict(reason='height', lines=lines)
    hctl = r('ACTIVE_HCTL') if (r('CONFIG') & (1 << 29)) and r('ACTIVE_HCTL') else r('DISPLAY_HCTL')
    w = (hctl >> 16) - (hctl & 0xffff) + 1
    wide = r('CONFIG2') & C['DPU_INTF_CFG2_WIDEN']
    return dict(reason=None, htotal=ht, vtotal=vt, a0=a0, a1=a0 + lines - 1, width=w, widebus=bool(wide),
                width_ok=w == width or (wide and 2 * w == width), counters_enabled=r('FRAME_LINE_COUNT_EN'))


def check(record):
    regs = {k: int(v, 0) if isinstance(v, str) else v for k, v in record['registers'].items()}
    out = dict(decode=decode(regs))
    for name, _, kind in CLOCKS:
        v = regs.get(name)
        out[name] = None if v is None else ('on' if (kind == 'clock' and not v >> 31) or (kind == 'gdsc' and v >> 31)
                                            else 'OFF')
    s = record.get('samples') or []
    if len(s) >= 2:
        dt, df = s[-1]['t'] - s[0]['t'], (s[-1]['frame'] - s[0]['frame']) & 0xffffffff
        out['frame_rate_hz'] = round(df / dt, 2) if dt > 0 else None
        lines = [x['line'] for x in s]
        out['line_min'], out['line_max'] = min(lines), max(lines)
        # samples are proxy reads far apart: min and max miss up to one step at the wrap (a 1-based counter reads 1..vtotal)
        steps = sorted((b['line'] - a['line']) % (max(lines) + 1) for a, b in zip(s, s[1:]))
        out['line_step'] = steps[len(steps) // 2] if steps else None
        vt = out['decode'].get('vtotal')
        if vt:
            out['counter_range'] = '1..vtotal' if max(lines) >= vt else '0..vtotal-1'
        out['frame_counter_moves'] = df > 0
    return out


def survey(device, output, seconds, pipe):
    sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
    import q1n1proxy
    proxy = q1n1proxy.connect(device=device)
    registers, record = {}, dict(schema='snapintosh-dpu-intf-survey-v1', device=device, started=time.time())
    for name, pa, kind in CLOCKS:                    # 1: clocks before any MDSS read
        v = registers[name] = proxy.read32(pa)
        if (kind == 'clock' and v >> 31) or (kind == 'gdsc' and not v >> 31):
            record.update(registers=registers, stopped=f'{name} = {v:#x}: MDSS not clocked or not powered; no MDSS read')
            Path(output).write_text(json.dumps(record, indent=1) + '\n')
            raise SystemExit(record['stopped'])
    for name, pa, kind in plan(pipe)[len(CLOCKS):]:  # 2, 3 (and 5)
        registers[name] = proxy.read32(pa)
    samples, end = [], time.time() + seconds          # 4
    while time.time() < end:
        t = time.time()
        samples.append(dict(t=t, frame=proxy.read32(C['DPU_INTF_PA'] + C['DPU_INTF_FRAME_COUNT']),
                            line=proxy.read32(C['DPU_INTF_PA'] + C['DPU_INTF_LINE_COUNT'])))
    record.update(registers={k: hex(v) for k, v in registers.items()}, samples=samples, finished=time.time())
    record['check'] = check(record)
    Path(output).write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps(record['check'], indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--plan', action='store_true')
    ap.add_argument('--pipe', action='store_true')
    ap.add_argument('--check')
    ap.add_argument('--survey', action='store_true')
    ap.add_argument('--device')
    ap.add_argument('--output')
    ap.add_argument('--seconds', type=float, default=2.0)
    a = ap.parse_args()
    if a.plan:
        for name, pa, kind in plan(a.pipe):
            print(f'{pa:#012x}  {kind:5}  {name}')
    elif a.check:
        print(json.dumps(check(json.loads(Path(a.check).read_text())), indent=1))
    elif a.survey:
        if not a.device or not a.output or Path(a.output).exists():
            raise SystemExit('--survey needs --device and a new --output')
        survey(a.device, a.output, a.seconds, a.pipe)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()
