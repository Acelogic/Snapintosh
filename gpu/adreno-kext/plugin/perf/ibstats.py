#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""GPU work breakdown of AdrenoMetal command streams (agents/gpu-perf): per commit, per pass, per draw.

    ibstats.py CAPTURE [--json OUT] [--passes] [--frames-from N] [--model 310|915|both]

CAPTURE is a desktop-scenes adreno run (report.json + commit-NNNN/commands.bin) or a ca-generic CA_BENCH capture
(scenes/report.json). Counts are exact (they are read from the packets); times come from tools/costmodel.py and are a
model, not a measurement.

Pass boundaries: every pass starts with CP_SET_MODE (emit_restore) or CP_THREAD_CONTROL (blit and compute passes, which
select BR before their first flush); a new pass begins at the first such packet after the current pass did any work
(draw, blit, memcpy, dispatch). Kinds: render (RM6_DIRECT_RENDER), compute (RM6_COMPUTE), mip (RM6_BLIT2DSCALE), copy
(CP_MEMCPY only).

Per pass: draws, render area, summed draw bounding-box pixels (scissor x viewport x window, an upper bound of what each
draw shades) and the overdraw it implies, blended pixels, sampled textures, clears and their pixels, every event,
WFI, CCHE invalidate, WAIT_MEM_WRITES and CP_MEMCPY (count and bytes; in a render pass these are the unaligned-UBO
stagings), IB dwords, and 2D blits.
"""
import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C  # noqa: E402

R = C.regs()
E = R['E']
REG = R['REG']
OFF = {n: r['offset'] for n, r in REG.items() if 'offset' in r}
EVNAME = {}
for k, v in E.items():
    if k in ('CCU_CLEAN_COLOR', 'CCU_CLEAN_DEPTH', 'CCU_INVALIDATE_COLOR', 'CCU_INVALIDATE_DEPTH', 'CACHE_CLEAN',
             'CACHE_INVALIDATE7', 'CACHE_FLUSH7', 'LRZ_CACHE_FLUSH', 'DUMMY_EVENT', 'SUBPASS_FENCE', 'DEBUG_LABEL'):
        EVNAME[v] = k
OP = {k[3:] if k.startswith('CP_') else k: v for k, v in E.items()}
OPNAME = {}
for k, v in E.items():
    if k.startswith('CP_') and k not in ('CP_TYPE4_PKT', 'CP_TYPE7_PKT'):
        OPNAME.setdefault(v, k)
# bytes per pixel of the RB colour formats the plug-in renders (AdrenoTargetFormatOf)
BPP = {E['FMT6_8_8_8_8_UNORM']: 4, E['FMT6_10_10_10_2_UNORM']: 4, E['FMT6_10_10_10_2_UNORM_DEST']: 4,
       E['FMT6_16_16_16_16_FLOAT']: 8}
for name, b in (('FMT6_8_UNORM', 1), ('FMT6_8_8_UNORM', 2), ('FMT6_16_FLOAT', 2), ('FMT6_16_16_FLOAT', 4),
                ('FMT6_32_FLOAT', 4), ('FMT6_32_32_FLOAT', 8), ('FMT6_32_32_32_32_FLOAT', 16), ('FMT6_16_16_UINT', 4),
                ('FMT6_16_UNORM', 2), ('FMT6_16_16_UNORM', 4), ('FMT6_16_16_16_16_UNORM', 8), ('FMT6_8_8_8_8_UINT', 4),
                ('FMT6_16_UINT', 2), ('FMT6_32_UINT', 4), ('FMT6_5_6_5_UNORM', 2), ('FMT6_32_32_UINT', 8)):
    if name in E:
        BPP[E[name]] = b


def field(name, word, f):
    return C.field(name, word, f)


def reg_at(name, i=0):
    r = REG[name]
    return r['offset'] + i * (r.get('array_stride', 0) or 1)


class Pass:
    def __init__(self, index):
        self.index = index
        self.kind = None
        self.markers = []
        self.draws = 0
        self.instances = 0
        self.vertices = 0
        self.area = 0                 # render area (window scissor)
        self.draw_px = 0              # summed draw bounding boxes
        self.blend_px = 0
        self.tex_px = 0               # summed bbox x sampled textures
        self.textures = 0             # summed per-draw texture count
        self.fbfetch_draws = 0
        self.clears = 0
        self.clear_px = 0
        self.blit2d = 0
        self.blit2d_px = 0
        self.memcpy = 0
        self.memcpy_bytes = 0
        self.memcpy_in_draws = 0      # CP_MEMCPY between a pass's first and last draw-section (UBO staging)
        self.wfi = 0
        self.cche = 0
        self.wait_mem = 0
        self.events = collections.Counter()
        self.dwords = 0
        self.dispatches = 0
        self.groups = 0
        self.bpp = 4
        self.work = False
        self.ubo_loads = 0
        self.max_draw_px = 0

    def as_dict(self):
        d = {k: v for k, v in self.__dict__.items() if k != 'events'}
        d['events'] = dict(self.events)
        return d


def box(state, tl, br):
    x0 = field(tl, state.get(OFF[tl], 0), 'X'); y0 = field(tl, state.get(OFF[tl], 0), 'Y')
    x1 = field(br, state.get(OFF[br], 0), 'X'); y1 = field(br, state.get(OFF[br], 0), 'Y')
    return x0, y0, x1, y1


def isect(a, b):
    return max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])


def px(b):
    return max(0, b[2] - b[0] + 1) * max(0, b[3] - b[1] + 1)


def walk_package(words, passes, state, commit_tag):
    """Append this package's passes (a package continues none: every pass opens with restore or thread BR)."""
    cur = None
    prev_op = None
    for ev in C.walk(words):
        if ev[0] == 'reg':
            state[ev[2]] = ev[3]
            continue
        _, at, op, body = ev
        if op in (E['CP_SET_MODE'], E['CP_THREAD_CONTROL']) and (cur is None or cur.work) and \
                not (op == E['CP_THREAD_CONTROL'] and prev_op == E['CP_SET_MODE']):
            cur = Pass(len(passes))
            cur.commit = commit_tag
            passes.append(cur)
        if cur is None:
            cur = Pass(len(passes)); cur.commit = commit_tag; passes.append(cur)
        cur.dwords += 1 + len(body)
        prev_op = op
        if op == E['CP_SET_MARKER']:
            mode = body[0] & 0xf
            cur.markers.append(mode)
            if mode == E['RM6_DIRECT_RENDER'] and cur.kind is None:
                cur.kind = 'render'
            elif mode == E['RM6_COMPUTE']:
                cur.kind = 'compute'
            elif mode == E['RM6_BLIT2DSCALE'] and cur.kind is None:
                cur.kind = 'mip'
        elif op == E['CP_WAIT_FOR_IDLE']:
            cur.wfi += 1
        elif op == E['CP_CCHE_INVALIDATE']:
            cur.cche += 1
        elif op == E['CP_WAIT_MEM_WRITES']:
            cur.wait_mem += 1
        elif op == E['CP_EVENT_WRITE7']:
            e = body[0] & 0xff
            cur.events[EVNAME.get(e, f'ev{e:#x}')] += 1
        elif op == E['CP_MEMCPY']:
            cur.memcpy += 1
            cur.memcpy_bytes += 4 * body[0]
            if cur.draws:
                cur.memcpy_in_draws += 1
            cur.work = True
        elif op == E['CP_EXEC_CS']:
            cur.dispatches += 1
            cur.groups += body[1] * body[2] * body[3]
            cur.work = True
        elif op == E['CP_BLIT']:
            cur.work = True
            tl, br = OFF['GRAS_A2D_DEST_TL'], OFF['GRAS_A2D_DEST_BR']
            b = (field('GRAS_A2D_DEST_TL', state.get(tl, 0), 'X'), field('GRAS_A2D_DEST_TL', state.get(tl, 0), 'Y'),
                 field('GRAS_A2D_DEST_BR', state.get(br, 0), 'X'), field('GRAS_A2D_DEST_BR', state.get(br, 0), 'Y'))
            solid = field('RB_A2D_BLT_CNTL', state.get(OFF['RB_A2D_BLT_CNTL'], 0), 'SOLID_COLOR')
            if solid:
                cur.clears += 1; cur.clear_px += px(b)
            else:
                cur.blit2d += 1; cur.blit2d_px += px(b)
        elif op in (E['CP_LOAD_STATE6_FRAG'], E['CP_LOAD_STATE6_GEOM']):
            w0 = body[0]
            st = (w0 >> 14) & 0x3; sb = (w0 >> 18) & 0xf; n = (w0 >> 22) & 0x3ff
            if sb == E['SB6_FS_TEX'] and st == E['ST6_CONSTANTS']:
                cur._tex = n
            if st == E['ST6_UBO']:
                cur.ubo_loads += 1
        elif op == E['CP_DRAW_INDX_OFFSET']:
            cur.work = True
            cur.draws += 1
            cur.instances += body[1]
            cur.vertices += body[2] * max(1, body[1])
            win = (0, 0, field('GRAS_SC_WINDOW_SCISSOR_BR', state.get(OFF['GRAS_SC_WINDOW_SCISSOR_BR'], 0), 'X'),
                   field('GRAS_SC_WINDOW_SCISSOR_BR', state.get(OFF['GRAS_SC_WINDOW_SCISSOR_BR'], 0), 'Y'))
            cur.area = px(win)
            b = isect(win, isect(box(state, 'GRAS_SC_SCREEN_SCISSOR_TL', 'GRAS_SC_SCREEN_SCISSOR_BR'),
                                 box(state, 'GRAS_SC_VIEWPORT_SCISSOR_TL', 'GRAS_SC_VIEWPORT_SCISSOR_BR')))
            p = px(b)
            cur.draw_px += p
            cur.max_draw_px = max(cur.max_draw_px, p)
            ctl = state.get(reg_at('RB_MRT_CONTROL', 0), 0)
            if field('RB_MRT_CONTROL', ctl, 'COLOR_BLEND_EN'):
                cur.blend_px += p
            ntex = getattr(cur, '_tex', 0)
            cur.textures += ntex
            cur.tex_px += p * ntex
            fmt = field('RB_MRT_BUF_INFO', state.get(reg_at('RB_MRT_BUF_INFO', 0), 0), 'COLOR_FORMAT')
            cur.bpp = BPP.get(fmt, 4)
            if field('GRAS_SC_CNTL', state.get(OFF['GRAS_SC_CNTL'], 0), 'SINGLE_PRIM_MODE'):
                cur.fbfetch_draws += 1
            cur._tex = 0
    for p in passes:
        if p.kind is None:
            p.kind = 'copy' if p.memcpy else ('compute' if p.dispatches else 'other')
        if p.kind == 'render' and not p.area:
            win = field('GRAS_SC_WINDOW_SCISSOR_BR', state.get(OFF['GRAS_SC_WINDOW_SCISSOR_BR'], 0), 'X')
            p.area = 0 if not win else p.area


def load(capture):
    cap = Path(capture)
    rep = cap / 'report.json'
    if not rep.is_file() and (cap / 'scenes/report.json').is_file():
        cap = cap / 'scenes'
    report = json.loads((cap / 'report.json').read_text())
    return cap, report


def commit_passes(cap, commit):
    f = cap / commit['dir'] / 'commands.bin'
    if not f.is_file():
        return [], 0, 0
    passes, fills, fill_bytes = [], 0, 0
    for kind, cmd in C.kernel_commands(f.read_bytes()):
        if kind == C.KCMD_IB:
            pkg = C.parse_package(cmd)
            words = C.ib_words(pkg)
            state = {}
            walk_package(words, passes, state, commit['dir'])
        elif kind == C.KCMD_FILL32:
            fills += 1
            fill_bytes += C.fill32(cmd)['bytes']
    return passes, fills, fill_bytes


def scene_of(c):
    return c['scene'].split(':')[-1] if isinstance(c.get('scene'), str) else str(c.get('scene'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('capture')
    ap.add_argument('--json')
    ap.add_argument('--passes', action='store_true', help='print every pass')
    ap.add_argument('--skip-first-frame', action='store_true', help='drop frame 0 of every scene (uploads, compiles)')
    ap.add_argument('--include-warmup', action='store_true')
    a = ap.parse_args()
    cap, report = load(a.capture)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import costmodel as M
    out = dict(capture=str(cap), scenes={})
    seq = collections.Counter()
    for c in report['commits']:
        if c.get('frame') is None:             # ca-generic captures: commits in order, one or more per frame
            c['frame'] = seq[str(c.get('scene'))]
            seq[str(c.get('scene'))] += 1
        if not c.get('has_commands'):
            continue
        if not a.include_warmup and str(c.get('scene', '')).startswith('warmup:'):
            continue
        if a.skip_first_frame and c.get('frame', 0) == 0:
            continue
        s = scene_of(c)
        passes, fills, fill_bytes = commit_passes(cap, c)
        sc = out['scenes'].setdefault(s, dict(commits=0, frames=set(), passes=[], fills=0, fill_bytes=0))
        sc['commits'] += 1
        sc['frames'].add(c.get('frame', 0))
        sc['fills'] += fills
        sc['fill_bytes'] += fill_bytes
        for p in passes:
            p.frame = c.get('frame', 0)
            sc['passes'].append(p)
    tot = collections.Counter()
    print(f'{"scene":12s} {"fr":>2s} {"pass":>4s} {"rend":>4s} {"cpy":>3s} {"mip":>3s} {"cs":>3s} {"draws":>5s} '
          f'{"ovdr":>5s} {"Mpx":>6s} {"stage":>5s} {"stKB":>7s} {"cpyKB":>7s} {"wfi":>5s} {"ccuC":>5s} {"ucheI":>5s} '
          f'{"kdw":>5s} {"ms310":>6s} {"ms915":>6s}')
    for s, sc in out['scenes'].items():
        P = sc['passes']
        nfr = max(1, len(sc['frames']))
        def S(attr, kind=None):
            return sum(getattr(p, attr) for p in P if kind is None or p.kind == kind)
        rend = [p for p in P if p.kind == 'render']
        area = sum(p.area for p in rend)
        stage = sum(p.memcpy for p in rend)
        stage_b = sum(p.memcpy_bytes for p in rend)
        copy_b = sum(p.memcpy_bytes for p in P if p.kind != 'render')
        ccu = sum(p.events.get('CCU_CLEAN_COLOR', 0) for p in P)
        uinv = sum(p.events.get('CACHE_INVALIDATE7', 0) for p in P)
        t310 = sum(M.pass_time(p, 310e6)['total'] for p in P)
        t915 = sum(M.pass_time(p, 915e6)['total'] for p in P)
        row = dict(frames=nfr, passes=len(P), render=len(rend), copy=sum(p.kind == 'copy' for p in P),
                   mip=sum(p.kind == 'mip' for p in P), compute=sum(p.kind == 'compute' for p in P), draws=S('draws'),
                   overdraw=(S('draw_px', 'render') / area) if area else 0, mpx=S('draw_px') / 1e6, stage=stage,
                   stage_kb=stage_b / 1024, copy_kb=copy_b / 1024, wfi=S('wfi'), ccu_clean=ccu, uche_inv=uinv,
                   kdwords=S('dwords') / 1000, ms310=t310 * 1e3, ms915=t915 * 1e3)
        sc['summary'] = row
        for k, v in row.items():
            if isinstance(v, (int, float)):
                tot[k] += v
        print(f'{s:12s} {nfr:2d} {row["passes"]:4d} {row["render"]:4d} {row["copy"]:3d} {row["mip"]:3d} '
              f'{row["compute"]:3d} {row["draws"]:5d} {row["overdraw"]:5.2f} {row["mpx"]:6.1f} {stage:5d} '
              f'{row["stage_kb"]:7.0f} {row["copy_kb"]:7.0f} {row["wfi"]:5d} {ccu:5d} {uinv:5d} {row["kdwords"]:5.0f} '
              f'{row["ms310"]:6.1f} {row["ms915"]:6.1f}')
        if a.passes:
            for p in P:
                t = M.pass_time(p, 310e6)
                print(f'   f{p.frame} #{p.index:<3d} {p.kind:7s} area={p.area/1e6:5.2f}M draws={p.draws:3d} '
                      f'dpx={p.draw_px/1e6:6.2f}M blend={p.blend_px/1e6:6.2f}M tex={p.textures:3d} clr={p.clears}/{p.clear_px/1e6:.2f}M '
                      f'2d={p.blit2d}/{p.blit2d_px/1e6:.2f}M mc={p.memcpy}/{p.memcpy_bytes/1024:.0f}K wfi={p.wfi} '
                      f'ev={sum(p.events.values())} bpp={p.bpp} fbf={p.fbfetch_draws} '
                      f't310={t["total"]*1e3:.2f}ms [' + ' '.join(f'{k}={v*1e3:.2f}' for k, v in t.items() if k != 'total' and v > 2e-5) + ']')
    print(f'{"TOTAL":12s} {int(tot["frames"]):2d} {int(tot["passes"]):4d} {int(tot["render"]):4d} {int(tot["copy"]):3d} '
          f'{int(tot["mip"]):3d} {int(tot["compute"]):3d} {int(tot["draws"]):5d} {"":5s} {tot["mpx"]:6.1f} '
          f'{int(tot["stage"]):5d} {tot["stage_kb"]:7.0f} {tot["copy_kb"]:7.0f} {int(tot["wfi"]):5d} '
          f'{int(tot["ccu_clean"]):5d} {int(tot["uche_inv"]):5d} {tot["kdwords"]:5.0f} {tot["ms310"]:6.1f} {tot["ms915"]:6.1f}')
    if a.json:
        js = dict(capture=out['capture'], scenes={})
        for s, sc in out['scenes'].items():
            js['scenes'][s] = dict(summary=sc['summary'], commits=sc['commits'], fills=sc['fills'],
                                   fill_bytes=sc['fill_bytes'], passes=[dict(p.as_dict(), model310=M.pass_time(p, 310e6),
                                                                              model915=M.pass_time(p, 915e6))
                                                                         for p in sc['passes']])
        Path(a.json).write_text(json.dumps(js, indent=1, default=lambda o: sorted(o) if isinstance(o, set) else str(o)))


if __name__ == '__main__':
    main()
