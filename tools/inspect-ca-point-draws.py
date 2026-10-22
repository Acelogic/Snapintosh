#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the draws of captured CoreAnimation command packages and check the point-size path.

For every CP_DRAW_INDX_OFFSET in a scene capture (tools/capture-ca-candidate-scenes.py output) this replays the
package's register writes (CP_CONTEXT_REG_BUNCH, CP_NON_CONTEXT_REG_BUNCH, type-4) and reports the state the
point-size and point-coordinate path programs, then checks it against the program exports of the pipeline that
drew:
  - a vertex function exporting VARYING_SLOT_PSIZ: PC_VS_CNTL.PSIZE, VPC_VS_CNTL.PSIZELOC = POSITIONLOC + 4,
    STRIDE_IN_VPC = PSIZELOC + 1, an SP_VS_OUTPUT_REG entry (regid, compmask 0x1) at that location, and
    GRAS_SU_POINT_MINMAX = [0, 511] (fd6_program.cc emit_vpc; Metal's measured clamp);
  - a fragment function reading VARYING_SLOT_PNTC: VPC_VARYING_REPLACE_MODE S/T at its locations
    (tu6_vpc_varying_mode), INTERP_ZERO/ONE for .z/.w;
  - everything else: PSIZE 0, PSIZELOC 0xff, replace modes 0, point size 1..1 (unchanged from before);
  - one-slice 3D textures: T# TYPE A6XX_TEX_3D, DEPTH 1, MIN_ARRAY_SLIZE_OFFSET = ARRAY_SLICE_OFFSET.
Host files only: no GPU execution, no A16. Doc: docs/SHADER-COMPILE-PATH-20260928.md section 7.

  python3 tools/inspect-ca-point-draws.py --capture DIR/SCENE-adreno.json [...] --output REPORT.json
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / 'gpu/adreno-kext/include/AdrenoA8xxRegs.h'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
SLOT_POS, SLOT_PSIZ, SLOT_PNTC = 0, 12, 25
TEX_2D, TEX_3D = 1, 3


def registers():
    text = HEADER.read_text()
    regs = {m.group(1): int(m.group(2), 16) for m in re.finditer(r'^#define A8XX_REG_(\w+) (0x[0-9a-f]+)u$', text, re.M)}
    enums = {m.group(1): int(m.group(2), 16) for m in re.finditer(r'^#define A8XX_E_(\w+) (0x[0-9a-f]+)u$', text, re.M)}
    return regs, enums


def package(capture):
    commit = capture['commits'][0]
    command = Path(commit['path']).read_bytes()
    assert sha(commit['path']) == commit['sha256']
    kind, size, version, flags, nwords, ndata, nrel, reserved, r0, r1 = struct.unpack_from('<IIIIIIIIQQ', command)
    assert kind == 0x1002 and version == 1
    words = struct.unpack_from('<%dI' % nwords, command, 48)
    package_bytes = ((4 * nwords + 63) & ~63) + ndata
    start = 48 + package_bytes
    relocs = [struct.unpack_from('<IIBBBBIQQ', command, start + 32 * i) for i in range(nrel)]
    return command, words, {r[0]: r for r in relocs}


def draws(words, regs, enums):
    names = {'PC_VS_CNTL', 'VPC_VS_CNTL', 'GRAS_SU_POINT_MINMAX', 'GRAS_SU_POINT_SIZE', 'SP_VS_OUTPUT_CNTL',
             'SP_PS_TEXMEMOBJ_BASE', 'SP_PS_TSIZE', 'SP_VS_INSTR_SIZE', 'SP_PS_INSTR_SIZE', 'VPC_REPLACE_MODE_CNTL',
             'VPC_PS_CNTL', 'SP_VS_BASE', 'SP_PS_BASE'}
    arrays = {'VPC_VARYING_REPLACE_MODE_MODE': 8, 'VPC_VARYING_INTERP_MODE_MODE': 8, 'SP_VS_OUTPUT_REG': 16,
              'SP_VS_VPC_DEST_REG': 8}
    watch = {regs[n]: (n, None) for n in names}
    for n, count in arrays.items():
        for i in range(count):
            watch[regs[n] + i] = (n, i)
    state, where, out, pos = {}, {}, [], 0
    def write(reg, value, at):
        if reg in watch:
            name, i = watch[reg]
            state[(name, i)] = value
            where[(name, i)] = at
    while pos < len(words):
        h = words[pos]
        if h >> 28 == 4:
            n, reg = h & 0x7f, (h >> 8) & 0x7ffff
            for k in range(n):
                write(reg + k, words[pos + 1 + k], pos + 1 + k)
        elif h >> 28 == 7:
            n, op = h & 0x3fff, (h >> 16) & 0x7f
            body = words[pos + 1:pos + 1 + n]
            if op == enums['CP_CONTEXT_REG_BUNCH']:
                for k in range(0, n, 2):
                    write(body[k], body[k + 1], pos + 2 + k)
            elif op == enums['CP_NON_CONTEXT_REG_BUNCH']:
                for k in range(2, n, 2):
                    write(body[k], body[k + 1], pos + 2 + k)
            elif op == enums['CP_DRAW_INDX_OFFSET']:
                out.append(dict(dword=pos, prim_type=body[0] & 0x3f, state=dict(state), where=dict(where)))
        else:
            raise AssertionError('packet type %d at dword %d' % (h >> 28, pos))
        pos += 1 + (h & (0x7f if h >> 28 == 4 else 0x3fff))
    return out


def field(value, shift, width):
    return (value >> shift) & ((1 << width) - 1)


def check_draw(draw, program, command, relocs, enums, resources):
    vs, fs = program
    s = draw['state']
    get = lambda name, i=None: s[(name, i)]
    outputs = {o['slot']: o['regid'] for o in vs['outputs']}
    inputs = [i for i in fs['inputs'] if i['bary'] and i['compmask'] and i['inloc'] < fs['total_in']]
    vpc = get('VPC_VS_CNTL')
    stride, posloc, psizeloc = field(vpc, 0, 8), field(vpc, 8, 8), field(vpc, 16, 8)
    pc = get('PC_VS_CNTL')
    minmax = get('GRAS_SU_POINT_MINMAX')
    replace = [get('VPC_VARYING_REPLACE_MODE_MODE', i) for i in range(8)]
    interp = [get('VPC_VARYING_INTERP_MODE_MODE', i) for i in range(8)]
    count = get('SP_VS_OUTPUT_CNTL') & 0x3f
    out_regs = []
    for i in range(count):
        word = get('SP_VS_OUTPUT_REG', i // 2) >> (16 * (i % 2))
        loc = (get('SP_VS_VPC_DEST_REG', i // 4) >> (8 * (i % 4))) & 0xff
        out_regs.append(dict(regid=word & 0xff, compmask=(word >> 8) & 0xf, loc=loc))
    row = dict(dword=draw['dword'], prim_type=draw['prim_type'], stride_in_vpc=stride, position_loc=posloc,
               psize_loc=psizeloc, pc_psize=field(pc, 8, 1), pc_stride=field(pc, 0, 8),
               point_min=field(minmax, 0, 16) / 16, point_max=field(minmax, 16, 16) / 16,
               point_size=get('GRAS_SU_POINT_SIZE') / 16, replace_mode=['%#x' % v for v in replace],
               interp_mode=['%#x' % v for v in interp], vs_exports=out_regs,
               vs_entry=vs['sidecar']['key_inputs']['entry'], fs_entry=fs['sidecar']['key_inputs']['entry'])
    assert field(get('VPC_REPLACE_MODE_CNTL'), 0, 1) == 0
    if SLOT_PSIZ in outputs:
        assert row['pc_psize'] == 1 and psizeloc == posloc + 4 and stride == psizeloc + 1 == row['pc_stride'], row
        assert dict(regid=outputs[SLOT_PSIZ], compmask=1, loc=psizeloc) in out_regs, row
        assert (row['point_min'], row['point_max'], row['point_size']) == (0.0, 511.0, 1.0), row
    else:
        assert row['pc_psize'] == 0 and psizeloc == 0xff, row
        assert (row['point_min'], row['point_max'], row['point_size']) == (1.0, 1.0, 1.0), row
    assert dict(regid=outputs[SLOT_POS], compmask=0xf, loc=posloc) in out_regs, row
    expect_replace, expect_interp = [0] * 8, [0] * 8
    for i in inputs:
        loc = i['inloc']
        for c in range(4):
            if not i['compmask'] & (1 << c):
                continue
            if i['slot'] == SLOT_PNTC:
                expect_replace[loc // 16] |= [1, 2, 0, 0][c] << (2 * (loc % 16))
                expect_interp[loc // 16] |= [0, 0, 2, 3][c] << (2 * (loc % 16))
            elif i['flat']:
                expect_interp[loc // 16] |= 1 << (2 * (loc % 16))
            loc += 1 if (i['slot'] == SLOT_PNTC or i['flat']) else 0
    assert replace == expect_replace and interp == expect_interp, (row, expect_replace, expect_interp)
    # Fragment T#s: resource bindings and the 3D descriptors.
    textures = []
    count = get('SP_PS_TSIZE') & 0xff
    if count:
        base = relocs[4 * draw['where'][('SP_PS_TEXMEMOBJ_BASE', None)]]
        assert base[2] == 2   # ADRENO_IB_RELOC_PACKAGE: the T# array lives in the package data area
        for slot in range(count):
            at = base[7] + 64 * slot
            d = struct.unpack_from('<16I', command, 48 + at)
            r = relocs.get(at)
            ttype, depth = field(d[1], 17, 3), field(d[1], 20, 12)
            entry = dict(slot=slot, type=ttype, depth=depth, width=field(d[2], 0, 15) + 0,
                         resource_id=r[6] if r else None, array_slice=field(d[7], 0, 23) << 12,
                         min_slice=field(d[7], 24, 4) << 12)
            if r:
                known = resources.get(r[6])
                if known and known.get('type') == 7:        # MTLTextureType3D
                    assert ttype == TEX_3D and depth == 1 and entry['min_slice'] == entry['array_slice'] > 0, entry
                elif known:
                    assert ttype == TEX_2D and entry['min_slice'] == 0, entry
            textures.append(entry)
    row['textures'] = textures
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path, action='append', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    assert not args.output.exists()
    regs, enums = registers()
    report = dict(status='RUNNING', source_sha256=sha(__file__), header_sha256=sha(HEADER), scenes=[],
                  gpu_execution=False, a16_access=False)
    for path in args.capture:
        capture = json.loads(path.read_text())
        assert capture['status'] == 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED'
        command, words, relocs = package(capture)
        programs = []
        for p in capture['programs']:
            vs, fs = [json.loads(Path(p[stage]['path']).read_text()) for stage in ('vertex', 'fragment')]
            programs.append((vs, fs))
        resources = {row['resource_id']: row for row in capture.get('layout_publications', [])}
        files = {row['id']: row for row in capture['commits'][0]['published_resources']}
        def code_at(draw, name):
            # The program each draw uses: the code bytes its SP_xS_BASE relocation points at (a code buffer).
            r = relocs[4 * draw['where'][(name, None)]]
            assert r[2] == 1, (name, r)
            data = Path(files[r[6]]['path']).read_bytes()
            assert sha(files[r[6]]['path']) == files[r[6]]['sha256']
            return data[r[7]:r[7] + r[8]]
        rows = []
        for draw in draws(words, regs, enums):
            vs_code, fs_code = code_at(draw, 'SP_VS_BASE'), code_at(draw, 'SP_PS_BASE')
            match = [p for p in programs if vs_code.startswith(bytes.fromhex(p[0]['code_hex'])) and
                     fs_code.startswith(bytes.fromhex(p[1]['code_hex']))]
            entries = {(p[0]['sidecar']['key_inputs']['entry'], p[1]['sidecar']['key_inputs']['entry'],
                        json.dumps(p[0]['outputs']), json.dumps(p[1]['inputs'])) for p in match}
            assert len(entries) == 1, (draw['dword'], len(match))
            rows.append(check_draw(draw, match[0], command, relocs, enums, resources))
        generic = [r for r in rows if r['pc_psize']]
        report['scenes'].append(dict(capture=str(path), capture_sha256=sha(path), commit_sha256=capture['commits'][0]['sha256'],
            draws=len(rows), point_size_draws=len(generic),
            prim_types=sorted({r['prim_type'] for r in rows}),
            pipelines=sorted({r['vs_entry'] + '/' + r['fs_entry'] for r in rows}),
            three_d_textures=sum(1 for r in rows for t in r['textures'] if t['type'] == TEX_3D), rows=rows))
    report['status'] = 'CA_POINT_SIZE_DRAWS_DECODED_AND_CHECKED'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(status=report['status'], output=str(args.output), sha256=sha(args.output),
        scenes=[dict(capture=Path(s['capture']).name, draws=s['draws'], point_size_draws=s['point_size_draws'],
                     prim_types=s['prim_types'], three_d_textures=s['three_d_textures']) for s in report['scenes']])))


if __name__ == '__main__':
    main()
