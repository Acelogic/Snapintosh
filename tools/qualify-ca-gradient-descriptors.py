#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind a real CA gradient capture to kernel replay and independent descriptors.

Failure inventory: docs/ADRENO-BUFFER-TEXTURES-20260928.md. Also reject stale
shader/resource captures, lost buffer offsets, missing sampler slots, nonzero
unused slots, mismatched native identities and incomplete kernel replay.
No hardware access. A passed artifact prepares physical replay, not GUI proof.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--capture', type=Path, required=True)
ap.add_argument('--kernel-replay', type=Path, required=True)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
capture, replay, output = [p.resolve() for p in (args.capture, args.kernel_replay, args.output)]
assert not output.exists()
c = json.loads(capture.read_text())
q = json.loads(replay.read_text())
assert c['status'] == 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED' and c['scene'] == 'gradient'
assert q['status'] == 'NATIVE_CA_COPY_KERNEL_REPLAY_PASSED' and q['capture_sha256'] == sha(capture)
assert not q['a16_access'] and not q['gpu_execution']
assert len(q['cases']) == 11 and len(q['copies']) == 4
assert not c['a16_access'] and not c['adreno_submitted_to_gpu'] and len(c['commits']) == 1
for name, digest in q['production_inputs'].items():
    assert sha(ROOT / name) == digest, name
for data in q['resource_snapshots'].values():
    assert sha(data['path']) == data['sha256'] and Path(data['path']).stat().st_size == data['bytes']
programs = []
for pair in c['programs']:
    for entry in pair.values():
        assert sha(entry['path']) == entry['sha256']
    programs.append(json.loads(Path(pair['fragment']['path']).read_text()))
textured = [p for p in programs if p['num_samp']]
assert len(textured) == 1 and textured[0]['num_samp'] == 10
shader = textured[0]
bindings = shader['sidecar']['reflection']['bindings']
assert [(b['metal_index'], b['slot']) for b in bindings if b['kind'] == 'texture'] == [(3, 3), (9, 9)]
assert [(b['metal_index'], b['slot']) for b in bindings if b['kind'] == 'sampler'] == [(0, 0)]
constant = shader['sidecar']['constant_samplers']
assert int(constant['bitmask'], 16) == 2 and len(constant['samplers']) == 1
assert constant['samplers'][0]['slot'] == 1
rows = [row for row in c['fragment_bindings'] if row['textures']]
assert len(rows) == 1 and len(rows[0]['textures']) == 2 and len(rows[0]['samplers']) == 1
textures = {t['index']: t for t in rows[0]['textures']}
assert set(textures) == {3, 9}
assert [(textures[i]['format'], textures[i]['width'], textures[i]['height'], textures[i]['pitch'])
        for i in (3, 9)] == [(115, 256, 1, 2048), (80, 32, 32, 128)]
sampler = rows[0]['samplers'][0]
assert all(sampler[k] == v for k, v in dict(index=0, min=1, mag=1, mip=0, s=0, t=0, r=0,
    aniso=1, normalized=True, lod_min=0, compare=0, border=0, lod_average=False).items())
assert sampler['lod_max'] > 0.25
sys.path.insert(0, str(ROOT.parent / 'q1n1/tools'))
import a16gpu_p6p7 as M
commit = c['commits'][0]
assert sha(commit['path']) == commit['sha256']
command = Path(commit['path']).read_bytes()
kind, size, version, flags, nwords, ndata, nrel, reserved, r0, r1 = struct.unpack_from('<8I2Q', command)
assert (kind, version, flags, reserved, r0, r1) == (0x1002, 1, 0, 0, 0, 0)
reloc_at = 48 + ((nwords * 4 + 63) & ~63) + ndata
assert size == reloc_at + 32 * nrel and command[size:] == struct.pack('<II', 0x1000, 8)
words = struct.unpack_from('<%dI' % nwords, command, 48)
relocs = [struct.unpack_from('<IIBBBBIQQ', command, reloc_at + 32 * i) for i in range(nrel)]
by_lo = {r[0]: r for r in relocs}
assert len(by_lo) == len(relocs)
loads, pos = {}, 0
while pos < len(words):
    header = words[pos]
    packet = header >> 28
    assert packet in (4, 7)
    count = header & (0x7f if packet == 4 else 0x3fff)
    assert pos + count + 1 <= len(words)
    if packet == 7 and (header >> 16) & 0x7f == 0x34 and count == 3:
        for name in ('ST6_SHADER', 'ST6_CONSTANTS'):
            _, expected = M.load_state6(False, name, 'SS6_INDIRECT', 'SB6_FS_TEX', 10)
            if words[pos + 1] == expected[0]:
                assert name not in loads
                loads[name] = by_lo[4 * (pos + 2)]
    pos += count + 1
assert set(loads) == {'ST6_SHADER', 'ST6_CONSTANTS'}
tr, sr = loads['ST6_CONSTANTS'], loads['ST6_SHADER']
assert tr[2:4] == sr[2:4] == (2, 1) and (tr[8], sr[8]) == (640, 160)
published = {row['id']: row for row in commit['published_resources']}
assert set(map(int, q['resource_snapshots'])) == set(published)
descriptors = []
for index in range(10):
    at = tr[7] + index * 64
    td = list(struct.unpack_from('<16I', command, 48 + at))
    if index not in textures:
        assert td == [0] * 16
        continue
    texture = textures[index]
    assert texture['layout_known'] and texture['usage'] & 1
    address = by_lo[at]
    assert address[2:5] == (1, 1, 6) and address[6] == texture['resource_id']
    assert address[7:] == (texture['offset'], texture['pitch'] * texture['height'])
    assert address[7] + address[8] <= published[address[6]]['size']
    expected = M.texture_descriptor(0, texture['width'], 64, texture['pitch'], 'rgba')
    expected[2] = M.desc('A8XX_TEX_MEMOBJ', 2, width=texture['width'], height=texture['height'], samples='MSAA_ONE')
    expected[3] = M.desc('A8XX_TEX_MEMOBJ', 3,
        fmt='FMT6_16_16_16_16_FLOAT' if index == 3 else 'FMT6_8_8_8_8_UNORM',
        swap='WZYX' if index == 3 else 'WXYZ', swiz_x='A8XX_SWIZ_X', swiz_y='A8XX_SWIZ_Y',
        swiz_z='A8XX_SWIZ_Z', swiz_w='A8XX_SWIZ_W')
    expected[6] = M.desc('A8XX_TEX_MEMOBJ', 6, tex_line_offset=texture['pitch'] * 8,
                         miplvls=0, min_line_offset=2 if index == 3 else 1)
    expected[7] = M.desc('A8XX_TEX_MEMOBJ', 7, array_slice_offset=4096)
    assert td == expected, (index, td, expected)
    descriptors.append(dict(texture=texture, words=td, relocation=address))
sd = [list(struct.unpack_from('<4I', command, 48 + sr[7] + i * 16)) for i in range(10)]
assert sd[0] == M.sampler_descriptor()
expected_constant = [M.desc('A8XX_TEX_SAMP', 0, mipmaping_dis=True,
    xy_mag='A6XX_TEX_NEAREST', xy_min='A6XX_TEX_NEAREST', wrap_s='A6XX_TEX_REPEAT',
    wrap_t='A6XX_TEX_REPEAT', wrap_r='A6XX_TEX_REPEAT', lod_bias=0.0, aniso='A6XX_TEX_ANISO_1'),
    M.desc('A8XX_TEX_SAMP', 1, max_lod=0.25, min_lod=0.0,
           reduction_mode='A6XX_REDUCTION_MODE_AVERAGE', compare_func='FUNC_NEVER', chroma_linear=False), 0, 0]
assert sd[1] == expected_constant == [int(x, 16) for x in constant['samplers'][0]['a8xx_tex_samp']]
assert all(row == [0] * 4 for row in sd[2:])
for alias in c.get('buffer_aliases', []):
    assert alias['buffer_retained'] and alias['buffer_id'] == alias['texture_id']
    assert alias['requested_offset'] == alias['layout_offset'] == alias['buffer_offset'] == alias['texture_cpu_delta']
    assert alias['layout_offset'] == textures[3]['offset']
    if alias['relocated_by']:
        assert alias['relocated_by'] == 256
        data = Path(published[alias['texture_id']]['path']).read_bytes()
        assert data[:256] == bytes([0xa5]) * 256, 'snapshot lost the allocation prefix'
record = dict(q, status='NATIVE_CA_TEXTURE_KERNEL_REPLAY_PASSED', source_sha256=sha(__file__),
    base_replay_sha256=sha(replay), base_replay_source_sha256=q['source_sha256'],
    texture_reference=dict(scene='gradient', textures=descriptors, sampler_words=sd,
        aliases=c.get('buffer_aliases', []), reference_sha256={str(ROOT.parent / 'q1n1/tools' / name):
            sha(ROOT.parent / 'q1n1/tools' / name) for name in ['a16gpu_p6p7.py', 'a8xx_regs.py']}),
    physical_sampling_verified=False, desktop_verified=False)
output.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], output=str(output), sha256=sha(output))))
