#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay a real CARenderer capture through the production kernel submission path.

Failure inventory: docs/ADRENO-CA-RENDERER-20260928.md. Host only; the monitor
backend is modeled and does not execute the captured shader or CP copies.
"""
from pathlib import Path
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--capture', type=Path, required=True)
ap.add_argument('--output', type=Path, required=True)
ap.add_argument('--verify-textures', action='store_true', help='Verify the captured CARenderer checkerboard bindings against q1n1/Mesa descriptors')
args = ap.parse_args()
capture = args.capture.resolve()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
record = dict(status='RUNNING', capture_sha256=sha(capture), source_sha256=sha(__file__),
              a16_access=False, gpu_execution=False, cases=[])


def save():
    (out/'qualification.json').write_text(json.dumps(record, indent=2) + '\n')


def run(name, command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
    (out/(name+'.log')).write_text(result.stdout + result.stderr)
    assert result.returncode == 0, (name, result.returncode)
    return result.stdout


try:
    spec = importlib.util.spec_from_file_location('ib_qualification', ROOT/'tools/qualify-adreno-ib-command.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    d = json.loads(capture.read_text())
    assert d['status'] == 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED'
    assert d['copy_availability_overridden'] and not d['adreno_submitted_to_gpu'] and not d['a16_access']
    assert len(d['commits']) == 1
    commit = d['commits'][0]
    commands_path = ROOT/commit['path']
    assert sha(commands_path) == commit['sha256']
    command = commands_path.read_bytes()
    kind, size, version, flags, nwords, ndata, nrel, reserved, r0, r1 = struct.unpack_from('<IIIIIIIIQQ', command)
    assert kind == 0x1002 and version == 1 and not (flags or reserved or r0 or r1)
    assert command[size:] == helper.FENCE
    package_bytes = helper.align64(4*nwords) + ndata
    reloc_start = 48 + package_bytes
    assert size == reloc_start + nrel*32
    words = struct.unpack_from('<%dI' % nwords, command, 48)
    relocs = [struct.unpack_from('<IIBBBBIQQ', command, reloc_start + i*32) for i in range(nrel)]
    by_lo = {r[0]:i for i,r in enumerate(relocs)}
    copies = []
    pos = 0
    while pos < len(words):
        header = words[pos]
        packet_type = header >> 28
        assert packet_type in (4, 7)
        count = header & (0x7f if packet_type == 4 else 0x3fff)
        assert pos + 1 + count <= len(words)
        if packet_type == 7 and (header >> 16) & 0x7f == 0x75:
            assert count == 5 and words[pos+1] > 0
            src_i, dst_i = by_lo[4*(pos+2)], by_lo[4*(pos+4)]
            src, dst = relocs[src_i], relocs[dst_i]
            assert src[2] == dst[2] == 1 and src[3] & 1 and dst[3] & 2
            assert words[pos+1]*4 <= min(src[8],dst[8])
            assert dst[7] % 64 == 0
            copies.append(dict(dword=pos, bytes=words[pos+1]*4, source_id=src[6], source_offset=src[7],
                               destination_id=dst[6], source_reloc=src_i, destination_reloc=dst_i))
        pos += 1 + count
    assert copies and any(c['source_offset'] == 0x120 for c in copies)
    record['copies'] = copies
    texture_relocations = None
    if args.verify_textures:
        sys.path.insert(0, str(ROOT.parent/'q1n1/tools'))
        import a16gpu_p6p7 as M
        rows = [row for row in d['fragment_bindings'] if row['textures']]
        assert len(rows) == 1 and len(rows[0]['textures']) == len(rows[0]['samplers']) == 1
        t, s = rows[0]['textures'][0], rows[0]['samplers'][0]
        # This is the real checkerboard scene's binding contract, not a synthetic texture fixture.
        assert (t['index'],t['format'],t['width'],t['height'],t['pitch']) == (3,70,8,8,64)
        assert t['layout_known'] and t['usage'] & 1
        assert all(s[k] == v for k,v in dict(index=0,min=0,mag=0,mip=0,s=0,t=0,r=0,aniso=1,
                                            normalized=True,lod_min=0,compare=0,border=0,lod_average=False).items())
        assert s['lod_max'] > 0.25
        variants = [json.loads(Path(p['fragment']['path']).read_text()) for p in d['programs']]
        textured = [v for v in variants if v['num_samp']]
        assert len(textured) == 1 and textured[0]['num_samp'] == 4
        bindings = textured[0]['sidecar']['reflection']['bindings']
        assert [(b['metal_index'],b['slot']) for b in bindings if b['kind'] == 'texture'] == [(3,3)]
        assert [(b['metal_index'],b['slot']) for b in bindings if b['kind'] == 'sampler'] == [(0,0)]
        loads = {}
        pos = 0
        while pos < len(words):
            header = words[pos]
            n = header & (0x7f if header >> 28 == 4 else 0x3fff)
            if header >> 28 == 7 and (header >> 16) & 0x7f == 0x34 and n == 3:
                for kind in ['ST6_SHADER','ST6_CONSTANTS']:
                    _, payload = M.load_state6(False,kind,'SS6_INDIRECT','SB6_FS_TEX',4)
                    if words[pos+1] == payload[0]:
                        assert kind not in loads
                        loads[kind] = by_lo[4*(pos+2)]
            pos += 1+n
        assert set(loads) == {'ST6_SHADER','ST6_CONSTANTS'}
        tr, sr = relocs[loads['ST6_CONSTANTS']], relocs[loads['ST6_SHADER']]
        assert tr[2:4] == sr[2:4] == (2,1) and tr[8] == 256 and sr[8] == 64
        base_at = tr[7] + 3*64
        base_index = by_lo[base_at]
        base = relocs[base_index]
        assert base[2] == 1 and base[3] == 1 and base[4] == 6 and base[6] == t['resource_id']
        assert base[7:] == (t['offset'],t['pitch']*t['height'])
        assert command[48+tr[7]:48+base_at] == bytes(3*64)
        td = list(struct.unpack_from('<16I',command,48+base_at))
        # q1n1's P7 reference uses 256-byte pitch and a 4 KiB-aligned slice.
        # The captured IOSurface has explicit 64-byte pitch and only one mip/layer.
        expected_t = M.texture_descriptor(0,8,64,64,'rgba')
        expected_t[2] = M.desc('A8XX_TEX_MEMOBJ',2,width=8,height=8,samples='MSAA_ONE')
        expected_t[6] = M.desc('A8XX_TEX_MEMOBJ',6,tex_line_offset=64*8,miplvls=0,min_line_offset=0)
        assert td == expected_t, (td,expected_t)
        sd = list(struct.unpack_from('<4I',command,48+sr[7]))
        expected_s = M.sampler_descriptor()
        expected_s[0] = M.desc('A8XX_TEX_SAMP',0,mipmaping_dis=True,xy_mag='A6XX_TEX_NEAREST',xy_min='A6XX_TEX_NEAREST',
                              wrap_s='A6XX_TEX_CLAMP_TO_EDGE',wrap_t='A6XX_TEX_CLAMP_TO_EDGE',wrap_r='A6XX_TEX_CLAMP_TO_EDGE',
                              lod_bias=0.0,aniso='A6XX_TEX_ANISO_1')
        expected_s[1] = M.desc('A8XX_TEX_SAMP',1,max_lod=0.25,min_lod=0.0,
                              reduction_mode='A6XX_REDUCTION_MODE_AVERAGE',compare_func='FUNC_NEVER',chroma_linear=False)
        assert sd == expected_s, (sd,expected_s)
        assert command[48+sr[7]+16:48+sr[7]+64] == bytes(48)
        published_texture = next(row for row in commit['published_resources'] if row['id'] == t['resource_id'])
        assert published_texture['usage'] & 1 and base[7]+base[8] <= published_texture['size']
        texture_relocations = (loads['ST6_CONSTANTS'],loads['ST6_SHADER'],base_index)
        record['texture_reference'] = dict(texture=t,sampler=s,texture_words=td,sampler_words=sd,
            reference_sha256={str(p):sha(p) for p in [ROOT.parent/'q1n1/tools/a16gpu_p6p7.py',
                ROOT.parent/'q1n1/tools/a8xx_regs.py',ROOT/'gpu/air2ir3/third_party/mesa/src/freedreno/fdl/fd6_view.cc',
                ROOT/'gpu/air2ir3/third_party/mesa/src/freedreno/fdl/fd6_layout.c']})
    published = commit['published_resources']
    unique = {}
    snapshots = {}
    for row in published:
        rid = row['id']
        assert 0 < row['size'] < 0x100000
        if 'path' in row:
            snapshot = Path(row['path'])
            assert snapshot.stat().st_size == row['size'] and sha(snapshot) == row['sha256']
            snapshots[rid] = dict(path=str(snapshot),sha256=row['sha256'],bytes=row['size'],
                                 snapshot_kind=row.get('snapshot_kind','cpu-memory'))
            if snapshots[rid]['snapshot_kind'] == 'undefined-private-replay-seed':
                seed = row['replay_seed']
                assert isinstance(seed,int) and 0 <= seed <= 255 and snapshot.read_bytes() == bytes([seed])*row['size']
                snapshots[rid]['replay_seed'] = seed
            else:
                assert snapshots[rid]['snapshot_kind'] == 'cpu-memory'
        if rid in unique:
            assert unique[rid]['size'] == row['size']
            unique[rid]['usage'] |= row['usage']
        else:
            unique[rid] = dict(row)
    if args.verify_textures:
        assert set(snapshots) == set(unique), 'Physical replay inputs require every retained allocation'
        target = unique[d['target_resource_id']]
        assert target['usage'] & 2 and target['size'] >= d['width']*d['height']*4
        pixels = Path(snapshots[t['resource_id']]['path']).read_bytes()
        colors = Counter(pixels[t['offset']+y*t['pitch']+4*x:t['offset']+y*t['pitch']+4*x+4].hex()
                         for y in range(t['height']) for x in range(t['width']))
        assert colors == {'14d2b4ff':32,'dc1eb4ff':32}
        record['texture_reference']['source_colors'] = dict(colors)
    if snapshots: record['resource_snapshots'] = snapshots
    resources = []
    fixture_va = 0x40100000
    for rid,row in unique.items():
        # Packed, page-aligned fixture mappings stay below the fixed IB arena
        # at0x44000000. The old 1MiB stride collided with it at resource64.
        mapped_bytes = (row['size']+0x3fff)&~0x3fff
        assert fixture_va+mapped_bytes <= 0x44000000
        resources.append((rid,fixture_va,row['size'],row['usage']))
        fixture_va += mapped_bytes
    sources = ['tools/test-adreno-ib-command.c','compat/adreno-ib-command.c']
    if (ROOT/'compat/adreno-ib.c').exists(): sources.append('compat/adreno-ib.c')
    sources += ['compat/adreno-fill-command.c','compat/adreno-fill.c','compat/adreno-submit.c',
                'compat/adreno-resource.c','compat/adreno-resource-list.c','compat/adreno.c',
                'compat/irq-forward.c','shadow/stage2.c','shadow/shadow.c','shadow/mmu.c']
    parts = [str(q.relative_to(ROOT)) for s in sources if s.endswith('.c') for q in source_files(ROOT/s)[1:]]
    record['production_inputs'] = {s:sha(ROOT/s) for s in sources+parts}
    binary = out/'kernel-replay'
    # Fit the actual native capture without changing any production limit.
    fixture_count = max(24,len(resources))
    list_capacity = max(48,((len(resources)+5)//6)*6)
    fixture_bytes = sum((r[2]+0x3fff)&~0x3fff for r in resources)
    arena_offset = max(0x300000,(0x10000+fixture_bytes+0xfffff)&~0xfffff)
    guest_bytes = arena_offset+0x100000
    assert len(resources) <= 4096 and guest_bytes <= 0x10000000
    record['host_fixture'] = dict(resources=fixture_count,list_capacity=list_capacity,
        fixture_bytes=fixture_bytes,arena_offset=arena_offset,guest_bytes=guest_bytes,
        private_replay_seed_resources=[rid for rid,s in snapshots.items() if s['snapshot_kind']=='undefined-private-replay-seed'])
    cflags = ['clang','-std=gnu11','-Icompat','-Ishadow',f'-DGUEST_SIZE={guest_bytes:#x}',
              f'-DIB_ARENA_OFFSET={arena_offset:#x}',f'-DIB_FIXTURES={fixture_count}',f'-DIB_REPLAY_CAPACITY={list_capacity}',
              '-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra','-Werror']
    run('build',cflags + sources + ['-o',str(binary)])
    record['binary_sha256'] = sha(binary)

    def replay(name, blob, expected):
        directory = out/name
        directory.mkdir()
        (directory/'commands.bin').write_bytes(blob)
        (directory/'list.bin').write_bytes(helper.resource_list([(r[0],r[3]) for r in resources]))
        (directory/'resources.txt').write_text(''.join(f'{rid:x} {va:x} {length:x}\n' for rid,va,length,_ in resources))
        (directory/'expect.txt').write_text('0 %d\n' % expected + ('1 0\n' if expected == 0 else ''))
        run(name,[str(binary),'--replay',str(directory)])
        text = (directory/'result.txt').read_text()
        lines = [dict(zip(line.split()[0::2],line.split()[1::2])) for line in text.splitlines() if line.startswith('command ')]
        assert lines and int(lines[0]['result']) == expected and 'failures 0' in text
        if expected:
            assert len(lines) == 1 and all(lines[0][k] == '0' for k in ['rings','to_device','from_device','frozen','latched'])
        else:
            assert len(lines) == 2 and lines[0]['rings'] == '1'
        record['cases'].append(dict(name=name, expected=expected, commands_sha256=sha(directory/'commands.bin'),
                                   result_sha256=sha(directory/'result.txt'), results=lines))
        save()

    replay('native-ca-capture',command,0)
    first = copies[0]
    cp = 48 + first['dword']*4
    src_off = reloc_start + first['source_reloc']*32
    dst_off = reloc_start + first['destination_reloc']*32
    source = relocs[first['source_reloc']]
    destination = relocs[first['destination_reloc']]
    def mutation(name, offset, fmt, value, expected):
        blob = bytearray(command)
        struct.pack_into(fmt,blob,offset,value)
        replay(name,blob,expected)
    mutation('copy-zero-count',cp+4,'<I',0,-122)
    mutation('copy-count-over-source',cp+4,'<I',source[8]//4+1,-126)
    mutation('copy-count-over-destination',cp+4,'<I',destination[8]//4+1,-126)
    mutation('copy-source-without-read',src_off+9,'B',2,-124)
    mutation('copy-destination-without-write',dst_off+9,'B',1,-124)
    mutation('copy-short-source-range',src_off+24,'<Q',first['bytes']-4,-126)
    mutation('copy-short-destination-range',dst_off+24,'<Q',first['bytes']-4,-126)
    mutation('copy-unaligned-source',src_off+16,'<Q',source[7]+1,-121)
    mutation('copy-wrong-packet-size',cp,'<I',helper.pkt7(0x75,4),-122)
    overlap = bytearray(command)
    struct.pack_into('B',overlap,dst_off+10,2)
    struct.pack_into('<IQQ',overlap,dst_off+12,source[6],source[7],source[8])
    replay('copy-overlap',overlap,-126)
    if texture_relocations:
        ti, si, bi = texture_relocations
        mutation('texture-load-short-range',reloc_start+ti*32+24,'<Q',192,-126)
        mutation('sampler-load-short-range',reloc_start+si*32+24,'<Q',16,-126)
        mutation('texture-base-low-alignment',reloc_start+bi*32+10,'B',2,-124)
        mutation('texture-base-short-high-field',reloc_start+bi*32+11,'B',16,-124)
        mutation('texture-unaligned-source',reloc_start+bi*32+16,'<Q',1,-121)
        record['status'] = 'NATIVE_CA_TEXTURE_KERNEL_REPLAY_PASSED'
    else:
        record['status'] = 'NATIVE_CA_COPY_KERNEL_REPLAY_PASSED'
except BaseException as error:
    record['status'] = 'FAIL'
    record['exception'] = repr(error)
    raise
finally:
    save()
print(json.dumps(dict(status=record['status'],copies=len(record['copies']),cases=len(record['cases']),output=str(out/'qualification.json'))))
