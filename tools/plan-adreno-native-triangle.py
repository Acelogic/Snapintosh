#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an offline a8xx command reference from a verified native Metal pipeline."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
Q = ROOT.parent / 'q1n1'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--comparison', type=Path, required=True)
    ap.add_argument('--source-ref', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    comparison, out = args.comparison.resolve(), args.output.resolve()
    assert not out.exists(), 'preserve prior evidence'
    proof = json.loads(comparison.read_text())
    assert proof['status'] == 'NATIVE_PROGRAM_EXPORT_MATCHES_INDEPENDENT_MESA'
    assert proof['program_linkage']['reference_equal']
    commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', '--verify',
        '--end-of-options', args.source_ref + '^{commit}'], text=True).strip()
    bindings, historical = {str(comparison): sha(comparison)}, {}
    for group in ['inputs_sha256', 'artifacts_sha256']:
        for name, digest in proof[group].items():
            path = comparison.parent / name if group == 'artifacts_sha256' else Path(name)
            if sha(path) != digest:
                relative = path.relative_to(ROOT)
                assert not str(relative).startswith('build/'), name
                old = subprocess.check_output(['git', '-C', str(ROOT), 'show', commit + ':' + str(relative)])
                assert hashlib.sha256(old).hexdigest() == digest, name
                historical[str(relative)] = digest
            else:
                bindings[str(path)] = digest
    pair_path = comparison.parent / 'pipeline.reference.json'
    pair = json.loads(pair_path.read_text())
    assert pair['chip_id'] == '0x44070041' and pair['link_vs_fs'] == {k:v for k,v in proof['program_linkage'].items() if k != 'reference_equal'}
    sys.path.insert(0, str(Q / 'tools'))
    import a16gpu_render as renderer
    import a16gpu_p6p7 as commands
    import adreno_x2 as gpu
    for module in list(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename and Path(filename).resolve().is_relative_to(Q / 'tools'):
            path = Path(filename).resolve()
            bindings[str(path)] = sha(path)
    bindings[str(Path(__file__))] = sha(Path(__file__))
    mesa_const = ROOT / 'gpu/air2ir3/third_party/mesa/src/gallium/drivers/freedreno/a6xx/fd6_const.cc'
    bindings[str(mesa_const)] = sha(mesa_const)
    out.mkdir(parents=True)
    record = dict(status='RUNNING', started=time.time(), inputs_sha256=bindings,
        historical_source_commit=commit, historical_sources_sha256=historical,
        a16_access=False, gpu_submission=False,
        boundary='Symbolic command plan from actual native Metal programs and the previously exercised q1n1 builder. No live mappings, driver integration or pixels.')
    try:
        width, height, pitch = 37, 23, 1024
        background = bytes((0xbf, 0x80, 0x40, 0xff)) * width * height
        scene = dict(name='native-triangle', width=width, height=height,
            vertex=dict(data=b'', stride=0, count=3, attributes=[]),
            buffers=dict(vs=[], fs=[]), textures=[], samplers=[], blend={},
            rts=[dict(index=0, format='bgra8', init=background)])
        original_ubo_table = renderer.B.ubo_table
        def application_ubos(variant):
            application = copy.deepcopy(variant)
            # Mesa emits driver UBOs independently of num_app_ubos.
            application['sidecar']['ir3']['driver_ubos'] = []
            return original_ubo_table(application)
        renderer.B.ubo_table = application_ubos
        try:
            plan = renderer.plan([scene], dict(pipelines={'native-triangle': pair}))
        finally:
            renderer.B.ubo_table = original_ubo_table
        function = plan['functions'][0]
        # Match the native IOSurface test's actual padded row/allocation layout.
        target = function['rts'][0]
        target.update(pitch=pitch, size=renderer.RT_GUARD + 32768)
        plan['rt_end'] = target['size'] + renderer.RT_GUARD
        window = renderer.Window(0)  # PA values are symbolic arena offsets only.
        driver_loads = []
        for stage, opcode, block in [('vs', gpu.CP_LOAD_STATE6_GEOM, 'SB6_VS_SHADER'),
                                      ('fs', gpu.CP_LOAD_STATE6_FRAG, 'SB6_FS_SHADER')]:
            variant = pair[stage]
            for driver in variant['sidecar']['ir3']['driver_ubos']:
                assert driver['kind'] == 'constant_data', driver
                slot, size = driver['ubo'], 16 * driver['size_vec4']
                offset = variant['info']['constant_data_offset']
                assert slot == variant['const_state']['consts_ubo']
                assert variant['const_state']['num_app_ubos'] <= slot < 16
                assert offset > 0 and offset % 16 == 0 and size > 0 and offset + size <= variant['info']['size']
                address = window.addr('r_code', function['code'][stage] + offset, size, False, stage + ' driver constant data')
                state = commands.pkt_word('CP_LOAD_STATE6_0', dst_off=slot, state_type='ST6_UBO',
                    state_src='SS6_DIRECT', state_block=block, num_unit=1)
                words = [gpu.pkt7(opcode, 5), state, 0, 0, *commands.ubo_desc(address, size)]
                driver_loads.append(dict(stage=stage, slot=slot, address=address, bytes=size, words=words))
        original_cs = commands.CS
        class DriverConstantCS(original_cs):
            def pkt7(self, opcode, *payload):
                if opcode == gpu.CP_DRAW_INDX_OFFSET:
                    for driver in driver_loads: self.raw(*driver['words'])
                super().pkt7(opcode, *payload)
        commands.CS = DriverConstantCS
        try:
            stream = renderer.build_ib(window, plan, function, 0x534e7001)
        finally:
            commands.CS = original_cs
        record['driver_constant_loads'] = driver_loads
        binary = struct.pack('<' + str(len(stream.w)) + 'I', *stream.w)
        assert 0 < len(binary) <= renderer.IB_SLOT
        (out / 'draw.ib.bin').write_bytes(binary)
        (out / 'draw.words.json').write_text(json.dumps(stream.w) + '\n')
        uploads = []
        for i, (region, offset, data, label) in enumerate(renderer.data_uploads(window, plan, function)):
            filename = f'upload-{i}.bin'
            (out / filename).write_bytes(data)
            uploads.append(dict(region=region, offset=offset, bytes=len(data), file=filename, label=label, sha256=sha(out / filename)))
        (out / 'target.before.bin').write_bytes(renderer.rt_region_bytes(plan))
        packets, at = [], 0
        while at < len(stream.w):
            header = stream.w[at]
            if header >> 28 == 7:
                count, opcode = header & 0x7fff, (header >> 16) & 0x7f
                assert header == gpu.pkt7(opcode, count)
                packet = dict(type=7, opcode=opcode)
            else:
                assert header >> 28 == 4
                count, offset = header & 0x7f, (header >> 8) & 0x3ffff
                assert header == commands.pkt4_header(offset, count)
                packet = dict(type=4, register=offset)
            assert at + 1 + count <= len(stream.w)
            packets.append(dict(packet, word=at, payload=stream.w[at+1:at+1+count]))
            at += count + 1
        draws = [p for p in packets if p.get('opcode') == gpu.CP_DRAW_INDX_OFFSET]
        assert len(draws) == 1 and draws[0]['payload'][1:] == [1, 3]
        assert window.refs and all(r['window'] in ['memptrs', 'r_code', 'r_misc', 'r_rt', 'r_data'] for r in window.refs)
        assert all(not r['write'] or r['window'] in ['memptrs', 'r_rt'] for r in window.refs)
        (out / 'packets.json').write_text(json.dumps(packets, indent=2) + '\n')
        (out / 'references.json').write_text(json.dumps(window.refs, indent=2) + '\n')
        (out / 'scene.json').write_text(json.dumps(dict(width=width, height=height, row_bytes=pitch,
            allocation_bytes=32768, target=target, vertex_count=3, uploads=uploads),
            default=lambda value: dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest()), indent=2) + '\n')
        for name, digest in bindings.items(): assert sha(Path(name)) == digest, name
        record.update(status='NATIVE_PIPELINE_SYMBOLIC_DRAW_PLAN_VERIFIED', ib_bytes=len(binary),
            packets=len(packets), address_references=len(window.refs), uploads=uploads,
            program_linkage=pair['link_vs_fs'], target_size=[width, height], target_row_bytes=pitch)
    except BaseException as error:
        record.update(status='FAIL', error=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k:record[k] for k in ['status', 'ib_bytes', 'packets', 'address_references']}))


if __name__ == '__main__':
    main()
