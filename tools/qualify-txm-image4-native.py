#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the replayed Image4 helper in private q1n1 RAM, with no SSD access.

Requires a fresh stage: earlier stopped guest RAM is no longer a live capture.
See TXM-TRUST-LOAD-20260925.md for failure analysis and qualification boundaries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1'
sys.path.insert(0, str(Q1N1 / 'tools'))
import q1n1proxy
sys.path.insert(0, str(ROOT / 'probes'))
import stagebind


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', default='udp://en5')
    ap.add_argument('--replay', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--generation', type=int, required=True)
    ap.add_argument('--adapter', type=Path, help='source-bound production adapter E2E build.json')
    ap.add_argument('--stage-build', type=Path, action='append', default=[],
                    help='q1n1 build/uefi of a resident stage pair other than ../q1n1 (probes/stagebind.py)')
    args = ap.parse_args()
    assert not args.output.exists(), 'preserve prior hardware records'
    replay_raw = args.replay.read_bytes()
    replay = json.loads(replay_raw)
    assert replay['replay_sha256'] == sha((ROOT / 'tools/replay-txm-load.py').read_bytes())
    assert replay['relocator_sha256'] == sha((ROOT / 'probes/txmnative.py').read_bytes())
    candidate = replay['portable']
    image_path = Path(candidate['image_path'])
    if not image_path.is_absolute():
        image_path = ROOT / image_path
    image = image_path.read_bytes()
    assert sha(image) == candidate['image_sha256'] and len(image) == 0x100308
    assert len(candidate['bridge_panic_cases']) == 3
    assert all(c['returned'] and c['bridge_panic'] == ['0x123', '0x456']
               for c in candidate['bridge_panic_cases'])
    assert len(replay['registration']) == 4
    positive = replay['registration'][0]['result']
    coexist = bool(replay.get('coexist_capture_path'))
    triple = bool(replay.get('coexist_app_capture_path'))
    assert len(positive['cdhash_queries']) == (1264 if triple else (940 if coexist else 148))
    assert all(c['callee_state_preserved'] and c['guest_simd_preserved']
               for c in positive['bridge_calls'])
    capture_path = Path(replay['capture_path'])
    capture_raw = capture_path.read_bytes()
    assert sha(capture_raw) == replay['capture_sha256']
    capture = json.loads(capture_raw)
    assert capture['source_bound'] and capture['selector'] == 12 and capture['cache_type'] == (27 if triple else (14 if coexist else 13))
    tree_path = ROOT / 'build/installed-image4-identity-300s-20260926-txm12-tree.bin'
    tree = tree_path.read_bytes()
    assert sha(tree) == capture['tree_sha256'] == replay['tree_sha256']
    inputs = {n: bytes.fromhex(capture[n]['hex']) for n in ('payload', 'manifest')}
    for name, data in inputs.items():
        assert sha(data) == capture[name]['sha256'] and len(data) == capture[name]['bytes']
    app_inputs = dict(inputs) if coexist else None
    rosetta_inputs = dict(inputs) if triple else None
    app_capture_raw = None
    os_capture_raw = None
    if coexist:
        os_capture_raw = Path(replay['coexist_capture_path']).read_bytes()
        assert sha(os_capture_raw) == replay['coexist_capture_sha256']
        os_capture = json.loads(os_capture_raw)
        assert os_capture['source_bound'] and os_capture['cache_type'] == 13
        assert os_capture['tree_sha256'] == sha(tree)
        inputs = {n: bytes.fromhex(os_capture[n]['hex']) for n in ('payload', 'manifest')}
        for name, data in inputs.items():
            assert sha(data) == os_capture[name]['sha256'] and len(data) == os_capture[name]['bytes']
        assert inputs['manifest'] == app_inputs['manifest']
    if triple:
        app_capture_raw=Path(replay['coexist_app_capture_path']).read_bytes()
        assert sha(app_capture_raw)==replay['coexist_app_capture_sha256']
        app_capture=json.loads(app_capture_raw)
        assert app_capture['source_bound'] and app_capture['cache_type']==14 and app_capture['tree_sha256']==sha(tree)
        app_inputs={n:bytes.fromhex(app_capture[n]['hex']) for n in ('payload','manifest')}
        for name,data in app_inputs.items():
            assert sha(data)==app_capture[name]['sha256'] and len(data)==app_capture[name]['bytes']
        assert app_inputs['manifest']==inputs['manifest']==rosetta_inputs['manifest']
    base = int(candidate['base'], 16)
    adapter = json.loads(args.adapter.read_bytes()) if args.adapter else None
    adapter_blob = None
    if adapter:
        assert all(sha((ROOT / n).read_bytes()) == h for n, h in adapter['source_sha256'].items())
        adapter_blob = Path(adapter['image_path']).read_bytes()
        assert sha(adapter_blob) == adapter['image_sha256'] and len(adapter_blob) == adapter['bytes']
        assert int(adapter['base'], 16) == 0xb0780000 and len(adapter_blob) < 0x10000
    record = dict(result='INCOMPLETE', started=time.time(), replay_sha256=sha(replay_raw),
        helper_sha256=sha(image), capture_sha256=sha(capture_raw), tree_sha256=sha(tree),
        coexist_capture_sha256=sha(os_capture_raw) if os_capture_raw else None,
        coexist_app_capture_sha256=sha(app_capture_raw) if app_capture_raw else None,
        source_sha256={str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                      (Path(__file__), ROOT / 'tools/txm-image4-bridge.S',
                       ROOT / 'tools/txm-image4-bridge.ld', ROOT / 'tools/replay-txm-load.py',
                       ROOT / 'probes/txmnative.py', ROOT / 'probes/stagebind.py')},
        cases=[], boundary='Native Snapdragon EL2 authentication/registration probe in private RAM; '
                           'not guest TXM12 ownership integration, Cryptex grafting or GUI proof.')
    p = None
    prior_guard = None
    try:
        p = q1n1proxy.connect(args.device)
        info = p.bootinfo()
        record['bootinfo'] = info
        assert info['current_el'] == 2 and info['stage_generation'] == args.generation
        assert info['stage_generation'] >= 8 and p.stage_features() & 1
        slot = info['stage_size'] // 2
        assert info['image_base'] in (info['stage_base'], info['stage_base'] + slot)
        assert info['stage_base'] <= base and base + len(image) <= info['stage_base'] + info['stage_size']
        stage = stagebind.bind(p.readmem, info, args.stage_build)
        assert not stagebind.overlaps(stage, base, base + len(image))
        if adapter:
            assert not stagebind.overlaps(stage, 0xb0780000, 0xb0780000 + len(adapter_blob))
        record['stage_text_sha256'] = stage['resident_text_sha256']
        record['stage_elf_sha256'] = stage['elf_sha256']
        record['stage_build'] = str(stage['build'])
        record['stage_bin_sha256'] = stage['bin_sha256']
        work = (info['heap_base'] + 0x100000 + 0x3fff) & ~0x3fff
        assert work + 0x300000 < info['heap_base'] + info['heap_size'] - 0x1000000
        record['placement'] = dict(image=hex(base), work=hex(work), bytes=0x300000)
        prior_guard = p.serror_state()
        assert not any(prior_guard[k] for k in ('before', 'during', 'unconsumed'))
        p.serror_strict(True)
        before_faults = p.get_exc_count()
        assert before_faults == 0
        leaf = bytes.fromhex('000080d2c0035fd6')
        p.writemem(base, leaf)
        p.flush_code(base, len(leaf))
        p.set_exc_guard(3)
        try:
            assert p.call(base, timeout=3) == 0 and p.get_exc_count() == 0
        finally:
            p.set_exc_guard(0)
        payload, manifest = work + 0x4000, work + 0x8000
        module, dynamic, config = work + 0xc000, work + 0x10000, work + 0x14000
        query, output = work + 0x18000, work + 0x20000
        stack, scratch, dt = work + 0x43c00, work + 0x100000, work + 0x200000
        runtime = base + 0x20400

        def write64(at, *values):
            p.writemem(at, struct.pack('<' + 'Q' * len(values), *values))

        def read64(at, count):
            return struct.unpack('<' + 'Q' * count, p.readmem(at, 8 * count))

        def invoke(entry, values=()):
            assert len(values) <= 8
            write64(work, base, stack, base + entry, *values, *([0] * (13 - len(values))))
            started = time.monotonic()
            result = p.call(base + 0x100000, work, timeout=30)
            fields = read64(work, 16)
            assert fields[14] == result
            assert p.get_exc_count() == 0
            return dict(status=hex(result), normal=fields[15], panic=[hex(v) for v in fields[12:14]],
                        seconds=round(time.monotonic() - started, 6))

        variants = [('intact', None, None, 1), ('payload-corrupt', 'payload', -1, 0xda502),
                    ('manifest-signature-corrupt', 'manifest', 1246, 0xca302),
                    ('certificate-signature-corrupt', 'manifest', 3065, 0xca302)]
        for name, which, offset, wanted in variants:
            case = dict(name=name)
            record['cases'].append(case)
            p.writemem(base, image)
            p.flush_code(base, len(image))
            assert p.readmem(base, len(image)) == image
            p.writemem(work, bytes(0x300000))
            current = dict(inputs)
            if which:
                changed = bytearray(current[which]); changed[offset] ^= 1
                current[which] = bytes(changed)
            p.writemem(payload, current['payload'])
            p.writemem(manifest, current['manifest'])
            p.writemem(dt, tree)
            write64(base + 0x203e0, dt, len(tree))
            p.writemem(base + 0x203f0, b'\1')
            p.writemem(stack, b'\1')
            write64(stack + 0x60, scratch, 0x100000, 0x100000)
            write64(runtime, config)
            write64(runtime + 0x20, dynamic)
            case['initialize'] = invoke(0x791a0)
            assert case['initialize']['normal'] == 1
            arguments = [runtime, 13, module, payload, len(current['payload']), manifest, len(current['manifest'])]
            case['load'] = invoke(0x46ac8, arguments)
            assert case['load']['normal'] == 1 and case['load']['status'] == hex(wanted)
            case['lists'] = [hex(read64(at, 1)[0]) for at in
                             (runtime + 0x10, runtime + 0x18, dynamic, dynamic + 8)]
            expected_lists = ['0x0', '0x0', hex(module), '0x0'] if wanted == 1 else ['0x0'] * 4
            assert case['lists'] == expected_lists
            case['module_hex'] = p.readmem(module, 32).hex()
            wanted_module = struct.pack('<QQQQ', 0, 13, len(inputs['payload']) - 23, payload + 23) if wanted == 1 else bytes(32)
            assert case['module_hex'] == wanted_module.hex()
            if wanted == 1:
                p.writemem(query, inputs['payload'][27:43])
                case['uuid_hit'] = invoke(0x463dc, [runtime, query, output])
                assert case['uuid_hit']['status'] == '0x5' and read64(output, 1)[0] == module
                arguments[2] = module + 0x100
                case['duplicate'] = invoke(0x46ac8, arguments)
                assert case['duplicate']['status'] == '0x82301'
                assert p.readmem(module + 0x100, 32) == bytes(32)
                assert read64(dynamic, 1)[0] == module and p.readmem(module, 32) == wanted_module
                case['hashes'] = []
                for index in range(148):
                    entry = payload + 47 + index * 24
                    write64(output, 0, 0)
                    hit = invoke(0x46668, [runtime, 2, entry, 20, output])
                    token = read64(output, 2)
                    assert hit['normal'] == 1 and hit['status'] == '0x10' and token == (module, entry)
                    case['hashes'].append(dict(index=index, status=hit['status'], token=[hex(v) for v in token]))
                if app_inputs:
                    app_payload, app_module = work + 0x28000, module + 0x200
                    app = dict(cases=[], hashes=[])
                    record['coexist'] = app
                    # Rejected App loads must leave the previously authenticated
                    # OS module and its payload intact before the valid App load.
                    for label, which, offset, expected_status in [
                            ('payload-corrupt', 'payload', -1, 0xda502),
                            ('manifest-corrupt', 'manifest', 1246, 0xca302),
                            ('certificate-corrupt', 'manifest', 3065, 0xca302),
                            ('intact', None, 0, 1)]:
                        altered = dict(app_inputs)
                        if which:
                            data = bytearray(altered[which]); data[offset] ^= 1; altered[which] = bytes(data)
                        p.writemem(app_payload, altered['payload']);p.writemem(manifest, altered['manifest'])
                        loaded = invoke(0x46ac8, [runtime, 14, app_module, app_payload,
                            len(altered['payload']), manifest, len(altered['manifest'])])
                        assert loaded['normal'] == 1 and loaded['status'] == hex(expected_status)
                        assert p.readmem(module, 32) == wanted_module
                        assert p.readmem(payload, len(inputs['payload'])) == inputs['payload']
                        assert read64(dynamic, 2) == (app_module if expected_status == 1 else module, 0)
                        expected_module = struct.pack('<QQQQ', module, 14, len(app_inputs['payload'])-23, app_payload+23)
                        assert p.readmem(app_module, 32) == (expected_module if expected_status == 1 else bytes(32))
                        assert p.readmem(app_payload, len(altered['payload'])) == altered['payload']
                        app['cases'].append(dict(name=label, **loaded))
                    for typ, location, data, expected_module in [(14, app_payload, app_inputs['payload'], app_module),
                                                                (13, payload, inputs['payload'], module)]:
                        p.writemem(query, data[27:43])
                        found = invoke(0x463dc, [runtime, query, output])
                        assert found['normal'] == 1 and found['status'] == '0x5'
                        assert read64(output, 1)[0] == expected_module
                        duplicate = invoke(0x46ac8, [runtime, typ, module+0x100, location,
                            len(data), manifest, len(inputs['manifest'])])
                        assert duplicate['normal'] == 1 and duplicate['status'] == '0x82301'
                        assert p.readmem(module+0x100, 32) == bytes(32)
                        for kind in range(4):
                            for index in range(struct.unpack_from('<I', data, 43)[0]):
                                entry = location + 47 + index*24
                                write64(output, 0, 0)
                                found = invoke(0x46668, [runtime, kind, entry, 20, output])
                                token = read64(output, 2)
                                expected_hit = kind in (0, 2)
                                assert found['normal'] == 1 and found['status'] == ('0x10' if expected_hit else '0x12411')
                                assert token == ((expected_module, entry) if expected_hit else (0, 0))
                                app['hashes'].append(dict(type=typ, kind=kind, index=index,
                                    status=found['status'], token=[hex(v) for v in token]))
                        print(json.dumps(dict(coexist_type=typ, queries=len(app['hashes']))), flush=True)
                    assert p.readmem(module, 32) == wanted_module
                    assert p.readmem(app_module, 32) == struct.pack('<QQQQ', module, 14, len(app_inputs['payload'])-23, app_payload+23)
                    assert read64(dynamic, 2) == (app_module, 0)
                    if rosetta_inputs:
                        ros_payload,ros_module=work+0x2c000,module+0x300
                        ros=dict(cases=[],hashes=[]);record['triple']=ros
                        old_modules=p.readmem(module,32)+p.readmem(app_module,32)
                        for label,which,offset,expected_status in [
                                ('payload-corrupt','payload',-1,0xda502),
                                ('manifest-corrupt','manifest',1246,0xca302),
                                ('certificate-corrupt','manifest',3065,0xca302),
                                ('intact',None,0,1)]:
                            altered=dict(rosetta_inputs)
                            if which:
                                data=bytearray(altered[which]);data[offset]^=1;altered[which]=bytes(data)
                            p.writemem(ros_payload,altered['payload']);p.writemem(manifest,altered['manifest'])
                            loaded=invoke(0x46ac8,[runtime,27,ros_module,ros_payload,
                                len(altered['payload']),manifest,len(altered['manifest'])])
                            assert loaded['normal']==1 and loaded['status']==hex(expected_status)
                            assert p.readmem(module,32)+p.readmem(app_module,32)==old_modules
                            assert p.readmem(payload,len(inputs['payload']))==inputs['payload']
                            assert p.readmem(app_payload,len(app_inputs['payload']))==app_inputs['payload']
                            assert read64(dynamic,2)==(ros_module if expected_status==1 else app_module,0)
                            ros_expected=struct.pack('<QQQQ',app_module,27,len(rosetta_inputs['payload'])-23,ros_payload+23)
                            assert p.readmem(ros_module,32)==(ros_expected if expected_status==1 else bytes(32))
                            assert p.readmem(ros_payload,len(altered['payload']))==altered['payload']
                            ros['cases'].append(dict(name=label,**loaded))
                        for typ,location,data,expected_module in [
                                (27,ros_payload,rosetta_inputs['payload'],ros_module),
                                (14,app_payload,app_inputs['payload'],app_module),
                                (13,payload,inputs['payload'],module)]:
                            p.writemem(query,data[27:43]);found=invoke(0x463dc,[runtime,query,output])
                            assert found['normal']==1 and found['status']=='0x5' and read64(output,1)[0]==expected_module
                            duplicate=invoke(0x46ac8,[runtime,typ,module+0x100,location,len(data),manifest,len(inputs['manifest'])])
                            assert duplicate['normal']==1 and duplicate['status']=='0x82301'
                            assert p.readmem(module+0x100,32)==bytes(32)
                            for kind in range(4):
                                for index in range(struct.unpack_from('<I',data,43)[0]):
                                    entry=location+47+index*24;write64(output,0,0)
                                    found=invoke(0x46668,[runtime,kind,entry,20,output]);token=read64(output,2)
                                    expected_hit=kind in (0,2)
                                    assert found['normal']==1 and found['status']==('0x10' if expected_hit else '0x12411')
                                    assert token==((expected_module,entry) if expected_hit else (0,0))
                                    ros['hashes'].append(dict(type=typ,kind=kind,index=index,status=found['status'],token=[hex(v) for v in token]))
                            print(json.dumps(dict(triple_type=typ,queries=len(ros['hashes']))),flush=True)
                        assert p.readmem(module,32)+p.readmem(app_module,32)==old_modules
                        assert p.readmem(ros_module,32)==ros_expected and read64(dynamic,2)==(ros_module,0)
            case['input_unchanged'] = all(p.readmem(at, len(current[n])) == current[n]
                                          for n, at in [('payload', payload), ('manifest', manifest)])
            case['scratch_released'] = p.readmem(stack + 0x78, 1) == b'\0'
            assert case['input_unchanged'] and case['scratch_released']
            print(json.dumps(dict(case=name, status=case['load']['status'], hashes=len(case.get('hashes', [])))), flush=True)
        record['panic_returns'] = [invoke(offset, [0x123, 0x456]) for offset in (0x3d818, 0x3d60c, 0x3d99c)]
        assert all(v['normal'] == 0 and v['status'] == '0xffffffffffffffff'
                   and v['panic'] == ['0x123', '0x456'] for v in record['panic_returns'])
        if adapter:
            # Fresh helper, exact tree, captured inputs and a C-owned result.
            # The outer probe seeds all q0..q31 around seven complete adapter
            # transactions and restores q1n1's own registers before returning.
            p.writemem(base, image);p.flush_code(base, len(image))
            p.writemem(work, bytes(0x320000))
            p.writemem(dt, tree)
            probe = work + 0x300000
            p.writemem(probe + 0x4000, inputs['payload'])
            p.writemem(probe + 0x8000, inputs['manifest'])
            write64(probe, base, work, 0x300000, len(tree),
                    probe + 0x4000, len(inputs['payload']),
                    probe + 0x8000, len(inputs['manifest']), probe + 0xc000)
            if app_inputs:
                p.writemem(probe+0x10000, app_inputs['payload'])
                write64(probe+0x800, probe+0x10000, len(app_inputs['payload']), probe+0x14000)
            if rosetta_inputs:
                p.writemem(probe+0x18000,rosetta_inputs['payload'])
                write64(probe+0xa00,probe+0x18000,len(rosetta_inputs['payload']),probe+0x1c000)
            patterns = b''.join(struct.pack('<QQ', 0x123456789abc0000 + n, 0xfedcba9876540000 + n)
                                for n in range(32))
            p.writemem(probe + 0x200, patterns)
            p.writemem(0xb0780000, adapter_blob);p.flush_code(0xb0780000, len(adapter_blob))
            assert p.readmem(0xb0780000, len(adapter_blob)) == adapter_blob
            started = time.monotonic()
            status = p.call(0xb0780000, probe, timeout=30)
            checks, failures, completed = read64(probe + 72, 3)
            cases = [dict(zip(('transport', 'status', 'bytes', 'offset'), read64(probe + 176 + n * 32, 4)))
                     for n in range(7)]
            record['adapter'] = dict(build_sha256=sha(args.adapter.read_bytes()), image_sha256=sha(adapter_blob),
                source_sha256=adapter['source_sha256'], status=status, checks=checks, failures=failures,
                completed=completed, cases=cases, state=list(read64(probe + 96, 10)),
                init_diagnostics=[hex(v) for v in read64(probe + 400, 3)],
                all_simd_preserved=p.readmem(probe + 0x400, 512) == patterns,
                seconds=round(time.monotonic() - started, 6))
            assert status == 0 and checks > 7000 and failures == 0 and completed == 1, record['adapter']
            assert record['adapter']['all_simd_preserved']
            assert [c['status'] for c in cases] == [1, 0x82301, 0xda502, 0xca302, 0xca302, 1, 0x82301]
            assert p.readmem(probe + 0x4000, len(inputs['payload'])) == inputs['payload']
            assert p.readmem(probe + 0x8000, len(inputs['manifest'])) == inputs['manifest']
            if app_inputs:
                co_cases = [dict(zip(('transport', 'status', 'bytes', 'offset'), read64(probe+0x818+n*32, 4)))
                            for n in range(7)]
                record['adapter']['coexist'] = dict(cases=co_cases,
                    invalid_refusals=read64(probe+0x8f8, 1)[0], completed=read64(probe+0x900, 1)[0])
                assert all(c['transport'] == 0 for c in co_cases)
                assert [c['status'] for c in co_cases] == [1, 0x82301, 0x82301, 0xda502, 0xca302, 0xca302, 1]
                assert record['adapter']['coexist']['invalid_refusals'] == 3
                assert record['adapter']['coexist']['completed'] == 1
                assert p.readmem(probe+0x10000, len(app_inputs['payload'])) == app_inputs['payload']
                assert p.readmem(probe+0xc000, len(inputs['payload'])-23) == inputs['payload'][23:]
                assert p.readmem(probe+0x14000, len(app_inputs['payload'])-23) == app_inputs['payload'][23:]
            if rosetta_inputs:
                tri_cases=[dict(zip(('transport','status','bytes','offset'),read64(probe+0xa18+n*32,4))) for n in range(8)]
                record['adapter']['triple']=dict(cases=tri_cases,invalid_refusals=read64(probe+0xb18,1)[0],completed=read64(probe+0xb20,1)[0])
                assert all(c['transport']==0 for c in tri_cases)
                assert [c['status'] for c in tri_cases]==[1,0x82301,0x82301,0x82301,0xda502,0xca302,0xca302,1]
                assert record['adapter']['triple']['invalid_refusals']==3 and record['adapter']['triple']['completed']==1
                assert checks>100000
                assert p.readmem(probe+0x18000,len(rosetta_inputs['payload']))==rosetta_inputs['payload']
                assert p.readmem(probe+0x1c000,len(rosetta_inputs['payload'])-23)==rosetta_inputs['payload'][23:]
        assert p.readmem(text[3], text[5]) == resident
        record['result'] = 'PASS'
    except Exception as error:
        record['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if p:
            try:
                after = p.serror_state()
                record['serror'] = {k: after[k] for k in ('before', 'during', 'unconsumed')}
                record['exceptions'] = p.get_exc_count()
                if any(record['serror'].values()) or record['exceptions']:
                    record['result'] = 'FAIL'
                if prior_guard:
                    p.serror_strict(bool(prior_guard['flags'] & q1n1proxy.SERROR_STRICT))
            finally:
                p.link.close()
        record['finished'] = time.time()
        with args.output.open('x') as f:
            json.dump(record, f, indent=2)
            f.write('\n')
        print(json.dumps(dict(result=record['result'], output=str(args.output))), flush=True)
    assert record['result'] == 'PASS'


if __name__ == '__main__':
    main()
