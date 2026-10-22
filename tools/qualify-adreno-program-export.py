#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare actual native Metal program exports with Mesa's independent reload path."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    capture, out = args.capture.resolve(), args.output.resolve()
    assert not out.exists(), 'preserve previous evidence'
    qualified = json.loads(capture.read_text())
    assert qualified['status'] == 'NATIVE_CALLBACK_BYTES_CAPTURED'
    assert not qualified['gpu_submission'] and not qualified['a16_access']
    inputs = {str(capture): sha(capture), str(Path(__file__)): sha(Path(__file__))}
    for group in ['sources_sha256', 'artifacts_sha256']:
        for name, digest in qualified[group].items():
            p = (ROOT if group == 'sources_sha256' else capture.parent) / name
            assert sha(p) == digest, name
            inputs[str(p)] = digest
    native_path = capture.parent / 'capture/capture.json'
    native = json.loads(native_path.read_text())
    assert native['command_buffers_submitted'] == 0
    assert [v['stage'] for v in native['variants']] == ['vertex', 'fragment', 'kernel']
    compiler = ROOT / 'gpu/air2ir3'
    build = compiler / 'src/build.sh'
    source = compiler / 'tools/p7ref/export_variant.cpp'
    for p in [build, source, source.with_name('export_p7_shaders.cpp')]: inputs[str(p)] = sha(p)
    text = build.read_text()

    def array(name):
        found = re.search(r'^' + name + r'=\((.*?)\)', text, re.M | re.S)
        assert found, name
        result = []
        for item in shlex.split(found.group(1)):
            for key, value in {'$HERE': compiler / 'src', '$M': compiler / 'third_party/mesa', '$B': compiler / 'build/mesa'}.items():
                item = item.replace(key, str(value))
            assert '$' not in item, item
            result.append(item)
        return result

    libraries = array('IR3LIBS') + array('BASELIBS')
    for name in libraries: inputs[name] = sha(Path(name))
    out.mkdir(parents=True)
    commands = []
    record = dict(status='RUNNING', started=time.time(), inputs_sha256=inputs, commands=commands,
        boundary='Actual native Metal pipelines own instructions identical to an independent Mesa reload/export. No GPU submission or pixels.')

    def run(command, label):
        command = [str(x) for x in command]
        row = dict(command=command, output=label)
        commands.append(row)
        with (out / label).open('x') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        row['exit_code'] = result.returncode
        assert result.returncode == 0, row

    try:
        exporter = out / 'export_variant'
        compiler_flags = ['clang++', '-std=c++17', '-O1', '-g', '-Wno-deprecated-declarations', '-Wno-c99-designator',
            *array('INC'), *array('DEFS')]
        linker_flags = [*libraries, '-L/opt/homebrew/opt/zstd/lib', '-lzstd', '-lz']
        run([*compiler_flags, source, *linker_flags, '-o', exporter], 'build.log')
        pair_exporter = out / 'export_pair'
        run([*compiler_flags, source.with_name('export_p7_shaders.cpp'), *linker_flags, '-o', pair_exporter], 'build-pair.log')
        summaries = []
        for v in native['variants']:
            stage = v['stage']
            run([exporter, native_path.parent / v['compiled_file'], native_path.parent / v['sidecar_file']], stage + '.reference.json')
            reference = json.loads((out / (stage + '.reference.json')).read_text())['variant']
            del reference['disasm']
            actual = json.loads((native_path.parent / v['program_file']).read_text())
            assert actual == reference, (stage, [k for k in reference.keys() | actual.keys() if reference.get(k) != actual.get(k)])
            machine = (native_path.parent / v['gpu_file']).read_bytes()
            assert machine == bytes.fromhex(reference['code_hex'])
            summaries.append(dict(stage=stage, machine_bytes=len(machine), machine_sha256=hashlib.sha256(machine).hexdigest(),
                program_sha256=v['program_sha256'], reference_equal=True, fields=len(reference)))
        vs, fs = native['variants'][:2]
        run([pair_exporter, native_path.parent / vs['compiled_file'], native_path.parent / fs['compiled_file'],
            native_path.parent / vs['sidecar_file'], native_path.parent / fs['sidecar_file']], 'pipeline.reference.json')
        pair = json.loads((out / 'pipeline.reference.json').read_text())
        assert native['program_linkage'] == pair['link_vs_fs'], 'native vertex/fragment linkage differs from Mesa'
        if native.get('varying_capture'):
            assert pair['link_vs_fs']['cnt'] >= 3
            fragment_inputs = [i for i in pair['fs']['inputs'] if i['compmask'] and i['bary']]
            assert any(i['flat'] for i in fragment_inputs) and any(not i['flat'] for i in fragment_inputs)
        record['program_linkage'] = dict(reference_equal=True, **pair['link_vs_fs'])
        for name, digest in inputs.items(): assert sha(Path(name)) == digest, name
        record.update(status='NATIVE_PROGRAM_EXPORT_MATCHES_INDEPENDENT_MESA', variants=summaries)
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], variants=record['variants'])))


if __name__ == '__main__':
    main()
