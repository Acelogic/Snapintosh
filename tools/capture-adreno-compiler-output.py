#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a fresh plug-in and capture real host Metal compiler callbacks only."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--function-constants', action='store_true')
    ap.add_argument('--varyings', action='store_true')
    ap.add_argument('--runtime-qualification', type=Path)
    args = ap.parse_args()
    out = args.output.resolve()
    assert not out.exists(), 'preserve prior evidence'
    out.mkdir(parents=True)
    plugin = ROOT / 'gpu/adreno-kext/plugin'
    sources = {str(p.relative_to(ROOT)): sha(p) for p in plugin.rglob('*')
               if p.is_file() and p.suffix in ('.m', '.h', '.tbd', '.plist', '.sh')}
    sources[str(Path(__file__).relative_to(ROOT))] = sha(Path(__file__))
    commands = []
    result = dict(status='RUNNING', started=time.time(), sources_sha256=sources,
        commands=commands, a16_access=False, gpu_submission=False,
        boundary='Host public Metal pipeline -> native compiler service -> Adreno callback bytes; no translation, shader execution or pixels yet.')
    env = {k: v for k, v in os.environ.items() if not k.startswith('ADRENO_')}
    env.update(OUT=str(out / 'plugin'), ADRENO_COMPILER_PLUGIN='simulatorDummyPlugin')

    def run(command, label, timeout=120):
        row = dict(command=[str(x) for x in command], log=label + '.log')
        commands.append(row)
        with (out / row['log']).open('x') as log:
            try:
                completed = subprocess.run(row['command'], cwd=ROOT, env=env,
                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
                row['exit_code'] = completed.returncode
            except subprocess.TimeoutExpired:
                row['timeout_seconds'] = timeout
                raise
        return completed.returncode

    try:
        if args.runtime_qualification:
            record_path = args.runtime_qualification.resolve()
            runtime = json.loads(record_path.read_text())
            assert runtime['status'] == 'PACKAGED_COMPILER_ARM64E_C_API_VERIFIED'
            for name, digest in runtime['artifacts_sha256'].items():
                assert sha(record_path.parent / name) == digest, name
            env['ADRENO_COMPILER_RUNTIME'] = str(record_path.parent / 'runtime')
            result['runtime_qualification'] = str(record_path)
            result['runtime_qualification_sha256'] = sha(record_path)
        result['host'] = subprocess.check_output(['sw_vers'], text=True)
        assert run(['sh', plugin / 'build.sh'], 'build-plugin') == 0
        probe = out / 'compiler-output'
        assert run(['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0',
            '-fobjc-arc', '-fobjc-arc-exceptions', '-O1', '-g', '-Wall', '-Werror',
            '-Wno-deprecated-declarations', plugin / 'harness/compiler-output.m',
            '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOKit',
            '-o', probe], 'build-probe') == 0
        assert run(['codesign', '-f', '-s', '-', probe], 'sign-probe') == 0
        bundle = out / 'plugin/AdrenoMetal.bundle'
        assert run(['codesign', '--verify', '--strict', bundle], 'verify-bundle') == 0
        assert run(['codesign', '--verify', '--strict', probe], 'verify-probe') == 0
        code = run([probe, bundle, out / 'capture', *(['--constants'] if args.function_constants else []),
            *(['--varyings'] if args.varyings else [])], 'capture')
        result['probe_exit_code'] = code
        report = out / 'capture/capture.json'
        if report.exists():
            capture = json.loads(report.read_text())
            result['capture_result'] = capture['result']
            result['capture_stage'] = capture['stage']
            assert capture['command_buffers_submitted'] == 0
            for row in capture.get('variants', []):
                if 'file' in row:
                    assert row['file'] == Path(row['file']).name
                    path = report.parent / row['file']
                    assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
                if 'air_file' in row:
                    assert row['air_file'] == Path(row['air_file']).name
                    path = report.parent / row['air_file']
                    assert path.stat().st_size == row['air_bytes'] and sha(path) == row['air_sha256']
                    assert row['air_entry'] == row['entry']
                if 'compiled_file' in row:
                    assert Path(row['compiled_file']).name == row['compiled_file']
                    assert Path(row['sidecar_file']).name == row['sidecar_file']
                    assert sha(report.parent / row['compiled_file']) == row['compiled_sha256']
                    assert sha(report.parent / row['sidecar_file']) == row['sidecar_sha256']
                    sidecar = json.loads((report.parent / row['sidecar_file']).read_text())
                    assert sidecar['key_inputs']['air_hash'] == row['air_sha256']
                    assert sidecar['key_inputs']['entry'] == row['entry']
                    assert sidecar['key'] == row['compiled_key']
                if 'gpu_file' in row:
                    assert Path(row['gpu_file']).name == row['gpu_file']
                    assert Path(row['program_file']).name == row['program_file']
                    machine = (report.parent / row['gpu_file']).read_bytes()
                    assert len(machine) == row['gpu_bytes'] and sha(report.parent / row['gpu_file']) == row['gpu_sha256']
                    assert sha(report.parent / row['program_file']) == row['program_sha256']
                    program = json.loads((report.parent / row['program_file']).read_text())
                    assert bytes.fromhex(program['code_hex']) == machine
                    assert program['info']['size'] == len(machine)
                    assert program['sidecar']['key'] == row['compiled_key']
            if code == 0:
                assert len(capture['variants']) == 3 and all('gpu_file' in row for row in capture['variants'])
            if 'source_sha256' in capture:
                assert sha(report.parent / 'input.metal') == capture['source_sha256']
        result['status'] = 'NATIVE_CALLBACK_BYTES_CAPTURED' if code == 0 else 'NATIVE_CALLBACK_CAPTURE_REJECTED'
        for name, digest in sources.items():
            assert sha(ROOT / name) == digest, name
    except BaseException as error:
        result.update(status='FAIL', exception=repr(error))
        raise
    finally:
        result['finished'] = time.time()
        result['artifacts_sha256'] = {str(p.relative_to(out)): sha(p)
            for p in out.rglob('*') if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ['status', 'capture_result', 'capture_stage', 'probe_exit_code']}))


if __name__ == '__main__':
    main()
