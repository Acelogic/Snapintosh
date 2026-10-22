#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Translate exact native Metal callback modules through the existing C API."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path, required=True)
    ap.add_argument('--compiler-root', type=Path, required=True)
    ap.add_argument('--capture-source-ref', help='Immutable committed source of the native capture; default checks current files')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    capture_path, compiler_root, out = args.capture.resolve(), args.compiler_root.resolve(), args.output.resolve()
    assert not out.exists(), 'preserve earlier qualifications'
    qualification = json.loads(capture_path.read_text())
    assert qualification['status'] == 'NATIVE_CALLBACK_BYTES_CAPTURED'
    assert not qualification['a16_access'] and not qualification['gpu_submission']
    capture_commit = None
    if args.capture_source_ref:
        capture_commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse',
            '--verify', '--end-of-options', args.capture_source_ref + '^{commit}'], text=True).strip()
    for name, h in qualification['sources_sha256'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts, name
        if capture_commit:
            captured_source = subprocess.check_output(['git', '-C', str(ROOT), 'show', capture_commit + ':' + name])
            assert hashlib.sha256(captured_source).hexdigest() == h, name
        else:
            assert sha(ROOT / name) == h, name
    for name, h in qualification['artifacts_sha256'].items():
        assert sha(capture_path.parent / name) == h, name
    native_path = capture_path.parent / 'capture/capture.json'
    native = json.loads(native_path.read_text())
    assert native['result'] == 'NATIVE_COMPILER_OUTPUTS_CAPTURED'
    assert native['command_buffers_submitted'] == 0
    variants = native['variants']
    assert [v['stage'] for v in variants] == ['vertex', 'fragment', 'kernel']
    assert [v['entry'] for v in variants] == ['vs', 'fs', 'cs']
    binaries = [compiler_root / 'build/api_test', compiler_root / 'build/air2ir3']
    binary_hashes = {str(p): sha(p) for p in binaries}
    compiler_sources = {str(p): sha(p) for folder in ['src', 'tests']
        for p in (compiler_root / folder).rglob('*') if p.is_file() and p.suffix in ['.c', '.cpp', '.h', '.sh']}
    out.mkdir(parents=True)
    (out / 'api').mkdir()
    commands = []
    record = dict(status='RUNNING', started=time.time(), capture=str(capture_path),
        capture_sha256=sha(capture_path), native_sha256=sha(native_path),
        capture_source_commit=capture_commit, capture_sources_sha256=qualification['sources_sha256'],
        source_sha256=sha(Path(__file__)), compiler_binaries_sha256=binary_hashes,
        compiler_sources_sha256=compiler_sources, commands=commands,
        boundary='Real native Metal callback modules through production extraction and air2ir3 C API; host translation only, no linked guest compiler or GPU shader execution.')

    def run(command, label):
        row = dict(command=[str(x) for x in command], log=label + '.log')
        commands.append(row)
        with (out / row['log']).open('x') as stream:
            result = subprocess.run(row['command'], cwd=compiler_root, stdout=stream,
                stderr=subprocess.STDOUT, timeout=120)
        row['exit_code'] = result.returncode
        assert result.returncode == 0, row

    try:
        record['compiler_id'] = subprocess.check_output([binaries[1], '--compiler-id'], text=True).strip()
        jobs = []
        for v in variants:
            module = native_path.parent / v['air_file']
            assert module.stat().st_size == v['air_bytes'] and sha(module) == v['air_sha256']
            rt0 = 80 if v['stage'] == 'fragment' else 0
            jobs.append(f"{module}\t{v['entry']}\t{v['stage']}\t{rt0}\n")
        (out / 'jobs.txt').write_text(''.join(jobs))
        run([binaries[0], 'list', out / 'jobs.txt', '--repeat', '1', '--threads', '2', '--out', out / 'api'], 'api')
        summaries = []
        for index, v in enumerate(variants):
            module = native_path.parent / v['air_file']
            flags = ['--entry', v['entry'], '--stage', v['stage']]
            if v['stage'] == 'fragment': flags += ['--rt-format', '0=80']
            blob, side = out / f"{v['stage']}.ir3v", out / f"{v['stage']}.json"
            run([binaries[1], *flags, '--variant', blob, '--json', side, module], v['stage'])
            api_blob, api_side = out / 'api' / f'{index}.ir3v', out / 'api' / f'{index}.json'
            assert blob.read_bytes() == api_blob.read_bytes(), v['stage']
            assert side.read_bytes() == api_side.read_bytes(), v['stage']
            data = json.loads(side.read_text())
            assert data['key_inputs']['air_hash'] == v['air_sha256']
            run([binaries[1], '--verify-variant', blob], v['stage'] + '-reload')
            summaries.append(dict(stage=v['stage'], entry=v['entry'], air_sha256=v['air_sha256'],
                key=data['key'], blob_sha256=sha(blob), blob_bytes=blob.stat().st_size,
                sidecar_sha256=sha(side), api_cli_equal=True, reload_exit=0))
        for name, h in {**binary_hashes, **compiler_sources}.items(): assert sha(Path(name)) == h, name
        assert sha(capture_path) == record['capture_sha256'] and sha(native_path) == record['native_sha256']
        record.update(status='NATIVE_CALLBACKS_TRANSLATED_TO_IR3', variants=summaries)
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], variants=len(record['variants']))))


if __name__ == '__main__':
    main()
