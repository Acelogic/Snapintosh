#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay actual QCC2072 containers through the native C parser; no hardware access."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'firmware-2.bin': '4c6a1be1f5bfad76319755ff76904abb21c4c7ece5293cc5f33a20b1f4c35254',
    'board-2.bin': '6880d8e6d51292f6bb5f855965b4c2d1bca3fa0d8a70e68bd693d1e73ff43bf1',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def records(blob, magic=None):
    pos = 0
    if magic:
        require(blob.startswith(magic + b'\0'), 'bad independent magic')
        pos = (len(magic) + 4) & ~3
    while pos < len(blob):
        require(pos + 8 <= len(blob), 'short independent header')
        kind, length = struct.unpack_from('<II', blob, pos)
        start = pos + 8
        end = start + length
        pos = start + ((length + 3) & ~3)
        require(pos <= len(blob), 'short independent body')
        yield kind, start, blob[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists(), 'output exists')
    inputs = {}
    for name, expected in EXPECTED.items():
        path = (args.firmware_dir / name).resolve()
        data = path.read_bytes()
        require(digest(data) == expected, 'different retained input: ' + name)
        inputs[name] = {'path': str(path), 'bytes': len(data), 'sha256': expected}
    output.parent.mkdir(parents=True, exist_ok=True)
    artifacts = output.parent / (output.stem + '-artifacts')
    artifacts.mkdir()  # Never overwrite a prior executable or log.
    binary = artifacts / 'transport-artifact'
    sources = [ROOT / 'src/qcc2072-firmware.c', ROOT / 'src/qcc2072-transport.c',
               ROOT / 're/transport-artifact.c']
    command = ['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
               *map(str, sources), '-o', str(binary)]
    compiled = subprocess.run(command, capture_output=True, text=True)
    (artifacts / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    require(compiled.returncode == 0, 'compile failed; see compile.log')
    run = subprocess.run([str(binary), inputs['firmware-2.bin']['path'],
                          inputs['board-2.bin']['path']], capture_output=True, text=True)
    (artifacts / 'execution.json').write_text(run.stdout)
    (artifacts / 'execution.stderr').write_text(run.stderr)
    require(run.returncode == 0 and not run.stderr, 'parser replay or sanitizer failed')
    result = json.loads(run.stdout)
    fw = Path(inputs['firmware-2.bin']['path']).read_bytes()
    independent = {kind: (offset, body) for kind, offset, body in records(fw, b'QCOM-ATH12K-FW')}
    for name, kind in [('amss', 2), ('m3', 3), ('aux', 5), ('features', 1)]:
        offset, body = independent[kind]
        require(result['firmware'][name] == {'offset': offset, 'bytes': len(body)},
                'independent slice mismatch: ' + name)
        result['firmware'][name]['sha256'] = digest(body)
    board = Path(inputs['board-2.bin']['path']).read_bytes()
    names = []
    board_records = 0
    for kind, _, body in records(board, b'QCA-ATH12K-BOARD'):
        if kind == 0:
            board_records += 1
            names.extend(data.rstrip(b'\0').decode('ascii')
                         for subkind, _, data in records(body) if subkind == 0)
    require(result['board']['names'] == len(names), 'independent board name count differs')
    require(result['board']['records'] == board_records, 'independent board record count differs')
    exact = [name for name in names if 'subsystem-vendor=105b' in name.split(',')
             and 'subsystem-device=e14f' in name.split(',')]
    require(not exact, 'expected missing board input changed')
    result['board']['independent_names'] = names
    result['board']['exact_module_name_count'] = len(exact)
    result['inputs'] = inputs
    source_paths = sources + [ROOT / 'src/qcc2072-firmware.h', ROOT / 'src/qcc2072-transport.h',
                              ROOT / 're/transport-failures.md', Path(__file__).resolve()]
    result['sources'] = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in source_paths}
    result['build'] = {'command': command, 'binary': str(binary),
                       'binary_sha256': digest(binary.read_bytes()),
                       'compile_exit': compiled.returncode, 'execution_exit': run.returncode,
                       'sanitizers': ['address', 'undefined'], 'device_probe_executed': False}
    result['limits'] = ['No live QMI identity is known; 33/24 is a diagnostic candidate only.',
                        'Firmware parsed; no device firmware transfer or DMA occurred.',
                        'Read-only MHI probe compiled only; no runtime device qualification.',
                        'Native interface, scan, association and packet I/O remain unqualified.']
    with output.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'artifact': str(output), 'sha256': digest(output.read_bytes()),
                      'status': result['status'], 'board': result['board']['exact_subsystem_candidate_result']}))


if __name__ == '__main__':
    main()
