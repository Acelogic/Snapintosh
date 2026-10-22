#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare real native callback shader modules on Metal and the AIR/NIR runner."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--translation', type=Path, required=True)
    ap.add_argument('--compiler-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    translation, compiler, out = args.translation.resolve(), args.compiler_root.resolve(), args.output.resolve()
    assert not out.exists(), 'preserve earlier runs'
    translated = json.loads(translation.read_text())
    assert translated['status'] == 'NATIVE_CALLBACKS_TRANSLATED_TO_IR3'
    assert sha(ROOT / 'tools/qualify-adreno-native-pipelines.py') == translated['source_sha256']
    for group in ['compiler_binaries_sha256', 'compiler_sources_sha256']:
        for name, digest in translated[group].items():
            assert sha(Path(name)) == digest, name
    for name, digest in translated['artifacts_sha256'].items():
        assert sha(translation.parent / name) == digest, name
    capture = Path(translated['capture'])
    assert sha(capture) == translated['capture_sha256']
    captured = json.loads(capture.read_text())
    for name, digest in captured['sources_sha256'].items():
        assert sha(ROOT / name) == digest, name
    for name, digest in captured['artifacts_sha256'].items():
        assert sha(capture.parent / name) == digest, name
    native_path = capture.parent / 'capture/capture.json'
    assert sha(native_path) == translated['native_sha256']
    native = json.loads(native_path.read_text())
    variants = {v['stage']: v for v in native['variants']}
    sources = [Path(__file__), compiler / 'src/nirexec.cpp', compiler / 'tools/mtlgold.swift']
    binaries = [compiler / 'build/nirexec', compiler / 'build/mtlgold']
    bindings = {str(p): sha(p) for p in sources + binaries}
    out.mkdir(parents=True)
    (out / 'scenes').mkdir()
    commands, comparisons = [], []
    record = dict(status='RUNNING', started=time.time(), translation=str(translation),
        translation_sha256=sha(translation), bindings_sha256=bindings,
        commands=commands, comparisons=comparisons,
        boundary='Identical native compiler callback shaders rendered on host Metal and through AIR-to-NIR/llvmpipe; no Adreno shader execution or panel presentation.')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ADRENO_', 'AIR2IR3_'))}
    try:
        for width, height in [(32, 24), (63, 47), (96, 64)]:
            name = f'{width}x{height}'
            scene = dict(width=width, height=height, rt=dict(format='bgra8'),
                clear=[0, 0, 0, 1], vertex=dict(stride=0, data=dict(floats=[]),
                count=3, primitive='triangle', attributes=[]))
            for key, stage in [('vs', 'vertex'), ('fs', 'fragment')]:
                v = variants[stage]
                scene[key] = dict(bc=str(native_path.parent / v['air_file']),
                    metallib=str(native_path.parent / v['file']), function=v['entry'])
            scene_path = out / 'scenes' / (name + '.json')
            scene_path.write_text(json.dumps(scene, indent=2) + '\n')
            for label, binary in [('nir', binaries[0]), ('metal', binaries[1])]:
                output = out / (name + '-' + label + '.bgra')
                row = dict(command=[str(binary), str(scene_path), str(output), '--frames', '3'],
                    log=name + '-' + label + '.log')
                commands.append(row)
                with (out / row['log']).open('x') as log:
                    result = subprocess.run(row['command'], cwd=compiler, env=env,
                        stdout=log, stderr=subprocess.STDOUT, timeout=120)
                row['exit_code'] = result.returncode
                assert result.returncode == 0, row
            a, b = [(out / (name + '-' + label + '.bgra')).read_bytes() for label in ['nir', 'metal']]
            assert len(a) == len(b) == width * height * 4
            colors = {b[i:i+4] for i in range(0, len(b), 4)}
            assert colors == {bytes([0, 0, 0, 255]), bytes([191, 128, 64, 255])}, colors
            count = sum(b[i:i+4] == bytes([191, 128, 64, 255]) for i in range(0, len(b), 4))
            assert width * height // 3 < count < width * height * 2 // 3, count
            comparison = dict(width=width, height=height, triangle_pixels=count,
                different_bytes=sum(x != y for x, y in zip(a, b)),
                max_channel_difference=max(abs(x-y) for x, y in zip(a, b)),
                nir_sha256=hashlib.sha256(a).hexdigest(), metal_sha256=hashlib.sha256(b).hexdigest())
            comparisons.append(comparison)
            assert comparison['different_bytes'] == 0, comparison
        for name, digest in bindings.items(): assert sha(Path(name)) == digest, name
        assert sha(translation) == record['translation_sha256']
        record['status'] = 'NATIVE_CALLBACK_RENDER_PIXELS_MATCH'
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], scenes=len(comparisons))))


if __name__ == '__main__':
    main()
