#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the existing patched Mesa compiler libraries as arm64e without changing shared sources."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'bbeb2dca9feed6ac88d71234a9dc5ae8aeed4275'
TARGETS = [
    'src/freedreno/ir3/libfreedreno_ir3.a', 'src/freedreno/isa/libir3encode.a',
    'src/freedreno/isa/libir3decode.a', 'src/compiler/isaspec/libisaspec.a',
    'src/freedreno/common/libfreedreno_common.a', 'src/compiler/nir/libnir.a',
    'src/compiler/libcompiler.a', 'src/util/libmesa_util.a',
    'src/util/libmesa_util_simd.a', 'src/c11/impl/libmesa_util_c11.a',
    'src/util/blake3/libblake3.a',
    'src/freedreno/registers/adreno/a8xx_descriptors.xml.h',
    'src/freedreno/registers/adreno/a8xx_enums.xml.h',
    'src/freedreno/registers/adreno/a6xx_enums.xml.h',
    'src/freedreno/registers/adreno/adreno_common.xml.h',
]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', type=Path, default=ROOT / 'gpu/air2ir3/third_party/mesa')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=8)
    ap.add_argument('--python', type=Path, default=Path(sys.executable), help='Python with Mako for generated sources and executable generator shebangs')
    args = ap.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    assert not out.exists()
    assert 1 <= args.jobs <= 16
    python = args.python.resolve()
    subprocess.run([python, '-c', 'import mako, packaging'], check=True)
    env = dict(os.environ, PATH=str(python.parent) + os.pathsep + os.environ.get('PATH', ''))
    assert subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip() == REVISION
    tracked = subprocess.check_output(['git', '-C', source, 'ls-files', '-z']).decode().split('\0')
    extra = subprocess.check_output(['git', '-C', source, 'ls-files', '--others', '--exclude-standard', '-z']).decode().split('\0')
    sources = {name: sha(source / name) for name in sorted(set(tracked + extra)) if name and (source / name).is_file()}
    out.mkdir(parents=True)
    shutil.copy2(Path(__file__), out / 'build-source.py')
    record = dict(status='RUNNING', started=time.time(), pid=os.getpid(), source=str(source),
        source_revision=REVISION, source_sha256=sources, python=str(python), commands=[],
        boundary='Local arm64e Mesa compiler build only; no hardware execution or shared source modification.')

    def save():
        (out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(command, label):
        row = dict(command=[str(x) for x in command], log=label + '.log', started=time.time())
        record['commands'].append(row)
        with (out / row['log']).open('x') as log:
            proc = subprocess.Popen(row['command'], stdout=log, stderr=subprocess.STDOUT, env=env)
            row['pid'] = proc.pid
            save()
            row['exit_code'] = proc.wait()
        row['finished'] = time.time()
        save()
        assert row['exit_code'] == 0, row

    try:
        native = out / 'arm64e.ini'
        native.write_text("[binaries]\nc = ['/usr/bin/clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0']\n"
            "cpp = ['/usr/bin/clang++', '-arch', 'arm64e', '-mmacosx-version-min=27.0']\n"
            "ar = '/usr/bin/ar'\nstrip = '/usr/bin/strip'\n")
        options = ['buildtype=debugoptimized', 'platforms=', 'gallium-drivers=', 'vulkan-drivers=',
            'opengl=false', 'gles1=disabled', 'gles2=disabled', 'glx=disabled', 'egl=disabled',
            'gbm=disabled', 'llvm=disabled', 'tools=freedreno', 'freedreno-kmds=msm',
            'video-codecs=', 'zstd=disabled']
        build = out / 'build'
        run(['meson', 'setup', build, source, '--native-file', native, *['-D' + x for x in options]], 'configure')
        run(['ninja', '-C', build, '-j', str(args.jobs), *TARGETS], 'compile')
        record['libraries'] = []
        for target in TARGETS:
            p = build / target
            assert p.is_file(), p
            if p.suffix != '.a': continue
            arch = subprocess.check_output(['lipo', '-archs', p], text=True).strip()
            assert arch == 'arm64e', (p, arch)
            record['libraries'].append(dict(path=str(p), sha256=sha(p), architecture=arch))
        for name, digest in sources.items(): assert sha(source / name) == digest, name
        record['status'] = 'ARM64E_MESA_BUILT'
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['logs_sha256'] = {p.name: sha(p) for p in out.glob('*.log')}
        save()
    print(json.dumps(dict(status=record['status'], libraries=len(record['libraries']))))


if __name__ == '__main__':
    main()
