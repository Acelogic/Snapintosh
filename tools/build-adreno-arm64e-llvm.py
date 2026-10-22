#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the pinned LLVM compiler components with the arm64e ABI, locally."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import time

VERSION = '22.1.8'
ARCHIVE = f'llvm-project-{VERSION}.src.tar.xz'
DIGEST = '922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888'
URL = f'https://github.com/llvm/llvm-project/releases/download/llvmorg-{VERSION}/{ARCHIVE}'


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=12)
    ap.add_argument('--archive', type=Path, help='Reuse a locally retained archive after checking the pinned digest')
    args = ap.parse_args()
    out = args.output.resolve()
    assert not out.exists(), 'preserve earlier builds'
    assert 1 <= args.jobs <= 16
    out.mkdir(parents=True)
    shutil.copy2(Path(__file__), out / 'build-source.py')
    record = dict(status='RUNNING', pid=os.getpid(), started=time.time(),
        source_sha256=sha(Path(__file__)), archive_url=URL, archive_sha256=DIGEST,
        commands=[], boundary='Local arm64e LLVM build only; no GPU or guest execution.')

    def save():
        (out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(command, label):
        row = dict(command=[str(x) for x in command], log=label + '.log', started=time.time())
        record['commands'].append(row)
        with (out / row['log']).open('x') as log:
            proc = subprocess.Popen(row['command'], stdout=log, stderr=subprocess.STDOUT)
            row['pid'] = proc.pid
            save()
            row['exit_code'] = proc.wait()
        row['finished'] = time.time()
        save()
        assert row['exit_code'] == 0, row

    try:
        archive = out / ARCHIVE
        if args.archive:
            assert sha(args.archive) == DIGEST
            shutil.copy2(args.archive, archive)
        else:
            run(['curl', '--fail', '--location', '--silent', '--show-error', '--output', archive, URL], 'download')
        assert archive.stat().st_size == 167061596 and sha(archive) == DIGEST
        source = out / 'source'
        source.mkdir()
        stem = f'llvm-project-{VERSION}.src'
        run(['tar', '-xJf', archive, '-C', source, stem + '/llvm', stem + '/cmake', stem + '/third-party'], 'extract')
        build = out / 'build'
        options = [
            '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=/usr/bin/clang',
            '-DCMAKE_CXX_COMPILER=/usr/bin/clang++', '-DCMAKE_OSX_ARCHITECTURES=arm64e',
            '-DCMAKE_OSX_DEPLOYMENT_TARGET=27.0', '-DLLVM_TARGETS_TO_BUILD=',
            '-DLLVM_ENABLE_PROJECTS=', '-DLLVM_INCLUDE_TESTS=OFF',
            '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_EXAMPLES=OFF',
            '-DLLVM_BUILD_TOOLS=OFF', '-DLLVM_ENABLE_RTTI=OFF',
            '-DLLVM_ENABLE_ASSERTIONS=ON', '-DLLVM_ENABLE_ZLIB=OFF',
            '-DLLVM_ENABLE_ZSTD=OFF', '-DLLVM_ENABLE_LIBXML2=OFF',
            '-DLLVM_ENABLE_LIBEDIT=OFF', '-DLLVM_ENABLE_FFI=OFF',
            '-DLLVM_ENABLE_Z3_SOLVER=OFF', '-DLLVM_BUILD_LLVM_DYLIB=ON',
            '-DLLVM_DYLIB_COMPONENTS=core;bitreader;bitwriter;passes;irreader;analysis;transformutils;ipo;scalaropts;instcombine',
        ]
        run(['cmake', '-G', 'Ninja', '-S', source / stem / 'llvm', '-B', build, *options], 'configure')
        run(['cmake', '--build', build, '--target', 'LLVM', 'llvm-config', '--parallel', str(args.jobs)], 'compile')
        libraries = sorted((build / 'lib').glob('libLLVM*.dylib'))
        assert libraries
        record['libraries'] = []
        for library in libraries:
            with library.open('rb') as f: magic, cpu, subtype = struct.unpack('<III', f.read(12))
            assert magic == 0xfeedfacf and cpu == 0x100000c and subtype & 0xffffff == 2, library
            record['libraries'].append(dict(path=str(library), sha256=sha(library), bytes=library.stat().st_size,
                cputype=hex(cpu), cpusubtype=hex(subtype),
                dependencies=subprocess.check_output(['otool', '-L', library], text=True)))
        record['llvm_config'] = subprocess.check_output([build / 'bin/llvm-config', '--version', '--targets-built'], text=True)
        record['status'] = 'ARM64E_LLVM_BUILT'
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
