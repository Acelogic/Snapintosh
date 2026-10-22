#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Every probe still builds and links for the target.

This exists because of a failure the other suites cannot see. `test-mmu`,
`test-shadow`, `test-classify` and `test-profile` all run on the host, where
there is a libc; the probe runs at EL2 on bare metal, where there is not. A
change can pass all four and still produce a probe that does not link.

The one that happened: clang lowers a struct assignment into a call to memcpy,
and `-ffreestanding` does not stop it -- that flag promises the compiler will
not assume the library's *semantics*, not that it will stop emitting calls into
it. The source said `c->first_exc = regs;` and the linker asked for a symbol the
source never mentions:

    ld.lld: error: undefined symbol: memcpy
    >>> referenced by xnuboot.c

Compiling is not enough to catch that, because the reference only becomes an
error at link time. So this links, and then checks the result has no undefined
symbols at all -- a blob that is about to be branched to on hardware cannot have
any.

    python3 tools/test-link.py
"""
import importlib.util
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('run', ROOT / 'probes' / 'run.py')
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

# Every probe run.py knows how to build. The multi-translation-unit ones are the
# ones at risk, but a single-file probe costs nothing to check.
PROBES = ['idregs', 'tgran16', 'tid3', 'shadowmmu', 'xnuboot']

checks = 0
out = ROOT / 'build'

for name in PROBES:
    try:
        blob = run.build(name, out)
    except subprocess.CalledProcessError as error:
        print(f'FAIL: {name} did not build\n  {error}')
        sys.exit(1)
    if not blob or len(blob) > run.OUT_AT - run.CODE_AT:
        print(f'FAIL: {name} built outside its reserved code size')
        sys.exit(1)
    checks += 1

    # A flat blob is branched to at offset 0 with no loader and no relocation,
    # so an unresolved symbol is not a warning, it is a jump into nothing.
    elf = out / f'{name}.elf'
    if not elf.exists():
        continue                      # single-file probes go straight to .bin
    nm = subprocess.run([str(run.LLVM / 'llvm-nm'), '--undefined-only', str(elf)],
                        capture_output=True, text=True)
    undefined = [line for line in nm.stdout.splitlines() if line.strip()]
    if undefined:
        print(f'FAIL: {name}.elf has undefined symbols, which means the blob '
              f'calls something that is not there:')
        for line in undefined:
            print(f'  {line}')
        print('  A name the source never mentions is compiler-generated -- '
              'clang lowering a\n  struct assignment or bulk copy into memcpy. '
              'Write it as an explicit loop\n  over words instead.')
        sys.exit(1)
    checks += 1

for blob in (b'', bytes(run.OUT_AT-run.CODE_AT+1)):
    try:
        run.run(object(), blob, 'xnuboot', 'must not touch hardware')
    except ValueError:
        checks += 1
    else:
        raise AssertionError('invalid code size was admitted')

print(f'PASS: {checks} probe build/link checks '
      f'({len(PROBES)} probes, no hardware)')
