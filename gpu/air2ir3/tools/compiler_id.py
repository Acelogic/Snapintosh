#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""compiler_id.py - identity of everything that decides the generated code (CACHE-FORMAT.md 2.3).

  air2ir3-src-<16 hex>+mesa-<rev>-p<8 hex>-o<8 hex>+llvm-<version>

  src   SHA-256 of the air2ir3 compiler sources (src/air2ir3*.{cpp,h}, src/a8xx_sampler.{c,h})
  mesa  the pinned Mesa revision, p = SHA-256 of patches/* (our Mesa changes),
        o = SHA-256 of the options the Mesa build in build/mesa was actually configured with
        (meson-private/cmd_line.txt [options], sorted), e.g. buildtype, which switches Mesa asserts
  llvm  Homebrew LLVM version (the AIR front end's optimisation pipeline)

src/build.sh bakes this string into the library (air2ir3_compiler_id(), `air2ir3 --compiler-id`);
the sweep writes the binary's own answer into the manifest.  Not the binary's hash: two links of the
same sources differ in the Mach-O debug map and would invalidate the cache for no reason.
"""
import hashlib, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = ['src/air2ir3.cpp', 'src/air2ir3.h', 'src/air2ir3_api.h', 'src/ir3_program_export.h', 'src/a8xx_sampler.c', 'src/a8xx_sampler.h']

def sha(parts):
    h = hashlib.sha256()
    for name, data in parts: h.update(name.encode() + b'\0' + data)
    return h.hexdigest()

def mesa_options(build=os.path.join(ROOT, 'build', 'mesa')):
    p = os.path.join(build, 'meson-private', 'cmd_line.txt')
    if not os.path.exists(p): sys.exit('compiler_id: build/mesa is not configured (run tools/mesa-setup.sh)')
    opts, sect = [], None
    for l in open(p):
        l = l.strip()
        if l.startswith('['): sect = l; continue
        if sect == '[options]' and '=' in l: opts.append(l.replace(' = ', '='))
    return sorted(opts)

def compiler_id(mesa_build=os.path.join(ROOT, 'build', 'mesa'), llvm_config='/opt/homebrew/opt/llvm/bin/llvm-config'):
    src = sha((f, open(os.path.join(ROOT, f), 'rb').read()) for f in SRC)[:16]
    pd = os.path.join(ROOT, 'patches')
    pat = sha((f, open(os.path.join(pd, f), 'rb').read()) for f in sorted(os.listdir(pd)))[:8]
    opt = hashlib.sha256('\n'.join(mesa_options(mesa_build)).encode()).hexdigest()[:8]
    rev = subprocess.run(['git', '-C', os.path.join(ROOT, 'third_party', 'mesa'), 'rev-parse', '--short=12', 'HEAD'],
                         capture_output=True, text=True).stdout.strip() or 'unknown'
    llvm = subprocess.run([llvm_config, '--version'], capture_output=True, text=True).stdout.strip()
    return f'air2ir3-src-{src}+mesa-{rev}-p{pat}-o{opt}+llvm-{llvm}'

if __name__ == '__main__':
    print(compiler_id())
