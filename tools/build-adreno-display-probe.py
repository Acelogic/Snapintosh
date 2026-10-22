#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build/sign the guest IOMobileFramebuffer display-swap probe, without executing a swap.

The probe needs no Metal plug-in: it draws an IOSurface with the CPU and swaps it
on the main IOMobileFramebuffer (AdrenoDisplay on the A16). This only builds it;
panel pixels remain unproven until the conductor's guest run and panel capture.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'gpu/adreno-kext/plugin/harness/guest-display-probe.m'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = output / 'display-probe'
    commands = []
    sources = {str(p.relative_to(ROOT)): sha(p) for p in (SOURCE, Path(__file__).resolve())}

    def run(name, argv):
        commands.append(argv)
        result = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / (name + '.log')).write_text(result.stdout)
        assert result.returncode == 0, (name, result.returncode, str(output / (name + '.log')))
        return result.stdout

    run('compiler', ['xcrun', 'clang', '--version'])
    run('build', ['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0',
                  '-fobjc-arc', '-fobjc-arc-exceptions', '-O2', '-Wall', '-Wextra', '-Werror',
                  str(SOURCE), '-o', str(binary),
                  '-framework', 'Foundation', '-framework', 'IOKit', '-framework', 'IOSurface'])
    run('sign', ['codesign', '-s', '-', str(binary)])
    run('verify-signature', ['codesign', '--verify', '--strict', '--verbose=2', str(binary)])
    architecture = run('architecture', ['lipo', '-archs', str(binary)]).strip()
    assert architecture == 'arm64e', architecture
    signing = run('signature', ['codesign', '-dvvv', str(binary)])
    cdhash, = re.findall(r'^CDHash=([0-9a-f]+)$', signing, re.M)
    # The private framework is loaded with dlopen at run time, never linked.
    linked = run('libraries', ['otool', '-L', str(binary)])
    assert 'IOMobileFramebuffer' not in linked, linked
    for name, digest in sources.items():
        assert sha(ROOT / name) == digest, name
    result = dict(status='GUEST_DISPLAY_PROBE_BUILT_NOT_EXECUTED', binary_sha256=sha(binary),
                  architecture=architecture, cdhash=cdhash, commands=commands, sources_sha256=sources,
                  artifacts_sha256={p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()},
                  boundary=__doc__)
    report = output / 'build.json'
    report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], report=str(report), binary=str(binary),
                          binary_sha256=result['binary_sha256'], cdhash=cdhash)))


if __name__ == '__main__':
    main()
