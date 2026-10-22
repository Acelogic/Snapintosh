#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build/sign the guest resource E2E probe; never run it or touch the A16.

Require the exact resource-encoder plug-in, a fresh output directory and a
verified arm64e signature. Preserve failed build logs; a build is not a test of
native allocation, resource submission, GPU execution, rendering or display.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PLUGIN = '12b774c3022e6fd1f5a684fff21256337e0e0ef4551a1a7d12559a9eb4b55dc1'
SOURCE = ROOT / 'gpu/adreno-kext/plugin/harness/guest-resource-probe.m'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin', type=Path, required=True, help='AdrenoMetal executable inside the bundle')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    plugin, output = args.plugin.resolve(), args.output.resolve()
    assert sha(plugin) == EXPECTED_PLUGIN, 'wrong resource-encoder plug-in'
    assert SOURCE.read_text().count(EXPECTED_PLUGIN) == 1, 'probe identity drift'
    output.mkdir(parents=True, exist_ok=False)
    binary = output / 'metal-resource-probe'
    commands = []

    def run(name, argv):
        commands.append(argv)
        result = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / (name + '.log')).write_text(result.stdout)
        assert result.returncode == 0, (name, result.returncode, str(output / (name + '.log')))
        return result.stdout

    run('compiler', ['xcrun', 'clang', '--version'])
    run('build', ['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0',
        '-fobjc-arc', '-fobjc-arc-exceptions', '-O2', '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', str(SOURCE), '-o', str(binary),
        '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOKit'])
    run('sign', ['codesign', '-s', '-', str(binary)])
    run('verify-signature', ['codesign', '--verify', '--strict', '--verbose=2', str(binary)])
    architecture = run('architecture', ['lipo', '-archs', str(binary)]).strip()
    assert architecture == 'arm64e', architecture
    signing = run('signature', ['codesign', '-dvvv', str(binary)])
    cdhash, = re.findall(r'^CDHash=([0-9a-f]+)$', signing, re.M)
    record = dict(status='GUEST_RESOURCE_PROBE_BUILT_NOT_EXECUTED', plugin=str(plugin),
        plugin_sha256=sha(plugin), binary_sha256=sha(binary), cdhash=cdhash,
        architecture=architecture, commands=commands,
        sources_sha256={str(path.relative_to(ROOT)): sha(path) for path in (SOURCE, Path(__file__).resolve())},
        artifacts_sha256={path.name: sha(path) for path in sorted(output.iterdir()) if path.is_file()},
        boundary='Build/signature only. Not installed or executed; no hardware client. '
                 'Guest JSON and physical resource mapping/completion evidence are still required.')
    path = output / 'build.json'
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], report=str(path), binary_sha256=record['binary_sha256'], cdhash=cdhash)))


if __name__ == '__main__':
    main()
