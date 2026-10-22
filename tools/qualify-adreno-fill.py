#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay GPU fill transport under sanitizers and build its ARM monitor object.

This never opens a hardware client. Model readback is retained explicitly as
model evidence; actual Metal/driver integration and A16 execution remain open.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ['tools/test-adreno-fill.c', 'compat/adreno-fill.c', 'compat/adreno-submit.c',
    'compat/adreno-resource.c', 'compat/adreno.c', 'compat/irq-forward.c',
    'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c']
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    output = parser.parse_args().output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    environment = dict(os.environ, SNAP_FILL_ARTIFACT_DIR=str(output))

    def run(name, command):
        commands.append(command)
        result = subprocess.run(command, cwd=ROOT, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / (name + '.log')).write_text(result.stdout)
        assert result.returncode == 0, (name, result.returncode, str(output / (name + '.log')))
        return result.stdout

    run('compiler', ['clang', '--version'])
    flags = ['-std=gnu11', '-Icompat', '-Ishadow']
    dependencies = run('dependencies', ['clang', *flags, '-MM', *SOURCES]).replace('\\\n', ' ')
    dependencies = re.sub(r'^[^:\n]+:', '', dependencies, flags=re.M)
    inputs = set(dependencies.split()) | {str(Path(__file__).resolve().relative_to(ROOT))}
    binary = output / 'fill-integration'
    run('build', ['clang', *flags, '-O1', '-g', '-fsanitize=address,undefined',
        '-Wall', '-Wextra', '-Werror', *SOURCES, '-o', str(binary)])
    result = run('replay', [str(binary)])
    assert 'PASS: 1969 Adreno' in result and re.search(r'PASS: \d+ fill transport checks;', result)
    assert 'FAIL' not in result
    arm = output / 'adreno-fill-aarch64.o'
    run('arm-build', ['clang', '--target=aarch64-none-elf', '-std=gnu11', '-ffreestanding',
        '-fno-stack-protector', '-O2', '-Wall', '-Wextra', '-Werror', '-Icompat',
        '-c', 'compat/adreno-fill.c', '-o', str(arm)])
    arm_bytes = arm.read_bytes()
    assert arm_bytes[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<HH', arm_bytes, 16) == (1, 183)
    # Independently inspect the retained CP stream/readback instead of accepting
    # only the fixture's pass string. Fetch q1n1's packet formatter, not this helper.
    import sys
    sys.path.insert(0, str(ROOT.parent / 'q1n1/tools'))
    from adreno_x2 import pkt7
    ring = (output / 'model-submitted-ring.bin').read_bytes()
    words = struct.unpack('<' + 'I' * (len(ring) // 4), ring)
    assert len(words) == 0x1000 + 7 and words[0] == pkt7(0x3d, 0x1002)
    assert words[1:3] == (0x40003f00, 0)
    assert all(word == 0xff00ff00 for word in words[3:0x1003])
    assert words[0x1003] == pkt7(0x3d, 3) and words[0x1004:0x1006] == (0x10200080, 0)
    destination = (output / 'model-gpu-destination.bin').read_bytes()
    assert len(destination) == 0x10000
    for offset in range(0, len(destination), 4):
        changed = 0x3f00 <= offset < 0x4000 or 0xc000 <= offset < 0xff00
        assert struct.unpack_from('<I', destination, offset)[0] == (0xff00ff00 if changed else 0xa55aa55a), offset
    record = dict(status='FILL_TRANSPORT_HOST_QUALIFIED_NOT_INTEGRATED', commands=commands,
        sources_sha256={name: sha(ROOT / name) for name in sorted(inputs)},
        packet_reference_sha256=sha(ROOT.parent / 'q1n1/tools/adreno_x2.py'),
        artifacts_sha256={p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()},
        result=result.splitlines(), model_gpu_written_bytes=0x4000,
        model_capture_bytes=len(destination), model_ring_bytes=len(ring),
        boundary='Sanitized noncoherent RAM/SMMU/variable-PM4 model and ARM object only. '
                 'Not wired into monitor HVC, kext or Metal; no A16 execution or image proof. '
                 'Initial operation is bounded to16KiB and refuses ring wrap; no shader cache barriers.')
    path = output / 'qualification.json'
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], sources=len(inputs), artifacts=len(record['artifacts_sha256']), report=str(path))))


if __name__ == '__main__':
    main()
