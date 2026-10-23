#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay actual queued blit streams through production admission and CP copy effects.

Failure inventory: docs/ADRENO-COPY-MODEL-20261019.md. No target access or IR3 execution.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def commands(raw):
    result = []
    at = 0
    while at < len(raw):
        assert at + 8 <= len(raw)
        kind, size = struct.unpack_from('<II', raw, at)
        assert size >= 8 and size % 4 == 0 and at + size <= len(raw)
        result.append((at, kind, raw[at:at + size]))
        at += size
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--verify', type=Path)
    args = ap.parse_args()
    if args.verify:
        receipt = args.verify.resolve()
        report = json.loads(receipt.read_text())
        assert report['status'] == 'PASS_BLIT_ADMISSION_AND_COPY_MODEL'
        for p, h in report['inputs'].items():
            assert sha(p) == h, 'changed input: ' + p
        for p, h in report['artifacts'].items():
            assert sha(receipt.parent / p) == h, 'changed artifact: ' + p
        for row in report['replays']:
            subprocess.run([str(receipt.parent / 'kernel-replay'), '--replay',
                            str(receipt.parent / row['directory'])], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        for p, h in report['artifacts'].items():
            assert sha(receipt.parent / p) == h, 'repeat replay differs: ' + p
        print('VERIFIED PASS_BLIT_ADMISSION_AND_COPY_MODEL:', len(report['replays']), 'exact stream replays')
        return
    if not args.capture or not args.out:
        ap.error('--capture and --out, or --verify, are required')
    capture_path = args.capture.resolve()
    base = capture_path.parent
    capture = json.loads(capture_path.read_text())
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    decoder = module(ROOT / 'tools/decode-mps-encoding.py', 'blit_packet_decoder')
    helper = module(ROOT / 'tools/qualify-a8xx-compute-admission.py', 'blit_admission_helper')
    sources = ['tools/test-adreno-ib-command.c', 'compat/adreno-ib-command.c', 'compat/adreno-ib.c',
               'compat/adreno-fill-command.c', 'compat/adreno-fill.c', 'compat/adreno-submit.c',
               'compat/adreno-resource.c', 'compat/adreno-resource-list.c', 'compat/adreno.c',
               'compat/irq-forward.c', 'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c']
    inputs = [ROOT / p for p in sources]
    inputs += [ROOT / 'tools' / p for p in ('test-adreno.c', 'test-adreno-fill.c', 'test-adreno-fill-command.c',
                                          'decode-mps-encoding.py', 'qualify-a8xx-compute-admission.py',
                                          'gen-adreno-ib-tables.py', 'gen-a8xx-regs.py')]
    inputs += list((ROOT / 'compat').glob('*.h')) + list((ROOT / 'shadow').glob('*.h'))
    inputs += list((ROOT / 'gpu/adreno-kext/include').glob('*.h'))
    inputs += [Path(__file__), capture_path, ROOT / 'docs/ADRENO-COPY-MODEL-20261019.md',
               ROOT / 'docs/ADRENO-BLIT-ENCODING-E2E-20261019.md',
               ROOT / 'gpu/air2ir3/third_party/mesa/src/freedreno/registers/adreno/adreno_pm4.xml',
               ROOT / 'gpu/air2ir3/third_party/mesa/src/freedreno/vulkan/tu_device.cc']
    report = {'status': 'RUNNING', 'target_access': False, 'gpu_submission': False,
              'boundary': 'Actual public Metal blit streams through production admission and SMMU/noncoherent CP_MEMCPY model. '
                          'Copy-only final bytes use independent API expectations. Mixed shader streams prove admission/order only. '
                          'No IR3 execution, Adreno execution, visible pixels or performance proof.',
              'inputs': {}, 'commands': [], 'replays': [], 'artifacts': {}}
    cases = []
    for case in capture['cases']:
        name = case['name']
        streams = [r for r in capture['streams'] if r['case'] == name]
        assert len(streams) == 1, name
        raw = decoder.filebytes(base, streams[0])
        inputs.append(base / streams[0]['file'])
        uses = {}
        for r in capture['published_resources']:
            if r['case'] != name:
                continue
            if r['id'] in uses:
                assert uses[r['id']]['bytes'] == r['bytes']
                uses[r['id']]['usage'] |= r['usage']
            else:
                uses[r['id']] = dict(r)
        assert uses
        memory = {}
        for r in case['memory']:
            rid = r['id']
            assert rid in uses and rid not in memory and r['bytes'] == uses[rid]['bytes']
            initial = decoder.filebytes(base, r, 'initial_file', 'initial_sha256')
            assert len(initial) == r['bytes'] and len(initial) % 4 == 0
            inputs.append(base / r['initial_file'])
            expected = None
            if case['copy_only_model']:
                expected = decoder.filebytes(base, r, 'expected_file', 'expected_sha256')
                assert len(expected) == len(initial)
                inputs.append(base / r['expected_file'])
            memory[rid] = (initial, expected)
        assert memory
        decoded = []
        copy_packets = copy_bytes = shaders = 0
        for offset, kind, command in commands(raw):
            if kind == 0x1002:
                package = decoder.decode_package(command, uses)
                decoded.append((offset, command, package))
                for p in package['packets']:
                    if p.get('opcode') == decoder.enum('CP_MEMCPY'):
                        assert len(p['payload']) == 5
                        copy_packets += 1
                        copy_bytes += 4 * p['payload'][0]
                    if p.get('opcode') in (decoder.enum('CP_EXEC_CS'), decoder.enum('CP_DRAW_INDX_OFFSET')):
                        shaders += 1
            elif kind == 0x1001:
                assert len(command) == 32
            else:
                assert kind == 0x1000 and len(command) == 8 and offset + 8 == len(raw)
        assert copy_packets and decoded
        if case['copy_only_model']:
            assert not shaders and set(memory) == set(uses), 'copy-only oracle must cover every allocation'
        cases.append((case, raw, uses, memory, decoded, copy_packets, copy_bytes))
    assert cases and any(c[0]['copy_only_model'] for c in cases)
    max_resources = max(len(c[2]) for c in cases)
    max_bytes = max(sum((r['bytes'] + 0x3fff) & ~0x3fff for r in c[2].values()) for c in cases)
    arena_offset = max(0x300000, (0x10000 + max_bytes + 0xfffff) & ~0xfffff)
    guest_bytes = arena_offset + 0x100000
    assert max_resources <= 4096 and guest_bytes <= 0x10000000
    report['fixture'] = {'max_resources': max_resources, 'arena_offset': arena_offset, 'guest_bytes': guest_bytes}
    inputs += [q for p in inputs if p.suffix == '.c' and p.is_file() for q in source_files(p)[1:]]
    report['inputs'] = {str(p): sha(p) for p in sorted(set(inputs))}

    def save():
        (out / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

    def run(label, argv):
        report['commands'].append(argv)
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=90)
        (out / (label + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, label + ': ' + result.stdout[-1200:] + result.stderr[-1200:]

    def replay(name, raw, uses, memory, expected_error=0, numeric=False, packets=0, byte_count=0):
        directory = out / 'segments' / name
        directory.mkdir(parents=True)
        (directory / 'commands.bin').write_bytes(raw)
        (directory / 'list.bin').write_bytes(helper.resource_list([(rid, r['usage']) for rid, r in uses.items()]))
        va = 0x40100000
        rows = []
        for rid, r in uses.items():
            rows.append(f"{rid:x} {va:x} {r['bytes']:x}\n")
            va += (r['bytes'] + 0x3fff) & ~0x3fff
        assert va < 0x44000000
        (directory / 'resources.txt').write_text(''.join(rows))
        ncommands = len(commands(raw)) if not expected_error else 1
        (directory / 'expect.txt').write_text(''.join(f'{i} {expected_error}\n' for i in range(ncommands)))
        for rid, (initial, expected) in memory.items():
            (directory / f'resource-{rid:x}.initial.bin').write_bytes(initial)
            if numeric:
                assert expected is not None
                (directory / f'resource-{rid:x}.expected.bin').write_bytes(expected)
        run(name, [str(out / 'kernel-replay'), '--replay', str(directory)])
        text = (directory / 'result.txt').read_text()
        records = [dict(zip(line.split()[::2], line.split()[1::2])) for line in text.splitlines()
                   if line.startswith('command ')]
        model = next(line.split() for line in text.splitlines() if line.startswith('copy_model '))
        model = dict(zip(model[1::2], model[2::2]))
        assert len(records) == ncommands and 'failures 0' in text
        assert all(int(r['result']) == expected_error and r['frozen'] == r['latched'] == '0' for r in records)
        comparisons = {}
        if expected_error:
            assert all(r[k] == '0' for r in records for k in ('rings', 'to_device', 'from_device'))
            assert model['packets'] == model['bytes'] == '0'
        else:
            assert sum(int(r['rings']) for r in records) == sum(kind == 0x1002 for _, kind, _ in commands(raw))
            assert int(model['packets']) == packets and int(model['bytes']) == byte_count
        for rid, (initial, expected) in memory.items():
            final = (directory / f'resource-{rid:x}.final.bin').read_bytes()
            if expected_error or numeric:
                assert final == (initial if expected_error else expected), f'{name}: final allocation {rid:x} differs'
                comparisons[str(rid)] = {'bytes': len(final), 'sha256': hashlib.sha256(final).hexdigest()}
        if numeric:
            assert model['observed_draws'] == model['observed_dispatches'] == '0'
        report['replays'].append({'name': name, 'directory': str(directory.relative_to(out)),
                                  'expected_error': expected_error, 'numeric_copy_model': numeric,
                                  'commands': records, 'copy_model': model, 'whole_allocation_comparisons': comparisons})
        save()

    try:
        run('tables-fresh', [sys.executable, 'tools/gen-adreno-ib-tables.py', '--check'])
        run('build', ['clang', '-std=gnu11', '-Icompat', '-Ishadow', '-O1', '-g',
                      '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
                      f'-DGUEST_SIZE={guest_bytes}', f'-DIB_ARENA_OFFSET={arena_offset}',
                      f'-DIB_FIXTURES={max(24, max_resources)}',
                      f'-DIB_REPLAY_CAPACITY={max(48, (max_resources + 5) // 6 * 6)}',
                      *sources, '-o', str(out / 'kernel-replay')])
        run('existing-paths', [str(out / 'kernel-replay')])
        for case, raw, uses, memory, decoded, packets, byte_count in cases:
            replay('native-' + case['name'], raw, uses, memory, numeric=case['copy_only_model'],
                   packets=packets, byte_count=byte_count)
        case, raw, uses, memory, decoded, _, _ = next(c for c in cases if c[0]['copy_only_model'])
        offset, command, package = decoded[0]
        assert offset == 0, 'negative controls need a stream that begins with its copy IB'
        copy = next(p for p in package['packets'] if p.get('opcode') == decoder.enum('CP_MEMCPY'))
        src = decoder.read_reloc(package, 4 * (copy['word'] + 2), 1)
        dst = decoder.read_reloc(package, 4 * (copy['word'] + 4), 1)
        reloc_base = 48 + len(package['package'])

        def corrupt(name, changes, error, usage=None):
            damaged = bytearray(raw)
            for at, fmt, value in changes:
                struct.pack_into(fmt, damaged, at, value)
            modified_uses = {rid: dict(r) for rid, r in uses.items()}
            for rid, value in (usage or {}).items():
                modified_uses[rid]['usage'] = value
            replay(name, bytes(damaged), modified_uses, memory, expected_error=error)
            report['replays'][-1]['mutations'] = changes
            report['replays'][-1]['fixture_usage_mutations'] = usage or {}

        count_at = 48 + 4 * (copy['word'] + 1)
        sr = reloc_base + 32 * src['index']
        dr = reloc_base + 32 * dst['index']
        corrupt('zero-copy-count', [(count_at, '<I', 0)], -122)
        corrupt('oversized-copy-count', [(count_at, '<I', 0xffffffff)], -126)
        corrupt('short-source-span', [(sr + 24, '<Q', src['length'] - 4)], -126)
        corrupt('short-destination-span', [(dr + 24, '<Q', dst['length'] - 4)], -126)
        corrupt('source-without-read', [(sr + 9, '<B', 2)], -124, {src['resource_id']: 3})
        corrupt('destination-without-write', [(dr + 9, '<B', 1)], -124, {dst['resource_id']: 3})
        corrupt('unaligned-source', [(sr + 16, '<Q', src['offset'] + 1)], -121)
        corrupt('unknown-source', [(sr + 12, '<I', 0x7fffffff)], -121)
        corrupt('package-source', [(sr + 8, '<B', 2), (sr + 12, '<I', 0), (sr + 16, '<Q', 0)], -124)
        corrupt('overlapping-copy', [(dr + 12, '<I', src['resource_id']),
                                     (dr + 16, '<Q', src['offset'])], -126, {src['resource_id']: 3})
        report['status'] = 'PASS_BLIT_ADMISSION_AND_COPY_MODEL'
    except Exception as exc:
        report['status'] = 'FAIL'
        report['error'] = str(exc)
        raise
    finally:
        report['artifacts'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*')
                               if p.is_file() and p.name != 'qualification.json'}
        save()
    print('PASS_BLIT_ADMISSION_AND_COPY_MODEL:', len(cases), 'real streams, ten pre-ring refusal controls')


if __name__ == '__main__':
    main()
