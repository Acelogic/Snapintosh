#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay real encoded MPS IBs through production admission and the noncoherent
monitor model. No target access or ir3 execution. Failure inventory precedes the
validator changes in docs/ADRENO-COMPUTE-PACKETS-20261019.md.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
MESA = ROOT / 'gpu/air2ir3/third_party/mesa'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def resource_list(entries):
    groups = [entries[i:i + 6] for i in range(0, len(entries), 6)]
    result = bytearray(32 + 64 * len(groups))
    struct.pack_into('<I', result, 28, len(groups))
    for group, rows in enumerate(groups):
        base = 32 + 64 * group
        for index, (rid, usage) in enumerate(rows):
            struct.pack_into('<I', result, base + 4 * index, rid)
            struct.pack_into('<H', result, base + 48 + 2 * index, usage)
        struct.pack_into('<H', result, base + 62, len(rows))
    return bytes(result)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--verify', type=Path)
    args = ap.parse_args()
    if args.verify:
        receipt = args.verify.resolve()
        report = json.loads(receipt.read_text())
        assert report['status'] == 'PASS_COMPUTE_ADMISSION'
        for path, digest in report['inputs'].items():
            assert sha(path) == digest, 'changed input: ' + path
        for path, digest in report['artifacts'].items():
            assert sha(receipt.parent / path) == digest, 'changed artifact: ' + path
        for row in report['replays']:
            directory = receipt.parent / row['directory']
            subprocess.run([str(receipt.parent / 'kernel-replay'), '--replay', str(directory)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            assert sha(directory / 'result.txt') == row['result_sha256'], 'replay differs: ' + row['name']
        print('VERIFIED PASS_COMPUTE_ADMISSION:', len(report['replays']), 'exact package replays; no ir3 execution')
        return
    if not args.capture or not args.out:
        ap.error('--capture and --out, or --verify, are required')
    capture_path = args.capture.resolve()
    capture_dir = capture_path.parent
    capture = json.loads(capture_path.read_text())
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    decoder = module(ROOT / 'tools/decode-mps-encoding.py', 'mps_admission_decoder')
    decoded = decoder.check_capture(capture, capture_dir)
    report = {'status': 'RUNNING', 'target_access': False, 'gpu_submission': False,
              'boundary': 'Real host-MPS production IB bytes through production kext admission, relocation, '
                          'resource/cache ownership and monitor fetch model. No ir3 execution, numeric GPU '
                          'result, A16, display, thermal or performance qualification.',
              'inputs': {}, 'artifacts': {}, 'commands': [], 'replays': [], 'encoded_cases': len(decoded)}
    sources = ['tools/test-adreno-ib-command.c', 'compat/adreno-ib-command.c', 'compat/adreno-ib.c',
               'compat/adreno-fill-command.c', 'compat/adreno-fill.c', 'compat/adreno-submit.c',
               'compat/adreno-resource.c', 'compat/adreno-resource-list.c', 'compat/adreno.c',
               'compat/irq-forward.c', 'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c']
    inputs = [ROOT / name for name in sources]
    # These model implementations are textually included by the replay TU.
    inputs += [ROOT / 'tools' / name for name in
               ('test-adreno-fill-command.c', 'test-adreno-fill.c', 'test-adreno.c')]
    inputs += list((ROOT / 'shadow').glob('*.h'))
    inputs += list((ROOT / 'compat').glob('adreno-*.h'))
    inputs += list((ROOT / 'gpu/adreno-kext/include').glob('*.h'))
    inputs += [Path(__file__), ROOT / 'tools/decode-mps-encoding.py', capture_path,
               ROOT / 'tools/gen-a8xx-regs.py', ROOT / 'tools/gen-adreno-ib-tables.py',
               ROOT / 'docs/ADRENO-COMPUTE-PACKETS-20261019.md',
               ROOT / 'docs/ADRENO-COPY-MODEL-20261019.md']
    for family in ('packages', 'streams'):
        inputs += [capture_dir / row['file'] for row in capture[family]]
    primary = [
        'src/gallium/drivers/freedreno/a6xx/fd6_compute.cc',
        'src/gallium/drivers/freedreno/a6xx/fd6_program.cc',
        'src/gallium/drivers/freedreno/a6xx/fd6_const.cc',
        'src/gallium/drivers/freedreno/a6xx/fd6_texture.cc',
        'src/gallium/drivers/freedreno/a6xx/fd6_barrier.cc',
        'src/gallium/drivers/freedreno/ir3/ir3_const.h',
        'src/freedreno/common/freedreno_gpu_event.h', 'src/freedreno/common/freedreno_devices.py',
        'src/freedreno/fdl/fd6_view.cc', 'src/freedreno/ir3/ir3_shader.h',
        'src/freedreno/ir3/ir3_shader.c', 'src/freedreno/ir3/ir3_compiler_nir.c',
        'src/freedreno/ir3/ir3_nir.c', 'src/compiler/shader_enums.h',
        'src/freedreno/decode/cffdec.c', 'src/freedreno/vulkan/tu_pipeline.cc']
    inputs += [MESA / path for path in primary]
    inputs += [q for p in inputs if p.suffix == '.c' and p.is_file() for q in source_files(p)[1:]]
    report['inputs'] = {str(path): sha(path) for path in sorted(set(inputs))}
    enums = (MESA / 'src/compiler/shader_enums.h').read_text()
    body = enums.split('} gl_system_value;')[0].rsplit('typedef enum', 1)[1]
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    body = re.sub(r'//[^\n]*', '', body)
    assert '=' not in body, 'explicit system-value enum assignments need a new decoder'
    names = re.findall(r'\bSYSTEM_VALUE_[A-Z0-9_]+\b', body)
    slots = {name: names.index(name) for name in ('SYSTEM_VALUE_LOCAL_INVOCATION_ID', 'SYSTEM_VALUE_WORKGROUP_ID')}
    assert list(slots.values()) == [42, 47]
    report['system_value_slots'] = slots

    def save():
        (out / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

    def run(label, argv):
        report['commands'].append([str(arg) for arg in argv])
        save()
        with (out / (label + '.log')).open('w') as log:
            subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)

    packages = []
    for row in capture['packages']:
        uses = {}
        passes = [p for p in capture['passes'] if p['case'] == row['case'] and p['package'] == row['package']]
        assert passes and any('dispatch' in p for p in passes), 'expected actual compute package'
        for p in passes:
            for r in p['resources']:
                if r['id'] in uses:
                    assert uses[r['id']]['bytes'] == r['bytes']
                    uses[r['id']]['usage'] |= r['usage']
                else:
                    uses[r['id']] = dict(r)
        raw = decoder.filebytes(capture_dir, row)
        package = decoder.decode_package(raw, uses)
        packages.append((row, uses, raw, package))
    max_resources = max(len(uses) for _, uses, _, _ in packages)
    max_bytes = max(sum((r['bytes'] + 0x3fff) & ~0x3fff for r in uses.values()) for _, uses, _, _ in packages)
    arena_offset = max(0x300000, (0x10000 + max_bytes + 0xfffff) & ~0xfffff)
    guest_bytes = arena_offset + 0x100000
    assert max_resources <= 4096 and guest_bytes <= 0x10000000
    report['fixture'] = {'max_resources': max_resources, 'arena_offset': arena_offset, 'guest_bytes': guest_bytes}
    try:
        run('tables-fresh', [sys.executable, 'tools/gen-adreno-ib-tables.py', '--check'])
        run('build', ['clang', '-std=gnu11', '-Icompat', '-Ishadow', '-O1', '-g',
                      '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
                      f'-DGUEST_SIZE={guest_bytes}', f'-DIB_ARENA_OFFSET={arena_offset}',
                      f'-DIB_FIXTURES={max(24, max_resources)}',
                      f'-DIB_REPLAY_CAPACITY={max(48, (max_resources + 5) // 6 * 6)}',
                      *sources, '-o', str(out / 'kernel-replay')])
        run('existing-paths', [str(out / 'kernel-replay')])

        def replay(name, raw, uses, expected):
            directory = out / 'segments' / name
            directory.mkdir(parents=True)
            (directory / 'commands.bin').write_bytes(raw)
            (directory / 'list.bin').write_bytes(resource_list([(rid, r['usage']) for rid, r in uses.items()]))
            va = 0x40100000
            rows = []
            for rid, r in uses.items():
                rows.append(f"{rid:x} {va:x} {r['bytes']:x}\n")
                va += (r['bytes'] + 0x3fff) & ~0x3fff
            assert va < 0x44000000
            (directory / 'resources.txt').write_text(''.join(rows))
            (directory / 'expect.txt').write_text(f'0 {expected}\n')
            run(name, [str(out / 'kernel-replay'), '--replay', str(directory)])
            result = (directory / 'result.txt').read_text()
            results = [dict(zip(line.split()[0::2], line.split()[1::2])) for line in result.splitlines()
                       if line.startswith('command ')]
            assert len(results) == 1 and int(results[0]['result']) == expected and 'failures 0' in result
            if expected:
                assert all(results[0][key] == '0' for key in ('rings', 'to_device', 'from_device', 'frozen', 'latched'))
            else:
                assert results[0]['rings'] == '1' and results[0]['frozen'] == results[0]['latched'] == '0'
                n = struct.unpack_from('<I', raw, 16)[0]
                assert (directory / 'fetched.bin').read_bytes() == (directory / 'package.bin').read_bytes()[:n * 4]
            report['replays'].append({'name': name, 'directory': str(directory.relative_to(out)),
                                      'expected': expected, 'result': results[0],
                                      'commands_sha256': sha(directory / 'commands.bin'),
                                      'result_sha256': sha(directory / 'result.txt')})
            save()

        for index, (row, uses, raw, package) in enumerate(packages):
            replay(f'native-{index:02d}-{row["case"]}', raw, uses, 0)
        row, uses, raw, package = packages[0]
        pkts = package['packets']
        launch = next(p for p in pkts if p.get('opcode') == decoder.enum('CP_EXEC_CS'))
        # Use the first pass geometry, before a later pass overwrites the same registers.
        before_launch = [p for p in pkts if p['word'] < launch['word']]
        register_words = {reg: value[1] // 4 for reg, value in decoder.registers(before_launch).items()}
        uav_word = register_words[decoder.reg('SP_CS_UAV_BASE')]
        table = next(r for r in package['relocations'] if r['lo'] == 4 * uav_word)
        image_at = table['offset'] + 64
        image_index, image = next((i, r) for i, r in enumerate(package['relocations']) if r['lo'] == image_at)
        reloc_at = 48 + len(package['package']) + image_index * 32

        def mutate(name, offset, fmt, value, expected):
            changed = bytearray(raw)
            struct.pack_into(fmt, changed, offset, value)
            replay(name, changed, uses, expected)

        mutate('zero-grid', 48 + 4 * (launch['word'] + 2), '<I', 0, -122)
        mutate('grid-register-disagreement', 48 + 4 * (launch['word'] + 2), '<I', launch['payload'][1] + 1, -122)
        mutate('dispatch-reserved-word', 48 + 4 * (launch['word'] + 1), '<I', 1, -122)
        mutate('global-range-disagreement', 48 + 4 * register_words[decoder.reg('SP_CS_NDRANGE_1')], '<I', 1, -122)
        mutate('nonzero-global-offset', 48 + 4 * register_words[decoder.reg('SP_CS_NDRANGE_2')], '<I', 1, -122)
        mutate('last-local-disagreement', 48 + 4 * register_words[decoder.reg('SP_CS_NDRANGE_7')], '<I', 0, -122)
        mutate('storage-without-write', reloc_at + 9, 'B', 1, -124)
        mutate('storage-short-extent', reloc_at + 24, '<Q', image['length'] - 1, -126)
        mutate('storage-nonzero-hole', 48 + table['offset'] + 8, '<I', 1, -124)
        mutate('storage-wrong-format', 48 + image_at + 12, '<I', 0, -122)
        mutate('storage-extra-plane-address', 48 + image_at + 16, '<I', 64, -122)
        mutate('storage-zero-width-height', 48 + image_at + 8, '<I', 0, -122)
        mutate('storage-zero-pitch', 48 + image_at + 24, '<I', 0, -122)
        mutate('storage-short-high-address-field', reloc_at + 11, 'B', 16, -124)
        assert all(sha(path) == digest for path, digest in report['inputs'].items()), 'inputs changed during replay'
        report['status'] = 'PASS_COMPUTE_ADMISSION'
    except BaseException as error:
        report['status'] = 'FAILED'
        report['error'] = str(error)
        raise
    finally:
        report['artifacts'] = {str(path.relative_to(out)): sha(path) for path in out.rglob('*')
                               if path.is_file() and path != out / 'qualification.json'}
        save()
    print('PASS_COMPUTE_ADMISSION:', len(packages), 'production packages,', len(report['replays']) - len(packages),
          'pre-ring refusal controls; no ir3 execution')


if __name__ == '__main__':
    main()
