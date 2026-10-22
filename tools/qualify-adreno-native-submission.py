#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay actual native Metal triangle commands through the production driver core.

Failure inventory: docs/ADRENO-GUI-INTEGRATION-20260927.md. The resource mappings
and GPU are modeled; the captured command bytes and driver parser are real.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def verify(path, bindings):
    record = json.loads(path.read_text())
    bindings[str(path)] = sha(path)
    for key, root in [('sources_sha256', ROOT), ('artifacts_sha256', path.parent),
                      ('q1n1_sha256', ROOT.parent/'q1n1/tools'), ('external_sha256', ROOT)]:
        for name, digest in record.get(key, {}).items():
            p = root/name
            assert sha(p) == digest, (key, name)
            bindings[str(p)] = digest
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--draw', type=Path, required=True)
    ap.add_argument('--driver', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    bindings = {}
    draw_path, driver_path = args.draw.resolve(), args.driver.resolve()
    draw, driver = [verify(p, bindings) for p in (draw_path, driver_path)]
    assert draw['status'] == 'ADRENO_DRAW_PACKAGES_MATCH_PLAN_AND_MODEL'
    assert driver['status'] == 'KEXT_IB_PATH_HOST_QUALIFIED_NOT_INSTALLED'
    assert driver['monitor_ib_linked'] and draw['cases']['plan-v2-clear']['result'] == 'PASS'
    capture = draw_path.parent/'plan-v2-clear'
    resources = json.loads((capture/'resources.json').read_text())['published']
    command_bytes = (capture/'commands.bin').read_bytes()
    kind, size, version, flags, words, data_bytes, count, reserved, r1, r2 = struct.unpack_from('<8I2Q', command_bytes)
    assert kind == 0x1002 and version == 1 and not (flags or reserved or r1 or r2)
    package_len = ((words*4+63)//64)*64+data_bytes
    assert size == 48+package_len+32*count and len(command_bytes) == size+8
    assert command_bytes[size:] == struct.pack('<II', 0x1000, 8)
    assert 0 < len(resources) <= 6 and len({r['id'] for r in resources}) == len(resources)
    mappings = {}
    for i, resource in enumerate(resources):
        assert 0 < resource['id'] < 2**32 and 0 < resource['size'] <= 0x100000
        assert resource['usage'] in (1, 2, 3)
        mappings[(1, resource['id'])] = 0x40100000+i*0x100000
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    record = dict(status='RUNNING', started=time.time(), a16_access=False,
        gpu_submission=False, draw=str(draw_path), driver=str(driver_path),
        inputs_sha256=bindings, sources_sha256={str(Path(__file__).relative_to(ROOT)): sha(Path(__file__))})
    try:
        segment = out/'native-triangle'
        segment.mkdir()
        resource_list = bytearray(96)
        struct.pack_into('<I', resource_list, 28, 1)
        for i, resource in enumerate(resources):
            struct.pack_into('<I', resource_list, 32+4*i, resource['id'])
            struct.pack_into('<H', resource_list, 80+2*i, resource['usage'])
        struct.pack_into('<H', resource_list, 94, len(resources))
        (segment/'list.bin').write_bytes(resource_list)
        (segment/'commands.bin').write_bytes(command_bytes)
        (segment/'resources.txt').write_text(''.join(
            f"{r['id']:x} {mappings[(1,r['id'])]:x} {r['size']:x}\n" for r in resources))
        (segment/'expect.txt').write_text('0 0\n1 0\n')
        argv = [str(driver_path.parent/'test-adreno-ib-command'), '--replay', str(segment)]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60)
        (out/'replay.log').write_text(result.stdout+result.stderr)
        record['command'] = dict(argv=argv, exit_code=result.returncode)
        assert result.returncode == 0, result.returncode
        lines = (segment/'result.txt').read_text().splitlines()
        commands = [dict(zip(l.split()[::2], l.split()[1::2])) for l in lines if l.startswith('command ')]
        info = dict(l.split(' ', 1) for l in lines if not l.startswith('command '))
        assert len(commands) == 2 and info['monitor_ib'] == '1' and info['list_frozen'] == '0'
        assert info['checks'].endswith(' failures 0')
        assert all(c['result'] == c['frozen'] == c['latched'] == '0' for c in commands)
        assert commands[0]['rings'] == commands[0]['from_device'] == '1'
        assert int(commands[0]['to_device']) == len(resources)
        assert commands[1]['rings'] == '0'
        mappings[(2, 0)] = int(info['package_gpu'], 16)
        mappings[(3, 0)] = int(info['zero_gpu'], 16)
        expected = bytearray(command_bytes[48:48+package_len])
        for i in range(count):
            lo, hi, kind, access, align, high_bits, rid, offset, length = struct.unpack_from(
                '<IIBBBBIQQ', command_bytes, 48+package_len+32*i)
            assert kind in (1, 2, 3) and access in (1, 2, 3) and length > 0
            address = mappings[(kind, rid)]+offset
            assert address % (1 << align) == 0
            assert lo+4 <= len(expected)
            struct.pack_into('<I', expected, lo, struct.unpack_from('<I', expected, lo)[0] | (address & 0xffffffff))
            if hi != 0xffffffff:
                assert hi+4 <= len(expected) and 0 < high_bits <= 32
                struct.pack_into('<I', expected, hi,
                    struct.unpack_from('<I', expected, hi)[0] | ((address >> 32) & ((1 << high_bits)-1)))
        assert (segment/'package.bin').read_bytes() == expected
        assert (segment/'fetched.bin').read_bytes() == expected[:words*4]
        assert (segment/'commands.bin').read_bytes() == command_bytes
        for name, digest in bindings.items():
            assert sha(Path(name)) == digest, name
        record.update(status='NATIVE_METAL_TRIANGLE_DRIVER_CORE_REPLAY_PASS_NOT_A16',
            command_bytes=len(command_bytes), package_bytes=len(expected), relocated_fields=count,
            fetched_ib_bytes=words*4, resources=len(resources), commands=commands,
            captured_commands_sha256=sha(capture/'commands.bin'),
            boundary='Native plug-in commands and production C parser/ownership/relocation; resource mappings and CP are modeled. No shader execution or A16 pixels.')
    except BaseException as error:
        record.update(status='FAIL', error=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out/'qualification.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({k: record[k] for k in ('status', 'command_bytes', 'relocated_fields', 'fetched_ib_bytes')}))


if __name__ == '__main__':
    main()
