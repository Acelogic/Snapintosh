#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read firmware pointer selection from ACPI NVS after a qualified guest stop.

Failure inventory: docs/A16-INPUT-VARIANT-NVS-20260928.md.
--check-inputs is offline. No I2C transaction or device initialization is issued.
"""
from pathlib import Path
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
DSL = ROOT.parent / 'q1n1/build/a16-acpi/DSDT.dsl'
DSL_SHA = '34b9c2f178c994dbea199cffe4ffbe77e7e7dc0435a247904e2e558b44e17a0b'
BASE_READER = ROOT / 'tools/survey-a16-input.py'
BASE_READER_SHA = '3806a6af287ee293e08b862aa091e30219d320ef69fd9119b0b567800d1274d0'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def derive_plan():
    assert sha(DSL) == DSL_SHA
    text = DSL.read_text()
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    regions = {}
    specifications = {
        'RAMW': ('AAML', 0x100, {'AECB': (12, 4), 'ASIB': (16, 4)}),
        'OGNV': ('IECL', 0x100, {'OEMB': (4, 4)}),
        'AECO': ('AECB', 0x1b, {'DSYN': (10, 1)}),
        'ASIO': ('ASIB', 0x0e, {'TPHI': (8, 1)}),
        'OEMC': ('OEMB', 0x80, {'PJID': (7, 1), 'TOUP': (8, 1)}),
    }
    for name, (base, extent, expected) in specifications.items():
        declaration = re.findall(r'OperationRegion\s*\(\s*' + name +
            r'\s*,\s*SystemMemory\s*,\s*\\_SB\.' + base + r'\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)', text)
        assert len(declaration) == 1 and int(declaration[0], 0) == extent, name
        fields = re.findall(r'Field\s*\(\s*' + name + r'\s*,\s*AnyAcc\s*,\s*NoLock\s*,\s*Preserve\s*\)\s*\{([^}]+)\}', text)
        assert len(fields) == 1, name
        body, offset, consumed, found = fields[0], 0, 0, {}
        token = re.compile(r'([A-Z_][A-Z0-9_]{3})\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*,?|Offset\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*,?')
        for match in token.finditer(body):
            assert not body[consumed:match.start()].strip(), ('unsupported field syntax', name)
            consumed = match.end()
            if match[3]:
                target = int(match[3], 0) * 8
                assert target >= offset
                offset = target
            else:
                field, bits = match[1], int(match[2], 0)
                assert field not in found and bits > 0 and offset + bits <= extent * 8
                found[field] = (offset, bits)
                offset += bits
        assert not body[consumed:].strip(), ('unsupported field tail', name)
        for field, (byte_offset, byte_length) in expected.items():
            assert found[field] == (byte_offset * 8, byte_length * 8), field
        regions[name] = dict(base_symbol=base, length=extent,
                             fields={k: dict(offset=v[0], length=v[1]) for k, v in expected.items()})
    roots = {}
    for name, expected in [('AAML', 0xd6d90000), ('IECL', 0xd6d80000)]:
        values = re.findall(r'Name\s*\(\s*' + name + r'\s*,\s*(0x[0-9A-Fa-f]+)\s*\)', text)
        assert len(values) == 1 and int(values[0], 0) == expected
        roots[name] = expected
    return dict(dsl_sha256=DSL_SHA, roots=roots, regions=regions,
                required_efi_memory_type=10, repetitions=2,
                boundary='Firmware selection only; physical HID response and input delivery unverified')


def capture_variant(proxy, info, record, output):
    plan = derive_plan()
    result = record['firmware_selection'] = dict(status='READING', plan=plan, attempts=[], reads=[])

    def save():
        output.write_text(json.dumps(record, indent=2) + '\n')

    def read(address, count, label):
        row = dict(label=label, address=hex(address), length=count, completed=False)
        result['reads'].append(row)
        save()
        data = b''.join(proxy.readmem(address + at, min(65536, count - at), live=True)
                        for at in range(0, count, 65536))
        assert len(data) == count, 'short native memory read'
        row.update(completed=True, sha256=hashlib.sha256(data).hexdigest())
        save()
        return data

    address, length, stride = [info[k] for k in ('memory_map', 'memory_map_size', 'memory_map_stride')]
    assert address and 40 <= stride <= 256 and stride % 8 == 0
    assert 0 < length <= 512 * 1024 and length % stride == 0
    assert info['memory_map_version'] == 1
    raw_map = read(address, length, 'retained EFI memory map')
    regions = []
    for offset in range(0, length, stride):
        kind, _pad, base, _virtual, pages, attributes = struct.unpack_from('<IIQQQQ', raw_map, offset)
        assert base % 4096 == 0 and pages and base + pages * 4096 <= 1 << 64
        regions.append(dict(type=kind, base=base, length=pages * 4096, attributes=attributes))
    result.update(memory_map_hex=raw_map.hex(), memory_map_stride=stride,
                  memory_map_sha256=hashlib.sha256(raw_map).hexdigest())

    def nvs(address, count, label):
        assert address and address % 4 == 0 and 0 < count <= 256
        assert address + count <= 1 << 64
        covering = [r for r in regions if r['base'] <= address and address + count <= r['base'] + r['length']]
        assert len(covering) == 1 and covering[0]['type'] == 10, ('range is not EFI ACPI NVS', label, hex(address), count, covering)
        return read(address, count, label), covering[0]

    def integer(blob, offset, length):
        return int.from_bytes(blob[offset:offset + length], 'little')

    selections = []
    for attempt in range(2):
        row = dict(attempt=attempt + 1, regions={}, fields={}, signatures={})
        result['attempts'].append(row)
        blobs = {}
        addresses = dict(RAMW=plan['roots']['AAML'], OGNV=plan['roots']['IECL'])
        for name in ('RAMW', 'OGNV', 'AECO', 'ASIO', 'OEMC'):
            description = plan['regions'][name]
            if name not in addresses:
                addresses[name] = row['fields'][description['base_symbol']]
            blob, covering = nvs(addresses[name], description['length'], f'{name} attempt{attempt + 1}')
            blobs[name] = blob
            row['regions'][name] = dict(address=hex(addresses[name]), raw_hex=blob.hex(), efi_region=covering)
            row['signatures'][name] = blob[:4].hex()
            for field, location in description['fields'].items():
                row['fields'][field] = integer(blob, **location)
            save()
        for name in ('RAMW', 'OGNV'):
            again, _ = nvs(addresses[name], plan['regions'][name]['length'], f'{name} pointer recheck{attempt + 1}')
            for field, location in plan['regions'][name]['fields'].items():
                assert integer(again, **location) == row['fields'][field], 'firmware pointer changed during child read'
        selections.append(dict(fields=row['fields'], signatures=row['signatures']))
        state = row['guard_after'] = proxy.serror_state()
        assert state['mechanism'] and not any(state[k] for k in ('before', 'during', 'unconsumed'))
        save()
    assert selections[0] == selections[1], 'firmware selection changed between captures'
    values = selections[0]['fields']
    branches = {0: (1, 'ASCE1206', 'ASCF1206'), 1: (3, 'ASUF1209', 'ASUP1209'),
                2: (5, 'ASCF120C', 'ASCP1201'), 3: (3, 'ASUF1209', 'ASUP1207')}
    branch = branches.get(values['PJID'])
    model = None if branch is None else branch[1 if values['TPHI'] == branch[0] else 2]
    result['result'] = dict(settings={k: values[k] for k in ('DSYN', 'TPHI', 'PJID', 'TOUP')},
        touchpad_present=bool(values['DSYN']), touchpad_firmware_hid=model,
        touchpad_hid_resolved=branch is not None,
        touchscreen_present=values['TOUP'] == 1, touchscreen_firmware_hid='MSFT0001',
        boundary='Firmware declarations evaluated; no peripheral response or guest input proof')
    result['status'] = 'TWO_STABLE_NVS_SELECTION_CAPTURES'
    save()


def main():
    plan = derive_plan()
    assert sha(BASE_READER) == BASE_READER_SHA
    source = BASE_READER.read_text()
    old = "    try:\n        os.kill(launch['pid'],0)\n    except ProcessLookupError:\n        pass\n    else:\n        raise RuntimeError('XNU launcher remains live')"
    new = """    from datetime import datetime, timezone
    import subprocess
    observed = subprocess.run(['ps', '-p', str(launch['pid']), '-o', 'lstart='],
        env=dict(os.environ, TZ='UTC', LC_ALL='C'), capture_output=True, text=True)
    if observed.stdout.strip():
        started = datetime.strptime(observed.stdout.strip(), '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
        assert started > launch['finished'], 'original launcher may still be present'
    else:
        assert observed.returncode == 1 and not observed.stderr.strip(), observed.stderr"""
    assert source.count(old) == 1
    source = source.replace(old, new)
    anchor = '    if args.check_inputs:'
    assert source.count(anchor) == 1
    source = source.replace(anchor,
        "    record['operation'] = 'READ_ACPI_NVS_INPUT_VARIANT'\n"
        "    record['boundary'] = 'Read-only firmware selection; no controller access or input proof'\n"
        "    record['firmware_plan'] = " + repr(plan) + '\n' + anchor)
    first = source.index('        for name,offset in REGISTERS:')
    last = source.index('        proxy.read64(previous', first)
    source = source[:first] + '        capture_variant(proxy, info, record, args.output)\n' + source[last:]
    first = source.index('        values = ')
    last = source.index("        record['status']=", first)
    source = source[:first] + "        record['interpretation'] = record['firmware_selection']['result']\n" + source[last:]
    source = source.replace('STOPPED_IC20_REGISTERS_CAPTURED', 'STOPPED_A16_INPUT_VARIANT_CAPTURED')
    exec(compile(source, str(BASE_READER), 'exec'), dict(__file__=__file__, __name__='__main__',
                                                      capture_variant=capture_variant))


if __name__ == '__main__':
    main()
