#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read generation47's retained texture, parent and accelerator mapping flags.

No guest calls or writes. Failure inventory: ADRENO-RESOURCE-LIFECYCLE-20260927.md.
The v1 namespace observation and all187 launch sources must still match.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'installed-metal-clear-threshold-2400s-20260927'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    assert not args.output.exists()
    capture_path = ROOT/'build'/f'{PREFIX}-resource-state-v1.json'
    assert sha(capture_path) == '4567f2bc532bf6fe9b36bdc8981a4590cfc8346ecff1ec9cdcdc9abd8f26c254'
    capture = json.loads(capture_path.read_text())
    for key in ['inputs_sha256', 'source_sha256']:
        for name, digest in capture[key].items():
            assert sha(Path(name)) == digest, name
    launch_path = ROOT/'build'/f'{PREFIX}-launch.json'
    launch = json.loads(launch_path.read_text())
    assert launch['exit_code'] == 7 and launch['finished']
    for name, digest in launch['source_sha256'].items():
        assert sha(Path(name)) == digest, name
    registry_path = ROOT/'build'/f'{PREFIX}-kernel-waits.json'
    registry = json.loads(registry_path.read_text())
    accelerator, = [row for row in registry['ioreg_state']['entries']
                    if row['class_name'] == 'AdrenoAcceleratorX2']
    assert len(capture['resources']) == 1
    resource = capture['resources'][0]
    assert resource['type'] == 0x82 and resource['map'] == '0x0'
    trace_path = ROOT/'build/adreno-resource-lifecycle-native-20260927-v1.json'
    assert sha(trace_path) == 'c7904faf7edbc6c3d45d25e08e1b8b6279e75571084e9ae77da300c96984b60e'
    reader_path = ROOT/'tools/port-receiver.py'
    tool = runpy.run_path(str(reader_path))
    if args.dry_run:
        print(json.dumps({'hardware_access': False, 'generation': 47,
                          'resource': resource['address'], 'accelerator': accelerator['address']}))
        return
    stopped = tool['open_stopped'](SimpleNamespace(prefix=PREFIX, device=args.device, page_budget=256))
    try:
        assert stopped['proxy'].bootinfo()['stage_generation'] == 47
        reads = []
        def ptr(value):
            if not value:
                return 0
            address = value | 0xffff000000000000
            assert address >= 0xffff800000000000 and address & 7 == 0
            return address
        def read(address, size):
            assert address and 0 < size <= 0x400
            raw = stopped['va_read'](address, size)
            assert len(raw) == size
            reads.append({'address': hex(address), 'bytes': size, 'data_hex': raw.hex()})
            return raw
        u64 = lambda raw, off: struct.unpack_from('<Q', raw, off)[0]
        u32 = lambda raw, off: struct.unpack_from('<I', raw, off)[0]
        # Re-establish the observed resource through the same retained namespace.
        client = read(int(capture['client']['address'], 0), 304)
        assert ptr(u64(client, 0)) == int(capture['client']['vtable'], 0)
        device_address = ptr(u64(client, 0x120))
        assert device_address == int(capture['device'], 0)
        device = read(device_address, 0x58)
        namespace_address = ptr(u64(device, 0x10))
        assert namespace_address == int(capture['namespace'], 0)
        namespace = read(namespace_address, 0x30)
        assert u32(namespace, 0x28) == capture['capacity']
        entry = read(ptr(u64(namespace, 0x10)) + 8*resource['id'], 8)
        resource_address = ptr(u64(entry, 0))
        assert resource_address == int(resource['address'], 0)
        raw = read(resource_address, 160)
        assert ptr(u64(raw, 0)) == int(resource['vtable'], 0)
        assert u32(raw, 0x10) == int(resource['flags_word'], 0) and u64(raw, 0x20) == 0
        accelerator_address = ptr(u64(raw, 0x50))
        assert accelerator_address == int(accelerator['address'], 0)
        accel = read(accelerator_address, 0x300)
        assert ptr(u64(accel, 0)) == int(accelerator['vtable'], 0)
        flags = u32(accel, 0x230)
        parent_address = ptr(u64(raw, 0x30))
        assert parent_address == ptr(int(resource['related_field'], 0))
        parent = read(parent_address, 160)
        parent_memory = ptr(u64(parent, 0x28))
        assert parent_memory
        memory_header = read(parent_memory, 64)
        stopped['recheck']()
        assert stopped['proxy'].bootinfo()['stage_generation'] == 47
        result = {'status': 'STOPPED_ADRENO_LIFECYCLE_CAPTURED', 'generation': 47,
            'prefix': PREFIX, 'hardware_writes': False, 'guest_calls': False,
            'accelerator': accelerator, 'config_flags': hex(flags),
            'native_map_enabled': bool(flags & (1 << 22)),
            'resource': resource, 'resource_offset_0x4c': u32(raw, 0x4c),
            'parent': {'address': hex(parent_address), 'type': u32(parent, 0x10)&0xff,
                       'flags': hex(u32(parent, 0x10)), 'map': hex(ptr(u64(parent, 0x20))),
                       'memory': hex(parent_memory), 'related': hex(ptr(u64(parent, 0x30)))},
            'reads': reads, 'pages_read': len(stopped['pages']), 'stop_rechecked': True,
            'inputs_sha256': {str(p): sha(p) for p in [capture_path, launch_path,
                registry_path, trace_path, ROOT/'build'/f'{PREFIX}-audit.json']},
            'source_sha256': {str(p): sha(p) for p in [Path(__file__), reader_path,
                ROOT/'tools/trace-adreno-resource-lifecycle.py']},
            'boundary': 'Stopped object fields. Native bit interpretation follows original image trace, not live code execution. No mapping, preparation, submission or pixels.'}
    finally:
        stopped['proxy'].link.close()
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ['status', 'config_flags', 'native_map_enabled',
        'resource_offset_0x4c', 'parent', 'pages_read']}))

if __name__ == '__main__':
    main()
