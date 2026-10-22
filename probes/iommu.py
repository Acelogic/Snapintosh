# SPDX-License-Identifier: MIT
"""Guest DART identities supplied by the loader, independent of host IOMMUs.

This registry supplies the monitor's device namespace. It neither enables DMA
nor acknowledges device operations; those need a separate runtime backend.
"""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class DARTBootSpec:
    abi: str
    bus: str
    compatible: tuple[bytes, ...]
    page_size: int
    id_limit: int = 256
    apf_abi: str | None = None


@dataclass(frozen=True)
class DARTDevice:
    device_id: int
    path: str
    compatible: bytes
    windows: tuple[tuple[int, int], ...]  # guest physical addresses, never host MMIO
    sid_count: int
    page_size: int


@dataclass(frozen=True)
class DARTAPFSlice:
    path: str
    instance: int
    index: int
    first: int
    last: int


def validate_apf_memory(slices, excluded):
    """APF device ranges must not alias any mapped guest/monitor resource.

    Check the entire intersected 16K page, conservatively including the last
    endpoint. This is an address-classification check, never a DMA grant.
    """
    for base, size in excluded:
        if base < 0 or size <= 0 or base+size > 1 << 36:
            raise ValueError('invalid APF exclusion range')
        for item in slices:
            low = item.first & ~0x3fff
            high = (item.last | 0x3fff)+1
            if low < base+size and base < high:
                raise ValueError(f'{item.path}: APF device slice overlaps owned memory')


def populate_dart_apf_exceptions(dt, spec, devices, dram_base, excluded):
    """Describe device slices above relocated DRAM through the stock ABI.

    AppleT8110DART::_apfSetupInstance uses chosen/dram-base as an address
    threshold, not a bounded RAM interval. Low guest RAM therefore needs
    explicit allow-dram-apf-slices indices for high virtual device ranges.
    Only resolved firmware device slices inside the arm-io physical ranges
    and outside all owned memory qualify. Preserve the APF records exactly;
    this neither implements DART nor changes stage-2 access permissions.
    """
    if (spec.apf_abi != 't8110-52-v1' or spec.page_size != 0x4000 or
            not 0 < dram_base < 1 << 36):
        raise ValueError('unsupported DART APF relocation contract')
    raw = dt.nodes[spec.bus].get('ranges')
    if raw is None or raw.placeholder or not len(raw) or len(raw) % 24:
        raise ValueError('APF requires resolved arm-io address ranges')
    windows = []
    for child, parent, size in struct.iter_unpack('<3Q', raw.value):
        if not size or child+size > 1 << 48 or parent+size > 1 << 48:
            raise ValueError('invalid APF bus address range')
        windows.append((parent, parent+size))
    slices, updates = [], []
    for device in devices:
        node = dt.nodes[device.path]
        for key, prop in node.items():
            if not key.startswith('dapf-instance-'):
                continue
            suffix = key[len('dapf-instance-'):]
            if (device.compatible != b'dart,t8110' or not suffix.isdecimal() or
                    str(int(suffix)) != suffix or int(suffix) >= 32 or
                    prop.placeholder or not len(prop) or len(prop) % 52 or len(prop) >= 65*52):
                raise ValueError(f'{device.path}: unsupported APF record geometry')
            instance, count = int(suffix), len(prop)//52
            allow_name = f'allow-dram-apf-slices-{instance}'
            previous = node.get(allow_name)
            indices = set()
            if previous is not None:
                if previous.placeholder or not len(previous) or len(previous) % 4:
                    raise ValueError(f'{device.path}: invalid APF exception property')
                values = struct.unpack(f'<{len(previous)//4}I', previous.value)
                indices = set(values)
                if len(values) != len(indices) or any(i >= count for i in indices):
                    raise ValueError(f'{device.path}: invalid APF exception index')
            for index in range(count):
                first, last = struct.unpack_from('<2Q', prop.value, index*52)
                if (first > last or last >= 1 << 36 or
                        not any(low <= first and last < high for low, high in windows)):
                    raise ValueError(f'{device.path}: APF slice is not a declared device range')
                slices.append(DARTAPFSlice(device.path, instance, index, first, last))
                if last >= dram_base:
                    indices.add(index)
            if indices:
                value = struct.pack(f'<{len(indices)}I', *sorted(indices))
                if previous is None or previous.value != value:
                    updates.append((device.path, allow_name, value))
    validate_apf_memory(slices, excluded)
    # Commit only after every node and resource exclusion has passed.
    for path, key, value in updates:
        dt.put(path, key, value)
    return tuple(slices)


def populate_dart_ids(dt, spec, windows):
    """Validate the complete registry before adding any missing dart-id.

    The audited driver requires a four-byte OSData property and SPTM requires
    unique IDs below 256. IDs are monitor-owned handles: retain existing valid
    values, then assign unused IDs in path order. All operations must resolve
    them through this registry instead of treating an ID as a host device.
    """
    if (spec.abi != 'sptm-dart-v1' or spec.id_limit != 256
            or spec.page_size != 0x4000 or not spec.compatible):
        raise ValueError('unsupported DART boot contract')
    if spec.bus not in dt.nodes:
        raise ValueError('DART guest bus is missing')
    pending, used = [], set()
    prefix = spec.bus + '/'
    for path in sorted(dt.nodes):
        if not path.startswith(prefix) or '/' in path[len(prefix):]:
            continue
        if dt.get(path, 'device_type') != b'dart\0':
            continue
        compatible = dt.get(path, 'compatible') or b''
        matched = [value for value in spec.compatible if value in compatible.split(b'\0')]
        if not compatible.endswith(b'\0') or len(matched) != 1:
            raise ValueError(f'{path}: unsupported DART compatible')

        def word(name):
            prop = dt.nodes[path].get(name)
            if prop is None or prop.placeholder or len(prop) != 4:
                raise ValueError(f'{path}: {name} must be a resolved four-byte property')
            return struct.unpack('<I', prop.value)[0]

        page_size, sid_count = word('page-size'), word('sid-count')
        if page_size != spec.page_size or not 1 <= sid_count <= 256:
            raise ValueError(f'{path}: unsupported DART geometry')
        spans = tuple(windows(path))
        if not spans:
            raise ValueError(f'{path}: no DART register windows')
        ordered = sorted(spans)
        for n, (pa, size) in enumerate(ordered):
            if pa < 0 or size <= 0 or pa+size > 1 << 48 or (pa | size) & 0x3fff:
                raise ValueError(f'{path}: invalid DART register window')
            if n and ordered[n-1][0]+ordered[n-1][1] > pa:
                raise ValueError(f'{path}: overlapping DART register windows')
        device_id = word('dart-id') if 'dart-id' in dt.nodes[path] else None
        if device_id is not None:
            if device_id >= spec.id_limit or device_id in used:
                raise ValueError(f'{path}: duplicate or out-of-range DART ID')
            used.add(device_id)
        pending.append((path, matched[0], spans, sid_count, page_size, device_id))
    if not pending or len(pending) > spec.id_limit:
        raise ValueError('empty or oversized DART registry')
    available = iter(value for value in range(spec.id_limit) if value not in used)
    registry, additions = [], []
    for path, compatible, spans, sid_count, page_size, device_id in pending:
        if device_id is None:
            device_id = next(available)
            additions.append((path, device_id))
        registry.append(DARTDevice(device_id, path, compatible, spans, sid_count, page_size))
    for path, device_id in additions:
        dt.add(path, 'dart-id', struct.pack('<I', device_id))
    return tuple(registry)
