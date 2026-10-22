# SPDX-License-Identifier: MIT
"""Bounded read-only SEP discovery inventory for the pinned J700 26A428 kernel.

The caller must verify kernel identity, resident monitor and terminal stop
before supplying a guest-virtual reader. This does not enable endpoints or
write mailbox replies. Control endpoints 0xfd/0xff are outside the 32-entry
normal endpoint array; the manager owns them separately.
"""
import struct


ENDPOINTS = 0xfffffe000c8f74c8
WITNESSES = (
    (0xfffffe00099cc838, 0x71007c1f),  # endpointWithIndex: index <= 31
    (0xfffffe00099cc844, 0xf0017949),
    (0xfffffe00099cc848, 0x91132129),  # normal endpoint array
    (0xfffffe00099cc45c, 0xf9003a60),  # endpoint manager at +0x70
    (0xfffffe00099cc994, 0x39418261),  # endpoint ID at +0x60
    (0xfffffe00099b3980, 0xf9007660),  # manager booter at +0xe8
    (0xfffffe00099b3990, 0xf9007a60),  # manager discovery at +0xf0
    (0xfffffe00099b3d9c, 0xf9007260),  # manager firmware at +0xe0
    (0xfffffe00099b8208, 0xb940de68),  # native send gate state at +0xdc
    (0xfffffe00099bafa4, 0x39033e75),  # both effective-status properties installed, +0xcf
    (0xfffffe00099c7e84, 0xb941b529),  # SEP page mode at manager +0x1b4
    (0xfffffe00099b0f74, 0x9102a66b),  # packed discovery records at +0xa9
    (0xfffffe00099b0f78, 0xf9454a6a),  # record count at +0xa90
    (0xfffffe00099b1188, 0xf103f55f),  # at most 253 advertisements
    (0xfffffe00099b113c, 0x39000148),  # OOL-advertisement flag
    (0xfffffe00099b1144, 0x39001948),
    (0xfffffe00099b114c, 0x39001d48),
    (0xfffffe00099b1154, 0x39002148),
    (0xfffffe00099b115c, 0x39002548),
    (0xfffffe00099b85a8, 0xb940c809),  # power state is distinct from send state
    (0xfffffe00099b8aa4, 0xb940da68),  # retained resume field at +0xd8
    (0xfffffe00099b344c, 0xf900c260),  # copyMapperForDevice result at +0x180
    (0xfffffe00099b345c, 0xf900c660),  # copyMapperForDeviceWithIndex(1) at +0x188
    (0xfffffe00099b5710, 0xf9409660),  # shared memory at +0x128
    (0xfffffe00099b6198, 0xa9137e7f),  # initialize channel PA/IOVA at +0x130/+0x138
    (0xfffffe00099b62ec, 0xa9532668),  # report the two distinct channel addresses
    (0xfffffe00099b89a8, 0xb941c268),  # hibernate boot counter at +0x1c0
    (0xfffffe00099b8664, 0xb901be68),  # IOHibernateState at +0x1bc
    (0xfffffe00099bf1b4, 0x79416408),  # booter phase at +0xb2
    (0xfffffe00099bf288, 0x3902a67f),  # booter waiting flag at +0xa9
    (0xfffffe00099bf28c, 0xf80aa274),  # last ROM response at +0xaa
    (0xfffffe00099c3788, 0xb940b800),  # firmware payload type at +0xb8
    (0xfffffe00099c3794, 0xf9404400),  # firmware descriptor at +0x88
    (0xfffffe00099c37a0, 0xf9405000),  # firmware byte length at +0xa0
    (0xfffffe00099c37ac, 0xf9404c00),  # firmware IOVA at +0x98
    (0xfffffe00099c36cc, 0xf9005ab3),  # firmware mapper at +0xb0
    (0xfffffe00099c3710, 0x39038008),  # from-preload flag at +0xe0
    (0xfffffe00099c3718, 0xf9005660),  # chosen memory-map node at +0xa8
    (0xfffffe00099c48b8, 0xf9004e68),  # native DMA-map result at +0x98
    (0xfffffe00099c48cc, 0x91034263),  # mapped patch address at +0xd0
    (0xfffffe00099c48e0, 0x91036263),  # mapped uStuff address at +0xd8
)


def collect(read, instruction):
    for address, expected in WITNESSES:
        if instruction(address) != expected:
            raise ValueError(f'SEP capture witness differs at {address:x}')

    def pointer(value):
        if not value:
            return 0
        value |= 0xffff000000000000
        if value < 0xfffffe0000000000 or value & 7:
            raise ValueError('invalid SEP object pointer')
        return value

    def q(address):
        return struct.unpack('<Q', read(address, 8))[0]

    endpoints, managers, seen = [], set(), set()
    for index, raw in enumerate(struct.unpack('<32Q', read(ENDPOINTS, 256))):
        address = pointer(raw)
        if not address:
            continue
        if address in seen:
            raise ValueError('aliased SEP endpoint objects')
        seen.add(address)
        data = read(address, 0x78)
        if data[0x60] != index:
            raise ValueError('SEP endpoint identity differs from array index')
        manager = pointer(struct.unpack_from('<Q', data, 0x70)[0])
        if not manager:
            raise ValueError('SEP endpoint has no manager')
        managers.add(manager)
        endpoints.append(dict(index=index, address=hex(address)))
    result = dict(endpoints=endpoints, manager=None, advertisements=[])
    if not endpoints:
        return result
    if len(managers) != 1:
        raise ValueError('SEP endpoint managers disagree')
    manager = managers.pop()
    firmware, booter, discovery = map(pointer, struct.unpack('<3Q', read(manager+0xe0, 24)))
    result.update(manager=hex(manager), firmware=hex(firmware),
                  booter=hex(booter), discovery=hex(discovery))
    result['send_gate_state'] = struct.unpack('<i', read(manager+0xdc, 4))[0]
    updated=read(manager+0xcf,1)[0]
    if updated not in (0,1):raise ValueError('invalid SEP effective-status update flag')
    result['effective_status_properties_updated']=bool(updated)
    mode = struct.unpack('<I', read(manager+0x1b4, 4))[0]
    result['page_mode'] = mode
    result['sep_page_size'] = 16384 if mode else 4096
    result['power_state'] = struct.unpack('<I', read(manager+0xc8, 4))[0]
    result['resume_field'] = struct.unpack('<I', read(manager+0xd8, 4))[0]
    result['shared_memory'] = hex(pointer(q(manager+0x128)))
    channel_pa, channel_iova = struct.unpack('<2Q', read(manager+0x130, 16))
    result['txm_channel'] = dict(pa=hex(channel_pa), iova=hex(channel_iova))
    primary, auxiliary = map(pointer, struct.unpack('<2Q', read(manager+0x180, 16)))
    result['firmware_mapper'] = hex(primary)
    result['auxiliary_mapper'] = hex(auxiliary)
    result['firmware_object'] = None
    if firmware:
        descriptor, mapping, iova, length, node, mapper, payload_type, patches, ustuff, patch_iova, ustuff_iova = struct.unpack(
            '<11Q', read(firmware+0x88, 88))
        preloaded = read(firmware+0xe0, 1)[0]
        if preloaded not in (0, 1):
            raise ValueError('invalid SEP firmware preload flag')
        result['firmware_object'] = dict(
            descriptor=hex(pointer(descriptor)), mapping=hex(pointer(mapping)),
            iova=hex(iova), bytes=length, memory_map_node=hex(pointer(node)),
            mapper=hex(pointer(mapper)), payload_type=payload_type & 0xffffffff,
            patch_descriptor=hex(pointer(patches)), ustuff_descriptor=hex(pointer(ustuff)),
            patch_iova=hex(patch_iova), ustuff_iova=hex(ustuff_iova), preloaded=bool(preloaded))
    result['hibernate_state'], result['hibernate_boot_count'] = struct.unpack(
        '<2I', read(manager+0x1bc, 8))
    result['rom_booter'] = None
    if booter:
        if pointer(q(booter+0x70)) != manager:
            raise ValueError('SEP booter manager differs')
        waiting, message, phase = struct.unpack('<BQH', read(booter+0xa9, 11))
        if waiting not in (0, 1):
            raise ValueError('invalid SEP booter waiting flag')
        result['rom_booter'] = dict(waiting=bool(waiting), phase=phase,
                                   last_message_hex=f'{message:016x}')
    if not discovery:
        return result
    if pointer(q(discovery+0x70)) != manager:
        raise ValueError('SEP discovery manager differs')
    count = q(discovery+0xa90)
    if count > 253:
        raise ValueError('SEP discovery count exceeds native capacity')
    data = read(discovery+0xa9, count*10) if count else b''
    ids, names = set(), set()
    for offset in range(0, len(data), 10):
        record = data[offset:offset+10]
        ready, name, endpoint, *sizes = struct.unpack('<BIB4B', record)
        if ready not in (0, 1) or endpoint in ids or name in names:
            raise ValueError('invalid or duplicate SEP advertisement')
        ids.add(endpoint)
        names.add(name)
        result['advertisements'].append(dict(endpoint=endpoint,
            name_hex=f'{name:08x}', ool_advertised=bool(ready),
            ool_size_fields=sizes, raw_hex=record.hex()))
    return result
