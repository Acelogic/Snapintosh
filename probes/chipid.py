# SPDX-License-Identifier: MIT
"""Publish the selected virtual SoC identity, separate from host identity."""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class ChipIDBootSpec:
    chip_id: int
    root_compatible: bytes
    arm_io_compatible: bytes
    board_id: int | None = None
    certificate_production_status: bool | None = None
    security_domain: int | None = None


def _check_binding(dt, spec):
    for path, binding in (('/device-tree', spec.root_compatible),
                          ('/device-tree/arm-io', spec.arm_io_compatible)):
        prop = dt.nodes.get(path, {}).get('compatible')
        if (not binding or b'\0' in binding or prop is None or prop.placeholder
                or binding not in prop.value.split(b'\0')):
            raise ValueError(f'{path}: unsupported guest chip binding')


def _populate_identity_field(dt, spec, name, value):
    _check_binding(dt, spec)
    chosen = '/device-tree/chosen'
    encoded = struct.pack('<I', value)
    prop = dt.nodes.get(chosen, {}).get(name)
    if (prop is None or prop.placeholder or len(prop.value) != 4
            or prop.value not in (bytes(4), encoded)):
        raise ValueError(f'missing, malformed or conflicting guest {name}')
    dt.put(chosen, name, encoded)


def populate_chip_id(dt, spec):
    """Publish the virtual SoC ID required by SEPROMPanicBuffer.

    This is not a host CPUID, unique hardware identity or SEP authentication.
    """
    if type(spec.chip_id) is not int or not 0 < spec.chip_id <= 0xffffffff:
        raise ValueError('guest chip ID must be a nonzero u32')
    _populate_identity_field(dt, spec, 'chip-id', spec.chip_id)
    return spec.chip_id


def populate_board_id(dt, spec):
    """Publish the selected virtual board read by Image4::_darwinGetBoardId."""
    if spec.board_id is None:
        return None
    if type(spec.board_id) is not int or not 0 <= spec.board_id <= 0xffffffff:
        raise ValueError('guest board ID must be a u32')
    _populate_identity_field(dt, spec, 'board-id', spec.board_id)
    return spec.board_id


def populate_image4_identity(dt, spec):
    """Publish a profile's fixed Image4 identity after chip/board publication.

    These describe the selected virtual guest, never the Qualcomm host. Values
    come from the pinned profile, not the manifest being evaluated. Profiles
    without this contract retain their prior tree byte-for-byte.
    """
    production, domain = spec.certificate_production_status, spec.security_domain
    if production is None and domain is None:
        return None
    if (type(production) is not bool or type(domain) is not int
            or not 0 <= domain <= 0xffffffff or spec.board_id is None):
        raise ValueError('incomplete or malformed guest Image4 identity')
    _check_binding(dt, spec)
    chosen = '/device-tree/chosen'
    for name, value in (('chip-id', spec.chip_id), ('board-id', spec.board_id)):
        prop = dt.nodes.get(chosen, {}).get(name)
        if (type(value) is not int or not 0 <= value <= 0xffffffff or prop is None
                or prop.placeholder or prop.value != struct.pack('<I', value)):
            raise ValueError(f'guest Image4 identity conflicts with {name}')
    fields = (('certificate-production-status', int(production)), ('security-domain', domain))
    # Validate both fields before publishing either. The extracted J700 tree
    # has CPRO=0 and no SDOM; an already personalized conflicting value refuses.
    for name, value in fields:
        prop = dt.nodes.get(chosen, {}).get(name)
        if prop is None and name == 'security-domain':
            continue
        if (prop is None or prop.placeholder or len(prop.value) != 4
                or prop.value not in (bytes(4), struct.pack('<I', value))):
            raise ValueError(f'malformed or conflicting guest {name}')
    for name, value in fields:
        dt.put(chosen, name, struct.pack('<I', value))
    return production, domain
