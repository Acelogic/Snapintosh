# SPDX-License-Identifier: MIT
"""Boot-time NVRAM images; independent of host flash or persistent storage.

CHRP v2 is audited against mac17p/26A428's IODTNVRAM parser. This supplies
an empty, valid initial variable store, not an NVRAM controller or persistence.
Other guest formats require an explicit encoder.
"""
from dataclasses import dataclass
import struct
import zlib


@dataclass(frozen=True)
class NVRAMBootSpec:
    format: str
    bank_size: int
    bank_count: int
    common_end: int

    def validate(self):
        if self.format != 'chrp-v2':
            raise ValueError('unsupported NVRAM boot format')
        # Each partition has a u16 length measured in 16-byte blocks.
        if not (0x60 <= self.bank_size <= 0xffff0) or self.bank_size % 16:
            raise ValueError('invalid NVRAM bank size')
        if not (0x40 <= self.common_end <= self.bank_size - 0x20) or self.common_end % 16:
            raise ValueError('invalid NVRAM common partition boundary')
        if not (1 <= self.bank_count <= 0xffffffff):
            raise ValueError('invalid NVRAM bank count')


def _header(signature, size, name):
    header = bytearray(struct.pack('<BBH12s', signature, 0, size // 16, name))
    checksum = header[0] + sum(header[2:])
    while checksum > 255:
        checksum = (checksum & 255) + (checksum >> 8)
    header[1] = checksum
    return header


def empty_bank(spec):
    """A complete CHRP v2 bank with empty common and system partitions.

    The Apple header occupies 32 bytes, followed by common through the
    profile's boundary, then system through the end of the bank. All lengths
    include their header. Adler-32 covers generation at +20 through bank end.
    """
    spec.validate()
    bank = bytearray(spec.bank_size)
    bank[:16] = _header(0x5a, 32, b'2nvram')
    bank[32:48] = _header(0x70, spec.common_end - 32, b'2common')
    bank[spec.common_end:spec.common_end + 16] = _header(
        0x70, spec.bank_size - spec.common_end, b'2system')
    struct.pack_into('<I', bank, 20, 1)  # Initial generation.
    struct.pack_into('<I', bank, 16, zlib.adler32(bank[20:]))
    return bytes(bank)


def populate_boot_nvram(dt, spec):
    """Fill only the audited empty iBoot inputs, failing before any mutation.

    A profile with existing variable data needs an explicit import policy;
    never silently replace it with a fresh empty store.
    """
    bank = empty_bank(spec)
    chosen = '/device-tree/chosen'
    image = dt.get(chosen, 'nvram-proxy-data')
    if image is None or len(image) != spec.bank_size or any(image):
        raise ValueError('NVRAM proxy must be the audited empty bank reservation')
    for name in ('nvram-bank-size', 'nvram-bank-count', 'nvram-current-bank'):
        if dt.get(chosen, name) != bytes(4):
            raise ValueError(f'NVRAM {name} must be an empty u32 boot input')
    dt.set(chosen, 'nvram-proxy-data', bank)
    dt.set_u32(chosen, 'nvram-bank-size', spec.bank_size)
    dt.set_u32(chosen, 'nvram-bank-count', spec.bank_count)
    dt.set_u32(chosen, 'nvram-current-bank', 0)
