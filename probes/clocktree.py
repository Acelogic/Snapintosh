# SPDX-License-Identifier: MIT
"""Audited AppleARMIO nclk binding to the guest's virtual timebase."""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class CounterClockBootSpec:
    provider: str
    provider_compatible: bytes
    source_cpu: str
    consumer: str
    consumer_compatible: bytes
    consumer_index: int
    clock_id: int


def populate_counter_clock(dt, spec, frequency):
    """Supply the running CPU's fixed-frequency, used by base clock ID 4.

    This supplies the virtual counter's frequency, not a physical peripheral
    clock or permission to access the watchdog registers on the host.
    """
    if type(frequency) is not int or not 0 < frequency <= 0xffffffff:
        raise ValueError('virtual counter frequency must be a nonzero u32')
    for node, compatible in ((spec.provider, spec.provider_compatible),
                             (spec.consumer, spec.consumer_compatible)):
        if compatible not in (dt.get(node, 'compatible') or b'').split(b'\0'):
            raise ValueError(f'{node}: unaudited counter-clock binding')
    ids = dt.get(spec.consumer, 'clock-ids')
    # AppleARMIO's six base clocks are synthesized from gPEClockFrequencyInfo.
    # ID 4 (nclk) uses fix_frequency_hz; it does not index the DT's opaque
    # clock-frequencies blob. Reject a dynamic-clock override until audited.
    if (spec.clock_id != 4 or
            dt.get(spec.provider, 'clock-frequencies-nclk') is not None or
            dt.get(spec.source_cpu, 'state') != b'running\0'):
        raise ValueError('unaudited fixed-clock source or inventory override')
    if (ids is None or len(ids) % 4 or
            not 0 <= spec.consumer_index < len(ids) // 4 or
            struct.unpack_from('<I', ids, spec.consumer_index * 4)[0] != spec.clock_id):
        raise ValueError('consumer counter clock ID mismatch')
    previous = dt.get(spec.source_cpu, 'fixed-frequency')
    if previous is not None and (len(previous) not in (4, 8) or
                                int.from_bytes(previous, 'little') not in (0, frequency)):
        raise ValueError('fixed clock has a conflicting supplied frequency')
    dt.put(spec.source_cpu, 'fixed-frequency', struct.pack('<I', frequency))
