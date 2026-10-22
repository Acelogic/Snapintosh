# SPDX-License-Identifier: MIT
"""Firmware-time PCIe reset binding for the selected virtual guest board.

This resolves a platform-function descriptor, not a PCIe controller or DMA
backend. The referenced GPIO model owns the reset line entirely in software.
"""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class PCIEResetBootSpec:
    bridge: str
    gpio: str
    variant: str
    pin: int


def populate_pcie_reset(dt, specs):
    updates = []
    seen = set()
    for spec in specs:
        if spec.bridge in seen:
            raise ValueError('duplicate PCIe reset binding')
        seen.add(spec.bridge)
        if (dt.get(spec.bridge, 'compatible') != b'apcie-bridge\0' or
                dt.get(spec.gpio, 'compatible') != b'gpio,t8101\0' or
                spec.variant not in ('tupai', 'tahiti')):
            raise ValueError('unsupported PCIe reset binding')

        def resolved(path, key, sizes):
            prop = dt.nodes[path].get(key)
            if prop is None or prop.placeholder or len(prop) not in sizes:
                raise ValueError(f'{path}: invalid {key} for PCIe reset')
            return bytes(prop.value)

        phandle = resolved(spec.gpio, 'AAPL,phandle', (4,))
        count, = struct.unpack('<I', resolved(spec.gpio, '#gpio-pins', (4,)))
        if phandle == bytes(4) or not 0 <= spec.pin < count:
            raise ValueError('PCIe reset GPIO is outside the provider')
        payload = resolved(spec.bridge, 'function-perst-'+spec.variant, (12,))
        if payload != b'OIPG'+struct.pack('<2I', spec.pin, 0):
            raise ValueError('PCIe reset variant differs from the selected virtual wiring')
        original = resolved(spec.bridge, 'function-perst', (4,16))
        complete = phandle+payload
        if original not in (phandle, complete):
            raise ValueError('PCIe reset provider or completed function differs')
        if original != complete:
            updates.append((spec.bridge, complete))
    for path, value in updates:
        dt.put(path, 'function-perst', value)
