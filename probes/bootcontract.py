# SPDX-License-Identifier: MIT
"""Inputs shared by guest loaders and host adapters; no board addresses here.

An adapter describes resources it actually owns. A guest loader decides how
its boot ABI represents them. Neither may turn holes into usable memory.
"""
from dataclasses import dataclass
from monitor_work import locator_address


@dataclass(frozen=True)
class PhysicalRange:
    base: int
    size: int
    name: str

    @property
    def end(self):
        return self.base + self.size

    def validate(self, page_shift=14, address_bits=36):
        if self.base < 0 or self.size <= 0 or self.end > 1 << address_bits:
            raise ValueError(f'{self.name}: invalid {address_bits}-bit physical range')
        if (self.base | self.size) & ((1 << page_shift) - 1):
            raise ValueError(f'{self.name}: range is not {1 << page_shift}-byte aligned')
        return self


def checked_ranges(ranges, page_shift=14, address_bits=36):
    ranges = tuple(sorted(ranges, key=lambda r: r.base))
    if not ranges:
        raise ValueError('no physical ranges supplied')
    for i, region in enumerate(ranges):
        region.validate(page_shift, address_bits)
        if i and region.base < ranges[i - 1].end:
            raise ValueError(f'{region.name} overlaps {ranges[i - 1].name}')
    return ranges


@dataclass(frozen=True)
class Framebuffer:
    base: int
    width: int
    height: int
    stride: int                 # bytes, never pixels
    depth: int

    def physical_range(self, page_shift=14):
        if self.base <= 0 or self.width <= 0 or self.height <= 0:
            raise ValueError('framebuffer: base and geometry must be positive')
        if self.depth != 32 or self.stride < self.width * 4 or self.stride % 4:
            raise ValueError('framebuffer: expected 32-bit pixels and a valid byte stride')
        page = 1 << page_shift
        lo = self.base & -page
        hi = (self.base + self.stride * self.height + page - 1) & -page
        return PhysicalRange(lo, hi - lo, 'panel')

    def boot_video(self):
        return self.base, self.width, self.height, self.stride, self.depth


@dataclass(frozen=True)
class HostRuntime:
    """Transport-independent facts; additional adapters return this contract.

    CPU feature checks still run at EL2 before guest entry. A valid descriptor
    is not a claim that a new CPU implements the required NV2/debug features.
    """
    adapter: str
    timer_hz: int
    heap: PhysicalRange
    framebuffer: Framebuffer | None

    @classmethod
    def from_q1n1(cls, info, *, with_framebuffer=False):
        if info.get('current_el') != 2:
            raise ValueError('q1n1 host adapter requires EL2')
        hz = info.get('timer_hz', 0)
        if not isinstance(hz, int) or not 0 < hz < 1 << 32:
            raise ValueError('q1n1 must report a nonzero 32-bit timer_hz')
        heap = PhysicalRange(info.get('heap_base', 0), info.get('heap_size', 0),
                             'q1n1 heap').validate(12)
        # Code/output/config remain below +5 MiB. The work arena is separately
        # reserved firmware RAM; only its checked locator lives in this heap.
        locator_address(info)
        fb = None
        if with_framebuffer:
            fmt = info.get('fb_format')
            if fmt not in (0, 1):
                raise ValueError(f'GOP pixel format {fmt} cannot be described by Boot_Video')
            fb = Framebuffer(info.get('fb_base', 0), info.get('fb_width', 0),
                             info.get('fb_height', 0), info.get('fb_stride', 0) * 4, 32)
            region = fb.physical_range().validate()
            if fb.stride * fb.height > info.get('fb_size', 0):
                raise ValueError('framebuffer geometry exceeds the host allocation')
            if region.base < heap.end and heap.base < region.end:
                raise ValueError('framebuffer overlaps the q1n1 heap')
        return cls('q1n1', hz, heap, fb)
