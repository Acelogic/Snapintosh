# SPDX-License-Identifier: MIT
"""Independent physical ownership and bootstrap-alias checks for live audits."""
import itertools


class ManagedFrames:
    def __init__(self, frame_map, frame_low, frame_high, alloc_low, alloc_high,
                 boot_ranges=(), boot_aliases=(), released=(0,0)):
        if not frame_low <= alloc_low < alloc_high <= frame_high:
            raise ValueError('invalid allocator geometry')
        if (frame_low | frame_high | alloc_low | alloc_high) & 0x3fff or frame_map & 15:
            raise ValueError('unaligned ownership geometry')
        map_end=frame_map+((frame_high-frame_low)>>14)*16
        if map_end >= 1 << 64:
            raise ValueError('frame map overflow')
        if not 0 <= len(boot_ranges) <= 8 or not 0 <= len(boot_aliases) <= 50:
            raise ValueError('too many boot ranges')
        self.intervals=[(alloc_low,alloc_high)]
        self.aliases=[]
        populations=[]
        for ranges in (boot_ranges,boot_aliases):
            physical=[];virtual=[]
            for va,pa,pages in ranges:
                if any(type(v) is not int for v in (va,pa,pages)):
                    raise ValueError('invalid boot range value')
                span=pages*0x4000
                if (not 0 < pages <= 0x1000 or (pa|va)&0x3fff or
                        not frame_low <= pa < pa+span <= alloc_low or
                        not 0xffff800000000000 <= va < va+span < 1 << 64 or
                        pa < map_end and frame_map < pa+span):
                    raise ValueError('invalid boot range geometry')
                if any(lo < pa+span and pa < hi for lo,hi in physical):
                    raise ValueError('overlapping boot physical ranges')
                if any(lo < va+span and va < hi for lo,hi in virtual):
                    raise ValueError('overlapping boot virtual ranges')
                physical.append((pa,pa+span));virtual.append((va,va+span))
            populations.append(physical)
        def merged(ranges):
            out=[]
            for lo,hi in sorted(ranges):
                if out and out[-1][1]==lo:out[-1]=(out[-1][0],hi)
                else:out.append((lo,hi))
            return out
        if merged(populations[0])!=merged(populations[1]):
            raise ValueError('bootstrap alias coverage differs from owned ranges')
        if any(not any(a <= lo < hi <= b for a,b in populations[0])
               for lo,hi in populations[1]):
            raise ValueError('bootstrap alias spans distinct source ranges')
        self.intervals+=populations[0]
        self.aliases=list(boot_aliases)
        # The SEPFW extent once XNU has freed it to the VM (compat/sptm.h
        # sep_firmware_released): below the arena, never aliased or metadata.
        if len(released)!=2 or any(type(v) is not int for v in released):
            raise ValueError('invalid released extent')
        pa,size=released
        if size:
            if ((pa|size)&0x3fff or not frame_low<=pa<pa+size<=alloc_low or
                    pa<map_end and frame_map<pa+size or
                    any(lo<pa+size and pa<hi for lo,hi in self.intervals)):
                raise ValueError('invalid released extent geometry')
            self.intervals.append((pa,pa+size))

    def contains(self,pa):
        return not pa&0x3fff and any(lo <= pa < hi for lo,hi in self.intervals)

    def frames(self):
        return itertools.chain.from_iterable(range(lo,hi,0x4000) for lo,hi in sorted(self.intervals))

    def bootstrap_alias(self,va,pa):
        return any(base <= va < base+pages*0x4000 and va-base==pa-physical
                   for base,physical,pages in self.aliases)


def released_extent(geometry):
    """The SEPFW extent once XNU owns it (geometry['sep_released']), else none."""
    return geometry.get('sep_firmware',(0,0)) if geometry.get('sep_released') else (0,0)


class SEPFirmwareFrames:
    """Separate reserved DMA data; contains() does not authorize CPU ownership.
    Pass (0,0) once released: the extent is then ordinary managed memory."""
    def __init__(self,managed,frame_map,frame_low,frame_high,alloc_low,extent=(0,0)):
        if len(extent)!=2 or any(type(v) is not int for v in extent):
            raise ValueError('invalid SEP firmware resource')
        pa,size=extent
        self.low=pa;self.high=pa+size
        if pa==size==0:return
        if (not 0<size<=0x1000000 or (pa|size)&0x3fff or
                not frame_low<=pa<pa+size<=alloc_low<=frame_high<=1<<36):
            raise ValueError('invalid SEP firmware resource geometry')
        map_end=frame_map+((frame_high-frame_low)>>14)*16
        if pa<map_end and frame_map<pa+size:
            raise ValueError('SEP firmware overlaps frame metadata')
        if any(pa<hi and lo<pa+size for lo,hi in managed.intervals):
            raise ValueError('SEP firmware overlaps reclaimable memory')

    def contains(self,pa):
        return not pa&0x3fff and self.low<=pa<self.high

    def frames(self):return range(self.low,self.high,0x4000)
