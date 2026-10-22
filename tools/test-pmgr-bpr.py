#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""PMGR's BPR word in the AES key block (docs/PMGR-BPR-20261017.md, failure mode 1).

Pins the 26A428 facts the model rests on, offline:
  - the J700 device tree puts PMGR range 1 +0x5c030 inside the AES node's key
    window at +0x30, and devicemodel gives model 8 exactly that word;
  - AppleT8140PMGR's getter is `mov w1,#0x5c030; mov w2,#0; b read32` and the
    next method the matching `write32(0x5c030, value)`;
  - AppleT8140PMGR's vtable slot for the getter is the 0x34cc-diversity method
    ApplePMGR's get-bpr path calls, and the get-bpr entitlement exists.
A different kernelcache, tree or model configuration fails here, not on the A16.

    python3 tools/test-pmgr-bpr.py
"""
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import devicemodel as dm  # noqa: E402
from appledt import DeviceTree  # noqa: E402

FIRMWARE = ROOT / 'downloads/extracted/j700ap'
KERNEL = FIRMWARE / 'kernelcache.release.mac17p'
GETTER, SETTER = 0xfffffe0009bedd30, 0xfffffe0009bedd44
GETTER_SLOT, DIVERSITY = 0xfffffe0008274c88, 0x34cc
ENTITLEMENT = b'com.apple.private.ApplePMGRUserClient.get-bpr'
# bti c; mov w1,#0xc030; movk w1,#0x5,lsl #16; mov w2,#0; b <read32>
GETTER_WORDS = (0xd503245f, 0x52980601, 0x72a000a1, 0x52800002)
# bti c; mov x2,x1; mov w1,#0xc030; movk w1,#0x5,lsl #16; mov w3,#0; b <write32>
SETTER_WORDS = (0xd503245f, 0xaa0103e2, 0x52980601, 0x72a000a1, 0x52800003)
checks = 0


def expect(ok, what):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(what)


def kernelcache():
    with KERNEL.open('rb') as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    ncmds = struct.unpack_from('<I', data, 16)[0]
    p, segments, entries = 32, [], {}
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, p)
        if cmd == 0x19:
            segments.append(struct.unpack_from('<QQQQ', data, p + 24))
        elif cmd == 0x80000035:
            vm, fo, name = struct.unpack_from('<QQI', data, p + 8)
            entries[data[p + name:p + size].split(b'\0')[0].decode()] = fo
        p += size
    return data, segments, entries


def read(data, segments, va, size):
    for vm, vs, fo, fs in segments:
        if vm <= va and va + size <= vm + fs:
            return data[fo + va - vm:fo + va - vm + size]
    raise AssertionError(f'{va:#x} is not in the kernelcache')


def owner(data, entries, va):
    for name, fo in entries.items():
        n, p = struct.unpack_from('<I', data, fo + 16)[0], fo + 32
        for _ in range(n):
            cmd, size = struct.unpack_from('<II', data, p)
            if cmd == 0x19:
                vm, vs = struct.unpack_from('<QQ', data, p + 24)
                if vm <= va < vm + vs:
                    return name
            p += size


def main():
    # The tree: PMGR range 1 +0x5c030 is the AES key window's +0x30.
    dt = DeviceTree((FIRMWARE / 'DeviceTree.j700ap').read_bytes())
    spec = dm.AESKeysBootSpec('/device-tree/arm-io/aes', 1, (0, 0x40, 0x44, 0x48), 5, True)
    expect(dm.aes_pmgr_bpr_offset(dt, spec) == 0x30, 'tree no longer places the BPR word at +0x30')
    pmgr = struct.unpack_from('<QQ', dt.get(dm.PMGR_NODE, 'reg'), 16)
    aes = struct.unpack_from('<QQ', dt.get(spec.node, 'reg'), 16)
    expect(pmgr == (0xf8280000, 0x80000) and aes == (0xf82dc000, 0x8000), 'PMGR range 1 or AES window moved')
    other = dm.AESKeysBootSpec(spec.node, 0, spec.offsets, 5, True)
    expect(dm.aes_pmgr_bpr_offset(dt, other) == 0, 'BPR word claimed in a window that does not hold it')
    keyed = dm.AESKeysBootSpec(spec.node, 1, (0, 0x30, 0x44, 0x48), 5, True)
    expect(dm.aes_pmgr_bpr_offset(dt, keyed) == 0, 'BPR word placed on a key control')
    # The kernelcache: getter, setter, vtable slot, entitlement.
    data, segments, entries = kernelcache()
    expect(owner(data, entries, GETTER) == 'com.apple.driver.AppleT8140PMGR', 'getter moved out of AppleT8140PMGR')
    expect(struct.unpack('<4I', read(data, segments, GETTER, 16)) == GETTER_WORDS, 'getter is not read32(0x5c030)')
    expect(struct.unpack('<5I', read(data, segments, SETTER, 20)) == SETTER_WORDS, 'setter is not write32(0x5c030)')
    slot = struct.unpack('<Q', read(data, segments, GETTER_SLOT, 8))[0]
    base = segments[0][0]
    expect(slot >> 63 and (slot >> 32) & 0xffff == DIVERSITY and base + (slot & 0x3fffffff) == GETTER,
           'vtable slot is not the 0x34cc getter')
    expect(data.find(ENTITLEMENT + b'\0') >= 0, 'get-bpr entitlement missing')
    print(f'PASS: {checks} PMGR BPR checks (tree topology, AppleT8140PMGR getter/setter, vtable slot, entitlement)')


if __name__ == '__main__':
    main()
