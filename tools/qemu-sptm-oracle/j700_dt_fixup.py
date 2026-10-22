#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Ported from darwin-vm dt_fixup.py (https://github.com/jprx/darwin-vm):
# Copyright (c) 2026 jprx
"""darwin-vm dt_fixup.py plus the J700-specific change qemu-sptm needs.

dt_fixup keeps any node whose compatible contains b'aic' (substring match),
so J700's /dock-connect ("dock,connect,aic") survives and AppleDockConnect
+ IOPortFamily start and panic (PC alignment) with no dock hardware. Drop it.
Also publish the BaseSystem sealed-volume auth blob exactly as Snapintosh
does (probes/ramdisk.py + guestprofile.py): /chosen/secure-boot-hashes/
system-volume-auth-blob = basesystem-26A428.root-hash, and the shipped
darwinos-ramdisk-environment no-SEP policy (protected-data-access=0,
sepfw-load-at-boot=0; boot with acm_fastsim=1).
Usage: j700_dt_fixup.py <DeviceTree.j700ap> <out> <darwin-vm dir> [root-hash]"""
import sys, os
src, out, dvm = sys.argv[1:4]
root_hash = sys.argv[4] if len(sys.argv) > 4 else None
ns = {}
exec(open(os.path.join(dvm, 'dt_fixup.py')).read().split("def main():")[0], ns)
root = ns['ADTNode'](); ns['decode_node'](open(src, 'rb').read(), root)
with open(os.path.join(dvm, 'nvram.bin'), 'rb') as nv:
    ns['fixup'](root, nvram_file=nv)
# 16 GiB guest DRAM: the GPT media (BaseSystem + ISC) alone is 3.3 GiB.
root['chosen'].props['dram-size'] = 'u64:0x400000000'
if 'dock-connect' in root:
    root.remove_child('dock-connect')
if root_hash:
    ch = root['chosen']
    ch['secure-boot-hashes'].props['system-volume-auth-blob'] = open(root_hash, 'rb').read()
    ch.props['protected-data-access'] = 'u32:0'
    ch.props['sepfw-load-at-boot'] = 'u32:0'
    # IOKit RAM image (Snapintosh ramdisk_mode='iokit'); qemu fills extents.
    uuid = 'A9037730-2821-4F3A-90DC-91BA521BB080'
    ch.props['boot-ramdmg-size'] = 'u64:0'
    ch.props['boot-ramdmg-extents'] = bytes(16)
    ch.props['boot-uuid'] = uuid
    ch.props['apfs-preboot-uuid'] = uuid
open(out, 'wb').write(ns['encode_node'](root))
