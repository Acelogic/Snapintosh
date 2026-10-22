#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end offline check of SNAP_KERNEL_USER_4K (probes/user4k.py).

    python3 tools/test-kernel-user-4k.py [--output NEW_DIR]

It builds the real loader image for the stock J700 26A428 kernelcache with
the patch off, explicitly off and on, alone and combined with sysreg-zero,
refmod-skip, native calls and the SPTM HVC experiment, and compares the
uploaded chunks word by word. It decodes each site before and after and walks
the code each new branch reaches. It needs the 26A428 KDK (dSYM) and
capstone. It does not execute XNU and establishes no speedup. --output writes
the site manifest.

Failure modes, written before the code:
 1. A default build changes. Guard: with the variable unset or 0 every
    executable word of the uploaded image equals the stock loaded image, and
    the unset, 0 and user_4k=False builds are chunk-for-chunk identical.
 2. Something besides the sites changes. Guard: the patched build has the
    same chunk geometry, no non-image chunk changes, and the executable bytes
    are stock plus exactly the four site words.
 3. The wrong branches are taken. Guard: each site is, independently (KDK
    segment translation and atos), load_machfile at mach_loader.c:781 and
    :1006 and exec_add_apple_strings at kern_exec.c:8165; capstone decodes
    the stock word as CBZ of the ip_px_sa register (P) or of W26 (Q) and the
    replacement as B to the psa_4k test's own force target (P) or to the
    CBZ's own target (Q); G is vm_guard_object_find_space_anywhere at
    vm_map_store.c:1958, B over the no-map default after LDRB W8 of
    map->hdr.page_shift, replaced by TBZ W8, #1 to the function's own
    "MOV W8, #46; B epilogue" fallback.
 4. A forced path reads spawn attributes that are not there (no posix_spawn,
    ip_px_sa NULL). Guard: from each P force target, every path up to its
    first call, return or join with the skip path writes the ip_px_sa
    register before any read of it (capstone).
 5. The gate is skipped wrongly. Guard: every exit from the gate block
    (entitled, or either cross-architecture entitlement) branches to the
    same target the Q branch now takes; its one failure exit is the only
    other one, and the block's calls are the entitlement checks.
 6. An unknown or different kernel is patched. Guard: a changed digest is
    refused; a pinned digest whose closure loses a site, or whose force path
    is not recognised, is refused.
 7. Composition breaks other patches. Guard: with sysreg-zero, refmod-skip
    and SNAP_NATIVE_CALLS (private and HVC) the native contract is unchanged
    and the image is stock plus exactly every patch's words; site sets are
    disjoint.
 8. A second application or a bad flag. Guard: patching patched data is
    refused; SNAP_KERNEL_USER_4K=2 and a non-boolean keyword are refused.
 9. A 4K map still reaches VM guard objects, whose slab bucket index is
    bit_length(page-rounded size - 1) - 14: a 4K request is index -2 and the
    new chunk pointer lands 16 bytes before the slab, at +1008 of the
    previous early.kalloc.1024 element (installed-fresh-20261018-v56 and
    -v58: "element modified after free (off:1008)"). Guard: G falls back for
    a page shift with bit 1 clear (12) and keeps 14 on the stock path (the
    next word re-loads 14, the stock B skipped exactly it); the fallback
    returns 46 through the function's epilogue, as its own early exits do;
    its one caller answers 46 with the ordinary allocator (CMP W0, #46;
    B.NE); and the bucket computation is the one this argument reads (the
    only SUB Xn, Xn, #0x70 slot index after CLZ in the function).
"""
import argparse
import contextlib
import hashlib
import importlib
import io
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone import arm64 as A

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'probes'))
kc_load = importlib.import_module('kc-load')
import user4k as z  # noqa: E402
import refmodskip  # noqa: E402
import sysregzero  # noqa: E402
from nativecalls import HVC_WORD  # noqa: E402

KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Kernels/kernel.release.t8140')
DSYM = KDK.with_name(KDK.name + '.dSYM') / 'Contents/Resources/DWARF' / KDK.name
ENV = ('SNAP_KERNEL_USER_4K', 'SNAP_KERNEL_REFMOD_SKIP', 'SNAP_KERNEL_SYSREG_ZERO', 'SNAP_NATIVE_CALLS',
       'SNAP_SPTM_HVC_CALLS', 'SNAP_SEED')
MASK = (1 << 64) - 1
WHERE = {'load_machfile force': ('load_machfile', 'mach_loader.c:781'),
         'entitlement gate': ('load_machfile', 'mach_loader.c:1006'),
         'apple string': ('exec_add_apple_strings', 'kern_exec.c:8165'),
         'guard objects fallback': ('vm_guard_object_find_space_anywhere', 'vm_map_store.c:1958')}
checks = 0


def need(condition, message):
    global checks
    if not condition:
        raise SystemExit('FAIL: ' + message)
    checks += 1


def refused(action, text):
    try:
        action()
    except ValueError as error:
        return text in str(error)
    return False


@contextlib.contextmanager
def environment(**values):
    saved = {k: os.environ.get(k) for k in ENV}
    try:
        for k in ENV:
            os.environ.pop(k, None)
        os.environ['SNAP_SEED'] = 'test-kernel-user-4k'
        os.environ.update(values)
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def build(xb, log, **kw):
    with contextlib.redirect_stdout(log):
        return xb.build(str(KERNELCACHE), **kw)


class Code:
    def __init__(self, image):
        self.image = image
        self.segments = [(va, off, size) for _, va, _, off, size in image.executable_segments]
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    def word(self, va):
        for sva, off, size in self.segments:
            if sva <= va < sva + size:
                return struct.unpack_from('<I', self.image.data, off + va - sva)[0]
        raise SystemExit(f'FAIL: {va:#x} is not executable')

    def insn(self, va, word=None):
        raw = struct.pack('<I', self.word(va) if word is None else word)
        found = list(self.md.disasm(raw, va))
        need(len(found) == 1, f'{va:#x}: capstone cannot decode {raw.hex()}')
        return found[0]


def wide(name):
    return 'x' + name[1:] if name.startswith('w') else name


def unread_before_written(code, start, reg, stop, limit=64):
    """Every path from start up to a call, return or stop: reg written before read."""
    work, seen = [start], set()
    while work:
        pc = work.pop()
        for _ in range(limit):
            if pc in seen or pc == stop:
                break
            seen.add(pc)
            i = code.insn(pc)
            reads, writes = i.regs_access()
            if reg in {wide(i.reg_name(r)) for r in reads}:
                return False
            if reg in {wide(i.reg_name(r)) for r in writes} or i.group(CS_GRP_CALL) or i.group(CS_GRP_RET):
                break
            if i.group(CS_GRP_JUMP):
                op = i.operands[-1]
                need(op.type == A.ARM64_OP_IMM, f'{pc:#x}: indirect jump on a forced path')
                if i.mnemonic == 'b':
                    pc = op.imm & MASK
                    continue
                work.append(op.imm & MASK)
            pc += 4
        else:
            raise SystemExit(f'FAIL: {start:#x}: forced path walk did not close')
    return True


def guard_objects(code, s, before, after):
    """9. G: the page-shift branch, its fallback, the bucket it guards and the caller."""
    va = s['va']
    cbz, ldrb, mov14 = code.insn(va - 8), code.insn(va - 4), code.insn(va + 4)
    need(cbz.mnemonic == 'cbz' and cbz.reg_name(cbz.operands[0].reg) == 'x0' and
         cbz.operands[1].imm & MASK == va + 4, f'{va:#x}: no CBZ X0 to the no-map default')
    need(ldrb.mnemonic == 'ldrb' and ldrb.reg_name(ldrb.operands[0].reg) == 'w8' and
         ldrb.operands[1].mem.disp == z.MAP_PAGE_SHIFT, f'{va:#x}: not LDRB W8 of map->hdr.page_shift')
    need(mov14.mnemonic == 'mov' and mov14.operands[1].imm == 14, f'{va:#x}: the no-map default is not 14')
    need(before.mnemonic == 'b' and before.operands[0].imm & MASK == va + 8, f'{va:#x}: stock word is not B over it')
    need(after.mnemonic == 'tbz' and after.reg_name(after.operands[0].reg) == 'w8' and after.operands[1].imm == 1 and
         after.operands[2].imm & MASK == s['target'], f'{va:#x}: replacement is not TBZ W8, #1, fallback')
    # Bit 1 of the shift: 14 (0b1110) falls through to MOV W8, #14 (the value it holds), 12 (0b1100) falls back.
    need(14 >> 1 & 1 and not 12 >> 1 & 1, 'bit 1 does not separate 16K from 4K')
    mov46, b = code.insn(s['target']), code.insn(s['target'] + 4)
    need(mov46.mnemonic == 'mov' and mov46.reg_name(mov46.operands[0].reg) == 'w8' and
         mov46.operands[1].imm == z.KERN_NOT_SUPPORTED and b.mnemonic == 'b', 'fallback is not MOV W8, #46; B')
    epi = b.operands[0].imm & MASK
    first = code.insn(epi)
    need(first.mnemonic == 'mov' and first.reg_name(first.operands[0].reg) == 'x0' and
         first.reg_name(first.operands[1].reg) == 'x8' and
         any(code.insn(epi + 4 * k).mnemonic == 'retab' for k in range(12)), 'epilogue does not return X8')
    # The function: entry, its own exits to the epilogue, the bucket index.
    entry = va
    while code.insn(entry).mnemonic != 'pacibsp':
        entry -= 4
        need(va - entry < 0x400, 'no function entry before the site')
    pc, branches, bucket = entry, 0, []
    while pc < s['target'] + 8:
        i = code.insn(pc)
        if i.group(CS_GRP_JUMP) and i.operands[-1].type == A.ARM64_OP_IMM and \
                i.operands[-1].imm & MASK in (epi, s['target']):
            branches += 1
        if i.mnemonic == 'sub' and len(i.operands) == 3 and i.operands[2].type == A.ARM64_OP_IMM and \
                i.operands[2].imm == 0x70 and code.insn(pc - 4).mnemonic == 'ubfiz':
            bucket.append(pc)
        pc += 4
    need(branches >= 3, f'the fallback is not one of the function\'s own exits ({branches})')
    need(len(bucket) == 1 and va < bucket[0] < s['target'], 'not exactly one slab bucket index after the site')
    # Replay the stock arithmetic that ends at that index (installed-fresh-20261018-v56/-v58): the
    # page mask from the map's shift, then bit_length(max(mask + 1, size) - 1), slot 8*bucket - 0x70.
    seq = [code.insn(bucket[0] - 4 * k) for k in range(10, -1, -1)]
    shape = [(i.mnemonic, i.op_str) for i in seq]
    need(shape == [('add', 'x8, x20, #1'), ('cmp', 'x8, x5'), ('csinc', 'x8, x5, x20, ls'), ('add', 'x8, x8, x9'),
                   ('subs', 'x8, x8, #1'), ('clz', 'x8, x8'), ('mov', 'w9, #0x40'), ('sub', 'w8, w9, w8'),
                   ('csel', 'w5, wzr, w8, eq'), ('ubfiz', 'x8, x5, #3, #0x20'), ('sub', 'x8, x8, #0x70')],
         f'the bucket arithmetic is not the reviewed one: {shape}')
    mask_ops = [(code.insn(va + 4 * k).mnemonic, code.insn(va + 4 * k).op_str) for k in range(2, 6)]
    need(mask_ops == [('mov', 'w9, #-1'), ('lsl', 'w8, w9, w8'), ('mvn', 'w8, w8'), ('orr', 'x20, x6, x8')],
         f'the page mask is not -1 << shift: {mask_ops}')

    def slot(shift, size, align=0):
        x20 = align | ~(-1 << shift) & 0xffffffff
        x8 = size if x20 + 1 <= size else x20 + 1
        x8 = x8 + 0 - 1                                    # x9 is 0 without the bit-58 option
        bucket_ = 0 if x8 == 0 else x8.bit_length()
        return 8 * bucket_ - 0x70
    for size in (0x1000, 0x800, 0x10):
        need(slot(12, size) == -16, f'4K map, {size:#x}: slot {slot(12, size)} (v56/v58: -16)')
        need(1024 + slot(12, size) == 1008, 'the 4K slot is not +1008 of the previous 1 KiB element')
    need(slot(12, 0x2000) == -8 and slot(12, 0x4000) == 0, '4K map, 8K/16K requests')
    for size in (0x10, 0x1000, 0x4000, 0x10000, 1 << 30):
        need(slot(14, size) >= 0, f'16K map, {size:#x}: negative slot')
    need(slot(14, 1 << 41) < 8 * 28, '16K map: the largest request leaves the 28-entry list')
    # The one caller answers 46 with the ordinary allocator.
    callers = []
    for sva, off, size in code.segments:
        for k in range(size // 4):
            w = struct.unpack_from('<I', code.image.data, off + 4 * k)[0]
            if w >> 26 == 0x25:
                target = (sva + 4 * k + 4 * (((w & 0x3ffffff) ^ 0x2000000) - 0x2000000)) & MASK
                if target == entry:
                    callers.append(sva + 4 * k)
    need(len(callers) == 1, f'{len(callers)} callers of vm_guard_object_find_space_anywhere')
    cmp, bne = code.insn(callers[0] + 4), code.insn(callers[0] + 8)
    need(cmp.mnemonic == 'cmp' and cmp.reg_name(cmp.operands[0].reg) == 'w0' and
         cmp.operands[1].imm == z.KERN_NOT_SUPPORTED and bne.mnemonic == 'b.ne', 'the caller does not treat 46 as fallback')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--output', type=Path, help='fresh directory for the site manifest')
    args = ap.parse_args()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    image = kc_load.Image(KERNELCACHE.read_bytes())
    need(hashlib.sha256(image.data).hexdigest() == z.J700_26A428, 'not the J700 26A428 kernelcache')
    sites = z.find(image)
    pin = z.PINS[z.J700_26A428]
    need(z.closure(sites) == pin, 'decoded closure differs from the pin')
    code = Code(image)
    sym = __import__('runpy').run_path(str(ROOT / 'tools/kc-symbolicate.py'))['Symbolicator']()

    # 3. Where each site is, and what it decodes to before and after.
    for s in sites:
        _, kva = sym.translate(s['va'])
        out = subprocess.run(['atos', '-o', str(DSYM), '-arch', 'arm64e', hex(kva)],
                             capture_output=True, text=True, check=True).stdout.strip()
        function, line = WHERE[s['kind']]
        need(out.startswith(function + ' (in ') and out.endswith(f'({line})'), f'{s["va"]:#x}: atos says {out}')
        before, after = code.insn(s['va']), code.insn(s['va'], s['replacement'])
        if s['kind'] == 'guard objects fallback':
            guard_objects(code, s, before, after)
            continue
        need(before.mnemonic == 'cbz' and after.mnemonic == 'b' and
             after.operands[0].imm & MASK == s['target'], f'{s["va"]:#x}: {before.mnemonic} -> {after.mnemonic}')
        reg = before.reg_name(before.operands[0].reg)
        if s['kind'] == 'entitlement gate':
            need(reg == 'w26' and before.operands[1].imm & MASK == s['target'], 'the gate branch is not CBZ W26')
        else:
            loads = [code.insn(s['va'] - 4 * k) for k in range(1, 5)]
            load = next((i for i in loads if i.mnemonic == 'ldr' and i.reg_name(i.operands[0].reg) == reg), None)
            need(load is not None and load.operands[1].mem.disp == z.IP_PX_SA and
                 all(reg not in {wide(i.reg_name(r)) for r in i.regs_access()[1]}
                     for i in loads[:loads.index(load)]), f'{s["va"]:#x}: not CBZ of ip_px_sa')
            tbnz = code.insn(s['va'] + 8)
            need(tbnz.mnemonic == 'tbnz' and tbnz.operands[2].imm & MASK == s['target'],
                 f'{s["va"]:#x}: the force target is not the psa_4k test\'s')
            s['register'] = reg
    need(sorted(s['kind'] for s in sites) == sorted(z.KINDS), 'not one site of each kind')

    # 4. Forced paths never read the (absent) spawn attributes.
    for s in sites:
        if s['kind'] in ('entitlement gate', 'guard objects fallback'):
            continue
        skip = code.insn(s['va']).operands[1].imm & MASK
        need(unread_before_written(code, s['target'], s['register'], skip),
             f'{s["va"]:#x}: the forced path reads {s["register"]}')

    # 5. The gate: its exits.
    gate = next(s for s in sites if s['kind'] == 'entitlement gate')
    exits, calls, pc = [], 0, gate['va'] + 4
    while pc < gate['target']:
        i = code.insn(pc)
        if i.group(CS_GRP_CALL):
            calls += 1
        elif i.group(CS_GRP_JUMP):
            exits.append(i.operands[-1].imm & MASK)
        pc += 4
    need(calls == 3 and exits.count(gate['target']) == 2 and len(exits) == 3 and
         all(not gate['va'] < e < gate['target'] for e in exits), f'gate exits {[hex(e) for e in exits]}')

    # 6 and 8. Admission on modified copies of the real image.
    stock = bytes(image.data)
    need(refused(lambda: z.admit(kc_load.Image(stock[:-1] + bytes([stock[-1] ^ 1]))),
                 'no reviewed user-4k closure'), 'a changed kernel digest was admitted')
    machfile = next(s for s in sites if s['kind'] == 'load_machfile force')
    for name, va, word, text in (
            ('lost site', machfile['va'] + 4, 0x39400000, 'closure differs'),             # LDRB W0,[X0]
            ('unrecognised force path', machfile['target'], 0x32000339, 'not recognised')):  # ORR W25,W25,#1
        changed = bytearray(stock)
        off = next(o + va - v for v, o, size in code.segments if v <= va < v + size)
        struct.pack_into('<I', changed, off, word)
        other = kc_load.Image(bytes(changed))
        digest = hashlib.sha256(other.data).hexdigest()
        z.PINS[digest] = z.PINS[z.J700_26A428]
        try:
            need(refused(lambda: z.admit(other), text), f'{name}: admitted')
        finally:
            del z.PINS[digest]
    loaded = bytearray(stock)
    for off, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', loaded, off, value)
    z.patch(image, loaded)
    need(refused(lambda: z.patch(image, loaded), 'already modified'), 'patched data was patched again')

    import xnuboot as xb
    xb.configure_guest('j700ap-26A428', KERNELCACHE.parent)
    log = io.StringIO()
    stock_loaded = bytearray(stock)
    for off, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', stock_loaded, off, value)

    def uploaded(built):
        out = []
        for va, _, size in code.segments:
            pa = xb.IMAGE_PA + va - image.vmin
            blobs = [bytes(blob[pa - base:pa - base + size]) for base, blob in built['chunks'].items()
                     if base <= pa and pa + size <= base + len(blob)]
            need(len(blobs) == 1, f'executable segment {va:#x} not uploaded whole, once')
            out.append(blobs[0])
        return out

    def expected(replaced):
        out = []
        for va, off, size in code.segments:
            body = bytearray(stock_loaded[off:off + size])
            for site, word in replaced.items():
                if va <= site < va + size:
                    struct.pack_into('<I', body, site - va, word)
            out.append(bytes(body))
        return out

    # 1, 2 and 8.
    with environment():
        default = build(xb, log)
        need(default['kernel_user_4k'] is None, 'default build reports a user-4k patch')
        need(uploaded(default) == expected({}), 'default build executable bytes differ from the stock loaded image')
        explicit_off = build(xb, log, user_4k=False)
        need(refused(lambda: build(xb, log, user_4k='1'), 'explicit boolean'), 'non-boolean keyword accepted')
    with environment(SNAP_KERNEL_USER_4K='0'):
        zero = build(xb, log)
    with environment(SNAP_KERNEL_USER_4K='2'):
        need(refused(lambda: build(xb, log), 'must be 0 or 1'), 'SNAP_KERNEL_USER_4K=2 accepted')
    for name, other in (('SNAP_KERNEL_USER_4K=0', zero), ('user_4k=False', explicit_off)):
        need(other['chunks'] == default['chunks'], f'{name} build differs from the default build')
    with environment(SNAP_KERNEL_USER_4K='1'):
        patched = build(xb, log)
    with environment():
        keyword = build(xb, log, user_4k=True)
    need(keyword['chunks'] == patched['chunks'], 'keyword and environment builds differ')
    record = patched['kernel_user_4k']
    need(record['closure_sha256'] == pin['closure_sha256'] and record['sites'] == 4, 'loader record')
    need({k: len(v) for k, v in patched['chunks'].items()} == {k: len(v) for k, v in default['chunks'].items()},
         'chunk geometry changed')
    changed_chunks = [k for k in default['chunks'] if default['chunks'][k] != patched['chunks'][k]]
    need(changed_chunks and all(xb.IMAGE_PA <= k < xb.IMAGE_PA + image.vmax - image.vmin for k in changed_chunks),
         'a non-image chunk changed (params, device tree or handoff)')
    replaced = {s['va']: s['replacement'] for s in sites}
    need(uploaded(patched) == expected(replaced), 'patched executable bytes are not stock plus exactly the sites')
    del explicit_off, zero, keyword

    # 7. With sysreg-zero, refmod-skip and native calls (private and HVC).
    sysreg = {s['va']: s['replacement'] for s in sysregzero.find(image)}
    refmod = {s['va']: s['replacement'] for s in refmodskip.find(image)['sites']}
    need(not (set(sysreg) | set(refmod)) & set(replaced), 'a user-4k site is another patch\'s site')
    with environment(SNAP_KERNEL_SYSREG_ZERO='1', SNAP_KERNEL_REFMOD_SKIP='1'):
        all3 = build(xb, log, user_4k=True)
    need(uploaded(all3) == expected({**sysreg, **refmod, **replaced}),
         'sysreg-zero, refmod-skip and user-4k together are not stock plus all three')
    for hvc in ('0', '1'):
        with environment(SNAP_NATIVE_CALLS='1', SNAP_SPTM_HVC_CALLS=hvc):
            base = build(xb, log)
            every = build(xb, log, user_4k=True, refmod_skip=True, sysreg_zero=True)
        contract = base['native_call_contract']
        need(every['native_call_contract']['pages'] == contract['pages'] and every['stub_pa'] == base['stub_pa'] and
             every['sptm_hvc_calls'] == (hvc == '1'), 'native-call contract changed under user-4k')
        need(not set(contract['call_sites']) & set(replaced) and not set(contract['writer_sites']) & set(replaced),
             'a user-4k site is a native call or writer site')
        hvc_words = {va: HVC_WORD for va in contract['call_sites']} if hvc == '1' else {}
        need(uploaded(every) == expected({**hvc_words, **sysreg, **refmod, **replaced}),
             f'HVC={hvc}: image differs from stock beyond every patch\'s words')
        del base, every

    manifest = dict(kernel_sha256=z.J700_26A428, closure=z.closure(sites),
                    sites=[dict(kind=s['kind'], va=hex(s['va']), where=' '.join(WHERE[s['kind']]),
                                before=f'{s["word"]:#010x}', after=f'{s["replacement"]:#010x}',
                                target=hex(s['target'])) for s in sites])
    if args.output:
        (args.output / 'user-4k-sites.json').write_text(json.dumps(manifest, indent=1) + '\n')
    print(f'PASS: {checks} checks; 4 sites (load_machfile :781 and :1006, exec_add_apple_strings :8165 '
          f'CBZ -> B; vm_guard_object_find_space_anywhere :1958 B -> TBZ W8, #1 fallback for 4K maps); '
          f'forced paths read no spawn attributes; defaults unchanged; composes with sysreg-zero, '
          f'refmod-skip and native calls')


if __name__ == '__main__':
    main()
