#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end offline check of SNAP_KERNEL_REFMOD_SKIP (probes/refmodskip.py).

    python3 tools/test-kernel-refmod-skip.py [--output NEW_DIR]

It builds the real loader image for the stock J700 26A428 kernelcache with
the patch off, explicitly off and on, alone and combined with sysreg-zero,
native calls and the SPTM HVC experiment, and compares the uploaded chunks
word by word. It decodes each site before and after, emulates the skipped
call's entry for the site's arguments, and walks the code after each site.
It needs the 26A428 KDK (dSYM), capstone and numpy. It does not execute XNU
and establishes no speedup. --output writes the site manifest.

Failure modes, written before the code:
 1. A default build changes. Guard: with the variable unset or 0 every
    executable word of the uploaded image equals the stock loaded image, and
    the unset, 0 and refmod_skip=False builds are chunk-for-chunk identical.
 2. Something besides the sites changes. Guard: the patched build has the
    same chunk addresses and lengths and differs from the default build only
    in the image words at the decoded sites.
 3. The wrong function is taken for the reference clear. Guard: the decoded
    function is, independently, the KDK's phys_attribute_clear_with_flush_range
    (segment translation, dSYM symbol at offset 0); its DWARF has no return
    type and the parameters (pn, bits, options, arg, flush_range); an
    independent numpy decode finds the same 16 BLs to it.
 4. A dropped call does more than clear the reference bit (a modify clear
    would lose dirty tracking for file-backed writes and MADV_FREE; reusable
    ledgers; CLEAR_WRITE). Guard: each site's arguments are exactly MOVZ
    W1,#0x40 (PP_ATTR_REFERENCED, xnu-12377 pmap_data.h), W2,#0x20
    (PMAP_OPTIONS_NOFLUSH, vm/pmap.h), X3,#0, X4,#0; a concrete emulation of
    the function's entry with those arguments reaches one tail call, to the
    KDK's arm_force_fast_fault_with_flush_range, with allow_mode VM_PROT_WRITE
    (write kept: no write protection), options NOFLUSH, bits_to_clear
    REFERENCED and no flush range; the same emulation of a modify clear gives
    a mode without VM_PROT_WRITE, so the decode tells them apart. Every other
    BL to the function (14, all modify clears among them) is unchanged.
 5. Another path reaches the BL with other arguments. Guard: no direct branch
    in any executable segment (independent numpy decode) lands on the three
    later MOVZs or the BL; the KDK function holding each site has no BR-family
    jump; the window holds no BTI landing pad.
 6. The NOP is visible to the caller. Guard: the call returns to site+4, the
    NOP's fall-through; on every path from there to a call or return, no
    caller-saved register x0-x17 is read before it is written (capstone);
    where a path returns with x0 unwritten, each caller of the containing
    function is walked the same way for x0.
 7. The sites drift from the policy. Guard: the KDK inline chain of each site
    is pmap_clear_refmod_options inlined in vm_page_balance_inactive
    (vm_pageout.c) or vm_fault_deactivate_behind (vm_fault.c), one each.
 8. An unknown or different kernel is patched. Guard: a changed digest is
    refused; a pinned digest whose closure gains or loses a site is refused;
    a branch into a window and an indirect jump in a site's region are
    refused.
 9. Composition breaks other patches. Guard: with sysreg-zero and with
    SNAP_NATIVE_CALLS (private and HVC) the native contract is unchanged and
    the image is stock plus exactly the HVC words, the sysreg sites and these
    sites; the site sets are disjoint.
10. A second application or a bad flag. Guard: patching patched data is
    refused; SNAP_KERNEL_REFMOD_SKIP=2 and a non-boolean keyword are refused.
"""
import argparse
import bisect
import contextlib
import hashlib
import importlib
import io
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone import arm64 as A

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'probes'))
kc_load = importlib.import_module('kc-load')
import refmodskip as z  # noqa: E402
import sysregzero  # noqa: E402
from nativecalls import HVC_WORD  # noqa: E402

KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
XNU = ROOT / 'gpu/adreno/pmap-panic/xnu-12377/osfmk'
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Kernels/kernel.release.t8140')
DSYM = KDK.with_name(KDK.name + '.dSYM') / 'Contents/Resources/DWARF' / KDK.name
ENV = ('SNAP_KERNEL_REFMOD_SKIP', 'SNAP_KERNEL_SYSREG_ZERO', 'SNAP_NATIVE_CALLS', 'SNAP_SPTM_HVC_CALLS', 'SNAP_SEED')
NOP = 0xd503201f
MASK = (1 << 64) - 1
VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE = 1, 2, 4
POLICY = {'vm_page_balance_inactive': 'vm_pageout.c', 'vm_fault_deactivate_behind': 'vm_fault.c'}
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


def define(path, name):
    m = re.search(r'#define\s+' + name + r'\s+(0x[0-9a-fA-F]+|\d+)', (XNU / path).read_text())
    need(m is not None, f'{name} not in {path}')
    return int(m.group(1), 0)


@contextlib.contextmanager
def environment(**values):
    saved = {k: os.environ.get(k) for k in ENV}
    try:
        for k in ENV:
            os.environ.pop(k, None)
        os.environ['SNAP_SEED'] = 'test-kernel-refmod-skip'
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
    """Independent decoding of the image's executable segments (numpy, capstone)."""

    def __init__(self, image):
        self.image = image
        self.segments = [(va, off, size) for _, va, _, off, size in image.executable_segments]
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        pcs, words = [], []
        for va, off, size in self.segments:
            w = np.frombuffer(image.data, dtype='<u4', count=size // 4, offset=off)
            words.append(w)
            pcs.append(np.uint64(va) + np.arange(len(w), dtype=np.uint64) * np.uint64(4))
        self.words, self.pcs = np.concatenate(words), np.concatenate(pcs)

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

    def targets(self):
        """(pc, target, is_call) arrays for every direct branch, decoded with numpy."""
        w = self.words.astype(np.int64)
        pc = self.pcs.astype(np.int64)        # two's complement view of the upper half

        def sext(v, bits):
            return np.where(v & (1 << (bits - 1)), v - (1 << bits), v)
        imm26 = (w & 0xfc000000 == 0x94000000) | (w & 0xfc000000 == 0x14000000)
        imm19 = (w & 0xff000000 == 0x54000000) | (w & 0x7e000000 == 0x34000000)
        imm14 = w & 0x7e000000 == 0x36000000
        target = np.where(imm26, pc + 4 * sext(w & 0x3ffffff, 26),
                          np.where(imm19, pc + 4 * sext((w >> 5) & 0x7ffff, 19),
                                   pc + 4 * sext((w >> 5) & 0x3fff, 14)))
        keep = imm26 | imm19 | imm14
        call = (w & 0xfc000000) == 0x94000000
        return pc[keep].astype(np.uint64), target[keep].astype(np.uint64), call[keep]


def kdk_symbols():
    out = subprocess.run(['nm', '-n', str(DSYM)], capture_output=True, text=True,
                         check=True).stdout
    rows = sorted({(int(p[0], 16), p[2]) for p in (line.split() for line in out.splitlines())
                   if len(p) == 3 and p[1] in 'tTsS'})  # the dSYM marks functions 's'
    return [a for a, _ in rows], [n for _, n in rows]


def dwarf(name):
    """[(tag, name, has_type)] for the subprogram and its direct parameters."""
    out = subprocess.run(['xcrun', 'dwarfdump', f'--name={name}', '--show-children', str(DSYM)],
                         capture_output=True, text=True, check=True).stdout
    entries, current = [], None
    for line in out.splitlines():
        m = re.match(r'0x[0-9a-f]+:(\s+)(DW_TAG_\w+)', line)
        if m:
            current = [len(m.group(1)), m.group(2), None, False]
            entries.append(current)
        elif current and 'DW_AT_name' in line and current[2] is None:
            current[2] = re.search(r'\("(.*)"\)', line).group(1)
        elif current and 'DW_AT_type' in line:
            current[3] = True
    need(entries and entries[0][1] == 'DW_TAG_subprogram' and entries[0][2] == name, f'no DWARF for {name}')
    depth, params = entries[0][0], []
    for e in entries[1:]:
        if e[0] <= depth:
            break
        if e[1] == 'DW_TAG_formal_parameter' and e[0] == depth + 2:
            params.append(e[2])
    return entries[0][3], params


def emulate(code, entry, args):
    """Concrete walk of the function's entry for x0..x4 = args, to its first
    branch out of the function. Returns (target, {x0..x5}). Only the
    instruction forms of this entry are modelled; anything else fails."""
    regs = {f'x{n}': None for n in range(31)}
    regs.update({f'x{n}': v for n, v in enumerate(args)})
    md, pc, flags = code.md, entry, None
    for _ in range(200):
        i = code.insn(pc)
        m, ops = i.mnemonic, i.operands
        name = [md.reg_name(op.reg) if op.type == A.ARM64_OP_REG else None for op in ops]

        def val(k):
            if ops[k].type == A.ARM64_OP_IMM:
                return ops[k].imm & MASK
            r = name[k]
            if r in ('xzr', 'wzr'):
                return 0
            v = regs['x' + r[1:] if r[0] == 'w' else r]
            need(v is not None, f'{pc:#x}: {m} reads an unknown {r}')
            return v & 0xffffffff if r[0] == 'w' else v

        def put(k, v):
            r = name[k]
            regs['x' + r[1:] if r[0] == 'w' else r] = v & (0xffffffff if r[0] == 'w' else MASK)
        nxt = pc + 4
        if m in ('pacibsp', 'autibsp', 'stp') or (m in ('add', 'sub') and name[0] in ('sp', 'fp')):
            pass
        elif m == 'ldp':
            for r in name[:2]:
                regs['x29' if r == 'fp' else 'x30' if r == 'lr' else r] = None
        elif m == 'mov':
            put(0, val(1))
        elif m in ('orr', 'and'):
            put(0, val(1) | val(2) if m == 'orr' else val(1) & val(2))
        elif m == 'ubfiz':
            put(0, (val(1) & ((1 << ops[3].imm) - 1)) << ops[2].imm)
        elif m in ('cmp', 'tst'):
            flags = (val(0) - val(1)) & MASK == 0 if m == 'cmp' else val(0) & val(1) == 0
        elif m == 'csel' and i.cc in (A.ARM64_CC_EQ, A.ARM64_CC_NE):
            put(0, val(1) if flags == (i.cc == A.ARM64_CC_EQ) else val(2))
        elif m in ('tbz', 'tbnz'):
            if ((val(0) >> ops[1].imm) & 1) == (m == 'tbnz'):
                nxt = ops[2].imm & MASK
        elif m in ('b.eq', 'b.ne'):
            if flags == (m == 'b.eq'):
                nxt = ops[0].imm & MASK
        elif m == 'b':
            return ops[0].imm & MASK, {k: regs[k] for k in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5')}
        else:
            raise SystemExit(f'FAIL: {pc:#x}: {m} {i.op_str} is outside the modelled entry')
        pc = nxt
    raise SystemExit('FAIL: the entry walk did not leave the function')


CALLER_SAVED = frozenset(f'x{n}' for n in range(18))


def liveness(code, start, entries, callers, regs=CALLER_SAVED, depth=0, limit=2000):
    """Read-before-write of regs on every path from start to a call or return."""
    md, bad, seen, work, visited = code.md, [], set(), [(start, frozenset())], 0

    def x(r):
        return 'x' + r[1:] if r[0] == 'w' and r[1:].isdigit() else r
    while work:
        pc, written = work.pop()
        while (pc, written) not in seen and visited < limit:
            seen.add((pc, written))
            visited += 1
            i = code.insn(pc)
            reads, writes = i.regs_access()
            bad += [(pc, i.mnemonic, r) for r in {x(md.reg_name(v)) for v in reads} & regs - written]
            written |= {x(md.reg_name(v)) for v in writes} & regs
            if i.group(CS_GRP_CALL):
                break
            if i.group(CS_GRP_RET):
                if 'x0' in regs and 'x0' not in written:
                    need(depth < 3, f'{pc:#x}: x0 unwritten through too many returns')
                    owner = entries[bisect.bisect_right(entries, pc) - 1]
                    for site in callers.get(owner, ()):
                        bad += liveness(code, site + 4, entries, callers, frozenset({'x0'}), depth + 1, limit)[0]
                        visited += 1
                break
            if i.group(CS_GRP_JUMP):
                op = i.operands[-1] if i.operands else None
                need(op is not None and op.type == A.ARM64_OP_IMM, f'{pc:#x}: indirect jump after a site')
                if i.mnemonic == 'b':
                    pc = op.imm & MASK
                    continue
                work.append((op.imm & MASK, written))
            pc += 4
        need(visited < limit, f'{start:#x}: liveness walk did not close')
    return bad, visited


def admission(image, found, code):
    """Failure modes 8 and 10 on modified copies of the real image."""
    stock = bytes(image.data)
    need(refused(lambda: z.admit(kc_load.Image(stock[:-1] + bytes([stock[-1] ^ 1]))),
                 'no reviewed refmod-skip closure'), 'a changed kernel digest was admitted')

    def offset(va):
        return next(off + va - v for v, off, size in code.segments if v <= va < v + size)
    others = [pc for pc, before in found['calls'] if set(before) != z.ARGUMENTS]
    reference = next(pc for pc, before in found['calls']
                     if before == [0x52800801, 0x52800002, 0xd2800003, 0xd2800004])  # pmap_clear_reference
    site = found['sites'][0]
    lo, hi = site['region']
    filler = next(va for va in range(lo, site['va'] - 16, 4) if code.word(va) & 0xffc00000 == 0xf9400000)  # an LDR
    b_into = 0x14000000 | (((site['va'] - 8) - filler) >> 2 & 0x3ffffff)
    for name, edits, text in (
            ('added site', {reference - 12: 0x52800402}, 'closure differs'),       # its MOVZ W2, #0 -> #0x20
            ('removed site', {site['va'] - 12: 0x52800002}, 'closure differs'),
            ('branch into a window', {filler: b_into}, 'lands inside the argument window'),
            ('indirect jump in a region', {filler: 0xd61f0200}, 'indirect jump in the containing region')):
        changed = bytearray(stock)
        for va, word in edits.items():
            struct.pack_into('<I', changed, offset(va), word)
        other = kc_load.Image(bytes(changed))
        digest = hashlib.sha256(other.data).hexdigest()
        z.PINS[digest] = z.PINS[z.J700_26A428]
        try:
            need(refused(lambda: z.admit(other), text), f'{name}: admitted')
        finally:
            del z.PINS[digest]
    need(len(others) == 14, 'not 14 other calls')
    loaded = bytearray(stock)
    for off, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', loaded, off, value)
    z.patch(image, loaded)
    need(refused(lambda: z.patch(image, loaded), 'already modified'), 'patched data was patched again')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--output', type=Path, help='fresh directory for the site manifest')
    args = ap.parse_args()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    image = kc_load.Image(KERNELCACHE.read_bytes())
    need(hashlib.sha256(image.data).hexdigest() == z.J700_26A428, 'not the J700 26A428 kernelcache')
    found = z.find(image)
    pin = z.PINS[z.J700_26A428]
    need(z.closure(found) == {k: pin[k] for k in ('function', 'string_refs', 'calls', 'sites', 'closure_sha256')},
         'decoded closure differs from the pin')
    sites, function = found['sites'], found['function']
    code = Code(image)

    # 3. The function, independently.
    sym = runpy_symbolicator()
    seg, kva = sym.translate(function)
    addrs, names = kdk_symbols()
    i = bisect.bisect_right(addrs, kva) - 1
    need(seg == '__TEXT_EXEC' and addrs[i] == kva and names[i] == '_phys_attribute_clear_with_flush_range',
         'the decoded function is not the KDK phys_attribute_clear_with_flush_range')
    typed, params = dwarf('phys_attribute_clear_with_flush_range')
    need(not typed and params == ['pn', 'bits', 'options', 'arg', 'flush_range'],
         'phys_attribute_clear_with_flush_range is not void (pn, bits, options, arg, flush_range)')
    pcs, targets, calls = code.targets()
    bl = sorted(int(p) for p in pcs[calls & (targets == np.uint64(function))])
    need(bl == [pc for pc, _ in found['calls']], 'an independent decode finds other BLs to the function')
    entries = sorted({int(t) for t in targets[calls]})

    # 4. The arguments and what the skipped call does with them.
    referenced = define('arm64/sptm/pmap/pmap_data.h', 'PP_ATTR_REFERENCED')
    modified = define('arm64/sptm/pmap/pmap_data.h', 'PP_ATTR_MODIFIED')
    noflush = define('vm/pmap.h', 'PMAP_OPTIONS_NOFLUSH')
    need((referenced, modified, noflush) == (z.PP_ATTR_REFERENCED, 0x80, z.PMAP_OPTIONS_NOFLUSH),
         'PP_ATTR_REFERENCED/PMAP_OPTIONS_NOFLUSH differ from xnu-12377')
    expected_args = {('w1', referenced), ('w2', noflush), ('x3', 0), ('x4', 0)}
    fafr = None
    for s in sites:
        window = [code.insn(s['va'] - 16 + 4 * k) for k in range(5)]
        decoded = {(i.reg_name(i.operands[0].reg), i.operands[1].imm) for i in window[:4] if i.mnemonic == 'mov'}
        need(decoded == expected_args and len(window[:4]) == 4, f'{s["va"]:#x}: arguments decode to {decoded}')
        need(window[4].mnemonic == 'bl' and window[4].operands[0].imm & MASK == function, f'{s["va"]:#x}: not BL')
        after = code.insn(s['va'], NOP)
        need(after.mnemonic == 'nop' and s['replacement'] == NOP, f'{s["va"]:#x}: replacement is not NOP')
    for bits, options, writable in ((referenced, noflush, True), (referenced | modified, 0, False),
                                    (modified, 0, False)):
        target, out = emulate(code, function, (0x1234, bits, options, 0, 0))
        fafr = target if fafr is None else fafr
        need(target == fafr, 'the entry walks reach different functions')
        need(out['x0'] == 0x1234 and out['x2'] == options and out['x3'] == 0 and out['x4'] == bits and
             out['x5'] == 0, f'bits {bits:#x}: tail-call arguments {out}')
        need(bool(out['x1'] & VM_PROT_WRITE) == writable and
             (not out['x1'] & (VM_PROT_READ | VM_PROT_EXECUTE)) == bool(bits & referenced),
             f'bits {bits:#x}: allow_mode {out["x1"]:#x}')
    seg, kfafr = sym.translate(fafr)
    i = bisect.bisect_right(addrs, kfafr) - 1
    need(addrs[i] == kfafr and names[i] == '_arm_force_fast_fault_with_flush_range',
         'the skipped call does not tail-call arm_force_fast_fault_with_flush_range')
    typed, params = dwarf('arm_force_fast_fault_with_flush_range')
    need(params == ['ppnum', 'allow_mode', 'options', 'locked_pvh', 'bits_to_clear', 'flush_range'],
         f'arm_force_fast_fault_with_flush_range parameters {params}')
    untouched = [(pc, before) for pc, before in found['calls'] if pc not in {s['va'] for s in sites}]
    for pc, before in untouched:
        need(set(before) != z.ARGUMENTS, f'{pc:#x}: a reference-clear call left out')

    # 5. Straight-line windows: no direct branch lands inside; no indirect
    # jump in the KDK function; no BTI landing pad in the window.
    landing = set(int(t) for t in targets)
    for s in sites:
        need(not any(a in landing for a in range(s['va'] - 12, s['va'] + 4, 4)), f'{s["va"]:#x}: branch into window')
        _, ks = sym.translate(s['va'])
        k = bisect.bisect_right(addrs, ks) - 1
        lo, hi = s['va'] - (ks - addrs[k]), s['va'] + (addrs[k + 1] - ks)
        jumps = [a for a in range(lo, hi, 4) if code.word(a) & 0xfeff0000 == 0xd61f0000]
        need(not jumps, f'{s["va"]:#x}: indirect jump in {names[k]}')
        need(all(code.word(a) & 0xffffff3f != 0xd503241f for a in range(s['va'] - 12, s['va'] + 4, 4)),
             f'{s["va"]:#x}: BTI in the window')
        s['function'] = names[k].lstrip('_')
        s['kdk_bounds'] = (lo, hi)

    # 6. What the caller sees after the call.
    callers = {}
    for p, t in zip(pcs[calls], targets[calls]):
        callers.setdefault(int(t), []).append(int(p))
    walked = 0
    for s in sites:
        bad, visited = liveness(code, s['va'] + 4, entries, callers)
        need(not bad, f'{s["va"]:#x}: caller-saved registers read after the call: {bad[:4]}')
        walked += visited

    # 7. The policy: KDK inline chains.
    for s in sites:
        out = subprocess.run(['atos', '-o', str(DSYM), '-arch', 'arm64e', '-i', hex(sym.translate(s['va'])[1])],
                             capture_output=True, text=True, check=True).stdout
        chain = [line.split(' (in ')[0] + ' ' + line.rsplit('(', 1)[-1].rstrip(')') for line in out.splitlines()
                 if line.strip()]
        s['chain'] = chain
        need(len(chain) >= 4 and chain[-2].startswith('pmap_clear_refmod_options pmap.c:') and
             chain[-1].split()[0] in POLICY and chain[-1].split()[1].startswith(POLICY[chain[-1].split()[0]] + ':'),
             f'{s["va"]:#x}: inline chain {chain}')
    need(sorted(s['chain'][-1].split()[0] for s in sites) == sorted(POLICY), 'not one site per policy function')

    admission(image, found, code)

    import xnuboot as xb
    xb.configure_guest('j700ap-26A428', KERNELCACHE.parent)
    log = io.StringIO()
    stock = bytearray(image.data)
    for off, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', stock, off, value)
    segments = code.segments

    def uploaded(built):
        out = []
        for va, _, size in segments:
            pa = xb.IMAGE_PA + va - image.vmin
            blobs = [bytes(blob[pa - base:pa - base + size]) for base, blob in built['chunks'].items()
                     if base <= pa and pa + size <= base + len(blob)]
            need(len(blobs) == 1, f'executable segment {va:#x} not uploaded whole, once')
            out.append(blobs[0])
        return out

    def expected(replaced):
        out = []
        for va, off, size in segments:
            body = bytearray(stock[off:off + size])
            for site, word in replaced.items():
                if va <= site < va + size:
                    struct.pack_into('<I', body, site - va, word)
            out.append(bytes(body))
        return out

    # 1, 2 and 10.
    with environment():
        default = build(xb, log)
        need(default['kernel_refmod_skip'] is None, 'default build reports a refmod patch')
        need(uploaded(default) == expected({}), 'default build executable bytes differ from the stock loaded image')
        explicit_off = build(xb, log, refmod_skip=False)
        need(refused(lambda: build(xb, log, refmod_skip='1'), 'explicit boolean'), 'non-boolean keyword accepted')
    with environment(SNAP_KERNEL_REFMOD_SKIP='0'):
        zero = build(xb, log)
    with environment(SNAP_KERNEL_REFMOD_SKIP='2'):
        need(refused(lambda: build(xb, log), 'must be 0 or 1'), 'SNAP_KERNEL_REFMOD_SKIP=2 accepted')
    for name, other in (('SNAP_KERNEL_REFMOD_SKIP=0', zero), ('refmod_skip=False', explicit_off)):
        need(other['chunks'] == default['chunks'], f'{name} build differs from the default build')
    with environment(SNAP_KERNEL_REFMOD_SKIP='1'):
        patched = build(xb, log)
    with environment():
        keyword = build(xb, log, refmod_skip=True)
    need(keyword['chunks'] == patched['chunks'], 'keyword and environment builds differ')
    record = patched['kernel_refmod_skip']
    need(record['closure_sha256'] == pin['closure_sha256'] and record['sites'] == len(sites) and
         record['function'] == function, 'loader record')
    need({k: len(v) for k, v in patched['chunks'].items()} == {k: len(v) for k, v in default['chunks'].items()},
         'chunk geometry changed')
    changed_chunks = [k for k in default['chunks'] if default['chunks'][k] != patched['chunks'][k]]
    need(all(xb.IMAGE_PA <= k < xb.IMAGE_PA + image.vmax - image.vmin for k in changed_chunks),
         'a non-image chunk changed (params, device tree or handoff)')
    replaced = {s['va']: NOP for s in sites}
    need(uploaded(patched) == expected(replaced), 'patched executable bytes are not stock plus exactly the sites')
    diff = 0
    for k in changed_chunks:
        a, b = np.frombuffer(default['chunks'][k], dtype=np.uint8), np.frombuffer(patched['chunks'][k], dtype=np.uint8)
        diff += int(np.count_nonzero(a != b))
    need(0 < diff <= 4 * len(sites), f'{diff} bytes differ, more than the site words')
    del explicit_off, zero, keyword

    # 9. With sysreg-zero, and with native calls (private and HVC).
    sysreg = {s['va']: s['replacement'] for s in sysregzero.find(image)}
    need(not set(sysreg) & set(replaced), 'a refmod site is a sysreg site')
    with environment(SNAP_KERNEL_SYSREG_ZERO='1'):
        both = build(xb, log, refmod_skip=True)
    need(uploaded(both) == expected({**sysreg, **replaced}), 'sysreg-zero plus refmod-skip is not stock plus both')
    for hvc in ('0', '1'):
        with environment(SNAP_NATIVE_CALLS='1', SNAP_SPTM_HVC_CALLS=hvc):
            base = build(xb, log)
            all3 = build(xb, log, refmod_skip=True, sysreg_zero=True)
        contract = base['native_call_contract']
        need(all3['native_call_contract']['pages'] == contract['pages'] and all3['stub_pa'] == base['stub_pa'] and
             all3['sptm_hvc_calls'] == (hvc == '1'), 'native-call contract changed under refmod-skip')
        need(not set(contract['call_sites']) & set(replaced) and not set(contract['writer_sites']) & set(replaced),
             'a refmod site is a native call or writer site')
        hvc_words = {va: HVC_WORD for va in contract['call_sites']} if hvc == '1' else {}
        need(uploaded(all3) == expected({**hvc_words, **sysreg, **replaced}),
             f'HVC={hvc}: image differs from stock beyond the HVC words, sysreg sites and refmod sites')
        del base, all3

    manifest = dict(kernel_sha256=z.J700_26A428, closure={k: (hex(v) if k == 'function' else v)
                                                          for k, v in z.closure(found).items()},
                    function='phys_attribute_clear_with_flush_range',
                    arguments=dict(bits='PP_ATTR_REFERENCED 0x40', options='PMAP_OPTIONS_NOFLUSH 0x20',
                                   arg='NULL', flush_range='NULL'),
                    skipped_call=dict(tail_call='arm_force_fast_fault_with_flush_range', allow_mode='VM_PROT_WRITE',
                                      bits_to_clear='PP_ATTR_REFERENCED'),
                    sites=[dict(va=hex(s['va']), function=s['function'], chain=s['chain'],
                                before=f'{s["word"]:#010x}', after=f'{NOP:#010x}') for s in sites],
                    left_alone=[dict(va=hex(pc), arguments=[f'{w:#010x}' for w in before]) for pc, before in untouched])
    if args.output:
        (args.output / 'refmod-skip-sites.json').write_text(json.dumps(manifest, indent=1) + '\n')
    print(f'PASS: {checks} checks; {len(sites)} sites ({", ".join(s["function"] for s in sites)}) BL -> NOP; '
          f'{len(untouched)} other calls unchanged; {walked} instructions walked after the sites; defaults unchanged')


def runpy_symbolicator():
    import runpy
    return runpy.run_path(str(ROOT / 'tools/kc-symbolicate.py'))['Symbolicator']()


if __name__ == '__main__':
    main()
