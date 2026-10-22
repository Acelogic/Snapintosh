#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Apple's SPTM operation x frame-type x options matrix, and where we differ.

Everything here is read out of the pinned sptm.t8140.release (26A428):

  * every frame type's descriptor (table ...2709e230, stride 144): name, kind,
    mapping policy (+4, 4-bit permission classes), retype transitions (+0x40),
    which data types a table type admits (+0x50), mixed aliases (+0x33) and
    deferred-revocation support (+0x34);
  * the UPDATE permission rows (...2701a8b8 applied, ...2701a938 ignored,
    ...2701a9b8 option800-only), replayed through Apple's own helper
    ...270fd544 under unicorn over EVERY (data type, old class, requested
    class, options, AF, WIRED) cell and compared with the monitor's C
    selection (tools/test-sptm-matrix.c --batch); plus every AttrIndx pair
    with XNU's shareability values under the SH/AttrIndx options (0x10/0x20,
    pmap_batch_set_cache_attributes' 0x130);
  * the MAP_PAGE admission prefix (...270f8f18..f9230): which bits of the
    requested descriptor Apple inspects at all (never AttrIndx or SH);
  * with --kernel, what the pinned kernelcache can issue: every RETYPE call
    site's (old, new) literals and every UPDATE option constant, including
    UPDATE_DISJOINT_MULTIPAGE (endpoint 0x15) header options.

    tools/replay-sptm-matrix.py --check-c /tmp/test-sptm-matrix [--kernel]

The unicorn replay proves descriptor selection only: no source CAS, reference
atomics, TLBI or deferred bookkeeping executes (as tools/replay-user-update.py).
"""
import collections
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE  # noqa: E402
import unicorn.arm64_const as reg  # noqa: E402

BASE = 0xfffffff027000000
SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
DESCRIPTORS, STRIDE, NAMES = 0xfffffff02709e230, 144, 0xfffffff02701e6b8
ROWS = dict(allowed=0xfffffff02701a8b8, ignored=0xfffffff02701a938,
            fault=0xfffffff02701a9b8)
HELPER, RETURN, DEFERRED = BASE + 0xfd544, BASE + 0xfd8f0, BASE + 0xfda34
POLICY_PANIC, ROW_PANIC = BASE + 0xfd904, BASE + 0xfd94c
MAP_PAGE, MAP_PAGE_CAS = 0xfffffff0270f8f18, 0xfffffff0270f9230


def image():
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](
        ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest() != SPTM_SHA:
        raise ValueError('SPTM differs from the selected 26A428 image')
    return im


def descriptors(im):
    out = {}
    for kind in range(0x44):
        address = DESCRIPTORS + kind * STRIDE
        off = im.locate(address)[1]
        if off is None:
            break
        d = im.data[off:off + STRIDE]
        out[kind] = dict(
            name=im.string(im.pointer(NAMES + kind * 8)), kind=d[1],
            policy=int.from_bytes(d[4:6], 'little'),
            transitions=int.from_bytes(d[0x40:0x50], 'little'),
            admits=int.from_bytes(d[0x50:0x60], 'little'),
            mixed_aliases=d[0x33] & 1, deferred=d[0x34] & 1)
    return out


def rows(im):
    result = {}
    for name, va in ROWS.items():
        off = im.locate(va)[1]
        result[name] = list(struct.unpack_from('<32I', im.data, off))
    return result


def bits(v, n=128):
    return [i for i in range(n) if v >> i & 1]


def pte(cls, af=1, wired=0, pa=0x94280c000):
    return (pa | 3 | 0x800 | 0x200 | (af << 10) | ((cls & 12) << 4) |
            ((cls & 3) << 53) | ((cls >> 4) << 59) | (wired << 58))


class Helper:
    """Apple's UPDATE descriptor helper with a DEFAULT-like data frame."""
    def __init__(self, im):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(BASE, 0x200000)
        for _, va, _, off, size in im.segs:
            u.mem_write(va, im.data[off:off + size])
        u.mem_map(0x1000000, 0x100000)
        self.context, self.data, self.table, self.out = 0x1010000, 0x1011000, 0x1012000, 0x1013000
        u.mem_write(self.context, self.data.to_bytes(8, 'little') + self.table.to_bytes(8, 'little'))
        u.mem_write(self.table + 2, bytes([20]))
        for a in (RETURN, DEFERRED, POLICY_PANIC, ROW_PANIC):
            u.hook_add(UC_HOOK_CODE, lambda uc, *_: uc.emu_stop(), begin=a, end=a)
        self.u, self.type = u, None

    def run(self, data_type, old, requested, options):
        u = self.u
        if data_type != self.type:
            u.mem_write(self.data + 2, bytes([data_type]))
            self.type = data_type
        u.mem_write(self.out, bytes(8))
        for n, value in enumerate((self.context, old, requested, options, self.out)):
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        u.reg_write(reg.UC_ARM64_REG_SP, 0x1080000)
        u.emu_start(HELPER, BASE + 0xfdb34, count=2000)
        pc = u.reg_read(reg.UC_ARM64_REG_PC)
        if pc not in (RETURN, DEFERRED, POLICY_PANIC, ROW_PANIC):
            raise ValueError(f'type {data_type} {old:x}->{requested:x} {options:x}: helper ended at {pc:x}')
        return (pc in (POLICY_PANIC, ROW_PANIC),
                int.from_bytes(u.mem_read(self.out, 8), 'little'), pc == DEFERRED)


OPTIONS = (1, 2, 3, 8, 9, 0xa, 0xb, 0x102, 0x10a, 0x40a, 0x50a, 0x802, 0x90a, 0xc0a)
USER_TYPES = (0, 11, 14, 15, 16, 17, 25, 26, 29, 30, 31, 35, 37)
KERNEL_TYPES = (11, 35)
# SH (0x10) and AttrIndx (0x20), alone, as pmap_batch_set_cache_attributes
# sends them (0x130), and with WIRED, AF (and 0x800) and permissions.
ATTR_OPTIONS = (0x10, 0x20, 0x30, 0x130, 0x31, 0x38, 0x838, 0x12, 0x22, 0x13a)
ATTR_TYPES = (11, 14, 17, 26, 35)


def attr_pte(cls, attr, sh, ns=0):
    return (pte(cls) & ~0x33c) | (attr << 2) | (sh << 8) | (ns << 5)


def cells():
    for data_type in sorted(set(USER_TYPES) | set(KERNEL_TYPES)):
        for old_class in range(32):
            for new_class in range(32):
                for options in OPTIONS:
                    for old_af, new_af in ((1, 1), (1, 0), (0, 1)):
                        for wired in ((0, 1) if options & 1 else (0,)):
                            yield (data_type, pte(old_class, old_af),
                                   pte(new_class, new_af, wired), options)
    # Every AttrIndx pair and the shareability values XNU issues (0 for WC,
    # 2 outer, 3 inner), with a template NS bit Apple copies only in stage-2
    # tables, on the fixed user and kernel classes and one permission change.
    for data_type in ATTR_TYPES:
        for old_class, new_class in ((7, 7), (7, 15), (15, 15), (3, 3), (3, 11), (13, 13)):
            for old_attr in range(8):
                for new_attr in range(8):
                    for old_sh, new_sh, ns in ((2, 0, 0), (0, 2, 1), (3, 3, 0), (2, 3, 1)):
                        for options in ATTR_OPTIONS:
                            yield (data_type, attr_pte(old_class, old_attr, old_sh),
                                   attr_pte(new_class, new_attr, new_sh, ns), options)


def compare(im, binary):
    helper = Helper(im)
    work = list(cells())
    lines = []
    for data_type, old, requested, options in work:
        if data_type in USER_TYPES:
            lines.append(f'{old:x} {requested:x} {options:x} {data_type:x} 0')
        if data_type in KERNEL_TYPES:
            lines.append(f'{old:x} {requested:x} {options:x} {data_type:x} 1')
    run = subprocess.run([binary, '--batch'], input='\n'.join(lines) + '\n',
                         capture_output=True, text=True, check=True)
    answers = iter(run.stdout.split('\n'))
    stats = collections.Counter()
    differences = []
    admitted_by_apple_refused_by_kernel = collections.Counter()
    for data_type, old, requested, options in work:
        rejected, new, deferred = helper.run(data_type, old, requested, options)
        stats['apple_rejected' if rejected else 'apple_admitted'] += 1
        stats['deferred'] += deferred
        for kernel in (0, 1):
            if (data_type in KERNEL_TYPES) if kernel else (data_type in USER_TYPES):
                status, value = next(answers).split()
                c_ok, value = status == '0', int(value, 16)
                from4 = ((old >> 4) & 12) | ((old >> 53) & 3)
                to4 = ((requested >> 4) & 12) | ((requested >> 53) & 3)
                if c_ok and not rejected and value == new:
                    stats['equal'] += 1
                elif not c_ok and rejected:
                    stats['both_refuse'] += 1
                elif kernel and not c_ok and not rejected and from4 != to4 and to4 not in (3, 11):
                    # The kernel root keeps only classes its views enforce natively.
                    admitted_by_apple_refused_by_kernel[(from4, to4)] += 1
                    stats['kernel_narrower'] += 1
                else:
                    stats['different'] += 1
                    if len(differences) < 20:
                        differences.append(dict(type=data_type, kernel=kernel, old=hex(old),
                            requested=hex(requested), options=hex(options), apple_rejected=rejected,
                            apple=hex(new), c_status=status, c=hex(value)))
    if next(answers, '') != '':
        raise ValueError('C batch produced extra answers')
    return dict(cells=len(work), stats=dict(stats), differences=differences,
                kernel_narrower=sorted(f'{a}->{b}' for a, b in admitted_by_apple_refused_by_kernel))


def c_tables(binary):
    run = subprocess.run([binary, '--tables'], capture_output=True, text=True, check=True)
    policy, row, retype = {}, {}, {}
    for line in run.stdout.splitlines():
        f = line.split()
        if f[0] == 'policy':
            policy[int(f[1])] = int(f[2], 16)
        elif f[0] == 'rows':
            row[int(f[1])] = tuple(int(x, 16) for x in f[2:5])
        elif f[0] == 'retype':
            retype[int(f[1])] = (int(f[2], 16), int(f[3], 16))
    return policy, row, retype


def map_page_bits(im):
    """Every use of the requested descriptor (x20) before the CAS loop, and
    the descriptor bits those uses can observe."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    off = im.locate(MAP_PAGE)[1]
    code = list(md.disasm(im.data[off:off + (MAP_PAGE_CAS - MAP_PAGE)], MAP_PAGE))
    uses, touched = [], 0
    for n, i in enumerate(code):
        ops = [o.strip() for o in i.op_str.split(',')]
        reads = any(o in ('x20', 'w20') for o in ops[1:]) or \
            (i.mnemonic in ('tst', 'tbz', 'tbnz') and ops[0] in ('x20', 'w20'))
        if not reads:
            continue
        uses.append(f'{i.address:x}: {i.mnemonic} {i.op_str}')
        nums = [int(x, 0) for x in re.findall(r'#(-?0x[0-9a-f]+|-?\d+)', i.op_str)]
        if i.mnemonic in ('tbz', 'tbnz'):
            touched |= 1 << nums[0]
        elif i.mnemonic in ('ubfx', 'bfxil'):
            touched |= ((1 << nums[1]) - 1) << nums[0]
        elif i.mnemonic == 'and':
            touched |= nums[0] & ((1 << 64) - 1)
        elif i.mnemonic in ('lsr', 'mvn'):
            # Follow the shifted/inverted copy to the mask that consumes it.
            shift = nums[0] if i.mnemonic == 'lsr' else 0
            dest = ops[0][1:]
            for j in code[n + 1:n + 6]:
                jops = [o.strip() for o in j.op_str.split(',')]
                if any(o[1:] == dest for o in jops[1:] + ([jops[0]] if j.mnemonic == 'tst' else [])):
                    m = re.findall(r'#(0x[0-9a-f]+|\d+)', j.op_str)
                    if j.mnemonic in ('and', 'tst') and m:
                        touched |= int(m[-1], 0) << shift
                        break
                    touched |= ((1 << 64) - 1) >> shift << shift
                    break
            else:
                touched |= ((1 << 64) - 1) >> shift << shift
        elif i.mnemonic == 'tst' and ops[1] == 'x9':
            touched |= 0xf38b000000000000   # the forbidden-bit mask built at f8fb0
        else:
            touched |= (1 << 64) - 1
    return dict(uses=uses, examined_bits=bits(touched, 64))


def kernel_issues():
    """RETYPE literals and UPDATE options the pinned kernel can issue."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    path = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
    kc = runpy.run_path(str(ROOT / 'tools/kc-xref.py'))['Kernelcache'](path)
    if hashlib.sha256(kc.data).hexdigest() != KERNEL_SHA:
        raise ValueError('kernel differs from the selected 26A428 image')
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    start, size = kc.section('__TEXT_EXEC', '__text')
    code = kc.data[kc.va2off(start):kc.va2off(start) + size]
    stubs = {0xfffffe000c22b3a8: ('RETYPE', '1', '2', '3'),
             0xfffffe000c22b4d4: ('UPDATE_DISJOINT', '3', None, None),
             0xfffffe000c22b498: ('UPDATE_REGION', '4', None, None),
             0xfffffe000c22ba74: ('UPDATE_DISJOINT_MULTIPAGE', None, None, None)}

    def at(va):
        o = va - start
        got = list(md.disasm(code[o:o + 4], va))
        return got[0] if got else None

    def source(va, register):
        for back in range(1, 60):
            i = at(va - 4 * back)
            if i is None:
                continue
            if i.mnemonic in ('bl', 'b', 'ret', 'blr', 'br'):
                return None
            if re.match(rf'[wx]{register}(,|$)', i.op_str):
                m = re.fullmatch(rf'[wx]{register}, #(0x[0-9a-f]+|\d+)', i.op_str)
                return int(m.group(1), 0) if i.mnemonic == 'mov' and m else f'{i.mnemonic} {i.op_str}'
        return None
    sites = collections.defaultdict(list)
    for o in range(0, len(code), 4):
        w = struct.unpack_from('<I', code, o)[0]
        if w >> 26 != 0b100101:
            continue
        imm = w & 0x3ffffff
        imm -= (imm & (1 << 25)) << 1
        va = start + o
        target = va + imm * 4
        if target in stubs:
            name, a, b, c = stubs[target]
            sites[name].append(dict(site=hex(va), **{k: source(va, r) for k, r in
                                    (('arg1', a), ('arg2', b), ('arg3', c)) if r}))
    # MULTIPAGE header options: literal stores of the u32 options word.
    headers = sorted({hex(int(x, 0)) for x in ('0x130', '0x330')})
    return dict(sites={k: v for k, v in sites.items()}, multipage_cache_header_options=headers)


def main():
    args = sys.argv[1:]
    im = image()
    d = descriptors(im)
    r = rows(im)
    result = dict(sptm_sha256=SPTM_SHA)
    result['types'] = {k: dict(name=v['name'], kind=v['kind'], policy=bits(v['policy'], 16),
                               transitions=[t for t in bits(v['transitions'])],
                               admits=[t for t in bits(v['admits'])],
                               mixed_aliases=v['mixed_aliases'], deferred=v['deferred'])
                       for k, v in d.items() if v['name']}
    result['update_rows'] = {name: {c: bits(x, 32) for c, x in enumerate(v) if x}
                             for name, v in r.items()}
    result['map_page'] = map_page_bits(im)
    examined = set(result['map_page']['examined_bits'])
    assert not examined & {2, 3, 4, 8, 9}, examined
    assert {0, 1, 11, 52, 6, 7, 53, 54} <= examined
    if '--check-c' in args:
        binary = args[args.index('--check-c') + 1]
        policy, crow, retype = c_tables(binary)
        for kind in range(0x44):
            want = d[kind]['policy'] if kind in d else 0
            if policy.get(kind, 0) != want and not (kind >= 48 and policy.get(kind, 0) == 0):
                raise ValueError(f'C policy for type {kind} is {policy.get(kind):#x}, Apple {want:#x}')
        for c in range(32):
            if crow[c] != (r['allowed'][c], r['ignored'][c], r['fault'][c]):
                raise ValueError(f'C permission row {c} differs from the image')
        for old, (apple_c, supported) in retype.items():
            apple = d[old]['transitions'] & ((1 << 64) - 1)
            if old not in (0,) and apple_c != apple:
                raise ValueError(f'C retype word for type {old} differs from the image')
            if supported & ~apple:
                raise ValueError(f'monitor admits a retype Apple refuses from type {old}')
        result['c_tables_match'] = True
        gaps = []
        for old in range(48):
            apple = d[old]['transitions'] & ((1 << 64) - 1)
            supported = retype[old][1]
            if old != 0:
                gaps += [f'{old}->{new} ({d[old]["name"]} -> {d[new]["name"]})'
                         for new in bits(apple & ~supported, 64) if new in d]
        result['retype_admitted_by_apple_only'] = gaps
        result['selection'] = compare(im, binary)
        if result['selection']['stats'].get('different'):
            print(json.dumps(result['selection'], indent=2))
            raise ValueError('C selection differs from Apple')
    if '--kernel' in args:
        result['kernel'] = kernel_issues()
    print(json.dumps(result, indent=1))


if __name__ == '__main__':
    main()
