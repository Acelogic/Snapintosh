#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end offline check of SNAP_KERNEL_SYSREG_ZERO (probes/sysregzero.py).

    python3 tools/test-kernel-sysreg-zero.py [--output NEW_DIR] [--symbolize]

It builds the real loader image for the stock J700 26A428 kernelcache with
the patch off, explicitly off and on, alone and combined with native calls and
the SPTM HVC experiment, and compares the uploaded chunks word by word. It does
not execute XNU and establishes no speedup. --output writes the site manifest
(with --symbolize, each site's function from the KDK, via tools/kc-symbolicate.py).

Failure modes, written before the code:
 1. A default build changes. Guard: with the variable unset or 0 every
    executable word of the uploaded image equals the stock loaded image, and
    the unset, 0 and sysreg_zero=False builds are chunk-for-chunk identical.
 2. Something besides the sites changes. Guard: the patched build has the same
    chunk addresses and lengths, and differs from the default build only in
    the image words at the decoded sites.
 3. A replacement is wrong. Guard: an independent decoder here checks every
    changed word: before, an MRS/MSR of a listed register; after, MOVZ Xt, #0
    with the same Rt (MRS) or NOP (MSR, MRS XZR).
 4. The finder misses an access. Guard: an independent full-word scan of the
    patched image's executable segments finds no access to a listed register.
 5. The registers drift from what the monitor does in either build. Guard: the
    set is exactly the census's 13 lock-only registers plus PMC0, PMC1, PMCR0,
    UPMSR (ignore default) and GXF_STATUS_EL1 (zero case), never
    CONTEXTIDR_EL1 or the JAPIB keys. Each ignored one is in fast_trap_ignored
    and named by no claimed-register macro (tools/test-fast-trap.py holds the
    full unclaimed proof); the locked default and GXF case bodies and the fast
    IGNORE/ZERO bodies are exactly "reads zero"; the locked system-register
    section has no build conditional, so control and fast share it.
 6. An unknown or different kernel is patched. Guard: a changed digest is
    refused; a pinned digest whose decoded closure gains or loses one site is
    refused; a listed-register word outside an executable __text section is
    refused.
 7. Composition breaks the call-entry contracts. Guard: with SNAP_NATIVE_CALLS
    (private and HVC) the native contract and its pages are unchanged, and the
    HVC image differs from stock at exactly the HVC sites plus these sites.
 8. A second application or a bad flag. Guard: patching patched data is
    refused; SNAP_KERNEL_SYSREG_ZERO=2 and a non-boolean keyword are refused.
"""
import argparse
import contextlib
import importlib
import io
import json
import os
import re
import struct
import sys
from pathlib import Path
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'probes'))
kc_load = importlib.import_module('kc-load')
import sysregzero as z  # noqa: E402
from nativecalls import HVC_WORD  # noqa: E402

KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
# docs/SYSREG-CENSUS-20261016.md: PMC2-PMC9 and the five other unclaimed
# registers, all reaching only the monitor's ignore default.
CENSUS = {(3, 2, 15, crm, 0) for crm in (2, 3, 4, 5, 6, 7, 9, 10)} | {
    (3, 4, 15, 15, 6), (3, 4, 15, 10, 4), (3, 1, 15, 1, 5), (3, 4, 15, 1, 4), (3, 4, 15, 1, 3)}
# PMC0, PMC1, PMCR0, UPMSR: the same ignore default. GXF_STATUS_EL1: zero case.
IGNORED = CENSUS | {(3, 2, 15, 0, 0), (3, 2, 15, 1, 0), (3, 1, 15, 0, 0), (3, 7, 15, 6, 4)}
ZERO = {(3, 6, 15, 8, 0)}
EXPECTED = IGNORED | ZERO
EXCLUDED = {(3, 0, 13, 0, 1), (3, 4, 15, 13, 6), (3, 4, 15, 13, 7)}   # CONTEXTIDR_EL1, JAPIBKeyLo/Hi
ENV = ('SNAP_KERNEL_SYSREG_ZERO', 'SNAP_NATIVE_CALLS', 'SNAP_SPTM_HVC_CALLS', 'SNAP_SEED')
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


def access(word):
    """Independent decode: (is_read, (op0, op1, CRn, CRm, op2), Rt) or None."""
    if word >> 22 != 0b1101010100 or not (word >> 20) & 1:
        return None
    op0 = 2 | ((word >> 19) & 1)
    return ((word >> 21) & 1, (op0, (word >> 16) & 7, (word >> 12) & 0xf, (word >> 8) & 0xf, (word >> 5) & 7),
            word & 0x1f)


def movz_zero(word):
    """Rd of MOVZ Xd, #0, LSL #0, else None."""
    return word & 0x1f if word & 0xffe00000 == 0xd2800000 and not (word >> 5) & 0xffff else None


def tuples(path, macro):
    """Every macro(a,b,c,d,e) register tuple in a source file."""
    text = read_source(ROOT / path)
    return {tuple(int(v) for v in m.groups())
            for m in re.finditer(macro + r'\(\s*(\d+)u?\s*,\s*(\d+)u?\s*,\s*(\d+)u?\s*,\s*(\d+)u?\s*,\s*(\d+)u?\s*\)', text)}


def word_at(chunks, pa):
    found = [struct.unpack_from('<I', blob, pa - base)[0] for base, blob in chunks.items()
             if base <= pa and pa + 4 <= base + len(blob)]
    need(len(found) == 1, f'{pa:#x} is not uploaded exactly once')
    return found[0]


@contextlib.contextmanager
def environment(**values):
    saved = {k: os.environ.get(k) for k in ENV}
    try:
        for k in ENV:
            os.environ.pop(k, None)
        os.environ['SNAP_SEED'] = 'test-kernel-sysreg-zero'
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


def admission(image, sites):
    """Failure modes 6 and 8 on modified copies of the real image."""
    stock = bytes(image.data)
    need(refused(lambda: z.admit(kc_load.Image(stock[:-1] + bytes([stock[-1] ^ 1]))),
                 'no reviewed sysreg-zero closure'), 'a changed kernel digest was admitted')
    text = next(s for s in z._sections(image) if s[2] == 'com.apple.kernel' and s[4] == '__text')
    stubs = next(s for s in z._sections(image) if s[4] == '__auth_stubs')

    def offset(va):
        return next(off + va - v for _, v, _, off, size in image.executable_segments if v <= va < v + size)
    pmc2 = 0xd53af200        # MRS X0, S3_2_C15_C2_0
    nop_va = next(va for va in range(text[0], text[1], 4)
                  if struct.unpack_from('<I', stock, offset(va))[0] == z.NOP)
    for name, va, word, text_error in (
            ('added site', nop_va, pmc2, 'closure differs'),
            ('removed site', sites[0]['va'], z.NOP, 'closure differs'),
            ('site outside __text', stubs[0], pmc2, 'outside an executable __text')):
        changed = bytearray(stock)
        struct.pack_into('<I', changed, offset(va), word)
        other = kc_load.Image(bytes(changed))
        digest = __import__('hashlib').sha256(other.data).hexdigest()
        z.PINS[digest] = z.PINS[z.J700_26A428]
        try:
            need(refused(lambda: z.admit(other), text_error), f'{name}: the closure check admitted it')
        finally:
            del z.PINS[digest]
    loaded = bytearray(stock)
    for off, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', loaded, off, value)
    z.patch(image, loaded)
    need(refused(lambda: z.patch(image, loaded), 'already modified'), 'patched data was patched again')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--output', type=Path, help='fresh directory for the site manifest')
    ap.add_argument('--symbolize', action='store_true', help='name each site from the KDK dSYM')
    args = ap.parse_args()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    image = kc_load.Image(KERNELCACHE.read_bytes())
    need(__import__('hashlib').sha256(image.data).hexdigest() == z.J700_26A428, 'not the J700 26A428 kernelcache')
    sites = z.find(image)
    pin = z.PINS[z.J700_26A428]
    need(z.closure(sites) == {k: pin[k] for k in ('sites', 'registers', 'bundles', 'closure_sha256')},
         'decoded closure differs from the pin')

    # 5. The register set and what each monitor build does with it.
    need(set(z.IGNORED) == IGNORED and set(z.ZERO_CASE) == ZERO and z.REGISTERS == {**z.IGNORED, **z.ZERO_CASE},
         'patched registers are not the census set plus PMC0/PMC1/PMCR0/UPMSR and GXF_STATUS_EL1')
    need(not EXCLUDED & set(z.REGISTERS), 'CONTEXTIDR_EL1 or a JAPIB key register is patched')
    header = (ROOT / 'compat/fast-trap.h').read_text()
    start = header.index('fast_trap_ignored[FAST_TRAP_IGNORED]')
    array = header[start:header.index('};', start)]
    ignored = {tuple(int(v) for v in m.groups())
               for m in re.finditer(r'FAST_TRAP_SYSREG\((\d+),(\d+),(\d+),(\d+),(\d+)\)', array)}
    need(len(ignored) == 20 and IGNORED <= ignored, 'an ignored register is not in fast_trap_ignored')
    claimed = (tuples('probes/xnuboot.c', r'#define SR_\w+\s+SYSREG') | tuples('compat/clock.h', 'CLOCK_SYSREG') |
               tuples('compat/ipi.h', 'IPI_SYSREG') | tuples('probes/shadowmmu.c', 'SYSREG') |
               {(3, 6, 15, crm, op2) for crm, op2 in ((1, 5), (1, 6), (3, 0), (3, 1))} |   # compat/sprr.h
               {(3, 4, 15, 1, 0), (3, 4, 15, 1, 1), (3, 4, 15, 0, 4)} |                  # KERNKey, APCTL
               {(3, 0, 2, crm, op2) for crm in (1, 2, 3) for op2 in range(4)})           # address/GA keys
    need(len(claimed) > 30 and not claimed & IGNORED, 'a monitor handler names an ignored register')
    need(ZERO <= claimed, 'GXF_STATUS_EL1 lost its locked case')

    def body(text, label):
        """The normalized statements after `label` up to its break."""
        text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
        m = re.search(re.escape(label) + r'(.*?)break;', text, flags=re.S)
        need(m is not None, f'no {label!r}')
        return re.sub(r'\s+', '', m.group(1))
    monitor = read_source(ROOT / 'probes/xnuboot.c')
    locked = monitor[monitor.index('static int xnuboot_trap_locked'):]
    locked = locked[locked.index('if (ec != 0x18) {'):locked.index('\n#if SNAP_FAST_VCPU_TRAPS')]
    need(not re.search(r'^\s*#\s*(if|ifdef|ifndef|else|elif)', locked, flags=re.M),
         'the locked system-register section differs between monitor builds')
    need(body(locked, 'default:') == 'record(c,EV_SYSREG,*elr,iss,value,is_read);if(is_read)value=0;',
         'the locked default no longer only reads zero and drops writes')
    need(body(locked, 'case SR_GXF_STATUS_EL1:') == 'if(is_read)value=0;', 'the GXF_STATUS_EL1 case changed')
    need(re.sub(r'\s+', '', locked).endswith('if(is_read&&rt!=31)frame[rt]=value;*elr+=4;return0;}'),
         'the locked sysreg epilogue changed')
    need(re.search(r'#define\s+SR_GXF_STATUS_EL1\s+SYSREG\(3,\s*6,\s*15,\s*8,\s*0\)', monitor),
         'SR_GXF_STATUS_EL1 encoding changed')
    need(body(header, 'case FAST_TRAP_IGNORE:') == 'if(is_read)value=0;' and
         body(header, 'case FAST_TRAP_ZERO:') == 'if(is_read)value=0;', 'a fast IGNORE/ZERO body changed')
    zero = header[header.index('static inline int fast_trap_zero_reg'):]
    zero = re.sub(r'/\*.*?\*/|\s+', '', zero[:zero.index('}')], flags=re.S)
    need(zero.endswith('{returnreg==FAST_TRAP_SYSREG(3,6,15,8,0);'),
         'fast_trap_zero_reg is not exactly GXF_STATUS_EL1')

    # 3 on the decoded sites themselves.
    for s in sites:
        is_read, reg, rt = access(s['word'])
        need(reg in EXPECTED and is_read == s['read'] and rt == s['rt'], f'{s["va"]:#x}: site decode')
        need(movz_zero(s['replacement']) == rt if is_read and rt != 31 else s['replacement'] == 0xd503201f,
             f'{s["va"]:#x}: replacement')
    admission(image, sites)

    import xnuboot as xb
    xb.configure_guest('j700ap-26A428', KERNELCACHE.parent)
    log = io.StringIO()
    stock = bytearray(image.data)
    for off, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', stock, off, value)
    segments = [(va, off, size) for _, va, _, off, size in image.executable_segments]

    def uploaded(built):
        """Every executable segment's bytes as uploaded, in segment order."""
        out = []
        for va, _, size in segments:
            pa = xb.IMAGE_PA + va - image.vmin
            blobs = [bytes(blob[pa - base:pa - base + size]) for base, blob in built['chunks'].items()
                     if base <= pa and pa + size <= base + len(blob)]
            need(len(blobs) == 1, f'executable segment {va:#x} not uploaded whole, once')
            out.append(blobs[0])
        return out

    def expected(replaced):
        """The stock loaded executable bytes with {va: word} replaced."""
        out = []
        for va, off, size in segments:
            body = bytearray(stock[off:off + size])
            for site, word in replaced.items():
                if va <= site < va + size:
                    struct.pack_into('<I', body, site - va, word)
            out.append(bytes(body))
        return out

    with environment():
        default = build(xb, log)
        need(default['kernel_sysreg_zero'] is None, 'default build reports a sysreg patch')
        need(uploaded(default) == expected({}), 'default build executable bytes differ from the stock loaded image')
        explicit_off = build(xb, log, sysreg_zero=False)
        need(refused(lambda: build(xb, log, sysreg_zero='1'), 'explicit boolean'), 'non-boolean keyword accepted')
    with environment(SNAP_KERNEL_SYSREG_ZERO='0'):
        zero = build(xb, log)
    with environment(SNAP_KERNEL_SYSREG_ZERO='2'):
        need(refused(lambda: build(xb, log), 'must be 0 or 1'), 'SNAP_KERNEL_SYSREG_ZERO=2 accepted')
    for name, other in (('SNAP_KERNEL_SYSREG_ZERO=0', zero), ('sysreg_zero=False', explicit_off)):
        need(other['chunks'] == default['chunks'], f'{name} build differs from the default build')
    with environment(SNAP_KERNEL_SYSREG_ZERO='1'):
        patched = build(xb, log)
    with environment():
        keyword = build(xb, log, sysreg_zero=True)
    need(keyword['chunks'] == patched['chunks'], 'keyword and environment builds differ')
    record = patched['kernel_sysreg_zero']
    need(record['closure_sha256'] == pin['closure_sha256'] and record['sites'] == len(sites), 'loader record')

    # 1-4: the patched build against the default one.
    need({k: len(v) for k, v in patched['chunks'].items()} == {k: len(v) for k, v in default['chunks'].items()},
         'chunk geometry changed')
    image_chunks = [k for k in default['chunks'] if default['chunks'][k] != patched['chunks'][k]]
    need(all(xb.IMAGE_PA <= k < xb.IMAGE_PA + image.vmax - image.vmin for k in image_chunks),
         'a non-image chunk changed (params, device tree or handoff)')
    replaced = {s['va']: s['replacement'] for s in sites}
    after = uploaded(patched)
    need(after == expected(replaced), 'patched executable bytes are not stock plus exactly the decoded sites')
    for s in sites:
        need(word_at(patched['chunks'], xb.IMAGE_PA + s['va'] - image.vmin) == s['replacement'] and
             word_at(default['chunks'], xb.IMAGE_PA + s['va'] - image.vmin) == s['word'], 'uploaded site word')
    changed = sum(1 for s in sites if s['word'] != s['replacement'])
    need(changed == len(sites), 'a replacement equals its original word')
    remaining = 0
    for blob in after:
        for w in memoryview(blob).cast('I'):
            if w >> 22 == 0b1101010100 and (a := access(w)) and a[1] in EXPECTED:
                remaining += 1
    need(not remaining, f'{remaining} listed-register accesses remain in the patched image')
    del explicit_off, zero, keyword, after

    # 7. With native calls, private and HVC.
    for hvc in ('0', '1'):
        with environment(SNAP_NATIVE_CALLS='1', SNAP_SPTM_HVC_CALLS=hvc):
            base = build(xb, log)
            both = build(xb, log, sysreg_zero=True)
        contract = base['native_call_contract']
        need(both['native_call_contract']['pages'] == contract['pages'] and
             both['stub_pa'] == base['stub_pa'] and both['sptm_hvc_calls'] == (hvc == '1'),
             'native-call contract changed under sysreg-zero')
        need(not set(contract['call_sites']) & set(replaced) and not set(contract['writer_sites']) & set(replaced),
             'a sysreg site is a native call or writer site')
        hvc_words = {va: HVC_WORD for va in contract['call_sites']} if hvc == '1' else {}
        need(uploaded(base) == expected(hvc_words), f'HVC={hvc}: base image is not stock plus HVC words')
        need(uploaded(both) == expected({**hvc_words, **replaced}),
             f'HVC={hvc}: image differs from stock beyond the HVC words and the sysreg sites')
        pages = {va & ~4095 for va in contract['call_sites']} | {va & ~4095 for va in contract['writer_sites']}
        shared = sum(1 for s in sites if s['va'] & ~4095 in pages)
        del base, both

    manifest = dict(kernel_sha256=z.J700_26A428, closure=z.closure(sites), movz=record['movz'], nop=record['nop'],
                    sites_on_native_call_or_writer_pages=shared,
                    sites=[dict(va=hex(s['va']), register=s['register'], op='MRS' if s['read'] else 'MSR',
                                rt=s['rt'], bundle=s['bundle'], before=f'{s["word"]:#010x}',
                                after=f'{s["replacement"]:#010x}') for s in sites])
    if args.symbolize:
        import runpy
        names = runpy.run_path(str(ROOT / 'tools/kc-symbolicate.py'))['Symbolicator']().resolve(
            [s['va'] for s in sites])
        for entry, line in zip(manifest['sites'], names):
            entry['function'] = line.split('  ', 1)[-1]
    if args.output:
        (args.output / 'sysreg-zero-sites.json').write_text(json.dumps(manifest, indent=1) + '\n')
    print(f'PASS: {checks} checks; {len(sites)} sites ({record["movz"]} MOVZ, {record["nop"]} NOP), '
          f'{changed} changed words; {shared} on native call/writer pages; defaults unchanged')


if __name__ == '__main__':
    main()
