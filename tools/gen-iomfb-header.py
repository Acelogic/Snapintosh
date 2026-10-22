#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate IOMobileGraphicsFamily26A428.h from Apple's own 26A428 binaries.

Inputs (read-only, host side, no hardware):
  * KDK IOMobileGraphicsFamily.kext (343.0.0), arm64e slice: symbolled vtables of
    IOMobileFramebuffer / IOMobileFramebufferService / IOMobileFramebufferLegacy,
    and the bodies used to infer return types.
  * KDK AppleParavirtGPUIOGPUFamily.kext, arm64e slice: AppleParavirtDisplay is an
    Apple-built IOMobileFramebufferLegacy subclass compiled against the private
    header. It names the pure virtuals (slots 318/320/361/362/428/429/462/463/470)
    and carries the header's inline bodies as local copies.
  * The J700 26A428 kernelcache: every slot's PAC diversity is re-read from the
    shipped vtables and must equal the KDK's, so the KDK is admitted as a stand-in.

Every declared virtual is checked: the ptrauth string discriminator of the
mangled name of the slot's *introducing* declaration must equal the vtable's
diversity. Slots whose implementation is not exported from the kernelcache are
inline in Apple's header; they are emitted with bodies transcribed from
Apple's own compiled copies (a subclass vtable must define them locally).

Return types are not in the mangling. They come from (in order): Apple's
override bodies in AppleParavirtDisplay, the inline bodies, and a heuristic over
the IOMobileFramebufferLegacy implementation. Each declaration carries its
evidence as a comment ("ret=pv", "ret=inline", "ret=heur:...").

Usage: tools/gen-iomfb-header.py [--out PATH] [--kc PATH] [--kdk PATH] [--json PATH]
The checker (tools/check-iomfb-vtable.py) imports this module.
"""
import argparse
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')
DEFAULT_KC = (ROOT / 'downloads/'
                  'extracted/j700ap/kernelcache.release.mac17p')
DEFAULT_OUT = ROOT / 'gpu/adreno-kext/kext/include/IOMobileGraphicsFamily26A428.h'
IOMGF_BUNDLE = 'com.apple.iokit.IOMobileGraphicsFamily'
CLASSES = ('IOMobileFramebuffer', 'IOMobileFramebufferService', 'IOMobileFramebufferLegacy')
SIZES = {'IOMobileFramebuffer': 0x90, 'IOMobileFramebufferService': 0x90,
         'IOMobileFramebufferLegacy': 0x1dd8}
IOSERVICE_SLOTS = 272
PURE = '___cxa_pure_virtual'

# ---------------------------------------------------------------- ptrauth hash
_M = (1 << 64) - 1


def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & _M


def _siphash24(key, data):
    k0, k1 = struct.unpack('<QQ', key)
    v = [k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d,
         k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573]

    def rnd():
        v[0] = (v[0] + v[1]) & _M; v[1] = _rotl(v[1], 13); v[1] ^= v[0]; v[0] = _rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & _M; v[3] = _rotl(v[3], 16); v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & _M; v[3] = _rotl(v[3], 21); v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & _M; v[1] = _rotl(v[1], 17); v[1] ^= v[2]; v[2] = _rotl(v[2], 32)
    n = len(data) // 8 * 8
    for i in range(0, n, 8):
        m = struct.unpack_from('<Q', data, i)[0]
        v[3] ^= m; rnd(); rnd(); v[0] ^= m
    b = len(data) << 56
    for i, c in enumerate(data[n:]):
        b |= c << (8 * i)
    v[3] ^= b; rnd(); rnd(); v[0] ^= b
    v[2] ^= 0xff
    for _ in range(4):
        rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


_PAC_KEY = bytes([0xb5, 0xd4, 0xc9, 0xeb, 0x79, 0x10, 0x4a, 0x79,
                  0x6f, 0xec, 0x8b, 0x1b, 0x42, 0x87, 0x81, 0xd4])


def discriminator(mangled):
    """llvm::getPointerAuthStableSipHash: the arm64e vtable slot diversity."""
    if mangled.startswith('__Z'):
        mangled = mangled[1:]
    return _siphash24(_PAC_KEY, mangled.encode()) % 0xffff + 1


# ---------------------------------------------------------------- binaries

def arm64e_slice(path, out):
    """Extract the plain arm64e (cpusubtype 0xc0000002) slice of a fat kext."""
    data = Path(path).read_bytes()
    magic, n = struct.unpack_from('>II', data, 0)
    if magic != 0xcafebabe:
        raise ValueError(f'{path}: not a fat binary')
    for i in range(n):
        ct, cs, off, size, _ = struct.unpack_from('>iIIII', data, 8 + i * 20)
        if ct == 0x100000c and cs == 0xc0000002:
            Path(out).write_bytes(data[off:off + size])
            return Path(out)
    raise ValueError(f'{path}: no arm64e kernel slice')


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw).stdout


def demangle(names):
    names = list(names)
    if not names:
        return {}
    out = run(['c++filt'], input='\n'.join(n[1:] if n.startswith('__Z') else n
                                             for n in names)).split('\n')
    return dict(zip(names, out))


class MachOKext:
    """A linked arm64e kext: symbols (nm -m) plus chained-fixup vtable reader."""

    def __init__(self, path):
        self.path = str(path)
        self.sym = {}
        self.text_names = {}
        self.external = set()
        for line in run(['nm', '-m', self.path]).split('\n'):
            m = re.match(r'([0-9a-f]{16}) \(([^)]*)\) (.*) (\S+)$', line)
            if not m:
                continue
            addr, sect, attrs, name = int(m.group(1), 16), m.group(2), m.group(3), m.group(4)
            self.sym[name] = addr
            if '__text' in sect:
                self.text_names.setdefault(addr, name)
            if 'non-external' not in attrs:
                self.external.add(name)
        self.fixups = {}
        for line in run(['dyld_info', '-fixups', self.path]).split('\n'):
            m = re.search(r'(0x[0-9A-F]+)\s+auth-rebase\s+(0x[0-9A-F]+) \(div=(0x[0-9A-F]+) '
                          r'ad=(\d) key=(\w+)\)', line)
            if m:
                self.fixups[int(m.group(1), 16)] = ('rebase', int(m.group(2), 16),
                                                    int(m.group(3), 16), m.group(4), m.group(5))
                continue
            m = re.search(r'(0x[0-9A-F]+)\s+auth-bind\s+\S*?/(\S+) \(div=(0x[0-9A-F]+) '
                          r'ad=(\d) key=(\w+)\)', line)
            if m:
                self.fixups[int(m.group(1), 16)] = ('bind', m.group(2),
                                                    int(m.group(3), 16), m.group(4), m.group(5))
        self._dis = None

    def vtable(self, cls):
        """[(slot, target_symbol, diversity, local, addr_div, key)] for class cls."""
        base = self.sym['__ZTV%d%s' % (len(cls), cls)] + 0x10
        out = []
        while base + 8 * len(out) in self.fixups:
            kind, tgt, div, ad, key = self.fixups[base + 8 * len(out)]
            if kind == 'rebase':
                name, local = self.text_names.get(tgt, '?0x%x' % tgt), True
            else:
                name, local = tgt, False
            out.append((len(out), name, div, local, ad == '1', key))
        return out

    def functions(self):
        """{mangled name: [instruction text]} from objdump."""
        if self._dis is None:
            self._dis = {}
            cur = None
            for line in run(['objdump', '-d', '--no-show-raw-insn', self.path]).split('\n'):
                m = re.match(r'^[0-9a-f]+ <(.+)>:$', line)
                if m:
                    # Keep the first body of a repeated label (coalesced inline copies).
                    cur = [] if m.group(1) in self._dis else self._dis.setdefault(m.group(1), [])
                    continue
                m = re.match(r'^\s+([0-9a-f]+):\s+(.*)$', line)
                if m and cur is not None:
                    cur.append(m.group(2).split(';')[0].strip())
        return self._dis


def kc_vtable_divs(kc_path, bundle, classes):
    """Diversities of the shipped vtables, read from the kernelcache's fixup chains."""
    out = run(['ipsw', 'macho', 'info', str(kc_path), '--fileset-entry', bundle, '--symbols'])
    out = re.sub(r'\x1b\[[0-9;]*m', '', out)
    addrs = {}
    for cls in classes:
        m = re.search(r'(0x[0-9a-f]+):\s+\(__DATA_CONST,__const\).*__ZTV%d%s\b' % (len(cls), cls), out)
        if not m:
            raise ValueError(f'{kc_path}: no vtable for {cls}')
        addrs[cls] = int(m.group(1), 16)
    data = Path(kc_path).read_bytes()
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off, segs = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            vm, vs, fo, fs = struct.unpack_from('<QQQQ', data, off + 24)
            segs.append((vm, fs, fo))
        off += size

    def fileoff(va):
        for vm, fs, fo in segs:
            if vm <= va < vm + fs:
                return fo + va - vm
        raise ValueError(f'{va:#x} not in the kernelcache image')
    result = {}
    for cls, va in addrs.items():
        divs, p = [], fileoff(va + 0x10)
        while True:
            v = struct.unpack_from('<Q', data, p + 8 * len(divs))[0]
            if not v >> 63:          # dyld_chained_ptr_64_kernel_cache_rebase.isAuth
                break
            divs.append((v >> 32) & 0xffff)
        result[cls] = divs
    return result


# ---------------------------------------------------------------- inference

_RET_SKIP = re.compile(r'^(ldp|ldr\s+x(19|2\d|30)|ldr\s+d(8|9|1[0-5])|add\s+sp|autibsp|autiasp|'
                       r'eor\s+x1[67]|tbz\s+x1[67]|brk|nop|ldp\s+d)')
_W0 = re.compile(r'^\w+(\.\w+)?\s+([wxsdqv]0)\b')


def _classify_dest(ins):
    m = _W0.match(ins)
    if not m:
        return None
    reg = m.group(2)
    mn = ins.split()[0]
    if mn in ('str', 'stp', 'strb', 'strh', 'stur', 'cbz', 'cbnz', 'tbz', 'tbnz', 'cmp', 'tst', 'cmn'):
        return None
    if reg[0] in 'sd':
        return {'s': 'float', 'd': 'double'}[reg[0]]
    if reg[0] in 'qv':
        return 'vector'
    if reg == 'x0':
        return 'x0' if not re.match(r'mov\s+x0, #0x0$', ins) else 'x0zero'
    if re.match(r'mov\s+w0, #0x0$', ins) or ins.startswith('mov\tw0, wzr') or re.match(r'mov\s+w0, wzr', ins):
        return 'w0zero'
    if re.match(r'(mov\s+w0, #0x1$|cset\s+w0|ldrb\s+w0|and\s+w0, w\d+, #0x1$)', ins):
        return 'w0bool'
    if re.match(r'movk\s+w0, #0xe00[0-9a-f], lsl #16', ins):
        return 'w0ioreturn'
    return 'w0'


def infer_return(body):
    """Heuristic return kind of a function body (list of instructions)."""
    kinds = set()
    text = '\n'.join(body)
    if re.search(r'movk\s+w0, #0xe00[0-9a-f], lsl #16', text):
        kinds.add('w0ioreturn')
    for i, ins in enumerate(body):
        mn = ins.split()[0] if ins else ''
        if mn in ('ret', 'retab'):
            for j in range(i - 1, max(-1, i - 14), -1):
                prev = body[j]
                if _RET_SKIP.match(prev):
                    continue
                pm = prev.split()[0]
                if pm in ('bl', 'blraa', 'blr', 'blraaz'):
                    kinds.add('call'); break
                if pm.startswith('b') and pm not in ('bic', 'bfi', 'bfxil', 'bti'):
                    kinds.add('unknown'); break
                k = _classify_dest(prev)
                if k:
                    kinds.add(k); break
            else:
                kinds.add('unknown')
        elif mn in ('b', 'braa', 'br', 'braaz') and '<' not in ins:
            kinds.add('tail')
        elif mn == 'b' and '->' in ins:
            kinds.add('tail')
    if not body:
        return 'unknown'
    for k in ('double', 'float'):
        if k in kinds:
            return k
    if 'x0' in kinds:
        return 'uint64'
    if 'w0ioreturn' in kinds:
        return 'IOReturn'
    if 'w0bool' in kinds and 'w0' not in kinds:
        return 'bool'
    if 'w0' in kinds or 'w0zero' in kinds:
        return 'IOReturn'
    if 'x0zero' in kinds:
        return 'uint64'
    if kinds <= {'unknown'} and not any(k for k in kinds if k != 'unknown'):
        # every return path is a bare ret after non-register work
        return 'void' if all(b.split()[0] not in ('mov',) or '0' not in b for b in body[-2:]) else 'unknown'
    return 'unknown'


_BOOL_NAME = re.compile(r'(^is_|^is[A-Z]|^has_|^supports_|_enabled$|^verify_|^check_drm$|^flush_rtps$|'
                        r'^keep_swaps|^computeAndVerify|^finfo_support|^async_swap_supported$|'
                        r'^are_|^in_sleep_media$|^swapWillChange|^first_client_open$|^start_hardware$|'
                        r'^surface_is|^need_|^wait_for_start_complete$)')


def c_return_type(kind, method, evidence=None):
    if kind == 'bool':
        return 'bool'
    if kind == 'IOReturn':
        return 'IOReturn'
    if kind == 'uint64':
        return 'uint64_t'
    if kind in ('float', 'double', 'void'):
        return kind
    if kind == 'uint32':
        return 'uint32_t'
    return 'IOReturn'   # unknown: 32-bit status is the family's convention


# ---------------------------------------------------------------- signatures

BUILTIN = {'unsigned', 'int', 'long', 'char', 'short', 'bool', 'float', 'double', 'void',
           'const', 'signed', 'volatile'}
SDK_TYPES = {'IOService', 'IOUserClient', 'OSObject', 'OSDictionary', 'IOMemoryMap', 'task',
             'IORegistryPlane', 'OSSerialize', 'OSString', 'OSSymbol', 'OSMetaClassBase',
             'IOWorkLoop', 'IORPC', 'OSArray', 'IOMemoryDescriptor'}

IOSERVICE_OVERRIDES = {
    '4freeEv': 'virtual void free() APPLE_KEXT_OVERRIDE;',
    '4initEP12OSDictionary': 'virtual bool init(OSDictionary *dictionary = NULL) APPLE_KEXT_OVERRIDE;',
    '13setPropertiesEP8OSObject': 'virtual IOReturn setProperties(OSObject *properties) APPLE_KEXT_OVERRIDE;',
    '18systemWillShutdownEj': 'virtual void systemWillShutdown(IOOptionBits specifier) APPLE_KEXT_OVERRIDE;',
    '5probeEP9IOServicePi': 'virtual IOService *probe(IOService *provider, SInt32 *score) APPLE_KEXT_OVERRIDE;',
    '5startEP9IOService': 'virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;',
    '4stopEP9IOService': 'virtual void stop(IOService *provider) APPLE_KEXT_OVERRIDE;',
    '11getWorkLoopEv': 'virtual IOWorkLoop *getWorkLoop() const APPLE_KEXT_OVERRIDE;',
    '13newUserClientEP4taskPvjPP12IOUserClient':
        'virtual IOReturn newUserClient(task_t owningTask, void *securityID, UInt32 type, '
        'IOUserClient **handler) APPLE_KEXT_OVERRIDE;',
    '13setPowerStateEmP9IOService':
        'virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *whatDevice) '
        'APPLE_KEXT_OVERRIDE;',
}


def split_params(params):
    out, depth, cur = [], 0, ''
    for c in params:
        if c in '(<[':
            depth += 1
        elif c in ')>]':
            depth -= 1
        if c == ',' and depth == 0:
            out.append(cur.strip()); cur = ''
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_demangled(dem):
    """'A::B::m(int, X*) const' -> (qualified class, method, [params], const)."""
    const = dem.endswith(' const')
    core = dem[:-6] if const else dem
    depth, i = 0, len(core) - 1
    while i >= 0:
        if core[i] == ')':
            depth += 1
        elif core[i] == '(':
            depth -= 1
            if depth == 0:
                break
        i -= 1
    head, params = core[:i], core[i + 1:-1]
    cls, _, meth = head.rpartition('::')
    return cls, meth, ([] if params in ('', 'void') else split_params(params)), const


NESTED_IN_LEGACY = ('SwapInfoBlob', 'pstatechgreq')


def named_param(ptype, i):
    name = 'a%d' % i
    # Inside IOMobileFramebufferLegacy's scope the nested SwapInfoBlob hides the global
    # one; spell global types explicitly or the mangling (and the diversity) changes.
    for t in NESTED_IN_LEGACY:
        ptype = re.sub(r'(?<![:\w])%s\b' % t, '::' + t, ptype)
    if '(*)' in ptype:
        return ptype.replace('(*)', '(*%s)' % name, 1)
    if '(&)' in ptype:
        return ptype.replace('(&)', '(&%s)' % name, 1)
    return '%s %s' % (ptype, name)


def type_idents(ptype):
    return [t for t in re.findall(r'[A-Za-z_][A-Za-z_0-9:]*', ptype) if t not in BUILTIN]


def mangled_for(cls, mangled_impl):
    """Rewrite the class prefix of an implementation's mangled name to cls."""
    m = re.match(r'^(__ZNK?)(\d+)', mangled_impl)
    if not m:
        raise ValueError(mangled_impl)
    ln = int(m.group(2))
    old = mangled_impl[m.end():m.end() + ln]
    rest = mangled_impl[m.end() + ln:]
    if old != cls:
        # S_ is the first substitution: the enclosing class. Re-spell nested names that
        # referred to the old class through it, and abbreviate those naming the new one.
        rest = rest.replace('NS_', 'N%d%s' % (len(old), old))
        rest = rest.replace('N%d%s' % (len(cls), cls), 'NS_')
    return '%s%d%s%s' % (m.group(1), len(cls), cls, rest)


# ---------------------------------------------------------------- inline bodies

def inline_body(body, meth, params, dem_params_named):
    """Transcribe Apple's compiled inline body (a handful of known shapes)."""
    ins = [b for b in body if not b.startswith('bti')]
    txt = '\n'.join(ins)
    if ins == ['ret']:
        return 'void', '{}'
    m = re.fullmatch(r'mov\s+w0, #(-?0x[0-9a-f]+)\nret', txt)
    if m:
        v = int(m.group(1), 16) & 0xffffffff
        if v in (0, 1) and _BOOL_NAME.search(meth):
            return 'bool', '{ return %s; }' % ('true' if v else 'false')
        if v == 0:
            return 'IOReturn', '{ return kIOReturnSuccess; }'
        if v == 0x80000000:
            return 'int32_t', '{ return INT32_MIN; }'
        return 'uint32_t', '{ return %d; }' % v
    m = re.fullmatch(r'mov\s+w0, #0x([0-9a-f]+)\nmovk\s+w0, #0x([0-9a-f]+), lsl #16\nret', txt)
    if m:
        v = int(m.group(1), 16) | (int(m.group(2), 16) << 16)
        name = {0xe00002c7: 'kIOReturnUnsupported', 0xe00002c2: 'kIOReturnBadArgument'}.get(v)
        return 'IOReturn', '{ return %s; }' % (name or '(IOReturn)0x%08x' % v)
    if re.fullmatch(r'mov\s+x0, #0x0\nret', txt):
        return 'uint64_t', '{ return 0; }'
    m = re.fullmatch(r'ldr\s+w0, \[x0, #0x([0-9a-f]+)\]\nret', txt)
    if m:
        return 'uint32_t', '{ return *(const uint32_t *)((const uint8_t *)this + 0x%s); }' % m.group(1)
    m = re.fullmatch(r'mov\s+w8, #0x([0-9a-f]+)\nadd\s+x0, x0, x8\nret', txt)
    if m:
        return 'IOMFB::AP::DisplayedData *', ('{ return (IOMFB::AP::DisplayedData *)((uint8_t *)'
                                              'const_cast<IOMobileFramebufferLegacy *>(this) + 0x%s); }'
                                              % m.group(1))
    if re.fullmatch(r'cbz\s+x1, .*\nldr\s+w8, \[x0, #0x1bf0\]\nstr\s+w8, \[x1\]\ncbz\s+x2, .*\n'
                    r'ldr\s+w8, \[x0, #0x1bf4\]\nstr\s+w8, \[x2\]\nret', txt):
        return 'void', ('{ if (a0) *a0 = *(const uint32_t *)((const uint8_t *)this + 0x1bf0); '
                        'if (a1) *a1 = *(const uint32_t *)((const uint8_t *)this + 0x1bf4); }')
    m = re.fullmatch(r'mov\s+x0, x1\nmov\s+x1, x2\nb\s+.*', txt)
    if m and meth in ('absolute_time_to_ns', 'ns_to_absolute_time'):
        fn = {'absolute_time_to_ns': 'absolutetime_to_nanoseconds',
              'ns_to_absolute_time': 'nanoseconds_to_absolutetime'}[meth]
        return 'void', '{ %s(a0, a1); }' % fn
    if meth == 'get_current_absolute_time' and re.fullmatch(r'b\s+[^\n]*', txt):
        return 'uint64_t', '{ return default_current_absolute_time(); }'
    if meth == 'swap_begin_async_gated' and '#0x7713' in txt and 'braa' in txt:
        return 'void', '{ swap_begin_gated(); }'
    raise ValueError(f'untranscribed inline body for {meth}:\n{txt}')


# ---------------------------------------------------------------- model

class Slot:
    def __init__(self, index):
        self.index = index
        self.div = None
        self.introducer = None      # class that declares the slot first (for slots >= 272)
        self.mangled = {}           # class -> mangled name of that class's declaration
        self.pure_in = set()
        self.impl = {}              # class -> implementation symbol (local or bind)
        self.inline = False
        self.inline_body = None
        self.ret = None
        self.ret_evidence = None
        self.params = []
        self.const = False
        self.method = None
        self.pv_impl = None


def build_model(kdk, kc, workdir):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    iomgf = MachOKext(arm64e_slice(kdk / 'System/Library/Extensions/IOMobileGraphicsFamily.kext/'
                                   'Contents/MacOS/IOMobileGraphicsFamily', workdir / 'iomgf.arm64e'))
    pv = MachOKext(arm64e_slice(kdk / 'System/Library/Extensions/AppleParavirtGPUIOGPUFamily.kext/'
                                'Contents/MacOS/AppleParavirtGPUIOGPUFamily', workdir / 'pvgpu.arm64e'))
    vts = {cls: iomgf.vtable(cls) for cls in CLASSES}
    pvvt = pv.vtable('AppleParavirtDisplay')
    kcdivs = kc_vtable_divs(kc, IOMGF_BUNDLE, CLASSES) if kc else None
    exports = None
    if kc:
        out = run(['ipsw', 'macho', 'info', str(kc), '--fileset-entry', IOMGF_BUNDLE, '--symbols'])
        out = re.sub(r'\x1b\[[0-9;]*m', '', out)
        exports = set(re.findall(r'\) external\s+(__Z\S+)', out))
        if len(exports) < 1000:
            raise ValueError('kernelcache export listing looks truncated')
    report = {'kc_checked': bool(kc), 'mismatch': []}
    legacy = vts['IOMobileFramebufferLegacy']
    nslots = len(legacy)
    if nslots != 483 or len(vts['IOMobileFramebuffer']) != 379:
        raise ValueError('unexpected vtable sizes %d/%d' % (nslots, len(vts['IOMobileFramebuffer'])))
    if kcdivs:
        for cls in CLASSES:
            kd = [e[2] for e in vts[cls]]
            if kd != kcdivs[cls]:
                raise ValueError(f'KDK vtable {cls} differs from the kernelcache')
        report['kc_equal'] = {cls: len(kcdivs[cls]) for cls in CLASSES}
    iomgf_fn = iomgf.functions()
    pv_fn = pv.functions()
    all_names = set()
    for cls in CLASSES:
        all_names.update(e[1] for e in vts[cls])
    all_names.update(e[1] for e in pvvt)
    dem = demangle(all_names)

    slots = []
    for i in range(nslots):
        s = Slot(i)
        s.div = legacy[i][2]
        for cls in CLASSES:
            if i < len(vts[cls]):
                name = vts[cls][i][1]
                s.impl[cls] = name
                if name == PURE:
                    s.pure_in.add(cls)
        s.pv_impl = pvvt[i][1]
        slots.append(s)

    # Slots >= 272: identify the introducing declaration and verify its hash.
    for s in slots[IOSERVICE_SLOTS:]:
        intro = 'IOMobileFramebuffer' if s.index < 379 else 'IOMobileFramebufferLegacy'
        s.introducer = intro
        # Name source: any non-pure implementation (Legacy, IOMFB) or the PV override.
        src = None
        for cand in (s.impl.get('IOMobileFramebufferLegacy'), s.impl.get('IOMobileFramebuffer'),
                     s.pv_impl):
            if cand and cand != PURE:
                src = cand
                break
        intro_div = vts[intro][s.index][2]
        want = mangled_for(intro, src)
        if discriminator(want) != intro_div:
            raise ValueError(f'slot {s.index}: {want} hashes {discriminator(want):#06x}, '
                             f'vtable says {intro_div:#06x}')
        s.mangled[intro] = want
        s.intro_div = intro_div
        d = dem[src] if src in dem else demangle([src])[src]
        _, s.method, s.params, s.const = parse_demangled(d)
        # Legacy re-declaration of an IOMFB pure (its own pure entry hashes its own name).
        if intro == 'IOMobileFramebuffer' and s.div != intro_div:
            lw = mangled_for('IOMobileFramebufferLegacy', src)
            if discriminator(lw) != s.div or 'IOMobileFramebufferLegacy' not in s.pure_in:
                raise ValueError(f'slot {s.index}: unexplained Legacy diversity {s.div:#06x}')
            s.mangled['IOMobileFramebufferLegacy'] = lw
            s.legacy_redeclared_pure = True
        else:
            s.legacy_redeclared_pure = False
        # Inline (not exported) implementations.
        for cls in ('IOMobileFramebufferLegacy', 'IOMobileFramebuffer'):
            impl = s.impl.get(cls)
            if impl and impl != PURE and impl.startswith('__ZN') and exports is not None \
                    and impl not in exports and vts[cls][s.index][3]:
                s.inline = True
                s.inline_class = impl_class(impl)
                body = pv_fn.get(impl) or iomgf_fn.get(impl)
                if body is None:
                    raise ValueError(f'slot {s.index}: no body for inline {impl}')
                named = [named_param(p, k) for k, p in enumerate(s.params)]
                s.ret, s.inline_body = inline_body(body, s.method, s.params, named)
                s.ret_evidence = 'inline'
                break
    # Return types for the remaining slots.
    for s in slots[IOSERVICE_SLOTS:]:
        if s.ret:
            continue
        pvi = s.pv_impl
        if pvi and pvi.startswith('__ZN20AppleParavirtDisplay') and pvi in pv_fn:
            k = infer_return(pv_fn[pvi])
            if k not in ('unknown',):
                s.ret, s.ret_evidence = c_return_type(k, s.method), 'pv:' + k
        if not s.ret:
            impl = s.impl.get('IOMobileFramebufferLegacy')
            body = iomgf_fn.get(impl) if impl and impl != PURE else None
            k = infer_return(body) if body else 'unknown'
            if k == 'bool' or (k == 'IOReturn' and _BOOL_NAME.search(s.method or '')):
                k = 'bool' if _BOOL_NAME.search(s.method or '') or k == 'bool' else k
            s.ret, s.ret_evidence = c_return_type(k, s.method), 'heur:' + k
    return {'slots': slots, 'vts': vts, 'pvvt': pvvt, 'report': report, 'exports': exports,
            'iomgf': iomgf, 'pv': pv, 'dem': dem}


def impl_class(mangled):
    m = re.match(r'^__ZNK?(\d+)', mangled)
    ln = int(m.group(1))
    return mangled[m.end():m.end() + ln]


# Return types proven by reading Apple's code where the heuristic is weak.
RET_OVERRIDES = {
    # AppleParavirtDisplay bodies (KDK 26A428), see the M0 report.
    'set_notify_tag_mask_gated': 'IOReturn', 'supported_frame_info': 'IOReturn',
    'factory_portal': 'IOReturn', 'executeFactoryConfigurations_gated': 'IOReturn',
    'set_frame_info_notification_state_gated': 'void', 'do_swap_info_notify_gated': 'void',
    'notify_swap_done_gated': 'IOReturn', 'notify_crc_ready_gated': 'void',
    'are_timings_enabled': 'bool', 'verify_swap': 'bool', 'verify_swap_surfaces': 'bool',
    'swap_begin_gated': 'void', 'swap_complete_gated': 'void', 'start_hardware': 'bool',
    'stop_hardware_gated': 'void', 'swap_layer_map': 'IOReturn', 'surface_layer_map': 'IOReturn',
    'surface_layer_unmap': 'void', 'dropSwap_gated': 'void', 'dropObsoleteSwaps_gated': 'bool',
    'dropNoOpSwaps_gated': 'void', 'dropAbortedSwaps_gated': 'void', 'dropDummySwaps_gated': 'void',
    'do_power_state_change_gated': 'IOReturn',
}


# ---------------------------------------------------------------- emit

HEADER_TOP = '''// GENERATED by tools/gen-iomfb-header.py from the 26A428 IOMobileGraphicsFamily 343.0.0
// contract (KDK kext + J700 kernelcache diversities + AppleParavirtDisplay). Do not edit by hand.
// Every virtual is declared in the class that introduces its slot, so clang's arm64e vtable
// diversity (SipHash of the introducing declaration's mangled name) equals the kernel's; the
// generator verified each one. Slots whose base implementation is not exported from the
// kernelcache are inline in Apple's header and are defined here with bodies transcribed from
// Apple's compiled copies. tools/check-iomfb-vtable.py compiles a subclass and compares every
// slot's target and PAC diversity with the kernelcache and AppleParavirtDisplay.
// Return types are not part of the mangling: "ret=" says where each one came from
// (pv = AppleParavirtDisplay override body, inline = Apple's inline copy, heur = inferred from
// the IOMobileFramebufferLegacy body; heur types are INFERRED and only matter to callers).
// No SDK or KDK ships these headers (IOMobileGraphicsFamily is private).
#ifndef IOMOBILEGRAPHICSFAMILY_26A428_H
#define IOMOBILEGRAPHICSFAMILY_26A428_H
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <kern/clock.h>
#include <stdint.h>

struct task;
'''

LEGACY_FIELDS = '''
private:
    // ---- Private IOMobileFramebufferLegacy state used by subclasses (26A428, PROVEN offsets):
    //  +0x1a40 current swap        AppleParavirtDisplay::swap_begin_gated str x1,[x19,#0x1a40];
    //                              IOMobileFramebufferLegacy::swap_complete_gated str xzr,[x19,#0x1a40]
    //  +0x1a48 pending queue head  clean_queue_gated ldr x8,[x0,#0x1a48] (TAILQ tqh_first)
    //  +0x1a50 pending queue tail  swap_begin_gated str x10,[x19,#0x1a50] (TAILQ tqh_last)
    //  +0x1b48 command gate        AppleParavirtDisplay::start_hardware runActionBlock on [x0,#0x1b48]
    //  +0x1bf0 / +0x1bf4 display width / height (inline display_width()/display_height())
    uint8_t _iomfbl_pad0[0x1a40 - 0x90];
protected:
    IOMFBSwapIORequest *fCurrentSwap;            // +0x1a40
    IOMFBSwapIORequest *fPendingSwapFirst;       // +0x1a48
    IOMFBSwapIORequest **fPendingSwapLast;       // +0x1a50
private:
    uint8_t _iomfbl_pad1[0x1b48 - 0x1a58];
protected:
    IOCommandGate *fLegacyCommandGate;           // +0x1b48
private:
    uint8_t _iomfbl_pad2[0x1bf0 - 0x1b50];
protected:
    uint32_t fDisplayWidth;                      // +0x1bf0
    uint32_t fDisplayHeight;                     // +0x1bf4
private:
    uint8_t _iomfbl_pad3[0x1dd8 - 0x1bf8];
'''

SWAP_FIELDS = '''
// IOMFBSwapIORequest (an OSObject subclass owned by the family). Only these fields are
// read by a Legacy subclass; offsets are PROVEN from AppleParavirtDisplay (26A428) and the
// IOMobileFramebufferLegacy::swap_submit (iomgf 0x23ec4) that fills them from the user's
// IOMFBSwap (its log strings name the fields):
//   +0x011 + 16*l int32 srcRect[l] {x, y, w, h}, surface pixels   swap_submit 0x2440c..0x24414
//          (add x9,x8,#0x11; str q0,[x9,x27,lsl #4] from IOMFBSwap+0xac); 0x2474c tbnz #31
//          "srcRect.x (%d) less than zero", 0x24760 "Buffer width (%d) doesn't cover read region"
//   +0x051 + 16*l int32 destRect[l] {x, y, w, h}, display pixels  swap_submit 0x24430..0x24438
//          (add x8,x8,#0x51 from IOMFBSwap+0x10c); 0x246f4 checks w/h against +0x1bf0/+0x1bf4
//          ("passthrough layers must be fullscreen"). PV program_hardware_gated 0x11900/0x11904
//          ldur w2,[x8,#0x61]; ldur w3,[x8,#0x65] = destRect[1].x/.y, passed as the two ints of
//          program_hardware_cursor_gated(IOSurface*, int, int). Unaligned: read with memcpy.
//   +0x3d8 u32 layer-enable mask (bit l = layer l)  swap_submit 0x24034 str w8,[x2,#0x3d8] from
//          IOMFBSwap+0x14c (transaction->enabled); PV program_hardware_gated ldrb [x8,#0x3d8]
//          (bit0 layer 0, bit1 the cursor layer). A layer whose bit is clear keeps its previous
//          state: swapWillChangeDisplayedData (0x2b9bc) compares only the layers in the mask.
//   +0x3ec u32 completion/abort state; programmable when (v & ~8) == 0     swap_begin_gated
//   +0xb80 + 8*l IOSurface *layer[l]  Legacy::swap_layer_map add x8,x1,#0xb80; swap_submit
//          0x24474/0x244d8 str x0,[x8,x27,lsl #3], looked up from surface ID IOMFBSwap+0x9c+4*l;
//          ID 0 leaves NULL: the layer is switched off (0x245a0..0x245ac accept that, refuse a
//          nonzero ID that does not resolve)
//   +0xd38/+0xd40 TAILQ entry (tqe_next, tqe_prev)             swap_begin_gated dequeue
namespace IOMFBSwapFields {
struct Rect { int32_t x, y, w, h; };
static constexpr size_t kSrcRect0 = 0x11;
static constexpr size_t kDstRect0 = 0x51;
static constexpr size_t kLayerMask = 0x3d8;
static constexpr size_t kState = 0x3ec;
static constexpr size_t kLayerSurface0 = 0xb80;
static constexpr size_t kLayerCount = 4;       // swap_submit 0x24884 and swapWillChangeDisplayedData 0x2bbd0: cmp #4
static constexpr size_t kQueueNext = 0xd38;
static constexpr size_t kQueuePrev = 0xd40;
static inline uint8_t layerMask(const IOMFBSwapIORequest *s)
{ return *((const uint8_t *)s + kLayerMask); }
static inline uint32_t layerMaskWord(const IOMFBSwapIORequest *s)
{ return *(const uint32_t *)((const uint8_t *)s + kLayerMask); }
static inline uint32_t state(const IOMFBSwapIORequest *s)
{ return *(const uint32_t *)((const uint8_t *)s + kState); }
static inline IOSurface *layerSurface(const IOMFBSwapIORequest *s, unsigned layer)
{ return ((IOSurface *const *)((const uint8_t *)s + kLayerSurface0))[layer]; }
static inline Rect srcRect(const IOMFBSwapIORequest *s, unsigned layer)
{ Rect r; __builtin_memcpy(&r, (const uint8_t *)s + kSrcRect0 + 16 * layer, sizeof r); return r; }
static inline Rect dstRect(const IOMFBSwapIORequest *s, unsigned layer)
{ Rect r; __builtin_memcpy(&r, (const uint8_t *)s + kDstRect0 + 16 * layer, sizeof r); return r; }
static inline IOMFBSwapIORequest *&queueNext(IOMFBSwapIORequest *s)
{ return *(IOMFBSwapIORequest **)((uint8_t *)s + kQueueNext); }
static inline IOMFBSwapIORequest **&queuePrev(IOMFBSwapIORequest *s)
{ return *(IOMFBSwapIORequest ***)((uint8_t *)s + kQueuePrev); }
}  // namespace IOMFBSwapFields
'''

IOSURFACE_BLOCK = '''
// IOSurface (IOSurface.kext). Only exported non-virtual accessors are declared; each mangles to
// an IOSurface.kext export imported by AppleParavirtGPUIOGPUFamily. Widths from the KDK bodies.
#ifndef IOSURFACE_26A428_ACCESSORS
#define IOSURFACE_26A428_ACCESSORS
class IOSurface : public OSObject
{
public:
    uint64_t getWidth() const;
    uint64_t getHeight() const;
    uint64_t getBytesPerRow() const;
    uint64_t getBytesPerElement() const;
    uint64_t getBaseOffset() const;
    uint32_t getPixelFormat() const;
    uint32_t getSurfaceID() const;
    uint64_t getAllocSize() const;
    IOMemoryDescriptor *getMemoryDescriptor() const;
private:
    IOSurface();                       // never constructed here
};
#endif
'''


def emit(model):
    slots = model['slots']
    vts = model['vts']
    # Types referenced by parameters.
    enums, structs, nested = set(), set(), set()
    for s in slots[IOSERVICE_SLOTS:]:
        for p in s.params:
            ids = type_idents(p)
            byval = '*' not in p and '&' not in p
            for t in ids:
                if t in SDK_TYPES or t in CLASSES:
                    continue
                if '::' in t:
                    nested.add(t)
                elif byval:
                    enums.add(t)
                else:
                    structs.add(t)
    structs.discard('IOSurface')
    structs.update({'IOMFBSwapIORequest', 'IOMFBNotifyRequest', 'SwapInfoBlob'})
    structs -= enums
    out = [HEADER_TOP]
    out.append('class IOCommandGate;\nclass IOSurface;\n')
    out.append('// Structures used only through pointers (mangling carries only the name).\n')
    for t in sorted(structs):
        out.append('struct %s;\n' % t)
    out.append('namespace IOMFB { struct RefreshTimingAttributes; namespace AP { struct DisplayedData; } }\n')
    out.append('// Enums passed by value (the mangling carries only the name; width INFERRED 32-bit).\n')
    for t in sorted(enums):
        out.append('enum %s : uint32_t {};\n' % t)
    out.append(IOSURFACE_BLOCK)
    for cls in CLASSES:
        out.append(emit_class(cls, model))
    out.append(SWAP_FIELDS)
    out.append('\n#endif  // IOMOBILEGRAPHICSFAMILY_26A428_H\n')
    return ''.join(out)


def decl_line(s, cls, pure=False, body=None, override=False):
    ret = RET_OVERRIDES.get(s.method, s.ret)
    if s.inline and s.ret_evidence == 'inline':
        ret = s.ret
    params = [named_param(p, k) for k, p in enumerate(s.params)]
    const = ' const' if s.const else ''
    ovr = ' APPLE_KEXT_OVERRIDE' if override else ''
    sep = '' if ret.endswith('*') else ' '
    tail = ' = 0;' if pure else (' %s' % body if body else ';')
    ev = 'inline' if body else ('pv' if s.method in RET_OVERRIDES else s.ret_evidence)
    return '    virtual %s%s%s(%s)%s%s%s  // [%d] div %#06x ret=%s%s\n' % (
        ret, sep, s.method, ', '.join(params), const, ovr, tail, s.index,
        discriminator(s.mangled.get(cls, s.mangled.get(s.introducer))), ev,
        ' PURE' if pure else '')


def emit_class(cls, model):
    slots, vts = model['slots'], model['vts']
    super_ = {'IOMobileFramebuffer': 'IOService', 'IOMobileFramebufferService': 'IOMobileFramebuffer',
              'IOMobileFramebufferLegacy': 'IOMobileFramebufferService'}[cls]
    vt = vts[cls]
    lines = ['\n// %s: %d bytes, %d vtable slots, super %s (abstract)\n' % (cls, SIZES[cls], len(vt), super_),
             'class %s : public %s\n{\n    OSDeclareAbstractStructors(%s)\n' % (cls, super_, cls)]
    if cls == 'IOMobileFramebufferLegacy':
        lines.append('public:\n    struct SwapInfoBlob;       // 48-byte ring entry (notify_swap_done_gated)\n'
                     '    struct pstatechgreq;\n')
    lines.append('public:\n')
    # IOService-range overrides.
    for i in range(IOSERVICE_SLOTS):
        name, local = vt[i][1], vt[i][3]
        if not local or i in (0, 1, 7):
            continue
        m = re.match(r'^__ZNK?(\d+)', name)
        rest = name[m.end() + int(m.group(1)):]
        decl = IOSERVICE_OVERRIDES.get(rest)
        if not decl:
            raise ValueError(f'{cls}: undeclared IOService override {name}')
        lines.append('    %s  // [%d]\n' % (decl, i))
    for s in slots[IOSERVICE_SLOTS:len(vt)]:
        impl = s.impl.get(cls)
        if s.introducer == cls:
            if impl == PURE:
                lines.append(decl_line(s, cls, pure=True))
            elif s.inline and s.inline_class == cls:
                lines.append(decl_line(s, cls, body=s.inline_body))
            else:
                lines.append(decl_line(s, cls))
        else:
            # Override of an ancestor's slot.
            if impl == PURE and getattr(s, 'legacy_redeclared_pure', False) \
                    and cls == 'IOMobileFramebufferLegacy':
                lines.append(decl_line(s, cls, pure=True, override=True))
            elif impl and impl != PURE and impl_class(impl) == cls:
                inline = s.inline and s.inline_class == cls
                lines.append(decl_line(s, cls, body=s.inline_body if inline else None, override=True))
    if cls == 'IOMobileFramebufferLegacy':
        lines.append('    // Exported non-virtual helpers (IOMobileGraphicsFamily 343.0.0 exports).\n'
                     '    void update_swap_info_state_gated(IOMFBSwapIORequest *swap, IOMFBSwapCompletionState state);\n'
                     '    void swap_info_notify_dispatch_gated(SwapInfoBlob *blob);\n'
                     '    static uint64_t default_current_absolute_time();\n')
        lines.append(LEGACY_FIELDS)
    else:
        lines.append('protected:\n    uint8_t _%s_opaque[%#x - sizeof(%s)] __attribute__((aligned(8)));\n'
                     % (cls, SIZES[cls], super_) if SIZES[cls] != SIZES.get(super_, -1) else '')
    lines.append('};\n')
    lines.append('static_assert(sizeof(%s) == %#x, "%s instance size differs from 26A428");\n'
                 % (cls, SIZES[cls], cls))
    if cls == 'IOMobileFramebufferLegacy':
        lines.append('struct IOMobileFramebufferLegacy::SwapInfoBlob { uint8_t bytes[0x30]; };\n')
    return ''.join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', type=Path, default=DEFAULT_OUT)
    ap.add_argument('--kdk', type=Path, default=DEFAULT_KDK)
    ap.add_argument('--kc', type=Path, default=DEFAULT_KC)
    ap.add_argument('--no-kc', action='store_true', help='skip the kernelcache cross-check')
    ap.add_argument('--work', type=Path, default=Path(os.environ.get('TMPDIR', '/tmp')) / 'gen-iomfb')
    ap.add_argument('--json', type=Path, help='also write the slot model as JSON')
    args = ap.parse_args()
    model = build_model(args.kdk, None if args.no_kc else args.kc, args.work)
    text = emit(model)
    args.out.write_text(text)
    if args.json:
        args.json.write_text(json.dumps(slot_json(model), indent=1))
    inl = sum(1 for s in model['slots'] if s.inline)
    print(f'{args.out}: {len(model["slots"])} Legacy slots, {inl} inline bodies, '
          f'kernelcache diversities {"equal" if model["report"].get("kc_equal") else "NOT CHECKED"}')


def slot_json(model):
    return [{'slot': s.index, 'div': s.div, 'introducer': s.introducer, 'mangled': s.mangled,
             'method': s.method, 'ret': RET_OVERRIDES.get(s.method, s.ret), 'inline': s.inline,
             'pure_in': sorted(s.pure_in), 'impl': s.impl, 'pv_impl': s.pv_impl}
            for s in model['slots']]


if __name__ == '__main__':
    main()
