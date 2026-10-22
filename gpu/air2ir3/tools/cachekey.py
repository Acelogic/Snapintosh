#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cachekey.py - reference implementation of the precompiled-cache key, format 5 (CACHE-FORMAT.md 2).

key = SHA-256( "AIR2IR3-CACHE-KEY\\0"
             | u32 cache_format_version (5) | u32 abi_version (6) | u32 chip_id
             | 32 bytes AIR hash (SHA-256 of the function's bitcode module; = the metallib HASH tag)
             | u32 stage (1 vertex, 2 fragment, 3 kernel)
             | u32 len | entry-point name (UTF-8, no NUL)
             | u32 n_fc | n_fc x { u16 index | u16 MTLDataType | u8 defined | u8 0 | u16 nbytes | value bytes }
             | u32 8 | 8 x u8 format class of colour attachments 0..7          (all 0 unless fragment)
             | for each attachment with class != 0: 7 x u8 blend
                   { enabled, rgbOp, alphaOp, srcRGB, dstRGB, srcAlpha, dstAlpha }   (all 0 when !enabled)
             | u32 16 | 16 x u8 draw-time format class of T# 0..15 (0 for every T# the function does
                                  not declare as a texture(n) argument)
             | u8 safe_constlen (1: ir3's safe_constlen variant, BINDING-ABI.md 5.2) )
Format 5 vs 4 (fix round 6, verify6 must-fix 2): the same key layout; the value bytes are each component
in its DECLARED type (integers wrapped to their width, bool 0/1, float / half their IEEE bits, NaN / inf / -0
included), and the sidecar's function_constants hold that value exactly (integers as JSON integers,
float / half as the shortest round-trip decimal or "nan" / "inf" / "-inf" / "-nan", plus "bits": the IEEE
bit pattern of each component, which this reader prefers).  The key recomputes from the sidecar for every value.
Format 4 vs 3: the same key layout; the version words change because ABI v4 changes what the code
and the sidecar mean (constexpr sampler slots, NTEX/NSAMP, sample shading, min/max XR blend,
unset-constant refusal), so no v3 entry can be taken for a v4 one.
ABI v5 (fix round 4) keeps format 4 and changes only the abi_version word: NSAMP counts the s# of
every texture instruction, unset constants fold only when provably value-independent, and presence
predicates that depend on an unset constant's value are refused (BINDING-ABI.md 3.4, 3.7).
ABI v6 keeps format 4 and changes only the abi_version word: every UBO index is below 16 (a8xx's
non-bindless UBO table), so the driver table moves from UBO 31 to 1 + the highest declared constant
buffer and ir3's driver UBOs follow it (BINDING-ABI.md 3.1, 3.2, 3.9).
Format 3 vs 2: + safe_constlen; texture classes masked to the declared texture(n) arguments; the
raster sample count is gone (the compile never reads it).
All integers little-endian.  FC records are sorted by index and cover every function constant the
function declares (defined=0 records carry no value bytes).  The C library computes the same key
(air2ir3_compile, sidecar "key"); tests/pipelinekey.swift computes it a third time from real
MTLRenderPipelineDescriptors.
"""
import hashlib, struct

CACHE_FORMAT_VERSION = 5
ABI_VERSION = 6
MAGIC = b'AIR2IR3-CACHE-KEY\0'
STAGE = {'vertex': 1, 'fragment': 2, 'kernel': 3}

# MTLDataType values (Metal/MTLArgument.h)
MTL_DATA_TYPE = {
    'float': 3, 'float2': 4, 'float3': 5, 'float4': 6,
    'half': 16, 'half2': 17, 'half3': 18, 'half4': 19,
    'int': 29, 'int2': 30, 'int3': 31, 'int4': 32,
    'uint': 33, 'uint2': 34, 'uint3': 35, 'uint4': 36,
    'short': 37, 'short2': 38, 'short3': 39, 'short4': 40,
    'ushort': 41, 'ushort2': 42, 'ushort3': 43, 'ushort4': 44,
    'char': 45, 'char2': 46, 'char3': 47, 'char4': 48,
    'uchar': 49, 'uchar2': 50, 'uchar3': 51, 'uchar4': 52,
    'bool': 53, 'bool2': 54, 'bool3': 55, 'bool4': 56,
    'long': 81, 'ulong': 85,
}
# MTLPixelFormat values used by WindowServer / CA (Metal/MTLPixelFormat.h + the private XR/YCbCr ones)
MTL_PIXEL_FORMAT = {
    'invalid': 0, 'a8Unorm': 1, 'r8Unorm': 10, 'r16Float': 25, 'rg8Unorm': 30, 'rgba8Unorm': 70,
    'rgba8Unorm_srgb': 71, 'bgra8Unorm': 80, 'bgra8Unorm_srgb': 81, 'rgb10a2Unorm': 90, 'bgr10a2Unorm': 94,
    'rg11b10Float': 92, 'rgba16Unorm': 110, 'rgba16Float': 115, 'rgba32Float': 125,
    'bgra10_xr': 552, 'bgra10_xr_srgb': 553, 'bgr10_xr': 554, 'bgr10_xr_srgb': 555,
    'r32Float': 55, 'rg16Float': 65, 'r16Unorm': 20, 'rg16Unorm': 60,
    'rgb10a8_2p_xr10': 550, 'rgb10a8_2p_xr10_srgb': 551, 'ycbcr10_420_2p_packed': 508, 'ycbcr10_444_2p_packed': 510,
}
# FORMAT CLASS (CACHE-FORMAT.md 2.2, FORMATS.md): 0 = the Adreno RB renders it natively (or no attachment)
FORMAT_CLASS = {554: 1, 552: 2, 550: 3, 551: 3, 508: 4, 510: 4, 553: 5, 555: 5}
CLASS_NAME = ['native', 'xr10_bgr32', 'xr10_bgra64', 'xr10_rgb10a8_2p', 'ycbcr10_packed', 'xr10_srgb']

def format_class(mtl_pixel_format):
    return FORMAT_CLASS.get(int(mtl_pixel_format), 0)

def _scalar(t):
    for p in ('uchar', 'char', 'ushort', 'short', 'uint', 'int', 'ulong', 'long', 'half', 'float', 'bool'):
        if t.startswith(p):
            n = t[len(p):]
            return p, int(n) if n else 1
    raise ValueError('unknown function-constant type ' + t)

def _num(v):
    """a sidecar / scene value: a JSON number, or a string such as "nan", "-inf", "-0.0" (format 5)"""
    if isinstance(v, bool): return 1 if v else 0
    if isinstance(v, str): return float(v)
    return v

def _int(v):
    """C conversion toward zero of a number (the value the compiler canonicalises, fcCanon)"""
    v = _num(v)
    if isinstance(v, int): return v
    if v != v: return 0
    if v in (float('inf'), float('-inf')): return -1 if v > 0 else -(1 << 63)
    return int(v)

def fc_bytes(t, values, bits=None):
    """value bytes in the declared type; float / half from `bits` (the sidecar's IEEE patterns) when given"""
    base, n = _scalar(t)
    vals = list(values) + [values[0] if values else 0] * (n - len(values))
    bl = list(bits or [])
    bl = bl + [bl[0] if bl else None] * (n - len(bl))
    out = b''
    for v, b in zip(vals[:n], bl[:n]):
        if base == 'bool': out += struct.pack('<B', 1 if _num(v) != 0 else 0)
        elif base in ('uchar', 'char'): out += struct.pack('<B', _int(v) & 0xff)
        elif base in ('ushort', 'short'): out += struct.pack('<H', _int(v) & 0xffff)
        elif base in ('uint', 'int'): out += struct.pack('<I', _int(v) & 0xffffffff)
        elif base in ('ulong', 'long'): out += struct.pack('<Q', _int(v) & 0xffffffffffffffff)
        elif base == 'float': out += struct.pack('<I', int(b, 16)) if b is not None else struct.pack('<f', float(_num(v)))
        elif base == 'half': out += struct.pack('<H', int(b, 16)) if b is not None else struct.pack('<e', float(_num(v)))
    return out

BLEND_FIELDS = ('rgb_op', 'alpha_op', 'src_rgb', 'dst_rgb', 'src_alpha', 'dst_alpha')

def key_material(chip_id, air_hash_hex, stage, entry, fcs, rt_classes=None, blend=None, tex_classes=None, safe_constlen=False,
                 declared_textures=None):
    """fcs: [{index, type, defined, value}]; rt_classes: 8 ints; blend: {attachment: {enabled, rgb_op, ...}};
    tex_classes: 16 ints; declared_textures: the T# the function declares (None = the classes are already masked)."""
    st = STAGE[stage] if isinstance(stage, str) else int(stage)
    m = MAGIC + struct.pack('<III', CACHE_FORMAT_VERSION, ABI_VERSION, chip_id)
    h = bytes.fromhex(air_hash_hex); assert len(h) == 32
    m += h + struct.pack('<I', st)
    e = entry.encode()
    m += struct.pack('<I', len(e)) + e
    fcs = sorted(fcs, key=lambda f: f['index'])
    m += struct.pack('<I', len(fcs))
    for f in fcs:
        vb = fc_bytes(f['type'], f['value'], f.get('bits')) if f['defined'] else b''
        m += struct.pack('<HHBBH', f['index'], MTL_DATA_TYPE[f['type']], 1 if f['defined'] else 0, 0, len(vb)) + vb
    frag = st == 2
    rc = [int(c) if frag else 0 for c in (list(rt_classes or []) + [0] * 8)[:8]]
    m += struct.pack('<I', 8) + bytes(rc)
    blend = blend or {}
    for i in range(8):
        if not rc[i]: continue
        b = blend.get(i) or blend.get(str(i)) or {}
        en = 1 if b.get('enabled') else 0
        m += bytes([en] + [int(b.get(k, 0)) if en else 0 for k in BLEND_FIELDS])
    tc = [int(c) for c in (list(tex_classes or []) + [0] * 16)[:16]]
    if declared_textures is not None: tc = [c if t in declared_textures else 0 for t, c in enumerate(tc)]
    m += struct.pack('<I', 16) + bytes(tc)
    m += bytes([1 if safe_constlen else 0])
    return m

def cache_key(chip_id, air_hash_hex, stage, entry, fcs, rt_classes=None, blend=None, tex_classes=None, safe_constlen=False,
              declared_textures=None):
    return hashlib.sha256(key_material(chip_id, air_hash_hex, stage, entry, fcs, rt_classes, blend, tex_classes, safe_constlen,
                                       declared_textures)).hexdigest()

def key_of_sidecar(side, chip_id=None):
    """recompute a sidecar's key from its key_inputs + the reflection's function constants"""
    ki = side['key_inputs']
    return cache_key(chip_id if chip_id is not None else int(side['chip_id'], 16), ki['air_hash'], ki['stage'], ki['entry'],
                     side['reflection']['function_constants'], ki['rt_classes'], ki.get('blend'), ki.get('texture_classes'),
                     ki['safe_constlen'])

SELFTEST = '84d0e040476266a13d34c957018ff089e40e642ce6963f79367156f8aa3881c1'   # format 5, ABI 6 (format 4 + ABI 6: 5abb93e8...; ABI 5: 354396c4...; ABI 4: 1ab00a75...; format 3: bbc160e5...)

def selftest_key():
    """chip 0x44070041, all-zero hash, fragment "f", FCs {0: bool 1, 3: uchar4 (1,2,3,4), 5: float unset},
    RT0 = BGR10_XR (class 1) with premultiplied-over blending, RT1 = bgra8 (class 0), T#2 class 2 (declared),
    T#3 class 1 (not declared: masked), safe_constlen variant"""
    return cache_key(0x44070041, '00' * 32, 'fragment', 'f',
                     [dict(index=0, type='bool', defined=True, value=[1]),
                      dict(index=3, type='uchar4', defined=True, value=[1, 2, 3, 4]),
                      dict(index=5, type='float', defined=False, value=[])],
                     [format_class(554), format_class(80)],
                     {0: dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=1, dst_rgb=5, src_alpha=1, dst_alpha=5)},
                     [0, 0, 2, 1], True, declared_textures={0, 2})

if __name__ == '__main__':
    print(selftest_key())
