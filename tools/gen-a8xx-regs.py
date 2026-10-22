#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate gpu/adreno-kext/include/AdrenoA8xxRegs.h: the A8XX view of Mesa's freedreno register XML, as C.

  tools/gen-a8xx-regs.py [--mesa <mesa checkout>] [--out <header>]

Default Mesa tree: gpu/air2ir3/third_party/mesa (revision bbeb2dca9fee, the tree air2ir3 and q1n1's
tools/a16gpu-p7/gen_a8xx_regs.py read). Offsets, fields, packet dwords, descriptor dwords and enum values come
from Mesa's own parser (src/freedreno/registers/gen_header.py); a register with several chip variants resolves
to the one whose variant range contains A8XX, exactly as q1n1's generator and gen_header's `CHIP == A8XX`
templates do. No register number is typed here: this file lists names only.

Coverage:
  IB registers      every register q1n1's hardware-proven builders write (a16gpu_p6p7.py, a16gpu_render.py,
                    a16gpu_bindings.py through tools/a8xx_regs.py) = the draw-state set a user IB may program
                    (design section 5, section 3.3 KNOWN), plus the explicit nonbindless compute extension.
                    tools/test-draw-contract.sh proves every draw offset/field equals q1n1 and separately
                    checks the compute extension against pinned Mesa's native C generator.
  Monitor registers the CP/RBBM registers the monitor's IB/ring path reads or checks (design section 4).
  Packets           payload dwords of every PM4 packet the reference emits (adreno_pm4.xml).
  Descriptors       A8XX_TEX_MEMOBJ, A8XX_TEX_SAMP, A6XX_UBO.
  Enums             every enum the reference names plus every enum used as a field type above.
Output is deterministic; the test regenerates it and requires byte equality with the checked-in header.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_MESA = os.path.join(ROOT, 'gpu', 'air2ir3', 'third_party', 'mesa')
DEFAULT_OUT = os.path.join(ROOT, 'gpu', 'adreno-kext', 'include', 'AdrenoA8xxRegs.h')

# The header this writes reproduces Mesa's freedreno register database
# (MIT; Copyright (C) 2013 Rob Clark, Ilia Mirkin), so it carries that notice.
FREEDRENO_NOTICE = [
    '/*',
    " * The register definitions below are generated from Mesa's freedreno register",
    ' * database (src/freedreno/registers), which carries this notice:',
    ' *',
    ' * Copyright (C) 2013 by the following authors:',
    ' * - Rob Clark <robdclark@gmail.com> (Initial Author)',
    ' * - Ilia Mirkin <imirkin@alum.mit.edu> (many a3xx/a4xx contributions)',
    ' *',
    ' * Permission is hereby granted, free of charge, to any person obtaining',
    ' * a copy of this software and associated documentation files (the',
    ' * "Software"), to deal in the Software without restriction, including',
    ' * without limitation the rights to use, copy, modify, merge, publish,',
    ' * distribute, sublicense, and/or sell copies of the Software, and to',
    ' * permit persons to whom the Software is furnished to do so, subject to',
    ' * the following conditions:',
    ' *',
    ' * The above copyright notice and this permission notice (including the',
    ' * next paragraph) shall be included in all copies or substantial',
    ' * portions of the Software.',
    ' *',
    ' * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,',
    ' * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF',
    ' * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.',
    ' * IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE',
    ' * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION',
    ' * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION',
    ' * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.',
    ' */',
]
CORE_DOMAINS = ('A6XX', 'A7XX', 'A8XX')    # a6xx.xml's GPU-core domains (variants are split by chip)
ORDER = {'A2XX': 2, 'A3XX': 3, 'A4XX': 4, 'A5XX': 5, 'A6XX': 6, 'A7XX': 7, 'A8XX': 8}
CHIP = 'A8XX'

# The q1n1 reference's register set (tools/a16gpu-p7/gen_a8xx_regs.py REG_NAMES, 284 names), by XML name.
DRAW_REG_NAMES = """
GRAS_A2D_BLT_CNTL GRAS_A2D_DEST_BR GRAS_A2D_DEST_TL GRAS_A2D_SCISSOR_BR GRAS_A2D_SCISSOR_TL GRAS_A2D_SRC_XMAX
GRAS_A2D_SRC_XMIN GRAS_A2D_SRC_YMAX GRAS_A2D_SRC_YMIN GRAS_BIN_FOVEAT GRAS_BIN_FOVEAT_XY_FDM_OFFSET GRAS_CL_ARRAY_SIZE
GRAS_CL_CNTL GRAS_CL_GUARDBAND_CLIP_ADJ GRAS_CL_INTERP_CNTL GRAS_CL_VIEWPORT_XOFFSET GRAS_CL_VIEWPORT_XSCALE
GRAS_CL_VIEWPORT_YOFFSET GRAS_CL_VIEWPORT_YSCALE GRAS_CL_VIEWPORT_ZCLAMP_MAX GRAS_CL_VIEWPORT_ZCLAMP_MIN
GRAS_CL_VIEWPORT_ZOFFSET GRAS_CL_VIEWPORT_ZSCALE GRAS_CL_VS_CLIP_CULL_DISTANCE GRAS_LRZ_BUFFER_BASE
GRAS_LRZ_BUFFER_PITCH GRAS_LRZ_BUFFER_SLICE_PITCH GRAS_LRZ_CB_CNTL GRAS_LRZ_CNTL GRAS_LRZ_CNTL2
GRAS_LRZ_DEPTH_BUFFER_INFO GRAS_LRZ_FAST_CLEAR_BUFFER_BASE GRAS_LRZ_MRT_BUFFER_INFO_0 GRAS_LRZ_PS_INPUT_CNTL
GRAS_LRZ_PS_SAMPLEFREQ_CNTL GRAS_LRZ_QUALITY_LOOKUP_TABLE_REG GRAS_LRZ_VIEW_INFO GRAS_MODE_CNTL GRAS_RAST_CNTL
GRAS_SC_BIN_CNTL GRAS_SC_CNTL GRAS_SC_DEST_MSAA_CNTL GRAS_SC_MSAA_SAMPLE_POS_CNTL GRAS_SC_RAS_MSAA_CNTL
GRAS_SC_SCREEN_SCISSOR_BR GRAS_SC_SCREEN_SCISSOR_CNTL GRAS_SC_SCREEN_SCISSOR_TL GRAS_SC_VIEWPORT_SCISSOR_BR
GRAS_SC_VIEWPORT_SCISSOR_TL GRAS_SC_WINDOW_SCISSOR_BR GRAS_SC_WINDOW_SCISSOR_TL GRAS_SU_CNTL
GRAS_SU_CONSERVATIVE_RAS_CNTL GRAS_SU_DEPTH_BUFFER_INFO GRAS_SU_DEPTH_CNTL GRAS_SU_DEPTH_PLANE_CNTL
GRAS_SU_POINT_MINMAX GRAS_SU_POINT_SIZE GRAS_SU_POLY_OFFSET_OFFSET GRAS_SU_POLY_OFFSET_OFFSET_CLAMP
GRAS_SU_POLY_OFFSET_SCALE GRAS_SU_RENDER_CNTL GRAS_SU_STENCIL_CNTL GRAS_SU_VS_SIV_CNTL PC_ATTR_BUF_GMEM_SIZE
PC_BV_POS_BUF_GMEM_SIZE PC_CNTL PC_DGEN_RAST_CNTL PC_DGEN_SU_CONSERVATIVE_RAS_CNTL PC_HS_BUFFER_SIZE PC_MODE_CNTL
PC_POS_BUF_GMEM_SIZE PC_PS_CNTL PC_RESTART_INDEX PC_STEREO_RENDERING_CNTL PC_TF_BUFFER_SIZE PC_UNKNOWN_980B PC_VS_CNTL
PC_VS_INPUT_CNTL RB_A2D_BLT_CNTL RB_A2D_CLEAR_COLOR_DW0 RB_A2D_CLEAR_COLOR_DW1 RB_A2D_CLEAR_COLOR_DW2
RB_A2D_CLEAR_COLOR_DW3 RB_A2D_DEST_BUFFER_ARRAY_PITCH RB_A2D_DEST_BUFFER_BASE RB_A2D_DEST_BUFFER_INFO
RB_A2D_DEST_BUFFER_PITCH RB_A2D_PIXEL_CNTL RB_ALPHA_TEST_CNTL RB_BIN_FOVEAT RB_BLEND_CNTL RB_BLEND_CONSTANT_ALPHA_FP32
RB_BLEND_CONSTANT_BLUE_FP32 RB_BLEND_CONSTANT_GREEN_FP32 RB_BLEND_CONSTANT_RED_FP32 RB_BUFFER_CNTL RB_CCU_CACHE_CNTL
RB_CLEAR_TARGET RB_CNTL RB_COLOR_FLAG_BUFFER_ADDR RB_COLOR_FLAG_BUFFER_PITCH RB_DEPTH_BOUND_MAX RB_DEPTH_BOUND_MIN
RB_DEPTH_BUFFER_ARRAY_PITCH RB_DEPTH_BUFFER_BASE RB_DEPTH_BUFFER_INFO RB_DEPTH_BUFFER_PITCH RB_DEPTH_CNTL
RB_DEPTH_GMEM_BASE RB_DEPTH_GMEM_DIMENSION RB_DEPTH_PLANE_CNTL RB_DEST_MSAA_CNTL RB_DITHER_CNTL RB_INTERP_CNTL
RB_LB_PARAM_LIMIT RB_LRZ_CNTL RB_LRZ_CNTL2 RB_MODE_CNTL RB_MRT_ARRAY_PITCH RB_MRT_BASE RB_MRT_BASE_GMEM
RB_MRT_BLEND_CONTROL RB_MRT_BUF_INFO RB_MRT_CONTROL RB_MRT_GMEM_DIMENSION_REG RB_MRT_PITCH RB_MSAA_SAMPLE_POS_CNTL
RB_PS_CNTL RB_PS_INPUT_CNTL RB_PS_MRT_CNTL RB_PS_OUTPUT_CNTL RB_PS_OUTPUT_MASK RB_PS_SAMPLEFREQ_CNTL RB_RAS_MSAA_CNTL
RB_RENDER_CNTL RB_SAMPLE_COUNTER_CNTL RB_RESOLVE_CNTL_1 RB_RESOLVE_CNTL_2 RB_RESOLVE_CNTL_3 RB_RESOLVE_CNTL_5
RB_RESOLVE_GMEM_BUFFER_INFO
RB_RESOLVE_WINDOW_OFFSET RB_SRGB_CNTL RB_STENCIL_BUFFER_INFO RB_STENCIL_CNTL RB_STENCIL_GMEM_DIMENSION RB_STENCIL_MASK
RB_STENCIL_REF_CNTL RB_STENCIL_WRITE_MASK RB_UNKNOWN_8818 RB_UNKNOWN_8819 RB_UNKNOWN_881A RB_UNKNOWN_881B
RB_UNKNOWN_881C RB_UNKNOWN_881D RB_UNKNOWN_881E RB_VIEWPORT_ZCLAMP_MAX_REG RB_VIEWPORT_ZCLAMP_MIN_REG
RB_WINDOW_OFFSET SP_A2D_OUTPUT_INFO SP_ALPHA_TEST_CNTL SP_BIN_SIZE SP_BLEND_CNTL SP_DS_CONFIG SP_DS_CONST_CONFIG
SP_GFX_BINDLESS_BASE_DESCRIPTOR SP_GFX_USIZE SP_GS_CONFIG SP_GS_CONST_CONFIG SP_HLSQ_MODE_CNTL SP_HS_CONFIG
SP_HS_CONST_CONFIG SP_LB_PARAM_LIMIT
SP_MODE_CNTL SP_MRT_BLEND_CNTL_REG SP_PERFCTR_SHADER_MASK SP_PS_BASE SP_PS_CNTL_0 SP_PS_CNTL_1 SP_PS_CONFIG
SP_PS_CONST_CONFIG SP_PS_INITIAL_TEX_LOAD_CNTL SP_PS_INSTR_SIZE SP_PS_MRT_CNTL SP_PS_MRT_REG SP_PS_OUTPUT_CNTL
SP_PS_OUTPUT_CONST_CNTL SP_PS_OUTPUT_CONST_MASK SP_PS_OUTPUT_MASK SP_PS_OUTPUT_REG SP_PS_PROGRAM_COUNTER_OFFSET
SP_PS_PVT_MEM_BASE SP_PS_PVT_MEM_PARAM SP_PS_PVT_MEM_SIZE SP_PS_PVT_MEM_STACK_OFFSET SP_PS_SAMPLER_BASE
SP_PS_TEXMEMOBJ_BASE SP_PS_TSIZE SP_PS_VGS_CNTL SP_PS_WAVE_CNTL SP_REG_PROG_ID_0 SP_REG_PROG_ID_1 SP_REG_PROG_ID_2
SP_REG_PROG_ID_3 SP_RENDER_CNTL SP_SRGB_CNTL SP_UNKNOWN_A9A8 SP_UNKNOWN_AB01 SP_UNKNOWN_AB23 SP_UPDATE_CNTL SP_VS_BASE
SP_VS_CNTL_0 SP_VS_CONFIG SP_VS_CONST_CONFIG SP_VS_INSTR_SIZE SP_VS_OUTPUT_CNTL SP_VS_OUTPUT_REG
SP_VS_PROGRAM_COUNTER_OFFSET SP_VS_PVT_MEM_BASE SP_VS_PVT_MEM_PARAM SP_VS_PVT_MEM_SIZE SP_VS_PVT_MEM_STACK_OFFSET
SP_VS_VGS_CNTL SP_VS_VPC_DEST_REG SP_WINDOW_OFFSET TPL1_A2D_BIN_SIZE TPL1_A2D_BLT_CNTL TPL1_A2D_SRC_TEXTURE_BASE
TPL1_A2D_SRC_TEXTURE_FLAG_BASE TPL1_A2D_SRC_TEXTURE_FLAG_PITCH TPL1_A2D_SRC_TEXTURE_INFO TPL1_A2D_SRC_TEXTURE_PITCH
TPL1_A2D_SRC_TEXTURE_SIZE TPL1_A2D_WINDOW_OFFSET TPL1_BIN_SIZE TPL1_CS_BORDER_COLOR_BASE TPL1_DEST_MSAA_CNTL
TPL1_GFX_BORDER_COLOR_BASE TPL1_MODE_CNTL TPL1_PS_ROTATION_CNTL TPL1_PS_SWIZZLE_CNTL TPL1_RAS_MSAA_CNTL
TPL1_WINDOW_OFFSET VFD_CNTL_0 VFD_CNTL_1 VFD_CNTL_2 VFD_CNTL_3 VFD_CNTL_4 VFD_CNTL_5 VFD_CNTL_6 VFD_DEST_CNTL_INSTR
VFD_FETCH_INSTR_INSTR VFD_FETCH_INSTR_STEP_RATE VFD_INDEX_OFFSET VFD_INSTANCE_START_OFFSET VFD_MODE_CNTL
VFD_RENDER_MODE VFD_STEREO_RENDERING_CNTL VFD_VERTEX_BUFFER_BASE VFD_VERTEX_BUFFER_SIZE VFD_VERTEX_BUFFER_STRIDE
VPC_ATTR_BUF_GMEM_BASE VPC_ATTR_BUF_GMEM_SIZE VPC_BV_POS_BUF_GMEM_BASE VPC_BV_POS_BUF_GMEM_SIZE VPC_PC_CNTL
VPC_POS_BUF_GMEM_BASE VPC_POS_BUF_GMEM_SIZE VPC_PS_CNTL VPC_PS_RAST_CNTL VPC_RAST_CNTL VPC_RAST_STREAM_CNTL
VPC_REPLACE_MODE_CNTL VPC_ROTATION_CNTL VPC_SO_CNTL VPC_SO_OVERRIDE VPC_UNKNOWN_CNTL VPC_VARYING_INTERP_MODE_MODE
VPC_VARYING_LM_TRANSFER_CNTL_DISABLE VPC_VARYING_REPLACE_MODE_MODE VPC_VS_CLIP_CULL_CNTL VPC_VS_CNTL VPC_VS_SIV_CNTL
""".split()

# Explicit compute extension to the unchanged q1n1 draw baseline. These names
# come from pinned Mesa fd6_compute.cc/fd6_program.cc/fd6_texture.cc and the
# non-bindless UAV state in a6xx.xml. Values and A8xx fields remain XML-derived.
CS_REG_NAMES = """
SP_CS_CNTL_0 SP_CS_CNTL_1 SP_CS_PROGRAM_COUNTER_OFFSET SP_CS_BASE
SP_CS_PVT_MEM_PARAM SP_CS_PVT_MEM_BASE SP_CS_PVT_MEM_SIZE SP_CS_PVT_MEM_STACK_OFFSET
SP_CS_TSIZE SP_CS_CONFIG SP_CS_INSTR_SIZE SP_CS_HYSTERESIS SP_CS_VGS_CNTL
SP_CS_WIE_CNTL_0 SP_CS_WIE_CNTL_1 SP_CS_SAMPLER_BASE SP_CS_TEXMEMOBJ_BASE
SP_CS_UAV_BASE SP_CS_USIZE SP_CS_CONST_CONFIG SP_CS_WGE_CNTL
SP_CS_NDRANGE_0 SP_CS_NDRANGE_1 SP_CS_NDRANGE_2 SP_CS_NDRANGE_3
SP_CS_NDRANGE_4 SP_CS_NDRANGE_5 SP_CS_NDRANGE_6 SP_CS_NDRANGE_7
SP_CS_KERNEL_GROUP_X SP_CS_KERNEL_GROUP_Y SP_CS_KERNEL_GROUP_Z
""".split()
IB_REG_NAMES = DRAW_REG_NAMES + CS_REG_NAMES

# CP/RBBM registers of the monitor's ring and ADRENO_GUEST_IB path (design 4.2/4.3; compat/adreno.h reads the
# same ones by physical address). Not IB-writable; listed so the monitor never types an offset.
MONITOR_REG_NAMES = """
RBBM_GBIF_HALT RBBM_GBIF_HALT_ACK RBBM_STATUS RBBM_INT_0_MASK RBBM_INT_0_STATUS CP_RB_BASE CP_RB_CNTL
CP_RB_RPTR_ADDR CP_RB_RPTR CP_RB_WPTR CP_SQE_CNTL CP_SQE_INSTR_BASE CP_APRIV_CNTL_PIPE CP_PROTECT_CNTL_PIPE
CP_INTERRUPT_STATUS_GLOBAL
""".split()

# Field-only sets: registers whose A8XX (A6XX-domain) entry carries no bitfields while the generic domain does.
# AXXX CP_RB_CNTL (adreno_common.xml) is what Linux programs on a6xx..a8xx (MSM_GPU_RB_CNTL_DEFAULT).
FIELD_ONLY = (('adreno_common.xml', 'AXXX', 'CP_RB_CNTL'),)

PKT_DOMAINS = """
CP_EVENT_WRITE7 CP_DRAW_INDX_OFFSET CP_LOAD_STATE6 CP_SET_DRAW_STATE_ CP_SET_MARKER CP_THREAD_CONTROL CP_BLIT
CP_INDIRECT_BUFFER CP_WAIT_TIMESTAMP CP_SET_MODE CP_EXEC_CS
""".split()

DESC_DOMAINS = ('A8XX_TEX_MEMOBJ', 'A8XX_TEX_SAMP', 'A6XX_UBO')

# q1n1's ENUM_NAMES plus the PM4 packet-type enum (CP_TYPE4_PKT/CP_TYPE7_PKT) and every enum used as a field
# type above (added automatically in main()).
ENUM_NAMES = """
a3xx_color_swap a3xx_msaa_samples a3xx_rop_code a3xx_rb_blend_opcode a6xx_2d_ifmt a6xx_a2d_pixel_op a6xx_buffers_location
a6xx_ccu_cache_size a6xx_bindless_descriptor_size a6xx_format a6xx_fragcoord_sample_mode a6xx_isam_mode a6xx_coord_round
a6xx_nearest_mode a6xx_lrz_feedback_mask a6xx_marker a6xx_polygon_mode a6xx_raster_direction a6xx_raster_mode
a6xx_render_mode a6xx_rotation a6xx_sequenced_thread_dist a6xx_single_prim_mode a6xx_sp_a2d_output_ifmt_type
a6xx_state_block a6xx_state_src a6xx_state_type a6xx_tex_aniso a6xx_tex_clamp a6xx_tex_filter a6xx_tex_type
a6xx_threadsize a6xx_tile_mode a6xx_ztest_mode a6xx_depth_format a6xx_reduction_mode a6xx_fast_border_color
a6xx_shift_amount a8xx_tex_swiz adreno_compare_func adreno_rb_blend_factor adreno_rb_dither_mode vgt_event_type
pc_di_primtype set_marker_mode pc_di_src_sel pc_di_vis_cull_mode a4xx_index_size a6xx_patch_type
adreno_pm4_type3_packets ts_wait_value_src ts_wait_type event_write_src event_write_dst cp_thread cp_blit_cmd
a7xx_blit_clear_mode a6xx_lrz_dir_status a5xx_line_mode a3xx_threadmode a6xx_tess_output adreno_pm4_packet_type
""".split()

BUILTIN_TYPES = {None, 'a3xx_regid', 'boolean', 'uint', 'hex', 'int', 'fixed', 'ufixed', 'float', 'address',
                 'waddress'}

XML_FILES = ('a6xx.xml', 'adreno_pm4.xml', 'a8xx_descriptors.xml', 'a6xx_descriptors.xml', 'adreno_common.xml',
             'a6xx_enums.xml', 'a7xx_enums.xml', 'a8xx_enums.xml')


def covers(variant, chip=CHIP):
    if variant is None:
        return True
    for v in variant.split(','):
        v = v.strip()
        if '-' in v:
            a, b = v.split('-')
            if ORDER[a] <= ORDER[chip] and (not b or ORDER[chip] <= ORDER[b]):
                return True
        elif v == chip:
            return True
    return False


class Mesa:
    def __init__(self, tree):
        self.tree = tree
        self.regs_dir = os.path.join(tree, 'src', 'freedreno', 'registers')
        if not os.path.isfile(os.path.join(self.regs_dir, 'gen_header.py')):
            sys.exit(f'{tree}: no src/freedreno/registers/gen_header.py (pass --mesa)')
        sys.dont_write_bytecode = True        # the Mesa tree is read-only: no __pycache__ in it
        sys.path.insert(0, self.regs_dir)
        import gen_header  # noqa: E402
        self.G = gen_header

    def load(self, xml):
        p = self.G.Parser()
        p.parse(self.regs_dir, os.path.join(self.regs_dir, 'adreno', xml), False)
        return p

    def revision(self):
        try:
            return subprocess.run(['git', '-C', self.tree, 'rev-parse', 'HEAD'], check=True, capture_output=True,
                                  text=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return 'unknown'

    def xml_sha(self, name):
        with open(os.path.join(self.regs_dir, 'adreno', name), 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()


def variant_of(p, reg):
    for v, r in p.variant_regs.get(reg.name, {}).items():
        if r is reg:
            return v
    return reg.array.variant if reg.array is not None else None


def fields(bitset):
    return tuple((f.name, f.low, f.high, f.shr, f.type or 'uint', getattr(f, 'radix', 0) or 0)
                 for f in bitset.fields)


def regs_of(M, p, domains=None, by_full=False):
    """name -> info for the A8XX variant of every register (q1n1 gen_a8xx_regs.regs_of, plus a domain filter
    so a register of another block (PDC, CX_DBGC, the generic AXXX domain) never shadows a GPU-core one)."""
    G = M.G
    out = {}
    for e in p.file:
        regs = [e] if isinstance(e, G.Reg) else (e.children if isinstance(e, G.Array) else [])
        for r in regs:
            if domains is not None and r.domain not in domains:
                continue
            v = variant_of(p, r)
            if not covers(v):
                continue
            info = {'offset': r.total_offset(), 'bits': r.bit_size, 'variant': v, 'fields': fields(r.bitset),
                    'mesa_name': r.full_name,
                    'domain': r.domain, 'stride': 0, 'length': 1}
            arr = r.array
            if arr is not None and not arr.fixed_offsets and arr.length > 1:
                info['stride'], info['length'] = arr.stride, arr.length
            key = r.full_name if by_full else r.name
            prev = out.get(key)
            if prev and prev['variant'] and v is None:
                continue
            out[key] = info
    return out


def xml_enums(M, names):
    """Enum values straight from the XML, keeping only values whose `variants` cover A8XX."""
    found = {}
    folder = os.path.join(M.regs_dir, 'adreno')
    for fname in sorted(os.listdir(folder)):
        if not fname.endswith('.xml'):
            continue
        root = ET.parse(os.path.join(folder, fname)).getroot()
        for enum in root.iter():
            if enum.tag.split('}')[-1] != 'enum' or enum.get('name') not in names or enum.get('name') in found:
                continue
            values, nxt = {}, 0
            for v in enum:
                if v.tag.split('}')[-1] != 'value':
                    continue
                value = int(v.get('value'), 0) if v.get('value') is not None else nxt
                nxt = value + 1
                if covers(v.get('variants')):
                    values[v.get('name')] = value
            found[enum.get('name')] = values
    missing = sorted(n for n in names if n not in found)
    if missing:
        sys.exit(f'enums not found: {missing}')
    return found


def cname(s):
    return s.upper()


def emit_fields(out, prefix, bits, flds):
    """<prefix>__<FIELD>__SHIFT / __WIDTH / __MASK (in place) / [__SHR] and a packer <prefix>__<FIELD>(v).
    The packer takes the value before `shr` (an address, a byte count) and drops the low shr bits, as Mesa's
    pack does; it never converts float/fixed values (pass their raw bits)."""
    utype, suffix = ('uint64_t', 'ull') if bits == 64 else ('uint32_t', 'u')
    seen = set()
    for name, lo, hi, shr, ftype, radix in flds:
        fname = cname(name) if name else 'VALUE'
        if fname in seen:
            sys.exit(f'{prefix}: duplicate field {fname}')
        seen.add(fname)
        width = hi - lo + 1
        mask = ((1 << width) - 1) << lo
        p = f'{prefix}__{fname}'
        kind = ftype if ftype not in (None, 'uint') else 'uint'
        extra = f' radix {radix}' if ftype in ('fixed', 'ufixed') else ''
        out.append(f'/* {name or "(value)"}: bits {lo}..{hi}, {kind}{extra}{f", shr {shr}" if shr else ""} */')
        out.append(f'#define {p}__SHIFT {lo}u')
        out.append(f'#define {p}__WIDTH {width}u')
        out.append(f'#define {p}__MASK {mask:#x}{suffix}')
        if shr:
            out.append(f'#define {p}__SHR {shr}u')
            out.append(f'#define {p}(v) (((({utype})(v) >> {p}__SHR) << {p}__SHIFT) & {p}__MASK)')
        else:
            out.append(f'#define {p}(v) ((({utype})(v) << {p}__SHIFT) & {p}__MASK)')


FLAG_64, FLAG_ADDRESS, FLAG_WADDRESS = 1, 2, 4


def reg_flags(info):
    flags = FLAG_64 if info['bits'] == 64 else 0
    types = {f[4] for f in info['fields']}
    if 'address' in types or 'waddress' in types:
        flags |= FLAG_ADDRESS
    if 'waddress' in types:
        flags |= FLAG_WADDRESS
    return flags


def emit_reg(out, prefix, name, info):
    p = f'{prefix}_{name}'
    arr = f', array of {info["length"]} stride {info["stride"]:#x}' if info['length'] > 1 else ''
    out.append('')
    out.append(f'/* {name}: {info["bits"]}-bit, domain {info["domain"]}, variant {info["variant"] or "all"}{arr} */')
    out.append(f'#define {p} {info["offset"]:#07x}u')
    out.append(f'#define {p}__BIT_SIZE {info["bits"]}u')
    out.append(f'#define {p}__ARRAY_STRIDE {info["stride"]:#x}u')
    out.append(f'#define {p}__ARRAY_COUNT {info["length"]}u')
    if info['length'] > 1:
        out.append(f'#define {p}_I(i) ({p} + (uint32_t)(i) * {p}__ARRAY_STRIDE)')
    emit_fields(out, p, info['bits'], info['fields'])


PM4_BLOCK = r'''
/* ---- PM4 packet headers --------------------------------------------------------------------------------
 * Formulas of Mesa src/freedreno/common/freedreno_pm4.h (pm4_pkt4_hdr, pm4_pkt7_hdr, pm4_calc_odd_parity_bit,
 * type4/type7 parse masks); the type values are adreno_pm4.xml adreno_pm4_packet_type. Integer-only (the
 * monitor builds with -mgeneral-regs-only). Callers check count/opcode ranges; these helpers mask. */
#define A8XX_PKT4_COUNT_MASK 0x7fu
#define A8XX_PKT4_REG_MASK 0x3ffffu
#define A8XX_PKT7_COUNT_MASK 0x3fffu
#define A8XX_PKT7_OPCODE_MASK 0x7fu
static inline uint32_t a8xx_pm4_odd_parity(uint32_t v)
{
    return (0x9669u >> (0xfu & (v ^ (v >> 4) ^ (v >> 8) ^ (v >> 12) ^ (v >> 16) ^ (v >> 20) ^ (v >> 24) ^
                                (v >> 28)))) & 1u;
}
static inline uint32_t a8xx_pkt4_hdr(uint32_t reg, uint32_t count)
{
    return A8XX_E_CP_TYPE4_PKT | (count & A8XX_PKT4_COUNT_MASK) | (a8xx_pm4_odd_parity(count) << 7) |
           ((reg & A8XX_PKT4_REG_MASK) << 8) | (a8xx_pm4_odd_parity(reg) << 27);
}
static inline uint32_t a8xx_pkt7_hdr(uint32_t opcode, uint32_t count)
{
    return A8XX_E_CP_TYPE7_PKT | (count & A8XX_PKT7_COUNT_MASK) | (a8xx_pm4_odd_parity(count) << 15) |
           ((opcode & A8XX_PKT7_OPCODE_MASK) << 16) | (a8xx_pm4_odd_parity(opcode) << 23);
}
static inline int a8xx_pkt_is_type4(uint32_t h)
{
    return (h & 0xf0000000u) == A8XX_E_CP_TYPE4_PKT &&
           ((h >> 27) & 1u) == a8xx_pm4_odd_parity((h >> 8) & 0x7ffffu) &&
           ((h >> 7) & 1u) == a8xx_pm4_odd_parity(h & A8XX_PKT4_COUNT_MASK);
}
static inline int a8xx_pkt_is_type7(uint32_t h)
{
    return (h & 0xf0000000u) == A8XX_E_CP_TYPE7_PKT && (h & 0x0f000000u) == 0 &&
           ((h >> 23) & 1u) == a8xx_pm4_odd_parity((h >> 16) & A8XX_PKT7_OPCODE_MASK) &&
           ((h >> 15) & 1u) == a8xx_pm4_odd_parity(h & A8XX_PKT7_COUNT_MASK);
}
'''


def generate(M):
    a6 = regs_of(M, M.load('a6xx.xml'), domains=CORE_DOMAINS)
    missing = [n for n in IB_REG_NAMES + MONITOR_REG_NAMES if n not in a6]
    if missing:
        sys.exit(f'not in a6xx.xml (domains {CORE_DOMAINS}) for {CHIP}: {missing}')
    if len(set(IB_REG_NAMES)) != len(IB_REG_NAMES) or set(IB_REG_NAMES) & set(MONITOR_REG_NAMES):
        sys.exit('register name lists overlap or repeat')
    field_only = {}
    for xml, domain, name in FIELD_ONLY:
        r = regs_of(M, M.load(xml), domains=(domain,))
        if name not in r or not r[name]['fields']:
            sys.exit(f'{domain} {name}: no fields in {xml}')
        field_only[f'{domain}_{name}'] = r[name]
    pkt = {n: i for n, i in regs_of(M, M.load('adreno_pm4.xml'), by_full=True).items()
           if any(d in n for d in PKT_DOMAINS if d != 'CP_EXEC_CS') or i['domain'] == 'CP_EXEC_CS'}
    desc = {}
    for xml in ('a8xx_descriptors.xml', 'a6xx_descriptors.xml'):
        for name, info in regs_of(M, M.load(xml), by_full=True).items():
            if any(name.startswith(d + '_') for d in DESC_DOMAINS):
                desc.setdefault(name, info)

    enum_names = set(ENUM_NAMES)
    for table in (a6, pkt, desc, field_only):
        for n, info in table.items():
            if table is a6 and n not in IB_REG_NAMES and n not in MONITOR_REG_NAMES:
                continue
            for f in info['fields']:
                if f[4] not in BUILTIN_TYPES:
                    enum_names.add(f[4])
    # gen_header resolves bitset types too: keep only real enums.
    all_enum_tags = set()
    for fname in os.listdir(os.path.join(M.regs_dir, 'adreno')):
        if fname.endswith('.xml'):
            for e in ET.parse(os.path.join(M.regs_dir, 'adreno', fname)).getroot().iter():
                if e.tag.split('}')[-1] == 'enum':
                    all_enum_tags.add(e.get('name'))
    enum_names = sorted(n for n in enum_names if n in all_enum_tags or n in ENUM_NAMES)
    enums = xml_enums(M, enum_names)
    values = {}
    for ename in sorted(enums):
        for vname, v in enums[ename].items():
            if vname in values and values[vname][1] != v:
                sys.exit(f'enum value {vname} differs between {values[vname][0]} and {ename}')
            values.setdefault(vname, (ename, v))
    upper = {}
    for vname in values:
        if upper.setdefault(cname(vname), vname) != vname:
            sys.exit(f'enum values {upper[cname(vname)]} and {vname} collide as A8XX_E_{cname(vname)}')

    rev = M.revision()
    out = ['/* SPDX-License-Identifier: MIT */', *FREEDRENO_NOTICE,
           '/*',
           ' * AdrenoA8xxRegs.h - GENERATED by tools/gen-a8xx-regs.py. Do not edit; regenerate:',
           ' *   python3 tools/gen-a8xx-regs.py [--mesa <tree>]',
           f' * Source: Mesa {rev} src/freedreno/registers/adreno (gen_header.py parser),',
           f' * the {CHIP} variant of every register. XML sha256:']
    for x in XML_FILES:
        out.append(f' *   {x} {M.xml_sha(x)}')
    out += [' *',
            ' * Plain C (C11/C++17/ObjC; freestanding, integer-only). Names:',
            ' *   A8XX_REG_<NAME>                dword offset of register (array element 0); __BIT_SIZE',
            ' *                                  __ARRAY_STRIDE __ARRAY_COUNT,',
            ' *                                  <NAME>_I(i) for arrays',
            ' *   A8XX_REG_<NAME>__<FIELD>(v)    field packer (v before shr); __SHIFT __WIDTH __MASK [__SHR]',
            ' *   A8XX_PKT_<PKT>_<n>             payload dword index of a PM4 packet dword (after the header), fields',
            ' *   A8XX_DESC_<DESC>_<n>           dword index inside a descriptor, fields',
            ' *   A8XX_E_<VALUE>                 enum value (opcodes: A8XX_E_CP_NOP ...; events: A8XX_E_CACHE_CLEAN ...)',
            ' *   A8XX_FIELDS_<DOMAIN>_<NAME>    fields only, for a register whose A8XX entry has none',
            ' * Define A8XX_REGS_TABLES before including for the a8xx_ib_regs[] / a8xx_monitor_regs[] tables.',
            ' */',
            '#ifndef ADRENO_A8XX_REGS_H',
            '#define ADRENO_A8XX_REGS_H',
            '',
            '#include <stdint.h>',
            '',
            f'#define A8XX_REGS_MESA_REVISION "{rev}"',
            f'#define A8XX_REGS_IB_COUNT {len(IB_REG_NAMES)}u',
            f'#define A8XX_REGS_DRAW_COUNT {len(DRAW_REG_NAMES)}u',
            f'#define A8XX_REGS_CS_COUNT {len(CS_REG_NAMES)}u',
            f'#define A8XX_REGS_MONITOR_COUNT {len(MONITOR_REG_NAMES)}u',
            f'#define A8XX_REG_FLAG_64 {FLAG_64}u        /* reg64: the value spans offset and offset + 1 */',
            f'#define A8XX_REG_FLAG_ADDRESS {FLAG_ADDRESS}u   /* holds a GPU address (XML type address/waddress) */',
            f'#define A8XX_REG_FLAG_WADDRESS {FLAG_WADDRESS}u  /* ... that the GPU writes through (XML waddress) */',
            '',
            '/* ==== Enum values ==================================================================================== */']
    for ename in sorted(enums):
        out.append(f'/* enum {ename} */')
        for vname, v in sorted(enums[ename].items(), key=lambda kv: (kv[1], kv[0])):
            if values[vname][0] != ename:
                continue          # emitted once, under the first enum that defines it
            out.append(f'#define A8XX_E_{cname(vname)} {v:#x}u')
    out.append(PM4_BLOCK)
    out.append('/* ==== IB registers: exact q1n1 draw baseline plus explicit Mesa CS extension ================== */')
    for n in sorted(IB_REG_NAMES):
        emit_reg(out, 'A8XX_REG', n, a6[n])
    out.append('')
    out.append('/* ==== Monitor registers: CP/RBBM ring, idle and fault state ======================================= */')
    for n in sorted(MONITOR_REG_NAMES):
        emit_reg(out, 'A8XX_REG', n, a6[n])
    out.append('')
    out.append('/* ==== Field-only sets ============================================================================ */')
    for n in sorted(field_only):
        info = field_only[n]
        out.append(f'/* {n}: {info["bits"]}-bit, fields of the generic-domain register */')
        emit_fields(out, f'A8XX_FIELDS_{n}', info['bits'], info['fields'])
    out.append('')
    out.append('/* ==== PM4 packet payload dwords (index after the header) ========================================== */')
    for n in sorted(pkt):
        info = pkt[n]
        out.append('')
        out.append(f'/* {n}: {info["bits"]}-bit, variant {info["variant"] or "all"} */')
        out.append(f'#define A8XX_PKT_{n} {info["offset"]}u')
        out.append(f'#define A8XX_PKT_{n}__BIT_SIZE {info["bits"]}u')
        emit_fields(out, f'A8XX_PKT_{n}', info['bits'], info['fields'])
    out.append('')
    out.append('/* ==== Descriptor dwords ============================================================================ */')
    for n in sorted(desc):
        info = desc[n]
        out.append('')
        out.append(f'/* {n}: {info["bits"]}-bit */')
        out.append(f'#define A8XX_DESC_{n} {info["offset"]}u')
        emit_fields(out, f'A8XX_DESC_{n}', info['bits'], info['fields'])
    out.append('')
    out.append('/* ==== Tables (opt-in) ============================================================================= */')
    out.append('#ifdef A8XX_REGS_TABLES')
    out.append('struct a8xx_reg_info { const char *name; uint32_t offset, stride; uint16_t count; uint8_t bits, flags; };')
    for label, names in (('ib', IB_REG_NAMES), ('monitor', MONITOR_REG_NAMES)):
        out.append(f'static const struct a8xx_reg_info a8xx_{label}_regs[] = {{')
        for n in sorted(names, key=lambda k: (a6[k]['offset'], k)):
            i = a6[n]
            out.append(f'    {{"{n}", {i["offset"]:#07x}u, {i["stride"]:#x}u, {i["length"]}u, {i["bits"]}u, '
                       f'{reg_flags(i)}u}},')
        out.append('};')
    out.append('#endif /* A8XX_REGS_TABLES */')
    out.append('')
    out.append('#endif /* ADRENO_A8XX_REGS_H */')
    text = '\n'.join(out) + '\n'
    names = [l.split()[1].split('(')[0] for l in out if l.startswith('#define ')]
    dup = sorted({n for n in names if names.count(n) > 1}) if len(set(names)) != len(names) else []
    if dup:
        sys.exit(f'macro names emitted twice: {dup[:10]}')
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--mesa', default=os.environ.get('MESA_TREE', DEFAULT_MESA))
    ap.add_argument('--out', default=DEFAULT_OUT)
    args = ap.parse_args()
    text = generate(Mesa(os.path.abspath(args.mesa)))
    with open(args.out, 'w') as f:
        f.write(text)
    print(f'wrote {args.out}: {len(IB_REG_NAMES)} IB registers, {len(MONITOR_REG_NAMES)} monitor registers')


if __name__ == '__main__':
    main()
