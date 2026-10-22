/* SPDX-License-Identifier: MIT */
// nirexec - execute the NIR that air2ir3 produces from Apple AIR on Mesa llvmpipe.
//
// The same AIR -> NIR front end that feeds ir3 (air_frontend) is used; the NIR is then given to
// llvmpipe with the binding ABI mapped onto gallium state:
//   Metal buffer(n), constant space  -> constant buffer n
//   Metal buffer(n), device space    -> host pointer in the device-address table (constant buffer 31)
//   Metal texture(n) / sampler(n)    -> sampler view n / sampler state n
//   constexpr samplers               -> sampler state at the S# chosen by the front end
//   shader constant data             -> constant buffer 30
//   varyings                         -> linked by name (FS input slot := VS output slot)
// The scene (geometry, uniforms, textures, samplers) is a JSON file shared with the Metal golden
// generator (tools/mtlgold.swift) so both sides render exactly the same thing.
//
// Scene "rt" {"format": bgra8|rgba16f|bgr10_xr|bgra10_xr, "init_file": raw Metal-layout contents}
// and "blend" {Metal blend state} select the colour attachment; XR attachments and XR textures are
// run through the compiler's shader lowering (FORMATS.md) exactly as on the Adreno: the attachment
// is a UNORM view (B10G10R10A2_UNORM for 554, R16G16B16A16_UNORM for 552 with the B,G,R,A word order
// the RB swap provides, emulated here by reordering the words on upload/readback) and the gallium
// blend state is the compiler's hw_blend.  The output file holds the attachment's raw bytes in
// Metal's layout.
//
// usage: nirexec scene.json out.raw [--frames N] [--dump-nir] [--spv-vs ref.spv] [--spv-fs ref.spv]
//   --spv-vs/--spv-fs replace the AIR-derived NIR of that stage with the NIR Mesa's own SPIR-V front
//   end builds from the equivalent reference GLSL (spvnir.h); the AIR reflection still supplies the
//   constexpr sampler states, so both NIRs run with identical gallium state (NIR differential by
//   execution, tools/nirdiff.py).
#include "air2ir3.h"
#include "a8xx_sampler.h"
#include "spvnir.h"

#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "nir.h"
#include "nir_builder.h"
#include "pipe/p_context.h"
#include "pipe/p_screen.h"
#include "pipe/p_state.h"
#include "pipe/p_defines.h"
#include "util/format/u_format.h"
#include "util/u_inlines.h"
#include "llvmpipe/lp_public.h"
#include "sw/null/null_sw_winsys.h"

using namespace llvm;

[[noreturn]] static void fail(const std::string &m) { fprintf(stderr, "nirexec: %s\n", m.c_str()); exit(3); }

// llvmpipe has 16 constant-buffer slots (Metal indices used by the scenes are < 14), so the
// ABI's device-address table (UBO driver_table_ubo: ABI v6, 1 + the highest declared constant
// buffer) is remapped to slot 15 and shader constant data uses slot 14.
static const int CONSTDATA_CB = 14, DEVICE_VA_CB = 15;

static std::string ROOT;
static std::string rel(const std::string &p) { return p.size() && p[0] == '/' ? p : ROOT + "/" + p; }
static std::vector<uint8_t> readFile(const std::string &p) {
  auto b = MemoryBuffer::getFile(rel(p));
  if (!b) fail("cannot read " + p);
  return std::vector<uint8_t>((*b)->getBufferStart(), (*b)->getBufferEnd());
}
// Scene buffers: {"floats":[...]} | {"uints":[...]} | {"file":"x.bin"}
static std::vector<uint8_t> bytesOf(const json::Object *o) {
  std::vector<uint8_t> v;
  if (auto *f = o->getArray("floats")) for (auto &x : *f) { float y = (float)*x.getAsNumber(); uint8_t b[4]; memcpy(b, &y, 4); v.insert(v.end(), b, b + 4); }
  if (auto *u = o->getArray("uints")) for (auto &x : *u) { uint32_t y = (uint32_t)*x.getAsInteger(); uint8_t b[4]; memcpy(b, &y, 4); v.insert(v.end(), b, b + 4); }
  if (auto f = o->getString("file")) { auto d = readFile(f->str()); v.insert(v.end(), d.begin(), d.end()); }
  while (v.size() % 16) v.push_back(0);
  return v;
}

// ---------------------------------------------------------------- NIR fix-ups for gallium --
// frag coord: gallium wants a VARYING_SLOT_POS input variable, not the load_frag_coord intrinsic.
static void lower_frag_coord_to_var(nir_shader *s) {
  nir_variable *pos = nullptr;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type != nir_instr_type_intrinsic) continue;
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      if (in->intrinsic != nir_intrinsic_load_frag_coord) continue;
      if (!pos) { pos = nir_variable_create(s, nir_var_shader_in, glsl_vec4_type(), "gl_FragCoord"); pos->data.location = VARYING_SLOT_POS; }
      b.cursor = nir_before_instr(ins);
      nir_def_replace(&in->def, nir_load_var(&b, pos));
    }
  }
  s->info.fs.origin_upper_left = true;          // Metal: origin top-left, pixel centres at .5
  s->info.fs.pixel_center_integer = false;
}
// 16-bit phis and ALU operations -> 32-bit before llvmpipe: its gallivm fails LLVM instruction selection on 16-bit
// float vectors in CoreAnimation's generic fragment function ("Cannot select v4i16 = bitcast v4f32"). Phis move the
// same bits (u2u32 / u2u16); an ALU operation runs in fp32 and its result is rounded back to 16 bits (f2f16), which
// for +, -, *, / and sqrt equals the correctly rounded half result (24 >= 2 * 11 + 2 bits). Conversions and
// operations with sized operand or result types keep their bit sizes.
static unsigned lower16(const nir_instr *instr, void *) {
  if (instr->type == nir_instr_type_phi) {
    unsigned bits = nir_instr_as_phi(const_cast<nir_instr *>(instr))->def.bit_size;
    return bits == 16 || bits == 8 ? 32 : 0;
  }
  if (instr->type != nir_instr_type_alu) return 0;
  const nir_alu_instr *alu = nir_instr_as_alu(const_cast<nir_instr *>(instr));
  const nir_op_info *info = &nir_op_infos[alu->op];
  if (info->is_conversion) return 0;
  if (nir_alu_type_get_type_size(info->output_type) && nir_alu_type_get_base_type(info->output_type) != nir_type_bool)
    return 0;                                                 // comparisons (bool results) widen; pack/unpack do not
  // 8-bit integer operations too (CoreAnimation's configuration bytes): gallivm evaluates some of them wrongly.
  auto small = [](unsigned bits) { return bits == 16 || bits == 8; };
  bool narrow = small(alu->def.bit_size);
  for (unsigned i = 0; i < info->num_inputs; i++) {
    if (nir_alu_type_get_type_size(info->input_types[i])) continue;
    unsigned bits = alu->src[i].src.ssa->bit_size;
    if (small(bits)) narrow = true;
    else if (bits > 16) return 0;                               // mixed sizes
  }
  return narrow ? 32 : 0;
}
// Texture results as half (Metal texture2d<half>/texture3d<half>): sample to fp32 and convert with f2f16, since
// gallivm reinterprets its fp32 filter result as a 16-bit vector otherwise (the same selection failure).
static bool widen_tex16(nir_shader *s) {
  bool progress = false;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type != nir_instr_type_tex) continue;
      nir_tex_instr *t = nir_instr_as_tex(ins);
      if (t->def.bit_size != 16 || nir_alu_type_get_base_type(t->dest_type) != nir_type_float) continue;
      t->def.bit_size = 32; t->dest_type = nir_type_float32;
      b.cursor = nir_after_instr(ins);
      nir_def *narrow = nir_f2f16(&b, &t->def);
      nir_def_rewrite_uses_after(&t->def, narrow);
      progress = true;
    }
    nir_progress(progress, impl, nir_metadata_control_flow);
  }
  return progress;
}
// fp16 varyings: llvmpipe interpolates in fp32 and then reinterprets the result as a 16-bit vector (the selection
// failure again). Make the interface variables fp32: the vertex stores f2f32(value), the fragment loads fp32 and
// narrows with f2f16 (lower_f16_conversions then keeps fp32 where the consumer widens again).
static bool widen_io16(nir_shader *s, nir_variable_mode mode) {
  bool progress = false;
  nir_foreach_variable_with_modes(var, s, mode) {
    const glsl_type *t = var->type;
    if (!glsl_type_is_vector_or_scalar(t) || glsl_get_base_type(t) != GLSL_TYPE_FLOAT16) continue;
    var->type = glsl_vector_type(GLSL_TYPE_FLOAT, glsl_get_vector_elements(t));
    progress = true;
  }
  if (!progress) return false;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type == nir_instr_type_deref) {
        nir_deref_instr *d = nir_instr_as_deref(ins);
        if (d->deref_type == nir_deref_type_var && (d->modes & mode)) d->type = d->var->type;
        continue;
      }
      if (ins->type != nir_instr_type_intrinsic) continue;
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      if (in->intrinsic != nir_intrinsic_load_deref && in->intrinsic != nir_intrinsic_store_deref) continue;
      nir_deref_instr *d = nir_src_as_deref(in->src[0]);
      if (!(d->modes & mode) || glsl_get_bit_size(d->type) != 32) continue;
      if (in->intrinsic == nir_intrinsic_load_deref && in->def.bit_size == 16) {
        in->def.bit_size = 32;
        b.cursor = nir_after_instr(ins);
        nir_def *narrow = nir_f2f16(&b, &in->def);
        nir_def_rewrite_uses_after(&in->def, narrow);
      } else if (in->intrinsic == nir_intrinsic_store_deref && in->src[1].ssa->bit_size == 16) {
        b.cursor = nir_before_instr(ins);
        nir_src_rewrite(&in->src[1], nir_f2f32(&b, in->src[1].ssa));
      }
    }
    nir_progress(true, impl, nir_metadata_control_flow);
  }
  return true;
}
// Constant-buffer and device-memory loads narrower than 32 bits become 32-bit loads plus extraction, as ir3 does
// for UBOs (ir3_nir.c ir3_mem_access_size_align): gallivm's 16-bit buffer loads return wrong values.
static nir_mem_access_size_align mem_access_32(nir_intrinsic_op intrin, uint8_t bytes, uint8_t bit_size, uint32_t align,
                                               uint32_t align_offset, bool, enum gl_access_qualifier, const void *) {
  align = nir_combined_align(align, align_offset);
  if ((bytes & 1) || align == 1) bit_size = 8;
  else if ((bytes & 2) || align == 2) bit_size = 16;
  else if (bit_size >= 32) bit_size = 32;
  if (intrin == nir_intrinsic_load_ubo || intrin == nir_intrinsic_load_global || intrin == nir_intrinsic_load_global_constant)
    bit_size = 32;
  nir_mem_access_size_align r = {};
  r.num_components = (uint8_t)std::max(1, std::min(bytes / (bit_size / 8), 4));
  r.bit_size = bit_size; r.align = (uint16_t)(bit_size / 8); r.shift = nir_mem_access_shift_method_scalar;
  return r;
}
// Derivatives of fp16 values (ddx/ddy intrinsics, which nir_lower_bit_size leaves alone): take them in fp32.
static bool widen_derivatives16(nir_shader *s) {
  bool progress = false;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type != nir_instr_type_intrinsic) continue;
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      switch (in->intrinsic) {
      case nir_intrinsic_ddx: case nir_intrinsic_ddy: case nir_intrinsic_ddx_fine: case nir_intrinsic_ddy_fine:
      case nir_intrinsic_ddx_coarse: case nir_intrinsic_ddy_coarse: break;
      default: continue;
      }
      if (in->def.bit_size != 16) continue;
      b.cursor = nir_before_instr(ins);
      nir_src_rewrite(&in->src[0], nir_f2f32(&b, in->src[0].ssa));
      in->def.bit_size = 32;
      b.cursor = nir_after_instr(ins);
      nir_def *narrow = nir_f2f16(&b, &in->def);
      nir_def_rewrite_uses_after(&in->def, narrow);
      progress = true;
    }
    nir_progress(progress, impl, nir_metadata_control_flow);
  }
  return progress;
}
// After lower16 no float arithmetic is 16-bit, but conversions still are: gallivm builds LLVM half vectors for them
// (lp_bld_nir_soa.c f2f16/f2f32, and half constants), which LLVM's AArch64 back end cannot select without full fp16
// (the FIXME there). f2f32(f2f16(x)) keeps x (the reference then evaluates that fp16 rounding step in fp32); every
// other conversion to or from fp16 becomes integer code on the 16-bit pattern: f32 -> f16 rounds to nearest even
// (NaN -> 0x7e00, >= 65520 -> inf, subnormals by f * 2^24), f16 -> f32 is exact, b2f16 -> 0x3c00 / 0.
static nir_def *f32_to_f16_bits(nir_builder *b, nir_def *f) {
  nir_def *x = f, *a = nir_iand_imm(b, x, 0x7fffffff), *sign = nir_iand_imm(b, nir_ushr_imm(b, x, 16), 0x8000);
  nir_def *normal = nir_isub(b, nir_ushr_imm(b, nir_iadd(b, nir_iadd_imm(b, a, 0xfff), nir_iand_imm(b, nir_ushr_imm(b, a, 13), 1)), 13),
                             nir_imm_int(b, 112 << 10));
  nir_def *sub = nir_f2u32(b, nir_fround_even(b, nir_fmul_imm(b, nir_fabs(b, x), 16777216.0)));
  nir_def *h = nir_bcsel(b, nir_uge_imm(b, a, 0x38800000), normal, sub);
  h = nir_bcsel(b, nir_uge_imm(b, a, 0x477ff000), nir_imm_int(b, 0x7c00), h);
  h = nir_bcsel(b, nir_ult(b, nir_imm_int(b, 0x7f800000), a), nir_imm_int(b, 0x7e00), h);
  return nir_u2u16(b, nir_ior(b, h, sign));
}
static nir_def *f16_bits_to_f32(nir_builder *b, nir_def *bits16) {
  nir_def *h = nir_u2u32(b, bits16), *sign = nir_ishl_imm(b, nir_iand_imm(b, h, 0x8000), 16);
  nir_def *e = nir_iand_imm(b, nir_ushr_imm(b, h, 10), 0x1f), *m = nir_iand_imm(b, h, 0x3ff);
  nir_def *normal = nir_ior(b, nir_ishl_imm(b, nir_iadd_imm(b, e, 112), 23), nir_ishl_imm(b, m, 13));
  nir_def *infnan = nir_ior(b, nir_imm_int(b, 0x7f800000), nir_ishl_imm(b, m, 13));
  nir_def *sub = nir_fmul_imm(b, nir_u2f32(b, m), 5.9604644775390625e-8);
  nir_def *r = nir_bcsel(b, nir_ieq_imm(b, e, 0), sub, nir_bcsel(b, nir_ieq_imm(b, e, 31), infnan, normal));
  return nir_ior(b, r, sign);
}
static bool lower_f16_conversions(nir_shader *s) {
  bool progress = false;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type != nir_instr_type_alu) continue;
      nir_alu_instr *alu = nir_instr_as_alu(ins);
      nir_def *src = alu->src[0].src.ssa;
      b.cursor = nir_before_instr(ins);
      nir_def *rep = nullptr;
      if ((alu->op == nir_op_f2f16 || alu->op == nir_op_f2f16_rtne) && src->bit_size == 32) {
        rep = f32_to_f16_bits(&b, nir_ssa_for_alu_src(&b, alu, 0));
      } else if (alu->op == nir_op_f2f32 && src->bit_size == 16) {
        nir_alu_instr *def = nir_def_as_alu_or_null(src);
        if (def && (def->op == nir_op_f2f16 || def->op == nir_op_f2f16_rtne) && def->src[0].src.ssa->bit_size == 32) {
          nir_def *wide = nir_ssa_for_alu_src(&b, def, 0);       // the fp32 value before its fp16 rounding
          unsigned sw[NIR_MAX_VEC_COMPONENTS];
          for (unsigned i = 0; i < alu->def.num_components; i++) sw[i] = alu->src[0].swizzle[i];
          rep = nir_swizzle(&b, wide, sw, alu->def.num_components);
        } else {
          rep = f16_bits_to_f32(&b, nir_ssa_for_alu_src(&b, alu, 0));
        }
      } else if (alu->op == nir_op_b2f16) {
        rep = nir_u2u16(&b, nir_bcsel(&b, nir_ssa_for_alu_src(&b, alu, 0), nir_imm_int(&b, 0x3c00), nir_imm_int(&b, 0)));
      } else if (nir_op_infos[alu->op].is_conversion && src->bit_size == 16 &&
                 nir_alu_type_get_base_type(nir_op_infos[alu->op].input_types[0]) == nir_type_float) {
        nir_src_rewrite(&alu->src[0].src, f16_bits_to_f32(&b, src));   // f2i32(f16) etc.: convert from fp32
        progress = true;
        continue;
      } else if (nir_op_infos[alu->op].is_conversion && alu->def.bit_size == 16 &&
                 nir_alu_type_get_base_type(nir_op_infos[alu->op].output_type) == nir_type_float) {
        nir_op wide = nir_type_conversion_op((nir_alu_type)(nir_op_infos[alu->op].input_types[0] | src->bit_size),
                                             nir_type_float32, nir_rounding_mode_undef);
        rep = f32_to_f16_bits(&b, nir_build_alu1(&b, wide, nir_ssa_for_alu_src(&b, alu, 0)));
      }
      if (!rep) continue;
      nir_def_replace(&alu->def, rep);
      progress = true;
    }
    nir_progress(progress, impl, nir_metadata_control_flow);
  }
  return progress;
}
// Debugging aid (NIREXEC_PROBE_SSA=<index>[,<index>...]): the fragment colour output becomes the value that SSA def last
// held when the fragment finished (a function-temporary variable written right after each probed def, so a def inside
// control flow can be probed; -1 when it never ran). NIREXEC_PROBE_SSA=list prints the NIR these indices refer to.
static void probe_ssa(nir_shader *s, unsigned index) {
  nir_function_impl *impl = nir_shader_get_entrypoint(s);
  nir_def *probe = nullptr; nir_intrinsic_instr *store = nullptr;
  nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
    nir_def *d = nir_instr_def(ins);
    if (d && d->index == index) probe = d;
    if (ins->type == nir_instr_type_intrinsic && nir_instr_as_intrinsic(ins)->intrinsic == nir_intrinsic_store_deref) {
      nir_deref_instr *dr = nir_src_as_deref(nir_instr_as_intrinsic(ins)->src[0]);
      if (dr->modes & nir_var_shader_out) store = nir_instr_as_intrinsic(ins);
    }
  }
  if (!probe || !store) fail("probe: SSA value or colour store not found");
  nir_variable *var = nir_local_variable_create(impl, glsl_vec4_type(), "probe");
  nir_builder b = nir_builder_at(nir_before_impl(impl));
  nir_store_var(&b, var, nir_imm_vec4(&b, -1, -1, -1, -1), 0xf);
  nir_instr *def = nir_def_instr(probe);
  b.cursor = def->type == nir_instr_type_phi ? nir_after_phis(def->block) : nir_after_instr(def);
  nir_def *v = probe->bit_size == 16 ? f16_bits_to_f32(&b, probe) : probe->bit_size == 1 ? nir_b2f32(&b, probe)
             : probe->bit_size == 8 ? nir_u2f32(&b, probe) : probe;
  nir_def *c[4];
  for (unsigned i = 0; i < 4; i++) c[i] = nir_channel(&b, v, std::min<unsigned>(i, v->num_components - 1u));
  nir_store_var(&b, var, nir_vec(&b, c, 4), 0xf);
  b.cursor = nir_before_instr(&store->instr);
  nir_src_rewrite(&store->src[1], nir_load_var(&b, var));
}
// Debugging aid (NIREXEC_FOLD_UBO=<index>): constant-fold the fragment stage's 32-bit loads from that constant buffer
// with the scene's data for it, then fold and prune, so the uber shader collapses to the path one draw takes.
static bool fold_ubo_loads(nir_shader *s, unsigned index, const std::vector<uint8_t> &data) {
  bool progress = false;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type != nir_instr_type_intrinsic) continue;
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      if (in->intrinsic != nir_intrinsic_load_ubo || in->def.bit_size != 32) continue;
      if (!nir_src_is_const(in->src[0]) || nir_src_as_uint(in->src[0]) != index || !nir_src_is_const(in->src[1])) continue;
      uint64_t off = nir_src_as_uint(in->src[1]);
      if (off + 4 * in->def.num_components > data.size()) continue;
      b.cursor = nir_before_instr(ins);
      nir_def *c[NIR_MAX_VEC_COMPONENTS];
      for (unsigned i = 0; i < in->def.num_components; i++) {
        uint32_t w; memcpy(&w, &data[off + 4 * i], 4); c[i] = nir_imm_int(&b, (int)w);
      }
      nir_def_replace(&in->def, nir_vec(&b, c, in->def.num_components));
      progress = true;
    }
    nir_progress(progress, impl, nir_metadata_none);
  }
  return progress;
}
// ABI device-address table (UBO driver_table_ubo) -> llvmpipe constant buffer DEVICE_VA_CB.  Every
// constant buffer the function declares is below driver_table_ubo, so each load from that index
// is a table load.
static void remap_device_va_ubo(nir_shader *s, int tableUbo) {
  bool remapped = false;
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
      if (ins->type != nir_instr_type_intrinsic) continue;
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      if (in->intrinsic != nir_intrinsic_load_ubo || !nir_src_is_const(in->src[0]) || nir_src_as_uint(in->src[0]) != (unsigned)tableUbo) continue;
      b.cursor = nir_before_instr(ins);
      nir_src_rewrite(&in->src[0], nir_imm_int(&b, DEVICE_VA_CB));
      remapped = true;
    }
  }
  if (remapped || s->info.num_ubos > DEVICE_VA_CB + 1) s->info.num_ubos = DEVICE_VA_CB + 1;
}
// shader constant data (constexpr tables) -> constant buffer CONSTDATA_CB
static void lower_load_constant_to_ubo(nir_shader *s) {
  nir_foreach_function_impl(impl, s) {
    nir_builder b = nir_builder_create(impl);
    nir_foreach_block(blk, impl) nir_foreach_instr_safe(ins, blk) {
      if (ins->type != nir_instr_type_intrinsic) continue;
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      if (in->intrinsic != nir_intrinsic_load_constant) continue;
      b.cursor = nir_before_instr(ins);
      nir_def *off = nir_iadd_imm(&b, in->src[0].ssa, nir_intrinsic_base(in));
      nir_def *r = nir_load_ubo(&b, in->def.num_components, in->def.bit_size, nir_imm_int(&b, CONSTDATA_CB), off,
                                .align_mul = nir_intrinsic_align_mul(in), .align_offset = nir_intrinsic_align_offset(in),
                                .range_base = 0, .range = ~0u);
      nir_def_replace(&in->def, r);
    }
  }
  s->info.num_ubos = std::max<unsigned>(s->info.num_ubos, CONSTDATA_CB + 1);
}

// gallium derives the bound texture/sampler ranges from shader_info (set by the GL/VK front ends
// from variables); our NIR uses bare texture_index/sampler_index, so record them here.
static void mark_textures_used(nir_shader *s) {
  nir_foreach_function_impl(impl, s) nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
    if (ins->type != nir_instr_type_tex) continue;
    nir_tex_instr *t = nir_instr_as_tex(ins);
    BITSET_SET(s->info.textures_used, t->texture_index);
    if (t->op != nir_texop_txf && t->op != nir_texop_txs && t->op != nir_texop_query_levels)
      BITSET_SET(s->info.samplers_used, t->sampler_index);
    s->info.num_textures = std::max<unsigned>(s->info.num_textures, t->texture_index + 1);
  }
}

static pipe_format fmtOf(const std::string &f) {
  if (f == "bgra8") return PIPE_FORMAT_B8G8R8A8_UNORM;
  if (f == "bgr10_xr") return PIPE_FORMAT_B10G10R10A2_UNORM;      // UNORM view of MTLPixelFormatBGR10_XR
  if (f == "bgra10_xr") return PIPE_FORMAT_R16G16B16A16_UNORM;    // UNORM view of MTLPixelFormatBGRA10_XR (words swapped)
  if (f == "rgba32f") return PIPE_FORMAT_R32G32B32A32_FLOAT;
  if (f == "rgba8") return PIPE_FORMAT_R8G8B8A8_UNORM;
  if (f == "r8") return PIPE_FORMAT_R8_UNORM;
  if (f == "rg8") return PIPE_FORMAT_R8G8_UNORM;
  if (f == "rgba16f") return PIPE_FORMAT_R16G16B16A16_FLOAT;
  if (f == "float") return PIPE_FORMAT_R32_FLOAT;
  if (f == "float2") return PIPE_FORMAT_R32G32_FLOAT;
  if (f == "float3") return PIPE_FORMAT_R32G32B32_FLOAT;
  if (f == "float4") return PIPE_FORMAT_R32G32B32A32_FLOAT;
  if (f == "uchar4n") return PIPE_FORMAT_R8G8B8A8_UNORM;
  fail("format " + f);
}
static unsigned wrapOf(unsigned air) {
  switch (air) { case 0: return PIPE_TEX_WRAP_CLAMP_TO_BORDER; case 1: return PIPE_TEX_WRAP_CLAMP_TO_EDGE;
  case 2: return PIPE_TEX_WRAP_REPEAT; case 3: return PIPE_TEX_WRAP_MIRROR_REPEAT; default: return PIPE_TEX_WRAP_CLAMP_TO_EDGE; }
}
static unsigned wrapName(const std::string &s) {
  if (s == "repeat") return PIPE_TEX_WRAP_REPEAT; if (s == "clamp_to_zero") return PIPE_TEX_WRAP_CLAMP_TO_BORDER;
  if (s == "mirrored_repeat") return PIPE_TEX_WRAP_MIRROR_REPEAT; return PIPE_TEX_WRAP_CLAMP_TO_EDGE;
}

// MTLBlendFactor / MTLBlendOperation -> gallium
static unsigned pipeFactor(unsigned f) {
  static const unsigned m[] = {PIPE_BLENDFACTOR_ZERO, PIPE_BLENDFACTOR_ONE, PIPE_BLENDFACTOR_SRC_COLOR, PIPE_BLENDFACTOR_INV_SRC_COLOR,
    PIPE_BLENDFACTOR_SRC_ALPHA, PIPE_BLENDFACTOR_INV_SRC_ALPHA, PIPE_BLENDFACTOR_DST_COLOR, PIPE_BLENDFACTOR_INV_DST_COLOR,
    PIPE_BLENDFACTOR_DST_ALPHA, PIPE_BLENDFACTOR_INV_DST_ALPHA, PIPE_BLENDFACTOR_SRC_ALPHA_SATURATE, PIPE_BLENDFACTOR_CONST_COLOR,
    PIPE_BLENDFACTOR_INV_CONST_COLOR, PIPE_BLENDFACTOR_CONST_ALPHA, PIPE_BLENDFACTOR_INV_CONST_ALPHA, PIPE_BLENDFACTOR_SRC1_COLOR,
    PIPE_BLENDFACTOR_INV_SRC1_COLOR, PIPE_BLENDFACTOR_SRC1_ALPHA, PIPE_BLENDFACTOR_INV_SRC1_ALPHA};
  if (f >= sizeof m / sizeof m[0]) fail("blend factor");
  return m[f];
}
static unsigned pipeOp(unsigned o) {
  static const unsigned m[] = {PIPE_BLEND_ADD, PIPE_BLEND_SUBTRACT, PIPE_BLEND_REVERSE_SUBTRACT, PIPE_BLEND_MIN, PIPE_BLEND_MAX};
  if (o > 4) fail("blend op");
  return m[o];
}
static AirBlend blendOf(const json::Object *S) {
  AirBlend b;
  if (S->getBoolean("blend_premul_over").value_or(false)) { b.enabled = true; b.srcRGB = b.srcA = 1; b.dstRGB = b.dstA = 5; }
  if (auto *o = S->getObject("blend")) {
    b.enabled = o->getInteger("enabled").value_or(0) != 0;
    b.rgbOp = (uint8_t)o->getInteger("rgb_op").value_or(0); b.alphaOp = (uint8_t)o->getInteger("alpha_op").value_or(0);
    b.srcRGB = (uint8_t)o->getInteger("src_rgb").value_or(1); b.dstRGB = (uint8_t)o->getInteger("dst_rgb").value_or(0);
    b.srcA = (uint8_t)o->getInteger("src_alpha").value_or(1); b.dstA = (uint8_t)o->getInteger("dst_alpha").value_or(0);
  }
  return b;
}
static unsigned classOf(const std::string &f) { return f == "bgr10_xr" ? 1 : f == "bgra10_xr" ? 2 : 0; }
// Metal's BGRA10_XR stores 16-bit words B,G,R,A; the R16G16B16A16 view holds R,G,B,A (the Adreno RB
// swap does this in hardware).
static void swap_bgra16(std::vector<uint8_t> &d) {
  for (size_t i = 0; i + 8 <= d.size(); i += 8) { std::swap(d[i], d[i + 4]); std::swap(d[i + 1], d[i + 5]); }
}

struct Stage {
  AirFrontendResult R;
  void *cso = nullptr;
};

static AirOptions optsOf(const json::Object *st, const json::Object *S = nullptr) {
  AirOptions o;
  if (S) {   // fragment: attachment class + blend, and the draw-time class of every bound texture
    std::string rf = S->getObject("rt") && S->getObject("rt")->getString("format") ? S->getObject("rt")->getString("format")->str() : "bgra8";
    o.rtClass[0] = (uint8_t)classOf(rf);
    o.blend[0] = blendOf(S);
    if (auto *ts = S->getArray("textures"))
      for (auto &t : *ts) { const json::Object *to = t.getAsObject(); o.texClass[*to->getInteger("index")] = (uint8_t)classOf(to->getString("format")->str()); }
  }
  if (auto *fc = st->getObject("fc"))
    for (auto &kv : *fc) {
      std::vector<double> v;
      // a number, or (cache format 5 sidecar values, verify6's harness) a string such as "nan", "-inf", "-0.0"
      auto num = [](const json::Value &x) -> double {
        if (auto n = x.getAsNumber()) return *n;
        if (auto s = x.getAsString()) return strtod(s->str().c_str(), nullptr);
        if (auto b = x.getAsBoolean()) return *b ? 1 : 0;
        fail("function-constant value is neither a number nor a string");
      };
      if (auto *a = kv.second.getAsArray()) for (auto &x : *a) v.push_back(num(x));
      else v.push_back(num(kv.second));
      o.fc[atoi(kv.first.str().c_str())] = v;
    }
  if (auto e = st->getString("entry")) o.entry = e->str();
  return o;
}

int main(int argc, char **argv) {
  glsl_type_singleton_init_or_ref();   // held for the process: air_frontend takes and drops its own reference
  if (argc < 3) { fprintf(stderr, "usage: nirexec scene.json out.rgba [--frames N] [--dump-nir]\n"); return 1; }
  const char *scenePath = argv[1], *outPath = argv[2];
  int frames = 3; bool dump = false;
  const char *spvVs = nullptr, *spvFs = nullptr;
  for (int i = 3; i < argc; i++) {
    if (!strcmp(argv[i], "--frames")) frames = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--spv-vs")) spvVs = argv[++i];
    else if (!strcmp(argv[i], "--spv-fs")) spvFs = argv[++i];
    else if (!strcmp(argv[i], "--dump-nir")) dump = true;
  }
  { std::string sp = scenePath; size_t k = sp.rfind("/scenes/"); ROOT = k == std::string::npos ? "." : sp.substr(0, k); }
  auto sb = MemoryBuffer::getFile(scenePath);
  if (!sb) fail("cannot read scene");
  Expected<json::Value> J = json::parse((*sb)->getBuffer());
  if (!J) fail("scene json: " + toString(J.takeError()));
  const json::Object *S = J->getAsObject();
  unsigned W = (unsigned)*S->getInteger("width"), H = (unsigned)*S->getInteger("height");

  struct pipe_screen *screen = llvmpipe_create_screen(null_sw_create());
  if (!screen) fail("llvmpipe_create_screen failed");
  struct pipe_context *ctx = screen->context_create(screen, nullptr, 0);

  // ---- shaders ----
  Stage vs, fs;
  try {
    vs.R = air_frontend(rel(S->getObject("vs")->getString("bc")->str()).c_str(), optsOf(S->getObject("vs")), screen->nir_options[MESA_SHADER_VERTEX]);
  } catch (const AirError &e) { fail(std::string("front end (vertex): ") + e.what()); }
  AirOptions fsOpts = optsOf(S->getObject("fs"), S);
  try {
    fs.R = air_frontend(rel(S->getObject("fs")->getString("bc")->str()).c_str(), fsOpts, screen->nir_options[MESA_SHADER_FRAGMENT]);
  } catch (const AirError &e) { fail(std::string("front end: ") + e.what()); }
  if (vs.R.stage != MESA_SHADER_VERTEX || fs.R.stage != MESA_SHADER_FRAGMENT) fail("scene needs a vertex and a fragment function");
  nir_shader *vn = vs.R.nir, *fn = fs.R.nir;
  std::string spvErr;
  if (spvVs && !(vn = spv_frontend(spvVs, MESA_SHADER_VERTEX, screen->nir_options[MESA_SHADER_VERTEX], &spvErr))) fail(spvErr);
  if (spvFs && !(fn = spv_frontend(spvFs, MESA_SHADER_FRAGMENT, screen->nir_options[MESA_SHADER_FRAGMENT], &spvErr))) fail(spvErr);

  // VS inputs: driver_location = index in attribute-location order (= vertex element order)
  std::vector<nir_variable *> vins;
  nir_foreach_shader_in_variable(v, vn) vins.push_back(v);
  std::sort(vins.begin(), vins.end(), [](nir_variable *a, nir_variable *b) { return a->data.location < b->data.location; });
  for (unsigned i = 0; i < vins.size(); i++) vins[i]->data.driver_location = i;
  vn->num_inputs = vins.size();
  // Link varyings by name: FS input location := VS output location of the same name.
  std::map<std::string, int> vsSlot;
  for (auto &v : vs.R.varyings) vsSlot[v.name] = v.slot;
  nir_foreach_shader_in_variable(v, fn) {
    if (v->data.location < VARYING_SLOT_VAR0 || spvFs) continue;   // reference GLSL carries the AIR slots as locations
    auto it = vsSlot.find(v->name ? v->name : "");
    if (it == vsSlot.end()) fail(std::string("fragment input ") + (v->name ? v->name : "?") + " has no vertex output of that name");
    v->data.location = VARYING_SLOT_VAR0 + it->second;
  }
  lower_frag_coord_to_var(fn);
  bool vsConst = vn->constant_data_size, fsConst = fn->constant_data_size;
  // reference SPIR-V shaders keep the pre-v6 convention (their GLSL never uses the table)
  remap_device_va_ubo(vn, spvVs ? 31 : vs.R.driver_table_ubo); remap_device_va_ubo(fn, spvFs ? 31 : fs.R.driver_table_ubo);
  if (vsConst) lower_load_constant_to_ubo(vn);
  if (fsConst) lower_load_constant_to_ubo(fn);
  for (nir_shader *n : {vn, fn}) {
    if (n != vn) nir_assign_io_var_locations(n, nir_var_shader_in);
    nir_assign_io_var_locations(n, nir_var_shader_out);
    nir_shader_gather_info(n, nir_shader_get_entrypoint(n));
    mark_textures_used(n);
    {
      nir_lower_mem_access_bit_sizes_options mo = {};
      mo.callback = mem_access_32; mo.modes = nir_var_mem_ubo | nir_var_mem_global | nir_var_mem_constant;
      NIR_PASS(_, n, nir_lower_mem_access_bit_sizes, &mo);
    }
    if (n == fn && getenv("NIREXEC_FOLD_UBO")) {                    // debugging: specialise to one draw's config
      unsigned idx = (unsigned)atoi(getenv("NIREXEC_FOLD_UBO"));
      if (auto *bs = S->getObject("buffers") ? S->getObject("buffers")->getArray("fragment") : nullptr)
        for (auto &bb : *bs) {
          const json::Object *bo = bb.getAsObject();
          if ((unsigned)*bo->getInteger("index") != idx) continue;
          std::vector<uint8_t> data = bytesOf(bo);
          NIR_PASS(_, n, fold_ubo_loads, idx, data);
          bool more = true;
          while (more) {
            more = false;
            NIR_PASS(more, n, nir_opt_constant_folding); NIR_PASS(more, n, nir_opt_algebraic);
            NIR_PASS(more, n, nir_opt_copy_prop); NIR_PASS(more, n, nir_opt_dead_cf); NIR_PASS(more, n, nir_opt_dce);
            NIR_PASS(more, n, nir_opt_if, nir_opt_if_optimize_phi_true_false); NIR_PASS(more, n, nir_opt_cse);
            NIR_PASS(more, n, nir_opt_remove_phis);
          }
        }
    }
    NIR_PASS(_, n, widen_io16, n == vn ? nir_var_shader_out : nir_var_shader_in);
    NIR_PASS(_, n, widen_tex16);
    NIR_PASS(_, n, widen_derivatives16);
    NIR_PASS(_, n, nir_lower_bit_size, lower16, nullptr);
    NIR_PASS(_, n, lower_f16_conversions);
    NIR_PASS(_, n, nir_opt_dce);
    if (n == fn && getenv("NIREXEC_PROBE_SSA")) {
      nir_index_ssa_defs(nir_shader_get_entrypoint(n));
      if (!strcmp(getenv("NIREXEC_PROBE_SSA"), "list")) nir_print_shader(n, stderr);
      else { probe_ssa(n, (unsigned)atoi(getenv("NIREXEC_PROBE_SSA"))); NIR_PASS(_, n, nir_lower_vars_to_ssa); }
    }
    if (screen->finalize_nir) screen->finalize_nir(screen, n, true);
    nir_validate_shader(n, "nirexec before create");
    if (dump) nir_print_shader(n, stderr);
  }
  struct pipe_shader_state ss = {};
  ss.type = PIPE_SHADER_IR_NIR; ss.ir.nir = vn; vs.cso = ctx->create_vs_state(ctx, &ss);
  ss.ir.nir = fn; fs.cso = ctx->create_fs_state(ctx, &ss);
  ctx->bind_vs_state(ctx, vs.cso); ctx->bind_fs_state(ctx, fs.cso);

  // ---- vertex input ----
  const json::Object *V = S->getObject("vertex");
  std::vector<uint8_t> vdata = bytesOf(V->getObject("data"));
  unsigned stride = (unsigned)*V->getInteger("stride");
  std::vector<pipe_vertex_element> ve;
  for (nir_variable *v : vins) {
    int loc = v->data.location - VERT_ATTRIB_GENERIC0; bool found = false;
    for (auto &a : *V->getArray("attributes")) {
      const json::Object *ao = a.getAsObject();
      if (*ao->getInteger("index") != loc) continue;
      pipe_vertex_element e = {};
      e.src_offset = (uint16_t)*ao->getInteger("offset"); e.vertex_buffer_index = 0;
      e.src_format = fmtOf(ao->getString("format")->str()); e.src_stride = stride; found = true;
      ve.push_back(e);
    }
    if (!found) fail("attribute " + std::to_string(loc) + " missing from scene");
  }
  void *vecso = ctx->create_vertex_elements_state(ctx, ve.size(), ve.data());
  if (!ve.empty()) {
    ctx->bind_vertex_elements_state(ctx, vecso);
    pipe_vertex_buffer vb = {}; vb.is_user_buffer = true; vb.buffer.user = vdata.data(); vb.buffer_offset = 0;
    ctx->set_vertex_buffers(ctx, 1, &vb);
  } else {
    ctx->bind_vertex_elements_state(ctx, vecso);
  }

  // ---- buffers (constant + device) ----
  std::vector<std::vector<uint8_t>> keep;
  auto setCB = [&](mesa_shader_stage st, unsigned idx, const std::vector<uint8_t> &d) {
    if (idx >= 16) fail("constant buffer index " + std::to_string(idx) + " beyond llvmpipe's 16 slots");
    pipe_constant_buffer cb = {};
    cb.buffer = pipe_buffer_create_with_data(ctx, PIPE_BIND_CONSTANT_BUFFER, PIPE_USAGE_DEFAULT, d.size(), d.data());
    cb.buffer_size = d.size();
    ctx->set_constant_buffer(ctx, st, idx, &cb);
  };
  for (auto [key, stage] : {std::pair{"vertex", MESA_SHADER_VERTEX}, {"fragment", MESA_SHADER_FRAGMENT}}) {
    uint64_t vaTable[31] = {0};
    bool anyDev = false;
    if (auto *bs = S->getObject("buffers") ? S->getObject("buffers")->getArray(key) : nullptr)
      for (auto &b : *bs) {
        const json::Object *bo = b.getAsObject();
        keep.push_back(bytesOf(bo));
        int idx = (int)*bo->getInteger("index");
        bool device = bo->getBoolean("device").value_or(false);
        if (device) { vaTable[idx] = (uint64_t)(uintptr_t)keep.back().data(); anyDev = true; continue; }
        setCB(stage, idx, keep.back());
      }
    if (anyDev) {
      keep.push_back(std::vector<uint8_t>((uint8_t *)vaTable, (uint8_t *)vaTable + sizeof vaTable));
      setCB(stage, DEVICE_VA_CB, keep.back());
    }
    nir_shader *n = stage == MESA_SHADER_VERTEX ? vn : fn;
    if (n->constant_data_size) {
      keep.push_back(std::vector<uint8_t>((uint8_t *)n->constant_data, (uint8_t *)n->constant_data + n->constant_data_size));
      while (keep.back().size() % 16) keep.back().push_back(0);
      setCB(stage, CONSTDATA_CB, keep.back());
    }
  }

  // ---- textures + samplers (fragment stage) ----
  std::vector<pipe_sampler_view *> views(16, nullptr);
  unsigned nviews = 0;
  if (auto *ts = S->getArray("textures"))
    for (auto &t : *ts) {
      const json::Object *to = t.getAsObject();
      pipe_resource tmpl = {};
      bool is3d = to->getString("type") && to->getString("type")->str() == "3d";
      tmpl.target = is3d ? PIPE_TEXTURE_3D : PIPE_TEXTURE_2D; tmpl.format = fmtOf(to->getString("format")->str());
      tmpl.width0 = (unsigned)*to->getInteger("width"); tmpl.height0 = (uint16_t)*to->getInteger("height");
      tmpl.depth0 = is3d ? (unsigned)to->getInteger("depth").value_or(1) : 1; tmpl.array_size = 1; tmpl.bind = PIPE_BIND_SAMPLER_VIEW;
      pipe_resource *res = screen->resource_create(screen, &tmpl);
      auto data = readFile(to->getString("file")->str());
      if (to->getString("format")->str() == "bgra10_xr") swap_bgra16(data);
      pipe_box box = {}; box.width = tmpl.width0; box.height = tmpl.height0; box.depth = tmpl.depth0;
      unsigned bpp = util_format_get_blocksize(tmpl.format);
      if (data.size() < (size_t)tmpl.width0 * tmpl.height0 * tmpl.depth0 * bpp) fail("texture file too small");
      ctx->texture_subdata(ctx, res, 0, PIPE_MAP_WRITE, &box, data.data(), tmpl.width0 * bpp, tmpl.width0 * tmpl.height0 * bpp);
      pipe_sampler_view vt = {}; vt.format = tmpl.format; vt.target = tmpl.target; vt.texture = res;
      vt.swizzle_r = PIPE_SWIZZLE_X; vt.swizzle_g = PIPE_SWIZZLE_Y; vt.swizzle_b = PIPE_SWIZZLE_Z; vt.swizzle_a = PIPE_SWIZZLE_W;
      vt.u.tex.last_level = 0; vt.u.tex.last_layer = 0;
      int idx = (int)*to->getInteger("index");
      views[idx] = ctx->create_sampler_view(ctx, res, &vt);
      nviews = std::max<unsigned>(nviews, idx + 1);
    }
  ctx->set_sampler_views(ctx, MESA_SHADER_FRAGMENT, 0, nviews, 0, views.data());
  std::vector<void *> samplers(16, nullptr);
  auto mkSampler = [&](pipe_sampler_state st) { return ctx->create_sampler_state(ctx, &st); };
  unsigned nsamp = 0;
  if (auto *ss2 = S->getArray("samplers"))
    for (auto &s2 : *ss2) {
      const json::Object *so = s2.getAsObject();
      pipe_sampler_state st = {};
      st.wrap_s = st.wrap_t = st.wrap_r = wrapName(so->getString("address") ? so->getString("address")->str() : "clamp_to_edge");
      if (auto a = so->getString("address_s")) st.wrap_s = wrapName(a->str());
      if (auto a = so->getString("address_t")) st.wrap_t = wrapName(a->str());
      if (auto a = so->getString("address_r")) st.wrap_r = wrapName(a->str());
      bool lin = so->getString("filter") && so->getString("filter")->str() == "linear";
      st.min_img_filter = st.mag_img_filter = lin ? PIPE_TEX_FILTER_LINEAR : PIPE_TEX_FILTER_NEAREST;
      if (auto f = so->getString("min_filter")) st.min_img_filter = f->str() == "linear" ? PIPE_TEX_FILTER_LINEAR : PIPE_TEX_FILTER_NEAREST;
      if (auto f = so->getString("mag_filter")) st.mag_img_filter = f->str() == "linear" ? PIPE_TEX_FILTER_LINEAR : PIPE_TEX_FILTER_NEAREST;
      st.min_mip_filter = PIPE_TEX_MIPFILTER_NONE; st.max_lod = 0; st.seamless_cube_map = 0;
      int idx = (int)*so->getInteger("index");
      samplers[idx] = mkSampler(st); nsamp = std::max<unsigned>(nsamp, idx + 1);
    }
  for (auto &b : fs.R.bindings) if (b.kind == "constexpr_sampler") {   // BINDING-ABI.md 3.5
    air_sampler as; air_sampler_decode(b.sampler_word, &as);
    pipe_sampler_state st = {};
    st.wrap_s = wrapOf(as.s_address); st.wrap_t = wrapOf(as.t_address); st.wrap_r = wrapOf(as.r_address);
    st.min_img_filter = as.min_linear ? PIPE_TEX_FILTER_LINEAR : PIPE_TEX_FILTER_NEAREST;
    st.mag_img_filter = as.mag_linear ? PIPE_TEX_FILTER_LINEAR : PIPE_TEX_FILTER_NEAREST;
    st.min_mip_filter = as.mip_filter == 0 ? PIPE_TEX_MIPFILTER_NONE : as.mip_filter == 1 ? PIPE_TEX_MIPFILTER_NEAREST : PIPE_TEX_MIPFILTER_LINEAR;
    st.unnormalized_coords = as.pixel_coords;
    st.min_lod = as.lod_min; st.max_lod = as.pixel_coords ? 0 : std::min(as.lod_max, 16.0f);
    float bc[4] = {0, 0, 0, as.border == 0 ? 0.0f : 1.0f};
    if (as.border == 2) bc[0] = bc[1] = bc[2] = 1;
    memcpy(st.border_color.f, bc, sizeof bc);
    samplers[b.slot] = mkSampler(st); nsamp = std::max<unsigned>(nsamp, b.slot + 1);
  }
  // Any hole gets a default sampler (the ABI requires every S# up to the highest used to be valid).
  for (unsigned i = 0; i < nsamp; i++) if (!samplers[i]) { pipe_sampler_state st = {}; st.wrap_s = st.wrap_t = st.wrap_r = PIPE_TEX_WRAP_CLAMP_TO_EDGE; samplers[i] = mkSampler(st); }
  if (nsamp) ctx->bind_sampler_states(ctx, MESA_SHADER_FRAGMENT, 0, nsamp, samplers.data());

  // ---- fixed-function state (Metal defaults) ----
  pipe_rasterizer_state rs = {};
  rs.half_pixel_center = 1; rs.bottom_edge_rule = 0; rs.clip_halfz = 1; rs.depth_clip_near = rs.depth_clip_far = 1;
  rs.point_quad_rasterization = 1; rs.point_size_per_vertex = 1; rs.point_size = 1;   // Metal points are sprites
  rs.sprite_coord_mode = PIPE_SPRITE_COORD_UPPER_LEFT;
  rs.cull_face = PIPE_FACE_NONE; rs.flatshade_first = 1; rs.front_ccw = 0;
  ctx->bind_rasterizer_state(ctx, ctx->create_rasterizer_state(ctx, &rs));
  pipe_blend_state bl = {}; bl.rt[0].colormask = PIPE_MASK_RGBA;
  AirBlend hb = fsOpts.blend[0];
  for (auto &l : fs.R.rt_lowering) if (l.index == 0) {     // BINDING-ABI.md 4.5: program the compiler's hw_blend
    hb = l.hw;
    if (l.clear_alpha_write) bl.rt[0].colormask = PIPE_MASK_RGB;
  }
  // Metal ignores the blend factors of a min / max channel; gallium llvmpipe multiplies by them.
  // Program ONE/ONE there so the harness renders what Metal does for every blend state (verify3
  // item 2: 10 of 48 random XR scenes with min/max and non-ONE factors failed only because of this).
  if (hb.rgbOp == 3 || hb.rgbOp == 4) hb.srcRGB = hb.dstRGB = 1;
  if (hb.alphaOp == 3 || hb.alphaOp == 4) hb.srcA = hb.dstA = 1;
  if (hb.enabled) {
    bl.rt[0].blend_enable = 1;
    bl.rt[0].rgb_func = pipeOp(hb.rgbOp); bl.rt[0].alpha_func = pipeOp(hb.alphaOp);
    bl.rt[0].rgb_src_factor = pipeFactor(hb.srcRGB); bl.rt[0].rgb_dst_factor = pipeFactor(hb.dstRGB);
    bl.rt[0].alpha_src_factor = pipeFactor(hb.srcA); bl.rt[0].alpha_dst_factor = pipeFactor(hb.dstA);
  }
  ctx->bind_blend_state(ctx, ctx->create_blend_state(ctx, &bl));
  pipe_depth_stencil_alpha_state dsa = {};
  ctx->bind_depth_stencil_alpha_state(ctx, ctx->create_depth_stencil_alpha_state(ctx, &dsa));
  pipe_viewport_state vp = {};
  vp.scale[0] = W / 2.0f; vp.scale[1] = -(float)H / 2.0f; vp.scale[2] = 1;          // NDC +y is up; row 0 is the top
  vp.translate[0] = W / 2.0f; vp.translate[1] = H / 2.0f; vp.translate[2] = 0;
  if (auto *v = S->getObject("viewport")) {                                       // an MTLViewport in pixels
    double x = *v->getNumber("x"), y = *v->getNumber("y"), w = *v->getNumber("w"), h = *v->getNumber("h");
    vp.scale[0] = (float)(w / 2); vp.translate[0] = (float)(x + w / 2);
    vp.scale[1] = (float)(-h / 2); vp.translate[1] = (float)(y + h / 2);
  }
  vp.swizzle_x = PIPE_VIEWPORT_SWIZZLE_POSITIVE_X; vp.swizzle_y = PIPE_VIEWPORT_SWIZZLE_POSITIVE_Y;
  vp.swizzle_z = PIPE_VIEWPORT_SWIZZLE_POSITIVE_Z; vp.swizzle_w = PIPE_VIEWPORT_SWIZZLE_POSITIVE_W;
  ctx->set_viewport_states(ctx, 0, 1, &vp);

  std::string rtFmt = S->getObject("rt") && S->getObject("rt")->getString("format") ? S->getObject("rt")->getString("format")->str() : "bgra8";
  std::vector<uint8_t> rtInit;
  if (S->getObject("rt") && S->getObject("rt")->getString("init_file")) {
    rtInit = readFile(S->getObject("rt")->getString("init_file")->str());
    if (rtFmt == "bgra10_xr") swap_bgra16(rtInit);
  }
  pipe_resource rt = {};
  rt.target = PIPE_TEXTURE_2D; rt.format = fmtOf(rtFmt); rt.width0 = W; rt.height0 = H;
  rt.depth0 = 1; rt.array_size = 1; rt.bind = PIPE_BIND_RENDER_TARGET | PIPE_BIND_SAMPLER_VIEW;
  pipe_resource *rtres = screen->resource_create(screen, &rt);
  pipe_framebuffer_state fb = {};
  fb.width = W; fb.height = H; fb.nr_cbufs = 1; fb.layers = 1; fb.samples = 1;
  fb.cbufs[0].format = rt.format; fb.cbufs[0].texture = rtres; fb.cbufs[0].level = 0;
  ctx->set_framebuffer_state(ctx, &fb);

  const json::Array *clr = S->getArray("clear");
  union pipe_color_union cc = {};
  for (unsigned i = 0; i < 4; i++) cc.f[i] = clr ? (float)*(*clr)[i].getAsNumber() : 0.0f;
  if (unsigned cls = classOf(rtFmt))      // a clear of an XR attachment is programmed in the view's u-domain
    for (unsigned i = 0; i < 4; i++) {
      double n = std::min(1023.0, std::max(0.0, std::nearbyint(cc.f[i] * 510.0 + 384.0)));
      cc.f[i] = cls == 1 ? (i == 3 ? 1.0f : (float)(n / 1023.0)) : (float)(n * 64.0 / 65535.0);
    }
  pipe_draw_info di = {};
  di.mode = MESA_PRIM_TRIANGLES; di.instance_count = 1;
  if (auto p = V->getString("primitive")) {
    if (p->str() == "triangle_strip") di.mode = MESA_PRIM_TRIANGLE_STRIP;
    if (p->str() == "point") di.mode = MESA_PRIM_POINTS;
  }
  pipe_draw_start_count_bias dr = {}; dr.start = 0; dr.count = (unsigned)*V->getInteger("count");
  std::vector<uint8_t> indices;                   // "indices": {"file": u16 data} -> an indexed draw (vertex_id = index)
  if (auto *ix = V->getObject("indices")) {
    indices = bytesOf(ix);
    if (indices.size() < (size_t)dr.count * 2) fail("index file too small");
    di.index_size = 2; di.has_user_indices = 1; di.index.user = indices.data();
  }

  unsigned rbpp = util_format_get_blocksize(rt.format);
  std::vector<uint8_t> pix(W * H * rbpp);
  for (int f = 0; f < frames; f++) {               // frame >= 2 is the one compared (steady state)
    if (!rtInit.empty()) {                          // Metal loadAction .load of these contents
      if (rtInit.size() < pix.size()) fail("rt init_file too small");
      pipe_box ib = {}; ib.width = W; ib.height = H; ib.depth = 1;
      ctx->texture_subdata(ctx, rtres, 0, PIPE_MAP_WRITE, &ib, rtInit.data(), W * rbpp, W * H * rbpp);
    } else
    ctx->clear(ctx, PIPE_CLEAR_COLOR0, 0xf, 0, nullptr, &cc, 0, 0);
    ctx->draw_vbo(ctx, &di, 0, nullptr, &dr, 1);
    struct pipe_fence_handle *fence = nullptr;
    ctx->flush(ctx, &fence, 0);
    screen->fence_finish(screen, ctx, fence, OS_TIMEOUT_INFINITE);
    screen->fence_reference(screen, &fence, nullptr);
    pipe_box box = {}; box.width = W; box.height = H; box.depth = 1;
    pipe_transfer *tr = nullptr;
    uint8_t *m = (uint8_t *)ctx->texture_map(ctx, rtres, 0, PIPE_MAP_READ, &box, &tr);
    for (unsigned y = 0; y < H; y++) memcpy(&pix[y * W * rbpp], m + y * tr->stride, W * rbpp);
    ctx->texture_unmap(ctx, tr);
  }
  if (rtFmt == "bgra10_xr") swap_bgra16(pix);
  FILE *o = fopen(outPath, "wb"); if (!o) fail("cannot write output");
  fwrite(pix.data(), 1, pix.size(), o); fclose(o);
  printf("nirexec: %s %ux%u %s, %d frames, VS %s%s FS %s%s\n", outPath, W, H, rtFmt.c_str(), frames, vs.R.function.c_str(), spvVs ? " (SPIR-V NIR)" : "",
         fs.R.function.c_str(), spvFs ? " (SPIR-V NIR)" : "");
  return 0;
}
