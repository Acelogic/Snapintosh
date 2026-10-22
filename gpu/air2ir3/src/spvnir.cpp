/* SPDX-License-Identifier: MIT */
// spvnir.cpp - see spvnir.h.
#include "spvnir.h"

#include <cstdio>
#include <vector>

#include "nir.h"
#include "nir_builder.h"
#include "glsl_types.h"
#include "spirv/nir_spirv.h"

// vulkan_resource_index(set, binding) -> vec2(binding + array_index, 0); load_vulkan_descriptor -> its
// source.  With nir_address_format_32bit_index_offset nir_lower_explicit_io then emits
// load_ubo(binding, offset), the form the AIR front end produces for Metal constant buffers.
static bool lower_vk_resources(nir_builder *b, nir_intrinsic_instr *in, void *) {
  if (in->intrinsic == nir_intrinsic_vulkan_resource_index) {
    b->cursor = nir_before_instr(&in->instr);
    nir_def *idx = nir_iadd_imm(b, in->src[0].ssa, nir_intrinsic_binding(in));
    nir_def_replace(&in->def, nir_vec2(b, idx, nir_imm_int(b, 0)));
    return true;
  }
  if (in->intrinsic == nir_intrinsic_load_vulkan_descriptor) {
    nir_def_replace(&in->def, in->src[0].ssa);
    return true;
  }
  return false;
}

// texture/sampler derefs -> texture_index / sampler_index = binding.
static bool lower_tex_derefs(nir_builder *b, nir_instr *ins, void *) {
  if (ins->type != nir_instr_type_tex) return false;
  nir_tex_instr *t = nir_instr_as_tex(ins);
  bool p = false;
  for (nir_tex_src_type ty : {nir_tex_src_texture_deref, nir_tex_src_sampler_deref}) {
    int i = nir_tex_instr_src_index(t, ty);
    if (i < 0) continue;
    nir_deref_instr *d = nir_src_as_deref(t->src[i].src);
    nir_variable *v = nir_deref_instr_get_variable(d);
    if (!v) { fprintf(stderr, "spvnir: indirect texture/sampler deref not supported\n"); exit(3); }
    if (ty == nir_tex_src_texture_deref) t->texture_index = v->data.binding;
    else t->sampler_index = v->data.binding;
    nir_tex_instr_remove_src(t, i);
    p = true;
  }
  if (p && nir_tex_instr_src_index(t, nir_tex_src_sampler_deref) < 0 &&
      (t->op == nir_texop_txf || t->op == nir_texop_txs)) t->sampler_index = 0;
  return p;
}

nir_shader *spv_frontend(const char *path, mesa_shader_stage stage, const nir_shader_compiler_options *nopts,
                         std::string *err) {
  FILE *f = fopen(path, "rb");
  if (!f) { *err = std::string("cannot read ") + path; return nullptr; }
  std::vector<uint32_t> w;
  uint32_t x;
  while (fread(&x, 4, 1, f) == 1) w.push_back(x);
  fclose(f);
  if (w.size() < 5 || w[0] != 0x07230203) { *err = std::string(path) + " is not SPIR-V"; return nullptr; }
  glsl_type_singleton_init_or_ref();

  spirv_to_nir_options so = {};
  so.environment = NIR_SPIRV_VULKAN;
  so.ubo_addr_format = nir_address_format_32bit_index_offset;
  so.ssbo_addr_format = nir_address_format_32bit_index_offset;
  so.phys_ssbo_addr_format = nir_address_format_64bit_global;
  so.push_const_addr_format = nir_address_format_32bit_offset;
  so.shared_addr_format = nir_address_format_32bit_offset;
  so.global_addr_format = nir_address_format_64bit_global;
  so.temp_addr_format = nir_address_format_32bit_offset;
  so.constant_addr_format = nir_address_format_32bit_offset;
  so.min_ubo_alignment = 16;
  so.min_ssbo_alignment = 16;
  so.skip_os_break_in_debug_build = true;
  nir_shader *s = spirv_to_nir(w.data(), w.size(), nullptr, stage, "main", &so, nopts);
  if (!s) { *err = "spirv_to_nir failed"; return nullptr; }

  // Same early pipeline as Mesa's vk_spirv_to_nir (src/vulkan/runtime/vk_nir.c).
  NIR_PASS(_, s, nir_lower_variable_initializers, nir_var_function_temp);
  NIR_PASS(_, s, nir_lower_returns);
  NIR_PASS(_, s, nir_inline_functions);
  NIR_PASS(_, s, nir_opt_copy_prop);
  NIR_PASS(_, s, nir_opt_constant_folding);
  NIR_PASS(_, s, nir_opt_deref);
  nir_remove_non_cmat_call_entrypoints(s);
  NIR_PASS(_, s, nir_lower_variable_initializers, (nir_variable_mode)~0);
  NIR_PASS(_, s, nir_split_var_copies);
  NIR_PASS(_, s, nir_split_per_member_structs);
  NIR_PASS(_, s, nir_remove_dead_variables, (nir_variable_mode)(nir_var_shader_in | nir_var_shader_out | nir_var_system_value), nullptr);
  NIR_PASS(_, s, nir_lower_var_copies);
  NIR_PASS(_, s, nir_lower_vars_to_ssa);
  NIR_PASS(_, s, nir_lower_system_values);

  // Resources -> the AIR front end's binding form.
  NIR_PASS(_, s, nir_shader_intrinsics_pass, lower_vk_resources, nir_metadata_control_flow, nullptr);
  NIR_PASS(_, s, nir_lower_explicit_io, nir_var_mem_ubo, nir_address_format_32bit_index_offset);
  NIR_PASS(_, s, nir_shader_instructions_pass, lower_tex_derefs, nir_metadata_control_flow, nullptr);
  NIR_PASS(_, s, nir_opt_dce);
  NIR_PASS(_, s, nir_remove_dead_derefs);
  NIR_PASS(_, s, nir_remove_dead_variables, (nir_variable_mode)(nir_var_uniform | nir_var_mem_ubo | nir_var_image), nullptr);

  unsigned ubos = 0, texs = 0;
  nir_foreach_function_impl(impl, s) nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
    if (ins->type == nir_instr_type_tex) texs = std::max(texs, nir_instr_as_tex(ins)->texture_index + 1);
    if (ins->type == nir_instr_type_intrinsic && nir_instr_as_intrinsic(ins)->intrinsic == nir_intrinsic_load_ubo &&
        nir_src_is_const(nir_instr_as_intrinsic(ins)->src[0]))
      ubos = std::max(ubos, (unsigned)nir_src_as_uint(nir_instr_as_intrinsic(ins)->src[0]) + 1);
  }
  s->info.num_ubos = ubos;
  s->info.num_textures = texs;
  nir_validate_shader(s, "spvnir");
  return s;
}
