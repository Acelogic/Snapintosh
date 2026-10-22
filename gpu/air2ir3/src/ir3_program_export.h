/* SPDX-License-Identifier: MIT
 * Owned a8xx program description from a live compiled Mesa variant.
 * Field contract follows tools/p7ref/export_p7_shaders.cpp, independently used
 * by the A16 renderer. No cache deserialization or borrowed pointers escape.
 */
#ifndef AIR2IR3_PROGRAM_EXPORT_H
#define AIR2IR3_PROGRAM_EXPORT_H
#include <sstream>

static std::string air2ir3_program_json(const ir3_shader_variant *v, const std::string &sidecar) {
  std::ostringstream o;
  o.imbue(std::locale::classic());
  const struct ir3_const_state *cs = ir3_const_state(v);
  o << "{\"type\":\"" << _mesa_shader_stage_to_abbrev(v->type) << "\"";
#define FIELD(name, value) o << ",\"" name "\":" << +(value)
  FIELD("binning_pass", (unsigned)v->binning_pass);
  o << ",\"code_hex\":\"";
  static const char hex[] = "0123456789abcdef";
  const auto *code = (const unsigned char *)v->bin;
  for (unsigned i = 0; i < v->info.size; ++i) o << hex[code[i] >> 4] << hex[code[i] & 15];
  o << "\",\"info\":{\"size\":" << v->info.size;
  FIELD("sizedwords", v->info.sizedwords);
  FIELD("constant_data_offset", v->info.constant_data_offset);
  FIELD("instrs_count", v->info.instrs_count);
  FIELD("max_reg", (int)v->info.max_reg);
  FIELD("max_half_reg", (int)v->info.max_half_reg);
  FIELD("double_threadsize", (unsigned)v->info.double_threadsize);
  FIELD("early_preamble", (unsigned)v->info.early_preamble);
  FIELD("preamble_instrs_count", v->info.preamble_instrs_count);
  o << "}";
  FIELD("instrlen", v->instrlen);
  FIELD("constlen", v->constlen);
  FIELD("branchstack", v->branchstack);
  FIELD("branchstack_hw", ir3_shader_branchstack_hw(v));
  FIELD("mergedregs", (unsigned)v->mergedregs);
  FIELD("early_preamble", (unsigned)v->early_preamble);
  FIELD("pvtmem_size", v->pvtmem_size);
  FIELD("pvtmem_per_wave", (unsigned)v->pvtmem_per_wave);
  FIELD("shared_size", v->shared_size);
  FIELD("total_in", v->total_in);
  FIELD("num_samp", (int)v->num_samp);
  FIELD("num_uavs", v->num_uavs);
  FIELD("num_sampler_prefetch", v->num_sampler_prefetch);
  FIELD("need_pixlod", (unsigned)v->need_pixlod);
  FIELD("need_full_quad", (unsigned)v->need_full_quad);
  FIELD("sample_shading", (unsigned)v->sample_shading);
  FIELD("frag_face", (unsigned)v->frag_face);
  FIELD("fragcoord_compmask", (unsigned)v->fragcoord_compmask);
  FIELD("reads_primid", (unsigned)v->reads_primid);
  FIELD("color0_mrt", (unsigned)v->color0_mrt);
  FIELD("dual_src_blend", (unsigned)v->dual_src_blend);
  FIELD("post_depth_coverage", (unsigned)v->post_depth_coverage);
  FIELD("yuv_color", v->type == MESA_SHADER_FRAGMENT ? (unsigned)v->fs.yuv_color : 0u);
  FIELD("fb_read", (unsigned)v->fb_read);
  FIELD("has_ssbo", (unsigned)v->has_ssbo);
  FIELD("has_kill", (unsigned)v->has_kill);
  FIELD("no_earlyz", (unsigned)v->no_earlyz);
  o << ",\"bindless\":[" << (unsigned)v->bindless_tex << "," << (unsigned)v->bindless_samp
    << "," << (unsigned)v->bindless_ibo << "," << (unsigned)v->bindless_ubo << "]";
  FIELD("clip_mask", v->clip_mask);
  FIELD("cull_mask", v->cull_mask);
  FIELD("stream_outputs", v->stream_output.num_outputs);
  FIELD("writes_psize", (unsigned)v->writes_psize);
  FIELD("need_driver_params", (unsigned)v->need_driver_params);
  if (v->type == MESA_SHADER_COMPUTE) {
    o << ",\"cs\":{\"force_linear_dispatch\":" << (unsigned)v->cs.force_linear_dispatch;
    FIELD("round_robin_mode", (unsigned)v->cs.round_robin_mode);
    FIELD("local_size_variable", (unsigned)v->local_size_variable);
    o << ",\"local_size\":[" << v->local_size[0] << "," << v->local_size[1] << "," << v->local_size[2] << "]}";
  }
  o << ",\"inputs\":[";
  for (unsigned i = 0; i < v->inputs_count; ++i) {
    if (i) o << ",";
    o << "{\"slot\":" << +v->inputs[i].slot;
    FIELD("regid", v->inputs[i].regid); FIELD("compmask", v->inputs[i].compmask);
    FIELD("inloc", v->inputs[i].inloc); FIELD("sysval", (unsigned)v->inputs[i].sysval);
    FIELD("bary", (unsigned)v->inputs[i].bary); FIELD("rasterflat", (unsigned)v->inputs[i].rasterflat);
    FIELD("half", (unsigned)v->inputs[i].half); FIELD("flat", (unsigned)v->inputs[i].flat);
    o << "}";
  }
  o << "],\"outputs\":[";
  for (unsigned i = 0; i < v->outputs_count; ++i) {
    if (i) o << ",";
    o << "{\"slot\":" << +v->outputs[i].slot;
    FIELD("regid", v->outputs[i].regid); FIELD("half", (unsigned)v->outputs[i].half);
    FIELD("aliased_components", v->outputs[i].aliased_components); o << "}";
  }
  static const unsigned sysvals[] = {
    SYSTEM_VALUE_LOCAL_INVOCATION_ID, SYSTEM_VALUE_WORKGROUP_ID, SYSTEM_VALUE_LOCAL_INVOCATION_INDEX,
    SYSTEM_VALUE_VERTEX_ID, SYSTEM_VALUE_INSTANCE_ID, SYSTEM_VALUE_PRIMITIVE_ID, SYSTEM_VALUE_FRONT_FACE,
    SYSTEM_VALUE_SAMPLE_ID, SYSTEM_VALUE_SAMPLE_MASK_IN, SYSTEM_VALUE_FRAG_COORD,
    SYSTEM_VALUE_BARYCENTRIC_PERSP_PIXEL, SYSTEM_VALUE_BARYCENTRIC_PERSP_SAMPLE, SYSTEM_VALUE_BARYCENTRIC_PERSP_CENTROID,
    SYSTEM_VALUE_BARYCENTRIC_PERSP_CENTER_RHW, SYSTEM_VALUE_BARYCENTRIC_LINEAR_PIXEL,
    SYSTEM_VALUE_BARYCENTRIC_LINEAR_CENTROID, SYSTEM_VALUE_BARYCENTRIC_LINEAR_SAMPLE,
  };
  o << "],\"sysval_regids\":{";
  for (unsigned i = 0; i < sizeof(sysvals) / sizeof(sysvals[0]); ++i) {
    if (i) o << ",";
    o << "\"" << gl_system_value_name((gl_system_value)sysvals[i]) << "\":" << ir3_find_sysval_regid(v, sysvals[i]);
  }
  o << "}";
  if (cs) {
    o << ",\"const_state\":{\"num_ubos\":" << cs->num_ubos;
    FIELD("num_app_ubos", cs->num_app_ubos); FIELD("num_driver_params", cs->num_driver_params);
    FIELD("consts_ubo", (int)cs->consts_ubo.idx); FIELD("driver_params_ubo", (int)cs->driver_params_ubo.idx);
    FIELD("primitive_map_ubo", (int)cs->primitive_map_ubo.idx); FIELD("primitive_param_ubo", (int)cs->primitive_param_ubo.idx);
    o << ",\"ubo_ranges\":[";
    for (unsigned i = 0; i < cs->ubo_state.num_enabled; ++i) {
      const auto *range = &cs->ubo_state.range[i];
      if (i) o << ",";
      o << "{\"block\":" << range->ubo.block;
      FIELD("bindless", (unsigned)range->ubo.bindless); FIELD("start", range->start);
      FIELD("end", range->end); FIELD("offset", range->offset); o << "}";
    }
    o << "]}";
  }
#undef FIELD
  o << ",\"sidecar\":" << sidecar << "}";
  return o.str();
}
#endif
