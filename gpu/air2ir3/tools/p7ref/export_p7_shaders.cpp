// SPDX-License-Identifier: MIT
// export_p7_shaders: turn the two air2ir3 variant blobs of the P7 pipeline (SkyLight SimpleVertex +
// SimpleTextureFragment) into the JSON the A16 tool reads (tools/a16gpu-p7/p7-shaders.json).
//
// The blobs are Mesa ir3_store_variant() payloads made by the Stage 6 compiler (air2ir3, BINDING-ABI
// v2). This program reloads them with Mesa's own ir3_retrieve_variant() -- the same call a Mesa-based
// command-stream builder uses -- and writes out exactly the variant fields that gallium's a8xx program
// state (fd6_program.cc) reads, the VS->FS linkage from Mesa's ir3_link_shaders(), the machine code and
// its disassembly. The A16 tool (tools/a16gpu_p6p7.py) never parses a blob and never runs Mesa.
//
// Build against the Stage 6 tree (AIR2IR3_TREE: its build/mesa and third_party/mesa), see README.md:
//   AIR2IR3_TREE=... tools/a16gpu-p7/make-p7-shaders.sh  (builds this, compiles both functions, writes the JSON)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "glsl_types.h"
#include "util/blob.h"
#include "freedreno_dev_info.h"
#include "ir3_compiler.h"
#include "ir3_shader.h"
extern "C" {
#include "disasm.h"
}

static std::vector<char> slurp(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
  std::vector<char> data;
  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof buf, f)) > 0) data.insert(data.end(), buf, buf + n);
  fclose(f);
  return data;
}

static std::string esc(const std::string &s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if (c == '\n') o += "\\n";
    else if (c == '\t') o += "\\t";
    else if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
    else o += c;
  }
  return o;
}

static std::string disasm(const ir3_shader_variant *v, unsigned gpu_id) {
  char *text = nullptr; size_t len = 0;
  FILE *mem = open_memstream(&text, &len);
  unsigned code_dw = v->info.constant_data_offset ? v->info.constant_data_offset / 4 : v->info.sizedwords;
  disasm_a3xx((const uint32_t *)v->bin, code_dw, 0, mem, gpu_id);
  fclose(mem);
  std::string s(text, len);
  free(text);
  return s;
}

static const unsigned SYSVALS[] = {
  SYSTEM_VALUE_VERTEX_ID, SYSTEM_VALUE_INSTANCE_ID, SYSTEM_VALUE_PRIMITIVE_ID, SYSTEM_VALUE_FRONT_FACE,
  SYSTEM_VALUE_SAMPLE_ID, SYSTEM_VALUE_SAMPLE_MASK_IN, SYSTEM_VALUE_FRAG_COORD,
  SYSTEM_VALUE_BARYCENTRIC_PERSP_PIXEL, SYSTEM_VALUE_BARYCENTRIC_PERSP_SAMPLE, SYSTEM_VALUE_BARYCENTRIC_PERSP_CENTROID,
  SYSTEM_VALUE_BARYCENTRIC_PERSP_CENTER_RHW, SYSTEM_VALUE_BARYCENTRIC_LINEAR_PIXEL,
  SYSTEM_VALUE_BARYCENTRIC_LINEAR_CENTROID, SYSTEM_VALUE_BARYCENTRIC_LINEAR_SAMPLE,
};

static void variant_json(FILE *o, const char *name, const ir3_shader_variant *v, const std::string &sidecar,
                         unsigned gpu_id) {
  const struct ir3_const_state *cs = v->const_state;
  fprintf(o, "  \"%s\": {\n", name);
  fprintf(o, "    \"type\": \"%s\", \"binning_pass\": %d,\n", _mesa_shader_stage_to_abbrev(v->type), v->binning_pass);
  fprintf(o, "    \"code_hex\": \"");
  for (unsigned i = 0; i < v->info.size; i++) fprintf(o, "%02x", ((uint8_t *)v->bin)[i]);
  fprintf(o, "\",\n");
  fprintf(o, "    \"info\": {\"size\": %u, \"sizedwords\": %u, \"constant_data_offset\": %u, \"instrs_count\": %u, "
             "\"max_reg\": %d, \"max_half_reg\": %d, \"double_threadsize\": %d, \"early_preamble\": %d, "
             "\"preamble_instrs_count\": %u},\n",
          v->info.size, v->info.sizedwords, v->info.constant_data_offset, v->info.instrs_count, v->info.max_reg,
          v->info.max_half_reg, v->info.double_threadsize, v->info.early_preamble, v->info.preamble_instrs_count);
  fprintf(o, "    \"instrlen\": %u, \"constlen\": %u, \"branchstack\": %u, \"branchstack_hw\": %u, \"mergedregs\": %d, "
             "\"early_preamble\": %d, \"pvtmem_size\": %u, \"pvtmem_per_wave\": %d, \"shared_size\": %u,\n",
          v->instrlen, v->constlen, v->branchstack, ir3_shader_branchstack_hw(v), v->mergedregs, v->early_preamble,
          v->pvtmem_size, v->pvtmem_per_wave, v->shared_size);
  fprintf(o, "    \"total_in\": %u, \"num_samp\": %d, \"num_uavs\": %u, \"num_sampler_prefetch\": %u, "
             "\"need_pixlod\": %d, \"need_full_quad\": %d, \"sample_shading\": %d, \"frag_face\": %d, "
             "\"fragcoord_compmask\": %u, \"reads_primid\": %d, \"color0_mrt\": %d, \"dual_src_blend\": %d, "
             "\"post_depth_coverage\": %d, \"yuv_color\": %d, \"fb_read\": %d, \"has_ssbo\": %d, \"has_kill\": %d, "
             "\"no_earlyz\": %d, \"bindless\": [%d, %d, %d, %d], \"clip_mask\": %u, \"cull_mask\": %u, "
             "\"stream_outputs\": %u, \"writes_psize\": %d, \"need_driver_params\": %d,\n",
          v->total_in, v->num_samp, v->num_uavs, v->num_sampler_prefetch, v->need_pixlod, v->need_full_quad,
          v->sample_shading, v->frag_face, v->fragcoord_compmask, v->reads_primid, v->color0_mrt, v->dual_src_blend,
          v->post_depth_coverage, v->type == MESA_SHADER_FRAGMENT ? v->fs.yuv_color : 0, v->fb_read, v->has_ssbo,
          v->has_kill, v->no_earlyz, v->bindless_tex, v->bindless_samp, v->bindless_ibo, v->bindless_ubo, v->clip_mask,
          v->cull_mask, v->stream_output.num_outputs, v->writes_psize, v->need_driver_params);
  fprintf(o, "    \"inputs\": [");
  for (unsigned i = 0; i < v->inputs_count; i++)
    fprintf(o, "%s{\"slot\": %u, \"regid\": %u, \"compmask\": %u, \"inloc\": %u, \"sysval\": %d, \"bary\": %d, "
               "\"rasterflat\": %d, \"half\": %d, \"flat\": %d}",
            i ? ", " : "", v->inputs[i].slot, v->inputs[i].regid, v->inputs[i].compmask, v->inputs[i].inloc,
            v->inputs[i].sysval, v->inputs[i].bary, v->inputs[i].rasterflat, v->inputs[i].half, v->inputs[i].flat);
  fprintf(o, "],\n    \"outputs\": [");
  for (unsigned i = 0; i < v->outputs_count; i++)
    fprintf(o, "%s{\"slot\": %u, \"regid\": %u, \"half\": %d, \"aliased_components\": %u}", i ? ", " : "",
            v->outputs[i].slot, v->outputs[i].regid, v->outputs[i].half, v->outputs[i].aliased_components);
  fprintf(o, "],\n    \"sysval_regids\": {");
  for (unsigned i = 0; i < sizeof SYSVALS / sizeof SYSVALS[0]; i++)
    fprintf(o, "%s\"%s\": %u", i ? ", " : "", gl_system_value_name((gl_system_value)SYSVALS[i]),
            ir3_find_sysval_regid(v, SYSVALS[i]));
  fprintf(o, "},\n");
  if (cs) {
    fprintf(o, "    \"const_state\": {\"num_ubos\": %u, \"num_app_ubos\": %u, \"num_driver_params\": %u, "
               "\"consts_ubo\": %d, \"driver_params_ubo\": %d, \"primitive_map_ubo\": %d, \"primitive_param_ubo\": %d, "
               "\"ubo_ranges\": [",
            cs->num_ubos, cs->num_app_ubos, cs->num_driver_params, cs->consts_ubo.idx, cs->driver_params_ubo.idx,
            cs->primitive_map_ubo.idx, cs->primitive_param_ubo.idx);
    for (unsigned i = 0; i < cs->ubo_state.num_enabled; i++) {
      const struct ir3_ubo_range *r = &cs->ubo_state.range[i];
      fprintf(o, "%s{\"block\": %u, \"bindless\": %d, \"start\": %u, \"end\": %u, \"offset\": %u}", i ? ", " : "",
              r->ubo.block, r->ubo.bindless, r->start, r->end, r->offset);
    }
    fprintf(o, "]},\n");
  }
  fprintf(o, "    \"sidecar\": %s,\n", sidecar.empty() ? "null" : sidecar.c_str());
  fprintf(o, "    \"disasm\": \"%s\"\n  }", esc(disasm(v, gpu_id)).c_str());
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: export_p7_shaders vs.ir3v fs.ir3v vs.sidecar.json fs.sidecar.json > p7-shaders.json\n");
    return 2;
  }
  struct fd_dev_id id = {};
  id.chip_id = 0x44070041;                       // Adreno X2-90, as air2ir3_compiler_create
  const struct fd_dev_info *info = fd_dev_info_raw(&id);
  if (!info) { fprintf(stderr, "chip unknown\n"); return 2; }
  glsl_type_singleton_init_or_ref();
  struct ir3_compiler_options copts = {};
  copts.bindless_fb_read_descriptor = 4;         // air2ir3 ABI_FS_BINDLESS_SET / ABI_FB_READ_SLOT: same options
  copts.bindless_fb_read_slot = 55;              // (they only matter for compiling, not for reloading)
  copts.lower_base_vertex = true;
  copts.push_ubo_with_preamble = true;
  copts.disable_cache = true;
  ir3_compiler *c = ir3_compiler_create(nullptr, &id, info, &copts);
  if (!c) { fprintf(stderr, "ir3_compiler_create failed\n"); return 2; }
  ir3_shader_variant *vv[2];
  std::string sidecars[2];
  for (int i = 0; i < 2; i++) {
    std::vector<char> blob = slurp(argv[1 + i]);
    struct blob_reader br;
    blob_reader_init(&br, blob.data(), blob.size());
    vv[i] = ir3_retrieve_variant(&br, c, nullptr);
    if (br.overrun || br.current != br.end) { fprintf(stderr, "%s: blob does not parse exactly\n", argv[1 + i]); return 3; }
    std::vector<char> sc = slurp(argv[3 + i]);
    sidecars[i] = std::string(sc.begin(), sc.end());
  }
  ir3_shader_variant *vs = vv[0], *fs = vv[1];
  if (vs->type != MESA_SHADER_VERTEX || fs->type != MESA_SHADER_FRAGMENT) { fprintf(stderr, "stages\n"); return 3; }
  struct ir3_shader_linkage l = {};
  l.primid_loc = l.clip0_loc = l.clip1_loc = 0xff;
  ir3_link_shaders(&l, vs, fs, true);           // fd6_program.cc emit_vpc: pack_vs_out = true
  unsigned gpu_id = fd_dev_gpu_id(&id);
  FILE *o = stdout;
  fprintf(o, "{\n  \"format\": 1, \"chip_id\": \"0x%llx\", \"gpu_id\": %u, \"max_branchstack\": %u,\n",
          (unsigned long long)id.chip_id, gpu_id, c->max_branchstack);
  fprintf(o, "  \"link_vs_fs\": {\"max_loc\": %u, \"cnt\": %u, \"varmask\": [%u, %u, %u, %u], \"primid_loc\": %u, "
             "\"viewid_loc\": %u, \"clip0_loc\": %u, \"clip1_loc\": %u, \"var\": [",
          l.max_loc, l.cnt, l.varmask[0], l.varmask[1], l.varmask[2], l.varmask[3], l.primid_loc, l.viewid_loc,
          l.clip0_loc, l.clip1_loc);
  for (unsigned i = 0; i < l.cnt; i++)
    fprintf(o, "%s{\"slot\": %u, \"regid\": %u, \"compmask\": %u, \"loc\": %u}", i ? ", " : "", l.var[i].slot,
            l.var[i].regid, l.var[i].compmask, l.var[i].loc);
  fprintf(o, "]},\n");
  variant_json(o, "vs", vs, sidecars[0], gpu_id);
  fprintf(o, ",\n");
  if (vs->binning) {
    variant_json(o, "vs_binning", vs->binning, "", gpu_id);
    fprintf(o, ",\n");
  }
  variant_json(o, "fs", fs, sidecars[1], gpu_id);
  fprintf(o, "\n}\n");
  ir3_compiler_destroy(c);
  glsl_type_singleton_decref();
  return 0;
}
