/* SPDX-License-Identifier: MIT */
// nirdiff - NIR-level differential check: the NIR air2ir3 builds from Apple AIR versus the NIR Mesa's
// own SPIR-V front end (spirv_to_nir) builds from an equivalent GLSL shader (glslc -> SPIR-V).
//
// Both shaders go through the same canonicalisation (IO lowered to load_input/store_output at the
// same slots, scalarised ALU and IO, the NIR algebraic/CSE/DCE loop) and are reduced to a multiset
// signature of the operations that carry meaning: ALU opcodes, texture ops (op, T#, S#, dim,
// sources), IO and UBO accesses (slot/component, block/offset) and scalar constants.  Pure data
// plumbing (mov/vecN) is counted separately.  Both are also compiled with the same ir3 pipeline as
// air2ir3 and the ir3 stats and binaries compared.
//
// usage: nirdiff --air fn.bc [--fc i=v] [--fc-name n=v] [--entry e] --spv ref.spv [--json out.json]
//                [--dump]  (prints both canonical NIRs)  [--disasm]  (prints both ir3 disassemblies)
// exit 0 = NIR signatures identical, 1 = they differ (details in the JSON / stdout), 2+ = error.
#include "air2ir3.h"
#include "spvnir.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "nir.h"
#include "nir_builder.h"
#include "glsl_types.h"
#include "util/blob.h"
#include "freedreno_dev_info.h"
#include "ir3_compiler.h"
#include "ir3_nir.h"
#include "ir3_shader.h"
extern "C" {
#include "disasm.h"
}

[[noreturn]] static void fail(const std::string &m) { fprintf(stderr, "nirdiff: %s\n", m.c_str()); exit(3); }

static unsigned type_size_vec4(const glsl_type *t, bool) { return glsl_count_attribute_slots(t, false); }

static void canon(nir_shader *s) {
  nir_foreach_variable_with_modes(v, s, (nir_variable_mode)(nir_var_shader_in | nir_var_shader_out)) v->data.driver_location = v->data.location;
  NIR_PASS(_, s, nir_lower_vars_to_ssa);
  NIR_PASS(_, s, nir_lower_io, (nir_variable_mode)(nir_var_shader_in | nir_var_shader_out), type_size_vec4,
           s->info.stage == MESA_SHADER_FRAGMENT ? nir_lower_io_use_interpolated_input_intrinsics : (nir_lower_io_options)0);
  NIR_PASS(_, s, nir_lower_io_to_scalar, (nir_variable_mode)(nir_var_shader_in | nir_var_shader_out | nir_var_mem_ubo), nullptr, nullptr);
  NIR_PASS(_, s, nir_lower_alu_to_scalar, nullptr, nullptr);
  bool progress;
  int it = 0;
  do {
    progress = false;
    NIR_PASS(progress, s, nir_opt_copy_prop);
    NIR_PASS(progress, s, nir_opt_dce);
    NIR_PASS(progress, s, nir_opt_cse);
    NIR_PASS(progress, s, nir_opt_algebraic);
    NIR_PASS(progress, s, nir_opt_constant_folding);
    NIR_PASS(progress, s, nir_opt_dead_cf);
    NIR_PASS(progress, s, nir_opt_remove_phis);
    NIR_PASS(progress, s, nir_opt_undef);
    NIR_PASS(progress, s, nir_lower_alu_to_scalar, nullptr, nullptr);
  } while (progress && ++it < 64);
  NIR_PASS(_, s, nir_lower_load_const_to_scalar);
  NIR_PASS(_, s, nir_opt_cse);
  NIR_PASS(_, s, nir_opt_dce);
}

struct Sig { std::map<std::string, int> ops; int plumbing = 0, total = 0; };

static std::string slotName(nir_shader *s, nir_intrinsic_instr *in, bool out) {
  nir_io_semantics sem = nir_intrinsic_io_semantics(in);
  const char *n;
  if (s->info.stage == MESA_SHADER_VERTEX && !out) n = gl_vert_attrib_name((gl_vert_attrib)sem.location);
  else if (s->info.stage == MESA_SHADER_FRAGMENT && out) n = gl_frag_result_name((gl_frag_result)sem.location);
  else n = gl_varying_slot_name_for_stage((gl_varying_slot)sem.location, s->info.stage);
  return std::string(n ? n : "?") + "." + "xyzw"[nir_intrinsic_component(in) & 3];
}

static Sig signature(nir_shader *s) {
  Sig g;
  nir_foreach_function_impl(impl, s) nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
    std::string k;
    switch (ins->type) {
    case nir_instr_type_alu: {
      nir_alu_instr *a = nir_instr_as_alu(ins);
      if (a->op == nir_op_mov || nir_op_is_vec(a->op)) { g.plumbing++; continue; }
      k = std::string("alu ") + nir_op_infos[a->op].name + std::to_string(a->def.bit_size);
      break;
    }
    case nir_instr_type_load_const: {
      nir_load_const_instr *c = nir_instr_as_load_const(ins);
      char b[64];
      if (c->def.bit_size == 32) snprintf(b, sizeof b, "const 0x%08x (%g)", c->value[0].u32, c->value[0].f32);
      else snprintf(b, sizeof b, "const %ub 0x%llx", c->def.bit_size, (unsigned long long)c->value[0].u64);
      k = b;
      break;
    }
    case nir_instr_type_tex: {
      nir_tex_instr *t = nir_instr_as_tex(ins);
      std::string opn;
      switch (t->op) { case nir_texop_tex: opn = "tex"; break; case nir_texop_txb: opn = "txb"; break; case nir_texop_txl: opn = "txl"; break;
        case nir_texop_txd: opn = "txd"; break; case nir_texop_txf: opn = "txf"; break; case nir_texop_txs: opn = "txs"; break;
        case nir_texop_tg4: opn = "tg4"; break; default: opn = "op" + std::to_string(t->op); }
      k = std::string("tex ") + opn + " T#" + std::to_string(t->texture_index) +
          " S#" + std::to_string(t->sampler_index) + " dim" + std::to_string(t->sampler_dim) + (t->is_array ? " array" : "") +
          " coord" + std::to_string(t->coord_components) + " dest" + std::to_string(t->dest_type);
      for (unsigned i = 0; i < t->num_srcs; i++)
        if (t->src[i].src_type != nir_tex_src_coord) {
          nir_tex_src_type st = t->src[i].src_type;
          k += st == nir_tex_src_lod ? " +lod" : st == nir_tex_src_bias ? " +bias" : st == nir_tex_src_offset ? " +offset" :
               st == nir_tex_src_ddx ? " +ddx" : st == nir_tex_src_ddy ? " +ddy" : st == nir_tex_src_min_lod ? " +min_lod" :
               st == nir_tex_src_comparator ? " +comparator" : " +src" + std::to_string(st);
        }
      break;
    }
    case nir_instr_type_intrinsic: {
      nir_intrinsic_instr *in = nir_instr_as_intrinsic(ins);
      k = std::string("intr ") + nir_intrinsic_infos[in->intrinsic].name;
      if (in->intrinsic == nir_intrinsic_load_input || in->intrinsic == nir_intrinsic_load_interpolated_input)
        k += " " + slotName(s, in, false);
      else if (in->intrinsic == nir_intrinsic_store_output) k += " " + slotName(s, in, true);
      else if (in->intrinsic == nir_intrinsic_load_ubo) {
        k += " b" + (nir_src_is_const(in->src[0]) ? std::to_string(nir_src_as_uint(in->src[0])) : std::string("?"));
        k += "+" + (nir_src_is_const(in->src[1]) ? std::to_string(nir_src_as_uint(in->src[1])) : std::string("dyn"));
      } else if (in->intrinsic == nir_intrinsic_load_barycentric_pixel || in->intrinsic == nir_intrinsic_load_barycentric_centroid ||
                 in->intrinsic == nir_intrinsic_load_barycentric_sample)
      {  // INTERP_MODE_NONE is GLSL's default (= smooth); Metal's default is perspective (= smooth)
        unsigned m = nir_intrinsic_interp_mode(in);
        k += std::string(" ") + (m == INTERP_MODE_NONE || m == INTERP_MODE_SMOOTH ? "smooth" : m == INTERP_MODE_FLAT ? "flat" :
                                 m == INTERP_MODE_NOPERSPECTIVE ? "noperspective" : "interp" + std::to_string(m));
      }
      break;
    }
    case nir_instr_type_undef: k = "undef"; break;
    case nir_instr_type_phi: k = "phi"; break;
    case nir_instr_type_jump: k = "jump"; break;
    default: k = "instr" + std::to_string(ins->type); break;
    }
    g.ops[k]++;
    g.total++;
  }
  return g;
}

struct Ir3Result { unsigned instrs = 0, dwords = 0, constlen = 0; int full_regs = 0, half_regs = 0; std::vector<uint8_t> bin; };

static Ir3Result ir3compile(ir3_compiler *compiler, nir_shader *nir) {
  nir_assign_io_var_locations(nir, nir_var_shader_in);
  nir_assign_io_var_locations(nir, nir_var_shader_out);
  ir3_nir_lower_io_vars_to_temporaries(nir);
  ir3_nir_lower_io(nir);
  ir3_shader_nir_options nopts = {};
  ir3_finalize_nir(compiler, &nopts, nir);
  ir3_shader_options sopts = {};
  sopts.api_wavesize = IR3_SINGLE_OR_DOUBLE; sopts.real_wavesize = IR3_SINGLE_OR_DOUBLE;
  ir3_shader *shader = ir3_shader_from_nir(compiler, nir, &sopts);
  ir3_shader_key key = {};
  ir3_shader_variant *v = ir3_shader_create_variant(shader, &key, true);
  if (!v || !v->bin) fail("ir3 compile failed");
  Ir3Result r;
  r.instrs = v->info.instrs_count; r.dwords = v->info.size / 4; r.constlen = v->constlen;
  r.full_regs = v->info.max_reg + 1; r.half_regs = v->info.max_half_reg + 1;
  r.bin.assign((uint8_t *)v->bin, (uint8_t *)v->bin + v->info.size);
  return r;
}

static std::string jesc(const std::string &s) {
  std::string o;
  for (char c : s) { if (c == '"' || c == '\\') o += '\\'; o += c; }
  return o;
}
static std::vector<double> parseVals(const std::string &s) {
  std::vector<double> v; size_t p = 0;
  while (p <= s.size()) {
    size_t q = s.find(',', p); if (q == std::string::npos) q = s.size();
    std::string t = s.substr(p, q - p);
    if (t == "true") v.push_back(1); else if (t == "false") v.push_back(0); else if (!t.empty()) v.push_back(strtod(t.c_str(), nullptr));
    p = q + 1;
  }
  return v;
}

int main(int argc, char **argv) {
  glsl_type_singleton_init_or_ref();   // held for the process: air_frontend takes and drops its own reference
  const char *air = nullptr, *spv = nullptr, *jsonOut = nullptr;
  bool dump = false, dis = false;
  AirOptions o;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { if (i + 1 >= argc) fail("missing value for " + a); return argv[++i]; };
    if (a == "--air") air = argv[++i];
    else if (a == "--spv") spv = argv[++i];
    else if (a == "--json") jsonOut = argv[++i];
    else if (a == "--dump") dump = true;
    else if (a == "--disasm") dis = true;
    else if (a == "--entry") o.entry = next();
    else if (a == "--fc") { std::string kv = next(); o.fc[atoi(kv.c_str())] = parseVals(kv.substr(kv.find('=') + 1)); }
    else if (a == "--fc-name") { std::string kv = next(); size_t e = kv.find('='); o.fcByName[kv.substr(0, e)] = parseVals(kv.substr(e + 1)); }
    else fail("unknown argument " + a);
  }
  if (!air || !spv) { fprintf(stderr, "usage: nirdiff --air fn.bc [--fc i=v] --spv ref.spv [--json out] [--dump]\n"); return 2; }

  glsl_type_singleton_init_or_ref();
  fd_dev_id did = {}; did.chip_id = 0x44070041;
  const struct fd_dev_info *info = fd_dev_info_raw(&did);
  ir3_compiler_options copts = {};
  copts.bindless_fb_read_descriptor = 4; copts.bindless_fb_read_slot = 32 + 32 - 1 - 8;   // BINDING-ABI.md
  copts.lower_base_vertex = true; copts.push_ubo_with_preamble = true; copts.disable_cache = true;
  ir3_compiler *compiler = ir3_compiler_create(nullptr, &did, info, &copts);
  const nir_shader_compiler_options *nopts = ir3_get_compiler_options(compiler);

  AirFrontendResult R = air_frontend(air, o, nopts);
  std::string err;
  nir_shader *B = spv_frontend(spv, R.stage, nopts, &err);
  if (!B) fail(err);
  nir_shader *A = R.nir;
  nir_shader *Ac = nir_shader_clone(nullptr, A), *Bc = nir_shader_clone(nullptr, B);
  canon(Ac); canon(Bc);
  if (dump) { printf("==== AIR-derived NIR (canonical)\n"); nir_print_shader(Ac, stdout); printf("==== SPIR-V-derived NIR (canonical)\n"); nir_print_shader(Bc, stdout); }
  Sig sa = signature(Ac), sb = signature(Bc);
  std::map<std::string, int> onlyA, onlyB;
  for (auto &kv : sa.ops) { int d = kv.second - (sb.ops.count(kv.first) ? sb.ops[kv.first] : 0); if (d > 0) onlyA[kv.first] = d; }
  for (auto &kv : sb.ops) { int d = kv.second - (sa.ops.count(kv.first) ? sa.ops[kv.first] : 0); if (d > 0) onlyB[kv.first] = d; }
  bool same = onlyA.empty() && onlyB.empty();

  Ir3Result ia = ir3compile(compiler, A), ib = ir3compile(compiler, B);
  bool binSame = ia.bin == ib.bin;
  if (dis) {
    printf("==== ir3 from AIR-derived NIR\n"); disasm_a3xx((uint32_t *)ia.bin.data(), ia.dwords, 0, stdout, fd_dev_gpu_id(&did));
    printf("==== ir3 from SPIR-V-derived NIR\n"); disasm_a3xx((uint32_t *)ib.bin.data(), ib.dwords, 0, stdout, fd_dev_gpu_id(&did));
  }

  printf("nirdiff %s (%s): NIR %s  [air %d ops + %d mov/vec, spv %d ops + %d mov/vec]\n", R.function.c_str(),
         R.stage == MESA_SHADER_VERTEX ? "vertex" : "fragment", same ? "IDENTICAL" : "DIFFERENT", sa.total, sa.plumbing, sb.total, sb.plumbing);
  for (auto &kv : onlyA) printf("   only in AIR NIR  x%d  %s\n", kv.second, kv.first.c_str());
  for (auto &kv : onlyB) printf("   only in SPV NIR  x%d  %s\n", kv.second, kv.first.c_str());
  printf("   ir3 air: %u instrs %u dwords constlen %u regs %d   spv: %u instrs %u dwords constlen %u regs %d   binary %s\n",
         ia.instrs, ia.dwords, ia.constlen, ia.full_regs, ib.instrs, ib.dwords, ib.constlen, ib.full_regs, binSame ? "IDENTICAL" : "differs");

  if (jsonOut) {
    FILE *f = fopen(jsonOut, "w"); if (!f) fail("cannot write json");
    auto m = [&](const std::map<std::string, int> &x) {
      std::string s = "{"; for (auto &kv : x) { if (s.size() > 1) s += ","; s += "\"" + jesc(kv.first) + "\":" + std::to_string(kv.second); } return s + "}"; };
    auto ir = [&](const Ir3Result &r) {
      char b[200]; snprintf(b, sizeof b, "{\"instrs\":%u,\"dwords\":%u,\"constlen\":%u,\"full_regs\":%d,\"half_regs\":%d}", r.instrs, r.dwords, r.constlen, r.full_regs, r.half_regs); return std::string(b); };
    fprintf(f, "{\"function\":\"%s\",\"stage\":\"%s\",\"nir_identical\":%s,\"air_ops\":%d,\"spv_ops\":%d,\"air_plumbing\":%d,\"spv_plumbing\":%d,"
               "\"only_air\":%s,\"only_spv\":%s,\"air_signature\":%s,\"ir3_air\":%s,\"ir3_spv\":%s,\"ir3_binary_identical\":%s}\n",
            R.function.c_str(), R.stage == MESA_SHADER_VERTEX ? "vertex" : "fragment", same ? "true" : "false", sa.total, sb.total, sa.plumbing, sb.plumbing,
            m(onlyA).c_str(), m(onlyB).c_str(), m(sa.ops).c_str(), ir(ia).c_str(), ir(ib).c_str(), binSame ? "true" : "false");
    fclose(f);
  }
  return same ? 0 : 1;
}
