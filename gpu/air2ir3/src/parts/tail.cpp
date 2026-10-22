/* SPDX-License-Identifier: MIT */

  nir_block *newBlock() {
    nir_block *n = nir_block_create(b.impl);
    exec_list_push_tail(&b.impl->body, &n->cf_node.node);
    n->cf_node.parent = &b.impl->cf_node;
    return n;
  }

  nir_shader *run(const nir_shader_compiler_options *opts) {
    b = nir_builder_init_simple_shader(stage, opts, "%s", F->getName().str().c_str());
    s = b.shader;
    b.impl->structured = false;
    setupArgs();
    // phi temporaries
    for (BasicBlock &BB : *F)
      for (PHINode &PN : BB.phis()) {
        std::vector<Type *> ts; flatten(PN.getType(), ts);
        for (Type *E : ts) if (E->isPointerTy()) die("phi of pointers (divergent buffer/threadgroup pointer selection): " + str(&PN));
        for (Type *E : ts) if (bits(E) != bits(ts[0]) || E->isFloatingPointTy() != ts[0]->isFloatingPointTy())
          die("phi of a mixed-type aggregate: " + str(&PN));
        phiVars[&PN] = nir_local_variable_create(b.impl, glsl_vector_type(baseOf(ts[0]), ts.size()), "phi");
      }
    // blocks: the LLVM entry continues the start block; the others are new unstructured blocks
    bool first = true;
    for (BasicBlock &BB : *F) { blocks[&BB] = first ? nir_start_block(b.impl) : newBlock(); first = false; }
    ReversePostOrderTraversal<Function *> RPOT(F);        // defs before uses
    for (BasicBlock *BB : RPOT) {
      b.cursor = nir_after_block(blocks[BB]);
      for (Instruction &I : *BB) { if (I.isTerminator()) terminator(&I); else inst(I); }
    }
    s->info.num_ubos = maxUbo + 1;
    s->info.shared_size = sharedSize;
    if (!constData.empty()) { s->constant_data_size = constData.size(); s->constant_data = ralloc_size(s, constData.size()); memcpy(s->constant_data, constData.data(), constData.size()); }
    if (stage == MESA_SHADER_COMPUTE) s->info.workgroup_size_variable = true;
    nir_progress(true, b.impl, nir_metadata_none);
    nir_sort_unstructured_blocks(b.impl);
    nir_index_blocks(b.impl);
    nir_validate_shader(s, "after AIR translation");
    NIR_PASS(_, s, nir_lower_goto_ifs);
    NIR_PASS(_, s, nir_lower_returns);
    NIR_PASS(_, s, nir_lower_vars_to_ssa);
    NIR_PASS(_, s, nir_opt_dce);
    nir_validate_shader(s, "after structurisation");
    R.constant_data_bytes = constData.size();
    R.shared_bytes = sharedSize;
    return s;
  }
};

// ---------------------------------------------------------------------- front end --
AirFrontendResult air_frontend(const char *path, const AirOptions &o, const nir_shader_compiler_options *nopts) {
  static LLVMContext Ctx;                 // lives for the process (tools are one-shot)
  AirFrontendResult R;
  auto buf = MemoryBuffer::getFile(path);
  if (!buf) die(std::string("cannot read input ") + path);
  auto modOr = parseBitcodeFile((*buf)->getMemBufferRef(), Ctx);
  if (!modOr) die("bitcode parse failed: " + toString(modOr.takeError()));
  Module *M = modOr->release();

  // Entry point via !air.vertex / !air.fragment / !air.kernel.
  Function *F = nullptr; mesa_shader_stage stage = MESA_SHADER_NONE; const MDNode *ins = nullptr, *outsMd = nullptr;
  for (auto [md, st] : {std::pair{"air.vertex", MESA_SHADER_VERTEX}, {"air.fragment", MESA_SHADER_FRAGMENT}, {"air.kernel", MESA_SHADER_COMPUTE}}) {
    if (NamedMDNode *N = M->getNamedMetadata(md)) {
      MDNode *E = N->getOperand(0);
      F = cast<Function>(cast<ValueAsMetadata>(E->getOperand(0))->getValue());
      stage = st;
      if (st == MESA_SHADER_COMPUTE) { ins = cast<MDNode>(E->getOperand(2)); }
      else { outsMd = cast<MDNode>(E->getOperand(1)); ins = cast<MDNode>(E->getOperand(2)); }
    }
  }
  if (!F) {
    if (M->getNamedMetadata("air.visible")) die("no AIR entry point (visible/stitchable function: needs linking into a caller)");
    die("no AIR entry point");
  }
  R.function = F->getName().str(); R.stage = stage; R.triple = M->getTargetTriple().str();

  // Metadata first (the specialiser may delete the globals it references).
  std::vector<ArgInfo> inArgs, outArgs;
  for (unsigned i = 0; outsMd && i < outsMd->getNumOperands(); i++) outArgs.push_back(parseArg(cast<MDNode>(outsMd->getOperand(i)), true));
  for (unsigned i = 0; ins && i < ins->getNumOperands(); i++) inArgs.push_back(parseArg(cast<MDNode>(ins->getOperand(i)), false));
  for (auto &a : inArgs) if (a.kind == "air.visible_function_table" || a.kind == "air.imageblock" || a.kind == "air.indirect_buffer")
    die("input kind " + a.kind);

  // Function constants: by index and by name.
  std::vector<FcDecl> decls = parseFcDecls(*M);
  std::map<int, std::vector<double>> fc = o.fc;
  for (auto &kv : o.fcByName) {
    bool found = false;
    for (auto &d : decls) if (d.name == kv.first) { fc[d.index] = kv.second; found = true; }
    if (!found) fprintf(stderr, "air2ir3: warning: function constant '%s' not declared by %s (ignored)\n", kv.first.c_str(), R.function.c_str());
  }
  for (auto &d : decls) {
    AirFc f; f.index = d.index; f.type = d.type; f.name = d.name; f.defined = fc.count(d.index) != 0;
    f.value = f.defined ? fc.at(d.index) : std::vector<double>{};
    R.fcs.push_back(f);
  }
  SpecResult spec = specialize_and_inline(*M, F, decls, fc);
  if (getenv("AIR2IR3_DUMP_LL")) { std::error_code ec; raw_fd_ostream os(getenv("AIR2IR3_DUMP_LL"), ec); M->print(os, nullptr); }

  glsl_type_singleton_init_or_ref();
  Translator *T = new Translator(*M, F, stage, R, spec);   // owns NIR builder state; intentionally leaked
  T->inArgs = inArgs; T->outArgs = outArgs;
  R.nir = T->run(nopts);
  // discard_fragment -> demote
  nir_foreach_function_impl(impl, R.nir) nir_foreach_block(blk, impl) nir_foreach_instr(ins2, blk)
    if (ins2->type == nir_instr_type_intrinsic && nir_instr_as_intrinsic(ins2)->intrinsic == nir_intrinsic_demote) R.uses_discard = true;
  R.report = T->report;
  return R;
}

std::string air_reflection_json(const AirFrontendResult &r) {
  std::string j = "{";
  auto kv = [&](const std::string &k, const std::string &v, bool q = true) { if (j.size() > 1) j += ","; j += "\"" + k + "\":" + (q ? "\"" + jesc(v) + "\"" : v); };
  kv("abi_version", std::to_string(ABI_VERSION), false);
  kv("function", r.function);
  kv("stage", r.stage == MESA_SHADER_VERTEX ? "vertex" : r.stage == MESA_SHADER_FRAGMENT ? "fragment" : "kernel");
  kv("air_triple", r.triple);
  std::string a = "[";
  for (auto &f : r.fcs) {
    if (a.size() > 1) a += ",";
    std::string v = "["; for (double x : f.value) { if (v.size() > 1) v += ","; char b[32]; snprintf(b, sizeof b, "%.9g", x); v += b; } v += "]";
    a += "{\"index\":" + std::to_string(f.index) + ",\"name\":\"" + jesc(f.name) + "\",\"type\":\"" + jesc(f.type) +
         "\",\"defined\":" + (f.defined ? "true" : "false") + ",\"value\":" + v + "}";
  }
  kv("function_constants", a + "]", false);
  a = "[";
  for (auto &b : r.bindings) {
    if (a.size() > 1) a += ",";
    a += "{\"kind\":\"" + b.kind + "\",\"metal_index\":" + std::to_string(b.metal_index) + ",\"slot\":" + std::to_string(b.slot);
    if (!b.arg_name.empty()) a += ",\"arg\":\"" + jesc(b.arg_name) + "\"";
    if (!b.type_name.empty()) a += ",\"type\":\"" + jesc(b.type_name) + "\"";
    if (!b.access.empty()) a += ",\"access\":\"" + b.access + "\"";
    a += std::string(",\"used\":") + (b.used ? "true" : "false");
    if (b.kind == "fb_fetch") a += ",\"bindless_set\":" + std::to_string(ABI_FS_BINDLESS_SET);
    if (b.kind == "device_buffer") a += ",\"va_table_ubo\":" + std::to_string(ABI_DEVICE_VA_UBO);
    if (b.kind == "constexpr_sampler") {
      char buf[512]; air_sampler as; air_sampler_decode(b.sampler_word, &as); char dec[400]; air_sampler_json(&as, dec, sizeof dec);
      snprintf(buf, sizeof buf, ",\"air_word\":\"0x%016llx\",\"unique_id\":\"0x%016llx\",\"a8xx_tex_samp\":[\"0x%08x\",\"0x%08x\",\"0x%08x\",\"0x%08x\"],\"state\":",
               (unsigned long long)b.sampler_word, (unsigned long long)b.unique_id, b.a8xx_desc[0], b.a8xx_desc[1], b.a8xx_desc[2], b.a8xx_desc[3]);
      a += buf; a += dec;
    }
    a += "}";
  }
  kv("bindings", a + "]", false);
  char m[32]; snprintf(m, sizeof m, "0x%04x", r.constexpr_sampler_mask); kv("constexpr_sampler_mask", m);
  a = "[";
  for (auto &v : r.varyings) {
    if (a.size() > 1) a += ",";
    a += "{\"name\":\"" + jesc(v.name) + "\",\"slot\":" + std::to_string(v.slot) + ",\"components\":" + std::to_string(v.comps) +
         ",\"bits\":" + std::to_string(v.bits) + ",\"type\":\"" + v.base + "\",\"interp\":\"" + v.interp + "\",\"sampling\":\"" + v.sampling + "\"}";
  }
  kv("varyings", a + "]", false);
  a = "[";
  for (auto &v : r.attributes) {
    if (a.size() > 1) a += ",";
    a += "{\"attribute\":" + std::to_string(v.index) + ",\"components\":" + std::to_string(v.comps) + ",\"bits\":" + std::to_string(v.bits) + ",\"type\":\"" + v.base + "\"}";
  }
  kv("vertex_attributes", a + "]", false);
  a = "[";
  for (auto &v : r.render_targets) {
    if (a.size() > 1) a += ",";
    a += "{\"index\":" + std::to_string(v.index) + ",\"components\":" + std::to_string(v.comps) + ",\"type\":\"" + v.base +
         "\",\"written\":" + (v.written ? "true" : "false") + ",\"fb_fetch\":" + (v.fb_fetch ? "true" : "false") + "}";
  }
  kv("render_targets", a + "]", false);
  a = "["; for (auto &s : r.sysvals) { if (a.size() > 1) a += ","; a += "\"" + s + "\""; } kv("system_values", a + "]", false);
  kv("writes_depth", r.writes_depth ? "true" : "false", false);
  kv("writes_point_size", r.writes_point_size ? "true" : "false", false);
  kv("uses_discard", r.uses_discard ? "true" : "false", false);
  kv("uses_fb_fetch", r.uses_fb_fetch ? "true" : "false", false);
  kv("constant_data_bytes", std::to_string(r.constant_data_bytes), false);
  kv("threadgroup_bytes", std::to_string(r.shared_bytes), false);
  return j + "}";
}

#ifndef AIR2IR3_NO_MAIN
// ---------------------------------------------------------------------------- CLI --
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
  uint64_t chip = 0x44070041;        // Adreno X2-90 (Mesa freedreno_devices.py)
  AirOptions o;
  const char *path = nullptr, *jsonOut = nullptr, *variantOut = nullptr; bool dumpNir = false, emitNir = false, quiet = false;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { if (i + 1 >= argc) die("missing value for " + a); return argv[++i]; };
    if (a == "--chip") chip = strtoull(next().c_str(), nullptr, 0);
    else if (a == "--fc") { std::string kv = next(); o.fc[atoi(kv.c_str())] = parseVals(kv.substr(kv.find('=') + 1)); }
    else if (a == "--fc-name") { std::string kv = next(); size_t e = kv.find('='); o.fcByName[kv.substr(0, e)] = parseVals(kv.substr(e + 1)); }
    else if (a == "--nir") dumpNir = true;
    else if (a == "--emit-nir") emitNir = true;
    else if (a == "--json") jsonOut = argv[++i];
    else if (a == "--variant") variantOut = argv[++i];
    else if (a == "--quiet") quiet = true;
    else path = argv[i];
  }
  if (!path) { fprintf(stderr, "usage: air2ir3 [--chip 0x44070041] [--fc idx=v[,v]] [--fc-name name=v[,v]] [--nir] [--emit-nir] [--json f] [--variant f] [--quiet] fn.bc\n"); return 1; }
  setvbuf(stdout, nullptr, _IONBF, 0);

  // ir3 for the requested chip.
  glsl_type_singleton_init_or_ref();
  fd_dev_id dev_id = {}; dev_id.chip_id = chip;
  const struct fd_dev_info *info = fd_dev_info_raw(&dev_id);
  if (!info) die("chip id not known to this Mesa");
  ir3_compiler_options copts = {};
  // BINDING-ABI.md: FS bindless set 4 carries the framebuffer-fetch descriptors at
  // 32 + 32 - 1 - max_rts + rt (Mesa gallium ir3_screen_init / fd6_build_bindless_state).
  copts.bindless_fb_read_descriptor = ABI_FS_BINDLESS_SET;
  copts.bindless_fb_read_slot = ABI_FB_READ_SLOT;
  copts.lower_base_vertex = true;
  copts.push_ubo_with_preamble = true;
  copts.disable_cache = true;
  ir3_compiler *compiler = ir3_compiler_create(nullptr, &dev_id, info, &copts);

  AirFrontendResult R = air_frontend(path, o, ir3_get_compiler_options(compiler));
  nir_shader *nir = R.nir;
  mesa_shader_stage stage = R.stage;
  if (!quiet) {
    printf("== %s  (%s, triple %s)\n", R.function.c_str(), stage == MESA_SHADER_VERTEX ? "vertex" : stage == MESA_SHADER_FRAGMENT ? "fragment" : "kernel", R.triple.c_str());
    printf("   target: %s  gen %u (chip_id 0x%llx)\n", fd_dev_name(&dev_id), compiler->gen, (unsigned long long)chip);
    printf("%s", R.report.c_str());
  }
  if (emitNir) nir_print_shader(nir, stdout);

  nir_assign_io_var_locations(nir, nir_var_shader_in);
  nir_assign_io_var_locations(nir, nir_var_shader_out);
  if (stage == MESA_SHADER_COMPUTE) {
    nir_lower_compute_system_values_options csv = {};
    csv.has_base_workgroup_id = false;
    NIR_PASS(_, nir, nir_lower_compute_system_values, &csv);
  }
  ir3_nir_lower_io_vars_to_temporaries(nir);
  ir3_nir_lower_io(nir);
  ir3_shader_nir_options nopts = {};
  ir3_finalize_nir(compiler, &nopts, nir);
  if (dumpNir) nir_print_shader(nir, stdout);

  ir3_shader_options sopts = {};
  sopts.api_wavesize = IR3_SINGLE_OR_DOUBLE; sopts.real_wavesize = IR3_SINGLE_OR_DOUBLE;
  ir3_shader *shader = ir3_shader_from_nir(compiler, nir, &sopts);
  ir3_shader_key key = {};
  ir3_shader_variant *v = ir3_shader_create_variant(shader, &key, true);
  if (!v || !v->bin) die("ir3 compile failed");
  const struct ir3_const_state *cs = ir3_const_state(v);
  char stats[1024];
  snprintf(stats, sizeof stats,
           "{\"instrs\":%u,\"dwords\":%u,\"full_regs\":%d,\"half_regs\":%d,\"constlen\":%u,\"branchstack\":%u,"
           "\"nops\":%u,\"mov\":%u,\"cov\":%u,\"sstall\":%u,\"systall\":%u,\"ss\":%u,\"sy\":%u,\"loops\":%u,"
           "\"max_waves\":%d,\"double_threadsize\":%s,\"preamble_instrs\":%u,\"early_preamble\":%s,"
           "\"num_ubos\":%u,\"consts_ubo\":%d,\"driver_params_ubo\":%d,\"num_driver_params\":%u,\"constant_data_offset\":%u,"
           "\"binning_variant\":%s,\"fb_read\":%s,\"bindless_tex\":%s}",
           v->info.instrs_count, v->info.size / 4, v->info.max_reg + 1, v->info.max_half_reg + 1, v->constlen, v->branchstack,
           v->info.nops_count, v->info.mov_count, v->info.cov_count, v->info.sstall, v->info.systall, v->info.ss, v->info.sy, v->info.loops,
           v->info.max_waves, v->info.double_threadsize ? "true" : "false", v->info.preamble_instrs_count, v->info.early_preamble ? "true" : "false",
           cs->num_ubos, cs->consts_ubo.idx, cs->driver_params_ubo.idx, cs->num_driver_params, v->info.constant_data_offset,
           v->binning ? "true" : "false", v->fb_read ? "true" : "false", v->bindless_tex ? "true" : "false");
  printf("   ir3: %u instructions, %u dwords, full regs %d, half regs %d, constlen %u, branchstack %u\n",
         v->info.instrs_count, v->info.size / 4, v->info.max_reg + 1, v->info.max_half_reg + 1, v->constlen, v->branchstack);
  printf("   ir3-stats: %s\n", stats);
  if (!quiet) fputs(v->disasm_info.disasm ? v->disasm_info.disasm : "(no disasm)\n", stdout);

  if (variantOut) {
    struct blob blob; blob_init(&blob);
    ir3_store_variant(&blob, v);
    FILE *f = fopen(variantOut, "wb"); if (!f) die("cannot write variant");
    fwrite(blob.data, 1, blob.size, f); fclose(f); blob_finish(&blob);
  }
  if (jsonOut) {
    std::string inl = "[";   // ir3 input/output register assignment for the command-stream builder
    for (unsigned i = 0; i < v->inputs_count; i++) {
      if (inl.size() > 1) inl += ",";
      inl += "{\"slot\":" + std::to_string(v->inputs[i].slot) + ",\"regid\":" + std::to_string(v->inputs[i].regid) +
             ",\"compmask\":" + std::to_string(v->inputs[i].compmask) + ",\"inloc\":" + std::to_string(v->inputs[i].inloc) + "}";
    }
    inl += "]";
    std::string outl = "[";
    for (unsigned i = 0; i < v->outputs_count; i++) {
      if (outl.size() > 1) outl += ",";
      outl += "{\"slot\":" + std::to_string(v->outputs[i].slot) + ",\"regid\":" + std::to_string(v->outputs[i].regid) +
              ",\"half\":" + (v->outputs[i].half ? "true" : "false") + "}";
    }
    outl += "]";
    FILE *f = fopen(jsonOut, "w"); if (!f) die("cannot write json");
    fprintf(f, "{\"reflection\":%s,\"ir3\":{\"chip_id\":\"0x%llx\",\"gen\":%u,\"stats\":%s,\"inputs\":%s,\"outputs\":%s}}\n",
            air_reflection_json(R).c_str(), (unsigned long long)chip, compiler->gen, stats, inl.c_str(), outl.c_str());
    fclose(f);
  }
  fflush(stdout);
  return 0;
}
#endif
