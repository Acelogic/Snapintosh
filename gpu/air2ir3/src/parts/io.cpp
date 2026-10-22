/* SPDX-License-Identifier: MIT */

  // ---- IO ----
  static std::string baseName(glsl_base_type bt) {
    switch (bt) {
    case GLSL_TYPE_FLOAT: return "float"; case GLSL_TYPE_FLOAT16: return "half"; case GLSL_TYPE_UINT: return "uint";
    case GLSL_TYPE_INT: return "int"; case GLSL_TYPE_UINT16: return "ushort"; case GLSL_TYPE_BOOL: return "bool";
    default: return "other";
    }
  }
  nir_variable *mkvar(nir_variable_mode mode, Type *T, int loc, const char *nm, bool force32 = false) {
    std::vector<Type *> ts; flatten(T, ts);
    Type *E = ts[0];
    unsigned eb = force32 ? 32 : bits(E);
    glsl_base_type bt = E->isFloatingPointTy() ? (eb == 16 ? GLSL_TYPE_FLOAT16 : GLSL_TYPE_FLOAT)
                                               : (eb == 16 ? GLSL_TYPE_UINT16 : GLSL_TYPE_UINT);
    nir_variable *v = nir_variable_create(s, mode, glsl_vector_type(bt, ts.size()), nm);
    v->data.location = loc;
    return v;
  }
  // Evaluate a gating predicate: an implicit predicate global evaluated from the static initialiser,
  // or a function-constant initialiser global directly.
  int predValue(const std::string &g) {
    auto it = spec.implicitVals.find(g);
    if (it != spec.implicitVals.end()) return it->second != 0;
    int idx = fcIndexOfGlobal(g);
    if (idx >= 0) {
      for (auto &f : R.fcs) if (f.index == idx) return !f.value.empty() && f.value[0] != 0;
      return 0;
    }
    return -1;   // unknown
  }
  int locValue(const ArgInfo &a) {
    if (a.locGlobal.empty()) return a.location;
    auto it = spec.implicitVals.find(a.locGlobal);
    if (it == spec.implicitVals.end()) die("binding index expression " + a.locGlobal + " could not be evaluated from the function constants");
    return (int)it->second;
  }

  void setupArgs() {
    // Resolve gating, attribute index expressions and usage first.
    for (ArgInfo &a : outArgs) {
      if (a.gated) { int p = predValue(a.predGlobal); a.active = p != 0; }
      a.location = locValue(a);
    }
    for (ArgInfo &a : inArgs) {
      Argument *A = F->getArg(a.argno);
      a.used = !A->use_empty();
      if (a.gated) { int p = predValue(a.predGlobal); a.active = p < 0 ? a.used : p != 0; }
      if (a.active) a.location = locValue(a);
      if (a.used && !a.active) die("argument " + a.argName + " is used but its function-constant predicate is false");
    }
    // Varying slots: deterministic, sorted by name (BINDING-ABI.md section 4).  VS and FS are
    // linked by name, never by slot.
    std::set<std::string> names;
    if (stage == MESA_SHADER_VERTEX) { for (auto &a : outArgs) if (a.active && a.kind == "air.vertex_output") names.insert(a.name); }
    if (stage == MESA_SHADER_FRAGMENT) { for (auto &a : inArgs) if (a.active && a.kind == "air.fragment_input") names.insert(a.name); }
    for (auto &n : names) { int sl = varyingSlot.size(); varyingSlot[n] = sl; }
    if (varyingSlot.size() > 32) die("more than 32 varyings");

    // Outputs: return value (vertex outputs / render targets).
    Type *RT = F->getReturnType();
    std::vector<Type *> rts;
    if (auto *ST = dyn_cast<StructType>(RT)) for (Type *e : ST->elements()) rts.push_back(e);
    else if (!RT->isVoidTy()) rts.push_back(RT);
    if (rts.size() != outArgs.size()) die("output metadata does not match the return type");
    for (unsigned i = 0; i < outArgs.size(); i++) {
      ArgInfo &a = outArgs[i];
      if (!a.active) {                                 // function-constant-gated output switched off
        for (unsigned c = 0; c < nflat(rts[i]); c++) outs.push_back({nullptr, c});
        report += "  out  " + a.kind + " " + a.name + " (function constant off)\n";
        continue;
      }
      int loc;
      if (a.kind == "air.position") loc = VARYING_SLOT_POS;
      else if (a.kind == "air.vertex_output") loc = VARYING_SLOT_VAR0 + varyingSlot.at(a.name);
      else if (a.kind == "air.render_target") {
        if (a.location < 0 || a.location >= ABI_MAX_RTS) die("render target index " + std::to_string(a.location) + " out of range");
        loc = FRAG_RESULT_DATA0 + a.location;
      }
      else if (a.kind == "air.depth") { loc = FRAG_RESULT_DEPTH; R.writes_depth = true; }
      else if (a.kind == "air.point_size") { loc = VARYING_SLOT_PSIZ; R.writes_point_size = true; }
      else if (a.kind == "air.sample_mask") loc = FRAG_RESULT_SAMPLE_MASK;
      else die("output kind " + a.kind);
      bool rt = a.kind == "air.render_target";
      nir_variable *v = mkvar(nir_var_shader_out, rts[i], loc, a.kind.c_str(), rt || a.kind == "air.sample_mask");
      if (rt) {
        v->data.index = 0;
        AirRenderTarget t; t.index = a.location; t.comps = glsl_get_vector_elements(v->type);
        t.base = baseName(glsl_get_base_type(v->type)); t.written = true; R.render_targets.push_back(t);
      }
      if (a.kind == "air.vertex_output") {
        AirVarying vy; vy.name = a.name; vy.slot = varyingSlot.at(a.name); vy.comps = glsl_get_vector_elements(v->type);
        vy.bits = glsl_get_bit_size(v->type); vy.base = baseName(glsl_get_base_type(v->type)); vy.interp = a.interp; vy.sampling = a.sampling;
        R.varyings.push_back(vy);
      }
      for (unsigned c = 0; c < nflat(rts[i]); c++) outs.push_back({v, c});
      report += "  out  " + a.kind + " " + a.name + " -> location " + std::to_string(loc) + "\n";
    }
    // Sampler slots used by API sampler arguments, then constexpr samplers packed downward from
    // S#15 into the free slots (Metal: at most 16 samplers per function including constexpr ones).
    uint32_t apiMask = 0;
    for (auto &a : inArgs) if (a.active && a.kind == "air.sampler") {
      if (a.location < 0 || a.location >= ABI_MAX_SAMPLERS) die("sampler index " + std::to_string(a.location) + " >= 16");
      apiMask |= 1u << a.location;
    }
    {
      std::vector<GlobalVariable *> cs;
      for (GlobalVariable &G : M.globals())
        if (G.getName().starts_with("__air_sampler_state") && !G.use_empty()) cs.push_back(&G);
      std::sort(cs.begin(), cs.end(), [](GlobalVariable *x, GlobalVariable *y) { return x->getName() < y->getName(); });
      int next = ABI_MAX_SAMPLERS - 1;
      for (GlobalVariable *G : cs) {
        while (next >= 0 && (apiMask >> next) & 1) next--;
        if (next < 0) die("more than 16 samplers (API + constexpr) in one function");
        constSamplers[G] = next;
        R.constexpr_sampler_mask |= 1u << next;
        // Native Metal specialization may lower the two-word AIR sampler
        // array to its packed i64 state. Keep the same decoder and identity.
        Constant *initial = G->getInitializer();
        uint64_t w0 = 0, w1 = 0;
        if (auto *word = dyn_cast<ConstantInt>(initial)) {
          if (!word->getType()->isIntegerTy(64)) die("constexpr sampler scalar is not i64");
          w0 = word->getZExtValue();
        } else if (auto *array = dyn_cast<ConstantDataArray>(initial)) {
          if (!array->getElementType()->isIntegerTy(64) || !array->getNumElements() || array->getNumElements() > 2)
            die("constexpr sampler array must contain one or two i64 words");
          w0 = array->getElementAsInteger(0);
          if (array->getNumElements() > 1) w1 = array->getElementAsInteger(1);
        } else {
          die("constexpr sampler initialiser is not an i64 state or constant array");
        }
        AirBinding bd; bd.kind = "constexpr_sampler"; bd.slot = next; bd.arg_name = G->getName().str();
        bd.sampler_word = w0;
        // unique id: first 8 bytes (big-endian) of SHA-256("AIRSAMP1" || w0 || w1), little-endian words
        SHA256 h; uint8_t buf[24]; memcpy(buf, "AIRSAMP1", 8); memcpy(buf + 8, &bd.sampler_word, 8); memcpy(buf + 16, &w1, 8);
        h.update(ArrayRef<uint8_t>(buf, 24)); auto dg = h.final();
        for (int i = 0; i < 8; i++) bd.unique_id = (bd.unique_id << 8) | dg[i];
        air_sampler as; air_sampler_decode(bd.sampler_word, &as); air_sampler_a8xx(&as, bd.a8xx_desc);
        R.bindings.push_back(bd);
        char buf2[160]; snprintf(buf2, sizeof buf2, "  constexpr sampler %s = 0x%016llx -> S#%d (unique id 0x%016llx)\n",
                                 G->getName().str().c_str(), (unsigned long long)bd.sampler_word, next, (unsigned long long)bd.unique_id);
        report += buf2;
        next--;
      }
    }
    // Inputs.
    for (ArgInfo &a : inArgs) {
      Argument *A = F->getArg(a.argno);
      std::string line = "  in   #" + std::to_string(a.argno) + " " + a.kind;
      if (!a.active) { report += line + " (function constant off)\n"; continue; }
      if (a.kind == "air.vertex_input") {
        if (a.used) {
          nir_variable *v = mkvar(nir_var_shader_in, A->getType(), VERT_ATTRIB_GENERIC0 + a.location, "attr");
          vals[A] = coerce(split(nir_load_var(&b, v)), A->getType());
          AirAttribute at; at.index = a.location; at.comps = glsl_get_vector_elements(v->type); at.bits = glsl_get_bit_size(v->type);
          at.base = baseName(glsl_get_base_type(v->type)); R.attributes.push_back(at);
        }
        line += " attribute " + std::to_string(a.location);
      } else if (a.kind == "air.fragment_input") {
        nir_variable *v = mkvar(nir_var_shader_in, A->getType(), VARYING_SLOT_VAR0 + varyingSlot.at(a.name), a.name.c_str());
        v->data.interpolation = a.interp == "flat" ? INTERP_MODE_FLAT : a.interp == "no_perspective" ? INTERP_MODE_NOPERSPECTIVE : INTERP_MODE_SMOOTH;
        v->data.centroid = a.sampling == "centroid"; v->data.sample = a.sampling == "sample";
        if (a.used) vals[A] = split(nir_load_var(&b, v));
        AirVarying vy; vy.name = a.name; vy.slot = varyingSlot.at(a.name); vy.comps = glsl_get_vector_elements(v->type);
        vy.bits = glsl_get_bit_size(v->type); vy.base = baseName(glsl_get_base_type(v->type)); vy.interp = a.interp; vy.sampling = a.sampling;
        R.varyings.push_back(vy);
        line += " " + a.name + " varying slot " + std::to_string(vy.slot) + " " + a.interp;
      } else if (a.kind == "air.position" && stage == MESA_SHADER_FRAGMENT) {
        if (a.used) { vals[A] = coerce(split(nir_load_frag_coord(&b)), A->getType()); R.sysvals.push_back("frag_coord"); }
      } else if (a.kind == "air.render_target") {        // framebuffer fetch: read the colour attachment
        if (a.location < 0 || a.location >= ABI_MAX_RTS) die("framebuffer-fetch colour index " + std::to_string(a.location) + " out of range");
        if (a.used) {
          nir_variable *v = nullptr;
          for (auto &o : outs) if (o.first && o.first->data.location == (int)(FRAG_RESULT_DATA0 + a.location)) v = o.first;
          if (!v) {
            v = mkvar(nir_var_shader_out, A->getType(), FRAG_RESULT_DATA0 + a.location, "fbfetch", true);
            AirRenderTarget t; t.index = a.location; t.comps = glsl_get_vector_elements(v->type);
            t.base = baseName(glsl_get_base_type(v->type)); t.written = false; R.render_targets.push_back(t);
          }
          for (auto &t : R.render_targets) if (t.index == a.location) t.fb_fetch = true;
          v->data.fb_fetch_output = 1;
          s->info.fs.uses_fbfetch_output = true;
          R.uses_fb_fetch = true;
          vals[A] = coerce(split(nir_load_var(&b, v)), A->getType());
          AirBinding bd; bd.kind = "fb_fetch"; bd.metal_index = a.location; bd.slot = ABI_FB_READ_SLOT + a.location;
          bd.arg_name = a.argName; bd.type_name = a.typeName; R.bindings.push_back(bd);
        }
        line += " (framebuffer fetch, colour " + std::to_string(a.location) + (a.used ? "" : ", unused") + ")";
      } else if (a.kind == "air.buffer") {
        PtrVal p{};
        AirBinding bd; bd.metal_index = a.location; bd.arg_name = a.argName; bd.type_name = a.typeName; bd.used = a.used;
        if (a.location < 0 || a.location > 30) die("buffer index " + std::to_string(a.location) + " out of range");
        if (a.addrspace == 2) {
          p.kind = PtrVal::UBO; p.index = a.location; if (a.used) maxUbo = std::max(maxUbo, a.location);
          bd.kind = "ubo"; bd.slot = a.location;
        } else if (a.addrspace == 1) {   // device buffer: 64-bit GPU VA from the device-address table (UBO 31)
          p.kind = PtrVal::GLOBAL;
          if (a.used) {
            _nir_load_ubo_indices ix = {}; ix.align_mul = 8; ix.range = ~0u;
            p.addr64 = nir_pack_64_2x32(&b, _nir_build_load_ubo(&b, 2, 32, nir_imm_int(&b, ABI_DEVICE_VA_UBO), nir_imm_int(&b, 8 * a.location), ix));
            maxUbo = ABI_DEVICE_VA_UBO;
          }
          bd.kind = "device_buffer"; bd.slot = 8 * a.location;
        } else die("buffer in address space " + std::to_string(a.addrspace) + " (threadgroup/other) as an argument");
        p.off = nir_imm_int(&b, 0);
        ptrs[A] = p;
        R.bindings.push_back(bd);
        line += " buffer(" + std::to_string(a.location) + ") addrspace " + std::to_string(a.addrspace) +
                (a.addrspace == 2 ? " -> UBO" : " -> global (VA from UBO31)");
      } else if (a.kind == "air.texture") {
        if (a.location < 0 || a.location >= ABI_MAX_TEXTURES)
          die("texture index " + std::to_string(a.location) + " >= " + std::to_string(ABI_MAX_TEXTURES) + " (ABI v1 non-bindless T# limit)");
        tex[A] = a.location; line += " texture(" + std::to_string(a.location) + ")";
        AirBinding bd; bd.kind = "texture"; bd.metal_index = bd.slot = a.location; bd.arg_name = a.argName;
        bd.type_name = a.typeName; bd.access = a.access; bd.used = a.used; R.bindings.push_back(bd);
      } else if (a.kind == "air.sampler") {
        smp[A] = a.location; line += " sampler(" + std::to_string(a.location) + ")";
        AirBinding bd; bd.kind = "sampler"; bd.metal_index = bd.slot = a.location; bd.arg_name = a.argName;
        bd.used = a.used; R.bindings.push_back(bd);
      } else if (!a.used) { line += " (unused)"; }
      else if (a.kind == "air.vertex_id") { vals[A] = coerce({nir_load_vertex_id(&b)}, A->getType()); R.sysvals.push_back("vertex_id"); }
      else if (a.kind == "air.instance_id") { vals[A] = coerce({nir_load_instance_id(&b)}, A->getType()); R.sysvals.push_back("instance_id"); }
      else if (a.kind == "air.base_vertex") { vals[A] = coerce({nir_load_base_vertex(&b)}, A->getType()); R.sysvals.push_back("base_vertex"); }
      else if (a.kind == "air.base_instance") { vals[A] = coerce({nir_load_base_instance(&b)}, A->getType()); R.sysvals.push_back("base_instance"); }
      else if (a.kind == "air.front_facing") { vals[A] = {nir_load_front_face(&b, 1)}; R.sysvals.push_back("front_facing"); }
      else if (a.kind == "air.sample_id") { vals[A] = coerce({nir_load_sample_id(&b)}, A->getType()); R.sysvals.push_back("sample_id"); }
      else if (a.kind == "air.point_coord") {
        nir_variable *v = mkvar(nir_var_shader_in, A->getType(), VARYING_SLOT_PNTC, "pntc");
        vals[A] = coerce(split(nir_load_var(&b, v)), A->getType()); R.sysvals.push_back("point_coord");
      }
      else if (a.kind == "air.thread_position_in_grid") vals[A] = coerce(split(nir_load_global_invocation_id(&b, 32)), A->getType());
      else if (a.kind == "air.thread_position_in_threadgroup") vals[A] = coerce(split(nir_load_local_invocation_id(&b)), A->getType());
      else if (a.kind == "air.threadgroup_position_in_grid") vals[A] = coerce(split(nir_load_workgroup_id(&b)), A->getType());
      else if (a.kind == "air.threads_per_threadgroup") vals[A] = coerce(split(nir_load_workgroup_size(&b)), A->getType());
      else if (a.kind == "air.threadgroups_per_grid") vals[A] = coerce(split(nir_load_num_workgroups(&b)), A->getType());
      else if (a.kind == "air.threads_per_grid") vals[A] = coerce(split(nir_imul(&b, nir_load_num_workgroups(&b), nir_load_workgroup_size(&b))), A->getType());
      else if (a.kind == "air.thread_index_in_threadgroup") vals[A] = coerce({nir_load_local_invocation_index(&b)}, A->getType());
      else if (a.kind == "air.thread_index_in_simdgroup") vals[A] = coerce({nir_load_subgroup_invocation(&b)}, A->getType());
      else if (a.kind == "air.simdgroup_index_in_threadgroup") vals[A] = coerce({nir_load_subgroup_id(&b)}, A->getType());
      else if (a.kind == "air.simdgroups_per_threadgroup") vals[A] = coerce({nir_load_num_subgroups(&b)}, A->getType());
      else if (a.kind == "air.thread_index_in_quadgroup") vals[A] = coerce({nir_iand_imm(&b, nir_load_subgroup_invocation(&b), 3)}, A->getType());
      else die("input kind " + a.kind);
      report += line + "\n";
    }
  }
