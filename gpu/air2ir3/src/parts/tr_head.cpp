/* SPDX-License-Identifier: MIT */

// ------------------------------------------------------------- translator ---
struct PtrVal {
  enum Kind { UBO, GLOBAL, SHARED, SAMPLER_CONST, CONSTDATA, PRIVATE } kind;
  nir_variable *var = nullptr;     // PRIVATE: uint8 array
  int index = -1;                 // UBO index
  nir_def *addr64 = nullptr;      // GLOBAL base
  nir_def *off = nullptr;         // 32-bit byte offset
  const GlobalVariable *gv = nullptr;
};

struct Translator {
  Module &M; const DataLayout &DL; Function *F; mesa_shader_stage stage;
  AirFrontendResult &R; const SpecResult &spec;
  std::vector<ArgInfo> inArgs, outArgs;
  nir_shader *s = nullptr; nir_builder b;
  std::unordered_map<const Value *, std::vector<nir_def *>> vals;
  std::unordered_map<const Value *, PtrVal> ptrs;
  std::unordered_map<const Value *, int> tex, smp;
  std::map<const GlobalVariable *, int> constSamplers;       // constexpr sampler -> S# (assigned up front)
  std::map<const BasicBlock *, nir_block *> blocks;
  std::map<const PHINode *, nir_variable *> phiVars;
  std::vector<std::pair<nir_variable *, unsigned>> outs;     // per return scalar: var (nullptr = inactive), comp
  std::map<std::string, int> varyingSlot;                    // name -> VAR slot (sorted-name order)
  int maxUbo = -1;
  std::map<const GlobalVariable *, unsigned> sharedOff; unsigned sharedSize = 0;
  std::map<const GlobalVariable *, unsigned> constOff; std::vector<uint8_t> constData;
  std::map<const GlobalVariable *, nir_variable *> privVars;
  std::string report;

  Translator(Module &m, Function *f, mesa_shader_stage st, AirFrontendResult &r, const SpecResult &sp)
      : M(m), DL(m.getDataLayout()), F(f), stage(st), R(r), spec(sp) {}

  // ---- types ----
  static void flatten(Type *T, std::vector<Type *> &o) {
    if (auto *V = dyn_cast<FixedVectorType>(T)) { for (unsigned i = 0; i < V->getNumElements(); i++) o.push_back(V->getElementType()); }
    else if (auto *S = dyn_cast<StructType>(T)) { for (Type *E : S->elements()) flatten(E, o); }
    else if (auto *A = dyn_cast<ArrayType>(T)) { for (unsigned i = 0; i < A->getNumElements(); i++) flatten(A->getElementType(), o); }
    else o.push_back(T);
  }
  static unsigned nflat(Type *T) { std::vector<Type *> v; flatten(T, v); return v.size(); }
  static unsigned bits(Type *T) {
    if (T->isIntegerTy()) return T->getIntegerBitWidth();
    if (T->isHalfTy()) return 16; if (T->isFloatTy()) return 32; if (T->isDoubleTy()) return 64;
    if (T->isPointerTy()) return 64;
    die("unsupported scalar type");
  }
  // GLSL base type for a scalar LLVM type (bool, 8/16/32/64-bit int, half/float/double).
  // Prototype bug fixed: 64-bit values (i64 phis in prefix-sum kernels, 64-bit addresses) were
  // declared as 32-bit uint temporaries ("bit size mismatch comp 0 for phi i64").
  static glsl_base_type baseOf(Type *E) {
    unsigned bs = bits(E);
    if (bs == 1) return GLSL_TYPE_BOOL;
    if (E->isFloatingPointTy()) return bs == 16 ? GLSL_TYPE_FLOAT16 : bs == 64 ? GLSL_TYPE_DOUBLE : GLSL_TYPE_FLOAT;
    switch (bs) {
    case 8: return GLSL_TYPE_UINT8; case 16: return GLSL_TYPE_UINT16; case 32: return GLSL_TYPE_UINT;
    case 64: return GLSL_TYPE_UINT64;
    default: die("unsupported integer width " + std::to_string(bs));
    }
  }
