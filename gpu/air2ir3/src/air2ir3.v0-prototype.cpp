/* SPDX-License-Identifier: MIT */
// air2ir3 — prototype offline compiler: Metal AIR (LLVM bitcode from a .metallib)
//           -> NIR (Mesa) -> ir3 (Adreno A8xx / X2-90 ISA).
//
// Scope: proof of the AIR->NIR->ir3 path for WindowServer/SkyLight-class shaders
// (vertex + fragment, constant buffers, sampled textures, constexpr samplers,
// function constants, framebuffer fetch, CFG via unstructured NIR + goto lowering).
// Not a product: unsupported constructs abort with a clear message.
//
// Usage: air2ir3 [--chip 0x44070041] [--fc idx=val ...] [--vs-slots name,name] file.bc
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/CFG.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "nir.h"
#include "nir_builder.h"
#include "nir_builtin_builder.h"
#include "glsl_types.h"
#include "freedreno_dev_info.h"
#include "ir3_compiler.h"
#include "ir3_nir.h"
#include "ir3_shader.h"

using namespace llvm;

[[noreturn]] static void die(const std::string &m) {
  fprintf(stderr, "air2ir3: UNSUPPORTED/ERROR: %s\n", m.c_str());
  exit(2);
}
static std::string str(const Value *v) {
  std::string s; raw_string_ostream os(s); v->print(os); return s;
}

// ---------------------------------------------------------------- metadata --
struct ArgInfo {
  std::string kind;          // air.vertex_input, air.fragment_input, air.position,
                             // air.render_target, air.buffer, air.texture, air.sampler ...
  std::string name;          // user(...) / generated(...) varying name
  int location = -1;         // air.location_index / render target index
  int addrspace = -1;        // for buffers
  std::string interp = "perspective", sampling = "center";
  int fc_index = -1;         // argument is conditional on a function constant
};
static std::string mdstr(const Metadata *m) {
  if (auto *s = dyn_cast_or_null<MDString>(m)) return s->getString().str();
  return "";
}
static int mdint(const Metadata *m) {
  if (auto *c = dyn_cast_or_null<ConstantAsMetadata>(m))
    if (auto *ci = dyn_cast<ConstantInt>(c->getValue())) return (int)ci->getSExtValue();
  return -1;
}
static ArgInfo parseArg(const MDNode *n, bool isOutput) {
  ArgInfo a;
  unsigned i = isOutput ? 0 : 1;               // inputs start with the arg number
  if (i < n->getNumOperands()) a.kind = mdstr(n->getOperand(i));
  for (unsigned j = i + 1; j < n->getNumOperands(); j++) {
    std::string s = mdstr(n->getOperand(j));
    if (s == "air.location_index" && j + 1 < n->getNumOperands()) a.location = mdint(n->getOperand(j + 1));
    else if (s == "air.address_space") a.addrspace = mdint(n->getOperand(j + 1));
    else if (s == "air.perspective" || s == "air.no_perspective" || s == "air.flat") a.interp = s.substr(4);
    else if (s == "air.center" || s == "air.centroid" || s == "air.sample") a.sampling = s.substr(4);
    else if (s.rfind("user(", 0) == 0 || s.rfind("generated(", 0) == 0) a.name = s;
  }
  if (a.kind == "air.function_constant") {        // [idx, air.function_constant, !fc, <real kind>...]
    a.kind = mdstr(n->getOperand(i + 2));
    for (unsigned j = i + 3; j < n->getNumOperands(); j++) {
      std::string s = mdstr(n->getOperand(j));
      if (s == "air.location_index") a.location = mdint(n->getOperand(j + 1));
      if (s == "air.address_space") a.addrspace = mdint(n->getOperand(j + 1));
    }
  }
  if (a.kind == "air.render_target" && a.location < 0) a.location = mdint(n->getOperand(i + 1));
  return a;
}

// ----------------------------------------------------- LLVM-level preparation --
// 1) function-constant specialisation, 2) inline everything into the entry,
// 3) cleanup pipeline so the translator sees small SSA code.
static void specialize_and_inline(Module &M, Function *entry, const std::map<int, int64_t> &fc) {
  // Replace loads of "*.MTL_FC_INIT_<idx>_<ty>" constants with the chosen values.
  for (GlobalVariable &G : M.globals()) {
    if (G.getSection() != "air.fc_initializer") continue;
    StringRef nm = G.getName();
    size_t p = nm.find(".MTL_FC_INIT_");
    if (p == StringRef::npos) continue;
    int idx = std::atoi(nm.substr(p + 13).str().c_str());
    int64_t v = fc.count(idx) ? fc.at(idx) : 0;
    for (User *U : make_early_inc_range(G.users()))
      if (auto *LI = dyn_cast<LoadInst>(U)) {
        Type *T = LI->getType();
        Constant *C = T->isFloatingPointTy() ? ConstantFP::get(T, (double)v) : ConstantInt::get(T, v);
        LI->replaceAllUsesWith(C);
        LI->eraseFromParent();
      }
  }
  // is_function_constant_defined(@fc) -> whether the caller supplied a value; fold predicates.
  for (Function &Fn : M) {
    if (!Fn.isDeclaration()) continue;
    StringRef fn = Fn.getName();
    for (User *U : make_early_inc_range(Fn.users())) {
      auto *CI = dyn_cast<CallInst>(U); if (!CI) continue;
      if (fn == "air.is_function_constant_defined") {
        auto *G = dyn_cast<GlobalVariable>(CI->getArgOperand(0)->stripPointerCasts());
        int idx = -1; if (G) { size_t q = G->getName().find(".MTL_FC_INIT_"); if (q != StringRef::npos) idx = atoi(G->getName().substr(q + 13).str().c_str()); }
        CI->replaceAllUsesWith(ConstantInt::getBool(CI->getContext(), fc.count(idx) != 0)); CI->eraseFromParent();
      } else if (fn.starts_with("air.normalize_function_constant_predicate")) {
        if (auto *C = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          CI->replaceAllUsesWith(ConstantInt::get(CI->getType(), C->isZero() ? 0 : 1)); CI->eraseFromParent();
        }
      }
    }
  }
  // Let GlobalOpt evaluate the (now constant) static initialisers into global initialisers.
  {
    LoopAnalysisManager LAM0; FunctionAnalysisManager FAM0; CGSCCAnalysisManager CGAM0; ModuleAnalysisManager MAM0;
    PassBuilder PB0;
    PB0.registerModuleAnalyses(MAM0); PB0.registerCGSCCAnalyses(CGAM0); PB0.registerFunctionAnalyses(FAM0);
    PB0.registerLoopAnalyses(LAM0); PB0.crossRegisterProxies(LAM0, FAM0, CGAM0, MAM0);
    ModulePassManager MPM0;
    if (auto Err = PB0.parsePassPipeline(MPM0, "function(instcombine),globalopt")) die(toString(std::move(Err)));
    MPM0.run(M, MAM0);
  }
  // Run any remaining static initialisers (air.static_init) at the top of the entry point.
  if (GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors")) {
    if (auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer())) {
      IRBuilder<> B(&*entry->getEntryBlock().getFirstInsertionPt());
      for (Use &U : CA->operands())
        if (auto *CS = dyn_cast<ConstantStruct>(U.get()))
          if (auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()))
            B.CreateCall(Fn);
    }
  }
  for (Function &F : M)
    if (!F.isDeclaration() && &F != entry) {
      F.removeFnAttr(Attribute::NoInline);
      F.removeFnAttr(Attribute::OptimizeNone);
      F.addFnAttr(Attribute::AlwaysInline);
    }
  LoopAnalysisManager LAM; FunctionAnalysisManager FAM; CGSCCAnalysisManager CGAM; ModuleAnalysisManager MAM;
  PassBuilder PB;
  PB.registerModuleAnalyses(MAM); PB.registerCGSCCAnalyses(CGAM); PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM); PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
  ModulePassManager MPM;
  if (auto Err = PB.parsePassPipeline(MPM,
        "always-inline,function(sroa,early-cse<memssa>,instcombine,gvn,simplifycfg,instcombine,adce,simplifycfg)"))
    die(toString(std::move(Err)));
  MPM.run(M, MAM);
  // Function-constant shadows (_ZL<name>) are internal addrspace(2) globals written once by the
  // static initialiser. After inlining + GVN the loads are forwarded; forward any remaining
  // loads from the single constant store and drop the now-dead stores.
  bool changed = true;
  while (changed) {
    changed = false;
    for (GlobalVariable &G : M.globals()) {
      if (!G.hasLocalLinkage() || G.isConstant()) continue;
      SmallVector<StoreInst *, 4> stores; SmallVector<LoadInst *, 4> loads; bool other = false;
      for (User *U : G.users()) {
        if (auto *S = dyn_cast<StoreInst>(U)) stores.push_back(S);
        else if (auto *L = dyn_cast<LoadInst>(U)) loads.push_back(L);
        else if (!isa<Constant>(U)) other = true;
      }
      if (other || stores.empty()) continue;
      if (!loads.empty()) {
        bool same = isa<Constant>(stores[0]->getValueOperand());
        for (StoreInst *S : stores) same = same && S->getValueOperand() == stores[0]->getValueOperand();
        if (!same) continue;   // all stores write the same constant (the ctor can be duplicated by simplifycfg)
        for (LoadInst *L : loads)
          if (L->getType() == stores[0]->getValueOperand()->getType()) { L->replaceAllUsesWith(stores[0]->getValueOperand()); L->eraseFromParent(); }
      }
      bool anyLoad = false; for (User *U : G.users()) if (isa<LoadInst>(U)) anyLoad = true;
      if (!anyLoad) { for (StoreInst *S : stores) S->eraseFromParent(); changed = true; }
    }
  }
  {
    ModulePassManager MPM2;
    if (auto Err = PB.parsePassPipeline(MPM2, "function(instcombine,simplifycfg,adce,simplifycfg)")) die(toString(std::move(Err)));
    MPM2.run(M, MAM);
  }
  if (verifyModule(M, &errs())) die("module failed verification after specialisation");
}

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
  nir_shader *s = nullptr; nir_builder b;
  std::unordered_map<const Value *, std::vector<nir_def *>> vals;
  std::unordered_map<const Value *, PtrVal> ptrs;
  std::unordered_map<const Value *, int> tex, smp;
  std::map<const GlobalVariable *, int> constSamplers;       // constexpr sampler -> slot
  std::map<const BasicBlock *, nir_block *> blocks;
  std::map<const PHINode *, nir_variable *> phiVars;
  std::vector<std::pair<nir_variable *, unsigned>> outs;     // per return scalar: var, comp
  std::map<std::string, int> varyingSlot;                    // name -> VAR slot
  int maxUbo = -1;
  std::map<const GlobalVariable *, unsigned> sharedOff; unsigned sharedSize = 0;
  std::map<const GlobalVariable *, unsigned> constOff; std::vector<uint8_t> constData;
  std::map<const GlobalVariable *, nir_variable *> privVars;
  std::string report;

  Translator(Module &m, Function *f, mesa_shader_stage st) : M(m), DL(m.getDataLayout()), F(f), stage(st) {}

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

  // ---- values ----
  std::vector<nir_def *> cst(Constant *C) {
    std::vector<nir_def *> r;
    Type *T = C->getType();
    if (isa<UndefValue>(C) || isa<PoisonValue>(C) || isa<ConstantAggregateZero>(C) || isa<ConstantPointerNull>(C)) {
      std::vector<Type *> ts; flatten(T, ts);
      for (Type *e : ts) r.push_back(isa<ConstantAggregateZero>(C) || isa<ConstantPointerNull>(C)
                                       ? nir_imm_zero(&b, 1, bits(e)) : nir_undef(&b, 1, bits(e)));
      return r;
    }
    if (auto *CF = dyn_cast<ConstantFP>(C)) { r.push_back(nir_imm_floatN_t(&b, CF->getValueAPF().convertToDouble(), bits(T))); return r; }
    if (auto *CI = dyn_cast<ConstantInt>(C)) {
      if (bits(T) == 1) r.push_back(nir_imm_bool(&b, CI->isOne()));
      else r.push_back(nir_imm_intN_t(&b, CI->getSExtValue(), bits(T)));
      return r;
    }
    if (auto *CDS = dyn_cast<ConstantDataSequential>(C)) {
      for (unsigned i = 0; i < CDS->getNumElements(); i++) { auto v = cst(CDS->getElementAsConstant(i)); r.insert(r.end(), v.begin(), v.end()); }
      return r;
    }
    if (isa<ConstantVector>(C) || isa<ConstantStruct>(C) || isa<ConstantArray>(C)) {
      for (Use &U : C->operands()) { auto v = cst(cast<Constant>(U.get())); r.insert(r.end(), v.begin(), v.end()); }
      return r;
    }
    die("unsupported constant: " + str(C));
  }
  std::vector<nir_def *> get(Value *V) {
    auto it = vals.find(V);
    if (it != vals.end()) return it->second;
    if (auto *C = dyn_cast<Constant>(V)) if (!isa<GlobalValue>(C)) return cst(C);
    die("value not translated: " + str(V));
  }
  nir_def *get1(Value *V) { auto v = get(V); if (v.size() != 1) die("expected scalar: " + str(V)); return v[0]; }
  nir_def *vec(const std::vector<nir_def *> &c) { return nir_vec(&b, const_cast<nir_def **>(c.data()), c.size()); }
  std::vector<nir_def *> split(nir_def *d) { std::vector<nir_def *> r; for (unsigned i = 0; i < d->num_components; i++) r.push_back(nir_channel(&b, d, i)); return r; }

  // Serialise a constant initialiser to bytes (little endian, DataLayout offsets).
  void bytesOf(Constant *C, std::vector<uint8_t> &o, size_t at) {
    Type *T = C->getType();
    if (isa<ConstantAggregateZero>(C) || isa<UndefValue>(C) || isa<ConstantPointerNull>(C)) return;
    if (auto *CI = dyn_cast<ConstantInt>(C)) { APInt v = CI->getValue(); unsigned n = (T->getIntegerBitWidth() + 7) / 8;
      for (unsigned i = 0; i < n; i++) o[at + i] = (uint8_t)v.extractBitsAsZExtValue(std::min(8u, T->getIntegerBitWidth() - i * 8), i * 8); return; }
    if (auto *CF = dyn_cast<ConstantFP>(C)) { APInt v = CF->getValueAPF().bitcastToAPInt(); unsigned n = v.getBitWidth() / 8;
      for (unsigned i = 0; i < n; i++) o[at + i] = (uint8_t)v.extractBitsAsZExtValue(8, i * 8); return; }
    if (auto *CDS = dyn_cast<ConstantDataSequential>(C)) { StringRef raw = CDS->getRawDataValues();
      uint64_t es = DL.getTypeAllocSize(CDS->getElementType());
      for (unsigned i = 0; i < CDS->getNumElements(); i++) memcpy(&o[at + i * es], raw.data() + i * CDS->getElementByteSize(), CDS->getElementByteSize());
      return; }
    if (auto *CS = dyn_cast<ConstantStruct>(C)) { const StructLayout *SL = DL.getStructLayout(CS->getType());
      for (unsigned i = 0; i < CS->getNumOperands(); i++) bytesOf(CS->getOperand(i), o, at + SL->getElementOffset(i)); return; }
    if (isa<ConstantArray>(C) || isa<ConstantVector>(C)) { Type *E = isa<ArrayType>(T) ? T->getArrayElementType() : cast<VectorType>(T)->getElementType();
      uint64_t es = DL.getTypeAllocSize(E);
      for (unsigned i = 0; i < C->getNumOperands(); i++) bytesOf(cast<Constant>(C->getOperand(i)), o, at + i * es); return; }
    die("cannot serialise initialiser: " + str(C));
  }

  // ---- pointers ----
  PtrVal ptr(Value *V) {
    auto it = ptrs.find(V);
    if (it != ptrs.end()) return it->second;
    if (auto *GV = dyn_cast<GlobalVariable>(V)) {
      if (GV->getName().starts_with("__air_sampler_state")) { PtrVal p{PtrVal::SAMPLER_CONST}; p.gv = GV; return p; }
      if (GV->getAddressSpace() == 3) {             // threadgroup (static) -> shared memory
        auto it2 = sharedOff.find(GV);
        if (it2 == sharedOff.end()) {
          unsigned al = std::max<unsigned>(16, GV->getAlign() ? GV->getAlign()->value() : 16);
          sharedSize = (sharedSize + al - 1) & ~(al - 1);
          it2 = sharedOff.emplace(GV, sharedSize).first;
          sharedSize += DL.getTypeAllocSize(GV->getValueType());
        }
        PtrVal p{PtrVal::SHARED}; p.off = nir_imm_int(&b, it2->second); return p;
      }
      if (GV->hasInitializer() && GV->isConstant()) {      // constant table -> shader constant data (ir3 const UBO)
        auto it2 = constOff.find(GV);
        if (it2 == constOff.end()) {
          size_t at = (constData.size() + 15) & ~size_t(15); uint64_t sz = DL.getTypeAllocSize(GV->getValueType());
          constData.resize(at + sz, 0); bytesOf(GV->getInitializer(), constData, at);
          it2 = constOff.emplace(GV, at).first;
          report += "  constant table " + GV->getName().str() + " (" + std::to_string(sz) + " bytes) -> constant data @" + std::to_string(at) + "\n";
        }
        PtrVal p{PtrVal::CONSTDATA}; p.off = nir_imm_int(&b, it2->second); return p;
      }
      if (GV->hasInitializer() && GV->hasLocalLinkage()) {  // mutable per-invocation state (fc shadows, statics)
        auto it2 = privVars.find(GV);
        if (it2 == privVars.end()) {
          uint64_t sz = DL.getTypeAllocSize(GV->getValueType());
          nir_variable *v = nir_local_variable_create(b.impl, glsl_array_type(glsl_uint8_t_type(), sz, 1), GV->getName().str().c_str());
          std::vector<uint8_t> init(sz, 0); bytesOf(GV->getInitializer(), init, 0);
          nir_builder ib = nir_builder_at(nir_before_impl(b.impl));
          for (uint64_t i = 0; i < sz; i++)
            nir_store_deref(&ib, nir_build_deref_array_imm(&ib, nir_build_deref_var(&ib, v), i), nir_imm_intN_t(&ib, init[i], 8), 1);
          it2 = privVars.emplace(GV, v).first;
        }
        PtrVal p{PtrVal::PRIVATE}; p.var = it2->second; p.off = nir_imm_int(&b, 0); return p;
      }
      die("global variable access not supported: " + GV->getName().str());
    }
    if (auto *GEP = dyn_cast<GEPOperator>(V)) {
      PtrVal p = ptr(GEP->getPointerOperand());
      unsigned bw = DL.getIndexTypeSizeInBits(GEP->getType());
      APInt constOff(bw, 0);
      SmallMapVector<Value *, APInt, 4> varOffs;
      if (!GEP->collectOffset(DL, bw, varOffs, constOff)) die("GEP offset: " + str(V));
      nir_def *o = nir_iadd_imm(&b, p.off, (int64_t)constOff.getSExtValue());
      for (auto &kv : varOffs) {
        nir_def *iv = get1(kv.first);
        iv = iv->bit_size == 32 ? iv : nir_i2i32(&b, iv);
        o = nir_iadd(&b, o, nir_imul_imm(&b, iv, kv.second.getSExtValue()));
      }
      p.off = o; ptrs[V] = p; return p;
    }
    if (auto *C = dyn_cast<ConstantExpr>(V)) if (C->getOpcode() == Instruction::AddrSpaceCast || C->getOpcode() == Instruction::BitCast) return ptr(C->getOperand(0));
    die("unsupported pointer: " + str(V));
  }
  void loadScalars(const PtrVal &p, Type *T, int64_t extra, unsigned align, std::vector<nir_def *> &out) {
    if (auto *S = dyn_cast<StructType>(T)) {
      const StructLayout *SL = DL.getStructLayout(S);
      for (unsigned i = 0; i < S->getNumElements(); i++) loadScalars(p, S->getElementType(i), extra + SL->getElementOffset(i), 4, out);
      return;
    }
    if (auto *A = dyn_cast<ArrayType>(T)) {
      uint64_t es = DL.getTypeAllocSize(A->getElementType());
      for (unsigned i = 0; i < A->getNumElements(); i++) loadScalars(p, A->getElementType(), extra + i * es, 4, out);
      return;
    }
    Type *E = T->getScalarType();
    unsigned n = isa<FixedVectorType>(T) ? cast<FixedVectorType>(T)->getNumElements() : 1;
    unsigned bs = bits(E);
    nir_def *off = nir_iadd_imm(&b, p.off, extra);
    if (bs < 16 && (p.kind == PtrVal::PRIVATE)) {
      for (unsigned i = 0; i < n; i++) {
        nir_def *byte = load(p, nir_iadd_imm(&b, off, i), 1, 8, 1);
        out.push_back(bs == 1 ? nir_ine_imm(&b, byte, 0) : byte);
      }
      return;
    }
    if (bs < 16) {                                    // bool / i8: load the containing dword, extract bytes
      for (unsigned i = 0; i < n; i++) {
        nir_def *o = nir_iadd_imm(&b, off, i);
        nir_def *dw = load(p, nir_iand_imm(&b, o, ~3u), 1, 32, 4);
        nir_def *byte = nir_ubitfield_extract(&b, dw, nir_imul_imm(&b, nir_iand_imm(&b, o, 3), 8), nir_imm_int(&b, 8));
        out.push_back(bs == 1 ? nir_ine_imm(&b, byte, 0) : nir_u2uN(&b, byte, bs));
      }
      return;
    }
    nir_def *v = load(p, off, n, bs, std::max(align, bs / 8));
    for (unsigned i = 0; i < n; i++) out.push_back(nir_channel(&b, v, i));
  }
  nir_def *load(const PtrVal &p, nir_def *off, unsigned n, unsigned bs, unsigned align) {
    if (p.kind == PtrVal::UBO) {
      _nir_load_ubo_indices ix = {}; ix.align_mul = align; ix.align_offset = 0; ix.range_base = 0; ix.range = ~0u;
      return _nir_build_load_ubo(&b, n, bs, nir_imm_int(&b, p.index), off, ix);
    }
    if (p.kind == PtrVal::GLOBAL) {
      _nir_load_global_indices ix = {}; ix.align_mul = align; ix.align_offset = 0;
      return _nir_build_load_global(&b, n, bs, nir_iadd(&b, p.addr64, nir_u2u64(&b, off)), ix);
    }
    if (p.kind == PtrVal::CONSTDATA) {
      _nir_load_constant_indices ix = {}; ix.base = 0; ix.range = ~0u; ix.align_mul = align;
      return _nir_build_load_constant(&b, n, bs, off, ix);
    }
    if (p.kind == PtrVal::PRIVATE) {                 // byte-granular private storage
      std::vector<nir_def *> by;
      for (unsigned i = 0; i < n * bs / 8; i++)
        by.push_back(nir_load_deref(&b, nir_build_deref_array(&b, nir_build_deref_var(&b, p.var), nir_iadd_imm(&b, off, i))));
      return nir_extract_bits(&b, by.data(), by.size(), 0, n, bs);
    }
    if (p.kind == PtrVal::SHARED) {
      _nir_load_shared_indices ix = {}; ix.align_mul = align; ix.align_offset = 0;
      return _nir_build_load_shared(&b, n, bs, off, ix);
    }
    die("load from unsupported pointer kind");
  }

  void store(const PtrVal &p, nir_def *off, nir_def *v, unsigned align) {
    if (p.kind == PtrVal::GLOBAL) {
      _nir_store_global_indices ix = {}; ix.write_mask = (1u << v->num_components) - 1; ix.align_mul = align;
      _nir_build_store_global(&b, v, nir_iadd(&b, p.addr64, nir_u2u64(&b, off)), ix); return;
    }
    if (p.kind == PtrVal::SHARED) {
      _nir_store_shared_indices ix = {}; ix.write_mask = (1u << v->num_components) - 1; ix.align_mul = align;
      _nir_build_store_shared(&b, v, off, ix); return;
    }
    if (p.kind == PtrVal::PRIVATE) {
      nir_def *by = nir_extract_bits(&b, &v, 1, 0, v->num_components * v->bit_size / 8, 8);
      for (unsigned i = 0; i < by->num_components; i++)
        nir_store_deref(&b, nir_build_deref_array(&b, nir_build_deref_var(&b, p.var), nir_iadd_imm(&b, off, i)), nir_channel(&b, by, i), 1);
      return;
    }
    die("store to read-only (constant address space) pointer");
  }
  void storeScalars(const PtrVal &p, Type *T, const std::vector<nir_def *> &v, unsigned &idx, int64_t extra, unsigned align) {
    if (auto *S = dyn_cast<StructType>(T)) { const StructLayout *SL = DL.getStructLayout(S);
      for (unsigned i = 0; i < S->getNumElements(); i++) storeScalars(p, S->getElementType(i), v, idx, extra + SL->getElementOffset(i), 4); return; }
    if (auto *A = dyn_cast<ArrayType>(T)) { uint64_t es = DL.getTypeAllocSize(A->getElementType());
      for (unsigned i = 0; i < A->getNumElements(); i++) storeScalars(p, A->getElementType(), v, idx, extra + i * es, 4); return; }
    unsigned n = isa<FixedVectorType>(T) ? cast<FixedVectorType>(T)->getNumElements() : 1;
    std::vector<nir_def *> c(v.begin() + idx, v.begin() + idx + n); idx += n;
    for (auto &d : c) if (d->bit_size == 1) d = nir_b2i8(&b, d);
    store(p, nir_iadd_imm(&b, p.off, extra), vec(c), std::max<unsigned>(align, c[0]->bit_size / 8));
  }
  // Convert loaded/system values to the bit sizes of the LLVM argument type.
  std::vector<nir_def *> coerce(std::vector<nir_def *> v, Type *T) {
    std::vector<Type *> ts; flatten(T, ts);
    if (v.size() > ts.size()) v.resize(ts.size());
    for (unsigned i = 0; i < v.size(); i++) {
      unsigned bs = bits(ts[i]);
      if (v[i]->bit_size == bs) continue;
      v[i] = ts[i]->isFloatingPointTy() ? nir_f2fN(&b, v[i], bs) : nir_u2uN(&b, v[i], bs);
    }
    return v;
  }

  // ---- IO ----
  int slotFor(const std::string &name) {
    auto it = varyingSlot.find(name);
    if (it != varyingSlot.end()) return it->second;
    int s = varyingSlot.size(); varyingSlot[name] = s; return s;
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

  void setupArgs(const MDNode *inputs, const MDNode *outputs) {
    // Outputs: return value (vertex outputs / render targets).
    Type *RT = F->getReturnType();
    std::vector<Type *> rts;
    if (auto *ST = dyn_cast<StructType>(RT)) for (Type *e : ST->elements()) rts.push_back(e);
    else if (!RT->isVoidTy()) rts.push_back(RT);
    for (unsigned i = 0; outputs && i < outputs->getNumOperands(); i++) {
      ArgInfo a = parseArg(cast<MDNode>(outputs->getOperand(i)), true);
      int loc;
      if (a.kind == "air.position") loc = VARYING_SLOT_POS;
      else if (a.kind == "air.vertex_output") loc = VARYING_SLOT_VAR0 + slotFor(a.name);
      else if (a.kind == "air.render_target") loc = FRAG_RESULT_DATA0 + a.location;
      else if (a.kind == "air.depth") loc = FRAG_RESULT_DEPTH;
      else if (a.kind == "air.point_size") loc = VARYING_SLOT_PSIZ;
      else die("output kind " + a.kind);
      nir_variable *v = mkvar(nir_var_shader_out, rts[i], loc, a.kind.c_str(), a.kind == "air.render_target");
      if (a.kind == "air.render_target") v->data.index = 0;
      for (unsigned c = 0; c < nflat(rts[i]); c++) outs.push_back({v, c});
      report += "  out  " + a.kind + " " + a.name + " -> location " + std::to_string(loc) + "\n";
    }
    // Inputs.
    for (unsigned i = 0; inputs && i < inputs->getNumOperands(); i++) {
      const MDNode *n = cast<MDNode>(inputs->getOperand(i));
      int argno = mdint(n->getOperand(0));
      Argument *A = F->getArg(argno);
      ArgInfo a = parseArg(n, false);
      std::string line = "  in   #" + std::to_string(argno) + " " + a.kind;
      if (a.kind == "air.vertex_input") {
        nir_variable *v = mkvar(nir_var_shader_in, A->getType(), VERT_ATTRIB_GENERIC0 + a.location, "attr");
        vals[A] = split(nir_load_var(&b, v));
        line += " attribute " + std::to_string(a.location);
      } else if (a.kind == "air.fragment_input") {
        nir_variable *v = mkvar(nir_var_shader_in, A->getType(), VARYING_SLOT_VAR0 + slotFor(a.name), a.name.c_str());
        v->data.interpolation = a.interp == "flat" ? INTERP_MODE_FLAT : a.interp == "no_perspective" ? INTERP_MODE_NOPERSPECTIVE : INTERP_MODE_SMOOTH;
        v->data.centroid = a.sampling == "centroid"; v->data.sample = a.sampling == "sample";
        vals[A] = split(nir_load_var(&b, v));
        line += " " + a.name + " varying slot " + std::to_string(v->data.location - VARYING_SLOT_VAR0) + " " + a.interp;
      } else if (a.kind == "air.position" && stage == MESA_SHADER_FRAGMENT) {
        vals[A] = coerce(split(nir_load_frag_coord(&b)), A->getType());
      } else if (a.kind == "air.render_target") {        // framebuffer fetch: read the colour attachment
        nir_variable *v = nullptr;
        for (auto &o : outs) if (o.first->data.location == (int)(FRAG_RESULT_DATA0 + a.location)) v = o.first;
        if (!v) v = mkvar(nir_var_shader_out, A->getType(), FRAG_RESULT_DATA0 + a.location, "fbfetch", true);
        v->data.fb_fetch_output = 1;
        s->info.fs.uses_fbfetch_output = true;
        vals[A] = coerce(split(nir_load_var(&b, v)), A->getType());
        line += " (framebuffer fetch, colour " + std::to_string(a.location) + ")";
      } else if (a.kind == "air.buffer") {
        PtrVal p{};
        if (a.addrspace == 2) { p.kind = PtrVal::UBO; p.index = a.location; maxUbo = std::max(maxUbo, a.location); }
        else {                     // device buffer: 64-bit GPU VA from the driver's argument-address table (UBO 31)
          p.kind = PtrVal::GLOBAL;
          _nir_load_ubo_indices ix = {}; ix.align_mul = 8; ix.range = ~0u;
          p.addr64 = nir_pack_64_2x32(&b, _nir_build_load_ubo(&b, 2, 32, nir_imm_int(&b, 31), nir_imm_int(&b, 8 * a.location), ix));
          maxUbo = 31;
        }
        p.off = nir_imm_int(&b, 0);
        ptrs[A] = p;
        line += " buffer(" + std::to_string(a.location) + ") addrspace " + std::to_string(a.addrspace) +
                (a.addrspace == 2 ? " -> UBO" : " -> global (VA from UBO31)");
      } else if (a.kind == "air.texture") {
        tex[A] = a.location; line += " texture(" + std::to_string(a.location) + ")";
      } else if (a.kind == "air.sampler") {
        smp[A] = a.location; line += " sampler(" + std::to_string(a.location) + ")";
      } else if (a.kind == "air.vertex_id") { vals[A] = coerce({nir_load_vertex_id(&b)}, A->getType()); }
      else if (a.kind == "air.instance_id") { vals[A] = coerce({nir_load_instance_id(&b)}, A->getType()); }
      else if (a.kind == "air.front_facing") { vals[A] = {nir_load_front_face(&b, 1)}; }
      else if (a.kind == "air.point_coord") {
        nir_variable *v = mkvar(nir_var_shader_in, A->getType(), VARYING_SLOT_PNTC, "pntc");
        vals[A] = coerce(split(nir_load_var(&b, v)), A->getType());
      }
      else if (a.kind == "air.thread_position_in_grid") vals[A] = coerce(split(nir_load_global_invocation_id(&b, 32)), A->getType());
      else if (a.kind == "air.thread_position_in_threadgroup") vals[A] = coerce(split(nir_load_local_invocation_id(&b)), A->getType());
      else if (a.kind == "air.threadgroup_position_in_grid") vals[A] = coerce(split(nir_load_workgroup_id(&b)), A->getType());
      else if (a.kind == "air.threads_per_threadgroup") vals[A] = coerce(split(nir_load_workgroup_size(&b)), A->getType());
      else if (a.kind == "air.threadgroups_per_grid") vals[A] = coerce(split(nir_load_num_workgroups(&b)), A->getType());
      else if (a.kind == "air.thread_index_in_threadgroup") vals[A] = coerce({nir_load_local_invocation_index(&b)}, A->getType());
      else if (a.kind == "air.thread_index_in_simdgroup") vals[A] = coerce({nir_load_subgroup_invocation(&b)}, A->getType());
      else if (a.kind == "air.simdgroup_index_in_threadgroup") vals[A] = coerce({nir_load_subgroup_id(&b)}, A->getType());
      else if (a.kind == "air.simdgroups_per_threadgroup") vals[A] = coerce({nir_load_num_subgroups(&b)}, A->getType());
      else if (a.kind == "air.thread_index_in_quadgroup") vals[A] = coerce({nir_iand_imm(&b, nir_load_subgroup_invocation(&b), 3)}, A->getType());
      else die("input kind " + a.kind);
      report += line + "\n";
    }
  }

  // ---- texture ops ----
  int texOf(Value *V) { auto it = tex.find(V); if (it == tex.end()) die("texture operand not an argument"); return it->second; }
  int smpOf(Value *V) {
    auto it = smp.find(V); if (it != smp.end()) return it->second;
    if (auto *CI = dyn_cast<CallInst>(V)) if (CI->getCalledFunction() && CI->getCalledFunction()->getName().starts_with("air.get_read_sampler")) return -1;
    if (auto *GV = dyn_cast<GlobalVariable>(V->stripPointerCasts())) {
      auto c = constSamplers.find(GV); if (c != constSamplers.end()) return c->second;
      int slot = 16 + constSamplers.size();          // constexpr samplers live after the 16 API slots
      constSamplers[GV] = slot;
      auto *CA = cast<ConstantDataArray>(GV->getInitializer());
      char buf[128]; snprintf(buf, sizeof buf, "  constexpr sampler %s = 0x%016llx -> sampler slot %d\n",
                              GV->getName().str().c_str(), (unsigned long long)CA->getElementAsInteger(0), slot);
      report += buf;
      return slot;
    }
    die("sampler operand");
  }
  std::vector<nir_def *> texop(nir_texop op, glsl_sampler_dim dim, bool array, int t, int sm, nir_def *coord,
                               nir_def *lod, nir_def *bias, nir_def *offset, nir_def *minlod,
                               nir_def *ddx, nir_def *ddy, unsigned bs, nir_alu_type dt, unsigned ncomp = 4) {
    std::vector<std::pair<nir_tex_src_type, nir_def *>> srcs;
    if (coord) srcs.push_back({nir_tex_src_coord, coord});
    if (lod) srcs.push_back({nir_tex_src_lod, lod});
    if (bias) srcs.push_back({nir_tex_src_bias, bias});
    if (offset) srcs.push_back({nir_tex_src_offset, offset});
    if (minlod) srcs.push_back({nir_tex_src_min_lod, minlod});
    if (ddx) srcs.push_back({nir_tex_src_ddx, ddx});
    if (ddy) srcs.push_back({nir_tex_src_ddy, ddy});
    nir_tex_instr *ti = nir_tex_instr_create(s, srcs.size());
    ti->op = op; ti->sampler_dim = dim; ti->is_array = array; ti->dest_type = dt;
    ti->texture_index = t; ti->sampler_index = sm < 0 ? 0 : sm;
    ti->coord_components = coord ? coord->num_components : 0;
    for (unsigned i = 0; i < srcs.size(); i++) ti->src[i] = nir_tex_src_for_ssa(srcs[i].first, srcs[i].second);
    nir_def_init(&ti->instr, &ti->def, ncomp, bs);
    nir_builder_instr_insert(&b, &ti->instr);
    s->info.num_textures = std::max<unsigned>(s->info.num_textures, t + 1);
    return split(&ti->def);
  }
  bool isZeroConst(Value *v) { auto *c = dyn_cast<Constant>(v); return c && c->isNullValue(); }

  // ---- AIR intrinsic calls ----
  std::vector<nir_def *> callAir(CallInst *CI) {
    std::string nm = CI->getCalledFunction()->getName().str();
    auto A = [&](unsigned i) { return get(CI->getArgOperand(i)); };
    auto A1 = [&](unsigned i) { return get1(CI->getArgOperand(i)); };
    Type *RT = CI->getType();
    unsigned n = isa<StructType>(RT) || RT->isVoidTy() ? 1 : nflat(RT);
    auto starts = [&](const char *p) { return nm.rfind(p, 0) == 0; };
    auto perComp = [&](auto fn, unsigned nargs) {
      std::vector<std::vector<nir_def *>> in; for (unsigned i = 0; i < nargs; i++) in.push_back(A(i));
      std::vector<nir_def *> r;
      for (unsigned c = 0; c < n; c++) {
        auto pick = [&](unsigned i) { return in[i].size() == 1 ? in[i][0] : in[i][c]; };
        r.push_back(fn(pick));
      }
      return r;
    };
    auto base = [&](const std::string &x) { std::string p = "air." + x + "."; return nm.rfind(p, 0) == 0 || nm == "air." + x; };
#define UN(name, expr) if (base(name) || base("fast_" name)) return perComp([&](auto p) { nir_def *x = p(0); return expr; }, 1);
#define BIN(name, expr) if (base(name) || base("fast_" name)) return perComp([&](auto p) { nir_def *x = p(0), *y = p(1); return expr; }, 2);
    UN("sqrt", nir_fsqrt(&b, x)) UN("rsqrt", nir_frsq(&b, x)) UN("fabs", nir_fabs(&b, x))
    UN("floor", nir_ffloor(&b, x)) UN("ceil", nir_fceil(&b, x)) UN("fract", nir_ffract(&b, x))
    UN("trunc", nir_ftrunc(&b, x)) UN("rint", nir_fround_even(&b, x))
    UN("saturate", nir_fsat(&b, x)) UN("log2", nir_flog2(&b, x)) UN("exp2", nir_fexp2(&b, x))
    UN("log", nir_fmul_imm(&b, nir_flog2(&b, x), 0.69314718055994530942))
    UN("exp", nir_fexp2(&b, nir_fmul_imm(&b, x, 1.44269504088896340736)))
    UN("sin", nir_fsin(&b, x)) UN("cos", nir_fcos(&b, x)) UN("sign", nir_fsign(&b, x))
    UN("dfdx", nir_ddx(&b, x)) UN("dfdy", nir_ddy(&b, x))
    UN("fwidth", nir_fadd(&b, nir_fabs(&b, nir_ddx(&b, x)), nir_fabs(&b, nir_ddy(&b, x))))
    BIN("fmax", nir_fmax(&b, x, y)) BIN("fmin", nir_fmin(&b, x, y))
    BIN("pow", nir_fpow(&b, x, y)) BIN("powr", nir_fpow(&b, x, y)) BIN("atan2", nir_atan2(&b, x, y))
    if (base("fmax3") || base("fast_fmax3")) return perComp([&](auto p) { return nir_fmax(&b, p(0), nir_fmax(&b, p(1), p(2))); }, 3);
    if (base("fmin3") || base("fast_fmin3")) return perComp([&](auto p) { return nir_fmin(&b, p(0), nir_fmin(&b, p(1), p(2))); }, 3);
    if (base("clamp") || base("fast_clamp")) return perComp([&](auto p) { return nir_fmin(&b, nir_fmax(&b, p(0), p(1)), p(2)); }, 3);
    if (base("mix")) return perComp([&](auto p) { return nir_fadd(&b, p(0), nir_fmul(&b, nir_fsub(&b, p(1), p(0)), p(2))); }, 3);
    if (base("fma")) return perComp([&](auto p) { return nir_fadd(&b, nir_fmul(&b, p(0), p(1)), p(2)); }, 3);
    if (starts("air.max.s.")) return perComp([&](auto p) { return nir_imax(&b, p(0), p(1)); }, 2);
    if (starts("air.max.u.")) return perComp([&](auto p) { return nir_umax(&b, p(0), p(1)); }, 2);
    if (starts("air.min.s.")) return perComp([&](auto p) { return nir_imin(&b, p(0), p(1)); }, 2);
    if (starts("air.min.u.")) return perComp([&](auto p) { return nir_umin(&b, p(0), p(1)); }, 2);
    if (starts("air.abs.s.")) return perComp([&](auto p) { return nir_iabs(&b, p(0)); }, 1);
    if (starts("air.clamp.s.")) return perComp([&](auto p) { return nir_imin(&b, nir_imax(&b, p(0), p(1)), p(2)); }, 3);
    if (starts("air.clamp.u.")) return perComp([&](auto p) { return nir_umin(&b, nir_umax(&b, p(0), p(1)), p(2)); }, 3);
    if (base("dot") || base("fast_dot")) return {nir_fdot(&b, vec(A(0)), vec(A(1)))};
    if (base("normalize") || base("fast_normalize")) { nir_def *v = vec(A(0)); return split(nir_fmul(&b, v, nir_frsq(&b, nir_fdot(&b, v, v)))); }
    if (base("length") || base("fast_length")) { nir_def *v = vec(A(0)); return {nir_fsqrt(&b, nir_fdot(&b, v, v))}; }
    if (starts("air.any.")) { auto v = A(0); nir_def *r = v[0]; for (unsigned i = 1; i < v.size(); i++) r = nir_ior(&b, r, v[i]); return {r}; }
    if (starts("air.all.")) { auto v = A(0); nir_def *r = v[0]; for (unsigned i = 1; i < v.size(); i++) r = nir_iand(&b, r, v[i]); return {r}; }
    if (starts("air.normalize_function_constant_predicate")) return {nir_b2iN(&b, nir_ine_imm(&b, A1(0), 0), bits(RT))};
    if (starts("air.unpack.unorm4x8")) return coerce(split(nir_unpack_unorm_4x8(&b, A1(0))), RT);
    if (starts("air.convert.")) {
      // air.convert.<dk>.<dty>.<sk>.<sty>
      SmallVector<StringRef, 6> parts; StringRef(nm).split(parts, '.');
      char dk = parts[2][0], sk = parts[4][0];
      Type *DE = RT->getScalarType(); unsigned db = bits(DE);
      return perComp([&](auto p) -> nir_def * {
        nir_def *x = p(0);
        if (x->bit_size == 1) return dk == 'f' ? nir_b2fN(&b, x, db) : nir_b2iN(&b, x, db);
        if (dk == 'f') return sk == 'f' ? nir_f2fN(&b, x, db) : sk == 's' ? nir_i2fN(&b, x, db) : nir_u2fN(&b, x, db);
        if (db == 1) return sk == 'f' ? nir_fneu_imm(&b, x, 0.0) : nir_ine_imm(&b, x, 0);
        if (dk == 's') return sk == 'f' ? nir_f2iN(&b, x, db) : nir_i2iN(&b, x, db);
        return sk == 'f' ? nir_f2uN(&b, x, db) : nir_u2uN(&b, x, db);
      }, 1);
    }
    if (starts("air.discard_fragment")) { nir_demote(&b); return {}; }
    if (starts("air.wg.barrier") || starts("air.simdgroup.barrier")) {
      unsigned flags = cast<ConstantInt>(CI->getArgOperand(0))->getZExtValue();   // mem_flags: 1 device, 2 threadgroup, 4 texture (INFERRED)
      _nir_barrier_indices ix = {};
      ix.execution_scope = starts("air.wg.") ? SCOPE_WORKGROUP : SCOPE_SUBGROUP; ix.memory_scope = SCOPE_WORKGROUP;
      ix.memory_semantics = NIR_MEMORY_ACQ_REL;
      ix.memory_modes = (nir_variable_mode)((flags & 2 ? nir_var_mem_shared : 0) | (flags & 1 ? nir_var_mem_global : 0) | (flags & 8 ? nir_var_mem_shared | nir_var_image : 0) | (flags & 4 ? nir_var_image : 0));
      _nir_build_barrier(&b, ix); return {};
    }
    if (starts("air.get_simdgroup_size")) return coerce({nir_load_subgroup_size(&b)}, RT);
    if (starts("air.quad_shuffle_xor.") || starts("air.simd_shuffle_xor.")) {
      nir_def *m = nir_u2u32(&b, A1(1)); std::vector<nir_def *> r;
      for (nir_def *x : A(0)) r.push_back(nir_shuffle_xor(&b, x, m)); return r;
    }
    if (starts("air.simd_shuffle.") || starts("air.quad_shuffle.")) {
      nir_def *lane = nir_u2u32(&b, A1(1)); std::vector<nir_def *> r;
      if (starts("air.quad_shuffle.")) lane = nir_ior(&b, nir_iand_imm(&b, nir_load_subgroup_invocation(&b), ~3u), lane);
      for (nir_def *x : A(0)) r.push_back(nir_shuffle(&b, x, lane)); return r;
    }
    if (starts("air.simd_shuffle_and_fill_down.")) {   // (data, filling, delta, modulo)
      nir_def *lane = nir_load_subgroup_invocation(&b), *delta = nir_u2u32(&b, A1(2)), *mod = nir_u2u32(&b, A1(3));
      nir_def *inWin = nir_umod(&b, lane, mod), *src = nir_iadd(&b, lane, delta);
      nir_def *fromData = nir_ult(&b, nir_iadd(&b, inWin, delta), mod);
      nir_def *fillLane = nir_isub(&b, src, mod);
      std::vector<nir_def *> d = A(0), f = A(1), r;
      for (unsigned i = 0; i < d.size(); i++) r.push_back(nir_bcsel(&b, fromData, nir_shuffle(&b, d[i], src), nir_shuffle(&b, f[i], fillLane)));
      return r;
    }
    if (starts("air.simd_sum.") || starts("air.simd_max.") || starts("air.simd_min.")) {
      nir_op op = starts("air.simd_sum.") ? (RT->getScalarType()->isFloatingPointTy() ? nir_op_fadd : nir_op_iadd)
                : starts("air.simd_max.") ? nir_op_fmax : nir_op_fmin;
      std::vector<nir_def *> r; _nir_reduce_indices ix = {}; ix.reduction_op = op; ix.cluster_size = 0;
      for (nir_def *x : A(0)) r.push_back(_nir_build_reduce(&b, x, ix)); return r;
    }
    if (starts("air.write_texture_2d.")) {             // (tex, coord, color, lod, access)
      int t = texOf(CI->getArgOperand(0));
      std::vector<nir_def *> c = A(1); for (auto &x : c) x = nir_u2u32(&b, x);
      c.push_back(nir_undef(&b, 1, 32)); c.push_back(nir_undef(&b, 1, 32));
      std::vector<nir_def *> col = A(2);
      _nir_image_store_indices ix = {}; ix.image_dim = GLSL_SAMPLER_DIM_2D; ix.format = PIPE_FORMAT_NONE;
      ix.src_type = (nir_alu_type)(nir_type_float | col[0]->bit_size); ix.access = ACCESS_NON_READABLE;
      _nir_build_image_store(&b, nir_imm_int(&b, t), vec(c), nir_undef(&b, 1, 32), vec(col), nir_u2u32(&b, A1(3)), ix);
      s->info.num_images = std::max<unsigned>(s->info.num_images, t + 1);
      report += "  image store -> image(" + std::to_string(t) + ")\n";
      return {};
    }
    // Textures: (tex, sampler, coord, i1 ?, offset, i1 is_level, float bias|level, float min_lod, i32 0)
    auto resType = [&](unsigned &bs, nir_alu_type &dt) {
      Type *E = cast<StructType>(RT)->getElementType(0)->getScalarType();
      bs = bits(E); dt = (nir_alu_type)((E->isFloatingPointTy() ? nir_type_float : (nm.find(".s.") != std::string::npos ? nir_type_int : nir_type_uint)) | bs);
    };
    auto sampleCommon = [&](glsl_sampler_dim dim, bool arr, unsigned coordArg, int arrArg, unsigned offArg, unsigned lvlFlag) {
      unsigned bs; nir_alu_type dt; resType(bs, dt);
      std::vector<nir_def *> c = A(coordArg);
      if (arr) c.push_back(nir_u2f32(&b, A1(arrArg)));
      nir_def *off = isZeroConst(CI->getArgOperand(offArg)) ? nullptr : vec(A(offArg));
      bool isLevel = cast<ConstantInt>(CI->getArgOperand(lvlFlag))->isOne();
      Value *lb = CI->getArgOperand(lvlFlag + 1), *ml = CI->getArgOperand(lvlFlag + 2);
      nir_def *lod = isLevel ? A1(lvlFlag + 1) : nullptr;
      nir_def *bias = (!isLevel && !isZeroConst(lb)) ? A1(lvlFlag + 1) : nullptr;
      nir_def *minlod = isZeroConst(ml) ? nullptr : A1(lvlFlag + 2);
      nir_texop op = lod ? nir_texop_txl : bias ? nir_texop_txb : nir_texop_tex;
      if (stage != MESA_SHADER_FRAGMENT && op == nir_texop_tex) { op = nir_texop_txl; lod = nir_imm_float(&b, 0); }
      auto r = texop(op, dim, arr, texOf(CI->getArgOperand(0)), smpOf(CI->getArgOperand(1)), vec(c), lod, bias, off, minlod, nullptr, nullptr, bs, dt);
      r.push_back(nir_imm_intN_t(&b, 0, 8));           // the i8 "residency" field of the result struct
      return r;
    };
    if (starts("air.sample_texture_2d_grad.")) {
      unsigned bs; nir_alu_type dt; resType(bs, dt);
      auto r = texop(nir_texop_txd, GLSL_SAMPLER_DIM_2D, false, texOf(CI->getArgOperand(0)), smpOf(CI->getArgOperand(1)),
                     vec(A(2)), nullptr, nullptr, isZeroConst(CI->getArgOperand(7)) ? nullptr : vec(A(7)), nullptr, vec(A(3)), vec(A(4)), bs, dt);
      r.push_back(nir_imm_intN_t(&b, 0, 8)); return r;
    }
    if (starts("air.sample_texture_2d.")) return sampleCommon(GLSL_SAMPLER_DIM_2D, false, 2, -1, 4, 5);
    if (starts("air.sample_texture_3d.")) return sampleCommon(GLSL_SAMPLER_DIM_3D, false, 2, -1, 4, 5);
    if (starts("air.sample_texture_1d_array.")) return sampleCommon(GLSL_SAMPLER_DIM_1D, true, 2, 3, 5, 6);
    if (starts("air.sample_texture_1d.")) return sampleCommon(GLSL_SAMPLER_DIM_1D, false, 2, -1, 4, 5);
    if (starts("air.read_texture_2d.")) {          // (tex, ?, coord, offset, lod, access)
      unsigned bs; nir_alu_type dt; resType(bs, dt);
      nir_def *coord = vec(A(2)); if (coord->bit_size != 32) coord = nir_u2u32(&b, coord);
      nir_def *lod = A1(4); if (lod->bit_size != 32) lod = nir_u2u32(&b, lod);
      auto r = texop(nir_texop_txf, GLSL_SAMPLER_DIM_2D, false, texOf(CI->getArgOperand(0)), -1, coord, lod, nullptr, nullptr, nullptr, nullptr, nullptr, bs, dt);
      r.push_back(nir_imm_intN_t(&b, 0, 8)); return r;
    }
    if (starts("air.get_width_texture_2d") || starts("air.get_height_texture_2d")) {
      auto r = texop(nir_texop_txs, GLSL_SAMPLER_DIM_2D, false, texOf(CI->getArgOperand(0)), -1, nullptr, A1(1), nullptr, nullptr, nullptr, nullptr, nullptr, 32, nir_type_uint32, 2);
      return {r[starts("air.get_width") ? 0 : 1]};
    }
    die("AIR intrinsic not implemented in prototype: " + nm);
#undef UN
#undef BIN
  }

  std::vector<nir_def *> callLLVM(CallInst *CI) {
    Intrinsic::ID id = CI->getIntrinsicID();
    auto A = [&](unsigned i) { return get(CI->getArgOperand(i)); };
    unsigned n = nflat(CI->getType());
    auto per2 = [&](auto fn) { auto x = A(0), y = A(1); std::vector<nir_def *> r; for (unsigned c = 0; c < n; c++) r.push_back(fn(x[c], y[c])); return r; };
    auto per1 = [&](auto fn) { auto x = A(0); std::vector<nir_def *> r; for (unsigned c = 0; c < n; c++) r.push_back(fn(x[c])); return r; };
    auto per3 = [&](auto fn) { auto x = A(0), y = A(1), z = A(2); std::vector<nir_def *> r; for (unsigned c = 0; c < n; c++) r.push_back(fn(x[c], y[c], z[c])); return r; };
    switch (id) {
    case Intrinsic::lifetime_start: case Intrinsic::lifetime_end: case Intrinsic::assume: return {};
    case Intrinsic::umax: return per2([&](nir_def *x, nir_def *y) { return nir_umax(&b, x, y); });
    case Intrinsic::umin: return per2([&](nir_def *x, nir_def *y) { return nir_umin(&b, x, y); });
    case Intrinsic::smax: return per2([&](nir_def *x, nir_def *y) { return nir_imax(&b, x, y); });
    case Intrinsic::smin: return per2([&](nir_def *x, nir_def *y) { return nir_imin(&b, x, y); });
    case Intrinsic::maxnum: return per2([&](nir_def *x, nir_def *y) { return nir_fmax(&b, x, y); });
    case Intrinsic::minnum: return per2([&](nir_def *x, nir_def *y) { return nir_fmin(&b, x, y); });
    case Intrinsic::fabs: return per1([&](nir_def *x) { return nir_fabs(&b, x); });
    case Intrinsic::floor: return per1([&](nir_def *x) { return nir_ffloor(&b, x); });
    case Intrinsic::sqrt: return per1([&](nir_def *x) { return nir_fsqrt(&b, x); });
    case Intrinsic::fma: case Intrinsic::fmuladd: return per3([&](nir_def *x, nir_def *y, nir_def *z) { return nir_fadd(&b, nir_fmul(&b, x, y), z); });
    case Intrinsic::copysign: return per2([&](nir_def *x, nir_def *y) { return nir_bcsel(&b, nir_flt_imm(&b, y, 0.0), nir_fneg(&b, nir_fabs(&b, x)), nir_fabs(&b, x)); });
    case Intrinsic::ceil: return per1([&](nir_def *x) { return nir_fceil(&b, x); });
    case Intrinsic::trunc: return per1([&](nir_def *x) { return nir_ftrunc(&b, x); });
    case Intrinsic::abs: return per1([&](nir_def *x) { return nir_iabs(&b, x); });
    default: die("LLVM intrinsic not implemented: " + CI->getCalledFunction()->getName().str());
    }
  }

  // ---- instructions ----
  void inst(Instruction &I) {
    auto set = [&](std::vector<nir_def *> v) {
      std::vector<Type *> ts; flatten(I.getType(), ts);
      if (ts.size() != v.size()) die("component count mismatch (" + std::to_string(v.size()) + " vs " + std::to_string(ts.size()) + ") for " + str(&I));
      for (unsigned k = 0; k < v.size(); k++) if (!ts[k]->isPointerTy() && v[k]->bit_size != bits(ts[k])) die("bit size mismatch comp " + std::to_string(k) + " for " + str(&I));
      vals[&I] = std::move(v); };
    if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
      auto x = get(BO->getOperand(0)), y = get(BO->getOperand(1)); std::vector<nir_def *> r;
      for (unsigned c = 0; c < x.size(); c++) {
        nir_def *a = x[c], *d = y[c], *o;
        switch (BO->getOpcode()) {
        case Instruction::FAdd: o = nir_fadd(&b, a, d); break; case Instruction::FSub: o = nir_fsub(&b, a, d); break;
        case Instruction::FMul: o = nir_fmul(&b, a, d); break; case Instruction::FDiv: o = nir_fdiv(&b, a, d); break;
        case Instruction::FRem: o = nir_fsub(&b, a, nir_fmul(&b, d, nir_ftrunc(&b, nir_fdiv(&b, a, d)))); break;
        case Instruction::Add: o = nir_iadd(&b, a, d); break; case Instruction::Sub: o = nir_isub(&b, a, d); break;
        case Instruction::Mul: o = nir_imul(&b, a, d); break; case Instruction::UDiv: o = nir_udiv(&b, a, d); break;
        case Instruction::SDiv: o = nir_idiv(&b, a, d); break; case Instruction::URem: o = nir_umod(&b, a, d); break;
        case Instruction::SRem: o = nir_irem(&b, a, d); break;
        case Instruction::Shl: o = nir_ishl(&b, a, nir_u2u32(&b, d)); break; case Instruction::LShr: o = nir_ushr(&b, a, nir_u2u32(&b, d)); break;
        case Instruction::AShr: o = nir_ishr(&b, a, nir_u2u32(&b, d)); break;
        case Instruction::And: o = nir_iand(&b, a, d); break; case Instruction::Or: o = nir_ior(&b, a, d); break;
        case Instruction::Xor: o = nir_ixor(&b, a, d); break;
        default: die("binop " + str(&I));
        }
        r.push_back(o);
      }
      return set(r);
    }
    if (auto *UO = dyn_cast<UnaryOperator>(&I)) { std::vector<nir_def *> r; for (nir_def *a : get(UO->getOperand(0))) r.push_back(nir_fneg(&b, a)); return set(r); }
    if (auto *C = dyn_cast<CmpInst>(&I)) {
      auto x = get(C->getOperand(0)), y = get(C->getOperand(1)); std::vector<nir_def *> r;
      for (unsigned c = 0; c < x.size(); c++) {
        nir_def *a = x[c], *d = y[c], *o;
        switch (C->getPredicate()) {
        case CmpInst::FCMP_OEQ: case CmpInst::FCMP_UEQ: o = nir_feq(&b, a, d); break;
        case CmpInst::FCMP_ONE: case CmpInst::FCMP_UNE: o = nir_fneu(&b, a, d); break;
        case CmpInst::FCMP_OLT: case CmpInst::FCMP_ULT: o = nir_flt(&b, a, d); break;
        case CmpInst::FCMP_OLE: case CmpInst::FCMP_ULE: o = nir_fge(&b, d, a); break;
        case CmpInst::FCMP_OGT: case CmpInst::FCMP_UGT: o = nir_flt(&b, d, a); break;
        case CmpInst::FCMP_OGE: case CmpInst::FCMP_UGE: o = nir_fge(&b, a, d); break;
        case CmpInst::FCMP_ORD: o = nir_iand(&b, nir_feq(&b, a, a), nir_feq(&b, d, d)); break;
        case CmpInst::FCMP_UNO: o = nir_ior(&b, nir_fneu(&b, a, a), nir_fneu(&b, d, d)); break;
        case CmpInst::FCMP_TRUE: o = nir_imm_true(&b); break; case CmpInst::FCMP_FALSE: o = nir_imm_false(&b); break;
        case CmpInst::ICMP_EQ: o = nir_ieq(&b, a, d); break; case CmpInst::ICMP_NE: o = nir_ine(&b, a, d); break;
        case CmpInst::ICMP_ULT: o = nir_ult(&b, a, d); break; case CmpInst::ICMP_ULE: o = nir_uge(&b, d, a); break;
        case CmpInst::ICMP_UGT: o = nir_ult(&b, d, a); break; case CmpInst::ICMP_UGE: o = nir_uge(&b, a, d); break;
        case CmpInst::ICMP_SLT: o = nir_ilt(&b, a, d); break; case CmpInst::ICMP_SLE: o = nir_ige(&b, d, a); break;
        case CmpInst::ICMP_SGT: o = nir_ilt(&b, d, a); break; case CmpInst::ICMP_SGE: o = nir_ige(&b, a, d); break;
        default: die("cmp " + str(&I));
        }
        r.push_back(o);
      }
      return set(r);
    }
    if (auto *S = dyn_cast<SelectInst>(&I)) {
      auto c = get(S->getCondition()), t = get(S->getTrueValue()), f = get(S->getFalseValue()); std::vector<nir_def *> r;
      for (unsigned i = 0; i < t.size(); i++) r.push_back(nir_bcsel(&b, c.size() == 1 ? c[0] : c[i], t[i], f[i]));
      return set(r);
    }
    if (auto *CI = dyn_cast<CastInst>(&I)) {
      auto x = get(CI->getOperand(0)); Type *DT = CI->getDestTy(); unsigned db = bits(DT->getScalarType()); std::vector<nir_def *> r;
      if (CI->getOpcode() == Instruction::BitCast || CI->getOpcode() == Instruction::AddrSpaceCast) {
        if (DT->isPointerTy()) { ptrs[&I] = ptr(CI->getOperand(0)); return; }
        unsigned n = nflat(DT);
        if (x.size() == n && x[0]->bit_size == db) return set(x);
        nir_def *packed = nir_extract_bits(&b, x.data(), x.size(), 0, n, db);
        return set(split(packed));
      }
      for (nir_def *a : x) {
        nir_def *o;
        switch (CI->getOpcode()) {
        case Instruction::FPTrunc: case Instruction::FPExt: o = nir_f2fN(&b, a, db); break;
        case Instruction::SIToFP: o = a->bit_size == 1 ? nir_fneg(&b, nir_b2fN(&b, a, db)) : nir_i2fN(&b, a, db); break;
        case Instruction::UIToFP: o = a->bit_size == 1 ? nir_b2fN(&b, a, db) : nir_u2fN(&b, a, db); break;
        case Instruction::FPToSI: case Instruction::FPToUI:
          o = db == 1 ? nir_fneu_imm(&b, nir_ftrunc(&b, a), 0.0)
                      : CI->getOpcode() == Instruction::FPToSI ? nir_f2iN(&b, a, db) : nir_f2uN(&b, a, db); break;
        case Instruction::ZExt: o = a->bit_size == 1 ? nir_b2iN(&b, a, db) : nir_u2uN(&b, a, db); break;
        case Instruction::SExt: o = a->bit_size == 1 ? nir_ineg(&b, nir_b2iN(&b, a, db)) : nir_i2iN(&b, a, db); break;
        case Instruction::Trunc: o = db == 1 ? nir_ine_imm(&b, nir_iand_imm(&b, a, 1), 0) : nir_u2uN(&b, a, db); break;
        default: die("cast " + str(&I));
        }
        r.push_back(o);
      }
      return set(r);
    }
    if (auto *EE = dyn_cast<ExtractElementInst>(&I)) {
      auto v = get(EE->getVectorOperand());
      if (auto *ci = dyn_cast<ConstantInt>(EE->getIndexOperand())) return set({v[ci->getZExtValue()]});
      nir_def *idx = get1(EE->getIndexOperand()), *o = v[0];
      for (unsigned i = 1; i < v.size(); i++) o = nir_bcsel(&b, nir_ieq_imm(&b, idx, i), v[i], o);
      return set({o});
    }
    if (auto *IE = dyn_cast<InsertElementInst>(&I)) {
      auto v = get(IE->getOperand(0)); nir_def *e = get1(IE->getOperand(1));
      auto *ci = dyn_cast<ConstantInt>(IE->getOperand(2)); if (!ci) die("dynamic insertelement");
      v[ci->getZExtValue()] = e; return set(v);
    }
    if (auto *SV = dyn_cast<ShuffleVectorInst>(&I)) {
      auto x = get(SV->getOperand(0)), y = get(SV->getOperand(1)); std::vector<nir_def *> r;
      for (int m : SV->getShuffleMask())
        r.push_back(m < 0 ? nir_undef(&b, 1, x[0]->bit_size) : (unsigned)m < x.size() ? x[m] : y[m - x.size()]);
      return set(r);
    }
    if (auto *EV = dyn_cast<ExtractValueInst>(&I)) {
      auto v = get(EV->getAggregateOperand()); Type *T = EV->getAggregateOperand()->getType(); unsigned off = 0;
      for (unsigned idx : EV->getIndices()) {
        if (auto *ST = dyn_cast<StructType>(T)) { for (unsigned i = 0; i < idx; i++) off += nflat(ST->getElementType(i)); T = ST->getElementType(idx); }
        else { T = T->getArrayElementType(); off += idx * nflat(T); }
      }
      return set(std::vector<nir_def *>(v.begin() + off, v.begin() + off + nflat(T)));
    }
    if (auto *IV = dyn_cast<InsertValueInst>(&I)) {
      auto v = get(IV->getAggregateOperand()), e = get(IV->getInsertedValueOperand()); Type *T = IV->getType(); unsigned off = 0;
      for (unsigned idx : IV->getIndices()) {
        if (auto *ST = dyn_cast<StructType>(T)) { for (unsigned i = 0; i < idx; i++) off += nflat(ST->getElementType(i)); T = ST->getElementType(idx); }
        else { T = T->getArrayElementType(); off += idx * nflat(T); }
      }
      for (unsigned i = 0; i < e.size(); i++) v[off + i] = e[i];
      return set(v);
    }
    if (isa<GetElementPtrInst>(&I)) { ptrs[&I] = ptr(&I); return; }
    if (auto *LI = dyn_cast<LoadInst>(&I)) {
      PtrVal p = ptr(LI->getPointerOperand());
      if (p.kind == PtrVal::SAMPLER_CONST) die("load from constexpr sampler");
      std::vector<nir_def *> out; loadScalars(p, LI->getType(), 0, LI->getAlign().value(), out); return set(out);
    }
    if (auto *CI = dyn_cast<CallInst>(&I)) {
      Function *Fn = CI->getCalledFunction();
      if (!Fn) die("indirect call");
      if (Fn->getName().starts_with("air.get_read_sampler")) { smp[&I] = -1; return; }
      if (Fn->getName().starts_with("air.")) { auto r = callAir(CI); if (!CI->getType()->isVoidTy()) set(r); return; }
      if (Fn->isIntrinsic()) { auto r = callLLVM(CI); if (!CI->getType()->isVoidTy()) set(r); return; }
      die("call to non-inlined function " + Fn->getName().str());
    }
    if (auto *PN = dyn_cast<PHINode>(&I)) {
      std::vector<nir_def *> r; unsigned n = nflat(PN->getType());
      nir_variable *v = phiVars.at(PN);
      nir_def *l = nir_load_var(&b, v);
      for (unsigned i = 0; i < n; i++) r.push_back(nir_channel(&b, l, i));
      return set(r);
    }
    if (auto *SI = dyn_cast<StoreInst>(&I)) {
      PtrVal p = ptr(SI->getPointerOperand()); auto v = get(SI->getValueOperand()); unsigned idx = 0;
      storeScalars(p, SI->getValueOperand()->getType(), v, idx, 0, SI->getAlign().value()); return;
    }
    if (isa<AllocaInst>(&I)) die("alloca survived SROA: " + str(&I));
    die("instruction " + str(&I));
  }

  void storePhis(BasicBlock *from, BasicBlock *to) {
    for (PHINode &PN : to->phis()) {
      auto v = get(PN.getIncomingValueForBlock(from));
      nir_store_var(&b, phiVars.at(&PN), vec(v), (1u << v.size()) - 1);
    }
  }

  void terminator(Instruction *T) {
    if (auto *R = dyn_cast<ReturnInst>(T)) {
      if (Value *rv = R->getReturnValue()) {
        auto v = get(rv);
        std::map<nir_variable *, std::vector<nir_def *>> per;
        for (unsigned i = 0; i < outs.size(); i++) {
          nir_def *d = v[i]; unsigned vb = glsl_get_bit_size(glsl_without_array(outs[i].first->type));
          if (d->bit_size != vb) d = glsl_base_type_is_integer(glsl_get_base_type(outs[i].first->type)) ? nir_u2uN(&b, d, vb) : nir_f2fN(&b, d, vb);
          per[outs[i].first].push_back(d);
        }
        for (auto &kv : per) nir_store_var(&b, kv.first, vec(kv.second), (1u << kv.second.size()) - 1);
      }
      nir_goto(&b, b.impl->end_block);
      return;
    }
    if (auto *Br = dyn_cast<BranchInst>(T)) {
      BasicBlock *cur = Br->getParent();
      if (Br->isUnconditional()) { storePhis(cur, Br->getSuccessor(0)); nir_goto(&b, blocks.at(Br->getSuccessor(0))); return; }
      nir_def *c = get1(Br->getCondition());
      BasicBlock *t = Br->getSuccessor(0), *f = Br->getSuccessor(1);
      bool tp = !t->phis().empty(), fp = !f->phis().empty();
      if (!tp && !fp) { nir_goto_if(&b, blocks.at(t), c, blocks.at(f)); return; }
      // Edge blocks carry the phi stores.
      nir_block *te = newBlock(), *fe = newBlock();
      nir_goto_if(&b, te, c, fe);
      b.cursor = nir_after_block(te); storePhis(cur, t); nir_goto(&b, blocks.at(t));
      b.cursor = nir_after_block(fe); storePhis(cur, f); nir_goto(&b, blocks.at(f));
      return;
    }
    if (auto *SW = dyn_cast<SwitchInst>(T)) {
      nir_def *c = get1(SW->getCondition());
      BasicBlock *cur = SW->getParent();
      for (auto &Case : SW->cases()) {
        nir_block *hit = newBlock(), *next = newBlock();
        nir_goto_if(&b, hit, nir_ieq_imm(&b, c, Case.getCaseValue()->getSExtValue()), next);
        b.cursor = nir_after_block(hit); storePhis(cur, Case.getCaseSuccessor()); nir_goto(&b, blocks.at(Case.getCaseSuccessor()));
        b.cursor = nir_after_block(next);
      }
      storePhis(cur, SW->getDefaultDest()); nir_goto(&b, blocks.at(SW->getDefaultDest()));
      return;
    }
    if (isa<UnreachableInst>(T)) { nir_goto(&b, b.impl->end_block); return; }
    die("terminator " + str(T));
  }

  nir_block *newBlock() {
    nir_block *n = nir_block_create(b.impl);
    exec_list_push_tail(&b.impl->body, &n->cf_node.node);
    n->cf_node.parent = &b.impl->cf_node;
    return n;
  }

  nir_shader *run(const nir_shader_compiler_options *opts, const MDNode *inputs, const MDNode *outputs) {
    b = nir_builder_init_simple_shader(stage, opts, "%s", F->getName().str().c_str());
    s = b.shader;
    b.impl->structured = false;
    setupArgs(inputs, outputs);
    // phi temporaries
    for (BasicBlock &BB : *F)
      for (PHINode &PN : BB.phis()) {
        std::vector<Type *> ts; flatten(PN.getType(), ts);
        Type *E = ts[0];
        glsl_base_type bt = bits(E) == 1 ? GLSL_TYPE_BOOL : E->isFloatingPointTy() ? (bits(E) == 16 ? GLSL_TYPE_FLOAT16 : GLSL_TYPE_FLOAT)
                                                                                 : bits(E) == 16 ? GLSL_TYPE_UINT16 : bits(E) == 8 ? GLSL_TYPE_UINT8 : GLSL_TYPE_UINT;
        phiVars[&PN] = nir_local_variable_create(b.impl, glsl_vector_type(bt, ts.size()), "phi");
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
    return s;
  }
};

// ----------------------------------------------------------------------------
int main(int argc, char **argv) {
  uint64_t chip = 0x44070041;        // Adreno X2-90 (Mesa freedreno_devices.py)
  std::map<int, int64_t> fc;
  const char *path = nullptr; bool dumpNir = false;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--chip") chip = strtoull(argv[++i], nullptr, 0);
    else if (a == "--fc") { std::string kv = argv[++i]; fc[atoi(kv.c_str())] = atoll(kv.substr(kv.find('=') + 1).c_str()); }
    else if (a == "--nir") dumpNir = true;
    else path = argv[i];
  }
  if (!path) { fprintf(stderr, "usage: air2ir3 [--chip 0x44070041] [--fc idx=val] [--nir] fn.bc\n"); return 1; }

  LLVMContext Ctx;
  auto buf = MemoryBuffer::getFile(path);
  if (!buf) die("cannot read input");
  auto modOr = parseBitcodeFile((*buf)->getMemBufferRef(), Ctx);
  if (!modOr) die("bitcode parse failed: " + toString(modOr.takeError()));
  std::unique_ptr<Module> M = std::move(*modOr);

  // Find the entry point via !air.vertex / !air.fragment / !air.kernel.
  Function *F = nullptr; mesa_shader_stage stage = MESA_SHADER_NONE; const MDNode *ins = nullptr, *outs = nullptr;
  for (auto [md, st] : {std::pair{"air.vertex", MESA_SHADER_VERTEX}, {"air.fragment", MESA_SHADER_FRAGMENT}, {"air.kernel", MESA_SHADER_COMPUTE}}) {
    if (NamedMDNode *N = M->getNamedMetadata(md)) {
      MDNode *E = N->getOperand(0);
      F = cast<Function>(cast<ValueAsMetadata>(E->getOperand(0))->getValue());
      stage = st;
      if (st == MESA_SHADER_COMPUTE) { ins = cast<MDNode>(E->getOperand(2)); }
      else { outs = cast<MDNode>(E->getOperand(1)); ins = cast<MDNode>(E->getOperand(2)); }
    }
  }
  if (!F) die("no AIR entry point");
  setvbuf(stdout, nullptr, _IONBF, 0);
  printf("== %s  (%s, triple %s)\n", F->getName().str().c_str(), stage == MESA_SHADER_VERTEX ? "vertex" : stage == MESA_SHADER_FRAGMENT ? "fragment" : "kernel",
         M->getTargetTriple().str().c_str());
  specialize_and_inline(*M, F, fc);
  if (getenv("AIR2IR3_DUMP_LL")) { std::error_code ec; raw_fd_ostream os(getenv("AIR2IR3_DUMP_LL"), ec); M->print(os, nullptr); }

  // ir3 for the requested chip.
  glsl_type_singleton_init_or_ref();
  fd_dev_id dev_id = {}; dev_id.chip_id = chip;
  const struct fd_dev_info *info = fd_dev_info_raw(&dev_id);
  if (!info) die("chip id not known to this Mesa");
  ir3_compiler_options copts = {};
  // Our driver's layout (same shape as gallium freedreno): FS bindless set 4, last image slot = fb-read.
  copts.bindless_fb_read_descriptor = 4;
  copts.bindless_fb_read_slot = 32 + 32 - 1;
  copts.lower_base_vertex = true;
  copts.push_ubo_with_preamble = true;
  copts.disable_cache = true;
  ir3_compiler *compiler = ir3_compiler_create(nullptr, &dev_id, info, &copts);
  printf("   target: %s  gen %u (chip_id 0x%llx)\n", fd_dev_name(&dev_id), compiler->gen, (unsigned long long)chip);

  Translator T(*M, F, stage);
  nir_shader *nir = T.run(ir3_get_compiler_options(compiler), ins, outs);
  printf("%s", T.report.c_str());

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
  printf("   ir3: %u instructions, %u dwords, full regs %d, half regs %d, constlen %u, branchstack %u\n",
         v->info.instrs_count, v->info.size / 4, v->info.max_reg + 1, v->info.max_half_reg + 1, v->constlen, v->branchstack);
  fputs(v->disasm_info.disasm ? v->disasm_info.disasm : "(no disasm)\n", stdout);
  fflush(stdout);
  return 0;
}
