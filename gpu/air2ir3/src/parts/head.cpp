/* SPDX-License-Identifier: MIT */
// air2ir3 — offline compiler: Metal AIR (LLVM bitcode from a .metallib) -> NIR (Mesa) -> ir3
//           (Adreno A8xx / X2-90 ISA).  Stage-6 hardened version.
//
// Scope: WindowServer-class shaders (SkyLight, CoreDisplay, QuartzCore): vertex + fragment (+ simple
// kernels), constant buffers, device buffers, sampled/read textures, constexpr samplers, function
// constants (scalar + vector, by index or by name), function-constant-gated arguments/outputs,
// function-constant attribute index expressions, framebuffer fetch, unstructured CFG.
// Unsupported constructs abort with "air2ir3: UNSUPPORTED/ERROR: <exact missing feature>".
//
// The binding ABI implemented here is BINDING-ABI.md (abi_version 1); the cache sidecar written by
// --json is described in CACHE-FORMAT.md.
//
// Usage: air2ir3 [--chip 0x44070041] [--fc idx=v[,v..]] [--fc-name name=v[,v..]] [--nir] [--emit-nir]
//                [--json out.json] [--variant out.bin] [--quiet] file.bc
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
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
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Evaluator.h"

#include <algorithm>
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
#include "util/blob.h"
#include "freedreno_dev_info.h"
#include "ir3_compiler.h"
#include "ir3_nir.h"
#include "ir3_shader.h"
#include "a8xx_sampler.h"
#include "air2ir3.h"

using namespace llvm;

// ---------------------------------------------------------------- ABI constants (BINDING-ABI.md) --
static const int ABI_VERSION = 1;
static const int ABI_MAX_TEXTURES = 16;          // Metal texture(n), n < 16  -> T# n (non-bindless)
static const int ABI_MAX_SAMPLERS = 16;          // Metal sampler(n) + constexpr samplers share S# 0..15
static const int ABI_DEVICE_VA_UBO = 31;         // device-address table: UBO 31, 8 bytes per Metal buffer index
static const int ABI_MAX_RTS = 8;                // A6XX_MAX_RENDER_TARGETS
static const int ABI_FS_BINDLESS_SET = 4;        // ir3_shader_descriptor_set(MESA_SHADER_FRAGMENT)
static const int ABI_FB_READ_SLOT = 32 + 32 - 1 - ABI_MAX_RTS;  // IR3_BINDLESS_IMAGE_OFFSET + IR3_BINDLESS_IMAGE_COUNT - 1 - max_rts

[[noreturn]] static void die(const std::string &m) {
  fprintf(stderr, "air2ir3: UNSUPPORTED/ERROR: %s\n", m.c_str());
  fflush(stdout);
  exit(2);
}
static std::string str(const Value *v) {
  std::string s; raw_string_ostream os(s); v->print(os); return s;
}
static std::string jesc(const std::string &s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
    else o += c;
  }
  return o;
}

// ---------------------------------------------------------------- metadata --
// Argument / output metadata, parsed BEFORE specialisation (GlobalOpt may delete the implicit
// globals that the metadata points at).
struct ArgInfo {
  std::string kind;          // air.vertex_input, air.fragment_input, air.position, air.render_target, ...
  std::string name;          // user(...) / generated(...) varying name
  std::string argName, typeName;
  int argno = -1;            // input argument number (-1 for outputs)
  int location = -1;         // air.location_index / render target index
  std::string locGlobal;     // location given by a function-constant expression global
  int addrspace = -1;        // for buffers
  std::string interp = "perspective", sampling = "center";
  bool gated = false;        // [[function_constant(...)]]
  std::string predGlobal;    // predicate global (e.g. __metal_implicit_fc_pred_3 or an FC initialiser)
  bool active = true;        // predicate evaluated true (or not gated)
  bool used = true;          // (inputs) argument has uses after specialisation
  std::string access;        // air.read / air.sample / air.write / air.read_write
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
static std::string mdglobal(const Metadata *m) {
  if (auto *v = dyn_cast_or_null<ValueAsMetadata>(m))
    if (auto *g = dyn_cast<GlobalValue>(v->getValue()->stripPointerCasts())) return g->getName().str();
  return "";
}
// Layout (26A428 AIR 2.9):
//   output: [kind, positional..., "key", value, ...]            gated: ["air.function_constant", !pred, kind, ...]
//   input:  [argno, kind, positional..., "key", value, ...]     gated: [argno, "air.function_constant", !pred, kind, ...]
//   air.render_target positional: <index> [<dual-source index>]; air.location_index value may be
//   an i32 or a pointer to a function-constant expression global (__metal_implicit_attr_int_expr_N).
// Prototype bug fixed here: for gated render targets the index was read from the predicate slot
// (giving colour -1 = FRAG_RESULT_SAMPLE_MASK).
static ArgInfo parseArg(const MDNode *n, bool isOutput) {
  ArgInfo a;
  unsigned i = isOutput ? 0 : 1;
  if (!isOutput) a.argno = mdint(n->getOperand(0));
  unsigned k = i;
  if (k < n->getNumOperands()) a.kind = mdstr(n->getOperand(k));
  if (a.kind == "air.function_constant") {
    a.gated = true;
    if (auto *pn = dyn_cast_or_null<MDNode>(n->getOperand(k + 1).get()))
      if (pn->getNumOperands() > 0) a.predGlobal = mdglobal(pn->getOperand(0));
    k += 2;
    a.kind = k < n->getNumOperands() ? mdstr(n->getOperand(k)) : "";
  }
  if (a.kind == "air.render_target" && k + 1 < n->getNumOperands()) a.location = mdint(n->getOperand(k + 1));
  for (unsigned j = k + 1; j < n->getNumOperands(); j++) {
    std::string s = mdstr(n->getOperand(j));
    if (s == "air.location_index" && j + 1 < n->getNumOperands()) {
      int v = mdint(n->getOperand(j + 1));
      if (v >= 0) a.location = v; else a.locGlobal = mdglobal(n->getOperand(j + 1));
    }
    else if (s == "air.address_space" && j + 1 < n->getNumOperands()) a.addrspace = mdint(n->getOperand(j + 1));
    else if (s == "air.perspective" || s == "air.no_perspective" || s == "air.flat") a.interp = s.substr(4);
    else if (s == "air.center" || s == "air.centroid" || s == "air.sample") {
      if (a.kind == "air.texture" && s == "air.sample") a.access = "sample"; else a.sampling = s.substr(4);
    }
    else if (s == "air.read" || s == "air.write" || s == "air.read_write") a.access = s.substr(4);
    else if (s == "air.arg_name" && j + 1 < n->getNumOperands()) a.argName = mdstr(n->getOperand(j + 1));
    else if (s == "air.arg_type_name" && j + 1 < n->getNumOperands()) a.typeName = mdstr(n->getOperand(j + 1));
    else if (s.rfind("user(", 0) == 0 || s.rfind("generated(", 0) == 0) a.name = s;
  }
  return a;
}

// Function constants declared by the module (!air.function_constants).
struct FcDecl { int index; std::string type, name, global; };
static std::vector<FcDecl> parseFcDecls(Module &M) {
  std::vector<FcDecl> r;
  if (NamedMDNode *N = M.getNamedMetadata("air.function_constants"))
    for (MDNode *E : N->operands()) {
      if (E->getNumOperands() < 4) continue;
      FcDecl d; d.global = mdglobal(E->getOperand(0)); d.type = mdstr(E->getOperand(1));
      d.name = mdstr(E->getOperand(2)); d.index = mdint(E->getOperand(3));
      r.push_back(d);
    }
  std::sort(r.begin(), r.end(), [](const FcDecl &a, const FcDecl &b) { return a.index < b.index; });
  return r;
}
static int fcIndexOfGlobal(StringRef nm) {
  size_t p = nm.find(".MTL_FC_INIT_");
  if (p == StringRef::npos) return -1;
  return std::atoi(nm.substr(p + 13).str().c_str());
}

// ----------------------------------------------------- LLVM-level preparation --
// 1) function-constant specialisation, 2) evaluate the static initialiser (function-constant
//    predicates and attribute-index expressions), 3) inline everything into the entry,
// 4) cleanup pipeline so the translator sees small SSA code.
static Constant *fcConstant(Type *T, const std::vector<double> &v) {
  auto scalar = [&](Type *E, double x) -> Constant * {
    if (E->isFloatingPointTy()) return ConstantFP::get(E, x);
    return ConstantInt::get(E, (uint64_t)(int64_t)x);
  };
  if (auto *VT = dyn_cast<FixedVectorType>(T)) {
    std::vector<Constant *> el;
    for (unsigned i = 0; i < VT->getNumElements(); i++) el.push_back(scalar(VT->getElementType(), v.size() > i ? v[i] : (v.empty() ? 0 : v[0])));
    return ConstantVector::get(el);
  }
  return scalar(T, v.empty() ? 0 : v[0]);
}

// PassBuilder pipelines. All instcombine instances use <no-verify-fixpoint>: LLVM >= 18 aborts
// ("did not reach a fixpoint after 1 iterations") on some specialised WindowServer variants
// (39 of 410 SkyLight function-constant variants).  Not reaching the fixpoint is harmless here.
static const char *PIPE_PRE = "function(instcombine<no-verify-fixpoint>),globalopt";
static const char *PIPE_MAIN =
    "always-inline,function(sroa,early-cse<memssa>,instcombine<no-verify-fixpoint>,gvn,simplifycfg,"
    "instcombine<no-verify-fixpoint>,adce,simplifycfg)";
static const char *PIPE_POST = "function(instcombine<no-verify-fixpoint>,simplifycfg,adce,simplifycfg)";

static void runPipeline(Module &M, const char *pipe) {
  LoopAnalysisManager LAM; FunctionAnalysisManager FAM; CGSCCAnalysisManager CGAM; ModuleAnalysisManager MAM;
  PassBuilder PB;
  PB.registerModuleAnalyses(MAM); PB.registerCGSCCAnalyses(CGAM); PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM); PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
  ModulePassManager MPM;
  if (auto Err = PB.parsePassPipeline(MPM, pipe)) die(toString(std::move(Err)));
  MPM.run(M, MAM);
}

struct SpecResult {
  std::map<std::string, int64_t> implicitVals;   // evaluated static-initialiser globals (by name)
  std::map<int, bool> fcDefined;
  bool ctorEvaluated = false;
};

static SpecResult specialize_and_inline(Module &M, Function *entry, const std::vector<FcDecl> &decls,
                                        const std::map<int, std::vector<double>> &fc) {
  SpecResult R;
  // Replace loads of "*.MTL_FC_INIT_<idx>_<ty>" constants with the chosen values.
  for (GlobalVariable &G : M.globals()) {
    if (G.getSection() != "air.fc_initializer") continue;
    int idx = fcIndexOfGlobal(G.getName());
    if (idx < 0) continue;
    std::vector<double> v = fc.count(idx) ? fc.at(idx) : std::vector<double>{0};
    for (User *U : make_early_inc_range(G.users()))
      if (auto *LI = dyn_cast<LoadInst>(U)) {
        LI->replaceAllUsesWith(fcConstant(LI->getType(), v));
        LI->eraseFromParent();
      }
  }
  for (auto &d : decls) R.fcDefined[d.index] = fc.count(d.index) != 0;
  // is_function_constant_defined(@fc) -> whether the caller supplied a value; fold predicates.
  for (Function &Fn : M) {
    if (!Fn.isDeclaration()) continue;
    StringRef fn = Fn.getName();
    for (User *U : make_early_inc_range(Fn.users())) {
      auto *CI = dyn_cast<CallInst>(U); if (!CI) continue;
      if (fn == "air.is_function_constant_defined") {
        auto *G = dyn_cast<GlobalVariable>(CI->getArgOperand(0)->stripPointerCasts());
        int idx = G ? fcIndexOfGlobal(G->getName()) : -1;
        CI->replaceAllUsesWith(ConstantInt::getBool(CI->getContext(), fc.count(idx) != 0)); CI->eraseFromParent();
      } else if (fn.starts_with("air.normalize_function_constant_predicate")) {
        if (auto *C = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          CI->replaceAllUsesWith(ConstantInt::get(CI->getType(), C->isZero() ? 0 : 1)); CI->eraseFromParent();
        }
      }
    }
  }
  // Evaluate the static initialiser(s) on a clone: this yields the function-constant predicates
  // (__metal_implicit_fc_pred_N) and attribute index expressions (__metal_implicit_attr_int_expr_N)
  // that gate arguments/outputs and choose binding indices.
  if (GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors")) {
    if (auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer())) {
      std::unique_ptr<Module> C = CloneModule(M);
      runPipeline(*C, "function(instcombine<no-verify-fixpoint>)");
      TargetLibraryInfoImpl TLII(C->getTargetTriple());
      TargetLibraryInfo TLI(TLII);
      Evaluator Eval(C->getDataLayout(), &TLI);
      bool ok = true;
      GlobalVariable *cctors = C->getGlobalVariable("llvm.global_ctors");
      if (auto *CCA = dyn_cast<ConstantArray>(cctors->getInitializer()))
        for (Use &U : CCA->operands())
          if (auto *CS = dyn_cast<ConstantStruct>(U.get()))
            if (auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts())) {
              Constant *rv = nullptr; SmallVector<Constant *, 0> args;
              ok = ok && Eval.EvaluateFunction(Fn, rv, args);
            }
      R.ctorEvaluated = ok;
      if (ok)
        for (auto &kv : Eval.getMutatedInitializers()) {
          if (auto *CI = dyn_cast<ConstantInt>(kv.second)) R.implicitVals[kv.first->getName().str()] = CI->getSExtValue();
        }
      (void)CA;
    }
  }
  // Implicit globals that the initialiser never writes keep their (constant) initialiser.
  for (GlobalVariable &G : M.globals())
    if (G.getName().starts_with("__metal_implicit") && !R.implicitVals.count(G.getName().str()) && G.hasInitializer())
      if (auto *CI = dyn_cast<ConstantInt>(G.getInitializer())) R.implicitVals[G.getName().str()] = CI->getSExtValue();

  // Let GlobalOpt evaluate the (now constant) static initialisers into global initialisers.
  runPipeline(M, PIPE_PRE);
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
  runPipeline(M, PIPE_MAIN);
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
      if (!anyLoad) {
        // keep the value of implicit globals we could not evaluate from the initialiser
        if (G.getName().starts_with("__metal_implicit") && !R.implicitVals.count(G.getName().str()))
          if (auto *CI = dyn_cast<ConstantInt>(stores[0]->getValueOperand())) R.implicitVals[G.getName().str()] = CI->getSExtValue();
        for (StoreInst *S : stores) S->eraseFromParent();
        changed = true;
      }
    }
  }
  runPipeline(M, PIPE_POST);
  if (verifyModule(M, &errs())) die("module failed verification after specialisation");
  return R;
}
