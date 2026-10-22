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
// The binding ABI implemented here is BINDING-ABI.md (abi_version 5); the cache key and sidecar are
// described in CACHE-FORMAT.md (format 4).  The compiler is a library (air2ir3_api.h); the CLI at the
// bottom of this file is a thin wrapper over the same entry point.
//
// Usage: air2ir3 --help
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Utils/Local.h"
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
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
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
extern "C" {
#include "disasm.h"
}
#include "air2ir3.h"
#include "air2ir3_api.h"
#ifndef AIR2IR3_COMPILER_ID
#define AIR2IR3_COMPILER_ID "air2ir3-unversioned-build"
#endif

using namespace llvm;

// ---------------------------------------------------------------- ABI constants (BINDING-ABI.md) --
static const int ABI_VERSION = 6;
static const int CACHE_FORMAT_VERSION = 5;      // format 5 (ABI 6): function-constant values exact in their declared type (verify6 must-fix 2)
static const int ABI_MAX_TEXTURES = 16;          // Metal texture(n), n < 16  -> T# n (non-bindless)
static const int ABI_MAX_SAMPLERS = 16;          // Metal sampler(n) + constexpr samplers share S# 0..15 (constexpr: lowest free, ABI v4)
// ABI v6: the non-bindless UBO table a8xx honours has 16 entries (freedreno advertises
// max_const_buffers = 16 for ir3; Turnip binds app UBOs bindless; q1n1 A16 render run 1: a load from
// UBO 31 read zeros although its descriptor was loaded).  Every UBO index a variant uses is < 16.
// The driver table (device-buffer VAs) sits at R.driver_table_ubo = 1 + the highest constant buffer
// the function declares (0 when it declares none), and ir3's own driver UBOs follow it.
static const int ABI_UBO_SLOTS = 16;
static const int ABI_TG_TABLE_OFFSET = 256;      //   ... + threadgroup(n) byte offsets at 256 + 4n (BINDING-ABI.md 3.8)
static const int ABI_MAX_UBO_INDEX = ABI_UBO_SLOTS - 1;   // app UBOs, the driver table, ir3 driver UBOs: all <= 15 (ABI v6)
// the UBO table size a compile checks against: 16, or the probe-only --test-ubo-slots N (q1n1 render probe_ubo_hi)
static int uboSlots(const AirOptions &o) { return o.testUboSlots > 0 ? std::min(o.testUboSlots, 32) : ABI_UBO_SLOTS; }
static const int ABI_MAX_RTS = 8;                // A6XX_MAX_RENDER_TARGETS
static const int ABI_FS_BINDLESS_SET = 4;        // ir3_shader_descriptor_set(MESA_SHADER_FRAGMENT)
static const int ABI_FB_READ_SLOT = 32 + 32 - 1 - ABI_MAX_RTS;  // IR3_BINDLESS_IMAGE_OFFSET + IR3_BINDLESS_IMAGE_COUNT - 1 - max_rts

[[noreturn]] static void die(const std::string &m) { throw AirError(m); }
// The only way this compiler reads a call operand. An index past the call's operand count is a refusal: LLVM's
// getArgOperand() asserts on it, and that assertion aborts the Metal client. WindowServer died this way in
// installed-fresh-20261020-v13 and -v14 on CoreAnimation's compute_apl, whose AIR 2.2 texture read has four operands
// where the AIR 2.9 one has six (docs/WINDOWSERVER-APL-ABORT-20261020.md).
static Value *argOperand(const CallInst *CI, unsigned i) {
  if (i >= CI->arg_size()) {
    const Function *F = CI->getCalledFunction();
    die("call to " + (F ? F->getName().str() : std::string("an indirect callee")) + " has " + std::to_string(CI->arg_size()) +
        " operands, operand " + std::to_string(i) + " was expected (an operand layout this compiler does not know)");
  }
  return CI->getArgOperand(i);
}
static bool containsPointer(Type *T) {
  if (T->isPointerTy()) return true;
  if (auto *S = dyn_cast<StructType>(T)) { for (Type *E : S->elements()) if (containsPointer(E)) return true; return false; }
  if (auto *A = dyn_cast<ArrayType>(T)) return containsPointer(A->getElementType());
  if (auto *V = dyn_cast<VectorType>(T)) return containsPointer(V->getElementType());
  return false;
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
  int dualIndex = 0;         // air.render_target's second positional: [[color(n), index(1)]] = 1
  std::string locGlobal;     // location given by a function-constant expression global
  int addrspace = -1;        // for buffers
  int64_t bufferSize = -1;   // explicit AIR argument buffer extent, if present
  std::string interp = "perspective", sampling = "center";
  bool gated = false;        // [[function_constant(...)]]
  std::string predGlobal;    // predicate global (e.g. __metal_implicit_fc_pred_3 or an FC initialiser)
  bool active = true;        // gets a binding: present, or read by the specialised code
  bool present = true;       // Metal's notion: predicate true (or not gated)
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
  if (a.kind == "air.render_target" && k + 2 < n->getNumOperands()) a.dualIndex = std::max(0, mdint(n->getOperand(k + 2)));
  for (unsigned j = k + 1; j < n->getNumOperands(); j++) {
    std::string s = mdstr(n->getOperand(j));
    if (s == "air.location_index" && j + 1 < n->getNumOperands()) {
      int v = mdint(n->getOperand(j + 1));
      if (v >= 0) a.location = v; else a.locGlobal = mdglobal(n->getOperand(j + 1));
    }
    else if (s == "air.address_space" && j + 1 < n->getNumOperands()) a.addrspace = mdint(n->getOperand(j + 1));
    else if (s == "air.buffer_size" && j + 1 < n->getNumOperands()) {
      int size = mdint(n->getOperand(j + 1));
      if (size < 0) die("invalid air.buffer_size metadata");
      a.bufferSize = size;
    }
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
// Function-constant values in their DECLARED type (cache format 5, ABI 6; verify6 must-fix 2).  The
// CLI and the C API carry values as doubles; resolveFcs canonicalises every component once, here, to
// the value the declared type holds (integers wrapped to their width, bool 0/1, float / half rounded
// to that format, NaN / inf / -0 kept), and pads a vector to its component count.  The compile, the
// key bytes (fcBytes) and the sidecar (fcValueJson) all read that one canonical value, so the key
// recomputes from the sidecar for every value.  long / ulong beyond 2^53 cannot arrive through a
// double (C API 2 limit); what the double holds is canonicalised the same way everywhere.
static std::string fcScalarBase(const std::string &t, unsigned &n) {
  static const char *bases[] = {"uchar", "char", "ushort", "short", "uint", "int", "ulong", "long", "half", "float", "bool"};
  for (const char *b : bases)
    if (t.rfind(b, 0) == 0) { std::string r = t.substr(strlen(b)); n = r.empty() ? 1 : atoi(r.c_str()); return b; }
  die("function-constant type " + t);
}
static int64_t fcToI64(double v) {                  // C conversion toward zero, wrapping modulo 2^64 (no UB)
  if (std::isnan(v)) return 0;
  if (v >= 9223372036854775808.0) return v >= 18446744073709551616.0 ? -1 : (int64_t)(uint64_t)v;
  if (v < -9223372036854775808.0) return INT64_MIN;
  return (int64_t)v;
}
static double fcCanonScalar(const std::string &base, double v) {
  int64_t i = fcToI64(v);
  if (base == "bool") return v != 0 ? 1 : 0;               // NaN != 0: true
  if (base == "uchar") return (double)(uint8_t)i;
  if (base == "char") return (double)(int8_t)i;
  if (base == "ushort") return (double)(uint16_t)i;
  if (base == "short") return (double)(int16_t)i;
  if (base == "uint") return (double)(uint32_t)i;
  if (base == "int") return (double)(int32_t)i;
  if (base == "ulong") return (double)(uint64_t)i;
  if (base == "long") return (double)i;
  if (base == "float") return (double)(float)v;
  if (base == "half") return (double)(_Float16)v;
  die("function-constant type " + base);
}
static std::vector<double> fcCanon(const std::string &type, const std::vector<double> &v) {
  unsigned n = 1; std::string base = fcScalarBase(type, n);
  std::vector<double> r;
  for (unsigned i = 0; i < n; i++) r.push_back(fcCanonScalar(base, i < v.size() ? v[i] : (v.empty() ? 0 : v[0])));
  return r;
}
static uint64_t fcIntBits(double v) { return v < 0 ? (uint64_t)(int64_t)v : (uint64_t)v; }   // a canonical integer value
static Constant *fcConstant(Type *T, const std::vector<double> &v) {
  auto scalar = [&](Type *E, double x) -> Constant * {
    if (E->isFloatingPointTy()) return ConstantFP::get(E, x);
    return ConstantInt::get(E, fcIntBits(x));
  };
  if (auto *VT = dyn_cast<FixedVectorType>(T)) {
    std::vector<Constant *> el;
    for (unsigned i = 0; i < VT->getNumElements(); i++) el.push_back(scalar(VT->getElementType(), v.size() > i ? v[i] : (v.empty() ? 0 : v[0])));
    return ConstantVector::get(el);
  }
  return scalar(T, v.empty() ? 0 : v[0]);
}
// A load of a function-constant initialiser global (fix round 5, verify5 item 3): the value is built
// in the constant's DECLARED type (the global's value type) and its bytes are reinterpreted as the
// load's type.  The front end loads a float / half constant as an integer of the same size for
// isnan / isinf / signbit / as_type (`load i32, ptr @_Z1F.MTL_FC_INIT_4_f` in a static initialiser);
// converting the VALUE to the load's type (fix round 4 and before) turned F = -7.5 into the integer
// -7, whose bit pattern isnan() reads as a NaN (pun_ctor_isnan: buffer(2) present, Metal absent).
// Used by abstract_eval_ctors, indep_eval_ctors and the body replacement in specialize_and_inline.
static Constant *fcLoadConstant(const GlobalVariable *G, Type *loadT, const std::vector<double> &v, const DataLayout &DL) {
  Type *DT = G->getValueType();
  if (DT == loadT) return fcConstant(loadT, v);
  if (Constant *c = ConstantFoldLoadFromConst(fcConstant(DT, v), loadT, DL)) return c;
  std::string t; raw_string_ostream os(t); loadT->print(os); DT->print(os << " from ");
  die("function constant " + G->getName().str() + " is loaded as " + os.str() + ": cannot reinterpret its bytes");
}
// A static-initialiser load of a global the initialiser stored with another type (a shadow read
// through as_type): the stored constant's bytes, as a load from memory gives them (fix round 5).
static Constant *punStored(Constant *c, Type *loadT, const DataLayout &DL) {
  return c->getType() == loadT ? c : ConstantFoldLoadFromConst(c, loadT, DL);
}

// PassBuilder pipelines. All instcombine instances use <no-verify-fixpoint>: LLVM >= 18 aborts
// ("did not reach a fixpoint after 1 iterations") on some specialised WindowServer variants
// (39 of 410 SkyLight function-constant variants).  Not reaching the fixpoint is harmless here.
static const char *PIPE_PRE = "function(instcombine<no-verify-fixpoint>),globalopt";
// PIPE_MAIN folds the (now constant) function constants and prunes the dead feature branches and helpers before it
// inlines: inlining the ubershader's every call first and folding afterwards was 68% of a specialised CoreAnimation
// compile, for the same code (docs/USERSPACE-GRAPHICS-20261019.md, "Speed: shader compile time").
static const char *PIPE_MAIN =
    "function(instcombine<no-verify-fixpoint>,simplifycfg),globaldce,always-inline,globaldce,"
    "function(sroa,early-cse<memssa>,instcombine<no-verify-fixpoint>,gvn,simplifycfg,"
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
  std::set<std::string> taintedGlobals;          // globals whose value depends on an unset function constant
  unsigned taintedPredicates = 0;                // air.normalize_function_constant_predicate calls forced to 0
  bool ctorEvaluated = false;
  unsigned unsetMarkers = 0, unsetIndependent = 0;           // resolve_unset_in_body
  std::map<std::string, std::string> ambiguousPredicates;    // presenceVerdicts: refused if they gate something
  std::set<std::string> directPredicates;                    // presenceVerdicts: direct copies of an unset constant (absent)
  std::string ctorWhy;                                       // why the static initialiser could not be evaluated (if so)
};

// Unset function constants, Metal semantics (BINDING-ABI.md 3.7).  Metal leaves a constant that
// the pipeline does not set undefined: is_function_constant_defined() is false, and an argument or
// output gated by a predicate that evaluates to "undefined" is ABSENT.  Measured on the M3 Max
// (tests/regress.py "unset_fc_semantics", tests/fixtures/fcsem.metal): Metal evaluates the
// predicates with LLVM undef semantics, i.e. an undefined operand only makes the result undefined
// when it matters:  A && B with A = true, B unset -> undefined -> absent;  A || B with A unset,
// B = true -> true -> present;  A ? B : C with A unset and B == C -> B;  and
// air.normalize_function_constant_predicate(undefined) -> false.
// This abstract interpreter runs the static initialiser (llvm.global_ctors) over the lattice
// Unknown < Const < Undef, following branches on constant conditions; a branch on an undefined
// condition takes the false edge (measured: fixture fc3) and a switch its first case.  Its result
// decides the implicit predicate globals.  Across the randomized test (tests/fcrand.py) the present
// sets it gives match Metal in every compiled case.  Uses of an unset constant in the function BODY
// are not guessed: resolve_unset_in_body refuses a variant in which one decides anything (ABI v4;
// ABI v3 materialised them as 0, fix round 2 took the false side of selects and branches, and both
// disagreed with Metal, verify3 item 1).  The hardened compiler before ABI v3 evaluated the
// predicates with the unset constants as 0, which made Shadow*BlurFragment's
// is_radius_low_priority true and bound buffer(2) where Metal has none (verifier must-fix 7).
struct AV { enum K { Unknown, C, U } k = Unknown; Constant *c = nullptr; };
static AV avC(Constant *c) { AV v; if (!c || isa<UndefValue>(c)) { v.k = AV::U; return v; } v.k = AV::C; v.c = c; return v; }
static AV avU() { AV v; v.k = AV::U; return v; }
static AV meet(const AV &a, const AV &b) {
  if (a.k == AV::Unknown) return b;
  if (b.k == AV::Unknown) return a;
  if (a.k == AV::U || b.k == AV::U) return avU();
  return a.c == b.c ? a : avU();
}
static bool sameAV(const AV &a, const AV &b) { return a.k == b.k && a.c == b.c; }

static Constant *foldCtorAirCall(CallInst *CI, ArrayRef<Constant *> args);
static std::string ctorCallStr(CallInst *CI, ArrayRef<Constant *> args);
// Fix round 6 (fc6 shadow 3 shader 27, found while fixing verify6 item 3): an LLVM floating-point
// arithmetic instruction of the static initialiser carries Metal's fast-math flags.  When it CREATES an
// inf or a NaN from finite operands (an overflow, x / 0, 0 / 0) under `ninf` / `nnan`, Metal's answer
// is not reproducible: `signbit(float(K) * F - 0)` with K = -128 is false for F = FLT_MAX and true for
// F = 1e38 (both products are -inf; fixture tests/fixtures/v6/fmf_poison.metal).  Such an initialiser is
// not evaluated, and what it decides is refused.  Measured, everything else follows IEEE in Metal and
// is evaluated as IEEE here: an inf / NaN that is already there and propagates (`half(70000) + 0` >=
// 255.5 is true, overflow_body), comparisons with inf / NaN operands (`x >= -INFINITY`, pun_probe's
// `as_type<half2>(F).y == -7.5h`), and the AIR conversions (bool(NaN) true, half(65535) inf).  fc6 runs:
// without this rule 1 presence mismatch in about 10,000 all-set cases (shader 27); refusing on every
// flag violation instead refused a third of all cases that Metal answers the IEEE way.
static bool fpNonFinite(Constant *c, bool inf, bool nan) {
  auto chk = [&](Constant *e) { auto *f = dyn_cast_or_null<ConstantFP>(e); return f && ((inf && f->getValueAPF().isInfinity()) || (nan && f->getValueAPF().isNaN())); };
  if (auto *VT = dyn_cast<FixedVectorType>(c->getType())) {
    for (unsigned i = 0; i < VT->getNumElements(); i++) if (chk(c->getAggregateElement(i))) return true;
    return false;
  }
  return chk(c);
}
static std::string fmfPoison(Instruction &I, ArrayRef<Constant *> ops, Constant *res) {
  auto *BO = dyn_cast<BinaryOperator>(&I);
  if (!BO || !BO->getType()->isFPOrFPVectorTy() || !res) return "";
  bool ninf = BO->hasNoInfs(), nnan = BO->hasNoNaNs();
  if (!ninf && !nnan) return "";
  for (Constant *c : ops) if (!c || fpNonFinite(c, true, true)) return "";          // an inf / NaN operand propagates: IEEE
  if (fpNonFinite(res, ninf, nnan)) return str(&I) + " creates an inf / NaN from finite operands under Metal's fast-math flags (poison; Metal's value is not reproducible)";
  return "";
}
struct CtorEval {
  bool ok = true; std::string why;
  std::map<const GlobalVariable *, AV> mem;
  std::map<CallInst *, AV> normalize;      // value of every normalize call reached
};
static CtorEval abstract_eval_ctors(Module &M, const std::map<int, std::vector<double>> &fc) {
  CtorEval E;
  GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors");
  if (!ctors || !ctors->hasInitializer()) return E;
  auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer());
  if (!CA) { E.ok = false; E.why = "global_ctors not an array"; return E; }
  const DataLayout &DL = M.getDataLayout();
  std::map<const GlobalVariable *, std::set<const BasicBlock *>> storeBlocks;
  for (Use &U : CA->operands()) {
    auto *CS = dyn_cast<ConstantStruct>(U.get()); if (!CS) continue;
    auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()); if (!Fn || Fn->isDeclaration()) continue;
    for (BasicBlock &BB : *Fn) for (Instruction &I : BB) if (auto *SI = dyn_cast<StoreInst>(&I))
      if (auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts())) storeBlocks[G].insert(&BB);
  }
  for (Use &U : CA->operands()) {
    auto *CS = dyn_cast<ConstantStruct>(U.get()); if (!CS) continue;
    auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()); if (!Fn || Fn->isDeclaration()) continue;
    std::map<const Value *, AV> val;
    std::set<std::pair<const BasicBlock *, const BasicBlock *>> edges;
    std::set<const BasicBlock *> live{&Fn->getEntryBlock()};
    auto get = [&](Value *v) -> AV {
      if (auto *C = dyn_cast<Constant>(v)) { if (isa<GlobalValue>(C)) return avU(); return avC(C); }
      auto it = val.find(v); return it == val.end() ? AV() : it->second;
    };
    // An instruction with an undefined operand: LLVM's own constant folder decides, with the unset
    // constants as `undef` (Metal's specialiser is LLVM and folds them the same way: e.g.
    // `and undef, 0` -> 0, `or undef, -1` -> -1, `icmp sgt undef, C` -> false,
    // `icmp eq undef, C` -> undef, `select undef, X, Y` -> Y).  A result the folder leaves
    // undef (or cannot fold) stays undefined.
    auto foldU = [&](Instruction *I) -> AV {
      SmallVector<Constant *, 4> ops;
      for (Value *op : I->operands()) {
        AV v = get(op);
        ops.push_back(v.k == AV::C ? v.c : UndefValue::get(op->getType()));
      }
      Constant *res = ConstantFoldInstOperands(I, ops, DL, nullptr);
      if (!res || isa<UndefValue>(res)) return avU();
      return avC(res);
    };
    ReversePostOrderTraversal<Function *> RPOT(Fn);
    for (int iter = 0; iter < 64; iter++) {
      bool changed = false;
      auto setv = [&](Instruction *I, AV v) { AV o = val.count(I) ? val[I] : AV(); AV n = meet(o, v); if (!sameAV(o, n)) { val[I] = n; changed = true; } };
      auto edge = [&](BasicBlock *f, BasicBlock *t) { if (edges.insert({f, t}).second) changed = true; if (live.insert(t).second) changed = true; };
      for (BasicBlock *BB : RPOT) {
        if (!live.count(BB)) continue;
        for (Instruction &I : *BB) {
          if (auto *PN = dyn_cast<PHINode>(&I)) {
            AV r;
            for (unsigned i = 0; i < PN->getNumIncomingValues(); i++)
              if (edges.count({PN->getIncomingBlock(i), BB})) r = meet(r, get(PN->getIncomingValue(i)));
            setv(&I, r); continue;
          }
          if (auto *LI = dyn_cast<LoadInst>(&I)) {
            auto *G = dyn_cast<GlobalVariable>(LI->getPointerOperand()->stripPointerCasts());
            if (!G) { setv(&I, avU()); continue; }
            if (G->getSection() == "air.fc_initializer") {
              int idx = fcIndexOfGlobal(G->getName());
              setv(&I, idx >= 0 && fc.count(idx) ? avC(fcLoadConstant(G, LI->getType(), fc.at(idx), DL)) : avU());
              continue;
            }
            auto m = E.mem.find(G);
            if (m != E.mem.end()) {
              if (m->second.k == AV::C) { Constant *pc = punStored(m->second.c, LI->getType(), DL); setv(&I, pc ? avC(pc) : avU()); }
              else setv(&I, m->second);
              continue;
            }
            if (G->hasInitializer() && G->getInitializer()->getType() == LI->getType()) setv(&I, avC(G->getInitializer()));
            else setv(&I, avU());
            continue;
          }
          if (auto *SI = dyn_cast<StoreInst>(&I)) {
            auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts());
            if (!G) continue;
            AV v = get(SI->getValueOperand());
            if (v.k == AV::Unknown) continue;
            AV &slot = E.mem[G];
            AV n = storeBlocks[G].size() > 1 ? meet(slot, v) : v;       // one store site: last write wins
            if (!sameAV(slot, n)) { slot = n; changed = true; }
            continue;
          }
          if (auto *CI = dyn_cast<CallInst>(&I)) {
            Function *cf = CI->getCalledFunction();
            StringRef nm = cf ? cf->getName() : "";
            if (nm.starts_with("air.normalize_function_constant_predicate")) {
              AV x = get(argOperand(CI, 0));
              if (x.k == AV::Unknown) continue;
              AV r;
              if (x.k == AV::U) r = avC(Constant::getNullValue(CI->getType()));
              else { auto *ci = dyn_cast<ConstantInt>(x.c); r = avC(ConstantInt::get(CI->getType(), ci ? !ci->isZero() : 0)); }
              setv(&I, r); E.normalize[CI] = val[&I];
              continue;
            }
            if (nm == "air.is_function_constant_defined") {
              auto *G = dyn_cast<GlobalVariable>(argOperand(CI, 0)->stripPointerCasts());
              int idx = G ? fcIndexOfGlobal(G->getName()) : -1;
              setv(&I, avC(ConstantInt::getBool(CI->getContext(), idx >= 0 && fc.count(idx))));
              continue;
            }
            if (cf && cf->isIntrinsic() && (cf->getIntrinsicID() == Intrinsic::lifetime_start || cf->getIntrinsicID() == Intrinsic::lifetime_end)) continue;
            if (cf && cf->isDeclaration() && nm.starts_with("air.")) {
              // fix round 5 (verify5 item 2 + minor): an AIR conversion with a constant operand folds
              // (foldCtorAirCall); an undefined operand makes it undefined.  What does not fold (NaN /
              // out-of-range float -> integer: poison in Metal; any other AIR function, which Metal
              // rejects in a static initialiser) leaves the initialiser unevaluated: the predicates it
              // computes are then refused, never guessed.
              SmallVector<Constant *, 3> args; bool unk = false, und = false;
              for (Value *op : CI->args()) { AV x = get(op); if (x.k == AV::Unknown) unk = true; else if (x.k == AV::U) und = true; else args.push_back(x.c); }
              if (unk) continue;
              if (und) { setv(&I, avU()); continue; }
              if (Constant *r = foldCtorAirCall(CI, args)) { setv(&I, avC(r)); continue; }
              E.ok = false; E.why = ctorCallStr(CI, args) + " in the static initialiser does not fold"; return E;
            }
            E.ok = false; E.why = "call to " + nm.str() + " in the static initialiser"; return E;
          }
          if (auto *Br = dyn_cast<BranchInst>(&I)) {
            if (Br->isUnconditional()) { edge(BB, Br->getSuccessor(0)); continue; }
            AV c = get(Br->getCondition());
            if (c.k == AV::Unknown) continue;
            // branch on undef: Metal takes the false edge (successor 1), as LLVM SCCP's
            // "resolve undef branch" does (measured: fixture fc3, predicate Q7 = A ? .. : .. with A unset).
            if (c.k == AV::U) { edge(BB, Br->getSuccessor(1)); continue; }
            edge(BB, cast<ConstantInt>(c.c)->isOne() ? Br->getSuccessor(0) : Br->getSuccessor(1));
            continue;
          }
          if (auto *SW = dyn_cast<SwitchInst>(&I)) {
            AV c = get(SW->getCondition());
            if (c.k == AV::Unknown) continue;
            // switch on undef: the first case (LLVM SCCP's "resolve undef switch"; ABI v4, measured
            // in the function body by the randomized differential test, tests/fcrand.py).  v3 took
            // the default edge here.
            if (c.k == AV::U) { edge(BB, SW->getNumCases() ? SW->case_begin()->getCaseSuccessor() : SW->getDefaultDest()); continue; }
            edge(BB, SW->findCaseValue(cast<ConstantInt>(c.c))->getCaseSuccessor());
            continue;
          }
          if (isa<ReturnInst>(&I) || isa<UnreachableInst>(&I)) continue;
          if (auto *Sel = dyn_cast<SelectInst>(&I)) {
            AV c = get(Sel->getCondition()), t = get(Sel->getTrueValue()), f = get(Sel->getFalseValue());
            if (c.k == AV::Unknown) continue;
            if (c.k == AV::C) {
              AV r = cast<ConstantInt>(c.c)->isOne() ? t : f;
              if (r.k != AV::Unknown) setv(&I, r);
              continue;
            }
            if (t.k == AV::Unknown || f.k == AV::Unknown) continue;
            // select undef, X, Y: LLVM's constant folder (ConstantFoldSelectInstruction) gives Y
            // unless X is undef, and so does Metal (fixtures fcsem/fc2/fc3, 405 cases, regression
            // test unset_fc_semantics).  v2 of this file returned "undefined" unless X == Y, which
            // disagreed with Metal for A ? B : C and (A || B) && C with A unset (verify2 item 5).
            setv(&I, foldU(&I));
            continue;
          }
          // generic: constant-fold; an undefined operand makes the result undefined unless absorbed
          SmallVector<Constant *, 4> ops; bool anyU = false, anyUnknown = false;
          for (Value *op : I.operands()) {
            AV v = get(op);
            if (v.k == AV::Unknown) anyUnknown = true; else if (v.k == AV::U) anyU = true; else ops.push_back(v.c);
          }
          if (anyUnknown) continue;
          if (anyU) { setv(&I, foldU(&I)); continue; }
          Constant *res = ConstantFoldInstOperands(&I, ops, DL, nullptr);
          if (!res) { E.ok = false; E.why = "cannot fold " + str(&I); return E; }
          if (std::string w = fmfPoison(I, ops, res); !w.empty()) { E.ok = false; E.why = w + " in the static initialiser"; return E; }
          setv(&I, avC(res));
        }
      }
      if (!changed) break;
      if (iter == 63) { E.ok = false; E.why = "static initialiser did not converge"; return E; }
    }
  }
  return E;
}

// ---------------------------------------------------------- unset constants in the body (ABI v4) --
// See resolve_unset_in_body below: an unset constant may decide the static-initialiser predicates
// (presence, reproduced exactly as Metal does, abstract_eval_ctors), but not anything in the body.
// Constant folding of the AIR integer intrinsics (min/max/abs/clamp) and of int/float conversions
// with constant scalar operands.  LLVM cannot fold these calls; Metal's compiler can (it knows its
// own intrinsics), so without this a `switch (min(N, 2))` with N set kept every case and marked
// buffers used that Metal's specialised code never reads (tests/fcrand.py).  Folding a call whose
// operands are all constants changes no value.
static Constant *foldAirCall(CallInst *CI, ArrayRef<Constant *> argv = {}) {
  Function *cf = CI->getCalledFunction();
  if (!cf || !cf->getName().starts_with("air.")) return nullptr;
  StringRef nm = cf->getName();
  Type *RT = CI->getType();
  if (RT->isVectorTy()) return nullptr;
  if (!argv.empty() && argv.size() != CI->arg_size()) return nullptr;
  SmallVector<ConstantInt *, 3> ci; SmallVector<ConstantFP *, 3> cfp;
  for (unsigned i = 0; i < CI->arg_size(); i++) {           // argv: the operands' values (static-initialiser evaluators)
    Value *a = argv.empty() ? argOperand(CI, i) : argv[i];
    if (auto *c = dyn_cast<ConstantInt>(a)) ci.push_back(c);
    else if (auto *f = dyn_cast<ConstantFP>(a)) cfp.push_back(f);
    else return nullptr;
  }
  auto I = [&](const APInt &v) { return ConstantInt::get(RT, v); };
  if (ci.size() == CI->arg_size() && RT->isIntegerTy()) {
    if (nm.starts_with("air.min.s.") && ci.size() == 2) return I(APIntOps::smin(ci[0]->getValue(), ci[1]->getValue()));
    if (nm.starts_with("air.max.s.") && ci.size() == 2) return I(APIntOps::smax(ci[0]->getValue(), ci[1]->getValue()));
    if (nm.starts_with("air.min.u.") && ci.size() == 2) return I(APIntOps::umin(ci[0]->getValue(), ci[1]->getValue()));
    if (nm.starts_with("air.max.u.") && ci.size() == 2) return I(APIntOps::umax(ci[0]->getValue(), ci[1]->getValue()));
    if (nm.starts_with("air.abs.s.") && ci.size() == 1) return I(ci[0]->getValue().abs());
    if (nm.starts_with("air.clamp.s.") && ci.size() == 3) return I(APIntOps::smin(APIntOps::smax(ci[0]->getValue(), ci[1]->getValue()), ci[2]->getValue()));
    if (nm.starts_with("air.clamp.u.") && ci.size() == 3) return I(APIntOps::umin(APIntOps::umax(ci[0]->getValue(), ci[1]->getValue()), ci[2]->getValue()));
  }
  if (nm.starts_with("air.convert.") && CI->arg_size() == 1) {
    SmallVector<StringRef, 6> parts; nm.split(parts, '.');
    if (parts.size() < 5) return nullptr;
    char dk = parts[2][0], sk = parts[4][0];
    Type *ST = argOperand(CI, 0)->getType();
    if (ST->isIntegerTy(1) || RT->isIntegerTy(1)) return nullptr;
    if (ci.size() == 1 && dk == 'f') {
      APFloat f(RT->getFltSemantics());
      f.convertFromAPInt(ci[0]->getValue(), sk == 's', APFloat::rmNearestTiesToEven);
      return ConstantFP::get(RT, f);
    }
    if (ci.size() == 1 && (dk == 's' || dk == 'u'))
      return I(sk == 's' ? ci[0]->getValue().sextOrTrunc(RT->getIntegerBitWidth()) : ci[0]->getValue().zextOrTrunc(RT->getIntegerBitWidth()));
    // verify6 must-fix 4: float -> integer truncates toward zero, as Metal folds it (and as
    // foldCtorAirCall does): char(-128.5) == -128, short(-32768.5) == -32768.  Left to NIR, the constant
    // reached nir_opcodes' f2i8 / f2i16 folding, which calls any source below the type's minimum
    // poison BEFORE truncating and returned 0 (cv_neg, cv_charm128, cv_shortm32768).  NaN or a value
    // whose truncation is out of range is poison in Metal: not folded.
    if (cfp.size() == 1 && (dk == 's' || dk == 'u') && RT->isIntegerTy()) {
      APSInt r(RT->getIntegerBitWidth(), dk == 'u'); bool exact = false;
      if (cfp[0]->getValueAPF().convertToInteger(r, APFloat::rmTowardZero, &exact) & APFloat::opInvalidOp) return nullptr;
      return ConstantInt::get(RT, r);
    }
  }
  return nullptr;
}
// AIR conversions in the static initialiser (fix round 5, verify5 item 2 and minor 1).  With a
// constant operand, the conversions the front end emits for bool(F), int(F), uint(F), short(H),
// float(N), half(N) ... fold, so a predicate that reads them is known when every constant is set, and
// judged by the value-independence model when some are unset.  v4 folded none of them: with every
// constant set a predicate such as `int(F) == 2` fell back to "present if used" (verify5 item 2), and
// with one unset the variant was refused whatever the call read (verify5 minor).  Only conversions:
// Metal itself rejects a pipeline whose static initialiser calls popcount / clz / clamp / abs / floor
// ("cannot have global constructors", tests/fixtures/v5/ctor_helpers.metal, regression test
// ctor_air_calls), so those still leave the initialiser unevaluated and the variant refused, as in
// Metal.  Metal's folding, measured (tests/fixtures/v5/convprobe.metal): float -> integer truncates
// toward zero (uint(-0.5) == 0); NaN or a truncated value outside the destination range is poison
// (int(F) == INT_MAX false for F = inf / 1e10 / 3e9, uint(-7.5) == 0 false, uchar(300.0) == 255
// false) and is NOT folded here: the variant is refused where it decides a predicate; bool(x) = x != 0
// (NaN true).
static Constant *foldCtorAirCall(CallInst *CI, ArrayRef<Constant *> args) {
  Function *cf = CI->getCalledFunction();
  if (!cf || !cf->getName().starts_with("air.convert.") || args.size() != 1 || CI->arg_size() != 1) return nullptr;
  StringRef nm = cf->getName();
  Type *RT = CI->getType();
  if (RT->isVectorTy()) return nullptr;
  SmallVector<StringRef, 6> parts; nm.split(parts, '.');
  if (parts.size() < 5) return nullptr;
  char dk = parts[2][0];
  if (auto *fx = dyn_cast<ConstantFP>(args[0])) {
    const APFloat &f = fx->getValueAPF();
    if (RT->isIntegerTy(1)) return ConstantInt::getBool(RT->getContext(), !f.isZero());
    if (RT->isIntegerTy() && (dk == 's' || dk == 'u')) {
      APSInt r(RT->getIntegerBitWidth(), dk == 'u'); bool exact = false;
      if (f.convertToInteger(r, APFloat::rmTowardZero, &exact) & APFloat::opInvalidOp) return nullptr;   // poison in Metal
      return ConstantInt::get(RT, r);
    }
    if (RT->isFloatingPointTy() && dk == 'f') {
      APFloat g = f; bool lost = false;
      g.convert(RT->getFltSemantics(), APFloat::rmNearestTiesToEven, &lost);
      return ConstantFP::get(RT, g);
    }
    return nullptr;
  }
  auto *ix = dyn_cast<ConstantInt>(args[0]);
  if (!ix) return nullptr;
  if (RT->isIntegerTy(1)) return ConstantInt::getBool(RT->getContext(), !ix->isZero());
  if (ix->getType()->isIntegerTy(1)) {
    if (RT->isFloatingPointTy()) return ConstantFP::get(RT, ix->isOne() ? 1.0 : 0.0);
    if (RT->isIntegerTy()) return ConstantInt::get(RT, ix->isOne() ? 1 : 0);
  }
  return foldAirCall(CI, args);                                   // integer -> float / integer
}
static std::string ctorCallStr(CallInst *CI, ArrayRef<Constant *> args) {
  std::string r; raw_string_ostream os(r);
  os << (CI->getCalledFunction() ? CI->getCalledFunction()->getName() : StringRef("?")) << "(";
  for (unsigned i = 0; i < args.size(); i++) { if (i) os << ", "; args[i]->printAsOperand(os, true); }
  os << ")";
  return os.str();
}
// An AIR integer min/max/abs/clamp or scalar conversion with an UNDEFINED operand is expanded into
// plain LLVM instructions (icmp + select, sitofp, ...), so resolve_unset_in_body can tell whether its
// result depends on the undefined value (`min(N, 2) >= -5` does not; `min(N, 2) == 2` does).
static Value *expandAirCall(CallInst *CI) {
  Function *cf = CI->getCalledFunction();
  if (!cf) return nullptr;
  StringRef nm = cf->getName();
  Type *RT = CI->getType();
  if (RT->isVectorTy()) return nullptr;
  IRBuilder<> B(CI);
  auto mm = [&](CmpInst::Predicate p, Value *a, Value *b) { return B.CreateSelect(B.CreateICmp(p, a, b), a, b); };
  if (RT->isIntegerTy() && !RT->isIntegerTy(1)) {
    if (nm.starts_with("air.min.s.")) return mm(CmpInst::ICMP_SLT, argOperand(CI, 0), argOperand(CI, 1));
    if (nm.starts_with("air.max.s.")) return mm(CmpInst::ICMP_SGT, argOperand(CI, 0), argOperand(CI, 1));
    if (nm.starts_with("air.min.u.")) return mm(CmpInst::ICMP_ULT, argOperand(CI, 0), argOperand(CI, 1));
    if (nm.starts_with("air.max.u.")) return mm(CmpInst::ICMP_UGT, argOperand(CI, 0), argOperand(CI, 1));
    if (nm.starts_with("air.clamp.s.")) return mm(CmpInst::ICMP_SLT, mm(CmpInst::ICMP_SGT, argOperand(CI, 0), argOperand(CI, 1)), argOperand(CI, 2));
    if (nm.starts_with("air.clamp.u.")) return mm(CmpInst::ICMP_ULT, mm(CmpInst::ICMP_UGT, argOperand(CI, 0), argOperand(CI, 1)), argOperand(CI, 2));
    if (nm.starts_with("air.abs.s.")) { Value *x = argOperand(CI, 0); return B.CreateSelect(B.CreateICmpSLT(x, Constant::getNullValue(RT)), B.CreateNeg(x), x); }
  }
  if (nm.starts_with("air.convert.") && CI->arg_size() == 1) {
    SmallVector<StringRef, 6> parts; nm.split(parts, '.');
    if (parts.size() < 5) return nullptr;
    char dk = parts[2][0], sk = parts[4][0];
    Value *x = argOperand(CI, 0); Type *ST = x->getType();
    if (ST->isIntegerTy(1) || RT->isIntegerTy(1) || ST->isVectorTy()) return nullptr;
    if (dk == 'f' && sk == 's') return B.CreateSIToFP(x, RT);
    if (dk == 'f' && sk == 'u') return B.CreateUIToFP(x, RT);
    if (dk == 's' && sk == 'f') return B.CreateFPToSI(x, RT);
    if (dk == 'u' && sk == 'f') return B.CreateFPToUI(x, RT);
    // integer -> integer: C semantics, the SOURCE signedness picks the extension (uint(short(-1)) is
    // 0xffffffff, int(ushort(65535)) is 65535); fix round 6 (v5 zero-extended every conversion to an
    // unsigned type and did not expand unsigned -> signed)
    if ((dk == 's' || dk == 'u') && sk == 's') return B.CreateSExtOrTrunc(x, RT);
    if ((dk == 's' || dk == 'u') && sk == 'u') return B.CreateZExtOrTrunc(x, RT);
  }
  return nullptr;
}
static bool foldAirCalls(Module &M) {
  bool any = false;
  for (Function &F : M) for (BasicBlock &BB : F) for (Instruction &I : make_early_inc_range(BB))
    if (auto *CI = dyn_cast<CallInst>(&I)) if (Constant *c = foldAirCall(CI)) { CI->replaceAllUsesWith(c); CI->eraseFromParent(); any = true; }
  return any;
}

struct UnsetResolveStats { unsigned markers = 0, folded = 0, independent = 0; };
static std::string fcNameOfGlobal(const GlobalVariable *G, const std::vector<FcDecl> &decls) {
  int idx = fcIndexOfGlobal(G->getName());
  for (auto &d : decls) if (d.index == idx || d.global == G->getName()) return d.name + " (index " + std::to_string(d.index) + ")";
  return G->getName().str();
}
// knownGlobals: every constant global the body may load whose value the specialisation decides:
// the function-constant initialisers (value, or nullptr when unset) and the static-initialiser
// shadows (the abstract evaluation's constant, or nullptr when undefined).
struct KnownGlobal { Constant *value = nullptr; std::string name; };
// ------------------------------------------ unset constants: value independence, proved (ABI v5) --
// verify4 item 1: ABI v4 decided "independent of the unset constant" from a handful of sample values
// (0, 1, 2, 3, -1, 5, 17, 255, INT_MIN, INT_MAX), so `N == 4` was false for every sample and folded to
// false, while Metal leaves it undefined and often takes the true side (verify4 work/fc/min m0..m6).
// ABI v5 folds a use of an unset constant only when the result is PROVABLY the same for every value
// the undefined operands can take, and every other use stays undefined (and is refused where it
// decides something).  The model is LLVM's undef as Metal's specialiser sees it: every USE of an
// unset constant may take a different value (so `N - N` or `A != A` is not independent), and a value
// that can be poison for some constant value is never folded.
//   - small domains are enumerated exhaustively: every operand combination whose domains multiply to
//     at most 2^16 (bool, i8 and i16 constants, i1 results, two i8s, ...), each combination folded by
//     LLVM (ConstantFold / InstSimplify), and the poison-generating flags (nsw/nuw/exact/disjoint/
//     nneg/samesign, fast-math nnan/ninf) and out-of-range shifts / zero divisors checked;
//   - wider integers (i32/i64) by LLVM ConstantRange arithmetic (its and/or/xor use KnownBits): an
//     icmp is independent only when ConstantRange::icmp proves it true (or its inverse true) for the
//     whole ranges, a binary operator or cast only when its range is a single value and no flag can
//     make it poison;
//   - floats and vectors: never independent through arithmetic (a float constant can be any value,
//     NaN and infinities included), only structurally (select with equal arms, extractelement of a
//     lane the constant never reached).
struct UAbs {                                   // an undefined (tainted) value
  bool poison = false;                          // may be poison for some value of the constants
  bool hasRange = false;                        // integer scalar: every value it may take is in cr
  ConstantRange cr = ConstantRange::getFull(1);
};
static UAbs uFull(Type *T) {
  UAbs a;
  if (T->isIntegerTy()) { a.hasRange = true; a.cr = ConstantRange::getFull(T->getIntegerBitWidth()); }
  return a;
}
static UAbs uJoin(const UAbs &x, const UAbs &y) {
  UAbs r; r.poison = x.poison || y.poison;
  if (x.hasRange && y.hasRange && x.cr.getBitWidth() == y.cr.getBitWidth()) { r.hasRange = true; r.cr = x.cr.unionWith(y.cr); }
  return r;
}
struct UOpnd { Value *v = nullptr; const UAbs *t = nullptr; };  // defined value (v), or undefined (t; v = the SSA value)
struct UResult { Value *v = nullptr; UAbs a; };                  // v: the result, the same for every value; else a
static const uint64_t UNSET_ENUM_LIMIT = 1u << 16;
static ConstantRange uRange(const UOpnd &o, unsigned w) {
  if (o.t) return o.t->hasRange && o.t->cr.getBitWidth() == w ? o.t->cr : ConstantRange::getFull(w);
  if (auto *ci = dyn_cast_or_null<ConstantInt>(o.v)) return ConstantRange(ci->getValue());
  return ConstantRange::getFull(w);
}
// Members of an undefined operand's domain, or empty when too many to enumerate.
static std::vector<Constant *> uMembers(const UOpnd &o, uint64_t limit) {
  std::vector<Constant *> r;
  Type *T = o.v->getType();
  if (!T->isIntegerTy() || o.t->poison) return r;
  unsigned w = T->getIntegerBitWidth();
  ConstantRange cr = uRange(o, w);
  if (cr.isEmptySet() || cr.isSizeLargerThan(limit)) return r;
  uint64_t n = cr.isFullSet() ? (uint64_t(1) << w) : (cr.getUpper() - cr.getLower()).getZExtValue();
  APInt x = cr.isFullSet() ? APInt::getZero(w) : cr.getLower();
  for (uint64_t i = 0; i < n; i++, ++x) r.push_back(ConstantInt::get(T->getContext(), x));
  return r;
}
// Does I, evaluated on these (constant where the constants were substituted) operands, give poison
// (or UB)?  `res` is what LLVM folded it to.  Conservative: true when it cannot tell.
static bool uPoisonAt(Instruction &I, ArrayRef<Value *> ops, Value *res) {
  if (auto *c = dyn_cast_or_null<Constant>(res)) if (isa<UndefValue>(c) || c->containsUndefOrPoisonElement()) return true;
  auto C = [&](unsigned i) -> ConstantInt * { return i < ops.size() ? dyn_cast<ConstantInt>(ops[i]) : nullptr; };
  auto FP = [&](Value *v) -> const ConstantFP * { return dyn_cast_or_null<ConstantFP>(v); };
  // fast-math nnan / ninf: poison when a substituted (constant) operand or the folded result is NaN /
  // infinite.  Non-constant operands are the variant's own run-time values, not the constant's.
  if (isa<FPMathOperator>(&I) && (I.hasNoNaNs() || I.hasNoInfs())) {
    auto bad = [&](Value *v) {
      if (!v || !v->getType()->isFPOrFPVectorTy() || !isa<Constant>(v)) return false;
      const ConstantFP *f = FP(v); if (!f) return true;   // constant vectors: cannot tell cheaply
      return (I.hasNoNaNs() && f->isNaN()) || (I.hasNoInfs() && f->isInfinity());
    };
    for (Value *v : ops) if (bad(v)) return true;
    if (bad(res)) return true;
  }
  unsigned opc = I.getOpcode();
  switch (opc) {
  case Instruction::Add: case Instruction::Sub: case Instruction::Mul: case Instruction::Shl: {
    auto *OBO = cast<OverflowingBinaryOperator>(&I);
    ConstantInt *a = C(0), *b = C(1);
    if (opc == Instruction::Shl && (!b || b->getValue().uge(b->getBitWidth()))) return true;
    if (!OBO->hasNoSignedWrap() && !OBO->hasNoUnsignedWrap()) return false;
    if (!a || !b) return true;
    bool so = false, uo = false; const APInt &x = a->getValue(), &y = b->getValue();
    if (opc == Instruction::Add) { (void)x.sadd_ov(y, so); (void)x.uadd_ov(y, uo); }
    if (opc == Instruction::Sub) { (void)x.ssub_ov(y, so); (void)x.usub_ov(y, uo); }
    if (opc == Instruction::Mul) { (void)x.smul_ov(y, so); (void)x.umul_ov(y, uo); }
    if (opc == Instruction::Shl) { (void)x.sshl_ov(y, so); (void)x.ushl_ov(y, uo); }
    return (OBO->hasNoSignedWrap() && so) || (OBO->hasNoUnsignedWrap() && uo);
  }
  case Instruction::LShr: case Instruction::AShr: {
    ConstantInt *a = C(0), *b = C(1);
    if (!b || b->getValue().uge(b->getBitWidth())) return true;
    if (cast<PossiblyExactOperator>(&I)->isExact()) return !a || a->getValue().countr_zero() < b->getValue().getZExtValue();
    return false;
  }
  case Instruction::UDiv: case Instruction::SDiv: case Instruction::URem: case Instruction::SRem: {
    ConstantInt *a = C(0), *b = C(1);
    if (!b || b->isZero()) return true;                                         // division by zero: UB
    if ((opc == Instruction::SDiv || opc == Instruction::SRem) && b->isMinusOne() && (!a || a->getValue().isMinSignedValue())) return true;
    if (isa<PossiblyExactOperator>(&I) && cast<PossiblyExactOperator>(&I)->isExact())
      return !a || !(opc == Instruction::UDiv ? a->getValue().urem(b->getValue()) : a->getValue().srem(b->getValue())).isZero();
    return false;
  }
  case Instruction::Or:
    if (cast<PossiblyDisjointInst>(&I)->isDisjoint()) { ConstantInt *a = C(0), *b = C(1); return !a || !b || (a->getValue() & b->getValue()) != 0; }
    return false;
  case Instruction::And: case Instruction::Xor: case Instruction::Select: case Instruction::PHI: case Instruction::Freeze:
  case Instruction::SExt: case Instruction::BitCast: case Instruction::FPExt: case Instruction::FPTrunc:
  case Instruction::SIToFP: case Instruction::FCmp: case Instruction::FAdd: case Instruction::FSub: case Instruction::FMul:
  case Instruction::FDiv: case Instruction::FRem: case Instruction::FNeg:
  case Instruction::ExtractElement: case Instruction::InsertElement: case Instruction::ShuffleVector:
  case Instruction::ExtractValue: case Instruction::InsertValue:
    return false;                                                               // (poison results caught above)
  case Instruction::ICmp:
    if (cast<ICmpInst>(&I)->hasSameSign()) { ConstantInt *a = C(0), *b = C(1); return !a || !b || a->isNegative() != b->isNegative(); }
    return false;
  case Instruction::Trunc: {
    auto *TI = cast<TruncInst>(&I);
    if (!TI->hasNoUnsignedWrap() && !TI->hasNoSignedWrap()) return false;
    ConstantInt *a = C(0); if (!a) return true;
    unsigned w = I.getType()->getScalarSizeInBits();
    return (TI->hasNoUnsignedWrap() && !a->getValue().isIntN(w)) || (TI->hasNoSignedWrap() && !a->getValue().isSignedIntN(w));
  }
  case Instruction::ZExt: case Instruction::UIToFP:
    if (cast<PossiblyNonNegInst>(&I)->hasNonNeg()) { ConstantInt *a = C(0); return !a || a->isNegative(); }
    return false;
  default:
    return canCreateUndefOrPoison(cast<Operator>(&I), /*ConsiderFlagsAndMetadata=*/true);
  }
}
// Evaluate I, some of whose operands are undefined, under the model above.
//   isUndef(v): whether the value v (a folded result) is itself undefined.
static UResult uEval(Instruction &I, ArrayRef<UOpnd> ops, const SimplifyQuery &SQ, const TargetLibraryInfo *TLI,
                     const std::function<bool(Value *)> &isUndef) {
  const DataLayout &DL = I.getModule()->getDataLayout();
  UResult R;
  bool anyPoison = false;
  for (auto &o : ops) if (o.t && o.t->poison) anyPoison = true;
  auto undefOut = [&](bool poison) { UResult u; u.a = uFull(I.getType()); u.a.poison = poison; return u; };
  // select on a defined constant condition: the chosen arm, whatever the other one is
  if (auto *Sel = dyn_cast<SelectInst>(&I))
    if (!ops[0].t) if (auto *c = dyn_cast<ConstantInt>(ops[0].v)) { R.v = c->isOne() ? Sel->getTrueValue() : Sel->getFalseValue(); return R; }
  // structural: a lane / field the undefined value never reached (no arithmetic on it)
  if (isa<ExtractElementInst>(&I) || isa<ExtractValueInst>(&I) || isa<ShuffleVectorInst>(&I)) {
    if (Value *r = simplifyInstruction(&I, SQ.getWithInstruction(&I))) { R.v = r; return R; }
  }
  // 1. exhaustive enumeration of small domains
  std::vector<unsigned> tops; std::vector<std::vector<Constant *>> dom; uint64_t combos = 1; bool enumerable = true;
  for (unsigned i = 0; i < ops.size(); i++) {
    if (!ops[i].t) continue;
    auto m = uMembers(ops[i], UNSET_ENUM_LIMIT);
    if (m.empty()) { enumerable = false; break; }
    combos *= m.size();
    if (combos > UNSET_ENUM_LIMIT) { enumerable = false; break; }
    tops.push_back(i); dom.push_back(std::move(m));
  }
  if (enumerable && !tops.empty()) {
    Value *common = nullptr; bool same = true, poison = false, allInt = true;
    APInt lo, hi; bool haveLH = false;
    SmallVector<Value *, 4> vals; for (auto &o : ops) vals.push_back(o.v);
    for (uint64_t c = 0; c < combos; c++) {
      uint64_t k = c;
      for (size_t j = 0; j < tops.size(); j++) { vals[tops[j]] = dom[j][k % dom[j].size()]; k /= dom[j].size(); }
      Value *r = nullptr;
      bool allC = !isa<PHINode>(&I);
      SmallVector<Constant *, 4> cs;
      for (Value *v : vals) { auto *cc = dyn_cast<Constant>(v); if (!cc || isa<GlobalValue>(cc)) { allC = false; break; } cs.push_back(cc); }
      if (allC) r = ConstantFoldInstOperands(&I, cs, DL, TLI);
      if (!r) r = simplifyInstructionWithOperands(&I, vals, SQ.getWithInstruction(&I));
      if (!r) return undefOut(anyPoison);                                       // not foldable: depends on it
      if (uPoisonAt(I, vals, r)) { poison = true; same = false; break; }
      if (!common) common = r; else if (common != r) same = false;
      if (auto *ci = dyn_cast<ConstantInt>(r)) {
        if (!haveLH) { lo = hi = ci->getValue(); haveLH = true; }
        else { if (ci->getValue().ult(lo)) lo = ci->getValue(); if (ci->getValue().ugt(hi)) hi = ci->getValue(); }
      } else allInt = false;
      if (!same && !allInt) break;
    }
    if (same && !poison && !anyPoison) { R.v = common; return R; }
    UResult u = undefOut(poison || anyPoison);
    if (!poison && allInt && haveLH && I.getType()->isIntegerTy()) { u.a.hasRange = true; u.a.cr = ConstantRange::getNonEmpty(lo, hi + 1); }
    return u;
  }
  // 2. integer ranges
  Type *RT = I.getType();
  auto isIntOp = [&](const UOpnd &o) { return o.v->getType()->isIntegerTy(); };
  bool ints = RT->isIntegerTy();
  for (auto &o : ops) if (!isIntOp(o)) ints = false;
  if (ints && (isa<BinaryOperator>(&I) || isa<ICmpInst>(&I) || isa<TruncInst>(&I) || isa<ZExtInst>(&I) || isa<SExtInst>(&I) ||
               isa<SelectInst>(&I) || isa<PHINode>(&I) || isa<FreezeInst>(&I))) {
    unsigned w = RT->getIntegerBitWidth();
    UResult u = undefOut(anyPoison);
    bool poison = anyPoison;
    if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
      ConstantRange L = uRange(ops[0], w), Rr = uRange(ops[1], w);
      unsigned opc = BO->getOpcode();
      using OR = ConstantRange::OverflowResult;
      if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(BO)) {
        bool nsw = OBO->hasNoSignedWrap(), nuw = OBO->hasNoUnsignedWrap();
        if (opc == Instruction::Add) { if (nsw && L.signedAddMayOverflow(Rr) != OR::NeverOverflows) poison = true; if (nuw && L.unsignedAddMayOverflow(Rr) != OR::NeverOverflows) poison = true; }
        if (opc == Instruction::Sub) { if (nsw && L.signedSubMayOverflow(Rr) != OR::NeverOverflows) poison = true; if (nuw && L.unsignedSubMayOverflow(Rr) != OR::NeverOverflows) poison = true; }
        if (opc == Instruction::Mul) {
          if (nsw) {                                            // no signedMulMayOverflow: multiply at twice the width
            ConstantRange P = L.signExtend(2 * w).multiply(Rr.signExtend(2 * w));
            if (P.getSignedMin().slt(APInt::getSignedMinValue(w).sext(2 * w)) || P.getSignedMax().sgt(APInt::getSignedMaxValue(w).sext(2 * w))) poison = true;
          }
          if (nuw && L.unsignedMulMayOverflow(Rr) != OR::NeverOverflows) poison = true;
        }
        if (opc == Instruction::Shl && (nsw || nuw)) poison = true;
      }
      if ((opc == Instruction::Shl || opc == Instruction::LShr || opc == Instruction::AShr) && Rr.getUnsignedMax().uge(w)) poison = true;
      if (isa<PossiblyExactOperator>(BO) && BO->isExact()) poison = true;
      if (opc == Instruction::UDiv || opc == Instruction::SDiv || opc == Instruction::URem || opc == Instruction::SRem) {
        if (Rr.contains(APInt::getZero(w))) poison = true;
        if ((opc == Instruction::SDiv || opc == Instruction::SRem) && L.contains(APInt::getSignedMinValue(w)) && Rr.contains(APInt::getAllOnes(w))) poison = true;
      }
      if (opc == Instruction::Or && cast<PossiblyDisjointInst>(BO)->isDisjoint()) poison = true;
      u.a.cr = L.binaryOp((Instruction::BinaryOps)opc, Rr);
    } else if (auto *IC = dyn_cast<ICmpInst>(&I)) {
      unsigned ow = ops[0].v->getType()->getIntegerBitWidth();
      ConstantRange L = uRange(ops[0], ow), Rr = uRange(ops[1], ow);
      if (IC->hasSameSign()) poison = true;
      if (L.icmp(IC->getPredicate(), Rr)) u.a.cr = ConstantRange(APInt(1, 1));
      else if (L.icmp(IC->getInversePredicate(), Rr)) u.a.cr = ConstantRange(APInt(1, 0));
      else u.a.cr = ConstantRange::getFull(1);
    } else if (auto *TI = dyn_cast<TruncInst>(&I)) {
      if (TI->hasNoUnsignedWrap() || TI->hasNoSignedWrap()) poison = true;
      u.a.cr = uRange(ops[0], ops[0].v->getType()->getIntegerBitWidth()).truncate(w);
    } else if (auto *ZI = dyn_cast<ZExtInst>(&I)) {
      ConstantRange L = uRange(ops[0], ops[0].v->getType()->getIntegerBitWidth());
      if (ZI->hasNonNeg() && !L.isAllNonNegative()) poison = true;
      u.a.cr = L.zeroExtend(w);
    } else if (isa<SExtInst>(&I)) {
      u.a.cr = uRange(ops[0], ops[0].v->getType()->getIntegerBitWidth()).signExtend(w);
    } else if (auto *Sel = dyn_cast<SelectInst>(&I)) {
      if (Sel->getTrueValue() == Sel->getFalseValue()) { R.v = Sel->getTrueValue(); if (!ops[0].t || !ops[0].t->poison) return R; }
      u.a.cr = uRange(ops[1], w).unionWith(uRange(ops[2], w));
    } else if (auto *PN = dyn_cast<PHINode>(&I)) {
      if (Value *same = PN->hasConstantValue()) { R.v = same; if (!anyPoison) return R; }
      ConstantRange cr = ConstantRange::getEmpty(w);
      for (auto &o : ops) cr = cr.unionWith(uRange(o, w));
      u.a.cr = cr;
    } else if (isa<FreezeInst>(&I)) {
      u.a.cr = uRange(ops[0], w); poison = false;
    }
    u.a.hasRange = true; u.a.poison = poison;
    if (!poison && u.a.cr.isSingleElement()) { R.v = ConstantInt::get(RT, *u.a.cr.getSingleElement()); return R; }
    return u;
  }
  // 3. anything else: select with equal arms, otherwise undefined
  if (auto *Sel = dyn_cast<SelectInst>(&I))
    if (Sel->getTrueValue() == Sel->getFalseValue() && !(ops[0].t && ops[0].t->poison)) { R.v = Sel->getTrueValue(); return R; }
  if (auto *PN = dyn_cast<PHINode>(&I))
    if (Value *same = PN->hasConstantValue()) if (!anyPoison) { R.v = same; return R; }
  return undefOut(anyPoison || canCreateUndefOrPoison(cast<Operator>(&I), /*ConsiderFlagsAndMetadata=*/true));
}

// resolve_unset_in_body (ABI v4, verify3 item 1; proof rule ABI v5, verify4 item 1): an unset
// function constant must not decide anything in the function body.  Its loads become "undefined"
// markers (any value of the constant's type); every instruction that uses one is evaluated by uEval:
// if the result is provably the same for every value (exhaustively for small domains, by
// ConstantRange otherwise), the constant does not matter there and the instruction folds to that
// result (`A && B` with B = false set, `and x, 0`, `select u, x, x`, `(N & 3) < 4`); otherwise the
// result stays undefined, with the range of values it may take.  A variant in which an undefined
// value decides a branch, a switch, a select that is used, a store, a call or the returned value is
// REFUSED:
//   "the value of unset function constant X reaches the body ...: set the constant".
// ABI v4 decided independence from ten sample values and folded `N == 4` to false (verify4 item 1).
// Why not reproduce Metal's choice, as the static initialiser does for the predicates?  Metal
// specialises with LLVM `undef` and its optimiser's choices depend on the surrounding code: the
// randomized differential test (tests/fcrand.py) and the reductions in scratch/probe found two
// branches of the same shape going opposite ways, `select u, true, false` giving false in one
// function and true in another, and no rule that matches: SCCP's false edge (ABI v3 fix round 2)
// matched 826 of 960 cases, JumpThreading's fewest-predecessors rule 772, Apple's own air-opt
// O1..O3 disagreed as well.  With this refusal every compiled variant matches Metal.
static UnsetResolveStats resolve_unset_in_body(Module &M, Function *entry, const std::set<Function *> &ctorFns,
                                               const std::map<const GlobalVariable *, KnownGlobal> &knownGlobals,
                                               const std::map<int, std::vector<double>> &fc) {
  UnsetResolveStats S;
  const DataLayout &DL = M.getDataLayout();
  // only the entry point and what it calls (a .air may hold other entry points: not ours to judge)
  std::set<Function *> reach{entry};
  { SmallVector<Function *, 8> w{entry};
    while (!w.empty()) { Function *f = w.pop_back_val();
      for (BasicBlock &BB : *f) for (Instruction &I : BB) if (auto *CI = dyn_cast<CallInst>(&I))
        if (Function *c = CI->getCalledFunction()) if (!c->isDeclaration() && reach.insert(c).second) w.push_back(c); } }
  std::map<Value *, std::string> origin;                        // marker -> which constant (for the refusal message)
  std::set<Value *> T;                                          // undefined values (markers + derived)
  std::map<Value *, UAbs> tabs;                                 // what each undefined value may be (uEval)
  std::vector<WeakVH> Tvh; std::vector<std::pair<WeakVH, std::string>> originVh;
  auto taint = [&](Value *v) { if (T.insert(v).second) Tvh.push_back(WeakVH(v)); };
  auto refreshT = [&] {
    T.clear(); std::vector<WeakVH> keep;
    for (auto &h : Tvh) if (h) { T.insert(h); keep.push_back(h); }
    Tvh.swap(keep);
    origin.clear(); for (auto &o : originVh) if (o.first) origin[(Value *)o.first] = o.second;
  };
  std::set<Function *> fns;
  for (auto &kv : knownGlobals) {
    GlobalVariable *G = const_cast<GlobalVariable *>(kv.first);
    SmallVector<User *, 16> work(G->user_begin(), G->user_end());
    while (!work.empty()) {
      User *U = work.pop_back_val();
      if (auto *CE = dyn_cast<ConstantExpr>(U)) { for (User *u2 : CE->users()) work.push_back(u2); continue; }
      auto *I = dyn_cast<Instruction>(U);
      if (!I || ctorFns.count(I->getFunction()) || !reach.count(I->getFunction())) continue;
      if (auto *LI = dyn_cast<LoadInst>(I)) {
        Constant *v = kv.second.value;
        bool direct = LI->getPointerOperand()->stripPointerCasts() == G && v && v->getType() == LI->getType();
        if (v && !direct) continue;                             // partial load of a defined constant: GlobalOpt folds it later
        fns.insert(LI->getFunction());
        if (v) { LI->replaceAllUsesWith(v); LI->eraseFromParent(); continue; }
        auto *mk = new FreezeInst(PoisonValue::get(LI->getType()), "air2ir3.unset", LI->getIterator());
        LI->replaceAllUsesWith(mk); LI->eraseFromParent();
        tabs[mk] = uFull(mk->getType()); taint(mk); origin[mk] = kv.second.name; originVh.push_back({WeakVH(mk), kv.second.name}); S.markers++;
        continue;
      }
      if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) { for (User *u2 : GEP->users()) work.push_back(u2); continue; }
      if (auto *BC = dyn_cast<CastInst>(I)) { for (User *u2 : BC->users()) work.push_back(u2); continue; }
      if (auto *CI = dyn_cast<CallInst>(I))                     // is_function_constant_defined(@c): folded below
        if (CI->getCalledFunction() && CI->getCalledFunction()->getName() == "air.is_function_constant_defined") continue;
      if (!kv.second.value) die("unset function constant " + kv.second.name + " is used by address (" + str(I) + "): set it");
    }
  }
  if (T.empty()) return S;                                      // nothing undefined reaches the body
  // is_function_constant_defined() is known up front.
  for (Function *F : fns) for (BasicBlock &BB : *F) for (Instruction &I : make_early_inc_range(BB))
    if (auto *CI = dyn_cast<CallInst>(&I))
      if (CI->getCalledFunction() && CI->getCalledFunction()->getName() == "air.is_function_constant_defined") {
        auto *G = dyn_cast<GlobalVariable>(argOperand(CI, 0)->stripPointerCasts());
        int idx = G ? fcIndexOfGlobal(G->getName()) : -1;
        CI->replaceAllUsesWith(ConstantInt::getBool(CI->getContext(), idx >= 0 && fc.count(idx))); CI->eraseFromParent();
      }
  auto originOf = [&](Value *v0) {
    std::set<Value *> seen; SmallVector<Value *, 8> w{v0};
    while (!w.empty()) {
      Value *x = w.pop_back_val();
      if (!seen.insert(x).second) continue;
      auto o = origin.find(x); if (o != origin.end()) return o->second;
      if (auto *xi = dyn_cast<Instruction>(x)) for (Value *op : xi->operands()) if (T.count(op)) w.push_back(op);
    }
    return std::string("?");
  };
  auto refuse = [&](Value *v, Instruction *where, const char *what) {
    std::string w = str(where); for (char &ch : w) if (ch == '\n') ch = ' ';
    die("the value of unset function constant " + originOf(v) + " " + what + " in the function body (" + w.substr(0, 140) +
        "); Metal leaves it undefined and its choice is not reproducible: set the constant (BINDING-ABI.md 3.7)");
  };
  TargetLibraryInfoImpl TLII(M.getTargetTriple()); TargetLibraryInfo TLI(TLII);
  // The value-independence evaluation of I (uEval) with the ranges of its undefined operands.
  auto evalUndef = [&](Instruction &I, const SimplifyQuery &SQ) -> UResult {
    SmallVector<UOpnd, 4> ops;
    for (Value *op : I.operands()) {
      UOpnd o; o.v = op;
      if (T.count(op)) { auto it = tabs.find(op); if (it == tabs.end()) it = tabs.emplace(op, uFull(op->getType())).first; o.t = &it->second; }
      ops.push_back(o);
    }
    return uEval(I, ops, SQ, &TLI, [&](Value *v) { return T.count(v) != 0; });
  };
  for (Function *F : fns) {
    bool changed = true;
    for (int iter = 0; changed; iter++) {
      if (iter > 10000) die("internal: resolving unset constants did not converge");
      changed = false;
      bool cfgChanged = false;
      DominatorTree DT(*F);
      SimplifyQuery SQ(DL, &TLI, &DT);
      ReversePostOrderTraversal<Function *> RPOT(F);
      for (BasicBlock *BB : RPOT) {
        for (Instruction &I : make_early_inc_range(*BB)) {
          if (T.count(&I)) continue;                           // already undefined (monotone)
          bool anyT = false, anyC = false, allC = true;
          for (Value *op : I.operands()) {
            if (T.count(op)) anyT = true;
            if (isa<Constant>(op) && !isa<GlobalValue>(op)) anyC = true; else if (!isa<BasicBlock>(op)) allC = false;
          }
          if (auto *Br = dyn_cast<BranchInst>(&I)) {
            if (!Br->isConditional()) continue;
            Value *c = Br->getCondition();
            if (T.count(c)) refuse(c, Br, "decides a branch");
            auto *ci = dyn_cast<ConstantInt>(c);
            if (!ci) continue;
            BasicBlock *keep = Br->getSuccessor(ci->isZero() ? 1 : 0), *drop = Br->getSuccessor(ci->isZero() ? 0 : 1);
            if (drop != keep) drop->removePredecessor(BB, /*KeepOneInputPHIs=*/true);
            BranchInst::Create(keep, Br->getIterator()); Br->eraseFromParent();
            changed = cfgChanged = true;
            break;
          }
          if (auto *SW = dyn_cast<SwitchInst>(&I)) {
            Value *c = SW->getCondition();
            if (T.count(c)) refuse(c, SW, "decides a switch");
            auto *ci = dyn_cast<ConstantInt>(c);
            if (!ci) continue;
            BasicBlock *keep = SW->findCaseValue(ci)->getCaseSuccessor();
            std::set<BasicBlock *> seen;
            for (unsigned i = 0; i < SW->getNumSuccessors(); i++) {
              BasicBlock *s = SW->getSuccessor(i);
              if (s != keep && seen.insert(s).second) s->removePredecessor(BB, /*KeepOneInputPHIs=*/true);
            }
            BranchInst::Create(keep, SW->getIterator()); SW->eraseFromParent();
            changed = cfgChanged = true;
            break;
          }
          bool pure = !I.getType()->isVoidTy() && !I.isTerminator() && !I.mayHaveSideEffects();
          if (!anyT) {
            // propagate the defined values first (Metal's GlobalOpt+InstCombine do), constant results only
            if (!(pure || (isa<CallInst>(&I) && allC && foldAirCall(cast<CallInst>(&I)))) || !(anyC || isa<PHINode>(&I))) continue;
            Value *r = allC && !isa<PHINode>(&I) ? ConstantFoldInstruction(&I, DL, &TLI) : simplifyInstruction(&I, SQ.getWithInstruction(&I));
            if (!r && allC) if (auto *CI = dyn_cast<CallInst>(&I)) r = foldAirCall(CI);
            if (!r) continue;
            auto *rc = dyn_cast<Constant>(r);
            if (!isa<PHINode>(&I) && !rc) continue;
            if (rc && (isa<UndefValue>(rc) || rc->containsUndefOrPoisonElement())) continue;
            I.replaceAllUsesWith(r); I.eraseFromParent(); changed = true;
            continue;
          }
          if (auto *CI = dyn_cast<CallInst>(&I))                // AIR integer ops / conversions -> plain instructions
            if (Value *e = expandAirCall(CI)) { CI->replaceAllUsesWith(e); CI->eraseFromParent(); changed = true; continue; }
          if (!pure) refuse(&I, &I, isa<ReturnInst>(&I) ? "reaches the returned value" : "reaches a store or a call");
          UResult ur = evalUndef(I, SQ);
          if (ur.v && ur.v != &I) {
            I.replaceAllUsesWith(ur.v); I.eraseFromParent(); S.independent++; changed = true;
            continue;
          }
          tabs[&I] = ur.a; taint(&I); changed = true;
        }
        if (cfgChanged) break;                                 // the traversal and DT are stale
      }
      if (cfgChanged) {
        std::set<BasicBlock *> alive;
        for (BasicBlock *bb : depth_first(&F->getEntryBlock())) alive.insert(bb);
        for (auto it = T.begin(); it != T.end();) {
          auto *I = cast<Instruction>(*it);
          if (I->getFunction() == F && !alive.count(I->getParent())) it = T.erase(it); else ++it;
        }
        removeUnreachableBlocks(*F);
      }
      refreshT();
    }
  }
  refreshT();
  // Anything still undefined must be dead: a use by a defined instruction means the constant
  // decides something the variant computes.
  std::set<Instruction *> live;
  for (Value *v : T) live.insert(cast<Instruction>(v));
  for (Instruction *I : live)
    for (User *U : I->users())
      if (auto *UI = dyn_cast<Instruction>(U))
        if (!T.count(UI)) refuse(I, UI, "reaches");
  bool again = true;
  while (again) {
    again = false;
    for (auto it = live.begin(); it != live.end();) {
      if ((*it)->use_empty()) { (*it)->eraseFromParent(); it = live.erase(it); again = true; } else ++it;
    }
  }
  if (!live.empty()) die("internal: undefined values left after resolving unset constants");
  return S;
}

// Which unset function constants each static-initialiser value can depend on (data and control
// dependence, over-approximated: a store below a conditional branch depends on the branch's
// condition).  Used to check whether a predicate is in fact the same for every value of the
// constants it reads (e.g. `(C && !B) || (!C && is_function_constant_defined(B))` with B set and
// C unset is true for C = 0 and C = 1, while the undef rules say undefined -> absent).
static std::map<const Value *, std::set<int>> ctorDeps(Module &M, const std::map<int, std::vector<double>> &fc) {
  std::map<const Value *, std::set<int>> dep;
  GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors");
  if (!ctors || !ctors->hasInitializer()) return dep;
  auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer());
  if (!CA) return dep;
  for (int round = 0; round < 8; round++) {
    bool changed = false;
    for (Use &U : CA->operands()) {
      auto *CS = dyn_cast<ConstantStruct>(U.get()); if (!CS) continue;
      auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()); if (!Fn || Fn->isDeclaration()) continue;
      std::set<int> ctrl;
      for (BasicBlock &BB : *Fn) if (auto *Br = dyn_cast<BranchInst>(BB.getTerminator())) if (Br->isConditional())
        { auto it = dep.find(Br->getCondition()); if (it != dep.end()) ctrl.insert(it->second.begin(), it->second.end()); }
      for (BasicBlock &BB : *Fn) if (auto *SW = dyn_cast<SwitchInst>(BB.getTerminator()))
        { auto it = dep.find(SW->getCondition()); if (it != dep.end()) ctrl.insert(it->second.begin(), it->second.end()); }
      for (BasicBlock &BB : *Fn) for (Instruction &I : BB) {
        std::set<int> d;
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
          if (auto *G = dyn_cast<GlobalVariable>(LI->getPointerOperand()->stripPointerCasts())) {
            if (G->getSection() == "air.fc_initializer") { int idx = fcIndexOfGlobal(G->getName()); if (idx >= 0 && !fc.count(idx)) d.insert(idx); }
            else { auto it = dep.find(G); if (it != dep.end()) d = it->second; }
          }
        } else for (Value *op : I.operands()) { auto it = dep.find(op); if (it != dep.end()) d.insert(it->second.begin(), it->second.end()); }
        if (isa<PHINode>(&I) || isa<StoreInst>(&I)) d.insert(ctrl.begin(), ctrl.end());
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
          if (auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts())) {
            auto &g = dep[G]; size_t n = g.size(); g.insert(d.begin(), d.end()); if (g.size() != n) changed = true;
          }
          continue;
        }
        auto &cur = dep[&I]; size_t n = cur.size(); cur.insert(d.begin(), d.end()); if (cur.size() != n) changed = true;
      }
    }
    if (!changed) break;
  }
  return dep;
}
// ---------------------------------------- unset constants in the static initialiser (ABI v5) --
// The static initialiser (llvm.global_ctors) computes the presence predicates (__metal_implicit_fc_pred_N),
// the binding-index expressions and the constant shadows (_ZL<name>) the body reads.  ABI v5 evaluates
// it with the value-independence model of uEval (every use of an unset constant any value of its type,
// a branch on an undefined condition explores both edges): a global comes out as a constant only when
// it has that value for every value of the unset constants.  verify4 item 2: fix round 3 took the
// predicates from Metal's undef folding (abstract_eval_ctors), and fcrand seed 23 shader 38
// (work/fc/pmin/p0.metal, `Q0 = (A || (N*2)==1) ? (A != ((N&1)!=0)) : (((N>>1)>0) && B)` with only A
// unset) came out absent where Metal has buffer(10) present.
struct IV { enum K { Unknown, C, T } k = Unknown; Constant *c = nullptr; UAbs a; };
static IV ivC(Constant *c) {
  IV v;
  if (!c || isa<UndefValue>(c) || c->containsUndefOrPoisonElement()) { v.k = IV::T; v.a = c ? uFull(c->getType()) : UAbs(); v.a.poison = c && isa<PoisonValue>(c); return v; }
  v.k = IV::C; v.c = c; return v;
}
static IV ivT(const UAbs &a) { IV v; v.k = IV::T; v.a = a; return v; }
static UAbs ivAbs(const IV &v) {
  if (v.k == IV::T) return v.a;
  UAbs a; if (auto *ci = dyn_cast_or_null<ConstantInt>(v.c)) { a.hasRange = true; a.cr = ConstantRange(ci->getValue()); }
  return a;
}
static IV ivJoin(const IV &x, const IV &y) {
  if (x.k == IV::Unknown) return y;
  if (y.k == IV::Unknown) return x;
  if (x.k == IV::C && y.k == IV::C && x.c == y.c) return x;
  return ivT(uJoin(ivAbs(x), ivAbs(y)));
}
static bool ivSame(const IV &x, const IV &y) {
  if (x.k != y.k) return false;
  if (x.k == IV::C) return x.c == y.c;
  if (x.k == IV::T) return x.a.poison == y.a.poison && x.a.hasRange == y.a.hasRange && (!x.a.hasRange || x.a.cr == y.a.cr);
  return true;
}
struct CtorIndep { bool ok = true; std::string why; std::map<const GlobalVariable *, IV> mem; };
static CtorIndep indep_eval_ctors(Module &M, const std::map<int, std::vector<double>> &fc) {
  CtorIndep E;
  GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors");
  if (!ctors || !ctors->hasInitializer()) return E;
  auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer());
  if (!CA) { E.ok = false; E.why = "global_ctors not an array"; return E; }
  const DataLayout &DL = M.getDataLayout();
  TargetLibraryInfoImpl TLII(M.getTargetTriple()); TargetLibraryInfo TLI(TLII);
  std::vector<Function *> fns;
  for (Use &U : CA->operands()) {
    auto *CS = dyn_cast<ConstantStruct>(U.get()); if (!CS) continue;
    auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()); if (!Fn || Fn->isDeclaration()) continue;
    fns.push_back(Fn);
  }
  // A global stored at one site that runs on every path keeps the stored value; otherwise (several
  // sites, or a conditional one) it may also keep its initialiser or an earlier store.
  std::map<const GlobalVariable *, int> sites; std::set<const StoreInst *> always;
  for (Function *Fn : fns) {
    PostDominatorTree PDT(*Fn);
    for (BasicBlock &BB : *Fn) for (Instruction &I : BB) if (auto *SI = dyn_cast<StoreInst>(&I))
      if (auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts())) {
        sites[G]++;
        if (PDT.dominates(&BB, &Fn->getEntryBlock())) always.insert(SI);
      }
  }
  auto initOf = [&](const GlobalVariable *G, Type *T) -> IV {
    if (G->hasInitializer() && G->getInitializer()->getType() == T) return ivC(const_cast<Constant *>(G->getInitializer()));
    return ivT(uFull(T));
  };
  for (Function *Fn : fns) {
    std::map<const Value *, IV> val;
    std::set<std::pair<const BasicBlock *, const BasicBlock *>> edges;
    std::set<const BasicBlock *> live{&Fn->getEntryBlock()};
    auto get = [&](Value *v) -> IV {
      if (auto *C = dyn_cast<Constant>(v)) { if (isa<GlobalValue>(C)) return ivT(uFull(v->getType())); return ivC(C); }
      auto it = val.find(v); return it == val.end() ? IV() : it->second;
    };
    SimplifyQuery SQ(DL, &TLI);
    ReversePostOrderTraversal<Function *> RPOT(Fn);
    for (int iter = 0; iter < 64; iter++) {
      bool changed = false;
      auto setv = [&](Instruction *I, const IV &v) {
        if (v.k == IV::Unknown) return;
        IV o = val.count(I) ? val[I] : IV(); IV n = ivJoin(o, v);
        if (!ivSame(o, n)) { val[I] = n; changed = true; }
      };
      auto edge = [&](BasicBlock *f, BasicBlock *t) { if (edges.insert({f, t}).second) changed = true; if (live.insert(t).second) changed = true; };
      for (BasicBlock *BB : RPOT) {
        if (!live.count(BB)) continue;
        for (Instruction &I : *BB) {
          if (auto *PN = dyn_cast<PHINode>(&I)) {
            IV r;
            for (unsigned i = 0; i < PN->getNumIncomingValues(); i++)
              if (edges.count({PN->getIncomingBlock(i), BB})) r = ivJoin(r, get(PN->getIncomingValue(i)));
            setv(&I, r); continue;
          }
          if (auto *LI = dyn_cast<LoadInst>(&I)) {
            auto *G = dyn_cast<GlobalVariable>(LI->getPointerOperand()->stripPointerCasts());
            if (!G) { setv(&I, ivT(uFull(LI->getType()))); continue; }
            if (G->getSection() == "air.fc_initializer") {
              int idx = fcIndexOfGlobal(G->getName());
              setv(&I, idx >= 0 && fc.count(idx) ? ivC(fcLoadConstant(G, LI->getType(), fc.at(idx), DL)) : ivT(uFull(LI->getType())));
              continue;
            }
            auto m = E.mem.find(G);
            if (m != E.mem.end()) {
              if (m->second.k == IV::C) { Constant *pc = punStored(m->second.c, LI->getType(), DL); setv(&I, pc ? ivC(pc) : ivT(uFull(LI->getType()))); }
              else setv(&I, m->second);
              continue;
            }
            setv(&I, initOf(G, LI->getType()));
            continue;
          }
          if (auto *SI = dyn_cast<StoreInst>(&I)) {
            auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts());
            if (!G) continue;
            IV v = get(SI->getValueOperand());
            if (v.k == IV::Unknown) continue;
            auto it = E.mem.find(G);
            IV slot = it != E.mem.end() ? it->second : initOf(G, SI->getValueOperand()->getType());
            IV n = sites[G] == 1 && always.count(SI) ? v : ivJoin(slot, v);
            if (it == E.mem.end() || !ivSame(it->second, n)) { E.mem[G] = n; changed = true; }
            continue;
          }
          if (auto *CI = dyn_cast<CallInst>(&I)) {
            Function *cf = CI->getCalledFunction();
            StringRef nm = cf ? cf->getName() : "";
            if (nm.starts_with("air.normalize_function_constant_predicate")) {
              IV x = get(argOperand(CI, 0));
              if (x.k == IV::Unknown) continue;
              if (x.k == IV::C) { auto *ci = dyn_cast<ConstantInt>(x.c); setv(&I, ivC(ConstantInt::get(CI->getType(), ci ? !ci->isZero() : 0))); continue; }
              unsigned w = CI->getType()->getIntegerBitWidth();
              if (x.a.hasRange && !x.a.poison && !x.a.cr.contains(APInt::getZero(x.a.cr.getBitWidth()))) { setv(&I, ivC(ConstantInt::get(CI->getType(), 1))); continue; }
              UAbs a; a.hasRange = true; a.cr = ConstantRange(APInt(w, 0), APInt(w, 2)); a.poison = x.a.poison;
              setv(&I, ivT(a)); continue;
            }
            if (nm == "air.is_function_constant_defined") {
              auto *G = dyn_cast<GlobalVariable>(argOperand(CI, 0)->stripPointerCasts());
              int idx = G ? fcIndexOfGlobal(G->getName()) : -1;
              setv(&I, ivC(ConstantInt::getBool(CI->getContext(), idx >= 0 && fc.count(idx))));
              continue;
            }
            if (cf && cf->isIntrinsic() && (cf->getIntrinsicID() == Intrinsic::lifetime_start || cf->getIntrinsicID() == Intrinsic::lifetime_end)) continue;
            if (cf && cf->isDeclaration() && nm.starts_with("air.")) {
              // fix round 5 (verify5 minor): an AIR conversion of set constants folds as in
              // abstract_eval_ctors; on a value that depends on an unset constant (or when it does not
              // fold) its result may be any value of its type, and poison for a float -> integer
              // conversion (out of range / NaN).  v4 refused the variant for any call.  (Any other AIR
              // call leaves abstract_eval_ctors unevaluated, and the variant is refused there.)
              SmallVector<Constant *, 3> args; bool unk = false, dep = false;
              for (Value *op : CI->args()) { IV x = get(op); if (x.k == IV::Unknown) unk = true; else if (x.k == IV::T) dep = true; else args.push_back(x.c); }
              if (unk) continue;
              if (!dep) if (Constant *r = foldCtorAirCall(CI, args)) { setv(&I, ivC(r)); continue; }
              UAbs a = uFull(CI->getType());
              Type *RT = CI->getType();
              if (nm.starts_with("air.convert.") && RT->isIntegerTy() && !RT->isIntegerTy(1) && CI->arg_size() == 1 && argOperand(CI, 0)->getType()->isFPOrFPVectorTy())
                a.poison = true;
              setv(&I, ivT(a));
              continue;
            }
            E.ok = false; E.why = "call to " + nm.str() + " in the static initialiser"; return E;
          }
          if (auto *Br = dyn_cast<BranchInst>(&I)) {
            if (Br->isUnconditional()) { edge(BB, Br->getSuccessor(0)); continue; }
            IV c = get(Br->getCondition());
            if (c.k == IV::Unknown) continue;
            if (c.k == IV::T) { edge(BB, Br->getSuccessor(0)); edge(BB, Br->getSuccessor(1)); continue; }   // either way
            edge(BB, cast<ConstantInt>(c.c)->isOne() ? Br->getSuccessor(0) : Br->getSuccessor(1));
            continue;
          }
          if (auto *SW = dyn_cast<SwitchInst>(&I)) {
            IV c = get(SW->getCondition());
            if (c.k == IV::Unknown) continue;
            if (c.k == IV::T) { for (unsigned i = 0; i < SW->getNumSuccessors(); i++) edge(BB, SW->getSuccessor(i)); continue; }
            edge(BB, SW->findCaseValue(cast<ConstantInt>(c.c))->getCaseSuccessor());
            continue;
          }
          if (isa<ReturnInst>(&I) || isa<UnreachableInst>(&I)) continue;
          SmallVector<UOpnd, 4> ops; std::vector<IV> ivs; bool anyUnknown = false, anyT = false;
          ivs.reserve(I.getNumOperands());
          for (Value *op : I.operands()) {
            IV v = get(op);
            if (v.k == IV::Unknown) { anyUnknown = true; break; }
            ivs.push_back(v);
          }
          if (anyUnknown) continue;
          for (unsigned i = 0; i < I.getNumOperands(); i++) {
            UOpnd o;
            if (ivs[i].k == IV::T) { o.v = I.getOperand(i); o.t = &ivs[i].a; anyT = true; }
            else o.v = ivs[i].c;
            ops.push_back(o);
          }
          if (!anyT) {
            SmallVector<Constant *, 4> cs; for (auto &o : ops) cs.push_back(cast<Constant>(o.v));
            Constant *res = ConstantFoldInstOperands(&I, cs, DL, &TLI);
            if (!res) { E.ok = false; E.why = "cannot fold " + str(&I); return E; }
            setv(&I, ivC(res));
            continue;
          }
          UResult ur = uEval(I, ops, SQ, &TLI, [&](Value *v) { IV x = get(v); return x.k == IV::T; });
          if (ur.v && ur.v != &I) { IV r = get(ur.v); if (r.k != IV::Unknown) setv(&I, r); }
          else setv(&I, ivT(ur.a));
        }
      }
      if (!changed) break;
      if (iter == 63) { E.ok = false; E.why = "static initialiser did not converge"; return E; }
    }
  }
  return E;
}
// A presence predicate that is a direct copy of an unset constant: `[[function_constant(A)]]` with
// `constant bool Q = A;` style initialisers (normalize(A), possibly through a shadow and casts / != 0).
// Metal marks such arguments absent (measured, fixtures fcsem/fc2/fc3), and that is kept.
static bool directUnsetPredicate(const GlobalVariable *P, const std::map<int, std::vector<double>> &fc, int depth = 0) {
  if (depth > 4) return false;
  const StoreInst *only = nullptr; int n = 0;
  for (const User *U : P->users()) {
    if (auto *CE = dyn_cast<ConstantExpr>(U)) { for (const User *u2 : CE->users()) if (auto *S = dyn_cast<StoreInst>(u2)) { only = S; n++; } continue; }
    if (auto *S = dyn_cast<StoreInst>(U)) { only = S; n++; }
  }
  if (n != 1 || !only) return false;
  const Value *v = only->getValueOperand();
  for (int k = 0; k < 8; k++) {
    if (auto *CI = dyn_cast<CallInst>(v)) {
      if (CI->getCalledFunction() && CI->getCalledFunction()->getName().starts_with("air.normalize_function_constant_predicate")) { v = argOperand(CI, 0); continue; }
      return false;
    }
    if (isa<ZExtInst>(v) || isa<SExtInst>(v) || isa<TruncInst>(v)) { v = cast<Instruction>(v)->getOperand(0); continue; }
    if (auto *IC = dyn_cast<ICmpInst>(v)) {
      if (IC->getPredicate() != ICmpInst::ICMP_NE) return false;
      if (auto *z = dyn_cast<ConstantInt>(IC->getOperand(1)); z && z->isZero()) { v = IC->getOperand(0); continue; }
      if (auto *z = dyn_cast<ConstantInt>(IC->getOperand(0)); z && z->isZero()) { v = IC->getOperand(1); continue; }
      return false;
    }
    break;
  }
  auto *LI = dyn_cast<LoadInst>(v); if (!LI) return false;
  auto *G = dyn_cast<GlobalVariable>(LI->getPointerOperand()->stripPointerCasts()); if (!G) return false;
  if (G->getSection() == "air.fc_initializer") { int idx = fcIndexOfGlobal(G->getName()); return idx >= 0 && !fc.count(idx); }
  return directUnsetPredicate(G, fc, depth + 1);                    // a shadow copy of the constant
}

// verify4 item 2 (ABI v5): a presence predicate that depends on an unset constant is accepted only
// when it is a direct copy of an unset constant (absent, as in Metal) or has the same value for every
// value of the unset constants (indep_eval_ctors); every other one is refused where it gates an
// argument or output of the entry point (Translator::predValue).  ABI v4 took Metal's undef folding
// for these, and Metal's choice is not reproducible (fcrand seed 23 shader 38, work/fc/pmin/p0).
static std::map<std::string, std::string> presenceVerdicts(Module &M, const CtorEval &AE, const CtorIndep &IE, const std::vector<FcDecl> &decls,
                                                          const std::map<int, std::vector<double>> &fc, std::set<std::string> &direct) {
  std::map<std::string, std::string> amb;
  auto dep = ctorDeps(M, fc);
  for (auto &kv : IE.mem) {
    const GlobalVariable *G = kv.first;
    if (!G->getName().contains("__metal_implicit_fc_pred")) continue;
    std::string g = G->getName().str(), names;
    auto it = dep.find(G);
    if (it != dep.end())
      for (int i : it->second) for (auto &d : decls) if (d.index == i) names += (names.empty() ? "" : ", ") + d.name + " (index " + std::to_string(i) + ")";
    if (kv.second.k == IV::C) {
      // guard: the value-independent result must also be what LLVM's undef folding (Metal's) gives
      auto a = AE.mem.find(G);
      bool agree = a != AE.mem.end() && a->second.k == AV::C && a->second.c == kv.second.c;
      if (!agree)
        amb[g] = "the presence predicate " + g + " is the same for every value of the unset function constant(s) " + (names.empty() ? "?" : names) +
                 " but LLVM's undef folding gives another value; set the constant(s) (BINDING-ABI.md 3.7)";
      continue;
    }
    if (kv.second.k != IV::T) continue;
    if (directUnsetPredicate(G, fc)) { direct.insert(g); continue; }
    amb[g] = "the presence predicate " + g + " depends on the value of the unset function constant(s) " + (names.empty() ? "?" : names) +
             " (it is neither a direct copy of an unset constant nor the same for every value of it); Metal resolves such a predicate "
             "either way (verify4: fcrand seed 23 shader 38): set the constant(s) (BINDING-ABI.md 3.7)";
  }
  return amb;
}

static SpecResult specialize_and_inline(Module &M, Function *entry, const std::vector<FcDecl> &decls,
                                        const std::map<int, std::vector<double>> &fc) {
  SpecResult R;
  // Metal's view of the predicates (before anything is rewritten), see abstract_eval_ctors.
  CtorEval AE = abstract_eval_ctors(M, fc);
  if (!AE.ok) R.ctorWhy = AE.why;
  bool allDefined = true;
  for (auto &d : decls) if (!fc.count(d.index)) allDefined = false;
  // ABI v5: which static-initialiser globals are the same for every value of the unset constants
  // (indep_eval_ctors), and the presence predicates that are not (presenceVerdicts).
  CtorIndep IE;
  if (!allDefined) {
    IE = indep_eval_ctors(M, fc);
    if (!IE.ok) die("cannot evaluate the static initialiser with unset constants (" + IE.why + "): set the constants");
    if (AE.ok) R.ambiguousPredicates = presenceVerdicts(M, AE, IE, decls, fc, R.directPredicates);
  }
  // The body sees unset constants as undefined values; a use folds only when its result is the
  // same for every value (resolve_unset_in_body).  Run on the AIR as loaded, before any of our passes.
  if (AE.ok && !allDefined) {
    std::set<Function *> ctorFns;
    if (GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors"))
      if (auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer()))
        for (Use &U : CA->operands())
          if (auto *CS = dyn_cast<ConstantStruct>(U.get()))
            if (auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts())) ctorFns.insert(Fn);
    std::map<const GlobalVariable *, KnownGlobal> known;
    for (GlobalVariable &G : M.globals()) {
      if (G.getSection() == "air.fc_initializer") {
        int idx = fcIndexOfGlobal(G.getName());
        if (idx < 0) continue;
        KnownGlobal k; k.name = fcNameOfGlobal(&G, decls);
        if (fc.count(idx)) k.value = fcConstant(G.getValueType(), fc.at(idx));
        known[&G] = k;
        continue;
      }
      // a shadow the body may load: its value when it is the same for every value of the unset
      // constants, else an undefined marker (ABI v5; v4 used Metal's undef folding here, verify4 item 1)
      auto m = IE.mem.find(&G);
      if (m == IE.mem.end() || m->second.k == IV::Unknown || G.getName().contains("__metal_implicit")) continue;
      KnownGlobal k; k.name = "shadow " + G.getName().str();
      if (m->second.k == IV::C) k.value = m->second.c;
      known[&G] = k;
    }
    // name the undefined shadows after the constant whose initialiser they copy
    for (Function *Fn : ctorFns) for (BasicBlock &BB : *Fn) for (Instruction &I : BB)
      if (auto *SI = dyn_cast<StoreInst>(&I))
        if (auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts()))
          if (known.count(G) && !known[G].value)
            if (auto *LI = dyn_cast<LoadInst>(SI->getValueOperand()))
              if (auto *FG = dyn_cast<GlobalVariable>(LI->getPointerOperand()->stripPointerCasts()))
                if (FG->getSection() == "air.fc_initializer") known[G].name = fcNameOfGlobal(FG, decls);
    // a shadow computed from several constants: name the unset ones it depends on
    { auto dep = ctorDeps(M, fc);
      for (auto &kv : known) {
        if (kv.second.value || kv.second.name.rfind("shadow ", 0) != 0) continue;
        auto it = dep.find(kv.first); if (it == dep.end() || it->second.empty()) continue;
        std::string n;
        for (int i : it->second) for (auto &d : decls) if (d.index == i) n += (n.empty() ? "" : " or ") + d.name + " (index " + std::to_string(i) + ")";
        if (!n.empty()) kv.second.name = n + " [through " + kv.first->getName().str() + "]";
      } }
    UnsetResolveStats us = resolve_unset_in_body(M, entry, ctorFns, known, fc);
    R.unsetMarkers = us.markers; R.unsetIndependent = us.independent;
  }
  // The static initialiser gets the predicate values the gates get (a normalize the evaluation
  // reached folds to its abstract value; undefined -> 0).  Since ABI v4 the body no longer loads an
  // undefined shadow (resolve_unset_in_body replaced or refused every such load), so the stores
  // below only keep the initialiser consistent for GlobalOpt and the Evaluator self-check.
  if (AE.ok && !allDefined) {
    for (auto &kv : AE.normalize) {
      CallInst *CI = kv.first;
      Constant *c = kv.second.k == AV::C ? kv.second.c : Constant::getNullValue(CI->getType());
      CI->replaceAllUsesWith(c); CI->eraseFromParent();
    }
    // The initialiser stores the value-independent result wherever there is one (ABI v5), and 0
    // where the value depends on an unset constant (the body never reads those: resolve_unset_in_body
    // replaced every such load by an undefined marker and refused the variant where it mattered).
    if (GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors"))
      if (auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer()))
        for (Use &U : CA->operands())
          if (auto *CS = dyn_cast<ConstantStruct>(U.get()))
            if (auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()))
              for (BasicBlock &BB : *Fn) for (Instruction &I : BB)
                if (auto *SI = dyn_cast<StoreInst>(&I))
                  if (auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts())) {
                    auto m = IE.mem.find(G);
                    if (m == IE.mem.end() || G->getSection() == "air.fc_initializer") continue;
                    Type *T = SI->getValueOperand()->getType();
                    if (m->second.k == IV::C && m->second.c->getType() == T) SI->setOperand(0, m->second.c);
                    else if (m->second.k == IV::T && (T->isIntegerTy() || T->isFloatingPointTy()))
                      SI->setOperand(0, Constant::getNullValue(T));   // undefined -> 0 (false): absent AND not read
                  }
  }
  // Replace loads of "*.MTL_FC_INIT_<idx>_<ty>" constants with the chosen values.
  for (GlobalVariable &G : M.globals()) {
    if (G.getSection() != "air.fc_initializer") continue;
    int idx = fcIndexOfGlobal(G.getName());
    if (idx < 0) continue;
    std::vector<double> v = fc.count(idx) ? fc.at(idx) : std::vector<double>{0};
    for (User *U : make_early_inc_range(G.users()))
      if (auto *LI = dyn_cast<LoadInst>(U)) {
        LI->replaceAllUsesWith(fcLoadConstant(&G, LI->getType(), v, M.getDataLayout()));
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
        auto *G = dyn_cast<GlobalVariable>(argOperand(CI, 0)->stripPointerCasts());
        int idx = G ? fcIndexOfGlobal(G->getName()) : -1;
        CI->replaceAllUsesWith(ConstantInt::getBool(CI->getContext(), fc.count(idx) != 0)); CI->eraseFromParent();
      } else if (fn.starts_with("air.normalize_function_constant_predicate")) {
        // normalize(x) == (x != 0) ? 1 : 0; expand it so instcombine / the evaluator can fold it.
        IRBuilder<> B(CI);
        Value *x = argOperand(CI, 0);
        Value *r = B.CreateZExt(B.CreateICmpNE(x, Constant::getNullValue(x->getType())), CI->getType());
        CI->replaceAllUsesWith(r); CI->eraseFromParent();
      }
    }
  }
  // verify6 must-fix 3: the static initialiser is IEEE arithmetic.  Metal decides presence with IEEE
  // values (half(70000) is inf, isfinite(inf) false), and so do abstract_eval_ctors and
  // indep_eval_ctors; with Metal's fast-math flags left on, the initialiser inlined into the body
  // folded an overflow to poison (overflow_body: output 0 where Metal has 3; absent_read: the body
  // read UBO 0 and 1, which the sidecar marks absent), and LLVM's Evaluator disagreed with ours
  // (the spurious "static-initialiser evaluation disagrees" refusal).  No WindowServer initialiser has
  // a float operation (verify6: 455 of 455), so this changes none of them.
  std::set<Function *> ctorFnSet;
  if (GlobalVariable *ctors = M.getGlobalVariable("llvm.global_ctors"))
    if (auto *CA = dyn_cast<ConstantArray>(ctors->getInitializer()))
      for (Use &U : CA->operands())
        if (auto *CS = dyn_cast<ConstantStruct>(U.get()))
          if (auto *Fn = dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()); Fn && !Fn->isDeclaration()) ctorFnSet.insert(Fn);
  for (Function *Fn : ctorFnSet)
    for (BasicBlock &BB : *Fn) for (Instruction &I : BB)
      if (isa<FPMathOperator>(&I)) I.copyFastMathFlags(FastMathFlags());   // (setFastMathFlags only ORs flags in)
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
      // verify6 must-fix 1: when our evaluator could not decide the initialiser (a poison conversion,
      // a call Metal rejects), LLVM's Evaluator may still succeed on the instcombined clone, because
      // instcombine drops a dead conversion whose result another set constant absorbs
      // (`(uint(F) == 7u) || A` with A = true).  Metal evaluates such a predicate as poison (false), so
      // no predicate or binding index is taken from it: gatedPresent / locValue refuse instead.
      if (ok && AE.ok)
        for (auto &kv : Eval.getMutatedInitializers()) {
          if (kv.first->getName().contains("__metal_implicit"))
            if (auto *CI = dyn_cast<ConstantInt>(kv.second)) R.implicitVals[kv.first->getName().str()] = CI->getSExtValue();
        }
      (void)CA;
    }
  }
  // Implicit globals that the initialiser never writes keep their (constant) initialiser.
  bool hasCtor = M.getGlobalVariable("llvm.global_ctors") != nullptr;
  auto storedTo = [](const GlobalVariable &G) {
    for (const User *U : G.users()) {
      if (isa<StoreInst>(U)) return true;
      if (isa<ConstantExpr>(U)) for (const User *u2 : U->users()) if (isa<StoreInst>(u2)) return true;
    }
    return false;
  };
  if (!hasCtor || (R.ctorEvaluated && AE.ok))
  for (GlobalVariable &G : M.globals())
    if (G.getName().contains("__metal_implicit") && !R.implicitVals.count(G.getName().str()) && G.hasInitializer())
      if (auto *CI = dyn_cast<ConstantInt>(G.getInitializer())) R.implicitVals[G.getName().str()] = CI->getSExtValue();
  // an implicit global no store writes keeps its initialiser whether or not the initialiser evaluated
  if (hasCtor && !AE.ok)
    for (GlobalVariable &G : M.globals())
      if (G.getName().contains("__metal_implicit") && !R.implicitVals.count(G.getName().str()) && G.hasInitializer() && !storedTo(G))
        if (auto *CI = dyn_cast<ConstantInt>(G.getInitializer())) R.implicitVals[G.getName().str()] = CI->getSExtValue();

  // The predicates and binding-index expressions: with unset constants, the value-independent
  // result (ABI v5, indep_eval_ctors; a direct copy of an unset constant and everything that depends
  // on one are "undefined" -> 0, i.e. absent, and presenceVerdicts refuses the latter where it gates
  // something).  With every constant defined the abstract evaluation must agree with LLVM's
  // Evaluator: a self-check run on every compile.
  if (AE.ok) {
    for (auto &kv : AE.mem) {
      std::string g = kv.first->getName().str();
      if (g.find("__metal_implicit") == std::string::npos) continue;
      int64_t v = 0; bool undef = kv.second.k != AV::C;
      Constant *cv = undef ? nullptr : kv.second.c;
      if (!allDefined) {
        auto ie = IE.mem.find(kv.first);
        undef = ie == IE.mem.end() || ie->second.k != IV::C;
        cv = undef ? nullptr : ie->second.c;
      }
      if (!undef) { auto *ci = dyn_cast<ConstantInt>(cv); if (!ci) continue; v = ci->getSExtValue(); }
      if (undef) R.taintedGlobals.insert(g);
      if (allDefined && R.ctorEvaluated && R.implicitVals.count(g) && (undef || R.implicitVals[g] != v))
        die("internal: static-initialiser evaluation disagrees for " + g);
      if (undef && g.find("__metal_implicit_fc_pred") != std::string::npos) R.taintedPredicates++;
      R.implicitVals[g] = undef ? 0 : v;
    }
  } else if (!allDefined) {
    die("cannot evaluate function-constant predicates with unset constants (" + AE.why + ")");
  }
  // verify6 must-fix 3: with every constant set, the initialiser's stores get the evaluator's values
  // (the unset path above stores the value-independent ones), so the body reads exactly what the
  // presence decision used.  Only a global the initialisers store once (an implicit predicate, a
  // shadow): a global stored at several sites keeps its code, which is IEEE now (flags cleared above).
  if (AE.ok && allDefined) {
    std::map<const GlobalVariable *, std::vector<StoreInst *>> st;
    for (Function *Fn : ctorFnSet) for (BasicBlock &BB : *Fn) for (Instruction &I : BB)
      if (auto *SI = dyn_cast<StoreInst>(&I))
        if (auto *G = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts())) st[G].push_back(SI);
    for (auto &kv : st) {
      const GlobalVariable *G = kv.first;
      if (kv.second.size() != 1 || G->getSection() == "air.fc_initializer") continue;
      auto m = AE.mem.find(G);
      if (m == AE.mem.end() || m->second.k != AV::C) continue;
      StoreInst *SI = kv.second[0];
      if (m->second.c->getType() == SI->getValueOperand()->getType()) SI->setOperand(0, m->second.c);
    }
  }
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
  // Resource handles stored into private memory that is never read back as a pointer (docs/USERSPACE-GRAPHICS-20261019.md):
  // RenderBox's custom effects copy a texture into an RB::Layer that a loop keeps in memory, while every sample uses
  // the argument itself. The translator has no private form for a handle, so drop those dead stores. Memory that is
  // read back as a pointer, copied, passed to a call or escapes keeps them (and still refuses in the translator).
  for (Function &F : M) {
    std::map<const AllocaInst *, bool> readBack;
    auto pointerReadBack = [&](const AllocaInst *A) {
      auto it = readBack.find(A);
      if (it != readBack.end()) return it->second;
      bool read = false;
      SmallVector<const Value *, 16> work{A}; std::set<const Value *> seen;
      while (!work.empty() && !read) {
        const Value *V = work.pop_back_val();
        if (!seen.insert(V).second) continue;
        for (const User *U : V->users()) {
          if (auto *L = dyn_cast<LoadInst>(U)) {
            read |= containsPointer(L->getType());
          } else if (auto *S = dyn_cast<StoreInst>(U)) {
            read |= S->getValueOperand() == V;                        // the address itself escapes
          } else if (isa<GetElementPtrInst>(U) || isa<BitCastInst>(U) || isa<AddrSpaceCastInst>(U)) {
            work.push_back(U);
          } else if (auto *II = dyn_cast<IntrinsicInst>(U)) {
            read |= !II->isLifetimeStartOrEnd();
          } else read = true;                                           // calls, phis, selects, ptrtoint, ...
        }
      }
      return readBack[A] = read;
    };
    for (BasicBlock &BB : F)
      for (Instruction &I : make_early_inc_range(BB)) {
        auto *S = dyn_cast<StoreInst>(&I);
        if (!S || !S->getValueOperand()->getType()->isPointerTy()) continue;
        const Value *base = S->getPointerOperand();
        while (true) {
          if (auto *G = dyn_cast<GEPOperator>(base)) base = G->getPointerOperand();
          else if (auto *O = dyn_cast<Operator>(base); O && (O->getOpcode() == Instruction::BitCast ||
                                                            O->getOpcode() == Instruction::AddrSpaceCast)) base = O->getOperand(0);
          else break;
        }
        if (auto *A = dyn_cast<AllocaInst>(base); A && !pointerReadBack(A)) S->eraseFromParent();
      }
  }
  // AIR intrinsics with constant operands (Metal folds them; LLVM cannot): fold and clean up again
  for (int i = 0; i < 4 && foldAirCalls(M); i++) runPipeline(M, PIPE_POST);
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
        // keep the value of implicit globals we could not evaluate from the initialiser -- only when
        // our evaluator succeeded (verify6 must-fix 1: after it gave up on a poison conversion, the
        // optimiser drops the dead conversion and the store here holds a value Metal does not have)
        if (AE.ok && G.getName().contains("__metal_implicit") && !R.implicitVals.count(G.getName().str()))
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
  std::unordered_map<const Value *, nir_def *> tgBase;          // threadgroup(n) argument -> base byte offset
  const AirOptions *opt = nullptr;
  // XR colour attachments lowered in the shader (FORMATS.md, BINDING-ABI.md 4.5)
  struct RtLow { unsigned cls = 0; AirBlend api, hw; bool dual = false, fetch = false; nir_variable *src1 = nullptr, *var = nullptr; int ri = -1; };
  std::map<int, RtLow> rtLow;                                  // by render-target index

  // ---- XR10 affine encoding: u = k*v + c in the UNORM view of the attachment/texture ----
  // 554 BGR10_XR: 10-bit fields, v = (n - 384) / 510, viewed as B10G10R10A2_UNORM (u = n / 1023)
  // 552 BGRA10_XR: 10 bits in the top of 16-bit words, viewed as R16G16B16A16_UNORM (u = 64 n / 65535)
  static double xrK(unsigned cls) { return cls == AIR_FMT_XR10_BGR32 ? 510.0 / 1023.0 : 510.0 * 64.0 / 65535.0; }
  static double xrC(unsigned cls) { return cls == AIR_FMT_XR10_BGR32 ? 384.0 / 1023.0 : 384.0 * 64.0 / 65535.0; }
  nir_def *xrDecode(unsigned cls, nir_def *u) { return nir_fmul_imm(&b, nir_fadd_imm(&b, u, -xrC(cls)), 1.0 / xrK(cls)); }
  // Exact encoding (no blending): round to the 10-bit code first so the UNORM store is bit-exact.
  nir_def *xrEncodeExact(unsigned cls, nir_def *v) {
    nir_def *n = nir_fround_even(&b, nir_fmin(&b, nir_fmax(&b, nir_fadd_imm(&b, nir_fmul_imm(&b, v, 510.0), 384.0), nir_imm_float(&b, 0)), nir_imm_float(&b, 1023)));
    return nir_fmul_imm(&b, n, cls == AIR_FMT_XR10_BGR32 ? 1.0 / 1023.0 : 64.0 / 65535.0);
  }
  static void checkFormatClass(unsigned cls, const std::string &what) {
    if (cls == AIR_FMT_NATIVE || cls == AIR_FMT_XR10_BGR32 || cls == AIR_FMT_XR10_BGRA64) return;
    if (cls == AIR_FMT_XR10_RGB10A8_2P || cls == AIR_FMT_XR10_SRGB)
      die(what + " has format class " + air_format_class_name(cls) + ": no shader lowering in ABI v5; the command stream uses the conversion-blit path (FORMATS.md)");
    if (cls == AIR_FMT_YCBCR10_PACKED)
      die(what + " has format class " + air_format_class_name(cls) + ": sampled through a conversion blit, never rendered (FORMATS.md)");
    die(what + ": unknown format class " + std::to_string(cls));
  }
  static bool srcFactor(unsigned f) { return f >= 2 && f <= 5; }
  int writtenRts = 0;                                          // render targets the function writes (dual-source check)
  // Two ways to blend into a lowered (XR) attachment (BINDING-ABI.md 4.5, FORMATS.md 3):
  //  - "hw": the RB blends in the view's u-domain; the shader writes an offset-corrected source.
  //    Only for blend states that are exact for EVERY source value: complementary factor pairs,
  //    a zero source factor, a zero destination factor, min and max; never with source colour
  //    (2, 3) as an RGB factor, which the RB would clamp to [0, 1] (ABI v5 fix round 5, verify5 item 1).
  //  - "shader" (ABI v3): the shader reads the destination by framebuffer fetch, decodes it, blends
  //    exactly as Metal does (source clamped to the XR range, then s*Fs op d*Fd) and stores the
  //    exact code; the RB's blending is off.  Used for premultiplied source-over, whose hw form is
  //    exact only for premultiplied in-range sources (|s| <= range*a; verify2 item 7: tint -0.7 with
  //    partial alpha was off by 26 codes), for additive / subtract / destination factors (refused in
  //    ABI v3), and whenever the hw form would need dual-source blending while another attachment
  //    is written (Adreno dual-source drives colour(0) only; verify2 item 7, work/mrt.json).
  void setupRtLowering(int idx, nir_variable *v, bool written) {
    unsigned cls = opt->rtClass[idx];
    checkFormatClass(cls, "colour attachment " + std::to_string(idx));
    if (glsl_get_base_type(v->type) != GLSL_TYPE_FLOAT) die("integer [[color(" + std::to_string(idx) + ")]] on an XR attachment");
    v->type = glsl_vec4_type();
    RtLow L; L.cls = cls; L.api = opt->blend[idx]; L.hw = L.api; L.var = v;
    if (written && L.api.enabled) {
      const AirBlend &a = L.api;
      bool alphaStored = cls == AIR_FMT_XR10_BGRA64;
      // min / max ignore the blend factors (Metal, like Vulkan and GL): the factors of such a channel
      // are neither checked nor used, and the hw blend state carries ONE/ONE there (verify3 item 2:
      // v3 handed the app's factors to the RB, remapped SRC_* to SRC1_* and even turned dual-source
      // on, which forced shader blending whenever another attachment was written).
      bool rgbMM = a.rgbOp == 3 || a.rgbOp == 4, alphaMM = a.alphaOp == 3 || a.alphaOp == 4;
      unsigned fs[4] = {a.srcRGB, a.dstRGB, a.srcA, a.dstA};
      for (int i = 0; i < 4; i++) {
        if (!alphaStored && i >= 2) continue;                 // 554: alpha is not stored (write-masked)
        if (i < 2 ? rgbMM : alphaMM) continue;               // min / max: factors ignored
        if (fs[i] >= 11) die("blend factor " + std::to_string(fs[i]) + " (blend colour or source1) on an XR attachment: not in ABI v5; conversion-blit path");
      }
      if (a.rgbOp > 4 || (alphaStored && a.alphaOp > 4)) die("blend operation " + std::to_string(a.rgbOp) + " on an XR attachment");
      // hw form exact for every source?  (u_s = k*s + c*(1 - Fd) must stay in [0,1] for all s in the XR range)
      auto hwExact = [&](unsigned op, unsigned sf, unsigned df, bool rgb) {
        if (op == 3 || op == 4) return true;                  // min / max ignore the factors
        if (op != 0) return false;                            // subtract / reverse subtract
        if (sf > 5 || df > 5) return false;                   // destination factors
        // Source colour as a factor on RGB (2, 3): the RB reads it from dual-source output 1 of the
        // UNORM view and clamps it to [0, 1]; Metal uses it clamped only to the XR range
        // [-0.753, 1.251].  Not exact outside [0, 1] (verify5 item 1: 76..439 codes off, fixtures
        // p000..p035, r554_204): the shader path.  On the alpha channel these factors read the source
        // alpha, which is in [0, 1] anyway (verify4 item 3), so they stay on the RB.
        if (rgb && (sf == 2 || sf == 3 || df == 2 || df == 3)) return false;
        bool compl_ = (sf == 4 && df == 5) || (sf == 5 && df == 4) || (sf == 2 && df == 3) || (sf == 3 && df == 2);
        return compl_ || sf == 0 || (sf == 1 && df == 0);   // u_s = k*s + c*(1 - Fd) assumes Fs = 1 (or complementary)
      };
      bool hw = hwExact(a.rgbOp, a.srcRGB, a.dstRGB, true) && (!alphaStored || hwExact(a.alphaOp, a.srcA, a.dstA, false));
      bool needsDual = false;
      if (hw) {
        // Factors that read the source colour see the encoded value: route the raw colour through
        // dual-source output 1 and use the SRC1 factors (MTLBlendFactorSource1* = 15..18).
        // A min / max channel has no factors, so it never needs dual-source.
        bool rgbDual = !rgbMM && (srcFactor(a.srcRGB) || srcFactor(a.dstRGB));
        needsDual = rgbDual;
        if (alphaStored) needsDual = needsDual || (!alphaMM && (srcFactor(a.srcA) || srcFactor(a.dstA)));
        else needsDual = !rgbMM && (a.srcRGB == 2 || a.srcRGB == 3 || a.dstRGB == 2 || a.dstRGB == 3);   // alpha output stays raw on 554
        if (needsDual && (idx != 0 || writtenRts > 1)) hw = false;   // Adreno dual-source: colour(0) only, no other attachment
      }
      if (hw) {
        if (rgbMM) { L.hw.srcRGB = 1; L.hw.dstRGB = 1; }       // min / max: ONE/ONE (the factors are ignored)
        if (alphaMM) { L.hw.srcA = 1; L.hw.dstA = 1; }
        if (a.srcRGB == 0 && a.rgbOp == 0) L.hw.srcRGB = 1;   // ZERO source factor: the shader outputs only the offset term
        if (alphaStored && a.srcA == 0 && a.alphaOp == 0) L.hw.srcA = 1;
        if (needsDual) {
          L.dual = true;
          auto remap = [](uint8_t &f) { if (f >= 2 && f <= 5) f = (uint8_t)(f + 13); };
          remap(L.hw.srcRGB); remap(L.hw.dstRGB); remap(L.hw.srcA); remap(L.hw.dstA);
          L.src1 = nir_variable_create(s, nir_var_shader_out, glsl_vec4_type(), "xr_dual_src1");
          L.src1->data.location = FRAG_RESULT_DATA0; L.src1->data.index = 1;
          s->info.fs.color_is_dual_source = true;
        }
      } else {
        L.fetch = true;
        L.hw = AirBlend();                                    // RB blending off: the shader stores the blended code
        v->data.fb_fetch_output = 1;
        s->info.fs.uses_fbfetch_output = true;
        R.uses_fb_fetch = true;
        bool have = false;
        for (auto &bd : R.bindings) if (bd.kind == "fb_fetch" && bd.metal_index == idx) have = true;
        if (!have) {
          AirBinding bd; bd.kind = "fb_fetch"; bd.metal_index = idx; bd.slot = ABI_FB_READ_SLOT + idx;
          bd.arg_name = "(xr blend: destination)"; R.bindings.push_back(bd);
        }
      }
      if (L.dual && writtenRts > 1) die("internal: dual-source XR lowering with another attachment written");
    }
    L.ri = idx;
    rtLow[idx] = L;
    AirRtLowering rl; rl.index = idx; rl.cls = cls; rl.api = L.api; rl.hw = L.hw; rl.dual_source = L.dual; rl.blend_in_shader = L.fetch;
    rl.clear_alpha_write = cls == AIR_FMT_XR10_BGR32;
    for (auto &x : R.rt_lowering) if (x.index == idx) { x = rl; return; }
    R.rt_lowering.push_back(rl);
  }
  // The four channels of a lowered colour output, in the view's u-domain (BINDING-ABI.md 4.5).
  nir_def *xrEncodeOutput(RtLow &L, std::vector<nir_def *> sv) {
    while (sv.size() < 3) sv.push_back(nir_imm_float(&b, 0));
    if (sv.size() < 4) sv.push_back(nir_imm_float(&b, 1));
    for (auto &x : sv) if (x->bit_size != 32) x = nir_f2f32(&b, x);
    double k = xrK(L.cls), c = xrC(L.cls);
    const AirBlend &a = L.api;
    // Metal clamps the source to the format's representable range before blending (as Vulkan does
    // for normalized formats): [-384/510, 638/510] = [-0.752941, 1.25098], the range Apple documents
    // for the XR10 formats (codes 0..1022).  Measured: without it premultiplied-over differed by up to
    // 21 codes where a bright source met a dark destination; with the upper bound at 639/510 (ABI v3)
    // verify3's subtract scene v3xr554_40 (s*s - d*d, source red up to 1.47) was 3 codes off on 122
    // pixels, and 638/510 brings it to <= 1 code (tools/xrrand.py, scratch/xr40/model.py).
    for (unsigned ch = 0; ch < 4; ch++)
      if (a.enabled && (ch < 3 || L.cls == AIR_FMT_XR10_BGRA64))
        sv[ch] = nir_fmin(&b, nir_fmax(&b, sv[ch], nir_imm_float(&b, -384.0 / 510.0)), nir_imm_float(&b, 638.0 / 510.0));
    // ... and the source ALPHA to [0, 1] wherever it is a blend factor (source alpha, one minus source
    // alpha, source alpha saturate, and source colour on the alpha channel), on both XR formats
    // (verify4 item 3: with alpha 1.2, premultiplied source-over was 117 codes off and subtract with
    // source alpha 104 / 224, because 1 - 1.2 blended in a negative share of the destination).
    nir_def *sa = a.enabled ? nir_fsat(&b, sv[3]) : sv[3];
    if (L.fetch) {
      // Blend in the shader, exactly as Metal: read the destination (framebuffer fetch of the view),
      // decode, s*Fs op d*Fd per channel, then store the exact code (RB blending off).
      std::vector<nir_def *> u = split(nir_load_var(&b, L.var)), d;
      for (unsigned ch = 0; ch < 4; ch++)
        d.push_back(ch == 3 && L.cls == AIR_FMT_XR10_BGR32 ? nir_imm_float(&b, 1.0) : xrDecode(L.cls, u[ch]));
      auto factor = [&](unsigned f, unsigned ch, bool alpha) -> nir_def * {
        switch (f) {
        case 0: return nir_imm_float(&b, 0); case 1: return nir_imm_float(&b, 1);
        case 2: return ch == 3 ? sa : sv[ch]; case 3: return nir_fsub_imm(&b, 1.0, ch == 3 ? sa : sv[ch]);
        case 4: return sa; case 5: return nir_fsub_imm(&b, 1.0, sa);
        case 6: return d[ch]; case 7: return nir_fsub_imm(&b, 1.0, d[ch]);
        case 8: return d[3]; case 9: return nir_fsub_imm(&b, 1.0, d[3]);
        case 10: return alpha ? nir_imm_float(&b, 1.0) : nir_fmin(&b, sa, nir_fsub_imm(&b, 1.0, d[3]));
        }
        die("blend factor");
      };
      // BGRA10_XR alpha is not extended range: its source value is clamped to [0, 1] too before
      // blending (measured: a552_sub_sa_12, alpha 1.2 with subtract, is off by 102 codes otherwise).
      auto blend = [&](unsigned ch, bool alpha) -> nir_def * {
        unsigned op = alpha ? a.alphaOp : a.rgbOp, sf = alpha ? a.srcA : a.srcRGB, df = alpha ? a.dstA : a.dstRGB;
        nir_def *s_ = ch == 3 ? sa : sv[ch];
        if (op == 3) return nir_fmin(&b, s_, d[ch]);
        if (op == 4) return nir_fmax(&b, s_, d[ch]);
        nir_def *x = nir_fmul(&b, s_, factor(sf, ch, alpha)), *y = nir_fmul(&b, d[ch], factor(df, ch, alpha));
        return op == 0 ? nir_fadd(&b, x, y) : op == 1 ? nir_fsub(&b, x, y) : nir_fsub(&b, y, x);
      };
      // BGRA10_XR alpha is not extended range: Metal clamps the blended alpha to [0, 1] (measured:
      // scene xr552_tint_additive, alpha 1 + d stored as code 894 = 1.0).
      nir_def *o[4] = {xrEncodeExact(L.cls, blend(0, false)), xrEncodeExact(L.cls, blend(1, false)), xrEncodeExact(L.cls, blend(2, false)),
                       L.cls == AIR_FMT_XR10_BGR32 ? nir_imm_float(&b, 1.0) : xrEncodeExact(L.cls, nir_fsat(&b, blend(3, true)))};
      return nir_vec(&b, o, 4);
    }
    // RB path: the shader hands the RB a source alpha already in [0, 1] (the factor Metal uses; on
    // BGRA10_XR also the stored alpha, which Metal clamps to [0, 1] after blending: for every blend
    // state the hw path takes, blending the clamped alpha gives the same result), so the result does
    // not depend on whether the RB clamps SRC_ALPHA / SRC1_ALPHA for the UNORM view (verify4 item 3:
    // a552_srcover_12, alpha 1.2, was 102 codes off on llvmpipe).
    sv[3] = sa;
    auto factor = [&](unsigned f, unsigned ch) -> nir_def * {
      switch (f) {
      case 0: return nir_imm_float(&b, 0); case 1: return nir_imm_float(&b, 1);
      case 2: return sv[ch]; case 3: return nir_fsub_imm(&b, 1.0, sv[ch]);
      case 4: return sv[3]; case 5: return nir_fsub_imm(&b, 1.0, sv[3]);
      }
      die("blend factor");
    };
    auto chan = [&](unsigned ch, bool alpha) -> nir_def * {
      if (!a.enabled) return xrEncodeExact(L.cls, sv[ch]);
      unsigned op = alpha ? a.alphaOp : a.rgbOp, sf = alpha ? a.srcA : a.srcRGB, df = alpha ? a.dstA : a.dstRGB;
      nir_def *ks = nir_fadd_imm(&b, nir_fmul_imm(&b, sv[ch], k), 0.0);
      if (op != 0) return nir_fadd_imm(&b, ks, c);                                  // min / max
      if (sf == 1) return nir_fadd(&b, ks, nir_fmul_imm(&b, nir_fsub_imm(&b, 1.0, factor(df, ch)), c));
      if (sf == 0) return nir_fmul_imm(&b, nir_fsub_imm(&b, 1.0, factor(df, ch)), c);
      return nir_fadd_imm(&b, ks, c);                                               // complementary pair
    };
    nir_def *o[4] = {chan(0, false), chan(1, false), chan(2, false),
                     L.cls == AIR_FMT_XR10_BGR32 ? sv[3] : chan(3, true)};
    if (L.dual) nir_store_var(&b, L.src1, nir_vec4(&b, sv[0], sv[1], sv[2], sv[3]), 0xf);
    return nir_vec(&b, o, 4);
  }
  std::map<const GlobalVariable *, int> constSamplers;       // constexpr sampler -> S# (assigned up front)
  std::map<const BasicBlock *, nir_block *> blocks;
  std::map<const PHINode *, nir_variable *> phiVars;
  // Pointer phis (docs/USERSPACE-GRAPHICS-20261019.md, RenderBox's path and alpha-effect shaders): a 32-bit offset from
  // one base (root, or the single threadgroup / constant-data space when root is null), or a 64-bit device address.
  struct PtrPhi { nir_variable *var = nullptr; PtrVal::Kind kind = PtrVal::GLOBAL; Value *root = nullptr; bool addr64 = false; };
  std::map<const PHINode *, PtrPhi> ptrPhis;
  std::vector<std::pair<nir_variable *, unsigned>> outs;     // per return scalar: var (nullptr = inactive), comp
  std::map<std::string, int> varyingSlot;                    // name -> VAR slot (sorted-name order)
  int maxUbo = -1;
  // ABI v6: the driver table's UBO index; a function whose declared constant buffers leave no room
  // for it below 16 is refused (no WindowServer function comes close: they declare buffer(0..7)).
  int driverTableUbo() {
    int maxIdx = uboSlots(*opt) - 1;
    if (R.driver_table_ubo > maxIdx)
      die("device or threadgroup buffer with constant buffers declared up to buffer(" + std::to_string(R.declared_ubo_max) +
          "): the driver table would be UBO " + std::to_string(R.driver_table_ubo) + ", but a8xx honours only UBO 0.." +
          std::to_string(maxIdx) + " (ABI v6, BINDING-ABI.md 3.2)");
    return R.driver_table_ubo;
  }
  std::map<const GlobalVariable *, unsigned> sharedOff; unsigned sharedSize = 0;
  std::map<const GlobalVariable *, unsigned> constOff; std::vector<uint8_t> constData;
  std::map<const GlobalVariable *, nir_variable *> privVars;
  uint64_t allocaBytes = 0;
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
  // The objects a pointer can point into, through GEPs, casts, phis and selects; nullptr stands for any other origin
  // (a loaded, integer-made or returned pointer). undef/poison incoming values point nowhere.
  void ptrRoots(Value *V, std::set<Value *> &roots, std::set<Value *> &seen) {
    if (!seen.insert(V).second || isa<UndefValue>(V)) return;
    if (auto *GEP = dyn_cast<GEPOperator>(V)) return ptrRoots(GEP->getPointerOperand(), roots, seen);
    if (auto *O = dyn_cast<Operator>(V))
      if (O->getOpcode() == Instruction::BitCast || O->getOpcode() == Instruction::AddrSpaceCast) return ptrRoots(O->getOperand(0), roots, seen);
    if (auto *PN = dyn_cast<PHINode>(V)) { for (Value *in : PN->incoming_values()) ptrRoots(in, roots, seen); return; }
    if (auto *S = dyn_cast<SelectInst>(V)) { ptrRoots(S->getTrueValue(), roots, seen); ptrRoots(S->getFalseValue(), roots, seen); return; }
    roots.insert(isa<Argument>(V) || isa<GlobalVariable>(V) || isa<AllocaInst>(V) ? V : nullptr);
  }
  // The PtrVal kind a root resolves to, without emitting code (as setupArgs() and ptr() decide); -1 if unsupported.
  int rootKind(Value *R) {
    if (auto *A = dyn_cast<Argument>(R)) { auto it = ptrs.find(A); return it == ptrs.end() ? -1 : it->second.kind; }
    if (auto *GV = dyn_cast<GlobalVariable>(R)) {
      if (GV->getName().starts_with("__air_sampler_state")) return -1;
      if (GV->getAddressSpace() == 3) return PtrVal::SHARED;
      if (GV->hasInitializer() && GV->isConstant()) return PtrVal::CONSTDATA;
      if (GV->hasInitializer() && GV->hasLocalLinkage()) return PtrVal::PRIVATE;
      return -1;
    }
    return isa<AllocaInst>(R) ? PtrVal::PRIVATE : -1;
  }
  // Two pointers address the same object space, so their offsets can be phi'd or selected.
  static bool sameBase(const PtrVal &a, const PtrVal &c) {
    if (a.kind != c.kind) return false;
    switch (a.kind) {
    case PtrVal::SHARED: case PtrVal::CONSTDATA: return true;      // one space each: offsets are absolute
    case PtrVal::UBO: return a.index == c.index;
    case PtrVal::GLOBAL: return a.addr64 && a.addr64 == c.addr64;
    case PtrVal::PRIVATE: return a.var && a.var == c.var;
    default: return false;
    }
  }
  nir_def *globalAddress(const PtrVal &p) { return nir_iadd(&b, p.addr64, nir_u2u64(&b, p.off)); }
  PtrPhi ptrPhiOf(PHINode *PN) {
    std::set<Value *> roots, seen; ptrRoots(PN, roots, seen);
    if (roots.count(nullptr)) die("phi of pointers that are loaded, made from integers or returned by calls: " + str(PN));
    if (roots.empty()) die("phi of undefined pointers: " + str(PN));
    std::set<int> kinds; for (Value *R : roots) kinds.insert(rootKind(R));
    if (kinds.count(-1)) die("phi of unsupported pointers (sampler state or unknown arguments): " + str(PN));
    PtrPhi pp; pp.kind = (PtrVal::Kind)*kinds.begin();
    if (roots.size() == 1) pp.root = *roots.begin();
    else if (kinds.size() == 1 && (pp.kind == PtrVal::SHARED || pp.kind == PtrVal::CONSTDATA)) pp.root = nullptr;
    else if (kinds.size() == 1 && pp.kind == PtrVal::GLOBAL) pp.addr64 = true;
    else die("phi of pointers into different buffers or address spaces (" + std::to_string(roots.size()) + " objects): " + str(PN));
    pp.var = nir_local_variable_create(b.impl, pp.addr64 ? glsl_uint64_t_type() : glsl_uint_type(), "pphi");
    return pp;
  }
  PtrVal ptrPhiBase(const PtrPhi &pp) { if (pp.root) return ptr(pp.root); PtrVal p{pp.kind}; return p; }
  PtrVal ptrPhiValue(const PtrPhi &pp) {
    nir_def *l = nir_load_var(&b, pp.var);
    if (pp.addr64) { PtrVal p{PtrVal::GLOBAL}; p.addr64 = l; p.off = nir_imm_int(&b, 0); return p; }
    PtrVal p = ptrPhiBase(pp); p.off = l; return p;
  }
  void storePtrPhi(const PtrPhi &pp, Value *in, PHINode *PN) {
    if (isa<UndefValue>(in)) { nir_store_var(&b, pp.var, pp.addr64 ? nir_imm_int64(&b, 0) : nir_imm_int(&b, 0), 1); return; }
    PtrVal p = ptr(in);
    if (pp.addr64) {
      if (p.kind != PtrVal::GLOBAL || !p.addr64) die("pointer phi incoming value is not a device-buffer pointer: " + str(PN));
      nir_store_var(&b, pp.var, globalAddress(p), 1); return;
    }
    if (!sameBase(p, ptrPhiBase(pp))) die("pointer phi incoming value has another base than the phi: " + str(PN));
    nir_store_var(&b, pp.var, p.off, 1);
  }

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
  // or a function-constant initialiser global directly.  -1: unknown (gatedPresent refuses it).
  int predValue(const std::string &g) {
    auto am = spec.ambiguousPredicates.find(g);
    if (am != spec.ambiguousPredicates.end()) die(am->second);
    auto it = spec.implicitVals.find(g);
    if (it != spec.implicitVals.end()) return it->second != 0;
    int idx = fcIndexOfGlobal(g);
    if (idx >= 0) {
      for (auto &f : R.fcs) if (f.index == idx) return !f.value.empty() && f.value[0] != 0;
      return 0;
    }
    return -1;   // unknown
  }
  // fix round 5 (verify5 item 2): a gating predicate the static-initialiser evaluation could not
  // decide refuses the variant.  v4 fell back to "present if the code reads it" for arguments (and
  // "present" for outputs): with every constant set, `int(F) == 2`, `bool(F)`, `uint(F)`, `short(H)`
  // (AIR conversion calls, which neither our evaluator nor LLVM's folded) gave ours [0, 1, 3] where
  // Metal has [] (fixtures conv_pred_allset*, regression test conv_predicates).
  bool gatedPresent(const ArgInfo &a, const char *what) {
    int p = predValue(a.predGlobal);
    if (p < 0)
      die(std::string(what) + " " + (a.argName.empty() ? a.kind : a.argName) + " is gated by " + a.predGlobal +
          ", which the static initialiser does not decide" + (spec.ctorWhy.empty() ? std::string() : " (" + spec.ctorWhy + ")") +
          ": refused rather than guessing its presence (BINDING-ABI.md 3.7)");
    return p != 0;
  }
  int locValue(const ArgInfo &a) {
    if (a.locGlobal.empty()) return a.location;
    if (spec.taintedGlobals.count(a.locGlobal)) die("binding index expression " + a.locGlobal + " depends on an unset function constant");
    auto it = spec.implicitVals.find(a.locGlobal);
    if (it == spec.implicitVals.end()) die("binding index expression " + a.locGlobal + " could not be evaluated from the function constants");
    return (int)it->second;
  }

  void setupArgs() {
    // Resolve gating, attribute index expressions and usage first.
    for (ArgInfo &a : outArgs) {
      if (a.gated && a.kind == "air.render_target" && spec.ambiguousPredicates.count(a.predGlobal)) {
        // ABI v5 (verify4 item 2): a colour output whose presence depends on an unset constant's
        // value.  Which way Metal goes cannot be predicted, but it is unobservable when the pipeline
        // has no colour attachment at that index (the write goes nowhere).  The output is not
        // written and the sidecar says the variant is valid only for such pipelines
        // (reflection.requires_no_attachment); the plug-in refuses a pipeline that has that
        // attachment (BINDING-ABI.md 3.7, checklist 5.1 step 12).  Measured need: CA's
        // 02_PBGRA_Xgfc fragment, whose [[color(1)]] is gated by
        // frg_has_color1 = (fc_generic && fc_attachment_count > 1) || fc_dest_index == 1 with the
        // uchar fc_dest_index unset, on a pipeline with one colour attachment.
        int loc = locValue(a);
        if (loc < 0 || loc >= ABI_MAX_RTS) die(spec.ambiguousPredicates.at(a.predGlobal));
        if (opt->rtClass[loc]) die(spec.ambiguousPredicates.at(a.predGlobal) + " (colour attachment " + std::to_string(loc) + " is an XR attachment of this pipeline)");
        a.active = a.present = false; a.location = loc;
        if (std::find(R.requires_no_attachment.begin(), R.requires_no_attachment.end(), loc) == R.requires_no_attachment.end())
          R.requires_no_attachment.push_back(loc);
        // verify5 minor: name a dual-source output [[color(n), index(1)]] as such (the conservative
        // requires_no_attachment entry for n is kept: whether its blend state reads SRC1 is not in the key)
        R.warnings.push_back("[[color(" + std::to_string(loc) + (a.dualIndex ? "), index(" + std::to_string(a.dualIndex) : std::string()) + ")]] is gated by " + a.predGlobal + ", which depends on the value of an unset function constant: "
                             "not written; valid only for a pipeline without colour attachment " + std::to_string(loc) + " (BINDING-ABI.md 3.7)");
        continue;
      }
      if (a.gated) a.active = a.present = gatedPresent(a, "output");
      if (a.active) a.location = locValue(a);
    }
    for (ArgInfo &a : inArgs) {
      Argument *A = F->getArg(a.argno);
      a.used = !A->use_empty();
      if (a.gated) a.present = gatedPresent(a, "argument");
      a.active = a.present || a.used;
      if (a.active) a.location = locValue(a);
      if (a.used && !a.present) {
        // The argument is absent in Metal's reflection (predicate false, or it depends on an unset
        // constant) but the specialised code still reads it.  Metal then reads whatever the app
        // bound at that index.  ABI v3: the binding keeps its slot with present=false, and the
        // command stream binds the app's object at that Metal index, or the driver's zero buffer /
        // null descriptor (BINDING-ABI.md 3.7).  Informational, not a refusal.
        R.warnings.push_back("argument " + a.argName + " is absent (function-constant predicate false or unset) but the code reads it: bind-through");
      }
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
    for (auto &a : outArgs) if (a.active && a.kind == "air.render_target") writtenRts++;
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
        // fix round 5: an app dual-source output was stored as a second DATA<n> index-0 output (silently
        // colliding with [[color(n)]]); no WindowServer / CA function has one (corpus scan): refused.
        if (a.dualIndex) die("[[color(" + std::to_string(a.location) + "), index(" + std::to_string(a.dualIndex) + ")]] (app dual-source blending) is not in ABI v5");
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
        if (opt->rtClass[a.location]) setupRtLowering(a.location, v, true);
        AirRenderTarget t; t.index = a.location; t.comps = glsl_get_vector_elements(v->type);
        t.base = baseName(glsl_get_base_type(v->type)); t.written = true; R.render_targets.push_back(t);
      }
      if (a.kind == "air.vertex_output") {
        AirVarying vy; vy.name = a.name; vy.slot = varyingSlot.at(a.name); vy.comps = glsl_get_vector_elements(v->type);
        vy.bits = glsl_get_bit_size(v->type); vy.base = baseName(glsl_get_base_type(v->type)); vy.interp = a.interp; vy.sampling = a.sampling;
        R.varyings.push_back(vy);
        // VPC exports select full registers: SP_VS_OUTPUT_REG has no half-register bit.
        // Keep the AIR interface's logical type above, and keep half arithmetic in
        // the function. terminator() widens the final value at the output store.
        if (glsl_get_bit_size(v->type) < 32) {
          glsl_base_type transport = glsl_base_type_is_integer(glsl_get_base_type(v->type)) ? GLSL_TYPE_UINT : GLSL_TYPE_FLOAT;
          v->type = glsl_vector_type(transport, glsl_get_vector_elements(v->type));
        }
      }
      for (unsigned c = 0; c < nflat(rts[i]); c++) outs.push_back({v, c});
      report += "  out  " + a.kind + " " + a.name + " -> location " + std::to_string(loc) + "\n";
    }
    // Sampler slots used by API sampler arguments, then constexpr samplers in the LOWEST free slots
    // (Metal: at most 16 samplers per function including constexpr ones).  ABI v4 (verify3 item 3):
    // v3 packed them downward from S#15, so every variant with a constexpr sampler needed NSAMP 16
    // (and, with the counts tied, NTEX 16): 86% of the sweep loaded 16 T# + 16 S# per draw.
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
      int next = 0;
      for (GlobalVariable *G : cs) {
        while (next < ABI_MAX_SAMPLERS && (apiMask >> next) & 1) next++;
        if (next >= ABI_MAX_SAMPLERS) die("more than 16 samplers (API + constexpr) in one function");
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
        next++;
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
          if (opt->rtClass[a.location]) {
            // framebuffer fetch of an XR attachment: decode the view's u-domain value
            if (!rtLow.count(a.location)) setupRtLowering(a.location, v, false);
            unsigned cls = rtLow[a.location].cls;
            std::vector<nir_def *> u = split(nir_load_var(&b, v)), d;
            for (unsigned c = 0; c < u.size(); c++)
              d.push_back(c == 3 && cls == AIR_FMT_XR10_BGR32 ? nir_imm_float(&b, 1.0) : xrDecode(cls, u[c]));
            vals[A] = coerce(d, A->getType());
          } else
          vals[A] = coerce(split(nir_load_var(&b, v)), A->getType());
          AirBinding bd; bd.kind = "fb_fetch"; bd.metal_index = a.location; bd.slot = ABI_FB_READ_SLOT + a.location;
          bd.arg_name = a.argName; bd.type_name = a.typeName; bd.present = a.present; R.bindings.push_back(bd);
        }
        line += " (framebuffer fetch, colour " + std::to_string(a.location) + (a.used ? "" : ", unused") + ")";
      } else if (a.kind == "air.buffer") {
        PtrVal p{};
        AirBinding bd; bd.metal_index = a.location; bd.arg_name = a.argName; bd.type_name = a.typeName; bd.used = a.used;
        bd.present = a.present;
        if (a.location < 0 || a.location > 30) die("buffer index " + std::to_string(a.location) + " out of range");
        if (a.addrspace == 2) {
          p.kind = PtrVal::UBO; p.index = a.location; if (a.used) maxUbo = std::max(maxUbo, a.location);
          bd.kind = "ubo"; bd.slot = a.location; bd.minimum_bytes = a.bufferSize;
        } else if (a.addrspace == 1) {   // device buffer: 64-bit GPU VA from the device-address table (UBO driver_table_ubo, ABI v6)
          p.kind = PtrVal::GLOBAL;
          if (a.used) {
            _nir_load_ubo_indices ix = {}; ix.align_mul = 8; ix.range = ~0u;
            p.addr64 = nir_pack_64_2x32(&b, _nir_build_load_ubo(&b, 2, 32, nir_imm_int(&b, driverTableUbo()), nir_imm_int(&b, 8 * a.location), ix));
            maxUbo = std::max(maxUbo, R.driver_table_ubo);
          }
          bd.kind = "device_buffer"; bd.slot = 8 * a.location;
        } else if (a.addrspace == 3) {
          // threadgroup(n) buffer argument (setThreadgroupMemoryLength:atIndex:).  Its size is only
          // known at dispatch, so it lives after the static threadgroup memory at a byte offset the
          // command stream writes into the driver table (UBO driver_table_ubo) at 256 + 4n (BINDING-ABI.md 3.8).
          if (stage != MESA_SHADER_COMPUTE) die("threadgroup buffer argument in a " + std::string(stage == MESA_SHADER_VERTEX ? "vertex" : "fragment") + " function (tile shaders are not in ABI v5)");
          p.kind = PtrVal::SHARED;
          if (a.used) {
            _nir_load_ubo_indices ix = {}; ix.align_mul = 4; ix.range = ~0u;
            tgBase[A] = _nir_build_load_ubo(&b, 1, 32, nir_imm_int(&b, driverTableUbo()), nir_imm_int(&b, ABI_TG_TABLE_OFFSET + 4 * a.location), ix);
            maxUbo = std::max(maxUbo, R.driver_table_ubo);
          }
          bd.kind = "threadgroup_buffer"; bd.slot = ABI_TG_TABLE_OFFSET + 4 * a.location;
          p.off = a.used ? tgBase[A] : nir_imm_int(&b, 0);
          ptrs[A] = p; R.bindings.push_back(bd);
          report += line + " threadgroup(" + std::to_string(a.location) + ") -> shared memory at driver-table offset\n";
          continue;
        } else die("buffer in address space " + std::to_string(a.addrspace) + " as an argument");
        p.off = nir_imm_int(&b, 0);
        ptrs[A] = p;
        R.bindings.push_back(bd);
        line += " buffer(" + std::to_string(a.location) + ") addrspace " + std::to_string(a.addrspace) +
                (a.addrspace == 2 ? " -> UBO" : " -> global (VA from UBO31)");
      } else if (a.kind == "air.texture") {
        if (a.location < 0 || a.location >= ABI_MAX_TEXTURES)
          die("texture index " + std::to_string(a.location) + " >= " + std::to_string(ABI_MAX_TEXTURES) + " (ABI v1 non-bindless T# limit)");
        tex[A] = a.location; line += " texture(" + std::to_string(a.location) + ")";
        if (a.access == "read_write") die("texture(" + std::to_string(a.location) + ") with access::read_write (coherent image load/store): not in ABI v5");
        // access::write -> ir3 image (IBO) n, BINDING-ABI.md 3.3; sample/read -> T# n
        AirBinding bd; bd.kind = a.access == "write" ? "storage_texture" : "texture"; bd.metal_index = bd.slot = a.location; bd.arg_name = a.argName;
        bd.type_name = a.typeName; bd.access = a.access; bd.used = a.used; bd.present = a.present; R.bindings.push_back(bd);
      } else if (a.kind == "air.sampler") {
        smp[A] = a.location; line += " sampler(" + std::to_string(a.location) + ")";
        AirBinding bd; bd.kind = "sampler"; bd.metal_index = bd.slot = a.location; bd.arg_name = a.argName;
        bd.used = a.used; bd.present = a.present; R.bindings.push_back(bd);
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
  // ---- texture ops ----
  int texOf(Value *V) { auto it = tex.find(V); if (it == tex.end()) die("texture operand not an argument"); return it->second; }
  int smpOf(Value *V) {
    auto it = smp.find(V); if (it != smp.end()) return it->second;
    if (auto *CI = dyn_cast<CallInst>(V)) if (CI->getCalledFunction() && CI->getCalledFunction()->getName().starts_with("air.get_read_sampler")) return -1;
    if (auto *GV = dyn_cast<GlobalVariable>(V->stripPointerCasts())) {
      auto c = constSamplers.find(GV); if (c != constSamplers.end()) return c->second;
      die("constexpr sampler " + GV->getName().str() + " was not assigned a slot");
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
    std::vector<nir_def *> r = split(&ti->def);
    unsigned cls = t >= 0 && t < 16 ? opt->texClass[t] : 0;
    if (cls && op != nir_texop_txs && op != nir_texop_query_levels) {
      // Draw-time texture class (BINDING-ABI.md 3.3): the T# is a UNORM view of an XR texture;
      // hardware filtering is linear, so decoding after filtering is exact.
      checkFormatClass(cls, "texture(" + std::to_string(t) + ")");
      if (!(dt & nir_type_float)) die("texture(" + std::to_string(t) + ") has an XR format class but is read as an integer type");
      for (unsigned c = 0; c < r.size(); c++) {
        nir_def *x = r[c]->bit_size == 32 ? r[c] : nir_f2f32(&b, r[c]);
        x = c == 3 && cls == AIR_FMT_XR10_BGR32 ? nir_imm_float(&b, 1.0) : xrDecode(cls, x);
        r[c] = r[c]->bit_size == 32 ? x : nir_f2fN(&b, x, r[c]->bit_size);
      }
      R.tex_class[t] = cls;
    }
    return r;
  }
  bool isZeroConst(Value *v) { auto *c = dyn_cast<Constant>(v); return c && c->isNullValue(); }

  // ---- AIR intrinsic calls ----
  std::vector<nir_def *> callAir(CallInst *CI) {
    std::string nm = CI->getCalledFunction()->getName().str();
    auto A = [&](unsigned i) { return get(argOperand(CI, i)); };
    auto A1 = [&](unsigned i) { return get1(argOperand(CI, i)); };
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
    // Derivatives of 16-bit values are taken at 32 bits and narrowed: ir3 emits dsx / dsy as f32 (Mesa sets their
    // cat5 type to TYPE_F32), and on the X2-90 the half-register form returns derivatives tens of times too large
    // (A16 v101: Liquid Glass's fwidth(half) lost its shape mask; docs/USERSPACE-GRAPHICS-20261019.md).
    auto wide = [&](nir_def *x) { return x->bit_size == 16 ? nir_f2f32(&b, x) : x; };
    auto narrow = [&](nir_def *x, nir_def *r) { return x->bit_size == 16 ? nir_f2f16(&b, r) : r; };
    UN("dfdx", narrow(x, nir_ddx(&b, wide(x)))) UN("dfdy", narrow(x, nir_ddy(&b, wide(x))))
    UN("fwidth", narrow(x, nir_fadd(&b, nir_fabs(&b, nir_ddx(&b, wide(x))), nir_fabs(&b, nir_ddy(&b, wide(x))))))
    BIN("fmax", nir_fmax(&b, x, y)) BIN("fmin", nir_fmin(&b, x, y))
    BIN("pow", nir_fpow(&b, x, y)) BIN("powr", nir_fpow(&b, x, y)) BIN("atan2", nir_atan2(&b, x, y))
    if (base("fmax3") || base("fast_fmax3")) return perComp([&](auto p) { return nir_fmax(&b, p(0), nir_fmax(&b, p(1), p(2))); }, 3);
    if (base("fmin3") || base("fast_fmin3")) return perComp([&](auto p) { return nir_fmin(&b, p(0), nir_fmin(&b, p(1), p(2))); }, 3);
    // air.clamp.s.* / air.clamp.u.* (integer clamp) also start with "air.clamp.": they must not reach the
    // float clamp.  Fix round 6 (A16 run 2, probe_ubo_lo / probe_ubo_hi): `clamp(int(x) / 6, 0, 15)`
    // compiled to max.f / min.f on the integer's bits; 1..15 are fp32 denormals, which Adreno flushes
    // (Turnip: shaderDenormFlushToZeroFloat32), so every band selected slot 0.
    if (!starts("air.clamp.s.") && !starts("air.clamp.u.") && (base("clamp") || base("fast_clamp")))
      return perComp([&](auto p) { return nir_fmin(&b, nir_fmax(&b, p(0), p(1)), p(2)); }, 3);
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
        // float -> char / short: through f2i32 (verify6 must-fix 4): Metal truncates toward zero, so
        // char(-128.5) == -128; NIR's f2i8 / f2i16 constant folding calls it poison (source below the
        // minimum before truncation).  No corpus function converts float to a signed 8/16-bit type.
        if (dk == 's' && sk == 'f') return db < 32 ? nir_i2iN(&b, nir_f2i32(&b, x), db) : nir_f2iN(&b, x, db);
        if (dk == 'u' && sk == 'f') return nir_f2uN(&b, x, db);
        // integer -> integer: the SOURCE signedness picks the extension (C semantics; fix round 6)
        return sk == 's' ? nir_i2iN(&b, x, db) : nir_u2uN(&b, x, db);
      }, 1);
    }
    if (starts("air.discard_fragment")) { nir_demote(&b); return {}; }
    if (starts("air.wg.barrier") || starts("air.simdgroup.barrier")) {
      unsigned flags = cast<ConstantInt>(argOperand(CI, 0))->getZExtValue();   // mem_flags: 1 device, 2 threadgroup, 4 texture (INFERRED)
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
      int t = texOf(argOperand(CI, 0));
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
      nir_def *off = isZeroConst(argOperand(CI, offArg)) ? nullptr : vec(A(offArg));
      bool isLevel = cast<ConstantInt>(argOperand(CI, lvlFlag))->isOne();
      Value *lb = argOperand(CI, lvlFlag + 1), *ml = argOperand(CI, lvlFlag + 2);
      nir_def *lod = isLevel ? A1(lvlFlag + 1) : nullptr;
      nir_def *bias = (!isLevel && !isZeroConst(lb)) ? A1(lvlFlag + 1) : nullptr;
      nir_def *minlod = isZeroConst(ml) ? nullptr : A1(lvlFlag + 2);
      nir_texop op = lod ? nir_texop_txl : bias ? nir_texop_txb : nir_texop_tex;
      if (stage != MESA_SHADER_FRAGMENT && op == nir_texop_tex) { op = nir_texop_txl; lod = nir_imm_float(&b, 0); }
      auto r = texop(op, dim, arr, texOf(argOperand(CI, 0)), smpOf(argOperand(CI, 1)), vec(c), lod, bias, off, minlod, nullptr, nullptr, bs, dt);
      r.push_back(nir_imm_intN_t(&b, 0, 8));           // the i8 "residency" field of the result struct
      return r;
    };
    if (starts("air.sample_texture_2d_grad.")) {
      unsigned bs; nir_alu_type dt; resType(bs, dt);
      auto r = texop(nir_texop_txd, GLSL_SAMPLER_DIM_2D, false, texOf(argOperand(CI, 0)), smpOf(argOperand(CI, 1)),
                     vec(A(2)), nullptr, nullptr, isZeroConst(argOperand(CI, 7)) ? nullptr : vec(A(7)), nullptr, vec(A(3)), vec(A(4)), bs, dt);
      r.push_back(nir_imm_intN_t(&b, 0, 8)); return r;
    }
    if (starts("air.sample_texture_2d.")) return sampleCommon(GLSL_SAMPLER_DIM_2D, false, 2, -1, 4, 5);
    if (starts("air.sample_texture_3d.")) return sampleCommon(GLSL_SAMPLER_DIM_3D, false, 2, -1, 4, 5);
    if (starts("air.sample_texture_1d_array.")) return sampleCommon(GLSL_SAMPLER_DIM_1D, true, 2, 3, 5, 6);
    if (starts("air.sample_texture_1d.")) return sampleCommon(GLSL_SAMPLER_DIM_1D, false, 2, -1, 4, 5);
    if (starts("air.read_texture_2d.")) {
      // Two operand layouts, measured (docs/WINDOWSERVER-APL-ABORT-20261020.md):
      //   AIR 2.9 (system metallibs, `metal -c`):       (tex, read sampler, coord, offset, lod, access)
      //   AIR 2.2 (Metal's compiler service hands the plug-in this version): (tex, coord, lod, access)
      // access is 0 sample, 1 read, 3 read_write; Metal's read() has no offset, so the 2.9 offset is always zero.
      // The layout is told by the operand count and the operand types together; anything else is refused.
      auto intVec2 = [&](unsigned i) {
        auto *V = dyn_cast<FixedVectorType>(argOperand(CI, i)->getType());
        return V && V->getNumElements() == 2 && V->getElementType()->isIntegerTy();
      };
      auto intScalar = [&](unsigned i) { return argOperand(CI, i)->getType()->isIntegerTy(); };
      unsigned coordArg, lodArg;
      if (CI->arg_size() == 6 && argOperand(CI, 1)->getType()->isPointerTy() && intVec2(2) && intVec2(3) && intScalar(4) && intScalar(5)) {
        if (!isZeroConst(argOperand(CI, 3))) die(nm + " with an offset other than a constant zero");
        coordArg = 2; lodArg = 4;
      } else if (CI->arg_size() == 4 && intVec2(1) && intScalar(2) && intScalar(3)) {
        coordArg = 1; lodArg = 2;
      } else die(nm + " with " + std::to_string(CI->arg_size()) + " operands of an unknown layout");
      unsigned bs; nir_alu_type dt; resType(bs, dt);
      nir_def *coord = vec(A(coordArg)); if (coord->bit_size != 32) coord = nir_u2u32(&b, coord);
      nir_def *lod = A1(lodArg); if (lod->bit_size != 32) lod = nir_u2u32(&b, lod);
      auto r = texop(nir_texop_txf, GLSL_SAMPLER_DIM_2D, false, texOf(argOperand(CI, 0)), -1, coord, lod, nullptr, nullptr, nullptr, nullptr, nullptr, bs, dt);
      r.push_back(nir_imm_intN_t(&b, 0, 8)); return r;
    }
    // Multisample size queries have no lod operand; multisample textures are not in the binding ABI.
    if (starts("air.get_width_texture_2d_ms") || starts("air.get_height_texture_2d_ms"))
      die("AIR intrinsic " + nm + ": multisample textures are not supported");
    if (starts("air.get_width_texture_2d") || starts("air.get_height_texture_2d")) {
      auto r = texop(nir_texop_txs, GLSL_SAMPLER_DIM_2D, false, texOf(argOperand(CI, 0)), -1, nullptr, A1(1), nullptr, nullptr, nullptr, nullptr, nullptr, 32, nir_type_uint32, 2);
      return {r[starts("air.get_width") ? 0 : 1]};
    }
    die("AIR intrinsic not implemented in prototype: " + nm);
#undef UN
#undef BIN
  }

  std::vector<nir_def *> callLLVM(CallInst *CI) {
    Intrinsic::ID id = CI->getIntrinsicID();
    auto A = [&](unsigned i) { return get(argOperand(CI, i)); };
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
    if (auto *S = dyn_cast<SelectInst>(&I); S && S->getType()->isPointerTy()) {
      Value *TV = S->getTrueValue(), *FV = S->getFalseValue();
      if (isa<UndefValue>(TV) || isa<UndefValue>(FV)) { ptrs[&I] = ptr(isa<UndefValue>(TV) ? FV : TV); return; }
      nir_def *c = get1(S->getCondition());
      PtrVal t = ptr(TV), f = ptr(FV);
      if (sameBase(t, f)) { PtrVal p = t; p.off = nir_bcsel(&b, c, t.off, f.off); ptrs[&I] = p; return; }
      if (t.kind == PtrVal::GLOBAL && f.kind == PtrVal::GLOBAL && t.addr64 && f.addr64) {
        PtrVal p{PtrVal::GLOBAL}; p.addr64 = nir_bcsel(&b, c, globalAddress(t), globalAddress(f)); p.off = nir_imm_int(&b, 0);
        ptrs[&I] = p; return;
      }
      die("select of pointers into different buffers or address spaces: " + str(&I));
    }
    if (auto *S = dyn_cast<SelectInst>(&I)) {
      auto c = get(S->getCondition()), t = get(S->getTrueValue()), f = get(S->getFalseValue()); std::vector<nir_def *> r;
      for (unsigned i = 0; i < t.size(); i++) r.push_back(nir_bcsel(&b, c.size() == 1 ? c[0] : c[i], t[i], f[i]));
      return set(r);
    }
    if (auto *CI = dyn_cast<CastInst>(&I)) {
      Type *DT = CI->getDestTy();
      if (DT->isPointerTy() && (CI->getOpcode() == Instruction::BitCast || CI->getOpcode() == Instruction::AddrSpaceCast)) {
        ptrs[&I] = ptr(CI->getOperand(0)); return;
      }
      auto x = get(CI->getOperand(0)); unsigned db = bits(DT->getScalarType()); std::vector<nir_def *> r;
      if (CI->getOpcode() == Instruction::BitCast || CI->getOpcode() == Instruction::AddrSpaceCast) {
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
      if (auto *ci = dyn_cast<ConstantInt>(IE->getOperand(2))) { v[ci->getZExtValue()] = e; return set(v); }
      nir_def *idx = get1(IE->getOperand(2));             // dynamic index: per-component select
      for (unsigned i = 0; i < v.size(); i++) v[i] = nir_bcsel(&b, nir_ieq_imm(&b, idx, i), e, v[i]);
      return set(v);
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
      if (auto pit = ptrPhis.find(PN); pit != ptrPhis.end()) { ptrs[&I] = ptrPhiValue(pit->second); return; }
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
    if (auto *AI = dyn_cast<AllocaInst>(&I)) {
      if (!AI->isStaticAlloca() || AI->getAddressSpace() != 0 || !AI->getAllocatedType()->isSized())
        die("unsupported dynamic, non-entry or non-private alloca: " + str(&I));
      TypeSize elem = DL.getTypeAllocSize(AI->getAllocatedType());
      constexpr uint64_t maxBytes = 65536;
      uint64_t count = cast<ConstantInt>(AI->getArraySize())->getLimitedValue(maxBytes + 1);
      if (elem.isScalable() || elem.getFixedValue() > maxBytes || count > maxBytes ||
          (count && elem.getFixedValue() > (maxBytes - allocaBytes) / count))
        die("private allocations exceed 64 KiB or use scalable types: " + str(&I));
      uint64_t size = std::max<uint64_t>(1, elem.getFixedValue() * count);
      if (size > maxBytes - allocaBytes) die("private allocations exceed 64 KiB: " + str(&I));
      allocaBytes += size;
      PtrVal p{PtrVal::PRIVATE};
      p.var = nir_local_variable_create(b.impl, glsl_array_type(glsl_uint8_t_type(), size, 1), AI->getName().str().c_str());
      p.off = nir_imm_int(&b, 0);
      ptrs[AI] = p;
      return;
    }
    die("instruction " + str(&I));
  }

  void storePhis(BasicBlock *from, BasicBlock *to) {
    for (PHINode &PN : to->phis()) {
      if (auto pit = ptrPhis.find(&PN); pit != ptrPhis.end()) { storePtrPhi(pit->second, PN.getIncomingValueForBlock(from), &PN); continue; }
      auto v = get(PN.getIncomingValueForBlock(from));
      nir_store_var(&b, phiVars.at(&PN), vec(v), (1u << v.size()) - 1);
    }
  }

  void terminator(Instruction *T) {
    if (auto *R = dyn_cast<ReturnInst>(T)) {
      if (Value *rv = R->getReturnValue()) {
        auto v = get(rv);
        std::map<nir_variable *, std::vector<nir_def *>> per;
        if (v.size() != outs.size()) die("return value does not match the output metadata");
        for (unsigned i = 0; i < outs.size(); i++) {
          if (!outs[i].first) continue;                 // function-constant-gated output switched off
          nir_def *d = v[i]; unsigned vb = glsl_get_bit_size(glsl_without_array(outs[i].first->type));
          if (d->bit_size != vb) d = glsl_base_type_is_integer(glsl_get_base_type(outs[i].first->type)) ? nir_u2uN(&b, d, vb) : nir_f2fN(&b, d, vb);
          per[outs[i].first].push_back(d);
        }
        for (auto &kv : per) {
          int ri = kv.first->data.location - FRAG_RESULT_DATA0;
          if (stage == MESA_SHADER_FRAGMENT && ri >= 0 && ri < ABI_MAX_RTS && rtLow.count(ri) && kv.first->data.index == 0) {
            nir_store_var(&b, kv.first, xrEncodeOutput(rtLow[ri], kv.second), 0xf);
            continue;
          }
          nir_store_var(&b, kv.first, vec(kv.second), (1u << kv.second.size()) - 1);
        }
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

  nir_shader *run(const nir_shader_compiler_options *opts) {
    b = nir_builder_init_simple_shader(stage, opts, "%s", F->getName().str().c_str());
    s = b.shader;
    b.impl->structured = false;
    setupArgs();
    // phi temporaries
    for (BasicBlock &BB : *F)
      for (PHINode &PN : BB.phis()) {
        std::vector<Type *> ts; flatten(PN.getType(), ts);
        if (PN.getType()->isPointerTy()) { ptrPhis[&PN] = ptrPhiOf(&PN); continue; }
        for (Type *E : ts) if (E->isPointerTy()) die("phi of an aggregate holding pointers: " + str(&PN));
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
    // BINDING-ABI.md 3.9 (ABI v3): ir3 appends its driver UBOs at info.num_ubos.  Counting every
    // constant buffer the function DECLARES (used or not, present or not) keeps them clear of any
    // buffer(n) the app may bind: verify2's dpk.metal declares an unread buffer(1), and ABI v3 put
    // driver_params at UBO 1 on top of it.
    s->info.num_ubos = std::max(maxUbo, R.declared_ubo_max) + 1;
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
const char *air_format_class_name(unsigned c) {
  static const char *n[] = {"native", "xr10_bgr32", "xr10_bgra64", "xr10_rgb10a8_2p", "ycbcr10_packed", "xr10_srgb"};
  return c < AIR_FMT_CLASS_COUNT ? n[c] : "invalid";
}

AirFrontendResult air_frontend(const char *path, const AirOptions &o, const nir_shader_compiler_options *nopts) {
  auto buf = MemoryBuffer::getFile(path);
  if (!buf) die(std::string("cannot read input ") + path);
  return air_frontend_mem((*buf)->getBufferStart(), (*buf)->getBufferSize(), o, nopts);
}

// Entry point via !air.vertex / !air.fragment / !air.kernel.  A metallib function module has
// exactly one entry; a .air from `metal -c` may have several (select with AirOptions::entry / --entry).
struct AirEntry { Function *F = nullptr; mesa_shader_stage stage = MESA_SHADER_NONE; const MDNode *ins = nullptr, *outs = nullptr; };
static AirEntry findEntry(Module *M, const AirOptions &o) {
  AirEntry e;
  for (auto [md, st] : {std::pair{"air.vertex", MESA_SHADER_VERTEX}, {"air.fragment", MESA_SHADER_FRAGMENT}, {"air.kernel", MESA_SHADER_COMPUTE}}) {
    if (NamedMDNode *N = M->getNamedMetadata(md)) {
      for (MDNode *E : N->operands()) {
        Function *C = cast<Function>(cast<ValueAsMetadata>(E->getOperand(0))->getValue());
        if (!o.entry.empty() ? C->getName() != o.entry : (e.F != nullptr || (o.expectStage >= 0 && (int)st != o.expectStage))) continue;
        e.F = C; e.stage = st;
        if (st == MESA_SHADER_COMPUTE) { e.ins = cast<MDNode>(E->getOperand(2)); e.outs = nullptr; }
        else { e.outs = cast<MDNode>(E->getOperand(1)); e.ins = cast<MDNode>(E->getOperand(2)); }
      }
    }
  }
  if (!e.F && !o.entry.empty()) die("entry point " + o.entry + " not found");
  if (!e.F) {
    if (M->getNamedMetadata("air.visible")) die("no AIR entry point (visible/stitchable function: needs linking into a caller)");
    die("no AIR entry point");
  }
  if (o.expectStage >= 0 && o.expectStage != (int)e.stage)
    die("entry point " + e.F->getName().str() + " is a " + (e.stage == MESA_SHADER_VERTEX ? "vertex" : e.stage == MESA_SHADER_FRAGMENT ? "fragment" : "kernel") +
        " function, not the requested stage");
  return e;
}
// Function constants the module declares, with the values the caller set (by index or by name).
static std::vector<AirFc> resolveFcs(const std::vector<FcDecl> &decls, const AirOptions &o, const std::string &fn,
                                     std::map<int, std::vector<double>> &fc) {
  fc = o.fc;
  for (auto &kv : o.fcByName) {
    bool found = false;
    for (auto &d : decls) if (d.name == kv.first) { fc[d.index] = kv.second; found = true; }
    if (!found) fprintf(stderr, "air2ir3: warning: function constant '%s' not declared by %s (ignored)\n", kv.first.c_str(), fn.c_str());
  }
  std::vector<AirFc> r;
  for (auto &d : decls) {
    AirFc f; f.index = d.index; f.type = d.type; f.name = d.name; f.defined = fc.count(d.index) != 0;
    if (f.defined) fc[d.index] = fcCanon(d.type, fc.at(d.index));     // the value in the declared type (format 5)
    f.value = f.defined ? fc.at(d.index) : std::vector<double>{};
    r.push_back(f);
  }
  return r;
}
// texture(n) arguments the function DECLARES (gated or not): the draw-time texture classes of the
// other T# slots are not key material and do not reach the translator (CACHE-FORMAT.md 2.4).
static uint16_t declaredTextures(const std::vector<ArgInfo> &inArgs) {
  uint16_t m = 0;
  for (auto &a : inArgs) if (a.kind == "air.texture" && a.location >= 0 && a.location < 16) m |= 1u << a.location;
  return m;
}
static int declaredUboMax(const std::vector<ArgInfo> &inArgs) {
  int m = -1;
  for (auto &a : inArgs) if (a.kind == "air.buffer" && a.addrspace == 2 && a.location >= 0 && a.location <= 30) m = std::max(m, a.location);
  return m;
}

// Mesa's NIR_PASS validates the whole shader after every pass in builds without NDEBUG (runtime v5's Mesa is
// debugoptimized): a debugging aid that was 27% of a generic CoreAnimation ubershader compile. Off, as in Mesa's release
// builds, unless NIR_DEBUG is set (left as the developer set it) or AIR2IR3_NIR_VALIDATE=1 (the regression tests).
// Set once, before the first shader is created; nir_debug is only read afterwards.
static void nirValidationPolicy() {
  static std::once_flag once;
  std::call_once(once, [] {
    nir_process_debug_variable();
    const char *v = getenv("AIR2IR3_NIR_VALIDATE");
    if (!getenv("NIR_DEBUG") && !(v && atoi(v))) nir_debug |= NIR_DEBUG_NOVALIDATE;
  });
}

AirFrontendResult air_frontend_mem(const void *bitcode, size_t size, const AirOptions &o0, const nir_shader_compiler_options *nopts) {
  nirValidationPolicy();
  LLVMContext Ctx;                        // one context per compile: no state shared between calls
  AirFrontendResult R;
  MemoryBufferRef mref(StringRef((const char *)bitcode, size), "air");
  auto modOr = parseBitcodeFile(mref, Ctx);
  if (!modOr) die("bitcode parse failed: " + toString(modOr.takeError()));
  std::unique_ptr<Module> MOwn = std::move(*modOr);
  Module *M = MOwn.get();

  AirEntry E = findEntry(M, o0);
  Function *F = E.F; mesa_shader_stage stage = E.stage; const MDNode *ins = E.ins, *outsMd = E.outs;
  R.function = F->getName().str(); R.stage = stage; R.triple = M->getTargetTriple().str();

  // Metadata first (the specialiser may delete the globals it references).
  std::vector<ArgInfo> inArgs, outArgs;
  for (unsigned i = 0; outsMd && i < outsMd->getNumOperands(); i++) outArgs.push_back(parseArg(cast<MDNode>(outsMd->getOperand(i)), true));
  for (unsigned i = 0; ins && i < ins->getNumOperands(); i++) inArgs.push_back(parseArg(cast<MDNode>(ins->getOperand(i)), false));
  for (auto &a : inArgs) {
    if (a.argno < 0 || (unsigned)a.argno >= F->arg_size()) die("input argument index out of range");
    if (a.kind == "air.buffer") {
      auto *PT = dyn_cast<PointerType>(F->getArg(a.argno)->getType());
      if (!PT) die("buffer argument is not a pointer");
      int actual = (int)PT->getAddressSpace();
      if (a.addrspace >= 0 && a.addrspace != actual) die("buffer address-space metadata disagrees with pointer type");
      a.addrspace = actual;
    }
    if (a.kind == "air.imageblock")
      die("input kind air.imageblock (imageblocks/tile memory are Apple-family-4+ features; not in ABI v5, COVERAGE.md 6.1)");
    if (a.kind == "air.visible_function_table" || a.kind == "air.indirect_buffer") die("input kind " + a.kind);
  }
  R.declared_textures = declaredTextures(inArgs);
  R.declared_ubo_max = declaredUboMax(inArgs);
  if (R.declared_ubo_max > uboSlots(o0) - 1)
    die("constant buffer(" + std::to_string(R.declared_ubo_max) + "): a8xx honours only UBO 0.." + std::to_string(uboSlots(o0) - 1) +
        " and constant buffer n is UBO n (ABI v6, BINDING-ABI.md 3.1)");
  R.driver_table_ubo = R.declared_ubo_max + 1;
  AirOptions o = o0;
  for (int i = 0; i < 16; i++) if (!(R.declared_textures & (1u << i))) o.texClass[i] = 0;

  // Function constants: by index and by name.
  std::vector<FcDecl> decls = parseFcDecls(*M);
  std::map<int, std::vector<double>> fc;
  R.fcs = resolveFcs(decls, o, R.function, fc);
  SpecResult spec = specialize_and_inline(*M, F, decls, fc);
  if (getenv("AIR2IR3_DUMP_LL")) { std::error_code ec; raw_fd_ostream os(getenv("AIR2IR3_DUMP_LL"), ec); M->print(os, nullptr); }

  glsl_type_singleton_init_or_ref();
  std::unique_ptr<Translator> T(new Translator(*M, F, stage, R, spec));
  T->inArgs = inArgs; T->outArgs = outArgs; T->opt = &o;
  for (int i = 0; i < 16; i++) if (o.texClass[i]) Translator::checkFormatClass(o.texClass[i], "texture(" + std::to_string(i) + ")");
  try { R.nir = T->run(nopts); }
  catch (...) { if (T->s) ralloc_free(T->s); glsl_type_singleton_decref(); throw; }
  glsl_type_singleton_decref();
  // discard_fragment -> demote
  nir_foreach_function_impl(impl, R.nir) nir_foreach_block(blk, impl) nir_foreach_instr(ins2, blk)
    if (ins2->type == nir_instr_type_intrinsic && nir_instr_as_intrinsic(ins2)->intrinsic == nir_intrinsic_demote) R.uses_discard = true;
  std::string impl;
  if (M->getGlobalVariable("llvm.global_ctors") || !spec.implicitVals.empty())
    impl += std::string("  static initialiser evaluated: ") + (spec.ctorEvaluated ? "yes" : "no") + "\n";
  for (auto &kv : spec.implicitVals) impl += "  implicit " + kv.first + " = " + std::to_string(kv.second) + "\n";
  if (spec.taintedPredicates) impl += "  unset function constants: " + std::to_string(spec.taintedPredicates) + " predicate(s) forced false (Metal semantics)\n";
  if (spec.unsetMarkers)
    impl += "  unset function constants in the body: " + std::to_string(spec.unsetMarkers) + " load(s), " + std::to_string(spec.unsetIndependent) +
            " use(s) independent of the value (folded); nothing decided by them\n";
  R.report = impl + T->report;
  return R;
}

static std::string fcValueJson(const AirFc &f);
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
    a += "{\"index\":" + std::to_string(f.index) + ",\"name\":\"" + jesc(f.name) + "\",\"type\":\"" + jesc(f.type) +
         "\",\"defined\":" + (f.defined ? "true" : "false") + "," + fcValueJson(f) + "}";
  }
  kv("function_constants", a + "]", false);
  a = "[";
  for (auto &b : r.bindings) {
    if (a.size() > 1) a += ",";
    a += "{\"kind\":\"" + b.kind + "\",\"metal_index\":" + std::to_string(b.metal_index) + ",\"slot\":" + std::to_string(b.slot);
    if (!b.arg_name.empty()) a += ",\"arg\":\"" + jesc(b.arg_name) + "\"";
    if (!b.type_name.empty()) a += ",\"type\":\"" + jesc(b.type_name) + "\"";
    if (!b.access.empty()) a += ",\"access\":\"" + b.access + "\"";
    if (b.kind == "ubo" && b.minimum_bytes >= 0) a += ",\"minimum_bytes\":" + std::to_string(b.minimum_bytes);
    a += std::string(",\"present\":") + (b.present ? "true" : "false");
    a += std::string(",\"used\":") + (b.used ? "true" : "false");
    if (b.kind == "fb_fetch") a += ",\"bindless_set\":" + std::to_string(ABI_FS_BINDLESS_SET);
    if (b.kind == "device_buffer" || b.kind == "threadgroup_buffer") a += ",\"driver_table_ubo\":" + std::to_string(r.driver_table_ubo);
    if (b.kind == "constexpr_sampler") {
      char buf[512]; air_sampler as; air_sampler_decode(b.sampler_word, &as); char dec[640]; air_sampler_json(&as, dec, sizeof dec);
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
  auto blendJ = [](const AirBlend &x) {
    char bb[200]; snprintf(bb, sizeof bb, "{\"enabled\":%s,\"rgb_op\":%u,\"alpha_op\":%u,\"src_rgb\":%u,\"dst_rgb\":%u,\"src_alpha\":%u,\"dst_alpha\":%u}",
                           x.enabled ? "true" : "false", x.rgbOp, x.alphaOp, x.srcRGB, x.dstRGB, x.srcA, x.dstA);
    return std::string(bb);
  };
  a = "[";
  for (auto &l : r.rt_lowering) {
    if (a.size() > 1) a += ",";
    a += "{\"index\":" + std::to_string(l.index) + ",\"class\":" + std::to_string(l.cls) + ",\"class_name\":\"" + air_format_class_name(l.cls) +
         "\",\"view_format\":\"" + (l.cls == AIR_FMT_XR10_BGR32 ? "B10G10R10A2_UNORM" : "R16G16B16A16_UNORM, components stored B,G,R,A") +
         "\",\"api_blend\":" + blendJ(l.api) + ",\"hw_blend\":" + blendJ(l.hw) + ",\"dual_source\":" + (l.dual_source ? "true" : "false") +
         ",\"blend_in_shader\":" + (l.blend_in_shader ? "true" : "false") +
         ",\"hw_write_mask_clear\":\"" + (l.clear_alpha_write ? "A" : "") + "\"}";
  }
  kv("rt_lowering", a + "]", false);
  a = "{";
  for (int t = 0; t < 16; t++) if (r.tex_class[t]) { if (a.size() > 1) a += ","; a += "\"" + std::to_string(t) + "\":" + std::to_string(r.tex_class[t]); }
  kv("texture_classes", a + "}", false);
  a = "["; for (auto &s : r.sysvals) { if (a.size() > 1) a += ","; a += "\"" + s + "\""; } kv("system_values", a + "]", false);
  kv("writes_depth", r.writes_depth ? "true" : "false", false);
  kv("writes_point_size", r.writes_point_size ? "true" : "false", false);
  kv("uses_discard", r.uses_discard ? "true" : "false", false);
  kv("uses_fb_fetch", r.uses_fb_fetch ? "true" : "false", false);
  kv("constant_data_bytes", std::to_string(r.constant_data_bytes), false);
  kv("threadgroup_bytes", std::to_string(r.shared_bytes), false);
  a = "["; for (int x : r.requires_no_attachment) { if (a.size() > 1) a += ","; a += std::to_string(x); } kv("requires_no_attachment", a + "]", false);
  a = "["; for (auto &w : r.warnings) { if (a.size() > 1) a += ","; a += "\"" + jesc(w) + "\""; } kv("warnings", a + "]", false);
  return j + "}";
}

// ============================================================== library (air2ir3_api.h) ==
struct air2ir3_compiler {
  uint64_t chip = 0;
  fd_dev_id id = {};
  ir3_compiler *c = nullptr;
};

static std::string hexs(const uint8_t *d, size_t n) {
  static const char *h = "0123456789abcdef"; std::string o;
  for (size_t i = 0; i < n; i++) { o += h[d[i] >> 4]; o += h[d[i] & 15]; }
  return o;
}
static std::array<uint8_t, 32> sha256(const void *d, size_t n) {
  SHA256 h; h.update(ArrayRef<uint8_t>((const uint8_t *)d, n)); return h.final();
}
static char *dupstr(const std::string &s) { char *p = (char *)malloc(s.size() + 1); memcpy(p, s.c_str(), s.size() + 1); return p; }

// MTLDataType numbers (Metal/MTLArgument.h); same table as tools/cachekey.py
static int mtlDataType(const std::string &t) {
  static const std::map<std::string, int> m = {
    {"float", 3}, {"float2", 4}, {"float3", 5}, {"float4", 6}, {"half", 16}, {"half2", 17}, {"half3", 18}, {"half4", 19},
    {"int", 29}, {"int2", 30}, {"int3", 31}, {"int4", 32}, {"uint", 33}, {"uint2", 34}, {"uint3", 35}, {"uint4", 36},
    {"short", 37}, {"short2", 38}, {"short3", 39}, {"short4", 40}, {"ushort", 41}, {"ushort2", 42}, {"ushort3", 43}, {"ushort4", 44},
    {"char", 45}, {"char2", 46}, {"char3", 47}, {"char4", 48}, {"uchar", 49}, {"uchar2", 50}, {"uchar3", 51}, {"uchar4", 52},
    {"bool", 53}, {"bool2", 54}, {"bool3", 55}, {"bool4", 56}, {"long", 81}, {"ulong", 85}};
  auto it = m.find(t);
  if (it == m.end()) die("function-constant type " + t + " has no MTLDataType in the key table");
  return it->second;
}
// Key bytes of a function-constant value (CACHE-FORMAT.md 2): each component in its declared type,
// little-endian, from the canonical value (fcCanon): integers of their width, bool one byte 0/1,
// float / half their IEEE bit pattern (NaN, inf and -0 included).
static void fcBytes(const std::string &t, const std::vector<double> &vals0, std::string &out) {
  unsigned n = 1; std::string base = fcScalarBase(t, n);
  std::vector<double> vals = fcCanon(t, vals0);
  for (unsigned i = 0; i < n; i++) {
    double v = vals[i];
    auto put = [&](const void *p, size_t k) { out.append((const char *)p, k); };
    uint64_t u = base == "float" || base == "half" ? 0 : fcIntBits(v);
    if (base == "bool" || base == "uchar" || base == "char") { uint8_t x = (uint8_t)u; put(&x, 1); }
    else if (base == "ushort" || base == "short") { uint16_t x = (uint16_t)u; put(&x, 2); }
    else if (base == "uint" || base == "int") { uint32_t x = (uint32_t)u; put(&x, 4); }
    else if (base == "ulong" || base == "long") { put(&u, 8); }
    else if (base == "float") { float x = (float)v; put(&x, 4); }
    else if (base == "half") { _Float16 x = (_Float16)v; put(&x, 2); }
  }
}
// The sidecar's value of a function constant (reflection.function_constants[].value, cache format 5):
// valid JSON that holds the value exactly in its declared type.  Integers and bool are JSON integers
// (64-bit exact); float / half are the shortest decimal that reads back to the same float / half,
// always with a '.' or an exponent ("-0.0" for negative zero), and the strings "nan", "-nan", "inf",
// "-inf" where JSON has no number.  float / half constants also carry "bits": the IEEE bit pattern of
// each component ("0x7fc00000"), from which a reader rebuilds the key bytes (tools/cachekey.py).
static std::string fcValueJson(const AirFc &f) {
  unsigned n = 1; std::string base = fcScalarBase(f.type, n);
  bool fp = base == "float" || base == "half";
  std::string v = "[", bits = "[";
  for (double x : f.value) {
    if (v.size() > 1) { v += ","; bits += ","; }
    char b[64];
    if (!fp) {
      if (base == "ulong" || base == "uint" || base == "ushort" || base == "uchar" || base == "bool") snprintf(b, sizeof b, "%llu", (unsigned long long)fcIntBits(x));
      else snprintf(b, sizeof b, "%lld", (long long)(int64_t)fcIntBits(x));
      v += b; continue;
    }
    if (std::isnan(x)) v += std::signbit(x) ? "\"-nan\"" : "\"nan\"";
    else if (std::isinf(x)) v += x < 0 ? "\"-inf\"" : "\"inf\"";
    else if (x == 0) v += std::signbit(x) ? "-0.0" : "0.0";
    else {
      // the shortest decimal that reads back as the same float (a half's value is a float value, so a
      // half prints as the float it is: 65504.0, 0.099975586 for half(0.1))
      for (int prec = 1; prec <= 17; prec++) {
        snprintf(b, sizeof b, "%.*g", prec, x);
        if ((float)strtod(b, nullptr) == (float)x) break;
      }
      std::string s = b;
      if (s.find_first_of(".en") == std::string::npos) s += ".0";
      v += s;
    }
    if (base == "float") { float y = (float)x; uint32_t u; memcpy(&u, &y, 4); snprintf(b, sizeof b, "\"0x%08x\"", u); }
    else { _Float16 y = (_Float16)x; uint16_t u; memcpy(&u, &y, 2); snprintf(b, sizeof b, "\"0x%04x\"", u); }
    bits += b;
  }
  return "\"value\":" + v + "]" + (fp ? ",\"bits\":" + bits + "]" : std::string());
}
static void u32le(std::string &m, uint32_t v) { m.append((const char *)&v, 4); }
static void u16le(std::string &m, uint16_t v) { m.append((const char *)&v, 2); }

struct KeyInputs {
  std::array<uint8_t, 32> air_hash;
  unsigned stage = 0;                 // 1 vertex, 2 fragment, 3 kernel
  std::string entry;
  std::vector<AirFc> fcs;
  uint8_t rtClass[8] = {0};
  AirBlend blend[8];
  uint8_t texClass[16] = {0};         // masked to the declared texture(n) arguments
  bool safeConstlen = false;
};
// CACHE-FORMAT.md section 2 (key format 3); tools/cachekey.py is the reference implementation.
// Format 3 vs 2: + u8 safe_constlen (ir3 key bit, BINDING-ABI.md 5.2); texture classes masked to the
// declared texture(n) arguments; the raster sample count is no longer key material (no stage of the
// compile reads it: ir3's key.msaa exists only below a6xx, and the front end ignores it).
static std::string keyMaterial(uint64_t chip, const KeyInputs &k) {
  std::string m("AIR2IR3-CACHE-KEY\0", 18);
  u32le(m, CACHE_FORMAT_VERSION); u32le(m, ABI_VERSION); u32le(m, (uint32_t)chip);
  m.append((const char *)k.air_hash.data(), 32);
  u32le(m, k.stage);
  u32le(m, (uint32_t)k.entry.size()); m += k.entry;
  std::vector<AirFc> f = k.fcs;
  std::sort(f.begin(), f.end(), [](const AirFc &a, const AirFc &b) { return a.index < b.index; });
  u32le(m, (uint32_t)f.size());
  for (auto &x : f) {
    std::string vb; if (x.defined) fcBytes(x.type, x.value, vb);
    u16le(m, (uint16_t)x.index); u16le(m, (uint16_t)mtlDataType(x.type));
    m += (char)(x.defined ? 1 : 0); m += (char)0; u16le(m, (uint16_t)vb.size()); m += vb;
  }
  bool frag = k.stage == 2;
  u32le(m, 8);
  for (int i = 0; i < 8; i++) m += (char)(frag ? k.rtClass[i] : 0);
  for (int i = 0; i < 8; i++) {
    if (!frag || !k.rtClass[i]) continue;
    const AirBlend &b = k.blend[i];
    uint8_t r[7] = {(uint8_t)(b.enabled ? 1 : 0), 0, 0, 0, 0, 0, 0};
    if (b.enabled) { r[1] = b.rgbOp; r[2] = b.alphaOp; r[3] = b.srcRGB; r[4] = b.dstRGB; r[5] = b.srcA; r[6] = b.dstA; }
    m.append((const char *)r, 7);
  }
  u32le(m, 16);
  for (int i = 0; i < 16; i++) m += (char)k.texClass[i];
  m += (char)(k.safeConstlen ? 1 : 0);
  return m;
}
static std::string keyInputsJson(const KeyInputs &k) {
  bool frag = k.stage == 2;
  std::string ki = "{\"air_hash\":\"" + hexs(k.air_hash.data(), 32) + "\",\"stage\":\"" + (k.stage == 1 ? "vertex" : k.stage == 2 ? "fragment" : "kernel") +
                   "\",\"entry\":\"" + jesc(k.entry) + "\",\"rt_classes\":[";
  for (int i = 0; i < 8; i++) ki += std::string(i ? "," : "") + std::to_string(frag ? k.rtClass[i] : 0);
  ki += "],\"blend\":{";
  bool first = true;
  for (int i = 0; i < 8; i++) {
    if (!frag || !k.rtClass[i]) continue;
    const AirBlend &b = k.blend[i];
    char bb[200];
    snprintf(bb, sizeof bb, "%s\"%d\":{\"enabled\":%s,\"rgb_op\":%u,\"alpha_op\":%u,\"src_rgb\":%u,\"dst_rgb\":%u,\"src_alpha\":%u,\"dst_alpha\":%u}",
             first ? "" : ",", i, b.enabled ? "true" : "false", b.enabled ? b.rgbOp : 0, b.enabled ? b.alphaOp : 0, b.enabled ? b.srcRGB : 0,
             b.enabled ? b.dstRGB : 0, b.enabled ? b.srcA : 0, b.enabled ? b.dstA : 0);
    ki += bb; first = false;
  }
  ki += "},\"texture_classes\":[";
  for (int i = 0; i < 16; i++) ki += std::string(i ? "," : "") + std::to_string(k.texClass[i]);
  ki += std::string("],\"safe_constlen\":") + (k.safeConstlen ? "true" : "false") + "}";
  return ki;
}
static KeyInputs keyInputsOf(const void *air, size_t airSize, const AirOptions &o, const std::string &entry, mesa_shader_stage stage,
                             const std::vector<AirFc> &fcs, uint16_t declaredTex) {
  KeyInputs k;
  k.air_hash = sha256(air, airSize);
  k.stage = stage == MESA_SHADER_VERTEX ? 1 : stage == MESA_SHADER_FRAGMENT ? 2 : 3;
  k.entry = entry; k.fcs = fcs;
  for (int i = 0; i < 8; i++) { k.rtClass[i] = o.rtClass[i]; k.blend[i] = o.blend[i]; }
  for (int i = 0; i < 16; i++) k.texClass[i] = (declaredTex >> i) & 1 ? o.texClass[i] : 0;
  k.safeConstlen = o.safeConstlen;
  return k;
}
// The key without compiling: parse the module's metadata only (entry, function-constant
// declarations, texture arguments).  air2ir3_cache_key(); the same KeyInputs compile_internal builds.
static std::string keyOnly(uint64_t chip, const void *air, size_t airSize, const AirOptions &o) {
  LLVMContext Ctx;
  MemoryBufferRef mref(StringRef((const char *)air, airSize), "air");
  auto modOr = parseBitcodeFile(mref, Ctx);
  if (!modOr) die("bitcode parse failed: " + toString(modOr.takeError()));
  std::unique_ptr<Module> M = std::move(*modOr);
  AirEntry E = findEntry(M.get(), o);
  std::vector<ArgInfo> inArgs;
  for (unsigned i = 0; E.ins && i < E.ins->getNumOperands(); i++) inArgs.push_back(parseArg(cast<MDNode>(E.ins->getOperand(i)), false));
  std::map<int, std::vector<double>> fc;
  std::vector<AirFc> fcs = resolveFcs(parseFcDecls(*M), o, E.F->getName().str(), fc);
  KeyInputs k = keyInputsOf(air, airSize, o, E.F->getName().str(), E.stage, fcs, declaredTextures(inArgs));
  std::string km = keyMaterial(chip, k);
  auto kd = sha256(km.data(), km.size());
  return hexs(kd.data(), 32);
}

// The function constants a function declares, without compiling (CLI --list-fcs).  ABI v4 refuses
// a variant whose unset constants decide something, so tools can no longer learn the declarations
// from a compile with nothing set.
static std::string fcListJson(const void *air, size_t airSize, const AirOptions &o) {
  LLVMContext Ctx;
  MemoryBufferRef mref(StringRef((const char *)air, airSize), "air");
  auto modOr = parseBitcodeFile(mref, Ctx);
  if (!modOr) die("bitcode parse failed: " + toString(modOr.takeError()));
  std::unique_ptr<Module> M = std::move(*modOr);
  AirEntry E = findEntry(M.get(), o);
  std::string j = "{\"function\":\"" + jesc(E.F->getName().str()) + "\",\"function_constants\":[";
  bool first = true;
  for (auto &d : parseFcDecls(*M)) {
    j += std::string(first ? "" : ",") + "{\"index\":" + std::to_string(d.index) + ",\"name\":\"" + jesc(d.name) + "\",\"type\":\"" + jesc(d.type) + "\"}";
    first = false;
  }
  return j + "]}";
}

struct CompileOut {
  std::string blob, sidecar, key, stats_line, disasm, report, nir_before, nir_after, function;
  std::string machine_code, program_json;
  mesa_shader_stage stage = MESA_SHADER_NONE;
};

static std::string driverUboJson(const ir3_shader_variant *v, mesa_shader_stage stage, std::string &constDp, int maxUbo) {
  const struct ir3_const_state *cs = ir3_const_state(v);
  auto chk = [&](int idx, const char *what) {
    if (idx > maxUbo) die(std::string(what) + " landed at UBO " + std::to_string(idx) + ", beyond the ABI v6 limit " + std::to_string(maxUbo) + " (a8xx honours UBO 0..15)");
  };
  if (cs->primitive_map_ubo.idx >= 0 || cs->primitive_param_ubo.idx >= 0)
    die("ir3 allocated a primitive map/param driver UBO (geometry/tessellation): not in ABI v5");
  if (cs->driver_params_ubo.idx >= 0 && stage != MESA_SHADER_FRAGMENT && stage != MESA_SHADER_VERTEX && stage != MESA_SHADER_COMPUTE)
    die("ir3 allocated a driver-params UBO for a stage without a driver-param layout in ABI v5");
  std::string j = "[";
  if (cs->consts_ubo.idx >= 0) {
    chk(cs->consts_ubo.idx, "the constant-data UBO");
    j += "{\"kind\":\"constant_data\",\"ubo\":" + std::to_string(cs->consts_ubo.idx) + ",\"size_vec4\":" + std::to_string((v->constant_data_size + 15) / 16) +
         ",\"address\":\"code_iova + constant_data_offset\",\"constant_data_offset\":" + std::to_string(v->info.constant_data_offset) + "}";
  }
  if (cs->driver_params_ubo.idx >= 0) {
    // a8xx loads driver params through the preamble from this UBO (load_shader_consts_via_preamble);
    // the command stream fills Mesa's struct for the stage, as Turnip tu_emit_compute_driver_params /
    // freedreno fd6 emit_driver_params do (BINDING-ABI.md 3.9).
    chk(cs->driver_params_ubo.idx, "the driver-params UBO");
    const char *st = stage == MESA_SHADER_VERTEX ? "ir3_driver_params_vs" : stage == MESA_SHADER_COMPUTE ? "ir3_driver_params_cs" : "ir3_driver_params_fs";
    if (j.size() > 1) j += ",";
    j += std::string("{\"kind\":\"driver_params\",\"struct\":\"") + st + "\",\"ubo\":" + std::to_string(cs->driver_params_ubo.idx) +
         ",\"size_dwords\":" + std::to_string(cs->driver_params_ubo.size) + ",\"subgroup_size\":" + std::to_string(v->info.subgroup_size) + "}";
  }
  j += "]";
  const auto &dp = cs->allocs.consts[IR3_CONST_ALLOC_DRIVER_PARAMS];
  constDp = "null";
  if (cs->num_driver_params > 0 || dp.size_vec4 > 0) {
    const char *st = stage == MESA_SHADER_VERTEX ? "ir3_driver_params_vs" : stage == MESA_SHADER_COMPUTE ? "ir3_driver_params_cs"
                   : stage == MESA_SHADER_FRAGMENT ? "ir3_driver_params_fs" : nullptr;
    if (!st) die("driver params for this stage are not in ABI v5");
    constDp = std::string("{\"struct\":\"") + st + "\",\"offset_vec4\":" + std::to_string(dp.offset_vec4) + ",\"size_vec4\":" + std::to_string(dp.size_vec4) +
              ",\"num_driver_params\":" + std::to_string(cs->num_driver_params) + "}";
  }
  return j;
}

// Item 9 (A16 Stage 3 run 3): the facts ir3 derives from shader_info must be gathered before ir3
// sees the shader, as Turnip (tu_shader.cc: nir_shader_gather_info after tu_lower_io, then
// ir3_finalize_nir) and gallium freedreno (the GL linker) do.  Without it SkyLight
// SimpleTextureFragment reported num_samp 0 (SP_PS_CONFIG NTEX/NSAMP) and need_pixlod 0
// (RB_PS_CNTL PIXLODENABLE) although it samples T#0 with S#0 and implicit derivatives.
static void gatherInfo(nir_shader *nir) {
  // The front end declares no sampler/image variables (Metal resources are bound by index), so the
  // counts gather_info would rebuild from variables (0) are the front end's.
  unsigned nt = nir->info.num_textures, ni = nir->info.num_images;
  nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
  nir->info.num_textures = nt; nir->info.num_images = ni;
  // textures_used: ir3 sets num_samp = BITSET_LAST_BIT(textures_used) (ir3_compiler_nir.c), which
  // the command stream programs as NTEX and NSAMP.  A Metal T# and S# are independent indices, so
  // both count (Turnip sets the bits per descriptor in tu_lower_io; gallium's GL samplers are combined).
  BITSET_ZERO(nir->info.textures_used); BITSET_ZERO(nir->info.textures_used_by_txf); BITSET_ZERO(nir->info.samplers_used);
  nir_foreach_function_impl(impl, nir) nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
    if (ins->type != nir_instr_type_tex) continue;
    nir_tex_instr *t = nir_instr_as_tex(ins);
    if (nir_tex_instr_src_index(t, nir_tex_src_texture_handle) < 0 && nir_tex_instr_src_index(t, nir_tex_src_texture_offset) < 0) {
      BITSET_SET(nir->info.textures_used, t->texture_index);
      if (t->op == nir_texop_txf || t->op == nir_texop_txf_ms) BITSET_SET(nir->info.textures_used_by_txf, t->texture_index);
    }
    if (nir_tex_instr_need_sampler(t) && nir_tex_instr_src_index(t, nir_tex_src_sampler_handle) < 0 &&
        nir_tex_instr_src_index(t, nir_tex_src_sampler_offset) < 0) {
      BITSET_SET(nir->info.textures_used, t->sampler_index);
      BITSET_SET(nir->info.samplers_used, t->sampler_index);
    }
  }
}

// ABI v4 descriptor counts (BINDING-ABI.md 3.4, verify3 item 3).  ir3's num_samp is one number for
// both NTEX and NSAMP (BITSET_LAST_BIT(textures_used), where gatherInfo sets every T# and S#), and it
// adds one per framebuffer read even though that read uses the bindless descriptor of 3.6.  The
// command stream programs NTEX and NSAMP separately from these counts instead: 1 + the highest
// non-bindless T# (texture_index) and 1 + the highest S# (sampler_index) a texture instruction
// names, taken from the NIR ir3 compiles (before ir3 adds its own framebuffer-read instructions).
// ABI v5 (verify4 item 4): EVERY texture instruction counts for NSAMP, including the ones that do
// not sample (isam for read(), getsize, getinfo): ir3 encodes an s# in each of them (the
// sampler_index, get_tex_samp_tex_src), and Turnip / freedreno program NSAMP = num_samp >= 1 + that
// s#.  ABI v4 skipped them (nir_tex_instr_need_sampler), so a read()-only function reported NSAMP 0
// while its isam named s#0.  The S# slots below NSAMP that no API or constexpr sampler fills hold
// the driver's default sampler descriptor (BINDING-ABI.md 3.4).
struct DescCounts { int ntex = 0, nsamp = 0; };
static DescCounts descriptorCounts(nir_shader *nir) {
  DescCounts d;
  nir_foreach_function_impl(impl, nir) nir_foreach_block(blk, impl) nir_foreach_instr(ins, blk) {
    if (ins->type == nir_instr_type_tex) {
      nir_tex_instr *t = nir_instr_as_tex(ins);
      if (nir_tex_instr_src_index(t, nir_tex_src_texture_handle) >= 0 || nir_tex_instr_src_index(t, nir_tex_src_texture_offset) >= 0)
        die("internal: bindless or indirect texture instruction in the front end's NIR (not in ABI v5)");
      d.ntex = std::max(d.ntex, (int)t->texture_index + 1);
      d.nsamp = std::max(d.nsamp, (int)t->sampler_index + 1);             // every cat5 carries an s# (ABI v5)
    }
    if (ins->type == nir_instr_type_intrinsic) {
      nir_intrinsic_instr *ii = nir_instr_as_intrinsic(ins);
      // image loads through the texture path would take T#/S# slots after the textures (ir3_image_to_tex)
      if (ii->intrinsic == nir_intrinsic_image_load || ii->intrinsic == nir_intrinsic_image_sparse_load)
        die("image load (texture read through an image): not in ABI v5");
    }
  }
  return d;
}
// ABI v4 per-sample shading (BINDING-ABI.md 4.6, verify3 item 4).  The code does not depend on the
// raster sample count, but on a multisampled pipeline the fragment shader must run per sample when
// it reads the sample id or a sample-interpolated varying, or reads a colour attachment (framebuffer
// fetch, which includes the XR blending of 4.5: ir3 reads the attachment at load_sample_id).  Metal
// runs such functions per sample (tests/fixtures/msaa_probe.swift on the M3 Max: [[color(0)]] input
// -> per sample, a plain function -> per pixel).  ir3's own sample_shading flag comes from
// shader_info.fs.uses_sample_shading, which only API front ends set, so it misses all of these.
struct SampleShading { bool perSample = false; std::vector<std::string> reasons; };
static SampleShading sampleShading(nir_shader *nir, const AirFrontendResult &R) {
  SampleShading ss;
  if (nir->info.stage != MESA_SHADER_FRAGMENT) return ss;
  auto add = [&](const char *r) { ss.reasons.push_back(r); ss.perSample = true; };
  if (BITSET_TEST(nir->info.system_values_read, SYSTEM_VALUE_SAMPLE_ID)) add("sample_id");
  if (BITSET_TEST(nir->info.system_values_read, SYSTEM_VALUE_SAMPLE_POS) || BITSET_TEST(nir->info.system_values_read, SYSTEM_VALUE_SAMPLE_POS_OR_CENTER))
    add("sample_position");
  bool sampleVarying = nir->info.fs.uses_sample_qualifier;
  for (auto &v : R.varyings) if (v.sampling == "sample") sampleVarying = true;
  if (sampleVarying) add("sample_interpolation");
  bool xrShader = false;
  for (auto &l : R.rt_lowering) if (l.blend_in_shader) xrShader = true;
  bool appFetch = false;
  for (auto &b : R.bindings) if (b.kind == "fb_fetch" && b.arg_name != "(xr blend: destination)") appFetch = true;
  if (appFetch) add("framebuffer_fetch");
  if (xrShader) add("xr_shader_blend");
  if (!ss.perSample && (nir->info.fs.uses_fbfetch_output || R.uses_fb_fetch)) add("framebuffer_fetch");
  return ss;
}

// ABI v3 private memory (BINDING-ABI.md 3.10).  The command stream sizes one device-wide per-fiber
// pvtmem BO the way Turnip's tu_setup_pvtmem does: per_fiber = next_pow2(align(pvtmem_size, 512)),
// per_sp = align(per_fiber * fibers_per_sp, 4 KiB), total = num_sp_cores * per_sp.  X2-90:
// fibers_per_sp 4096, num_sp_cores 8.  A variant whose total exceeds the budget is refused.
// Budget 512 MiB = 16 KiB per fiber: every WindowServer variant fits (the worst, a Shadow*Blur
// with radius >= 612 and an inner rim, spills 11,264 bytes per fiber -> 16 KiB -> 512 MiB); the
// BO is allocated lazily and grown in powers of two, so it costs memory only once such a pipeline
// exists.  Measured distribution: COVERAGE.md 3.4.
static const uint64_t ABI_PVTMEM_BUDGET = 512ull << 20;

#include "ir3_program_export.h"

// The whole compile: AIR -> NIR -> ir3 variant, blob, sidecar and key.  Throws AirError.
static CompileOut compile_internal(air2ir3_compiler *C, const void *air, size_t airSize, const AirOptions &o,
                                   bool wantText, bool emitNir, bool dumpNir, bool wantProgram = false) {
  CompileOut out;
  AirFrontendResult R = air_frontend_mem(air, airSize, o, ir3_get_compiler_options(C->c));
  nir_shader *nir = R.nir;
  mesa_shader_stage stage = R.stage;
  out.function = R.function; out.stage = stage; out.report = R.report;
  if (emitNir) { char *t = nullptr; size_t n = 0; FILE *f = open_memstream(&t, &n); nir_print_shader(nir, f); fclose(f); out.nir_before = t; free(t); }
  nir_assign_io_var_locations(nir, nir_var_shader_in);
  nir_assign_io_var_locations(nir, nir_var_shader_out);
  if (stage == MESA_SHADER_COMPUTE) {
    nir_lower_compute_system_values_options csv = {};
    csv.has_base_workgroup_id = false;
    NIR_PASS(_, nir, nir_lower_compute_system_values, &csv);
  }
  ir3_nir_lower_io_vars_to_temporaries(nir);
  ir3_nir_lower_io(nir);
  gatherInfo(nir);
  DescCounts dc = descriptorCounts(nir);
  SampleShading ss = sampleShading(nir, R);
  unsigned driverUboBase = nir->info.num_ubos;
  ir3_shader_nir_options nopts = {};
  ir3_finalize_nir(C->c, &nopts, nir);
  if (dumpNir) { char *t = nullptr; size_t n = 0; FILE *f = open_memstream(&t, &n); nir_print_shader(nir, f); fclose(f); out.nir_after = t; free(t); }

  ir3_shader_options sopts = {};
  sopts.api_wavesize = IR3_SINGLE_OR_DOUBLE; sopts.real_wavesize = IR3_SINGLE_OR_DOUBLE;
  ir3_shader *shader = ir3_shader_from_nir(C->c, nir, &sopts);
  struct Guard { ir3_shader *s; ~Guard() { ir3_shader_destroy(s); } } guard{shader};
  ir3_shader_key key = {};
  key.safe_constlen = o.safeConstlen;
  // Disassembly (and the NIR text kept for it) only when a caller prints it: the C API never returns it, and
  // writing it was about a tenth of a large fragment compile (docs/SHADER-COMPILE-PATH-20260928.md section 7).
  ir3_shader_variant *v = ir3_shader_create_variant(shader, &key, wantText);
  if (!v || !v->bin) die("ir3 compile failed");
  const struct ir3_const_state *cs = ir3_const_state(v);
  // ir3's num_samp = max(T#, S#) + 1, plus one per framebuffer-read instruction (bindless, 3.6):
  // anything else would mean a T#/S# the counts above do not cover.
  if (v->num_samp < std::max(dc.ntex, dc.nsamp) || (!v->fb_read && v->num_samp != std::max(dc.ntex, dc.nsamp)))
    die("internal: ir3 num_samp " + std::to_string(v->num_samp) + " not explained by NTEX " + std::to_string(dc.ntex) + " / NSAMP " + std::to_string(dc.nsamp));
  int maxUbo = o.testMaxUboIndex >= 0 ? o.testMaxUboIndex : uboSlots(o) - 1;
  std::string constDp, dubos = driverUboJson(v, stage, constDp, maxUbo);
  // Highest UBO descriptor index the variant needs: the app's constant buffers (read by the
  // preamble even when pushed to consts), the driver table and ir3's driver UBOs.  (ir3's
  // const_state->num_ubos only counts UBOs still read by the main shader after the push.)
  int maxUboIdx = std::max(cs->consts_ubo.idx, cs->driver_params_ubo.idx);
  bool usesDriverTable = false;
  for (auto &bd : R.bindings) {
    if ((bd.kind == "device_buffer" || bd.kind == "threadgroup_buffer") && bd.used) usesDriverTable = true;
    if (bd.kind == "ubo" && bd.used) maxUboIdx = std::max(maxUboIdx, bd.slot);
    if ((bd.kind == "device_buffer" || bd.kind == "threadgroup_buffer") && bd.used) maxUboIdx = std::max(maxUboIdx, R.driver_table_ubo);
  }
  // Const budget (BINDING-ABI.md 5.2): Turnip builds a safe_constlen variant of every stage whose
  // constlen exceeds max_const_safe and swaps it in when ir3_trim_constlen says the pipeline's
  // stages do not fit max_const_pipeline together.
  bool exceedsSafe = ir3_exceeds_safe_constlen(v);
  if (o.safeConstlen && v->constlen > C->c->max_const_safe)
    die("safe_constlen variant still has constlen " + std::to_string(v->constlen) + " > max_const_safe " + std::to_string(C->c->max_const_safe));
  // Private memory (BINDING-ABI.md 3.10), including the binning variant as Turnip does.
  unsigned pvt = v->pvtmem_size; bool perWave = v->pvtmem_per_wave;
  if (v->binning) { pvt = std::max(pvt, v->binning->pvtmem_size); if (v->binning->pvtmem_size && !v->binning->pvtmem_per_wave) perWave = false; }
  if (!pvt) perWave = false;
  uint64_t perFiber = 0, perSp = 0, pvtTotal = 0;
  const struct fd_dev_info *di = C->c->info;
  if (pvt) {
    perFiber = 512; while (perFiber < pvt) perFiber <<= 1;              // util_next_power_of_two(align(pvt, 512))
    perSp = ((uint64_t)perFiber * di->fibers_per_sp + 4095) & ~4095ull;
    pvtTotal = (uint64_t)di->num_sp_cores * perSp;
  }
  uint64_t budget = o.testPvtmemBudgetMiB >= 0 ? (uint64_t)o.testPvtmemBudgetMiB << 20 : ABI_PVTMEM_BUDGET;
  if (pvtTotal > budget)
    die("private memory " + std::to_string(pvt) + " bytes per fiber needs a " + std::to_string(pvtTotal >> 20) + " MiB pvtmem BO, over the ABI v5 budget of " +
        std::to_string(budget >> 20) + " MiB (BINDING-ABI.md 3.10)");
  char stats[2000];
  snprintf(stats, sizeof stats,
           "{\"instrs\":%u,\"dwords\":%u,\"full_regs\":%d,\"half_regs\":%d,\"constlen\":%u,\"branchstack\":%u,"
           "\"nops\":%u,\"mov\":%u,\"cov\":%u,\"sstall\":%u,\"systall\":%u,\"ss\":%u,\"sy\":%u,\"loops\":%u,"
           "\"max_waves\":%d,\"double_threadsize\":%s,\"preamble_instrs\":%u,\"early_preamble\":%s,"
           "\"ubos_in_main\":%u,\"num_app_ubos\":%u,\"max_ubo_index\":%d,\"ubo_slots\":%d,\"driver_table_ubo\":%d,\"driver_ubo_base\":%u,\"consts_ubo\":%d,\"driver_params_ubo\":%d,\"num_driver_params\":%u,\"constant_data_offset\":%u,"
           "\"constant_data_size\":%u,\"shared_size\":%u,\"binning_variant\":%s,\"fb_read\":%s,\"bindless_tex\":%s,\"dual_src_blend\":%s,"
           "\"num_samp\":%d,\"ntex\":%d,\"nsamp\":%d,\"need_pixlod\":%s,\"need_full_quad\":%s,\"has_kill\":%s,\"pvtmem_size\":%u,\"pvtmem_per_wave\":%s,"
           "\"per_sample_shading_if_msaa\":%s}",
           v->info.instrs_count, v->info.size / 4, v->info.max_reg + 1, v->info.max_half_reg + 1, v->constlen, v->branchstack,
           v->info.nops_count, v->info.mov_count, v->info.cov_count, v->info.sstall, v->info.systall, v->info.ss, v->info.sy, v->info.loops,
           v->info.max_waves, v->info.double_threadsize ? "true" : "false", v->info.preamble_instrs_count, v->info.early_preamble ? "true" : "false",
           cs->num_ubos, cs->num_app_ubos, maxUboIdx, uboSlots(o), usesDriverTable ? R.driver_table_ubo : -1, driverUboBase, cs->consts_ubo.idx, cs->driver_params_ubo.idx, cs->num_driver_params, v->info.constant_data_offset,
           v->constant_data_size, v->shared_size, v->binning ? "true" : "false", v->fb_read ? "true" : "false", v->bindless_tex ? "true" : "false",
           v->dual_src_blend ? "true" : "false", v->num_samp, dc.ntex, dc.nsamp, v->need_pixlod ? "true" : "false", v->need_full_quad ? "true" : "false",
           v->has_kill ? "true" : "false", v->pvtmem_size, v->pvtmem_per_wave ? "true" : "false", ss.perSample ? "true" : "false");
  if (maxUboIdx > maxUbo) die("variant uses UBO index " + std::to_string(maxUboIdx) + ", beyond the ABI v6 limit " + std::to_string(maxUbo) + " (a8xx honours UBO 0..15)");
  char cb[400];
  snprintf(cb, sizeof cb, "{\"constlen\":%u,\"safe_constlen\":%s,\"exceeds_safe_constlen\":%s,\"max_const_safe\":%u,\"max_const_pipeline\":%u,\"max_const_stage\":%u}",
           v->constlen, o.safeConstlen ? "true" : "false", exceedsSafe ? "true" : "false", C->c->max_const_safe, C->c->max_const_pipeline,
           stage == MESA_SHADER_FRAGMENT ? C->c->max_const_frag : stage == MESA_SHADER_COMPUTE ? C->c->max_const_compute : C->c->max_const_geom);
  char pv[400];
  snprintf(pv, sizeof pv, "{\"pvtmem_size\":%u,\"pvtmem_per_wave\":%s,\"per_fiber_size\":%llu,\"per_sp_size\":%llu,\"total_size\":%llu,"
           "\"fibers_per_sp\":%u,\"num_sp_cores\":%u,\"budget\":%llu}",
           pvt, perWave ? "true" : "false", (unsigned long long)perFiber, (unsigned long long)perSp, (unsigned long long)pvtTotal,
           di->fibers_per_sp, di->num_sp_cores, (unsigned long long)ABI_PVTMEM_BUDGET);
  char line[300];
  snprintf(line, sizeof line, "   ir3: %u instructions, %u dwords, full regs %d, half regs %d, constlen %u, branchstack %u\n",
           v->info.instrs_count, v->info.size / 4, v->info.max_reg + 1, v->info.max_half_reg + 1, v->constlen, v->branchstack);
  out.stats_line = line;
  if (wantText) out.disasm = v->disasm_info.disasm ? v->disasm_info.disasm : "(no disasm)\n";

  struct blob blob; blob_init(&blob);
  ir3_store_variant(&blob, v);
  out.blob.assign((const char *)blob.data, blob.size); blob_finish(&blob);
  auto bh = sha256(out.blob.data(), out.blob.size());

  std::string inl = "[";
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

  KeyInputs k = keyInputsOf(air, airSize, o, R.function, stage, R.fcs, R.declared_textures);
  std::string km = keyMaterial(C->chip, k);
  auto kd = sha256(km.data(), km.size());
  out.key = hexs(kd.data(), 32);

  // Constant samplers (getConstantSamplersBitmasks): the bitmask and a set id over the samplers'
  // unique ids, CACHE-FORMAT.md 3.2.  In the library (verify2 item 4) so an online compile carries
  // the same sidecar as the cache entry.
  std::vector<const AirBinding *> csamp;
  for (auto &bd : R.bindings) if (bd.kind == "constexpr_sampler") csamp.push_back(&bd);
  std::sort(csamp.begin(), csamp.end(), [](const AirBinding *x, const AirBinding *y) { return x->slot < y->slot; });
  std::string sidm, csl = "[";
  for (auto *bd : csamp) {
    for (int i = 7; i >= 0; i--) sidm += (char)((bd->unique_id >> (8 * i)) & 0xff);
    sidm += (char)bd->slot;
    char bb[400]; air_sampler as; air_sampler_decode(bd->sampler_word, &as); char dec[640]; air_sampler_json(&as, dec, sizeof dec);
    snprintf(bb, sizeof bb, "{\"slot\":%d,\"unique_id\":\"0x%016llx\",\"air_word\":\"0x%016llx\",\"a8xx_tex_samp\":[\"0x%08x\",\"0x%08x\",\"0x%08x\",\"0x%08x\"],\"state\":",
             bd->slot, (unsigned long long)bd->unique_id, (unsigned long long)bd->sampler_word, bd->a8xx_desc[0], bd->a8xx_desc[1], bd->a8xx_desc[2], bd->a8xx_desc[3]);
    if (csl.size() > 1) csl += ",";
    csl += std::string(bb) + dec + "}";
  }
  csl += "]";
  auto sh = sha256(sidm.data(), sidm.size());
  char msk[16]; snprintf(msk, sizeof msk, "0x%04x", R.constexpr_sampler_mask);
  std::string csj = std::string("{\"bitmask\":\"") + msk + "\",\"set_id\":\"0x" + hexs(sh.data(), 8) + "\",\"samplers\":" + csl + "}";

  char hdr[400];
  snprintf(hdr, sizeof hdr, "{\"format_version\":%d,\"abi_version\":%d,\"compiler_id\":\"%s\",\"chip_id\":\"0x%llx\",\"key\":\"%s\",\"variant_id\":\"0x%.16s\",",
           CACHE_FORMAT_VERSION, ABI_VERSION, AIR2IR3_COMPILER_ID, (unsigned long long)C->chip, out.key.c_str(), out.key.c_str());
  out.sidecar = std::string(hdr) + "\"key_inputs\":" + keyInputsJson(k) + ",\"reflection\":" + air_reflection_json(R) +
                ",\"constant_samplers\":" + csj +
                ",\"blob\":{\"sha256\":\"" + hexs(bh.data(), 32) + "\",\"size\":" + std::to_string(out.blob.size()) +
                ",\"format\":\"mesa ir3_store_variant (ir3_disk_cache.c)\",\"path\":\"blobs/" + hexs(bh.data(), 32) + ".ir3v\"}" +
                ",\"ir3\":{\"chip_id\":\"0x" + [&] { char b2[20]; snprintf(b2, sizeof b2, "%llx", (unsigned long long)C->chip); return std::string(b2); }() +
                "\",\"gen\":" + std::to_string(C->c->gen) + ",\"stats\":" + stats + ",\"const_budget\":" + cb + ",\"pvtmem\":" + pv +
                ",\"driver_ubos\":" + dubos + ",\"const_driver_params\":" + constDp +
                ",\"sample_shading\":{\"per_sample_if_msaa\":" + (ss.perSample ? "true" : "false") + ",\"reasons\":[" +
                [&] { std::string r; for (auto &x : ss.reasons) r += (r.empty() ? "\"" : ",\"") + x + "\""; return r; }() +
                "],\"ir3_sample_shading\":" + (v->sample_shading ? "true" : "false") + "}" +
                ",\"inputs\":" + inl + ",\"outputs\":" + outl + "}}\n";
  if (wantProgram) {
    if (!v->info.size || v->info.size > (16u << 20)) die("GPU program exceeds export size limit");
    out.machine_code.assign((const char *)v->bin, v->info.size);
    out.program_json = air2ir3_program_json(v, out.sidecar);
  }
  return out;
}

static AirOptions optionsFromInfo(const air2ir3_compile_info *info) {
  AirOptions o;
  if (info->entry) o.entry = info->entry;
  o.expectStage = info->stage == AIR2IR3_STAGE_VERTEX ? MESA_SHADER_VERTEX : info->stage == AIR2IR3_STAGE_FRAGMENT ? MESA_SHADER_FRAGMENT
                : info->stage == AIR2IR3_STAGE_KERNEL ? MESA_SHADER_COMPUTE : -1;
  for (uint32_t i = 0; i < info->num_constants; i++) {
    const air2ir3_constant &c = info->constants[i];
    std::vector<double> v(c.values, c.values + std::min<uint32_t>(c.num_values, 4));
    if (c.name) o.fcByName[c.name] = v; else o.fc[c.index] = v;
  }
  for (int i = 0; i < 8; i++) {
    o.rtClass[i] = (uint8_t)air2ir3_format_class(info->color_pixel_format[i]);
    const air2ir3_blend &b = info->blend[i];
    o.blend[i].enabled = b.enabled; o.blend[i].rgbOp = b.rgb_op; o.blend[i].alphaOp = b.alpha_op;
    o.blend[i].srcRGB = b.src_rgb; o.blend[i].dstRGB = b.dst_rgb; o.blend[i].srcA = b.src_alpha; o.blend[i].dstA = b.dst_alpha;
  }
  for (int i = 0; i < 16; i++) o.texClass[i] = info->texture_class[i];
  if (info->struct_size >= offsetof(air2ir3_compile_info, safe_constlen) + sizeof(info->safe_constlen)) o.safeConstlen = info->safe_constlen != 0;
  return o;
}
static bool infoOk(const air2ir3_compile_info *info) {
  return info && info->struct_size >= offsetof(air2ir3_compile_info, safe_constlen) && info->air;
}

extern "C" {
uint32_t air2ir3_api_version(void) { return AIR2IR3_API_VERSION; }
uint32_t air2ir3_abi_version(void) { return ABI_VERSION; }
uint32_t air2ir3_cache_format_version(void) { return CACHE_FORMAT_VERSION; }
const char *air2ir3_compiler_id(void) { return AIR2IR3_COMPILER_ID; }
uint32_t air2ir3_format_class(uint32_t f) {
  switch (f) {
  case 554: return AIR_FMT_XR10_BGR32;          // BGR10_XR
  case 552: return AIR_FMT_XR10_BGRA64;         // BGRA10_XR
  case 550: case 551: return AIR_FMT_XR10_RGB10A8_2P;
  case 508: case 510: return AIR_FMT_YCBCR10_PACKED;
  case 553: case 555: return AIR_FMT_XR10_SRGB;
  default: return AIR_FMT_NATIVE;
  }
}
air2ir3_compiler *air2ir3_compiler_create(uint64_t chip, char **error) {
  nirValidationPolicy();
  if (!chip) chip = 0x44070041;                 // Adreno X2-90 (Mesa freedreno_devices.py)
  auto *C = new air2ir3_compiler;
  C->chip = chip; C->id.chip_id = chip;
  const struct fd_dev_info *info = fd_dev_info_raw(&C->id);
  if (!info) { if (error) *error = dupstr("chip id not known to this Mesa"); delete C; return nullptr; }
  glsl_type_singleton_init_or_ref();
  ir3_compiler_options copts = {};
  // BINDING-ABI.md: FS bindless set 4 carries the framebuffer-fetch descriptors at
  // 32 + 32 - 1 - max_rts + rt (Mesa gallium ir3_screen_init / fd6_build_bindless_state).
  copts.bindless_fb_read_descriptor = ABI_FS_BINDLESS_SET;
  copts.bindless_fb_read_slot = ABI_FB_READ_SLOT;
  copts.lower_base_vertex = true;
  copts.push_ubo_with_preamble = true;
  copts.disable_cache = true;
  C->c = ir3_compiler_create(nullptr, &C->id, info, &copts);
  if (!C->c) { glsl_type_singleton_decref(); if (error) *error = dupstr("ir3_compiler_create failed"); delete C; return nullptr; }
  return C;
}
void air2ir3_compiler_destroy(air2ir3_compiler *C) {
  if (!C) return;
  ir3_compiler_destroy(C->c);
  glsl_type_singleton_decref();
  delete C;
}
static int compile_result(air2ir3_compiler *C, const air2ir3_compile_info *info,
                          air2ir3_result *res, air2ir3_program_result *program) {
  if (!res) return 1;
  memset(res, 0, sizeof *res);
  if (program) memset(program, 0, sizeof *program);
  auto t0 = std::chrono::steady_clock::now();
  if (!C || !infoOk(info)) { res->error = dupstr("UNSUPPORTED/ERROR: bad arguments"); return 1; }
  try {
    CompileOut o = compile_internal(C, info->air, info->air_size, optionsFromInfo(info), false, false, false, program != nullptr);
    res->blob = malloc(o.blob.size());
    if (!res->blob) throw std::bad_alloc();
    memcpy(res->blob, o.blob.data(), o.blob.size()); res->blob_size = o.blob.size();
    res->sidecar_json = dupstr(o.sidecar); res->sidecar_size = o.sidecar.size();
    if (!res->sidecar_json) throw std::bad_alloc();
    memcpy(res->key_hex, o.key.c_str(), 65);
    if (program) {
      program->code = malloc(o.machine_code.size());
      if (!program->code) throw std::bad_alloc();
      memcpy(program->code, o.machine_code.data(), o.machine_code.size());
      program->code_size = o.machine_code.size();
      program->program_json = dupstr(o.program_json);
      if (!program->program_json) throw std::bad_alloc();
      program->program_size = o.program_json.size();
    }
  } catch (const AirError &e) {
    res->error = dupstr(std::string("UNSUPPORTED/ERROR: ") + e.what());
  } catch (const std::exception &e) {
    res->error = dupstr(std::string("UNSUPPORTED/ERROR: internal: ") + e.what());
  }
  res->compile_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  return res->error ? 1 : 0;
}
int air2ir3_compile(air2ir3_compiler *C, const air2ir3_compile_info *info, air2ir3_result *res) {
  return compile_result(C, info, res, nullptr);
}
int air2ir3_compile_program(air2ir3_compiler *C, const air2ir3_compile_info *info,
                           air2ir3_result *res, air2ir3_program_result *program) {
  if (!program) {
    if (res) { memset(res, 0, sizeof *res); res->error = dupstr("UNSUPPORTED/ERROR: missing program output"); }
    return 1;
  }
  if (!res) { memset(program, 0, sizeof *program); return 1; }
  return compile_result(C, info, res, program);
}
int air2ir3_cache_key(air2ir3_compiler *C, const air2ir3_compile_info *info, char key_hex[65], char **error) {
  if (error) *error = nullptr;
  if (!C || !infoOk(info) || !key_hex) { if (error) *error = dupstr("bad arguments"); return 1; }
  try {
    std::string k = keyOnly(C->chip, info->air, info->air_size, optionsFromInfo(info));
    memcpy(key_hex, k.c_str(), 65);
    return 0;
  } catch (const std::exception &e) {
    if (error) *error = dupstr(e.what());
    return 1;
  }
}
// ir3_trim_constlen (ir3_shader.c) for a VS+FS pipeline without shared consts: first the geometry
// group (VS) against max_const_geom, then VS+FS against max_const_pipeline; each step trims the
// largest stage to max_const_safe until the sum fits.
static uint32_t trimGroup(unsigned *cl, unsigned first, unsigned last, unsigned limit, unsigned safe) {
  unsigned tot = 0; uint32_t trimmed = 0;
  for (unsigned i = first; i <= last; i++) tot += cl[i];
  while (tot > limit) {
    unsigned ms = first, mc = 0;
    for (unsigned i = first; i <= last; i++) if (cl[i] >= mc) { ms = i; mc = cl[i]; }
    if (mc <= safe) break;
    trimmed |= 1u << ms; tot = tot - mc + safe; cl[ms] = safe;
  }
  return trimmed;
}
uint32_t air2ir3_trim_constlen(const air2ir3_compiler *C, uint32_t vs_constlen, uint32_t fs_constlen) {
  if (!C) return 0;
  unsigned cl[2] = {vs_constlen, fs_constlen};
  uint32_t t = trimGroup(cl, 0, 0, C->c->max_const_geom, C->c->max_const_safe);
  t |= trimGroup(cl, 0, 1, C->c->max_const_pipeline, C->c->max_const_safe);
  return t;     // bit 0: use the vertex function's safe_constlen variant, bit 1: the fragment function's
}
void air2ir3_result_free(air2ir3_result *r) { if (!r) return; free(r->blob); free(r->sidecar_json); free(r->error); memset(r, 0, sizeof *r); }
void air2ir3_program_result_free(air2ir3_program_result *r) {
  if (!r) return;
  free(r->code); free(r->program_json); memset(r, 0, sizeof *r);
}
void air2ir3_free(void *p) { free(p); }
}   // extern "C"

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
static const char *USAGE =
  "usage: air2ir3 [options] fn.bc|lib.air\n"
  "  --chip 0x44070041        target chip id\n"
  "  --entry NAME             entry point (modules with several functions)\n"
  "  --stage vertex|fragment|kernel   expected stage (with no --entry: the first entry of that stage)\n"
  "  --fc IDX=V[,V..]         function constant by index      --fc-name NAME=V[,V..]  by name\n"
  "  --rt-format I=MTLPixelFormat     colour attachment I format (sets the format class)\n"
  "  --blend I=en,rgbOp,aOp,srcRGB,dstRGB,srcA,dstA   Metal blend state of attachment I\n"
  "  --tex-class T=C          draw-time format class of T# T\n"
  "  --samples N              raster sample count (accepted; not key material, the code does not depend on it)\n"
  "  --safe-constlen          build ir3's safe_constlen variant (BINDING-ABI.md 5.2)\n"
  "  --test-ubo-slots N       A16 hardware probe only: accept UBO indices up to N-1 (sidecar ir3.stats.ubo_slots = N)\n"
  "  --key-only               print the cache key without compiling (air2ir3_cache_key)\n"
  "  --list-fcs               print the declared function constants as JSON, without compiling\n"
  "  --trim-constlen VS,FS    print air2ir3_trim_constlen's stage mask (bit0 VS, bit1 FS) and exit\n"
  "  --json side.json         sidecar (key, key_inputs, reflection, ir3)   --variant v.ir3v  blob\n"
  "  --key                    print the cache key                          --compiler-id  print it and exit\n"
  "  --nir / --emit-nir       NIR after / before the ir3 lowering          --quiet\n"
  "  --verify-variant v.ir3v  reload a blob with ir3_retrieve_variant and disassemble it\n";

int main(int argc, char **argv) {
  uint64_t chip = 0x44070041;        // Adreno X2-90 (Mesa freedreno_devices.py)
  AirOptions o;
  bool keyOnlyMode = false, listFcs = false; std::string trimArg;
  const char *path = nullptr, *jsonOut = nullptr, *variantOut = nullptr, *verifyPath = nullptr;
  bool dumpNir = false, emitNir = false, quiet = false, printKey = false;
  try {
    for (int i = 1; i < argc; i++) {
      std::string a = argv[i];
      auto next = [&]() -> std::string { if (i + 1 >= argc) die("missing value for " + a); return argv[++i]; };
      auto idxval = [&](const std::string &kv, int lim) { int k = atoi(kv.c_str()); if (k < 0 || k >= lim || kv.find('=') == std::string::npos) die("bad " + a + " " + kv); return k; };
      if (a == "--chip") chip = strtoull(next().c_str(), nullptr, 0);
      else if (a == "--fc") { std::string kv = next(); o.fc[atoi(kv.c_str())] = parseVals(kv.substr(kv.find('=') + 1)); }
      else if (a == "--fc-name") { std::string kv = next(); size_t e = kv.find('='); o.fcByName[kv.substr(0, e)] = parseVals(kv.substr(e + 1)); }
      else if (a == "--rt-format") { std::string kv = next(); int k = idxval(kv, 8); o.rtClass[k] = (uint8_t)air2ir3_format_class((uint32_t)atoi(kv.substr(kv.find('=') + 1).c_str())); }
      else if (a == "--rt-class") { std::string kv = next(); int k = idxval(kv, 8); o.rtClass[k] = (uint8_t)atoi(kv.substr(kv.find('=') + 1).c_str()); }
      else if (a == "--blend") {
        std::string kv = next(); int k = idxval(kv, 8); auto v = parseVals(kv.substr(kv.find('=') + 1));
        if (v.size() != 7) die("--blend needs 7 values");
        o.blend[k].enabled = v[0] != 0; o.blend[k].rgbOp = (uint8_t)v[1]; o.blend[k].alphaOp = (uint8_t)v[2];
        o.blend[k].srcRGB = (uint8_t)v[3]; o.blend[k].dstRGB = (uint8_t)v[4]; o.blend[k].srcA = (uint8_t)v[5]; o.blend[k].dstA = (uint8_t)v[6];
      }
      else if (a == "--tex-class") { std::string kv = next(); int k = idxval(kv, 16); o.texClass[k] = (uint8_t)atoi(kv.substr(kv.find('=') + 1).c_str()); }
      else if (a == "--samples") next();     // accepted, not key material and not read by the compile (CACHE-FORMAT.md 2)
      else if (a == "--safe-constlen") o.safeConstlen = true;
      else if (a == "--key-only") keyOnlyMode = true;
      else if (a == "--list-fcs") listFcs = true;
      else if (a == "--trim-constlen") { std::string kv = next(); trimArg = kv; }
      else if (a == "--nir") dumpNir = true;
      else if (a == "--emit-nir") emitNir = true;
      else if (a == "--json") jsonOut = argv[++i];
      else if (a == "--variant") variantOut = argv[++i];
      else if (a == "--quiet") quiet = true;
      else if (a == "--key") printKey = true;
      else if (a == "--entry") o.entry = next();
      else if (a == "--compiler-id") { printf("%s\n", AIR2IR3_COMPILER_ID); return 0; }
      else if (a == "--test-abi-max-ubo") o.testMaxUboIndex = atoi(next().c_str());   // regression test of the fail-loud path only
      else if (a == "--test-ubo-slots") o.testUboSlots = atoi(next().c_str());   // A16 hardware probe of the UBO table only
      else if (a == "--test-pvtmem-budget") o.testPvtmemBudgetMiB = atoi(next().c_str());   // regression test of the pvtmem refusal only
      else if (a == "--help" || a == "-h") { fputs(USAGE, stdout); return 0; }
      else if (a == "--verify-variant") verifyPath = argv[++i];
      else if (a == "--stage") { std::string st = next(); o.expectStage = st == "vertex" ? MESA_SHADER_VERTEX : st == "fragment" ? MESA_SHADER_FRAGMENT : st == "kernel" ? MESA_SHADER_COMPUTE : -1; }
      else if (a.rfind("--", 0) == 0) die("unknown option " + a);
      else path = argv[i];
    }
    if (verifyPath) {
      // Reload a cache payload with Mesa's own ir3_retrieve_variant() and disassemble it: proves the
      // blob is self-contained for a Mesa-derived command-stream builder.
      char *err = nullptr;
      air2ir3_compiler *C = air2ir3_compiler_create(chip, &err);
      if (!C) die(err);
      auto vb = MemoryBuffer::getFile(verifyPath);
      if (!vb) die("cannot read variant blob");
      struct blob_reader br; blob_reader_init(&br, (*vb)->getBufferStart(), (*vb)->getBufferSize());
      ir3_shader_variant *vv = ir3_retrieve_variant(&br, C->c, nullptr);
      if (br.overrun || br.current != br.end) die("variant blob has trailing data or is truncated");
      FILE *nul = fopen("/dev/null", "w");
      unsigned code_dw = vv->info.constant_data_offset ? vv->info.constant_data_offset / 4 : vv->info.sizedwords;
      if (disasm_a3xx((uint32_t *)vv->bin, code_dw, 0, quiet ? nul : stdout, fd_dev_gpu_id(&C->id)) != 0)
        die("variant code does not disassemble");
      printf("variant: stage %s instrs %u dwords %u constlen %u full_regs %d binning %s\n",
             _mesa_shader_stage_to_abbrev((mesa_shader_stage)vv->type), vv->info.instrs_count, vv->info.size / 4, vv->constlen,
             vv->info.max_reg + 1, vv->binning ? "yes" : "no");
      return 0;
    }
    if (!trimArg.empty()) {
      char *err = nullptr;
      air2ir3_compiler *C = air2ir3_compiler_create(chip, &err);
      if (!C) die(err);
      unsigned vsc = atoi(trimArg.c_str()), fsc = atoi(trimArg.substr(trimArg.find(',') + 1).c_str());
      printf("trim: %u\n", air2ir3_trim_constlen(C, vsc, fsc));
      air2ir3_compiler_destroy(C);
      return 0;
    }
    if (!path) { fputs(USAGE, stderr); return 1; }
    setvbuf(stdout, nullptr, _IONBF, 0);
    auto buf = MemoryBuffer::getFile(path);
    if (!buf) die(std::string("cannot read input ") + path);
    char *err = nullptr;
    air2ir3_compiler *C = air2ir3_compiler_create(chip, &err);
    if (!C) die(err);
    if (listFcs) {
      printf("%s\n", fcListJson((*buf)->getBufferStart(), (*buf)->getBufferSize(), o).c_str());
      air2ir3_compiler_destroy(C);
      return 0;
    }
    if (keyOnlyMode) {
      printf("key: %s\n", keyOnly(C->chip, (*buf)->getBufferStart(), (*buf)->getBufferSize(), o).c_str());
      air2ir3_compiler_destroy(C);
      return 0;
    }
    CompileOut out = compile_internal(C, (*buf)->getBufferStart(), (*buf)->getBufferSize(), o, !quiet, emitNir, dumpNir);
    if (!quiet) {
      printf("== %s  (%s)\n", out.function.c_str(), out.stage == MESA_SHADER_VERTEX ? "vertex" : out.stage == MESA_SHADER_FRAGMENT ? "fragment" : "kernel");
      printf("   target: %s  gen %u (chip_id 0x%llx)\n", fd_dev_name(&C->id), C->c->gen, (unsigned long long)chip);
      printf("%s", out.report.c_str());
    }
    if (emitNir) fputs(out.nir_before.c_str(), stdout);
    if (dumpNir) fputs(out.nir_after.c_str(), stdout);
    fputs(out.stats_line.c_str(), stdout);
    if (!quiet) fputs(out.disasm.c_str(), stdout);
    if (printKey) printf("key: %s\n", out.key.c_str());
    if (variantOut) {
      FILE *f = fopen(variantOut, "wb"); if (!f) die("cannot write variant");
      fwrite(out.blob.data(), 1, out.blob.size(), f); fclose(f);
    }
    if (jsonOut) {
      FILE *f = fopen(jsonOut, "w"); if (!f) die("cannot write json");
      fwrite(out.sidecar.data(), 1, out.sidecar.size(), f); fclose(f);
    }
    air2ir3_compiler_destroy(C);
  } catch (const AirError &e) {
    fflush(stdout);
    fprintf(stderr, "air2ir3: UNSUPPORTED/ERROR: %s\n", e.what());
    return 2;
  }
  fflush(stdout);
  return 0;
}
#endif
