/* SPDX-License-Identifier: MIT */
/* air2ir3_api.h - stable C API of the air2ir3 compiler library (build/libair2ir3.a).
 *
 * This is what the Metal plug-in calls at run time: AIR in, ir3 variant blob + sidecar out.  It is
 * the same code path the offline sweep uses (build/air2ir3 is a thin CLI over this API), so a
 * runtime compile and a cache entry for the same key are byte-identical.
 *
 * Threading and state:
 *  - There is no global mutable state of our own.  An air2ir3_compiler owns the Mesa ir3_compiler
 *    for one chip; air2ir3_compile() may be called concurrently on the same handle from several
 *    threads (each call has its own LLVMContext and NIR; ir3_compiler is shared read-only, as in
 *    Turnip).  The only process-wide object is Mesa's reference-counted, locked glsl_type
 *    singleton, taken in air2ir3_compiler_create and released in air2ir3_compiler_destroy.
 *  - Nothing calls exit() or prints: errors come back as an error string.
 *
 * Versioning: AIR2IR3_API_VERSION changes only when this header changes incompatibly.  The ABI of
 * the produced code is air2ir3_abi_version() (BINDING-ABI.md); the cache key layout is
 * air2ir3_cache_format_version() (CACHE-FORMAT.md).  Structs start with struct_size so fields can
 * be appended compatibly.
 */
#ifndef AIR2IR3_API_H
#define AIR2IR3_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define AIR2IR3_API_VERSION 2   /* 2: + safe_constlen, air2ir3_cache_key, air2ir3_trim_constlen */

typedef struct air2ir3_compiler air2ir3_compiler;

enum air2ir3_stage { AIR2IR3_STAGE_ANY = 0, AIR2IR3_STAGE_VERTEX = 1, AIR2IR3_STAGE_FRAGMENT = 2, AIR2IR3_STAGE_KERNEL = 3 };

/* One function-constant value, as given to MTLFunctionConstantValues.  Either index >= 0 or name
 * != NULL.  values[] holds the scalar or vector components as doubles (bool: 0/1).  The compiler
 * converts each to the constant's declared type once (cache format 5, CACHE-FORMAT.md 2.1: integers
 * wrapped to their width, float / half rounded, NaN / inf / -0 kept); a double cannot carry a long /
 * ulong beyond 2^53. */
typedef struct {
  int32_t index;
  const char *name;
  uint32_t num_values;
  double values[4];
} air2ir3_constant;

/* Blend state of one colour attachment, MTLBlendOperation / MTLBlendFactor numbering. */
typedef struct {
  uint8_t enabled, rgb_op, alpha_op, src_rgb, dst_rgb, src_alpha, dst_alpha, pad;
} air2ir3_blend;

typedef struct {
  uint32_t struct_size;               /* sizeof(air2ir3_compile_info) */
  const void *air;                    /* LLVM bitcode of the AIR module (a metallib function module or a .air) */
  size_t air_size;
  const char *entry;                  /* entry point, NULL = the module's only/first entry */
  uint32_t stage;                     /* enum air2ir3_stage expected, ANY = no check */
  uint32_t num_constants;
  const air2ir3_constant *constants;
  uint32_t color_pixel_format[8];     /* MTLPixelFormat of colour attachments 0..7 (0 = none); fragment only */
  air2ir3_blend blend[8];             /* per attachment; only used for attachments whose class is lowered */
  uint32_t raster_sample_count;       /* informational: not key material, the code does not depend on it (CACHE-FORMAT.md 2) */
  uint8_t texture_class[16];          /* draw-time format class of T# 0..15 (0 = native), BINDING-ABI.md 3.3;
                                         only the texture(n) arguments the function declares count */
  /* API 2 (a caller built against API 1 passes the smaller struct_size; the field then reads 0) */
  uint32_t safe_constlen;             /* 1: ir3's safe_constlen variant (BINDING-ABI.md 5.2, air2ir3_trim_constlen) */
} air2ir3_compile_info;

typedef struct {
  void *blob;          size_t blob_size;      /* Mesa ir3_store_variant() payload (includes the binning VS) */
  char *sidecar_json;  size_t sidecar_size;   /* {"key", "key_inputs", "reflection", "constant_samplers", "blob", "ir3"}: byte-identical
                                                 to the cache entry file entries/<k>/<key>.json (CACHE-FORMAT.md 3) */
  char key_hex[65];                           /* CACHE-FORMAT.md section 2 */
  char *error;                                /* NULL on success */
  double compile_ms;                          /* wall time of this call */
} air2ir3_result;

uint32_t air2ir3_api_version(void);
uint32_t air2ir3_abi_version(void);
uint32_t air2ir3_cache_format_version(void);
const char *air2ir3_compiler_id(void);        /* sources + Mesa rev/patches/build options + LLVM, set at build time */
uint32_t air2ir3_format_class(uint32_t mtl_pixel_format);

/* chip_id 0 = Adreno X2-90 (0x44070041). Returns NULL and sets *error (free with air2ir3_free) on failure. */
air2ir3_compiler *air2ir3_compiler_create(uint64_t chip_id, char **error);
void air2ir3_compiler_destroy(air2ir3_compiler *c);

/* Returns 0 on success.  On failure returns non-zero and result->error says why ("UNSUPPORTED/ERROR: ..."). */
int air2ir3_compile(air2ir3_compiler *c, const air2ir3_compile_info *info, air2ir3_result *result);
void air2ir3_result_free(air2ir3_result *result);

/* Additive API 2 extension: executable program bytes and the a8xx state needed
 * by the command builder, exported from the freshly compiled variant. Unlike
 * result.blob, code is suitable for a shader upload. Includes inline constant
 * data; program_json describes its offset and exact code_hex/size. No borrowed
 * variant pointers escape. Free both results, including after failure.
 * Existing compile() and its cache payload are unchanged. */
typedef struct {
  void *code; size_t code_size;
  char *program_json; size_t program_size;
} air2ir3_program_result;
int air2ir3_compile_program(air2ir3_compiler *c, const air2ir3_compile_info *info,
                           air2ir3_result *result, air2ir3_program_result *program);
void air2ir3_program_result_free(air2ir3_program_result *program);

/* The cache key of a compile without compiling: parses the module's metadata only (entry point,
 * function-constant declarations, texture arguments).  Equals air2ir3_compile()'s key_hex.
 * Returns 0 on success; on failure non-zero and *error (free with air2ir3_free). */
int air2ir3_cache_key(air2ir3_compiler *c, const air2ir3_compile_info *info, char key_hex[65], char **error);

/* Pipeline const budget (BINDING-ABI.md 5.2, Mesa ir3_trim_constlen): given the constlen of the
 * vertex and fragment variants (sidecar ir3.const_budget.constlen), the stages that must use their
 * safe_constlen variant instead: bit 0 vertex, bit 1 fragment.  0 = the pipeline fits as is. */
uint32_t air2ir3_trim_constlen(const air2ir3_compiler *c, uint32_t vs_constlen, uint32_t fs_constlen);
void air2ir3_free(void *p);

#ifdef __cplusplus
}
#endif
#endif
