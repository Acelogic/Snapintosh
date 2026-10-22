/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "adreno-guest.h"

#if defined(__cplusplus)
#define ADRENO_SUBMIT_ASSERT(c, m) static_assert(c, m)
#else
#define ADRENO_SUBMIT_ASSERT(c, m) _Static_assert(c, m)
#endif

#define ADRENO_KCMD_IOGPU_DEBUG_LOG 0u
#define ADRENO_KCMD_IOGPU_TIMESTAMP 1u
#define ADRENO_KCMD_VENDOR_BASE 0x1000u
#define ADRENO_KCMD_FENCE ADRENO_KCMD_VENDOR_BASE

struct adreno_submit_header { uint32_t type, size; };
enum {
    ADRENO_SUBMIT_GENERIC = 1,
    ADRENO_SUBMIT_E_FORMAT = -90,
    ADRENO_SUBMIT_E_COMMAND = -91,
    ADRENO_SUBMIT_E_UNCERTAIN = -92,
    ADRENO_SUBMIT_E_INACTIVE = -93,
};
#ifdef __cplusplus
extern "C" {
#endif
/* A synchronous fence returns zero only after GPU completion. Native generic
 * commands return GENERIC for the caller to delegate to IOGPU. No GPU address
 * or resource pointer is accepted from this first transport command. */
int adreno_submit_command(const void *command, uint64_t available,
                          int (*fence)(void *), void *context);
#ifdef __cplusplus
}
#endif

/* ---- ADRENO_KCMD_IB: one draw package (design S0, sections 2.2/2.3b/3.1) ----------------------------------
 * Wire bytes (little endian), inside IOGPU's kernel command buffer; the kext receives exactly this extent:
 *   [0, 48)                    struct adreno_ib_command (header.type ADRENO_KCMD_IB, header.size = total)
 *   [48, 48 + P)               the package: IB dwords [0, 4 * ib_dwords), zero padding to
 *                              adreno_ib_data_offset(ib_dwords), then data_bytes of data (T#/S# arrays,
 *                              setBytes uniforms, driver tables, inline vertex data), P = adreno_ib_package_bytes
 *   [48 + P, 48 + P + 32 * n)  struct adreno_ib_reloc[reloc_count]
 * The command is 4-aligned only: consumers copy it (volatile byte loads; user threads may rewrite it) and
 * parse the copy, never fields in place. Userspace never writes a GPU address: every address field holds a
 * zero placeholder and is named by exactly one relocation (per half). The kext copies the package into its
 * GPU-read-only arena, resolves the relocations against the command buffer's retained/prepared resource list,
 * validates the IB (allowlist of design 3.3), and submits package VA / ib_dwords / P with ADRENO_GUEST_IB.
 * Packages are processed synchronously in command order; the plug-in splits at the limits below (2.3b). */
#define ADRENO_KCMD_IB (ADRENO_KCMD_VENDOR_BASE + 2u)   /* FENCE 0x1000, FILL32 0x1001 */
#define ADRENO_IB_COMMAND_VERSION 1u
#define ADRENO_IB_MAX_RELOCS 16384u
#define ADRENO_IB_RELOC_NO_HI 0xffffffffu                /* adreno_ib_reloc.hi: the field has no high half */
#define ADRENO_IB_ZERO_BYTES 0x4000u                     /* kernel zero page: border colours, empty bindless sets */
#define ADRENO_IB_ARENA_BYTES 0x400000u                  /* kext arena: zero page + one package (INFERRED size) */

struct adreno_ib_command {              /* 48 bytes */
    struct adreno_submit_header header; /* type ADRENO_KCMD_IB; size = adreno_ib_command_bytes(...) */
    uint32_t version;                   /* ADRENO_IB_COMMAND_VERSION */
    uint32_t flags;                     /* 0 in version 1 */
    uint32_t ib_dwords;                 /* 1..ADRENO_IB_MAX_DWORDS */
    uint32_t data_bytes;                /* 0..ADRENO_IB_MAX_DATA, multiple of ADRENO_IB_ALIGN */
    uint32_t reloc_count;               /* 0..ADRENO_IB_MAX_RELOCS */
    uint32_t reserved0;                 /* 0 */
    uint64_t reserved1[2];              /* 0 */
};

/* One address field (a 64-bit register pair, a descriptor BASE_LO/BASE_HI pair, a driver-table u64, a packet
 * address) resolved by the kext:
 *   addr = base(kind, resource_id) + offset, with [offset, offset + length) inside the target's extent
 *          (RESOURCE: the mapped resource; PACKAGE: [0, P); ZERO: [0, ADRENO_IB_ZERO_BYTES)),
 *          addr % (1 << align_log2) == 0.
 *   Before patching: dword(lo) & ~((1 << align_log2) - 1) == 0 and, when hi != NO_HI,
 *          dword(hi) & ((1 << hi_bits) - 1) == 0 (the low bits of lo and the high bits of hi may carry other
 *          fields of the same register/descriptor).
 *   Patch:  dword(lo) |= (uint32_t)addr; dword(hi) |= (addr >> 32) & ((1 << hi_bits) - 1).
 *   lo/hi are package byte offsets, 4-aligned, inside [0, P), distinct; no package dword is the target of more
 *   than one reloc half. hi == NO_HI only where the field has no high half (the address must then be < 4 GiB:
 *   true of every default-window address; with ADRENO_VA_WIDE only the IB arena (PACKAGE, ZERO) is kept below
 *   4 GiB, and a RESOURCE above it is refused, ADRENO_IB_E_RELOC). access: READ and/or WRITE for RESOURCE (a subset of the resource's
 *   recorded MTLResourceUsage), READ only for PACKAGE and ZERO; GPU-written targets (render target, 2D
 *   destination) need WRITE. resource_id is the IOGPU resource ID for RESOURCE and 0 otherwise. */
struct adreno_ib_reloc {                /* 32 bytes */
    uint32_t lo;                        /* package byte offset of the dword taking address bits [31:0] */
    uint32_t hi;                        /* package byte offset of the dword taking bits [63:32], or NO_HI */
    uint8_t kind;                       /* ADRENO_IB_RELOC_* */
    uint8_t access;                     /* ADRENO_IB_ACCESS_* */
    uint8_t align_log2;                 /* 0..ADRENO_IB_RELOC_MAX_ALIGN_LOG2 */
    uint8_t hi_bits;                    /* 1..32 when hi != NO_HI (32 plain reg64; 17 UBO_1/TEX_MEMOBJ_1 BASE_HI) */
    uint32_t resource_id;
    uint64_t offset;                    /* byte offset in the resource / package / zero page */
    uint64_t length;                    /* bytes the GPU may touch from offset, > 0 */
};

enum {
    ADRENO_IB_RELOC_RESOURCE = 1,       /* an IOGPU resource of this command buffer's resource list */
    ADRENO_IB_RELOC_PACKAGE = 2,        /* this package (its arena copy) */
    ADRENO_IB_RELOC_ZERO = 3,           /* the kext's zero page */
};
#define ADRENO_IB_ACCESS_READ 1u
#define ADRENO_IB_ACCESS_WRITE 2u
#define ADRENO_IB_RELOC_MAX_ALIGN_LOG2 12u
/* Required alignments (AdrenoContract.h proves the shr-derived ones against AdrenoA8xxRegs.h). */
#define ADRENO_IB_ALIGN_LOG2_TEXTURE 6u     /* T# base: A8XX_TEX_MEMOBJ_0 BASE_LO shr 6; also RT, 2D, bindless set */
#define ADRENO_IB_ALIGN_LOG2_UBO 6u         /* Turnip's UBO alignment (A6XX_UBO_0 has no shr) */
#define ADRENO_IB_ALIGN_LOG2_SAMPLER 4u     /* S# array: 16-byte descriptors */
#define ADRENO_IB_ALIGN_LOG2_SHADER 8u      /* SP_xS_BASE: code buffers are 256-byte aligned */
#define ADRENO_IB_ALIGN_LOG2_LOAD_STATE 2u  /* CP_LOAD_STATE6_1 EXT_SRC_ADDR shr 2 */
#define ADRENO_IB_ALIGN_LOG2_VERTEX 2u
#define ADRENO_IB_ALIGN_LOG2_INDEX16 1u
#define ADRENO_IB_HI_BITS_REG64 32u
#define ADRENO_IB_HI_BITS_DESC 17u          /* A6XX_UBO_1 / A8XX_TEX_MEMOBJ_1 BASE_HI bits 0..16 */

/* Kext-side refusals of an IB command (compat/adreno-ib-command.c, S3). Each is a pre-submission refusal:
 * the command buffer completes with an error, nothing is latched. Monitor results are ADRENO_E_* and
 * ADRENO_IB_E_{UNCERTAIN,GPU_ERROR,BUSY,STICKY} (adreno-guest.h). */
enum {
    ADRENO_IB_E_FORMAT = -120,          /* header, version, flags, reserved, sizes, overflow */
    ADRENO_IB_E_RELOC = -121,           /* kind/access/offsets/placeholder/overlap/unknown or unadmitted ID */
    ADRENO_IB_E_PACKET = -122,          /* malformed packet or opcode outside the allowlist */
    ADRENO_IB_E_REGISTER = -123,        /* register outside KNOWN - PROTECTED */
    ADRENO_IB_E_ADDRESS = -124,         /* address register/descriptor field without a reloc (and not 0) */
    ADRENO_IB_E_CAPACITY = -125,        /* arena or reloc storage too small */
    ADRENO_IB_E_BOUNDS = -126,          /* an extent the IB implies exceeds its reloc length */
};

static inline uint64_t adreno_ib_data_offset(uint32_t ib_dwords)
{
    return ADRENO_IB_ALIGN_UP((uint64_t)ib_dwords * 4u);
}
static inline uint64_t adreno_ib_package_bytes(uint32_t ib_dwords, uint32_t data_bytes)
{
    return adreno_ib_data_offset(ib_dwords) + data_bytes;
}
static inline uint64_t adreno_ib_command_bytes(uint32_t ib_dwords, uint32_t data_bytes, uint32_t reloc_count)
{
    return sizeof(struct adreno_ib_command) + adreno_ib_package_bytes(ib_dwords, data_bytes) +
           (uint64_t)reloc_count * sizeof(struct adreno_ib_reloc);
}
#define ADRENO_IB_COMMAND_MAX_BYTES \
    (48ull + ADRENO_IB_MAX_PACKAGE + (unsigned long long)ADRENO_IB_MAX_RELOCS * 32ull)

ADRENO_SUBMIT_ASSERT(sizeof(struct adreno_submit_header) == 8, "kernel command header size");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_submit_header, size) == 4, "header size offset");
ADRENO_SUBMIT_ASSERT(sizeof(struct adreno_ib_command) == 48, "IB command header is 48 bytes");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, header) == 0, "ib header");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, version) == 8, "ib version");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, flags) == 12, "ib flags");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, ib_dwords) == 16, "ib dwords");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, data_bytes) == 20, "ib data bytes");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, reloc_count) == 24, "ib reloc count");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, reserved0) == 28, "ib reserved0");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_command, reserved1) == 32, "ib reserved1");
ADRENO_SUBMIT_ASSERT(sizeof(struct adreno_ib_reloc) == 32, "IB reloc record is 32 bytes");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, lo) == 0, "reloc lo");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, hi) == 4, "reloc hi");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, kind) == 8, "reloc kind");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, access) == 9, "reloc access");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, align_log2) == 10, "reloc align");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, hi_bits) == 11, "reloc hi_bits");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, resource_id) == 12, "reloc resource");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, offset) == 16, "reloc offset");
ADRENO_SUBMIT_ASSERT(__builtin_offsetof(struct adreno_ib_reloc, length) == 24, "reloc length");
ADRENO_SUBMIT_ASSERT(ADRENO_KCMD_FENCE == 0x1000u && ADRENO_KCMD_IB == 0x1002u, "vendor kernel command numbers");
ADRENO_SUBMIT_ASSERT(ADRENO_IB_MAX_PACKAGE == ADRENO_IB_ALIGN_UP(4ull * ADRENO_IB_MAX_DWORDS) + ADRENO_IB_MAX_DATA,
                     "a maximal IB plus maximal data is exactly one maximal package");
ADRENO_SUBMIT_ASSERT(ADRENO_IB_MAX_DATA % ADRENO_IB_ALIGN == 0 && ADRENO_IB_MAX_PACKAGE % ADRENO_IB_ALIGN == 0,
                     "package limits are 64-byte multiples");
ADRENO_SUBMIT_ASSERT(ADRENO_IB_ZERO_BYTES + ADRENO_IB_MAX_PACKAGE <= ADRENO_IB_ARENA_BYTES,
                     "the arena holds the zero page and a maximal package");
ADRENO_SUBMIT_ASSERT(ADRENO_IB_COMMAND_MAX_BYTES <= 0xffffffffull, "header.size is 32 bits");
