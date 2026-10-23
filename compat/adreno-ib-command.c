/* SPDX-License-Identifier: MIT */
/* ADRENO_KCMD_IB kext core. Contract, policy and the list of what is deliberately not enforced: adreno-ib-command.h.
 * Every table comes from generated headers: AdrenoA8xxRegs.h (Mesa XML: registers, fields, enums, PM4 headers)
 * and adreno-ib-tables.h (q1n1: CP_PROTECT ranges). No register number is typed here. */
#define A8XX_REGS_TABLES 1
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
#include "adreno-ib-command.h"
#include "adreno-ib-tables.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the kernel-command wire format is little endian and relocation records are read in place"
#endif

#define NONE ADRENO_IB_RELOC_NO_HI
#define KIND(k) (1u << (k))
#define READ_KINDS (KIND(ADRENO_IB_RELOC_RESOURCE) | KIND(ADRENO_IB_RELOC_PACKAGE) | KIND(ADRENO_IB_RELOC_ZERO))
#define RING_LIMIT ADRENO_RING_DWORDS(ADRENO_RING_BUFSZ)

#include "adreno-ib-command/stage_relocate.c"
#include "adreno-ib-command/validate.c"
#include "adreno-ib-command/submit.c"
