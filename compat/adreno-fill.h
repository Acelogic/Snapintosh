/* SPDX-License-Identifier: MIT */
#pragma once
#include "adreno.h"

/* ABI advertised by the candidate monitor; not installed on the A16 yet.
 * x0=request, x1=IOVA, x2=byte count, x3=u32 pattern. Destination and length
 * must be dword aligned. Results: signed status, completed bytes (zero on
 * failure), completion poll ticks, ring WPTR. No user-space GPU address is
 * accepted by this interface's eventual kernel command parser: the kext must
 * resolve a retained/prepared resource and range before making this HVC.
 */
#define ADRENO_GUEST_FILL32 0x00010004
#define ADRENO_GUEST_FILL32_PROPERTY "snapintosh,guest-fill32-abi"
#define ADRENO_FILL32_MAX_BYTES 0x4000UL
#define ADRENO_FILL32_E_UNCERTAIN (-74)
#if SNAP_ADRENO_FILL_BR
/* Opt-in (agents/gpu-x290 FAILURE-MODES.md F1-F5; turnip-audit FINDINGS item 3). The ring is in
 * CP_THREAD_CONTROL(BOTH) after every IB (compat/adreno-ib.c adreno_ib_ring_words), so by default both CP
 * threads execute the fill's CP_MEM_WRITEs and the marker can land before BR's copy of the fill. With this
 * define the words are CP_THREAD_CONTROL(BR | SYNC_THREADS), the fill, CP_WAIT_MEM_WRITES, the marker's
 * CP_MEM_WRITE, CP_THREAD_CONTROL(BOTH) -- 12 words around the data instead of 7 -- and completion also needs
 * RBBM_STATUS idle (ADRENO_IB_RBBM_IDLE_IGNORE, as an IB's retirement). */
#define ADRENO_FILL32_BR_EXTRA 12u
#endif

/* Caller serializes against DART mutation and other submissions, retains all
 * backing and has completed TO_DEVICE cache ownership. This helper writes
 * only ring storage and its private completion slot with the CPU; CP_MEM_WRITE
 * fills the destination. After success the caller must perform FROM_DEVICE
 * before reading destination bytes. This is CP memory transfer only: no shader
 * work may be outstanding, and no GPU-internal cache barrier is supplied.
 * The ring wraps with CP_NOP padding (compat/adreno.h adreno_ring_reserve).
 * Once a doorbell may have reached hardware (the padding's included), every
 * failure is UNCERTAIN: retain backing and prohibit more work until reset.
 */
int adreno_guest_fill32(const struct adreno_ops *ops, const struct adreno_params *params,
                        struct adreno_state *state, uint64_t regs[4],
                        uint64_t (*leaf)(void *context, uint64_t iova), void *context,
                        uint64_t mem_low, uint64_t mem_high);
