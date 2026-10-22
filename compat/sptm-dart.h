/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
#include "dart.h"

/* The Adreno virtual DART (/arm-io/dart-adreno, dart-id 31; compat/adreno.h):
 * stream 0 is mirrored into the GPU SMMU's context bank 0 over this window,
 * [1 GiB, 4 GiB), or [1 GiB, 16 GiB) with ADRENO_VA_WIDE (probes/xnuboot.c
 * asserts it equals ADRENO_WINDOW_*). Level-1 slots BASE >> 25 .. END >> 25. */
#ifndef ADRENO_VA_WIDE
#define ADRENO_VA_WIDE 0
#endif
#define SPTM_DART_ADRENO 31U
#define SPTM_DART_ADRENO_BASE 0x40000000UL
#if !ADRENO_VA_WIDE
#define SPTM_DART_ADRENO_END 0x100000000UL
#else
#define SPTM_DART_ADRENO_END 0x400000000UL
#endif

/* mac-v1 table 3 endpoint 0, for the admitted single-bank SIO topology.
 * Caller selects the bound, powered DART using device_dart_admit_frame.
 * Attaches an empty class-5 table, updating shared references before the
 * descriptor/TTBR. Does not enable streams or acknowledge live DMA. */
enum sptm_result sptm_dart_map_table(const struct sptm_memory *memory,
    struct dart_state *dart, uint64_t device_id, uint64_t sid, uint64_t iova,
    uint64_t level, uint64_t pa);

/* Table 3 endpoint 2: map an owned physical page list within one 32 MiB
 * leaf-table span. Options 0..3 select read/write disable bits. New leaves
 * and identical repeats are supported; replacement/subpage-disable modes
 * remain explicit stops. No stream enable or DMA completion is implied. */
enum sptm_result sptm_dart_map(const struct sptm_memory *memory,
    struct dart_state *dart,uint64_t device_id,uint64_t sid,uint64_t iova,
    uint64_t page_list,uint64_t size,uint64_t options);

/* Table 3 endpoint 3: remove all leaves touched by the byte range, within
 * one 32 MiB leaf-table span. Options 0 requires every leaf; 2 permits holes.
 * Preflight all ownership/references, clear and publish descriptors, finish
 * the synchronous cacheless DMA invalidation, then release references.
 * Caller holds the guest service lock across the complete operation. */
enum sptm_result sptm_dart_unmap(const struct sptm_memory *memory,
    struct dart_state *dart,uint64_t device_id,uint64_t sid,uint64_t iova,
    uint64_t size,uint64_t options);

/* Table 3 endpoint 8: enable the admitted stream without changing its
 * configuration, table ownership, fault state or translation counters. */
enum sptm_result sptm_dart_enable(const struct sptm_memory *memory,
    struct dart_state *dart,uint64_t device_id,uint64_t sid);

/* Synchronous DMA admission for one 16 KiB IOVA-page fragment. Caller holds
 * the guest service lock through the eventual data operation/publication.
 * Requires owned class-5 tables and DEFAULT data with a live DMA reference.
 * Refusals leave memory, output and DART state unchanged; the monitor stops
 * the command instead of manufacturing a guest hardware completion. */
enum sptm_result sptm_dart_dma_translate(const struct sptm_memory *memory,
    struct dart_state *dart,uint64_t device_id,uint64_t sid,uint64_t iova,
    uint64_t size,int write,uint64_t *physical);
/* Validate a complete SEP0 virtual boot buffer. Firmware must map exactly
 * the loader-pinned reserve; shared memory must be distinct managed pages
 * with read/write DMA permission. Failure preserves even DART counters. */
enum sptm_result sptm_sep_rom_buffer(const struct sptm_memory *,struct dart_state *,
    unsigned kind,uint64_t iova,uint64_t size);
/* Shared bootstrap plus both OOL bindings: validate all complete RW extents,
 * managed ownership, unique physical pages, and any retained identities before
 * returning addresses. No writes; failure preserves counters and output. */
#define SPTM_SEP_SERVICE_PAGES 17
#define SPTM_SEP_ENDPOINT_PAGES 21
#define SPTM_SEP_ALL_PAGES 27 /* Bootstrap5 + pnon14 + xars4 + sks4. */
struct sptm_sep_span { uint64_t iova,size;const uint64_t *expected; };
enum sptm_result sptm_sep_endpoint_buffers(const struct sptm_memory *,struct dart_state *,
    const struct sptm_sep_span *,unsigned count,uint64_t physical[SPTM_SEP_ENDPOINT_PAGES]);
enum sptm_result sptm_sep_all_buffers(const struct sptm_memory *,struct dart_state *,
    const struct sptm_sep_span *,unsigned count,uint64_t physical[SPTM_SEP_ALL_PAGES]);
enum sptm_result sptm_sep_service_buffers(const struct sptm_memory *,struct dart_state *,
    const struct sptm_sep_span *,unsigned count,uint64_t physical[SPTM_SEP_SERVICE_PAGES]);

/* The committed level-2 descriptor for `iova` of an admitted stream, or 0.
 * A plain walk of tables MAP/UNMAP have already validated and published;
 * used by the Adreno mirror after each table-3 MAP/UNMAP. */
uint64_t sptm_dart_leaf(const struct sptm_memory *m,const struct dart_state *s,
    uint64_t id,uint64_t sid,uint64_t iova);
