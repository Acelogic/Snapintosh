/* SPDX-License-Identifier: MIT
 * A16/Glymur read-only thermal policy. docs/A16-THERMAL-GUARD-20261018.md. */
#pragma once
#include <stdint.h>
#define A16_THERMAL_MAGIC UINT64_C(0x314d524548543641) /* A6THERM1 */
#define A16_THERMAL_ABI 1u
#define A16_THERMAL_BLOCKS 8u
#define A16_THERMAL_SLOTS 128u
#define A16_THERMAL_LIMIT_MC 95000 /* user, 2026-10-19: halt at 95-98 C (was a 60 C bring-up ceiling) */
#define A16_THERMAL_POLL_MS 250u
#define A16_THERMAL_ADMIT_SAMPLES 20u /* within half a second; docs admission retry */
#define A16_THERMAL_REPORT_WORDS 320u
#define A16_THERMAL_REPORT_OFFSET 0xf000u /* byte offset in monitor output, excluding 16-byte prefix */
enum a16_thermal_reason {
    A16_THERMAL_OK, A16_THERMAL_HOT, A16_THERMAL_CONFIG, A16_THERMAL_INVALID,
    A16_THERMAL_LATE, A16_THERMAL_READ, A16_THERMAL_RANGE, A16_THERMAL_CRITICAL,
    A16_THERMAL_UNCHANGED, A16_THERMAL_SLOW, A16_THERMAL_CLOCK
};
/* Exactly 320 u64 words, including the raw partial snapshot and per-sensor ages.
 * Signed temperature words are sign extended. Internal state is also the report. */
struct a16_thermal_state {
    uint64_t magic, abi, bytes, polls, reads, started, last_poll, next_poll;
    uint64_t last_change, trip_ticks, reason, location;
    int64_t current_mc, peak_mc;
    uint64_t valid_count, missing_count, max_gap_ticks, invalid_samples, read_failures;
    uint64_t poll_ticks, max_poll_ticks, ready, unchanged_ticks, read_inflight;
    uint64_t version[8], control[8], trdy[8], valid_mask[8], seen_mask[8];
    uint64_t last_valid[128], raw[128];
};
struct a16_thermal_io {
    void *ctx;
    int (*read32)(void *,uint64_t,uint32_t *); /* nonzero => stop; never retried */
    uint64_t (*counter)(void *);
};
struct early_stop_state;
int a16_thermal_address_allowed(uint64_t address);
uint64_t a16_thermal_wait(const struct a16_thermal_state *,uint64_t now,uint64_t hz,uint64_t limit);
int a16_thermal_poll(struct a16_thermal_state *,struct early_stop_state *,uint64_t now,uint64_t hz,const struct a16_thermal_io *);
/* 0: one complete 92-sensor sample. 1: tripped. -1: no complete sample within the bounds. */
int a16_thermal_admit(struct a16_thermal_state *,struct early_stop_state *,uint64_t hz,const struct a16_thermal_io *);
