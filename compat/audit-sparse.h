/* SPDX-License-Identifier: MIT */
#pragma once

/* SNAP_AUDIT_SPARSE (opt-in, default 0; cycle.py installed-fresh
 * --audit-sparse): four sampled self-audits that run under the service token
 * re-check 1 in 1024 of their events instead of 1 in 64. The mechanisms they
 * audit are unchanged; only how often the read-only re-derivation runs.
 *
 * Why (installed-fresh-neon-20261021-v2, 994 s, six vCPUs; context.bin decoded
 * with the run's own defines; A16 per-call costs from the per-CPU PPERM fit,
 * the 7.0 ms per-CPU PPERM maximum and host timings at the run's shape):
 *   a. TPRO class-proof hit verification (shadow/sprr-class-fast.h): 6,135
 *      whole-tree walks of ~5,300 tables, ~7 ms each, ~43 s of token hold.
 *      Each stalls every other vCPU that needs the token or the gate; the gate
 *      gives up after 5 ms (15,035 gate timeouts in the run).
 *   b. Kernel refresh reuse-hit verification (kernel_refresh_impl,
 *      sprr_views_verify_all): 12,455 x ~0.7 ms, ~9 s.
 *   c. Exact kernel-variant swap verification (kernel_variant_swap,
 *      sprr_views_verify_cpu): 30,772 x ~0.15 ms, ~4.5 s.
 *   d. PPERM-reuse skip verification (kernel_change_pperm_impl,
 *      sprr_views_verify_cpu): 6,790 x ~0.15 ms, ~1 s.
 * Together ~58 s of the run's 264.6 s token hold; at 1 in 1024 about 3.6 s.
 *
 * Failure modes, written before the code:
 *  1. The audit silently off (a mask of 0 or ~0, a never-true test) or at the
 *     wrong rate. Guard: each site keeps its "x & mask" test with the mask
 *     below; tools/test-audit-sparse.py checks every site's text and that
 *     tools/kernel_ops_perf.py and tools/capture-service-profile.py accept
 *     exactly hits // 1024 with the flag and exactly hits // 64 without.
 *  2. A changed default build. Guard: the default mask is the literal 63 the
 *     sites used; the default monitor for the deployed flag set rebuilds
 *     byte-identical (binary and ELF), and =0 equals absent.
 *  3. Anything other than the cadence changes (what a verification compares,
 *     what a mismatch does, the "first exact swap" verification). Guard: the
 *     same expressions with only the constant replaced (source check); the
 *     variant swap still verifies its first exact swap (exact == 0).
 *  4. Weaker detection, accepted for speed (as SNAP_UPDATE_CHECK_SPARSE): a
 *     monitor bug that leaves a stale class proof or a stale private kernel
 *     copy is found up to 1023 events later instead of 63. In that window a
 *     TPRO grant could rely on a stale "no class 9 kernel leaf" result, or a
 *     vCPU could run on a stale copy. Nothing is ever repaired either way;
 *     a mismatch stays terminal (kernel_view_failed). The invalidation rules,
 *     the exact reuse proof and every identity check still run on every event.
 *  5. The flag doing nothing on a build without the audited paths. Guard: a
 *     static assertion requires SNAP_KERNEL_PPERM_FAST, SNAP_KERNEL_VIEW_REUSE,
 *     SNAP_KERNEL_PPERM_REUSE and SNAP_KERNEL_PPERM_VARIANTS.
 *  6. The leaf-memo full rescan (1 in 64 incremental class walks, ~2.4 ms,
 *     654 in the run) is the only check of the leaf summaries; it is left at
 *     1 in 64 on purpose.
 *  7. Code budget. Guard: the build test checks the reservation. */
#ifndef SNAP_AUDIT_SPARSE
#define SNAP_AUDIT_SPARSE 0
#endif
#if SNAP_AUDIT_SPARSE
#define AUDIT_SAMPLE_MASK 1023
#else
#define AUDIT_SAMPLE_MASK 63
#endif
