/* SPDX-License-Identifier: MIT */
/* SPTM endpoint numbers and return codes: from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* Enter a stock XNU kernelcache at EL1 on silicon that has none of what it
 * expects, and report what it asks for first.
 *
 * Everything the host prepared is already in memory: the rebased image, 16K
 * page tables mapping it at 0xfffffe00_........, and the two handoff structures
 * the entry stub validates (probes/xnuboot.py). This does the parts that can
 * only be done at EL2:
 *
 *   - walk those 16K tables and emit an equivalent 4K translation, because the
 *     hardware cannot walk a 16K granule (docs/FEASIBILITY.md)
 *   - build a stage-2 map covering only what actually exists, so a touch of
 *     anything else is a fault at EL2 with the address in it, rather than a
 *     silent wander
 *   - mark the monitor-call pages and XNU's own exception vectors execute-never
 *     at stage 2, so both a `genter` and a fault XNU takes arrive here
 *   - ERET to the entry point with x0 = 0, x1 and x2 pointing at the handoff
 *
 * The first thing XNU does after setting its vectors is one monitor call with
 * x16 = 0xf. Reaching that is the milestone; everything before it is the boot
 * stub, and everything after is a new endpoint to implement.
 */
#include "shadow.h"
#include "sprr-view.h"
#include "sprr-publish.h"
#include "sprr-reuse.h"
#include "sprr-variants.h"
#include "sprr-class-proof.h"
#include "sprr-private-pages.h"
#include "stage2.h"
#include "dockchannel.h"
#include "idregs.h"
#include "../compat/pauth.h"
#include "../compat/pauth-user.h"
#include "../compat/pauth-domain.h"
#include "../compat/pauth-switch.h"
#include "../compat/pauth-native.h"
#include "../compat/pauth-batch.h"
#include "../compat/pauth-pointer.h"
#include "secondary.h"
#include "../compat/cpu-release.h"
#include "../compat/exception.h"
#include "../compat/panic-state.h"
#include "../compat/clock.h"
#include "../compat/ipi.h"
#include "../compat/cpu.h"
#include "../compat/service-lock.h"
#include "../compat/service-profile.h"
#include "../compat/service-detail.h"
#include "../compat/step-translation.h"
#include "../compat/step-alu.h"
#include "../compat/native-call.h"
#include "../compat/native-writer.h"
#include "../compat/native-writer-debug.h"
#ifndef SNAP_NATIVE_CALLS
#define SNAP_NATIVE_CALLS 0
#endif
#ifndef SNAP_SPTM_HVC_CALLS
#define SNAP_SPTM_HVC_CALLS 0
#endif
_Static_assert(!SNAP_SPTM_HVC_CALLS || SNAP_NATIVE_CALLS,
               "HVC call entry requires the pinned native-call contract");
#define NATIVE_COMPILED_FLAGS (NATIVE_CALL_FLAG | (SNAP_SPTM_HVC_CALLS ? NATIVE_HVC_FLAG : 0))
#ifndef SNAP_NATIVE_WRITER_ADMISSION
#define SNAP_NATIVE_WRITER_ADMISSION 0
#endif
_Static_assert(!SNAP_NATIVE_WRITER_ADMISSION || SNAP_NATIVE_CALLS,
               "writer admission requires the pinned native-call inventory");
#ifndef SNAP_NATIVE_WRITER_BREAKPOINTS
#define SNAP_NATIVE_WRITER_BREAKPOINTS 0
#endif
_Static_assert(!SNAP_NATIVE_WRITER_BREAKPOINTS || SNAP_NATIVE_WRITER_ADMISSION,
               "native writer breakpoints require mapping admission");
#ifndef SNAP_USER_VIEW_BATCH
#define SNAP_USER_VIEW_BATCH 0
#endif
#ifndef SNAP_USER_VIEW_FUSED
#define SNAP_USER_VIEW_FUSED 0
#endif
#ifndef SNAP_USER_PREPARE_FUSED
#define SNAP_USER_PREPARE_FUSED 0
#endif
_Static_assert(!SNAP_USER_PREPARE_FUSED || SNAP_USER_VIEW_FUSED,"fused preparation requires fused views");
#ifndef SNAP_USER_TABLE_READ
#define SNAP_USER_TABLE_READ 0
#endif
_Static_assert(!SNAP_USER_TABLE_READ || SNAP_USER_PREPARE_FUSED,
    "table reader requires transaction-local full user preparation");
#ifndef SNAP_USER_ZERO_GROUP
#define SNAP_USER_ZERO_GROUP 0
#endif
_Static_assert(!SNAP_USER_ZERO_GROUP || SNAP_USER_TABLE_READ,
    "zero groups require bounded immutable source mappings");
_Static_assert(!SNAP_USER_VIEW_FUSED || SNAP_USER_VIEW_BATCH,"fused user views require batch mode");
#ifndef SNAP_USER_VIEW_CACHE
#define SNAP_USER_VIEW_CACHE 0
#endif
#ifndef SNAP_USER_VIEW_VERIFY
#define SNAP_USER_VIEW_VERIFY 0
#endif
#ifndef SNAP_VIEW_TABLE_READ
#define SNAP_VIEW_TABLE_READ 0
#endif
_Static_assert(!SNAP_VIEW_TABLE_READ || (SNAP_USER_VIEW_CACHE && SNAP_USER_VIEW_VERIFY),
    "mapped private sync requires sampled independent user coverage");
#ifndef SNAP_PRIVATE_VIEW_EPOCH
#define SNAP_PRIVATE_VIEW_EPOCH 0
#endif
_Static_assert(!SNAP_PRIVATE_VIEW_EPOCH || (SNAP_USER_VIEW_CACHE && SNAP_USER_VIEW_VERIFY),
               "private provenance requires sampled user coverage proofs");
#ifndef SNAP_USER_ONLY_TLBI
#define SNAP_USER_ONLY_TLBI 0
#endif
#ifndef SNAP_KERNEL_DIRTY_PUBLISH
#define SNAP_KERNEL_DIRTY_PUBLISH 0
#endif
#ifndef SNAP_VIEW_STORE_COMPARE
#define SNAP_VIEW_STORE_COMPARE 0
#endif
_Static_assert(!SNAP_VIEW_STORE_COMPARE || (SNAP_VIEW_TABLE_READ &&
    SNAP_PRIVATE_VIEW_EPOCH && SNAP_KERNEL_DIRTY_PUBLISH),
    "private store comparison requires mapped sync, private provenance and idempotent stores");
#ifndef SNAP_USER_FUSED_COMPARE
#define SNAP_USER_FUSED_COMPARE 0
#endif
/* Skip the per-CPU view rewrite (and its broadcast TLBI) on an EL0/EL1 mode
 * switch whose translated view is provably identical; see user_enter_mode. */
#ifndef SNAP_USER_MODE_SKIP
#define SNAP_USER_MODE_SKIP 0
#endif
/* MDCR_EL2.TDE (software step) also routes guest BRK to EL2. Deliver it to
 * the guest's EL1 vector exactly as hardware without TDE would. */
#ifndef SNAP_GUEST_BRK_REFLECT
#define SNAP_GUEST_BRK_REFLECT 0
#endif
_Static_assert(!SNAP_USER_MODE_SKIP || SNAP_VIEW_STORE_COMPARE,"mode skip verification needs store compare");
_Static_assert(!SNAP_USER_FUSED_COMPARE || (SNAP_VIEW_STORE_COMPARE && SNAP_USER_ZERO_GROUP),
    "fused comparison requires private provenance and full grouped preparation");
/* Exact cross-transaction claims for user view refresh/sync: a per-page write
 * witness over the table arena lets unchanged level3 sources skip their rescan
 * and unchanged private copies skip their recompute; see shadow/sprr-table-memo.h. */
#ifndef SNAP_USER_TREE_MEMO
#define SNAP_USER_TREE_MEMO 0
#endif
_Static_assert(!SNAP_USER_TREE_MEMO || SNAP_USER_FUSED_COMPARE,
    "user tree memo extends the compared grouped refresh and compared cached sync");
#ifndef SNAP_KERNEL_VIEW_REUSE
#define SNAP_KERNEL_VIEW_REUSE 0
#endif
#ifndef SNAP_KERNEL_CLASS_PROOF
#define SNAP_KERNEL_CLASS_PROOF 0
#endif
#ifndef SNAP_STEP_ALU
#define SNAP_STEP_ALU 0
#endif
_Static_assert(!(SNAP_NATIVE_CALLS && SNAP_STEP_ALU),
               "qualify native calls without arithmetic emulation");
#ifndef SNAP_SERVICE_PROFILE
#define SNAP_SERVICE_PROFILE 0
#endif
#ifndef SNAP_SERVICE_DETAIL
#define SNAP_SERVICE_DETAIL 0
#endif
_Static_assert(!SNAP_SERVICE_DETAIL || SNAP_SERVICE_PROFILE,
               "detail timings require owned service intervals");
#ifndef SNAP_STEP_TRANSLATION
#define SNAP_STEP_TRANSLATION 1
#endif
#ifndef SNAP_STEP_TRANSLATION_VERIFY
#define SNAP_STEP_TRANSLATION_VERIFY 0
#endif
#include "../compat/device.h"
#include "../compat/mmio.h"

/* What the host puts in memory for us. Laid out by probes/xnuboot.py; the two
 * sides are checked against each other by the size assertion below. */
#include "../compat/sptm.h"
#include "../compat/sptm-refs.h"
#include "../compat/sptm-dart.h"
#include "../compat/sptm-slide.h"
#include "../compat/sptm-user.h"
#include "../compat/sptm-root.h"
#include "../compat/sptm-root-memo.h"
#include "../compat/sptm-root-policy.h"
#include "../compat/inactive-mirror.h"
#include "../compat/native-select.h"
#include "../shadow/native-view.h"
#include "../shadow/native-shared.h"
#include "../compat/sptm-papt.h"
#include "../compat/txm.h"
#include "../compat/uat.h"
#include "../compat/cputrace.h"
#include "../compat/cpu-runtime.h"
#include "../compat/table-pool.h"
#include "../shadow/root-publish.h"
#ifndef SNAP_ROOT_DIRTY_PUBLISH
#define SNAP_ROOT_DIRTY_PUBLISH 0
#endif
#include "../shadow/user-publish.h"
#ifndef SNAP_USER_DIRTY_PUBLISH
#define SNAP_USER_DIRTY_PUBLISH 0
#endif
_Static_assert(!SNAP_USER_DIRTY_PUBLISH ||
    (SNAP_ROOT_DIRTY_PUBLISH && SNAP_PRIVATE_VIEW_EPOCH && SNAP_USER_VIEW_BATCH),
    "user publication requires tracked writes, private ownership and batch views");
#include "../shadow/txn-publish.h"
/* Transaction-end cache publication from the root dirty bitmap instead of a
 * clean of the whole allocated arena (UPDATE_DISJOINT/REGION, kernel
 * UNMAP_REGION, SLIDE_REGION, aperture retypes). Sentinel-checked. */
#ifndef SNAP_TXN_DIRTY_PUBLISH
#define SNAP_TXN_DIRTY_PUBLISH 0
#endif
_Static_assert(!SNAP_TXN_DIRTY_PUBLISH || SNAP_ROOT_DIRTY_PUBLISH,
    "transaction publication shares the audited root dirty bitmap");
/* Keep the exact kernel-view snapshot valid across a PPERM transaction that
 * began current; skip that CPU's kernel sync when the new value cannot change
 * a kernel descriptor. Sampled read-only verification of every skipped view. */
#ifndef SNAP_KERNEL_PPERM_REUSE
#define SNAP_KERNEL_PPERM_REUSE 0
#endif
_Static_assert(!SNAP_KERNEL_PPERM_REUSE || (SNAP_KERNEL_VIEW_REUSE && SNAP_KERNEL_DIRTY_PUBLISH),
    "PPERM reuse extends the exact kernel snapshot and needs publication bits");
/* User-root UPDATE_DISJOINT touches no kernel canonical table, kernel copy or
 * PPERM: skip its redundant kernel refresh (publication and the all-VMID TLBI
 * are kept). Sampled read-only verification of all six kernel views. */
#ifndef SNAP_USER_UPDATE_KERNEL_SKIP
#define SNAP_USER_UPDATE_KERNEL_SKIP 0
#endif
_Static_assert(!SNAP_USER_UPDATE_KERNEL_SKIP || SNAP_USER_ONLY_TLBI,
    "user-update kernel skip extends the qualified user-only invalidation contract");
/* SNAP_UPDATE_CHECK_SPARSE: the skip's read-only re-derivation of all six
 * kernel copies runs 1 in 1024 skips instead of 1 in 64. A weaker audit
 * (opt-in): a stale copy is found later, never repaired; the skip itself is
 * unchanged. tools/kernel_ops_perf.py checks verified == skipped // 1024. */
#ifndef SNAP_UPDATE_CHECK_SPARSE
#define SNAP_UPDATE_CHECK_SPARSE 0
#endif
_Static_assert(!SNAP_UPDATE_CHECK_SPARSE || SNAP_USER_UPDATE_KERNEL_SKIP,
    "the sparse check samples the user-update kernel skip");
/* Root installation ends with its own all-VMID TLBI before the CPU can run
 * EL1/EL0 again; earlier invalidations of this CPU's private copies inside the
 * same installation are folded into it (issued anyway on any failure path). */
#ifndef SNAP_INSTALL_TLBI_DEFER
#define SNAP_INSTALL_TLBI_DEFER 0
#endif
/* Class-proof walks map each canonical table once (bounded span check) and
 * test eight-word zero groups; every descriptor is still loaded and decided
 * identically. Sampled hits still re-walk through the original word reader. */
#ifndef SNAP_CLASS_PROOF_MAPPED
#define SNAP_CLASS_PROOF_MAPPED 0
#endif
/* Reuse unchanged L3 class summaries using the existing table write clock.
 * Whole-tree coverage, structure checks and sampled word re-walks remain. */
#ifndef SNAP_CLASS_LEAF_MEMO
#define SNAP_CLASS_LEAF_MEMO 0
#endif
_Static_assert(!SNAP_CLASS_LEAF_MEMO ||
    (SNAP_CLASS_PROOF_MAPPED && SNAP_KERNEL_CLASS_PROOF && SNAP_USER_TREE_MEMO),
    "class leaf reuse requires mapped whole proofs and table write generations");
/* The TPRO preflight's kernel class proof made incremental: a miss reuses the
 * L3 summaries of tables whose write generation is unchanged and rescans the
 * rest; a sampled hit re-walks every table through one refusing mapping
 * instead of one callback per word (shadow/sprr-class-fast.h, which lists
 * the measurement and failure modes; tools/test-kernel-pperm-fast.py). */
#ifndef SNAP_KERNEL_PPERM_FAST
#define SNAP_KERNEL_PPERM_FAST 0
#endif
_Static_assert(!SNAP_KERNEL_PPERM_FAST ||
    (SNAP_CLASS_PROOF_MAPPED && SNAP_KERNEL_CLASS_PROOF && SNAP_USER_TREE_MEMO &&
     !SNAP_CLASS_LEAF_MEMO),
    "the fast class proof needs mapped whole proofs and table write generations, "
    "and replaces the leaf-memo option");
#if SNAP_KERNEL_PPERM_FAST
#include "sprr-class-fast.h"
#endif
/* SWITCH_ROOT validates the incoming user tree with aligned 64-bit descriptor
 * loads instead of eight volatile byte loads each; 1 in 64 validations repeats
 * the byte walk and must agree (compat/sptm-root.c). */
#ifndef SNAP_ROOT_VALIDATE_WORDS
#define SNAP_ROOT_VALIDATE_WORDS 0
#endif
/* A cache-hit SWITCH_ROOT reuses level-3 verdicts retained since their table
 * page, its frame record and every referenced mapped frame's type last
 * changed (compat/sptm-root-memo.h). Root, level-2, child records and links
 * are still checked on every switch; builds validate everything; the sampled
 * byte walk above runs without the memo and must agree. */
#ifndef SNAP_ROOT_VALIDATE_MEMO
#define SNAP_ROOT_VALIDATE_MEMO 0
#endif
_Static_assert(!SNAP_ROOT_VALIDATE_MEMO || SNAP_ROOT_VALIDATE_WORDS,
    "retained root verdicts require the sampled reference walk");
/* DART table verdicts (compat/sptm-dart-memo.h, docs/DART-MEMO-20261019.md):
 * MAP, UNMAP, MAP_TABLE and DMA translation skip the per-table scan for a
 * table that passed it with the same refs and no published store since;
 * sptm_publish is the write witness, every 64th hit is re-scanned. Kept in
 * root_ext, reported below the thermal block (OUT_DART_MEMO). */
#ifndef SNAP_DART_MEMO
#define SNAP_DART_MEMO 0
#endif
#if SNAP_DART_MEMO
#include "../compat/sptm-dart-memo.h"
_Static_assert(SNAP_ROOT_CACHE_WIDE, "the DART memo lives in the wide cache's arena pages");
#endif
/* MAP_PAGE and MAP_TABLE on a cached user root that no CPU has installed keep
 * its shadow in step with the guest tree instead of discarding it for a
 * rebuild on the next switch (compat/inactive-mirror.h). Fresh leaves use the
 * active root's prepare/commit pair, bounded per slot; TPRO leaves, a spent
 * budget, uncached roots and CONFIGURE_ROOT still invalidate. */
#ifndef SNAP_INACTIVE_MIRROR
#define SNAP_INACTIVE_MIRROR 0
#endif
/* Native page tables, phase 1 (docs/NATIVE-TABLES-DESIGN-20260929.md): a user
 * root runs on two permission-variant trees (TPRO read-only / writable) that
 * every CPU shares, each with its own hardware ASID, kept exact per canonical
 * store (shadow/native-view.h). SWITCH_ROOT, UPERM and TPRO PPERM writes and
 * EL0/EL1 boundaries select a variant (compat/native-select.h); user commits
 * invalidate exactly their 4K entries in every VMID. Proofs run sampled, 1 in
 * 2^SNAP_NATIVE_AUDIT_SHIFT (0: every time). */
#ifndef SNAP_NATIVE_TABLES
#define SNAP_NATIVE_TABLES 0
#endif
#ifndef SNAP_NATIVE_AUDIT_SHIFT
#define SNAP_NATIVE_AUDIT_SHIFT 6
#endif
_Static_assert(SNAP_NATIVE_AUDIT_SHIFT<32,"native audit sample");
/* Native page tables, phase 3 (SNAP_NATIVE_SHARED): a 16K user root links
 * each nested shared-region level-3 table to one shared set of 4K level-3
 * tables (shadow/native-shared.h) instead of copying its leaves into every
 * cached root. Builds, NEST and UNNEST link and unlink; a shared-region leaf
 * change is written once, for every nesting root and variant. */
#ifndef SNAP_NATIVE_SHARED
#define SNAP_NATIVE_SHARED 0
#endif
_Static_assert(!SNAP_NATIVE_SHARED || SNAP_NATIVE_TABLES,"shared groups need native page tables");
/* The table-pool allocation domain of every shared group page. */
#define NATIVE_SHARED_OWNER 200u
/* SNAP_NATIVE_LIVE: a new 16K user root is cached from its constructor with an
 * empty tree, so every SPTM call keeps it exact from its first mapping and its
 * first SWITCH_ROOT needs no build; an inactive root mirrors every MAP_PAGE
 * (no per-install budget, TPRO included: variant copies are kept per store). */
#ifndef SNAP_NATIVE_LIVE
#define SNAP_NATIVE_LIVE 0
#endif
_Static_assert(!SNAP_NATIVE_LIVE || SNAP_NATIVE_SHARED,"live roots need shared groups");
/* SNAP_ROOT_MISS_FAST (compat/root-miss.h): a full user-root cache gives up
 * the least recently installed inactive root (root_stamp) instead of the next
 * one round robin, and a miss's two walks answer the nested SHARED level-3
 * tables a linked build links from the retained verdicts above, as a hit
 * does; every copied table is still scanned in full. */
#ifndef SNAP_ROOT_MISS_FAST
#define SNAP_ROOT_MISS_FAST 0
#endif
_Static_assert(!SNAP_ROOT_MISS_FAST || (SNAP_ROOT_VALIDATE_MEMO && SNAP_ROOT_VALIDATE_WORDS &&
               SNAP_NATIVE_SHARED),
    "miss-path verdicts need their write witness, the sampled walk and linked builds");
/* SNAP_UPDATE_DISJOINT_FAST (compat/update-fast.h): a user leaf update whose
 * old leaf has AF clear (never cacheable: user regimes run with TCR.HA clear)
 * skips its TLBI; the sampled kernel-copy verifications check all six CPUs in
 * one pass with sprr_views_verify_cpu's exact verdict. */
#ifndef SNAP_UPDATE_DISJOINT_FAST
#define SNAP_UPDATE_DISJOINT_FAST 0
#endif
_Static_assert(!SNAP_UPDATE_DISJOINT_FAST || SNAP_NATIVE_TABLES,
    "the skipped invalidation is native_tlbi_range's");
#if SNAP_UPDATE_DISJOINT_FAST
#include "../compat/update-fast.h"
#endif
/* SNAP_ROOT_CACHE_WIDE (compat/root-wide.h): 192 cached user roots instead of
 * 64. Every slot's state lives in monitor arena pages taken at setup
 * (struct root_ext); struct context keeps its define-free 64-slot fields,
 * refreshed from the live state when the run stops (root_ext_mirror). */
#ifndef SNAP_ROOT_CACHE_WIDE
#define SNAP_ROOT_CACHE_WIDE 0
#endif
_Static_assert(!SNAP_ROOT_CACHE_WIDE || SNAP_NATIVE_SHARED,
    "wide link bits are the native-shared groups'");
#if SNAP_ROOT_CACHE_WIDE
#include "../compat/root-wide.h"
#endif
/* SNAP_USER_HW_WALK (compat/user-hw-walk.h, docs/USER-HW-WALK-20261017.md):
 * a 4K (format 1, SNAP_KERNEL_USER_4K) user root runs on its own guest
 * tables -- an UMPRR18 root on two monitor copies of the paths to its TPRO
 * leaves -- with its own hardware ASIDs: SWITCH_ROOT builds, caches and walks
 * nothing, and every SPTM call keeps the copies exact and invalidates what it
 * changed. 16K roots keep the shadow path unchanged. SNAP_USER_HW_WALK_S2RO
 * (on with it unless set to 0) keeps every SPTM page-table frame read-only at
 * stage 2 while typed, so the guest cannot edit a hardware-walked tree behind
 * the SPTM's validation. */
#ifndef SNAP_USER_HW_WALK
#define SNAP_USER_HW_WALK 0
#endif
#ifndef SNAP_USER_HW_WALK_S2RO
#define SNAP_USER_HW_WALK_S2RO SNAP_USER_HW_WALK
#endif
_Static_assert(!SNAP_USER_HW_WALK || (SNAP_NATIVE_TABLES && SNAP_ROOT_DIRTY_PUBLISH),
    "hardware-walk roots use the native per-CPU variant selection, TLBI and dirty-page flush");
_Static_assert(!SNAP_USER_HW_WALK_S2RO || SNAP_USER_HW_WALK,
    "stage-2 table protection is part of the hardware walk");
#if SNAP_USER_HW_WALK
#include "../compat/user-hw-walk.h"
_Static_assert(HW_WALK_OWNER!=NATIVE_SHARED_OWNER && HW_WALK_OWNER>SPTM_ROOT_CACHE &&
               HW_WALK_OWNER<TABLE_POOL_FREE,"copy pages have their own table-pool domain");
#define HW_WALK_PAGES ((sizeof(struct hw_walk_state)+4095)/4096)
#endif
/* SNAP_S2_FAULT_RETRY (compat/s2-fault-retry.h): a stage-2 translation fault
 * whose hardware IPA (HPFAR) is guest RAM this CPU's tree maps is snapshotted
 * and retried, bounded, instead of stopping the run; every stage-2 stop
 * carries HPFAR_EL2 in its terminal event. SNAP_S2_FAULT_RETRY_STAGE1 also
 * retries one whose HPFAR IPA is not mapped but whose stage-1 re-walk's is.
 * Off: nothing changes. */
#ifndef SNAP_S2_FAULT_RETRY
#define SNAP_S2_FAULT_RETRY 0
#endif
#ifndef SNAP_S2_FAULT_RETRY_STAGE1
#define SNAP_S2_FAULT_RETRY_STAGE1 0
#endif
_Static_assert(!SNAP_S2_FAULT_RETRY_STAGE1 || SNAP_S2_FAULT_RETRY,
    "the STAGE1 retry is part of the stage-2 fault retry");
#if SNAP_S2_FAULT_RETRY
#include "../compat/s2-fault-retry.h"
_Static_assert(S2_RETRY_CPUS==GUEST_CPU_COUNT,"one retry bound per vCPU");
#endif
/* SNAP_IDREG_MMFR3: every vCPU also records ID_AA64MMFR3_EL1 (S1PIE [11:8],
 * S1POE [19:16]) and ID_AA64MMFR1_EL1 at setup, one EV_OTHER event each
 * (probes/run.py "permission features"). Off: nothing changes. */
#ifndef SNAP_IDREG_MMFR3
#define SNAP_IDREG_MMFR3 0
#endif
/* Root installation cleans its noted pages with one barrier for the whole
 * flush (the installation sequence's own leading dsb ish) instead of one
 * dsb ish per page. */
#ifndef SNAP_ROOT_PUBLISH_BATCH_DSB
#define SNAP_ROOT_PUBLISH_BATCH_DSB 0
#endif
_Static_assert(!SNAP_ROOT_PUBLISH_BATCH_DSB || SNAP_ROOT_DIRTY_PUBLISH,
    "batched root publication applies to the dirty root flush");
_Static_assert(!SNAP_CLASS_PROOF_MAPPED || SNAP_KERNEL_CLASS_PROOF,
    "mapped class walks replace only the cached proof's full walk");
/* Emulate traps that touch only the trapping vCPU without the service lock:
 * PACGA, the modeled PAC key registers, guest counter reads, ESR/FAR reads and
 * the ignored context-switch/recount registers (compat/fast-trap.h has the
 * per-class shared-state proof). Declines to the locked path on any stop,
 * failure, step, guard, probe or pending secondary launch. */
#ifndef SNAP_FAST_VCPU_TRAPS
#define SNAP_FAST_VCPU_TRAPS 0
#endif
/* Diagnostic: per-vCPU counts of trapped system registers by encoding and
 * direction (locked and fast alike), for profiling the remaining traps. */
#ifndef SNAP_SYSREG_CENSUS
#define SNAP_SYSREG_CENSUS 0
#endif
/* CNTV_TVAL writes that keep the timer's synced interrupt line, applied without
 * the lock and rearmed by timer_arm; and the ACC idle-poll read
 * (compat/fast-mmio.h) answered without it (docs/FAST-TRAP-BATCH2-20261016.md). */
#ifndef SNAP_FAST_TIMER_WRITE
#define SNAP_FAST_TIMER_WRITE 0
#endif
#ifndef SNAP_FAST_IDLE_POLL
#define SNAP_FAST_IDLE_POLL 0
#endif
_Static_assert(!(SNAP_FAST_TIMER_WRITE || SNAP_FAST_IDLE_POLL) || SNAP_FAST_VCPU_TRAPS,
               "the timer-write and idle-poll paths use the fast-trap admission and counters");
/* A bit-8 PPERM flip exchanges this CPU's kernel copy column with its variant
 * column and installs the new root in TTBR1 (shadow/sprr-variants.h,
 * docs/KERNEL-PPERM-VARIANTS-20261016.md). */
#ifndef SNAP_KERNEL_PPERM_VARIANTS
#define SNAP_KERNEL_PPERM_VARIANTS 0
#endif
_Static_assert(!SNAP_KERNEL_PPERM_VARIANTS || (SNAP_NATIVE_TABLES && SNAP_KERNEL_PPERM_REUSE &&
               SNAP_KERNEL_VIEW_REUSE && SNAP_KERNEL_DIRTY_PUBLISH),
               "variants need the native local flush, the snapshot proof and dirty publication");
/* SNAP_AUDIT_SPARSE (compat/audit-sparse.h, which lists the measurement and
 * the failure modes): the TPRO class-proof hit verification, the kernel
 * refresh's reuse-hit verification, the exact kernel-variant swap
 * verification and the PPERM-reuse skip verification sample 1 in 1024 events
 * instead of 1 in 64 (AUDIT_SAMPLE_MASK). A weaker audit, accepted for speed;
 * every audited mechanism is unchanged (tools/test-audit-sparse.py). */
#include "../compat/audit-sparse.h"
_Static_assert(!SNAP_AUDIT_SPARSE ||
    (SNAP_KERNEL_PPERM_FAST && SNAP_KERNEL_VIEW_REUSE && SNAP_KERNEL_PPERM_REUSE &&
     SNAP_KERNEL_PPERM_VARIANTS),
    "the sparse audits sample the fast class proof, the kernel view reuse proof, "
    "the PPERM reuse skip and the kernel PPERM variants");
/* XNU's vector slot starts with an unconditional B out of its page: perform
 * it instead of opening the execute-never vector page for one single step, so
 * a guest exception costs no step exit, stage-2 write or broadcast TLBI
 * (compat/fast-vector.h). A slot holding anything else keeps the step. */
#ifndef SNAP_VECTOR_BRANCH
#define SNAP_VECTOR_BRANCH 0
#endif
/* Take the native-call exception snapshot at the ERET exit instead of at the
 * hardware breakpoint on exception_return's SPSR write (native writer site 5),
 * whose comparator is left unarmed. Prepare proves that the code from that
 * write to the kernel's only ERET is straight-line, forward-only, call-free
 * and exception-free (native_writer_return_window), so no native call can
 * restore a stale snapshot in between. The other five groups keep theirs. */
#ifndef SNAP_ERET_SNAPSHOT
#define SNAP_ERET_SNAPSHOT 0
#endif
_Static_assert(!SNAP_ERET_SNAPSHOT || SNAP_NATIVE_WRITER_BREAKPOINTS,
               "the ERET snapshot replaces one of the writer breakpoints");
/* The vector entry and the ERET of the common exception classes without the
 * service lock (compat/fast-vector.h has the per-class shared-state proof):
 * kernel page faults, EL0 SVCs and page faults and the virtual timer/device
 * interrupts on entry; kernel returns and user returns on exit. A crossing
 * between EL0 and EL1 is lock-free only under SNAP_NATIVE_TABLES, through
 * native_cross; otherwise it keeps the locked view switch. Declines to the
 * locked path on any stop, failure, step, guard, probe, pending secondary
 * launch, SPTM call or other class. */
#ifndef SNAP_FAST_CROSSINGS
#define SNAP_FAST_CROSSINGS 0
#endif
_Static_assert(!SNAP_FAST_CROSSINGS || (SNAP_FAST_VCPU_TRAPS && SNAP_VECTOR_BRANCH),
               "lock-free crossings share the fast-trap admission and never open the vector page");
/* The two EL0 IMPDEF reads this silicon cannot execute (SPRR_UPERM and the
 * ordered counter alias) emulated in the lock-free crossing path, exactly as
 * user_sysreg_access does under the lock; every other EL0 EC 0 entry, the
 * UPERM write included, stays locked (compat/fast-vector.h fast_el0_sysreg).
 * exit_profile.cpu[].el0 counts the outcomes. */
#ifndef SNAP_FAST_EL0_SYSREG
#define SNAP_FAST_EL0_SYSREG 0
#endif
_Static_assert(!SNAP_FAST_EL0_SYSREG || (SNAP_FAST_CROSSINGS && SNAP_NATIVE_TABLES),
               "the EL0 emulation is a lock-free crossing class; without native tables EL0 entries decline");
#define FAST_CROSS_EL0_SYSREG SNAP_FAST_EL0_SYSREG
/* The kernel's PACGA without a trap (docs/SPEED-BATCH4-20261020.md): each
 * vCPU keeps the guest kernel's GA key (guest_apga, the modeled APGAKey
 * writes) in APGAKey while EL1 runs and sets HCR_EL2.API for EL1, so PACGA
 * runs natively under exactly the key generic_sign would load. The kernel's
 * address-key enables stay masked, so every other PAC instruction still
 * returns its input; EL0 keeps its per-process bank (compat/pauth-switch.S).
 * The host APGAKey is saved in the private PAC bank and restored on each
 * CPU's terminal path. */
#ifndef SNAP_NATIVE_PACGA
#define SNAP_NATIVE_PACGA 0
#endif
/* The EL0 reads fast_el0_sysreg answers (SPRR_UPERM, the ordered counter
 * alias) return to EL0 with the process's PAC bank still installed: no
 * pauth_switch_leave on the entry, no pauth_switch_enter on the return, since
 * no EL1 instruction runs in between and the answer needs no other bank.
 * sync_lower's pauth_switch_live leaves the bank live only for that entry's
 * syndrome; el0_live_trap re-checks the exact slot, runs fast_crossing, and
 * restores the bank (pauth_switch_leave) before any other C when it declines;
 * xnuboot_pauth_resume refuses to reach EL1 with the bank live. */
#ifndef SNAP_PAUTH_EL0_LIVE
#define SNAP_PAUTH_EL0_LIVE 0
#endif
#if SNAP_PAUTH_EL0_LIVE && !(SNAP_FAST_CROSSINGS && SNAP_FAST_EL0_SYSREG)
#error "SNAP_PAUTH_EL0_LIVE keeps the bank live only for SNAP_FAST_EL0_SYSREG's lock-free EL0 reads"
#endif
#if SNAP_PAUTH_EL0_LIVE && defined(SNAP_PAUTH_FIXED_KEYS) && SNAP_PAUTH_FIXED_KEYS
#error "SNAP_PAUTH_FIXED_KEYS removes the bank switch; review before combining it with SNAP_PAUTH_EL0_LIVE"
#endif
/* Batch 6 (compat/el0-memo.h): fast_el0_word answers the EL0 read's fetch from
 * a per-vCPU memo of the PC page's translation, kept only from an agreeing
 * double read and trusted for addresses only: each hit re-reads every
 * descriptor both walks read, the code frame's type and the word, and
 * fast_el0_sysreg then skips its repeat read (FAST_EL0_FETCH_PROVEN). Every
 * root install on a vCPU makes its memo stale. The user return derives its
 * PAC bank through a 128-entry second level behind the 8-entry memo, which
 * reuses each key's constant first block (compat/pauth-domain.h); both levels
 * belong to the domain epoch xnuboot_prepare bumps. State in root_ext. */
#ifndef SNAP_EL0_MEMO
#define SNAP_EL0_MEMO 0
#endif
#if SNAP_EL0_MEMO && !(SNAP_PAUTH_EL0_LIVE && SNAP_ROOT_CACHE_WIDE)
#error "SNAP_EL0_MEMO memoizes SNAP_PAUTH_EL0_LIVE's lock-free EL0 reads and keeps its state in SNAP_ROOT_CACHE_WIDE's arena pages"
#endif
#if SNAP_EL0_MEMO
#include "../compat/el0-memo.h"
#endif
#define FAST_CROSS_EL0_MEMO SNAP_EL0_MEMO
/* Instrumentation (rides along, no trap removed): lock wait and hold of the
 * locked instruction aborts by sub-class (vector entry, each EL0 emulation,
 * each SPTM endpoint; compat/service-profile.h service_sub_*), and the
 * CNTPCT round trip of every lock-free exit by class (compat/perf-state.h
 * fast_exit_charge). Both live in exit_profile. */
#ifndef SNAP_SERVICE_SUBCLASS
#define SNAP_SERVICE_SUBCLASS 0
#endif
_Static_assert(!SNAP_SERVICE_SUBCLASS || SNAP_SERVICE_PROFILE,
               "sub-classes refine the service profile's EC 0x20 bucket");
/* Clear HCR_EL2.TWE: the guest's WFE runs natively and the hardware event
 * stream wakes it (CNTKCTL_EL1.EVNTEN as the guest sets it, EVNTI rescaled
 * from the guest to the host counter rate, clock_event_host_control),
 * instead of a trap that polls for the emulated event under the lock. */
#ifndef SNAP_NATIVE_WFE
#define SNAP_NATIVE_WFE 0
#endif
/* SNAP_EL0_WFE: SCTLR_EL1.nTWE (bit 18) in the SCTLR_EL1 this monitor
 * installs, as 26A428's SPTM installs it for XNU's regime (sptm.t8140 boot:
 * MOVK x0 = 0x12001010fc14793d, MSR SCTLR_EL1). Without it every EL0 WFE or
 * WFET traps to EL1, where XNU's handle_wf_trap (sleh.c:2474) raises
 * EXC_BAD_INSTRUCTION, a SIGILL. libdispatch waits for a racing enqueuer with
 * LDXR/WFE (_dispatch_wait_for_enqueuer+12), so any dispatch process can die
 * of it; launchd did in installed-fresh-20261017-v41, -20261019-v88,
 * -20261020-v16 and -desktop-20261021-v1 (initproc exited, subcode 0x4).
 * With SNAP_NATIVE_WFE (HCR_EL2.TWE clear) EL0 WFE then waits natively like
 * EL1's: SEV, a cleared exclusive monitor, the rescaled event stream or any
 * interrupt (the EL2 tick included) wakes it. Without it the WFE traps to EL2,
 * where the trapped-WFE branch answers every origin (clock_wfe, ELR+4) and
 * resume_lower reloads the EL0 PAC bank. nTWI stays clear: XNU traps EL0 WFI
 * on Apple silicon too. The readback refuses at preparation (-26). */
#ifndef SNAP_EL0_WFE
#define SNAP_EL0_WFE 0
#endif
/* SNAP_EL0_CACHE_MAINT: SCTLR_EL1.UCI (bit 26), the other EL0 permission
 * SPTM's value grants and the installed one lacks. Without it EL0 DC CVAU,
 * DC CVAC, DC CIVAC, DC CVAP, DC CVADP and IC IVAU trap to EL1 as EC 0x18,
 * which XNU's handle_msr_trap also turns into SIGILL. 26A428's shared cache
 * has one such EL0 instruction: IC IVAU in sys_icache_invalidate
 * (libsystem_platform), which JITs and code loaders call. Native: the
 * hardware checks translation and permission and reports faults to XNU as
 * ordinary EL0 data aborts with CM set. Separate from SNAP_EL0_WFE so either
 * can be withdrawn alone. */
#ifndef SNAP_EL0_CACHE_MAINT
#define SNAP_EL0_CACHE_MAINT 0
#endif
#define EL0_SCTLR_GRANTS ((SNAP_EL0_WFE ? (1UL << 18) : 0UL) | \
                          (SNAP_EL0_CACHE_MAINT ? (1UL << 26) : 0UL))
/* A monitor-only EL2 timer tick (the 1 ms IPI poll, the run budget, the host
 * stop poll) that interrupted an idle guest WFI in const-sealed kernel text,
 * with nothing to deliver and the next tick armed within the poll, returns to
 * the WFI instead of WFI+4: XNU's idle exit and re-entry do not run for a wake
 * that brought nothing (compat/wfi-resume.h). perf.fast[cpu].wfi counts it. */
#ifndef SNAP_WFI_RESUME
#define SNAP_WFI_RESUME 0
#endif
#if SNAP_WFI_RESUME
#include "../compat/wfi-resume.h"
#endif
/* vCPU 0's tick, too, without the token while none of its own duties (the
 * host poll, the thermal sample, the GPU tick) is due, with a locked tick at
 * least every FAST_IRQ_CPU0_LOCKED_MS (SNAP_FAST_TIMER_IRQ below;
 * docs/SPEED-BATCH4-20261020.md). */
#ifndef SNAP_FAST_TIMER_IRQ_CPU0
#define SNAP_FAST_TIMER_IRQ_CPU0 0
#endif
#define FAST_IRQ_CPU0 SNAP_FAST_TIMER_IRQ_CPU0
/* The EL2 timer tick of vCPUs 1-5 (the 1 ms IPI poll, the guest timer) without
 * the service token: this vCPU's timer, lines, re-arm, EOI and WFI decision.
 * vCPU 0, any other interrupt, a due or unsynced device deadline, a latched
 * reset, a due budget or early stop and every fast-trap admission decline take
 * the locked tick (compat/fast-timer-irq.h). root_ext->fast_irq[cpu] counts
 * the outcomes (the context's last page has no room), reported after the
 * exit-profile records (OUT_FAST_IRQ). */
#ifndef SNAP_FAST_TIMER_IRQ
#define SNAP_FAST_TIMER_IRQ 0
#endif
#if SNAP_FAST_TIMER_IRQ
#include "../compat/fast-timer-irq.h"
_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE && SNAP_SERVICE_SUBCLASS,
               "the lock-free tick uses the fast-trap admission, counts in the wide cache's arena pages "
               "and reports after the exit profile");
/* wfi_resume also runs in the lock-free tick: words other CPUs write under
 * the token are read atomically there. */
#define WFI_SHARED(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#else
#define WFI_SHARED(x) (x)
#endif
_Static_assert(!SNAP_FAST_TIMER_IRQ_CPU0 || SNAP_FAST_TIMER_IRQ,
               "vCPU 0's quiet tick is the secondaries' lock-free tick");
/* The Apple IPI registers (IPI_RR_LOCAL/GLOBAL, IPI_SR) without the service
 * token: guest_ipi_route's decision with atomic posts and acknowledgements
 * (compat/fast-ipi.h; compat/ipi.c's locked ones match under the define), for
 * a CPU the fast-trap admission accepts. root_ext->fast_ipi[cpu] counts the
 * outcomes, reported just below the thermal block (OUT_FAST_IPI). */
#ifndef SNAP_FAST_IPI
#define SNAP_FAST_IPI 0
#endif
#if SNAP_FAST_IPI
#include "../compat/fast-ipi.h"
_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE,
               "the lock-free IPI registers use the fast-trap admission and count in the wide cache's arena pages");
#endif
/* Fewer and cheaper lock-free system-register exits (compat/lean-trap.h).
 * 1: after an ESR/FAR/PMC read the lock-free path also emulates the adjacent
 * MRS it answers (one trap per FAR/ESR or PMC0/PMC1 pair), the counter
 * conversion has no division, and only PACGA reads the PAC ID registers.
 * 2: also FEAT_FGT in place of HCR_EL2.TVM/TRVM on each CPU whose FGT
 * registers read back, so ESR_EL1/FAR_EL1 reads and CONTEXTIDR_EL1 writes run
 * natively (needs SCR_EL3.FGTEn; unrecorded). root_ext->lean[cpu] holds the
 * saved host values; one EV_OTHER record (pc 3) per vCPU gives the outcome. */
#ifndef SNAP_LEAN_TRAPS
#define SNAP_LEAN_TRAPS 0
#endif
#if SNAP_LEAN_TRAPS
#include "../compat/lean-trap.h"
_Static_assert(SNAP_LEAN_TRAPS == 1 || SNAP_LEAN_TRAPS == 2, "SNAP_LEAN_TRAPS is 1 or 2");
_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE,
               "lean traps extend the fast-trap path and keep their state in the wide cache's arena pages");
#endif
/* vCPU 0 on a physical CPU other than q1n1's, chosen by the host (secondary
 * configuration mask bit 0), so all six vCPUs share one cluster that is not
 * q1n1's: the A16's Prime cluster 1 (compat/boot-relocate.h). Off, the code is
 * absent and bit 0 is refused as before. */
#ifndef SNAP_BOOT_RELOCATE
#define SNAP_BOOT_RELOCATE 0
#endif
#if SNAP_BOOT_RELOCATE
#include "../compat/boot-relocate.h"
#endif
/* ADRENO_GUEST_UNMAP also subtracts the leaves it clears from XNU's IOMMU
 * table count, as t8110dart_unmap would (compat/dart-wiredcnt.h): the kext's
 * unwire/rewire otherwise overflows it (installed-fresh-20261017-v29). */
#ifndef SNAP_DART_WIREDCNT
#define SNAP_DART_WIREDCNT 0
#endif
#if SNAP_DART_WIREDCNT
#include "../compat/dart-wiredcnt.h"
#endif
/* The built-in keyboard's GENI I2C page as Device-nGnRE passthrough for the
 * SnapI2CHID kext, from struct i2c_input_params appended to struct params
 * (compat/i2c-input.h, probes/i2cinput.py; cycle.py installed-fresh --input). */
#ifndef SNAP_I2C_INPUT
#define SNAP_I2C_INPUT 0
#endif
#if SNAP_I2C_INPUT
#include "../compat/i2c-input.h"
#endif
/* The QCC2072 Wi-Fi endpoint (BAR0, BAR2, its ECAM page read-only) and its
 * 64 MiB DMA arena and read-only control page for the SnapintoshQCC2072 kext,
 * from struct qcc2072_wifi_params appended after struct params
 * (compat/qcc2072-wifi.h, probes/qcc2072wifi.py; installed-fresh --qcc2072-wifi). */
#ifndef SNAP_QCC2072_WIFI
#define SNAP_QCC2072_WIFI 0
#endif
#if SNAP_QCC2072_WIFI
#include "../compat/qcc2072-wifi.h"
#endif
/* The eDP interface's timing engine page (DPU INTF_5) as read-only Device-nGnRE passthrough for the AdrenoDisplay
 * kext's beam (-DADRENO_BEAM=1), from struct display_timing_params appended after struct params and, when built in,
 * the QCC2072 block (compat/display-timing.h, probes/displaytiming.py; installed-fresh --present-beam). */
#ifndef SNAP_DISPLAY_TIMING
#define SNAP_DISPLAY_TIMING 0
#endif
#if SNAP_DISPLAY_TIMING
#include "../compat/display-timing.h"
#define SNAP_DISPLAY_TIMING_ROWS DISPLAY_TIMING_STAGE2_MAX
#else
#define SNAP_DISPLAY_TIMING_ROWS 0
#endif
/* NEST_REGION and UNNEST_REGION answer nested shared level-3 tables from the
 * SWITCH_ROOT memo's retained verdicts (or scan each once), and UNMAP_TABLE of
 * an empty level-3 table proves both trees empty table by table
 * (compat/nest-fast.h, docs/TOKEN-COSTS-20261018.md). */
#ifndef SNAP_NEST_FAST
#define SNAP_NEST_FAST 0
#endif
#ifndef SNAP_DETACH_FAST
#define SNAP_DETACH_FAST 0
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "../compat/nest-fast.h"
_Static_assert(!SNAP_NEST_FAST || (SNAP_ROOT_VALIDATE_MEMO && SNAP_ROOT_VALIDATE_WORDS && SNAP_NATIVE_SHARED),
    "nest verdicts are the SWITCH_ROOT memo's: its write witness, its sampled walk, linked groups");
_Static_assert(SNAP_ROOT_CACHE_WIDE,"the nest-fast counters live in the wide cache's arena pages");
#endif
/* UNNEST_REGION on 4K (format 1) user roots, the kernel-user-4k route's,
 * answers nested shared tables and their leaf counts from the same memo
 * (compat/nest-fast.h 3, docs/UNNEST-4K-FAST-20261020.md). */
#ifndef SNAP_UNNEST_4K_FAST
#define SNAP_UNNEST_4K_FAST 0
#endif
#if SNAP_UNNEST_4K_FAST && !SNAP_NEST_FAST
#error "SNAP_UNNEST_4K_FAST extends SNAP_NEST_FAST's UNNEST answer: build with SNAP_NEST_FAST"
#endif
/* TXM35/36/37 and USER_ROOT constructors find root records through an index
 * kept at every frame-type commit instead of scanning the whole frame map
 * (compat/root-index.h, docs/TOKEN-COSTS-20261018.md). */
#ifndef SNAP_ROOT_INDEX
#define SNAP_ROOT_INDEX 0
#endif
#if SNAP_ROOT_INDEX
#include "../compat/root-index.h"
_Static_assert(SNAP_ROOT_CACHE_WIDE,"the root index lives in the wide cache's arena pages");
#endif
/* call_other split by what the native call was, and a converted call that
 * waits out a long token hold on the gate instead of declining after 2^16
 * yields (compat/token-costs.h, docs/TOKEN-COSTS-20261018.md). */
#ifndef SNAP_OTHER_PROFILE
#define SNAP_OTHER_PROFILE 0
#endif
#ifndef SNAP_GATE_WAIT
#define SNAP_GATE_WAIT 0
#endif
/* compat/service-lock.h SNAP_PHASE_FAIR_GATE (batch 6): its announced wait is
 * bounded, and withdrawn at the bound, in SNAP_GATE_WAIT's loop. */
#if SNAP_PHASE_FAIR_GATE && !SNAP_GATE_WAIT
#error "SNAP_PHASE_FAIR_GATE bounds and withdraws a converted call's announced wait in SNAP_GATE_WAIT's loop"
#endif
#define SNAP_TOKEN_COSTS (SNAP_NEST_FAST || SNAP_DETACH_FAST || SNAP_ROOT_INDEX || SNAP_OTHER_PROFILE || \
                          SNAP_GATE_WAIT)
#if SNAP_TOKEN_COSTS
#include "../compat/token-costs.h"
_Static_assert(SNAP_ROOT_CACHE_WIDE && SNAP_SERVICE_SUBCLASS,
    "the token-cost counters live in the wide cache's arena pages and report after the exit profile");
#endif
/* SIGN/AUTH/BATCH_SIGN_USER_POINTER off the service token: converted calls
 * of the fine-lock dispatcher. Their header, which also defaults this
 * define, is included only with the fine locks, so the default and the
 * refusal of a build without them are here too. */
#ifndef SNAP_FAST_PAUTH_CALLS
#define SNAP_FAST_PAUTH_CALLS 0
#endif
#if SNAP_FAST_PAUTH_CALLS && !SNAP_FINE_LOCKS
#error "SNAP_FAST_PAUTH_CALLS converts calls in the fine locks' dispatcher: build with SNAP_FINE_LOCKS"
#endif
/* The kernel refresh's reuse proof from the table memo's write witness, and the
 * Adreno DART's MAP/UNMAP as converted calls (compat/token-trim.h, batch 5). */
#ifndef SNAP_TOKEN_TRIM
#define SNAP_TOKEN_TRIM 0
#endif
#if SNAP_TOKEN_TRIM
#include "../compat/token-trim.h"
#if !SNAP_KERNEL_VIEW_REUSE || !SNAP_USER_TREE_MEMO || !SNAP_ROOT_CACHE_WIDE || !SNAP_SERVICE_SUBCLASS
#error "SNAP_TOKEN_TRIM needs SNAP_KERNEL_VIEW_REUSE and SNAP_USER_TREE_MEMO (the witness), SNAP_ROOT_CACHE_WIDE (its state) and SNAP_SERVICE_SUBCLASS (its report)"
#endif
#endif
/* The Adreno DART's MAP/UNMAP as converted calls on their own: SNAP_TOKEN_TRIM's
 * part B without its kernel-view witness (compat/dart-converted.h, batch 9). The
 * fine-lock header refuses it without the fine locks and the pointer calls, and
 * beside SNAP_TOKEN_TRIM. */
#ifndef SNAP_DART_CONVERTED
#define SNAP_DART_CONVERTED 0
#endif
#if SNAP_DART_CONVERTED
#include "../compat/dart-converted.h"
#if !SNAP_FINE_LOCKS || !SNAP_ROOT_CACHE_WIDE
#error "SNAP_DART_CONVERTED needs SNAP_FINE_LOCKS (the converted-call dispatcher) and SNAP_ROOT_CACHE_WIDE (its state)"
#endif
#endif
/* SNAP_SPTM_FINE, SNAP_SPTM_FINE_RETYPE, SNAP_SPTM_FINE_KERNEL (compat/fine-lock.h,
 * agents/sptm-locks/FAILURE-MODES.md): more converted SPTM calls. The fine-lock
 * header refuses them without the fine locks and the hardware-walk events;
 * here, without what their converted bodies assume. */
#if SNAP_SPTM_FINE && (!SNAP_USER_HW_WALK || !SNAP_UPDATE_DISJOINT_FAST)
#error "SNAP_SPTM_FINE needs SNAP_USER_HW_WALK (its update events) and SNAP_UPDATE_DISJOINT_FAST (update_fast_uncached)"
#endif
#if SNAP_SPTM_FINE_KERNEL
#include "../compat/sptm-fine.h"
#endif
/* SNAP_REUSE_MATCH_MAPPED (shadow/sprr-reuse.h lists the measurement and the
 * failure modes): kernel_refresh_impl's exact reuse proof reads each copied
 * source table through class_table_read instead of one kernel_table_read
 * callback per word. Same verdict, counters and state. */
#if SNAP_REUSE_MATCH_MAPPED && (!SNAP_KERNEL_VIEW_REUSE || !SNAP_CLASS_PROOF_MAPPED || SNAP_TOKEN_TRIM)
#error "SNAP_REUSE_MATCH_MAPPED needs SNAP_KERNEL_VIEW_REUSE and SNAP_CLASS_PROOF_MAPPED (class_table_read), and not SNAP_TOKEN_TRIM (its witness answers the same proof)"
#endif
/* Root installation and transaction-end publication enumerate an index of
 * pages noted since the last publish instead of every bitmap word; same
 * callback sequence and counters (shadow/root-publish-index.h). _VERIFY also
 * enumerates the bitmap on every listed flush and must agree. */
#ifndef SNAP_INCREMENTAL_PUBLISH
#define SNAP_INCREMENTAL_PUBLISH 0
#endif
#ifndef SNAP_INCREMENTAL_PUBLISH_VERIFY
#define SNAP_INCREMENTAL_PUBLISH_VERIFY 0
#endif
_Static_assert(!SNAP_INCREMENTAL_PUBLISH || (SNAP_ROOT_DIRTY_PUBLISH && SNAP_TXN_DIRTY_PUBLISH),
    "the index lists pages of the root dirty bitmap both flushes consume");
_Static_assert(!SNAP_INCREMENTAL_PUBLISH_VERIFY || SNAP_INCREMENTAL_PUBLISH,
    "verification compares the index with the bitmap it indexes");
/* UPERM writes and TPRO PPERM transactions prove the canonical user view with
 * whole-table shadow reads and one source walk per source page
 * (sptm_root_view_mapped); every 64th proof also runs the reference walk and
 * any difference is terminal. */
#ifndef SNAP_CANONICAL_VIEW_FAST
#define SNAP_CANONICAL_VIEW_FAST 0
#endif
/* Appended last to struct context in every build, like the other appended
 * state, so host layout readers (which compute layouts without build defines)
 * agree with every monitor on the context size and the table-arena base. */
#include "../compat/perf-state.h"
#include "../compat/fast-mmio.h"
/* Keep the last EL0 crash-class events per vCPU (abort()'s self-SIGABRT,
 * kill with a core signal, payload aborts, fatal EL0 exception classes and
 * wild-address aborts) with registers, four frame records and any reason
 * string, read at XNU's vector entry. Diagnostic only; delivery unchanged.
 * The context field is present in every build (compat/user-crash.h). */
#ifndef SNAP_USER_CRASH_RING
#define SNAP_USER_CRASH_RING 0
#endif
#include "../compat/user-crash.h"
#include "../compat/auxkc-observe.h"
#include "../compat/adreno.h"
#include "../compat/adreno-fill.h"
#include "../compat/adreno-ib.h"
#include "../compat/ans.h"
#include "../compat/ans-window.h"
#include "../compat/nvme-host.h"
/* agents/nvme-async (FAILURE-MODES.md): SNAP_ANS_ASYNC serves the virtual ANS2's I/O queue without waiting for
 * the SSD (compat/ans.h); SNAP_ANS_CONVERTED runs its I/O doorbells and table-6 MAP/UNMAP_PAGES as converted
 * calls under the ANS device lock; SNAP_ATTR_CLEAN_DEFER moves attr_clean_finish's second clean past the token. */
#if SNAP_ANS_ASYNC && !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ANS_ASYNC keeps its schedule pointer in root_ext: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#if SNAP_ANS_CONVERTED && (!SNAP_FINE_LOCKS || !SNAP_ROOT_CACHE_WIDE)
#error "SNAP_ANS_CONVERTED needs SNAP_FINE_LOCKS (the gate and the converted-call dispatcher) and SNAP_ROOT_CACHE_WIDE"
#endif
#ifndef SNAP_ATTR_CLEAN_DEFER
#define SNAP_ATTR_CLEAN_DEFER 0
#endif
#if SNAP_ATTR_CLEAN_DEFER
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ATTR_CLEAN_DEFER keeps each CPU's deferred list in root_ext: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#define ATTR_DEFER_MAX 1024u        /* frames per call; past it attr_clean_finish cleans inline (D2) */
#endif
/* agents/sptm-locks/multipage (FAILURE-MODES.md P1-P18): SNAP_MULTIPAGE_FAST. UPDATE_DISJOINT_MULTIPAGE's
 * aperture steps are pre-cleaned before the token is taken, skip both cleans when the AttrIndx keeps its
 * cacheability class, patch a changed word of a kernel-view copy source into the six copies and the reuse
 * snapshot instead of a full re-sync, and are published, refreshed and invalidated once per run of headers
 * (b12v16: 7.79 ms per call, 82 % of it full view re-syncs, 12 % reuse proofs). */
#ifndef SNAP_MULTIPAGE_FAST
#define SNAP_MULTIPAGE_FAST 0
#endif
#if SNAP_MULTIPAGE_FAST && (!SNAP_ATTR_CLEAN_DEFER || !SNAP_KERNEL_VIEW_REUSE || !SNAP_ROOT_CACHE_WIDE || \
                            SNAP_TOKEN_TRIM)
#error "SNAP_MULTIPAGE_FAST needs SNAP_ATTR_CLEAN_DEFER, SNAP_KERNEL_VIEW_REUSE and SNAP_ROOT_CACHE_WIDE, not SNAP_TOKEN_TRIM"
#endif
#include "../compat/early-stop.h"
#include "../compat/a16-thermal.h"
#include "../compat/console-link.h"
#if SNAP_ADRENO_IB_ASYNC
/* SNAP_ADRENO_IB_ASYNC (compat/adreno-ib.h, agents/async-ib/FAILURE-MODES.md): ADRENO_GUEST_IB_START and _POLL,
 * so an IB's GPU execution no longer holds the service token. The flight lives in root_ext's arena pages (the
 * context's last page is full). The pacing report's 0x00010007 is ADRENO_GUEST_NET, which the dispatch answers
 * first (A0). */
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ADRENO_IB_ASYNC keeps its flight in root_ext's monitor arena pages: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#include "../compat/guest-net.h"
_Static_assert(ADRENO_GUEST_IB_START != ADRENO_GUEST_NET && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_NET &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_STOP && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_STOP &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_FILL32 && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_FILL32 &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_IB && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_IB &&
               ADRENO_GUEST_IB_START > ADRENO_GUEST_CACHE && ADRENO_GUEST_IB_POLL > ADRENO_GUEST_CACHE &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_IB_POLL, "IB_START/IB_POLL request words are unique");
#endif
#ifndef SNAP_CPU_DVFS
#define SNAP_CPU_DVFS 0
#endif
#ifndef SNAP_GPU_DVFS
#define SNAP_GPU_DVFS 0
#endif
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
/* agents/dvfs (FAILURE-MODES.md): opt-in CPU and GPU frequency governors on vCPU 0's locked tick, restored at the
 * stop. Their state is the last member of root_ext (the context's last page is full; agents/async-ib A14), and
 * they run only with the thermal guard (EARLY_STOP_F_THERMAL). */
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_CPU_DVFS/SNAP_GPU_DVFS keep their state in root_ext's monitor arena pages: they need SNAP_ROOT_CACHE_WIDE"
#endif
#if SNAP_CPU_DVFS && !SNAP_WFI_RESUME
#error "SNAP_CPU_DVFS reads the EL2 tick's WFI classification (perf.fast[].wfi): it needs SNAP_WFI_RESUME"
#endif
#if SNAP_CPU_DVFS
#include "../compat/cpu-dvfs.h"
#endif
#if SNAP_GPU_DVFS
#include "../compat/gpu-dvfs.h"
#endif
#endif
/* SNAP_GUEST_NET (compat/guest-net-link.h, docs/GUEST-NETWORK-20261019.md): the
 * guest's paravirtual NIC rides on the host poll. ADRENO_GUEST_NET attaches the
 * kext's ring, admitted like ADRENO_GUEST_STOP; a launch with EARLY_STOP_F_NET
 * then polls q1n1 with POLL2 and a net view. Off, the code is absent. */
#if SNAP_GUEST_NET
#include "../compat/guest-net-link.h"
struct guest_net_state {
    struct guest_net_link link;
    struct guest_net_view view;
    struct guest_net_poll_views views;
};
#define GUEST_NET_STATE_PAGES ((sizeof(struct guest_net_state)+4095)/4096)
#define GUEST_NET_POLL2 4u                     /* q1n1 Q1N1_CALL_POLL2 */
#define GUEST_NET_CALL_E_OP UINT64_C(0xffffffffffffffff)   /* Q1N1_CALL_E_OP: an older q1n1 */
#endif
#include "../compat/fast-vector.h"
_Static_assert(FAST_EXIT_CLASSES==FAST_TRAP_CLASSES-1+FAST_CROSS_CLASSES &&
               FAST_EXIT_CROSS_SLOT(1)==FAST_TRAP_CLASSES-1,
               "one exit-timing slot per lock-free class, the EL0 emulation last");
/* Table-arena reserve, in 4K pages. The arena (the240MiB work region less
 * this context) holds every shadow and private copy; each cached user root
 * owns ~365 pages at 61 processes and the kernel ~5.7k, so the 64-slot cache
 * alone left 2.8k of 31.9k free. Every monitor call first restores this many
 * free pages by giving back inactive cached roots (cheapest first), so no
 * transaction starts short of tables. 2048 pages (8 MiB) covers the largest
 * single non-build call (a shared-leaf insertion across 64 aliasing roots,
 * or a 48-descriptor nest). Zero disables the call-entry reserve; an
 * exhausted SWITCH_ROOT build still reclaims and retries once. */
#ifndef SNAP_ARENA_RESERVE_PAGES
#define SNAP_ARENA_RESERVE_PAGES 2048u
#endif
/* A root build that ran the arena dry retries after freeing this many. */
#define ARENA_RETRY_PAGES 8192u

struct params {
    uint64_t ttbr1_root;      /* the guest's own 16K root */
    uint64_t tcr;             /* the guest's TCR_EL1, 16K granules and all */
    uint64_t mair;
    uint64_t entry;           /* where to ERET to */
    uint64_t x1, x2;          /* the two handoff pointers */
    uint64_t vbar;            /* XNU's exception vectors, so faults come here */
    uint64_t stub_count;      /* NATIVE_CALL_FLAG opts into call/writer closure */
    uint64_t stub_pa[8];      /* legacy call guards, or five call + two writer pages */
    uint64_t vbar_va;         /* XNU's vectors, as a virtual address */
    uint64_t watch_pa;        /* handoff pages to observe, 4K each */
    uint64_t watch_count;
    uint64_t watch_va;        /* the same pages as XNU sees them */
    uint64_t vncr_va;         /* loader VNCR seed, copied into private CPU pages */
    uint64_t permissive;      /* acknowledge endpoints we have not implemented */
    uint64_t vmpidr;          /* MPIDR_EL1 as the guest's own cpu node describes it */
    uint64_t let_panic;       /* let XNU run its own exception handler and print */
    uint64_t watchdog_seconds;/* how long the guest may run before we take it back */
    uint64_t low_base, low_span;/* the range to shadow under TTBR0 */
    uint64_t scratch_pa;      /* per-CPU pages the monitor leaves results in */
    uint64_t skip_undef;      /* step over unimplemented encodings, and count them */
    uint64_t scratch_va;      /* the same pages as XNU sees them: what OUTPUT_AREA
                               * returns, because XNU dereferences the answer */
    uint64_t mem_low, mem_high;/* the physical memory we declared: the DRAM and
                                * the reserve above it. Stage 2 covers exactly
                                * this, so MAP_PAGE reports a PTE that points
                                * outside it and a touch outside it faults. */
    uint64_t fb_pa, fb_span;  /* the panel, when it is handed over: the one
                               * range outside mem_low..mem_high the guest may
                               * touch. A zero span means no panel. */
    /* Device register windows the guest's own device tree names, derived from
     * it at build time. Physical addresses on the machine the tree describes,
     * which is not this one -- nothing is there. They are listed so MAP_PAGE
     * can tell a device the kernel legitimately asked for from an address we
     * cannot account for, and install the first while still withholding the
     * second. Stage 2 leaves them absent, so the guest's access traps here
     * with the IPA instead of reaching the bus. */
    uint64_t device_count;
    uint64_t device_pa[4], device_span[4];
    uint64_t frame_map_pa, frame_low, frame_high, alloc_low, alloc_high;
    uint64_t ram_aperture_va;
    uint64_t write_watch_pa;  /* optional 4K page: stop before any guest write */
    uint64_t txm_stacks_pa, txm_stack_count, txm_log_pa;
    uint64_t txm_rw_pa, txm_ro_pa, txm_aspace_pa;
    struct uat_config uat;
    struct sptm_slide_config slide;
    uint64_t model_count;
    struct device_model models[DEVICE_MODEL_MAX];
    uint64_t clock_host_hz, clock_guest_hz;
    uint64_t const_begin, const_end; /* exclusive end, immutable KC prefix */
    struct txm_trust_cache trust_cache;
    uint64_t sep_firmware_pa, sep_firmware_size;
    /* A kmutil-linked AuxKC's VA and PA extents, or zeros. Observed by the
     * compat/auxkc-observe.h counters; nothing is gated on them. */
    struct auxkc_range auxkc;
    /* The Adreno behind the monitor (compat/adreno.h), from q1n1's adoption
     * record (probes/adreno.py). flags 0 leaves every Stage-4 path off. */
    struct adreno_params gpu;
    struct txm_native_params txm_native;
    /* Appended: opt-in early stop (compat/early-stop.h); all zero unless the
     * launch set SNAP_EARLY_STOP, which leaves every early-stop path off. */
    struct early_stop_params early_stop;
#if SNAP_I2C_INPUT
    /* Appended in -DSNAP_I2C_INPUT=1 builds only; the loader appends the six
     * words only for a profile with i2c_input (compat/i2c-input.h). */
    struct i2c_input_params i2c_input;
#endif
};

/* The two sides of this structure are written in different languages and there
 * is nothing but this line holding them together: probes/xnuboot.py builds it
 * as a flat list of u64s, in field order, and a field added on one side and not
 * the other shifts everything after it. That does not fault -- it hands the
 * guest a plausible address from the wrong field -- so the count is stated
 * here, asserted there, and a mismatch is a build error rather than a run. */
#define PARAMS_WORDS 1154
#if SNAP_I2C_INPUT
#undef PARAMS_WORDS
#define PARAMS_WORDS (1154 + I2C_INPUT_PARAMS_WORDS)
#endif
_Static_assert(sizeof(struct params) == PARAMS_WORDS * 8,
               "probes/xnuboot.py builds this structure word by word; "
               "update PARAMS_WORDS on both sides");
#if SNAP_QCC2072_WIFI
/* -DSNAP_QCC2072_WIFI=1 builds read QCC2072_WIFI_PARAMS_WORDS more words right
 * after struct params (after the i2c-input block when that is built in too);
 * the loader appends them only for --qcc2072-wifi. struct params itself, and
 * so every offset the host tools read, is unchanged. */
static inline const struct qcc2072_wifi_params *qcc2072_wifi_block(const struct params *p)
{
    return (const struct qcc2072_wifi_params *)(const void *)(p + 1);
}
#endif
#if SNAP_DISPLAY_TIMING
/* -DSNAP_DISPLAY_TIMING=1 builds read DISPLAY_TIMING_PARAMS_WORDS more words after struct params and, when it is built
 * in, the QCC2072 block; the loader appends them only for --present-beam. struct params itself is unchanged. */
static inline const struct display_timing_params *display_timing_block(const struct params *p)
{
    const uint64_t *after = (const uint64_t *)(const void *)(p + 1);
#if SNAP_QCC2072_WIFI
    after += QCC2072_WIFI_PARAMS_WORDS;
#endif
    return (const struct display_timing_params *)(const void *)after;
}
#endif

/* Events, in the order they happened. A first run is an exploration, so the
 * report is a log rather than a verdict.
 *
 * 512, not 64. The last run recorded 180 events and kept 64 of them, and 36 of
 * those 64 were sysreg traps -- so the log was three quarters full of one kind
 * of thing before the boot had finished starting. Growing it is not a fix for
 * a report that cannot name its ending; the terminal word above is that, and
 * it stays whatever this number is. This is a fix for a different loss: the
 * MIDDLE of the run, the sequence of what XNU asked for, which is most of the
 * evidence about what it is doing. Eight times the room costs 21 KiB in a
 * buffer with 960 KiB of slack before the work area. */
#define EVENT_MAX 512
struct event {
    uint64_t kind;            /* see EV_* */
    uint64_t pc, a, b, c;
    uint64_t repeats;         /* how many identical ones followed */
};
#define EV_MONITOR   1        /* a monitor call: a = x16, b = x0, c = x1 */
#define EV_S2_FAULT  2        /* a stage-2 fault, and the run stops on it:
                               * a = IPA (0 when neither the stage-1 walk nor
                               * HPFAR could name it), b = ESR_EL2 (the ISS:
                               * ISV, size, register, direction, S1PTW, FSC),
                               * c = the guest VA (FAR_EL2); pc = the guest PC.
                               * a is the stage-1 re-walk's IPA when it has one;
                               * with SNAP_S2_FAULT_RETRY the terminal word's
                               * sixth word is HPFAR_EL2, the hardware's. */
#define EV_GUEST_EXC 3        /* XNU took its own exception: a/b/c = ESR/FAR/ELR */
#define EV_SYSREG    4        /* a trapped MSR/MRS: a = ISS */
/* Which bits of that ISS name the register rather than the access.
 *
 * ESR_EL2 EC 0x18 lays the ISS out as Op0 [21:20], Op2 [19:17], Op1 [16:14],
 * CRn [13:10], Rt [9:5], CRm [4:1], Direction [0]. The first four fields and
 * CRm are the register's encoding; Rt and the direction are what this
 * particular instruction did with it. Keeping the first set and dropping the
 * second is what makes "the kernel is reading CNTFRQ" one log entry instead of
 * one per call site per destination register. */
#define SYSREG_ID    0x3FFC1EUL
#define EV_OTHER     5
#define EV_RETYPE    17       /* a = PA, b = old << 32 | new, c = options */
#define EV_RETYPE_FAILED 18   /* a = sptm_result, b = PA, c = new type */
#define EV_MAP_TABLE 19       /* a = VA, b = parent level, c = new TTE */
#define EV_TABLE_FAILED 20    /* a = sptm_result, b = VA, c = new TTE */
#define EV_UNMAP_REGION 21    /* a = VA, b = count, c = options */
#define EV_UNMAP_FAILED 22    /* a = sptm_result, b = VA, c = count */
#define EV_MAP_NEEDS_TABLE 23 /* recoverable TABLE_NOT_PRESENT; a = level, b = VA */
#define EV_EXCEPTION_RETURN 24 /* a = target PC, b = virtual SPSR, c = physical SPSR */
#define EV_RETURN_REFUSED 25   /* a = target PC, b = virtual SPSR, c = instruction */
#define EV_UPDATE_FAILED 26   /* a = sptm_result, b = target PA, c = options */
#define EV_REGION_FAILED 27   /* a = sptm_result, b = VA, c = options */
#define EV_REFERENCE_FAILED 28 /* a = sptm_result, b = VA, c = PTE */
#define EV_SLIDE_FAILED 29     /* a = sptm_result, b = VA, c = count */
#define EV_TXM_FAILED 30       /* a = sptm_result, b = object/argument, c = selector */
#define EV_SLIDE_REGION 31     /* a = source VA, b = new VA, c = count */
#define EV_CLOCK_FAILED 32     /* a = clock_result, b = ISS, c = value */
#define EV_TIMER_FIQ 33        /* a = interrupted PC, b = timer ctl, c = deadline */
#define EV_DEVICE_FAILED 34    /* a = kind << 32 | device_result, b = IPA, c = ESR */
#define EV_DEVICE_IRQ 35       /* a = interrupted PC; asserted virtual AIC IRQ */
#define EV_DEVICE_RESET 36     /* a = PC; b = model bitmap requesting guest reset */
#define EV_IPI_FAILED 37       /* a = ipi_result, b = ISS, c = requested value */
#define EV_CPU_FAILED 38       /* a = cpu_result, b = endpoint, c = argument */
#define EV_SPRR_FAILED 39      /* a = sprr_result, b = ISS, c = requested value */
#define EV_USER_RETURN 40      /* a = target, b = SPSR, c = active source root */
#define EV_USER_EXECUTED 41    /* a = entry PC, b = X0, c = physical SPSR */
#define EV_USER_STEP_FAILED 42 /* a = entry PC, b = X0, c = physical SPSR */
#define EV_PANIC_STATE_FAILED 43 /* a = x16, b = panic owner, c = CPU */
#define EV_NATIVE_WRITER_FAILED 44 /* a = ESR, b = instruction PA, c = word */
#define EV_AUXKC_EXEC 45       /* a = VA, b = old PTE, c = new PTE: a kernel-root
                                * leaf in the linked AuxKC gained EL1 execute */
/* Stage 4 (compat/adreno.h). A trapped GPU block and a refused HVC stop the run;
 * an SMMU fault and a test fence are recorded and the guest continues. */
#define EV_GPU_TRAP 46         /* a = IPA, b = ESR_EL2, c = block class */
#define EV_GPU_SMMU 47         /* a = FSYNR0 << 32 | FSR, b = FAR, c = sGFSR << 32 | CBFRSYNRA0 */
#define EV_GPU_SMC 48          /* a = x0 (fid), b = x1, c = TrustZone x0, or ~0 refused */
#define EV_GPU_RING 49         /* a = fence value, b = result (0 or ADRENO_E_*), c = ticks */
#define EV_GPU_IB 51           /* ADRENO_GUEST_IB: a = package VA, b = IB dwords << 32 | (u32)result, c = ticks */
/* Virtual ANS2 (compat/ans.h): a refused MMIO, mailbox or SPTM table 5/6 access
 * stops the run. a = ANS_E_* << 32 | window/kind (MMIO) or table << 8 | endpoint,
 * b = IPA or x0, c = ESR or x1. The first refusal is also kept in the state. */
#define EV_ANS 50
/* Early stop (compat/early-stop.h). A request is recorded and the guest
 * continues; the stop happens when its deadline expires on some CPU's timer. */
#define EV_EARLY_STOP 52         /* fired: a = source << 32 | reason, b = detail, c = accepted delay */
#define EV_NATIVE_SHARED_FULL 54 /* a call needed a shared-region group and none was free:
                                  * a = native_shared.full, b = root or shared root,
                                  * c = NATIVE_SHARED_GROUPS (SNAP_NATIVE_SHARED) */
#define EV_S2_RETRY 55           /* SNAP_S2_FAULT_RETRY: a stage-2 translation fault retried:
                                  * a = HPFAR's IPA, b = ESR_EL2, c = FAR_EL2; pc = the guest PC */
#define EV_EARLY_STOP_REQUEST 53 /* a = source << 32 | reason, b = requested delay << 32 | (u32)detail,
                                  * c = result (EARLY_STOP_ACCEPTED/_DUPLICATE or EARLY_STOP_E_*) */
#define EV_GUEST_NET 56          /* SNAP_GUEST_NET: ADRENO_GUEST_NET: a = sub-op, b = ring IPA,
                                  * c = result << 32 | (u32)generation; pc = the HVC */
#if SNAP_QCC2072_WIFI
#define EV_QCC2072_COMMAND 57    /* the monitor wrote the QCC2072 command register for the guest:
                                  * a = value, b = read back, c = ESR_EL2; pc = the store */
#endif
#if SNAP_ADRENO_RECOVER
#define EV_GPU_RECOVER 58        /* compat/adreno-ib.h adreno_recover ran: a = cause << 56 | (dead & 0xffff) << 32 |
                                  * (u32)epoch, b = RBBM_STATUS << 32 | RBBM_INT_0_STATUS, c = CP_INTERRUPT_STATUS_GLOBAL
                                  * << 32 | (u32)its own ticks (the snapshot before the reset); pc = the HVC, 0 the tick */
#endif
#define EV_HANDOFF   7        /* a field of the handoff was read: a = offset */
#define EV_WATCHDOG  6        /* the guest ran too long and was taken back */
#define EV_DISPATCH_CMD 8     /* a call that is not an endpoint call:
                               * a = command, b = domain, c = the raw x16 */
#define EV_PANIC_ENTRY 9      /* XNU announced a fatal exception:
                               * a = x30 (which caller), b = ELR_EL1, c = ESR_EL1 */
#define EV_MAP_FAILED 10      /* a MAP_PAGE that returned an error:
                               * a = reason (MAP_FAIL_*), b = the VA, c = detail */
#define EV_MAP_DEVICE 15      /* a MAP_PAGE onto a device window the guest's own
                               * tree names: installed, so the access traps at
                               * stage 2 rather than faulting at stage 1 */
/* 14 was EV_MAP_WITHHELD: a mapping outside our memory that we wrote into the
 * guest's table and kept out of the hardware's. Nothing withholds any more --
 * under the narrowed stage-2 map installing is the loud option, because the
 * access then traps to EL2 with its address instead of faulting inside XNU's
 * own handler. The number is left unused rather than reassigned, so an old
 * transcript keeps its meaning. */
#define EV_MAP_OUTSIDE 11     /* a MAP_PAGE we COMPLETED whose PTE points outside
                               * the memory we declared: a = PA, b = VA, c = PTE */
#define EV_SERROR 12          /* the guest took an SError -- an access the
                               * interconnect refused, which is a bus error and
                               * not a timeout: a = ESR_EL2 (EC 0x2f),
                               * b = ESR_EL1, c = ELR_EL1, pc = ELR_EL2 */
#define EV_ASYNC 13           /* an IRQ or FIQ that was not our timer:
                               * a = which vector (ASYNC_*), b = ESR_EL1,
                               * c = ELR_EL1, pc = ELR_EL2 */
#define EV_MMIO_STOP 16       /* an access to a device window we model, that the
                               * model does not answer -- and the run stops on
                               * it: a = (reason << 48) | (window << 32) |
                               * offset, b = ESR_EL2 (which carries the size and
                               * the direction), c = the IPA; pc = the guest PC.
                               *
                               * A modelled access records nothing. There is one
                               * per character of the kernel's output and the log
                               * holds 64 entries, so the counters carry them
                               * (mmio_reads, mmio_writes, uart_tx) and the log
                               * stays free for the thing that ends the run --
                               * exactly the rule SPTM_FN_SERIAL_PUTC follows. */
/* Why a device access stopped the run. Each one is a thing to go and model, and
 * the transcript names which. */
#define MMIO_STOP_OFFSET 1    /* the window is ours; this offset is not modelled */
#define MMIO_STOP_NO_ISV 2    /* ISS.ISV clear: a pair or writeback form, so the
                               * syndrome does not say which registers moved and
                               * emulating it would be a guess */
#define MMIO_STOP_FETCH  3    /* an instruction fetch from a device page */
#define MMIO_STOP_S1PTW  4    /* the stage-1 walk faulted into a device page: the
                               * fault is the walker's, not the access's */
#define MMIO_STOP_SHAPE  5    /* the tree's windows are not the shape the model
                               * was written against */
#define MAP_OUTSIDE_LOGGED 6  /* how many to record before the counter alone */

/* Which asynchronous vector an exception arrived at. The three values are
 * mirrored in probes/xnuboot.S, which is where they are chosen. */
#define ASYNC_IRQ    0
#define ASYNC_FIQ    1
#define ASYNC_SERROR 2
#if SNAP_FAST_TIMER_IRQ
/* Never chosen by a vector: an IRQ whose acknowledge on the lock-free tick
 * (fast_timer_irq) returned, and completed, another INTID than HPPIR's 26.
 * xnuboot_async_locked passes over its GPU and timer cases for it, so it
 * records and stops as after the same acknowledge of its own (probes/run.py
 * ASYNC_KINDS names it). */
#define ASYNC_IRQ_OTHER 3
#endif

/* CNTHP_CTL_EL2.ISTATUS -- the timer condition is met. This is the only thing
 * that entitles anything to print the word "watchdog": the register says the
 * comparator fired, rather than us assuming it because something asynchronous
 * happened while the guest was running. */
#define CNTHP_ISTATUS (1UL << 2)

/* Why a MAP_PAGE failed. Six branches returned one status and recorded nothing,
 * so a failed map was indistinguishable from a working one in the transcript.
 * The level a walk stopped at is packed into bits 15:8 of the reason. */
#define MAP_FAIL_START_LEVEL   1   /* T1SZ gives no valid starting level */
#define MAP_FAIL_LEVEL_MISSING 2   /* a table in the walk is absent: MAP_TABLE's job */
#define MAP_FAIL_READ_LEAF     3   /* the level-3 entry could not be read */
#define MAP_FAIL_WRITE_LEAF    4   /* ...or written */
#define MAP_FAIL_REREAD        5   /* written, but reading it back disagreed */
#define MAP_FAIL_SHADOW_INSERT 6   /* the 4K shadow refused it, usually no arena */
#define MAP_FAIL_SHADOW_ABSENT 7   /* inserted, but the shadow does not resolve it */
#define MAP_FAIL_SHADOW_WRONG  8   /* the shadow resolves it, to the wrong page */
#define MAP_FAIL_LEAF_INVALID  9   /* the guest says unmapped; we would no-op */
#define MAP_FAIL_SHADOW_EMPTY 10   /* shadow_insert accepted it and did nothing */
#define MAP_FAIL_ROOT_OUTSIDE 11   /* the root handed to us is not our memory */
#define MAP_FAIL_SPRR_CLASS   12   /* needs a prepared private permission path */

/* The monitor call ABI, from the stubs themselves: x16 packs the routing and
 * x0..x7 carry the arguments. Endpoint numbering matches
 * m1n1 (AsahiLinux) and the author's J700 research fork (sptm/private.h), reverse-engineered on this same
 * SoC -- see docs/BOOT-CHAIN.md section 5.
 *
 * Every name below is now Apple's own rather than a reconstruction. SPTM's
 * dispatch table is in its `__DATA_CONST` at 0xfffffff027022350 -- 51 entries
 * of `{void *handler; uint64_t flags; const char *name;}`, indexed by endpoint,
 * pointers stored as chained fixups -- and it carries the
 * `SPTM_FUNCTIONID_*` string for each one. `tools/sptm-dispatch.py` prints it.
 * Eight endpoints this file already implemented land exactly where they were
 * guessed, which is what makes the table trustworthy for the ones that were
 * not. */
/* x16 is four fields, not three:
 *
 *   dispatch command  [63:56]     domain  [55:48]
 *   table             [39:32]     endpoint [31:0]
 *
 * The command names which *kind* of call this is; only command 0 is an endpoint
 * call, where the other three fields mean anything. See monitor_call(). */
#define SPTM_CMD_ENDPOINT       0
#define SPTM_CMD_PANIC_ENTRY    2      /* XNU is taking a fatal exception */
#define SPTM_CMD_MAX            6      /* dispatch_cmd_handler rejects >= 7 */
#define SPTM_SUCCESS            0
/* Return codes, from m1n1-j700/src/sptm/private.h. */
#define SPTM_TABLE_NOT_PRESENT  7
#define SPTM_FN_RETYPE          1
#define SPTM_FN_MAP_TABLE       3
#define SPTM_FN_UNMAP_TABLE     4
#define SPTM_FN_CONDEMN_LEAF_TABLE 43
#define SPTM_FN_UNCONDEMN_LEAF_TABLE 44
#define SPTM_FN_UPDATE_DISJOINT 6
#define SPTM_FN_UPDATE_REGION   5
#define SPTM_FN_UPDATE_DISJOINT_MULTIPAGE 21
#define SPTM_FN_UNMAP_REGION    7
#define SPTM_FN_UNMAP_DISJOINT  8
#define SPTM_FN_CONFIGURE_SHAREDREGION 9
#define SPTM_FN_NEST_REGION 10
#define SPTM_FN_UNNEST_REGION 11
#define SPTM_FN_SET_SHARED_REGION 39
#define SPTM_FN_BATCH_SIGN_USER_POINTER 40
#define SPTM_FN_SIGN_USER_POINTER 16
#define SPTM_FN_AUTH_USER_POINTER 17
#define SPTM_FN_CONFIGURE_ROOT 12
#define SPTM_FN_SWITCH_ROOT     13
#define SPTM_FN_SLIDE_REGION    20
#define SPTM_FN_MAP_PAGE        2      /* SPTM_FUNCTIONID_MAP_PAGE */
#define SPTM_FN_SERIAL_DISABLE  46     /* SPTM_FUNCTIONID_SPTM_SERIAL_DISABLE */
#define SPTM_FN_LOCKDOWN        0      /* SPTM_FUNCTIONID_LOCKDOWN */
#define SPTM_FN_FIXUPS_COMPLETE 15     /* SPTM_FUNCTIONID_FIXUPS_COMPLETE */
#define SPTM_FN_REGISTER_CPU        14 /* SPTM_FUNCTIONID_REGISTER_CPU */
#define SPTM_FN_REGISTER_EXC_RETURN 18 /* SPTM_FUNCTIONID_REGISTER_EXC_RETURN */
#define SPTM_FN_SERIAL_PUTC     45     /* SPTM_FUNCTIONID_SPTM_SERIAL_PUTC */
#define SPTM_FN_CPU_ID          0x13   /* SPTM_FUNCTIONID_CPU_ID: which slot am I */
#define SPTM_FN_OUTPUT_AREA     0x32   /* SPTM_FUNCTIONID_OUTPUT_AREA: where that
                                        * slot's results are left */
#define CONSOLE_MAX           1024
#define CONSOLE_TAIL_MAX     65536
#define CONSOLE_LOG_MAX      (4u << 20)

/* A page the guest is not allowed to touch unobserved.
 *
 * Two kinds, one mechanism. EXEC pages are execute-never, so a call into a
 * monitor stub arrives at EL2; DATA pages are invalid outright, so *any* access
 * does. Both open the page and observe the next instruction with single-step.
 * DATA then closes; EXEC can remain open while each instruction on that page
 * is still stepped. Neither needs the faulting instruction decoded. That
 * matters: the alternative is decoding every load/store form XNU might use,
 * and being wrong about one of them silently. */
#define GUARD_EXEC 0
#define GUARD_DATA 1
struct guard {
    uint64_t pa, slot;        /* the page, and the level-3 entry that maps it */
    uint64_t descriptor;      /* what that entry says when the page is open */
    uint64_t mode;
};

/* The guest's register file at the moment it took an exception.
 *
 * Three values were not enough. ESR/FAR/ELR say what faulted and where; they do
 * not say what the kernel had in its hands, and the difference decides what the
 * fault means. A walk that lands on a null table base and a walk that lands on
 * a plausible one are the same syndrome and different problems, and telling
 * them apart by reading the disassembly backwards is guesswork the machine can
 * simply answer.
 *
 * These are the guest's own values, with no qualification needed: `sync_lower`
 * in probes/xnuboot.S pushes x0..x30 as the first thing it does, before any
 * call, so nothing at EL2 has run between the exception and the save. The
 * frame is what this copies from. */
struct guest_regs {
    uint64_t x[31];           /* x0 .. x30 */
    uint64_t sp_el1;          /* selected guest SP; historical wire field name */
    uint64_t spsr;            /* SPSR_EL2: the guest's PSTATE as it faulted */
    uint64_t pc;              /* ELR_EL1: the instruction that faulted */
    uint64_t esr;             /* ESR_EL1, the syndrome XNU's own handler sees */
    uint64_t far;             /* FAR_EL1, the address it faulted on */
};
#define GUEST_REGS_WORDS (sizeof(struct guest_regs) / 8)
_Static_assert(GUEST_REGS_WORDS == 36, "probes/run.py unpacks 36 words per snapshot");

/* Where the snapshots sit in the out buffer, in 64-bit words from the start of
 * the report area. Past the console, so every offset the host already reads
 * stays where it was:
 *
 *   0                          8 report words
 *   8                          EVENT_MAX events of 6 words
 *   8 + 6*EVENT_MAX            CONSOLE_MAX bytes
 *   OUT_GUEST_REGS             count, then two snapshots of GUEST_REGS_WORDS
 *   OUT_PANIC_REGS             count, then the frame at XNU's panic-entry call
 *   OUT_COUNTERS               OUT_COUNTERS_N counters
 *   OUT_EXC_RETURN             the trampoline XNU registered
 *   OUT_BAD_REGS               ELR_EL2 and FAR_EL2 at an EL2 fault
 *
 * The host's `out` is 16 bytes below this one (probes/xnuboot.S, OUT_REPORT),
 * so in its terms this area starts at out + 16 + OUT_GUEST_REGS * 8. */
#define OUT_GUEST_REGS (8 + 6 * EVENT_MAX + CONSOLE_MAX / 8)
/* And after the two exception snapshots: the frame at XNU's panic-entry call.
 * Appended rather than inserted, so every offset above keeps its address. */
#define OUT_PANIC_REGS (OUT_GUEST_REGS + 1 + 2 * GUEST_REGS_WORDS)
/* Counters the report otherwise loses. The event log holds 64 entries and
 * collapses repeats, so "how many maps failed" cannot be recovered by counting
 * lines in it -- these survive a log that overflowed. */
#define OUT_COUNTERS   (OUT_PANIC_REGS + 1 + GUEST_REGS_WORDS)
#define OUT_COUNTERS_N 13
/* The exception-return trampoline XNU registers, in a word of its own.
 *
 * It used to be written over the fault syndrome at report word 6, so once XNU
 * had answered REGISTER_EXC_RETURN -- which it does early in every boot -- that
 * slot held a code address. The host reads word 6 as an ESR: it printed the
 * trampoline under the label "ESR", and its "was a fault recorded?" test, which
 * is just "is that word non-zero", became permanently true. One word each, and
 * neither can be mistaken for the other. */
#define OUT_EXC_RETURN (OUT_COUNTERS + OUT_COUNTERS_N)
/* ELR_EL2 and FAR_EL2 as the `bad` vector found them. ESR_EL2 alone says an
 * EL2 fault happened and what kind; these say where in this file it happened
 * and what address it was reaching for, which is the difference between "the
 * monitor faulted" and a line number. */
#define OUT_BAD_REGS   (OUT_EXC_RETURN + 1)
/* The last event recorded, whatever the log did with it.
 *
 * Six words in the shape of a log entry, so the host parses it with the same
 * code. It exists because the log is a ring with a fixed size and the boot is
 * now longer than it: a run that drops events has no readable tail, and every
 * verdict that asks "what was the last thing that happened" was therefore
 * unavailable exactly when the run got far enough to be interesting. This slot
 * is written on every record() and never dropped, so the question always has
 * an answer. `repeats` is always zero here -- it is the ring's bookkeeping,
 * not this slot's -- and `kind` zero means nothing was ever recorded. */
#define OUT_LAST_EVENT (OUT_BAD_REGS + 2)
/* How many calls each endpoint took, and how many went somewhere else.
 *
 * The log collapses repeats and then drops what does not fit, so "which
 * endpoints did this run actually call, and how often" is not recoverable from
 * it. The last run made 390 monitor calls and the transcript could account for
 * 385; the missing five were not a mystery the log could solve, because the
 * log had already thrown them away. Sixty-four buckets covers SPTM's whole
 * dispatch table -- 51 entries, highest endpoint 0x32 -- so no two endpoints
 * share a bucket, and the sixty-fifth counts everything that is not an
 * XNU_BOOTSTRAP endpoint call. The two together must equal the number of calls
 * that reached the dispatcher, which is what makes the arithmetic checkable. */
#define OUT_ENDPOINTS  (OUT_LAST_EVENT + 6)
#define ENDPOINT_BUCKETS 64
/* The out-of-memory mappings, coalesced into spans.
 *
 * 379 of them arrived in the last run and the log kept five, because five
 * identical lines say what 379 say and the rest would push out everything
 * else. But "five examples and a count" loses the shape: which device, how
 * many pages of it, mapped once or twice. Spans keep the shape at a fixed
 * cost -- a run of consecutive pages of one device is one row however many
 * pages it is -- and the host turns each physical base back into the node of
 * the guest's own tree that named it.
 *
 * Twenty-four slots, a count, and a count of the spans that did not fit. The
 * overflow counter is not decoration: a table that silently stopped recording
 * would read as a device surface smaller than it is, which is the same lie
 * the 64-entry log was telling. */
#define OUT_RANGES     (OUT_ENDPOINTS + ENDPOINT_BUCKETS + 1)
#define MAP_RANGES     128
#define MAP_RANGE_WORDS 4
/* The guest's translation registers as the probe last saw them.
 *
 * TTBR0, TTBR1, TCR, MAIR, SCTLR -- five words, in that order. The probe has
 * tracked these since it started trapping them and has never shown them, so
 * "did XNU change one" has only ever been answerable by reading the log for a
 * sysreg event that may have been collapsed or dropped.
 *
 * MAIR is the one with a question attached. The loader publishes the value
 * SPTM's common start leaves for XNU (0x0c0d00ff01a040ff) on the strength of
 * there being no `msr MAIR_EL1` anywhere in this kernelcache; if that reading
 * is wrong, this word comes back as something else and says so. A static
 * claim about 120 MiB of image, measured for the cost of five words. */
#define OUT_GUEST_SYSREGS (OUT_RANGES + 2 + MAP_RANGES * MAP_RANGE_WORDS)
#define OUT_FRAMEBUFFER (OUT_GUEST_SYSREGS + 5)
#define OUT_ASYNC_REGS (OUT_FRAMEBUFFER + 3)
#define OUT_EXCEPTION_FLOW (OUT_ASYNC_REGS + 1 + GUEST_REGS_WORDS)
#define OUT_UPDATE_FLOW (OUT_EXCEPTION_FLOW + 3)
#define OUT_SLIDE_FLOW (OUT_UPDATE_FLOW + 4)
#define OUT_CLOCK_FLOW (OUT_SLIDE_FLOW + 3)
#define OUT_TIMER_FLOW (OUT_CLOCK_FLOW + 8)
#define OUT_DEVICE_FLOW (OUT_TIMER_FLOW + 11)
#define OUT_CLOCK_ADAPTER (OUT_DEVICE_FLOW + 1 + 2*DEVICE_MODEL_MAX)
#define OUT_AIC_FLOW (OUT_CLOCK_ADAPTER + 12)
#define OUT_WATCHDOG_FLOW (OUT_AIC_FLOW + 5)
#define OUT_OPTIONAL_FLOW (OUT_WATCHDOG_FLOW + DEVICE_RESET_WORDS + 3*DEVICE_MODEL_MAX)
#define OUT_IPI_FLOW (OUT_OPTIONAL_FLOW + 2)
#define OUT_CPU_FLOW (OUT_IPI_FLOW + 8)
#define OUT_VCPU_FLOW (OUT_CPU_FLOW + 8)
#define OUT_SHARED_FLOW (OUT_VCPU_FLOW + GUEST_CPU_COUNT*12)
#define OUT_SERVICE_FLOW (OUT_SHARED_FLOW + 3)
#define OUT_RUNTIME_STORAGE (OUT_SERVICE_FLOW + 4 + GUEST_CPU_COUNT*2)
_Static_assert(DEVICE_RESET_WORDS==2, "reset events record two bitmap words");
_Static_assert(OUT_RUNTIME_STORAGE + GUEST_CPU_COUNT*5 + 1 <= 0x10000/8,
               "device metrics must fit the report reservation");
/* Stage 4: struct adreno_state's counter words (compat/adreno.h), appended. */
#define OUT_GPU_FLOW (OUT_RUNTIME_STORAGE + GUEST_CPU_COUNT*5 + 1)
_Static_assert(OUT_GPU_FLOW + ADRENO_STATE_WORDS <= 0x10000/8,
               "the Adreno counters must fit the report reservation");
_Static_assert(__builtin_offsetof(struct adreno_state, irq) == 8*ADRENO_STATE_WORDS,
               "tools/adreno_counters.py decodes every word before irq");
/* Early stop (compat/early-stop.h): the whole record, appended after the GPU
 * words; probes/run.py EARLY_STOP_OFFSET and tools/early_stop.py read it. */
#define OUT_EARLY_STOP (OUT_GPU_FLOW + ADRENO_STATE_WORDS)
_Static_assert(OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS <= 0x10000/8,
               "the early-stop record must fit the report reservation");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
/* The exit profile (compat/perf-state.h), copied whole behind a magic word
 * and a word of build bits | size << 32, after the early-stop record: the
 * cycle tools capture context.bin at the define-free context size, which
 * ends before it, and report.bin whole. tools/perf_counters.py
 * decode_exit_profile reads it at probes/run.py EARLY_STOP_OFFSET + 8*30. */
#define OUT_EXIT_PROFILE (OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS)
#define EXIT_PROFILE_MAGIC UINT64_C(0x31464f5250544958)   /* "XITPROF1" */
#define EXIT_PROFILE_WORDS (sizeof(struct exit_profile)/8)
_Static_assert(OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS <= 0x10000/8,
               "the exit profile must fit the report reservation");
#endif
#if SNAP_FINE_LOCKS
#if !SNAP_SERVICE_SUBCLASS
#error "SNAP_FINE_LOCKS reports after the exit profile: build with SNAP_SERVICE_SUBCLASS"
#endif
/* Each CPU's converted-call profile (compat/fine-lock.h struct fine_profile)
 * behind a magic word and a word of SNAP_FINE_SWITCH | SNAP_FAST_PAUTH_CALLS
 * << 1 | profile bytes << 32, after the exit profile; tools/perf_counters.py
 * decodes it. */
#define OUT_FINE_PROFILE (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#define FINE_PROFILE_WORDS (sizeof(struct fine_profile)/8)
_Static_assert(OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS <= 0x10000/8,
               "the fine profile must fit the report reservation");
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST || SNAP_ROOT_INDEX || SNAP_OTHER_PROFILE || SNAP_GATE_WAIT
/* compat/token-costs.h struct token_costs_report behind "TOKCOST1" and a word
 * of define bits | bytes << 32, after the fine profile (or the exit profile);
 * tools/perf_counters.py decode_token_costs reads it. */
#if SNAP_FINE_LOCKS
#define OUT_TOKEN_COSTS (OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS)
#else
#define OUT_TOKEN_COSTS (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#endif
#define TOKEN_COSTS_WORDS 96u
_Static_assert(OUT_TOKEN_COSTS + 2 + TOKEN_COSTS_WORDS <= 0x10000/8,
               "the token-cost record must fit the report reservation");
#endif
/* Fixed unused report tail: do not move any existing decoder offset. */
#define OUT_THERMAL (A16_THERMAL_REPORT_OFFSET/8)
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_THERMAL,"thermal report overlap");
#elif SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_THERMAL,"thermal report overlap");
#elif SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_THERMAL,"thermal report overlap");
#else
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_THERMAL,"thermal report overlap");
#endif
_Static_assert(OUT_THERMAL+A16_THERMAL_REPORT_WORDS <= (0x10000-16)/8,"thermal report reservation");
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
/* agents/dvfs: "DVFSREP1", a word of SNAP_CPU_DVFS | SNAP_GPU_DVFS << 1 | CPU words << 16 | GPU words << 32,
 * then the reported prefix of struct cpu_dvfs_state and of struct gpu_dvfs_state (each header's ABI word says
 * its layout; their private tails are not written), word by word (absent ones are not written), in the
 * otherwise unused words after the thermal report. */
#define OUT_DVFS (OUT_THERMAL + A16_THERMAL_REPORT_WORDS)
#define DVFS_REPORT_MAGIC UINT64_C(0x3150455253465644)   /* "DVFSREP1" */
#if SNAP_CPU_DVFS
#define DVFS_CPU_WORDS CPU_DVFS_REPORT_WORDS
#else
#define DVFS_CPU_WORDS 0
#endif
#if SNAP_GPU_DVFS
#define DVFS_GPU_WORDS GPU_DVFS_REPORT_WORDS
#else
#define DVFS_GPU_WORDS 0
#endif
_Static_assert(OUT_DVFS + 2 + DVFS_CPU_WORDS + DVFS_GPU_WORDS <= (0x10000-16)/8, "DVFS report reservation");
#endif
#if SNAP_FAST_TIMER_IRQ
/* root_ext->fast_irq (compat/fast-timer-irq.h struct fast_irq_cpu, per CPU)
 * behind "FASTIRQ1" and a word of SNAP_WFI_RESUME | per-CPU bytes << 32, after
 * the last exit-profile record; tools/perf_counters.py decode_fast_irq. */
#if SNAP_TOKEN_COSTS
#define OUT_FAST_IRQ (OUT_TOKEN_COSTS + 2 + TOKEN_COSTS_WORDS)
#elif SNAP_FINE_LOCKS
#define OUT_FAST_IRQ (OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS)
#else
#define OUT_FAST_IRQ (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#endif
#define FAST_IRQ_MAGIC UINT64_C(0x3151524954534146)   /* "FASTIRQ1" */
#define FAST_IRQ_WORDS (sizeof(struct fast_irq_cpu)/8)
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_THERMAL,"thermal report overlap");
#endif
#if SNAP_GUEST_NET
/* The guest network (compat/guest-net-link.h): the link's words, then the net
 * view's (q1n1's counters included), behind "GUESTNT1" and a word of
 * EARLY_STOP_F_NET-enabled | link bytes << 32, after the last record before it;
 * tools/guest_net_report.py decodes it. */
#if SNAP_FAST_TIMER_IRQ
#define OUT_GUEST_NET (OUT_FAST_IRQ + 2 + GUEST_CPU_COUNT*FAST_IRQ_WORDS)
#elif SNAP_TOKEN_COSTS
#define OUT_GUEST_NET (OUT_TOKEN_COSTS + 2 + TOKEN_COSTS_WORDS)
#elif SNAP_FINE_LOCKS
#define OUT_GUEST_NET (OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS)
#elif SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
#define OUT_GUEST_NET (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#else
#define OUT_GUEST_NET (OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS)
#endif
#define GUEST_NET_REPORT_MAGIC UINT64_C(0x31544e5453455547)   /* "GUESTNT1" */
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_THERMAL,"thermal report overlap");
#endif
#if SNAP_FAST_IPI
/* root_ext->fast_ipi (compat/fast-ipi.h struct fast_ipi_cpu, per CPU) behind
 * "FASTIPI1" and a word of per-CPU bytes << 32, at a fixed place just below the
 * thermal block, so it does not move with the records chained above; each of
 * them must end before it. tools/perf_counters.py decode_fast_ipi. */
#define FAST_IPI_WORDS (sizeof(struct fast_ipi_cpu)/8)
#define OUT_FAST_IPI (OUT_THERMAL - 2 - GUEST_CPU_COUNT*FAST_IPI_WORDS)
#define FAST_IPI_MAGIC UINT64_C(0x3149504954534146)   /* "FASTIPI1" */
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#endif
_Static_assert(EARLY_STOP_E_DISABLED == ADRENO_E_PARAMS,
               "a disabled early stop answers like an older monitor's fence handler");
_Static_assert(sizeof(struct adreno_params) == 8*ADRENO_PARAMS_WORDS,
               "probes/adreno.py builds params.gpu word by word");
_Static_assert(ADRENO_DART_ID == SPTM_DART_ADRENO, "one virtual DART id");
_Static_assert(SPTM_DART_ADRENO_BASE == ADRENO_WINDOW_BASE && SPTM_DART_ADRENO_END == ADRENO_WINDOW_END,
               "one Adreno window (ADRENO_VA_WIDE)");
#if SNAP_DART_WIREDCNT
_Static_assert((ADRENO_WINDOW_END >> 25) <= 64 * DWC_PIN_WORDS, "the pin bitmap covers every Adreno level-1 slot");
#if ADRENO_VA_WIDE && !SNAP_ROOT_CACHE_WIDE
#error "ADRENO_VA_WIDE with SNAP_DART_WIREDCNT keeps its 8-word pin bitmap in struct root_ext (SNAP_ROOT_CACHE_WIDE)"
#endif
#endif
#if SNAP_DART_MEMO
/* root_ext->dart_memo's counters (compat/sptm-dart-memo.h struct
 * sptm_dart_memo_stats, then live) behind "DARTMEM1" and a word of stats
 * bytes << 32, at a fixed place: below the 98 words just under the thermal
 * block that SNAP_FAST_IPI's record (compat/fast-ipi.h) takes when it is on.
 * Every chained record must end before it. tools/perf_counters.py decode_dart_memo. */
#define DART_MEMO_STATS_WORDS (sizeof(struct sptm_dart_memo_stats)/8)
#define OUT_DART_MEMO (OUT_THERMAL - 98 - 3 - DART_MEMO_STATS_WORDS)
#define DART_MEMO_MAGIC UINT64_C(0x314d454d54524144)   /* "DARTMEM1" */
#if SNAP_FAST_IPI
_Static_assert(OUT_FAST_IPI == OUT_THERMAL - 98, "the fast IPI record's slot");
#endif
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#endif
#if SNAP_TOKEN_TRIM
/* root_ext->trim.stats (compat/token-trim.h struct token_trim_stats) behind
 * "TOKTRIM1" and a word of stats bytes << 32, at a fixed place just below the
 * DART memo's slot (used or not), so it does not move with the records chained
 * above; each of them must end before it. tools/perf_counters.py
 * decode_token_trim. */
#define TOKEN_TRIM_WORDS (sizeof(struct token_trim_stats)/8)
#define OUT_TOKEN_TRIM (OUT_THERMAL - 98 - 3 - 8 - 2 - TOKEN_TRIM_WORDS)
#define TOKEN_TRIM_MAGIC UINT64_C(0x314d4952544b4f54)   /* "TOKTRIM1" */
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#endif
#if SNAP_DART_MEMO
_Static_assert(OUT_TOKEN_TRIM+2+TOKEN_TRIM_WORDS==OUT_DART_MEMO,"the token-trim record ends at the DART memo's slot");
#endif
#endif
#if SNAP_ADRENO_IB_ASYNC
/* root_ext->ib_flight (compat/adreno-ib.h struct adreno_ib_flight) as the stop leaves it, behind "IBASYNC1" and a word of
 * flight bytes << 32 | ADRENO_IB_POLL_DIVISOR, at a fixed place just below the token-trim slot (its 18 words, used
 * or not), so it does not move with the records chained above; each of them must end before it.
 * tools/perf_counters.py decode_ib_async. */
#define OUT_IB_ASYNC (OUT_THERMAL - 98 - 3 - 8 - 2 - 16 - 2 - ADRENO_IB_FLIGHT_WORDS)
#define IB_ASYNC_MAGIC UINT64_C(0x31434e5953414249)   /* "IBASYNC1" */
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_TOKEN_TRIM
_Static_assert(OUT_IB_ASYNC+2+ADRENO_IB_FLIGHT_WORDS==OUT_TOKEN_TRIM,"the IB async record ends at the token-trim slot");
#endif
#if SNAP_DART_MEMO
_Static_assert(OUT_IB_ASYNC+2+ADRENO_IB_FLIGHT_WORDS+2+16==OUT_DART_MEMO,"the IB async record's slot");
#endif
#endif

struct context;
struct user_table_owner {struct context *context; unsigned owner;};
/* TPIDR_EL2 points to the current physical executor's private guest CPU.
 * Shared services and models live in context under the runtime service lock.
 * Coordinated stop and secondary setup remain before another executor may run. */
struct vcpu {
    /* Assembly exception/return ABI; never use a shared active-CPU index. */
    uint64_t el2_sp, out_ptr, bad_elr, bad_far;
    struct context *context;
    uint64_t slot, vmpidr, vncr_va, prepared;
    uint64_t shadow_root, stage2_root, low_root, low_leaves;
    uint64_t guest_ttbr0, guest_ttbr1, guest_tcr, guest_mair, guest_sctlr;
    uint64_t guest_apga_lo, guest_apga_hi;
    uint64_t kernel_returns, pacga_calls, last_kernel_return;
    struct guest_clock clock;
    struct guest_timer timer, idle_physical_timer;
    struct clock_rate clock_rate;
    struct guest_event clock_event;
    uint64_t save_cnthctl, guest_cnthctl;
    uint64_t clock_backend_reads, clock_raw_first, clock_raw_last;
    uint64_t clock_guest_first, clock_guest_last;
    uint64_t wfe_traps, event_wakes, wfe_early, arch_counter_reads;
    uint64_t save_cntkctl, clock_saved, clock_hz;
    uint64_t watchdog_deadline, watchdog_live;
    uint64_t timer_irqs, timer_asserts, timer_clears, timer_vectors, timer_irq_pc;
    uint64_t fault_esr, fault_far, fault_elr;
    uint64_t save_mdcr, save_mdscr, dbg_oslsr;
    struct exception_step stepping;
    uint64_t timer_pending;
    uint64_t model_irq_pending, model_irq_asserts, model_irq_clears, model_irq_vectors;
    uint64_t step_exception_repairs;
    uint64_t save_vbar, save_hcr, save_tpidr, save_sctlr, save_tcr, save_daif;
    uint64_t save_vmpidr, save_cnthp_ctl, save_cnthp_cval;
    uint64_t save_ttbr0, save_ttbr1, save_mair, save_vttbr, save_vtcr;
    struct guard guards[12];
    uint64_t guard_count, open_guards;
    uint64_t exceptions, panic_calls, async_captured;
    struct guest_regs first_exc, last_exc, panic_exc, async_regs;
    struct guest_ipi ipi;
    uint64_t ipi_request_pc, ipi_ack_pc;
    uint64_t service_acquires, service_fault;
} __attribute__((aligned(64))); /* independent cache lines for each CPU */

struct user_execution {
    uint64_t returns, pending, executed, interrupted, faults, svcs;
    uint64_t entry, stack, initial_spsr, root, shadow, ttbr, tcr;
    uint64_t entry_pa, source_pte, shadow_pte, instruction, initial_x0;
    uint64_t observed_pc, observed_spsr, observed_esr, observed_x0, observed_sp;
};

struct view_table_read_stats {
    uint64_t calls,complete,tables,map_calls,map_complete,errors;
};
struct context {
    const struct params *params;
#if SNAP_TXM_ASPACE_WIDE
    /* Define-free 512-slot twin for host readers, refreshed at the stop
     * (txm_ext_mirror); the live registry is TXM_REG(c), in arena pages
     * after the context (compat/txm.h A3). */
    struct txm_registry_compat txm_registry_host;
#else
    struct txm_registry txm_registry;
#endif
    uint64_t serial_disabled; /* the kernel has taken its console back */
    uint64_t lockdowns;       /* SPTM_FN_LOCKDOWN calls acknowledged */
    uint64_t skip_undef;      /* step over instructions this CPU lacks */
    uint64_t undef_skipped;   /* how many were stepped over: not "answered" */
    uint64_t next_table, work_start, work_base, work_end;
    uint64_t leaves, traps, events, steps, aborts;
    uint64_t map_pages;       /* SPTM_FN_MAP_PAGE calls completed */
    uint64_t map_failures;    /* ...and how many returned an error instead */
    uint64_t map_outside;     /* ...and how many pointed outside our memory */
    uint64_t map_device;      /* ...and how many were a device the tree names */
    uint64_t log_dropped;     /* events the log had no room for */
    uint64_t dispatch_cmds;   /* calls refused because they were not endpoint calls */
    /* Every monitor call that reached the dispatcher, by endpoint, whatever
     * became of it -- answered, refused, or acknowledged permissively. The
     * log cannot carry this: it collapses repeats and then drops the rest, so
     * a run that calls one endpoint four hundred times and another once shows
     * two lines and no counts. `endpoint_other` is the single bucket for
     * everything that is not an XNU_BOOTSTRAP endpoint call: another domain,
     * another table, a dispatch command that is not a call, or an endpoint
     * number too large to bucket honestly. Aliasing endpoint 64 onto endpoint
     * 0 would put a stranger's calls in LOCKDOWN's column, which is precisely
     * the kind of silent collapse this file keeps finding, so it does not. */
    uint64_t endpoint_calls[ENDPOINT_BUCKETS];
    uint64_t endpoint_other;
    /* Every PTE that pointed outside the memory we declared, as spans. A slot
     * is extended when the next page continues it in BOTH address spaces and
     * carries the same attributes; anything else starts a new one. All three
     * conditions matter: same VA run and same PA run is what makes it one
     * mapping rather than two that happen to be adjacent, and equal attributes
     * are what let a single `attrs` field describe the whole span instead of
     * quietly describing only its first page. */
    struct map_range { uint64_t va, pa, pages, attrs; } ranges[MAP_RANGES];
    uint64_t range_count;     /* slots used */
    uint64_t ranges_dropped;  /* spans that would have needed a 25th slot */
    uint64_t update_calls, update_entries;
    uint64_t region_calls, region_entries;
    struct sptm_update_workspace update_workspace;
    struct sptm_ref_batch references;
    struct sptm_slide_state slide;
    uint64_t device_reset_mask[DEVICE_RESET_WORDS];
    uint64_t txm_developer_notifications;
    uint32_t cputrace_queries[2]; /* independently saturated at UINT32_MAX */
    uint64_t model_reads[DEVICE_MODEL_MAX], model_writes[DEVICE_MODEL_MAX];
    struct device_state model_state[DEVICE_MODEL_MAX];
    uint64_t calls, console_len, exc_return;
    uint64_t console_dropped;  /* bytes past CONSOLE_MAX, counted not kept */
    /* The trapped-MMIO dispatcher. Every access to a device window the guest's
     * own tree names arrives at EL2 and is answered here; these are the tally,
     * because there is one per character of the kernel's output and the event
     * log would be nothing else. `uart_tx` is the one that matters: it is how
     * many bytes XNU put on its own serial line, which is the difference
     * between a console that works and a console that was never reached. */
    uint64_t mmio_reads, mmio_writes, uart_tx;
    struct dockchannel uart;  /* what its config and mask registers remember */
    uint8_t console[CONSOLE_MAX];
    /* The terminal word: the last event recorded, held outside the ring.
     *
     * The log fills from the front and drops the rest, so what it keeps is the
     * START of the run. That is the right trade -- a MAP_PAGE we refused is a
     * fact wherever it sits -- but it means the END of a long run is not in
     * the log at all, and "what was the last thing that happened" is the
     * question every unexplained stop starts with. One slot, written by
     * record() before it decides whether the ring has room, answers it for
     * free and cannot be dropped. */
    struct event last;
    struct event log[EVENT_MAX];
    uint64_t fb_observed, fb_before;
    /* Append-only: keep existing report/collector state offsets stable. */
    struct guest_cpu_registry cpus;
    const struct secondary_config *host_cpus;
    uint64_t secondary_base;
    struct guest_cpu_release cpu_release;
    struct vcpu vcpus[GUEST_CPU_COUNT];
    uint64_t shadow_tlb_syncs, root_checks, root_busy_refusals;
    /* SNAP_DART_WIREDCNT (compat/dart-wiredcnt.h DWC_*): located text PA,
     * commits, entries subtracted, refusals, last refusal reason | table << 8.
     * In the former alignment hole before services: every build, zero unless
     * on, with no other offset or the context size changed. */
    uint64_t dart_wiredcnt[5];
    struct guest_service_lock services;
    uint64_t txm_image4_uuid_rejections;
    struct txm_nonce_registry txm_nonces;
#if SNAP_ROOT_CACHE_WIDE
    struct sptm_root_state_compat user_roots_host;   /* live: root_ext->roots */
#else
    struct sptm_root_state user_roots;
#endif
    uint64_t root_installed[GUEST_CPU_COUNT][2], root_install_failures;
    uint64_t const_reads[2], const_sealed_cpus, const_tlb_invalidations;
    uint64_t user_live_tables, user_live_pages, user_missing_tables;
    uint64_t user_unmap_calls, user_unmap_pages;
    uint64_t user_condemn_calls, user_uncondemn_calls, user_detach_calls;
    struct txm_nonce_digest_registry txm_nonce_digests;
    uint64_t user_comm_attach_calls,user_comm_attach_leaves;
    uint64_t shared_root_converts,shared_root_releases;
    struct sptm_root_configuration root_configuration;
    struct sptm_shared_registry shared_regions;
    struct txm_trust_state trust_state;
    struct sptm_nest_state nest_state;
    struct sprr_views kernel_views;
    uint64_t kernel_installed[GUEST_CPU_COUNT],kernel_view_failed;
    uint64_t papt_protects,papt_releases,kernel_permission_changes;
    uint64_t user_exec_protects,user_exec_releases,user_exec_cache_syncs;
    struct user_execution user_execution[GUEST_CPU_COUNT];
    struct sptm_panic_state panic_state;
    /* Physical exception-entry evidence; keep the existing vCPU ABI stable. */
    struct pan_entry_state {
        uint64_t mmfr1, installed_sctlr, user_vectors, protected_vectors;
        uint64_t vector, saved_spsr, entry_spsr, entry_sctlr;
    } pan_entry[GUEST_CPU_COUNT];
    struct user_clock_state {
        uint64_t reads, pc, word, value, spsr, sp, root, cntkctl;
        uint64_t raw, host_hz, guest_hz;
    } user_clock[GUEST_CPU_COUNT];
    struct user_map_conflict_state {
        uint64_t count, root, va, wanted, options, old, pointer, result;
    } user_map_conflict[GUEST_CPU_COUNT];
    struct user_sprr_state {
        uint64_t reads, pc, word, value, spsr, sp, root, umprr;
    } user_sprr[GUEST_CPU_COUNT];
    struct sprr_uperm_update_state {
        uint64_t writes,changes,pc,word,before,after,spsr,sp;
        uint64_t root,shadow,tables,pages,classes,umprr;
    } sprr_uperm_update[GUEST_CPU_COUNT];
    struct sprr_pperm_update_state {
        uint64_t transactions,grants,restores,before,after,pc;
        uint64_t user_root,user_shadow,user_tables,user_pages,user_classes;
        uint64_t kernel_root,kernel_tables,kernel_pages,kernel_classes;
    } sprr_pperm_update[GUEST_CPU_COUNT];
    struct sprr_views user_views[SPTM_ROOT_CACHE_COMPAT];
    struct user_view_state {
        uint64_t root,shadow,el0,uperm,pperm,umprr;
        uint64_t syncs,entries,returns;
    } user_view_state[GUEST_CPU_COUNT];
    uint64_t user_view_failed,user_tpro_protects,user_tpro_releases;
    struct sptm_user_update_state user_updates[GUEST_CPU_COUNT];
    struct sptm_user_update_state kernel_updates[GUEST_CPU_COUNT];
    uint64_t shared_plan_mask,shared_plan_root,shared_plan_va,shared_plan_count;
    uint64_t shared_map_calls,shared_map_inserts,shared_map_updates,shared_map_aliases;
    uint64_t shared_map_root,shared_map_va,shared_map_old,shared_map_next,shared_map_shift;
    uint64_t shared_map_mask,shared_unmap_calls,shared_unmap_pages;
    uint64_t shared_map_requested,shared_map_options,shared_map_result,shared_map_cpu;
    uint64_t unnest_calls,unnest_descriptors,unnest_leaves,unnest_root,unnest_shared;
    uint64_t unnest_va,unnest_pages,unnest_cpu,unnest_format;
    struct sptm_unnest_plan unnest_plan;
    struct sptm_shared_detach_state shared_detaches;
    struct sptm_user_update_state user_regions[GUEST_CPU_COUNT];
    uint64_t service_budget_stops[GUEST_CPU_COUNT];
    struct sptm_shared_update_state shared_regions_updates[GUEST_CPU_COUNT];
    struct pauth_user_state user_pauth[GUEST_CPU_COUNT];
    struct pauth_switch pauth_bank[GUEST_CPU_COUNT];
    struct pauth_domain pauth_domain;
    uint64_t pauth_key_version[GUEST_CPU_COUNT],pauth_key_valid[GUEST_CPU_COUNT];
    struct pauth_batch_state pauth_batch[GUEST_CPU_COUNT];
    struct pauth_pointer_state pauth_pointer[GUEST_CPU_COUNT];
    struct sptm_shared_update_state user_disjoint_unmaps[GUEST_CPU_COUNT];
    struct sptm_user_update_state user_map_replacements[GUEST_CPU_COUNT];
    struct txm_release_type txm_release_type;
    struct txm_local_key txm_local_key;
    struct table_pool table_pool;
    struct user_table_owner user_table_owner[SPTM_ROOT_CACHE_COMPAT];
    struct service_profile service_profile[GUEST_CPU_COUNT];
    struct step_translation step_translation[GUEST_CPU_COUNT];
    struct step_alu_state step_alu[GUEST_CPU_COUNT];
    struct native_call_state native_calls[GUEST_CPU_COUNT];
    uint64_t user_view_epoch;
    struct sprr_view_proof user_view_proofs[SPTM_ROOT_CACHE_COMPAT];
    struct sprr_view_proof_stats user_view_proof_stats[GUEST_CPU_COUNT];
    uint64_t user_only_tlbi[4]; /* leaf, unmap, commpage attach, nest */
    struct service_detail service_detail[GUEST_CPU_COUNT];
    struct sprr_publish_state kernel_publish_state;
    struct sprr_reuse_state kernel_reuse_state;
    uint64_t user_fused_syncs;
    struct sprr_class_proof kernel_class_proof;
    struct sprr_user_prepare_stats user_prepare_stats;
    struct sprr_user_prepare_plan user_prepare_plan;
    struct sprr_private_pages private_pages;
    struct root_publish_state root_publish;
    struct user_publish_stats user_publish;
    uint64_t user_table_reads[3]; /* calls, complete, errors */
    struct view_table_read_stats view_table_reads[2]; /* kernel, single-CPU user */
    struct sprr_user_zero_stats user_zero_groups;
    struct native_writer_debug writer_debug[GUEST_CPU_COUNT];
    uint64_t writer_breakpoints_enabled;
    struct sprr_store_compare_stats view_store_compare[2]; /* kernel, single-CPU user */
    struct sprr_store_compare_stats user_fused_compare;
    /* Appended: FEAT_AES present, set once by pauth_domain_prepare. */
    uint64_t aes_hardware;
    /* Appended: per-vCPU PAC key derivation memo (install and user signing). */
    struct pauth_derive_cache pauth_derive[GUEST_CPU_COUNT];
    /* Appended: mode switches skipped, sampled full syncs, and sampled syncs
     * that still had to store (must stay zero). */
    struct user_mode_skip_stats { uint64_t skips,checks,mismatches,differs; }
        user_mode_skip[GUEST_CPU_COUNT];
    /* Appended: guest BRK64 exceptions delivered to EL1 (TDE-routed). */
    struct guest_brk_stats { uint64_t el0,el1,last_pc,last_esr,last_spsr; }
        guest_brk[GUEST_CPU_COUNT];
    /* Appended (kernel-ops-perf): transaction dirty publication + sentinel. */
    struct txn_publish_stats txn_publish;
    /* Appended: PPERM transactions against the exact kernel reuse snapshot.
     * skipped kernel syncs; verified = sampled read-only checks of a skipped
     * view (1 per 64 skips); mismatches must stay zero. */
    struct kernel_pperm_reuse_stats {
        uint64_t calls,current,skipped,synced,repinned,verified,mismatches,errors;
    } kernel_pperm_reuse;
    /* Appended: user UPDATE_DISJOINT kernel refreshes skipped and their
     * sampled (1/64) all-CPU read-only kernel view verification. */
    struct user_update_skip_stats {
        uint64_t skipped,verified,mismatches;
    } user_update_skip;
    /* Appended: root installations whose inner private-copy TLBIs were folded
     * into the installation's final all-VMID invalidation. */
    struct install_tlbi_stats {
        uint64_t installs,pperm_folded,view_folded,failure_flushes;
    } install_tlbi;
    /* Appended: mapped class-proof walks and their sampled differential walks
     * through the original word reader (mismatches must stay zero). */
    struct class_proof_mapped_stats {
        uint64_t walks,tables,groups,empty_groups,compared,errors;
    } class_proof_mapped;
    /* Appended: SWITCH_ROOT word-load validations and sampled byte re-walks. */
    struct sptm_root_validate_stats root_validate;
    /* Appended: process-fatal EL0 exceptions passed to XNU's vector. */
    uint64_t guest_user_signal[GUEST_CPU_COUNT];
    /* Appended: per-page write witness for the table arena and per-user-view
     * private-copy claims (SNAP_USER_TREE_MEMO); present in every build so the
     * layout readers see one context size. */
    struct sprr_table_memo table_memo;
    struct sprr_view_memo user_view_memo[SPTM_ROOT_CACHE_COMPAT];
    /* SWITCH_ROOT found all SPTM_ROOT_CACHE slots named and took one from a
     * root no CPU had installed (its shadow is rebuilt on its next switch). */
    uint64_t root_evictions;
    /* Appended: table-arena pressure reclaim. root_stamp orders valid cached
     * roots by last installation (arena_reclaim.clock). low_water is the
     * fewest free arena pages seen at any monitor-call entry; slots/pages
     * count cache slots given back and their table pages (retired, invalid
     * and valid slots separately); alloc_failures counts table allocations
     * refused for lack of pages; build_retries counts SWITCH_ROOT builds
     * retried after a reclaim; flush_failures must stay zero. */
    uint64_t root_stamp[SPTM_ROOT_CACHE_COMPAT];
    struct arena_reclaim_stats {
        uint64_t checks,low_water,clock,reclaims,slots,pages;
        uint64_t retired,invalid,valid,alloc_failures,build_retries,flush_failures;
    } arena_reclaim;
    /* Appended: last EL0 crash-class events per vCPU (SNAP_USER_CRASH_RING);
     * present in every build so the layout readers see one context size. */
    struct user_crash_ring user_crashes[GUEST_CPU_COUNT];
    /* Appended: UPDATE_DISJOINT_MULTIPAGE calls and their per-frame groups. */
    uint64_t multipage_calls, multipage_groups;
    /* Appended: kernel-root MAP_PAGE answered CONFLICT(6), count and last. */
    struct kernel_map_conflict_state {
        uint64_t count, va, wanted, old, pointer;
    } kernel_map_conflict;
    /* Appended: PV self-checks (moved MAP_PAGE pointers, different-PA leaf
     * replacements, duplicate disjoint records); see struct sptm_pv_audit. */
    struct sptm_pv_audit pv_audit;
    /* Appended: kernel-root SPTM calls touching the linked AuxKC. Counters
     * only, never a gate: tools/auxkc_counters.py decodes this. */
    struct auxkc_exec_state auxkc_exec;
    /* Appended: the adopted Adreno (compat/adreno.h); tools/adreno_counters.py. */
    struct adreno_state gpu;
    /* Append only: preserve the report and all earlier private offsets.
     * console_put runs under the shared service lock. The host reads this
     * late-boot ring only after all guest CPUs have stopped. */
    uint64_t console_tail_bytes;
    uint8_t console_tail[CONSOLE_TAIL_MAX];
    /* Appended: endpoint8 kernel removals, latest and last changed per CPU. */
    struct sptm_shared_update_state kernel_disjoint_unmaps[GUEST_CPU_COUNT];
    /* Appended: successful DEFAULT -> TXM_DEFAULT ownership transitions. */
    uint64_t txm_donations;
    uint64_t txm_imports,txm_releases;
    struct txm_native_state txm_native;
    struct txm_load_state txm_load;
    /* Appended private cache; its scalar prefix is captured independently.
     * Present even when disabled so host readers have one context layout. */
    struct sprr_class_leaf_cache class_leaf;
    /* Appended: policy loaded by the last successful SWITCH_ROOT on each CPU,
     * separately from root metadata subsequently changed by CONFIGURE_ROOT. */
    struct sptm_loaded_root root_loaded[GUEST_CPU_COUNT];
    /* SNAP_DART_WIREDCNT: Adreno DART level-1 slots whose table holds the
     * monitor's one reference (compat/dart-wiredcnt.h). In the former
     * alignment hole before perf: every build, zero unless on. */
    uint64_t dart_wiredcnt_pins[2];
    /* Appended (perf): fast-trap/census counters, the publication index and
     * canonical-view proof counters, zero unless their define is on. Present
     * in every build so layout readers see one context size;
     * tools/perf_counters.py decodes it. */
    struct perf_state perf;
    /* Appended service-lock-protected request capture; never guest key state. */
    uint8_t sep_sks_request[SEP_SKS_WIRE_MAX];
    /* Appended: SWITCH_ROOT level-3 verdict memo (SNAP_ROOT_VALIDATE_MEMO);
     * its stats prefix is a kernel-ops-perf record. Present in every build so
     * layout readers see one context size. */
    struct sptm_root_memo root_memo;
    /* Appended: memory-attribute changes (UPDATE options 0x10/0x20 and the
     * MULTIPAGE aperture AttrIndx step). cleans counts frames cleaned to PoC
     * before a commit, recleans the same frames again once that transaction's
     * TLBI completed (pending holds them in between), apertures the aperture
     * leaves rewritten; last_* describe the latest aperture step. */
    struct attr_update_state {
        uint64_t cleans,recleans,refused,apertures,last_pa,last_before,last_after,pending;
        uint64_t pending_pa[SPTM_DISJOINT_MAX];
    } attr_updates;
    /* Appended: early-stop request and outcome (compat/early-stop.h). Present
     * in every build so layout readers see one context size. */
    struct early_stop_state early_stop;
    /* Appended: inactive-root mirroring (SNAP_INACTIVE_MIRROR); its stats
     * prefix is a kernel-ops-perf record. budget[slot] counts fresh leaves
     * committed into that cache slot since its root was last installed.
     * Present in every build so layout readers see one context size. */
    struct inactive_mirror_state {
        struct inactive_mirror_stats stats;
        uint64_t budget[SPTM_ROOT_CACHE_COMPAT];
    } inactive_mirror;
    /* Appended: native page tables (SNAP_NATIVE_TABLES). Per-CPU variant
     * selection (compat/native-select.h); one bit per arena page whose stores
     * are propagated into variant copies; counters. Present in every build so
     * layout readers see one context size. */
    struct native_cpu native_cpu[GUEST_CPU_COUNT];
    uint64_t native_sources[MONITOR_ARENA_PAGES/64];
    struct native_table_stats {
        uint64_t propagated,refused,paths,syncs,installs,local_flushes,flips;
        uint64_t tlbi_calls,tlbi_pages,tlbi_full;
        uint64_t audit_asks,audits,audit_failures,hit_asks,hit_skips,proof_asks,proof_skips;
        uint64_t pperm_skips;
        /* Phase 2a: PPERM transactions. */
        uint64_t reuse_asks,reuse_checks,reuse_failures,pperm_flushes;
        /* Phase 3: roots cached at their constructor, and those it could not
         * cache (no slot or no page); full coverage audits. */
        uint64_t created,uncreated,coverages;
    } native_stats;
    /* Appended: shared-region groups (SNAP_NATIVE_SHARED), in every build. */
#if SNAP_ROOT_CACHE_WIDE
    struct native_shared_compat native_shared_host;  /* live: root_ext->native_shared */
#else
    struct native_shared native_shared;
#endif
    /* Appended in every build so offline layout readers agree. */
    struct native_hvc_state sptm_hvc[GUEST_CPU_COUNT];
    /* Appended: the device deadline timer_sync last armed for, per vCPU, as
     * guest ticks and host physical time (UINT64_MAX: none; zero until the
     * first sync, which makes the fast write decline). SNAP_FAST_TIMER_WRITE
     * rearms with it and declines once it has passed. */
    struct fast_timer_due { uint64_t guest,physical; } fast_timer_due[GUEST_CPU_COUNT];
    /* Appended: each CPU's other kernel copy column (SNAP_KERNEL_PPERM_VARIANTS). */
    struct sprr_view_variants kernel_variants;
    /* Appended: the first CONSOLE_LOG_MAX console bytes, never overwritten;
     * console_tail keeps the end. Both count with console_tail_bytes. */
    uint8_t console_log[CONSOLE_LOG_MAX];
    /* Appended: the two-way console (compat/console-link.h): q1n1's view, the
     * DockChannel receive ring, and what every host poll cost. Present in
     * every build so layout readers see one context size. */
    struct console_link console_link;
    /* Appended: UPDATE_DISJOINT records naming a configured shared-region root
     * (XNU aging the shared cache, compat/sptm-user.c), per CPU: the record
     * count and the latest one (root, VA, template, options, result, target,
     * the old leaf it returned; slot holds the caller's ELR). Diagnostic only. */
    uint64_t shared_disjoint_records[GUEST_CPU_COUNT];
    struct sptm_user_update_state shared_disjoint[GUEST_CPU_COUNT];
    /* Appended: per CPU, 1 + the shared-region slot of the last user root installed since this CPU's last full local
     * flush (0: none cached). Shared-region leaves are global (no nG), so a user-to-user TTBR0 switch keeps the
     * previous region's translations. SPTM's SWITCH_ROOT flushes them when the incoming root's slot differs
     * (sptm.t8140.release 0xfffffff02710050c: ldrb w25,[x19,#8] against the per-CPU byte, then tlbi rvaae1nxs or
     * vmalle1nxs); user_root_install does the same with a local tlbi vmalle1. Without it, the fast variant (no
     * per-exception guard flushes) ran processes on another region's shared-cache bytes: the v14-v16 crash storm. */
    uint16_t user_shared_slot[GUEST_CPU_COUNT];
    uint64_t shared_switch_flushes[GUEST_CPU_COUNT];
    struct a16_thermal_state *thermal; /* optional monitor-only arena page */
#if SNAP_ROOT_CACHE_WIDE
    /* The wide root cache's state (monitor arena pages, setup); appended in
     * the context's last page (the former tail padding), asserted below. */
    struct root_ext *root_ext;
#endif
#if SNAP_USER_HW_WALK
    /* compat/user-hw-walk.h: records, copies index and counters, in monitor
     * arena pages taken at setup (owner 0, never released); appended in the
     * context's last page, asserted below. */
    struct hw_walk_state *hw_walk;
#endif
#if SNAP_S2_FAULT_RETRY
    /* compat/s2-fault-retry.h: counters, per-vCPU bounds and the snapshot
     * ring, in a monitor arena page taken at setup (owner 0, never released). */
    struct s2_retry_state *s2_retry;
#endif
#if SNAP_GUEST_NET
    /* compat/guest-net-link.h: the link, the net view and POLL2's views, in
     * monitor arena pages taken at setup (owner 0, never released). */
    struct guest_net_state *guest_net;
#endif
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
    /* Appended only under these opt-in defines, inside the page before the
     * table arena (asserted below), so define-free layout readers keep every
     * offset and the arena base (compat/perf-state.h struct exit_profile). */
    struct exit_profile exit_profile;
#endif
};
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,exit_profile)+4095)/4096,
               "the exit profile must not move the table arena (next_table, probes/run.py)");
#endif
#if SNAP_GUEST_NET
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,guest_net)+4095)/4096,
               "the guest-network pointer must not move the table arena (next_table, probes/run.py)");
#endif
#if SNAP_USER_HW_WALK
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,hw_walk)+4095)/4096,
               "the hardware-walk pointer must not move the table arena (next_table, probes/run.py)");
static struct hw_walk_root *hw_root(struct context *,uint64_t);
static struct hw_walk_ops hw_ops(struct context *);
static void hw_install_user(struct context *,uint64_t,uint64_t,unsigned);
static int hw_fail(struct context *);
#if SNAP_USER_HW_WALK_S2RO
static int hw_s2_presplit_all(struct context *);
#endif
#endif
#if SNAP_ROOT_CACHE_WIDE
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,root_ext)+4095)/4096,
               "the wide root cache must not move the table arena (next_table, probes/run.py)");
#if SNAP_FINE_LOCKS
/* SNAP_FINE_LOCKS (compat/fine-lock.h): the stripes, aux and each CPU's
 * converted-call state, in the wide cache's arena pages (monitor-only,
 * written without notes, excluded from the publication sentinel). */
struct fine_cpu {
    struct fine_lockset locks;      /* this call's stripes */
    uint64_t stores;                /* stores made by this call (decline vs fatal) */
    uint64_t aux_wait;              /* this call's aux wait ticks */
    int alloc_refused;              /* this call's shadow allocator was asked */
    struct sptm_pv_audit audit;     /* this call's audit share, merged on success */
    struct fine_profile profile;
    struct sptm_ref_fine ref_fine;  /* this call's reference snapshots */
#if SNAP_SPTM_FINE_RETYPE
    struct sptm_frame_held frames;  /* this call's frame locks (compat/sptm-frame-lock.h) */
#endif
} __attribute__((aligned(64)));
struct fine_state {
    struct fine_ticket stripes[FINE_STRIPES];
    struct fine_ticket aux;
    struct fine_cpu cpu[GUEST_CPU_COUNT];
    struct sptm_ref_batch refs[GUEST_CPU_COUNT];
#if SNAP_SPTM_FINE_KERNEL
    struct fine_ticket kernel;      /* KL: converted kernel-root calls (compat/sptm-fine.h) */
#endif
#if SNAP_SPTM_FINE_RETYPE
    struct sptm_frame_locks frame_locks;
#endif
};
#endif
/* Every slot's state, SPTM_ROOT_CACHE of each (compat/root-wide.h). */
struct root_ext {
    struct sptm_root_state roots;
    struct native_shared native_shared;
    struct sprr_views views[SPTM_ROOT_CACHE];
    struct user_table_owner owner[SPTM_ROOT_CACHE];
    struct sprr_view_proof proofs[SPTM_ROOT_CACHE];
    struct sprr_view_memo memo[SPTM_ROOT_CACHE];
    uint64_t stamp[SPTM_ROOT_CACHE],budget[SPTM_ROOT_CACHE];
    sptm_root_mask_t shared_plan_mask;
#if SNAP_FINE_LOCKS
    struct fine_state fine;
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    struct sptm_nest_fast_stats nest_fast;    /* compat/nest-fast.h, reported (OUT_TOKEN_COSTS) */
#endif
#if SNAP_ROOT_INDEX
    struct sptm_root_index root_index;        /* compat/root-index.h, stats reported */
#endif
#if SNAP_OTHER_PROFILE
    struct other_profile other;               /* compat/token-costs.h */
#endif
#if SNAP_DART_MEMO
    struct sptm_dart_memo dart_memo;          /* compat/sptm-dart-memo.h, under the token (OUT_DART_MEMO) */
#endif
#if SNAP_GATE_WAIT
    uint64_t gate[16];                        /* waited, wait ticks, timeouts, stopped (atomic) */
#endif
#if SNAP_TOKEN_TRIM
    struct token_trim_state trim;             /* compat/token-trim.h (OUT_TOKEN_TRIM) */
#endif
#if SNAP_DART_CONVERTED
    struct dart_converted_state dart_cv;      /* compat/dart-converted.h (no record of its own) */
#endif
#if SNAP_FAST_IPI
    struct fast_ipi_cpu fast_ipi[GUEST_CPU_COUNT];  /* compat/fast-ipi.h, that CPU's (OUT_FAST_IPI) */
#endif
#if SNAP_FAST_TIMER_IRQ_CPU0
    struct fast_irq_cpu0 cpu0_tick;                 /* compat/fast-timer-irq.h, vCPU 0's only */
#endif
#if SNAP_LEAN_TRAPS
    struct lean_trap_cpu lean[GUEST_CPU_COUNT];     /* compat/lean-trap.h, that CPU's (not reported) */
#endif
#if SNAP_EL0_MEMO
    struct el0_memo_cpu el0_memo[GUEST_CPU_COUNT];         /* compat/el0-memo.h, that CPU's (not reported) */
    struct pauth_derive_wide derive_wide[GUEST_CPU_COUNT]; /* compat/pauth-domain.h, that CPU's */
    uint64_t pauth_epoch;                                  /* xnuboot_prepare: one per domain preparation */
#endif
#if SNAP_FAST_TIMER_IRQ
    struct fast_irq_cpu fast_irq[GUEST_CPU_COUNT];  /* compat/fast-timer-irq.h, that CPU's (OUT_FAST_IRQ) */
#endif
#if SNAP_ADRENO_IB_ASYNC
    /* compat/adreno-ib.h: the IB in flight and its counters (OUT_IB_ASYNC), under the token. Here because the
     * context's last page is full (a member would move the table arena) and these pages are monitor-only arena
     * pages already (zeroed at setup, txn_publish_exclude). Last, so no other member moves. */
    struct adreno_ib_flight ib_flight;
#endif
#if SNAP_CPU_DVFS
    struct cpu_dvfs_state cpu_dvfs;   /* compat/cpu-dvfs.h: vCPU 0's tick and the stop only (OUT_DVFS); last */
#endif
#if SNAP_GPU_DVFS
    struct gpu_dvfs_state gpu_dvfs;   /* compat/gpu-dvfs.h: under the token (OUT_DVFS); last */
#endif
#if ADRENO_VA_WIDE && SNAP_DART_WIREDCNT
    /* agents/gpu-va-wide V15: level-1 slots 0..511 (the context keeps its 2-word, slots 0..127 field so its
     * page count, and the table arena after it, do not move); zeroed with the rest of root_ext at setup. */
    uint64_t dart_wiredcnt_pins_wide[DWC_PIN_WORDS];
#endif
#if SNAP_ANS_ASYNC
    /* agents/nvme-async: the virtual ANS2's state when its window backend is adopted (ans_window_prepare), else
     * 0; read lock-free by timer_arm and the fast tick for the poll schedule (struct ans_async). Last. */
    struct ans_state *ans;
#endif
#if SNAP_ANS_CONVERTED
    /* The ANS device lock (FIFO, L1.5 beside the DART's) and this CPU's wait for the converted call in progress. */
    struct fine_ticket ans_lock;
    uint64_t ans_wait[GUEST_CPU_COUNT][2];
#endif
#if SNAP_ATTR_CLEAN_DEFER
    /* (d) Each CPU's second cleans of an attribute change, deferred past the token (attr_clean_finish). */
    struct attr_defer_cpu {uint64_t count,deferred,overflow,flushed;uint64_t pa[ATTR_DEFER_MAX];} attr_defer[GUEST_CPU_COUNT];
#endif
#if SNAP_ADRENO_RECOVER
    /* compat/adreno-ib.h (agents/gpu-recovery): level, epoch, the give-up state, the SQE sum. Under the token. Last, so
     * no other member moves; its counters ride in the IBASYNC1 record's reserved words and in EV_GPU_RECOVER. */
    struct adreno_recover_state gpu_recover;
#endif
#if SNAP_MULTIPAGE_FAST
    /* agents/sptm-locks/multipage: each vCPU's aperture targets cleaned before this trap took the token (P2;
     * frames counts them), and the batch counters, written under the token (P17). */
    struct multipage_preclean_cpu {uint64_t count,frames;uint64_t pa[SPTM_MULTIPAGE_MAX];} multipage_preclean[GUEST_CPU_COUNT];
    struct multipage_fast_stats {
        uint64_t preclean_hits,inline_cleans,same_class,patched,unpatched,variants,closes,barrier_closes,failures;
    } multipage_fast;
#endif
};
#if ADRENO_VA_WIDE && SNAP_DART_WIREDCNT
/* The wide bitmap replaces the context's field for all monitor code (as user_roots below). */
#define dart_wiredcnt_pins root_ext->dart_wiredcnt_pins_wide
#endif
#if SNAP_ADRENO_IB_ASYNC
#define IB_FLIGHT(c) (&(c)->root_ext->ib_flight)
#endif
#if SNAP_ADRENO_RECOVER
#define GPU_RECOVER(c) (&(c)->root_ext->gpu_recover)
#endif
#if SNAP_EL0_MEMO
#define EL0M(c) ((c)->root_ext->el0_memo)
#endif
#define ROOT_EXT_PAGES ((sizeof(struct root_ext)+4095)/4096)
/* The live state replaces the define-free fields for all monitor code. */
#define user_roots root_ext->roots
#define UNS(c) ((c)->root_ext->native_shared)
#define UVIEWS(c) ((c)->root_ext->views)
#define UOWNERS(c) ((c)->root_ext->owner)
#define UPROOFS(c) ((c)->root_ext->proofs)
#define UMEMOS(c) ((c)->root_ext->memo)
#define USTAMPS(c) ((c)->root_ext->stamp)
#define UBUDGETS(c) ((c)->root_ext->budget)
#define ROOT_PLAN_SET(c,m) ((c)->root_ext->shared_plan_mask=(m),(c)->shared_plan_mask=SPTM_ROOT_MASK_LOW(m))
#define ROOT_PLAN_MASK(c) ((c)->root_ext->shared_plan_mask)
#else
#define UNS(c) ((c)->native_shared)
#define UVIEWS(c) ((c)->user_views)
#define UOWNERS(c) ((c)->user_table_owner)
#define UPROOFS(c) ((c)->user_view_proofs)
#define UMEMOS(c) ((c)->user_view_memo)
#define USTAMPS(c) ((c)->root_stamp)
#define UBUDGETS(c) ((c)->inactive_mirror.budget)
#define ROOT_PLAN_SET(c,m) ((c)->shared_plan_mask=(m))
#define ROOT_PLAN_MASK(c) ((c)->shared_plan_mask)
#endif
#if SNAP_TXM_ASPACE_WIDE
/* compat/txm.h A3/A5: the 4096-slot registry takes the arena pages after the
 * context and root_ext; xnuboot_setup refuses an unaligned work base, so the
 * context's address plus this constant is that page. */
#define TXM_EXT_PAGES ((sizeof(struct txm_registry)+4095)/4096)
#if SNAP_ROOT_CACHE_WIDE
#define TXM_EXT_AFTER_ROOT (ROOT_EXT_PAGES*4096)
#else
#define TXM_EXT_AFTER_ROOT 0
#endif
#define TXM_EXT_OFFSET ((((uint64_t)sizeof(struct context)+0xfffUL)&~0xfffUL)+(uint64_t)TXM_EXT_AFTER_ROOT)
#define TXM_REG(c) ((struct txm_registry *)((uint64_t)(c)+TXM_EXT_OFFSET))
_Static_assert(__builtin_offsetof(struct context,txm_registry_host)==8 &&
               sizeof(struct txm_registry_compat)==17952,
               "the define-free TXM registry keeps its offset and size (host readers)");
#else
#define TXM_REG(c) (&(c)->txm_registry)
#endif

/* The vector ABI is private to each CPU, including failure and return state. */
_Static_assert(__builtin_offsetof(struct vcpu, el2_sp) == 0, "CPU return stack ABI");
_Static_assert(__builtin_offsetof(struct vcpu, out_ptr) == 8, "CPU output ABI");
_Static_assert(__builtin_offsetof(struct vcpu, bad_elr) == 16, "CPU bad ELR ABI");
_Static_assert(__builtin_offsetof(struct vcpu, bad_far) == 24, "CPU bad FAR ABI");
_Static_assert(__builtin_offsetof(struct vcpu, context) == 32, "PA context ABI");
_Static_assert(__builtin_offsetof(struct vcpu, slot) == 40, "PA CPU slot ABI");
_Static_assert(__builtin_offsetof(struct context, pauth_bank) == PAUTH_BANK_CONTEXT,"PA bank context ABI");
_Static_assert(sizeof(struct vcpu)==2368,"unchanged private CPU stride");
#if SNAP_BOOT_RELOCATE
/* Secondary record page 0 (otherwise unused): secondary_entry's record first,
 * then the relocation's own state. Host readers: tools/secondary-runtime.py. */
#define BOOT_HOST_WORDS 11
struct boot_relocation {
    struct secondary record;
    uint64_t armed, launched, handed_back, captured;
    uint64_t launch_tick, handback_tick, stop_requested, quarantined, wait_polls;
    uint64_t id_mismatch;
    /* The guest clock is CNTVCT_EL0 at EL2 (clock_counter): CNTPCT minus this
     * CPU's CNTVOFF_EL2, which the monitor never programs. Both CPUs' values,
     * and CNTFRQ_EL0, must agree for vCPU 0 to keep q1n1's CPU's timebase. */
    uint64_t boot_cntvoff, target_cntvoff, boot_cntfrq, target_cntfrq;
    /* q1n1's CPU's own values of what vcpu_arch_prepare saves and the report
     * restores: VTTBR VTCR VMPIDR CNTKCTL CNTHCTL MDCR MDSCR OSLSR TTBR0 TTBR1 MAIR. */
    uint64_t host[BOOT_HOST_WORDS];
    uint64_t boot_cache[2], target_cache[2];   /* CTR_EL0, DCZID_EL0 */
    uint64_t boot_id[BOOT_ID_COUNT], target_id[BOOT_ID_COUNT];   /* BOOT_RELOCATE_ID_REGS order */
    struct boot_relay relay;
};
_Static_assert(__builtin_offsetof(struct boot_relocation, armed) == BOOT_RELOCATE_ARMED,
               "the exit path reads armed");
_Static_assert(sizeof(struct boot_relocation) <= 4096, "record page 0");
_Static_assert(__builtin_offsetof(struct context, secondary_base) == CONTEXT_SECONDARY_BASE,
               "the exit path reads secondary_base");
static struct boot_relocation *boot_relocation_of(const struct context *c)
{
    struct boot_relocation *r = (struct boot_relocation *)c->secondary_base;
    return r && r->armed ? r : 0;
}
static int boot_relocation_on_boot_cpu(const struct context *c)
{
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return c->host_cpus && (mpidr & BOOT_RELOCATE_AFFINITY) == c->host_cpus->boot_affinity;
}
#endif

static struct vcpu *vcpu_of(const struct context *c)
{
    /* c documents the shared owner; selection is always this PE's TPIDR. */
    (void)c;
    uint64_t p;
    __asm__ volatile("mrs %0, tpidr_el2" : "=r"(p));
    return (struct vcpu *)p;
}

/* SNAP_SERVICE_SUBCLASS hooks; nothing at all without it. SERVICE_SUB_TAG
 * names what the locked handler decoded its entry to be (charged by
 * runtime_leave); FAST_EXIT_MARK records a lock-free exit's class in frame
 * slot 31 over sync_lower's start tick; FAST_EXIT_END, at the end of
 * xnuboot_pauth_resume, charges the round trip. */
#if SNAP_SERVICE_SUBCLASS
static void fast_exit_end(struct context *c,const struct vcpu *v,const uint64_t *frame)
{
    uint64_t now;
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(now)::"memory");
    fast_exit_charge(&c->exit_profile.cpu[v->slot],frame[31],now);
}
#define SERVICE_SUB_TAG(c,tag) service_sub_tag(&(c)->exit_profile.sub,(unsigned)vcpu_of(c)->slot,(tag))
#define FAST_EXIT_MARK(frame,slot) ((frame)[31]=fast_exit_mark((frame)[31],(slot)))
#define FAST_EXIT_END(c,v,frame) fast_exit_end((c),(v),(frame))
#else
#define SERVICE_SUB_TAG(c,tag) ((void)0)
#define FAST_EXIT_MARK(frame,slot) ((void)0)
#define FAST_EXIT_END(c,v,frame) ((void)0)
#endif

static struct context *context_of(void)
{
    return vcpu_of(0)->context;
}

static uint64_t service_profile_clock(void);
static int detail_begin(struct context *c,unsigned kind)
{
#if SNAP_SERVICE_DETAIL
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    /* Initial table construction precedes lock profiling and is deliberately
     * excluded. Otherwise the detailed totals could exceed runtime hold. */
    if(c->service_profile[cpu].stage!=2)return 0;
    return service_detail_begin(&c->service_detail[cpu],kind,service_profile_clock());
#else
    (void)c;(void)kind;return 0;
#endif
}
static void detail_end(struct context *c,unsigned kind,int started,int success)
{
#if SNAP_SERVICE_DETAIL
    if(started)service_detail_end(&c->service_detail[vcpu_of(c)->slot],kind,
                                 service_profile_clock(),success);
#else
    (void)c;(void)kind;(void)started;(void)success;
#endif
}

/* Both reads occur while q1n1's event loop and timer UI are suspended: one
 * before ERET, one before returning to q1n1. Unlike USB-side samples, status
 * redraws cannot produce a false difference during this interval. The hash
 * witnesses writes, not their glyph semantics; acquisition and capture still
 * need to agree. This code only reads the framebuffer. */
static uint64_t framebuffer_hash(const struct params *p)
{
    uint64_t hash = 0xcbf29ce484222325UL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (uint64_t i = 0; i < p->fb_span; i += 8)
        hash = (hash ^ *(volatile uint64_t *)(p->fb_pa + i)) * 0x100000001b3UL;
    return hash;
}

static int mem_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    *out = *(volatile uint64_t *)pa;
    return 0;
}

#if SNAP_NATIVE_SHARED
/* A root build, NEST or UNNEST linking cached slot `slot`'s tree `s`. */
struct native_links {struct context *c;struct shadow *s;unsigned slot;uint64_t shared;};
static void native_group_release(void *,uint64_t);
static int native_group_unlinked(struct context *,int);
static int user_live_write(void *,uint64_t,uint64_t);
static uint64_t native_shared_root_of(struct context *,uint64_t);
static struct sptm_root_links native_links_for(struct native_links *);
#if SNAP_ROOT_MISS_FAST
static int nl_grouped(void *,uint64_t,uint64_t);
#endif
#endif
#if SNAP_NATIVE_TABLES
static int native_reuse_current(struct context *,const struct shadow *,const uint64_t *);
static int native_store_admit(struct context *,uint64_t,uint64_t);
static int native_store_propagate(struct context *,uint64_t,uint64_t);
static int native_due(uint64_t *);
static void native_mark(struct context *,const struct sprr_views *,int);
#endif
static int mem_write(void *ctx, uint64_t pa, uint64_t value)
{
#if SNAP_NATIVE_TABLES
    /* Before the store: a raw TPRO leaf may enter only a table with variant
     * copies, and a table with copies only a value they can translate. */
    if(native_store_admit(ctx,pa,value))return -1;
#endif
#if SNAP_USER_VIEW_CACHE || SNAP_KERNEL_CLASS_PROOF || SNAP_ROOT_DIRTY_PUBLISH || SNAP_USER_TREE_MEMO
    struct context *c=ctx;
    /* Callback-based canonical stores, separate from the pointer-based SPTM
     * transactions below. Identical stores leave either proof unchanged. */
    if(pa>=c->work_base && pa<c->next_table && c->next_table-pa>=8 &&
       *(volatile uint64_t *)pa!=value) {
#if SNAP_USER_TREE_MEMO
        /* First, so even a store refused below cannot leave a stale claim.
         * Canonical and private pages alike: both are memo inputs. */
        sprr_table_memo_note(&c->table_memo,pa);
#endif
#if SNAP_ROOT_DIRTY_PUBLISH
#if SNAP_INCREMENTAL_PUBLISH
        if(!root_index_note(&c->root_publish,&c->perf.root_index,c->work_base,
                            c->next_table,pa,8))return -1;
#else
        if(!root_publish_note(&c->root_publish,c->work_base,c->next_table,pa,8))return -1;
#endif
#endif
#if SNAP_TXN_DIRTY_PUBLISH
        txn_publish_observe(&c->txn_publish,pa,8);
#endif
#if SNAP_USER_VIEW_CACHE
#if SNAP_PRIVATE_VIEW_EPOCH
        int private=sprr_private_write(&c->private_pages,c->work_base,c->next_table,pa);
        if(private<0)return -1;
        if(!private)
#endif
        sprr_view_epoch_advance(&c->user_view_epoch);
#endif
#if SNAP_KERNEL_CLASS_PROOF
        sprr_class_proof_note(&c->kernel_class_proof,pa);
#endif
    }
#elif !SNAP_NATIVE_TABLES
    (void)ctx;
#endif
    *(volatile uint64_t *)pa = value;
#if SNAP_NATIVE_TABLES
    /* After it: the same entry of both variant copies (O(1)). */
    if(native_store_propagate(ctx,pa,value))return -1;
#endif
    return 0;
}

/* Copy the guest's registers out of the exception frame.
 *
 * `frame` is what sync_lower pushed, and it pushed x0..x30 before executing
 * anything else, so these are the guest's values and not EL2's. SP and SPSR are
 * read here instead. XNU normally runs with SP_EL0 selected; its exception
 * entry switches to SP_EL1. SPSR_EL2 identifies the stack at this EL2 trap.
 * A capture at XNU's vector needs the original SPSR_EL1 instead (below). */
/* Filled in place, one word at a time, and never by assigning the struct.
 *
 * `*dst = src` and any bulk copy of the register array is lowered by clang into
 * a call to memcpy, which -ffreestanding does not prevent -- it only promises
 * the compiler will not assume the *semantics* of the library, not that it will
 * stop emitting calls into it. This probe links against no libc, so that call
 * has nothing to resolve and the link fails with an undefined symbol for a
 * function the source never mentions. The destinations are volatile so the
 * stores cannot be recognised as a copy idiom and folded back into one. */
static void fill_regs(volatile struct guest_regs *dst, const uint64_t *frame,
                      uint64_t esr, uint64_t pc, uint64_t far)
{
    for (unsigned n = 0; n < 31; n++) dst->x[n] = frame[n];
    uint64_t sp, spsr;
    __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
    if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    dst->sp_el1 = sp;
    dst->spsr = spsr;
    dst->pc = pc;
    dst->esr = esr;
    dst->far = far;
}

static void capture_regs(struct context *c, const uint64_t *frame,
                         uint64_t esr, uint64_t pc, uint64_t far)
{
    uint64_t spsr, sp;
    __asm__ volatile("mrs %0, spsr_el1" : "=r"(spsr));
    if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    if (!vcpu_of(c)->exceptions) {
        fill_regs(&vcpu_of(c)->first_exc, frame, esr, pc, far);
        vcpu_of(c)->first_exc.spsr = spsr;
        vcpu_of(c)->first_exc.sp_el1 = sp;
    }
    fill_regs(&vcpu_of(c)->last_exc, frame, esr, pc, far);
    vcpu_of(c)->last_exc.spsr = spsr;
    vcpu_of(c)->last_exc.sp_el1 = sp;
    vcpu_of(c)->exceptions++;
}

static uint64_t table_alloc_owned(struct context *c,unsigned owner)
{
    uint32_t used=(uint32_t)((c->next_table-c->work_base)/4096);
    uint32_t capacity=(uint32_t)((c->work_end-c->work_base)/4096);
    int index=table_pool_take(&c->table_pool,&used,capacity,owner);
    if(index<0) {c->arena_reclaim.alloc_failures++;return 0;}
    uint64_t table=c->work_base+(uint64_t)index*4096;
    c->next_table=c->work_base+(uint64_t)used*4096;
#if SNAP_ROOT_DIRTY_PUBLISH
#if SNAP_INCREMENTAL_PUBLISH
    if(!root_index_note(&c->root_publish,&c->perf.root_index,c->work_base,
                        c->next_table,table,4096))return 0;
#else
    if(!root_publish_note(&c->root_publish,c->work_base,c->next_table,table,4096))return 0;
#endif
#endif
#if SNAP_TXN_DIRTY_PUBLISH
    txn_publish_observe(&c->txn_publish,table,4096);
#endif
#if SNAP_PRIVATE_VIEW_EPOCH
    if(!sprr_private_clear(&c->private_pages,(unsigned)index,0))return 0;
#endif
#if SNAP_KERNEL_CLASS_PROOF
    sprr_class_proof_note(&c->kernel_class_proof,table);
#endif
#if SNAP_USER_VIEW_CACHE
    sprr_view_epoch_advance(&c->user_view_epoch);
#endif
#if SNAP_USER_TREE_MEMO
    /* Zeroing below bypasses mem_write; reuse gets a new generation and
     * loses any summary. Only allocator-issued pages are memo-eligible. */
    sprr_table_memo_alloc(&c->table_memo,table);
#endif
    for (unsigned n = 0; n < 0x1000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;
    return table;
}
static uint64_t table_alloc(void *ctx) {return table_alloc_owned(ctx,0);}
static uint64_t user_table_alloc(void *ctx)
{
    struct user_table_owner *owner=ctx;
    return table_alloc_owned(owner->context,owner->owner);
}
static uint64_t private_table_alloc_owned(struct context *c,unsigned owner)
{
    uint64_t pa=table_alloc_owned(c,owner);
#if SNAP_PRIVATE_VIEW_EPOCH
    if(pa && !sprr_private_mark(&c->private_pages,(unsigned)((pa-c->work_base)/4096)))return 0;
#endif
    return pa;
}
static uint64_t private_kernel_alloc(void *ctx)
{return private_table_alloc_owned(ctx,0);}
static uint64_t private_user_alloc(void *ctx)
{
    struct user_table_owner *owner=ctx;
    return private_table_alloc_owned(owner->context,owner->owner);
}

/* The table walker is a separate observer from our stores; without this it
 * reads whatever was in memory before and reports a translation fault on an
 * entry software can plainly see is valid. */
static void publish(uint64_t start, uint64_t end)
{
    for (uint64_t line = start & ~63UL; line < end; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
}

#if SNAP_ROOT_DIRTY_PUBLISH
static int root_publish_page(void *ctx,uint64_t pa)
{
    (void)ctx;publish(pa,pa+4096);return 1;
}
#endif
#if SNAP_TXN_DIRTY_PUBLISH || SNAP_ROOT_PUBLISH_BATCH_DSB
/* publish() for one page without its trailing barrier. Nothing is stored
 * between the pages of one flush, so a single dsb ish after the last page
 * gives exactly the completion guarantee of one per page before the TLBI. */
static int publish_page_lines(void *ctx,uint64_t pa)
{
    (void)ctx;
    for(uint64_t line=pa;line<pa+4096;line+=64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    return 1;
}
#endif

static int kernel_table_read(void *ctx,uint64_t pa,uint64_t *out)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;
    return mem_read(ctx,pa,out);
}
#if SNAP_CLASS_PROOF_MAPPED
/* kernel_table_read's bounds applied to a whole page-aligned table: accepted
 * iff all 512 word reads of that page would be accepted. Canonical kernel
 * tables are monitor-owned, guest read-only at stage 2 and stable under the
 * service token for the whole walk. */
static const volatile uint64_t *class_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096)return 0;
    return (const volatile uint64_t *)pa;
}
#endif
static int kernel_table_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;
#if SNAP_KERNEL_DIRTY_PUBLISH
    if(*(volatile uint64_t *)pa==value)return 0;
    if(!sprr_publish_note(&c->kernel_publish_state,&c->kernel_views,pa)) {
        c->kernel_view_failed=1;return -1;
    }
#endif
    return mem_write(ctx,pa,value);
}
/* Admission is separate from breakpoint enablement. Until every publication
 * path and the breakpoint lifecycle are qualified, writer guards stay intact.
 * The physical pages come from the loader's relocated, full-image inventory. */
static int native_writer_admit(struct context *c,enum native_writer_regime regime,
    uint64_t va,uint64_t pa,uint64_t size,uint64_t low,uint64_t upper)
{
    const struct params *p=c->params;
    if(p->stub_count!=(NATIVE_COMPILED_FLAGS|NATIVE_CONTRACT_PAGES))return 0;
    struct native_writer_mapping mapping={{p->stub_pa[NATIVE_CALL_PAGES],
                                          p->stub_pa[NATIVE_CALL_PAGES+1]}};
    return native_writer_mapping_admit(&mapping,regime,va,pa,size,low,upper);
}
static int native_writer_admit_high(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{return native_writer_admit(ctx,NATIVE_WRITER_KERNEL_HIGH,va,pa,size,low,upper);}
static int native_writer_admit_low(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{return native_writer_admit(ctx,NATIVE_WRITER_KERNEL_LOW,va,pa,size,low,upper);}
static int native_writer_admit_user(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{return native_writer_admit(ctx,NATIVE_WRITER_USER,va,pa,size,low,upper);}

static struct shadow kernel_shadow(struct context *c)
{
    return (struct shadow){.txsz=17,.root=c->vcpus[0].shadow_root,
        .alloc=private_kernel_alloc,.read=kernel_table_read,.write=kernel_table_write,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
}
#if SNAP_VIEW_TABLE_READ
static const volatile uint64_t *view_table_read(struct context *c,uint64_t pa,unsigned kind)
{
    struct view_table_read_stats *st=&c->view_table_reads[kind];
    if(st->errors)return 0;
    sprr_count(&st->map_calls);
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096) {
        sprr_count(&st->errors);return 0;
    }
    sprr_count(&st->map_complete);
    return (const volatile uint64_t *)pa;
}
static const volatile uint64_t *kernel_view_table_read(void *ctx,uint64_t pa)
{return view_table_read(ctx,pa,0);}
static const volatile uint64_t *user_view_table_read(void *ctx,uint64_t pa)
{return view_table_read(ctx,pa,1);}
#endif
#if SNAP_VIEW_STORE_COMPARE
static const volatile uint64_t *private_copy_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if(c->private_pages.errors || (pa&4095) || pa<c->work_base ||
       pa>=c->next_table || c->next_table-pa<4096)return 0;
    uint64_t index=(pa-c->work_base)/4096;
    if(index>=SPRR_PRIVATE_PAGES ||
       !(c->private_pages.bitmap[index/64]&(UINT64_C(1)<<(index%64))))return 0;
    /* Read-only comparison of allocated private storage. Changed words still
     * go through kernel_table_write/user_private_write and their publication,
     * ownership, break-before-make and epoch accounting. */
    return (const volatile uint64_t *)pa;
}
#endif
static int kernel_sync_view(struct context *c,const struct shadow *s,unsigned cpu,uint64_t pperm)
{
#if SNAP_VIEW_TABLE_READ
    struct view_table_read_stats *st=&c->view_table_reads[0];
    if(st->errors)return 0;
    sprr_count(&st->calls);st->tables+=c->kernel_views.count;
#if SNAP_VIEW_STORE_COMPARE
    int ok=sprr_views_sync_cpu_compared(&c->kernel_views,s,cpu,pperm,
        kernel_view_table_read,private_copy_table_read,&c->view_store_compare[0]);
#else
    int ok=sprr_views_sync_cpu_mapped(&c->kernel_views,s,cpu,pperm,kernel_view_table_read);
#endif
    if(!ok) {
        sprr_count(&st->errors);return 0;
    }
    sprr_count(&st->complete);return 1;
#else
    return sprr_views_sync_cpu(&c->kernel_views,s,cpu,pperm);
#endif
}
static int kernel_publish_cpu(struct context *c,unsigned cpu)
{
#if SNAP_KERNEL_DIRTY_PUBLISH
    struct sprr_publish_state *state=&c->kernel_publish_state;
    if(cpu>=GUEST_CPU_COUNT || !sprr_publish_prepare(state,&c->kernel_views)) {
        c->kernel_view_failed=1;return 0;
    }
    /* Publish children before parents, including newly allocated zero pages,
     * so a visible copied parent cannot expose an unpublished copied child. */
    for(unsigned level=4;level--;)for(unsigned n=0;n<c->kernel_views.count;n++) {
        if(c->kernel_views.tables[n].level!=level)continue;
        state->pages++;
        if(!sprr_publish_needed(state,cpu,n)) {state->skipped++;continue;}
        uint64_t pa=c->kernel_views.tables[n].copy[cpu];publish(pa,pa+4096);
        if(!sprr_publish_complete(state,cpu,n)) {c->kernel_view_failed=1;return 0;}
    }
    state->publishes++;
#else
    for(unsigned n=0;n<c->kernel_views.count;n++) {
        uint64_t pa=c->kernel_views.tables[n].copy[cpu];publish(pa,pa+4096);
    }
#endif
    return 1;
}
#if SNAP_TOKEN_TRIM
/* compat/token-trim.h part A, under the token. The words were just proven
 * equal to the snapshot (an exact hit or a completed save): every later note
 * of a copied source page stamps it with a clock above this one. */
static void token_trim_prove(struct context *c)
{
    struct token_trim_state *t=&c->root_ext->trim;
    t->proof=c->table_memo.clock;t->proven=1;
    if(t->stats.proofs!=UINT64_MAX)t->stats.proofs++;
}
/* sprr_reuse_match's answer: from the witness when it holds (counted as the
 * same hit), else exactly; every TOKEN_TRIM_SAMPLE-th witnessed answer is
 * also compared exactly and a disagreement is terminal (-1: the caller
 * latches kernel_view_failed). */
static int token_trim_match(struct context *c,struct sprr_reuse_state *reuse,
                            const struct shadow *s,const uint64_t *pp)
{
    struct token_trim_state *t=&c->root_ext->trim;
    t->stats.asks++;
    int w=token_trim_witness(reuse,&c->kernel_views,s,pp,&c->table_memo,t->proof,t->proven);
    if(w==1 && (++t->stats.witnessed&(TOKEN_TRIM_SAMPLE-1))) {
        reuse->calls++;reuse->hits++;return 1;
    }
    if(w==1)t->stats.sampled++;
    else if(w==-2)t->stats.stale++;
    else t->stats.unproven++;
    int match=sprr_reuse_match(reuse,&c->kernel_views,s,pp);
    if(w==1 && match!=1) {t->stats.mismatches++;t->proven=0;return -1;}
    if(match==1)token_trim_prove(c);
    return match;
}
#endif
static int kernel_refresh_impl(struct context *c)
{
    struct shadow s=kernel_shadow(c);
#if SNAP_KERNEL_VIEW_REUSE
    struct sprr_reuse_state *reuse=&c->kernel_reuse_state;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
#if SNAP_TOKEN_TRIM
    int match=token_trim_match(c,reuse,&s,pp);
#elif SNAP_REUSE_MATCH_MAPPED
    /* shadow/sprr-reuse.h: the same exact proof, each copied source table
     * read once through class_table_read (kernel_table_read's bound for the
     * whole page) instead of one callback per word. */
    int match=sprr_reuse_match_mapped(reuse,&c->kernel_views,&s,pp,class_table_read,c);
#else
    int match=sprr_reuse_match(reuse,&c->kernel_views,&s,pp);
#endif
    if(match<0) {c->kernel_view_failed=1;return 0;}
    if(match) {
        /* Differential read-only verification of one in 64 cache hits (one
         * in 1024 with SNAP_AUDIT_SPARSE). No bad copy is silently repaired by
         * the verification pass. */
        if(!(reuse->hits&AUDIT_SAMPLE_MASK)) {
#if SNAP_UPDATE_DISJOINT_FAST
            if(!sprr_views_verify_all(&c->kernel_views,&s,pp)) {
                reuse->mismatches++;reuse->valid=0;c->kernel_view_failed=1;return 0;
            }
#else
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pp[cpu])) {
                    reuse->mismatches++;reuse->valid=0;c->kernel_view_failed=1;return 0;
                }
#endif
            reuse->verified++;
        }
        return 1;
    }
    reuse->valid=0;
#endif
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        if(!kernel_sync_view(c,&s,cpu,c->user_roots.sprr[cpu].pperm)) {
            c->kernel_view_failed=1;return 0;
        }
        if(!kernel_publish_cpu(c,cpu))return 0;
    }
#if SNAP_KERNEL_VIEW_REUSE
#if SNAP_TOKEN_TRIM
    /* The save overwrites the words: no proof until it completes. */
    c->root_ext->trim.proven=0;
#endif
    if(!sprr_reuse_save(reuse,&c->kernel_views,&s,pp)) {
        c->kernel_view_failed=1;return 0;
    }
#if SNAP_TOKEN_TRIM
    token_trim_prove(c);
#endif
#endif
    return 1;
}
static int kernel_refresh(struct context *c)
{
    int started=detail_begin(c,DETAIL_KERNEL_REFRESH);
    int result=kernel_refresh_impl(c);
    detail_end(c,DETAIL_KERNEL_REFRESH,started,result);return result;
}
static void shadow_tlb_sync(struct context *c)
{
    /* The canonical tree is never installed directly. Refresh every copied
     * kernel path before invalidating, including ordinary updates that land
     * beside a protected aperture leaf. */
    if(c->kernel_views.count && !kernel_refresh(c))return;
    /* Shared stage-1 updates affect every guest VMID. ALLE1IS broadcasts to
     * all EL1 regimes; VMALLE1IS would leave the other CPUs' VMIDs stale.
     * Stage-2 guard changes retain their current-VMID invalidation below.
     * Callers still require shared-service serialization before SMP entry. */
    __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
    c->shadow_tlb_syncs++;
}
#if SNAP_USER_UPDATE_KERNEL_SKIP
/* User-root UPDATE_DISJOINT: sptm_mac_update_user_disjoint reaches only the
 * user backend (user canonical shadow, user private copies, guest PTE memory
 * and SPTM metadata) and never PPERM or a kernel canonical table. The kernel
 * sources and all six kernel copies are exactly as the previous transaction
 * left them (current: every kernel/PPERM mutation refreshes before returning,
 * the contract the qualified user-only TLBI commits already rely on), so the
 * refresh would store nothing. Publication and the all-VMID TLBI remain. Every
 * 64th skip regenerates all six kernel views read-only; a stale copy is
 * terminal, exactly like a failed refresh, and is never repaired. */
static void user_update_kernel_skip(struct context *c)
{
    struct user_update_skip_stats *k=&c->user_update_skip;
#if SNAP_UPDATE_CHECK_SPARSE
    if(!(++k->skipped&1023) && c->kernel_views.count) {
#else
    if(!(++k->skipped&63) && c->kernel_views.count) {
#endif
        struct shadow s=kernel_shadow(c);
#if SNAP_UPDATE_DISJOINT_FAST
        uint64_t pp[GUEST_CPU_COUNT];
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
        if(!sprr_views_verify_all(&c->kernel_views,&s,pp)) {
            k->mismatches++;c->kernel_view_failed=1;return;
        }
#else
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
            if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,c->user_roots.sprr[cpu].pperm)) {
                k->mismatches++;c->kernel_view_failed=1;return;
            }
#endif
        k->verified++;
    }
#if SNAP_NATIVE_TABLES
    /* Each changed leaf's user_commit_update already invalidated its own 4K
     * entries in every VMID, after both its canonical and variant stores were
     * cleaned; no other hardware-walked table changed. */
#else
    __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
    c->shadow_tlb_syncs++;
#endif
}
#endif

static int pperm_tpro_preflight(struct context *,struct sprr_pperm_update_state *,int);
static int user_refresh_pperm(struct context *,uint64_t);
#if SNAP_KERNEL_PPERM_VARIANTS
/* Cleaned when allocated: an exact swap installs a variant page without a
 * store, and a synced swap may leave words of it zero. */
static uint64_t kernel_variant_alloc(void *ctx)
{
    uint64_t pa=private_kernel_alloc(ctx);
    if(pa)publish(pa,pa+4096);
    return pa;
}
/* A bit-8 flip that began with the snapshot current: exchange this CPU's
 * kernel column with its variant column. 2: swapped, and the new column is
 * already its translation under pperm; 1: swapped, the new column still needs
 * its sync; 0: not swapped (the in-place path runs); -1: terminal. */
static int kernel_variant_swap(struct context *c,const struct shadow *s,unsigned cpu,
                               uint64_t before,uint64_t pperm)
{
    struct sprr_view_variants *a=&c->kernel_variants;
    int exact=sprr_variants_exact(a,&c->kernel_views,&c->kernel_reuse_state,cpu,pperm);
    if(!exact) {
        struct shadow vs=*s;vs.alloc=kernel_variant_alloc;
        if(!sprr_variants_reserve(a,&c->kernel_views,&vs,cpu)) {a->fallbacks++;return 0;}
    }
    if(!sprr_variants_swap(a,&c->kernel_views,&c->kernel_publish_state,cpu,before,
                           c->kernel_reuse_state.saves)) {a->fallbacks++;return 0;}
    if(!exact) {a->synced++;return 1;}
    /* The first and then one in 64 exact swaps (one in 1024 with
     * SNAP_AUDIT_SPARSE) regenerate the new column read-only and compare it;
     * a discrepancy is terminal, never repaired. */
    if(!(a->exact++&AUDIT_SAMPLE_MASK)) {
        if(!sprr_views_verify_cpu(&c->kernel_views,s,cpu,pperm)) {
            a->mismatches++;c->kernel_view_failed=1;return -1;
        }
        a->verified++;
    }
    return 2;
}
#endif
/* invalidate=0 only from root installation, whose final all-VMID TLBI follows
 * every store made here (this CPU's own kernel/user copies) before the CPU can
 * execute EL1/EL0 again; see user_root_install. */
static int kernel_change_pperm_impl(struct context *c,uint64_t pperm,int invalidate)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
#if SNAP_KERNEL_VIEW_REUSE
#if SNAP_KERNEL_PPERM_REUSE
    /* Exact pre-transaction proof, taken before any private write: every copied
     * kernel view equals the saved translation of the CURRENT canonical words
     * under the current six PPERMs. Anything else (including a read failure)
     * takes the unchanged path below, which repeats the same reads. */
    struct kernel_pperm_reuse_stats *kr=&c->kernel_pperm_reuse;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned n=0;n<GUEST_CPU_COUNT;n++)pp[n]=c->user_roots.sprr[n].pperm;
    struct shadow ks=kernel_shadow(c);
#if SNAP_NATIVE_TABLES
    int current=c->kernel_views.count && native_reuse_current(c,&ks,pp);
    if(c->kernel_view_failed)return 0;
#else
    int current=c->kernel_views.count &&
        sprr_reuse_current(&c->kernel_reuse_state,&c->kernel_views,&ks,pp)==1;
#endif
    kr->calls++;if(current)kr->current++;
#endif
    /* The only writer outside full refresh; invalidate before changing even
     * one private copy, including transactions whose later user sync fails. */
    sprr_reuse_invalidate(&c->kernel_reuse_state);
#endif
    uint64_t before=c->user_roots.sprr[cpu].pperm;
    int tpro=!!((before^pperm)&SPRR_UPERM_TPRO_WRITE);
    struct sprr_pperm_update_state proof={0};
#if SNAP_NATIVE_TABLES
    /* Audit mode: the canonical user-view proof runs on a CPU's first TPRO
     * change and then sampled, the record keeping the last one. The kernel
     * class proof (cached; hits are cheap) still runs on every change. */
    if(tpro) {
        const struct sprr_pperm_update_state *last=&c->sprr_pperm_update[cpu];
        int user_proof=!last->user_root || native_due(&c->native_stats.proof_asks);
        if(!user_proof) {proof=*last;c->native_stats.proof_skips++;}
        if(!pperm_tpro_preflight(c,&proof,user_proof))return 0;
    }
#else
    if(tpro && !pperm_tpro_preflight(c,&proof,1))return 0;
#endif
    struct shadow s=kernel_shadow(c);
    int skip=0,swap=0;
#if SNAP_KERNEL_PPERM_REUSE
    /* A kernel copy decodes PPERM only through SPRR_KERNEL_VIEW_PPERM
     * (entry_decode, user==NULL). With the snapshot current and that bit
     * unchanged, this CPU's copy already equals its translation under pperm:
     * the compared sync would pass the same preflight and store nothing, and
     * with no pending bit for this CPU the publish loop would clean nothing. */
    const struct sprr_publish_state *ps=&c->kernel_publish_state;
    skip=current && !((before^pperm)&SPRR_KERNEL_VIEW_PPERM) &&
        ps->root==c->kernel_views.canonical_root && ps->count==c->kernel_views.count &&
        !ps->pending[cpu][0] && !ps->pending[cpu][1];
#if SNAP_KERNEL_PPERM_VARIANTS
    if(!skip && current && ((before^pperm)&SPRR_KERNEL_VIEW_PPERM) &&
       (swap=kernel_variant_swap(c,&s,cpu,before,pperm))<0)return 0;
#endif
    if(skip) {
        /* One in 64 skipped views (one in 1024 with SNAP_AUDIT_SPARSE) is
         * regenerated and compared read-only; a discrepancy is terminal and
         * never repaired. */
        if(!(++kr->skipped&AUDIT_SAMPLE_MASK)) {
            if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pperm)) {
                kr->mismatches++;c->kernel_view_failed=1;return 0;
            }
            kr->verified++;
        }
    } else
#endif
    if(swap!=2 && !kernel_sync_view(c,&s,cpu,pperm)) {
        c->kernel_view_failed=1;return 0;
    }
    if(!user_refresh_pperm(c,pperm))return 0;
    if(!skip && !kernel_publish_cpu(c,cpu))return 0;
#if SNAP_KERNEL_PPERM_VARIANTS
    /* The new column is published; its root is installed before the
     * invalidation below (or, for invalidate=0, the root installation's
     * all-VMID TLBI). Kernel entries are global: the TLBI is what removes
     * the old column's. */
    if(swap) {
        uint64_t root=sprr_views_root(&c->kernel_views,cpu);
        __asm__ volatile("msr ttbr1_el1, %0; isb" :: "r"(root) : "memory");
        c->kernel_installed[cpu]=root;
    }
#endif
    if(invalidate) {
#if SNAP_NATIVE_TABLES
        /* Only this CPU walks its private kernel copy, and a user variant
         * changes by TTBR0 alone: nothing to invalidate when the copy is
         * provably unchanged (skip), else this CPU's own TLB, locally. */
        if(!skip) {
            __asm__ volatile("dsb ishst; tlbi vmalle1; dsb nsh; isb" ::: "memory");
            c->native_stats.pperm_flushes++;c->shadow_tlb_syncs++;
        }
#else
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        c->shadow_tlb_syncs++;
#endif
    }
    if(before!=pperm)c->kernel_permission_changes++;
    if(tpro) {
        struct sprr_pperm_update_state *u=&c->sprr_pperm_update[cpu];
        proof.transactions=u->transactions+1;
        proof.grants=u->grants+!!(pperm&SPRR_UPERM_TPRO_WRITE);
        proof.restores=u->restores+!(pperm&SPRR_UPERM_TPRO_WRITE);
        proof.before=before;proof.after=pperm;
        __asm__ volatile("mrs %0, elr_el2":"=r"(proof.pc));
        *u=proof;
    }
#if SNAP_KERNEL_PPERM_REUSE
    /* Neither the TPRO preflight (read-only) nor the user sync (user copies and
     * fresh user-owned pages only) changed a canonical kernel word or view
     * identity; only this CPU's copy was (re)written for pperm. The snapshot
     * describes all six copies exactly again. */
    if(current) {
        if(!skip)kr->synced++;
        if(!(swap ? sprr_variants_repin(&c->kernel_reuse_state,&c->kernel_views,cpu,pperm) :
                    sprr_reuse_repin(&c->kernel_reuse_state,&c->kernel_views,cpu,pperm))) {
            kr->errors++;c->kernel_view_failed=1;return 0;
        }
        kr->repinned++;
    }
#endif
    return 1;
}
static int kernel_change_pperm_timed(struct context *c,uint64_t pperm,int invalidate)
{
    int started=detail_begin(c,DETAIL_KERNEL_PPERM);
    int result=kernel_change_pperm_impl(c,pperm,invalidate);
    detail_end(c,DETAIL_KERNEL_PPERM,started,result);return result;
}
static int kernel_change_pperm(void *ctx,uint64_t pperm)
{return kernel_change_pperm_timed(ctx,pperm,1);}

static int vcpu_root_busy(struct context *c, uint64_t root)
{
    struct guest_cpu_address_space spaces[GUEST_CPU_COUNT];
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        spaces[cpu] = (struct guest_cpu_address_space){c->vcpus[cpu].guest_ttbr0,
                                                     c->vcpus[cpu].guest_ttbr1};
    c->root_checks++;
    int busy = guest_cpu_root_busy(spaces, root);
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)busy|=c->user_roots.active[cpu]==root;
    if (busy) c->root_busy_refusals++;
    return busy;
}

static volatile uint8_t *sptm_map(void *ctx, uint64_t pa, uint64_t size)
{
    const struct params *p = ((struct context *)ctx)->params;
    if (pa < p->mem_low || pa >= p->mem_high || size > p->mem_high - pa)
        return 0;
    return (volatile uint8_t *)pa;
}

static void sptm_publish(void *ctx, uint64_t pa, uint64_t size)
{
#if SNAP_DART_MEMO
    /* The DART memo's write witness (compat/sptm-dart-memo.h). */
    if (((struct context *)ctx)->root_ext)
        sptm_dart_memo_publish(&((struct context *)ctx)->root_ext->dart_memo, pa, size);
#endif
#if SNAP_ROOT_VALIDATE_MEMO
    /* Every SPTM store to guest tables or frame records is published here
     * (compat/sptm.h map/publish contract): the memo's write witness. */
    struct context *c=ctx;const struct params *p=c->params;
    sptm_root_memo_publish(&c->root_memo,p->frame_map_pa,p->frame_low,p->frame_high,
                           sptm_map,c,pa,size);
#else
    (void)ctx;
#endif
    publish(pa, pa + size);
}

/* memory.clean_frame (compat/sptm.h): a frame whose SH/AttrIndx is about to
 * change is cleaned and invalidated to PoC through EL2's identity map of guest
 * RAM before any new descriptor is stored, and again by attr_clean_finish
 * once the transaction's TLBI has retired every translation that could still
 * allocate its lines with the old attributes. Maintenance by address reaches
 * the physical lines whichever alias allocated them. */
static int sptm_attr_clean(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct attr_update_state *s=&c->attr_updates;
    if(size!=0x4000 || (pa&0x3fff) || pa<p->mem_low || pa>=p->mem_high ||
       size>p->mem_high-pa || s->pending>=SPTM_DISJOINT_MAX) {
        s->refused++;return 0;
    }
    publish(pa,pa+size);
    s->pending_pa[s->pending++]=pa;s->cleans++;
    return 1;
}
static void attr_clean_finish(struct context *c)
{
    struct attr_update_state *s=&c->attr_updates;
#if SNAP_ATTR_CLEAN_DEFER
    /* agents/nvme-async D1-D6: this second clean (after the TLBI) moves to
     * attr_clean_flush, after the token is released and before this vCPU
     * resumes; the first one, before the store, stays. Counted here, under the
     * token, as before; past ATTR_DEFER_MAX it cleans inline. */
    struct attr_defer_cpu *d=&c->root_ext->attr_defer[vcpu_of(c)->slot];
    for(uint64_t n=0;n<s->pending && n<SPTM_DISJOINT_MAX;n++) {
        if(d->count<ATTR_DEFER_MAX) {d->pa[d->count++]=s->pending_pa[n];d->deferred++;}
        else {publish(s->pending_pa[n],s->pending_pa[n]+0x4000);d->overflow++;}
        s->recleans++;
    }
    s->pending=0;
    return;
#endif
    for(uint64_t n=0;n<s->pending && n<SPTM_DISJOINT_MAX;n++) {
        publish(s->pending_pa[n],s->pending_pa[n]+0x4000);s->recleans++;
    }
    s->pending=0;
}
#if SNAP_ATTR_CLEAN_DEFER
/* xnuboot_trap, after runtime_leave: this vCPU's deferred second cleans, by VA
 * through EL2's identity map of guest RAM (data-preserving: no lock), one
 * barrier at the end, before the guest resumes (D1, D3). */
static void attr_clean_flush(struct context *c)
{
    struct attr_defer_cpu *d=&c->root_ext->attr_defer[vcpu_of(c)->slot];
    if(!d->count)return;
    for(uint64_t n=0;n<d->count;n++)
        for(uint64_t line=d->pa[n];line<d->pa[n]+0x4000;line+=64)
            __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    d->flushed+=d->count;d->count=0;
}
#endif

static volatile uint8_t *sptm_shadow_map(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;
    if (pa<c->work_base || pa>=c->next_table || size>c->next_table-pa) return 0;
#if SNAP_INCREMENTAL_PUBLISH
    if(size && !root_index_note(&c->root_publish,&c->perf.root_index,c->work_base,
                                c->next_table,pa,size))return 0;
#elif SNAP_ROOT_DIRTY_PUBLISH
    if(size && !root_publish_note(&c->root_publish,c->work_base,c->next_table,pa,size))return 0;
#endif
#if SNAP_TXN_DIRTY_PUBLISH
    txn_publish_observe(&c->txn_publish,pa,size);
#endif
#if SNAP_USER_TREE_MEMO
    /* The caller may store through this pointer without mem_write. Kernel
     * update backends never reach a user view refresh before those stores,
     * so noting every mapped page now is conservative and complete. */
    for(uint64_t page=pa&~4095UL;size && page<pa+size;page+=4096)
        sprr_table_memo_note(&c->table_memo,page);
#endif
    return (volatile uint8_t *)pa;
}

/* UPDATE_REGION/DISJOINT, SLIDE_REGION and the two aperture commits hold
 * mapped canonical pointers and write bytes directly. Invalidate before
 * entering those transactions; no class proof is renewed before commit.
 * Their existing publication, private-view refresh and TLBI remain intact. */
static void kernel_class_proof_forget(struct context *c)
{
#if SNAP_KERNEL_CLASS_PROOF
    sprr_class_proof_forget(&c->kernel_class_proof);
#else
    (void)c;
#endif
}

#if SNAP_TXN_DIRTY_PUBLISH
/* guard_write stores and cleans stage-2 guard descriptors directly, without a
 * dirty note. Such pages are published by that path and are never armed as a
 * coverage sentinel. Guards are only added while building stage 2. */
static int txn_publish_exclude(void *ctx,uint64_t page)
{
    struct context *c=ctx;
    if(c->thermal && page==(uint64_t)c->thermal)return 1;
#if SNAP_ROOT_CACHE_WIDE
    /* Monitor-only state stored without a note: no translation table, never
     * published, never a coverage sentinel (compat/root-wide.h W6). */
    if(page>=(uint64_t)c->root_ext && page-(uint64_t)c->root_ext<ROOT_EXT_PAGES*4096)return 1;
#endif
#if SNAP_TXM_ASPACE_WIDE
    /* The TXM registry, stored the same way (compat/txm.h A4). */
    if(page>=(uint64_t)TXM_REG(c) && page-(uint64_t)TXM_REG(c)<TXM_EXT_PAGES*4096)return 1;
#endif
#if SNAP_USER_HW_WALK
    /* The hardware-walk records, index and counters, stored the same way
     * (compat/user-hw-walk.h). Its copy pages are pool tables: noted. */
    if(page>=(uint64_t)c->hw_walk && page-(uint64_t)c->hw_walk<HW_WALK_PAGES*4096)return 1;
#endif
#if SNAP_S2_FAULT_RETRY
    /* The retry snapshot page, stored the same way (compat/s2-fault-retry.h). */
    if(page>=(uint64_t)c->s2_retry && page-(uint64_t)c->s2_retry<S2_RETRY_PAGES*4096)return 1;
#endif
#if SNAP_GUEST_NET
    /* The guest-network state, stored the same way (compat/guest-net-link.h). */
    if(page>=(uint64_t)c->guest_net && page-(uint64_t)c->guest_net<GUEST_NET_STATE_PAGES*4096)return 1;
#endif
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        for(uint64_t g=0;g<c->vcpus[cpu].guard_count;g++)
            if((c->vcpus[cpu].guards[g].slot&~UINT64_C(4095))==page)return 1;
    return 0;
}
#endif
/* Runtime transaction end: previously dc civac over every allocated arena
 * line. Called after the transaction's last table store and before its TLBI.
 * Failure (tracking error or a sentinel store the bitmap missed) is terminal. */
static int transaction_publish(struct context *c)
{
#if SNAP_TXN_DIRTY_PUBLISH
#if SNAP_INCREMENTAL_PUBLISH
    int ok=txn_index_flush(&c->root_publish,&c->perf.root_index,&c->txn_publish,
                           c->work_base,c->next_table,publish_page_lines,txn_publish_exclude,c);
#else
    int ok=txn_publish_flush(&c->root_publish,&c->txn_publish,c->work_base,c->next_table,
                             publish_page_lines,txn_publish_exclude,c);
#endif
    __asm__ volatile("dsb ish" ::: "memory");
    return ok;
#else
    publish(c->work_base,c->next_table);return 1;
#endif
}

static int sptm_admit_iommu(void *ctx, unsigned iommu_class, unsigned device_id,
                           unsigned sid, unsigned level)
{
    struct context *c=ctx;
    return device_dart_admit_frame(c->params->models,c->model_state,
        c->params->model_count,iommu_class,device_id,sid,level,0)==DEVICE_OK;
}

static int gfx_power_idle(void *ctx)
{
    struct context *c=ctx;
    const struct params *p=c->params;
    struct sptm_aperture aperture={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_memory memory={.map=sptm_map,.ctx=c};
    /* Only UAT information queries are accepted by table 7. Graphics
     * mappings, commands and ASC execution remain unsupported. Preserve
     * the reserved pages; the runtime service lock holds them stable. */
    return uat_power_idle(&p->uat,&aperture,&memory)==SPTM_OK;
}

static int sptm_retype_user_tpro(void *,uint64_t,uint64_t,uint64_t);
static struct sptm_moved xnu_moved(const struct context *);
/* AppleSEPFirmware::releaseFirmware (0xfffffe00099c3904) frees the SEPFW
 * extent through ml_static_mfree (0xfffffe000ba89dd0) once the SEP is up.
 * That routine retypes only frames whose type is not XNU_DEFAULT, and every
 * frame here is 0x0b, so the release makes no monitor call: the first sign of
 * it is an ordinary MAP_PAGE or RETYPE of one of those frames. The firmware is
 * dead from the ROM's bootstrap handoff on, so that is when XNU owns it. */
static uint64_t sep_firmware_released(const struct context *c)
{
    const struct params *p=c->params;
    if (!p->sep_firmware_size) return 0;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 && p->models[i].config[4])
            return c->model_state[i].sep_asc.service_ready!=0;
    return 0;
}

static struct sptm_memory sptm_context_memory(struct context *c)
{
    const struct params *p=c->params;
    return (struct sptm_memory){.frame_map_pa=p->frame_map_pa,
        .frame_low=p->frame_low,.frame_high=p->frame_high,
        .alloc_low=p->alloc_low,.alloc_high=p->alloc_high,
        .map=sptm_map,.publish=sptm_publish,.ctx=c,
        .aperture_va=p->ram_aperture_va,.aperture_size=p->alloc_high-p->mem_low,
        .refs=&c->references,.boot_ranges=p->slide.regions,.boot_count=p->slide.count,
        .shared_regions=&c->shared_regions,.retype_user_tpro=sptm_retype_user_tpro,
        .boot_aliases=c->slide.count ? c->slide.regions : p->slide.regions,
        .boot_alias_count=c->slide.count ? c->slide.count : p->slide.count,
        .sep_firmware_pa=p->sep_firmware_pa,.sep_firmware_size=p->sep_firmware_size,
        .sep_firmware_released=sep_firmware_released(c),
        /* The panel is plain firmware memory behind stage 2, not a modeled
         * device: IOFramebufferUserClient maps it into WindowServer. It is
         * admitted only wholly outside guest RAM and every monitor range. */
        .user_io_pa=p->fb_span && (p->fb_pa>=p->mem_high ||
            (p->fb_span<=p->mem_low && p->fb_pa<=p->mem_low-p->fb_span)) ? p->fb_pa : 0,
        .user_io_size=p->fb_span && (p->fb_pa>=p->mem_high ||
            (p->fb_span<=p->mem_low && p->fb_pa<=p->mem_low-p->fb_span)) ? p->fb_span : 0,
        .audit=&c->pv_audit,.root_memo=SNAP_ROOT_VALIDATE_MEMO ? &c->root_memo : 0,
        .clean_frame=sptm_attr_clean
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
        ,.nest_fast=&c->root_ext->nest_fast
#endif
#if SNAP_DART_MEMO
        ,.dart_memo=&c->root_ext->dart_memo
#endif
#if SNAP_ROOT_INDEX
        ,.root_index=&c->root_ext->root_index
#endif
        };
}

/* Virtual ANS2 glue. The state lives at the start of the loader's reservation
 * (config[0]), outside guest memory and stage 2; DMA reaches only guest RAM
 * frames admitted with SPTM reference counts under the DART data-leaf rule
 * (XNU_DEFAULT only, clear metadata; ans_frame_ref). */
_Static_assert(ANS_DMA_FRAME_TYPE==SPTM_MAC_DEFAULT,"ANS DMA admits the DART data-leaf type");
static struct ans_state *ans_state_of(const struct context *c)
{
    const struct params *p=c->params;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_ANS_NVME_V1)
            return (struct ans_state *)p->models[i].config[0];
    return 0;
}
static int ans_frame_ref(void *ctx,uint64_t pa,int writable,int release)
{
    struct sptm_memory m=sptm_context_memory(ctx);
    uint64_t f=pa&~0x3fffUL;
    if (!sptm_managed_frame(&m,f)) return 1;
    if (!release) {
        /* sptm_refs_dart counts references but leaves type checks to its
         * caller (delta() also accepts ROZONE, KERNEL_RESTRICTED and
         * COMMPAGE frames): admit only what ans_dma_frame does, the DART
         * data-leaf rule (XNU_DEFAULT, clear metadata). A release never
         * re-checks, so a held reference can always be dropped. */
        volatile uint8_t *e=m.map(m.ctx,m.frame_map_pa+((f-m.frame_low)>>14)*16,16);
        if (!e || !ans_dma_frame(e)) return 1;
    }
    sptm_refs_begin(m.refs);
    enum sptm_result r=release ? sptm_refs_dart_remove(&m,f,!writable) :
                                 sptm_refs_dart(&m,f,!writable);
    if (!r) r=sptm_refs_validate(&m);
    if (r) return 1;
    sptm_refs_commit(&m);
    return 0;
}
/* Window mode (full-install M6, compat/ans.h ANS_WINDOW_*): the synthesized GPT's first and last
 * MiB come from the reservation; every other virtual block is the M4 partition on the SSD, read
 * through the controller q1n1 left running (compat/nvme-host.h) at real LBA first + 8 * block. */
static const struct device_model *ans_nvme_model(const struct context *c)
{
    const struct params *p=c->params;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_ANS_NVME_V1) return &p->models[i];
    return 0;
}
static int ans_window(const struct context *c)
{
    const struct device_model *m=ans_nvme_model(c);
    return m && m->config[3]==ANS_WINDOW_MODE;
}
static const struct nvmeh_ops nvmeh_direct;   /* NVMEH_DIRECT: the monitor reaches the SSD itself */
#define ANS_NVMEH_PARAMS(res) ((struct nvmeh_params *)((res)+ANS_WINDOW_NVMEH))
#define ANS_NVMEH_STATE(res) ((struct nvmeh_state *)((res)+ANS_WINDOW_NVMEH+0x80))
/* agents/nvme-async: the window flight (compat/ans-window.h) and the asynchronous callbacks, initializers that
 * expand to nothing without SNAP_ANS_ASYNC (the define-off text stays the base's). */
#if SNAP_ANS_ASYNC
#define ANS_WINDOW_FLIGHT(res) ,(struct ans_window_flight *)((struct ans_state *)(res))->async.backend
#define ANS_ASYNC_OPS(window) .disk_start=(window) ? ans_window_start_cb : 0,\
    .disk_poll=(window) ? ans_window_poll_cb : 0,.disk_quiesce=(window) ? ans_window_quiesce_cb : 0,
#else
#define ANS_WINDOW_FLIGHT(res)
#define ANS_ASYNC_OPS(window)
#endif
_Static_assert(sizeof(struct nvmeh_params)<=0x80 && sizeof(struct nvmeh_state)<=0xc0,"window params/state slots");
static struct ans_window_backend ans_window_backend(const struct context *c)
{
    const struct device_model *m=ans_nvme_model(c);
    uint64_t res=m->config[0];
    return (struct ans_window_backend){m->config[1]/ANS_BLOCK,
        (const volatile uint8_t *)(res+ANS_WINDOW_HEAD),
        (const volatile uint8_t *)(res+ANS_WINDOW_TAIL),
        (volatile uint8_t *)(res+ANS_WINDOW_STAGE),
        (volatile uint8_t *)(res+ANS_WINDOW_DMA+NVMEH_DATA),
        &nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res)ANS_WINDOW_FLIGHT(res)};
}
static int ans_window_read(void *ctx,uint64_t lba,uint64_t n,volatile uint8_t **data)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_read_blocks(&b,lba,n,data);
}
static int ans_window_write_buffer(void *ctx,uint64_t lba,uint64_t n,volatile uint8_t **data)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_prepare_write(&b,lba,n,data);
}
static int ans_window_write(void *ctx,uint64_t lba,uint64_t n)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_write_blocks(&b,lba,n);
}
static int ans_window_flush(void *ctx)
{
    uint64_t res=ans_nvme_model(ctx)->config[0];
    return nvmeh_flush(&nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res));
}
/* Before the guest runs: adopt the SSD q1n1 left running, or refuse the launch. */
static int64_t ans_window_prepare(struct context *c)
{
    if (!ans_window(c)) return 0;
    const struct device_model *m=ans_nvme_model(c);
    uint64_t res=m->config[0];
#if SNAP_ANS_ASYNC
    /* The schedule's lock-free readers (timer_arm, the fast tick) find the state here; window mode only. */
    c->root_ext->ans=(struct ans_state *)res;
#endif
    return nvmeh_adopt(&nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res),
                       c->params->mem_low,c->params->mem_high);
}
static void ans_window_stop(struct context *c)
{
    if (!ans_window(c)) return;
    uint64_t res=ans_nvme_model(c)->config[0];
    nvmeh_stop(&nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res));
}
#if SNAP_ANS_ASYNC
/* compat/ans-window.h's flight, for compat/ans.c's asynchronous backend (ans_ops.disk_start/disk_poll). */
static int ans_window_start_cb(void *ctx,unsigned op,uint64_t lba,uint64_t n)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_start(&b,op,lba,n);
}
static int ans_window_poll_cb(void *ctx,volatile uint8_t **data)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_poll(&b,data);
}
static void ans_window_quiesce_cb(void *ctx)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    (void)ans_window_quiesce(&b);
}
#endif
static struct ans_ops ans_ops_of(struct context *c)
{
    int window=ans_window(c);
    return (struct ans_ops){ANS_ASYNC_OPS(window).ctx=c,.map=sptm_map,.frame_ref=ans_frame_ref,.publish=sptm_publish,
        .disk_read=window ? ans_window_read : 0,
        .disk_write_buffer=window ? ans_window_write_buffer : 0,
        .disk_write=window ? ans_window_write : 0,.disk_flush=window ? ans_window_flush : 0};
}
/* After a successful ANS mutation: the three ASC/NVMe interrupt levels. */
static enum device_result ans_route(struct context *c)
{
    const struct params *p=c->params;
    const struct ans_state *s=ans_state_of(c);
    int level[3];
    ans_levels(s,level);
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_AIC3_FLAT_V1) {
            static const uint16_t irq[3]={1007,1010,1039};
            for (unsigned n=0;n<3;n++)
                if (device_irq_set_level(&p->models[i],&c->model_state[i],irq[n],level[n])!=DEVICE_OK)
                    return DEVICE_BAD_CONFIG;
            return DEVICE_OK;
        }
    return DEVICE_BAD_CONFIG;
}
#if SNAP_ANS_ASYNC
/* ---- SNAP_ANS_ASYNC: the poll schedule (agents/nvme-async N3, N11, N18, N19) ----
 * One deadline for the physical command in flight (CNTPCT ticks), owned by the
 * vCPU whose ANS operation started it: timer_arm arms that vCPU's EL2 timer for
 * it and its fast tick peeks at the completion. Every other ANS operation polls
 * anyway; any vCPU's locked tick polls a command ANS_ASYNC_BACKSTOP_US past its
 * deadline. Written under ANS exclusion, and the deadline also by the owner's
 * fast tick (a push); atomic words, so a race moves one poll, never loses one. */
#define ANS_ASYNC_MIN_US 15u
#define ANS_ASYNC_MAX_US 1000u
#define ANS_ASYNC_FIRST_US 30u          /* the first deadline before any latency was measured */
#define ANS_ASYNC_BACKSTOP_US 1000u
/* tests/gain-model.py (agents/nvme-async): with the first deadline at a quarter of the latency average and then
 * an eighth of the command's age, a 177 us command (gamma, cv^2 1..3) completes 20-31 us later than the busy-poll
 * would have seen it, after 7-8 peeks; the owner's peeks cost no token (its fast tick). */
static uint64_t ans_async_us(const struct context *c,uint64_t us) {return c->params->clock_host_hz*us/1000000;}
/* The next deadline of a command still running: an eighth of its age, within [MIN, MAX]. */
static uint64_t ans_async_next(const struct context *c,uint64_t now,uint64_t start)
{
    uint64_t gap=(now-start)/8,lo=ans_async_us(c,ANS_ASYNC_MIN_US),hi=ans_async_us(c,ANS_ASYNC_MAX_US);
    return now+(gap<lo ? lo : gap>hi ? hi : gap);
}
/* Under ANS exclusion, after any ANS operation (every one polled first). */
static void ans_async_schedule(struct context *c)
{
    struct ans_state *s=c->root_ext->ans;
    if(!s)return;
    struct ans_async *a=&s->async;
    uint64_t seq,now=service_profile_clock();
    /* The latency average: physical commands reaped since the last call, by nvme-host's own tick sums
     * (submit to reap, so it includes the poll granularity it is used to set). */
    const struct nvmeh_state *ns=ANS_NVMEH_STATE((uint64_t)s);
    uint64_t done=ns->reads+ns->writes+ns->flushes+ns->errors,ticks=ns->total_ticks;
    if(done>a->sched[7] && ticks>=a->sched[6]) {
        uint64_t avg=(ticks-a->sched[6])/(done-a->sched[7]);
        a->ewma=a->ewma ? a->ewma-a->ewma/8+avg/8 : avg;
        a->sched[4]+=ticks-a->sched[6];a->sched[5]+=done-a->sched[7];
    }
    a->sched[6]=ticks;a->sched[7]=done;
    uint64_t me=(uint64_t)vcpu_of(c)->slot+1;
    if(!ans_async_busy(s,&seq)) {__atomic_store_n(&a->due,0,__ATOMIC_RELAXED);return;}
    if(!a->phys) {
        /* Work queued and nothing in flight (a progress budget ran out): poll at once. */
        __atomic_store_n(&a->owner,me,__ATOMIC_RELAXED);__atomic_store_n(&a->due,now,__ATOMIC_RELAXED);
        return;
    }
    if(seq!=a->sched_seq) {
        uint64_t lo=ans_async_us(c,ANS_ASYNC_MIN_US),hi=ans_async_us(c,ANS_ASYNC_MAX_US);
        uint64_t first=a->ewma ? a->ewma/4 : ans_async_us(c,ANS_ASYNC_FIRST_US);
        a->sched_seq=seq;a->start=now;
        __atomic_store_n(&a->owner,me,__ATOMIC_RELAXED);
        __atomic_store_n(&a->due,now+(first<lo ? lo : first>hi ? hi : first),__ATOMIC_RELAXED);
        return;
    }
    __atomic_store_n(&a->due,ans_async_next(c,now,a->start),__ATOMIC_RELAXED);
}
/* timer_arm's, lock-free: this vCPU's deadline when it owns the command in flight. */
static int ans_async_due_of(const struct context *c,uint64_t slot,uint64_t *due)
{
    const struct ans_state *s=c->root_ext ? c->root_ext->ans : 0;
    if(!s || __atomic_load_n(&s->async.owner,__ATOMIC_RELAXED)!=slot+1)return 0;
    *due=__atomic_load_n(&s->async.due,__ATOMIC_RELAXED);
    return *due!=0;
}
/* After an ANS operation that may have posted (N3): the lines, then this vCPU's view of them. */
static enum device_result ans_async_lines(struct context *c)
{
    enum device_result r=ans_route(c);
    if(r!=DEVICE_OK)return r;
    vcpu_of(c)->model_irq_pending=0;
    for (unsigned i=0;i<c->params->model_count;i++)
        vcpu_of(c)->model_irq_pending|=device_irq_pending(&c->params->models[i],&c->model_state[i]);
    return DEVICE_OK;
}
#endif

static int sptm_retype_rozone(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    /* A SLIDE_REGION-moved frame also has the alias XNU's phystokv uses;
     * both leaves need private paths before either becomes selector2. */
    struct shadow s=kernel_shadow(c);
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)==9 ||
           !sprr_views_prepare(&c->kernel_views,&s,change.leaf[i].va))return 0;
    /* Detach copied paths while canonical descriptors still have their old
     * permissions. No guest CPU may see an untranslated raw selector2 leaf. */
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    kernel_class_proof_forget(c);
    sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    if(new_type==SPTM_MAC_ROZONE)c->papt_protects++;else c->papt_releases++;
    return 1;
}

static int sptm_retype_txm_default(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    if(old_type!=SPTM_MAC_DEFAULT || new_type!=SPTM_MAC_TXM_DEFAULT)return 0;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    struct shadow s=kernel_shadow(c);
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)!=4 ||
           !sprr_views_prepare(&c->kernel_views,&s,change.leaf[i].va))return 0;
    /* Detach every CPU's path while the canonical aperture is still class3.
     * After commit, private class4 is always EL1 RO/NX, with no EL0 access. */
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    kernel_class_proof_forget(c);sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    c->txm_donations++;return 1;
}

static int sptm_retype_txm_owned(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    if(!((old_type==SPTM_MAC_TXM_DEFAULT && new_type==SPTM_MAC_TXM_OWNED) ||
         (old_type==SPTM_MAC_TXM_OWNED && new_type==SPTM_MAC_DEFAULT)))return 0;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    unsigned selector=new_type==SPTM_MAC_TXM_OWNED ? 11:3;
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)!=selector)return 0;
    /* Donation already detached selector4's paths on every CPU. Import uses
     * fixed RO/NX selector11; release restores ordinary RW/NX selector3.
     * Keep the counted, separately mapped read-only kernel alias intact. */
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    kernel_class_proof_forget(c);sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    if(new_type==SPTM_MAC_TXM_OWNED)c->txm_imports++;else c->txm_releases++;
    return 1;
}

static enum sptm_result txm_load_prepare(void *ctx,const uint64_t args[8],uint64_t pa[2])
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);m.retype_txm_owned=sptm_retype_txm_owned;
    struct txm_kernel_memory kernel={&m,vcpu_of(c)->guest_ttbr1&0x0000ffffffffc000UL,
                                    vcpu_of(c)->guest_tcr};
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    for(unsigned i=0;i<2;i++) {
        if(!txm_resolve_kernel_page(&kernel,args[2+i*2],args[3+i*2],&pa[i]))return SPTM_BAD_ADDRESS;
        enum sptm_result r=sptm_txm_retype_check(&m,pa[i],42,60);
        if(r)return r;
        struct sptm_papt_change change;
        r=sptm_papt_prepare(&m,&b,&a,&moved,pa[i],42,60,&change);
        if(r)return r;
    }
    return pa[0]!=pa[1] ? SPTM_OK:SPTM_BAD_ADDRESS;
}
static int txm_load_stage(void *ctx,const uint8_t *payload,uint64_t size,
                           const uint8_t *manifest,uint64_t manifest_size)
{
    struct context *c=ctx;
    return txm_native_stage(&c->params->txm_native,&c->txm_native,payload,size,manifest,manifest_size);
}
static int txm_load_authenticate(void *ctx,uint64_t type,const struct txm_native_cache *boot,
    const struct txm_native_cache *dynamic,unsigned count,struct txm_native_result *result)
{
    struct context *c=ctx;
    return txm_native_load_caches(&c->params->txm_native,&c->txm_native,type,boot,dynamic,count,result);
}

static int sptm_retype_user_exec(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)==9)return 0;
    /* Class11 uses fixed ARM permissions on all CPUs, so no new private
     * branches are needed. Existing private paths still receive the update. */
    kernel_class_proof_forget(c);
    sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    if(new_type==SPTM_MAC_USER_EXEC) {
        /* Publish data to PoC, then invalidate instruction caches in the
         * inner-shareable domain across all guest VMIDs and VA aliases. */
        publish(pa,pa+SPTM_MAC_FRAME_SIZE);
        __asm__ volatile("ic ialluis; dsb ish; isb" ::: "memory");
        c->user_exec_cache_syncs++;c->user_exec_protects++;
    } else c->user_exec_releases++;
    return 1;
}

static int sptm_retype_user_tpro(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    for(unsigned i=0;i<change.count;i++)
        if(change.leaf[i].before!=change.leaf[i].after ||
           sprr_pte_class(change.leaf[i].after)!=3)return 0;
#if SNAP_ROOT_VALIDATE_MEMO
    /* A mapped frame's TPRO retype changes canonical_leaf's verdict for its
     * leaves. sptm_mac_retype admits this transition only with zero
     * references and reports every type store itself; retire retained
     * SWITCH_ROOT verdicts here too if that ever changes. */
    sptm_root_memo_retype(&c->root_memo,
        m.map(m.ctx,m.frame_map_pa+((pa-m.frame_low)>>14)*16,16));
#endif
    /* Both types keep the same RW/NX physical aperture. Preflight verifies
     * the source and all four canonical hardware leaves; there is no page
     * data or descriptor mutation before the lifecycle publishes metadata. */
    if(new_type==SPTM_MAC_USER_TPRO)c->user_tpro_protects++;
    else c->user_tpro_releases++;
    return 1;
}

static int sptm_retire_user_root(void *ctx, uint64_t pa, uint16_t asid)
{
    struct context *c = ctx;
    if (vcpu_root_busy(c, pa)) return 0;
    for (unsigned n = 0; n < TXM_REG(c)->count; n++)
        if (TXM_REG(c)->root[n] == pa ||
            (!TXM_REG(c)->shared[n] && TXM_REG(c)->asid[n] == asid))
            return 0;
    /* No CPU holds this root. Remove translations in every guest VMID before
     * allowing the retired ASID/frame to recur. */
    if(!sptm_root_invalidate(&c->user_roots,pa,1))return 0;
    shadow_tlb_sync(c);
#if SNAP_USER_HW_WALK
    /* After that flush its hardware ASIDs and copy pages may recur too. */
    struct hw_walk_root *hr=hw_root(c,pa);
    if(hr) {struct hw_walk_ops o=hw_ops(c);hw_walk_detach(c->hw_walk,&o,hr);}
#endif
    return 1;
}

static int sptm_share_user_root(void *ctx,uint64_t pa,uint16_t asid,uint8_t slot)
{
    struct context *c=ctx;
    if(vcpu_root_busy(c,pa))return 0;
    const struct params *p=c->params;
    struct sptm_memory memory=sptm_context_memory(c);
    struct sptm_aperture ap={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct txm_arena arena={p->txm_aspace_pa,sptm_aperture_pointer(&ap,p->txm_aspace_pa,TXM_ASPACE_SIZE)};
    struct txm_share_plan plan;
    if(txm_share_prepare(&memory,&arena,TXM_REG(c),pa,asid,slot,&plan))return 0;
    if(!sptm_root_invalidate(&c->user_roots,pa,1))return 0;
    shadow_tlb_sync(c);
#if SNAP_USER_HW_WALK
    /* A shared root is never switched to: its user-root record goes. */
    struct hw_walk_root *hr=hw_root(c,pa);
    if(hr) {struct hw_walk_ops o=hw_ops(c);hw_walk_detach(c->hw_walk,&o,hr);}
#endif
    txm_share_commit(&memory,TXM_REG(c),&plan);
    c->shared_root_converts++;
    return 1;
}

static int sptm_retire_shared_root(void *ctx,uint64_t pa,uint8_t slot)
{
    struct context *c=ctx;
    if(vcpu_root_busy(c,pa))return 0;
    for(unsigned i=0;i<TXM_REG(c)->count;i++)
        if(TXM_REG(c)->root[i]==pa || (TXM_REG(c)->root[i] &&
           TXM_REG(c)->shared[i] && TXM_REG(c)->asid[i]==slot))return 0;
    if(!sptm_root_invalidate(&c->user_roots,pa,1))return 0;
#if SNAP_NATIVE_SHARED
    for(unsigned g=0;g<NATIVE_SHARED_GROUPS;g++)if(UNS(c).group[g].guest &&
                                                   UNS(c).group[g].shared==pa) {
        if(!native_group_unlinked(c,(int)g) ||
           !native_shared_free(&UNS(c),(int)g,native_group_release,c) || c->user_view_failed)
            return 0;
    }
#endif
    shadow_tlb_sync(c);
    c->shared_root_releases++;
    return 1;
}

static int sptm_bind_shared_root(void *ctx,uint64_t user,uint16_t asid,
    uint64_t shared,uint8_t slot,uint64_t start,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory memory=sptm_context_memory(c);
    struct sptm_aperture ap={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct txm_arena arena={p->txm_aspace_pa,sptm_aperture_pointer(&ap,p->txm_aspace_pa,TXM_ASPACE_SIZE)};
    return txm_bind_shared(&memory,&arena,TXM_REG(c),user,asid,shared,slot,start,size)==SPTM_OK;
}

static int sptm_configure_user_root(void *ctx,uint64_t root,uint16_t before,uint16_t after)
{
    struct context *c=ctx;
    unsigned active=0;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)active+=c->user_roots.active[cpu]==root;
    if(active) {
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
            if(!sptm_root_recorded_matches(&c->user_roots,cpu,c->vcpus[cpu].guest_ttbr0,
                                          c->params->ttbr1_root) ||
               (c->vcpus[cpu].guest_ttbr1&UINT64_C(0x0000ffffffffc000))==root)return 0;
#if SNAP_USER_HW_WALK
        /* As for a cached root: UMPRR11 only, which no user leaf class (and so
         * no copy) depends on; UMPRR18 never changes under a running CPU. */
        struct hw_walk_root *hr=hw_root(c,root);
        if(hr) {
            if((before^after)!=SPTM_MAC_ROOT_FLAG_UMPRR11 || hr->entry.flags!=before)return 0;
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                if(!hw_walk_loaded_valid(&c->user_roots,c->hw_walk,c->root_loaded,cpu))return 0;
            hr->entry.flags=after;
            hr->umprr=((uint64_t)(after&8)<<15)|((uint64_t)(after&1)<<11);
            return 1;
        }
        /* A cached root, with hardware-walk roots possibly active elsewhere. */
        return hw_walk_configure_active(&c->user_roots,c->hw_walk,c->root_loaded,root,before,after);
#else
        return sptm_root_configure_active(&c->user_roots,c->root_loaded,root,before,after);
#endif
    }
#if SNAP_INACTIVE_MIRROR
    unsigned cached=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
        cached|=c->user_roots.cache[i].root==root && c->user_roots.cache[i].valid;
#endif
    if(vcpu_root_busy(c,root) || !sptm_root_invalidate(&c->user_roots,root,0))return 0;
#if SNAP_INACTIVE_MIRROR
    c->inactive_mirror.stats.configured+=cached;
#endif
    shadow_tlb_sync(c);
#if SNAP_USER_HW_WALK
    /* Inactive and flushed: the record goes; the next install attaches the
     * root again under its new flags (copies and discovery included). */
    struct hw_walk_root *hr=hw_root(c,root);
    if(hr) {struct hw_walk_ops o=hw_ops(c);hw_walk_detach(c->hw_walk,&o,hr);}
#endif
    return 1;
}

static void record(struct context *c, uint64_t kind, uint64_t pc,
                   uint64_t a, uint64_t b, uint64_t d)
{
    /* The terminal word, first and unconditionally.
     *
     * Before the repeat check and before the capacity check, because both of
     * those return early: a run whose last hundred events were repeats of one
     * sysreg trap, or whose log filled long ago, still has an answer to "what
     * was it doing when it stopped". This is the whole point of the slot -- a
     * write here that any branch below could skip would reintroduce the gap it
     * exists to close. Five words; `repeats` stays zero, because counting
     * repeats is the ring's job and this slot holds one event. */
    c->last.kind = kind;
    c->last.pc = pc;
    c->last.a = a;
    c->last.b = b;
    c->last.c = d;

    /* A spin loop reading one register fills the whole log with one fact. Repeats
     * of the last entry are counted instead of stored, so 32 slots hold 32
     * distinct things rather than 32 copies of the first. */
    if (c->events) {
        struct event *last = &c->log[c->events - 1];
        int same;
        if (kind == EV_SYSREG) {
            /* Sysreg traps collapse by which REGISTER was touched, not by
             * (pc, ISS).
             *
             * The ISS of an MSR/MRS trap carries the register's encoding, the
             * general-purpose register the value moved through, and the
             * direction. Collapsing on the whole word therefore treats "read
             * CNTFRQ into x0" and "read CNTFRQ into x1" as two different
             * facts, and the pc test splits them again per call site. They are
             * one fact -- the kernel is reading CNTFRQ -- and in the last run
             * that one fact took 36 of the 64 entries, three quarters of the
             * log before the boot had finished starting.
             *
             * SYSREG_ID keeps Op0, Op1, Op2, CRn and CRm and drops Rt (bits
             * 9:5) and the direction (bit 0). `pc` is not compared at all:
             * the same register read from two places is still the same
             * register, and the pc of the first is kept as the example. */
            same = last->kind == kind &&
                   (last->a & SYSREG_ID) == (a & SYSREG_ID);
        } else {
            same = last->kind == kind && last->pc == pc && last->a == a;
        }
        if (same) {
            last->repeats++;
            return;
        }
    }
    /* Dropped, and counted as dropped.
     *
     * This used to return silently, which made `events` cap at EVENT_MAX and
     * quietly falsified the host's overflow guard -- that guard tests
     * `events > len(log)`, which can never be true if the counter stops. A run
     * that overflowed therefore looked like a run that fitted, and the
     * classifier named a cause from a truncated tail with full confidence. */
    if (c->events >= EVENT_MAX) { c->log_dropped++; return; }
    struct event *e = &c->log[c->events++];
    e->repeats = 0;
    e->kind = kind;
    e->pc = pc;
    e->a = a;
    e->b = b;
    e->c = d;
}

/* One byte of the guest's console output, from wherever it came.
 *
 * There are two sources and one buffer. Early on the kernel asks us to print
 * for it, one character per SPTM_FN_SERIAL_PUTC; from the moment it takes its
 * serial line back it writes the same characters into a UART's transmit
 * register instead, and the dispatcher below brings them here. The host reads
 * one buffer and does not need to care which half of the boot it is reading.
 *
 * Counted when it does not fit, the way the event log counts events it drops.
 * A console that stops at exactly 1024 bytes looks the same as a kernel that
 * stopped talking, and the two are very different findings; one number tells
 * them apart. */
static void console_put(struct context *c, uint8_t byte)
{
    if (c->console_tail_bytes < CONSOLE_LOG_MAX)
        c->console_log[c->console_tail_bytes] = byte;
    c->console_tail[c->console_tail_bytes % CONSOLE_TAIL_MAX] = byte;
    c->console_tail_bytes++;
    if (c->console_len < CONSOLE_MAX)
        c->console[c->console_len++] = byte;
    else
        c->console_dropped++;
}

/* One out-of-memory mapping, folded into the span table.
 *
 * Called once per such PTE, in the order the guest asked for them. The guest
 * maps a device a page at a time -- ml_io_map walks the window handing each
 * 16K page to MAP_PAGE -- so consecutive calls walk one device's registers in
 * both address spaces at once, and folding them back into spans recovers the
 * window the kernel was working from. A span survives the log filling up,
 * which is the point: this is the shape of the device surface, and it is the
 * question the next step asks. */
static void map_range_note(struct context *c, uint64_t va, uint64_t pa,
                           uint64_t attrs)
{
    const uint64_t page = 1UL << 14;      /* the guest's granule, not ours */
    if (c->range_count) {
        struct map_range *r = &c->ranges[c->range_count - 1];
        if (r->attrs == attrs && r->va + r->pages * page == va &&
            r->pa + r->pages * page == pa) {
            r->pages++;
            return;
        }
    }
    /* Out of slots. Counted, never wrapped and never silently discarded: a
     * table that stopped growing would describe a device surface smaller than
     * the one the kernel actually asked for, and be believed. */
    if (c->range_count >= MAP_RANGES) { c->ranges_dropped++; return; }
    struct map_range *r = &c->ranges[c->range_count++];
    r->va = va;
    r->pa = pa;
    r->pages = 1;
    r->attrs = attrs;
}

/* One failed MAP_PAGE, named.
 *
 * Counted as well as logged: the log keeps 64 entries and collapses repeats, so
 * a storm of failures at different addresses would push everything before it
 * out. The count survives that and says how many there were even when the log
 * only had room for the first few. */
static void map_page_failed(struct context *c, uint64_t pc, uint64_t reason,
                            uint64_t va, uint64_t detail)
{
    c->map_failures++;
    record(c, EV_MAP_FAILED, pc, reason, va, detail);
}

/* --- stage 2 ---------------------------------------------------------------
 *
 * Stage 2 is what makes a first boot legible. It translates what stage 1
 * produced, the guest cannot see or change it, and a miss raises a fault at EL2
 * carrying the address. So it is built to cover exactly what we own -- the map
 * itself is shadow/stage2.c, walked page by page in tools/test-stage2.c -- and
 * anything XNU reaches for that we did not prepare lands here with its address,
 * which is the question to answer next rather than a hang.
 *
 * Until docs/PLAN-HISTORY-20260922.md's T4 this was sixty-four 1 GiB identity blocks over the whole
 * 36-bit space: every device access passed through to whatever the SoC keeps
 * at that physical address, unreported, and the kernel's console -- once it
 * released the monitor's serial -- went somewhere that was not us. That state
 * does not come back. The attribute bits are in stage2.h.
 */
#define S2_TXSZ    28u             /* 36-bit IPA: one 64-entry level-1 table */

static int guard_add(struct context *c, struct vcpu *v, uint64_t root,
                     uint64_t pa, uint64_t mode)
{
    if (v->guard_count >= 12) return -1;
    /* The page has to be in the map already: a guard changes what a mapped
     * page does, and an absent page is not guarded into existence. */
    struct shadow s2 = {.txsz = S2_TXSZ, .root = root, .alloc = table_alloc,
                        .read = mem_read, .write = mem_write, .ctx = c};
    uint64_t l3 = stage2_split(&s2, pa);
    if (!l3) return -1;
    struct guard *g = &v->guards[v->guard_count++];
    g->pa = pa & ~0xfffUL;
    g->slot = l3 + 8UL * ((pa >> 12) & 0x1ff);
    g->descriptor = *(volatile uint64_t *)g->slot;
    g->mode = mode;
    return 0;
}

static uint64_t writer_debug_read(void *ctx,unsigned index,int control)
{
    (void)ctx;uint64_t value=~0UL;
#define READ_WRITER_DEBUG(n) case n: \
    if(control) {__asm__ volatile("mrs %0, dbgbcr" #n "_el1":"=r"(value));} \
    else {__asm__ volatile("mrs %0, dbgbvr" #n "_el1":"=r"(value));} break
    switch(index) {
        READ_WRITER_DEBUG(0);READ_WRITER_DEBUG(1);READ_WRITER_DEBUG(2);
        READ_WRITER_DEBUG(3);READ_WRITER_DEBUG(4);READ_WRITER_DEBUG(5);
    }
#undef READ_WRITER_DEBUG
    return value;
}
static void writer_debug_write(void *ctx,unsigned index,int control,uint64_t value)
{
    (void)ctx;
#define WRITE_WRITER_DEBUG(n) case n: \
    if(control) {__asm__ volatile("msr dbgbcr" #n "_el1, %0"::"r"(value):"memory");} \
    else {__asm__ volatile("msr dbgbvr" #n "_el1, %0"::"r"(value):"memory");} break
    switch(index) {
        WRITE_WRITER_DEBUG(0);WRITE_WRITER_DEBUG(1);WRITE_WRITER_DEBUG(2);
        WRITE_WRITER_DEBUG(3);WRITE_WRITER_DEBUG(4);WRITE_WRITER_DEBUG(5);
    }
#undef WRITE_WRITER_DEBUG
}
static void writer_debug_barrier(void *ctx)
{(void)ctx;__asm__ volatile("isb":::"memory");}
static const struct native_writer_debug_ops writer_debug_ops={
    .read=writer_debug_read,.write=writer_debug_write,.barrier=writer_debug_barrier};

static void native_exception_snapshot(struct context *c)
{
    struct native_call_state *s=&c->native_calls[vcpu_of(c)->slot];
    uint64_t elr,spsr,esr,far;
    __asm__ volatile("mrs %0, elr_el1; mrs %1, spsr_el1; "
                     "mrs %2, esr_el1; mrs %3, far_el1"
                     : "=r"(elr), "=r"(spsr), "=r"(esr), "=r"(far)
                     :: "memory");
    /* Avoid dirtying adjacent CPU state when the legitimate values did not
     * change. In particular, ready is published only once per CPU. */
    if(s->elr!=elr)s->elr=elr;
    if(s->spsr!=spsr)s->spsr=spsr;
    if(s->esr!=esr)s->esr=esr;
    if(s->far!=far)s->far=far;
    if(!s->ready)s->ready=1;
}

static void native_exception_restore(struct native_call_state *s)
{
    __asm__ volatile("msr elr_el1, %0; msr spsr_el1, %1; "
                     "msr esr_el1, %2; msr far_el1, %3; isb"
                     :: "r"(s->elr), "r"(s->spsr), "r"(s->esr), "r"(s->far)
                     : "memory");
    s->restores++;
}

static void guard_write(struct context *c, struct guard *g, int open)
{
    uint64_t value = g->descriptor;
    if (!open) value = (g->mode == GUARD_EXEC) ? (value | S2_XN) : (value & ~PT_VALID);
#if SNAP_USER_TREE_MEMO
    /* The one post-boot arena store outside mem_write: a stage-2 guard
     * descriptor. Stage-2 pages are never user sources or copies; noting
     * them keeps the witness complete without relying on that. */
    if (g->slot >= c->work_base && g->slot < c->next_table)
        sprr_table_memo_note(&c->table_memo, g->slot);
#else
    (void)c;
#endif
    *(volatile uint64_t *)g->slot = value;
    __asm__ volatile("dc civac, %0" :: "r"(g->slot) : "memory");
}

static struct guard *guard_find(struct context *c, uint64_t pa)
{
    for (uint64_t n = 0; n < vcpu_of(c)->guard_count; n++)
        if (vcpu_of(c)->guards[n].pa == (pa & ~0xfffUL)) return &vcpu_of(c)->guards[n];
    return 0;
}

static void guard_open(struct context *c, struct guard *g)
{
    guard_write(c, g, 1);
    vcpu_of(c)->open_guards++;
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");
}

/* Shut every guard when leaving a stepped page or consuming a DATA access.
 * The normal same-page EXEC step can retain its one open descriptor. */
static void guards_close(struct context *c)
{
    if (!vcpu_of(c)->open_guards) return;
    for (uint64_t n = 0; n < vcpu_of(c)->guard_count; n++) guard_write(c, &vcpu_of(c)->guards[n], 0);
    vcpu_of(c)->open_guards = 0;
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");
}

/* Build private stage-2 tables and guards before running any guest CPU.
 * Shared allocator synchronization remains required for concurrent execution. */
static int vcpu_stage2_prepare(struct context *c, struct vcpu *v)
{
    const struct params *p = c->params;
    uint64_t stub_count = p->stub_count & ~NATIVE_CALL_FLAGS;
    if (!!(p->stub_count & NATIVE_CALL_FLAG) != !!SNAP_NATIVE_CALLS ||
        !!(p->stub_count & NATIVE_HVC_FLAG) != !!SNAP_SPTM_HVC_CALLS ||
        stub_count > 8) return -30;
    if (SNAP_NATIVE_CALLS) {
        unsigned calls=0,writers=0;
        if (stub_count != NATIVE_CONTRACT_PAGES || !p->vncr_va ||
            !p->vbar || !p->vbar_va || p->const_begin<p->mem_low ||
            p->const_begin>=p->const_end || p->const_end>p->alloc_low ||
            ((p->const_begin|p->const_end)&0x3fff)) return -31;
        for (unsigned n=0;n<stub_count;n++) {
            uint64_t pa=p->stub_pa[n];
            unsigned nc=0,nw=0;
            if ((pa&4095) || pa<p->const_begin || pa>p->const_end-4096) return -32;
            for (unsigned j=0;j<n;j++) if(pa==p->stub_pa[j]) return -32;
            const uint32_t *words=(const uint32_t *)pa;
            for (unsigned i=0;i<1024;i++) {
                nc+=SNAP_SPTM_HVC_CALLS ? words[i]==NATIVE_HVC_WORD : native_call_word(words[i]);
                if(SNAP_SPTM_HVC_CALLS ? native_call_word(words[i]) : words[i]==NATIVE_HVC_WORD)
                    return -35;
                nw+=native_exception_writer(words[i]);
            }
            if (n<NATIVE_CALL_PAGES ? (!nc || nw) : (!nw || nc)) return -33;
            calls+=nc;writers+=nw;
        }
        if (calls!=348 || writers!=10) return -34;
    }
    uint64_t root = table_alloc(c);
    if (!root) return -3;
    struct shadow s2 = {.txsz = S2_TXSZ, .root = root, .alloc = table_alloc,
                        .read = mem_read, .write = mem_write, .ctx = c};
#if SNAP_I2C_INPUT && SNAP_QCC2072_WIFI
    struct stage2_range ranges[8 + I2C_INPUT_STAGE2_MAX + QCC2072_WIFI_STAGE2_MAX + SNAP_DISPLAY_TIMING_ROWS];
#elif SNAP_I2C_INPUT
    struct stage2_range ranges[8 + I2C_INPUT_STAGE2_MAX + SNAP_DISPLAY_TIMING_ROWS];
#elif SNAP_QCC2072_WIFI
    struct stage2_range ranges[8 + QCC2072_WIFI_STAGE2_MAX + SNAP_DISPLAY_TIMING_ROWS];
#else
    struct stage2_range ranges[8 + SNAP_DISPLAY_TIMING_ROWS];
#endif
    unsigned count = 0;
    uint64_t panic_page=p->scratch_pa-SPTM_PANIC_PAGE_SIZE;
    ranges[count++] = (struct stage2_range){
        .lo = p->mem_low, .hi = panic_page, .low = S2_AP_RW | S2_ATTRS, .upper = 0};
    ranges[count++] = (struct stage2_range){
        .lo = panic_page, .hi = p->scratch_pa, .low = S2_AP_RO | S2_ATTRS, .upper = S2_XN};
    ranges[count++] = (struct stage2_range){
        .lo = p->scratch_pa, .hi = p->mem_high, .low = S2_AP_RW | S2_ATTRS, .upper = 0};
    if (p->fb_span)
        ranges[count++] = (struct stage2_range){
            .lo = p->fb_pa, .hi = p->fb_pa + p->fb_span,
            .low = S2_AP_RW | S2_ATTRS, .upper = S2_XN};
    ranges[count++] = (struct stage2_range){
        .lo = c->work_base, .hi = c->work_end,
        .low = S2_AP_RO | S2_ATTRS, .upper = S2_XN};
    /* Stage 4: the Adreno register windows the guest drives itself, as device
     * memory; every other block of the GPU aperture stays absent (adreno.h). */
    if (p->gpu.flags & ADRENO_F_ENABLE) {
        ranges[count++] = (struct stage2_range){ADRENO_PA, ADRENO_PASS0_END,
            S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        ranges[count++] = (struct stage2_range){ADRENO_PASS1_PA, ADRENO_PASS1_END,
            S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        if (p->gpu.flags & ADRENO_F_CX_MISC)
            ranges[count++] = (struct stage2_range){ADRENO_CX_MISC_PA, ADRENO_CX_MISC_END,
                S2_AP_RO | S2_ATTRS_DEVICE, S2_XN};
    }
#if SNAP_I2C_INPUT
    /* The keyboard's GENI page only, after an exact allow-list check of the
     * loader's words: anything else refuses the boot before a guest runs. */
    {
        int rows = i2c_input_rows(&p->i2c_input, ranges + count);
        if (rows < 0) return -41;
        count += (unsigned)rows;
    }
#endif
#if SNAP_QCC2072_WIFI
    /* The QCC2072's five windows, after an exact allow-list check of the
     * loader's words and of the provider record it placed on the control page
     * (read here through EL2's identity map). Anything else refuses the boot. */
    {
        const struct qcc2072_wifi_params *q = qcc2072_wifi_block(p);
        int rows = qcc2072_wifi_valid(q) ?
            qcc2072_wifi_rows(q, (const volatile uint64_t *)(uintptr_t)q->control_pa, ranges + count) : -1;
        if (rows < 0) return -42;
        count += (unsigned)rows;
    }
#endif
#if SNAP_DISPLAY_TIMING
    /* The eDP interface's timing page, read-only Device-nGnRE, after an exact allow-list check of the loader's words
     * (compat/display-timing.h): anything else, a missing block included, refuses the boot before a guest runs. */
    {
        int rows = display_timing_rows(display_timing_block(p), ranges + count);
        if (rows < 0) return -43;
        count += (unsigned)rows;
    }
#endif
    int built = stage2_build(&s2, ranges, count);
    if (built == STAGE2_BAD_RANGES) return -10;
    if (built) return -11;
    if(p->const_begin<p->mem_low || p->const_begin>=p->const_end ||
       p->const_end>p->alloc_low || ((p->const_begin|p->const_end)&0x3fff) ||
       !stage2_split(&s2,p->const_begin) || !stage2_split(&s2,p->const_end-4096))return -20;
    if(p->trust_cache.pa) {
        uint64_t begin=p->trust_cache.pa;
        uint64_t end=begin+0x4000+((p->trust_cache.size+0x3fff)&~0x3fffUL);
        if(!stage2_split(&s2,begin) || !stage2_split(&s2,end-4096) ||
           stage2_readonly(&s2,begin,end,0))return -21;
    }
    if (p->write_watch_pa) {
        if ((p->write_watch_pa & 0xfff) || p->write_watch_pa < p->mem_low ||
            p->write_watch_pa >= p->mem_high) return -12;
        uint64_t l3 = stage2_split(&s2, p->write_watch_pa);
        if (!l3) return -12;
        uint64_t *slot = (uint64_t *)(l3 + 8 * ((p->write_watch_pa >> 12) & 511));
        *slot &= ~(1UL << 7);  /* S2AP RW -> RO; execute guards retain this */
    }

    for (uint64_t n = SNAP_NATIVE_WRITER_BREAKPOINTS ? stub_count :
             SNAP_NATIVE_CALLS ? NATIVE_CALL_PAGES : 0; n < stub_count; n++)
        if (guard_add(c, v, root, p->stub_pa[n], GUARD_EXEC)) return -4;
    if (p->vbar && guard_add(c, v, root, p->vbar, GUARD_EXEC)) return -5;
    /* The handoff, observed rather than guessed. Every field XNU reads faults
     * here with its own offset, which is the struct layout measured instead of
     * inferred from a header that may have moved. */
    for (uint64_t n = 0; n < p->watch_count; n++)
        if (guard_add(c, v, root, p->watch_pa + n * 0x1000, GUARD_DATA)) return -7;
    for (uint64_t n = 0; n < v->guard_count; n++) guard_write(c, &v->guards[n], 0);
    /* Publish all descendants before installing this previously unused root. */
    publish(root, c->next_table);
    v->stage2_root = root;
    return 0;
}

static uint64_t vcpu_vttbr(const struct vcpu *v)
{
    /* VTCR.VS is zero: eight-bit VMIDs. Distinct roots also need distinct
     * translation-cache identities to keep temporary guards CPU-local. */
    return v->stage2_root | ((v->slot + 1UL) << 48);
}

static int const_region_seal(struct context *c)
{
    const struct params *p=c->params;
    /* Validate every CPU before the first permission change. Boundaries were
     * split before entry: no live block-to-table transition or allocation. */
    for(unsigned pass=0;pass<2;pass++)for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct vcpu *v=&c->vcpus[cpu];
        struct shadow s={.txsz=S2_TXSZ,.root=v->stage2_root,
            .read=mem_read,.write=mem_write,.ctx=c};
        if(stage2_readonly(&s,p->const_begin,p->const_end,!pass))return -1;
        if(pass)for(unsigned g=0;g<v->guard_count;g++)
            if(v->guards[g].pa>=p->const_begin && v->guards[g].pa<p->const_end)
                v->guards[g].descriptor&=~(1UL<<7);
    }
    publish(c->work_base,c->next_table);
    /* Publish the permission changes, then invalidate stage 1+2 for each distinct
     * VMID, including prepared CPUs that have not entered yet. */
    uint64_t saved;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ish" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        uint64_t vttbr=vcpu_vttbr(&c->vcpus[cpu]);
        __asm__ volatile("msr vttbr_el2, %0; isb; tlbi vmalls12e1is; dsb ish; isb"
                         :: "r"(vttbr) : "memory");
        c->const_tlb_invalidations++;
    }
    __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    c->const_sealed_cpus=(1UL<<GUEST_CPU_COUNT)-1;
    return 0;
}

/* A guest virtual address, resolved to a physical one.
 *
 * EL2 has its own flat view of memory and cannot dereference a kernel VA. With
 * stage 2 enabled AT S1E1R performs stage 1 alone and reports the intermediate
 * address, which this stage-2 map translates to itself, so the result is usable
 * directly. Zero means the walk faulted. */
static uint64_t guest_pa(uint64_t va)
{
    uint64_t par, saved_par;
    /* PAR_EL1 belongs to the guest too. A debug step can arrive between its
     * AT and MRS PAR_EL1: fetching the stepped instruction must not replace
     * its data translation with the physical address of the code page. */
    __asm__ volatile("mrs %0, par_el1; at s1e1r, %2; isb; "
                     "mrs %1, par_el1; msr par_el1, %0; isb"
                     : "=&r"(saved_par), "=&r"(par) : "r"(va) : "memory");
    if (par & 1) return 0;
    return (par & 0x0000fffffffff000UL) | (va & 0xfff);
}

static uint64_t step_instruction_pa(struct context *c, uint64_t va, uint64_t spsr)
{
    struct vcpu *v = vcpu_of(c);
    struct step_translation *t = &c->step_translation[v->slot];
    int eligible = SNAP_STEP_TRANSLATION && exception_monitor_origin(va, spsr) &&
                   v->stepping.active && v->open_guards == 1;
    if (eligible && step_translation_match(t, va, c->shadow_tlb_syncs) &&
        t->guard < v->guard_count) {
        struct guard *g = &v->guards[t->guard];
        if (g->mode == GUARD_EXEC && g->pa == t->pa_page &&
            *(volatile uint64_t *)g->slot == g->descriptor) {
            uint64_t pa = t->pa_page | (va & 0xfff);
            t->hits++;
            /* Diagnostic builds sample the actual architectural translation.
             * A mismatch stops the run rather than using a stale address. */
            if (SNAP_STEP_TRANSLATION_VERIFY && !(t->hits & 1023)) {
                uint64_t actual = guest_pa(va);
                t->verified++;
                if (actual != pa) {
                    t->mismatches++;
                    step_translation_clear(t);
                    c->kernel_view_failed = 1;
                    return 0;
                }
            }
            return pa;
        }
    }
    t->misses++;
    step_translation_clear(t);
    uint64_t pa = guest_pa(va);
    if (eligible && pa) {
        struct guard *g = guard_find(c, pa);
        if (g && g->mode == GUARD_EXEC &&
            *(volatile uint64_t *)g->slot == g->descriptor) {
            t->va_page = va & ~UINT64_C(0xfff);
            t->pa_page = pa & ~UINT64_C(0xfff);
            t->generation = c->shadow_tlb_syncs;
            t->guard = (uint64_t)(g - v->guards);
            t->valid = 1;
        }
    }
    return pa;
}

/* Software step, driven from EL2: MDCR_EL2.TDE routes the guest's debug
 * exceptions here, MDSCR_EL1.SS plus SPSR_EL2.SS means "one instruction, then
 * except". PSTATE.D masks debug exceptions and the guest runs with it set, so
 * it is cleared for the duration and put back. This machine's firmware also
 * leaves the OS Lock held, which disables self-hosted debug outright; without
 * clearing it the step silently never fires. */
static void guest_interrupt_sync(struct context *c)
{
    uint64_t hcr;
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
    int fiq = exception_step_fiq(&vcpu_of(c)->stepping, guest_ipi_fiq(&vcpu_of(c)->ipi,vcpu_of(c)->timer_pending));
    int irq = exception_step_fiq(&vcpu_of(c)->stepping, vcpu_of(c)->model_irq_pending);
    if (fiq != !!(hcr & (1UL << 6))) {
        if (fiq) vcpu_of(c)->timer_asserts++; else vcpu_of(c)->timer_clears++;
    }
    if (irq != !!(hcr & (1UL << 7))) {
        if (irq) vcpu_of(c)->model_irq_asserts++; else vcpu_of(c)->model_irq_clears++;
    }
    uint64_t next = (hcr & ~((1UL << 6) | (1UL << 7))) |
                    (fiq ? 1UL << 6 : 0) | (irq ? 1UL << 7 : 0);
    if (next != hcr) __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(next));
}

static void step_arm(struct context *c, int on)
{
    uint64_t mdscr, spsr;
    __asm__ volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
    exception_step_set(&vcpu_of(c)->stepping, on, &spsr, &mdscr);
    __asm__ volatile("msr mdscr_el1, %0" :: "r"(mdscr));
    __asm__ volatile("msr spsr_el2, %0" :: "r"(spsr));
    __asm__ volatile("isb");
    /* Do not expose our temporary D=0/SS=1 in XNU's saved IRQ/FIQ state. Hold the
     * level pending during monitor stepping, then assert it after restoring
     * the guest mask. Physical timer IRQs and the watchdog remain enabled. */
    guest_interrupt_sync(c);
}

static void guard_step(struct context *c, uint64_t pa)
{
    struct guard *here = pa ? guard_find(c, pa) : 0;
    struct vcpu *v = vcpu_of(c);
    /* Every guard_open increments open_guards, and guards_close resets it.
     * Exactly one open plus this unchanged open descriptor rules out an
     * outstanding DATA access or a different open EXEC page. Keep observing
     * each instruction without rewriting identical descriptors and issuing
     * two broadcast TLB invalidations. Rearm SS while preserving saved D and
     * the pending guest interrupt mask. Synchronous vectors are handled before
     * this path; all other cases retain the close/reopen sequence. */
    if (here && here->mode == GUARD_EXEC && v->stepping.active &&
        v->open_guards == 1 &&
        *(volatile uint64_t *)here->slot == here->descriptor) {
        step_arm(c, 1);
        return;
    }
    step_arm(c, 0);
    guards_close(c);
    if (here && here->mode == GUARD_EXEC) {
        guard_open(c, here);
        step_arm(c, 1);
    }
}

static uint64_t shadow_tcr(uint64_t guest_tcr)
{
    /* TG1 is not TG0: the field at [31:30] encodes 0b10 as 4K, while TG0 at
     * [15:14] encodes 0b00 as 4K. Both halves are forced to 4K here.
     *
     * TTBR0 used to be disabled, on the grounds that the kernelcache lives
     * entirely in the upper half. That is true of the image and does not cover
     * what the kernel does: it walks and then *accesses* addresses numerically
     * equal to physical ones, down at level-1 entry 0. Its software walker
     * masks a virtual address into the regime's offset space and never asks
     * which table base would apply, so those walks resolved through the upper
     * tables while the first real load through one went to a regime that was
     * switched off -- a level-0 translation fault on 0xf6010000 with everything
     * correctly mapped. See docs/APERTURE-FAULT.md. */
    uint64_t tcr = (guest_tcr & ~(3UL << 30)) | (2UL << 30);
    tcr &= ~(1UL << 23);                       /* EPD1 clear: walk TTBR1 */
    tcr &= ~(1UL << 7);                        /* EPD0 clear: walk TTBR0 too */
    tcr = (tcr & ~(3UL << 14));                /* TG0 = 0b00, 4K */
    /* T0SZ matches T1SZ so both halves are the same shape and one shadow
     * builder serves both. */
    tcr = (tcr & ~0x3fUL) | ((guest_tcr >> 16) & 0x3f);

    /* IPS is ours, not the guest's. XNU ships TCR_EL1.IPS = 0, which caps every
     * output address of this regime -- including the shadow's own table
     * addresses -- at 32 bits. That held only because the image and the probe's
     * work area both happened to sit under 4 GiB on the A16. They do not have
     * to: the work area comes from q1n1's heap, and firmware that allocates from
     * the top of a 4 GiB map puts it above the line, at which point the very
     * first table fetch is an address size fault and the entry point looks
     * unmappable. The guest never sees this value -- TRVM hands XNU back its own
     * TCR -- so it is set from what the hardware can actually address. */
    uint64_t parange;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(parange));
    parange &= 0xf;
    if (parange > 5) parange = 5;              /* 48 bits; no LPA here */
    tcr = (tcr & ~(7UL << 32)) | (parange << 32);
    return tcr;
}

/* Give back every table page cache slot `slot` owns: canonical shadow and
 * private CPU copies alike (both carry owner slot+1). No CPU can install the
 * slot while the service lock is held and its entry is invalid. Retire all
 * VMID translations before recycling its canonical and private pages; other
 * roots and permanent monitor pages retain ownership. With require_flush a
 * TLBI that did not happen (kernel refresh failure) keeps every page owned.
 * Returns the number of pages released, or -1. */
static int root_slot_release(struct context *c,unsigned slot,int require_flush)
{
    uint64_t syncs=c->shadow_tlb_syncs;
    shadow_tlb_sync(c);
    if(require_flush && c->shadow_tlb_syncs==syncs)return -1;
#if SNAP_NATIVE_SHARED
    /* The slot's tables and the links in them go; the groups stay. */
    if(!native_shared_forget_slot(&UNS(c),slot))return -1;
#endif
#if SNAP_USER_VIEW_CACHE
    sprr_view_epoch_advance(&c->user_view_epoch);
    UPROOFS(c)[slot].valid=0;
#endif
#if SNAP_PRIVATE_VIEW_EPOCH
    for(unsigned i=0;i<(c->next_table-c->work_base)/4096;i++)
        if(c->table_pool.owner[i]==slot+1 && !sprr_private_clear(&c->private_pages,i,1))return -1;
#endif
    int released=table_pool_release(&c->table_pool,
        (uint32_t)((c->next_table-c->work_base)/4096),slot+1);
    if(released<0)return -1;
#if SNAP_NATIVE_TABLES
    native_mark(c,&UVIEWS(c)[slot],0);
#endif
    volatile uint64_t *view=(volatile uint64_t *)&UVIEWS(c)[slot];
    for(unsigned i=0;i<sizeof(UVIEWS(c)[slot])/8;i++)view[i]=0;
    /* The view's claims describe metadata that no longer exists. */
    volatile uint64_t *memo=(volatile uint64_t *)&UMEMOS(c)[slot];
    for(unsigned i=0;i<sizeof(UMEMOS(c)[slot])/8;i++)memo[i]=0;
    return released;
}
static uint64_t arena_available(const struct context *c)
{
    return (c->work_end-c->next_table)/4096+c->table_pool.count;
}
/* Table-arena pressure: give back inactive cached roots, cheapest first
 * (sptm_root_reclaim_pick), until `target` pages are free or none qualifies.
 * Only between transactions -- at a monitor-call entry or inside a root build,
 * whose own slot is in `exclude` -- never from an allocation callback, since
 * prepare/commit alias masks and reservations name cached slots. A given-back
 * root is simply uncached: user updates to it go to its guest tables and its
 * next SWITCH_ROOT rebuilds the shadow, exactly as after a full-cache eviction. */
static void arena_reclaim(struct context *c,uint64_t target,sptm_root_mask_t exclude)
{
    struct arena_reclaim_stats *a=&c->arena_reclaim;
    for(unsigned n=0;n<SPTM_ROOT_CACHE && arena_available(c)<target;n++) {
        unsigned slot=sptm_root_reclaim_pick(&c->user_roots,USTAMPS(c),exclude);
        if(slot>=SPTM_ROOT_CACHE)return;
        SPTM_ROOT_MASK_SET(exclude,slot);
        struct sptm_root_cached *e=&c->user_roots.cache[slot];
        if(e->root && vcpu_root_busy(c,e->root))continue;
        unsigned kind=!e->root ? 0 : e->valid ? 2 : 1;
        if(!sptm_root_reclaim_forget(&c->user_roots,slot))return;
        int released=root_slot_release(c,slot,1);
        if(released<0) {a->flush_failures++;return;}
        a->slots++;a->pages+=(unsigned)released;
        if(kind==0)a->retired++;else if(kind==1)a->invalid++;else a->valid++;
    }
}
/* Monitor-call entry: record the arena low-water mark and restore the
 * reserve before the call can allocate. SWITCH_ROOT's own target is never
 * given back just to be rebuilt by the same call. */
static void arena_reserve(struct context *c,const uint64_t *frame)
{
    struct arena_reclaim_stats *a=&c->arena_reclaim;
    const uint64_t reserve=SNAP_ARENA_RESERVE_PAGES;
    uint64_t available=arena_available(c);
    if(!a->checks || available<a->low_water)a->low_water=available;
    a->checks++;
    if(!reserve || available>=reserve || c->kernel_view_failed)return;
    sptm_root_mask_t exclude=SPTM_ROOT_MASK_NONE;
    if(frame[16]==SPTM_FN_SWITCH_ROOT && frame[0])
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
            if(c->user_roots.cache[i].root==frame[0])SPTM_ROOT_MASK_SET(exclude,i);
    a->reclaims++;
    arena_reclaim(c,reserve+reserve/2,exclude);
}
#if SNAP_NATIVE_LIVE
/* USER_ROOT constructor (the new root page is empty): cache the root with an
 * empty tree in a never-used slot, else the cheapest inactive one
 * (sptm_root_reclaim_pick; never an active root). Best effort: without a slot
 * or a page the root stays uncached and its first switch builds as before. */
static void native_root_created(void *ctx,uint64_t pa,uint16_t asid,unsigned format,unsigned flags)
{
    struct context *c=ctx;struct sptm_root_state *s=&c->user_roots;
    unsigned slot=SPTM_ROOT_CACHE;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        if(s->cache[i].root==pa) {c->native_stats.uncreated++;return;}
        if(slot==SPTM_ROOT_CACHE && !s->cache[i].root && !s->cache[i].shadow)slot=i;
    }
    if(format) {c->native_stats.uncreated++;return;}
    if(slot==SPTM_ROOT_CACHE) {
        slot=sptm_root_reclaim_pick(s,USTAMPS(c),SPTM_ROOT_MASK_NONE);
        if(slot>=SPTM_ROOT_CACHE || (s->cache[slot].root && vcpu_root_busy(c,s->cache[slot].root)) ||
           !sptm_root_reclaim_forget(s,slot) || root_slot_release(c,slot,1)<0) {
            c->native_stats.uncreated++;return;
        }
        c->root_evictions++;
    }
    uint64_t shadow=user_table_alloc(&UOWNERS(c)[slot]);
    if(!shadow) {c->native_stats.uncreated++;return;}
    s->cache[slot]=(struct sptm_root_cached){.root=pa,.shadow=shadow,.asid=asid,.format=0,
                                             .flags=flags,.valid=1};
    USTAMPS(c)[slot]=++c->arena_reclaim.clock;
    c->native_stats.created++;
}
#endif
static int user_root_build(void *ctx,const struct sptm_memory *memory,
    uint64_t root,unsigned format,unsigned flags,uint64_t previous,
    uint64_t *result,uint64_t *leaves)
{
    struct context *c=ctx;
    unsigned slot=SPTM_ROOT_CACHE;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];
        if((previous && e->shadow==previous) ||
           (!previous && !e->shadow && (!e->root || e->root==root))) {slot=i;break;}
    }
    if(slot==SPTM_ROOT_CACHE)return 0;
    struct sptm_root_cached *e=&c->user_roots.cache[slot];
    if(e->valid || (e->root && vcpu_root_busy(c,e->root)))return 0;
    for(unsigned attempt=0;;attempt++) {
        uint64_t failures=c->arena_reclaim.alloc_failures;
        if(root_slot_release(c,slot,0)<0)return 0;
        struct user_table_owner *owner=&UOWNERS(c)[slot];
        struct shadow s={.txsz=17,.root=user_table_alloc(owner),
            .alloc=user_table_alloc,.read=mem_read,.write=mem_write,.ctx=c,.alloc_ctx=owner,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
#if SNAP_NATIVE_SHARED
        /* 16K roots link their nested shared tables' groups. */
        struct native_links nl={c,&s,slot,native_shared_root_of(c,root)};
        struct sptm_root_links links=native_links_for(&nl);
        int built=s.root && (format ? sptm_root_build_shadow(memory,&s,root,format,flags,leaves) :
#if SNAP_ROOT_MISS_FAST
                             /* Linked shared tables may be answered by retained
                              * verdicts; copied tables are scanned (compat/root-miss.h). */
                             sptm_root_build_linked_memo(memory,&s,root,format,flags,leaves,&links,
                                                         &c->root_memo,nl_grouped));
#else
                             sptm_root_build_linked(memory,&s,root,format,flags,leaves,&links));
#endif
#else
        int built=s.root && sptm_root_build_shadow(memory,&s,root,format,flags,leaves);
#endif
        if(built) {
            *result=s.root;return 1;
        }
        /* Only a build the arena ran dry is retried, once: give back other
         * inactive slots, then release this slot's partial tables (the next
         * pass does) and build again from the unchanged guest tables. Any
         * other failure is terminal; partial allocations stay owned for
         * capture -- rewinding the bump pointer would lose reclaimed-page
         * ownership. */
        if(attempt || c->arena_reclaim.alloc_failures==failures || c->kernel_view_failed)
            return 0;
        c->arena_reclaim.build_retries++;
        arena_reclaim(c,ARENA_RETRY_PAGES,SPTM_ROOT_MASK_ONE(slot));
    }
}

static struct sptm_root_cached *user_cached(struct context *,uint64_t);
static uint64_t user_install_view(struct context *,uint64_t,uint64_t,int);
/* A root installation's earlier invalidations cover only this CPU's own
 * kernel copy and its old/new user copy (every copy page belongs to exactly one
 * CPU's view; other CPUs' copies are invalidated by the refresh that writes
 * them). This CPU stays at EL2 until the final sequence below has completed
 * its all-VMID TLBI, after the same publication. With SNAP_INSTALL_TLBI_DEFER
 * those inner TLBIs are folded into that one; any failure exit still issues
 * the deferred invalidation before returning. */
static void install_failed(struct context *c,int deferred)
{
    c->root_install_failures++;
    if(deferred) {
        c->install_tlbi.failure_flushes++;
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        c->shadow_tlb_syncs++;
    }
}
static void user_root_install(void *ctx,uint64_t shadow,uint64_t guest_root,
                              uint64_t asid,unsigned format)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
#if SNAP_EL0_MEMO
    /* Before anything changes: this vCPU's EL0 fetch memo is stale. */
    el0_memo_installed(&EL0M(c)[v->slot]);
#endif
    const int defer=SNAP_INSTALL_TLBI_DEFER;int deferred=0;
    if(defer)c->install_tlbi.installs++;
#if SNAP_NATIVE_TABLES
    /* The reset PPERM is usually this CPU's value already, and its kernel
     * copy is exact for it: nothing to do. Otherwise the transaction runs
     * with its own invalidation, since no install-wide flush follows. Nothing
     * is folded (install_tlbi counts installs only); a failure still flushes
     * on its way to the terminal stop. */
    if(c->user_roots.sprr[v->slot].pperm!=SPRR_PPERM_INITIAL) {
        if(!kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,1)) {c->root_install_failures++;return;}
    } else c->native_stats.pperm_skips++;
    deferred=defer;
#if SNAP_USER_HW_WALK
    /* compat/sptm-root.c installs a hardware-walk root with shadow 0: the
     * same PPERM reset above, then its own TTBR0 values (hw_install_user). */
    if(asid && !shadow) {hw_install_user(c,guest_root,asid,format);return;}
#endif
    if(asid) {
        shadow=user_install_view(c,guest_root,shadow,0);
        if(!shadow) {install_failed(c,deferred);return;}
    } else {
#else
    if(!kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,!defer)) {c->root_install_failures++;return;}
    if(defer) {deferred=1;c->install_tlbi.pperm_folded++;}
    if(asid) {
        shadow=user_install_view(c,guest_root,shadow,!defer);
        if(!shadow) {install_failed(c,deferred);return;}
        if(defer)c->install_tlbi.view_folded++;
    } else {
#endif
        struct user_view_state *u=&c->user_view_state[v->slot];
        u->root=u->shadow=u->el0=u->uperm=u->pperm=u->umprr=0;
#if SNAP_NATIVE_TABLES
        native_uninstall(&c->native_cpu[v->slot]);
#endif
    }
    /* mac-v1 format descriptors ...2701ec78/...2701ece0, with AS set by
     * SWITCH_ROOT. Both become the same hardware4K regime on the A16. */
    if(asid) {
        v->guest_tcr=(format ? SPTM_ROOT_TCR_4K : SPTM_ROOT_TCR_16K)|(1UL<<36);
        struct sptm_root_cached *entry=user_cached(c,guest_root);
        if(!entry) {install_failed(c,deferred);return;}
        USTAMPS(c)[entry-c->user_roots.cache]=++c->arena_reclaim.clock;
        v->guest_sctlr=pauth_root_enables(v->guest_sctlr,(unsigned)entry->flags);
    }
#if SNAP_NATIVE_TABLES
    /* The variant native_install named, in its own ASID; XNU's ASID stays
     * in guest_ttbr0. */
    const struct native_cpu *nc=&c->native_cpu[v->slot];
    uint64_t ttbr=asid ? nc->ttbr0[nc->w&1][nc->k&1] : shadow;
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    if(asid && (ttbr&PT_OA_MASK)!=shadow) {install_failed(c,deferred);return;}
#else
    uint64_t ttbr=shadow|(asid<<48),tcr=shadow_tcr(v->guest_tcr);
#endif
#if SNAP_ROOT_DIRTY_PUBLISH
    /* With SNAP_ROOT_PUBLISH_BATCH_DSB the pages are cleaned without per-page
     * barriers; the leading dsb ish of the sequence below completes them all
     * before the TLBI, as each per-page barrier did. */
#if SNAP_ROOT_PUBLISH_BATCH_DSB
    int (*page)(void *,uint64_t)=publish_page_lines;
#else
    int (*page)(void *,uint64_t)=root_publish_page;
#endif
#if SNAP_INCREMENTAL_PUBLISH
    if(!root_index_flush(&c->root_publish,&c->perf.root_index,c->work_base,c->next_table,page,c)) {
#else
    if(!root_publish_flush(&c->root_publish,c->work_base,c->next_table,page,c)) {
#endif
        __asm__ volatile("dsb ish" ::: "memory");
        install_failed(c,deferred);return;
    }
#else
    publish(c->work_base,c->next_table);
#endif
#if SNAP_NATIVE_TABLES
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    if(live_tcr==tcr) {
        /* Same regime: every address space and variant has its own ASID, so
         * a switch is a TTBR0 write. Only crossing between the kernel root
         * (ASID 0, global low entries) and a user root drops this CPU's
         * entries, locally: its VMID is its own. */
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        /* A different shared region than the one whose global entries this CPU may hold: flush them, as SPTM does
         * (see user_shared_slot). An unreadable binding flushes too. */
        int shared_flush=0;
        if(asid) {
            struct sptm_memory memory=sptm_context_memory(c);
            int region=sptm_mac_root_shared_slot(&memory,guest_root);
            uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
            uint16_t last=c->user_shared_slot[v->slot];
            shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        }
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            c->native_stats.local_flushes++;
            if(shared_flush)c->shared_switch_flushes[v->slot]++;
            c->user_shared_slot[v->slot]=0;
        }
    } else
#endif
    /* Break the old regime before changing granule/control values. Flush all
     * guest VMIDs because each CPU owns a private stage2 identity. */
    __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                     "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                     :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1"
                     :"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    /* Record the region whose global entries this CPU may now cache (after any flush above). */
    if(asid) {
        struct sptm_memory memory=sptm_context_memory(c);
        int region=sptm_mac_root_shared_slot(&memory,guest_root);
        c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    }
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)c->root_install_failures++;
    v->guest_ttbr0=guest_root|(asid<<48);
    c->shadow_tlb_syncs++;
}

int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,
                  const struct secondary_config *host_cpus);
int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,
                  const struct secondary_config *host_cpus)
{
    struct context *c = (struct context *)work;
    for (unsigned n = 0; n < sizeof(*c) / 8; n++) ((uint64_t *)c)[n] = 0;
#if SNAP_ROOT_CACHE_WIDE
    /* The wide cache's state takes the arena's first pages (owner 0, never
     * released); next_table starts after it below. */
    if (size < sizeof(*c) + 4096 + ROOT_EXT_PAGES * 4096) return 1;
    c->root_ext = (struct root_ext *)((work + sizeof(*c) + 0xfff) & ~0xfffUL);
    for (uint64_t n = 0; n < ROOT_EXT_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->root_ext)[n] = 0;
#endif
#if SNAP_TXM_ASPACE_WIDE
    /* The TXM registry follows (compat/txm.h A3/A5): zeroed before any TXM
     * call, owner 0, below next_table, never a table. */
    if ((work & 0xfff) || size < TXM_EXT_OFFSET + TXM_EXT_PAGES * 4096 + 4096) return 1;
    for (uint64_t n = 0; n < TXM_EXT_PAGES * 4096 / 8; n++) ((volatile uint64_t *)TXM_REG(c))[n] = 0;
#endif
    c->params = (const struct params *)params;
    c->writer_breakpoints_enabled=SNAP_NATIVE_WRITER_BREAKPOINTS;
    c->host_cpus=host_cpus;
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        c->vcpus[n].context = c;
        c->vcpus[n].slot = n;
        c->vcpus[n].vmpidr = 0x80000000UL | (n < 4 ? n : 0x100+n-4);
        sprr_root_reset(&c->user_roots.sprr[n],0);
        if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,n))return 1;
        pauth_user_init(&c->user_pauth[n]);
        c->vcpus[n].guest_apga_lo=c->user_pauth[n].key[PAUTH_GA].lo;
        c->vcpus[n].guest_apga_hi=c->user_pauth[n].key[PAUTH_GA].hi;
    }
    c->vcpus[0].vmpidr = c->params->vmpidr;
    c->vcpus[0].vncr_va = c->params->vncr_va;
    __asm__ volatile("msr tpidr_el2, %0; isb" :: "r"(&c->vcpus[0]) : "memory");
    c->skip_undef = c->params->skip_undef;
    vcpu_of(c)->out_ptr = out;
    c->cpus.registered = 1; /* The loader has already entered guest CPU0. */
    c->next_table = (work + sizeof(*c) + 0xfff) & ~0xfffUL;
    c->work_start = work;
    c->work_base = c->next_table;
#if SNAP_ROOT_CACHE_WIDE
    c->next_table += ROOT_EXT_PAGES * 4096;
#endif
#if SNAP_TXM_ASPACE_WIDE
    if (c->next_table != (uint64_t)TXM_REG(c)) return 1;
    c->next_table += TXM_EXT_PAGES * 4096;
#endif
#if SNAP_USER_HW_WALK
    /* The records follow root_ext and (SNAP_TXM_ASPACE_WIDE) the TXM registry,
     * whose fixed offset assumes it sits right after root_ext; also owner 0
     * (the pool's owner bytes start zero), stored without a note and so
     * never a coverage sentinel (txn_publish_exclude). */
    if (c->next_table + HW_WALK_PAGES * 4096 > work + size) return 1;
    c->hw_walk = (struct hw_walk_state *)c->next_table;
    for (uint64_t n = 0; n < HW_WALK_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->hw_walk)[n] = 0;
    /* The zeroing is done through a uint64_t view: no typed store below may
     * be moved above it (compat/user-hw-walk.h hw_walk_prune, v55). */
    __asm__ volatile("" ::: "memory");
    for (unsigned n = 0; n < HW_WALK_ROOTS; n++) c->hw_walk->roots[n].index = n;
    c->next_table += HW_WALK_PAGES * 4096;
#endif
    c->work_end = work + size;
    if(c->params->txm_native.image) {
        const struct txm_native_params *n=&c->params->txm_native;
        if(n->image!=0xb0600000 || n->size!=TXM_NATIVE_BYTES ||
           size<TXM_NATIVE_BYTES || n->work!=work+size-TXM_NATIVE_BYTES ||
           (n->work&0x3fff) || !n->tree_size || n->tree_size>0x100000)return 1;
        c->work_end=n->work; /* Private crypto scratch must never become a shadow table. */
    } else if(c->params->txm_native.work || c->params->txm_native.size || c->params->txm_native.tree_size)return 1;
#if SNAP_S2_FAULT_RETRY
    /* compat/s2-fault-retry.h: one page, owner 0 (the pool's owner bytes
     * start zero), zeroed through a uint64_t view and stored without a note
     * (txn_publish_exclude). */
    if (c->next_table + S2_RETRY_PAGES * 4096 > c->work_end) return 1;
    c->s2_retry = (struct s2_retry_state *)c->next_table;
    for (uint64_t n = 0; n < S2_RETRY_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->s2_retry)[n] = 0;
    __asm__ volatile("" ::: "memory");
    c->next_table += S2_RETRY_PAGES * 4096;
#endif
#if SNAP_GUEST_NET
    /* compat/guest-net-link.h: stored the same way (txn_publish_exclude). */
    if (c->next_table + GUEST_NET_STATE_PAGES * 4096 > c->work_end) return 1;
    c->guest_net = (struct guest_net_state *)c->next_table;
    for (uint64_t n = 0; n < GUEST_NET_STATE_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->guest_net)[n] = 0;
    __asm__ volatile("" ::: "memory");
    c->next_table += GUEST_NET_STATE_PAGES * 4096;
#endif
    if(c->params->early_stop.flags & EARLY_STOP_F_THERMAL) {
        if(c->next_table>c->work_end || c->work_end-c->next_table<4096)return 1;
        c->thermal=(struct a16_thermal_state *)c->next_table;
        for(unsigned n=0;n<4096/8;n++)((volatile uint64_t *)c->thermal)[n]=0;
        __asm__ volatile("" ::: "memory");
        c->next_table+=4096;
    }
    if(c->work_end<c->work_base || (c->work_end-c->work_base)/4096>TABLE_POOL_MAX)return 1;
    c->table_pool.head=TABLE_POOL_MAX;
    /* Every table page lies in [work_base, work_base+pages*4096). */
    c->table_memo.base=c->work_base;
    c->table_memo.pages=(c->work_end-c->work_base)/4096;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        UOWNERS(c)[i].context=c;UOWNERS(c)[i].owner=i+1;
    }
    return 0;
}

void xnuboot_save(uint64_t vbar, uint64_t hcr, uint64_t tpidr,
                  uint64_t sctlr, uint64_t tcr, uint64_t daif);
void xnuboot_save(uint64_t vbar, uint64_t hcr, uint64_t tpidr,
                  uint64_t sctlr, uint64_t tcr, uint64_t daif)
{
    struct context *c = context_of();
    vcpu_of(c)->save_vbar = vbar;
    vcpu_of(c)->save_hcr = hcr;
    vcpu_of(c)->save_tpidr = tpidr;
    vcpu_of(c)->save_sctlr = sctlr;
    vcpu_of(c)->save_tcr = tcr;
    vcpu_of(c)->save_daif = daif;
}

/* A guest that never comes back leaves EL2 blocked inside the proxy call, which
 * on this machine means a power cycle -- the exact failure that makes a boot
 * attempt expensive instead of cheap. So the guest runs on a clock: the EL2
 * physical timer is armed before the ERET and routed to EL2 with HCR_EL2.IMO,
 * which EL1's own PSTATE.I cannot mask. Whatever XNU is doing, control comes
 * back and says so.
 *
 * q1n1 drives its own 1 kHz tick from this timer, so its state is saved and put
 * back rather than assumed unused. */
static void timer_arm(struct context *c,uint64_t physical,uint64_t device_due);
void xnuboot_watchdog(uint64_t seconds);
void xnuboot_watchdog(uint64_t seconds)
{
    struct context *c = context_of();
    uint64_t freq, now;
    __asm__ volatile("mrs %0, cnthp_ctl_el2" : "=r"(vcpu_of(c)->save_cnthp_ctl));
    __asm__ volatile("mrs %0, cnthp_cval_el2" : "=r"(vcpu_of(c)->save_cnthp_cval));
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (!freq) freq = 24000000;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
    vcpu_of(c)->watchdog_deadline = now + freq * seconds;
    vcpu_of(c)->watchdog_live = 1;
    /* The first guest instruction may never trap. Apply the same host-stop,
     * thermal, pending-stop and peer-poll bounds used by every later tick. */
    timer_arm(c,now,UINT64_MAX);
}

static void watchdog_off(struct context *c)
{
    if (!vcpu_of(c)->watchdog_live) return;
    vcpu_of(c)->watchdog_live = 0;
    __asm__ volatile("msr cnthp_ctl_el2, xzr; isb");
    __asm__ volatile("msr cnthp_cval_el2, %0" :: "r"(vcpu_of(c)->save_cnthp_cval));
    __asm__ volatile("msr cnthp_ctl_el2, %0" :: "r"(vcpu_of(c)->save_cnthp_ctl));
    __asm__ volatile("isb");
}

/* The deadline this CPU's timer honours: the budget, or an accepted early
 * stop before it (compat/early-stop.h). Equal to the budget when idle. */
static uint64_t run_deadline(struct context *c)
{
    return early_stop_deadline(&c->early_stop, vcpu_of(c)->watchdog_deadline);
}

static uint64_t service_profile_clock(void)
{
    uint64_t now;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(now) :: "memory");
    return now;
}

static int runtime_enter(struct context *c, const uint64_t *frame, uint64_t elr,
                         unsigned category)
{
    struct vcpu *v = vcpu_of(c);
    struct service_profile *profile = &c->service_profile[v->slot];
    if (SNAP_STEP_ALU) step_alu_enter(&c->step_alu[v->slot], category);
    /* No translation survives a sysreg access, another fault, IRQ, or CPU
     * bootstrap. Cross-CPU shadow updates are detected by shadow_tlb_syncs.
     * Only consecutive ordinary step traps in one open EXEC page can hit. */
    if (category != 0x32) step_translation_clear(&c->step_translation[v->slot]);
    if (SNAP_SERVICE_PROFILE)
        service_profile_begin(profile, service_profile_clock(), category);
#if SNAP_FAIR_TOKEN
    /* compat/service-lock.h: the token in arrival order. */
    uint32_t ticket = guest_service_queue(&c->services);
    enum guest_service_result result = guest_service_try_turn(&c->services, v->slot, ticket);
#else
    enum guest_service_result result = guest_service_try(&c->services, v->slot);
#endif
    int contended = result == SERVICE_BUSY;
    if (result == SERVICE_BUSY) {
        uint64_t now;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
        uint64_t deadline = now + c->params->clock_host_hz; /* at most one second */
        do {
            __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
            if(guest_service_stopped(&c->services)) {result=SERVICE_STOPPED;break;}
            result=guest_service_wait_expiry(now,deadline,v->watchdog_live,v->watchdog_deadline);
            if(result!=SERVICE_BUSY) {
                if(result==SERVICE_STOPPED) {
                    guest_service_stop(&c->services,v->slot,SERVICE_STOP_NORMAL);
                    if(guest_service_stopped(&c->services)==(((uint64_t)SERVICE_STOP_NORMAL<<32)|(v->slot+1)))
                        c->service_budget_stops[v->slot]=1;
                }
                break;
            }
            __asm__ volatile("yield");
#if SNAP_FAIR_TOKEN
            result = guest_service_try_turn(&c->services, v->slot, ticket);
#else
            result = guest_service_try(&c->services, v->slot);
#endif
        } while (result == SERVICE_BUSY);
    }
#if SNAP_FINE_LOCKS
    /* The token excludes converted calls once their readers have left
     * (compat/fine-lock.h L0): none can enter while it is held, and each in
     * flight finishes one bounded critical section. Counted as wait. */
    if (result == SERVICE_OK && !guest_service_drained(&c->services)) {
        uint64_t now, deadline;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
        deadline = now + c->params->clock_host_hz;
#if SNAP_PHASE_FAIR_GATE
        uint64_t drain_from = now;
#endif
        contended = 1;
        while (!guest_service_drained(&c->services)) {
            __asm__ volatile("yield; mrs %0, cntpct_el0" : "=r"(now));
            if ((int64_t)(now - deadline) >= 0) {
                guest_service_release(&c->services, v->slot);
                result = SERVICE_TIMEOUT;
                break;
            }
        }
#if SNAP_PHASE_FAIR_GATE
        /* compat/token-costs.h gate[5], gate[6]: drains that waited (now also
         * for converted calls queued in the previous writer's phase). */
        if (result == SERVICE_OK) {
            fine_add(&c->root_ext->gate[5], 1);
            fine_add(&c->root_ext->gate[6], now - drain_from);
        }
#endif
    }
#endif
    if (SNAP_SERVICE_PROFILE)
        service_profile_wait_done(profile, service_profile_clock(), result == SERVICE_OK,
                                  contended);
    if (result == SERVICE_OK) { v->service_acquires++; return 1; }
    /* No shared log/device writes without ownership. The private snapshot and
     * dedicated report fields preserve failure even if the event ring is full. */
    v->service_fault = result == SERVICE_STOPPED ? 0 : result;
    fill_regs(&v->async_regs, frame, 0, elr, 0);
    v->async_captured = 1;
    if (result != SERVICE_STOPPED)
        guest_service_stop(&c->services, v->slot, SERVICE_STOP_FAULT);
    watchdog_off(c);
    return 0;
}

static int runtime_leave(struct context *c, int stop)
{
    struct vcpu *v = vcpu_of(c);
    stop|=!!(c->user_view_failed || c->root_install_failures || c->kernel_view_failed);
    if (stop) guest_service_stop(&c->services, v->slot, SERVICE_STOP_NORMAL);
#if SNAP_SERVICE_SUBCLASS
    int completed = c->service_profile[v->slot].stage == 2;
#endif
    /* End before release: never charge another CPU's ownership to this one.
     * Assembly entry/exit, release itself and this instrumentation are not a
     * separately measured guest-time bucket. */
    if (SNAP_SERVICE_PROFILE)
        service_profile_end(&c->service_profile[v->slot], service_profile_clock());
#if SNAP_SERVICE_SUBCLASS
    /* Still under the lock: the sub-class buckets are shared. */
#if SNAP_OTHER_PROFILE
    unsigned sub_tag = v->slot < SERVICE_SUB_CPUS ? c->exit_profile.sub.current[v->slot] : SERVICE_SUB_OTHER;
#endif
    service_sub_charge(&c->exit_profile.sub, (unsigned)v->slot, &c->service_profile[v->slot],
                       completed);
#if SNAP_OTHER_PROFILE
    other_profile_charge(&c->root_ext->other, (unsigned)v->slot, &c->service_profile[v->slot],
                         completed, sub_tag);
#endif
#endif
    enum guest_service_result result = guest_service_release(&c->services, v->slot);
    if (result != SERVICE_OK) {
        v->service_fault = result;
        guest_service_stop(&c->services, v->slot, SERVICE_STOP_FAULT);
    }
    return stop || result != SERVICE_OK || guest_service_stopped(&c->services) != 0;
}

/* The q1n1 adapter multiplexes the guest deadline and the fixed run budget on
 * its already enabled EL2 timer PPI (26). No Apple AIC or Qualcomm peripheral
 * registers are involved. A timer expiry drives a guest level FIQ; watchdog
 * expiry still exits even when XNU has all its own interrupts masked.
 * Physical SMP also uses a 1 ms service deadline for remote IPI delivery.
 * This wakes a sleeping/busy guest without depending on its next trap or
 * borrowing an unowned SGI; only guest SR W1C consumes the queued IPI. */
static uint64_t clock_counter(void *ctx);
/* This CPU's EL2 timer at the earliest of its guest timer, the device deadline
 * (guest ticks, UINT64_MAX for none), the run budget, the IPI poll and CPU0's
 * host-stop poll. timer_sync and the lock-free CNTV_TVAL write share it. */
static void timer_arm(struct context *c, uint64_t physical, uint64_t device_due)
{
    if (!vcpu_of(c)->watchdog_live) return;
    uint64_t end = run_deadline(c);
    uint64_t budget = (int64_t)(end - physical) > 0 ? end - physical : 0;
    uint64_t delay = budget;
    if (vcpu_of(c)->timer.ctl == 1 && !vcpu_of(c)->timer_pending)
        delay = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last,
                                vcpu_of(c)->timer.cval, budget);
    if (device_due != UINT64_MAX)
        delay = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last,
                                device_due, delay);
#if SNAP_ANS_ASYNC
    {   /* agents/nvme-async N3, N19: the SSD command this vCPU owns is polled at its deadline. */
        uint64_t ans_due;
        if (ans_async_due_of(c, vcpu_of(c)->slot, &ans_due)) {
            uint64_t d = (int64_t)(ans_due - physical) > 0 ? ans_due - physical : 0;
            if (d < delay) delay = d;
        }
    }
#endif
    if (c->host_cpus) delay=guest_ipi_poll_delay(vcpu_of(c)->clock_rate.host_hz,delay);
    /* CPU0 polls q1n1 for a host stop no less often than asked. */
    const struct early_stop_params *stop = &c->params->early_stop;
    if (!vcpu_of(c)->slot && (stop->flags & EARLY_STOP_F_HOST)) {
        uint64_t poll = c->params->clock_host_hz / 1000 * stop->host_poll_ms;
        if (poll && poll < delay) delay = poll;
    }
    if(!vcpu_of(c)->slot && c->thermal)
        delay=a16_thermal_wait(c->thermal,physical,c->params->clock_host_hz,delay);
    uint64_t next = physical + delay;
    __asm__ volatile("msr cnthp_cval_el2, %0" :: "r"(next));
    __asm__ volatile("msr cnthp_ctl_el2, %0; isb" :: "r"(1UL));
}
static void timer_sync(struct context *c)
{
    uint64_t now, physical;
    now = clock_counter(c);
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(physical));
    uint64_t device_ticks = UINT64_MAX;
    for (unsigned i=0; i<c->params->model_count; i++) {
        device_ticks = device_model_wait(&c->params->models[i], &c->model_state[i],
                                         now, device_ticks);
    }
    device_latch_resets(c->params->models,c->model_state,
                        c->params->model_count,c->device_reset_mask);
    vcpu_of(c)->timer_pending = guest_timer_pending(&vcpu_of(c)->timer, now);
    guest_interrupt_sync(c);
    uint64_t due = device_ticks == UINT64_MAX ? UINT64_MAX : now + device_ticks;
    struct fast_timer_due *d = &c->fast_timer_due[vcpu_of(c)->slot];
    d->guest = due;
    d->physical = due == UINT64_MAX ? UINT64_MAX : physical +
        clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last, due, UINT64_MAX);
    timer_arm(c, physical, due);
}

static int device_reset_stop(struct context *c, uint64_t elr, const uint64_t *frame)
{
    if (!(c->device_reset_mask[0] | c->device_reset_mask[1])) return 0;
    record(c, EV_DEVICE_RESET, elr, c->device_reset_mask[0], c->device_reset_mask[1], 0);
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
    vcpu_of(c)->async_captured = 1;
    watchdog_off(c);
    return 1;
}
#if SNAP_ANS_ASYNC
/* The locked tick's ANS poll (token held; agents/nvme-async N3, N18): the owner
 * at its deadline, anyone once the command is ANS_ASYNC_BACKSTOP_US late. A
 * refusal found here stops the run as the doorbell's would (EV_ANS, kind 0xa5:
 * the tick). 1: stop. */
static int ans_async_tick(struct context *c, uint64_t elr, const uint64_t *frame)
{
    struct ans_state *s = c->root_ext->ans;
    if (!s || !ans_async_busy(s, 0)) return 0;
    struct ans_async *a = &s->async;
    uint64_t now = service_profile_clock(), due = __atomic_load_n(&a->due, __ATOMIC_RELAXED);
    int mine = __atomic_load_n(&a->owner, __ATOMIC_RELAXED) == (uint64_t)vcpu_of(c)->slot + 1 && due &&
               (int64_t)(now - due) >= 0;
    int late = due && (int64_t)(now - due - ans_async_us(c, ANS_ASYNC_BACKSTOP_US)) >= 0;
    if (!mine && !late) return 0;
    __atomic_fetch_add(&a->sched[mine ? 0 : 1], 1, __ATOMIC_RELAXED);
    struct ans_ops o = ans_ops_of(c);
    int r = ans_async_progress(s, &o, ANS_ASYNC_STEP_MAX);
    if (!r) {
        ans_async_schedule(c);
        if (ans_async_lines(c) == DEVICE_OK) return 0;
        r = ANS_E_STATE;
    }
    record(c, EV_ANS, elr, (uint64_t)r << 32 | 0xa5, s->refusal[1], s->refusal[2]);
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
    vcpu_of(c)->async_captured = 3;
    watchdog_off(c);
    return 1;
}
#endif

static void timer_eoi(uint64_t intid)
{
    uint64_t ctl;
    __asm__ volatile("mrs %0, icc_ctlr_el1" : "=r"(ctl));
    __asm__ volatile("dsb sy; msr icc_eoir1_el1, %0; isb" :: "r"(intid) : "memory");
    if (ctl & 2) /* EOImode: priority drop and deactivation are separate. */
        __asm__ volatile("msr icc_dir_el1, %0; isb" :: "r"(intid));
}

/* Stage 4: the Adreno through compat/adreno.h. EL2 reaches the GPU registers,
 * the GIC distributor and the q1n1 GPU arena through q1n1's identity map; the
 * guest reaches none of the arena and only the passthrough register windows. */
static uint32_t gpu_rd(uint64_t pa) {return *(volatile uint32_t *)pa;}
static void gpu_wr(uint64_t pa,uint32_t v) {*(volatile uint32_t *)pa=v;}
static int gpu_smc(void *ctx,uint64_t *r)
{
    (void)ctx;
    register uint64_t x0 __asm__("x0")=r[0],x1 __asm__("x1")=r[1],x2 __asm__("x2")=r[2],
        x3 __asm__("x3")=r[3],x4 __asm__("x4")=r[4],x5 __asm__("x5")=r[5],
        x6 __asm__("x6")=r[6],x7 __asm__("x7")=r[7];
    __asm__ volatile("smc #0" : "+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),
                     "+r"(x6),"+r"(x7) :: "x8","x9","x10","x11","x12","x13","x14",
                     "x15","x16","x17","memory");
    r[0]=x0;r[1]=x1;r[2]=x2;r[3]=x3;r[4]=x4;r[5]=x5;r[6]=x6;r[7]=x7;
    return 0;
}
static struct adreno_ops gpu_ops(struct context *c)
{
    /* adreno.c reaches registers, DRAM, caches and the counter itself here. */
    return (struct adreno_ops){.ctx=c,.smc=gpu_smc,.hz=c->params->clock_host_hz};
}
static int aic_model(const struct context *c)
{
    for (unsigned i=0;i<c->params->model_count;i++)
        if (c->params->models[i].kind==DEVICE_AIC3_FLAT_V1) return (int)i;
    return -1;
}
static void fwd_disable(void *ctx,uint32_t intid)
{
    uint64_t g=((struct context *)ctx)->params->gpu.gicd;
    gpu_wr(g+GICD_ICENABLER+4*(intid/32),1u<<(intid%32));
    for (unsigned n=0;n<100000 && (gpu_rd(g+GICD_CTLR)&(1u<<31));n++) {}
}
static void fwd_enable(void *ctx,uint32_t intid)
{
    gpu_wr(((struct context *)ctx)->params->gpu.gicd+GICD_ISENABLER+4*(intid/32),1u<<(intid%32));
}
static int fwd_pending(void *ctx,uint32_t intid)
{
    return !!(gpu_rd(((struct context *)ctx)->params->gpu.gicd+GICD_ISPENDR+4*(intid/32))&
              (1u<<(intid%32)));
}
static void fwd_complete(void *ctx,uint32_t intid) {(void)ctx;timer_eoi(intid);}
static int fwd_level(void *ctx,uint32_t irq,int level)
{
    struct context *c=ctx;
    int a=aic_model(c);
    return a<0 || device_irq_set_level(&c->params->models[a],&c->model_state[a],irq,level)!=DEVICE_OK;
}
static struct irqfwd_ops fwd_ops(struct context *c)
{
    return (struct irqfwd_ops){c,fwd_disable,fwd_enable,fwd_pending,fwd_complete,fwd_level};
}
static void gpu_serror_check(struct context *c)
{
    uint64_t isr;
    __asm__ volatile("mrs %0, isr_el1" : "=r"(isr));
    if (isr&(1u<<8)) c->gpu.serrors++;
}
static void gpu_fault_record(struct context *c,uint64_t pc)
{
    const struct adreno_state *s=&c->gpu;
    record(c,EV_GPU_SMMU,pc,s->fault_fsynr0<<32|s->fault_fsr,s->fault_far,
           s->fault_gfsr<<32|s->fault_cbfrsynra);
}
/* EL2 IRQ for INTID 0x14C: mask, complete, raise AIC 975 (compat/irq-forward.c). */
static void gpu_irq(struct context *c)
{
    uint64_t intid;
    __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy" : "=r"(intid) :: "memory");
    struct irqfwd_ops f=fwd_ops(c);
    if (irqfwd_physical(&c->gpu.irq,&f,(uint32_t)intid)==IRQFWD_NOT_OURS && intid<1020)
        timer_eoi(intid);   /* a level source that is not ours re-asserts on its own */
    vcpu_of(c)->model_irq_pending=0;
    for (unsigned i=0;i<c->params->model_count;i++)
        vcpu_of(c)->model_irq_pending|=device_irq_pending(&c->params->models[i],&c->model_state[i]);
    guest_interrupt_sync(c);
}
#if SNAP_ADRENO_RECOVER
/* After a call that may have run adreno_recover: its EV_GPU_RECOVER, and the fault it recorded and cleared. */
static void gpu_recover_record(struct context *c,uint64_t pc,uint64_t attempts,uint64_t faults)
{
    const struct adreno_recover_state *rs=GPU_RECOVER(c);
    if (rs->attempts!=attempts)
        record(c,EV_GPU_RECOVER,pc,rs->last_cause<<56|(rs->dead&0xffff)<<32|(uint32_t)rs->epoch,
               rs->snap[0]<<32|(uint32_t)rs->snap[1],rs->snap[2]<<32|(uint32_t)rs->last_ticks);
    if (c->gpu.faults!=faults) gpu_fault_record(c,pc);
    IB_FLIGHT(c)->reserved[2]=rs->epoch;
}
/* ADRENO_GUEST_RECOVER (compat/adreno-guest.h): QUERY and SETTLE, under the token like the rest of the GPU state. */
static void gpu_recover_hvc(struct context *c,uint64_t *frame,uint64_t elr)
{
    uint64_t r[4]={frame[0],frame[1],frame[2],frame[3]};
    struct adreno_ops o=gpu_ops(c);
    const uint64_t attempts=GPU_RECOVER(c)->attempts,faults=c->gpu.faults;
    adreno_guest_recover(&o,&c->params->gpu,&c->gpu,IB_FLIGHT(c),GPU_RECOVER(c),r);
    gpu_recover_record(c,elr,attempts,faults);
    for (unsigned n=0;n<4;n++) frame[n]=r[n];
}
#endif
/* vCPU 0's timer tick: once a second after ring_at, poll CB0 for faults and
 * make the in-run test fence (and the one-shot GIC self-test of the IRQ path
 * while the guest still holds AIC 975 masked). */
static void gpu_tick(struct context *c,uint64_t pc)
{
    const struct params *p=c->params;
    struct adreno_state *s=&c->gpu;
    uint64_t now=service_profile_clock();
    if (!(s->status&ADRENO_S_ADOPTED) || (s->status&ADRENO_S_QUIESCED) || now<s->run_at) return;
    s->run_at=now+p->clock_host_hz;
    struct adreno_ops o=gpu_ops(c);
#if SNAP_ADRENO_IB_ASYNC
    /* No fault poll (it clears FSR before the IB's own POLL sees it) and no run fence while an IB is in flight
     * (A2, A7). A flight nobody polled for its budget + grace ends here, recorded as its POLL would have (A3). */
    struct adreno_ib_flight *f=IB_FLIGHT(c);
    uint64_t ib_va=f->va,ib_dwords=f->dwords;
    int final,idle=adreno_ib_flight_tick(&o,&p->gpu,s,f,ADRENO_IB_FLIGHT_GRACE_SECONDS*p->clock_host_hz,&final);
#if SNAP_ADRENO_RECOVER
    if (final!=ADRENO_IB_PENDING) {   /* agents/gpu-recovery R20: an abandoned flight is recovered here */
        const uint64_t attempts=GPU_RECOVER(c)->attempts,faults=s->faults;
        final=adreno_recover_final(&o,&p->gpu,s,f,GPU_RECOVER(c),final,1,0);
        gpu_recover_record(c,pc,attempts,faults);
    }
#endif
    if (final!=ADRENO_IB_PENDING) record(c,EV_GPU_IB,pc,ib_va,ib_dwords<<32|(uint32_t)final,f->last_ticks);
    if (!idle) {gpu_serror_check(c);return;}
#endif
    if (adreno_fault_poll(&o,s)) gpu_fault_record(c,pc);
    if ((p->gpu.flags&ADRENO_F_RING) && !(s->status&ADRENO_S_RUN_FENCE)) {
        s->status|=ADRENO_S_RUN_FENCE;
        int e=adreno_fence(&o,&p->gpu,s,0x534e0002u);
        record(c,EV_GPU_RING,pc,0x534e0002u,(uint64_t)(int64_t)e,s->fence_ticks);
        int a=aic_model(c);
        if ((p->gpu.flags&ADRENO_F_SELF_IRQ) && a>=0 &&
            !(c->model_state[a].aic.unmasked[ADRENO_AIC_IRQ/32]&(1u<<(ADRENO_AIC_IRQ%32)))) {
            gpu_wr(p->gpu.gicd+GICD_ISPENDR+4*(ADRENO_INTID/32),1u<<(ADRENO_INTID%32));
            s->self_irq++;
        }
    }
    gpu_serror_check(c);
}
#if SNAP_ADRENO_IB_ASYNC
/* ADRENO_GUEST_IB_POLL (compat/adreno-guest.h): one completion pass of the IB in flight, from any vCPU (A4). No
 * DART access, so no DART model admission. One EV_GPU_IB per IB (A18): the POLL that ends the flight records it
 * with ADRENO_GUEST_IB's fields; PENDING and IDLE are counted in the flight, not logged. */
static void gpu_ib_poll_hvc(struct context *c, uint64_t *frame, uint64_t elr)
{
    uint64_t r[4] = {frame[0], frame[1], frame[2], frame[3]};
    struct adreno_ops o = gpu_ops(c);
    struct adreno_ib_flight *f = IB_FLIGHT(c);
    uint64_t va = f->va, dwords = f->dwords, active = f->active;
    int e = adreno_guest_ib_poll(&o, &c->params->gpu, &c->gpu, f, r);
#if SNAP_ADRENO_RECOVER
    if (active && !f->active) {          /* agents/gpu-recovery: UNCERTAIN/GPU_ERROR may become a reset (RESET) */
        const uint64_t attempts = GPU_RECOVER(c)->attempts, faults = c->gpu.faults;
        e = adreno_recover_final(&o, &c->params->gpu, &c->gpu, f, GPU_RECOVER(c), e, 1, r);
        gpu_recover_record(c, elr, attempts, faults);
    }
#endif
    if (active && !f->active) record(c, EV_GPU_IB, elr, va, dwords << 32 | (uint32_t)e, r[2]);
    for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
}
#endif
static int64_t gpu_prepare(struct context *c)
{
    const struct params *p=c->params;
    if (!p->gpu.flags) return 0;
    struct adreno_params g=p->gpu;
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    g.affinity=(mpidr&0xffffff)|((mpidr>>32)&0xff)<<32;  /* this CPU runs vCPU 0 */
#if SNAP_BOOT_RELOCATE
    const struct boot_relocation *relocated=boot_relocation_of(c);
    if (relocated) g.affinity=relocated->record.affinity;  /* unless it is relocated */
#endif
    /* The loader proved the arena clear of the panel and the work area
     * (probes/adreno.py); adreno_adopt proves it clear of guest memory. */
    int a=aic_model(c);
    if (a<0 || p->models[a].config[0]<=ADRENO_AIC_IRQ)
        return c->gpu.prepare=(uint64_t)(int64_t)ADRENO_E_PARAMS,ADRENO_E_PARAMS;
    struct adreno_ops o=gpu_ops(c);
    int e=adreno_adopt(&o,&g,&c->gpu,p->mem_low,p->mem_high);
    if (!e && irqfwd_add(&c->gpu.irq,ADRENO_INTID,ADRENO_AIC_IRQ)!=IRQFWD_OK) e=ADRENO_E_PARAMS;
    if (e) return e;
    e=adreno_gic_route(&o,&g,&c->gpu);
    if (e) return c->gpu.prepare=(uint64_t)(int64_t)e,e;
    fwd_enable(c,ADRENO_INTID);
    if (g.flags&ADRENO_F_RING) {
        e=adreno_fence(&o,&g,&c->gpu,0x534e0001u);
        record(c,EV_GPU_RING,0,0x534e0001u,(uint64_t)(int64_t)e,c->gpu.fence_ticks);
    }
    c->gpu.run_at=service_profile_clock()+g.ring_at_seconds*p->clock_host_hz;
#if SNAP_ADRENO_RECOVER
    if (c->root_ext) adreno_recover_init(&o,&g,&c->gpu,GPU_RECOVER(c));   /* agents/gpu-recovery R8 */
#endif
    gpu_serror_check(c);
    return e;
}
/* Before the guest's memory is handed back: the line, then the GPU (adreno.h). */
static int gpu_quiesce(struct context *c)
{
    if (!(c->gpu.status&ADRENO_S_ADOPTED)) return 1;
    struct irqfwd_ops f=fwd_ops(c);
    struct adreno_ops o=gpu_ops(c);
    irqfwd_quiesce(&c->gpu.irq,&f);
    adreno_gic_restore(&o,&c->params->gpu,&c->gpu);
    uint64_t faults=c->gpu.faults;
    adreno_quiesce(&o,&c->params->gpu,&c->gpu);
    if (c->gpu.faults!=faults) gpu_fault_record(c,0);
    gpu_serror_check(c);
    if (c->gpu.serrors) c->gpu.status &= ~ADRENO_S_QUIESCED;
    return !!(c->gpu.status & ADRENO_S_QUIESCED);
}
struct gpu_leaf_ctx { const struct sptm_memory *memory; struct dart_state *dart; };
static uint64_t gpu_leaf(void *ctx,uint64_t iova)
{
    struct gpu_leaf_ctx *l=ctx;
    return sptm_dart_leaf(l->memory,l->dart,SPTM_DART_ADRENO,0,iova);
}
#if SNAP_DART_WIREDCNT
_Static_assert(sizeof(((struct context *)0)->dart_wiredcnt) == DWC_WORDS * 8 &&
               sizeof(((struct context *)0)->dart_wiredcnt_pins) == DWC_PIN_WORDS * 8,
               "DWC state words");
static uint64_t dwc_kva(void *ctx, uint64_t va) {(void)ctx; return guest_pa(va);}
static uint64_t dwc_read(void *ctx, uint64_t pa, unsigned size)
{
    (void)ctx;
    return size == 8 ? *(volatile uint64_t *)pa : size == 4 ? *(volatile uint32_t *)pa :
           *(volatile uint16_t *)pa;
}
static int dwc_cas16(void *ctx, uint64_t pa, uint16_t expected, uint16_t desired)
{
    (void)ctx;
    return __atomic_compare_exchange_n((uint16_t *)pa, &expected, desired, 0,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
/* The level-2 (leaf) table the Adreno DART's level-1 root names for iova. */
static uint64_t dwc_table(void *ctx, uint64_t iova)
{
    struct gpu_leaf_ctx *l=ctx;
    uint32_t ttbr=l->dart->ttbr[0];
    if (!(ttbr&1)) return 0;
    volatile uint8_t *root=l->memory->map(l->memory->ctx,(uint64_t)(ttbr&0x3ffffffcU)<<12,0x4000);
    if (!root) return 0;
    uint64_t v=*(volatile uint64_t *)(root+8*((iova>>25)&2047));
    return (v&1) ? (v&0x3ffffffc00UL)<<4 : 0;
}
static int dwc_sptm_unmap(void *ctx, uint64_t iova, uint64_t size)
{
    struct gpu_leaf_ctx *l=ctx;
    return sptm_dart_unmap(l->memory,l->dart,SPTM_DART_ADRENO,0,iova,size,2);
}
#endif
static int gpu_unmap(void *ctx,uint64_t iova,uint64_t size)
{
    struct gpu_leaf_ctx *l=ctx;
#if SNAP_DART_WIREDCNT
    /* The same clear, plus XNU's own count of the leaves it removes. */
    struct context *c=context_of();
    const struct params *p=c->params;
    const struct dwc_ops o={l,p->mem_low,p->mem_high,
        (const volatile uint32_t *)(uintptr_t)p->const_begin,p->const_begin,
        p->const_end>p->const_begin ? (p->const_end-p->const_begin)/4 : 0,
        p->vbar_va-p->vbar,SPTM_DART_ADRENO,
        dwc_kva,dwc_read,dwc_cas16,dwc_table,gpu_leaf,dwc_sptm_unmap};
    return dwc_unmap(&o,c->dart_wiredcnt,c->dart_wiredcnt_pins,iova,size);
#else
    /* Permit holes when rolling back a partially inserted resource. This is
     * native table-3 endpoint3/option2, with its ownership/reference checks. */
    return sptm_dart_unmap(l->memory,l->dart,SPTM_DART_ADRENO,0,iova,size,2);
#endif
}

#if SNAP_BOOT_RELOCATE
/* vCPU 0 relocated (compat/boot-relocate.h): post the call to q1n1's CPU, the
 * only one that may run the call service, and wait at most a second. POLL's
 * latch travels through the relay's own buffer: a caller that gave up never
 * has a late answer written into its stack. */
static uint64_t boot_relay_call(struct context *c, struct boot_relocation *r, uint64_t op,
                                uint64_t a1, uint64_t a2, uint64_t a3)
{
    struct boot_relay *q = &r->relay;
    int latch = op == EARLY_STOP_HOST_POLL;
    if ((latch && (!a1 || (a2 & 7) || a2 > sizeof q->buffer)) || !boot_relay_idle(q)) {
        q->refused++;
        return BOOT_RELAY_FAILED;
    }
    volatile uint64_t *buffer = q->buffer, *caller = (volatile uint64_t *)(uintptr_t)a1;
    if (latch) for (uint64_t n = 0; n < a2 / 8; n++) buffer[n] = caller[n];
    uint64_t ticket, result, start, now;
    if (!boot_relay_post(q, op, latch ? (uintptr_t)q->buffer : a1, a2, a3, &ticket)) {
        q->refused++;
        return BOOT_RELAY_FAILED;
    }
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(start));
    while (!boot_relay_answered(q, ticket, &result)) {
        __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(now));
        if (now - start >= c->params->clock_host_hz) {
            __atomic_store_n(&q->abandoned, 1, __ATOMIC_RELEASE);
            return BOOT_RELAY_FAILED;
        }
        __asm__ volatile("yield" ::: "memory");
    }
    if (latch) for (uint64_t n = 0; n < a2 / 8; n++) caller[n] = buffer[n];
    return result;
}
#endif
#if SNAP_GUEST_NET
static struct guest_net_ops guest_net_ops_of(struct context *c);
#endif
/* Host abort (compat/early-stop.h). CPU0 is the CPU inside q1n1's P_CALL; it
 * alone calls q1n1's call service, which runs on this stack at EL2 in q1n1's
 * identity map. host_in_call keeps the report from re-entering q1n1 when a
 * fault inside it is what ended the run. */
static uint64_t early_stop_host_call(struct context *c, uint64_t op, uint64_t a1, uint64_t a2,
                                     uint64_t a3)
{
    struct early_stop_state *s = &c->early_stop;
    uint64_t (*call)(uint64_t, uint64_t, uint64_t, uint64_t) =
        (uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)c->params->early_stop.host_call;
    s->host_in_call = 1;
#if SNAP_BOOT_RELOCATE
    struct boot_relocation *relocated = boot_relocation_of(c);
    uint64_t result = relocated && !boot_relocation_on_boot_cpu(c) ?
        boot_relay_call(c, relocated, op, a1, a2, a3) : call(op, a1, a2, a3);
#else
    uint64_t result = call(op, a1, a2, a3);
#endif
    s->host_in_call = 0;
    s->host_status = result;
    return result;
}

/* At most one poll per host_poll_ms. 1 when a host stop was accepted: the
 * caller rearms the timer so its deadline (normally now) is taken at once. */
static int early_stop_host_tick(struct context *c, uint64_t physical)
{
    const struct early_stop_params *p = &c->params->early_stop;
    struct early_stop_state *s = &c->early_stop;
    if (vcpu_of(c)->slot || !early_stop_host_due(s, p, physical, c->params->clock_host_hz))
        return 0;
    if (!s->host_armed) {
        if (early_stop_host_call(c, EARLY_STOP_HOST_ARM, p->session, 0, 0)) {
            s->host_errors++;
            return 0;
        }
        s->host_armed = 1;
    }
    /* The console rides on this poll (compat/console-link.h): q1n1 serves the
     * Mac from the view while it runs, and staged input moves into the UART's
     * receive ring after it. Every poll is timed, console or not. */
    struct console_link *link = &c->console_link;
    int console = !!(p->flags & EARLY_STOP_F_CONSOLE);
    if (console) console_link_prepare(link, c->console_tail, CONSOLE_TAIL_MAX, c->console_tail_bytes);
    struct early_stop_host_request r = {0};
    uint64_t before, after;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(before));
#if SNAP_GUEST_NET
    /* The guest network rides on the same poll (compat/guest-net-link.h):
     * POLL2 carries the console view and the net view together. An older
     * q1n1 answers Q1N1_CALL_E_OP once; from then on this run polls as before
     * and the ring is never offered (poll2_unsupported). */
    struct guest_net_state *net = c->guest_net;
    int net_on = (p->flags & EARLY_STOP_F_NET) && !net->link.poll2_unsupported;
    int net_view = 0;
    uint64_t latched;
    if (net_on) {
        const struct guest_net_ops o = guest_net_ops_of(c);
        net_view = guest_net_prepare(&net->link, &o, &net->view);
        net->views = (struct guest_net_poll_views){GUEST_NET_VIEWS_MAGIC, GUEST_NET_VIEWS_VERSION,
            console ? (uintptr_t)&link->view : 0, net_view ? (uintptr_t)&net->view : 0};
        latched = early_stop_host_call(c, GUEST_NET_POLL2, (uintptr_t)&r, sizeof r, (uintptr_t)&net->views);
        if (latched == GUEST_NET_CALL_E_OP) {
            net->link.poll2_unsupported = 1;
            net_view = 0;
            latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,
                                           console ? (uintptr_t)&link->view : 0);
        }
        if (net_view) guest_net_commit(&net->link, &o, &net->view);
    } else
        latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,
                                       console ? (uintptr_t)&link->view : 0);
#else
    uint64_t latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,
                                            console ? (uintptr_t)&link->view : 0);
#endif
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(after));
    console_link_account(link, after - before);
    if (console) console_link_drain(link);
    if (latched != 1) {
        if (latched) s->host_errors++;
        return 0;
    }
    uint64_t accepted = 0;
    int e = early_stop_host_admit(p, &r, &accepted);
    if (!e) e = early_stop_request(s, EARLY_STOP_SOURCE_HOST, r.reason, r.nonce, r.delay_s,
                                   accepted, physical, c->params->clock_host_hz, 0, 0, r.text);
    else early_stop_refuse(s, e);
    record(c, EV_EARLY_STOP_REQUEST, 0, (uint64_t)EARLY_STOP_SOURCE_HOST << 32 | (uint32_t)r.reason,
           r.delay_s << 32 | (uint32_t)r.nonce, (uint64_t)(int64_t)e);
    return e == EARLY_STOP_ACCEPTED;
}

/* Read only the surveyed A16 TSENS registers. A synchronous bus abort takes
 * the monitor's fault path; read_inflight/location retain the attempted read.
 * No software policy can recover an interconnect that never returns. */
static int thermal_read(void *ctx,uint64_t address,uint32_t *value)
{
    (void)ctx;
    if(!a16_thermal_address_allowed(address))return -1;
    *value=*(const volatile uint32_t *)address;
    __asm__ volatile("dsb sy" ::: "memory");return 0;
}
static uint64_t thermal_clock(void *ctx) {(void)ctx;return service_profile_clock();}
static int thermal_tick(struct context *c,uint64_t physical)
{
    if(vcpu_of(c)->slot || !c->thermal)return 0;
    const struct a16_thermal_io io={c,thermal_read,thermal_clock};
    uint64_t previous=c->thermal->reason;
    int stop=a16_thermal_poll(c->thermal,&c->early_stop,physical,c->params->clock_host_hz,&io);
    if(stop && !previous)
        record(c,EV_EARLY_STOP_REQUEST,0,(uint64_t)EARLY_STOP_SOURCE_THERMAL<<32|c->thermal->reason,
               c->thermal->location,0);
    return stop;
}
/* Preparation checkpoints: one complete sample, resampling a brief VALID clear
 * (compat/a16-thermal.c a16_thermal_admit). Nonzero refuses entry. */
static int thermal_admit(struct context *c)
{
    if(vcpu_of(c)->slot || !c->thermal)return -1;
    const struct a16_thermal_io io={c,thermal_read,thermal_clock};
    uint64_t previous=c->thermal->reason;
    int admit=a16_thermal_admit(c->thermal,&c->early_stop,c->params->clock_host_hz,&io);
    if(admit>0 && !previous)
        record(c,EV_EARLY_STOP_REQUEST,0,(uint64_t)EARLY_STOP_SOURCE_THERMAL<<32|c->thermal->reason,
               c->thermal->location,0);
    return admit;
}
/* Preparation sampling between and inside the long setup steps (docs/
 * A16-THERMAL-GUARD-20261018.md, finer checkpoints). A trip is immutable, so
 * the next thermal_admit refuses with -28. Runtime allocation keeps table_alloc. */
static void thermal_prepare_tick(struct context *c)
{
    if(c->thermal)(void)thermal_tick(c,service_profile_clock());
}
static uint64_t prepare_table_alloc(void *ctx)
{
    thermal_prepare_tick(ctx);
    return table_alloc(ctx);
}

#include "../compat/dvfs-glue.h"

#if SNAP_WFI_RESUME
static uint64_t wfi_resume_pa(void *ctx, uint64_t va) {(void)ctx; return guest_pa(va);}
static uint32_t wfi_resume_fetch(void *ctx, uint64_t pa) {(void)ctx; return *(const volatile uint32_t *)pa;}
_Static_assert(sizeof(((struct fast_trap_cpu *)0)->wfi) == WFI_RESULTS * sizeof(uint32_t),
               "one perf.fast[cpu].wfi counter per wfi_resume_result");
/* The EL2 timer tick's last step, under the service lock after timer_sync, the
 * EOI, the GPU tick, the host-stop poll and the device-reset check: rewind the
 * saved ELR_EL2 (frame[32], xnuboot.S async_lower/resume_lower) from WFI+4 to
 * the WFI when compat/wfi-resume.h says nothing is due. An IPI another CPU
 * posts after the release is picked up by the next tick, which timer_arm has
 * armed no later than the 1 ms poll, as for a vCPU that never woke.
 * SNAP_FAST_TIMER_IRQ's lock-free tick (fast_timer_irq) makes the same call
 * after the same steps: WFI_SHARED then reads the words other CPUs write under
 * the token atomically. The models' lines stay plain reads there: a line
 * another CPU changes during the scan can only make the decision resume once
 * more (the guest sleeps at most one more poll, as for a line raised after the
 * locked tick's release) or decline once more (XNU runs its idle exit). */
static void wfi_resume(struct context *c, uint64_t elr, uint64_t *frame, int stop)
{
    struct vcpu *v = vcpu_of(c);
    const struct params *p = c->params;
    uint64_t models = 0;
    for (unsigned i = 0; i < p->model_count; i++)
        models |= (uint64_t)device_irq_pending(&p->models[i], &c->model_state[i]);
    struct wfi_resume_state s = {
        .elr = elr,
        .stop = (uint64_t)(stop || guest_service_stopped(&c->services) != 0 ||
                           WFI_SHARED(c->user_view_failed) || WFI_SHARED(c->root_install_failures) ||
                           WFI_SHARED(c->kernel_view_failed)),
        .monitor = (uint64_t)(v->stepping.active || v->open_guards || c->user_execution[v->slot].pending),
        .last_return = v->last_kernel_return,
        .ipi_pending = WFI_SHARED(v->ipi.pending), .timer_pending = v->timer_pending,
        .timer_ctl = v->timer.ctl, .timer_cval = v->timer.cval, .guest_now = v->clock_guest_last,
        .model_irq_pending = v->model_irq_pending, .models_pending = models,
        .device_due = c->fast_timer_due[v->slot].physical,
        .wake_bound = v->watchdog_live ? guest_ipi_poll_delay(v->clock_rate.host_hz, UINT64_MAX) : 0,
    };
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, hcr_el2; mrs %2, cnthp_ctl_el2; mrs %3, cnthp_cval_el2"
                     : "=r"(s.spsr), "=r"(s.hcr), "=r"(s.el2_ctl), "=r"(s.el2_cval));
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(s.physical) :: "memory");
    const struct wfi_resume_mem m = {c, p->mem_low, p->mem_high, p->const_begin, p->const_end,
                                     wfi_resume_pa, wfi_resume_fetch};
    unsigned r = wfi_resume_decide(&s, &m);
    c->perf.fast[v->slot].wfi[r]++;
    if (r == WFI_RESUME) frame[32] = elr - 4;
}
#endif

/* Something asynchronous arrived while the guest was running. Either way the
 * guest is not coming back on its own, and what it was doing is the whole point
 * of catching it -- so EL1's fault state comes back with it. A guest spinning in
 * its own exception vectors leaves the reason in ESR_EL1.
 *
 * Three different findings used to share one name. IRQ, FIQ and SError all
 * landed here and all recorded EV_WATCHDOG, so "the guest was still running
 * when its time ran out" was printed for a bus error -- the guest touching a
 * Qualcomm peripheral that does not answer -- which is the opposite reading: a
 * kernel that needed longer against a kernel that touched something that is not
 * there. `which` comes from the vector, because IRQ and FIQ do not write
 * ESR_EL2 and reading it after one of them yields an earlier trap's syndrome.
 *
 * The timer is the only interrupt this probe routes to EL2, so an IRQ with
 * ISTATUS clear is a fact about the machine that was not known, and it is
 * recorded as that rather than folded into the watchdog. */
static int xnuboot_async_locked(uint64_t elr, uint64_t which, const uint64_t *frame)
{
    struct context *c = context_of();
    uint64_t esr, far, el1, ctl, physical;
    __asm__ volatile("mrs %0, esr_el1" : "=r"(esr));
    __asm__ volatile("mrs %0, far_el1" : "=r"(far));
    __asm__ volatile("mrs %0, elr_el1" : "=r"(el1));
    /* Read before watchdog_off(), which clears the enable bit and with it
     * ISTATUS -- the only evidence that the timer is what brought us here. */
    __asm__ volatile("mrs %0, cnthp_ctl_el2" : "=r"(ctl));
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(physical));
    if (which == ASYNC_IRQ && (c->params->gpu.flags & ADRENO_F_ENABLE)) {
        uint64_t pending;
        __asm__ volatile("mrs %0, icc_hppir1_el1" : "=r"(pending));
        if (pending == ADRENO_INTID) {
            gpu_irq(c);
            return device_reset_stop(c, elr, frame);
        }
    }
    if (which == ASYNC_IRQ && (ctl & CNTHP_ISTATUS) &&
        (int64_t)(run_deadline(c) - physical) > 0) {
        uint64_t pending;
        __asm__ volatile("mrs %0, icc_hppir1_el1" : "=r"(pending));
        if (pending == 26) {
            uint64_t intid;
            __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy" : "=r"(intid) :: "memory");
            if (intid == 26) {
                vcpu_of(c)->timer_irqs++;
                vcpu_of(c)->timer_irq_pc = elr;
#if SNAP_FAST_TIMER_IRQ_CPU0
                /* vCPU 0's quiet ticks count from here (fast_cpu0_quiet). */
                if (!vcpu_of(c)->slot) c->root_ext->cpu0_tick.locked = physical;
#endif
#if SNAP_ANS_ASYNC
                /* Before timer_sync, so the re-arm sees the next deadline (N19). */
                int ans_stop = ans_async_tick(c, elr, frame);
#endif
                timer_sync(c); /* rearm/deassert physical level before EOI */
                timer_eoi(intid);
#if SNAP_ANS_ASYNC
                if (ans_stop) return 1;
#endif
                int thermal_stop=thermal_tick(c,physical);
                if (!thermal_stop && !vcpu_of(c)->slot && c->params->gpu.flags) gpu_tick(c, elr);
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
                if (!thermal_stop) dvfs_tick(c,physical);
#endif
                int host_stop=thermal_stop ? 0 : early_stop_host_tick(c,physical);
                /* Thermal trip exits this handler immediately, before any new
                 * GPU/host service. runtime_leave publishes the service stop. */
                if(thermal_stop) {
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
                    dvfs_cpu_restore(c);   /* C5: the CPU's at once; the GPU's at the stop, before quiesce */
#endif
                    uint64_t now=service_profile_clock();
                    if(early_stop_fire(&c->early_stop,now,vcpu_of(c)->watchdog_deadline,(unsigned)vcpu_of(c)->slot))
                        record(c,EV_EARLY_STOP,elr,c->early_stop.source<<32|(uint32_t)c->early_stop.reason,
                               c->early_stop.detail,c->early_stop.accepted_delay);
                    fill_regs(&vcpu_of(c)->async_regs,frame,0,elr,0);
                    vcpu_of(c)->async_captured=1;watchdog_off(c);return 1;
                }
                if(host_stop)timer_sync(c);
                int stop=device_reset_stop(c,elr,frame);
#if SNAP_WFI_RESUME
                wfi_resume(c,elr,(uint64_t *)frame,stop || host_stop);
#endif
                return stop;
            }
            if (intid < 1020) timer_eoi(intid);
        }
    }
    /* IRQ/FIQ do not supply a new syndrome or fault address. Keep those zero
     * in the snapshot rather than attributing stale EL1 state to this stop. */
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
    vcpu_of(c)->async_captured = 1;

    if (which == ASYNC_SERROR) {
        /* The one asynchronous vector that does write ESR_EL2: EC 0x2f, with
         * the syndrome valid only when IDS is clear. ELR_EL2 is the guest
         * instruction the error was taken against.
         *
         * FAR is deliberately not carried here. An SError has no faulting
         * address -- that is what asynchronous means -- so printing FAR_EL1
         * beside it would label the guest's last unrelated abort as this
         * error's address, which is the same class of lie this fix exists to
         * remove. ESR_EL1/ELR_EL1 go in instead: they say where the guest was
         * in its own terms. */
        uint64_t hyp_esr;
        __asm__ volatile("mrs %0, esr_el2" : "=r"(hyp_esr));
        record(c, EV_SERROR, elr, hyp_esr, esr, el1);
    } else if ((ctl & CNTHP_ISTATUS) &&
               early_stop_fire(&c->early_stop, physical, vcpu_of(c)->watchdog_deadline,
                               (unsigned)vcpu_of(c)->slot)) {
        /* An accepted early stop's deadline, strictly before the budget. */
        const struct early_stop_state *s = &c->early_stop;
        record(c, EV_EARLY_STOP, elr, s->source << 32 | (uint32_t)s->reason, s->detail,
               s->accepted_delay);
    } else if ((ctl & CNTHP_ISTATUS) &&
               (int64_t)(vcpu_of(c)->watchdog_deadline - physical) <= 0) {
        record(c, EV_WATCHDOG, elr, esr, far, el1);
    } else {
        record(c, EV_ASYNC, elr, which, esr, el1);
    }
    watchdog_off(c);
    return 1;
}

#if SNAP_FAST_TIMER_IRQ
#define FAST_IRQ_LOCKED (-1)        /* fast_timer_irq: take the locked path */
#define FAST_IRQ_LOCKED_OTHER (-2)  /* ...as ASYNC_IRQ_OTHER: IAR returned another INTID */
static int fast_timer_irq(struct context *c, uint64_t elr, uint64_t *frame);
#endif
int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame);
int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame)
{
    struct context *c = context_of();
#if SNAP_FAST_TIMER_IRQ
    /* A secondary's timer tick without the token (compat/fast-timer-irq.h):
     * 0 or 1 is its stop. Otherwise the locked path, profiled as this vector;
     * an acknowledge of another INTID reaches it as ASYNC_IRQ_OTHER, a stop. */
    int stop = which == ASYNC_IRQ ? fast_timer_irq(c, elr, (uint64_t *)frame) : FAST_IRQ_LOCKED;
    if (stop < 0) {
        uint64_t kind = stop == FAST_IRQ_LOCKED_OTHER ? ASYNC_IRQ_OTHER : which;
        if (!runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)) return 1;
        stop = runtime_leave(c, xnuboot_async_locked(elr, kind, frame));
    }
#else
    if (!runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)) return 1;
    int stop = runtime_leave(c, xnuboot_async_locked(elr, which, frame));
#endif
    if (stop && !vcpu_of(c)->async_captured) {
        fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
        vcpu_of(c)->async_captured = 1;
    }
    return stop;
}

/* Build everything and program EL1. Returns 0 when the guest may be entered,
 * negative with the step identified when it may not. */
/* int64_t, not int: probes/xnuboot.S stores the whole of x0 into the status
 * word and the host reads it as a signed 64-bit value, so a 32-bit -6 arrives
 * as 0x00000000fffffffa and reads as an EL2 fault with a nonsense ESR. */
static int64_t vcpu_arch_prepare(struct context *c);
static int secondary_prepare_records(struct context *c);
int64_t xnuboot_prepare(void);
static int pauth_domain_prepare(struct context *c)
{
    uint64_t isar0,isar1,isar2,seed[4]={0};
    __asm__ volatile("mrs %0,id_aa64isar0_el1; mrs %1,id_aa64isar1_el1; mrs %2,id_aa64isar2_el1"
                     :"=r"(isar0),"=r"(isar1),"=r"(isar2));
    if(!(isar0>>60) || !(((isar1>>4)&255)|((isar2>>12)&15)))return 0;
    /* PAC key derivation runs 15 AES blocks per key install or user sign.
     * The AES path saves/restores v0/v1 only; with SVE or SME a NEON write
     * would clear live Z-register bits above 128, so keep software AES there. */
    uint64_t pfr0,pfr1;
    __asm__ volatile("mrs %0,id_aa64pfr0_el1; mrs %1,id_aa64pfr1_el1":"=r"(pfr0),"=r"(pfr1));
    c->aes_hardware=(uint64_t)(aes_hardware_supported(isar0) &&
        !((pfr0>>32)&15) && !((pfr1>>24)&15));
    for(unsigned i=0;i<4;i++) {
        unsigned ok=0;
        for(unsigned retry=0;retry<64 && !ok;retry++)
            __asm__ volatile("mrs %0,s3_3_c2_c4_0; cset %w1,ne"
                             :"=r"(seed[i]),"=r"(ok)::"cc");
        if(!ok) {aes_clear(seed,sizeof(seed));return 0;}
    }
    int ok=pauth_domain_init(&c->pauth_domain,(const uint8_t *)seed);
    aes_clear(seed,sizeof(seed));return ok;
}

#if SNAP_BOOT_RELOCATE
/* Allocated encodings only (compat/boot-relocate.h), never id_register: its
 * unallocated CRm=0 cases trap on the A16 (v48). Not inlined, so the build
 * check can read every MRS it contains. */
static __attribute__((noinline)) void boot_relocation_ids(uint64_t id[BOOT_ID_COUNT], uint64_t cache[2])
{
#define BOOT_ID_READ(name, op1, crn, crm, op2, shared) \
    __asm__ volatile("mrs %0, s3_" #op1 "_c" #crn "_c" #crm "_" #op2 : "=r"(id[BOOT_ID_##name]));
    BOOT_RELOCATE_ID_REGS(BOOT_ID_READ)
#undef BOOT_ID_READ
    __asm__ volatile("mrs %0, ctr_el0":"=r"(cache[0]));
    __asm__ volatile("mrs %0, dczid_el0":"=r"(cache[1]));
}
/* On q1n1's CPU, in place of vcpu_arch_prepare: what the report will restore
 * here, read here, and the ID registers the shared preparation just used. */
static int64_t boot_relocation_capture(struct boot_relocation *r)
{
    uint64_t *h=r->host;
    __asm__ volatile("mrs %0, vttbr_el2":"=r"(h[0]));
    __asm__ volatile("mrs %0, vtcr_el2":"=r"(h[1]));
    __asm__ volatile("mrs %0, vmpidr_el2":"=r"(h[2]));
    __asm__ volatile("mrs %0, cntkctl_el1":"=r"(h[3]));
    __asm__ volatile("mrs %0, cnthctl_el2":"=r"(h[4]));
    __asm__ volatile("mrs %0, mdcr_el2":"=r"(h[5]));
    __asm__ volatile("mrs %0, mdscr_el1":"=r"(h[6]));
    __asm__ volatile("mrs %0, oslsr_el1":"=r"(h[7]));
    __asm__ volatile("mrs %0, ttbr0_el1":"=r"(h[8]));
    __asm__ volatile("mrs %0, ttbr1_el1":"=r"(h[9]));
    __asm__ volatile("mrs %0, mair_el1":"=r"(h[10]));
    boot_relocation_ids(r->boot_id,r->boot_cache);
    __asm__ volatile("mrs %0, cntvoff_el2":"=r"(r->boot_cntvoff));
    __asm__ volatile("mrs %0, cntfrq_el0":"=r"(r->boot_cntfrq));
    r->captured=1;
    return 0;
}
#endif

int64_t xnuboot_prepare(void)
{
    struct context *c = context_of();
    const struct params *p = c->params;
    if(!pauth_domain_prepare(c))return -24;
#if SNAP_EL0_MEMO
    /* A new master key: every derivation kept in either level is another
     * domain's (pauth_domain_user_cached_wide flushes on the epoch). */
    c->root_ext->pauth_epoch++;
#endif
    uint64_t physical_hz, mmfr0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(physical_hz));
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    if (physical_hz != p->clock_host_hz || !(mmfr0 >> 60) ||
        clock_rate_init(&vcpu_of(c)->clock_rate, physical_hz, p->clock_guest_hz)) return -15;
    if(c->thermal && (physical_hz!=19200000 || thermal_admit(c)))return -28;
    if (p->device_count > 4 || p->mem_high <= p->mem_low) return -14;
    uint64_t panic_page=p->scratch_pa-SPTM_PANIC_PAGE_SIZE;
    if((p->scratch_pa&0x3fff) || panic_page<p->mem_low || p->scratch_pa>p->mem_high ||
       panic_page<p->txm_aspace_pa+TXM_ASPACE_SIZE+3*0x4000 || p->watch_pa<p->mem_low ||
       p->watch_pa>p->mem_high-0x1000 ||
       *(volatile uint64_t *)(p->watch_pa+SPTM_PANIC_HANDOFF_OFFSET)!=
            p->ram_aperture_va+panic_page-p->mem_low)return -22;
#if SNAP_TXM_ASPACE_WIDE
    /* compat/txm.h A2: the loader's 64-page layout puts UAT right after the
     * whole arena; the 8-page one would leave UAT inside it. */
    if(p->uat.reserved_pa!=p->txm_aspace_pa+TXM_ASPACE_SIZE)return -22;
#endif
    for(unsigned i=0;i<SPTM_PANIC_PAGE_SIZE;i++)
        if(*(volatile uint8_t *)(panic_page+i))return -22;
    sptm_panic_init(&c->panic_state);
    if(p->trust_cache.pa) {
        uint64_t span=0x4000+((p->trust_cache.size+0x3fff)&~0x3fffUL),pa=p->trust_cache.pa;
        /* Either the window between the TXM address space and the panic page (BaseSystem's
         * cache), or -- for the installed OS's larger cache -- the payload area above the
         * per-CPU scratch buffers and below XNU's allocator, clear of the SEP preload. */
        int window=pa>=p->txm_aspace_pa+TXM_ASPACE_SIZE+3*0x4000 && pa<=UINT64_MAX-span &&
                   pa+span<=panic_page;
        int payload=pa>=p->scratch_pa+GUEST_CPU_COUNT*0x8000UL && pa<=UINT64_MAX-span &&
                    pa+span<=p->alloc_low &&
                    !(p->sep_firmware_size && pa<p->sep_firmware_pa+p->sep_firmware_size &&
                      p->sep_firmware_pa<pa+span);
        if(p->trust_cache.size<24 || p->trust_cache.size>TXM_TRUST_MAX_BYTES ||
           !(window || payload) ||
           pa<p->mem_low || pa+span>p->mem_high)return -21;
    }
    struct sptm_memory trust_memory=sptm_context_memory(c);
    if (!sptm_sep_firmware_valid(&trust_memory) ||
        (p->sep_firmware_size && (p->sep_firmware_pa<p->mem_low ||
         p->sep_firmware_pa<p->scratch_pa+GUEST_CPU_COUNT*0x8000UL))) return -25;
    struct txm_service trust_service={.stacks_pa=p->txm_stacks_pa,
        .stack_count=p->txm_stack_count,.log_pa=p->txm_log_pa,
        .rw_pa=p->txm_rw_pa,.ro_pa=p->txm_ro_pa};
    if(txm_trust_bootstrap(&trust_memory,&trust_service,&p->trust_cache,&c->trust_state))return -21;
    if(p->txm_native.image && (!p->trust_cache.pa ||
       txm_native_init(&p->txm_native,&c->txm_native,
           id_forge(4,0,id_register(4,0)),id_forge(4,1,id_register(4,1)))))return -26;
    thermal_prepare_tick(c);
    if (p->vmpidr != 0x80000000 ||
        !guest_cpu_buffers_valid(p->scratch_pa,p->scratch_va,p->mem_low,p->mem_high))
        return -16;
    struct device_range excluded[7] = {
        {p->mem_low, p->mem_high-p->mem_low}, {p->fb_pa, p->fb_span},
        {c->work_start, c->work_end-c->work_start}
    };
    for (uint64_t n=0; n<p->device_count; n++)
        excluded[3+n] = (struct device_range){p->device_pa[n], p->device_span[n]};
    if (!device_models_valid(p->models, p->model_count, excluded, 3+p->device_count))
        return -14;
    if (!device_models_boot_cpu_valid(p->models, p->model_count, p->vmpidr)) return -14;
    for (unsigned i=0;i<p->model_count;i++)
        if(p->models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 && p->models[i].config[4] &&
           !p->sep_firmware_size)return -25;
    if (p->sep_firmware_size) {
        unsigned bindings=0;
        for (unsigned i=0;i<p->model_count;i++)
            if (p->models[i].kind==DEVICE_DART_T8110_V1 &&
                p->models[i].config[1]==DEVICE_DART_SEP_BOOT_V1 &&
                p->models[i].config[4]==(1U<<20)) bindings++;
        if (bindings!=1) return -25;
    }
    uint64_t device_now = clock_counter(c);
    if (device_models_start(p->models,c->model_state,(unsigned)p->model_count,
                            device_now,p->clock_guest_hz)!=DEVICE_OK) return -14;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_ANS_NVME_V1)
            ans_reset((struct ans_state *)p->models[i].config[0],p->models[i].config[1]);
    thermal_prepare_tick(c);

    /* 1. The shadow: the guest's 16K upper half, re-translated into 4K. */
    uint32_t t1sz = (uint32_t)((p->tcr >> 16) & 0x3f);
    struct mmu_config guest = {.granule_shift = 14, .txsz = t1sz, .root = p->ttbr1_root};
    struct shadow shadow = {.txsz = t1sz, .alloc = prepare_table_alloc, .read = mem_read,
                            .write = mem_write, .ctx = c,
                            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    shadow.root = table_alloc(c);
    if (!shadow.root) return -1;
    long leaves = shadow_build(&shadow, &guest, 0, 1UL << (64 - t1sz), mem_read, c);
    if (leaves < 0) return -2;
    vcpu_of(c)->shadow_root = shadow.root;
    c->leaves = (uint64_t)leaves;
    if (t1sz!=17 || p->slide.begin>=p->slide.end ||
        p->slide.end-p->slide.begin>0x4000000 ||
        shadow_reserve(&shadow,p->slide.begin&((1UL<<47)-1),
                       p->slide.end-p->slide.begin)) return -13;

    /* The low regime. The guest's own 16K tables already describe these
     * addresses -- the loader maps the reserve identity, and the kernel's
     * software walker finds them there because it masks rather than asking
     * which half it is in. What was missing is a table base for the hardware to
     * use when the kernel stops walking and starts loading. So this is the same
     * guest tables shadowed a second time, over the low range only, rather than
     * a second description of the same memory that could drift from the first. */
    struct shadow low = {.txsz = t1sz, .alloc = prepare_table_alloc, .read = mem_read,
                         .write = mem_write, .ctx = c,
                         .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_low:0};
    low.root = table_alloc(c);
    if (!low.root) return -8;
    long low_leaves = shadow_build(&low, &guest, p->low_base,
                                   p->low_base + p->low_span, mem_read, c);
    if (low_leaves < 0) return -9;
    vcpu_of(c)->low_root = low.root;
    vcpu_of(c)->low_leaves = (uint64_t)low_leaves;

    struct shadow canonical=kernel_shadow(c);
    if(!sprr_views_init(&c->kernel_views,&canonical) || !kernel_refresh(c))return -22;
    thermal_prepare_tick(c);

    /* 2. Stage 2: exactly what we own, then execute-never on the pages we want
     * to hear about -- every page holding a monitor call, and XNU's own vectors
     * -- so a fault XNU takes is delivered here instead of disappearing into
     * its handler.
     *
     * Three ranges, each mapped to itself, and nothing else:
     *   - the DRAM we declared and the reserve above it, read-write;
     *   - the panel, when it is handed over, read-write;
     *   - this probe's table arena, read-only. The private context and PA
     *     keys before work_base remain completely absent from stage 2.
     *     The hardware walks the 4K shadow
     *     tables through stage 2 -- at EL1, and for the AT S1E1R at the end of
     *     this function, since HCR_EL2.VM is already set -- so they must be
     *     reachable. The guest must never write them, and a write is a fault
     *     we want to see. The walker itself never writes: the TCR the shadow
     *     runs under has HA and HD clear, and a guest TCR write is stored, not
     *     applied.
     * Every other intermediate address is absent. A touch is a stage-2 fault
     * that arrives in xnuboot_trap with the IPA, and the run stops there. The
     * list is checked before a descriptor is written -- empty, unaligned,
     * past 36 bits or overlapping is -10 -- because a map that is quietly
     * partial would read like the identity map this replaces, minus whatever
     * it lost. */
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        int built = vcpu_stage2_prepare(c, &c->vcpus[n]);
        if (built) return built;
        thermal_prepare_tick(c);
    }
#if SNAP_USER_HW_WALK_S2RO
    /* Guest RAM in level-3 leaves in every tree before any vCPU runs: a
     * RETYPE then changes only a leaf's S2AP, never a block size under a
     * running CPU (compat/user-hw-walk.h hw_s2_presplit, v62). */
    if (hw_s2_presplit_all(c)) return -27;
#endif

    /* Allocate CPU-local runtime memory after every stage-2 tree, preserving
     * their existing addresses. Six VNCR pages and five stacks/output pages
     * remain inside monitor-owned RAM, read-only to the guest at stage 2. */
    struct guest_cpu_storage storage[GUEST_CPU_COUNT];
    uint64_t storage_end;
    if (!p->vncr_va || p->vncr_va&0xfff || p->vncr_va<p->mem_low ||
        p->vncr_va>p->mem_high-GUEST_RUNTIME_PAGE ||
        guest_cpu_storage_plan(c->next_table,c->work_end,storage,&storage_end)) return -17;
    uint64_t seed_hcr=*(const volatile uint64_t *)(p->vncr_va+0x78);
#if SNAP_ROOT_DIRTY_PUBLISH
    c->root_publish.always_first=c->next_table;
#endif
    for (uint64_t address=c->next_table; address<storage_end; address+=8)
        *(volatile uint64_t *)address=0;
    c->next_table=storage_end;
    c->vcpus[0].vncr_va=storage[0].vncr;
    for (unsigned n=0; n<GUEST_RUNTIME_PAGE/8; n++)
        *(volatile uint64_t *)(storage[0].vncr+n*8)=
            *(const volatile uint64_t *)(p->vncr_va+n*8);
    for (unsigned n=1; n<GUEST_CPU_COUNT; n++) {
        struct vcpu *v=&c->vcpus[n];
        const struct guest_cpu_storage *s=&storage[n];
        v->vncr_va=s->vncr;
        v->out_ptr=s->output;
        v->el2_sp=s->stack_high;
        v->shadow_root=c->vcpus[0].shadow_root;
        v->low_root=c->vcpus[0].low_root;
        *(volatile uint64_t *)(v->vncr_va+0x78)=seed_hcr;
    }
    if (!secondary_prepare_records(c)) return -19;
#if SNAP_ROOT_DIRTY_PUBLISH
    c->root_publish.always_end=c->next_table;
#endif
    /* Long preparation is not silently exempt from the sample-gap policy. */
    if(c->thermal && thermal_admit(c))return -28;
    int64_t gpu=gpu_prepare(c);
    if (gpu) return gpu;
    thermal_prepare_tick(c);
    int64_t window=ans_window_prepare(c);
    if (window) return window;
    if(c->thermal && thermal_admit(c))return -28;
#if SNAP_BOOT_RELOCATE
    /* The CPU that runs vCPU 0 installs its own state (boot_relocated_run). */
    struct boot_relocation *relocated=boot_relocation_of(c);
    if (relocated) return boot_relocation_capture(relocated);
#endif
    return vcpu_arch_prepare(c);
}

#if SNAP_ERET_SNAPSHOT
/* The live translation of exception_return from its SPSR write (writer site
 * 5) to the first ERET, in const-sealed kernel text, must pass
 * native_writer_return_window before site 5's comparator may stay unarmed. */
static int eret_window_proof(struct context *c)
{
    const struct params *p=c->params;
    uint32_t words[NATIVE_WRITER_RETURN_WINDOW];
    uint64_t va=native_writer_sites[NATIVE_WRITER_RETURN_SITE].va;
    for(unsigned i=0;i<NATIVE_WRITER_RETURN_WINDOW;i++) {
        uint64_t pa=guest_pa(va+4*i);
        if(pa<p->const_begin || pa+4>p->const_end)return 0;
        words[i]=*(const volatile uint32_t *)pa;
        if(words[i]==NATIVE_WRITER_ERET)return i && native_writer_return_window(words,i+1)==i;
    }
    return 0;
}
#endif

#if SNAP_NATIVE_PACGA
static int native_pacga_prepare(struct context *c, struct vcpu *v);
static void native_pacga_restore(struct context *c, struct vcpu *v);
#endif
#if SNAP_LEAN_TRAPS == 2
static void lean_fgt_prepare(struct context *c, struct vcpu *v);
static void lean_fgt_restore(struct context *c, struct vcpu *v);
#endif
/* Shared model/table construction runs only once above. This portion installs
 * the current CPU's own hardware state. A secondary caller must already have
 * its physical EL2 stack, TPIDR, vectors, interrupt backend and service token. */
static int64_t vcpu_arch_prepare(struct context *c)
{
    const struct params *p=c->params;
    struct vcpu *v=vcpu_of(c);
    if (v->slot) {
        uint64_t physical_hz,mmfr0;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(physical_hz));
        __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
        if (physical_hz!=p->clock_host_hz || !(mmfr0>>60) ||
            clock_rate_init(&v->clock_rate,physical_hz,p->clock_guest_hz)) return -15;
    }
    uint64_t root = vcpu_vttbr(vcpu_of(c));

    uint64_t parange;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(parange));
    parange &= 0xf;
    if (parange > 5) parange = 5;
    uint64_t vtcr = S2_TXSZ | (1UL << 6) | (1UL << 8) | (1UL << 10)
                  | (3UL << 12) | (0UL << 14) | (parange << 16);
    __asm__ volatile("mrs %0, vttbr_el2" : "=r"(vcpu_of(c)->save_vttbr));
    __asm__ volatile("mrs %0, vtcr_el2" : "=r"(vcpu_of(c)->save_vtcr));
    __asm__ volatile("msr vtcr_el2, %0" :: "r"(vtcr));
    __asm__ volatile("msr vttbr_el2, %0" :: "r"(root));
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");

    /* What this CPU actually says about itself, logged once. XNU is configuring
     * SME unconditionally for this board, so whether the silicon under it has
     * SME at all decides whether that is deniable or has to be emulated. */
    if (!v->slot) record(c, EV_OTHER, 0, id_register(4, 0), id_register(4, 1), id_register(0, 0));
    /* ID_AA64MMFR2_EL1.NV at [27:24] and ID_AA64MMFR4_EL1.NV_frac at [27:24]:
     * 2 (or 1 + frac) means FEAT_NV2, which redirects a guest's EL2 register
     * accesses into memory instead of leaving them undefined. XNU writes EL2
     * registers, so whether this silicon has NV2 decides whether it can be run
     * at all without pretending to be something it is not. */
    if (!v->slot) record(c, EV_OTHER, 1, id_register(7, 2), id_register(7, 4), id_register(7, 0));
#if SNAP_IDREG_MMFR3
    /* Every vCPU: S1PIE/S1POE (MMFR3) and HAFDBS/HPDS/PAN (MMFR1), per core. */
    record(c, EV_OTHER, 2, id_register(7, 3), id_register(7, 1), v->slot);
#endif

    /* Nested virtualization.
     *
     * XNU is not an EL1 kernel. It writes EL2 registers -- SMPRIMAP_EL2 at
     * 0xfffffe000c245030, and Apple IMPDEF registers with op1=4 before that --
     * because on Apple silicon HCR_EL2.E2H is RES1 and the kernel runs at EL2
     * under VHE, with SPTM in the guarded shadow of EL2. `genter` from ELn
     * enters GLn, and XNU's calls land in SPTM at GL2, which says the same
     * thing. Run at EL1, every one of those accesses is simply undefined.
     *
     * FEAT_NV2 is exactly the mechanism for this, and this silicon has it
     * (ID_AA64MMFR2_EL1.NV == 2, measured). With NV and NV2 set, EL1 accesses
     * to EL2 registers become memory accesses at VNCR_EL2 instead of faulting,
     * so a kernel that believes it is the hypervisor runs unmodified and its
     * idea of EL2 state is left somewhere we can read. */
    /* MPIDR_EL1 is read 22 times in __TEXT_EXEC -- it is how XNU asks which core
     * it is, and it has to answer with the affinity the device tree gives cpu0,
     * not with Qualcomm's. VMPIDR_EL2 is the architectural way to say so: it
     * supplies the value EL1 sees, leaving the real register alone for EL2. (The
     * matching VPIDR_EL2 is deliberately left at the true MIDR: there is exactly
     * one MIDR_EL1 read in the whole kernel, so nothing is gained by lying about
     * the part number, and the truth is easier to debug.) */
    __asm__ volatile("mrs %0, vmpidr_el2" : "=r"(vcpu_of(c)->save_vmpidr));
    __asm__ volatile("msr vmpidr_el2, %0" :: "r"(vcpu_of(c)->vmpidr));

    /* Non-VHE host: CNTKCTL_EL1 governs the EL1 guest event stream. The Apple
     * alias below programs this register, not the host CNTHCTL_EL2. Save even
     * the unsupported fields so every run restores q1n1's original state. */
    __asm__ volatile("mrs %0, cntkctl_el1" : "=r"(vcpu_of(c)->save_cntkctl));
    __asm__ volatile("mrs %0, cnthctl_el2" : "=r"(vcpu_of(c)->save_cnthctl));
    vcpu_of(c)->clock_hz = p->clock_guest_hz;
    /* Non-VHE EL1TVCT/EL1TVT trap virtual reads/timers. Withhold physical
     * counter/timer access: unsupported alternate domains must stop rather
     * than silently use an unscaled counter. ECV was checked above. */
    vcpu_of(c)->guest_cnthctl = (vcpu_of(c)->save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13);
    __asm__ volatile("msr cnthctl_el2, %0; isb" :: "r"(vcpu_of(c)->guest_cnthctl));
    vcpu_of(c)->clock_saved = 1;
    __asm__ volatile("msr cntkctl_el1, xzr; isb");

    if (vcpu_of(c)->vncr_va) {
        uint64_t hcr;
        /* VNCR_EL2 by encoding: the assembler only knows the name with an
         * explicit -march that the rest of this blob does not want. */
        __asm__ volatile("msr s3_4_c2_c2_0, %0" :: "r"(vcpu_of(c)->vncr_va));
        __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
        hcr |= (1UL << 42) | (1UL << 45);          /* NV, NV2 */
        __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr));
    }
    if (SNAP_NATIVE_WFE) {
        /* TWE off: the guest's WFE sleeps natively until the event stream
         * clock_control programs, a SEV, a cleared monitor or any interrupt,
         * physical IRQs to EL2 (timer, watchdog, IPI poll) included. */
        uint64_t hcr;
        __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
        __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr & ~(1UL << 14)));
    }
#if SNAP_NATIVE_PACGA
    /* The guest GA key in APGAKey and HCR_EL2.API for EL1; every later HCR
     * write is read-modify-write. */
    {
        int pacga = native_pacga_prepare(c, v);
        if (pacga) return pacga;
    }
#endif
#if SNAP_LEAN_TRAPS == 2
    /* FEAT_FGT for TVM/TRVM, or this CPU unchanged (compat/lean-trap.h). */
    lean_fgt_prepare(c, v);
#endif

    /* 3. Debug exceptions to EL2, with the OS Lock opened if firmware left it
     * shut, so the single-step fallback can run at all. */
    __asm__ volatile("mrs %0, mdcr_el2" : "=r"(vcpu_of(c)->save_mdcr));
    __asm__ volatile("mrs %0, mdscr_el1" : "=r"(vcpu_of(c)->save_mdscr));
    __asm__ volatile("msr mdcr_el2, %0; isb" :: "r"(vcpu_of(c)->save_mdcr | (1UL << 8)));
    __asm__ volatile("mrs %0, oslsr_el1" : "=r"(vcpu_of(c)->dbg_oslsr));
    if (vcpu_of(c)->dbg_oslsr & (1UL << 1))
        __asm__ volatile("msr oslar_el1, xzr; isb");

    /* 4. EL1's translation regime, pointed at the shadow rather than at what
     * the guest believes. The guest's own values are kept so TRVM can hand them
     * back unchanged. */
    vcpu_of(c)->guest_ttbr1 = p->ttbr1_root;
    vcpu_of(c)->guest_tcr = p->tcr;
    vcpu_of(c)->guest_mair = p->mair;
    publish(c->work_base, c->next_table);

    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(vcpu_of(c)->save_ttbr0));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(vcpu_of(c)->save_ttbr1));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(vcpu_of(c)->save_mair));
    __asm__ volatile("msr mair_el1, %0" :: "r"(p->mair));
    __asm__ volatile("msr tcr_el1, %0" :: "r"(shadow_tcr(p->tcr)));
    uint64_t kernel_root=sprr_views_root(&c->kernel_views,(unsigned)v->slot);
    if(!kernel_root)return -22;
    __asm__ volatile("msr ttbr1_el1, %0; isb" :: "r"(kernel_root));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(c->kernel_installed[v->slot]));
    if(c->kernel_installed[v->slot]!=kernel_root)return -22;
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(vcpu_of(c)->low_root));
    /* XNU installs its own vectors 35 instructions in. Until then a fault would
     * go to whatever VBAR_EL1 happened to hold -- zero, on this machine, which
     * turns the first mistake into an unreadable loop at address 0x200. Pointing
     * it at XNU's own vectors early costs nothing (XNU writes the same value)
     * and makes that window reportable, because the page is execute-never. */
    if (p->vbar_va) __asm__ volatile("msr vbar_el1, %0" :: "r"(p->vbar_va));
    /* EL1's fault registers survive between runs of this probe, so a watchdog
     * report would otherwise show the previous run's abort and read as a fault
     * that is still happening. Cleared so anything reported is from this run. */
    __asm__ volatile("msr esr_el1, xzr");
    __asm__ volatile("msr far_el1, xzr");
    __asm__ volatile("dsb ish; tlbi vmalle1is; dsb ish; isb");

    /* 5. Translation and normal-memory caches on, and then checked. The loader
     * already publishes the image; guest table updates are also published.
     * Leaving I/C clear made native allocator type sorting consume seconds
     * without another monitor call. Device attributes still control MMIO.
     * AT S1E1R reports PA == VA with
     * SCTLR_EL1.M clear, so asking before enabling is a check that always
     * passes and means nothing. */
    /* The reached libsystem_platform zeroing loop uses native 64-byte DC ZVA.
     * Qualify that physical geometry on every CPU before allowing it at EL0.
     * Leave translation, write permissions and faults to the hardware: this
     * enables the instruction, it does not emulate a write or skip a fault. */
    uint64_t dczid;
    __asm__ volatile("mrs %0, dczid_el0":"=r"(dczid));
    if(dczid!=4)return -26;
    vcpu_of(c)->guest_sctlr = 1UL | (1UL << 2) | (1UL << 11) | (1UL << 12) | (1UL << 14)
                   | (1UL << 20) | (1UL << 22)
                   | (1UL << 28) | (1UL << 29) | EL0_SCTLR_GRANTS;
    /* SPAN=0 lets hardware set PAN when an EL0 exception enters physical EL1.
     * SPAN=1 preserved the user's PAN=0, triggering XNU's pcb.c context-switch
     * assertion during its first instruction fault. Do not alter the saved
     * user PSTATE: ERET must restore it exactly. */
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(vcpu_of(c)->guest_sctlr));
    __asm__ volatile("isb");
    struct pan_entry_state *pan=&c->pan_entry[v->slot];
    __asm__ volatile("mrs %0, id_aa64mmfr1_el1":"=r"(pan->mmfr1));
    __asm__ volatile("mrs %0, sctlr_el1":"=r"(pan->installed_sctlr));
    if(!((pan->mmfr1>>20)&15) || (pan->installed_sctlr&(1UL<<23)))return -23;
    if(!(pan->installed_sctlr&(1UL<<14)))return -26;
#if SNAP_EL0_WFE || SNAP_EL0_CACHE_MAINT
    /* The EL0 grants must read back; a PE that drops one keeps the SIGILL. */
    if((pan->installed_sctlr&EL0_SCTLR_GRANTS)!=EL0_SCTLR_GRANTS)return -26;
#endif

    uint64_t par;
    __asm__ volatile("at s1e1r, %0; isb" :: "r"(p->entry));
    __asm__ volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1) {
        __asm__ volatile("msr sctlr_el1, xzr; isb");
        vcpu_of(c)->fault_esr = par;
        return -6;
    }
    if (!v->slot && p->fb_span) {
        c->fb_before = framebuffer_hash(p);
        c->fb_observed = p->fb_span;
    }
    if (!v->slot && guest_service_boot(&c->services) != SERVICE_OK) return -7;
    if(SNAP_NATIVE_WRITER_BREAKPOINTS) {
        /* The instruction inventory and live architectural translation must
         * agree before exposing unguarded writer pages to this physical CPU. */
        for(unsigned i=0;i<NATIVE_WRITER_SITE_COUNT;i++) {
            const struct native_writer_site *site=&native_writer_sites[i];
            uint64_t expected=p->stub_pa[NATIVE_CALL_PAGES+site->page]+(site->va&4095);
            if(guest_pa(site->va)!=expected ||
               *(const volatile uint32_t *)expected!=site->word)return -35;
        }
#if SNAP_ERET_SNAPSHOT
        if(!eret_window_proof(c))return -38;
#endif
        uint64_t dfr0,mdscr;
        __asm__ volatile("mrs %0, id_aa64dfr0_el1":"=r"(dfr0));
        if(!native_writer_debug_install_armed(&c->writer_debug[v->slot],&writer_debug_ops,dfr0,
               SNAP_ERET_SNAPSHOT ? NATIVE_WRITER_ARMED_ALL&~(1u<<NATIVE_WRITER_RETURN_SITE) :
                                    NATIVE_WRITER_ARMED_ALL))return -36;
        __asm__ volatile("mrs %0, mdscr_el1":"=r"(mdscr));
        mdscr|=NATIVE_WRITER_MDSCR;
        __asm__ volatile("msr mdscr_el1, %0; isb"::"r"(mdscr):"memory");
        __asm__ volatile("mrs %0, mdscr_el1":"=r"(mdscr));
        if((mdscr&NATIVE_WRITER_MDSCR)!=NATIVE_WRITER_MDSCR)return -37;
    }
    vcpu_of(c)->prepared = 1;
    if (SNAP_NATIVE_CALLS) native_exception_snapshot(c);
    return 0;
}

int64_t xnuboot_prepare_cpu(void);
int64_t xnuboot_prepare_cpu(void)
{
    struct context *c=context_of();
    struct vcpu *v=vcpu_of(c);
    if (!v->slot || v->slot>=GUEST_CPU_COUNT || v->prepared ||
        guest_service_owner(&c->services)!=v->slot+1 ||
        (guest_service_lifecycle(&c->services)&SERVICE_ADMISSION_CLOSED) ||
        ((guest_service_lifecycle(&c->services)>>(v->slot*3))&7)!=EXECUTOR_RUNNING)
        return -18;
    return vcpu_arch_prepare(c);
}

static struct secondary *secondary_of(struct context *c,unsigned slot)
{
    return (struct secondary *)(c->secondary_base+(uint64_t)slot*4096);
}
void xnuboot_secondary_stop(void) __attribute__((noreturn));
static void secondary_run(struct secondary *s) __attribute__((noreturn));
#if SNAP_BOOT_RELOCATE
void xnuboot_relocated_stop(void) __attribute__((noreturn));
static void boot_relocated_run(struct secondary *s) __attribute__((noreturn));
void boot_guest_enter(uint64_t entry, uint64_t out, uint64_t x1, uint64_t x2) __attribute__((noreturn));
#endif
extern const uint8_t xnuboot_vectors[];
static int secondary_prepare_records(struct context *c)
{
    const struct secondary_config *h=c->host_cpus;
    if (!h) return 1;
    uint64_t mpidr,regime[4];
    __asm__ volatile("mrs %0, mpidr_el1":"=r"(mpidr));
    __asm__ volatile("mrs %0, sctlr_el2":"=r"(regime[0]));
    __asm__ volatile("mrs %0, tcr_el2":"=r"(regime[1]));
    __asm__ volatile("mrs %0, ttbr0_el2":"=r"(regime[2]));
    __asm__ volatile("mrs %0, mair_el2":"=r"(regime[3]));
#if SNAP_BOOT_RELOCATE
    /* Bit 0: vCPU 0 on affinity[0], with an EL2 stack of its own. */
    uint64_t relocate=h->mask&BOOT_RELOCATE_MASK ? GUEST_RUNTIME_STACK : 0;
    if (h->magic!=SECONDARY_MAGIC || h->size!=sizeof(*h) ||
        (mpidr&UINT64_C(0xff00ffffff))!=h->boot_affinity ||
        !h->mask || h->mask&~UINT64_C(0x3f) ||
        !boot_relocate_layout_valid(h->boot_affinity,h->mask,h->affinity,h->redistributor) ||
        c->work_end-c->next_table<6*4096+relocate) return 0;
#else
    if (h->magic!=SECONDARY_MAGIC || h->size!=sizeof(*h) ||
        (mpidr&UINT64_C(0xff00ffffff))!=h->boot_affinity ||
        !h->mask || h->mask&~UINT64_C(0x3e) ||
        c->work_end-c->next_table<6*4096) return 0;
#endif
    for (unsigned i=0;i<4;i++) if (regime[i]!=h->regime[i]) return 0;
    for (unsigned i=1;i<6;i++) if (h->mask&(1U<<i)) {
        uint64_t r=h->redistributor[i];
        if (h->affinity[i]&~UINT64_C(0xff00ffffff) || h->affinity[i]==h->boot_affinity ||
            r<0x17080000 || r>=0x17500000 || (r-0x17080000)%0x40000) return 0;
        for (unsigned j=1;j<i;j++) if ((h->mask&(1U<<j)) &&
            (h->affinity[i]==h->affinity[j] || r==h->redistributor[j])) return 0;
    }
    c->secondary_base=c->next_table;
    c->next_table+=6*4096;
    for (uint64_t p=c->secondary_base;p<c->next_table;p+=8) *(uint64_t *)p=0;
#if SNAP_BOOT_RELOCATE
    if (relocate) {
        struct boot_relocation *r=(struct boot_relocation *)secondary_of(c,0);
        uint64_t stack=c->next_table;
        c->next_table+=relocate;
        for (uint64_t p=stack;p<c->next_table;p+=8) *(uint64_t *)p=0;
        for (unsigned j=0;j<4;j++) r->record.regime[j]=regime[j];
        r->record.cpu=(uint64_t)&c->vcpus[0];r->record.stack=c->next_table;
        r->record.affinity=h->affinity[0];r->record.redistributor=h->redistributor[0];
        r->record.vectors=(uint64_t)xnuboot_vectors;r->record.callback=(uint64_t)boot_relocated_run;
        r->record.stop_callback=(uint64_t)xnuboot_relocated_stop;
        r->record.on_result=r->record.off_result=r->record.affinity_result=UINT64_MAX;
        r->armed=1;
    }
#endif
    for (unsigned i=1;i<6;i++) if (h->mask&(1U<<i)) {
        struct secondary *s=secondary_of(c,i);
        for (unsigned j=0;j<4;j++) s->regime[j]=regime[j];
        s->cpu=(uint64_t)&c->vcpus[i];s->stack=c->vcpus[i].el2_sp;
        s->affinity=h->affinity[i];s->redistributor=h->redistributor[i];
        s->vectors=(uint64_t)xnuboot_vectors;s->callback=(uint64_t)secondary_run;
        s->stop_callback=(uint64_t)xnuboot_secondary_stop;
        s->on_result=s->off_result=s->affinity_result=UINT64_MAX;
    }
    return 1;
}
static void secondary_run(struct secondary *s)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    __atomic_store_n(&s->phase,1,__ATOMIC_RELEASE);
    enum guest_service_result arrived=guest_service_arrive(&c->services,v->slot);
    if (arrived!=SERVICE_OK) { s->error=arrived; xnuboot_secondary_stop(); }
    if (!secondary_gic_start(s)) { s->error=0x100;xnuboot_secondary_stop(); }
    __atomic_store_n(&s->phase,2,__ATOMIC_RELEASE);
    uint64_t frame[31]={0};
    if (!runtime_enter(c,frame,c->params->entry,SERVICE_PROFILE_BOOT)) xnuboot_secondary_stop();
    uint64_t hcr=(UINT64_C(1)<<31)|(UINT64_C(1)<<26)|(UINT64_C(1)<<30)|
        (UINT64_C(1)<<20)|(UINT64_C(1)<<18)|(UINT64_C(1)<<14)|1;
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr));
    s->prepare_result=(uint64_t)xnuboot_prepare_cpu();
    *(uint64_t *)v->out_ptr=s->prepare_result;
    if (s->prepare_result) { s->error=0x101;xnuboot_secondary_stop(); }
    __asm__ volatile("mrs %0, s3_4_c2_c2_0":"=r"(s->active_vncr));
    __asm__ volatile("mrs %0, vmpidr_el2":"=r"(s->active_vmpidr));
    __asm__ volatile("mrs %0, vttbr_el2":"=r"(s->active_vttbr));
    if (s->active_vncr!=v->vncr_va || s->active_vmpidr!=v->vmpidr ||
        s->active_vttbr!=vcpu_vttbr(v)) { s->error=0x103;xnuboot_secondary_stop(); }
    /* Firmware enables SIMD on its boot CPU, but PSCI secondaries can enter
     * with FPEN clear. The stock warm path assumes the platform supplied FP.
     * These are native per-CPU registers; SVE/SME access policy is unchanged. */
    uint64_t pfr0,cpacr,cptr;
    __asm__ volatile("mrs %0, id_aa64pfr0_el1":"=r"(pfr0));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->initial_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->initial_cptr));
    if (((pfr0>>16)&15)>1 || ((pfr0>>20)&15)>1) {
        s->error=0x104;xnuboot_secondary_stop();
    }
    __asm__ volatile("msr cpacr_el1, %0; msr cptr_el2, %1; isb"::
        "r"(s->initial_cpacr|(UINT64_C(3)<<20)),"r"(s->initial_cptr&~(UINT64_C(1)<<10)));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(cptr));
    if ((cpacr&(UINT64_C(3)<<20))!=(UINT64_C(3)<<20) || (cptr&(UINT64_C(1)<<10))) {
        s->error=0x105;xnuboot_secondary_stop();
    }
    xnuboot_watchdog(c->params->watchdog_seconds);
    __asm__ volatile("mrs %0, hcr_el2":"=r"(hcr));
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr|24));
    if (runtime_leave(c,0)) xnuboot_secondary_stop();
    s->entered=1;
    __atomic_store_n(&s->phase,3,__ATOMIC_RELEASE);
    secondary_guest_enter(c->params->entry,v->out_ptr);
}
void xnuboot_secondary_stop(void)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    if (!v->slot || v->slot>=6 || !c->secondary_base)
        for (;;) __asm__ volatile("yield":::"memory");
    struct secondary *s=secondary_of(c,(unsigned)v->slot);
    watchdog_off(c);
    guards_close(c);
    /* Secondary CPUs bypass xnuboot_report and go straight to PSCI CPU_OFF.
     * Restore their bank on its owning CPU, while its debug state is still
     * accessible, including after a partially successful preparation. */
    if (SNAP_NATIVE_WRITER_BREAKPOINTS && c->writer_debug[v->slot].saved) {
        int restored=native_writer_debug_restore(&c->writer_debug[v->slot],&writer_debug_ops);
        __asm__ volatile("msr mdcr_el2, %0; msr mdscr_el1, %1; isb"::
                         "r"(v->save_mdcr),"r"(v->save_mdscr):"memory");
        if (v->dbg_oslsr & (1UL<<1)) {
            uint64_t one=1;
            __asm__ volatile("msr oslar_el1, %0; isb"::"r"(one):"memory");
        }
        if (!restored) { s->error=0x106;v->service_fault=SERVICE_BAD_STATE; }
    }
#if SNAP_NATIVE_PACGA
    native_pacga_restore(c,v);
#endif
#if SNAP_LEAN_TRAPS == 2
    lean_fgt_restore(c,v);
#endif
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->final_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->final_cptr));
    if (!secondary_gic_stop(s)) { s->error=0x102;v->service_fault=SERVICE_BAD_STATE; }
    if (s->error || v->service_fault)
        guest_service_stop(&c->services,v->slot,SERVICE_STOP_FAULT);
    /* Preserve this CPU's terminal snapshot independently of CPU0's report. */
    const uint64_t *snapshot=(const uint64_t *)(v->async_captured ? &v->async_regs : &v->last_exc);
    uint64_t *out=(uint64_t *)v->out_ptr;
    out[2]=v->fault_esr;out[3]=v->fault_elr;out[4]=v->bad_elr;out[5]=v->bad_far;
    out[6]=v->async_captured ? v->async_captured : v->exceptions ? 4 : 0;
    out[7]=v->service_fault;
    for (unsigned i=0;i<GUEST_REGS_WORDS;i++) out[8+i]=snapshot[i];
    s->finish_result=guest_service_finish(&c->services,v->slot);
    if (s->finish_result!=SERVICE_OK) v->service_fault=s->finish_result;
    __atomic_store_n(&s->phase,4,__ATOMIC_RELEASE);
    secondary_power_off(s);
}
#if SNAP_BOOT_RELOCATE
/* The relocated vCPU 0's CPU (compat/boot-relocate.h), from secondary_entry
 * with record page 0: the boot path's per-CPU half, then the guest's cold
 * entry. No other executor exists yet (secondaries start only at the guest's
 * request) and q1n1's CPU touches only the relay, so, as on the boot path, no
 * service token is taken before guest_service_boot (in vcpu_arch_prepare). */
static void boot_relocated_run(struct secondary *s)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct boot_relocation *r=(struct boot_relocation *)s;
    __atomic_store_n(&s->phase,1,__ATOMIC_RELEASE);
    boot_relocation_ids(r->target_id,r->target_cache);
    r->id_mismatch=boot_relocate_id_mismatch(r->boot_id,r->target_id);
    if (r->id_mismatch) { s->error=BOOT_RELOCATE_ERROR_ID;xnuboot_relocated_stop(); }
    __asm__ volatile("mrs %0, cntvoff_el2":"=r"(r->target_cntvoff));
    __asm__ volatile("mrs %0, cntfrq_el0":"=r"(r->target_cntfrq));
    if (r->target_cntvoff!=r->boot_cntvoff || r->target_cntfrq!=r->boot_cntfrq ||
        r->target_cntfrq!=c->params->clock_host_hz) {
        s->error=BOOT_RELOCATE_ERROR_CLOCK;xnuboot_relocated_stop();
    }
    if (!secondary_gic_start(s)) { s->error=0x100;xnuboot_relocated_stop(); }
    __atomic_store_n(&s->phase,2,__ATOMIC_RELEASE);
    /* _start's HCR_EL2; vcpu_arch_prepare adds NV/NV2 (and clears TWE). */
    uint64_t hcr=(UINT64_C(1)<<31)|(UINT64_C(1)<<26)|(UINT64_C(1)<<30)|
        (UINT64_C(1)<<20)|(UINT64_C(1)<<18)|(UINT64_C(1)<<14)|1;
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr));
    /* As secondary_run: PSCI can start this CPU with FP/SIMD trapped. */
    uint64_t pfr0,cpacr,cptr;
    __asm__ volatile("mrs %0, id_aa64pfr0_el1":"=r"(pfr0));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->initial_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->initial_cptr));
    if (((pfr0>>16)&15)>1 || ((pfr0>>20)&15)>1) { s->error=0x104;xnuboot_relocated_stop(); }
    __asm__ volatile("msr cpacr_el1, %0; msr cptr_el2, %1; isb"::
        "r"(s->initial_cpacr|(UINT64_C(3)<<20)),"r"(s->initial_cptr&~(UINT64_C(1)<<10)));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(cptr));
    if ((cpacr&(UINT64_C(3)<<20))!=(UINT64_C(3)<<20) || (cptr&(UINT64_C(1)<<10))) {
        s->error=0x105;xnuboot_relocated_stop();
    }
    s->prepare_result=(uint64_t)vcpu_arch_prepare(c);
    if (s->prepare_result) { s->error=0x101;xnuboot_relocated_stop(); }
    __asm__ volatile("mrs %0, s3_4_c2_c2_0":"=r"(s->active_vncr));
    __asm__ volatile("mrs %0, vmpidr_el2":"=r"(s->active_vmpidr));
    __asm__ volatile("mrs %0, vttbr_el2":"=r"(s->active_vttbr));
    if (s->active_vncr!=v->vncr_va || s->active_vmpidr!=v->vmpidr ||
        s->active_vttbr!=vcpu_vttbr(v)) { s->error=0x103;xnuboot_relocated_stop(); }
    xnuboot_watchdog(c->params->watchdog_seconds);
    __asm__ volatile("mrs %0, hcr_el2":"=r"(hcr));
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr|24));   /* IMO, FMO */
    s->entered=1;
    __atomic_store_n(&s->phase,3,__ATOMIC_RELEASE);
    boot_guest_enter(c->params->entry,v->out_ptr,c->params->x1,c->params->x2);
}
/* The relocated CPU's terminal path, from the exit path (xnuboot.S, on its own
 * stack) or a refusal above: like xnuboot_secondary_stop, it puts back only
 * this CPU's state, finishes vCPU 0's executor and powers off. q1n1's CPU
 * reports once AFFINITY_INFO says OFF. */
void xnuboot_relocated_stop(void)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct boot_relocation *r=boot_relocation_of(c);
    if (v->slot || !r || boot_relocation_on_boot_cpu(c))
        for (;;) __asm__ volatile("yield":::"memory");
    struct secondary *s=&r->record;
    watchdog_off(c);
    guards_close(c);
    if (SNAP_NATIVE_WRITER_BREAKPOINTS && c->writer_debug[0].saved) {
        int restored=native_writer_debug_restore(&c->writer_debug[0],&writer_debug_ops);
        __asm__ volatile("msr mdcr_el2, %0; msr mdscr_el1, %1; isb"::
                         "r"(v->save_mdcr),"r"(v->save_mdscr):"memory");
        if (v->dbg_oslsr & (1UL<<1)) {
            uint64_t one=1;
            __asm__ volatile("msr oslar_el1, %0; isb"::"r"(one):"memory");
        }
        /* This CPU's bank: the report must not restore it onto q1n1's CPU. */
        c->writer_debug[0].saved=0;
        if (!restored) { s->error=0x106;v->service_fault=SERVICE_BAD_STATE; }
    }
#if SNAP_NATIVE_PACGA
    native_pacga_restore(c,v);
#endif
#if SNAP_LEAN_TRAPS == 2
    lean_fgt_restore(c,v);
#endif
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->final_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->final_cptr));
    if (!secondary_gic_stop(s)) { s->error=0x102;v->service_fault=SERVICE_BAD_STATE; }
    if (s->error || v->service_fault)
        guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
    s->finish_result=guest_service_finish(&c->services,0);
    if (s->finish_result!=SERVICE_OK) v->service_fault=s->finish_result;
    __atomic_store_n(&s->phase,4,__ATOMIC_RELEASE);
    secondary_power_off(s);
}
/* On q1n1's CPU: run one relayed call. Not live (after an EL2 fault on this
 * CPU, possibly inside q1n1): answer without calling it. */
static void boot_relay_serve(struct context *c, struct boot_relocation *r, uint64_t ticket, int live)
{
    struct boot_relay *q=&r->relay;
    if (!live || !c->params->early_stop.host_call) {
        q->refused++;
        boot_relay_answer(q,ticket,BOOT_RELAY_FAILED);
        return;
    }
    uint64_t (*call)(uint64_t, uint64_t, uint64_t, uint64_t) =
        (uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)c->params->early_stop.host_call;
    uint64_t before,after;
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(before));
    q->in_call=1;
    uint64_t result=call(q->op,q->a1,q->a2,q->a3);
    q->in_call=0;
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(after));
    if (after-before>q->max_ticks) q->max_ticks=after-before;
    q->served++;
    boot_relay_answer(q,ticket,result);
}
/* q1n1's CPU until the target can no longer execute monitor code. */
static void boot_relocation_wait(struct context *c, struct boot_relocation *r, int live)
{
    uint64_t hz=c->params->clock_host_hz,queried=0;
    struct boot_wait w={.off=-1,.launched=r->launch_tick,.arrival=hz,
                        .session=(c->params->watchdog_seconds+60)*hz};
    for (;;) {
        uint64_t ticket;
        if (boot_relay_take(&r->relay,&ticket)) boot_relay_serve(c,r,ticket,live);
        w.phase=__atomic_load_n(&r->record.phase,__ATOMIC_ACQUIRE);
        __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(w.now));
        w.stopped=guest_service_stopped(&c->services)!=0;
        /* AFFINITY_INFO only where it decides, at most once a millisecond. */
        if ((w.phase==4 || (!w.phase && w.now-w.launched>=w.arrival)) && w.now-queried>=hz/1000) {
            w.off=secondary_psci(0xc4000004,r->record.affinity,0,0);
            queried=w.now;
        }
        r->wait_polls++;
        switch (boot_relocate_wait(&w)) {
        case BOOT_WAIT_HANDBACK:
            r->record.affinity_result=(uint64_t)w.off;
            return;
        case BOOT_WAIT_STOP:
            r->stop_requested++;
            guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
            break;
        case BOOT_WAIT_QUARANTINE:
            /* As the report for a peer that never quiesced: never return to q1n1. */
            r->quarantined=1;
            guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
            for (;;) __asm__ volatile("yield":::"memory");
        case BOOT_WAIT_SERVE:
            break;
        }
        __asm__ volatile("yield":::"memory");
    }
}
/* The target is OFF (or never started): q1n1's own registers back into vCPU
 * 0's record for the report, and a prepare result if the guest never ran. */
static void boot_relocation_handback(struct context *c, struct boot_relocation *r)
{
    struct vcpu *v=&c->vcpus[0];
    if (r->captured) {
        const uint64_t *h=r->host;
        v->save_vttbr=h[0];v->save_vtcr=h[1];v->save_vmpidr=h[2];v->save_cntkctl=h[3];
        v->save_cnthctl=h[4];v->save_mdcr=h[5];v->save_mdscr=h[6];v->dbg_oslsr=h[7];
        v->save_ttbr0=h[8];v->save_ttbr1=h[9];v->save_mair=h[10];
    }
    /* A fault inside a relayed q1n1 call ended the run: never re-enter it. */
    if (r->relay.in_call) c->early_stop.host_in_call=1;
    uint64_t *out=(uint64_t *)v->out_ptr;
    if (!out[0] && !out[1]) {
        const struct secondary *s=&r->record;
        out[0]=(uint64_t)(int64_t)(!r->launched ? BOOT_RELOCATE_E_CPU_ON :
            !s->phase ? BOOT_RELOCATE_E_ARRIVAL :
            (int64_t)s->prepare_result<0 ? (int64_t)s->prepare_result : BOOT_RELOCATE_E_TARGET);
    }
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(r->handback_tick));
    __atomic_store_n(&r->handed_back,1,__ATOMIC_RELEASE);
}
/* From _start after the shared preparation: 0 when vCPU 0 stays here (no
 * request); otherwise launch it on the target, serve until it is OFF, hand
 * back, and return 1 for the exit path's report. */
int xnuboot_boot_relocate(void);
int xnuboot_boot_relocate(void)
{
    struct context *c=context_of();
    struct boot_relocation *r=boot_relocation_of(c);
    if (!r) return 0;
    struct secondary *s=&r->record;
    s->affinity_result=(uint64_t)secondary_psci(0xc4000004,s->affinity,0,0);
    if (s->affinity_result==1) {
        r->launched=1;
        publish(c->work_start,c->next_table);
        __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(r->launch_tick));
        int64_t on=secondary_psci(0xc4000003,s->affinity,(uint64_t)secondary_entry,(uint64_t)s);
        s->on_result=(uint64_t)on;   /* not record(): the target may already be logging */
        if (on) {
            /* Only a definite refusal of a CPU that is OFF rules out a start. */
            s->affinity_result=(uint64_t)secondary_psci(0xc4000004,s->affinity,0,0);
            if (s->affinity_result==1 && (on==-1 || on==-2 || on==-3 || on==-9)) r->launched=0;
        }
        if (r->launched) boot_relocation_wait(c,r,1);
    }
    boot_relocation_handback(c,r);
    return 1;
}
/* The report's first step on q1n1's CPU: normally a no-op after the handback.
 * Reached without it, this CPU took an EL2 fault while the target runs: stop
 * it, wait without calling q1n1, then hand back. */
static void boot_relocation_settle(struct context *c)
{
    struct boot_relocation *r=boot_relocation_of(c);
    if (!r || __atomic_load_n(&r->handed_back,__ATOMIC_ACQUIRE)) return;
    if (!boot_relocation_on_boot_cpu(c)) xnuboot_relocated_stop();
    if (r->launched) {
        r->stop_requested++;
        guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
        boot_relocation_wait(c,r,0);
    }
    boot_relocation_handback(c,r);
}
#endif
/* Called with the requesting executor's service token. Success means firmware accepted a real
 * launch, not that the guest completed initialization. No request is retried. */
static int secondary_launch(struct context *c,unsigned slot,uint64_t pc)
{
    unsigned caller=(unsigned)vcpu_of(c)->slot;
    if (!c->host_cpus || !c->secondary_base || !slot || slot>=6 ||
        !(c->host_cpus->mask&(1U<<slot)) || !(c->cpus.registered&(1U<<slot))) return 0;
    struct secondary *s=secondary_of(c,slot);
    if (s->phase || s->on_result!=UINT64_MAX ||
        secondary_psci(0xc4000004,s->affinity,0,0)!=1 ||
        guest_service_reserve(&c->services,caller,slot)!=SERVICE_OK) return 0;
    publish(c->work_start,c->next_table);
    int64_t result=secondary_psci(0xc4000003,s->affinity,(uint64_t)secondary_entry,(uint64_t)s);
    s->on_result=(uint64_t)result;
    record(c,EV_OTHER,pc,UINT64_C(0x534d504f),slot,(uint64_t)result);
    if (!result) return 1;
    int64_t off=secondary_psci(0xc4000004,s->affinity,0,0);
    s->affinity_result=(uint64_t)off;
    guest_service_cancel_launch(&c->services,caller,slot,result,off);
    return 0;
}
struct secondary_request { struct context *context;uint64_t pc; };
static int secondary_release(void *opaque,unsigned slot)
{
    struct secondary_request *request=opaque;
    return secondary_launch(request->context,slot,request->pc);
}
static int secondary_collect(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    if(guest_service_reusable(&c->services))return 1;
    uint64_t hz=c->params->clock_host_hz;
    if(v->slot || !c->secondary_base || hz<1000 || hz>1000000000)goto quarantine;
    uint64_t started=service_profile_clock();
    struct early_stop_state retirement_stop={0};
    const struct a16_thermal_io thermal_io={c,thermal_read,thermal_clock};
    /* CPU0 has finished its executor and its guest timer is off. Bound this
     * wait independently, retaining every unresolved owner/reservation. Only
     * CPU0 writes thermal state; a local stop record avoids shared log/state
     * writes while a peer may still own the service. */
    while (!guest_service_reusable(&c->services)) {
        uint64_t now=service_profile_clock();
        if(now-started>=hz)goto quarantine;
        int thermal_failed=c->thermal && (c->thermal->read_inflight ||
            a16_thermal_poll(c->thermal,&retirement_stop,now,hz,&thermal_io));
        for (unsigned i=1;i<6;i++) {
            uint64_t state=(guest_service_lifecycle(&c->services)>>(i*3))&7;
            if (state!=EXECUTOR_QUIESCED) continue;
            struct secondary *s=secondary_of(c,i);
            uint64_t phase=__atomic_load_n(&s->phase,__ATOMIC_ACQUIRE);
            if(phase==5)goto quarantine; /* CPU_OFF returned, never reusable. */
            if(phase!=4)continue;
            int64_t off=secondary_psci(0xc4000004,s->affinity,0,0);
            s->affinity_result=(uint64_t)off;
            if(off<0 || off>2)goto quarantine;
            if (off==1) guest_service_confirm_off(&c->services,0,i,off);
        }
        /* Still reconcile peers already physically OFF on a thermal stop;
         * do not extend the wait if any owner/reservation remains. */
        if(thermal_failed && !guest_service_reusable(&c->services))goto quarantine;
        __asm__ volatile("yield":::"memory");
    }
    return 1;
quarantine:
    v->service_fault=SERVICE_NOT_QUIESCENT;
    return 0;
}
static int secondary_wait_entry(struct context *c)
{
    if (!c->secondary_base || vcpu_of(c)->slot) return 0;
    for (unsigned i=1;i<6;i++) {
        if (!(c->host_cpus->mask&(1U<<i))) continue;
        struct secondary *s=secondary_of(c,i);
        if (s->on_result || __atomic_load_n(&s->phase,__ATOMIC_ACQUIRE)>=3) continue;
        uint64_t now,deadline;
        __asm__ volatile("mrs %0, cntpct_el0":"=r"(now));
        deadline=now+c->params->clock_host_hz;
        while (__atomic_load_n(&s->phase,__ATOMIC_ACQUIRE)<3 &&
               !guest_service_stopped(&c->services)) {
            __asm__ volatile("mrs %0, cntpct_el0":"=r"(now));
            if ((int64_t)(deadline-now)<=0) {
                vcpu_of(c)->service_fault=SERVICE_TIMEOUT;
                guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
                return 1;
            }
            __asm__ volatile("yield":::"memory");
        }
    }
    return guest_service_stopped(&c->services)!=0;
}

/* ISS layout for a trapped MSR/MRS: Op0[21:20] Op2[19:17] Op1[16:14]
 * CRn[13:10] Rt[9:5] CRm[4:1] Direction[0]. */
#define SYSREG(op0, op1, crn, crm, op2) \
    (((op0) << 20) | ((op2) << 17) | ((op1) << 14) | ((crn) << 10) | ((crm) << 1))
#define ISS_REG(iss)  ((iss) & ~((0x1fUL << 5) | 1UL))
#define ISS_RT(iss)   (((iss) >> 5) & 0x1f)
#define ISS_READ(iss) ((iss) & 1)

static uint64_t clock_counter(void *ctx)
{
    struct context *c = ctx;
    if (!vcpu_of(c)->clock_rate.host_hz || !vcpu_of(c)->clock_rate.guest_hz) return 0;
    uint64_t value;
    /* ISB supplies the ordered read required by the speculative-safe alias.
     * The converted count and all guest deadlines use the declared guest Hz. */
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(value) :: "memory");
#if SNAP_LEAN_TRAPS
    uint64_t guest = lean_rate_sample(&vcpu_of(c)->clock_rate, value);
#else
    uint64_t guest = clock_rate_sample(&vcpu_of(c)->clock_rate, value);
#endif
    if (!vcpu_of(c)->clock_backend_reads++) {
        vcpu_of(c)->clock_raw_first = value;
        vcpu_of(c)->clock_guest_first = guest;
    }
    vcpu_of(c)->clock_raw_last = value;
    vcpu_of(c)->clock_guest_last = guest;
    return guest;
}

static int clock_control(void *ctx, uint64_t value)
{
    struct context *c = ctx;
    guest_event_configure(&vcpu_of(c)->clock_event, value, clock_counter(c));
#if SNAP_NATIVE_WFE
    /* WFE runs natively (TWE clear): the hardware event stream wakes it, its
     * period moved to the host counter rate by the nearest power of two. */
    uint64_t native = clock_event_host_control(value, vcpu_of(c)->clock_rate.host_hz,
                                               vcpu_of(c)->clock_rate.guest_hz);
#else
    /* WFE traps consume coalesced virtual events. Keep native access bits,
     * but never generate an event stream at the unscaled physical rate. */
    uint64_t native = value & ~4UL;
#endif
    __asm__ volatile("msr cntkctl_el1, %0; isb" :: "r"(native) : "memory");
    return 0;
}

static void clock_wfe(struct context *c)
{
    uint64_t now = clock_counter(c), physical;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(physical));
    /* WFE may wake spuriously. Bound an EL2 polling slice to 1 ms so even
     * disabled event streams cannot mask host service for a whole run. */
    uint64_t budget = vcpu_of(c)->clock_rate.host_hz/1000 + 1;
    if (vcpu_of(c)->watchdog_live) {
        uint64_t left = (int64_t)(vcpu_of(c)->watchdog_deadline-physical)>0 ?
                        vcpu_of(c)->watchdog_deadline-physical : 0;
        if (left < budget) budget = left;
    }
    uint64_t ticks = guest_event_wait(&vcpu_of(c)->clock_event, now, UINT64_MAX);
    for (unsigned i=0; i<c->params->model_count; i++)
        ticks = device_model_wait(&c->params->models[i], &c->model_state[i], now, ticks);
    if (ticks != UINT64_MAX)
        budget = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last, now+ticks, budget);
    if (guest_ipi_fiq(&vcpu_of(c)->ipi,guest_timer_pending(&vcpu_of(c)->timer, now)) || vcpu_of(c)->model_irq_pending) budget = 0;
    else if (vcpu_of(c)->timer.ctl == 1)
        budget = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last, vcpu_of(c)->timer.cval, budget);
    uint64_t until = physical+budget, sample=physical;
    while ((int64_t)(until-sample)>0)
        __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(sample));
    vcpu_of(c)->wfe_traps++;
    if (guest_event_consume(&vcpu_of(c)->clock_event, clock_counter(c))) vcpu_of(c)->event_wakes++;
    else vcpu_of(c)->wfe_early++;
    timer_sync(c);
}

#define SR_SCTLR_EL1 SYSREG(3, 0, 1, 0, 0)
#define SR_TTBR0_EL1 SYSREG(3, 0, 2, 0, 0)
#define SR_TTBR1_EL1 SYSREG(3, 0, 2, 0, 1)
#define SR_TCR_EL1   SYSREG(3, 0, 2, 0, 2)
#define SR_MAIR_EL1  SYSREG(3, 0, 10, 2, 0)
#define SR_ESR_EL1   SYSREG(3, 0, 5, 2, 0)
#define SR_FAR_EL1   SYSREG(3, 0, 6, 0, 0)
#define SR_APGAKEYLO_EL1 SYSREG(3, 0, 2, 3, 0)
#define SR_APGAKEYHI_EL1 SYSREG(3, 0, 2, 3, 1)

/* During guest EL1 execution HCR.API/APK remain clear. This trap backend
 * handles kernel PACGA and restores the host key inside one assembly block.
 * EL0 uses the separate scoped pauth_switch bank and native instructions;
 * the batch user-pointer signing service has not yet been connected to it. */
static uint64_t generic_sign(void *opaque, uint64_t data, uint64_t modifier)
{
    struct context *c = opaque;
    uint64_t lo, hi, result;
    __asm__ volatile(
        "mrs %0, s3_0_c2_c3_0\n\t"
        "mrs %1, s3_0_c2_c3_1\n\t"
        "msr s3_0_c2_c3_0, %5\n\t"
        "msr s3_0_c2_c3_1, %6\n\tisb\n\t"
        ".arch_extension pauth\n\tpacga %2, %3, %4\n\t"
        "msr s3_0_c2_c3_0, %0\n\t"
        "msr s3_0_c2_c3_1, %1\n\tisb"
        : "=&r"(lo), "=&r"(hi), "=&r"(result)
        : "r"(data), "r"(modifier), "r"(vcpu_of(c)->guest_apga_lo),
          "r"(vcpu_of(c)->guest_apga_hi) : "memory");
    return result;
}

static int generic_pauth_supported(void)
{
    uint64_t isar1 = id_register(6, 1), isar2 = id_register(6, 2);
    unsigned gpa = (isar1 >> 24) & 15, gpi = (isar1 >> 28) & 15;
    unsigned gpa3 = (isar2 >> 8) & 15;
    return gpa == 1 || gpi == 1 || gpa3 == 1;
}

#if SNAP_NATIVE_PACGA
/* APGAKey := the guest kernel's GA key, the one generic_sign would load. Only
 * while EL1's bank is installed (pauth_switch_leave has run, as it has before
 * any C); the ERET back to the guest synchronizes the write. */
static void native_pacga_load(struct context *c, struct vcpu *v)
{
    __asm__ volatile("msr s3_0_c2_c3_0, %0; msr s3_0_c2_c3_1, %1"
                     :: "r"(v->guest_apga_lo), "r"(v->guest_apga_hi) : "memory");
    c->pauth_bank[v->slot].ga_loads++;
}
/* After an emulated key write: reload only when the GA key changed. */
static void native_pacga_sync(struct context *c, struct vcpu *v, uint64_t lo, uint64_t hi)
{
    if (v->guest_apga_lo != lo || v->guest_apga_hi != hi) native_pacga_load(c, v);
}
/* This CPU's first prepare saves its host APGAKey (private bank, owner =
 * this MPIDR), then loads the guest key and sets HCR_EL2.API for EL1. */
static int native_pacga_prepare(struct context *c, struct vcpu *v)
{
    if (!generic_pauth_supported()) return -29;
    struct pauth_switch *bank = &c->pauth_bank[v->slot];
    uint64_t mpidr, hcr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if (!bank->ga_owner) {
        __asm__ volatile("mrs %0, s3_0_c2_c3_0; mrs %1, s3_0_c2_c3_1"
                         : "=r"(bank->ga_host_lo), "=r"(bank->ga_host_hi));
        bank->ga_owner = mpidr;
    } else if (bank->ga_owner != mpidr) return -29;
    native_pacga_load(c, v);
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
    __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr | (1UL << 41)));
    return 0;
}
/* A terminal path: the saving CPU puts its host APGAKey back, once. */
static void native_pacga_restore(struct context *c, struct vcpu *v)
{
    struct pauth_switch *bank = &c->pauth_bank[v->slot];
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if (!bank->ga_owner || bank->ga_owner != mpidr) return;
    __asm__ volatile("msr s3_0_c2_c3_0, %0; msr s3_0_c2_c3_1, %1; isb"
                     :: "r"(bank->ga_host_lo), "r"(bank->ga_host_hi) : "memory");
    bank->ga_host_lo = bank->ga_host_hi = 0;
    bank->ga_owner = 0;
}
#endif

#if SNAP_LEAN_TRAPS == 2
/* This CPU's TVM/TRVM as FEAT_FGT traps of the same registers, minus ESR_EL1
 * and FAR_EL1 reads and CONTEXTIDR_EL1 writes (compat/lean-trap.h). The host's
 * HFGRTR/HFGWTR/CONTEXTIDR are saved once, owned by this MPIDR. TVM/TRVM are
 * cleared only after both FGT registers read back exactly as written; any
 * other outcome leaves this CPU's traps as they were. EV_OTHER pc 3: a = the
 * HFGRTR_EL2 read back, b = HFGWTR_EL2, c = slot | status << 8. */
static void lean_fgt_prepare(struct context *c, struct vcpu *v)
{
    struct lean_trap_cpu *l = &c->root_ext->lean[v->slot];
    uint64_t mmfr0, mmfr3, mpidr, r = 0, w = 0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    __asm__ volatile("mrs %0, s3_0_c0_c7_3" : "=r"(mmfr3));     /* ID_AA64MMFR3_EL1 */
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    unsigned status = lean_fgt_admit(mmfr0, mmfr3);
    if (status == LEAN_FGT_ACTIVE && l->owner && l->owner != mpidr) status = LEAN_FGT_OWNER;
    if (status == LEAN_FGT_ACTIVE) {
        if (!l->owner) {
            /* HFGRTR_EL2, HFGWTR_EL2 by encoding (FEAT_FGT). */
            __asm__ volatile("mrs %0, s3_4_c1_c1_4; mrs %1, s3_4_c1_c1_5; mrs %2, contextidr_el1"
                             : "=r"(l->host_hfgrtr), "=r"(l->host_hfgwtr), "=r"(l->host_contextidr));
            l->owner = mpidr;
        }
        uint64_t want_r = lean_fgt_read(l->host_hfgrtr), want_w = lean_fgt_write(l->host_hfgwtr);
        __asm__ volatile("msr s3_4_c1_c1_4, %2; msr s3_4_c1_c1_5, %3; isb; "
                         "mrs %0, s3_4_c1_c1_4; mrs %1, s3_4_c1_c1_5"
                         : "=&r"(r), "=&r"(w) : "r"(want_r), "r"(want_w) : "memory");
        if (r != want_r || w != want_w) {
            __asm__ volatile("msr s3_4_c1_c1_4, %0; msr s3_4_c1_c1_5, %1; isb"
                             :: "r"(l->host_hfgrtr), "r"(l->host_hfgwtr) : "memory");
            status = LEAN_FGT_READBACK;
        } else {
            uint64_t hcr;
            __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
            __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr & ~LEAN_HCR_TVM_TRVM));
        }
    }
    l->status = status;
    record(c, EV_OTHER, 3, r, w, v->slot | ((uint64_t)status << 8));
}
/* A terminal path: the saving CPU puts its host FGT registers and CONTEXTIDR
 * back, once. HCR_EL2 is the caller's (q1n1's CPU restores its saved value). */
static void lean_fgt_restore(struct context *c, struct vcpu *v)
{
    struct lean_trap_cpu *l = &c->root_ext->lean[v->slot];
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if (!l->owner || l->owner != mpidr) return;
    __asm__ volatile("msr s3_4_c1_c1_4, %0; msr s3_4_c1_c1_5, %1; msr contextidr_el1, %2; isb"
                     :: "r"(l->host_hfgrtr), "r"(l->host_hfgwtr), "r"(l->host_contextidr) : "memory");
    l->owner = 0;
}
#endif

struct pauth_batch_native { struct pauth_key_pair keys[PAUTH_KEYS]; };
static int pauth_batch_native_sign(void *opaque,const struct pauth_batch_entry *entry,
                                   uint64_t tbi,uint64_t tbid,uint64_t *out)
{
    struct pauth_batch_native *ctx=opaque;
    if(entry->key!=PAUTH_IA && entry->key!=PAUTH_DA)return 0;
    struct pauth_native_request request={entry->pointer,entry->modifier,
        ctx->keys[entry->key].lo,ctx->keys[entry->key].hi,entry->key,tbi,tbid};
    struct pauth_native_result result={0};
    int ok=!pauth_native_user(&request,&result) && result.restored==15 &&
           result.authenticated==entry->pointer;
    if(ok)*out=result.signed_pointer;
    aes_clear(&request,sizeof(request));return ok;
}

static int pauth_pointer_native_sign(void *opaque,const struct pauth_batch_entry *entry,
                                     uint64_t tbi,uint64_t tbid,uint64_t *out)
{
    struct pauth_batch_native *ctx=opaque;
    if(entry->key!=PAUTH_IA && entry->key!=PAUTH_DA)return 0;
    struct pauth_native_request request={entry->pointer,entry->modifier,
        ctx->keys[entry->key].lo,ctx->keys[entry->key].hi,entry->key,tbi,tbid};
    struct pauth_native_result result={0};
    int ok=!pauth_native_sign_user(&request,&result) && result.restored==15 &&
           result.authenticated==0;
    if(ok)*out=result.signed_pointer;
    aes_clear(&request,sizeof(request));return ok;
}

#if SNAP_FAST_PAUTH_CALLS
/* SIGN_USER_POINTER/AUTH_USER_POINTER and BATCH_SIGN_USER_POINTER: the body
 * of monitor_call_impl's cases (whose define-off text is the same statements
 * inline: a default build stays byte-identical), run by those cases and by
 * the converted calls (fine_pauth_pointer, fine_pauth_batch), so the two
 * answers cannot diverge. They read this CPU's TCR_EL1, PAC bank, key operands
 * and derivation cache and write its pauth_pointer or pauth_batch record (a
 * batch also its scratch page, through memory->publish); the rest is
 * boot-fixed (pauth_domain, aes_hardware). The native helpers mask DAIF and
 * restore this PE's TCR/SCTLR_EL2 and key registers. SPTM_BAD_CONFIG with
 * *ran still 0: the configuration refused before anything changed (the
 * derivation refuses without touching its cache); otherwise *ran is 1 and the
 * result is the engine's, which has counted the attempt. */
static enum sptm_result user_pointer_call(struct context *c,const uint64_t *frame,uint32_t endpoint,int *ran)
{
    struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;uint64_t tcr;
    __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
    if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
       !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                 &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
        aes_clear(&native,sizeof(native));return SPTM_BAD_CONFIG;
    }
    *ran=1;
    enum sptm_result result=pauth_pointer(frame[0],frame[1],frame[2],
        endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,
        pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);
    aes_clear(&native,sizeof(native));
    return result;
}
static enum sptm_result user_pointer_batch(struct context *c,const struct sptm_memory *memory,
                                           const uint64_t *frame,const struct guest_cpu_buffer *scratch,int *ran)
{
    struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;uint64_t tcr;
    __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
    if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
       !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                 &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
        aes_clear(&native,sizeof(native));return SPTM_BAD_CONFIG;
    }
    *ran=1;
    enum sptm_result result=pauth_batch_sign(memory,&c->pauth_batch[v->slot],
        frame[0],frame[1],scratch->pa,scratch->va,(tcr>>37)&1,(tcr>>51)&1,
        pauth_batch_native_sign,&native);
    aes_clear(&native,sizeof(native));
    return result;
}
#endif

int xnuboot_pauth_failed(const uint64_t *frame);
int xnuboot_pauth_failed(const uint64_t *frame)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    v->service_fault=0x504143;
    fill_regs(&v->async_regs,frame,0,frame[32],0);v->async_captured=1;
    guest_service_stop(&c->services,v->slot,SERVICE_STOP_FAULT);
    watchdog_off(c);return 1;
}

/* Called after C handling but before restoring the guest's register frame.
 * Every exception path restores keys in assembly before it calls any C
 * (SNAP_PAUTH_EL0_LIVE: except sync_lower's EL0-read entry, which
 * el0_live_trap answers or restores before any other C).
 * All C here is built without PAC prologues and uses general registers only. */
int xnuboot_pauth_resume(const uint64_t *frame);
int xnuboot_pauth_resume(const uint64_t *frame)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct pauth_switch *bank=&c->pauth_bank[v->slot];uint64_t spsr;
#if SNAP_PAUTH_EL0_LIVE
    /* el0_live_trap answered an EL0 read with the EL0 bank still installed (the
     * only way the bank is live here): EL0 resumes with it, exactly as it ran,
     * without a key check or an enter (no EL1 instruction ran, so the key
     * operands and enables are the ones installed); never EL1. */
    int live=bank->active==1 && !bank->failures;
    if(!live && (bank->failures || bank->active))return xnuboot_pauth_failed(frame);
#else
    if(bank->failures || bank->active)return xnuboot_pauth_failed(frame);
#endif
    __asm__ volatile("mrs %0,spsr_el2":"=r"(spsr));
#if SNAP_PAUTH_EL0_LIVE
    if(live && (spsr&31))return xnuboot_pauth_failed(frame);
#endif
    if(spsr&31) {FAST_EXIT_END(c,v,frame);return 0;}
#if SNAP_PAUTH_EL0_LIVE
    if(!live) {
#endif
    struct pauth_user_state *state=&c->user_pauth[v->slot];
    if(!c->pauth_key_valid[v->slot] || c->pauth_key_version[v->slot]!=state->writes) {
#if SNAP_EL0_MEMO
        /* Behind the 8-entry memo, this vCPU's second level (both flushed when
         * the domain epoch moves). */
        if(!pauth_domain_user_cached_wide(&c->pauth_domain,state,&c->pauth_derive[v->slot],
                                          &c->root_ext->derive_wide[v->slot],c->root_ext->pauth_epoch,
                                          bank->guest,(int)c->aes_hardware))
#else
        if(!pauth_domain_user_cached(&c->pauth_domain,state,&c->pauth_derive[v->slot],
                                     bank->guest,(int)c->aes_hardware))
#endif
            return xnuboot_pauth_failed(frame);
        c->pauth_key_version[v->slot]=state->writes;
        c->pauth_key_valid[v->slot]=1;
    }
    bank->enables=v->guest_sctlr&0xc8002000UL;
    if(pauth_switch_enter(bank))return xnuboot_pauth_failed(frame);
#if SNAP_PAUTH_EL0_LIVE
    }
#endif
    FAST_EXIT_END(c,v,frame);
    return 0;
}

static struct sptm_root_cached *user_cached(struct context *c,uint64_t root)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
        if(c->user_roots.cache[i].root==root && c->user_roots.cache[i].valid)
            return &c->user_roots.cache[i];
    return 0;
}
static struct sprr_views *user_views(struct context *c,struct sptm_root_cached *e)
{return &UVIEWS(c)[e-c->user_roots.cache];}
static int user_private_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;uint64_t old;
    if(kernel_table_read(c,pa,&old))return -1;
    if(old==value)return 0;
    /* A shared table path may become private while another CPU executes.
     * Break a valid output-address change before making its replacement. */
    if((old&1) && (value&1) && ((old^value)&PT_OA_MASK)) {
        if(kernel_table_write(c,pa,0))return -1;
        publish(pa,pa+8);
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        c->shadow_tlb_syncs++;
    }
    return kernel_table_write(c,pa,value);
}
static struct shadow user_shadow(struct context *c,struct sptm_root_cached *e)
{
    return (struct shadow){.txsz=17,.root=e->shadow,.alloc=user_table_alloc,
        .read=kernel_table_read,.write=user_private_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
}
/* Keep user_shadow's allocator canonical for shared and unnest commits. Only
 * sprr_views operations allocate permission copies through this constructor. */
static struct shadow user_view_shadow(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_shadow(c,e);s.alloc=private_user_alloc;return s;
}
#if SNAP_NATIVE_TABLES
/* UMPRR of a cached root, exactly as sprr_root_reset derives it. */
static uint64_t native_umprr(const struct sptm_root_cached *e)
{return ((uint64_t)(e->flags&8)<<15)|((uint64_t)(e->flags&1)<<11);}
/* Monitor-owned hardware ASIDs, never XNU's: one per (slot, w, k). The
 * kernel root keeps ASID 0. A slot's are flushed when it is released
 * (root_slot_release's all-VMID invalidation). */
static uint64_t native_asid(unsigned slot,unsigned w,unsigned k)
{return 0x100UL+4UL*slot+2UL*w+k;}
/* 1 in 2^SNAP_NATIVE_AUDIT_SHIFT calls, counted in *asks. */
static int native_due(uint64_t *asks)
{return !((*asks)++&((UINT64_C(1)<<SNAP_NATIVE_AUDIT_SHIFT)-1));}
static int native_page(const struct context *c,uint64_t pa,uint64_t *index)
{
    if(pa<c->work_base || pa>=c->next_table)return 0;
    *index=(pa-c->work_base)/4096;return *index<MONITOR_ARENA_PAGES;
}
static int native_source(const struct context *c,uint64_t index)
{return !!(c->native_sources[index/64]&(UINT64_C(1)<<(index%64)));}
/* Mark or clear every table of v whose stores reach variant copies. */
static void native_mark(struct context *c,const struct sprr_views *v,int set)
{
    for(unsigned n=0;n<v->count && n<SPRR_VIEW_TABLES;n++) {
        uint64_t i;
        if(!native_page(c,v->tables[n].source,&i))continue;
        if(set)c->native_sources[i/64]|=UINT64_C(1)<<(i%64);
        else c->native_sources[i/64]&=~(UINT64_C(1)<<(i%64));
    }
}
/* mem_write, before the store. Nonzero refuses it (terminal). Kernel
 * tables, and a user root whose variants do not exist yet (built, never
 * installed; its first install derives them), take raw TPRO as before. */
static int native_store_admit(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i))return 0;
    /* A shared group is reachable from every nesting root and variant. */
    if(c->table_pool.owner[i]==NATIVE_SHARED_OWNER && (value&1) && sprr_pte_class(value)==9) {
        c->native_stats.refused++;c->user_view_failed=1;return 1;
    }
    int source=native_source(c,i);
    if(!source && (!(value&1) || sprr_pte_class(value)!=9))return 0;
    unsigned owner=c->table_pool.owner[i];
    const struct sprr_views *v=owner && owner<=SPTM_ROOT_CACHE ? &UVIEWS(c)[owner-1] : 0;
    if(!source && (!v || !v->count))return 0;
    /* A source always belongs to a root with variants (native_mark). */
    if(source && v && v->count &&
       native_views_admit(v,pa,value,native_umprr(&c->user_roots.cache[owner-1])))return 0;
    c->native_stats.refused++;c->user_view_failed=1;return 1;
}
/* Variant copies are hardware-walked while other CPUs run: each store is
 * cleaned at once, as user_live_write does for canonical stores, so the
 * TLBI that completes the call finds both in memory. The zeroing of a new
 * copy is cleaned before anything can link it. */
static int native_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=user_private_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static uint64_t native_live_alloc(void *ctx)
{
    uint64_t pa=private_user_alloc(ctx);
    if(pa)publish(pa,pa+4096);
    return pa;
}
static struct shadow native_live_shadow(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_view_shadow(c,e);
    s.alloc=native_live_alloc;s.write=native_copy_write;return s;
}
/* mem_write, after the store: the same entry of both variant copies. */
static int native_store_propagate(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i) || !native_source(c,i))return 0;
    unsigned owner=c->table_pool.owner[i];
    if(!owner || owner>SPTM_ROOT_CACHE) {c->user_view_failed=1;return 1;}
    struct sptm_root_cached *e=&c->user_roots.cache[owner-1];
    struct shadow s=native_live_shadow(c,e);
    if(!native_views_store(&UVIEWS(c)[owner-1],&s,pa,value,native_umprr(e))) {
        c->user_view_failed=1;return 1;
    }
    c->native_stats.propagated++;return 0;
}
/* Invalidate [va, va+size) of the EL1&0 regime by VA for every ASID (every
 * variant, every address space) in every guest CPU's VMID: stage 2 is per
 * CPU, and a stage-1 TLBI names only the current VMID. Larger ranges drop
 * each VMID's stage-1 entries instead. */
#define NATIVE_TLBI_PAGES 64u
static void native_tlbi_range(struct context *c,uint64_t va,uint64_t size)
{
    uint64_t first=va>>12,pages=(size+4095)>>12,saved;
    int all=!pages || pages>NATIVE_TLBI_PAGES;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        if(all)__asm__ volatile("tlbi vmalle1is" ::: "memory");
        else for(uint64_t n=0;n<pages;n++)
            __asm__ volatile("tlbi vaae1is, %0" :: "r"((first+n)&((UINT64_C(1)<<44)-1)) : "memory");
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    c->native_stats.tlbi_calls++;
    if(all)c->native_stats.tlbi_full++;else c->native_stats.tlbi_pages+=pages;
    c->shadow_tlb_syncs++;
}
/* The kernel PPERM snapshot in audit mode. Its identity -- valid, root,
 * count, the six PPERMs and every copy identity -- is checked on every
 * transaction, and the exact re-read of every source word runs 1 in
 * 2^SNAP_NATIVE_AUDIT_SHIFT times. Every canonical kernel change refreshes the
 * copies and re-saves the snapshot (shadow_tlb_sync) before another PPERM
 * transaction can run, so identity without equal words is a broken
 * invariant: terminal. 1 means current (proved or sampled away). */
static int native_reuse_current(struct context *c,const struct shadow *ks,const uint64_t *pp)
{
    const struct sprr_reuse_state *r=&c->kernel_reuse_state;
    const struct sprr_views *v=&c->kernel_views;
    if(!sprr_reuse_configured(v,ks,pp) || !r->valid || r->root!=ks->root || r->count!=v->count)
        return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(r->pperm[cpu]!=pp[cpu])return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&r->tables[n],*b=&v->tables[n];
        if(a->source!=b->source || a->level!=b->level)return 0;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(a->copy[cpu]!=b->copy[cpu])return 0;
    }
    if(!native_due(&c->native_stats.reuse_asks))return 1;
    c->native_stats.reuse_checks++;
    if(sprr_reuse_current(r,v,ks,pp)==1)return 1;
    c->native_stats.reuse_failures++;c->kernel_view_failed=1;return 0;
}
/* SWITCH_ROOT audit mode: walk 1 in 2^SNAP_NATIVE_AUDIT_SHIFT cache hits. */
static int native_skip_hit(void *ctx)
{
    struct context *c=ctx;
    if(native_due(&c->native_stats.hit_asks))return 0;
    c->native_stats.hit_skips++;return 1;
}
#define NATIVE_SKIP_HIT native_skip_hit
#else
#define NATIVE_SKIP_HIT 0
#endif
#if SNAP_NATIVE_TABLES
/* Copy the paths of a TPRO leaf's 4K parts before its raw canonical store.
 * Every copy store is cleaned in program order (native_live_shadow): a new
 * copy is zeroed and filled in memory before the one store that links it,
 * and that link (a table-address change, so user_private_write breaks it
 * first) is in memory before the range is invalidated. After that no walk,
 * cached or new, reaches the shared table the path replaced, and the raw
 * leaf can be stored. No variants exist before a root's first install; its
 * sync derives them. */
static int native_prepare_tpro(struct context *c,struct sptm_root_cached *e,
                               uint64_t va,unsigned shift)
{
    struct sprr_views *v=&UVIEWS(c)[e-c->user_roots.cache];
    if(!v->count)return 1;
    struct shadow live=native_live_shadow(c,e);
    int linked=0;
    for(uint64_t off=0;off<(UINT64_C(1)<<shift);off+=4096) {
        int r=native_views_prepare_leaf(v,&live,va+off,native_umprr(e));
        if(!r) {c->user_view_failed=1;return 0;}
        linked|=r==2;
    }
    native_mark(c,v,1);
    if(linked) {c->native_stats.paths++;native_tlbi_range(c,va,UINT64_C(1)<<shift);}
    return 1;
}
#endif
#if SNAP_NATIVE_SHARED
static int user_source_read(void *,uint64_t,uint64_t *);
_Static_assert(NATIVE_SHARED_OWNER>SPTM_ROOT_CACHE && NATIVE_SHARED_OWNER<TABLE_POOL_FREE,
               "shared group allocation domain");
/* Group pages are walked by every nesting root: cleaned when allocated and on
 * every store, as user_live_alloc/user_live_write do for a live root. */
static uint64_t native_group_alloc(void *ctx)
{
    uint64_t pa=table_alloc_owned(ctx,NATIVE_SHARED_OWNER);
    if(pa)publish(pa,pa+4096);
    return pa;
}
static int native_group_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static struct shadow native_group_shadow(struct context *c)
{
    return (struct shadow){.txsz=17,.alloc=native_group_alloc,.read=kernel_table_read,
        .write=native_group_write,.ctx=c};
}
/* No root links a freed group, and each unlink already invalidated. */
static void native_group_release(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    uint32_t used=(uint32_t)((c->next_table-c->work_base)/4096);
    if(pa<c->work_base || table_pool_release_one(&c->table_pool,used,
            (uint32_t)((pa-c->work_base)/4096),NATIVE_SHARED_OWNER))
        c->user_view_failed=1;
}
_Static_assert(SPTM_ROOT_CACHE<=NATIVE_SHARED_SLOTS,"a link bit per cached slot");
/* Before group g is freed with its guest table: a cached slot that is no
 * longer valid (invalidated, evicted or retired; its tree is kept until the
 * slot is reused) may still link it, since UNNEST of an uncached root leaves
 * that stale tree alone. Such a tree is derived state: the slot goes now. A
 * valid slot still linking g would name a table the guest is detaching. */
static int native_group_unlinked(struct context *c,int g)
{
    struct native_shared *ns=&UNS(c);
    for(unsigned s=0;s<SPTM_ROOT_CACHE;s++)if(NATIVE_SHARED_SLOT_HAS(ns->group[g].slots,s)) {
        struct sptm_root_cached *e=&c->user_roots.cache[s];
        if(e->valid || (e->root && vcpu_root_busy(c,e->root)) ||
           !sptm_root_reclaim_forget(&c->user_roots,s) || root_slot_release(c,s,1)<0)return 0;
        ns->stale++;
    }
    return !NATIVE_SHARED_SLOTS_ANY(ns->group[g].slots);
}
static uint64_t native_no_alloc(void *ctx) {(void)ctx;return 0;}
/* A linking slot's canonical tree for native_shared_grow: allocation-free,
 * each store cleaned (user_live_write), as the NEST commit writes links. */
static int nl_tree(void *ctx,unsigned slot,struct shadow *out)
{
    struct context *c=ctx;
    if(slot>=SPTM_ROOT_CACHE || !c->user_roots.cache[slot].shadow)return -1;
    struct sptm_root_cached *e=&c->user_roots.cache[slot];
    *out=(struct shadow){.txsz=17,.root=e->shadow,.alloc=native_no_alloc,.read=mem_read,
        .write=user_live_write,.ctx=c,.alloc_ctx=&UOWNERS(c)[slot],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    return 0;
}
/* The shared root a user root is bound to (its nested tables' owner), or 0. */
static uint64_t native_shared_root_of(struct context *c,uint64_t root)
{
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,root) || !m.shared_regions)return 0;
    volatile uint8_t *u=m.map(m.ctx,m.frame_map_pa+((root-m.frame_low)>>14)*16,16);
    return u && u[8]<SPTM_MAC_SHARED_ROOT_LIMIT ? m.shared_regions->slots[u[8]].root : 0;
}
static int nl_group(void *ctx,uint64_t child,uint64_t va)
{
    struct native_links *l=ctx;struct native_shared *ns=&UNS(l->c);
    int g=native_shared_find(ns,child);
    if(g>=0)return ns->group[g].va==va && ns->group[g].shared==l->shared ? g : -1;
    if(!l->shared)return -1;
    struct shadow w=native_group_shadow(l->c);
    return native_shared_create(ns,&w,l->shared,child,va,user_source_read,l->c,native_group_release,l->c);
}
#if SNAP_ROOT_MISS_FAST
/* Read-only: nl_group will find child's group rather than create (and fill)
 * one, so a linked build copies none of child's leaves (compat/root-miss.h). */
static int nl_grouped(void *ctx,uint64_t child,uint64_t va)
{
    struct native_links *l=ctx;(void)va;
    return native_shared_find(&UNS(l->c),child)>=0;
}
#endif
static int nl_find(struct native_links *l,uint64_t child,uint64_t va)
{
    int g=native_shared_find(&UNS(l->c),child);
    return g>=0 && UNS(l->c).group[g].va==va ? g : -1;
}
static int nl_link(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    struct native_links *l=ctx;int g=nl_find(l,child,va);
    if(g<0 || !native_shared_link(&UNS(l->c),l->s,l->slot,g))return 0;
    *leaves=UNS(l->c).group[g].leaves;return 1;
}
static int nl_linked(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    struct native_links *l=ctx;int g=nl_find(l,child,va);
    if(g<0 || !native_shared_slot_links(&UNS(l->c),l->slot,g) ||
       !native_shared_linked(&UNS(l->c),l->s,g))return 0;
    *leaves=UNS(l->c).group[g].leaves;return 1;
}
static int nl_unlink(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    struct native_links *l=ctx;int g=nl_find(l,child,va);
    if(g<0)return 0;
    *leaves=UNS(l->c).group[g].leaves;
    return native_shared_unlink(&UNS(l->c),l->s,l->slot,g);
}
static struct sptm_root_links native_links_for(struct native_links *l)
{return (struct sptm_root_links){nl_group,nl_link,nl_linked,nl_unlink,l};}
/* The group mirroring the shared table under va of 16K shared root `shared`
 * (-1 when none exists yet) and that table's PA; 0 when no table is there. */
static int native_group_at(struct context *c,uint64_t shared,uint64_t va,int *g,uint64_t *child)
{
    struct sptm_memory m=sptm_context_memory(c);
    *child=sptm_root_shared_child(&m,shared,va);
    *g=*child ? native_shared_find(&UNS(c),*child) : -1;
    return *child!=0;
}
/* Every cached root aliasing the range links group g (so needs no write). */
static int native_aliases_link(struct context *c,sptm_root_mask_t mask,int g)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct shadow s=user_shadow(c,&c->user_roots.cache[i]);
        if(g<0 || !native_shared_slot_links(&UNS(c),i,g) ||
           !native_shared_linked(&UNS(c),&s,g))return 0;
    }
    return 1;
}
/* Before a shared-root leaf change of count pages from va: every aliasing
 * root links its group and each group holds the current guest leaves. */
static int native_shared_prepare(struct context *c,uint64_t shared,uint64_t va,unsigned shift,
                                 uint64_t count,sptm_root_mask_t mask,uint64_t next)
{
    struct shadow w=native_group_shadow(c);
    const struct native_shared_roots roots={nl_tree,c};
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+(n<<shift),child,guest;int g;
        /* No shared table there (an UNMAP the SPTM skips as TABLE_MISSING): no
         * guest leaf and no group, so no root may alias it. */
        if(!native_group_at(c,shared,addr,&g,&child)) {
            if(SPTM_ROOT_MASK_ANY(mask))return 0;
            continue;
        }
        if(user_source_read(c,child+8*((addr>>14)&2047),&guest) || !native_aliases_link(c,mask,g) ||
           (g>=0 && !native_shared_holds(&UNS(c),&w,g,addr,guest)))return 0;
        /* A new leaf's 2 MiB gets its page, linked into every linking tree,
         * before the guest store (nothing is mapped there yet). */
        if(g>=0 && (next&1) && !native_shared_grow(&UNS(c),&w,g,addr,&roots))return 0;
    }
    return 1;
}
/* After it: write each group once (next[n], or 0 without next). */
static int native_shared_commit(struct context *c,uint64_t shared,uint64_t va,unsigned shift,
                                uint64_t count,const struct sptm_shared_update_entry *entries,
                                uint64_t next)
{
    struct shadow w=native_group_shadow(c);
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+(n<<shift),child;int g;
        if(entries && entries[n].old==entries[n].next)continue;
        /* Without a shared table nothing is mirrored (prepare: no alias). */
        if(!native_group_at(c,shared,addr,&g,&child)) {
            if(next || entries)return 0;
            continue;
        }
        if(g>=0 && !native_shared_store(&UNS(c),&w,g,addr,entries ? entries[n].next : next))
            return 0;
    }
    return 1;
}
#endif
/* The table this CPU's hardware walks for cached root e. */
static uint64_t user_hw_root(struct context *c,struct sptm_root_cached *e,unsigned cpu)
{
#if SNAP_USER_HW_WALK
    /* A hardware-walk root's identity entry: the installed variant's table
     * (the guest root or a copy of it). */
    if(hw_walk_of_entry(c->hw_walk,e)) {
        const struct native_cpu *n=&c->native_cpu[cpu];
        return n->installed && n->w<2 ? n->ttbr0[n->w][n->k&1]&PT_OA_MASK : 0;
    }
#endif
#if SNAP_NATIVE_TABLES
    const struct native_cpu *n=&c->native_cpu[cpu];
    return n->installed && n->w<2 ? native_views_root(&UVIEWS(c)[e-c->user_roots.cache],n->w) : 0;
#else
    return sprr_views_root(&UVIEWS(c)[e-c->user_roots.cache],cpu);
#endif
}
static void user_tlb_sync(struct context *c)
{
    __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
    c->shadow_tlb_syncs++;
}
/* These four commits touch only a user shadow and its private views. Their
 * prepare/commit callbacks cannot change a kernel mapping or PPERM. Retyping
 * and kernel transactions finish their own kernel refresh before returning.
 * Keep the same all-VMID hardware invalidation, including inactive roots and
 * before reference release, without rebuilding unchanged kernel copies. */
#if !SNAP_NATIVE_TABLES
static int user_commit_tlb_sync(struct context *c,unsigned kind)
{
    if(kind>=4 || c->kernel_view_failed || c->user_view_failed)return 0;
#if SNAP_USER_ONLY_TLBI
    user_tlb_sync(c);sprr_count(&c->user_only_tlbi[kind]);
#else
    shadow_tlb_sync(c);
#endif
    return !c->kernel_view_failed && !c->user_view_failed;
}
#endif
/* The same completion for a known VA range. Native tables invalidate exactly
 * that range (size 0: everything) in every VMID; the counters are kept. */
static int user_commit_tlb_range(struct context *c,unsigned kind,uint64_t va,uint64_t size)
{
#if SNAP_NATIVE_TABLES
    if(kind>=4 || c->kernel_view_failed || c->user_view_failed)return 0;
    native_tlbi_range(c,va,size);
#if SNAP_USER_ONLY_TLBI
    sprr_count(&c->user_only_tlbi[kind]);
#endif
    return !c->kernel_view_failed && !c->user_view_failed;
#else
    (void)va;(void)size;return user_commit_tlb_sync(c,kind);
#endif
}
static void user_tlb_range(struct context *c,uint64_t va,uint64_t size)
{
#if SNAP_NATIVE_TABLES
    native_tlbi_range(c,va,size);
#else
    (void)va;(void)size;user_tlb_sync(c);
#endif
}
#if SNAP_USER_HW_WALK
/* --- SNAP_USER_HW_WALK glue (compat/user-hw-walk.h) ----------------------
 * Copies live in arena pages of their own pool domain; guest tables are read
 * where the SPTM wrote them. Every store into a copy is cleaned before the
 * walker can need it; invalidation is native_tlbi_range (every VMID). */
static int hw_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table)return -1;
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static uint64_t hw_copy_alloc(void *ctx)
{
    uint64_t pa=table_alloc_owned(ctx,HW_WALK_OWNER);
    if(pa)publish(pa,pa+4096);
    return pa;
}
static void hw_copy_release(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    /* A page that cannot be given back is a broken invariant: terminal. */
    if(pa<c->work_base || pa>=c->next_table || (pa&4095) ||
       table_pool_release_one(&c->table_pool,(uint32_t)((c->next_table-c->work_base)/4096),
                              (uint32_t)((pa-c->work_base)/4096),HW_WALK_OWNER))
        c->user_view_failed=1;
}
static int hw_table_read(void *ctx,uint64_t pa,uint64_t *out)
{
    struct context *c=ctx;
    if(pa&7)return -1;
    if(pa>=c->work_base && pa<c->next_table)return mem_read(ctx,pa,out);
    volatile uint8_t *p=sptm_map(ctx,pa,8);
    if(!p)return -1;
    *out=*(volatile uint64_t *)p;return 0;
}
static int hw_table_type(void *ctx,uint64_t table)
{
    struct context *c=ctx;struct sptm_memory m=sptm_context_memory(c);
    uint64_t frame=table&~UINT64_C(0x3fff);
    if(!sptm_managed_frame(&m,frame))return -1;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((frame-m.frame_low)>>14)*16,16);
    return meta ? meta[2] : -1;
}
static struct hw_walk_ops hw_ops(struct context *c)
{return (struct hw_walk_ops){hw_table_read,hw_copy_write,hw_copy_alloc,hw_copy_release,hw_table_type,c};}
static void hw_tlb_range(void *ctx,uint64_t va,uint64_t size){native_tlbi_range(ctx,va,size);}
static struct hw_walk_root *hw_root(struct context *c,uint64_t root){return hw_walk_find(c->hw_walk,root);}
/* The identity runtime paths read for an active root that has no cache
 * entry: its hardware-walk record's, or 0. */
static struct sptm_root_cached *hw_record_entry(struct context *c,uint64_t root)
{
    struct hw_walk_root *r=hw_root(c,root);
    return r ? &r->entry : 0;
}
static int hw_fail(struct context *c){c->user_view_failed=1;return 0;}
static int hw_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);
    if(!r || shift!=12)return 0;
    if(sprr_pte_class(pte)!=9)return 1;
    struct hw_walk_ops o=hw_ops(c);struct hw_walk_tlb t={hw_tlb_range,c};
    return hw_walk_before_tpro(&o,r,va,UINT64_C(1)<<shift,&t,&c->hw_walk->stats);
}
static int hw_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    (void)pte;
    if(!r || !hw_walk_after_add(&o,r,va,UINT64_C(1)<<shift,&c->hw_walk->stats))return hw_fail(c);
    c->user_live_pages++;return 1;
}
static int hw_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)va;(void)count;return hw_root(ctx,root) && shift==12;}
static int hw_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};
    if(!r || !hw_walk_after_change(&o,r,va,count<<shift,&t,&c->hw_walk->stats))return hw_fail(c);
    c->user_unmap_calls++;c->user_unmap_pages+=removed;return 1;
}
static int hw_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);
    if(!r || shift!=12)return 0;
    if(sprr_pte_class(next)!=9 || sprr_pte_class(old)==9)return 1;
    struct hw_walk_ops o=hw_ops(c);struct hw_walk_tlb t={hw_tlb_range,c};
    return hw_walk_before_tpro(&o,r,va,UINT64_C(1)<<shift,&t,&c->hw_walk->stats);
}
static int hw_prepare_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{(void)va;(void)level;(void)removed;return hw_root(ctx,root) && shift==12;}
static int hw_commit_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};(void)shift;(void)removed;
    if(!r || level>2 || !hw_walk_after_unlink(&o,r,va,4*hw_walk_span(level),&t,&c->hw_walk->stats))
        return hw_fail(c);
    c->user_detach_calls++;return !c->user_view_failed;
}
static int hw_prepare_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{(void)va;(void)child;return hw_root(ctx,root) && shift==12;}
static int hw_commit_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};(void)shift;(void)child;
    uint64_t span=4*hw_walk_span(2);
    if(!r || !hw_walk_after_change(&o,r,va&~(span-1),span,&t,&c->hw_walk->stats))return hw_fail(c);
    c->user_comm_attach_calls++;return 1;
}
static int hw_prepare_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{(void)shared;(void)va;(void)pages;return hw_root(ctx,root) && shift==12;}
/* NEST links empty level-2 slots: nothing to invalidate (compat/user-hw-walk.h). */
static int hw_commit_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    if(!r || !hw_walk_after_add(&o,r,va,pages<<shift,&c->hw_walk->stats))return hw_fail(c);
    uint64_t span=UINT64_C(1)<<(2*shift-3),last=va+((pages-1)<<shift);
    struct sptm_nest_state *n=&c->nest_state;
    n->calls++;n->descriptors+=last/span-va/span+1;
    n->root=root;n->shared=shared;n->va=va;n->pages=pages;
    n->first=va&~(span-1);n->last=(last&~(span-1))+span;
    return 1;
}
static int hw_prepare_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                             const struct sptm_unnest_plan *plan)
{(void)shared;(void)plan;return hw_root(ctx,root) && shift==12;}
static int hw_commit_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                            const struct sptm_unnest_plan *plan)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};
    if(!r || !hw_walk_after_unlink(&o,r,plan->base,plan->span*plan->count,&t,&c->hw_walk->stats))
        return hw_fail(c);
    c->unnest_calls++;c->unnest_descriptors+=plan->descriptors;c->unnest_leaves+=plan->leaves;
    c->unnest_root=root;c->unnest_shared=shared;c->unnest_format=shift==12;
    return !c->user_view_failed;
}
/* MAP_TABLE and (UN)CONDEMN store table descriptors without a callback. */
static int hw_after_table(struct context *c,uint64_t root,uint64_t va,unsigned level)
{
    struct hw_walk_root *r=hw_root(c,root);
    if(!r)return 1;
    struct hw_walk_ops o=hw_ops(c);uint64_t span=4*hw_walk_span(level>2 ? 2 : level);
    return hw_walk_after_add(&o,r,va&~(span-1),span,&c->hw_walk->stats) || hw_fail(c);
}
/* Before a UPERM write or TPRO PPERM change, in place of the canonical-view
 * proof: the copies are exact, and 1 in 4096 also the whole private tree. */
static int hw_entry_proof(struct context *c,const struct sptm_root_cached *e,struct sptm_fixed_view *out)
{
    struct hw_walk_root *r=hw_walk_of_entry(c->hw_walk,e);
    if(!r)return 0;
    struct hw_walk_ops o=hw_ops(c);unsigned tables=0;
    int deep=!(c->hw_walk->stats.proofs++&4095);
    c->hw_walk->stats.verifies++;
    if(!hw_walk_verify(&o,r,deep,&tables)) {c->hw_walk->stats.verify_failures++;return 0;}
    out->tables=deep ? tables : r->count;out->pages=r->count;out->classes=0;
    return 1;
}
/* SWITCH_ROOT (compat/sptm-root.c hw_eligible; user_root_install then gets
 * shadow 0). A format-1 root with a record, or one that has no cached shadow
 * and gets a record now. */
static int hw_switch_eligible(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned asid,
                              unsigned format,unsigned flags)
{
    struct context *c=ctx;(void)m;
    if(format!=1)return 0;
    struct hw_walk_root *r=hw_root(c,root);
    if(r)return r->entry.asid==asid && r->entry.flags==flags ? 1 : -1;
    if(user_cached(c,root))return 0;          /* a shadow keeps this root for its lifetime */
    struct hw_walk_ops o=hw_ops(c);
    if(!hw_walk_attach(c->hw_walk,&o,root,asid,flags)) {c->hw_walk->stats.fallbacks++;return 0;}
    return 1;
}
/* user_root_install's user-root transaction for a record's TTBR0 values,
 * after its PPERM reset: the native variant selection (w from UPERM), the
 * same register sequence, shared-region flush and installed-state records. */
static void hw_install_user(struct context *c,uint64_t root,uint64_t asid,unsigned format)
{
    struct vcpu *v=vcpu_of(c);
    struct hw_walk_root *r=hw_root(c,root);
    if(!r || format!=1 || r->entry.asid!=asid) {c->root_install_failures++;return;}
    unsigned flags=(unsigned)r->entry.flags;
    struct sprr_state initial={0};sprr_root_reset(&initial,flags);
    struct native_cpu *n=&c->native_cpu[v->slot];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)ttbr0[w][k]=hw_walk_ttbr0(r,w);
    uint64_t ttbr=native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0);
    if(!ttbr) {c->user_view_failed=1;c->root_install_failures++;return;}
    c->native_stats.installs++;c->hw_walk->stats.installs++;
    struct user_view_state *u=&c->user_view_state[v->slot];
    u->root=root;u->shadow=ttbr&PT_OA_MASK;u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    v->guest_tcr=SPTM_ROOT_TCR_4K|(1UL<<36);
    v->guest_sctlr=pauth_root_enables(v->guest_sctlr,flags);
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    /* Copies were cleaned as written; other noted arena pages as for every
     * installation (requires SNAP_ROOT_DIRTY_PUBLISH, asserted above). */
#if SNAP_ROOT_PUBLISH_BATCH_DSB
    int (*page)(void *,uint64_t)=publish_page_lines;
#else
    int (*page)(void *,uint64_t)=root_publish_page;
#endif
#if SNAP_INCREMENTAL_PUBLISH
    if(!root_index_flush(&c->root_publish,&c->perf.root_index,c->work_base,c->next_table,page,c)) {
#else
    if(!root_publish_flush(&c->root_publish,c->work_base,c->next_table,page,c)) {
#endif
        __asm__ volatile("dsb ish" ::: "memory");
        install_failed(c,0);return;
    }
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    struct sptm_memory memory=sptm_context_memory(c);
    int region=sptm_mac_root_shared_slot(&memory,root);
    if(live_tcr==tcr) {
        /* Kernel root (ASID 0, global low entries) to a user root, or a
         * different shared region's global entries: drop them locally. */
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
        uint16_t last=c->user_shared_slot[v->slot];
        int shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            c->native_stats.local_flushes++;
            if(shared_flush)c->shared_switch_flushes[v->slot]++;
            c->user_shared_slot[v->slot]=0;
        }
    } else
        __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                         "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                         :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)c->root_install_failures++;
    v->guest_ttbr0=root|(asid<<48);
    c->shadow_tlb_syncs++;
}
/* Stage 2: a retyped page-table frame read-only (ro) or RW again in every
 * vCPU's tree, then every VMID forgets it: stage 2 by IPA, then the frame's
 * aperture aliases (the only stage-1 mappings a typed frame keeps). */
#if SNAP_USER_HW_WALK_S2RO
static struct sptm_aperture xnu_aperture(const struct context *);
static int hw_s2_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
/* xnuboot_prepare, after every vCPU's tree: guest RAM [mem_low, mem_high) in
 * level-3 leaves, every store published, then every VMID forgets stage 2. */
static int hw_s2_presplit_all(struct context *c)
{
    const struct params *p=c->params;
    struct shadow trees[HW_S2_TREES];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        trees[cpu]=(struct shadow){.txsz=S2_TXSZ,.root=c->vcpus[cpu].stage2_root,.alloc=prepare_table_alloc,
                                   .read=mem_read,.write=hw_s2_write,.ctx=c};
    int created=hw_s2_presplit(trees,GUEST_CPU_COUNT,p->mem_low&~((UINT64_C(1)<<21)-1),p->mem_high);
    if(created<0)return -1;
    c->hw_walk->stats.s2_tables=(unsigned)created;     /* RETYPE adds none: no splits after this */
    __asm__ volatile("dsb ish; tlbi alle1is; dsb ish; isb" ::: "memory");
    return 0;
}
static int hw_s2_frame(struct context *c,uint64_t frame,int ro)
{
    struct shadow trees[HW_S2_TREES];
    _Static_assert(GUEST_CPU_COUNT==HW_S2_TREES,"one stage-2 tree per vCPU");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        trees[cpu]=(struct shadow){.txsz=S2_TXSZ,.root=c->vcpus[cpu].stage2_root,.alloc=table_alloc,
                                   .read=mem_read,.write=hw_s2_write,.ctx=c};
    /* Leaves only: the trees were pre-split at setup (hw_s2_presplit_all). */
    if(hw_s2_set(trees,GUEST_CPU_COUNT,frame,ro)<0) {c->hw_walk->stats.s2_failures++;return 0;}
    if(ro)c->hw_walk->stats.s2_protects++;else c->hw_walk->stats.s2_unprotects++;
    struct sptm_aperture ap=xnu_aperture(c);struct sptm_moved mv=xnu_moved(c);
    uint64_t linear=sptm_aperture_pointer(&ap,frame,0x4000);
    uint64_t moved=sptm_published_pointer(&ap,&mv,frame,0x4000);
    uint64_t saved,mask=(UINT64_C(1)<<44)-1;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        for(unsigned p=0;p<4;p++)
            __asm__ volatile("tlbi ipas2e1is, %0" :: "r"(((frame+4096UL*p)>>12)&mask) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        for(unsigned p=0;p<4;p++) {
            if(linear)__asm__ volatile("tlbi vaae1is, %0" :: "r"(((linear+4096UL*p)>>12)&mask) : "memory");
            if(moved && moved!=linear)
                __asm__ volatile("tlbi vaae1is, %0" :: "r"(((moved+4096UL*p)>>12)&mask) : "memory");
        }
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    c->shadow_tlb_syncs++;
    return 1;
}
#endif
#endif
static int user_publish_view(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                              const struct sprr_state *state,int el0)
{
    struct sprr_views *views=user_views(c,e);
#if SNAP_USER_DIRTY_PUBLISH
    _Static_assert(SPRR_VIEW_TABLES==USER_PUBLISH_MAX,"user publication selection ABI");
    uint64_t pages[USER_PUBLISH_MAX];
    if(cpu>=GUEST_CPU_COUNT || !views->count || views->count>USER_PUBLISH_MAX) {
        c->user_publish.errors++;c->user_view_failed=1;return 0;
    }
    for(unsigned n=0;n<views->count;n++)pages[n]=views->tables[n].copy[cpu];
    if(!user_publish_flush(&c->root_publish,&c->private_pages,&c->user_publish,
        c->work_base,c->next_table,pages,(unsigned)views->count,root_publish_page,c)) {
        c->user_view_failed=1;return 0;
    }
#else
    for(unsigned n=0;n<views->count;n++) {
        uint64_t pa=views->tables[n].copy[cpu];publish(pa,pa+4096);
    }
#endif
    if(c->user_roots.active[cpu]==e->root) {
        struct user_view_state *u=&c->user_view_state[cpu];
        u->root=e->root;u->shadow=sprr_views_root(views,cpu);u->el0=el0;
        u->uperm=state->uperm;u->pperm=state->pperm;u->umprr=state->umprr;u->syncs++;
    }
    return 1;
}
static int user_sync_view_impl(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                          const struct sprr_state *state,int el0)
{
    struct shadow s=user_view_shadow(c,e);struct sprr_views *views=user_views(c,e);
#if SNAP_USER_VIEW_CACHE
#if SNAP_VIEW_TABLE_READ
    struct view_table_read_stats *st=&c->view_table_reads[1];
    if(st->errors) {c->user_view_failed=1;return 0;}
    sprr_count(&st->calls);st->tables+=views->count;
#if SNAP_USER_TREE_MEMO
    int ok=sprr_views_sync_user_cached_memo(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY,user_view_table_read,private_copy_table_read,&c->view_store_compare[1],
        &c->table_memo,&UMEMOS(c)[e-c->user_roots.cache]);
#elif SNAP_VIEW_STORE_COMPARE
    int ok=sprr_views_sync_user_cached_compared(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY,user_view_table_read,private_copy_table_read,&c->view_store_compare[1]);
#else
    int ok=sprr_views_sync_user_cached_mapped(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY,user_view_table_read);
#endif
    if(!ok) {
        sprr_count(&st->errors);c->user_view_failed=1;return 0;
    }
    sprr_count(&st->complete);
#else
    if(!sprr_views_sync_user_cached(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY)) {
        c->user_view_failed=1;return 0;
    }
#endif
#else
    if(!sprr_views_sync_user_cpu(views,&s,cpu,state,el0)) {
        c->user_view_failed=1;return 0;
    }
#endif
    return user_publish_view(c,e,cpu,state,el0);
}
static int user_sync_view(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                          const struct sprr_state *state,int el0)
{
    int started=detail_begin(c,DETAIL_USER_SYNC);
    int result=user_sync_view_impl(c,e,cpu,state,el0);
    detail_end(c,DETAIL_USER_SYNC,started,result);return result;
}
#if SNAP_USER_TABLE_READ && !SNAP_NATIVE_TABLES
static const volatile uint64_t *user_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if(c->user_table_reads[2])return 0;
    sprr_count(&c->user_table_reads[0]);
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096) {
        sprr_count(&c->user_table_reads[2]);return 0;
    }
    /* Canonical user tables are monitor-owned and stable under the service
     * token. Check the complete allocation span once; the walker still loads
     * and validates all512 descriptors. No mapping or proof is reused. */
    sprr_count(&c->user_table_reads[1]);
    return (const volatile uint64_t *)pa;
}
#endif
#if SNAP_USER_FUSED_COMPARE && !SNAP_NATIVE_TABLES
static const volatile uint64_t *user_fused_source_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if(c->private_pages.errors || (pa&4095) || pa<c->work_base ||
       pa>=c->next_table || c->next_table-pa<4096)return 0;
    uint64_t index=(pa-c->work_base)/4096;
    if(index>=SPRR_PRIVATE_PAGES ||
       (c->private_pages.bitmap[index/64]&(UINT64_C(1)<<(index%64))))return 0;
    /* Separate from the full-tree reader counters: this is the private-path
     * preflight/commit mapping, after full source and coverage validation. */
    return (const volatile uint64_t *)pa;
}
#endif
#if !SNAP_NATIVE_TABLES
static int user_refresh_all_impl(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_view_shadow(c,e);struct sprr_views *views=user_views(c,e);
#if SNAP_USER_VIEW_CACHE
    struct sprr_view_proof *proof=&UPROOFS(c)[e-c->user_roots.cache];
    proof->valid=0;
#endif
    if(!views->count && !sprr_views_init(views,&s)) {c->user_view_failed=1;return 0;}
#if !SNAP_USER_PREPARE_FUSED
    if(!sprr_views_prepare_user(views,&s)) {c->user_view_failed=1;return 0;}
#endif
#if SNAP_USER_VIEW_BATCH
    struct sprr_state states[GUEST_CPU_COUNT];int modes[GUEST_CPU_COUNT];
    _Static_assert(GUEST_CPU_COUNT==SPRR_VIEW_CPUS,"batch view CPU count");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
        int active=c->user_roots.active[cpu]==e->root;
        states[cpu]=active ? c->user_roots.sprr[cpu]:initial;
        modes[cpu]=active ? (int)c->user_view_state[cpu].el0:0;
    }
#if SNAP_USER_VIEW_FUSED
#if SNAP_USER_PREPARE_FUSED
#if SNAP_USER_ZERO_GROUP
#if SNAP_USER_TREE_MEMO
    if(!sprr_views_prepare_sync_user_memo(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read,
            &c->user_zero_groups,user_fused_source_read,private_copy_table_read,
            &c->user_fused_compare,&c->table_memo,
            &UMEMOS(c)[e-c->user_roots.cache])) {c->user_view_failed=1;return 0;}
#elif SNAP_USER_FUSED_COMPARE
    if(!sprr_views_prepare_sync_user_compared(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read,
            &c->user_zero_groups,user_fused_source_read,private_copy_table_read,
            &c->user_fused_compare)) {c->user_view_failed=1;return 0;}
#else
    if(!sprr_views_prepare_sync_user_grouped(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read,
            &c->user_zero_groups)) {c->user_view_failed=1;return 0;}
#endif
#else
#if SNAP_USER_TABLE_READ
    if(!sprr_views_prepare_sync_user_mapped(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read)) {c->user_view_failed=1;return 0;}
#else
    if(!sprr_views_prepare_sync_user_fused(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats)) {c->user_view_failed=1;return 0;}
#endif
#endif
#else
    if(!sprr_views_sync_user_fused(views,&s,states,modes)) {c->user_view_failed=1;return 0;}
#endif
    sprr_count(&c->user_fused_syncs);
#else
    if(!sprr_views_sync_user_all(views,&s,states,modes)) {c->user_view_failed=1;return 0;}
#endif
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(!user_publish_view(c,e,cpu,&states[cpu],modes[cpu]))return 0;
#else
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
        int active=c->user_roots.active[cpu]==e->root;
        const struct sprr_state *state=active ? &c->user_roots.sprr[cpu]:&initial;
        int el0=active ? (int)c->user_view_state[cpu].el0:0;
        if(!user_sync_view(c,e,cpu,state,el0))return 0;
    }
#endif
#if SNAP_USER_VIEW_CACHE
    proof->root=s.root;proof->count=views->count;proof->epoch=c->user_view_epoch;
    proof->valid=c->user_view_epoch!=UINT64_MAX;
#endif
    user_tlb_sync(c);return 1;
}
#endif
static int user_refresh_all(struct context *c,struct sptm_root_cached *e)
{
#if SNAP_NATIVE_TABLES
    /* The variant copies follow every canonical store; before the first
     * install they do not exist yet. A sampled audit re-derives them all. */
    struct sprr_views *v=user_views(c,e);
    if(!v->count || !native_due(&c->native_stats.audit_asks))return !c->user_view_failed;
    int started=detail_begin(c,DETAIL_USER_REFRESH);
    struct shadow s=user_view_shadow(c,e);
    /* Every sampled audit re-derives every copy; every 64th of them also
     * walks the whole canonical tree for coverage. */
    int full=!(c->native_stats.audits&63);
    int result=full ? native_views_verify(v,&s,native_umprr(e)) : native_views_exact(v,&s,native_umprr(e));
    c->native_stats.audits++;c->native_stats.coverages+=full;
    if(!result) {c->native_stats.audit_failures++;c->user_view_failed=1;}
    detail_end(c,DETAIL_USER_REFRESH,started,result);return result;
#else
    int started=detail_begin(c,DETAIL_USER_REFRESH);
    int result=user_refresh_all_impl(c,e);
    detail_end(c,DETAIL_USER_REFRESH,started,result);return result;
#endif
}
static uint64_t user_install_view(struct context *c,uint64_t root,uint64_t canonical,
                                  int invalidate)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,root);
#if SNAP_NATIVE_TABLES
    (void)invalidate;
    if(!e || e->shadow!=canonical)return 0;
    unsigned slot=(unsigned)(e-c->user_roots.cache);
    struct sprr_views *v=user_views(c,e);
    /* First install after a build: derive both variants once. From then on
     * every canonical store keeps them exact. */
    if(!v->count) {
        struct shadow s=user_view_shadow(c,e);
        if(!native_views_sync(v,&s,native_umprr(e))) {c->user_view_failed=1;return 0;}
        native_mark(c,v,1);c->native_stats.syncs++;
        /* No CPU could reach these copies before now: clean them whole. */
        for(unsigned t=0;t<v->count;t++)
            for(unsigned w=0;w<NATIVE_VARIANTS;w++)
                publish(v->tables[t].copy[w],v->tables[t].copy[w]+4096);
    }
#if SNAP_INACTIVE_MIRROR
    UBUDGETS(c)[slot]=0;
#endif
    /* The reset state: UPERM and PPERM initial, EL1 about to run. Phase 1
     * has no kernel variants, so k selects the same TTBR0 and TTBR1 stays. */
    struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
    struct native_cpu *n=&c->native_cpu[cpu];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)
        ttbr0[w][k]=native_views_root(v,w)|(native_asid(slot,w,0)<<48);
    if(!native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0)) {
        c->user_view_failed=1;return 0;
    }
    c->native_stats.installs++;
    struct user_view_state *u=&c->user_view_state[cpu];
    u->root=root;u->shadow=native_views_root(v,n->w);u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    return u->shadow;
#else
    if(!e || e->shadow!=canonical || !user_refresh_all(c,e))return 0;
#if SNAP_INACTIVE_MIRROR
    UBUDGETS(c)[e-c->user_roots.cache]=0;
#endif
    /* SWITCH_ROOT commits its logical reset after this callback. Install the
     * incoming root's reset state, not the previous address space's state. */
    struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
    if(!user_sync_view(c,e,cpu,&initial,0))return 0;
    /* Only this CPU's copy was written after the refresh's own TLBI. */
    if(invalidate)user_tlb_sync(c);
    struct user_view_state *u=&c->user_view_state[cpu];
    u->root=root;u->shadow=sprr_views_root(user_views(c,e),cpu);u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;
    return u->shadow;
#endif
}
static int user_refresh_pperm(struct context *c,uint64_t value)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    if(!c->user_roots.active[cpu])return 1;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[cpu]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[cpu]);
#endif
    if(!e) {c->user_view_failed=1;return 0;}
#if SNAP_NATIVE_TABLES
    /* PPERM governs EL1: its TPRO bit selects the variant while EL1 runs.
     * The regime is the tracked one, as user_sync_view's was. */
    struct user_view_state *u=&c->user_view_state[cpu];
    struct native_cpu *n=&c->native_cpu[cpu];unsigned w=n->w;
    if(!native_set_pperm(n,value,(int)u->el0)) {c->user_view_failed=1;return 0;}
    c->native_stats.flips+=n->w!=w;
    u->pperm=value;u->shadow=user_hw_root(c,e,cpu);
    return !c->user_view_failed;
#else
    struct sprr_state next=c->user_roots.sprr[cpu];next.pperm=value;
    return user_sync_view(c,e,cpu,&next,(int)c->user_view_state[cpu].el0);
#endif
}
#if SNAP_USER_MODE_SKIP
/* The only mode-dependent input to a user view is a class9 leaf's write bit:
 * entry_decode takes it from UPERM at EL0 and PPERM at EL1. Everything else
 * (fixed native leaves, UMPRR validity, child copies) is mode-independent. */
static int user_mode_write(const struct sprr_state *s,unsigned el0)
{return !!((el0 ? s->uperm : s->pperm)&SPRR_UPERM_TPRO_WRITE);}
#endif
#if SNAP_NATIVE_TABLES
/* An EL0<->EL1 crossing, safe without the service lock: it touches only this
 * CPU's native_cpu, user_view_state and user_roots.active entries, which no
 * other CPU writes, and reads the latched failure flag. 1: the variant of
 * the regime about to run (el0) is live and u->el0/shadow/entries/returns
 * are updated exactly as user_enter_mode does. 0: declined with nothing
 * changed (a failure latched, no native address space installed, state that
 * disagrees with the active root, a missing variant); the caller takes the
 * locked path, user_enter_mode, which decides and reports. Per-CPU counters
 * only: native_cpu.selects/flips count every crossing, native_stats.flips
 * the locked ones. */
static int native_cross(struct context *c,unsigned cpu,int el0)
{
    if(cpu>=GUEST_CPU_COUNT || c->user_view_failed)return 0;
    struct native_cpu *n=&c->native_cpu[cpu];
    struct user_view_state *u=&c->user_view_state[cpu];
    uint64_t root=c->user_roots.active[cpu];
    el0=!!el0;
    if(!n->installed || !root || u->root!=root || n->el0!=u->el0)return 0;
    if(u->el0==(unsigned)el0)return 1;
    if(!n->ttbr0[native_variant_w(n->uperm,n->pperm,el0)][native_variant_k(n->pperm)])return 0;
    if(!native_select(n,el0))return 0;
    u->el0=(unsigned)el0;u->shadow=n->ttbr0[n->w][n->k]&PT_OA_MASK;
    if(el0)u->returns++;else u->entries++;
    return 1;
}
#endif
static int user_enter_mode(struct context *c,int el0)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[cpu]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[cpu]);
#endif
    if(!e) {c->user_view_failed=1;return 0;}
    struct user_view_state *u=&c->user_view_state[cpu];
    if(u->el0==(unsigned)el0)return !c->user_view_failed;
#if SNAP_NATIVE_TABLES
    /* The governing register changes with the regime: select its variant.
     * Under the lock a declined crossing is a failure. */
    unsigned w=c->native_cpu[cpu].w;
    if(!native_cross(c,cpu,el0) || u->shadow!=user_hw_root(c,e,cpu)) {c->user_view_failed=1;return 0;}
    c->native_stats.flips+=c->native_cpu[cpu].w!=w;
    return 1;
#endif
#if SNAP_USER_MODE_SKIP
    /* This CPU's copies were last written (sync, refresh or install) for
     * exactly this root, view and SPRR state in mode u->el0. If the mode's
     * TPRO write bit is the same, a sync for the new mode would store
     * nothing, so there is nothing to publish or invalidate. Every 256th
     * skip runs the real sync instead and counts any store as a mismatch. */
    const struct sprr_state *now=&c->user_roots.sprr[cpu];
    struct user_mode_skip_stats *k=&c->user_mode_skip[cpu];
    if(!c->user_view_failed && u->root==e->root &&
       u->shadow==sprr_views_root(user_views(c,e),cpu) &&
       u->uperm==now->uperm && u->pperm==now->pperm && u->umprr==now->umprr &&
       user_mode_write(now,(unsigned)u->el0)==user_mode_write(now,(unsigned)el0)) {
        if((k->skips++&255)!=255) {
            u->el0=(unsigned)el0;
            if(el0)u->returns++;else u->entries++;
            return 1;
        }
        uint64_t changed=c->view_store_compare[1].changed;
#if SNAP_USER_TREE_MEMO
        /* Keep this check independent of memo claims: the sync recomputes
         * and compares every private word, and also verifies every claim. */
        c->table_memo.force=1;
#endif
        int synced=user_sync_view(c,e,cpu,now,el0);
#if SNAP_USER_TREE_MEMO
        c->table_memo.force=0;
#endif
        if(!synced)return 0;
        k->checks++;
        if(c->view_store_compare[1].changed!=changed)k->mismatches++;
        user_tlb_sync(c);
        if(el0)u->returns++;else u->entries++;
        return 1;
    }
    k->differs++;
#endif
    if(!user_sync_view(c,e,cpu,&c->user_roots.sprr[cpu],el0))return 0;
    user_tlb_sync(c);
    if(el0)u->returns++;else u->entries++;
    return 1;
}
#if SNAP_EL0_MEMO
/* The lookup, then every other check (user_return_check, which a memo hit
 * runs on the entry it remembers). */
static struct sptm_root_cached *user_return_check(struct context *c,struct sptm_root_cached *e);
static struct sptm_root_cached *user_return_root(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[v->slot]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[v->slot]);
#endif
    return user_return_check(c,e);
}
static struct sptm_root_cached *user_return_check(struct context *c,struct sptm_root_cached *e)
{
    struct vcpu *v=vcpu_of(c);
#else
static struct sptm_root_cached *user_return_root(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[v->slot]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[v->slot]);
#endif
#endif
    if(!e || !e->asid || e->asid>0xffff || e->format>1 ||
       c->root_install_failures || c->kernel_view_failed || c->user_view_failed)return 0;
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,e->root))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((e->root-m.frame_low)>>14)*16,16);
    if(!meta || meta[0] || meta[1] || meta[2]!=SPTM_MAC_USER_ROOT_TABLE ||
       ((unsigned)meta[4]|((unsigned)meta[5]<<8))!=e->asid ||
       ((unsigned)meta[10]|((unsigned)meta[11]<<8))!=e->flags ||
       meta[12]!=e->format || meta[13] || meta[14] || meta[15] ||
       !sptm_mac_user_binding_valid(&m,meta))return 0;
    uint64_t ttbr,tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(ttbr),"=r"(tcr));
    if(v->guest_ttbr0!=(e->root|(e->asid<<48)) ||
#if SNAP_NATIVE_TABLES
       ttbr!=c->native_cpu[v->slot].ttbr0[c->native_cpu[v->slot].w&1][c->native_cpu[v->slot].k&1] ||
       !c->native_cpu[v->slot].installed ||
#else
       ttbr!=(sprr_views_root(user_views(c,e),(unsigned)v->slot)|(e->asid<<48)) ||
#endif
       tcr!=shadow_tcr(v->guest_tcr) ||
       (tcr&((1UL<<7)|(3UL<<14))) || (tcr&63)!=17)return 0;
    return e;
}
static int user_source_read(void *ctx,uint64_t pa,uint64_t *out)
{
    volatile uint8_t *p=sptm_map(ctx,pa,8);
    if(!p || (pa&7))return -1;
    *out=*(volatile uint64_t *)p;return 0;
}
#if SNAP_EL0_MEMO
/* user_instruction_read's code frame and word at pa (also a memo hit's
 * re-read): a managed USER_EXEC frame. */
static int user_code_word(struct context *c,uint64_t pa,uint32_t *word)
{
    struct sptm_memory m=sptm_context_memory(c);uint64_t frame=pa&~16383UL;
    if(!sptm_managed_frame(&m,frame))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((frame-m.frame_low)>>14)*16,16);
    volatile uint8_t *code=m.map(m.ctx,pa,4);
    if(!meta || meta[0] || meta[1] || meta[2]!=SPTM_MAC_USER_EXEC || !code)return 0;
    *word=*(volatile uint32_t *)code;
    return 1;
}
/* This vCPU's memo while its fast_el0_word's full read records, else 0. */
static struct el0_memo_cpu *el0_memo_recording(struct context *c)
{
    struct el0_memo_cpu *m=&EL0M(c)[vcpu_of(c)->slot];
    return m->recording ? m : 0;
}
#endif
/* Capture a bounded, independently walkable witness for the initial dyld-like
 * entry. Later ERETs may target demand-paged addresses: a missing instruction
 * is XNU's fault to resolve, not a reason to fabricate a mapping here. */
static int user_instruction_read(struct context *c,struct sptm_root_cached *e,
    uint64_t target,struct mmu_leaf *source_leaf,struct mmu_leaf *hardware_leaf,
    uint32_t *word)
{
    struct mmu_config source={e->format ? 12 : 14,17,e->root},
        hardware={12,17,user_hw_root(c,e,(unsigned)vcpu_of(c)->slot)};
    struct mmu_leaf a,b;
#if SNAP_EL0_MEMO
    /* fast_el0_word's full read records every descriptor both walks read
     * (compat/el0-memo.h); every other caller reads exactly as below. */
    struct el0_memo_cpu *memo=el0_memo_recording(c);
#if SNAP_USER_HW_WALK
    unsigned hardware_kind=hw_walk_of_entry(c->hw_walk,e)!=0;
    mmu_read_fn hardware_read=hardware_kind ? hw_table_read : kernel_table_read;
#else
    unsigned hardware_kind=0;
    mmu_read_fn hardware_read=kernel_table_read;
#endif
    struct el0_memo_reader rs={user_source_read,c,memo ? &memo->pending.walk[0] : 0},
        rh={hardware_read,c,memo ? &memo->pending.walk[1] : 0};
    if(mmu_walk(&source,target,memo ? el0_memo_read : user_source_read,memo ? (void *)&rs : c,&a) ||
       !a.valid || a.level!=3 ||
       mmu_walk(&hardware,target,memo ? el0_memo_read : hardware_read,memo ? (void *)&rh : c,&b) ||
       !b.valid || b.level!=3 ||
#else
#if SNAP_USER_HW_WALK
    /* A hardware-walk root's tables are guest RAM (or copies in the arena). */
    mmu_read_fn hardware_read=hw_walk_of_entry(c->hw_walk,e) ? hw_table_read : kernel_table_read;
    if(mmu_walk(&source,target,user_source_read,c,&a) || !a.valid || a.level!=3 ||
       mmu_walk(&hardware,target,hardware_read,c,&b) || !b.valid || b.level!=3 ||
#else
    if(mmu_walk(&source,target,user_source_read,c,&a) || !a.valid || a.level!=3 ||
       mmu_walk(&hardware,target,kernel_table_read,c,&b) || !b.valid || b.level!=3 ||
#endif
#endif
       a.pa!=b.pa || (a.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))!=
                       (b.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER)) ||
       (a.descriptor&PT_AP)!=PT_AP || !(a.descriptor&PT_AF) ||
       !(a.descriptor&PT_PXN) || (a.descriptor&PT_UXN))return 0;
#if SNAP_EL0_MEMO
    uint32_t code_word;
    if(!user_code_word(c,a.pa,&code_word))return 0;
    *source_leaf=a;*hardware_leaf=b;*word=code_word;
    if(memo)el0_memo_recorded(memo,e,source.root,source.granule_shift,hardware.root,hardware_kind,
                              a.descriptor,b.descriptor,a.pa);
    return 1;
#else
    struct sptm_memory m=sptm_context_memory(c);uint64_t frame=a.pa&~16383UL;
    if(!sptm_managed_frame(&m,frame))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((frame-m.frame_low)>>14)*16,16);
    volatile uint8_t *code=m.map(m.ctx,a.pa,4);
    if(!meta || meta[0] || meta[1] || meta[2]!=SPTM_MAC_USER_EXEC || !code)return 0;
    *source_leaf=a;*hardware_leaf=b;*word=*(volatile uint32_t *)code;
    return 1;
#endif
}
#if SNAP_USER_CRASH_RING
/* One aligned user word through the guest's own tables for the active root:
 * a software walk (no AT, no shadow view), accepted only when the leaf is a
 * valid accessed page of SPTM-managed RAM, so a stray frame pointer can
 * never reach device memory or anything outside the declared DRAM. */
static int user_crash_read(void *ctx,uint64_t va,uint64_t *out)
{
    struct context *c=ctx;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[vcpu_of(c)->slot]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[vcpu_of(c)->slot]);
#endif
    struct mmu_leaf a;
    if(!e || !e->root || e->format>1 || (va&7) || va>=(UINT64_C(1)<<47))return 0;
    struct mmu_config source={e->format ? 12 : 14,17,e->root};
    if(mmu_walk(&source,va,user_source_read,c,&a) || !a.valid || a.level!=3 ||
       !(a.descriptor&PT_AF))return 0;
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,a.pa&~16383UL))return 0;
    volatile uint8_t *word=sptm_map(c,a.pa,8);
    if(!word)return 0;
    *out=*(volatile uint64_t *)word;
    return 1;
}
static void user_crash_note(struct context *c,unsigned kind,const uint64_t *frame,
                            uint64_t esr,uint64_t elr,uint64_t far)
{
    struct vcpu *v=vcpu_of(c);
    uint64_t raw,sp,thread,tsd;
    __asm__ volatile("isb; mrs %0, cntvct_el0; mrs %1, sp_el0; mrs %2, tpidr_el1; "
                     "mrs %3, tpidrro_el0":"=r"(raw),"=r"(sp),"=r"(thread),"=r"(tsd)::"memory");
    uint64_t guest=v->clock_rate.host_hz && v->clock_rate.guest_hz ?
                   clock_rate_sample(&v->clock_rate,raw) : 0;
    user_crash_record(&c->user_crashes[v->slot],kind,(unsigned)v->slot,guest,raw,esr,elr,
                      far,frame,sp,v->guest_ttbr0,thread,tsd,user_crash_read,c);
}
#endif
static int user_entry_snapshot(struct context *c,struct sptm_root_cached *e,
    struct user_execution *u,uint64_t target,uint64_t spsr,uint64_t x0)
{
    struct mmu_leaf a,b;uint32_t word;
    if(!user_instruction_read(c,e,target,&a,&b,&word))return 0;
    __asm__ volatile("mrs %0, sp_el0":"=r"(u->stack));
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(u->ttbr),"=r"(u->tcr));
    u->entry=target;u->initial_spsr=spsr;u->root=e->root;
    u->shadow=user_hw_root(c,e,(unsigned)vcpu_of(c)->slot);
    u->entry_pa=a.pa;u->source_pte=a.descriptor;u->shadow_pte=b.descriptor;
    u->instruction=word;u->initial_x0=x0;
    return u->instruction==0x910003e0 && !(spsr&(1UL<<21));
}
#if SNAP_CANONICAL_VIEW_FAST
/* kernel_table_read accepts all 512 words of pa..pa+4095 exactly when pa is
 * 4K aligned inside the allocated arena with a whole page before next_table. */
static const volatile uint64_t *canonical_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096)return 0;
    return (const volatile uint64_t *)pa;
}
/* sptm_root_canonical_view's proof through sptm_root_view_mapped. Every 64th
 * call also runs the reference walk: a different verdict or result is terminal
 * and nothing is repaired. */
static int canonical_view(struct context *c,const struct sptm_root_cached *e,
    const struct shadow *s,const struct sptm_memory *m,struct sptm_fixed_view *out)
{
    struct canonical_view_perf *p=&c->perf.canonical;
    int ok=sptm_root_view_mapped(e,s,m,out,1,canonical_table_read,&p->mapped);
    if(!(p->mapped.calls&63)) {
        struct sptm_fixed_view reference={0};
        int again=sptm_root_canonical_view(e,s,m,&reference);
        p->sampled++;
        if(again!=ok || (ok && (reference.tables!=out->tables ||
            reference.pages!=out->pages || reference.classes!=out->classes))) {
            p->mismatches++;return 0;
        }
    }
    return ok;
}
#endif
/* The canonical user-view proof taken before every UPERM write and TPRO PPERM
 * change: all of the active root's 4K leaves against its source tables. Its
 * own detail bucket; UPERM writes are otherwise outside every bucket. */
static int user_canonical_proof(struct context *c,const struct sptm_root_cached *e,
    const struct shadow *s,const struct sptm_memory *m,struct sptm_fixed_view *out)
{
    int started=detail_begin(c,DETAIL_USER_VIEW_PROOF);
#if SNAP_CANONICAL_VIEW_FAST
    int result=canonical_view(c,e,s,m,out);
#else
    int result=sptm_root_canonical_view(e,s,m,out);
#endif
    detail_end(c,DETAIL_USER_VIEW_PROOF,started,result);return result;
}
/* user_proof=0 (native audit mode, sampled away): keep proof's user fields,
 * which the caller copied from this CPU's last proof. */
static int pperm_tpro_preflight(struct context *c,struct sprr_pperm_update_state *proof,
                                int user_proof)
{
    struct sptm_root_cached *e=user_return_root(c);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.read=kernel_table_read,.ctx=c};
    struct sptm_memory m=sptm_context_memory(c);struct sptm_fixed_view user={0};
    struct shadow k=kernel_shadow(c);struct sprr_view_classes kernel;
#if SNAP_USER_HW_WALK
    if(user_proof && (hw_walk_of_entry(c->hw_walk,e) ? !hw_entry_proof(c,e,&user) :
                      !user_canonical_proof(c,e,&s,&m,&user)))return 0;
#else
    if(user_proof && !user_canonical_proof(c,e,&s,&m,&user))return 0;
#endif
#if SNAP_KERNEL_CLASS_PROOF && SNAP_CLASS_PROOF_MAPPED
    struct class_proof_mapped_stats *cm=&c->class_proof_mapped;
    struct sprr_class_walk_stats walk={0};
    uint64_t walks=c->kernel_class_proof.walks,verified=c->kernel_class_proof.verified;
#if SNAP_CLASS_LEAF_MEMO
    int proved=sprr_class_proof_check_leaf(&c->kernel_class_proof,&k,1UL<<9,
        c->work_base,c->work_end,&kernel,class_table_read,c,&walk,
        &c->class_leaf,&c->table_memo);
#elif SNAP_KERNEL_PPERM_FAST
    /* Walks run only here, at the top of a PPERM write or a root install,
     * never inside an SPTM transaction between a mapped page's write note
     * and its stores, so an unchanged generation means unchanged bytes. */
    int proved=sprr_class_proof_check_fast(&c->kernel_class_proof,&k,1UL<<9,
        c->work_base,c->work_end,&kernel,class_table_read,c,&walk,
        &c->class_leaf,&c->table_memo);
#else
    int proved=sprr_class_proof_check_with(&c->kernel_class_proof,&k,1UL<<9,
        c->work_base,c->work_end,&kernel,class_table_read,c,&walk);
#endif
    /* A full walk used the mapped traversal; a verifying hit re-walked through
     * the original word reader and matched that walk's saved result. */
    cm->walks+=c->kernel_class_proof.walks-walks;
    cm->compared+=c->kernel_class_proof.verified-verified;
    cm->tables+=walk.tables;cm->groups+=walk.groups;cm->empty_groups+=walk.empty_groups;
    if(!proved) {cm->errors++;return 0;}
#elif SNAP_KERNEL_CLASS_PROOF
    if(!sprr_class_proof_check(&c->kernel_class_proof,&k,1UL<<9,
                              c->work_base,c->work_end,&kernel))return 0;
#else
    if(!sprr_views_check_classes(&k,1UL<<9,&kernel))return 0;
#endif
    if(user_proof) {
        proof->user_root=e->root;proof->user_shadow=e->shadow;
        proof->user_tables=user.tables;proof->user_pages=user.pages;proof->user_classes=user.classes;
    }
    proof->kernel_root=k.root;proof->kernel_tables=kernel.tables;
    proof->kernel_pages=kernel.pages;proof->kernel_classes=kernel.classes;
    return 1;
}
static int user_change_uperm(void *ctx,uint64_t value)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
    struct sptm_root_cached *e=user_return_root(c);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.read=kernel_table_read,.ctx=c};
    struct sptm_memory m=sptm_context_memory(c);struct sptm_fixed_view view;
#if SNAP_NATIVE_TABLES
    /* Audit mode: the proof runs on a CPU's first write and then sampled; its
     * record keeps the last proof. The flip itself is a TTBR0 write. */
    struct sprr_uperm_update_state *u=&c->sprr_uperm_update[v->slot];
    if(!u->root || native_due(&c->native_stats.proof_asks)) {
#if SNAP_USER_HW_WALK
        if(hw_walk_of_entry(c->hw_walk,e) ? !hw_entry_proof(c,e,&view) :
           !user_canonical_proof(c,e,&s,&m,&view))return 0;
#else
        if(!user_canonical_proof(c,e,&s,&m,&view))return 0;
#endif
        u->root=e->root;u->shadow=e->shadow;u->tables=view.tables;
        u->pages=view.pages;u->classes=view.classes;
    } else c->native_stats.proof_skips++;
    struct user_view_state *state=&c->user_view_state[v->slot];
    struct native_cpu *n=&c->native_cpu[v->slot];unsigned w=n->w;
    if(!native_set_uperm(n,value,(int)state->el0)) {c->user_view_failed=1;return 0;}
    c->native_stats.flips+=n->w!=w;
    state->uperm=value;state->shadow=user_hw_root(c,e,(unsigned)v->slot);
    return !c->user_view_failed;
#else
    if(!user_canonical_proof(c,e,&s,&m,&view))return 0;
    struct sprr_state next=c->user_roots.sprr[v->slot];next.uperm=value;
    if(!user_sync_view(c,e,(unsigned)v->slot,&next,
                      (int)c->user_view_state[v->slot].el0))return 0;
    user_tlb_sync(c);
    struct sprr_uperm_update_state *u=&c->sprr_uperm_update[v->slot];
    u->root=e->root;u->shadow=e->shadow;u->tables=view.tables;
    u->pages=view.pages;u->classes=view.classes;return 1;
#endif
}
static enum sprr_result user_write_uperm(struct context *c,uint64_t *frame,
    uint64_t pc,uint64_t saved,uint32_t word)
{
    struct vcpu *v=vcpu_of(c);struct sprr_state *s=&c->user_roots.sprr[v->slot];
    uint64_t before=s->uperm,value=(word&31)==31 ? 0 : frame[word&31];
    enum sprr_result result=sprr_user_write(s,word,frame,user_change_uperm,c);
    if(result!=SPRR_OK)return result;
    struct sprr_uperm_update_state *u=&c->sprr_uperm_update[v->slot];
    u->writes++;u->changes+=before!=value;u->pc=pc;u->word=word;
    u->before=before;u->after=value;u->spsr=saved;u->umprr=s->umprr;
    __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
    return SPRR_OK;
}
static int user_sysreg_access(struct context *c,uint64_t *frame,uint64_t pc,
                          uint64_t saved,uint64_t esr,uint64_t vector,uint64_t *elr)
{
    if(vector!=0x400 || esr!=0x02000000 || pc>=(1UL<<47)-4)return 0;
    struct vcpu *v=vcpu_of(c);
    uint64_t vhcr=v->vncr_va ? *(volatile uint64_t *)(v->vncr_va+0x78) : 0,translated;
    if(!exception_user_return(0xd69f03e0,vhcr,pc+4,saved,&translated))return 0;
    struct sptm_root_cached *root=user_return_root(c);
    struct mmu_leaf source,hardware;uint32_t word;
    if(!root || !user_instruction_read(c,root,pc,&source,&hardware,&word))return 0;
    struct clock_backend backend={c,clock_counter,clock_control};
    struct sprr_state *sprr=&c->user_roots.sprr[v->slot];
    enum clock_result clock_result=guest_clock_user_read(&v->clock,&backend,word,frame);
    if(clock_result==CLOCK_OK) {
        struct user_clock_state *u=&c->user_clock[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=v->clock.last;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root->root;u->cntkctl=v->clock.cntkctl;u->raw=v->clock_raw_last;
        u->host_hz=v->clock_rate.host_hz;u->guest_hz=v->clock_rate.guest_hz;
        SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_CLOCK);
    } else if(clock_result==CLOCK_UNHANDLED && (word&~31U)==0xd51ef1a0U) {
        if(user_write_uperm(c,frame,pc,saved,word)!=SPRR_OK)return 0;
        SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_UPERM_WRITE);
    } else if(clock_result==CLOCK_UNHANDLED && sprr_user_read(sprr,word,frame)==SPRR_OK) {
        struct user_sprr_state *u=&c->user_sprr[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=sprr->uperm;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root->root;u->umprr=sprr->umprr;
        SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_UPERM);
    } else return 0;
    /* The vector page has executed no instruction: restore the original user
     * PSTATE and keep SP_EL0/registers intact except the MRS destination. */
    step_arm(c,0);guards_close(c);
    __asm__ volatile("msr spsr_el2, %0"::"r"(translated));
    *elr=pc+4;
    return 1;
}
static uint64_t user_live_alloc(void *ctx)
{
    uint64_t pa=user_table_alloc(ctx);
    /* Publish zeroed child storage before descend links it into a live root. */
    if(pa)publish(pa,pa+4096);
    return pa;
}
static int user_live_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static int user_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    if(!sptm_root_prepare_leaf(e,&s,va,shift))return 0;
    if(sprr_pte_class(pte)==9) {
        /* Detach every active CPU's path while all future leaves are still
         * absent. No running CPU may observe raw Apple class9 as Arm RX. */
#if SNAP_NATIVE_TABLES
        if(!native_prepare_tpro(c,e,va,shift))return 0;
#else
        struct shadow private=user_view_shadow(c,e);
        for(uint64_t off=0;off<(1UL<<shift);off+=4096)
            if(!sprr_views_prepare_user_leaf(user_views(c,e),&private,va+off))return 0;
        if(!user_refresh_all(c,e))return 0;
#endif
    }
    return 1;
}
static int user_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_root_commit_leaf(e,&s,&m,va,shift,pte) || !user_refresh_all(c,e))return 0;
    if(!user_commit_tlb_range(c,0,va,UINT64_C(1)<<shift))return 0;
    c->user_live_pages++;return 1;
}
#if SNAP_INACTIVE_MIRROR
/* After an accepted, non-conflicting MAP_PAGE on a root no CPU has installed
 * (e: its valid cached entry, or 0): nonzero keeps a shadow that still equals
 * the guest tree (compat/inactive-mirror.h). A fresh leaf counts as committed
 * only if user_commit_leaf finished for this call. Zero: invalidate. */
static int inactive_map_keep(struct context *c,struct sptm_root_cached *e,
    const struct sptm_user_backend *b,uint64_t pte,uint64_t status,uint64_t live)
{
    struct inactive_mirror_state *m=&c->inactive_mirror;
    if(!e)return 0;
    int committed=b->mirror && c->user_live_pages==live+1;
    if(!inactive_mirror_keep(e->valid!=0,status,committed)) {
        /* Not admitted: the same reasons, in inactive_mirror_admit's order
         * (with SNAP_NATIVE_LIVE only arena room is asked). */
        if(!SNAP_NATIVE_LIVE && sprr_pte_class(pte)==9)m->stats.tpro++;
        else if(!SNAP_NATIVE_LIVE && UBUDGETS(c)[e-c->user_roots.cache]>=INACTIVE_MIRROR_BUDGET)m->stats.budget++;
        else m->stats.arena++;
        return 0;
    }
    if(committed) {m->stats.leaves++;UBUDGETS(c)[e-c->user_roots.cache]++;}
    else m->stats.present++;
    return 1;
}
#endif
static int user_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    /* user_backend has already rejected active roots without a valid cache. */
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    return sptm_root_prepare_unmap(e,&s,&m,va,shift,count);
}
static int user_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    if(!user_prepare_unmap(ctx,root,va,shift,1))return 0;
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e && sprr_pte_class(next)==9 && sprr_pte_class(old)!=9) {
        /* Prepare private paths before an existing fixed leaf becomes TPRO.
         * The source still contains its old permissions while copies detach. */
#if SNAP_NATIVE_TABLES
        if(!native_prepare_tpro(c,e,va,shift))return 0;
#else
        struct shadow private=user_view_shadow(c,e);
        for(uint64_t off=0;off<(1UL<<shift);off+=4096)
            if(!sprr_views_prepare_user_leaf(user_views(c,e),&private,va+off))return 0;
        if(!user_refresh_all(c,e))return 0;
#endif
    }
    return 1;
}
static int user_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
#if SNAP_USER_HW_WALK
    /* A hardware-walk root (never cached): its copies follow the store, then
     * the same skip and invalidation as below (hardware never caches an
     * AF-clear leaf, and the copies keep AF). */
    struct hw_walk_root *hr=hw_root(c,root);
    if(hr) {
        struct hw_walk_ops o=hw_ops(c);
        if(e || !hw_walk_after_add(&o,hr,va,UINT64_C(1)<<shift,&c->hw_walk->stats))return hw_fail(c);
    }
#endif
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        struct sptm_memory m=sptm_context_memory(c);
        if(!sptm_root_commit_update(e,&s,&m,va,shift,old,next) || !user_refresh_all(c,e))return 0;
    }
#if SNAP_UPDATE_DISJOINT_FAST
    /* An old leaf with AF clear raised an Access flag fault on every walk, so
     * no TLB holds it, and prepare proved the cached copies equal it
     * (compat/update-fast.h): nothing to revoke. */
    if(update_fast_uncached(old))return !c->user_view_failed;
#endif
    /* Option400 permits a weaker final synchronization in Apple's monitor.
     * Finish it here, including every VMID, so no deferred revocation remains. */
    user_tlb_range(c,va,UINT64_C(1)<<shift);return !c->user_view_failed;
}
static int user_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                             uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed) || !user_refresh_all(c,e))return 0;
    }
    /* Flush even an inactive root: its previous translations must not outlive
     * the references about to be released by sptm_mac_unmap_user_region. */
    if(!user_commit_tlb_range(c,1,va,count<<shift))return 0;
    c->user_unmap_calls++;c->user_unmap_pages+=removed;return 1;
}
static int user_prepare_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                               unsigned level,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
#if SNAP_NATIVE_SHARED
    /* A shared root detaching an (empty, un-nested) level-3 table: its group
     * is derived state no root links; drop it so the PA can be reused. */
    if(!e && level==2 && shift==14) {
        uint64_t child;int g;
        if(native_group_at(c,root,va,&g,&child) && g>=0) {
            if(UNS(c).group[g].leaves || UNS(c).group[g].shared!=root ||
               !native_group_unlinked(c,g))return 0;
            if(!native_shared_free(&UNS(c),g,native_group_release,c) || c->user_view_failed)return 0;
        }
    }
#endif
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    return sptm_root_prepare_detach(e,&s,&m,va,shift,level,removed);
}
static int user_commit_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                              unsigned level,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        if(!sptm_root_commit_detach(e,&s,va,shift,level,removed) || !user_refresh_all(c,e))return 0;
    }
    /* No kernel mapping changed. Always invalidate every guest VMID before
     * source-table lifetime references can be released. */
    user_tlb_range(c,0,0);c->user_detach_calls++;return !c->user_view_failed;
}
static int user_prepare_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    return sptm_root_prepare_attach(e,&s,&m,va,shift,child);
}
static int user_commit_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    struct sptm_memory m=sptm_context_memory(c);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        if(!sptm_root_commit_attach(e,&s,&m,va,shift,child) || !user_refresh_all(c,e))return 0;
    }
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((child-m.frame_low)>>14)*16,16);
    if(!meta)return 0;
    uint64_t leaves=meta[8]|((uint64_t)meta[9]<<8);
    if(!user_commit_tlb_range(c,2,0,0))return 0;
    if(leaves){c->user_comm_attach_calls++;c->user_comm_attach_leaves+=leaves;}
    return 1;
}
static int user_prepare_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,
                             unsigned shift,uint64_t pages)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
    if(!e->format && shift==14) {
        struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
        struct sptm_root_links links=native_links_for(&nl);
        return sptm_root_prepare_nest_linked(e,&s,&m,shared,va,shift,pages,&links);
    }
#endif
    return sptm_root_prepare_nest(e,&s,&m,shared,va,shift,pages);
}
static int user_commit_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,
                            unsigned shift,uint64_t pages)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
        if(!e->format && shift==14) {
            /* Prepare made every table; commit links only. */
            s.alloc=native_no_alloc;
            struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
            struct sptm_root_links links=native_links_for(&nl);
            if(!sptm_root_commit_nest_linked(e,&s,&m,shared,va,shift,pages,&links) ||
               !user_refresh_all(c,e))return 0;
        } else
#endif
        if(!sptm_root_commit_nest(e,&s,&m,shared,va,shift,pages) || !user_refresh_all(c,e))return 0;
    }
    if(!user_commit_tlb_range(c,3,va,pages<<shift))return 0;
    uint64_t span=1UL<<(2*shift-3),last=va+((pages-1)<<shift);
    struct sptm_nest_state *n=&c->nest_state;
    n->calls++;n->descriptors+=last/span-va/span+1;
    n->root=root;n->shared=shared;n->va=va;n->pages=pages;
    n->first=va&~(span-1);n->last=(last&~(span-1))+span;
    return 1;
}
static int user_prepare_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                               const struct sptm_unnest_plan *plan)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s=user_shadow(c,e);struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
    if(!e->format && shift==14) {
        struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
        struct sptm_root_links links=native_links_for(&nl);
        return sptm_root_prepare_unnest_linked(e,&s,&m,shared,shift,plan,&links);
    }
#endif
    return sptm_root_prepare_unnest(e,&s,&m,shared,shift,plan);
}
static int user_commit_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                              const struct sptm_unnest_plan *plan)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s=user_shadow(c,e);struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
        if(!e->format && shift==14) {
            /* The cleared links are in memory before the invalidation below. */
            s.alloc=native_no_alloc;s.read=mem_read;s.write=user_live_write;
            struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
            struct sptm_root_links links=native_links_for(&nl);
            if(!sptm_root_commit_unnest_linked(e,&s,&m,shared,shift,plan,&links) ||
               !user_refresh_all(c,e))return 0;
        } else
#endif
        if(!sptm_root_commit_unnest(e,&s,&m,shared,shift,plan) || !user_refresh_all(c,e))return 0;
    }
    user_tlb_range(c,0,0);
    if(c->user_view_failed)return 0;
    c->unnest_calls++;c->unnest_descriptors+=plan->descriptors;c->unnest_leaves+=plan->leaves;
    c->unnest_root=root;c->unnest_shared=shared;c->unnest_format=shift==12;
    volatile uint64_t *dst=(volatile uint64_t *)&c->unnest_plan;
    const uint64_t *src=(const uint64_t *)plan;
    for(unsigned i=0;i<sizeof(*plan)/8;i++)dst[i]=src[i];
    return 1;
}
static int user_shared_mask(struct context *c,uint64_t root,uint64_t va,unsigned shift,
                            sptm_root_mask_t *mask)
{
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(!sptm_root_recorded_matches(&c->user_roots,cpu,
            c->vcpus[cpu].guest_ttbr0,c->params->ttbr1_root))return 0;
    struct sptm_memory m=sptm_context_memory(c);
#if SNAP_USER_HW_WALK
    return sptm_root_shared_aliases_hw(&m,&c->user_roots,root,va,shift,mask,hw_walk_recorded,c->hw_walk);
#else
    return sptm_root_shared_aliases(&m,&c->user_roots,root,va,shift,mask);
#endif
}
static int user_prepare_shared_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                    uint64_t old,uint64_t next)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask))return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        /* Every aliasing root links the group: one write, no per-root work. */
        if(!native_shared_storable(next) || !native_shared_prepare(c,root,va,shift,1,mask,next))return 0;
        ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=1;
        return 1;
    }
#endif
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        uint64_t user=c->user_roots.cache[i].root;
        if(!user_prepare_unmap(c,user,va,shift,1) ||
           (!old && !user_prepare_leaf(c,user,va,shift,next)))return 0;
    }
    ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=1;
    return 1;
}
static int user_commit_shared_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                   uint64_t old,uint64_t next)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask) || SPTM_ROOT_MASK_NE(mask,ROOT_PLAN_MASK(c)) ||
       root!=c->shared_plan_root || va!=c->shared_plan_va || c->shared_plan_count!=1)return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_commit(c,root,va,shift,1,0,next))return 0;
        uint64_t aliases=0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
            c->user_roots.cache[i].leaves+=!old;aliases++;
        }
        user_tlb_range(c,va,UINT64_C(1)<<shift);
        c->shared_map_calls++;c->shared_map_inserts+=!old;c->shared_map_updates+=!!old;
        c->shared_map_aliases+=aliases;c->shared_map_root=root;c->shared_map_va=va;
        c->shared_map_old=old;c->shared_map_next=next;c->shared_map_shift=shift;c->shared_map_mask=SPTM_ROOT_MASK_LOW(mask);
        return !c->user_view_failed;
    }
#endif
    struct sptm_memory m=sptm_context_memory(c);uint64_t aliases=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];struct shadow s=user_shadow(c,e);
        if(!(old ? sptm_root_commit_update(e,&s,&m,va,shift,old,next) :
                   sptm_root_commit_leaf(e,&s,&m,va,shift,next)) || !user_refresh_all(c,e))return 0;
        aliases++;
    }
    user_tlb_range(c,va,UINT64_C(1)<<shift);
    c->shared_map_calls++;c->shared_map_inserts+=!old;c->shared_map_updates+=!!old;
    c->shared_map_aliases+=aliases;c->shared_map_root=root;c->shared_map_va=va;
    c->shared_map_old=old;c->shared_map_next=next;c->shared_map_shift=shift;c->shared_map_mask=SPTM_ROOT_MASK_LOW(mask);
    return !c->user_view_failed;
}
static int user_prepare_shared_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask))return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_prepare(c,root,va,shift,count,mask,0))return 0;
        ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=count;
        return 1;
    }
#endif
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i))
        if(!user_prepare_unmap(c,c->user_roots.cache[i].root,va,shift,count))return 0;
    ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=count;
    return 1;
}
static int user_commit_shared_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                    uint64_t count,uint64_t removed)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask) || SPTM_ROOT_MASK_NE(mask,ROOT_PLAN_MASK(c)) ||
       root!=c->shared_plan_root || va!=c->shared_plan_va || count!=c->shared_plan_count)return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_commit(c,root,va,shift,count,0,0))return 0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
            struct sptm_root_cached *e=&c->user_roots.cache[i];
            if(e->leaves<removed)return 0;
            e->leaves-=removed;
        }
    } else
#endif
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];struct shadow s=user_shadow(c,e);
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed) || !user_refresh_all(c,e))return 0;
    }
    user_tlb_range(c,va,count<<shift);c->shared_unmap_calls++;c->shared_unmap_pages+=removed;
    return !c->user_view_failed;
}
static int user_commit_shared_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                     uint64_t count,const struct sptm_shared_update_entry *entries)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask) || SPTM_ROOT_MASK_NE(mask,ROOT_PLAN_MASK(c)) ||
       root!=c->shared_plan_root || va!=c->shared_plan_va || count!=c->shared_plan_count)return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_commit(c,root,va,shift,count,entries,0))return 0;
        user_tlb_range(c,va,count<<shift);return !c->user_view_failed;
    }
#endif
    struct sptm_memory m=sptm_context_memory(c);
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];struct shadow s=user_shadow(c,e);
        for(uint64_t n=0;n<count;n++)if(entries[n].old!=entries[n].next)
            if(!sptm_root_commit_update(e,&s,&m,va+(n<<shift),shift,entries[n].old,entries[n].next))return 0;
        if(!user_refresh_all(c,e))return 0;
    }
    user_tlb_range(c,va,count<<shift);return !c->user_view_failed;
}
/* XNU's phystokv is linear except for frames SLIDE_REGION moved; every PTE
 * pointer returned to XNU goes through both (see sptm.h). */
static struct sptm_aperture xnu_aperture(const struct context *c)
{
    const struct params *p=c->params;
    return (struct sptm_aperture){p->mem_low,p->ram_aperture_va,p->alloc_high-p->mem_low};
}
static struct sptm_moved xnu_moved(const struct context *c)
{
    return sptm_slide_moved(&c->slide,&c->params->slide);
}
static int user_backend(struct context *c,uint64_t root,struct sptm_user_backend *b)
{
    b->ttbr0=vcpu_of(c)->guest_ttbr0;b->ttbr1=vcpu_of(c)->guest_ttbr1;
    b->aperture=xnu_aperture(c);b->moved=xnu_moved(c);
    b->active_refs=0;b->mirror=0;b->prepare_leaf=user_prepare_leaf;b->commit_leaf=user_commit_leaf;b->ctx=c;
    b->prepare_unmap=user_prepare_unmap;b->commit_unmap=user_commit_unmap;
    b->prepare_detach=user_prepare_detach;b->commit_detach=user_commit_detach;
    b->shared_detaches=&c->shared_detaches;
    b->prepare_attach=user_prepare_attach;b->commit_attach=user_commit_attach;
    b->prepare_nest=user_prepare_nest;b->commit_nest=user_commit_nest;
    b->prepare_unnest=user_prepare_unnest;b->commit_unnest=user_commit_unnest;
    b->prepare_update=user_prepare_update;b->commit_update=user_commit_update;
    b->prepare_shared_leaf=user_prepare_shared_leaf;b->commit_shared_leaf=user_commit_shared_leaf;
    b->prepare_shared_unmap=user_prepare_shared_unmap;b->commit_shared_unmap=user_commit_shared_unmap;
    b->prepare_shared_update=user_prepare_shared_unmap;b->commit_shared_update=user_commit_shared_update;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        int active=c->user_roots.active[cpu]==root;
        int recorded=(c->vcpus[cpu].guest_ttbr0&0x0000ffffffffc000UL)==root;
        if(active!=recorded || (c->vcpus[cpu].guest_ttbr1&0x0000ffffffffc000UL)==root)return 0;
        b->active_refs+=active;
    }
#if SNAP_USER_HW_WALK
    /* A hardware-walk root: its own events, for an inactive root too (stale
     * TLB entries under its ASIDs, and copies the next install walks).
     * Shared-root calls keep the cached-alias callbacks above. */
    if(hw_root(c,root)) {
        b->prepare_leaf=hw_prepare_leaf;b->commit_leaf=hw_commit_leaf;
        b->prepare_unmap=hw_prepare_unmap;b->commit_unmap=hw_commit_unmap;
        b->prepare_detach=hw_prepare_detach;b->commit_detach=hw_commit_detach;
        b->prepare_attach=hw_prepare_attach;b->commit_attach=hw_commit_attach;
        b->prepare_nest=hw_prepare_nest;b->commit_nest=hw_commit_nest;
        b->prepare_unnest=hw_prepare_unnest;b->commit_unnest=hw_commit_unnest;
        b->prepare_update=hw_prepare_update;   /* commit: user_commit_update's hw prelude */
        b->mirror=!b->active_refs;
        return 1;
    }
#endif
    return !b->active_refs || user_cached(c,root)!=0;
}
static int user_update_backend(void *ctx,uint64_t root,struct sptm_user_backend *b)
{return user_backend(ctx,root,b);}
/* One UPDATE_DISJOINT engine call (Apple ...270fdc44): endpoint 6 and each
 * endpoint 0x15 group. A frame can have both user and kernel aliases; every
 * record must preflight before either domain publishes any changes. */
struct mixed_kernel_context {
    const struct sptm_memory *memory;
    const struct sptm_update_backend *backend;
};
static enum sptm_result mixed_kernel_prepare(void *ctx,uint64_t target,uint64_t va,
    uint64_t requested,uint64_t options,uint64_t scratch,uint64_t bytes,
    struct sptm_update_entry *entry)
{
    const struct mixed_kernel_context *k=ctx;
    return sptm_kernel_update_prepare(k->memory,k->backend,target,va,requested,
                                      options,scratch,bytes,entry);
}
static void mixed_kernel_commit(void *ctx,struct sptm_update_entry *entry)
{
    const struct mixed_kernel_context *k=ctx;sptm_kernel_update_commit(k->memory,entry);
}
/* Linked-AuxKC observation (compat/auxkc-observe.h): count, log the first
 * few execute transitions, never refuse. */
static void auxkc_note_leaf(struct context *c,unsigned kind,uint64_t elr,
                            uint64_t va,uint64_t old,uint64_t next)
{
    if(auxkc_observe_leaf(&c->auxkc_exec,&c->params->auxkc,kind,elr,va,old,next))
        record(c,EV_AUXKC_EXEC,elr,va,old,next);
}

static int update_disjoint_call(struct context *c,uint64_t target,uint64_t list,
    uint64_t count,uint64_t options,uint64_t scratch,uint64_t elr,uint64_t *out)
{
    const struct params *p=c->params;
    struct sptm_memory memory=sptm_context_memory(c);
    struct sptm_update_backend backend={.kernel_root=p->ttbr1_root,
        .shadow_root=vcpu_of(c)->shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    enum sptm_result result=SPTM_BAD_CONFIG;
    uint64_t response=SPTM_SUCCESS;
    volatile uint8_t *records=count && count<=64 && !(list&7) && list<=UINT64_MAX-count*24 ?
        memory.map(memory.ctx,list,count*24):0;
    int user=0,kernel=0;
    if(records)for(uint64_t n=0;n<count;n++) {
        if(((volatile uint64_t *)records)[n*3]==p->ttbr1_root)kernel=1;
        else user=1;
    }
    if(kernel)kernel_class_proof_forget(c);
    c->attr_updates.pending=0;
    if(user && kernel && ((p->tcr>>16)&63)==17) {
        struct mixed_kernel_context kctx={&memory,&backend};
        struct sptm_mixed_kernel_backend k={.root=p->ttbr1_root,
            .workspace=&c->update_workspace,.ctx=&kctx,
            .prepare=mixed_kernel_prepare,.commit=mixed_kernel_commit};
        result=sptm_mac_update_mixed_disjoint(&memory,user_update_backend,c,&k,
            target,list,count,options,scratch,&response,
            &c->user_updates[vcpu_of(c)->slot]);
    } else if(user && !kernel)
        result=sptm_mac_update_user_disjoint(&memory,user_update_backend,c,
            target,list,count,options,scratch,&response,
            &c->user_updates[vcpu_of(c)->slot]);
    else if (((p->tcr>>16)&63)==17) {
        kernel_class_proof_forget(c);
        result=sptm_mac_update_disjoint(&memory,&backend,&c->update_workspace,
            target,list,count,options,scratch);
    }
    if (result!=SPTM_OK) {
        record(c,EV_UPDATE_FAILED,elr,result,target,options);
        return 0;
    }
    if(!user) {
        response=sptm_update_result(&c->update_workspace,count,options);
        struct sptm_user_update_state *s=&c->kernel_updates[vcpu_of(c)->slot];
        struct sptm_update_entry *e=&c->update_workspace.entries[0];
        s->calls++;s->entries+=count;
        for(uint64_t n=0;n<count;n++) {
            s->changed+=c->update_workspace.entries[n].old!=c->update_workspace.entries[n].next;
            if(p->auxkc.va_end)
                auxkc_note_leaf(c,AUXKC_KIND_UPDATE,elr,((volatile uint64_t *)records)[3*n+1],
                    c->update_workspace.entries[n].old,c->update_workspace.entries[n].next);
        }
        s->options=options;s->result=response;s->target=target;s->count=count;
        s->root=p->ttbr1_root;s->va=((volatile uint64_t *)records)[1];
        s->requested=((volatile uint64_t *)records)[2];
        s->slot=e->slot_pa;s->old=e->old;s->next=e->next;s->shift=14;s->flags=0;
        s->last_changed=e->old!=e->next;
    }
    if(user && kernel && p->auxkc.va_end)for(uint64_t n=0;n<count;n++)
        if(((volatile uint64_t *)records)[3*n]==p->ttbr1_root)
            auxkc_note_leaf(c,AUXKC_KIND_UPDATE,elr,((volatile uint64_t *)records)[3*n+1],
                c->update_workspace.entries[n].old,c->update_workspace.entries[n].next);
    if(!transaction_publish(c)) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,target,options);return 0;
    }
#if SNAP_USER_UPDATE_KERNEL_SKIP
    if(user && !kernel)user_update_kernel_skip(c);
    else
#endif
    shadow_tlb_sync(c);
    attr_clean_finish(c);
    c->update_calls++; c->update_entries+=count;
    *out=response;
    if(user) {
        volatile uint64_t *rec=(volatile uint64_t *)records;
        volatile uint64_t *old=(volatile uint64_t *)memory.map(memory.ctx,scratch,count*8);
        for(uint64_t n=0;n<count;n++) {
            uint64_t root=rec[3*n];
            if(root==p->ttbr1_root || (root&0x3fff) || root<memory.frame_low || root>=memory.frame_high)continue;
            volatile uint8_t *meta=memory.map(memory.ctx,
                memory.frame_map_pa+((root-memory.frame_low)>>14)*16,16);
            if(!meta || meta[2]!=SPTM_MAC_SHARED_ROOT_TABLE)continue;
            unsigned slot=vcpu_of(c)->slot;
            struct sptm_user_update_state *s=&c->shared_disjoint[slot];
            c->shared_disjoint_records[slot]++;
            s->calls++;s->entries+=count;s->options=options;s->result=response;s->target=target;
            s->count=count;s->root=root;s->va=rec[3*n+1];s->requested=rec[3*n+2];
            s->old=old ? old[n]:0;s->slot=elr;
        }
    }
    return 1;
}
/* UPDATE_DISJOINT_MULTIPAGE's aperture step for a header without 0x200
 * (...270dfb1c): flag 2 gives both aperture aliases of the DEFAULT frame the
 * header's AttrIndx (SH and permissions unchanged). The frame is cleaned to
 * PoC before the store; publication, the private-view refresh and the
 * all-VMID TLBI complete before the group's own records, then the frame is
 * cleaned again. Apple defers that TLBI under flag 0x80 and answers 5,
 * except when the leaf leaves a posted AttrIndx (...dfd7c); the answer is
 * reproduced although the invalidation here is always synchronous. */
#if !SNAP_MULTIPAGE_FAST
static int multipage_aperture(struct context *c,const struct sptm_multipage_group *g,
    uint64_t elr,uint64_t *out)
{
    const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    c->attr_updates.pending=0;
    uint64_t before=0,after=0;
    enum sptm_result r=SPTM_OK;
    if(g->aperture_flags&2) {
        r=sptm_papt_prepare_attr(&m,&b,&a,&moved,g->target,(unsigned)g->aperture_attr,&change);
        if(r)goto failed;
        /* Apple rewrites the alias its phystokv names: the moved one if any. */
        before=change.leaf[change.count-1].before;after=change.leaf[change.count-1].after;
        int changed=0;
        for(unsigned i=0;i<change.count;i++)changed|=change.leaf[i].before!=change.leaf[i].after;
        if(changed) {
            r=SPTM_MEMORY_UNAVAILABLE;
            if(!sptm_attr_clean(c,g->target,0x4000))goto failed;
            kernel_class_proof_forget(c);
            sptm_papt_commit(&m,&change);
            r=SPTM_SHADOW_FAILED;
            if(!transaction_publish(c))goto failed;
            shadow_tlb_sync(c);if(c->kernel_view_failed)goto failed;
            attr_clean_finish(c);
            c->attr_updates.apertures+=change.count;
        }
        c->attr_updates.last_pa=g->target;
        c->attr_updates.last_before=before;c->attr_updates.last_after=after;
    }
    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;
    return 1;
failed:
    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);
    return 0;
}
#else
_Static_assert(SPTM_MULTIPAGE_MAX<=SPTM_DISJOINT_MAX,"one call's changed frames fit attr_updates.pending (P6)");
/* P5: the cacheability class of an AttrIndx under the pinned MAIR (tools/test-sptm-mair.py): 1 Normal
 * write-back 0xff (0 WRITEBACK, 4 INNERWRITEBACK), 2 Normal-NC (1 WRITECOMB), 3 WRITETHRU (2), 4 Device (3, 5,
 * 6, 7). Both cleans are skipped only when no cache can hold anything different for the frame afterwards: the
 * same write-back encoding, or non-cacheable before and after. */
static int multipage_same_class(uint64_t before,uint64_t after)
{
    static const unsigned char attr_class[8]={1,2,3,4,1,4,4,4};
    unsigned a=attr_class[(before&PT_ATTRINDX)>>2],b=attr_class[(after&PT_ATTRINDX)>>2];
    return (a==1 && b==1) || ((a==2 || a==4) && (b==2 || b==4));
}
/* P1-P3: xnuboot_trap, before runtime_enter, without the token. The ops page is read with the planner's bounds
 * and every aperture-step target (a header without 0x200, with option 0x20) is cleaned to PoC by VA through
 * EL2's identity map of guest RAM; the set is this vCPU's, armed for this trap only. The plan read under the
 * token decides; a target not in the set is cleaned inline. Data-preserving, so a stale or hostile list only
 * costs cleans. */
static void multipage_preclean(struct context *c,const uint64_t *frame,uint64_t esr)
{
    struct multipage_preclean_cpu *set=&c->root_ext->multipage_preclean[vcpu_of(c)->slot];
    set->count=0;
    if((esr>>26)!=0x20 || frame[16]!=SPTM_FN_UPDATE_DISJOINT_MULTIPAGE)return;
    const struct params *p=c->params;
    uint64_t ops=frame[0],count=frame[1];
    if(!count || count>SPTM_MULTIPAGE_MAX || (ops&7) || (ops&0x3fff)+count*24>0x4000)return;
    volatile uint8_t *in=sptm_map(c,ops,count*24);
    if(!in)return;
    for(uint64_t i=0;i<count;) {
        volatile uint8_t *h=in+i*24;
        uint64_t target=*(volatile uint64_t *)h,w=*(volatile uint64_t *)(h+16);
        uint32_t mappings=(uint32_t)w,options=(uint32_t)(w>>32);
        i++;
        if(!(options&0x200) && (options&0x20) && !(target&0x3fff) && target>=p->mem_low &&
           target<p->mem_high && p->mem_high-target>=0x4000 && set->count<SPTM_MULTIPAGE_MAX) {
            for(uint64_t line=target;line<target+0x4000;line+=64)
                __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
            set->pa[set->count++]=target;
        }
        if(mappings>count-i)break;
        i+=mappings;
    }
    if(set->count) {__asm__ volatile("dsb ish" ::: "memory");set->frames+=set->count;}
}
static void multipage_preclean_clear(struct context *c)
{c->root_ext->multipage_preclean[vcpu_of(c)->slot].count=0;}
static int multipage_precleaned(struct context *c,uint64_t pa)
{
    const struct multipage_preclean_cpu *set=&c->root_ext->multipage_preclean[vcpu_of(c)->slot];
    for(uint64_t n=0;n<set->count && n<SPTM_MULTIPAGE_MAX;n++)if(set->pa[n]==pa)return 1;
    return 0;
}
/* sptm_attr_clean for a frame already cleaned to PoC before the token: the same refusals, the same pending
 * entry for attr_clean_finish's second clean, the same count. */
static int attr_clean_note(struct context *c,uint64_t pa)
{
    const struct params *p=c->params;struct attr_update_state *s=&c->attr_updates;
    if((pa&0x3fff) || pa<p->mem_low || pa>=p->mem_high || 0x4000>p->mem_high-pa ||
       s->pending>=SPTM_DISJOINT_MAX) {
        s->refused++;return 0;
    }
    s->pending_pa[s->pending++]=pa;s->cleans++;
    return 1;
}
/* P7-P9, P19: a changed canonical shadow word. In a level-3 kernel-view copy source, while the reuse snapshot is
 * valid for these views and PPERMs, it is written into the six copies (sprr_views_sync_word: a full sync's own
 * translation), into every PPERM variant column still exact for this snapshot generation (sprr_variants_exact's
 * test: an unchanged saves means unchanged canonical words, which must stay true), and into the snapshot. Otherwise
 * nothing is written: the run's refresh then misses its proof and syncs and saves in full. */
static int multipage_view_patch(struct context *c,uint64_t pa)
{
    if(!c->kernel_views.count)return 1;
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    int n=sprr_views_word_table(&c->kernel_views,pa);
    if(n==-1)return 1;
    struct shadow s=kernel_shadow(c);
    struct sprr_reuse_state *r=&c->kernel_reuse_state;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
    int ok=n>=0 && r->valid && r->root==s.root && r->count==c->kernel_views.count;
    if(ok) {
        const struct sprr_view_table *a=&r->tables[n],*b=&c->kernel_views.tables[n];
        ok=a->source==b->source && a->level==b->level;
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)ok=ok && a->copy[cpu]==b->copy[cpu] && r->pperm[cpu]==pp[cpu];
    }
    if(!ok) {st->unpatched++;return 1;}
    uint64_t extra[GUEST_CPU_COUNT]={0},extra_pp[GUEST_CPU_COUNT]={0};
#if SNAP_KERNEL_PPERM_VARIANTS
    const struct sprr_view_variants *v=&c->kernel_variants;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(v->count[cpu]==c->kernel_views.count && v->saves[cpu] && v->saves[cpu]==r->saves &&
           v->copy[n][cpu] && v->source[n][cpu]==c->kernel_views.tables[n].source) {
            extra[cpu]=v->copy[n][cpu];extra_pp[cpu]=v->pperm[cpu];st->variants++;
        }
#endif
    unsigned index=(unsigned)((pa&4095)/8);
    if(!sprr_views_sync_word(&c->kernel_views,&s,(unsigned)n,index,pp,extra,extra_pp)) {
        c->kernel_view_failed=1;return 0;
    }
    r->words[n][index]=*(volatile uint64_t *)pa;
    st->patched++;return 1;
}
/* multipage_aperture without its own publication, refresh, TLBI and second clean: the open run is closed by
 * multipage_close (P12). The first clean is the pre-clean's when this trap made one (P1), none for a
 * same-class change (P5), else inline as before. The answer is computed exactly as before. */
static int multipage_aperture_fast(struct context *c,const struct sptm_multipage_group *g,
    uint64_t elr,uint64_t *out,int *open)
{
    const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    uint64_t before=0,after=0;
    enum sptm_result r=SPTM_OK;
    if(g->aperture_flags&2) {
        r=sptm_papt_prepare_attr(&m,&b,&a,&moved,g->target,(unsigned)g->aperture_attr,&change);
        if(r)goto failed;
        before=change.leaf[change.count-1].before;after=change.leaf[change.count-1].after;
        int changed=0,same=1;
        for(unsigned i=0;i<change.count;i++) {
            changed|=change.leaf[i].before!=change.leaf[i].after;
            same&=multipage_same_class(change.leaf[i].before,change.leaf[i].after);
        }
        if(changed) {
            r=SPTM_MEMORY_UNAVAILABLE;
            if(same)st->same_class++;
            else if(multipage_precleaned(c,g->target)) {
                if(!attr_clean_note(c,g->target))goto failed;
                st->preclean_hits++;
            } else {
                if(!sptm_attr_clean(c,g->target,0x4000))goto failed;
                st->inline_cleans++;
            }
            kernel_class_proof_forget(c);
            sptm_papt_commit(&m,&change);
            *open=1;
            r=SPTM_SHADOW_FAILED;
            for(unsigned i=0;i<change.count;i++)for(unsigned n=0;n<4;n++)
                if(!multipage_view_patch(c,(uint64_t)(uintptr_t)change.leaf[i].shadow[n]))goto failed;
            c->attr_updates.apertures+=change.count;
        }
        c->attr_updates.last_pa=g->target;
        c->attr_updates.last_before=before;c->attr_updates.last_after=after;
    }
    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;
    return 1;
failed:
    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);
    return 0;
}
/* P10/P12/P6: the open run's publication (copies included: their stores were noted), then the exact reuse
 * proof and the all-VMID TLBI, then the second cleans (deferred past the token by SNAP_ATTR_CLEAN_DEFER). */
static int multipage_close(struct context *c,uint64_t elr,const struct sptm_multipage_group *g,int barrier)
{
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    st->closes++;if(barrier)st->barrier_closes++;
    if(!transaction_publish(c)) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
    }
#if SNAP_KERNEL_DIRTY_PUBLISH
    /* P20: the patched copy pages through their own publication, so every pending row is empty again (the PPERM
     * skip and the variant swap require it). */
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if((c->kernel_publish_state.pending[cpu][0] || c->kernel_publish_state.pending[cpu][1]) &&
           !kernel_publish_cpu(c,cpu)) {
            record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
        }
#endif
    shadow_tlb_sync(c);
    if(c->kernel_view_failed) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
    }
    attr_clean_finish(c);
    return 1;
}
/* The MULTIPAGE loop: a run of aperture steps is closed before any group with records (update_disjoint_call
 * resets attr_updates.pending and does its own transaction, P6) and at the end; a failure closes an open run
 * best-effort before the guest is stopped (P13). */
static int multipage_fast(struct context *c,const struct sptm_multipage_plan *plan,uint64_t elr,
                          uint64_t scratch,uint64_t *response)
{
    int open=0;
    c->attr_updates.pending=0;
    for(uint64_t g=0;g<plan->groups;g++) {
        const struct sptm_multipage_group *grp=&plan->group[g];
        uint64_t one;
        if(grp->aperture_flags) {
            if(!multipage_aperture_fast(c,grp,elr,&one,&open)) {
                c->root_ext->multipage_fast.failures++;
                if(open)(void)multipage_close(c,elr,grp,0);
                return 0;
            }
            if(one==5)*response=5;
        }
        if(!grp->count)continue;
        if(open) {
            if(!multipage_close(c,elr,grp,1))return 0;
            open=0;
        }
        if(!update_disjoint_call(c,grp->target,grp->list,grp->count,grp->options,scratch,elr,&one))return 0;
        if(one==5)*response=5;
    }
    if(open && !multipage_close(c,elr,&plan->group[plan->groups-1],0))return 0;
    return 1;
}
#endif

/* Apple IMPDEF registers, reached through HCR_EL2.TIDCP. Names from
 * m1n1 (AsahiLinux, cpu_regs.h) and the author's J700 research fork. */
#define SR_AMXIDR_EL1     SYSREG(3, 6, 15, 2, 7)
#define SR_GXF_STATUS_EL1 SYSREG(3, 6, 15, 8, 0)
#define SR_CONST_LOWER   SYSREG(3, 0, 11, 1, 2)
#define SR_CONST_UPPER   SYSREG(3, 0, 11, 1, 3)


/* AMX is not optional to this kernel. `machine_routines_apple.c:165` decodes
 * AMXIDR_EL1 as a version: bits 0..5 select versions 1..6, anything set in bits
 * 6..15 panics, and so does zero --
 *
 *     panic: AMXIDR_EL1 doesn't advertise any known version of AMX
 *
 * which is what a zero answer produced. Version 1 is the smallest claim that
 * satisfies it, and XNU takes an extra path only at version 5 and above, so it
 * is also the one that asks the least of a machine that has no AMX at all. */
#define AMXIDR_VERSION_1  1UL

/* Opt-in: after XNU's PANIC_ENTRY, serve ordinary calls instead of stopping.
 * Apple's dispatcher then switches to a panic-only protocol this monitor does
 * not implement (docs/PANIC-STATE-HANDOFF-20260922.md), so by default the first
 * post-panic call from any CPU stops the run, which can happen before the
 * panicking CPU has printed its panic string (v32: CPU 1's SWITCH_ROOT after
 * CPU 2's entry). With this define the dying guest is served as if it had not
 * panicked, so it can finish its report; panic_state.rejected counts the calls
 * served this way. An invalid panic state still stops. */
#ifndef SNAP_PANIC_SERVE
#define SNAP_PANIC_SERVE 0
#endif

/* Answer a monitor call in place, or 0 if it is one we do not implement yet.
 *
 * The first thing a stock XNU asks for is SERIAL_PUTC. Answering it is what
 * turns this from a machine that stops at the first question into one that
 * tells us what it is doing, so it is the first endpoint implemented and the
 * console it produces is the report. */
static int monitor_call_impl(struct context *c, uint64_t *frame, uint64_t *elr)
{
    uint64_t x16 = frame[16];
    uint32_t cmd = (uint32_t)((x16 >> 56) & 0xff);
    uint32_t domain = (uint32_t)((x16 >> 48) & 0xff);
    /* Sixteen bits, not eight. Not a live bug in this kernelcache -- all 173
     * distinct x16 constants it builds have bits 47:40 clear, so the two masks
     * give identical answers for every call it makes -- but the dispatcher
     * takes the whole of bits 63:32 with `lsr x21, x0, #32` and narrows
     * nothing, so eight bits is an assumption rather than a reading. Widening
     * costs nothing and makes two tables aliasing onto one impossible, which is
     * the bug this file just fixed one field over. */
    uint32_t table = (uint32_t)((x16 >> 32) & 0xffff);
    uint32_t endpoint = (uint32_t)x16;
    if(!sptm_panic_dispatch(&c->panic_state,(unsigned)vcpu_of(c)->slot,x16)
#if SNAP_PANIC_SERVE
       && !(c->panic_state.triggered==1 && c->panic_state.phase==1 && c->panic_state.owner<6 &&
            vcpu_of(c)->slot<6)
#endif
       ) {
        record(c,EV_PANIC_STATE_FAILED,*elr,x16,c->panic_state.owner,vcpu_of(c)->slot);
        return 0;
    }

    /* Counted here, at the top, before any branch can decline to answer.
     *
     * Every path out of this function is a call that happened: the ones we
     * implement, the ones we acknowledge permissively, and the ones we refuse
     * and stop on. Counting after the dispatch would leave the refusals out,
     * and the refusals are the ones worth counting. The guard on `endpoint` is
     * what keeps the index honest rather than merely in range -- see the
     * declaration. */
    if (cmd == SPTM_CMD_ENDPOINT && domain == 0 && table == 0 &&
        endpoint < ENDPOINT_BUCKETS)
        c->endpoint_calls[endpoint & (ENDPOINT_BUCKETS - 1)]++;
    else
        c->endpoint_other++;
    /* A reference batch abandoned by an earlier refusal is not a remap. */
    c->pv_audit.pending = 0;
    /* Before any endpoint can allocate a table: restore the arena reserve. */
    if (cmd == SPTM_CMD_ENDPOINT) arena_reserve(c, frame);

    /* The dispatch command comes first, because it decides whether the rest of
     * the word means anything at all.
     *
     * This field was unread until now, and not reading it was not a cosmetic
     * gap: four distinct calls the kernel makes -- x16 = 0x02, 0x04, 0x05 and
     * 0x06 in bits 63:56, with domain, table and endpoint all zero -- decoded
     * as domain 0 / table 0 / endpoint 0, which is LOCKDOWN. We answered all
     * four with SPTM_SUCCESS. Four different questions, one wrong answer each.
     *
     * SPTM's own dispatcher is the authority. `dispatch_cmd_handler` at
     * 0xfffffff0270f2270 does exactly this:
     *
     *   lsr  x20, x0, #56          ; the dispatch command
     *   ubfx x9,  x0, #48, #8      ; the domain
     *   lsr  x21, x0, #32          ; the table, in the low byte
     *   cmp  x20, #0x7 ; b.hs      -> illegal dispatch command
     *   ldr  x10, [x12, x20, lsl #3]   ; table[calling_domain][command]
     *
     * so the commands run 0..6 and are indexed per calling domain, and its
     * error strings name the field: "dispatch_cmd_id(%u)",
     * VIOLATION_ILLEGAL_DISPATCH_CMD. XNU is calling domain 1: the table at
     * 0xfffffff02701f4f8 has handlers for that row at commands 0, 4, 5 and 6,
     * and command 2 is special-cased before the lookup (0xfffffff0270f2310
     * tests exactly `cmd == 2 && calling_domain == 1`). That is the full set
     * the kernelcache emits, which is the cross-check.
     *
     * Command 0 is an ordinary endpoint call and is the only one this monitor
     * implements. The genuine LOCKDOWN call still reaches its handler: the stub
     * at 0xfffffe000c22b37c builds x16 = 0 outright -- all four fields zero --
     * and its genter is at 0xfffffe000c22b38c. */
    if (cmd == SPTM_CMD_PANIC_ENTRY) {
        if(x16!=UINT64_C(0x0200000000000000) ||
           !sptm_panic_enter(&c->panic_state,(unsigned)vcpu_of(c)->slot)) {
            record(c,EV_PANIC_STATE_FAILED,*elr,x16,c->panic_state.owner,vcpu_of(c)->slot);
            return 0;
        }
        /* The same global service token serializes first-owner selection,
         * byte publication and the return to any of the six guest CPUs. */
        uint64_t panic_page=c->params->scratch_pa-SPTM_PANIC_PAGE_SIZE;
        *(volatile uint8_t *)panic_page=1;
        publish(panic_page,panic_page+1);
        /* XNU announcing that it is taking a fatal exception.
         *
         * Implemented, not acknowledged, and the distinction is the point: the
         * return values below are not a permissive stub that happens to be
         * zero. Apple's handler is the five instructions at 0xfffffff0270f2520
         * -- a call to a helper, `mov x0, #0`, `mov x1, #0`, and a branch to the
         * monitor exit -- so zero in both is byte-for-byte what the real monitor
         * returns. The trampoline marshals nothing (`mov x16, #0x200...; genter;
         * ret`), so there are no arguments to read either.
         *
         * The helper at 0xfffffff0270f220c has exactly three side effects and
         * including a guest-visible byte: 0xfffffff0271100a4 is set
         * to 1, a halfword at 0xfffffff02710c00c compare-and-swapped from its
         * 0x8000 "nobody" sentinel to this CPU's logical id, and a byte at
         * 0xfffffff02710c00e swapped from 0xff to 1. XNU's EL0 fault path
         * reads that byte through handoff +0x198. The loader supplies a private
         * page, read-only and execute-never in all six stage-2 roots.
         *
         * First-owner and flag semantics are implemented. Native SPTM's
         * restricted panic dispatch uses a separate exception-return protocol;
         * that protocol remains unsupported. The gate above stops explicitly
         * if requested instead of continuing ordinary services after panic.
         *
         * It is rare, not hot, and the distinction was worth correcting: this
         * is not called on every synchronous exception. XNU runs the kernel
         * with SPSel = 0, so an ordinary kernel exception takes the EL1t vector
         * and never comes here; the EL1h sites are reached only when an
         * exception happened inside a handler, which SPTM itself calls an error
         * ("Synchronous exception taken while SP1 selected"). The normal
         * continuation at 0xfffffe000b86f61c gates twice before calling --
         * `tst x4, #0xc` on SPSR_EL1 so EL0 exceptions never reach it, then a
         * fatal-class predicate at 0xfffffe000ba862c0 -- so it fires for
         * unrecoverable kernel control-flow failures and nothing else. Never
         * for EL0, never for ordinary page faults, never for copyio. In
         * practice once per boot. */
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);

        /* The fault itself, which is the reason this call is worth anything.
         *
         * XNU reads ELR_EL1, ESR_EL1 and FAR_EL1 into x26, x27 and x28 in the
         * three instructions before the genter -- but only at three of the six
         * call sites. At 0xfffffe000b86ebbc (the wedge), 0xfffffe000b8c13b8 and
         * 0xfffffe000b8c1b48, those registers hold something else entirely, so
         * reading them as a fault there would report a per-CPU pointer as a
         * faulting address and be believed.
         *
         * So the registers are recorded raw and the host decides, and the
         * system registers are read here as well: EL1 still holds the fault
         * that got us here -- XNU has only copied them, not rewritten them --
         * which is a source that does not depend on which caller it was. */
        uint64_t p_esr, p_far, p_elr;
        __asm__ volatile("mrs %0, esr_el1" : "=r"(p_esr));
        __asm__ volatile("mrs %0, far_el1" : "=r"(p_far));
        __asm__ volatile("mrs %0, elr_el1" : "=r"(p_elr));
        if (!vcpu_of(c)->panic_calls)
            fill_regs(&vcpu_of(c)->panic_exc, frame, p_esr, p_elr, p_far);
        /* x30 names the caller, and one of them decides whether anything after
         * this runs at all: a return to 0xfffffe000b86ebc0 lands on `wfe` and a
         * branch to itself. The host spells that out. */
        record(c, EV_PANIC_ENTRY, *elr, frame[30], p_elr, p_esr);
        vcpu_of(c)->panic_calls++;

        frame[0] = 0;
        frame[1] = 0;
        c->calls++;
        *elr += 4;
        return 1;
    }

    if (cmd != SPTM_CMD_ENDPOINT) {
        /* Recorded twice on purpose: once as the call it is, so the transcript
         * shows where it sits in the sequence, and once as the reason we
         * stopped, so the last event names the command rather than leaving a
         * reader to decode the top byte of x16 by hand. */
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        record(c, EV_DISPATCH_CMD, *elr, cmd, domain, x16);
        c->dispatch_cmds++;
        /* Not answered, and not answered even in permissive mode.
         *
         * Permissive exists so one run can show the whole sequence of endpoints
         * XNU asks for, and for an endpoint the cost of a false acknowledgement
         * is a wrong value. Here it is worse than that. Two of these calls do
         * not return: the trampolines for 0x05 (0xfffffe000c22a9b0) and 0x06
         * (0xfffffe000c22a9d4) are followed by `b #0x0`, a branch to
         * themselves, because SPTM transfers control into another domain and
         * never comes back to that instruction. Stepping over one of those puts
         * the guest in a one-instruction infinite loop, which the watchdog
         * would report as "still running" -- a hang wearing the costume of
         * progress. 0x04 does not return either. Only 0x02 ends in a `ret`.
         *
         * So there is no acknowledgement to give that is not a lie, and the
         * honest move is to stop and say which command was asked for. */
        return 0;
    }

    if (domain == 2 && table == 0 &&
        (endpoint == 1 || endpoint == 2 || endpoint == 3 || endpoint == 7 || endpoint == 12 || endpoint == 14 || endpoint == 16 ||
         endpoint == 26 || endpoint == 30 || endpoint == 31 ||
         endpoint == 35 || endpoint == 36 || endpoint == 37 || endpoint == 45 || endpoint == 52)) {
        const struct params *p = c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        memory.retype_txm_owned=sptm_retype_txm_owned;
        struct sptm_aperture aperture = {p->mem_low, p->ram_aperture_va,
                                        p->mem_high - p->mem_low};
        struct txm_service service = {p->txm_stacks_pa, p->txm_stack_count,
            p->txm_log_pa, sptm_aperture_pointer(&aperture, p->txm_log_pa, 0x4000),
            p->txm_rw_pa, sptm_aperture_pointer(&aperture, p->txm_rw_pa, 0x4000),
            p->txm_ro_pa, sptm_aperture_pointer(&aperture, p->txm_ro_pa, 0x4000)};
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        struct txm_arena arena = {p->txm_aspace_pa,
            sptm_aperture_pointer(&aperture, p->txm_aspace_pa, TXM_ASPACE_SIZE)};
        struct txm_kernel_memory kernel_memory={&memory,
            vcpu_of(c)->guest_ttbr1&0x0000ffffffffc000UL,vcpu_of(c)->guest_tcr};
        uint64_t image4_status=TXM_IMAGE4_UUID_UNAVAILABLE;
        uint64_t trust_status=TXM_TRUST_CACHE_MISS;
        uint64_t compilation_status=8;
        struct txm_load_ops load_ops={c,txm_load_prepare,txm_load_stage,txm_load_authenticate};
        enum sptm_result result = !service.log_va ? SPTM_BAD_CONFIG :
            endpoint == 12 ?
            txm_trust_load(&memory,&service,&p->trust_cache,&c->trust_state,
                &c->txm_load,&load_ops,frame,&trust_status) :
            endpoint == 7 ?
            txm_sep_channel_unavailable(&memory,&service,endpoint,frame) :
            endpoint == 26 ?
            txm_set_local_key(&memory,&service,&c->txm_local_key,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame) :
            endpoint == 52 ?
            txm_image4_nonce_digest(&memory,&service,&c->txm_nonce_digests,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame) :
            endpoint == 14 ?
            txm_trust_query(&memory,&service,&p->trust_cache,&c->trust_state,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&trust_status) :
            endpoint == 16 ?
            txm_trust_uuid(&memory,&service,&p->trust_cache,&c->trust_state,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&trust_status) :
            endpoint == 30 ?
            txm_compilation_match_empty(&memory,&service,txm_copy_kernel_input,
                &kernel_memory,endpoint,frame,&compilation_status) :
            endpoint == 45 && frame[1]==0 ?
            txm_image4_release_type(&memory,&service,&c->txm_release_type,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&image4_status) :
            endpoint == 45 && frame[1]==3 ?
            txm_image4_nonce(&memory,&service,&c->txm_nonces,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&image4_status) :
            endpoint == 45 ? txm_image4(&memory,&service,endpoint,frame) :
            endpoint == 31 ?
            txm_developer_mode(&memory, &service, endpoint, frame) :
            endpoint == 35 || endpoint == 36 || endpoint == 37 ?
            txm_aspace(&memory, &service, &arena, TXM_REG(c), endpoint, frame) :
            txm_info_with_trust(&memory,&service,&p->trust_cache,&c->trust_state,endpoint,frame);
        if (result != SPTM_OK) {
            record(c,EV_TXM_FAILED,*elr,result,
                   frame[1],endpoint);return 0;
        }
        frame[0] = endpoint==45 ? image4_status : (endpoint==12 || endpoint==14) ? trust_status :
            endpoint==30 ? compilation_status : endpoint==7 ? TXM_SEP_CHANNEL_UNAVAILABLE : 0;
        if (endpoint==45 && frame[1]==6) c->txm_image4_uuid_rejections++;
        if (endpoint == 31) c->txm_developer_notifications++;
        c->calls++;
        *elr += 4;
        return 1;
    }
    if (domain == 0 && table == 3 && (endpoint == 0 || endpoint == 2 || endpoint == 3 || endpoint == 8)) {
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        unsigned index;
        unsigned level=endpoint==0 ? (unsigned)frame[3] : (endpoint==2 || endpoint==3) ? 2 : 0;
        if (frame[0]>=32 || frame[1]>=2 || (endpoint==0 && frame[3]>2) ||
            device_dart_admit_frame(c->params->models,c->model_state,
                (unsigned)c->params->model_count,5,(unsigned)frame[0],
                (unsigned)frame[1],level,&index)!=DEVICE_OK) return 0;
        struct sptm_memory memory=sptm_context_memory(c);
        enum sptm_result result=endpoint==0 ?
            sptm_dart_map_table(&memory,&c->model_state[index].dart,
                frame[0],frame[1],frame[2],frame[3],frame[4]) :
            endpoint==2 ? sptm_dart_map(&memory,&c->model_state[index].dart,
                frame[0],frame[1],frame[2],frame[3],frame[4],frame[5]) :
            endpoint==3 ? sptm_dart_unmap(&memory,&c->model_state[index].dart,
                frame[0],frame[1],frame[2],frame[3],frame[4]) :
            sptm_dart_enable(&memory,&c->model_state[index].dart,frame[0],frame[1]);
        if (result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[2],frame[4]);return 0;
        }
        /* Stage 4: stream 0 of the Adreno virtual DART, into SMMU CB0. UNMAP
         * returns only after the SMMU TLB invalidation has completed. */
        const struct params *gp=c->params;
        if ((endpoint==2 || endpoint==3) && (gp->gpu.flags & ADRENO_F_DART) &&
            frame[0]==SPTM_DART_ADRENO && !frame[1]) {
            struct gpu_leaf_ctx leaf={&memory,&c->model_state[index].dart};
            struct adreno_ops o=gpu_ops(c);
            if (endpoint==2) c->gpu.maps++; else c->gpu.unmaps++;
            int e=adreno_mirror(&o,&gp->gpu,&c->gpu,frame[2],endpoint==2 ? frame[4] : frame[3],
                                gpu_leaf,&leaf,gp->mem_low,gp->mem_high);
            if (e) {record(c,EV_GPU_SMMU,*elr,(uint64_t)(int64_t)e,frame[2],endpoint);return 0;}
        }
        frame[0]=0;c->calls++;*elr+=4;return 1;
    }
    if (domain == 0 && table == 3 && (endpoint == 5 || endpoint == 6)) {
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        enum device_result result=endpoint==6 ?
            device_dart_monitor_init(c->params->models,c->model_state,
                (unsigned)c->params->model_count,frame[0]) :
            device_dart_monitor_powerup(c->params->models,c->model_state,
                (unsigned)c->params->model_count,frame[0]);
        if (result != DEVICE_OK) return 0;
        /* Both services are void. The kernel control wrapper supplies its
         * own success status; x1..x7 are not inputs. */
        frame[0] = 0;
        c->calls++;
        *elr += 4;
        return 1;
    }
    if (domain == 0 && table == 7 && endpoint == 12) {
        const struct params *p = c->params;
        struct sptm_aperture aperture = {p->mem_low, p->ram_aperture_va,
                                        p->mem_high - p->mem_low};
        uint64_t value;
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        if (uat_get_info(&p->uat, &aperture, frame[0], &value) != SPTM_OK) return 0;
        frame[0] = value;
        c->calls++;
        *elr += 4;
        return 1;
    }
    if (domain == 0 && table == 9) {
        uint64_t value;
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        if (!cputrace_empty_query(endpoint, &value)) return 0;
        if (c->cputrace_queries[endpoint-1] != UINT32_MAX)
            c->cputrace_queries[endpoint-1]++;
        frame[0] = value;
        c->calls++;
        *elr += 4;
        return 1;
    }
    /* SPTM table 6 (NVME) and 5 (SART): the virtual ANS2 only. Without its
     * models these fall through exactly as before (unimplemented). */
    if (domain == 0 && (table == 5 || table == 6) && ans_state_of(c)) {
        struct ans_state *s=ans_state_of(c);
        struct ans_ops o=ans_ops_of(c);
        uint64_t ret=0;
        if (table == 5 || endpoint > 2) record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        int r=ans_sptm(s,&o,table,endpoint,frame,&ret);
        if (r) {
            record(c, EV_ANS, *elr, (uint64_t)r << 32 | table << 8 | endpoint, frame[0], frame[1]);
            return 0;
        }
#if SNAP_ANS_ASYNC
        /* The call polled queue 1 first (compat/ans.c): a completion it posted raises its line here, and a
         * command it started arms this vCPU's deadline (N3). */
        ans_async_schedule(c);
        if (ans_async_lines(c)!=DEVICE_OK) {
            record(c, EV_ANS, *elr, (uint64_t)ANS_E_STATE << 32 | table << 8 | endpoint, frame[0], frame[1]);
            return 0;
        }
        timer_sync(c);
#endif
        frame[0]=ret; c->calls++; *elr += 4;
        return 1;
    }
    if (domain != 0 || table != 0) return 0;

    /* Log every call, not just the ones we cannot answer. An implemented
     * endpoint that returns the wrong thing is invisible otherwise, and the
     * sequence of what XNU asks for is most of the evidence about what it is
     * doing. SERIAL_PUTC is the exception: it is one call per character and
     * would fill the log with the console, which is already captured. */
    if (endpoint != SPTM_FN_SERIAL_PUTC)
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);

    struct guest_cpu_buffer cpu_scratch;
    enum guest_cpu_result cpu_status = guest_cpu_buffer(&c->cpus,vcpu_of(c)->slot,
        c->params->scratch_pa,c->params->scratch_va,c->params->mem_low,
        c->params->mem_high,&cpu_scratch);
    if (cpu_status != CPU_OK) {
        record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,vcpu_of(c)->slot);
        return 0;
    }

    switch (endpoint) {
    case SPTM_FN_SIGN_USER_POINTER:
    case SPTM_FN_AUTH_USER_POINTER: {
#if SNAP_FAST_PAUTH_CALLS
        /* The converted call's body too; a refused configuration is
         * SPTM_BAD_CONFIG, recorded as below. */
        struct vcpu *v=vcpu_of(c);int ran=0;
        enum sptm_result result=user_pointer_call(c,frame,endpoint,&ran);
#else
        struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;uint64_t tcr;
        __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
        if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
           !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                     &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
            aes_clear(&native,sizeof(native));
            record(c,EV_TABLE_FAILED,*elr,SPTM_BAD_CONFIG,frame[0],endpoint);return 0;
        }
        enum sptm_result result=pauth_pointer(frame[0],frame[1],frame[2],
            endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,
            pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);
        aes_clear(&native,sizeof(native));
#endif
        if(result) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],endpoint);return 0;
        }
        frame[0]=c->pauth_pointer[v->slot].result;
        break;
    }
    case SPTM_FN_BATCH_SIGN_USER_POINTER: {
#if SNAP_FAST_PAUTH_CALLS
        /* As above; a refused configuration ran nothing, so its record
         * names the endpoint, not a failed_index. */
        struct vcpu *v=vcpu_of(c);int ran=0;
        struct sptm_memory memory=sptm_context_memory(c);
        enum sptm_result result=user_pointer_batch(c,&memory,frame,&cpu_scratch,&ran);
        if(result) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],ran ? c->pauth_batch[v->slot].failed_index : endpoint);
            return 0;
        }
#else
        struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;
        struct sptm_memory memory=sptm_context_memory(c);uint64_t tcr;
        __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
        if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
           !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                     &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
            aes_clear(&native,sizeof(native));
            record(c,EV_TABLE_FAILED,*elr,SPTM_BAD_CONFIG,frame[0],endpoint);return 0;
        }
        enum sptm_result result=pauth_batch_sign(&memory,&c->pauth_batch[v->slot],
            frame[0],frame[1],cpu_scratch.pa,cpu_scratch.va,(tcr>>37)&1,(tcr>>51)&1,
            pauth_batch_native_sign,&native);
        aes_clear(&native,sizeof(native));
        if(result) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],c->pauth_batch[v->slot].failed_index);
            return 0;
        }
#endif
        frame[0]=c->pauth_batch[v->slot].result_va;
        break;
    }
    case SPTM_FN_SWITCH_ROOT: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_root_backend backend={.kernel_root=c->params->ttbr1_root,
            .kernel_shadow=vcpu_of(c)->low_root,.build=user_root_build,
            .install=user_root_install,.ctx=c,
            .validate=SNAP_ROOT_VALIDATE_WORDS ? &c->root_validate : 0,
            .evictions=&c->root_evictions,
            .memo=SNAP_ROOT_VALIDATE_MEMO ? &c->root_memo : 0,
            .skip_hit_validation=NATIVE_SKIP_HIT
#if SNAP_ROOT_MISS_FAST
            ,.stamp=USTAMPS(c),.linked_builds=1
#endif
#if SNAP_USER_HW_WALK
            ,.hw_eligible=hw_switch_eligible
#endif
            };
        uint64_t full=UNS(c).full;
        enum sptm_result r=sptm_mac_switch_root(&memory,&c->user_roots,&backend,
            (unsigned)vcpu_of(c)->slot,frame[0],frame[1],frame[2]);
        if(r || c->root_install_failures) {
            if(UNS(c).full!=full)
                record(c,EV_NATIVE_SHARED_FULL,*elr,UNS(c).full,frame[0],NATIVE_SHARED_GROUPS);
            else record(c,EV_REFERENCE_FAILED,*elr,r,frame[0],frame[1]);
            return 0;
        }
#if SNAP_USER_HW_WALK
        /* A hardware-walk root has a record, not a cache entry (v53). */
        if(!hw_walk_note_loaded(&c->user_roots,c->hw_walk,c->root_loaded,(unsigned)vcpu_of(c)->slot)) {
#else
        if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,(unsigned)vcpu_of(c)->slot)) {
#endif
            record(c,EV_REFERENCE_FAILED,*elr,SPTM_BAD_CONFIG,frame[0],frame[1]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_SLIDE_REGION: {
        const struct params *p=c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_update_backend backend={.kernel_root=p->ttbr1_root,
            .shadow_root=vcpu_of(c)->shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
        kernel_class_proof_forget(c);
        enum sptm_result result=sptm_mac_slide_region(&memory,&backend,&p->slide,
            &c->slide,frame[0],frame[1],c->lockdowns!=0);
        if(result!=SPTM_OK) {
            record(c,EV_SLIDE_FAILED,*elr,result,frame[0],frame[1]);return 0;
        }
        if(!transaction_publish(c)) {
            record(c,EV_SLIDE_FAILED,*elr,SPTM_SHADOW_FAILED,frame[0],frame[1]);return 0;
        }
        shadow_tlb_sync(c);
        record(c,EV_SLIDE_REGION,*elr,frame[0],c->slide.cursor-frame[1]*0x4000,frame[1]);
        frame[0]=SPTM_SUCCESS;
        break;
    }
    case SPTM_FN_UPDATE_REGION: {
        const struct params *p=c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        c->attr_updates.pending=0;
        if(frame[0]!=p->ttbr1_root) {
            struct sptm_user_backend user={0};uint64_t result=0;
            enum sptm_result r=SPTM_BAD_TABLE;
            if(user_backend(c,frame[0],&user)) {
                volatile uint8_t *meta=0;
                if(!(frame[0]&0x3fff) && sptm_managed_frame(&memory,frame[0]))
                    meta=memory.map(memory.ctx,memory.frame_map_pa+((frame[0]-memory.frame_low)>>14)*16,16);
                if(meta && meta[2]==SPTM_MAC_SHARED_ROOT_TABLE)
                    r=sptm_mac_update_shared_region(&memory,&user,frame[0],frame[1],frame[2],
                        frame[3],frame[4],cpu_scratch.pa,&result,&c->shared_regions_updates[vcpu_of(c)->slot]);
                else r=sptm_mac_update_user_region(&memory,&user,frame[0],frame[1],frame[2],
                        frame[3],frame[4],cpu_scratch.pa,&result,&c->user_regions[vcpu_of(c)->slot]);
            }
            if(r) {record(c,EV_REGION_FAILED,*elr,r,frame[1],frame[4]);return 0;}
            /* Every changed leaf's commit_update completed its all-VMID TLBI. */
            attr_clean_finish(c);
            frame[0]=result;break;
        }
        struct sptm_update_backend backend={.kernel_root=p->ttbr1_root,
            .shadow_root=vcpu_of(c)->shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
        enum sptm_result result=SPTM_BAD_CONFIG;
        if (((p->tcr>>16)&63)==17) {
            kernel_class_proof_forget(c);
            result=sptm_mac_update_region(&memory,&backend,&c->update_workspace,
                frame[0],frame[1],frame[2],frame[3],frame[4],cpu_scratch.pa);
        }
        if (result!=SPTM_OK) {
            record(c,EV_REGION_FAILED,*elr,result,frame[1],frame[4]);return 0;
        }
        if(!transaction_publish(c)) {
            record(c,EV_REGION_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],frame[4]);return 0;
        }
        shadow_tlb_sync(c);
        attr_clean_finish(c);
        c->region_calls++;c->region_entries+=frame[2];
        if(auxkc_overlaps(&p->auxkc,frame[1],frame[2]))
            for(uint64_t n=0;n<frame[2] && n<SPTM_DISJOINT_MAX;n++)
                auxkc_note_leaf(c,AUXKC_KIND_UPDATE,*elr,frame[1]+n*0x4000,
                    c->update_workspace.entries[n].old,c->update_workspace.entries[n].next);
        frame[0]=sptm_update_result(&c->update_workspace,frame[2],frame[4]);
        break;
    }
    case SPTM_FN_UPDATE_DISJOINT: {
        uint64_t response;
        if(!update_disjoint_call(c,frame[0],frame[1],frame[2],frame[3],cpu_scratch.pa,
                                 *elr,&response))return 0;
        frame[0]=response;
        break;
    }
    case SPTM_FN_UPDATE_DISJOINT_MULTIPAGE: {
        /* (ops PA, record count). Each header's group is its aperture step
         * (no 0x200), then one UPDATE_DISJOINT engine call; the result is 5
         * if any step returned 5. The plan is copied and validated whole
         * before the first group runs. */
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_multipage_plan plan;
        enum sptm_result r=sptm_mac_multipage_plan(&memory,frame[0],frame[1],&plan);
        if(r) {record(c,EV_UPDATE_FAILED,*elr,r,frame[0],frame[1]);return 0;}
        uint64_t response=SPTM_SUCCESS;
#if SNAP_MULTIPAGE_FAST
        if(!multipage_fast(c,&plan,*elr,cpu_scratch.pa,&response))return 0;
#else
        for(uint64_t g=0;g<plan.groups;g++) {
            uint64_t one;
            /* A failed step leaves earlier ones applied; the guest is not resumed. */
            if(plan.group[g].aperture_flags) {
                if(!multipage_aperture(c,&plan.group[g],*elr,&one))return 0;
                if(one==5)response=5;
            }
            if(!plan.group[g].count)continue;
            if(!update_disjoint_call(c,plan.group[g].target,plan.group[g].list,
                   plan.group[g].count,plan.group[g].options,cpu_scratch.pa,*elr,&one))
                return 0;
            if(one==5)response=5;
        }
#endif
        c->multipage_calls++;c->multipage_groups+=plan.groups;
        frame[0]=response;
        break;
    }
    case SPTM_FN_UNMAP_DISJOINT: {
        const struct params *p=c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        uint64_t count=(uint32_t)frame[2];
        volatile uint8_t *records=count && count<=64 && !(frame[1]&7) ?
            memory.map(memory.ctx,frame[1],count*24):0;
        int kernel=records && *(volatile uint64_t *)records==p->ttbr1_root;
#if SNAP_UNMAP_MIXED
        /* Every record's domain, as UPDATE_DISJOINT: one frame aliased by user
         * and kernel roots comes as one list (v39 stopped on a user-first
         * one). A mixed list then publishes as a kernel one below. */
        int mixed=0;
        if(records)for(uint64_t n=1;n<count;n++)
            mixed|=(((volatile uint64_t *)records)[n*3]==p->ttbr1_root)!=kernel;
        if(mixed)kernel=1;
#endif
        enum sptm_result result=SPTM_BAD_CONFIG;
#if SNAP_UNMAP_MIXED
        if(mixed) {
            if(((p->tcr>>16)&63)==17) {
                struct shadow shadow={.txsz=17,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,
                    .read=mem_read,.write=mem_write,.ctx=c};
                const struct sptm_unmap_kernel k={p->ttbr1_root,&shadow,
                    &c->kernel_disjoint_unmaps[vcpu_of(c)->slot]};
                kernel_class_proof_forget(c);
                result=sptm_mac_unmap_mixed_disjoint(&memory,user_update_backend,c,&k,
                    frame[0],frame[1],count,cpu_scratch.pa,
                    &c->user_disjoint_unmaps[vcpu_of(c)->slot]);
            }
        } else
#endif
        if(kernel && ((p->tcr>>16)&63)==17) {
            struct shadow shadow={.txsz=17,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,
                .read=mem_read,.write=mem_write,.ctx=c};
            kernel_class_proof_forget(c);
            result=sptm_mac_unmap_kernel_disjoint(&memory,&shadow,p->ttbr1_root,
                frame[0],frame[1],count,cpu_scratch.pa,
                &c->kernel_disjoint_unmaps[vcpu_of(c)->slot]);
        } else if(!kernel)
            result=sptm_mac_unmap_user_disjoint(&memory,user_update_backend,c,
                frame[0],frame[1],count,cpu_scratch.pa,
                &c->user_disjoint_unmaps[vcpu_of(c)->slot]);
        if(result) {
            record(c,EV_UNMAP_FAILED,*elr,result,frame[0],frame[2]);return 0;
        }
        if(kernel) {
            if(!transaction_publish(c)) {
                record(c,EV_UNMAP_FAILED,*elr,SPTM_SHADOW_FAILED,frame[0],count);return 0;
            }
            shadow_tlb_sync(c);
            if(c->kernel_view_failed) {
                record(c,EV_UNMAP_FAILED,*elr,SPTM_SHADOW_FAILED,frame[0],count);return 0;
            }
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_UNMAP_REGION: {
        const struct params *p=c->params;
        record(c,EV_UNMAP_REGION,*elr,frame[1],frame[2],frame[3]);
        struct sptm_memory memory=sptm_context_memory(c);
        struct shadow shadow={.txsz=17,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,
            .read=mem_read,.write=mem_write,.ctx=c,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
        enum sptm_result result=SPTM_BAD_TABLE;
        if (frame[0]==p->ttbr1_root && ((p->tcr>>16)&63)==17)
            result=sptm_mac_unmap_region(&memory,&shadow,frame[0],frame[1],
                                         frame[2],frame[3],cpu_scratch.pa);
        struct sptm_user_backend user={0};
        if(frame[0]!=p->ttbr1_root && user_backend(c,frame[0],&user))
            result=sptm_mac_unmap_user_region(&memory,&user,frame[0],frame[1],
                                             frame[2],frame[3],cpu_scratch.pa);
        if (result!=SPTM_OK) {
            record(c,EV_UNMAP_FAILED,*elr,result,frame[1],frame[2]);
            return 0;
        }
        if(frame[0]==p->ttbr1_root) {
            if(!transaction_publish(c)) {
                record(c,EV_UNMAP_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],frame[2]);return 0;
            }
            shadow_tlb_sync(c);
        }
        frame[0]=SPTM_SUCCESS;
        break;
    }
    case SPTM_FN_NEST_REGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};enum sptm_result r=SPTM_BAD_TABLE;
        uint64_t full=UNS(c).full;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_nest_region(&memory,&backend,frame[0],frame[1],frame[2],frame[3]);
        if(r && UNS(c).full!=full) {
            record(c,EV_NATIVE_SHARED_FULL,*elr,UNS(c).full,frame[1],NATIVE_SHARED_GROUPS);return 0;
        }
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[2],frame[3]);return 0;}
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_UNNEST_REGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};enum sptm_result r=SPTM_BAD_TABLE;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_unnest_region(&memory,&backend,frame[0],frame[1],frame[2],frame[3]);
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[2],frame[3]);return 0;}
        c->unnest_va=frame[2];c->unnest_pages=(uint32_t)frame[3];c->unnest_cpu=vcpu_of(c)->slot;
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_UNMAP_TABLE: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};
        enum sptm_result r=SPTM_BAD_TABLE;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_unmap_user_table(&memory,&backend,frame[0],frame[1],frame[2]);
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[1],frame[2]);return 0;}
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_CONDEMN_LEAF_TABLE:
    case SPTM_FN_UNCONDEMN_LEAF_TABLE: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};uint64_t result=0;
        enum sptm_result r=SPTM_BAD_TABLE;
        unsigned condemn=x16==SPTM_FN_CONDEMN_LEAF_TABLE;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_condemn_user_table(&memory,&backend,frame[0],frame[1],condemn,&result);
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[1],x16);return 0;}
#if SNAP_USER_HW_WALK
        /* The level-2 group's software bit: copies stay byte-exact. */
        if(!result && !hw_after_table(c,frame[0],frame[1],2)) {
            record(c,EV_TABLE_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],x16);return 0;
        }
#endif
        if(!result) {
            if(condemn)c->user_condemn_calls++;else c->user_uncondemn_calls++;
        }
        frame[0]=result;break;
    }
    case SPTM_FN_MAP_TABLE: {
        const struct params *p = c->params;
        record(c, EV_MAP_TABLE, *elr, frame[1], frame[2], frame[3]);
        struct sptm_memory memory=sptm_context_memory(c);
        enum sptm_result result = SPTM_BAD_TABLE;
        if (frame[0] == p->ttbr1_root && ((p->tcr >> 16) & 63) == 17)
            result = sptm_mac_map_table(&memory, frame[0], frame[1], frame[2], frame[3]);
        struct sptm_user_backend user={0};
        if(frame[0]!=p->ttbr1_root && user_backend(c,frame[0],&user))
            result=sptm_mac_map_user_table_live(&memory,&user,frame[0],frame[1],frame[2],frame[3]);
        if (result != SPTM_OK && result != SPTM_TABLE_MISSING && result != SPTM_TABLE_EXISTS) {
            record(c, EV_TABLE_FAILED, *elr, result, frame[1], frame[3]);
            return 0;
        }
#if SNAP_USER_HW_WALK
        if(result==SPTM_OK && frame[0]!=p->ttbr1_root &&
           !hw_after_table(c,frame[0],frame[1],(unsigned)frame[2])) {
            record(c,EV_TABLE_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],frame[3]);return 0;
        }
#endif
        if(result==SPTM_OK && frame[0]!=p->ttbr1_root) {
            /* An empty table adds no hardware mappings; retain live roots. */
            if(user.active_refs)c->user_live_tables++;
#if SNAP_INACTIVE_MIRROR
            /* And cached inactive ones: the attach callbacks already copied a
             * commpage table's leaves into every cached root. */
            else if(user_cached(c,frame[0]))c->inactive_mirror.stats.tables++;
#endif
            else if(!sptm_root_invalidate(&c->user_roots,frame[0],0))return 0;
        }
        frame[0] = result == SPTM_TABLE_MISSING ? 7 : result == SPTM_TABLE_EXISTS ? 8 : 0;
        break;
    }
    case SPTM_FN_CONFIGURE_ROOT: {
        struct sptm_memory memory=sptm_context_memory(c);
        memory.configure_user_root=sptm_configure_user_root;
        memory.root_configuration=&c->root_configuration;
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        enum sptm_result result=sptm_mac_configure_root(&memory,frame[0],frame[1],frame[2]);
        if(result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],frame[2]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_SET_SHARED_REGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        memory.bind_shared_root=sptm_bind_shared_root;
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        enum sptm_result result=sptm_mac_set_shared_region(&memory,frame[0],frame[1]);
        if(result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],frame[1]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_CONFIGURE_SHAREDREGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        enum sptm_result result=sptm_mac_configure_sharedregion(&memory,frame[0],frame[1],frame[2]);
        if(result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],frame[2]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_RETYPE: {
        struct sptm_memory memory=sptm_context_memory(c);
        memory.retire_user_root=sptm_retire_user_root;
        memory.share_user_root=sptm_share_user_root;
        memory.retire_shared_root=sptm_retire_shared_root;
        memory.admit_iommu=sptm_admit_iommu;
        memory.retype_rozone=sptm_retype_rozone;
        memory.retype_user_exec=sptm_retype_user_exec;
        memory.retype_txm_default=sptm_retype_txm_default;
#if SNAP_NATIVE_LIVE
        memory.created_user_root=native_root_created;
#endif
        record(c, EV_RETYPE, *elr, frame[0],
               (frame[1] << 32) | (frame[2] & 0xffffffffUL), frame[3]);
        int aux_frame = auxkc_observe_retype(&c->auxkc_exec, &c->params->auxkc,
                                             frame[0], frame[1], frame[2]);
        enum sptm_result result = sptm_mac_retype(&memory, frame[0], frame[1],
                                                frame[2], frame[3]);
        if (result != SPTM_OK) {
            c->auxkc_exec.retype_failed += (uint64_t)aux_frame;
            record(c, EV_RETYPE_FAILED, *elr, result, frame[0], frame[2]);
            return 0;       /* no permissive acknowledgement of a failed retype */
        }
#if SNAP_USER_HW_WALK_S2RO
        /* A frame that became (or stopped being) an SPTM table: read-only
         * (or RW again) at stage 2 before XNU sees the result. */
        int s2=hw_s2_retype_action((unsigned)frame[1],(unsigned)frame[2]);
        if (s2 >= 0 && !hw_s2_frame(c, frame[0], s2)) {
            record(c, EV_RETYPE_FAILED, *elr, SPTM_SHADOW_FAILED, frame[0], frame[2]);
            return 0;
        }
#endif
        frame[0] = SPTM_SUCCESS;
        break;
    }
    case SPTM_FN_MAP_PAGE: {
        /* (root_pa, va, new_pte). The reference handler is
         * m1n1-j700/src/sptm/xnu.c:163.
         *
         * Two views have to agree or the guest and the hardware diverge
         * silently: XNU's own 16K tables, which it reads back and reasons
         * about, and the 4K shadow the MMU actually walks. Writing the guest
         * slot and then re-inserting that one leaf into the shadow is the whole
         * transaction, and doing it in that order means the shadow is derived
         * from what the guest now says rather than from what we were passed --
         * so a PTE we decode wrongly shows up as a shadow that disagrees with
         * the guest, which test-shadow.c is built to catch, instead of as two
         * consistent wrong answers.
         *
         * This does not create tables. The reference returns TABLE_NOT_PRESENT
         * when a level is missing, and MAP_TABLE is the call that adds one. */
        uint64_t root_pa = frame[0], va = frame[1], new_pte = frame[2];
        /* User leaves update their own shared shadow, never TTBR1's image. */
        if(root_pa!=c->params->ttbr1_root) {
            struct sptm_memory memory=sptm_context_memory(c);
            struct sptm_user_backend backend={0};
            uint64_t shared_before=c->shared_map_calls;
            uint64_t result;
            enum sptm_result r=SPTM_BAD_TABLE;
#if SNAP_INACTIVE_MIRROR
            struct sptm_root_cached *kept=0;uint64_t live=c->user_live_pages;
#endif
            if(user_backend(c,root_pa,&backend)) {
                backend.map_updates=&c->user_map_replacements[vcpu_of(c)->slot];
#if SNAP_INACTIVE_MIRROR
                if(!backend.active_refs && (kept=user_cached(c,root_pa))!=0)
#if SNAP_NATIVE_LIVE
                    /* Every leaf, TPRO included, is O(1) to mirror (variant
                     * copies follow each store): only arena room is asked. */
                    backend.mirror=arena_available(c)>=INACTIVE_MIRROR_ARENA_PAGES;
#else
                    backend.mirror=(unsigned)inactive_mirror_admit(0,1,new_pte,
                        UBUDGETS(c)[kept-c->user_roots.cache],arena_available(c));
#endif
#endif
                r=sptm_mac_map_user_page(&memory,&backend,root_pa,
                    va,new_pte,frame[3],cpu_scratch.pa,&result);
            }
            if(r==SPTM_TABLE_MISSING) {
                c->user_missing_tables++;frame[0]=7;break;
            }
            if(r) {record(c,EV_REFERENCE_FAILED,*elr,r,va,new_pte);return 0;}
            if(c->shared_map_calls!=shared_before) {
                c->shared_map_requested=new_pte;c->shared_map_options=frame[3];
                c->shared_map_result=result;c->shared_map_cpu=vcpu_of(c)->slot;
            }
            if(result==SPTM_USER_MAP_CONFLICT) {
                struct user_map_conflict_state *s=&c->user_map_conflict[vcpu_of(c)->slot];
                s->count++;s->root=root_pa;s->va=va;s->wanted=new_pte;
                s->options=frame[3];s->old=s->pointer=0;s->result=result;
                if(!(frame[3]&1)) {
                    volatile uint64_t *out=(volatile uint64_t *)cpu_scratch.pa;
                    s->old=out[0];s->pointer=out[1];
                }
            } else if(!backend.active_refs &&
#if SNAP_INACTIVE_MIRROR
                      !inactive_map_keep(c,kept,&backend,new_pte,result,live) &&
#endif
                      !sptm_root_invalidate(&c->user_roots,root_pa,0))return 0;
            c->map_pages++;frame[0]=result;break;
        }
        /* ROZONE aperture leaves are created by the validated RETYPE path,
         * which detaches private CPU views before publishing selector2.
         * MAP_PAGE must not expose that raw selector through a shared branch. */
        if((new_pte&1) && (sprr_pte_class(new_pte)==2 || sprr_pte_class(new_pte)==4 ||
                          sprr_pte_class(new_pte)==9)) {
            map_page_failed(c,*elr,MAP_FAIL_SPRR_CLASS,va,new_pte);return 0;
        }
        uint32_t t1sz = (uint32_t)((c->params->tcr >> 16) & 0x3f);
        struct mmu_config guest = {.granule_shift = 14, .txsz = t1sz, .root = root_pa};

        /* Is the root we were handed inside memory we own?
         *
         * The walk below dereferences it at EL2 through mem_read, which is a
         * raw load that cannot fail and has no return code to check. So a root
         * pointing anywhere else is not a failure reason: it is an EL2 fault
         * with no label, which arrives at the host as "the monitor faulted,
         * ESR ..." and says nothing about which call did it or with what.
         *
         * Checking first is what turns that into a named, counted refusal with
         * the VA and the root in it. Refused rather than reported, unlike the
         * out-of-window PTE below: a PTE we cannot vouch for still describes a
         * mapping the kernel wants, while a root we cannot read is an address
         * we are about to fault on. The whole root table has to fit, not just
         * its first byte. */
        if (c->params->mem_low &&
            (root_pa < c->params->mem_low ||
             root_pa + 0x4000 > c->params->mem_high)) {
            map_page_failed(c, *elr, MAP_FAIL_ROOT_OUTSIDE, va, root_pa);
            frame[0] = SPTM_TABLE_NOT_PRESENT;
            break;
        }

        /* Every failure below says which one it was.
         *
         * All six returned the same SPTM_TABLE_NOT_PRESENT and recorded
         * nothing, so a run that failed a map looked exactly like one that did
         * not: the transcript showed 144 consecutive successes and then a panic
         * from pmap, with no way to tell which call failed or why. That is the
         * endpoint-0 collapse again, one layer down -- several distinct causes
         * flattened onto one answer. The count and the address are what turn
         * "MAP_PAGE failed" into a question with one answer instead of six. */
        uint64_t table = root_pa;
        int start = mmu_start_level(14, t1sz);
        if (start < 0) { map_page_failed(c, *elr, MAP_FAIL_START_LEVEL, va, root_pa);
                         frame[0] = SPTM_TABLE_NOT_PRESENT; break; }
        int missing = 0;
        uint64_t missing_at = 0;
        for (int level = start; level < 3; level++) {
            uint64_t entry;
            if (mem_read(c, table + 8UL * mmu_index(14, (uint32_t)level, va), &entry)
                || (entry & 3) != 3) { missing = 1; missing_at = (uint64_t)level; break; }
            table = entry & PT_OA_MASK;
        }
        /* The one a missing table hierarchy produces, and the one that decides
         * whether MAP_TABLE is what we are missing. The level is recorded
         * because "which level was absent" is the next question after "was it
         * this branch". */
        if (missing) { record(c, EV_MAP_NEEDS_TABLE, *elr, missing_at, va, table);
                       frame[0] = SPTM_TABLE_NOT_PRESENT; break; }

        /* Does this PTE point at memory we told XNU about?
         *
         * Reported, never refused. We do not know whether a PTE outside the
         * window is XNU asking for something wrong or our idea of the window
         * being too narrow, and refusing a mapping the kernel needs turns a
         * diagnosable problem into a hang. So this completes the map and says
         * so -- counted separately from the failures, because it is not one.
         *
         * Worth having because of what it would have caught: 379 maps were
         * accepted with output addresses at 8 and 12 GiB, against a window that
         * ends at 3.83 GiB, and nothing said a word. That is the same shape as
         * every other bug this file has grown a log line for -- an answer that
         * could be wrong in a way nobody can see.
         *
         * The whole PTE goes in the record rather than a decode of it: the
         * attribute bits differ between the entries we write and the ones XNU
         * does (0x703 against 0x40f), that difference may matter, and the host
         * can decode a PTE better than this can. */
        uint64_t pte_pa = new_pte & PT_OA_MASK;
        int points_outside = 0;
        if (c->params->mem_low && (new_pte & 1) &&
            (pte_pa < c->params->mem_low || pte_pa >= c->params->mem_high) &&
            !(c->params->fb_span && pte_pa >= c->params->fb_pa &&
              pte_pa - c->params->fb_pa < c->params->fb_span)) {
            points_outside = 1;
            /* Only the first few, because they are all the same shape and
             * the log is 64 entries. 379 identical lines say nothing that five
             * do not, and they push every other event out -- which is how this
             * broke the classifier the first time it fired in anger. The
             * counter carries the true total either way. */
            if (c->map_outside < MAP_OUTSIDE_LOGGED)
                record(c, EV_MAP_OUTSIDE, *elr, pte_pa, va, new_pte);
            c->map_outside++;
            /* Here rather than beside one of the branches below, so the table
             * and the counter describe the same set of pages by construction:
             * the spans must add up to map_outside, and the host checks that
             * they do. */
            map_range_note(c, va, pte_pa, new_pte & 0xfff);
        }

        uint64_t slot = table + 8UL * mmu_index(14, 3, va);
        struct sptm_aperture aperture = xnu_aperture(c);
        struct sptm_moved moved = xnu_moved(c);
        uint64_t existing = 0;
        if (mem_read(c, slot, &existing)) { map_page_failed(c, *elr, MAP_FAIL_READ_LEAF, va, slot);
                                            frame[0] = SPTM_TABLE_NOT_PRESENT; break; }
        if ((new_pte&3)!=3) {
            map_page_failed(c,*elr,MAP_FAIL_LEAF_INVALID,va,new_pte);return 0;
        }
        /* The old leaf decides before anything is written (sptm.h). */
        struct sptm_kernel_leaf plan;
        if (sptm_mac_kernel_map_leaf(&aperture, &moved, slot, existing, new_pte, &plan)) {
            map_page_failed(c, *elr, MAP_FAIL_READ_LEAF, va, slot);
            frame[0] = SPTM_TABLE_NOT_PRESENT;
            break;
        }
        uint64_t slot_va = plan.pointer;
        int moved_pointer = slot_va != sptm_aperture_pointer(&aperture, slot, 8);
        if (!plan.install) {
            /* A valid leaf of another page: CONFLICT, no store, no reference
             * move, shadow untouched. XNU removes the old mapping (and its PV
             * entry) and retries. The old PTE and pointer are reported as on
             * the accepted path below. */
            if (cpu_scratch.pa) {
                volatile uint64_t *out = (volatile uint64_t *)cpu_scratch.pa;
                out[0] = plan.old;
                out[1] = plan.pointer;
                __asm__ volatile("dc cvau, %0\n\tdc cvau, %1\n\tdsb ish"
                                 :: "r"(&out[0]), "r"(&out[1]) : "memory");
            }
            c->kernel_map_conflict = (struct kernel_map_conflict_state){
                .count = c->kernel_map_conflict.count + 1, .va = va,
                .wanted = new_pte, .old = plan.old, .pointer = plan.pointer};
            c->map_pages++;
            frame[0] = plan.status;
            break;
        }
        struct sptm_memory memory=sptm_context_memory(c);
        sptm_refs_begin(memory.refs);
        enum sptm_result ref_result=sptm_refs_leaf(&memory,table,va,existing,new_pte);
        if (ref_result==SPTM_OK) ref_result=sptm_refs_validate(&memory);
        if (ref_result!=SPTM_OK) {
            record(c,EV_REFERENCE_FAILED,*elr,ref_result,va,new_pte);return 0;
        }
        if (mem_write(c, slot, new_pte)) { map_page_failed(c, *elr, MAP_FAIL_WRITE_LEAF, va, slot);
                                           return 0; }

        /* What the caller reads back afterwards. The reference writes the PTE
         * that was replaced and the guest VA of the entry itself; XNU reads both
         * and a zero where it expects a pointer is a null dereference several
         * thousand calls later, a long way from here. The clean is not
         * decoration: this is written at EL2 and read at EL1, and nothing else
         * makes the line visible to the other reader.
         *
         * 0xfffffe000ba62e0c is the read: the instruction after this call
         * returns loads cpu_data + 0 and dereferences it. That word is the
         * answer to SPTM_FN_OUTPUT_AREA below, which is why the two have to name
         * the same page. */
        if (cpu_scratch.pa) {
            volatile uint64_t *out = (volatile uint64_t *)cpu_scratch.pa;
            out[0] = existing;
            out[1] = slot_va;
            __asm__ volatile("dc cvau, %0\n\tdc cvau, %1\n\tdsb ish"
                             :: "r"(&out[0]), "r"(&out[1]) : "memory");
            c->pv_audit.moved_pointers += (uint64_t)moved_pointer;
        }

        /* Re-read through the guest's own tables, so the shadow copies what the
         * guest will see rather than what the caller said. */
        struct mmu_leaf leaf;
        if (mmu_walk(&guest, va, mem_read, c, &leaf) < 0) {
            /* The PTE went in and the re-read disagreed, which means the guest
             * table and our decode of it have diverged -- a different failure
             * from the table simply not being there, and the guest has already
             * been modified by the time we get here. */
            map_page_failed(c, *elr, MAP_FAIL_REREAD, va, new_pte);
            return 0;
        }
        int is_device = 0;
        uint64_t model_off;
        if (device_model_find(c->params->models, c->params->model_count,
                              pte_pa, &model_off) >= 0) is_device = 1;
        for (uint64_t n = 0; n < c->params->device_count && n < 4; n++) {
            if (pte_pa >= c->params->device_pa[n] &&
                pte_pa < c->params->device_pa[n] + c->params->device_span[n]) {
                is_device = 1;
                break;
            }
        }
        /* The GPU node's reg windows (adreno.h): passthrough at stage 2. */
        unsigned gpu_block = adreno_block(pte_pa, c->params->gpu.flags);
        if (c->params->gpu.flags && (gpu_block == ADRENO_PASS || gpu_block == ADRENO_CX_MISC_RO))
            is_device = 1;
#if SNAP_I2C_INPUT
        /* The input node's reg page (compat/i2c-input.h): passthrough at stage 2. */
        if (i2c_input_window(&c->params->i2c_input, pte_pa))
            is_device = 1;
#endif
#if SNAP_QCC2072_WIFI
        /* The QCC2072 node's reg windows (compat/qcc2072-wifi.h): passthrough at stage 2. */
        if (qcc2072_wifi_window(qcc2072_wifi_block(c->params), pte_pa))
            is_device = 1;
#endif
#if SNAP_DISPLAY_TIMING
        /* The DPU INTF_5 page (compat/display-timing.h): read-only passthrough at stage 2. */
        if (display_timing_window(display_timing_block(c->params), pte_pa))
            is_device = 1;
#endif
        if (leaf.valid && points_outside && is_device) {
            /* A device the guest's own tree names, so the kernel is right to
             * ask and we are right to answer. The leaf goes in.
             *
             * This is only safe because stage 2 is narrowed (T4). The guest's
             * stage-1 walk now resolves, the access reaches stage 2, the IPA is
             * absent there, and it traps to EL2 with the address -- which is
             * how a device model ever gets a chance to answer. Withholding
             * instead leaves a stage-1 fault that EL1 handles itself, and the
             * kernel dies inside its own serial driver having never reached us.
             *
             * Under the old identity map this would have been the machine
             * reset. The order those two changes landed in was luck, not
             * judgement, and it is worth saying so. */
            if (c->map_device <= MAP_OUTSIDE_LOGGED)
                record(c, EV_MAP_DEVICE, *elr, pte_pa, va, new_pte);
            c->map_device++;
        }
        if (leaf.valid) {
            /* Every PTE goes in, including the ones pointing outside the memory
             * we declared. Withholding is gone, and the reasoning inverts the
             * one that used to sit here.
             *
             * That branch called itself "the accident becomes the policy", and
             * it was right about the accident: before the clip fix, a leaf like
             * this went into a slot the hardware never reads, so withholding
             * was what the code happened to do rather than what it meant. The
             * fix made every insert real, the first run after it reset the
             * machine, and withholding was adopted to stop that.
             *
             * What has changed since is stage 2. Under the narrowed map (T4)
             * these addresses are not identity-mapped to the Snapdragon's bus
             * any more -- they are absent, so an installed PTE means the
             * guest's stage-1 walk resolves, the access reaches stage 2, and it
             * traps to EL2 with the IPA, the register, the size and the
             * direction. That is a device access we can answer or name.
             * Withholding instead leaves a stage-1 fault that EL1 handles
             * itself, and the transcript reads "XNU faulted" where it could
             * have read "the AIC at 0x301000000 was read". The reset this
             * branch was protecting against cannot happen through a map that
             * does not contain those pages.
             *
             * So installing is the loud option and withholding was the quiet
             * one, which is the opposite of how they were introduced. The
             * counter and the span table stay: what is reported has not
             * shrunk, only what is refused. Device models stay per-device,
             * strict and on demand -- the window list is consulted at fault
             * time, not here. */
            /* The clip bounds go in the regime's offset space, not the caller's.
             *
             * This is the bug that made five successful MAP_PAGEs produce a
             * level-1 translation fault. mmu_walk reports `leaf.base` masked
             * into the regime -- `out->base = address & ~(size - 1)`, where
             * `address` has already had the top bits stripped -- but the clip
             * was the raw kernel VA. Being the larger of the two it won, so
             * shadow_map indexed with the raw address: for
             * 0xfffffed000010000 that is level-0 slot 509 where the hardware
             * reads slot 253. The leaf was written into a slot nothing walks.
             *
             * It stayed invisible because every VA mapped before this was
             * already in the shadow from the initial shadow_build, which passes
             * bounds in the same space its walk produces. The wrongly-indexed
             * entries were harmless duplicates of mappings that already
             * resolved. The range above the static map was the first with no
             * prior entry, so it was the first where the wrong slot mattered. */
            uint64_t va_off = va & ((1UL << (64 - t1sz)) - 1);
            struct shadow shadow = {.txsz = t1sz, .root = vcpu_of(c)->shadow_root,
                                    .alloc = table_alloc, .read = mem_read,
                                    .write = mem_write, .ctx = c,
                                    .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
            int put_leaf = shadow_insert(&shadow, &leaf, va_off,
                                         va_off + (1UL << 14));
            if (put_leaf < 0) {
                /* Almost always the 4K shadow's table arena being exhausted,
                 * so the work pointer is recorded rather than the guest's --
                 * that is the number that says whether we ran out of room. */
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_INSERT, va, c->next_table);
                return 0;
            }
            if (put_leaf == SHADOW_NOTHING) {
                /* Accepted and did nothing. This is what a clip in the wrong
                 * address space produced, and reporting success for it is what
                 * let five mappings go missing without a word. */
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_EMPTY, va, leaf.base);
                return 0;
            }

            /* And read it back through the shadow, which is what the hardware
             * actually walks.
             *
             * The guest half of this call has been re-read since the day it was
             * written -- the PTE goes in, then it is walked back through the
             * guest's own tables, so a decode error shows up as a disagreement
             * rather than as two consistent wrong answers. The shadow half was
             * still taking shadow_insert's word for it, and a success there
             * means "nothing refused me", not "the mapping is present".
             *
             * That gap is not theoretical: XNU mapped five pages into the
             * tables above the static map, every call returned success, and it
             * then took a level-1 translation fault reading the fifth. The
             * hardware disagreed with what we had reported, and nothing in the
             * transcript said so.
             *
             * Same walker, 4K config, rooted where TTBR1 points. */
            struct mmu_config shadow_view = {.granule_shift = 12, .txsz = t1sz,
                                             .root = vcpu_of(c)->shadow_root};
            struct mmu_leaf got;
            uint64_t want = leaf.descriptor & PT_OA_MASK & ~(leaf.size - 1);
            if (mmu_walk(&shadow_view, va_off, mem_read, c, &got) < 0 || !got.valid) {
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_ABSENT, va, vcpu_of(c)->shadow_root);
                return 0;
            }
            uint64_t resolved = (got.descriptor & PT_OA_MASK & ~(got.size - 1))
                                + (va_off - got.base);
            if (resolved != want) {
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_WRONG, va, resolved);
                return 0;
            }
        } else {
            /* The guest's own tables say this address is not mapped, yet we are
             * about to report success. That is a silent no-op: any shadow entry
             * from a previous mapping of this address is still there, so the
             * hardware and the guest now disagree in the other direction.
             *
             * Recorded rather than fixed. Removing the shadow leaf is what an
             * unmap should do, and whether this call IS an unmap -- rather than
             * a PTE we decoded wrongly -- is not established. */
            map_page_failed(c, *elr, MAP_FAIL_LEAF_INVALID, va, new_pte);
            return 0;
        }
        /* The shadow is what the MMU walks, so a stale entry for this address
         * outlives the write unless it is dropped. */
        shadow_tlb_sync(c);
        sptm_refs_commit(&memory);
        c->map_pages++;
        auxkc_note_leaf(c, AUXKC_KIND_MAP, *elr, va, existing, new_pte);
        /* Apple reports 1 when a valid same-PA leaf was already present and 0
         * only for an empty slot (sptm_mac_map_page_status); a different-PA
         * valid leaf returned CONFLICT above. */
        frame[0] = plan.status;
        break;
    }
    case SPTM_FN_SERIAL_PUTC:
        console_put(c, (uint8_t)frame[0]);
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_LOCKDOWN:
        if(const_region_seal(c)) {
            record(c,EV_MAP_FAILED,*elr,0x434f4e53,c->params->const_begin,c->params->const_end);
            return 0;
        }
        c->lockdowns++;
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_SERIAL_DISABLE:
        /* The kernel letting go of the monitor's early serial, which it does
         * when it is ready to drive a console of its own. Nothing to release
         * here -- the "serial" is a byte buffer in this context -- so this is
         * an acknowledgement rather than a stub standing in for work.
         *
         * It is recorded because it marks the end of the transcript: any kernel
         * output after this point is the kernel's own console on the panel, not
         * bytes relayed through us, and a console that goes quiet here has
         * succeeded rather than hung. */
        c->serial_disabled = 1;
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_REGISTER_CPU:
        cpu_status = guest_cpu_register(&c->cpus,frame[0]);
        if (cpu_status != CPU_OK) {
            record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,frame[0]);return 0;
        }
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_REGISTER_EXC_RETURN:
        /* The trampoline the monitor is to place in ELR_EL1 when it returns an
         * interrupt to XNU. Recorded because it will be needed the moment
         * anything is delivered, and answered so boot continues. */
        c->exc_return = frame[0];
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_CPU_ID:
        /* ba78910 supplies the topology's physical affinity. Its result is
         * a slot index, stored as u16 and used with a 0x8000-byte stride. */
        {
            uint64_t slot;
            cpu_status = guest_cpu_id(&c->cpus,frame[0],&slot);
            if (cpu_status != CPU_OK) {
                record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,frame[0]);return 0;
            }
            frame[0] = slot;
        }
        break;
    case SPTM_FN_OUTPUT_AREA: {
        /* "Where do I read slot N's results?" -- and the answer is dereferenced,
         * so it is a virtual address and not the physical one we hold.
         *
         * Apple's handler is `sptm_output_area` at 0xfffffff0270bd8d0: it bounds
         * the id against sptm_n_cpus, checks the cpu record agrees with its own
         * index, and returns that record's `+0x1680`, panicking "Scratch page
         * not configured for cpu %p (ID %d)" if it is zero. So a zero is not a
         * neutral answer here; it is the one value the real monitor refuses to
         * give back.
         *
         * What XNU does with it settles the address space. At
         * 0xfffffe000ba7894c it stores the answer at cpu_data + 0, and at
         * 0xfffffe000ba62e0c -- the instruction after a MAP_PAGE call returns --
         * it reloads that word and immediately runs `ldr x8, [x9]` and
         * `ldr x1, [x9, #8]`, keeping the first and comparing it against the PTE
         * it had just asked for. Those two words are exactly what MAP_PAGE above
         * writes into the scratch page: the entry we replaced, and the address
         * of the entry. This is one channel, written at EL2 and read at EL1, and
         * the read is an ordinary EL1 load through the guest's own tables -- so
         * the value handed back has to be the scratch page's *virtual* address.
         *
         * The loader now backs six separate areas in reserved monitor data.
         * Registration and a valid slot are required; no result aliases a
         * different CPU. Allocation does not claim that a CPU has started. */
        uint64_t slot = frame[0];
        struct guest_cpu_buffer output;
        cpu_status = guest_cpu_output(&c->cpus,slot,c->params->scratch_pa,
            c->params->scratch_va,c->params->mem_low,c->params->mem_high,&output);
        if (cpu_status != CPU_OK) {
            record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,slot);return 0;
        }
        frame[0] = output.va;
        break;
    }
    case SPTM_FN_FIXUPS_COMPLETE:
        /* On a real machine this is where SPTM retypes the frames it just let
         * XNU rebase. The host loader applied the chained fixups before the
         * image was ever uploaded (tools/kc-load.py), so there is nothing left
         * to do but agree. */
        frame[0] = SPTM_SUCCESS;
        break;
    default:
        /* Bring-up mode: acknowledge what is not implemented and log it, so one
         * run shows the whole sequence of what XNU asks for instead of one
         * endpoint per round trip. Every answer here is a lie of omission, and
         * the run after a new endpoint appears is the one that has to make it
         * true. */
        if (!c->params->permissive) return 0;
        frame[0] = SPTM_SUCCESS;
        break;
    }

    c->calls++;
    *elr += 4;                      /* over the call, onto the stub's own return */
    return 1;
}
static int monitor_call(struct context *c,uint64_t *frame,uint64_t *elr)
{
    unsigned kind=service_detail_call_bucket(frame[16]);
    int started=detail_begin(c,kind);
    int result=monitor_call_impl(c,frame,elr);
    detail_end(c,kind,started,result);return result;
}

/* --------------------------------------------------------------------------
 * Trapped MMIO: giving XNU back its console.
 *
 * *The story.* The kernel's device tree says there is a UART at 12.13 GiB.
 * There is not -- that is a J700 address and this is a Snapdragon -- so the
 * stage-2 map deliberately leaves those pages absent and every touch of them
 * arrives here instead of wandering onto a bus we do not own. This is where
 * they are answered. The fault syndrome already says how wide the access was,
 * which register it used and which way it went, so the instruction at the PC
 * never has to be fetched or decoded; the device model says what the register
 * holds; the guest's PC steps over the instruction and EL1 resumes none the
 * wiser. A byte written to the transmit register lands in the same console
 * buffer the host has been reading since the first SPTM_FN_SERIAL_PUTC.
 *
 * Keyed by IPA page through the windows the loader derived from the tree, not
 * by a constant: a different tree moves the UART and this still finds it.
 *
 * Strict, and loudly so. An offset the model does not answer stops the run and
 * names the window, the offset, the size and the direction, so the next one is
 * one iteration away rather than a guess. Nothing is ever read as zero because
 * we did not recognise it -- that is step F's SNAP_MMIO_INVENTORY, which is
 * labelled and counted, and doing it here would let a run get further past a
 * register we do not understand and call that progress.
 */

/* Everything the next iteration needs, in one event, and then the run stops. */
static int mmio_stop(struct context *c, uint64_t pc, uint64_t reason,
                     uint64_t window, uint64_t off, uint64_t esr, uint64_t ipa)
{
    record(c, EV_MMIO_STOP, pc, (reason << 48) | (window << 32) | off, esr, ipa);
    return 1;
}

/* Returns 1 to stop and report, 0 to step over the access and resume. */
static int mmio_dispatch(struct context *c, uint64_t *frame, uint64_t *elr,
                         uint64_t esr, uint64_t ipa, int window, uint64_t off)
{
    const struct params *p = c->params;
    uint64_t iss = esr & 0x1ffffff;
    uint64_t w = (uint64_t)window;
    struct dc_access a;

    /* The windows this model was written against. A tree whose node is a
     * different shape would have its offsets mean other things, and answering
     * them anyway is how a model becomes fiction. */
    if (!dc_shape(p->device_span, p->device_count))
        return mmio_stop(c, *elr, MMIO_STOP_SHAPE, w, off, esr, ipa);
    /* An instruction fetch out of a device page. There is no register and no
     * value to emulate, only a PC that should not be there. */
    if ((esr >> 26) != 0x24)
        return mmio_stop(c, *elr, MMIO_STOP_FETCH, w, off, esr, ipa);
    /* S1PTW: it is the stage-1 table walker that faulted, not the access. The
     * syndrome describes the access that provoked the walk, so emulating from
     * it would move the wrong register. */
    if ((iss >> 7) & 1)
        return mmio_stop(c, *elr, MMIO_STOP_S1PTW, w, off, esr, ipa);

    a = dc_decode(esr);
    if (!a.valid)
        return mmio_stop(c, *elr, MMIO_STOP_NO_ISV, w, off, esr, ipa);

    if (a.write) {
        uint8_t tx[4];
        unsigned tx_len = 0, n;
        uint64_t value = dc_narrow(&a, a.reg == 31 ? 0 : frame[a.reg]);
        if (dc_write(&c->uart, window, off, value, tx, &tx_len) != DC_OK)
            return mmio_stop(c, *elr, MMIO_STOP_OFFSET, w, off, esr, ipa);
        for (n = 0; n < tx_len; n++) {
            console_put(c, tx[n]);
            c->uart_tx++;
        }
        c->mmio_writes++;
    } else {
        /* Host input reaches the receive registers only when the launch
         * enabled the console link; otherwise dc_read_rx is dc_read. This
         * runs under the service lock, as console_link_drain does, so it
         * must stay off any lock-free fast path while the ring exists. */
        uint64_t value = 0;
        struct dc_rx *rx = (p->early_stop.flags & EARLY_STOP_F_CONSOLE) ? &c->console_link.rx : 0;
        if (dc_read_rx(&c->uart, rx, window, off, &value) != DC_OK)
            return mmio_stop(c, *elr, MMIO_STOP_OFFSET, w, off, esr, ipa);
        if (a.reg != 31)
            frame[a.reg] = dc_extend(&a, value);
        c->mmio_reads++;
    }

    /* Over the instruction we just stood in for, and back to EL1. */
    *elr += 4;
    return 0;
}

/* PTD reads and ASC messages use integer pairs, whose abort has ISV=0.
 * Validate the instruction and both stage-1 translations before consuming
 * device state. No instruction fetch or data read can reach physical MMIO. */
static enum device_result model_pair_access(struct context *c, uint64_t *frame,
    uint64_t pc, uint64_t esr, uint64_t ipa, unsigned index)
{
    const struct params *p=c->params;
    const struct device_model *model=&p->models[index];
    int write=!!(esr&(1UL<<6));
    if ((model->kind != DEVICE_MCC_PTD_COHERENT_V1 &&
         model->kind != DEVICE_PTD_PMP_ACTIVE_V1 &&
         model->kind != DEVICE_SEP_ASC_MAILBOX_V1 && model->kind != DEVICE_ANS_ASC_V1) || (pc & 3) ||
        (write && model->kind!=DEVICE_SEP_ASC_MAILBOX_V1 && model->kind!=DEVICE_ANS_ASC_V1) ||
        (vcpu_of(c)->guest_sctlr & (1UL << 25))) return DEVICE_BAD_WIDTH;
    uint64_t code=guest_pa(pc), spsr, sp, far;
    if (code < p->mem_low || code > p->mem_high-4) return DEVICE_BAD_WIDTH;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2"
                     : "=r"(spsr), "=r"(far));
    if ((spsr & 31) != 4 && (spsr & 31) != 5) return DEVICE_BAD_WIDTH;
    if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    struct mmio_pair pair;
    uint32_t instruction=*(volatile uint32_t *)code;
    int decoded=write ? mmio_stp64_decode(instruction,esr,frame,sp,&pair) :
                        mmio_ldp64_decode(instruction,esr,frame,sp,&pair);
    if (!decoded ||
        (far != pair.address && far != pair.address+8)) return DEVICE_BAD_WIDTH;
    uint64_t first=guest_pa(pair.address), second=guest_pa(pair.address+8);
    if (!first || first > UINT64_MAX-15 || second != first+8 ||
        (ipa != first && ipa != second) || first < model->base ||
        first-model->base >= model->span || model->span-(first-model->base)<16)
        return DEVICE_NOT_FOUND;
    uint64_t values[2];
    if (model->kind==DEVICE_ANS_ASC_V1) {
        struct ans_ops o=ans_ops_of(c);
        if (write) for (unsigned i=0;i<2;i++) values[i]=pair.reg[i]==31 ? 0 : frame[pair.reg[i]];
        int r=ans_mailbox_pair(ans_state_of(c),&o,first-model->base,write,values);
        if (r) return (enum device_result)(0x100|r);
#if SNAP_ANS_ASYNC
        ans_async_schedule(c);
#endif
        if (!write) mmio_ldp64_complete(&pair,values,frame);
        return ans_route(c);
    }
    if (write) {
        for (unsigned i=0;i<2;i++) values[i]=pair.reg[i]==31 ? 0 : frame[pair.reg[i]];
        enum device_result result=device_model_write_pair(model,&c->model_state[index],
                                                           first-model->base,values);
        if (result==DEVICE_OK) c->model_writes[index]+=2;
        return result;
    }
    enum device_result result=device_model_read_pair(model,&c->model_state[index],
                                                      first-model->base,values);
    if (result == DEVICE_OK) {
        mmio_ldp64_complete(&pair,values,frame);
        __atomic_fetch_add(&c->model_reads[index],2,__ATOMIC_RELAXED);
    }
    return result;
}

/* The I2C error path uses a pre-indexed LDR Wt with ISV=0. Fetch and decode
 * it from guest RAM, then bind its effective address to FAR and the trapped
 * device IPA before reading the model. Base writeback happens only on success. */
static enum device_result model_preload_read(struct context *c, uint64_t *frame,
    uint64_t pc, uint64_t esr, uint64_t ipa, unsigned index)
{
    const struct params *p=c->params;
    const struct device_model *model=&p->models[index];
    if (model->kind!=DEVICE_I2C_EMPTY_V1 || (pc&3) ||
        (vcpu_of(c)->guest_sctlr&(1UL<<25))) return DEVICE_BAD_WIDTH;
    uint64_t code=guest_pa(pc), spsr, sp, far;
    if (code<p->mem_low || code>p->mem_high-4) return DEVICE_BAD_WIDTH;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2" : "=r"(spsr), "=r"(far));
    if ((spsr&31)!=4 && (spsr&31)!=5) return DEVICE_BAD_WIDTH;
    if (spsr&1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    struct mmio_preload load;
    if (!mmio_ldr32_pre_decode(*(volatile uint32_t *)code,esr,frame,sp,&load) ||
        far!=load.address) return DEVICE_BAD_WIDTH;
    uint64_t translated=guest_pa(load.address);
    if (!translated || translated!=ipa || translated<model->base ||
        model->span<4 || translated-model->base>model->span-4) return DEVICE_NOT_FOUND;
    uint64_t value=0;
    const struct device_power_resources resources={c,gfx_power_idle};
    enum device_result result=device_models_access_power_at(p->models,c->model_state,
        (unsigned)p->model_count,index,clock_counter(c),translated-model->base,
        4,0,&value,&resources);
    if (result==DEVICE_OK) {
        mmio_ldr32_pre_complete(&load,(uint32_t)value,frame,&sp);
        if (load.base==31) {
            if (spsr&1) __asm__ volatile("msr sp_el1, %0" :: "r"(sp));
            else __asm__ volatile("msr sp_el0, %0" :: "r"(sp));
        }
        __atomic_fetch_add(&c->model_reads[index],1,__ATOMIC_RELAXED);
    }
    return result;
}

struct aes_dma_context {
    struct context *c;
    const struct device_model *model;
    enum sptm_result refusal;
    uint64_t refused_iova;
};
static volatile uint8_t *aes_dma_map(void *opaque,uint64_t iova,size_t size,int write)
{
    struct aes_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if (device_dart_admit_frame(c->params->models,c->model_state,
        (unsigned)c->params->model_count,5,(unsigned)a->model->config[3],
        (unsigned)a->model->config[4],0,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;a->refused_iova=iova;return 0;
    }
    struct sptm_memory memory=sptm_context_memory(c);uint64_t pa;
    enum sptm_result r=sptm_dart_dma_translate(&memory,&c->model_state[index].dart,
        a->model->config[3],a->model->config[4],iova,size,write,&pa);
    if (r) {a->refusal=r;a->refused_iova=iova;return 0;}
    return memory.map(memory.ctx,pa,size);
}
static void aes_dma_publish(void *opaque,volatile uint8_t *p,size_t size)
{
    struct aes_dma_context *a=opaque;
    sptm_publish(a->c,(uint64_t)p,size);
}
#include "sep-callbacks.h"

static int model_dispatch(struct context *c, uint64_t *frame, uint64_t *elr,
                          uint64_t esr, uint64_t ipa, unsigned index, uint64_t offset)
{
    const struct device_model *model = &c->params->models[index];
    struct dc_access access = dc_decode(esr);
    enum device_result result = DEVICE_BAD_WIDTH;
    if ((esr >> 26) == 0x24 && !(esr & (1UL << 7)) && access.valid) {
        uint64_t value = access.write ? dc_narrow(&access,
            access.reg == 31 ? 0 : frame[access.reg]) : 0;
        const struct device_power_resources resources={c,gfx_power_idle};
        if (model->kind==DEVICE_ANS_ASC_V1 || model->kind==DEVICE_ANS_NVME_V1) {
            struct ans_ops o=ans_ops_of(c);
            int r=ans_mmio(ans_state_of(c),&o,model->kind==DEVICE_ANS_NVME_V1,offset,
                           access.size,access.write,&value);
#if SNAP_ANS_ASYNC
            if(!r)ans_async_schedule(c);   /* timer_sync below arms the owner's deadline */
#endif
            result=r ? (enum device_result)(0x100|r) : ans_route(c);
        } else if (model->kind==DEVICE_AES_SOFTWARE_V1) {
            /* The trap-wide service lock serializes DMA with SPTM ownership
             * and DART changes. All fragments are admitted before data writes. */
            struct aes_dma_context a={.c=c,.model=model};
            const struct aes_dma dma={&a,aes_dma_map,aes_dma_publish};
            enum aes_result r=device_aes_powered(c->params->models,c->model_state,
                (unsigned)c->params->model_count,index)==DEVICE_OK ?
                aes_engine_access(&c->model_state[index].aes,&dma,
                    offset,access.size,access.write,&value) : AES_BAD_STATE;
            result=r==AES_OK ? DEVICE_OK : DEVICE_BAD_VALUE;
            if (r!=AES_OK) record(c,EV_TABLE_FAILED,*elr,
                0x4145530000000000UL|((uint64_t)r<<32)|a.refusal,a.refused_iova,value);
        } else result = device_models_access_power_at(c->params->models, c->model_state,
                (unsigned)c->params->model_count, index, clock_counter(c),
                offset, access.size, access.write, &value,&resources);
        if (result == DEVICE_OK) {
            if (access.write) {
                c->model_writes[index]++;
                /* AIC MASK_CLR: the guest finished an event; resample the line. */
                if (model->kind == DEVICE_AIC3_FLAT_V1 && offset >= 0x14600 &&
                    offset < 0x14800 && c->params->gpu.flags) {
                    struct irqfwd_ops f = fwd_ops(c);
                    irqfwd_unmasked(&c->gpu.irq, &f, (unsigned)((offset - 0x14600) / 4),
                                    (uint32_t)value);
                }
            } else {
                if (access.reg != 31) frame[access.reg] = dc_extend(&access, value);
                __atomic_fetch_add(&c->model_reads[index],1,__ATOMIC_RELAXED);
                if (model->kind==DEVICE_PMGR_CPU_PERF_BOOT_V1 &&
                    (offset==0x48 || offset==0x50)) {
                    uint64_t *w=c->model_state[index].cpu_perf_reads[(offset-0x48)/8];
                    if (w[0]!=UINT64_MAX) w[0]++;
                    w[1]=*elr;w[2]=ipa;w[3]=esr;w[4]=value;
                    w[5]=access.reg==31 ? 0 : frame[access.reg];
                    w[6]=frame[30];w[7]=vcpu_of(c)->slot;
                }
            }
        }
    } else if ((esr >> 26) == 0x24 && !(esr & (1UL << 24))) {
        if (model->kind==DEVICE_I2C_EMPTY_V1)
            result=model_preload_read(c,frame,*elr,esr,ipa,index);
        else result=model_pair_access(c,frame,*elr,esr,ipa,index);
    }
    if (result == DEVICE_OK && model->kind==DEVICE_SEP_ASC_MAILBOX_V1 && model->config[4]) {
        struct sep_rom_dma_context dma={.c=c,
            .pnon_refusal=!!(model->config[4]&16),
            .shared_iova=c->model_state[index].sep_asc.rom_shared_iova,
            .shared_size=c->model_state[index].sep_asc.rom_shared_size,
            .asc=&c->model_state[index].sep_asc};
        const struct sep_pnon_io pnon={&dma,sep_pnon_bind,sep_pnon_query};
        const struct sep_xars_io xars={&dma,sep_xars_bind,sep_xars_validate,sep_xars_slot};
        const struct sep_sks_endpoint_io sks={&dma,sep_sks_bind,sep_sks_prepare,sep_sks_publish};
        const struct device_sep_rom_resources resources={&dma,c->params->sep_firmware_size,
            sep_rom_admit,sep_rom_bootstrap,sep_entropy32,&pnon,&xars,&sks};
        result=device_sep_rom_step(model,&c->model_state[index],&resources);
        if(dma.refusal)record(c,EV_TABLE_FAILED,*elr,0x5345500000000000UL|dma.refusal,
            c->model_state[index].sep_asc.request[0][0],c->params->sep_firmware_size);
    }
    if (result == DEVICE_OK)
        result=device_models_route_irqs(c->params->models,c->model_state,
                                       (unsigned)c->params->model_count);
    if (result == DEVICE_OK) {
        vcpu_of(c)->model_irq_pending = 0;
        for (unsigned i=0; i<c->params->model_count; i++)
            vcpu_of(c)->model_irq_pending |= device_irq_pending(&c->params->models[i],
                                                       &c->model_state[i]);
        timer_sync(c);
        if (device_reset_stop(c, *elr, frame)) return 1;
        *elr += 4;
        return 0;
    }
    if (result & 0x100) record(c, EV_ANS, *elr, (uint64_t)(result & 0xff) << 32 | model->kind, ipa, esr);
    else record(c, EV_DEVICE_FAILED, *elr, (model->kind << 32) | result, ipa, esr);
    fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, ipa);
    vcpu_of(c)->async_captured = 3;
    return 1;
}

/* Returns 1 to stop and report, 0 to resume the guest. */
static int monitor_request(struct context *c, uint64_t *frame, uint64_t *elr)
{
    step_translation_clear(&c->step_translation[vcpu_of(c)->slot]);
    if (monitor_call(c, frame, elr)) return 0;
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, *elr, 0);
    vcpu_of(c)->async_captured = 2;
    if (c->last.kind != EV_RETYPE_FAILED && c->last.kind != EV_TABLE_FAILED &&
        c->last.kind != EV_UNMAP_FAILED && c->last.kind != EV_UPDATE_FAILED &&
        c->last.kind != EV_REGION_FAILED && c->last.kind != EV_REFERENCE_FAILED &&
        c->last.kind != EV_SLIDE_FAILED && c->last.kind != EV_TXM_FAILED &&
        c->last.kind != EV_MAP_FAILED && c->last.kind != EV_PANIC_STATE_FAILED &&
        c->last.kind != EV_NATIVE_SHARED_FULL)
        record(c, EV_MONITOR, *elr, frame[16], frame[0], frame[1]);
    step_arm(c, 0);
    guards_close(c);
    return 1;
}

/* ADRENO_GUEST_STOP (compat/adreno-guest.h): admitted only when the launch
 * enabled it, from EL1, and for the HVC that the loaded AuxKC's own frames
 * hold -- its one bundle is our Adreno kext. The request is recorded and
 * answered; the run continues until the deadline expires on some CPU. */
static void early_stop_hvc(struct context *c, uint64_t *frame, uint64_t elr, uint64_t spsr)
{
    const struct params *p = c->params;
    struct early_stop_state *s = &c->early_stop;
    uint64_t hvc = elr - 4, pa = guest_pa(hvc), now, accepted = 0;
    uint32_t word = 0;
    if (pa && p->auxkc.pa_end > p->auxkc.pa_base + 4 &&
        pa >= p->auxkc.pa_base && pa <= p->auxkc.pa_end - 4)
        word = *(volatile uint32_t *)pa;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(now));
    int e = early_stop_guest_admit(&p->early_stop, &p->auxkc, hvc, pa, word, spsr,
                                   frame[1], frame[2], &accepted);
    if (!e) e = early_stop_request(s, EARLY_STOP_SOURCE_GUEST, frame[1], frame[3], frame[2],
                                   accepted, now, p->clock_host_hz, (unsigned)vcpu_of(c)->slot,
                                   hvc, 0);
    else early_stop_refuse(s, e);
    record(c, EV_EARLY_STOP_REQUEST, hvc, (uint64_t)EARLY_STOP_SOURCE_GUEST << 32 | (uint32_t)frame[1],
           frame[2] << 32 | (uint32_t)frame[3], (uint64_t)(int64_t)e);
    frame[0] = (uint64_t)(int64_t)e;
    frame[1] = e < 0 ? 0 : accepted;
    frame[2] = __atomic_load_n(&s->state, __ATOMIC_ACQUIRE);
    frame[3] = p->early_stop.max_delay_s;
}

#if SNAP_GUEST_NET
/* compat/guest-net-link.h's operations: the ring's frames are held under the
 * virtual ANS's DMA rule (XNU_DEFAULT, clear metadata, a DART reference), and
 * guest RAM is the monitor's identity mapping, as every guest buffer is. */
static int guest_net_monitor_page(void *ctx, uint64_t pa)
{
    const struct context *c = ctx;
    const struct auxkc_range *kc = &c->params->auxkc;
    return (pa >= c->work_start && pa < c->work_end) || (pa >= kc->pa_base && pa < kc->pa_end);
}
static int guest_net_frame_ref(void *ctx, uint64_t pa, int release) {return ans_frame_ref(ctx, pa, 1, release);}
static volatile void *guest_net_map(void *ctx, uint64_t pa)
{
    const struct params *p = ((const struct context *)ctx)->params;
    return pa >= p->mem_low && pa < p->mem_high ? (volatile void *)(uintptr_t)pa : 0;
}
static struct guest_net_ops guest_net_ops_of(struct context *c)
{
    return (struct guest_net_ops){c, c->params->mem_low, c->params->mem_high,
                                  guest_net_monitor_page, guest_net_frame_ref, guest_net_map};
}

/* ADRENO_GUEST_NET (compat/guest-net.h): admitted only when the launch enabled
 * the network, from EL1, for the HVC the loaded AuxKC's own frames hold
 * (early_stop_guest_caller, as ADRENO_GUEST_STOP). Under the service lock. */
static void guest_net_hvc(struct context *c, uint64_t *frame, uint64_t elr, uint64_t spsr)
{
    const struct params *p = c->params;
    struct guest_net_link *l = &c->guest_net->link;
    const struct guest_net_ops o = guest_net_ops_of(c);
    uint64_t hvc = elr - 4, pa = guest_pa(hvc), generation = 0;
    uint32_t word = 0;
    if (pa && p->auxkc.pa_end > p->auxkc.pa_base + 4 &&
        pa >= p->auxkc.pa_base && pa <= p->auxkc.pa_end - 4)
        word = *(volatile uint32_t *)pa;
    int e;
    if (!(p->early_stop.flags & EARLY_STOP_F_NET) || !(p->early_stop.flags & EARLY_STOP_F_HOST))
        e = guest_net_refuse(l, GUEST_NET_E_DISABLED);
    else if (early_stop_guest_caller(&p->auxkc, hvc, pa, word, spsr))
        e = guest_net_refuse(l, GUEST_NET_E_ORIGIN);
    else if (frame[1] == GUEST_NET_ATTACH)
        e = guest_net_attach(l, &o, frame[2], frame[3], &generation);
    else if (frame[1] == GUEST_NET_DETACH) {
        guest_net_detach(l, &o);
        e = 0;
    } else
        e = guest_net_refuse(l, GUEST_NET_E_OP);
    record(c, EV_GUEST_NET, hvc, frame[1], frame[2], (uint64_t)(uint32_t)e << 32 | (uint32_t)generation);
    int attached = !e && frame[1] == GUEST_NET_ATTACH;
    frame[0] = (uint64_t)(int64_t)e;
    frame[1] = attached ? GUEST_NET_LINK_UP : 0;
    frame[2] = attached ? GUEST_NET_MTU : 0;
    frame[3] = attached ? generation : 0;
}
#endif

#if SNAP_VECTOR_BRANCH
/* Perform the first instruction of the vector slot at *elr, an unconditional
 * B out of the vector page (fast_vector_branch), and never open the page:
 * the same state the single step would leave, with the step disarmed and
 * every guard closed, but without the step exit, the two stage-2 descriptor
 * writes and the two broadcast TLB invalidations. 0: the slot holds anything
 * else, nothing changed, and the caller opens and steps the page as before. */
static int vector_branch(struct context *c, uint64_t *elr)
{
    const struct params *p = c->params;
    uint64_t target;
    if (*elr - p->vbar_va >= 0x800 ||
        !fast_vector_branch(*(const volatile uint32_t *)(p->vbar | (*elr & 0xfff)), *elr, &target))
        return 0;
    step_arm(c, 0);
    guards_close(c);
    c->perf.fast[vcpu_of(c)->slot].branches++;
    *elr = target;
    return 1;
}
#endif

#if SNAP_S2_FAULT_RETRY
/* compat/s2-fault-retry.h: a guest abort that is about to stop the run as a
 * stage-2 fault (no guard, device window, model or Adreno block took it).
 * Every translation fault is snapshotted; one whose HPFAR IPA is guest RAM
 * that this CPU's tree maps (or, with SNAP_S2_FAULT_RETRY_STAGE1, whose
 * stage-1 re-walk's IPA is) is retried within the bounds: this CPU's stage 1
 * and stage 2 for its VMID are invalidated and the instruction runs again
 * (1). 0: stop as before. */
static int s2_fault_retry(struct context *c, uint64_t esr, uint64_t elr, uint64_t far, uint64_t hpfar)
{
    const struct params *p = c->params;
    struct vcpu *v = vcpu_of(c);
    struct s2_retry_state *s = c->s2_retry;
    int level = s2_retry_translation(esr);
    if (!s || level < 0 || v->slot >= S2_RETRY_CPUS) return 0;
    struct s2_retry_entry e = {0};
    uint64_t parange;
    __asm__ volatile("mrs %0, vttbr_el2; mrs %1, vtcr_el2; mrs %2, hcr_el2; mrs %3, spsr_el2"
                     : "=r"(e.vttbr), "=r"(e.vtcr), "=r"(e.hcr), "=r"(e.spsr));
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1; mrs %2, mpidr_el1; mrs %3, id_aa64mmfr0_el1"
                     : "=r"(e.ttbr0), "=r"(e.tcr), "=r"(e.mpidr), "=r"(parange));
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(e.counter));
    parange &= 0xf;
    if (parange > 5) parange = 5;               /* as vcpu_arch_prepare */
    e.esr = esr; e.far = far; e.hpfar = hpfar; e.elr = elr;
    e.vttbr_expected = vcpu_vttbr(v);
    e.vtcr_expected = s2_retry_vtcr(S2_TXSZ, parange);
    e.ipa_hw = s2_retry_hpfar_ipa(hpfar, far, esr);
    e.ipa_at = ((esr >> 7) & 1) ? 0 : guest_pa(far);
    /* Both walks through the tree VTTBR names now, whatever it is. */
    uint64_t root = e.vttbr & UINT64_C(0x0000fffffffffffe);
    int hw_mapped = s2_retry_dram(e.ipa_hw, p->mem_low, p->mem_high) &&
                    s2_retry_walk(mem_read, c, root, S2_TXSZ, e.ipa_hw, e.d_hw);
    int at_mapped = e.ipa_at && s2_retry_dram(e.ipa_at, p->mem_low, p->mem_high) &&
                    s2_retry_walk(mem_read, c, root, S2_TXSZ, e.ipa_at, e.d_at);
    enum s2_retry_kind kind;
    enum s2_retry_verdict verdict =
        s2_retry_judge(&s->cpu[v->slot],
                       s2_retry_registers_ok(e.vttbr, e.vttbr_expected, e.vtcr, e.vtcr_expected, e.hcr),
                       hw_mapped, at_mapped, SNAP_S2_FAULT_RETRY_STAGE1, e.counter,
                       p->clock_host_hz, elr, far, &kind);
    s2_retry_note(s, &e, (unsigned)v->slot, level, kind, verdict);
    if (verdict != S2_RETRY_RESUME) return 0;
    record(c, EV_S2_RETRY, elr, e.ipa_hw, esr, far);
    __asm__ volatile("dsb ish; tlbi vmalls12e1; dsb nsh; isb" ::: "memory");
    return 1;
}
#endif

static int xnuboot_trap_locked(uint64_t *frame, uint64_t esr, uint64_t *elr)
{
    struct context *c = context_of();
    const struct params *p = c->params;
    uint64_t ec = esr >> 26, iss = esr & 0x1ffffff;
    struct user_execution *user=&c->user_execution[vcpu_of(c)->slot];
    uint64_t physical_spsr;
    __asm__ volatile("mrs %0, spsr_el2":"=r"(physical_spsr));
    if(SNAP_NATIVE_WRITER_BREAKPOINTS && ec==0x30) {
        struct vcpu *v=vcpu_of(c);
        struct native_writer_debug *debug=&c->writer_debug[v->slot];
        uint64_t value=0,pa=0;int spsr=0;unsigned site=0;uint32_t word=0;
        debug->last_pc=*elr;
        unsigned mode=physical_spsr&31;
        if(debug->installed && (mode==4 || mode==5) && (esr&(1UL<<25))) {
            pa=guest_pa(*elr);
            for(unsigned i=0;i<NATIVE_WRITER_SITE_COUNT;i++) {
                const struct native_writer_site *entry=&native_writer_sites[i];
                uint64_t expected=p->stub_pa[NATIVE_CALL_PAGES+entry->page]+(entry->va&4095);
                if(*elr==entry->va && pa==expected)word=*(const volatile uint32_t *)expected;
            }
        }
        debug->last_word=word;
        if(!native_writer_value(*elr,word,frame,&value,&spsr,&site)) {
            debug->rejected++;
            record(c,EV_NATIVE_WRITER_FAILED,*elr,esr,pa,word);
            fill_regs(&v->async_regs,frame,esr,*elr,pa);v->async_captured=2;return 1;
        }
        if(spsr) {__asm__ volatile("msr spsr_el1, %0"::"r"(value):"memory");}
        else {__asm__ volatile("msr elr_el1, %0"::"r"(value):"memory");}
        if(v->stepping.active) {debug->stepped++;step_arm(c,0);}
        guards_close(c);debug->traps++;*elr+=4;
        /* The common exit snapshots both physical exception registers before
         * a later native private call can overwrite them. */
        return 0;
    }
    if(user->pending && ec==0x32 && !(physical_spsr&31)) {
        uint64_t sp;__asm__ volatile("mrs %0, sp_el0":"=r"(sp));
        user->observed_pc=*elr;user->observed_spsr=physical_spsr;
        user->observed_esr=esr;user->observed_x0=frame[0];user->observed_sp=sp;
        int done=exception_user_step((uint32_t)user->instruction,user->entry,user->stack,
                                    esr,physical_spsr,*elr,frame[0],sp);
        user->pending=0;
        step_arm(c,0);guards_close(c);
        record(c,done ? EV_USER_EXECUTED : EV_USER_STEP_FAILED,*elr,user->entry,frame[0],physical_spsr);
        if(done) {user->executed++;return 0;}
        fill_regs(&vcpu_of(c)->async_regs,frame,esr,*elr,sp);
        vcpu_of(c)->async_captured=2;return 1;
    }

#if SNAP_GUEST_BRK_REFLECT
    /* BRK64 (EC 0x3c) from guest AArch64 EL0/EL1 arrives here only because
     * MDCR_EL2.TDE is set. Take it to EL1 as the architecture would without
     * TDE: ESR/ELR/SPSR_EL1 from the trap, FAR_EL1 untouched (UNKNOWN for
     * BRK), vector +0x400 from EL0, +0x200 from EL1h, +0x000 from EL1t.
     * Entry PSTATE is EL1h with DAIF masked, PAN set (SCTLR_EL1.SPAN=0 in
     * guest_sctlr), SSBS clear (DSSBS=0), SS/IL/BTYPE clear. Not while the
     * monitor single-steps (its own debug state owns that window). */
    if(ec==0x3c && !(physical_spsr&(1UL<<4)) && !vcpu_of(c)->stepping.active && !user->pending) {
        unsigned mode=physical_spsr&31;
        uint64_t sctlr,vbar,offset=mode==0 ? 0x400 : mode==5 ? 0x200 : mode==4 ? 0 : 1;
        __asm__ volatile("mrs %0, sctlr_el1; mrs %1, vbar_el1":"=r"(sctlr),"=r"(vbar));
        if(offset!=1 && vbar && !(vbar&0x7ff) && !(sctlr&(1UL<<23)) && !(sctlr&(1UL<<44))) {
            struct guest_brk_stats *b=&c->guest_brk[vcpu_of(c)->slot];
            __asm__ volatile("msr elr_el1, %0; msr spsr_el1, %1; msr esr_el1, %2; isb"
                             ::"r"(*elr),"r"(physical_spsr),"r"(esr):"memory");
            if(mode)b->el1++;else b->el0++;
            b->last_pc=*elr;b->last_esr=esr;b->last_spsr=physical_spsr;
            __asm__ volatile("msr spsr_el2, %0"::"r"(UINT64_C(0x3c5)|(UINT64_C(1)<<22)):"memory");
            guards_close(c);
            *elr=vbar+offset;
            return 0;
        }
    }
#endif
    /* A stepped instruction can enter EL1's exception vectors. The debug
     * exception is delivered before the vector's first instruction, without
     * an intervening stage-2 execute fault. Treat that landing exactly like
     * a guarded vector fetch, or we lose the primary exception and observe
     * only the fault inside XNU's not-yet-initialized exception handler. */
    int vector_step = p->vbar && exception_vector_step(esr, *elr, p->vbar_va);
    if (vector_step) {
        step_translation_clear(&c->step_translation[vcpu_of(c)->slot]);
        ec = 0x20; iss = 0;
    }

    if (ec == 0x20 || ec == 0x24) {              /* abort from EL1, insn or data */
        uint64_t hpfar, far;
        __asm__ volatile("mrs %0, hpfar_el2" : "=r"(hpfar));
        __asm__ volatile("mrs %0, far_el2" : "=r"(far));
        if (vector_step) far = *elr;
        /* Where the IPA comes from. HPFAR_EL2 read back as zero for a stage-2
         * permission fault on this silicon, so the address is recovered by
         * translating the VA through stage 1, which answers whenever stage 1
         * itself resolved. When the stage-1 walk is what faulted (S1PTW: a
         * table page stage 2 does not map, or would not let the walker write)
         * the VA translates to nothing and HPFAR names the table page, without
         * an offset. Zero means neither could say, and is reported as that
         * rather than as an address. */
        uint64_t s1ptw = (iss >> 7) & 1;
        uint64_t ipa = s1ptw ? 0 : guest_pa(far);
        if (!ipa && (hpfar & 0x0000fffffffffff0UL))
            ipa = ((hpfar >> 4) << 12) | (s1ptw ? 0 : (far & 0xfff));

        struct guard *g = guard_find(c, ipa);
        if (g && g->mode == GUARD_DATA) {
            /* A handoff field. Log which one, then let exactly one instruction
             * run against it. */
            record(c, EV_HANDOFF, *elr, ipa - p->watch_pa, esr, far);
            guard_open(c, g);
            step_arm(c, 1);
            return 0;
        }
        if (ec == 0x20 && g) {
            if (p->vbar && (ipa & ~0xfffUL) == p->vbar) {
                /* XNU tried to enter its own vectors: it faulted. Its syndrome
                 * is what we actually want, not ours. */
                uint64_t g_esr, g_far, g_elr;
                __asm__ volatile("mrs %0, esr_el1" : "=r"(g_esr));
                __asm__ volatile("mrs %0, far_el1" : "=r"(g_far));
                __asm__ volatile("mrs %0, elr_el1" : "=r"(g_elr));
                /* IRQ/FIQ entries do not update ESR/FAR. Recognize their
                 * architectural slots and require our asserted AIC/timer
                 * level. Never infer an interrupt from a stale syndrome. */
                uint64_t vector = *elr - p->vbar_va, hcr, saved;
                __asm__ volatile("mrs %0, spsr_el1" : "=r"(saved));
                if (SNAP_NATIVE_CALLS && g_esr==(1UL<<25) &&
                    ((saved&31)==8 || (saved&31)==9) && !(g_elr&3) &&
                    g_elr>=UINT64_C(0xffff800000000000)) {
                    uint64_t pa=guest_pa(g_elr),physical=0;
                    int call_page=0;
                    for(unsigned n=0;n<NATIVE_CALL_PAGES;n++)
                        call_page|=(pa&~0xfffUL)==p->stub_pa[n];
                    uint32_t word=call_page ? *(const uint32_t *)pa : 0;
                    if (native_call_word(word)) {
                        SERVICE_SUB_TAG(c,service_sub_call(frame[16],SPTM_CMD_ENDPOINT));
#if SNAP_OTHER_PROFILE
                        other_profile_tag(&c->root_ext->other,(unsigned)vcpu_of(c)->slot,frame[16]);
#endif
                        struct vcpu *v=vcpu_of(c);
                        struct native_call_state *s=&c->native_calls[v->slot];
                        s->calls++;s->last_pc=g_elr;s->last_word=word;s->last_saved=saved;
                        if (s->ready!=1 || v->stepping.active || v->open_guards ||
                            !native_call_return(vector,g_esr,saved,physical_spsr,
                                                g_elr,word,&physical)) {
                            s->rejected++;
                            fill_regs(&v->async_regs,frame,g_esr,g_elr,g_far);
                            v->async_captured=2;
                            record(c,EV_MONITOR,g_elr,word,saved,physical_spsr);
                            return 1;
                        }
                        s->last_physical=physical;
                        native_exception_restore(s);
                        __asm__ volatile("msr spsr_el2, %0" :: "r"(physical) : "memory");
                        *elr=g_elr;
                        return monitor_request(c,frame,elr);
                    }
                }
                if (vector < 0x800 && !(vector & 0x7f)) {
                    if(vector>=0x400 && vector<=0x580 && !(saved&31)) {
                        struct pan_entry_state *pan=&c->pan_entry[vcpu_of(c)->slot];
                        pan->user_vectors++;
                        pan->protected_vectors+=!!(physical_spsr&(1UL<<22));
                        pan->vector=vector;pan->saved_spsr=saved;
                        pan->entry_spsr=physical_spsr;
                        __asm__ volatile("mrs %0, sctlr_el1":"=r"(pan->entry_sctlr));
                    }
                    if(user->pending) {user->interrupted++;user->pending=0;}
                    if (exception_step_suspend(&vcpu_of(c)->stepping, &saved)) {
                        __asm__ volatile("msr spsr_el1, %0" :: "r"(saved));
                        vcpu_of(c)->step_exception_repairs++;
                        step_arm(c, 0);
                    }
                }
                if(user_sysreg_access(c,frame,g_elr,saved,g_esr,vector,elr))return 0;
                SERVICE_SUB_TAG(c,SERVICE_SUB_VECTOR);
                /* This is the first instruction of a lower-EL vector,
                 * including IRQ/FIQ. Switch to PPERM before opening it.
                 * The emulated EL0 sysreg fast return above executes no EL1
                 * instruction and retains its UPERM view throughout. */
                if(vector>=0x400 && vector<=0x580 && !(vector&0x7f) &&
                   !(saved&31) && !user_enter_mode(c,0))return 1;
                __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
                if ((vector == 0x100 || vector == 0x300 ||
                     (vector == 0x500 && !(saved&31))) && (hcr & (1UL << 6))) {
                    vcpu_of(c)->timer_vectors++;
                    record(c, EV_TIMER_FIQ, *elr, g_elr, vcpu_of(c)->timer.ctl, vcpu_of(c)->timer.cval);
                    vcpu_of(c)->fault_esr = vcpu_of(c)->fault_far = 0;
                    step_arm(c, 0);
#if SNAP_VECTOR_BRANCH
                    if (vector_branch(c, elr)) return 0;
#endif
                    guard_open(c, g);
                    if (SNAP_NATIVE_WRITER_BREAKPOINTS) step_arm(c, 1);
                    return 0;
                }
                if ((vector == 0x80 || vector == 0x280 ||
                     (vector == 0x480 && !(saved&31))) && (hcr & (1UL << 7))) {
                    vcpu_of(c)->model_irq_vectors++;
                    record(c, EV_DEVICE_IRQ, *elr, g_elr, vcpu_of(c)->model_irq_pending, 0);
                    vcpu_of(c)->fault_esr = vcpu_of(c)->fault_far = 0;
                    step_arm(c, 0);
#if SNAP_VECTOR_BRANCH
                    if (vector_branch(c, elr)) return 0;
#endif
                    guard_open(c, g);
                    if (SNAP_NATIVE_WRITER_BREAKPOINTS) step_arm(c, 1);
                    return 0;
                }
                /* The caller, not the vector. Every blocker at this stage is
                 * a null pointer somewhere, and the faulting PC is usually
                 * inside bzero or memcpy -- shared by dozens of call sites, so
                 * it names nothing. x30 is the one register that says which of
                 * them, and the guest's copy is right here in the frame. The
                 * vector address it replaces was never informative: it is the
                 * page we guarded, so we already knew it. */
                /* An instruction this silicon does not implement.
                 *
                 * EC 0 is "unknown reason", which at EL1 is what an unallocated
                 * encoding produces -- and this kernel is built for a CPU with
                 * Apple's additions. Stopping here reports one instruction and
                 * learns nothing more; stepping over it asks the only question
                 * that matters, which is whether anything downstream needed its
                 * effect. If the boot goes further, the encoding is worth
                 * identifying properly. If it faults immediately afterwards on
                 * whatever the instruction should have produced, that is the
                 * answer too, and a louder one.
                 *
                 * This is a lie of omission and is counted as one: skipped is
                 * reported separately from answered, so a run that only gets
                 * further because of this cannot be read as one that works. */
                if ((g_esr >> 26) == 0 && c->skip_undef) {
                    uint64_t pa = guest_pa(g_elr);
                    uint32_t word = pa ? *(volatile uint32_t *)pa : 0;
                    record(c, EV_OTHER, g_elr, 0xDEAD0000UL | (word & 0xffff),
                           word, c->undef_skipped);
                    c->undef_skipped++;
                    __asm__ volatile("msr elr_el1, %0" :: "r"(g_elr + 4));
                    *elr = g_elr + 4;
                    guards_close(c);
                    return 0;
                }
                /* The whole register file, into its own area rather than into
                 * the log. The four EV_OTHER records below predate it and are
                 * kept because the report already parses them, but they are a
                 * twelve-register sample and this is all of it. */
                capture_regs(c, frame, g_esr, g_elr, g_far);
                /* And the registers the fault was computed from. A null pointer
                 * says nothing about where it came from; the callee-saved
                 * registers of the frame that produced it usually say exactly.
                 * Cheaper than a second event kind, and this is the one moment
                 * the guest's register file is worth more than any counter. */
                record(c, EV_OTHER, 8, frame[8], frame[9], frame[10]);
                record(c, EV_OTHER, 11, frame[11], frame[12], frame[13]);
                record(c, EV_OTHER, 19, frame[19], frame[20], frame[21]);
                record(c, EV_OTHER, 22, frame[22], frame[23], frame[24]);
                /* Keep the terminal slot meaningful when the detailed log
                 * is full; the register sample is secondary to the fault. */
                record(c, EV_GUEST_EXC, frame[30], g_esr, g_far, g_elr);
                vcpu_of(c)->fault_esr = g_esr;
                vcpu_of(c)->fault_far = g_far;
                step_arm(c, 0);

                /* Demand paging requires XNU to see ordinary kernel memory
                 * faults. Record them, then let its handler decide whether
                 * to resolve them or panic. Other exceptions stop by default;
                 * let_panic explicitly allows their diagnostic handlers too.
                 * The watchdog still bounds every run, and unsupported
                 * monitor endpoints remain strict. */
                int user_sync=exception_user_sync(vector,saved,g_esr);
                if(user_sync) {
                    if((g_esr>>26)==0x15)user->svcs++;else user->faults++;
                }
#if SNAP_GUEST_BRK_REFLECT
                /* Process-fatal EL0 synchronous exceptions at the lower-EL
                 * AArch64 sync vector: XNU turns these into the task's own
                 * exception/signal (BRK64 0x3c, unknown 0x00, illegal state
                 * 0x0e, FPAC 0x1c, PC/SP alignment 0x22/0x26). EL1 origins
                 * and every other class still stop the run. */
                if(!user_sync && vector==0x400 && !(saved&31) && !(saved&(1UL<<4))) {
                    unsigned uec=(unsigned)(g_esr>>26)&63;
                    if(uec==0x3c || uec==0x00 || uec==0x0e || uec==0x1c || uec==0x22 || uec==0x26) {
                        user_sync=1;c->guest_user_signal[vcpu_of(c)->slot]++;
                    }
                }
#endif
#if SNAP_USER_CRASH_RING
                /* Evidence before XNU acts: the same lower-EL AArch64 sync
                 * entry the gates above test. Recording changes nothing. */
                if(vector==0x400 && !(saved&31)) {
                    unsigned crash=user_crash_classify(g_esr,g_far,frame[16],frame[1]);
                    if(crash)user_crash_note(c,crash,frame,g_esr,g_elr,g_far);
                }
#endif
                if (exception_kernel_page_fault(g_esr) || user_sync || p->permissive || p->let_panic) {
                    /* These were observations, not terminal faults. The
                     * register snapshots retain them; later refusals must
                     * not inherit a stale syndrome as their stop reason. */
                    vcpu_of(c)->fault_esr = 0;
                    vcpu_of(c)->fault_far = 0;
#if SNAP_VECTOR_BRANCH
                    if (vector_branch(c, elr)) return 0;
#endif
                    guard_open(c, g);
                    /* Writer pages no longer fault when breakpoints own them.
                     * Step only through this vector page so guard_step closes
                     * it at the first instruction outside it. Otherwise the
                     * next private call enters an unguarded XNU vector. */
                    if (SNAP_NATIVE_WRITER_BREAKPOINTS) step_arm(c, 1);
                    return 0;
                }
                return 1;
            }
            /* A monitor call page. The stub marshals its arguments before the
             * call instruction, so the useful state is at the call itself --
             * which means letting the stub run up to it, one instruction at a
             * time, rather than emulating it from its first byte. */
            c->aborts++;
            guard_open(c, g);
            step_arm(c, 1);
            return 0;
        }

        /* A device window the guest's own tree names. MAP_PAGE installed the
         * leaf for exactly this reason: the stage-1 walk resolves, the access
         * reaches stage 2, the IPA is absent there, and it arrives here where
         * a model can answer it. */
        {
            uint64_t off = 0;
#if SNAP_QCC2072_WIFI
            /* The QCC2072's ECAM page is read-only at stage 2. A store to its
             * command register with memory decode on and bus mastering on or
             * off (2 or 6) is performed here, sixteen bits, and read back; any
             * other store falls through and stops the run like any other
             * stage-2 fault (compat/qcc2072-wifi.h). */
            if (ec == 0x24 && !(iss & (1U << 7))) {
                const struct qcc2072_wifi_params *q = qcc2072_wifi_block(p);
                struct dc_access a = dc_decode(esr);
                uint16_t command;
                if (a.valid && a.write &&
                    qcc2072_wifi_command_store(q, ipa, a.size,
                                               dc_narrow(&a, a.reg == 31 ? 0 : frame[a.reg]), &command)) {
                    volatile uint16_t *reg = (volatile uint16_t *)(uintptr_t)(QCC2072_WIFI_ECAM_PA +
                                                                             QCC2072_WIFI_COMMAND);
                    __asm__ volatile("dsb sy" ::: "memory");
                    *reg = command;
                    __asm__ volatile("dsb sy" ::: "memory");
                    uint16_t back = *reg;
                    record(c, EV_QCC2072_COMMAND, *elr, command, back, esr);
                    *elr += 4;
                    return 0;
                }
            }
#endif
            /* Exact binary: global core mask at +4 precedes cluster starts
             * at +8/+c. Only the cluster write may call the real executor. */
            if (ipa>=UINT64_C(0x300734004) && ipa<=UINT64_C(0x30073400c) &&
                c->host_cpus && ec==0x24 &&
                !(iss&(1U<<7))) {
                struct dc_access a=dc_decode(esr);
                uint64_t value=dc_narrow(&a,a.reg==31 ? 0 : frame[a.reg]);
                struct secondary_request request={c,*elr};
                if (a.valid && a.write && guest_cpu_release_write(&c->cpu_release,
#if SNAP_BOOT_RELOCATE
                    boot_relocate_release_mask(c->host_cpus->mask),ipa-UINT64_C(0x300734000),a.size,value,
#else
                    c->host_cpus->mask,ipa-UINT64_C(0x300734000),a.size,value,
#endif
                    secondary_release,&request)) { *elr+=4;return 0; }
            }
            int window = dc_window(p->device_pa, p->device_span,
                                   p->device_count, ipa, &off);
            if (window >= 0)
                return mmio_dispatch(c, frame, elr, esr, ipa, window, off);
            int model = device_model_find(p->models, p->model_count, ipa, &off);
            if (model >= 0)
                return model_dispatch(c, frame, elr, esr, ipa, (unsigned)model, off);
        }

        /* Everything the next step needs, and then the run stops: the IPA
         * says which device, the ESR's ISS says the access size, the register
         * and the direction (when ISV is set) and whether the stage-1 walk was
         * what faulted, the guest VA says which of the kernel's mappings was
         * used, and the PC says which code. Nothing is answered until it has
         * a model (docs/PLAN-HISTORY-20260922.md steps B and F). */
        unsigned block = adreno_block(ipa, p->gpu.flags);
#if SNAP_S2_FAULT_RETRY
        if (!(p->gpu.flags && block) && s2_fault_retry(c, esr, *elr, far, hpfar)) return 0;
#endif
        if (p->gpu.flags && block) {
            c->gpu.traps++;
            c->gpu.trap_ipa = ipa;
            c->gpu.trap_esr = esr;
            c->gpu.trap_block = block;
            record(c, EV_GPU_TRAP, *elr, ipa, esr, block);
        } else {
            record(c, EV_S2_FAULT, *elr, ipa, esr, far);
#if SNAP_S2_FAULT_RETRY
            /* The terminal word's sixth word, otherwise always zero: HPFAR_EL2,
             * the IPA the hardware faulted on (ipa above is the stage-1
             * re-walk's), printed by probes/run.py stage2_stop_hpfar. */
            c->last.repeats = hpfar;
#endif
        }
        fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, far);
        vcpu_of(c)->async_captured = 3;
        return 1;
    }

    if (ec == 0x32) {                            /* the stepped instruction is done */
        c->steps++;
        uint64_t pa = step_instruction_pa(c, *elr, physical_spsr);
        if (SNAP_STEP_ALU && pa && exception_monitor_origin(*elr, physical_spsr) &&
            vcpu_of(c)->stepping.active && vcpu_of(c)->open_guards == 1 &&
            (pa & ~0xfffUL) != p->vbar) {
            struct guard *g = guard_find(c, pa);
            /* The service lock excludes every guest stage-1 update. Stage-2
             * read-only code excludes concurrent stores. No memory access,
             * flags change, SP access, branch, or system operation is emulated.
             * The bounded batch remains in this translation; all unsupported
             * instructions retain their existing native-step/monitor path. */
            uint64_t mdscr;
            __asm__ volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
            if (g && g->mode == GUARD_EXEC && !(g->descriptor & (1UL << 7)) &&
                *(volatile uint64_t *)g->slot == g->descriptor &&
                step_alu_ready(&c->step_alu[vcpu_of(c)->slot], *elr,
                               c->shadow_tlb_syncs, physical_spsr, mdscr)) {
                unsigned n = step_alu_batch((volatile uint32_t *)pa, elr, frame);
                if (n) {
                    struct step_alu_state *s = &c->step_alu[vcpu_of(c)->slot];
                    s->batches++;
                    s->instructions += n;
                    if (s->max_batch < n) s->max_batch = n;
                    pa += n * 4;
                }
            }
        }
        uint32_t word = pa ? *(volatile uint32_t *)pa : 0;
        /* genter, and the second call encoding this kernelcache pairs with every
         * one of them. Both are undefined instructions on this silicon; what
         * matters is that the stub has arrived at one. */
        if (exception_monitor_origin(*elr,physical_spsr) &&
            (word == 0x00201420 || word == 0xd4e00000)) {
            /* Single stepping is still armed, so answering the call and
             * returning keeps us on the next instruction -- which is how the
             * rest of the stub page stays under observation. */
            return monitor_request(c,frame,elr);
        }
        guard_step(c, pa);
        if (SNAP_STEP_ALU && vcpu_of(c)->stepping.active)
            step_alu_resume(&c->step_alu[vcpu_of(c)->slot], *elr, c->shadow_tlb_syncs);
        return 0;
    }

    if (ec == 1 && (iss & 1)) {                  /* trapped WFE */
        clock_wfe(c);
        if (device_reset_stop(c, *elr, frame)) return 1;
        *elr += 4;
        return 0;
    }
    if (ec == 0x16) {                            /* HVC from the guest */
#if SNAP_SPTM_HVC_CALLS
        if ((iss & 0xffff) == NATIVE_HVC_IMMEDIATE) {
            struct vcpu *v=vcpu_of(c);
            struct native_hvc_state *s=&c->sptm_hvc[v->slot];
            uint64_t pc=*elr-4,pa=0;uint32_t word=0;
            unsigned mode=physical_spsr&31;int page=0;
            s->last_pc=pc;
            if((mode==4 || mode==5) && !(pc&3) &&
               pc>=UINT64_C(0xffff800000000000)) {
                pa=guest_pa(pc);
                for(unsigned n=0;n<NATIVE_CALL_PAGES;n++)
                    page|=(pa&~UINT64_C(4095))==p->stub_pa[n] &&
                          (pc&~UINT64_C(4095))==native_call_page_va(n);
                if(page)word=*(const volatile uint32_t *)pa;
            }
            if(p->stub_count!=(NATIVE_COMPILED_FLAGS|NATIVE_CONTRACT_PAGES) ||
               esr!=((UINT64_C(0x16)<<26)|(UINT64_C(1)<<25)|NATIVE_HVC_IMMEDIATE) ||
               !page || word!=NATIVE_HVC_WORD || v->stepping.active || v->open_guards ||
               !v->prepared || c->native_calls[v->slot].ready!=1 ||
               (physical_spsr>>32) || (physical_spsr&((1UL<<20)|(1UL<<21)))) {
                s->rejected++;
                record(c,EV_MONITOR,pc,esr,pa,word);
                fill_regs(&v->async_regs,frame,esr,pc,pa);v->async_captured=2;
                return 1;
            }
            /* HVC already saved the following PC. The shared dispatcher takes
             * the call PC and advances once; failure evidence names that call.
             * EL1's ELR/SPSR/ESR/FAR were not overwritten, so never restore the
             * private-call snapshot here. Endpoint/lock semantics are unchanged. */
            s->calls++;*elr=pc;
            return monitor_request(c,frame,elr);
        }
#endif
        if ((iss & 0xffff) == ADRENO_GUEST_HVC && (p->gpu.flags & ADRENO_F_ENABLE)) {
            if (frame[0] == ADRENO_GUEST_STOP) {
                early_stop_hvc(c, frame, *elr, physical_spsr);
                return 0;
            }
#if SNAP_GUEST_NET
            if (frame[0] == ADRENO_GUEST_NET) {
                guest_net_hvc(c, frame, *elr, physical_spsr);
                return 0;
            }
#endif
#if SNAP_ADRENO_IB_ASYNC
            if (frame[0] == ADRENO_GUEST_IB_POLL) {
                gpu_ib_poll_hvc(c, frame, *elr);
                return 0;
            }
#endif
#if SNAP_ADRENO_RECOVER
            if (frame[0] == ADRENO_GUEST_RECOVER) {
                gpu_recover_hvc(c, frame, *elr);
                return 0;
            }
            const uint64_t recover_attempts = GPU_RECOVER(c)->attempts, recover_faults = c->gpu.faults;
#endif
            /* runtime_enter holds the service lock across native DART lookup,
             * mirror validation and the bounded CP poll. HVC ELR is advanced. */
            uint64_t r[4] = {frame[0], frame[1], frame[2], frame[3]};
            unsigned index;
            int e = ADRENO_E_PARAMS;
            if (device_dart_admit_frame(p->models, c->model_state,
                    (unsigned)p->model_count, 5, SPTM_DART_ADRENO, 0, 2, &index) == DEVICE_OK) {
                struct sptm_memory memory = sptm_context_memory(c);
                struct gpu_leaf_ctx leaf = {&memory, &c->model_state[index].dart};
                struct adreno_ops o = gpu_ops(c);
#if SNAP_GPU_DVFS
                /* G18: the first IB of a burst runs at the ceiling: vote it before this doorbell (once per burst;
                 * every IB holds it). A START refused because a flight is active is not a doorbell. */
                if (r[0] == ADRENO_GUEST_IB
#if SNAP_ADRENO_IB_ASYNC
                    || (r[0] == ADRENO_GUEST_IB_START && !IB_FLIGHT(c)->active)
#endif
                    )
                    dvfs_gpu_kick(c);
#endif
#if SNAP_ADRENO_RECOVER
                /* agents/gpu-recovery R25: after the monitor gave up, ring users are refused before any write. */
                e = adreno_recover_refuse(GPU_RECOVER(c), &c->gpu, r);
                if (!e)
#endif
#if SNAP_ADRENO_IB_ASYNC
                /* An IB in flight: ring users and an UNMAP of its package are refused before any write (A7, A1b). */
                e = adreno_ib_flight_refuse(&c->gpu, IB_FLIGHT(c), r);
                if (!e)
#endif
                e = r[0] == ADRENO_GUEST_UNMAP ?
                    adreno_guest_unmap(&o, &p->gpu, &c->gpu, r, gpu_leaf, gpu_unmap, &leaf,
                                       p->mem_low, p->mem_high) :
                    r[0] == ADRENO_GUEST_CACHE ?
                    adreno_guest_cache(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                       p->mem_low, p->mem_high) :
                    r[0] == ADRENO_GUEST_FILL32 ?
                    adreno_guest_fill32(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                       p->mem_low, p->mem_high) :
                    r[0] == ADRENO_GUEST_IB ?
                    adreno_guest_ib(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                    p->mem_low, p->mem_high) :
#if SNAP_ADRENO_RECOVER
                    r[0] == ADRENO_GUEST_IB_START ?
                    adreno_recover_start(&o, &p->gpu, &c->gpu, IB_FLIGHT(c), GPU_RECOVER(c), r, gpu_leaf, &leaf,
                                         p->mem_low, p->mem_high) :
#elif SNAP_ADRENO_IB_ASYNC
                    r[0] == ADRENO_GUEST_IB_START ?
                    adreno_guest_ib_start(&o, &p->gpu, &c->gpu, IB_FLIGHT(c), r, gpu_leaf, &leaf,
                                          p->mem_low, p->mem_high) :
#endif
                    adreno_guest_fence(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                       p->mem_low, p->mem_high);
            } else {
                r[0] = (uint64_t)(int64_t)e; r[1] = r[2] = 0; r[3] = c->gpu.wptr;
                c->gpu.fence_error = r[0];
            }
#if SNAP_ADRENO_RECOVER
            gpu_recover_record(c, *elr, recover_attempts, recover_faults);
#endif
            if (frame[0] == ADRENO_GUEST_UNMAP || frame[0] == ADRENO_GUEST_CACHE)
                record(c, EV_GPU_SMMU, *elr, (uint64_t)(int64_t)e, frame[1], frame[0]);
            else if (frame[0] == ADRENO_GUEST_IB)
                record(c, EV_GPU_IB, *elr, frame[1], frame[2] << 32 | (uint32_t)e, r[2]);
#if SNAP_ADRENO_IB_ASYNC
            else if (frame[0] == ADRENO_GUEST_IB_START) {
                /* One EV_GPU_IB per IB (A18): here when START ended it, else by the POLL that does. */
                if (e != ADRENO_IB_PENDING)
                    record(c, EV_GPU_IB, *elr, frame[1], frame[2] << 32 | (uint32_t)e, r[2]);
            }
#endif
            else
                record(c, EV_GPU_RING, *elr,
                       frame[0] == ADRENO_GUEST_FILL32 ? frame[3] : frame[2],
                       (uint64_t)(int64_t)e, r[2]);
#if SNAP_GPU_DVFS
            /* G9: the GPU time of each synchronous submission (an IB's doorbell to completion, a fence's or
             * FILL32's ticks); async flights count when they end (dvfs_tick, sum_ticks). */
            if (c->root_ext && (frame[0] == ADRENO_GUEST_IB || frame[0] == ADRENO_GUEST_FENCE ||
                                frame[0] == ADRENO_GUEST_FILL32
#if SNAP_ADRENO_IB_ASYNC
                                || (frame[0] == ADRENO_GUEST_IB_START && e != ADRENO_IB_PENDING)
#endif
                                ))
                gpu_dvfs_busy(&c->root_ext->gpu_dvfs, r[2]);
#endif
            for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
            return 0;
        }
        if (!(iss & 0xffff) && (p->gpu.flags & ADRENO_F_ENABLE)) {
            /* HVC #0 as SMCCC: the two TrustZone GPU calls q1n1 forwards. */
            uint64_t r[8] = {frame[0], frame[1], frame[2], frame[3]};
            struct adreno_ops o = gpu_ops(c);
            int refused = adreno_smc(&o, p->gpu.flags, &c->gpu, r);
            record(c, EV_GPU_SMC, *elr, frame[0], frame[1], refused ? ~0UL : r[0]);
            if (refused) return 1;
            for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
            return 0;
        }
        record(c, EV_OTHER, *elr, esr, frame[0], 0);
        return 1;
    }

    if (ec == 0x1a) { /* HCR.NV traps ERET from the nested host kernel. */
        uint64_t target, spsr, translated, pa = guest_pa(*elr);
        __asm__ volatile("mrs %0, elr_el1" : "=r"(target));
        __asm__ volatile("mrs %0, spsr_el1" : "=r"(spsr));
        uint32_t word = pa >= p->mem_low && pa <= p->mem_high - 4
            ? *(volatile uint32_t *)pa : 0;
        uint64_t vhcr = vcpu_of(c)->vncr_va ? *(volatile uint64_t *)(vcpu_of(c)->vncr_va + 0x78) : 0;
        uint64_t target_pa = guest_pa(target);
        if (target_pa >= p->mem_low && target_pa <= p->mem_high - 4 &&
            exception_kernel_return(word, vhcr, target, spsr, &translated)) {
            step_arm(c, 0);
            guards_close(c);
            __asm__ volatile("msr spsr_el2, %0" :: "r"(translated));
            record(c, EV_EXCEPTION_RETURN, *elr, target, spsr, translated);
            vcpu_of(c)->kernel_returns++;
            vcpu_of(c)->last_kernel_return = target;
            *elr = target;
            return 0;
        }
        struct sptm_root_cached *root;
        if(exception_monitor_origin(*elr,physical_spsr) &&
           exception_user_return(word,vhcr,target,spsr,&translated) &&
           (root=user_return_root(c))) {
            if(!user_enter_mode(c,1))return 1;
            step_arm(c,0);guards_close(c);
            int probe=!user->returns && user_entry_snapshot(c,root,user,target,spsr,frame[0]);
            user->returns++;
            __asm__ volatile("msr spsr_el2, %0"::"r"(translated));
            record(c,EV_USER_RETURN,*elr,target,spsr,root->root);
            *elr=target;
            if(probe) {user->pending=1;step_arm(c,1);}
            return 0;
        }
        fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, target);
        vcpu_of(c)->async_captured = 2;
        record(c, EV_RETURN_REFUSED, *elr, target, spsr, word);
        return 1;
    }
    if (ec == 0x09 && generic_pauth_supported()) {
        uint64_t pa = guest_pa(*elr), sp, spsr;
        /* Executable guest memory only; never read an instruction from MMIO
         * or from a translation that points outside the owned RAM window. */
        if (pa >= p->mem_low && pa <= p->mem_high - 4) {
            __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
            if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
            else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
            uint32_t word = *(volatile uint32_t *)pa;
            if (pauth_pacga(word, frame, sp, generic_sign, c)) {
                vcpu_of(c)->pacga_calls++;
                record(c, EV_OTHER, *elr, 0x50414347, word, 0);
                *elr += 4;
                return 0;
            }
        }
    }
    if (ec != 0x18) {
        __asm__ volatile("mrs %0, far_el2" : "=r"(vcpu_of(c)->fault_far));
        record(c, EV_OTHER, *elr, esr, vcpu_of(c)->fault_far, 0);
        return 1;
    }

    c->traps++;
    uint64_t reg = ISS_REG(iss), rt = ISS_RT(iss);
    /* The ID group, trapped by TID3: answer with the truth, minus the features
     * this hypervisor cannot stand behind. An unallocated or reserved encoding
     * (FEAT_IDST brings those here too) reads as zero: id_register never
     * executes an MRS of one, which would fault at EL2 (probes/idregs.h). */
    uint32_t op0 = (uint32_t)((iss >> 20) & 3), op1 = (uint32_t)((iss >> 14) & 7);
    uint32_t crn = (uint32_t)((iss >> 10) & 0xf), crm = (uint32_t)((iss >> 1) & 0xf);
    uint32_t op2 = (uint32_t)((iss >> 17) & 7);
    if (op0 == 3 && op1 == 0 && crn == 0 && crm < 8 && (iss & 1)) {
        if (rt != 31) frame[rt] = id_forge(crm, op2, id_register(crm, op2));
        *elr += 4;
        return 0;
    }
    uint64_t value = (rt == 31) ? 0 : frame[rt];
    int is_read = ISS_READ(iss);
    if(pauth_user_reg(&c->user_pauth[vcpu_of(c)->slot],reg,is_read,&value)) {
        /* Preserve PACGA's existing scoped native backend while replacing
         * ignored key/control MSRs with explicit guest operator state.
         * Address PAC consumers remain disabled until their key domain and
         * EL0 entry/exit switching are integrated and qualified. */
        struct pauth_user_state *state=&c->user_pauth[vcpu_of(c)->slot];
#if SNAP_NATIVE_PACGA
        uint64_t apga_lo=vcpu_of(c)->guest_apga_lo,apga_hi=vcpu_of(c)->guest_apga_hi;
#endif
        vcpu_of(c)->guest_apga_lo=state->key[PAUTH_GA].lo;
        vcpu_of(c)->guest_apga_hi=state->key[PAUTH_GA].hi;
#if SNAP_NATIVE_PACGA
        native_pacga_sync(c,vcpu_of(c),apga_lo,apga_hi);
#endif
        if(is_read && rt!=31)frame[rt]=value;
        *elr+=4;return 0;
    }
    enum ipi_result ipi_status=IPI_UNHANDLED;
    if(reg==IPI_RR_LOCAL || reg==IPI_RR_GLOBAL || reg==IPI_SR) {
        struct guest_ipi *states[GUEST_CPU_COUNT];
        uint64_t affinities[GUEST_CPU_COUNT],runnable=0;
        uint64_t life=guest_service_lifecycle(&c->services);
        for(unsigned i=0;i<GUEST_CPU_COUNT;i++) {
            states[i]=&c->vcpus[i].ipi;affinities[i]=c->vcpus[i].vmpidr;
            if(!(life&SERVICE_ADMISSION_CLOSED) && c->vcpus[i].prepared &&
               ((life>>(i*3))&7)==EXECUTOR_RUNNING) runnable|=UINT64_C(1)<<i;
        }
        ipi_status=guest_ipi_route(states,affinities,GUEST_CPU_COUNT,runnable,
                                    (unsigned)vcpu_of(c)->slot,reg,is_read,&value);
    }
    if(ipi_status!=IPI_UNHANDLED) {
        if(ipi_status!=IPI_OK) {
            record(c,EV_IPI_FAILED,*elr,ipi_status,iss,value);
            return 1;
        }
        if(!is_read) {
            if(reg==IPI_SR && value) vcpu_of(c)->ipi_ack_pc=*elr;
            else if(reg!=IPI_SR) vcpu_of(c)->ipi_request_pc=*elr;
        }
        guest_interrupt_sync(c);
        if(is_read && rt!=31) frame[rt]=value;
        *elr+=4;
        return 0;
    }
    if (reg == CLOCK_ARCH_CNTP_CTL) {
        enum clock_result status = guest_timer_idle_access(&vcpu_of(c)->idle_physical_timer,
                                                           reg, is_read, &value);
        if (status != CLOCK_OK) {
            record(c, EV_CLOCK_FAILED, *elr, status, iss, value);
            return 1;
        }
        if (is_read && rt != 31) frame[rt] = value;
        *elr += 4;
        return 0;
    }
    if (op0 == 3 && op1 == 3 && crn == 14 &&
        reg != CLOCK_ARCH_CNTVCT && reg != CLOCK_ARCH_CNTVCTSS) {
        record(c, EV_CLOCK_FAILED, *elr, CLOCK_TIMER_UNSUPPORTED, iss, value);
        return 1;
    }
    if (reg == CLOCK_ARCH_CNTVCT || reg == CLOCK_ARCH_CNTVCTSS)
        vcpu_of(c)->arch_counter_reads += is_read;

    if (reg == CLOCK_CNTV_CTL || reg == CLOCK_CNTV_TVAL) {
        uint64_t now = clock_counter(c);
        enum clock_result status = guest_timer_access(&vcpu_of(c)->timer, reg, is_read, &value, now);
        if (status != CLOCK_OK) {
            record(c, EV_CLOCK_FAILED, *elr, status, iss, value);
            return 1;
        }
        timer_sync(c);
        if (device_reset_stop(c, *elr, frame)) return 1;
        if (is_read && rt != 31) frame[rt] = value;
        *elr += 4;
        return 0;
    }

    struct clock_backend clock_host = {c, clock_counter, clock_control};
    enum clock_result clock_status = guest_clock_access(&vcpu_of(c)->clock, &clock_host,
                                                        reg, is_read, &value);
    if (clock_status != CLOCK_UNHANDLED) {
        if (clock_status != CLOCK_OK) {
            record(c, EV_CLOCK_FAILED, *elr, clock_status, iss, value);
            return 1;
        }
        if (is_read && rt != 31) frame[rt] = value;
        *elr += 4;
        return 0;
    }

    struct sprr_state *sprr=&c->user_roots.sprr[vcpu_of(c)->slot];
    enum sprr_result sprr_status;
    if(reg==SPRR_UPERM && !is_read && value!=sprr->uperm) {
        uint64_t saved;__asm__ volatile("mrs %0, spsr_el2":"=r"(saved));
        sprr_status=user_write_uperm(c,frame,*elr,saved,0xd51ef1a0U|rt);
    } else sprr_status=sprr_access_with(sprr,reg,is_read,&value,kernel_change_pperm,c);
    if(sprr_status!=SPRR_UNHANDLED) {
        if(sprr_status!=SPRR_OK) {
            record(c,EV_SPRR_FAILED,*elr,sprr_status,iss,value);
            /* A system-register trap need not pass through XNU's exception
             * vectors. Preserve this CPU's actual frame for the stop reader;
             * last_exc may be empty or belong to an earlier guest exception. */
            fill_regs(&vcpu_of(c)->async_regs,frame,esr,*elr,0);
            vcpu_of(c)->async_captured=2;
            return 1;
        }
        if(is_read && rt!=31)frame[rt]=value;
        *elr+=4;return 0;
    }
    switch (reg) {
    case SR_CONST_LOWER:
    case SR_CONST_UPPER:
        /* ...ba87c08/c14 read these; c18 adds 0xfff to the upper
         * page base. Guest writes cannot change the firmware-owned range. */
        if(!is_read)return 1;
        value=reg==SR_CONST_LOWER ? p->const_begin : p->const_end-4096;
        c->const_reads[reg==SR_CONST_UPPER]++;
        break;
    case SR_ESR_EL1:
        /* TVM/TRVM also trap these architectural exception registers. A
         * zero fallback hides the data abort's IL/EC/FSC from XNU and makes
         * it panic about a two-byte instruction instead of paging it in. */
        if (is_read) __asm__ volatile("mrs %0, esr_el1" : "=r"(value));
        else __asm__ volatile("msr esr_el1, %0" :: "r"(value));
        break;
    case SR_FAR_EL1:
        if (is_read) __asm__ volatile("mrs %0, far_el1" : "=r"(value));
        else __asm__ volatile("msr far_el1, %0" :: "r"(value));
        break;
    case SR_TTBR0_EL1:
        if (is_read) value = vcpu_of(c)->guest_ttbr0; else vcpu_of(c)->guest_ttbr0 = value;
        break;
    case SR_TTBR1_EL1:
        if (is_read) value = vcpu_of(c)->guest_ttbr1; else vcpu_of(c)->guest_ttbr1 = value;
        break;
    case SR_TCR_EL1:
        if (is_read) value = vcpu_of(c)->guest_tcr; else vcpu_of(c)->guest_tcr = value;
        break;
    case SR_MAIR_EL1:
        if (is_read) value = vcpu_of(c)->guest_mair; else vcpu_of(c)->guest_mair = value;
        break;
    case SR_SCTLR_EL1:
        if (is_read) value = vcpu_of(c)->guest_sctlr; else vcpu_of(c)->guest_sctlr = value;
        break;
    case SR_AMXIDR_EL1:
        if (is_read) value = AMXIDR_VERSION_1;
        break;
    case SR_GXF_STATUS_EL1:
        /* There is no guarded world here, so execution is never inside one.
         * Zero is the truthful answer rather than a placeholder. */
        if (is_read) value = 0;
        break;
    default:
        /* Remaining Apple IMPDEF registers are still provisional zero/ignored
         * models. A constant read is not evidence of hardware compatibility:
         * the counter aliases above demonstrated why each reached register
         * needs its own semantics. Keep this remaining surface in the log. */
        record(c, EV_SYSREG, *elr, iss, value, is_read);
        if (is_read) value = 0;
        break;
    }

    if (is_read && rt != 31) frame[rt] = value;
    *elr += 4;
    return 0;
}

#if SNAP_FAST_VCPU_TRAPS
/* This CPU's operations for compat/fast-trap.h, identical to the reads the
 * locked handlers make. */
static uint64_t fast_guest_pa(void *ctx,uint64_t va) {(void)ctx;return guest_pa(va);}
static uint32_t fast_fetch(void *ctx,uint64_t pa) {(void)ctx;return *(volatile uint32_t *)pa;}
static uint64_t fast_stack(void *ctx,uint64_t spsr)
{
    uint64_t sp;(void)ctx;
    if(spsr&1)__asm__ volatile("mrs %0, sp_el1":"=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0":"=r"(sp));
    return sp;
}
static uint64_t fast_esr(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, esr_el1":"=r"(v));return v;}
static uint64_t fast_far(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, far_el1":"=r"(v));return v;}
/* secondary_wait_entry's condition: CPU0 must keep taking the locked path,
 * which waits for a launched secondary after release, until it has entered. */
static int fast_secondary_pending(struct context *c)
{
    if(!c->secondary_base)return 0;
    for(unsigned i=1;i<6;i++) {
        if(!(c->host_cpus->mask&(1U<<i)))continue;
        struct secondary *s=secondary_of(c,i);
        if(!s->on_result && __atomic_load_n(&s->phase,__ATOMIC_ACQUIRE)<3)return 1;
    }
    return 0;
}
/* 1: emulated without the service lock, resume the guest. 0: take the locked
 * path, which repeats the classification and handles the trap unchanged. */
/* What every lock-free trap path requires: the service admits this CPU, no
 * view or install failure is latched, and no step, guard, user-entry probe,
 * pending secondary launch or native-call snapshot needs the locked path. */
static int fast_admitted(struct context *c,const struct vcpu *v,uint64_t esr)
{
    return guest_service_admitted(&c->services,(unsigned)v->slot) &&
       !__atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED) &&
       !__atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED) &&
       !__atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED) &&
       !v->stepping.active && !v->open_guards && !c->user_execution[v->slot].pending &&
       !(!v->slot && fast_secondary_pending(c)) && !native_call_snapshot_required(esr,0);
}
static int fast_reset_latched(struct context *c)
{
    return (__atomic_load_n(&c->device_reset_mask[0],__ATOMIC_RELAXED) |
            __atomic_load_n(&c->device_reset_mask[1],__ATOMIC_RELAXED))!=0;
}
/* The guest's virtual FIQ/IRQ lines agree with their sources. A path that
 * would leave a disagreement (an IPI another CPU posted, a changed timer or
 * model line) declines, so guest_interrupt_sync on the locked path raises it. */
static int fast_lines_current(const struct vcpu *v)
{
    uint64_t hcr;__asm__ volatile("mrs %0, hcr_el2":"=r"(hcr));
    int fiq=v->timer_pending || __atomic_load_n(&v->ipi.pending,__ATOMIC_RELAXED);
    return !(hcr&(1UL<<6))==!fiq && !(hcr&(1UL<<7))==!v->model_irq_pending;
}
/* A CNTV_TVAL write may skip timer_sync only while the watchdog is live, no
 * device deadline has passed since this CPU's last sync and nothing else is
 * waiting for the locked path. */
static int fast_timer_write_ready(struct context *c,const struct vcpu *v)
{
    if(!SNAP_FAST_TIMER_WRITE || !v->watchdog_live)return 0;
    uint64_t physical;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(physical));
    return physical<c->fast_timer_due[v->slot].physical && fast_lines_current(v) &&
           !fast_reset_latched(c);
}
#if SNAP_FAST_IPI
/* The locked handler's IPI case (xnuboot_trap_locked: c->traps, guest_ipi_route,
 * the request/ack PC, guest_interrupt_sync, Rt and ELR) for an admitted CPU,
 * without the token: compat/fast-ipi.h decides, with the same runnable mask.
 * guest_interrupt_sync touches only this vCPU (no step is active once
 * admitted). 1: handled; 0: the locked path repeats it unchanged. */
static int fast_ipi_trap(struct context *c,struct vcpu *v,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    uint64_t start;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(start)::"memory");
    uint64_t iss=esr&0x1ffffff,reg=ISS_REG(iss),rt=ISS_RT(iss);
    int is_read=(int)ISS_READ(iss);
    struct fast_ipi_cpu *f=&c->root_ext->fast_ipi[v->slot];
    if(!fast_admitted(c,v,esr)) {f->result[FAST_IPI_DECLINE_STATE]++;return 0;}
    struct guest_ipi *states[GUEST_CPU_COUNT];
    uint64_t affinities[GUEST_CPU_COUNT],runnable=0,life=guest_service_lifecycle(&c->services);
    for(unsigned i=0;i<GUEST_CPU_COUNT;i++) {
        states[i]=&c->vcpus[i].ipi;affinities[i]=c->vcpus[i].vmpidr;
        if(!(life&SERVICE_ADMISSION_CLOSED) && c->vcpus[i].prepared &&
           ((life>>(i*3))&7)==EXECUTOR_RUNNING) runnable|=UINT64_C(1)<<i;
    }
    uint64_t value=(rt==31) ? 0 : frame[rt];
    unsigned r=fast_ipi_access(states,affinities,GUEST_CPU_COUNT,runnable,(unsigned)v->slot,
                               reg,is_read,&value);
    f->result[r]++;
    if(r>=FAST_IPI_DECLINES)return 0;
    if(!is_read) {
        if(reg==IPI_SR && value) v->ipi_ack_pc=*elr;
        else if(reg!=IPI_SR) v->ipi_request_pc=*elr;
    }
    guest_interrupt_sync(c);
    if(is_read && rt!=31) frame[rt]=value;
    *elr+=4;
    /* c->traps' share (report word 2 adds every CPU's fast sysreg count), and
     * runtime_enter's per-vCPU bookkeeping for the category. */
    c->perf.fast[v->slot].sysreg++;
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],0x18);
    step_translation_clear(&c->step_translation[v->slot]);
    uint64_t end;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(end)::"memory");
    f->ticks+=end-start;
    if(end-start>f->max)f->max=end-start;
    return 1;
}
#endif
#if SNAP_LEAN_TRAPS
/* After a lock-free ESR/FAR/PMC read at EL1 (lean_run_start), the next
 * instructions while each is an MRS the lock-free path answers: read from the
 * const-sealed kernel image through the current stage-1 translation, emulated
 * by fast_trap_emulate with the syndrome a trap would report, at most
 * LEAN_RUN_MAX. The first trap's admission covers them (no stop, step, guard
 * or probe can begin without a trap or tick); an ignored register not yet
 * logged ends the run, so it traps and takes the locked path's record. Not
 * traps: neither the census nor handled[] counts them (lean->steps does). */
static inline __attribute__((always_inline)) void lean_run_ahead(struct context *c,
    struct fast_trap_cpu *f,struct lean_trap_cpu *l,
    const struct fast_trap_hw *hw,const struct fast_trap_vcpu *state,uint64_t spsr,
    uint64_t *frame,uint64_t *elr)
{
    const struct params *p=c->params;
    uint64_t page=UINT64_MAX,base=0;
    l->runs++;
    for(unsigned n=0;n<LEAN_RUN_MAX;n++) {
        uint64_t va=*elr;
        if((va>>12)!=page) {
            uint64_t pa=guest_pa(va);
            if(!pa) {l->ends++;return;}
            page=va>>12;base=pa&~UINT64_C(0xfff);
        }
        uint64_t pa=base|(va&0xfff);
        if(pa<p->const_begin || pa>p->const_end-4) {l->ends++;return;}
        uint64_t reg;unsigned rt;
        if(!lean_mrs(*(const volatile uint32_t *)pa,&reg,&rt))return;
        unsigned cls=fast_trap_sysreg_class(reg,1);
        uint64_t bit=fast_trap_log_bit(cls,reg);
        if(!lean_run_class(cls) || (bit && !(f->logged&bit)))return;
        if(fast_trap_emulate(hw,state,lean_mrs_esr(reg,rt),spsr,frame,elr)!=cls)return;
        l->steps++;
    }
}
#endif
static int fast_vcpu_trap(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    uint64_t ec=esr>>26,reg=0;
    if(ec!=0x09 && ec!=0x18)return 0;
    struct vcpu *v=vcpu_of(c);
    struct fast_trap_cpu *f=&c->perf.fast[v->slot];
    unsigned cls=FAST_TRAP_PACGA;
    if(ec==0x18) {
        uint64_t iss=esr&0x1ffffff;reg=ISS_REG(iss);
#if SNAP_FAST_IPI
        if(reg==IPI_RR_LOCAL || reg==IPI_RR_GLOBAL || reg==IPI_SR)return fast_ipi_trap(c,v,frame,esr,elr);
#endif
        cls=fast_trap_sysreg_class(reg,(int)ISS_READ(iss));
        if(cls==FAST_TRAP_NONE)return 0;
    }
    /* The first trap of each recording class/register per vCPU keeps its
     * shared-log record by taking the locked path. */
    uint64_t bit=fast_trap_log_bit(cls,reg);
    if(bit && !(f->logged&bit)) {f->logged|=bit;f->first++;f->declined++;return 0;}
    if(!fast_admitted(c,v,esr) ||
       /* A latched device reset stops the guest at its next locked timer access. */
       (cls==FAST_TRAP_TIMER && fast_reset_latched(c)) ||
       (cls==FAST_TRAP_TIMER_WRITE && !fast_timer_write_ready(c,v))) {
        f->declined++;return 0;
    }
    uint64_t spsr;
    __asm__ volatile("mrs %0, spsr_el2":"=r"(spsr));
    const struct clock_backend clock={c,clock_counter,clock_control};
    const struct fast_trap_hw hw={.ctx=c,.mem_low=c->params->mem_low,
#if SNAP_LEAN_TRAPS
        /* Only PACGA asks; the ID registers are not read for the others. */
        .mem_high=c->params->mem_high,.pac_supported=ec==0x09 && generic_pauth_supported(),
#else
        .mem_high=c->params->mem_high,.pac_supported=generic_pauth_supported(),
#endif
        .guest_pa=fast_guest_pa,.fetch=fast_fetch,.stack=fast_stack,.sign=generic_sign,
        .esr=fast_esr,.far=fast_far,.clock=&clock};
    const struct fast_trap_vcpu state={&c->user_pauth[v->slot],&v->guest_apga_lo,
        &v->guest_apga_hi,&v->pacga_calls,&v->clock,&v->arch_counter_reads,&v->timer,
        &c->user_roots.sprr[v->slot],&v->timer_pending};
#if SNAP_NATIVE_PACGA
    uint64_t apga_lo=v->guest_apga_lo,apga_hi=v->guest_apga_hi;
#endif
    unsigned done=fast_trap_emulate(&hw,&state,esr,spsr,frame,elr);
    if(done==FAST_TRAP_NONE) {f->declined++;return 0;}
#if SNAP_NATIVE_PACGA
    if(done==FAST_TRAP_KEY)native_pacga_sync(c,v,apga_lo,apga_hi);
#endif
    if(done==FAST_TRAP_TIMER_WRITE) {
        /* The line is unchanged (fast_trap_emulate checked it), so only this
         * CPU's EL2 timer moves, exactly as timer_sync would arm it. */
        uint64_t physical;__asm__ volatile("mrs %0, cntpct_el0":"=r"(physical));
        timer_arm(c,physical,c->fast_timer_due[v->slot].guest);
    }
    /* runtime_enter's per-vCPU bookkeeping for every non-step category. */
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],(unsigned)ec);
    step_translation_clear(&c->step_translation[v->slot]);
    f->handled[done]++;
    if(ec==0x18)f->sysreg++;
    FAST_EXIT_MARK(frame,FAST_EXIT_TRAP_SLOT(done));
#if SNAP_LEAN_TRAPS
    if(ec==0x18 && lean_run_start(done,reg,(int)ISS_READ(esr&0x1ffffff)))
        lean_run_ahead(c,f,&c->root_ext->lean[v->slot],&hw,&state,spsr,frame,elr);
#endif
    return 1;
}
#endif

#if SNAP_FAST_TIMER_IRQ
/* This CPU's operations for compat/fast-timer-irq.h: the reads, writes and
 * calls of xnuboot_async_locked's tick and timer_sync. */
_Static_assert(FAST_IRQ_ISTATUS==CNTHP_ISTATUS && ASYNC_IRQ_OTHER!=ASYNC_IRQ &&
               ASYNC_IRQ_OTHER!=ASYNC_FIQ && ASYNC_IRQ_OTHER!=ASYNC_SERROR,
               "the gate's ISTATUS; the hand-over kind is no vector's");
static uint64_t fast_irq_acknowledge(void *ctx)
{
    uint64_t intid;(void)ctx;
    __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy":"=r"(intid)::"memory");
    return intid;
}
static void fast_irq_complete(void *ctx,uint64_t intid) {(void)ctx;timer_eoi(intid);}
static uint64_t fast_irq_physical(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, cntpct_el0":"=r"(v));return v;}
static uint64_t fast_irq_hcr(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, hcr_el2":"=r"(v));return v;}
static void fast_irq_set_hcr(void *ctx,uint64_t v) {(void)ctx;__asm__ volatile("msr hcr_el2, %0; isb"::"r"(v));}
static void fast_irq_arm(void *ctx,uint64_t physical,uint64_t due) {timer_arm(ctx,physical,due);}
/* 0, or 1 when the run stopped meanwhile: the tick ran here. FAST_IRQ_LOCKED:
 * nothing but this CPU's counter changed, take the locked path.
 * FAST_IRQ_LOCKED_OTHER: the acknowledged INTID was completed, take the
 * locked path's stop for it. */
#if SNAP_FAST_TIMER_IRQ_CPU0
/* vCPU 0 only: 1 when none of the duties its locked tick adds is due, by the
 * same tests those duties make, without their bookkeeping: the host poll
 * (early_stop_host_due), the thermal sample (a16_thermal_wait is 0 when due)
 * and the GPU tick (adopted, not quiesced, run_at reached), and a locked tick
 * within FAST_IRQ_CPU0_LOCKED_MS. Each schedule is written only by vCPU 0, in
 * its locked tick, so this CPU reads its own last values. Counts the first
 * duty found due. */
static int fast_cpu0_quiet(struct context *c,uint64_t physical)
{
    const struct params *p=c->params;
    struct fast_irq_cpu0 *z=&c->root_ext->cpu0_tick;
    const struct early_stop_params *e=&p->early_stop;
    const struct early_stop_state *s=&c->early_stop;
    if(!z->locked || physical-z->locked>=p->clock_host_hz/1000*FAST_IRQ_CPU0_LOCKED_MS) {z->backstop++;return 0;}
    if((e->flags&EARLY_STOP_F_HOST) && e->host_call && e->session &&
       e->host_poll_ms>=EARLY_STOP_POLL_FLOOR(e) && e->host_poll_ms<=EARLY_STOP_POLL_MAX_MS &&
       (!s->host_polls || (int64_t)(physical-s->host_next_poll)>=0)) {z->host++;return 0;}
    if(c->thermal && !a16_thermal_wait(c->thermal,physical,p->clock_host_hz,1)) {z->thermal++;return 0;}
    if(p->gpu.flags && (c->gpu.status&ADRENO_S_ADOPTED) && !(c->gpu.status&ADRENO_S_QUIESCED) &&
       physical>=c->gpu.run_at) {z->gpu++;return 0;}
    z->quiet++;
    return 1;
}
#endif
static int fast_timer_irq(struct context *c,uint64_t elr,uint64_t *frame)
{
    struct vcpu *v=vcpu_of(c);
    struct fast_irq_cpu *f=&c->root_ext->fast_irq[v->slot];
    struct fast_irq_gate g={.slot=v->slot};
    if(v->slot) {
        /* xnuboot_async_locked's reads, then fast_timer_write_ready's gate:
         * this CPU's last synced device deadline, no reset latched. */
        __asm__ volatile("mrs %0, cnthp_ctl_el2; mrs %1, icc_hppir1_el1; mrs %2, cntpct_el0"
                         :"=r"(g.ctl),"=r"(g.hppir),"=r"(g.physical));
        g.admitted=(uint64_t)fast_admitted(c,v,0);
        g.watchdog_live=v->watchdog_live;
        g.device_due=c->fast_timer_due[v->slot].physical;
        g.reset_latched=(uint64_t)fast_reset_latched(c);
        g.deadline=run_deadline(c);
    }
#if SNAP_FAST_TIMER_IRQ_CPU0
    else {
        /* vCPU 0: the same inputs, and whether any of its own duties is due. */
        __asm__ volatile("mrs %0, cnthp_ctl_el2; mrs %1, icc_hppir1_el1; mrs %2, cntpct_el0"
                         :"=r"(g.ctl),"=r"(g.hppir),"=r"(g.physical));
        g.admitted=(uint64_t)fast_admitted(c,v,0);
        g.watchdog_live=v->watchdog_live;
        g.device_due=c->fast_timer_due[0].physical;
        g.reset_latched=(uint64_t)fast_reset_latched(c);
        g.deadline=run_deadline(c);
        g.cpu0_quiet=(uint64_t)fast_cpu0_quiet(c,g.physical);
    }
#endif
#if SNAP_ANS_ASYNC
    /* agents/nvme-async N11, N19: at this vCPU's SSD deadline, peek at the completion (read-only). Ready, or
     * work queued with nothing in flight, or the backstop: the deadline counts as a passed device deadline, so
     * the gate declines and the locked tick polls. Not ready: push this vCPU's deadline and stay here. */
    {
        struct ans_state *as=c->root_ext->ans;
        uint64_t due;
        if(as && ans_async_due_of(c,v->slot,&due) && (int64_t)(g.physical-due)>=0) {
            struct ans_async *a=&as->async;
            __atomic_fetch_add(&a->sched[2],1,__ATOMIC_RELAXED);
            struct ans_window_backend b=ans_window_backend(c);
            if(!__atomic_load_n(&a->phys,__ATOMIC_RELAXED) || ans_window_ready(&b) ||
               (int64_t)(g.physical-a->start-ans_async_us(c,ANS_ASYNC_BACKSTOP_US))>=0) {
                if(due<g.device_due)g.device_due=due;     /* 0 (unsynced) already declines */
                __atomic_fetch_add(&a->sched[3],1,__ATOMIC_RELAXED);
            } else {
                uint64_t next=ans_async_next(c,g.physical,a->start);
                __atomic_compare_exchange_n(&a->due,&due,next,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED);
            }
        }
    }
#endif
    unsigned r=fast_timer_irq_gate(&g);
    if(r==FAST_IRQ_HANDLED) {
        const struct fast_irq_hw hw={c,fast_irq_acknowledge,fast_irq_complete,clock_counter,
                                     fast_irq_physical,fast_irq_hcr,fast_irq_set_hcr,fast_irq_arm};
        const struct fast_irq_vcpu state={&v->timer,&v->timer_pending,&v->ipi.pending,
            &v->model_irq_pending,&v->timer_irqs,&v->timer_irq_pc,&v->timer_asserts,&v->timer_clears,
            &v->model_irq_asserts,&v->model_irq_clears,c->fast_timer_due[v->slot].guest};
        r=fast_timer_irq_tick(&hw,&state,elr);
    }
    f->result[r]++;
    if(r==FAST_IRQ_OTHER)return FAST_IRQ_LOCKED_OTHER;
    if(r!=FAST_IRQ_HANDLED)return FAST_IRQ_LOCKED;
    /* runtime_enter's per-vCPU bookkeeping for the IRQ category. */
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],SERVICE_PROFILE_ASYNC+ASYNC_IRQ);
    step_translation_clear(&c->step_translation[v->slot]);
#if SNAP_WFI_RESUME
    /* The locked tick's last step, after the same ones; a reset latched since
     * the gate declines it, as device_reset_stop's stop does there. */
    wfi_resume(c,elr,frame,fast_reset_latched(c));
    if(frame[32]!=elr)f->resumed++;
#else
    (void)frame;
#endif
    uint64_t end;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(end)::"memory");
    f->ticks+=end-g.physical;
    if(end-g.physical>f->max)f->max=end-g.physical;
    return guest_service_stopped(&c->services)!=0;
}
#endif

#if SNAP_FAST_CROSSINGS
/* This CPU's operations for compat/fast-vector.h, identical to the reads the
 * locked vector and ERET branches make. */
static void fast_el1(void *ctx,struct fast_cross_el1 *r)
{
    (void)ctx;
    __asm__ volatile("mrs %0, esr_el1; mrs %1, far_el1; mrs %2, elr_el1; "
                     "mrs %3, spsr_el1; mrs %4, sctlr_el1"
                     :"=r"(r->esr),"=r"(r->far),"=r"(r->elr),"=r"(r->spsr),"=r"(r->sctlr));
}
static uint64_t fast_hcr(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, hcr_el2":"=r"(v));return v;}
static uint64_t fast_vhcr(void *ctx)
{
    const struct vcpu *v=vcpu_of(ctx);
    return v->vncr_va ? *(volatile uint64_t *)(v->vncr_va+0x78) : 0;
}
/* EL0 crossings select through native tables (native_cross, per-CPU by its
 * contract). Without them a crossing rewrites this CPU's shared view copies
 * under the lock: no selection, so every EL0 entry and user return declines.
 * user_enter_mode's own check stays: the variant selected must be the active
 * root's (the active root's cache entry and views cannot change while it is
 * installed, and roots are unique in the cache, so the read-only lookup needs
 * no lock). A mismatch latches the failure as it does under the lock, and the
 * declined exit's locked path stops the run. */
#if SNAP_NATIVE_TABLES
static int fast_select(void *ctx,int el0)
{
    struct context *c=ctx;
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[cpu]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[cpu]);
#endif
    if(!e || !native_cross(c,cpu,el0))return 0;
    if(c->user_view_state[cpu].shadow==user_hw_root(c,e,cpu))return 1;
    __atomic_store_n(&c->user_view_failed,1,__ATOMIC_RELAXED);
    return 0;
}
#define FAST_SELECT fast_select
#else
#define FAST_SELECT 0
#endif
static int fast_user_root(void *ctx) {return user_return_root(ctx)!=0;}
static void fast_capture(void *ctx,const uint64_t *frame,uint64_t esr,uint64_t elr,uint64_t far)
{capture_regs(ctx,frame,esr,elr,far);}
#if SNAP_FAST_EL0_SYSREG
#if SNAP_EL0_MEMO
/* SNAP_EL0_MEMO: fast_el0_word's answer from this vCPU's memo
 * (compat/el0-memo.h), or 0 and the full read follows. The root: no install
 * on this vCPU since the way was read and the same active root, so
 * user_return_root's lookup still names the way's entry (an installed root's
 * cache slot is never evicted, invalidated or retired, its hardware-walk
 * record never detached, and a root has one identity), which is re-checked
 * here before user_return_root's own checks (user_return_check). The walks:
 * their configuration recomputed and every recorded descriptor re-read,
 * unchanged, through user_instruction_read's readers. The code frame and the
 * word: re-read by user_code_word. A stale or changed way is dropped. */
static int el0_memo_answer(struct context *c,uint64_t pc,struct fast_el0_fetch *out)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct el0_memo_cpu *m=&EL0M(c)[cpu];
    struct el0_memo_entry *w=el0_memo_find(m,pc);
    if(!w)return 0;
    uint64_t active=c->user_roots.active[cpu];
    struct sptm_root_cached *e=(struct sptm_root_cached *)w->entry;
    if(!el0_memo_current(m,w,active) || !e->valid || e->root!=active || user_return_check(c,e)!=e) {
        el0_memo_drop(w);m->stats.stale++;return 0;
    }
#if SNAP_USER_HW_WALK
    unsigned hardware_kind=hw_walk_of_entry(c->hw_walk,e)!=0;
    mmu_read_fn hardware_read=hardware_kind ? hw_table_read : kernel_table_read;
#else
    unsigned hardware_kind=0;
    mmu_read_fn hardware_read=kernel_table_read;
#endif
    uint64_t pa=w->page_pa|(pc&0xfff);uint32_t word;
    if(!el0_memo_check(w,e,e->root,e->format ? 12u : 14u,user_hw_root(c,e,cpu),hardware_kind,
                       user_source_read,c,hardware_read,c) || !user_code_word(c,pa,&word)) {
        el0_memo_drop(w);m->stats.changed++;return 0;
    }
    *out=(struct fast_el0_fetch){w->source_leaf,w->hardware_leaf,pa,e->root,word};
    m->stats.hits++;
    return 1;
}
#endif
/* user_sysreg_access's root and word, by the same two functions. */
static int fast_el0_word(void *ctx,uint64_t pc,struct fast_el0_fetch *out)
{
    struct context *c=ctx;
#if SNAP_EL0_MEMO
    /* A memo hit is already the second read of a pair (FAST_EL0_FETCH_PROVEN);
     * otherwise this full read records itself for fast_el0_note to keep. */
    if(el0_memo_answer(c,pc,out))return FAST_EL0_FETCH_PROVEN;
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    el0_memo_begin(&EL0M(c)[cpu],pc,c->user_roots.active[cpu]);
#endif
    struct sptm_root_cached *root=user_return_root(c);
    struct mmu_leaf source,hardware;uint32_t word;
#if SNAP_EL0_MEMO
    int read=root && user_instruction_read(c,root,pc,&source,&hardware,&word);
    el0_memo_end(&EL0M(c)[cpu],read);
    if(!read)return 0;
#else
    if(!root || !user_instruction_read(c,root,pc,&source,&hardware,&word))return 0;
#endif
    *out=(struct fast_el0_fetch){source.descriptor,hardware.descriptor,source.pa,root->root,word};
    return 1;
}
/* user_sysreg_access's records, statement for statement
 * (tools/test-fast-el0-sysreg.py compares them). */
static void fast_el0_note(void *ctx,unsigned kind,uint64_t pc,uint32_t word,uint64_t saved,uint64_t root)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
    if(kind==FAST_EL0_CLOCK) {
        struct user_clock_state *u=&c->user_clock[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=v->clock.last;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root;u->cntkctl=v->clock.cntkctl;u->raw=v->clock_raw_last;
        u->host_hz=v->clock_rate.host_hz;u->guest_hz=v->clock_rate.guest_hz;
    } else {
        struct sprr_state *sprr=&c->user_roots.sprr[v->slot];
        struct user_sprr_state *u=&c->user_sprr[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=sprr->uperm;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root;u->umprr=sprr->umprr;
    }
#if SNAP_EL0_MEMO
    /* Both reads agreed and the word was emulated: keep that read's record. */
    el0_memo_keep(&EL0M(c)[v->slot],pc,root);
#endif
}
#endif
/* 1: the vector entry or ERET was handled without the service lock. 0: take
 * the locked path, which repeats the classification and handles it unchanged. */
static int fast_crossing(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    uint64_t ec=esr>>26;
    if(ec!=0x20 && ec!=0x1a)return 0;
    struct vcpu *v=vcpu_of(c);
    struct fast_trap_cpu *f=&c->perf.fast[v->slot];
    const struct params *p=c->params;
    uint64_t spsr,far,hcr;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2; mrs %2, hcr_el2"
                     :"=r"(spsr),"=r"(far),"=r"(hcr));
    /* Only the vector fetch of an exception entry: its IPA is the vector page. */
    if(ec==0x20 && (!p->vbar || far!=*elr || (esr&(1UL<<7)) ||
                    (guest_pa(far)&~0xfffUL)!=p->vbar))return 0;
    /* The locked boundary re-derives the virtual FIQ/IRQ lines (step_arm ->
     * guest_interrupt_sync), which is where an IPI another CPU posted is first
     * raised: take the locked path while a line disagrees with its sources. */
    int fiq=v->timer_pending || __atomic_load_n(&v->ipi.pending,__ATOMIC_RELAXED);
    if(((spsr&31)!=4 && (spsr&31)!=5) ||
       !guest_service_admitted(&c->services,(unsigned)v->slot) ||
       __atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED) ||
       __atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED) ||
       __atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED) ||
       v->stepping.active || v->open_guards || c->user_execution[v->slot].pending ||
       (!v->slot && fast_secondary_pending(c)) ||
       !(hcr&(1UL<<6))!=!fiq || !(hcr&(1UL<<7))!=!v->model_irq_pending) {
        f->declined++;return 0;
    }
#if SNAP_FAST_EL0_SYSREG
    const struct clock_backend clock={c,clock_counter,clock_control};
    const struct fast_el0_hw el0_hw={.ctx=c,.fetch=fast_el0_word,.clock=&clock,.note=fast_el0_note};
    uint64_t el0_spsr=0;
    const struct fast_el0_vcpu el0_state={&v->clock,&c->user_roots.sprr[v->slot],frame,
        c->exit_profile.cpu[v->slot].el0,&el0_spsr};
#endif
    const struct fast_cross_hw hw={.ctx=c,.vbar_va=p->vbar_va,.vbar_pa=p->vbar,
        .mem_low=p->mem_low,.mem_high=p->mem_high,.crash_ring=SNAP_USER_CRASH_RING,
        .guest_pa=fast_guest_pa,.fetch=fast_fetch,.el1=fast_el1,.hcr=fast_hcr,
        .vhcr=fast_vhcr,.cross=FAST_SELECT,.user_root=fast_user_root,.capture=fast_capture,
#if SNAP_FAST_EL0_SYSREG
        .el0=&el0_hw,
#endif
    };
    struct pan_entry_state *pan=&c->pan_entry[v->slot];
    struct user_execution *user=&c->user_execution[v->slot];
    const struct fast_cross_vcpu state={&pan->user_vectors,&pan->protected_vectors,
        &pan->vector,&pan->saved_spsr,&pan->entry_spsr,&pan->entry_sctlr,
        &v->timer_vectors,&v->model_irq_vectors,&v->fault_esr,&v->fault_far,
        &v->kernel_returns,&v->last_kernel_return,&user->returns,&user->svcs,&user->faults,
        &f->logged,&f->first,
#if SNAP_FAST_EL0_SYSREG
        &el0_state,
#endif
    };
    uint64_t next=0;
    unsigned done=ec==0x20 ? fast_cross_entry(&hw,&state,spsr,frame,elr) :
                             fast_cross_return(&hw,&state,spsr,elr,&next);
    if(done==FAST_CROSS_NONE) {f->declined++;return 0;}
    if(ec==0x1a)__asm__ volatile("msr spsr_el2, %0"::"r"(next));
#if SNAP_FAST_EL0_SYSREG
    /* The emulated EL0 read: back to EL0 with user_sysreg_access's PSTATE
     * (xnuboot_pauth_resume reloads the EL0 keys from SPSR_EL2's mode), the
     * vector slot not taken. */
    else if(done==FAST_CROSS_EL0_SYSREG_CLASS)__asm__ volatile("msr spsr_el2, %0"::"r"(el0_spsr));
#endif
    else f->branches++;
    /* The common exit's native-call snapshot: a vector entry always, an ERET
     * under SNAP_ERET_SNAPSHOT. */
    if(SNAP_NATIVE_CALLS && (ec==0x20 || SNAP_ERET_SNAPSHOT))native_exception_snapshot(c);
    /* runtime_enter's per-vCPU bookkeeping for every non-step category. */
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],(unsigned)ec);
    step_translation_clear(&c->step_translation[v->slot]);
    if(ec==0x20)f->entries++;else f->returns++;
    FAST_EXIT_MARK(frame,FAST_EXIT_CROSS_SLOT(done));
    return 1;
}
#endif

#if SNAP_FAST_IDLE_POLL
/* The ACC idle poll (compat/fast-mmio.h): routed exactly as the locked data
 * abort is (stage-1 IPA, device windows, then device_model_find), answered
 * with the locked access's value, clock sample and read count. The locked
 * path's interrupt rerouting, model rescans and timer_sync follow an access
 * that changed nothing; the next locked trap or EL2 timer redoes them. */
static int fast_idle_poll(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    if((esr>>26)!=0x24 || (esr&(1UL<<7)))return 0;      /* data abort, not a stage-1 walk */
    struct dc_access a=dc_decode(esr);
    if(!a.valid || a.write || a.size!=8)return 0;
    struct vcpu *v=vcpu_of(c);
    const struct params *p=c->params;
    uint64_t spsr,far,hpfar;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2; mrs %2, hpfar_el2"
                     :"=r"(spsr),"=r"(far),"=r"(hpfar));
    if((spsr&31)!=4 && (spsr&31)!=5)return 0;
    uint64_t ipa=guest_pa(far),off=0;
    if(!ipa && (hpfar&0x0000fffffffffff0UL))ipa=((hpfar>>4)<<12)|(far&0xfff);
    if(!ipa || dc_window(p->device_pa,p->device_span,p->device_count,ipa,&off)>=0)return 0;
    int index=device_model_find(p->models,p->model_count,ipa,&off);
    if(index<0 || !fast_idle_poll_model(&p->models[index],off,a.size,a.write))return 0;
    struct fast_trap_cpu *f=&c->perf.fast[v->slot];
    if(!fast_admitted(c,v,esr) || !fast_lines_current(v) || fast_reset_latched(c)) {
        f->declined++;return 0;
    }
    (void)clock_counter(c);
    if(a.reg!=31)frame[a.reg]=dc_extend(&a,0);
    __atomic_fetch_add(&c->model_reads[index],1,__ATOMIC_RELAXED);
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],0x24);
    step_translation_clear(&c->step_translation[v->slot]);
    f->handled[FAST_TRAP_IDLE_POLL]++;
    FAST_EXIT_MARK(frame,FAST_EXIT_TRAP_SLOT(FAST_TRAP_IDLE_POLL));
    *elr+=4;return 1;
}
#endif

#if SNAP_FINE_LOCKS
/* ---- SNAP_FINE_LOCKS: converted user address-space calls -----------------
 * docs/FINE-LOCKS-20261017.md; compat/fine-lock.h has the lock levels.
 * A converted call is a native SPTM call (MAP_PAGE, UNMAP_REGION,
 * UPDATE_DISJOINT; SWITCH_ROOT cache hits with SNAP_FINE_SWITCH; the user
 * pointer-authentication calls, which name no root, with
 * SNAP_FAST_PAUTH_CALLS) that runs with the gate shared and its roots'
 * stripes held instead of the token. The
 * code below repeats the locked path's statements for that call (the native
 * call entry of xnuboot_trap_locked, monitor_request, monitor_call,
 * monitor_call_impl, the endpoint's case and its backend callbacks), with
 * three differences, each argued in the note:
 *  - global words the locked path writes are written atomically (counters,
 *    tracker bits, the memo clock, epochs), or under aux (the event log, the
 *    SWITCH_ROOT memo, the kernel class proof);
 *  - classification declines, with nothing changed, wherever the call would
 *    leave the converted envelope; the locked path then repeats the call;
 *  - the call's own stores are published at the store (live writes), so it
 *    runs no transaction_publish: no global flush, no runtime-page clean.
 * Frame types, cache identity and validity, root activity (without
 * SNAP_FINE_SWITCH), the arena and the kernel and shared-region state are
 * written only on the token path, so they are read here as constants. */
#if !SNAP_ROOT_CACHE_WIDE || !SNAP_NATIVE_TABLES || !SNAP_NATIVE_SHARED || !SNAP_NATIVE_CALLS || \
    !SNAP_USER_VIEW_CACHE || !SNAP_PRIVATE_VIEW_EPOCH || !SNAP_KERNEL_CLASS_PROOF || \
    !SNAP_ROOT_DIRTY_PUBLISH || !SNAP_TXN_DIRTY_PUBLISH || !SNAP_USER_TREE_MEMO || \
    !SNAP_USER_ONLY_TLBI || !SNAP_USER_UPDATE_KERNEL_SKIP || !SNAP_UPDATE_DISJOINT_FAST || \
    !SNAP_FAST_VCPU_TRAPS || SNAP_INCREMENTAL_PUBLISH || SNAP_STEP_ALU || !SNAP_SERVICE_DETAIL
#error "SNAP_FINE_LOCKS is written for the installed-fresh fast flag set (see docs/FINE-LOCKS-20261017.md)"
#endif
static struct fine_state *fine_of(struct context *c) {return &c->root_ext->fine;}
static struct fine_cpu *fine_cpu(struct context *c) {return &c->root_ext->fine.cpu[vcpu_of(c)->slot];}
#if SNAP_USER_HW_WALK
/* compat/user-hw-walk.h under fine locks (docs/USER-HW-WALK-20261017.md,
 * "Fine locks"). Every piece of hardware-walk state is token-path state: the
 * record index and records (attach in SWITCH_ROOT, detach in CONFIGURE,
 * RETIRE and SHARE), the copy pages (allocated and released only there and
 * in the hw_* backend callbacks), every copy store, the hw_walk_stats
 * counters and the stage-2 table protection (RETYPE). None is reached from a
 * converted call, so none needs a stripe, aux or an atomic: a converted call
 * naming a root that has a record declines with FINE_NO_ROOT, before any
 * stripe is taken, and the locked path runs the hw_* callbacks (an inactive
 * hardware-walk root would otherwise pass fine_user_backend uncached and its
 * TPRO copies would keep a leaf XNU removed). The lookup is a read of the
 * index, which only a token holder writes: with the gate shared it cannot
 * change. A converted switch whose target has a record declines (it is not
 * a cache hit: SWITCH_ROOT never caches a root with a record). A converted
 * switch from such a root to the kernel or to a cached root stays converted:
 * the token path runs no hardware-walk code for it either (sptm_mac_switch_root
 * consults hw_eligible only for its target) and the per-CPU words
 * hw_install_user set are the ones fine_user_root_install rewrites. */
#define FINE_HW_ROOT(c,root) (hw_root((c),(root))!=0)
#endif
#if SNAP_FINE_HW && !SNAP_USER_HW_WALK
#error "SNAP_FINE_HW requires SNAP_USER_HW_WALK"
#endif
#if SNAP_FINE_SWITCH_HW && !SNAP_USER_HW_WALK
#error "SNAP_FINE_SWITCH_HW requires SNAP_USER_HW_WALK"
#endif
/* The latched failures runtime_leave stops on; set elsewhere with plain
 * stores on the token path, read here atomically. */
static uint64_t fine_failed(const struct context *c)
{
    return __atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED) |
           __atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED) |
           __atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED);
}
static void fine_view_failed(struct context *c) {__atomic_store_n(&c->user_view_failed,1,__ATOMIC_RELAXED);}
static void fine_aux_lock(struct context *c)
{
    struct fine_cpu *f=fine_cpu(c);
    uint64_t start=service_profile_clock();
    if(fine_ticket_lock(&fine_of(c)->aux)) {
        f->profile.aux_contended++;f->aux_wait+=service_profile_clock()-start;
    }
    f->profile.aux_entries++;
}
static void fine_aux_unlock(struct context *c) {fine_ticket_unlock(&fine_of(c)->aux);}

/* native_due, native_tlbi_range, native_store_admit, user_private_write,
 * kernel_table_write, native_copy_write, native_live_shadow,
 * native_store_propagate, mem_write, user_live_write, in that order. */
static int fine_native_due(uint64_t *asks)
{return !(__atomic_fetch_add(asks,1,__ATOMIC_RELAXED)&((UINT64_C(1)<<SNAP_NATIVE_AUDIT_SHIFT)-1));}
static void fine_native_tlbi_range(struct context *c,uint64_t va,uint64_t size)
{
    uint64_t first=va>>12,pages=(size+4095)>>12,saved;
    int all=!pages || pages>NATIVE_TLBI_PAGES;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        if(all)__asm__ volatile("tlbi vmalle1is" ::: "memory");
        else for(uint64_t n=0;n<pages;n++)
            __asm__ volatile("tlbi vaae1is, %0" :: "r"((first+n)&((UINT64_C(1)<<44)-1)) : "memory");
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    fine_add(&c->native_stats.tlbi_calls,1);
    if(all)fine_add(&c->native_stats.tlbi_full,1);else fine_add(&c->native_stats.tlbi_pages,pages);
    fine_add(&c->shadow_tlb_syncs,1);
}
static int fine_native_store_admit(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i))return 0;
    if(c->table_pool.owner[i]==NATIVE_SHARED_OWNER && (value&1) && sprr_pte_class(value)==9) {
        fine_add(&c->native_stats.refused,1);fine_view_failed(c);return 1;
    }
    int source=native_source(c,i);
    if(!source && (!(value&1) || sprr_pte_class(value)!=9))return 0;
    unsigned owner=c->table_pool.owner[i];
    const struct sprr_views *v=owner && owner<=SPTM_ROOT_CACHE ? &UVIEWS(c)[owner-1] : 0;
    if(!source && (!v || !v->count))return 0;
    if(source && v && v->count &&
       native_views_admit(v,pa,value,native_umprr(&c->user_roots.cache[owner-1])))return 0;
    fine_add(&c->native_stats.refused,1);fine_view_failed(c);return 1;
}
static int fine_mem_write(void *ctx,uint64_t pa,uint64_t value);
/* kernel_table_write without its kernel-copy publication note: a converted
 * call writes only pages its root's slot owns, never a kernel copy, and the
 * note's preparation only marks newly grown kernel copies, which
 * kernel_publish_cpu prepares again before it publishes anything. */
static int fine_kernel_table_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;
    if(*(volatile uint64_t *)pa==value)return 0;
    uint64_t i;unsigned owner=native_page(c,pa,&i) ? c->table_pool.owner[i] : 0;
    if(!owner || owner>SPTM_ROOT_CACHE) {fine_view_failed(c);return -1;}
    return fine_mem_write(ctx,pa,value);
}
static int fine_user_private_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;uint64_t old;
    if(kernel_table_read(c,pa,&old))return -1;
    if(old==value)return 0;
    if((old&1) && (value&1) && ((old^value)&PT_OA_MASK)) {
        if(fine_kernel_table_write(c,pa,0))return -1;
        publish(pa,pa+8);
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        fine_add(&c->shadow_tlb_syncs,1);
    }
    return fine_kernel_table_write(c,pa,value);
}
static int fine_native_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=fine_user_private_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
/* The converted call's allocator: refuses, so a shadow path that would need
 * a table fails preflight before any store and the call declines. */
static uint64_t fine_refuse_alloc(void *ctx)
{
    const struct user_table_owner *owner=ctx;
    fine_cpu(owner->context)->alloc_refused=1;return 0;
}
static struct shadow fine_native_live_shadow(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_view_shadow(c,e);
    s.alloc=fine_refuse_alloc;s.write=fine_native_copy_write;return s;
}
static int fine_native_store_propagate(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i) || !native_source(c,i))return 0;
    unsigned owner=c->table_pool.owner[i];
    if(!owner || owner>SPTM_ROOT_CACHE) {fine_view_failed(c);return 1;}
    struct sptm_root_cached *e=&c->user_roots.cache[owner-1];
    struct shadow s=fine_native_live_shadow(c,e);
    if(!native_views_store(&UVIEWS(c)[owner-1],&s,pa,value,native_umprr(e))) {
        fine_view_failed(c);return 1;
    }
    fine_add(&c->native_stats.propagated,1);return 0;
}
static int fine_mem_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if(fine_native_store_admit(c,pa,value))return -1;
    if(pa>=c->work_base && pa<c->next_table && c->next_table-pa>=8 &&
       *(volatile uint64_t *)pa!=value) {
        sprr_table_memo_note_fine(&c->table_memo,pa);
        if(!root_publish_note_fine(&c->root_publish,c->work_base,c->next_table,pa,8))return -1;
        txn_publish_observe_fine(&c->txn_publish,pa,8);
        int private=sprr_private_write_fine(&c->private_pages,c->work_base,c->next_table,pa);
        if(private<0)return -1;
        if(!private)sprr_view_epoch_advance_fine(&c->user_view_epoch);
        /* Kernel tables only: never one of a user root's pages. */
        if(sprr_class_proof_tracked(&c->kernel_class_proof,pa)) {
            fine_aux_lock(c);sprr_class_proof_note(&c->kernel_class_proof,pa);fine_aux_unlock(c);
        }
    }
    fine_cpu(c)->stores++;
    *(volatile uint64_t *)pa = value;
    if(fine_native_store_propagate(c,pa,value))return -1;
    return 0;
}
static int fine_user_live_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=fine_mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
/* sptm_publish: the SWITCH_ROOT memo's write witness, under aux. */
static void fine_sptm_publish(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    fine_cpu(c)->stores++;
    fine_aux_lock(c);
    sptm_root_memo_publish(&c->root_memo,p->frame_map_pa,p->frame_low,p->frame_high,
                           sptm_map,c,pa,size);
    fine_aux_unlock(c);
    publish(pa, pa + size);
}
/* sptm_context_memory with this CPU's reference batch, snapshots and audit
 * share. No clean_frame: an SH/AttrIndx change is refused in preflight and
 * runs on the token path (attr_updates is token-path state). */
static struct sptm_memory fine_memory(struct context *c)
{
    struct sptm_memory m=sptm_context_memory(c);
    struct fine_cpu *f=fine_cpu(c);
    m.publish=fine_sptm_publish;m.refs=&fine_of(c)->refs[vcpu_of(c)->slot];
    m.audit=&f->audit;m.fine=&f->ref_fine;m.clean_frame=0;
#if SNAP_DART_MEMO
    m.dart_memo=0;   /* the memo is the token path's */
#endif
    return m;
}

/* The user backend: user_live_shadow, user_refresh_all,
 * user_commit_tlb_range, user_tlb_range, user_prepare/commit_leaf,
 * user_prepare_unmap, user_prepare/commit_update, user_commit_unmap,
 * user_backend. */
static struct shadow fine_live_shadow(struct context *c,struct sptm_root_cached *e)
{
    return (struct shadow){.txsz=17,.root=e->shadow,.alloc=fine_refuse_alloc,
        .read=mem_read,.write=fine_user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
}
static int fine_user_refresh_all(struct context *c,struct sptm_root_cached *e)
{
    struct sprr_views *v=user_views(c,e);
    if(!v->count || !fine_native_due(&c->native_stats.audit_asks))return !fine_failed(c);
    int started=detail_begin(c,DETAIL_USER_REFRESH);
    struct shadow s=user_view_shadow(c,e);
    /* Every 64th sampled audit also walks the whole canonical tree. */
    int full=!(__atomic_fetch_add(&c->native_stats.audits,1,__ATOMIC_RELAXED)&63);
    int result=full ? native_views_verify(v,&s,native_umprr(e)) : native_views_exact(v,&s,native_umprr(e));
    fine_add(&c->native_stats.coverages,(uint64_t)full);
    if(!result) {fine_add(&c->native_stats.audit_failures,1);fine_view_failed(c);}
    detail_end(c,DETAIL_USER_REFRESH,started,result);return result;
}
static int fine_user_commit_tlb_range(struct context *c,unsigned kind,uint64_t va,uint64_t size)
{
    if(kind>=4 || fine_failed(c))return 0;
    fine_native_tlbi_range(c,va,size);
    fine_sat_add(&c->user_only_tlbi[kind],1,UINT64_MAX);
    return !fine_failed(c);
}
static int fine_user_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s=fine_live_shadow(c,e);
    if(!sptm_root_prepare_leaf(e,&s,va,shift))return 0;
    /* A class9 leaf's private paths (native_prepare_tpro) are token-path work:
     * refused in preflight, so the call declines. */
    return sprr_pte_class(pte)!=9;
}
static int fine_user_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s=fine_live_shadow(c,e);
    struct sptm_memory m=fine_memory(c);
    if(!sptm_root_commit_leaf(e,&s,&m,va,shift,pte) || !fine_user_refresh_all(c,e))return 0;
    if(!fine_user_commit_tlb_range(c,0,va,UINT64_C(1)<<shift))return 0;
    fine_add(&c->user_live_pages,1);return 1;
}
static int fine_user_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s=fine_live_shadow(c,e);
    struct sptm_memory m=fine_memory(c);
    return sptm_root_prepare_unmap(e,&s,&m,va,shift,count);
}
static int fine_user_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    if(!fine_user_prepare_unmap(ctx,root,va,shift,1))return 0;
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    /* Becoming class9 needs native_prepare_tpro: token path. */
    return !(e && sprr_pte_class(next)==9 && sprr_pte_class(old)!=9);
}
static int fine_user_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s=fine_live_shadow(c,e);
        struct sptm_memory m=fine_memory(c);
        if(!sptm_root_commit_update(e,&s,&m,va,shift,old,next) || !fine_user_refresh_all(c,e))return 0;
    }
    if(update_fast_uncached(old))return !fine_failed(c);
    fine_native_tlbi_range(c,va,UINT64_C(1)<<shift);return !fine_failed(c);
}
static int fine_user_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                  uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s=fine_live_shadow(c,e);
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed) || !fine_user_refresh_all(c,e))return 0;
    }
    if(!fine_user_commit_tlb_range(c,1,va,count<<shift))return 0;
    fine_add(&c->user_unmap_calls,1);fine_add(&c->user_unmap_pages,removed);return 1;
}
#if SNAP_FINE_HW && SNAP_USER_HW_WALK
/* ---- SNAP_FINE_HW: hardware-walk roots (docs/FINE-HW-WALK-20261019.md) ----
 * user_backend's hw_* events for a converted MAP_PAGE or UNMAP_REGION, under
 * the root's stripe: the record, its copies and copy pages are read, the
 * copies' existing entries rewritten (compat/user-hw-walk.h hw_walk_fine_*),
 * nothing allocated, linked or released; the shared counters are added
 * atomically. A class-9 leaf and a replacing MAP_PAGE decline before any
 * store (token path: hw_walk_before_tpro and user_commit_update's prelude). */
static void fine_hw_tlb_range(void *ctx,uint64_t va,uint64_t size){fine_native_tlbi_range(ctx,va,size);}
static void fine_hw_counted(struct context *c,const struct hw_walk_fine_counts *n)
{
    if(n->refreshes)fine_add(&c->hw_walk->stats.refreshes,n->refreshes);
    if(n->refreshed)fine_add(&c->hw_walk->stats.refreshed,n->refreshed);
}
#if SNAP_SPTM_FINE
/* SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md S9, S10): the events'
 * memory access. hw_ops' copy writer is hw_copy_write, i.e. mem_write, whose
 * tracker updates (memo clock, dirty bits, txn sentinel, private pages, epoch)
 * are plain RMWs: token-path only. A converted event writes a copy through
 * fine_mem_write and publishes it at the store (hw_copy_write's bounds and
 * clean); it never allocates or releases a copy page, so those two latch a
 * view failure if ever reached. */
static int fine_hw_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table)return -1;
    return fine_user_live_write(ctx,pa,value);    /* fine_mem_write, then publish */
}
static uint64_t fine_hw_refuse_alloc(void *ctx){fine_view_failed(ctx);return 0;}
static void fine_hw_refuse_release(void *ctx,uint64_t pa){(void)pa;fine_view_failed(ctx);}
static struct hw_walk_ops fine_hw_ops(struct context *c)
{return (struct hw_walk_ops){hw_table_read,fine_hw_copy_write,fine_hw_refuse_alloc,fine_hw_refuse_release,hw_table_type,c};}
#define FINE_HW_OPS(c) fine_hw_ops(c)
#else
#define FINE_HW_OPS(c) hw_ops(c)
#endif
static int fine_hw_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)va;return hw_walk_fine_prepare_leaf(hw_root(ctx,root),shift,pte);}
static int fine_hw_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct hw_walk_ops o=FINE_HW_OPS(c);struct hw_walk_fine_counts n;
    (void)pte;
    int ok=hw_walk_fine_after_add(&o,hw_root(c,root),va,UINT64_C(1)<<shift,&n);
    fine_hw_counted(c,&n);
    if(!ok) {fine_view_failed(c);return 0;}
    fine_add(&c->user_live_pages,1);
    return 1;
}
static int fine_hw_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)va;(void)count;return hw_walk_fine_prepare_unmap(hw_root(ctx,root),shift);}
static int fine_hw_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct hw_walk_ops o=FINE_HW_OPS(c);struct hw_walk_tlb t={fine_hw_tlb_range,c};
    struct hw_walk_fine_counts n;
    int ok=hw_walk_fine_after_change(&o,hw_root(c,root),va,count<<shift,&t,&n);
    fine_hw_counted(c,&n);
    if(!ok) {fine_view_failed(c);return 0;}
    if(fine_failed(c))return 0;
    fine_add(&c->user_unmap_calls,1);fine_add(&c->user_unmap_pages,removed);return 1;
}
#if SNAP_SPTM_FINE
/* SNAP_SPTM_FINE: a replacing MAP_PAGE and every update on a hardware-walk
 * root run converted. prepare: hw_prepare_update without its class-9 path
 * preparation (allocation: refused, the call declines before any store).
 * commit: user_commit_update's hardware-walk prelude (a hardware-walk root is
 * never cached: one that is fails as there), the copies' refresh, then its
 * skip and its invalidation (native_tlbi_range, every VMID). */
static int fine_hw_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)va;return hw_walk_fine_prepare_update(hw_root(ctx,root),shift,old,next);}
static int fine_hw_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct hw_walk_ops o=FINE_HW_OPS(c);struct hw_walk_tlb t={fine_hw_tlb_range,c};
    struct hw_walk_fine_counts n={0,0};
    (void)next;
    int ok=!user_cached(c,root) &&
        hw_walk_fine_after_update(&o,hw_root(c,root),va,UINT64_C(1)<<shift,!update_fast_uncached(old),&t,&n);
    fine_hw_counted(c,&n);
    if(!ok) {fine_view_failed(c);return 0;}
    return !fine_failed(c);
}
#else
/* A replacing MAP_PAGE (and any update): token path. Both are set because the
 * engine accepts a backend only with both or neither, and neither would let
 * an inactive root's replacement through without events. */
static int fine_hw_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;(void)old;(void)next;return 0;}
static int fine_hw_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;(void)old;(void)next;return 0;}
#endif
/* user_backend's hardware-walk branch: the same identity checks (activity
 * words loaded atomically), the events above, the inactive mirror, and no
 * shared-root, detach, attach or nest callbacks (the engine refuses those
 * calls before any store: declined). */
static int fine_hw_backend(struct context *c,uint64_t root,struct sptm_user_backend *b)
{
    b->ttbr0=vcpu_of(c)->guest_ttbr0;b->ttbr1=vcpu_of(c)->guest_ttbr1;
    b->aperture=xnu_aperture(c);b->moved=xnu_moved(c);b->ctx=c;
    b->prepare_leaf=fine_hw_prepare_leaf;b->commit_leaf=fine_hw_commit_leaf;
    b->prepare_unmap=fine_hw_prepare_unmap;b->commit_unmap=fine_hw_commit_unmap;
    b->prepare_update=fine_hw_prepare_update;b->commit_update=fine_hw_commit_update;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        int active=__atomic_load_n(&c->user_roots.active[cpu],__ATOMIC_RELAXED)==root;
        int recorded=(__atomic_load_n(&c->vcpus[cpu].guest_ttbr0,__ATOMIC_RELAXED)&0x0000ffffffffc000UL)==root;
        if(active!=recorded || (c->vcpus[cpu].guest_ttbr1&0x0000ffffffffc000UL)==root)return 0;
        b->active_refs+=active;
    }
    b->mirror=!b->active_refs;
    return 1;
}
#endif
/* user_backend for a converted call: the same identity checks, the fine
 * callbacks, no shared-root, detach, attach or nest callbacks (those roots
 * and operations run on the token path), and a root outside the call's
 * lockset refused, so every root the engine touches is one whose stripe this
 * CPU holds (the records are read again by the engine). Activity words are
 * loaded atomically: with SNAP_FINE_SWITCH another CPU's converted switch
 * writes its own words while this CPU holds other stripes. */
static int fine_user_backend(struct context *c,uint64_t root,struct sptm_user_backend *b)
{
    *b=(struct sptm_user_backend){0};
    if(!fine_lockset_has(&fine_cpu(c)->locks,root))return 0;
#if SNAP_USER_HW_WALK
#if SNAP_FINE_HW
    /* SNAP_FINE_HW: a MAP_PAGE or UNMAP_REGION on one (fine_lockset_for
     * admits no other converted kind) gets the converted hardware-walk events. */
    if(FINE_HW_ROOT(c,root))return fine_hw_backend(c,root,b);
#endif
    /* fine_lockset_for refused it already; every root an engine reaches is
     * checked here again (FINE_HW_ROOT). */
    if(FINE_HW_ROOT(c,root))return 0;
#endif
    b->ttbr0=vcpu_of(c)->guest_ttbr0;b->ttbr1=vcpu_of(c)->guest_ttbr1;
    b->aperture=xnu_aperture(c);b->moved=xnu_moved(c);
    b->prepare_leaf=fine_user_prepare_leaf;b->commit_leaf=fine_user_commit_leaf;b->ctx=c;
    b->prepare_unmap=fine_user_prepare_unmap;b->commit_unmap=fine_user_commit_unmap;
    b->prepare_update=fine_user_prepare_update;b->commit_update=fine_user_commit_update;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        int active=__atomic_load_n(&c->user_roots.active[cpu],__ATOMIC_RELAXED)==root;
        int recorded=(__atomic_load_n(&c->vcpus[cpu].guest_ttbr0,__ATOMIC_RELAXED)&0x0000ffffffffc000UL)==root;
        if(active!=recorded || (c->vcpus[cpu].guest_ttbr1&0x0000ffffffffc000UL)==root)return 0;
        b->active_refs+=active;
    }
    return !b->active_refs || user_cached(c,root)!=0;
}
static int fine_update_backend(void *ctx,uint64_t root,struct sptm_user_backend *b)
{return fine_user_backend(ctx,root,b);}
/* An admitted user root: managed, unlocked, USER_ROOT_TABLE (not a shared
 * root, whose leaves propagate to every alias), not the kernel root. */
static int fine_user_root(struct context *c,uint64_t root)
{
    struct sptm_memory m=sptm_context_memory(c);
    if(root==c->params->ttbr1_root || !sptm_managed_frame(&m,root))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((root-m.frame_low)>>14)*16,16);
    return meta && !meta[0] && !meta[1] && meta[2]==SPTM_MAC_USER_ROOT_TABLE;
}
static unsigned fine_frame_type(struct context *c,uint64_t pa)
{
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,pa&~UINT64_C(0x3fff)))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+(((pa&~UINT64_C(0x3fff))-m.frame_low)>>14)*16,16);
    return meta ? meta[2] : 0;
}

/* ---- the converted endpoints ------------------------------------------
 * Each returns FINE_DONE with frame[0] set, FINE_DECLINE with nothing
 * changed (*reason says why), or FINE_FATAL after a commit failure (stores
 * were made: terminal, reported under the token as the locked path does). */
enum {FINE_DECLINE,FINE_DONE,FINE_FATAL};
struct fine_call_state {
    uint64_t x16,a0,a1,a2,a3,elr;   /* arguments, and the guest ELR the call reports */
    unsigned kind,reason;
    uint64_t fail_kind,fail_a,fail_b;  /* the locked path's failure record */
    enum sptm_result result;
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    uint64_t fail_value;               /* with fail_raw: the record's a, in place of result */
    int fail_raw;
#endif
#if SNAP_SPTM_FINE_KERNEL
    uint64_t aux_va,aux_old,aux_new;   /* a converted kernel MAP_PAGE's auxkc_note_leaf, made under aux */
    int aux_note;
#endif
};
static int fine_engine_end(struct context *c,struct fine_call_state *s,enum sptm_result r,
                           uint64_t kind,uint64_t a,uint64_t b)
{
    struct fine_cpu *f=fine_cpu(c);
    if(r==SPTM_OK)return FINE_DONE;
    s->result=r;s->fail_kind=kind;s->fail_a=a;s->fail_b=b;
    if(!f->stores) {s->reason=f->alloc_refused ? FINE_NO_ALLOC : FINE_NO_ENGINE;return FINE_DECLINE;}
    return FINE_FATAL;
}
/* MAP_PAGE's user branch (monitor_call_impl case SPTM_FN_MAP_PAGE). */
static int fine_map_page(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    uint64_t root_pa=frame[0],va=frame[1],new_pte=frame[2];
    struct sptm_memory memory=fine_memory(c);
    struct sptm_user_backend backend={0};
    uint64_t result=0;
    if(!fine_user_backend(c,root_pa,&backend)) {s->reason=FINE_NO_ROOT;return FINE_DECLINE;}
    /* A cached root no CPU runs: inactive_map_keep's mirror/invalidation
     * decision rewrites the cache, a token-path structure. */
    if(!backend.active_refs && user_cached(c,root_pa)) {s->reason=FINE_NO_INACTIVE;return FINE_DECLINE;}
    if((new_pte&1) && sprr_pte_class(new_pte)==9) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    backend.map_updates=&c->user_map_replacements[vcpu_of(c)->slot];
    enum sptm_result r=sptm_mac_map_user_page(&memory,&backend,root_pa,va,new_pte,frame[3],scratch,&result);
    if(r==SPTM_TABLE_MISSING && !fine_cpu(c)->stores) {
        fine_add(&c->user_missing_tables,1);frame[0]=7;return FINE_DONE;
    }
    int end=fine_engine_end(c,s,r,EV_REFERENCE_FAILED,va,new_pte);
    if(end!=FINE_DONE)return end;
    if(result==SPTM_USER_MAP_CONFLICT) {
        struct user_map_conflict_state *w=&c->user_map_conflict[vcpu_of(c)->slot];
        w->count++;w->root=root_pa;w->va=va;w->wanted=new_pte;
        w->options=frame[3];w->old=w->pointer=0;w->result=result;
        if(!(frame[3]&1) && (mem_read(c,scratch,&w->old) || mem_read(c,scratch+8,&w->pointer)))
            w->old=w->pointer=0;
    }
    /* Otherwise an inactive root here is uncached: inactive_map_keep(c,0,..)
     * is 0 and sptm_root_invalidate finds no entry, so nothing changes. */
    fine_add(&c->map_pages,1);frame[0]=result;return FINE_DONE;
}
/* UNMAP_REGION's user branch. */
static int fine_unmap_region(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    struct sptm_user_backend user={0};
    if(!fine_user_backend(c,frame[0],&user)) {s->reason=FINE_NO_ROOT;return FINE_DECLINE;}
    enum sptm_result r=sptm_mac_unmap_user_region(&memory,&user,frame[0],frame[1],
                                                 frame[2],frame[3],scratch);
    int end=fine_engine_end(c,s,r,EV_UNMAP_FAILED,frame[1],frame[2]);
    if(end!=FINE_DONE)return end;
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
/* UPDATE_DISJOINT with user records only (update_disjoint_call's
 * sptm_mac_update_user_disjoint branch). transaction_publish is not run:
 * every store this call made was published at the store. The 1-in-1024
 * kernel-view verification of user_update_kernel_skip stays on the token
 * path (no kernel view can change while the gate is shared); the skip is
 * counted. attr_updates.pending is zero between token transactions. */
static int fine_update_disjoint(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    const struct params *p=c->params;
    struct sptm_memory memory=fine_memory(c);
    uint64_t target=frame[0],list=frame[1],count=frame[2],options=frame[3],response=SPTM_SUCCESS;
    unsigned type=fine_frame_type(c,target);
    if((options&(UINT64_C(0x10)|UINT64_C(0x20))) || (type!=SPTM_MAC_DEFAULT && type!=SPTM_MAC_USER_EXEC)) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    enum sptm_result r=sptm_mac_update_user_disjoint(&memory,fine_update_backend,c,
        target,list,count,options,scratch,&response,&c->user_updates[vcpu_of(c)->slot]);
    int end=fine_engine_end(c,s,r,EV_UPDATE_FAILED,target,options);
    if(end!=FINE_DONE)return end;
    (void)p;
    fine_add(&c->user_update_skip.skipped,1);
    fine_add(&c->update_calls,1);fine_add(&c->update_entries,count);
    frame[0]=response;return FINE_DONE;
}
#if SNAP_SPTM_FINE
/* ---- SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md) -------------------
 * UNMAP_DISJOINT with user records only: case SPTM_FN_UNMAP_DISJOINT's branch
 * for a list with no kernel record (sptm_mac_unmap_user_disjoint and nothing
 * else: each removed leaf's commit_unmap completed its TLBI in every VMID
 * before the references drop). fine_lockset_for admitted every record's root
 * and holds its stripe; the backend refuses any other root. */
static int fine_unmap_disjoint(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    uint64_t count=(uint32_t)frame[2];
    enum sptm_result r=sptm_mac_unmap_user_disjoint(&memory,fine_update_backend,c,
        frame[0],frame[1],count,scratch,&c->user_disjoint_unmaps[vcpu_of(c)->slot]);
    int end=fine_engine_end(c,s,r,EV_UNMAP_FAILED,frame[0],frame[2]);
    if(end!=FINE_DONE)return end;
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
/* UPDATE_REGION on a user root that is not a shared root: case
 * SPTM_FN_UPDATE_REGION's sptm_mac_update_user_region branch. No clean_frame
 * (fine_memory): a leaf whose SH/AttrIndx would change is refused in preflight
 * (SPTM_UNSUPPORTED_OPTIONS before any store), so attr_updates stays empty and
 * the token path's attr_clean_finish has nothing to do. */
static int fine_update_region(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    struct sptm_user_backend user={0};uint64_t result=0;
    if(!fine_user_backend(c,frame[0],&user)) {s->reason=FINE_NO_ROOT;return FINE_DECLINE;}
    enum sptm_result r=sptm_mac_update_user_region(&memory,&user,frame[0],frame[1],frame[2],
        frame[3],frame[4],scratch,&result,&c->user_regions[vcpu_of(c)->slot]);
    int end=fine_engine_end(c,s,r,EV_REGION_FAILED,frame[1],frame[4]);
    if(end!=FINE_DONE)return end;
    frame[0]=result;return FINE_DONE;
}
#endif
#if SNAP_SPTM_FINE_RETYPE
/* RETYPE for the page-table frame lifecycle (11->20, 20->11) and the data
 * reset (11->11): case SPTM_FN_RETYPE with none of its host callbacks, which
 * these transitions never call (no root, IOMMU, exec, TPRO, TXM, ROZONE or
 * shared transition; sptm_mac_retype's own guards keep it that way). The frame
 * is held exclusive (compat/sptm-frame-lock.h): no converted call holds a
 * reference touch, an input frame or a retype on it, and none can start one
 * until this call has published the new record. Every refusal of
 * sptm_mac_retype precedes its first store: a decline, and the token path
 * repeats and reports it (EV_RETYPE_FAILED). An AuxKC-range frame stays on the
 * token path (auxkc_observe_retype counts it there). sptm_root_memo_retype is
 * a read-only no-op here (the record's counts are zero, checked before, and
 * held still by the lock); the root index notes nothing (no root key). */
#if SNAP_USER_HW_WALK_S2RO
/* hw_s2_frame for a converted RETYPE: the same leaf-only S2AP change of the
 * frame's four pages in every vCPU's tree (pre-split at setup: nothing is
 * allocated; distinct frames are distinct words, so two converted retypes
 * never write one word), stored through fine_mem_write and cleaned at the
 * store, counters added atomically, then the same stage-2-by-IPA and aperture
 * invalidation in every VMID (this CPU's VTTBR, restored). */
static int fine_hw_s2_write(void *ctx,uint64_t pa,uint64_t value)
{return fine_user_live_write(ctx,pa,value);}     /* hw_s2_write: fine_mem_write, then publish */
static int fine_hw_s2_frame(struct context *c,uint64_t frame,int ro)
{
    struct shadow trees[HW_S2_TREES];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        trees[cpu]=(struct shadow){.txsz=S2_TXSZ,.root=c->vcpus[cpu].stage2_root,.alloc=fine_hw_refuse_alloc,
                                   .read=mem_read,.write=fine_hw_s2_write,.ctx=c};
    if(hw_s2_set(trees,GUEST_CPU_COUNT,frame,ro)<0) {fine_add(&c->hw_walk->stats.s2_failures,1);return 0;}
    if(ro)fine_add(&c->hw_walk->stats.s2_protects,1);else fine_add(&c->hw_walk->stats.s2_unprotects,1);
    struct sptm_aperture ap=xnu_aperture(c);struct sptm_moved mv=xnu_moved(c);
    uint64_t linear=sptm_aperture_pointer(&ap,frame,0x4000);
    uint64_t moved=sptm_published_pointer(&ap,&mv,frame,0x4000);
    uint64_t saved,mask=(UINT64_C(1)<<44)-1;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        for(unsigned p=0;p<4;p++)
            __asm__ volatile("tlbi ipas2e1is, %0" :: "r"(((frame+4096UL*p)>>12)&mask) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        for(unsigned p=0;p<4;p++) {
            if(linear)__asm__ volatile("tlbi vaae1is, %0" :: "r"(((linear+4096UL*p)>>12)&mask) : "memory");
            if(moved && moved!=linear)
                __asm__ volatile("tlbi vaae1is, %0" :: "r"(((moved+4096UL*p)>>12)&mask) : "memory");
        }
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    fine_add(&c->shadow_tlb_syncs,1);
    return 1;
}
#endif
static int fine_retype(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    const struct params *p=c->params;
    uint64_t pa=frame[0],old=frame[1],next=frame[2],options=frame[3];
    if(!((old==SPTM_MAC_DEFAULT && (next==SPTM_MAC_PAGE_TABLE || next==SPTM_MAC_DEFAULT)) ||
         (old==SPTM_MAC_PAGE_TABLE && next==SPTM_MAC_DEFAULT)) ||
       (p->auxkc.pa_end && pa>=p->auxkc.pa_base && pa<p->auxkc.pa_end)) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    if(!sptm_frame_exclusive(&fine_cpu(c)->frames,pa&~UINT64_C(0x3fff))) {s->reason=FINE_NO_FRAME;return FINE_DECLINE;}
    struct sptm_memory memory=fine_memory(c);
    memory.retype_user_tpro=0;
    enum sptm_result r=sptm_mac_retype(&memory,pa,old,next,options);
    int end=fine_engine_end(c,s,r,EV_RETYPE_FAILED,pa,next);
    if(end!=FINE_DONE)return end;
#if SNAP_USER_HW_WALK_S2RO
    /* As case SPTM_FN_RETYPE: a frame that became (or stopped being) a table is
     * read-only (or RW again) at stage 2 before XNU sees the result; a refusal
     * after the type store is terminal there too. */
    int s2=hw_s2_retype_action((unsigned)old,(unsigned)next);
    if(s2>=0 && !fine_hw_s2_frame(c,pa,s2)) {
        s->result=SPTM_SHADOW_FAILED;s->fail_kind=EV_RETYPE_FAILED;s->fail_a=pa;s->fail_b=next;
        return FINE_FATAL;
    }
#endif
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
/* The input frames a converted call reads besides its references: an
 * UPDATE_DISJOINT or UNMAP_DISJOINT record list, a pointer batch's input. Held
 * shared before the first read (S3, S18); 0: one is held exclusive. */
static int fine_input_frames(struct context *c,const struct fine_call_state *s)
{
    struct sptm_frame_held *h=&fine_cpu(c)->frames;
    uint64_t input=0;
    if(s->kind==FINE_CALL_UPDATE_DISJOINT || s->kind==FINE_CALL_UNMAP_DISJOINT)input=s->a1;
#if SNAP_FAST_PAUTH_CALLS
    if(s->kind==FINE_CALL_PAUTH_BATCH)input=s->a0;
#endif
    const struct params *p=c->params;
    if(!input || input<p->frame_low || input>=p->frame_high)return 1;
    return sptm_frame_share(h,input&~UINT64_C(0x3fff));
}
#endif
#if SNAP_SPTM_FINE_KERNEL
/* ---- SNAP_SPTM_FINE_KERNEL: kernel-root MAP_PAGE and UNMAP_REGION ----------
 * compat/sptm-fine.h has the converted bodies and why no kernel_refresh is
 * needed. Here: the token path's logged refusals and reports stay there
 * (classes 2/4/9, a root outside guest RAM, a PTE outside it: map_range_note
 * and the EV_MAP_OUTSIDE/EV_MAP_DEVICE records; a missing table, a conflict, a
 * copied or unbuilt shadow path); everything else runs under KL, the one lock
 * of every converted kernel-root call (the token path takes none: the gate). */
static int fine_kernel_copied(void *ctx,uint64_t table)
{
    const struct sprr_views *v=&((struct context *)ctx)->kernel_views;
    if(v->count>SPRR_VIEW_TABLES)return 1;
    for(uint64_t n=0;n<v->count;n++)if(v->tables[n].source==table)return 1;
    return 0;
}
static void fine_kernel_tlbi(void *ctx,uint64_t va,uint64_t size){fine_native_tlbi_range(ctx,va,size);}
static void fine_kernel_clean_out(void *ctx,volatile uint64_t *out)
{
    (void)ctx;
    __asm__ volatile("dc cvau, %0\n\tdc cvau, %1\n\tdsb ish" :: "r"(&out[0]), "r"(&out[1]) : "memory");
}
/* The canonical kernel shadow MAP_PAGE and UNMAP_REGION use (vcpu_of(c)->
 * shadow_root, shared by every vCPU), with the converted allocator (refuses:
 * the path was checked) and writer (fine_mem_write, cleaned at the store). */
static struct sptm_fine_kernel fine_kernel_of(struct context *c,struct sptm_memory *m,struct shadow *s,
    struct user_table_owner *owner,struct sptm_aperture *a,struct sptm_moved *moved,uint32_t txsz)
{
    *owner=(struct user_table_owner){c,0};
    *s=(struct shadow){.txsz=txsz,.root=vcpu_of(c)->shadow_root,.alloc=fine_refuse_alloc,
        .write=fine_user_live_write,.read=mem_read,.ctx=c,.alloc_ctx=owner,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    *a=xnu_aperture(c);*moved=xnu_moved(c);
    return (struct sptm_fine_kernel){.m=m,.shadow=s,.guest_read=mem_read,.guest_write=fine_mem_write,
        .copied=fine_kernel_copied,.tlbi=fine_kernel_tlbi,.clean_out=fine_kernel_clean_out,.ctx=c,
        .aperture=a,.moved=moved,.t1sz=(uint32_t)((c->params->tcr>>16)&0x3f)};
}
static int fine_kernel_map(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    const struct params *p=c->params;
    uint64_t root=frame[0],va=frame[1],new_pte=frame[2],pte_pa=new_pte&PT_OA_MASK;
    unsigned cls=sprr_pte_class(new_pte);
    if(((new_pte&1) && (cls==2 || cls==4 || cls==9)) ||
       (p->mem_low && (root<p->mem_low || root+0x4000>p->mem_high)) ||
       (p->mem_low && (new_pte&1) && (pte_pa<p->mem_low || pte_pa>=p->mem_high) &&
        !(p->fb_span && pte_pa>=p->fb_pa && pte_pa-p->fb_pa<p->fb_span))) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    struct sptm_memory memory=fine_memory(c);
    struct shadow shadow;struct user_table_owner owner;struct sptm_aperture aperture;struct sptm_moved moved;
    struct sptm_fine_kernel k=fine_kernel_of(c,&memory,&shadow,&owner,&aperture,&moved,
                                             (uint32_t)((p->tcr>>16)&0x3f));
    volatile uint64_t *out=scratch ? (volatile uint64_t *)scratch : 0;
    enum sptm_fine_kernel_end e=sptm_fine_kernel_map(&k,root,va,new_pte,out);
    if(e==SPTM_FINE_K_COPIED) {s->reason=FINE_NO_COPIED;return FINE_DECLINE;}
    if(e==SPTM_FINE_K_DECLINE) {s->reason=fine_cpu(c)->alloc_refused ? FINE_NO_ALLOC : FINE_NO_ENGINE;return FINE_DECLINE;}
    if(e==SPTM_FINE_K_FATAL) {
        /* map_page_failed's record, made under the token by fine_fatal. */
        s->fail_kind=EV_MAP_FAILED;s->result=(enum sptm_result)k.fail;s->fail_a=k.fail_va;s->fail_b=k.fail_detail;
        return FINE_FATAL;
    }
    if(out)fine_cpu(c)->audit.moved_pointers+=(uint64_t)k.moved_pointer;
    s->aux_note=1;s->aux_va=va;s->aux_old=k.old;s->aux_new=new_pte;
    fine_add(&c->map_pages,1);
    frame[0]=k.status;return FINE_DONE;
}
static int fine_kernel_unmap(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    const struct params *p=c->params;
    if(((p->tcr>>16)&63)!=17) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    struct sptm_memory memory=fine_memory(c);
    struct shadow shadow;struct user_table_owner owner;struct sptm_aperture aperture;struct sptm_moved moved;
    struct sptm_fine_kernel k=fine_kernel_of(c,&memory,&shadow,&owner,&aperture,&moved,17);
    enum sptm_result r=SPTM_OK;
    enum sptm_fine_kernel_end e=sptm_fine_kernel_unmap(&k,frame[0],frame[1],frame[2],frame[3],scratch,&r);
    if(e==SPTM_FINE_K_COPIED) {s->reason=FINE_NO_COPIED;return FINE_DECLINE;}
    if(e==SPTM_FINE_K_DECLINE) {
        if(r)return fine_engine_end(c,s,r,EV_UNMAP_FAILED,frame[1],frame[2]);
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
#define FINE_KERNEL_CALL(kind) ((kind)==FINE_CALL_KERNEL_MAP || (kind)==FINE_CALL_KERNEL_UNMAP)
#endif
#if SNAP_FINE_SWITCH
/* ---- SNAP_FINE_SWITCH: SWITCH_ROOT cache hits (phase 1b) ----------------
 * The case SPTM_FN_SWITCH_ROOT body and user_root_install's NATIVE_TABLES
 * branch for a switch that changes no cache state (compat/sptm-root.h
 * sptm_mac_switch_root_hit). The stripes of this CPU's current root and of
 * the target are held, so no converted call on either root runs while their
 * activity, records and (for the target) view selection change, and every
 * other CPU's activity words are its own. Declined before any change: a
 * PPERM that is not the reset value (the install's kernel PPERM transaction
 * rewrites kernel copies, token-path state), a target whose variants do not
 * exist yet (the first install derives them: allocation), a sampled tree walk
 * (the memo is token-path state), and every case sptm_mac_switch_root_hit
 * declines. */
/* The owner's sampled walk, read without counting: the token path's
 * native_skip_hit counts and walks this switch if it is due. A converted
 * hit counts its skip afterwards. */
static int fine_skip_hit(void *ctx)
{
    struct context *c=ctx;
    return !!(__atomic_load_n(&c->native_stats.hit_asks,__ATOMIC_RELAXED)&
              ((UINT64_C(1)<<SNAP_NATIVE_AUDIT_SHIFT)-1));
}
static int fine_no_build(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned format,
                         unsigned flags,uint64_t previous,uint64_t *result,uint64_t *leaves)
{(void)ctx;(void)m;(void)root;(void)format;(void)flags;(void)previous;(void)result;(void)leaves;return 0;}
static void fine_install_failed(struct context *c,int deferred)
{
    fine_add(&c->root_install_failures,1);
    if(deferred) {
        fine_add(&c->install_tlbi.failure_flushes,1);
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        fine_add(&c->shadow_tlb_syncs,1);
    }
}
/* user_install_view once the variants exist: this CPU's selection, its view
 * state and the slot's budget (the target's stripe is held). */
static uint64_t fine_user_install_view(struct context *c,uint64_t root,uint64_t canonical)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,root);
    if(!e || e->shadow!=canonical)return 0;
    unsigned slot=(unsigned)(e-c->user_roots.cache);
    struct sprr_views *v=user_views(c,e);
    if(!v->count)return 0;
    UBUDGETS(c)[slot]=0;
    struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
    struct native_cpu *n=&c->native_cpu[cpu];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)
        ttbr0[w][k]=native_views_root(v,w)|(native_asid(slot,w,0)<<48);
    if(!native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0)) {
        fine_view_failed(c);return 0;
    }
    fine_add(&c->native_stats.installs,1);
    struct user_view_state *u=&c->user_view_state[cpu];
    u->root=root;u->shadow=native_views_root(v,n->w);u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    return u->shadow;
}
/* root_publish_flush for a converted install, under aux: every dirty page
 * this CPU's walkers can reach after the switch -- the target slot's
 * canonical and variant pages (owner slot+1), the shared groups it links and
 * every monitor and kernel page (owner 0, which includes the kernel root's
 * low shadow) -- is cleaned and its bit cleared; other roots' bits stay for
 * the next token-path flush (their converted writers clean at the store, so
 * those bits are already clean). Aux orders this against other converted
 * installs, and the dsb completes the cleaning before aux is released. The
 * 97 runtime pages are not cleaned: no walker reads them, no converted call
 * writes them, secondary_launch publishes the whole work area before CPU_ON,
 * and every token-path transaction and install still cleans them. */
static int fine_install_publish(struct context *c,unsigned owner)
{
    struct root_publish_state *s=&c->root_publish;
    fine_aux_lock(c);
    int ok=!__atomic_load_n(&s->errors,__ATOMIC_RELAXED) &&
           root_publish_geometry(c->work_base,c->next_table);
    unsigned pages=ok ? (unsigned)((c->next_table-c->work_base)/4096) : 0,dirty=0;
    for(unsigned w=0;w<(pages+63)/64;w++) {
        uint64_t bits=__atomic_load_n(&s->bitmap[w],__ATOMIC_RELAXED),mine=0;
        while(bits) {
            unsigned bit=(unsigned)__builtin_ctzll(bits),index=w*64+bit;
            unsigned who=c->table_pool.owner[index];
            bits&=bits-1;
            if(who && who!=owner && who!=NATIVE_SHARED_OWNER)continue;
            publish_page_lines(c,c->work_base+(uint64_t)index*4096);
            mine|=UINT64_C(1)<<bit;dirty++;
        }
        if(mine)__atomic_fetch_and(&s->bitmap[w],~mine,__ATOMIC_RELAXED);
    }
    __asm__ volatile("dsb ish" ::: "memory");
    if(ok) {s->calls++;s->complete++;s->considered+=pages;s->published+=dirty;s->skipped+=pages-dirty;}
    fine_aux_unlock(c);
    return ok;
}
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
/* ---- SNAP_FINE_SWITCH_HW: SWITCH_ROOT to a hardware-walk root with a record
 * (batch8 switch FAILURES-AND-DESIGN.md S1-S14). The record, its index slot,
 * copies' addresses and identity are token-path state (attach, detach, path
 * preparation, prune): constants while the gate is shared. */
/* hw_switch_eligible without the attach: a record answers 1 or -1 exactly
 * as there; no record answers 0, the cache-hit test then declines a root
 * with no cache entry, and the token path attaches it (S3, S4). */
static int fine_hw_switch_eligible(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned asid,
                                   unsigned format,unsigned flags)
{
    struct context *c=ctx;(void)m;
    if(format!=1)return 0;
    struct hw_walk_root *r=hw_root(c,root);
    if(r)return r->entry.asid==asid && r->entry.flags==flags ? 1 : -1;
    return 0;     /* no record: the token path attaches (or keeps the shadow) */
}
/* hw_install_user for a converted switch: the same native selection, view
 * state, register sequence, shared-region flush and installed-state records
 * (this CPU's words), shared counters added atomically (S6), guest_ttbr0
 * stored with release like fine_user_root_install's, and the converted
 * publication in place of root_publish_flush: every dirty page of owner 0,
 * of the native shared groups and of the copy domain this CPU's TTBR0 can
 * now reach, under aux (S7). */
static void fine_hw_install_user(struct context *c,uint64_t root,uint64_t asid,unsigned format)
{
    struct vcpu *v=vcpu_of(c);
    struct hw_walk_root *r=hw_root(c,root);
    if(!r || format!=1 || r->entry.asid!=asid) {fine_add(&c->root_install_failures,1);return;}
    unsigned flags=(unsigned)r->entry.flags;
    struct sprr_state initial={0};sprr_root_reset(&initial,flags);
    struct native_cpu *n=&c->native_cpu[v->slot];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)ttbr0[w][k]=hw_walk_ttbr0(r,w);
    uint64_t ttbr=native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0);
    if(!ttbr) {fine_view_failed(c);fine_add(&c->root_install_failures,1);return;}
    fine_add(&c->native_stats.installs,1);fine_add(&c->hw_walk->stats.installs,1);
    struct user_view_state *u=&c->user_view_state[v->slot];
    u->root=root;u->shadow=ttbr&PT_OA_MASK;u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    v->guest_tcr=SPTM_ROOT_TCR_4K|(1UL<<36);
    v->guest_sctlr=pauth_root_enables(v->guest_sctlr,flags);
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    if(!fine_install_publish(c,HW_WALK_OWNER)) {
        fine_install_failed(c,0);return;
    }
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    struct sptm_memory memory=sptm_context_memory(c);
    int region=sptm_mac_root_shared_slot(&memory,root);
    if(live_tcr==tcr) {
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
        uint16_t last=c->user_shared_slot[v->slot];
        int shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            fine_add(&c->native_stats.local_flushes,1);
            if(shared_flush)fine_add(&c->shared_switch_flushes[v->slot],1);
            c->user_shared_slot[v->slot]=0;
        }
    } else
        __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                         "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                         :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)fine_add(&c->root_install_failures,1);
    __atomic_store_n(&v->guest_ttbr0,root|(asid<<48),__ATOMIC_RELEASE);
    fine_add(&c->shadow_tlb_syncs,1);
}
#endif
/* user_root_install, NATIVE_TABLES branch, PPERM already the reset value. */
static void fine_user_root_install(void *ctx,uint64_t shadow,uint64_t guest_root,
                                   uint64_t asid,unsigned format)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
#if SNAP_EL0_MEMO
    /* Before anything changes: this vCPU's EL0 fetch memo is stale. */
    el0_memo_installed(&EL0M(c)[v->slot]);
#endif
    const int defer=SNAP_INSTALL_TLBI_DEFER;int deferred=0;
    if(defer)fine_add(&c->install_tlbi.installs,1);
    fine_add(&c->native_stats.pperm_skips,1);
    deferred=defer;
    unsigned owner=0;
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* As user_root_install: a hardware-walk root comes with shadow 0, after
     * the same EL0-memo, TLBI-defer and PPERM-skip accounting. */
    if(asid && !shadow) {fine_hw_install_user(c,guest_root,asid,format);return;}
#endif
    if(asid) {
        shadow=fine_user_install_view(c,guest_root,shadow);
        if(!shadow) {fine_install_failed(c,deferred);return;}
    } else {
        struct user_view_state *u=&c->user_view_state[v->slot];
        u->root=u->shadow=u->el0=u->uperm=u->pperm=u->umprr=0;
        native_uninstall(&c->native_cpu[v->slot]);
    }
    if(asid) {
        v->guest_tcr=(format ? SPTM_ROOT_TCR_4K : SPTM_ROOT_TCR_16K)|(1UL<<36);
        struct sptm_root_cached *entry=user_cached(c,guest_root);
        if(!entry) {fine_install_failed(c,deferred);return;}
        owner=(unsigned)(entry-c->user_roots.cache)+1;
        USTAMPS(c)[entry-c->user_roots.cache]=__atomic_add_fetch(&c->arena_reclaim.clock,1,__ATOMIC_RELAXED);
        v->guest_sctlr=pauth_root_enables(v->guest_sctlr,(unsigned)entry->flags);
    }
    const struct native_cpu *nc=&c->native_cpu[v->slot];
    uint64_t ttbr=asid ? nc->ttbr0[nc->w&1][nc->k&1] : shadow;
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    if(asid && (ttbr&PT_OA_MASK)!=shadow) {fine_install_failed(c,deferred);return;}
    if(!fine_install_publish(c,owner)) {fine_install_failed(c,deferred);return;}
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    if(live_tcr==tcr) {
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        int shared_flush=0;
        if(asid) {
            struct sptm_memory memory=sptm_context_memory(c);
            int region=sptm_mac_root_shared_slot(&memory,guest_root);
            uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
            uint16_t last=c->user_shared_slot[v->slot];
            shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        }
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            fine_add(&c->native_stats.local_flushes,1);
            if(shared_flush)c->shared_switch_flushes[v->slot]++;
            c->user_shared_slot[v->slot]=0;
        }
    } else
    __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                     "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                     :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1"
                     :"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    if(asid) {
        struct sptm_memory memory=sptm_context_memory(c);
        int region=sptm_mac_root_shared_slot(&memory,guest_root);
        c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    }
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)fine_add(&c->root_install_failures,1);
    __atomic_store_n(&v->guest_ttbr0,guest_root|(asid<<48),__ATOMIC_RELEASE);
    fine_add(&c->shadow_tlb_syncs,1);
}
/* case SPTM_FN_SWITCH_ROOT for a converted hit or kernel switch. */
static int fine_switch_root(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    struct vcpu *v=vcpu_of(c);
    uint64_t root=frame[0];
    int kernel=root==c->params->ttbr1_root;
    if(frame[1] || frame[2]) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    if(c->user_roots.sprr[v->slot].pperm!=SPRR_PPERM_INITIAL) {s->reason=FINE_NO_SWITCH;return FINE_DECLINE;}
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* SNAP_FINE_SWITCH_HW: a target with a hardware-walk record has no cache
     * entry and no views (its install selects among the record's TTBR0
     * values); the record cannot change while the gate is shared. */
    int hw=!kernel && hw_root(c,root)!=0;
    if(!kernel && !hw) {
#else
    if(!kernel) {
#endif
        struct sptm_root_cached *e=user_cached(c,root);
        if(!e || !UVIEWS(c)[e-c->user_roots.cache].count) {s->reason=FINE_NO_SWITCH;return FINE_DECLINE;}
    }
    struct sptm_memory memory=fine_memory(c);
    /* No validation, memo, eviction or stamps: a converted switch never
     * walks, builds or evicts (sptm_mac_switch_root_hit declines those). */
    struct sptm_root_backend backend={.kernel_root=c->params->ttbr1_root,
        .kernel_shadow=v->low_root,.build=fine_no_build,
        .install=fine_user_root_install,.ctx=c,.skip_hit_validation=fine_skip_hit};
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* The token path's hook without its attach (S3). */
    backend.hw_eligible=fine_hw_switch_eligible;
#endif
    if(!sptm_mac_switch_root_hit(&memory,&c->user_roots,&backend,(unsigned)v->slot,
                                 root,frame[1],frame[2])) {
        s->reason=FINE_NO_SWITCH;return FINE_DECLINE;
    }
    s->fail_kind=EV_REFERENCE_FAILED;s->fail_a=s->a0;s->fail_b=s->a1;
    if(__atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED)) {s->result=SPTM_OK;return FINE_FATAL;}
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* As the token path's case with SNAP_USER_HW_WALK (S9): a hardware-walk
     * root's identity is its record's entry; without a record this is
     * sptm_root_note_loaded. */
    if(!hw_walk_note_loaded(&c->user_roots,c->hw_walk,c->root_loaded,(unsigned)v->slot)) {
#else
    if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,(unsigned)v->slot)) {
#endif
        s->result=SPTM_BAD_CONFIG;return FINE_FATAL;
    }
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* The token path asks skip_hit_validation for cached roots only (S8). */
    if(!kernel && !hw) {fine_add(&c->native_stats.hit_asks,1);fine_add(&c->native_stats.hit_skips,1);}
#else
    if(!kernel) {fine_add(&c->native_stats.hit_asks,1);fine_add(&c->native_stats.hit_skips,1);}
#endif
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
#endif
#if SNAP_FAST_PAUTH_CALLS
/* ---- SNAP_FAST_PAUTH_CALLS: the user pointer-authentication calls -------
 * SIGN_USER_POINTER and AUTH_USER_POINTER (FINE_CALL_PAUTH) and
 * BATCH_SIGN_USER_POINTER (FINE_CALL_PAUTH_BATCH) with the gate shared and no
 * stripe: they name no root. Each runs monitor_call_impl's body for the
 * endpoint (user_pointer_call, user_pointer_batch), so the answer is the
 * locked path's. Besides this CPU's own state the helpers read only words no
 * one writes while the gate is shared: the boot-fixed pauth_domain and
 * aes_hardware, the frame-map geometry, and a batch input frame's type and
 * lock bytes (written only by RETYPE, under the token). The input records
 * themselves are guest memory, as unordered against the other CPUs' EL1 as
 * under the token. The native helpers change this PE's TCR/SCTLR_EL2 and one
 * key pair with DAIF masked and a local TLBI: another CPU signing at once
 * uses its own PE. A refused configuration (TCR, an entered bank, a failed
 * derivation: none changes anything) declines; the locked path repeats it and
 * stops. A failure once the helper ran (key class, AUTH of an upper address,
 * a native failure, a batch's shape, address, type or lock) is terminal with
 * the locked path's record, made under the token (fine_fatal) without a
 * latched view failure: nothing shared was written. A batch publishes its
 * scratch output through fine_memory (fine_sptm_publish: the SWITCH_ROOT
 * memo's write witness under aux, then the clean). No reference batch, no
 * allocation: pv_audit and the arena are left alone (fine_state_admits keeps
 * the arena at its reserve, where arena_reserve only counts). */
static int fine_pauth_pointer(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    int ran=0;
    enum sptm_result r=user_pointer_call(c,frame,(uint32_t)s->x16,&ran);
    if(!ran) {s->reason=FINE_NO_ENGINE;return FINE_DECLINE;}
    if(r) {s->result=r;s->fail_kind=EV_TABLE_FAILED;s->fail_a=s->a0;s->fail_b=(uint32_t)s->x16;return FINE_FATAL;}
    frame[0]=c->pauth_pointer[vcpu_of(c)->slot].result;return FINE_DONE;
}
static int fine_pauth_batch(struct context *c,uint64_t *frame,const struct guest_cpu_buffer *scratch,
                            struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    int ran=0;
    enum sptm_result r=user_pointer_batch(c,&memory,frame,scratch,&ran);
    if(!ran) {s->reason=FINE_NO_ENGINE;return FINE_DECLINE;}
    if(r) {
        s->result=r;s->fail_kind=EV_TABLE_FAILED;s->fail_a=s->a0;
        s->fail_b=c->pauth_batch[vcpu_of(c)->slot].failed_index;return FINE_FATAL;
    }
    frame[0]=c->pauth_batch[vcpu_of(c)->slot].result_va;return FINE_DONE;
}
#define FINE_POINTER_CALL(kind) ((kind)==FINE_CALL_PAUTH || (kind)==FINE_CALL_PAUTH_BATCH)
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
/* ---- The Adreno DART's MAP and UNMAP as converted calls -------------------
 * SNAP_DART_CONVERTED (compat/dart-converted.h, batch 9: this block on its own,
 * re-checked against the phase-fair gate, the fine locks and SNAP_FINE_SWITCH_HW;
 * batch9/dart FAILURES-AND-DESIGN.md A1-A19) or SNAP_TOKEN_TRIM's part B
 * (compat/token-trim.h), never both; the numbers below are batch 5's. The
 * body of monitor_call_impl's table-3 branch for endpoints 2 and 3 on the
 * Adreno virtual DART, stream 0, with ADRENO_F_DART (the SMMU CB0 mirror
 * always runs then): device_dart_admit_frame, sptm_dart_map/unmap, the GPU
 * counters and adreno_mirror. The gate is shared and no stripe is held (the
 * call names no root); the device lock serializes these calls among
 * themselves, and every other writer of what they touch holds the token:
 *  - the DART tables, their frame records' refs and the model's dart_state
 *    (MAP_TABLE, enable, the HVC kext's own unmap, DART MMIO, RETYPE) (9);
 *  - the DART memo (every token-path SPTM publish) (12);
 *  - c->gpu and the SMMU tables (the GPU tick, MMIO, SMC, HVC, quiesce;
 *    vCPU 0's lock-free tick reads only status, quiesce and run_at) (14).
 * Data-frame counts change by atomic delta through this CPU's fine
 * reference batch, beside converted user calls on the same frames (8);
 * frame types are read as constants (RETYPE is exclusive) (11). Both
 * engines are fallible only before their first store, so a refusal declines
 * (17); the reader bit is held until the mirror's SMMU TLBI has completed, so
 * no RETYPE can free a frame whose DART reference an UNMAP dropped while the
 * GPU can still reach it (10). A mirror failure is terminal with the token
 * path's EV_GPU_SMMU record and no latched view failure (19). */
#define FINE_X16_DART_MAP UINT64_C(0x0000000300000002)    /* domain 0, table 3, endpoint 2 */
#define FINE_X16_DART_UNMAP UINT64_C(0x0000000300000003)  /* endpoint 3 */
#define FINE_DART_CALL(kind) ((kind)==FINE_CALL_DART_MAP || (kind)==FINE_CALL_DART_UNMAP)
/* The device lock and this CPU's device-lock wait: batch 5's, or batch 9's.
 * FINE_DART_COUNT keeps batch 5's TOKTRIM1 counters under SNAP_TOKEN_TRIM only:
 * SNAP_DART_CONVERTED reports through the fine profile's DART buckets. */
#if SNAP_TOKEN_TRIM
#define FINE_DART_STATE_T struct token_trim_state
#define FINE_DART_STATE(c) (&(c)->root_ext->trim)
#define FINE_DART_COUNT(...) __VA_ARGS__
#else
#define FINE_DART_STATE_T struct dart_converted_state
#define FINE_DART_STATE(c) (&(c)->root_ext->dart_cv)
#define FINE_DART_COUNT(...)
#endif
/* sptm_publish for a DART call: the DART memo's write witness (the device
 * lock is held), then the SWITCH_ROOT memo's under aux and the clean (12, 13). */
static void fine_dart_publish(void *ctx,uint64_t pa,uint64_t size)
{
#if SNAP_DART_MEMO
    sptm_dart_memo_publish(&((struct context *)ctx)->root_ext->dart_memo,pa,size);
#endif
    fine_sptm_publish(ctx,pa,size);
}
static int fine_dart_call(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    const struct params *p=c->params;
    FINE_DART_STATE_T *t=FINE_DART_STATE(c);
    unsigned slot=(unsigned)vcpu_of(c)->slot,index=0;
    int unmap=s->kind==FINE_CALL_DART_UNMAP;
    t->device_wait[slot][0]=t->device_wait[slot][1]=0;
    /* The token path's admission, read-only; anything else is not this envelope. */
    if(frame[0]!=SPTM_DART_ADRENO || frame[1] || !(p->gpu.flags & ADRENO_F_DART) ||
       device_dart_admit_frame(p->models,c->model_state,(unsigned)p->model_count,5,
                               (unsigned)frame[0],(unsigned)frame[1],2,&index)!=DEVICE_OK) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    uint64_t start=service_profile_clock();
    if(fine_ticket_lock(&t->device)) {
        t->device_wait[slot][0]=service_profile_clock()-start;t->device_wait[slot][1]=1;
        FINE_DART_COUNT(t->stats.device_contended++;t->stats.device_wait+=t->device_wait[slot][0];)
    }
    FINE_DART_COUNT(t->stats.device_entries++;)
    struct sptm_memory memory=fine_memory(c);
    memory.publish=fine_dart_publish;
#if SNAP_DART_MEMO
    memory.dart_memo=&c->root_ext->dart_memo;
#endif
    struct dart_state *d=&c->model_state[index].dart;
    enum sptm_result r=unmap ?
        sptm_dart_unmap(&memory,d,frame[0],frame[1],frame[2],frame[3],frame[4]) :
        sptm_dart_map(&memory,d,frame[0],frame[1],frame[2],frame[3],frame[4],frame[5]);
    if(r) {
        FINE_DART_COUNT(if(!fine_cpu(c)->stores)t->stats.dart_declines++;)
        fine_ticket_unlock(&t->device);
        return fine_engine_end(c,s,r,EV_TABLE_FAILED,frame[2],frame[4]);
    }
    /* Stage 4: stream 0 of the Adreno virtual DART, into SMMU CB0; UNMAP
     * returns only after the SMMU TLB invalidation has completed. */
    struct gpu_leaf_ctx leaf={&memory,d};
    struct adreno_ops o=gpu_ops(c);
    /* Under the device lock; atomic like every context word a converted
     * call writes outside aux (adreno_mirror's own counters are the device
     * lock's: the token path is excluded by the gate). */
    fine_add(unmap ? &c->gpu.unmaps : &c->gpu.maps,1);
    int e=adreno_mirror(&o,&p->gpu,&c->gpu,frame[2],unmap ? frame[3] : frame[4],
                        gpu_leaf,&leaf,p->mem_low,p->mem_high);
    FINE_DART_COUNT(if(!e) {if(unmap)t->stats.dart_unmaps++;else t->stats.dart_maps++;})
    fine_ticket_unlock(&t->device);
    if(e) {
        s->fail_kind=EV_GPU_SMMU;s->fail_value=(uint64_t)(int64_t)e;s->fail_raw=1;
        s->fail_a=frame[2];s->fail_b=unmap ? 3 : 2;return FINE_FATAL;
    }
    frame[0]=0;return FINE_DONE;
}
#endif
#if SNAP_ANS_CONVERTED
/* ---- SNAP_ANS_CONVERTED: the virtual ANS2 off the token -------------------
 * agents/nvme-async/FAILURE-MODES.md N2, N3, N9, N10. Two converted calls under
 * one ANS device lock (FIFO, L1.5: after the gate, never with a stripe, KL or
 * the DART lock; before frame locks and aux):
 *  - FINE_CALL_ANS_SPTM, table-6 MAP_PAGES/UNMAP_PAGES (fine_sptm_call):
 *    compat/ans.c ans_sptm_converted, the references as one all-or-nothing
 *    batch on this CPU's fine memory (fine_ans_frame_refs), every token-path
 *    refusal a decline;
 *  - FINE_CALL_ANS_MMIO, the I/O SQ doorbell 0x24910 and CQ head 0x100c
 *    (fine_ans_mmio, a data abort): compat/ans.c ans_mmio, which with
 *    SNAP_ANS_ASYNC queues and polls but never waits for the SSD.
 * Every other writer of the ANS state (the mailbox, CC, the admin doorbell,
 * the other endpoints, SART, the ticks, the stop) holds the token, which
 * drains the gate. Both calls end with the ANS lines on the AIC model
 * (ans_async_lines): every other AIC writer holds the token and no lock-free
 * path writes it (N3). */
#define FINE_X16_ANS_MAP UINT64_C(0x0000000600000001)     /* domain 0, table 6, endpoint 1 MAP_PAGES */
#define FINE_X16_ANS_UNMAP UINT64_C(0x0000000600000002)   /* endpoint 2 UNMAP_PAGES */
#define FINE_ANS_CALL(kind) ((kind)==FINE_CALL_ANS_MMIO || (kind)==FINE_CALL_ANS_SPTM)
static void fine_ans_lock(struct context *c)
{
    uint64_t *w=c->root_ext->ans_wait[vcpu_of(c)->slot],start=service_profile_clock();
    w[0]=w[1]=0;
    if(fine_ticket_lock(&c->root_ext->ans_lock)) {w[0]=service_profile_clock()-start;w[1]=1;}
}
static void fine_ans_unlock(struct context *c) {fine_ticket_unlock(&c->root_ext->ans_lock);}
/* ans_frame_ref's references as one batch on this CPU's fine memory: every page
 * through sptm_refs_dart (its first touch takes the frame shared under
 * SNAP_SPTM_FINE_RETYPE), the DART data-leaf rule re-checked under that lock,
 * one validate, one atomic commit; anything else changes nothing (1). */
/* ans_dma_frame on a snapshot of the entry: bytes 0..7 (busy, type, metadata) are written only by the token path
 * and a converted RETYPE, which the gate and this frame's shared lock exclude; the +8/+12 counts change under
 * other converted calls' atomic deltas, so they are loaded atomically (tools/test-ans-converted.c, TSan). */
static int fine_ans_dma_frame(volatile uint8_t *e)
{
    uint8_t copy[16];
    for(unsigned i=0;i<8;i++)copy[i]=e[i];
    uint32_t ro=__atomic_load_n((volatile uint32_t *)(volatile void *)(e+8),__ATOMIC_RELAXED);
    uint32_t other=__atomic_load_n((volatile uint32_t *)(volatile void *)(e+12),__ATOMIC_RELAXED);
    for(unsigned i=0;i<4;i++) {copy[8+i]=(uint8_t)(ro>>(8*i));copy[12+i]=(uint8_t)(other>>(8*i));}
    return ans_dma_frame(copy);
}
static int fine_ans_frame_refs(void *ctx,const uint64_t *pa,unsigned n,int writable,int release)
{
    struct context *c=ctx;
    struct sptm_memory m=fine_memory(c);
    sptm_refs_begin(m.refs);
    for(unsigned i=0;i<n;i++) {
        uint64_t f=pa[i]&~0x3fffUL;
        if(!sptm_managed_frame(&m,f))return 1;
        if(release ? sptm_refs_dart_remove(&m,f,!writable) : sptm_refs_dart(&m,f,!writable))return 1;
        if(!release) {
            volatile uint8_t *e=m.map(m.ctx,m.frame_map_pa+((f-m.frame_low)>>14)*16,16);
            if(!e || !fine_ans_dma_frame(e))return 1;
        }
    }
    if(sptm_refs_validate(&m))return 1;
    sptm_refs_commit(&m);
    return 0;
}
/* The token path's single-reference callback never runs here (no converted
 * entry takes one): refuse, so a regression is a decline or a refusal, never a
 * plain global batch off the token. */
static int fine_ans_frame_ref(void *ctx,uint64_t pa,int writable,int release)
{
    (void)ctx;(void)pa;(void)writable;(void)release;return 1;
}
static struct ans_ops fine_ans_ops(struct context *c)
{
    struct ans_ops o=ans_ops_of(c);
    o.frame_ref=fine_ans_frame_ref;o.publish=fine_sptm_publish;o.frame_refs=fine_ans_frame_refs;
    return o;
}
static int fine_ans_sptm(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    struct ans_state *st=c->root_ext->ans;
    if(!st) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    fine_ans_lock(c);
    struct ans_ops o=fine_ans_ops(c);
    uint64_t ret=0;
    int r=ans_sptm_converted(st,&o,(unsigned)(s->x16&0xffff),frame,&ret);
    int decline=r==ANS_DECLINE || r==ANS_DECLINE_BUSY;
    if(!r || decline) {
        /* The progress it ran may have posted or started a command, declined or not. */
        ans_async_schedule(c);
        if(ans_async_lines(c)!=DEVICE_OK)r=ANS_E_STATE,decline=0;
    }
    fine_ans_unlock(c);
    if(decline) {s->reason=r==ANS_DECLINE_BUSY ? FINE_NO_BUSY : FINE_NO_ENGINE;return FINE_DECLINE;}
    if(r) {
        s->fail_kind=EV_ANS;s->fail_a=(uint64_t)r<<32|6u<<8|(s->x16&0xffff);s->fail_b=frame[0];
        return FINE_FATAL;
    }
    guest_interrupt_sync(c);
    timer_arm(c,service_profile_clock(),c->fast_timer_due[vcpu_of(c)->slot].guest);
    frame[0]=ret;return FINE_DONE;
}
/* monitor_request's report of the call_other EV_ANS refusal, under the token
 * after the gate was left (fine_fatal's order); no view failure is latched. */
static int fine_ans_fatal(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,
                          const struct fine_call_state *s)
{
    if(!runtime_enter(c,frame,*elr,(esr>>26)&63))return 1;
    record(c,EV_ANS,*elr,s->fail_a,s->fail_b,frame[1]);
    fill_regs(&vcpu_of(c)->async_regs,frame,0,*elr,0);
    vcpu_of(c)->async_captured=2;
    record(c,EV_MONITOR,*elr,frame[16],frame[0],frame[1]);
    step_arm(c,0);guards_close(c);
    return runtime_leave(c,1);
}
#endif
/* The roots a call names, into this CPU's lockset; 0 declines. Reads the
 * guest's record list once; the backend refuses any root the engine reads
 * later that is not in the set. */
static int fine_lockset_for(struct context *c,const struct fine_call_state *s,struct fine_lockset *set)
{
#if SNAP_ANS_CONVERTED
    /* An ANS call names no root: the empty set; fine_ans_sptm takes the ANS lock. */
    if(s->kind==FINE_CALL_ANS_SPTM) {fine_lockset_init(set);return 1;}
#endif
#if SNAP_FAST_PAUTH_CALLS
    /* A pointer call names no root (a0 is a pointer): the empty set. */
    if(FINE_POINTER_CALL(s->kind)) {fine_lockset_init(set);return 1;}
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    /* A DART call names no root either (a0 is the DART id): the empty set;
     * fine_dart_call takes the device lock. */
    if(FINE_DART_CALL(s->kind)) {fine_lockset_init(set);return 1;}
#endif
#if SNAP_SPTM_FINE
    /* SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md S16, S19): a record
     * list's roots (UPDATE_DISJOINT, UNMAP_DISJOINT) and UPDATE_REGION's root
     * must be admitted user roots, hardware-walk ones included (their update
     * and unmap events are converted); a kernel or shared root in a list keeps
     * the whole list on the token path (its mixed and shared engines). RETYPE
     * and the kernel-root calls name no user root: the empty set (the kernel
     * calls take KL in fine_sptm_call). */
    if(s->kind==FINE_CALL_UPDATE_DISJOINT || s->kind==FINE_CALL_UNMAP_DISJOINT) {
        fine_lockset_init(set);
        uint64_t count=s->kind==FINE_CALL_UNMAP_DISJOINT ? (uint32_t)s->a2 : s->a2,list=s->a1;
        if(!count || count>64 || (list&7) || list>UINT64_MAX-count*24)return 0;
        if(!sptm_map(c,list,count*24))return 0;
        for(uint64_t n=0;n<count;n++) {
            uint64_t root;
            if(mem_read(c,list+24*n,&root) || !fine_user_root(c,root) || !fine_lockset_add(set,root))
                return 0;
        }
        return 1;
    }
    if(s->kind==FINE_CALL_UPDATE_REGION) {
        fine_lockset_init(set);
        return fine_user_root(c,s->a0) && fine_lockset_add(set,s->a0);
    }
    if(s->kind==FINE_CALL_RETYPE || s->kind==FINE_CALL_KERNEL_MAP || s->kind==FINE_CALL_KERNEL_UNMAP) {
        fine_lockset_init(set);return 1;
    }
#endif
    fine_lockset_init(set);
#if SNAP_USER_HW_WALK
    /* A call naming a hardware-walk root declines (FINE_HW_ROOT); a switch
     * from one (the old root) stays converted. */
#if SNAP_FINE_SWITCH_HW
    /* SNAP_FINE_SWITCH_HW: nor does a switch to one. It takes the stripes of
     * this CPU's current root and of its target below, as a cache hit does;
     * fine_switch_root converts it only when the target's record exists
     * (fine_hw_switch_eligible never attaches). The decline below then
     * applies to every other kind exactly as before. */
    if(s->kind!=FINE_CALL_SWITCH_HIT)
#endif
#if SNAP_FINE_HW
    /* SNAP_FINE_HW converts MAP_PAGE and UNMAP_REGION on such a root
     * (fine_hw_backend); UPDATE_DISJOINT records and switch targets still
     * decline. */
    if(s->kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && s->kind!=FINE_CALL_MAP_PAGE &&
       s->kind!=FINE_CALL_UNMAP_REGION && FINE_HW_ROOT(c,s->a0))return 0;
#else
    if(s->kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && FINE_HW_ROOT(c,s->a0))return 0;
#endif
#endif
#if SNAP_FINE_SWITCH
    if(s->kind==FINE_CALL_SWITCH_HIT || s->kind==FINE_CALL_SWITCH_KERNEL) {
        /* This CPU's current root (its own word) and a user target. */
        uint64_t old=c->user_roots.active[vcpu_of(c)->slot];
        if(old && (!fine_user_root(c,old) || !fine_lockset_add(set,old)))return 0;
        return s->kind==FINE_CALL_SWITCH_KERNEL ||
               (fine_user_root(c,s->a0) && fine_lockset_add(set,s->a0));
    }
#endif
    if(s->kind==FINE_CALL_UPDATE_DISJOINT) {
        uint64_t count=s->a2,list=s->a1;
        if(!count || count>64 || (list&7) || list>UINT64_MAX-count*24)return 0;
        if(!sptm_map(c,list,count*24))return 0;
        for(uint64_t n=0;n<count;n++) {
            uint64_t root;
            if(mem_read(c,list+24*n,&root) || !fine_user_root(c,root) || !fine_lockset_add(set,root))
                return 0;
#if SNAP_USER_HW_WALK
            if(FINE_HW_ROOT(c,root))return 0;
#endif
        }
        return 1;
    }
    if(!fine_user_root(c,s->a0))return 0;
    return fine_lockset_add(set,s->a0);
}
/* What the locked path requires that this path does not repeat: no latched
 * failure or panic, no monitor step, guard, user-entry probe or pending
 * secondary launch, a ready native-call snapshot, and an arena at its
 * reserve (arena_reserve would otherwise reclaim, a token-path operation). */
static int fine_state_admits(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    return !fine_failed(c) && !c->panic_state.triggered &&
        !v->stepping.active && !v->open_guards && !c->user_execution[v->slot].pending &&
        !(!v->slot && fast_secondary_pending(c)) &&
        arena_available(c)>=SNAP_ARENA_RESERVE_PAGES;
}
/* The token-path report of a commit failure (monitor_call_impl's failure
 * record, monitor_request's capture and stop), under the token. */
static int fine_fatal(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,
                      const struct fine_call_state *s)
{
#if SNAP_ANS_CONVERTED
    if(s->kind==FINE_CALL_ANS_SPTM)return fine_ans_fatal(c,frame,esr,elr,s);
#endif
#if SNAP_FAST_PAUTH_CALLS
    /* A pointer call's failure wrote nothing shared: no latched view failure. */
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    /* Nor a DART call's: it writes no user view (its terminal failure is the
     * SMMU mirror's; its engines fail only before their first store). */
    if(!FINE_DART_CALL(s->kind))
#endif
    if(!FINE_POINTER_CALL(s->kind))
#endif
    fine_view_failed(c);
    if(!runtime_enter(c,frame,*elr,(esr>>26)&63))return 1;
#if SNAP_SPTM_FINE_KERNEL
    /* map_page_failed's counter, beside its record below (EV_MAP_FAILED: the
     * reason travels in result). */
    if(s->fail_kind==EV_MAP_FAILED)fine_add(&c->map_failures,1);
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    if(s->fail_raw)record(c,s->fail_kind,s->elr,s->fail_value,s->fail_a,s->fail_b);else
#endif
    record(c,s->fail_kind,s->elr,s->result,s->fail_a,s->fail_b);
    fill_regs(&vcpu_of(c)->async_regs,frame,0,*elr,0);
    vcpu_of(c)->async_captured=2;
    step_arm(c,0);guards_close(c);
    return runtime_leave(c,1);
}
/* xnuboot_trap's converted call. 0: declined, nothing changed (the locked
 * path takes the trap). 1: handled; *stop as xnuboot_trap would return. */
static int fine_sptm_call(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,int *stop)
{
    if((esr>>26)!=0x20)return 0;
    struct vcpu *v=vcpu_of(c);
    const struct params *p=c->params;
    uint64_t x16=frame[16];
    unsigned kind;
    switch(x16) {
    case SPTM_FN_UPDATE_DISJOINT: kind=FINE_CALL_UPDATE_DISJOINT;break;
#if SNAP_SPTM_FINE_KERNEL
    /* The kernel root's: KL instead of a stripe (compat/sptm-fine.h). */
    case SPTM_FN_MAP_PAGE:
        kind=frame[0]==p->ttbr1_root ? FINE_CALL_KERNEL_MAP : FINE_CALL_MAP_PAGE;break;
    case SPTM_FN_UNMAP_REGION:
        kind=frame[0]==p->ttbr1_root ? FINE_CALL_KERNEL_UNMAP : FINE_CALL_UNMAP_REGION;break;
#else
    case SPTM_FN_MAP_PAGE: kind=FINE_CALL_MAP_PAGE;break;
    case SPTM_FN_UNMAP_REGION: kind=FINE_CALL_UNMAP_REGION;break;
#endif
#if SNAP_SPTM_FINE
    case SPTM_FN_UNMAP_DISJOINT: kind=FINE_CALL_UNMAP_DISJOINT;break;
    case SPTM_FN_UPDATE_REGION: kind=FINE_CALL_UPDATE_REGION;break;
#endif
#if SNAP_SPTM_FINE_RETYPE
    case SPTM_FN_RETYPE: kind=FINE_CALL_RETYPE;break;
#endif
#if SNAP_FINE_SWITCH
    case SPTM_FN_SWITCH_ROOT:
        kind=frame[0]==p->ttbr1_root ? FINE_CALL_SWITCH_KERNEL : FINE_CALL_SWITCH_HIT;break;
#endif
#if SNAP_FAST_PAUTH_CALLS
    case SPTM_FN_SIGN_USER_POINTER: case SPTM_FN_AUTH_USER_POINTER: kind=FINE_CALL_PAUTH;break;
    case SPTM_FN_BATCH_SIGN_USER_POINTER: kind=FINE_CALL_PAUTH_BATCH;break;
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    case FINE_X16_DART_MAP: kind=FINE_CALL_DART_MAP;break;
    case FINE_X16_DART_UNMAP: kind=FINE_CALL_DART_UNMAP;break;
#endif
#if SNAP_ANS_CONVERTED
    case FINE_X16_ANS_MAP: case FINE_X16_ANS_UNMAP: kind=FINE_CALL_ANS_SPTM;break;
#endif
    default: return 0;
    }
    /* The locked path's classification of a native call (xnuboot_trap_locked,
     * EC 0x20 from EL1), read-only: a guarded vector-page fetch whose EL1
     * syndrome is the call stub's undefined instruction. */
    uint64_t hpfar,far,spsr,iss=esr&0x1ffffff;
    __asm__ volatile("mrs %0, hpfar_el2; mrs %1, far_el2; mrs %2, spsr_el2"
                     :"=r"(hpfar),"=r"(far),"=r"(spsr));
    if(!p->vbar || ((iss>>7)&1) || exception_vector_step(esr,*elr,p->vbar_va))return 0;
    uint64_t ipa=guest_pa(far);
    if(!ipa && (hpfar&0x0000fffffffffff0UL))ipa=((hpfar>>4)<<12)|(far&0xfff);
    struct guard *g=guard_find(c,ipa);
    if(!g || g->mode==GUARD_DATA || (ipa&~0xfffUL)!=p->vbar)return 0;
    uint64_t g_esr,g_elr,saved;
    __asm__ volatile("mrs %0, esr_el1; mrs %1, elr_el1; mrs %2, spsr_el1"
                     :"=r"(g_esr),"=r"(g_elr),"=r"(saved));
    uint64_t vector=*elr-p->vbar_va;
    if(g_esr!=(1UL<<25) || ((saved&31)!=8 && (saved&31)!=9) || (g_elr&3) ||
       g_elr<UINT64_C(0xffff800000000000))return 0;
    uint64_t gpa=guest_pa(g_elr),physical=0;
    int call_page=0;
    for(unsigned n=0;n<NATIVE_CALL_PAGES;n++)call_page|=(gpa&~0xfffUL)==p->stub_pa[n];
    uint32_t word=call_page ? *(const uint32_t *)gpa : 0;
    struct native_call_state *ns=&c->native_calls[v->slot];
    if(!native_call_word(word) || ns->ready!=1 ||
       !native_call_return(vector,g_esr,saved,spsr,g_elr,word,&physical))return 0;
    struct guest_cpu_buffer cpu_scratch;
    if(guest_cpu_buffer(&c->cpus,v->slot,p->scratch_pa,p->scratch_va,p->mem_low,
                        p->mem_high,&cpu_scratch)!=CPU_OK)return 0;
    struct fine_cpu *f=fine_cpu(c);
    struct fine_call_state s={.x16=x16,.a0=frame[0],.a1=frame[1],.a2=frame[2],.a3=frame[3],
                              .elr=g_elr,.kind=kind,.reason=FINE_NO_STATE};
    /* L0: the gate, shared. A token holder makes this CPU wait like a token
     * waiter (bounded: a long wait declines and the locked path waits, with
     * its deadline and stop handling). */
    uint64_t t0=service_profile_clock(),t1,t2;
    enum guest_service_result gate;
#if SNAP_GATE_WAIT
#define GATE_WAIT_BUILT 1
    /* compat/token-costs.h: wait out a long token hold, up to 1/200 s and
     * never past this CPU's probe budget, before declining; the locked
     * path's own wait has the one-second deadline and stop handling. */
#if SNAP_PHASE_FAIR_GATE
    /* compat/service-lock.h: a BUSY arrival is announced in the present
     * writer's bank and enters when that writer's phase ends (the next
     * writer waits for it); at the bound it is withdrawn before declining,
     * or this CPU's own token drain would wait for it. */
    unsigned ahead=0;
#endif
    for(int waited=0;;waited=1) {
#if SNAP_PHASE_FAIR_GATE
        gate=waited ? guest_service_wait_shared(&c->services,v->slot,&ahead) :
                      guest_service_enter_shared(&c->services,v->slot);
#else
        gate=guest_service_enter_shared(&c->services,v->slot);
#endif
        uint64_t now=service_profile_clock();
        if(gate!=SERVICE_BUSY) {
            if(waited && gate==SERVICE_OK) {
                fine_add(&c->root_ext->gate[0],1);fine_add(&c->root_ext->gate[1],now-t0);
#if SNAP_PHASE_FAIR_GATE
                if(ahead)fine_add(&c->root_ext->gate[4],1);   /* entered ahead of a queued writer */
#endif
            }
            if(gate==SERVICE_STOPPED)fine_add(&c->root_ext->gate[3],1);
            break;
        }
        if((int64_t)(now-t0-c->params->clock_host_hz/200)>=0 ||
           (v->watchdog_live && (int64_t)(now-v->watchdog_deadline)>=0)) {
#if SNAP_PHASE_FAIR_GATE
            guest_service_leave_shared(&c->services,v->slot);   /* withdraw the arrival */
#endif
            fine_add(&c->root_ext->gate[2],1);break;
        }
        __asm__ volatile("yield");
    }
#else
    for(unsigned spins=0;;spins++) {
        gate=guest_service_enter_shared(&c->services,v->slot);
        if(gate!=SERVICE_BUSY || spins>=(1u<<16))break;
        __asm__ volatile("yield");
    }
#endif
    if(gate!=SERVICE_OK) {f->profile.declined[FINE_NO_GATE]++;return 0;}
    t1=service_profile_clock();
    int result=FINE_DECLINE;
    int admitted=fine_state_admits(c);
    if(admitted)s.reason=FINE_NO_ROOT;
#if SNAP_SPTM_FINE_RETYPE
    /* This call's frame locks (compat/sptm-frame-lock.h), empty until here and
     * released at the one point below, after the call's last TLBI (S5, S25):
     * its reference first touches through ref_fine.held, its input frames now. */
    f->frames.locks=&fine_of(c)->frame_locks;f->frames.count=0;f->frames.exclusive=0;
    f->ref_fine.held=&f->frames;
    if(admitted && !fine_input_frames(c,&s)) {admitted=0;s.reason=FINE_NO_FRAME;}
#endif
    if(admitted && fine_lockset_for(c,&s,&f->locks)) {
        unsigned waited=fine_lockset_acquire(fine_of(c)->stripes,&f->locks);
#if SNAP_SPTM_FINE_KERNEL
        /* KL after the (empty) stripe set: a kernel call holds no stripe. Its
         * wait is charged as stripe wait. */
        int kernel=FINE_KERNEL_CALL(kind);
        if(kernel)waited+=(unsigned)fine_ticket_lock(&fine_of(c)->kernel);
#endif
        t2=service_profile_clock();
        f->stores=0;f->alloc_refused=0;f->aux_wait=0;f->audit=(struct sptm_pv_audit){0};
        s.reason=FINE_NO_SHAPE;
        result=kind==FINE_CALL_MAP_PAGE ? fine_map_page(c,frame,cpu_scratch.pa,&s) :
               kind==FINE_CALL_UNMAP_REGION ? fine_unmap_region(c,frame,cpu_scratch.pa,&s) :
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
               FINE_DART_CALL(kind) ? fine_dart_call(c,frame,&s) :
#endif
#if SNAP_ANS_CONVERTED
               kind==FINE_CALL_ANS_SPTM ? fine_ans_sptm(c,frame,&s) :
#endif
#if SNAP_FAST_PAUTH_CALLS
               kind==FINE_CALL_PAUTH ? fine_pauth_pointer(c,frame,&s) :
               kind==FINE_CALL_PAUTH_BATCH ? fine_pauth_batch(c,frame,&cpu_scratch,&s) :
#endif
#if SNAP_SPTM_FINE
               kind==FINE_CALL_UNMAP_DISJOINT ? fine_unmap_disjoint(c,frame,cpu_scratch.pa,&s) :
               kind==FINE_CALL_UPDATE_REGION ? fine_update_region(c,frame,cpu_scratch.pa,&s) :
#endif
#if SNAP_SPTM_FINE_RETYPE
               kind==FINE_CALL_RETYPE ? fine_retype(c,frame,&s) :
#endif
#if SNAP_SPTM_FINE_KERNEL
               kind==FINE_CALL_KERNEL_MAP ? fine_kernel_map(c,frame,cpu_scratch.pa,&s) :
               kind==FINE_CALL_KERNEL_UNMAP ? fine_kernel_unmap(c,frame,cpu_scratch.pa,&s) :
#endif
#if SNAP_FINE_SWITCH
               kind!=FINE_CALL_UPDATE_DISJOINT ? fine_switch_root(c,frame,&s) :
#endif
               fine_update_disjoint(c,frame,cpu_scratch.pa,&s);
        if(result!=FINE_DECLINE) {
            /* The call entry's effects (xnuboot_trap_locked before
             * monitor_request), now that the call is no longer declined. */
            ns->calls++;ns->last_pc=g_elr;ns->last_word=word;ns->last_saved=saved;
            ns->last_physical=physical;
            native_exception_restore(ns);
            __asm__ volatile("msr spsr_el2, %0" :: "r"(physical) : "memory");
            *elr=g_elr;
        }
        if(result==FINE_DONE) {
            /* monitor_call_impl's prologue (endpoint count, audit share,
             * arena check, EV_MONITOR), the case's own record and its
             * epilogue (calls), in the locked path's order. */
            fine_aux_lock(c);
#if SNAP_ANS_CONVERTED
            /* A table-6 call is counted as other, as monitor_call_impl does. */
            if(kind==FINE_CALL_ANS_SPTM)c->endpoint_other++;else
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
            /* A table-3 call is counted as other, as monitor_call_impl does (18). */
            if(FINE_DART_CALL(kind))c->endpoint_other++;else
#endif
            c->endpoint_calls[x16 & (ENDPOINT_BUCKETS - 1)]++;
            struct arena_reclaim_stats *a=&c->arena_reclaim;
            uint64_t available=arena_available(c);
            if(!a->checks || available<a->low_water)a->low_water=available;
            a->checks++;
#if SNAP_ANS_CONVERTED
            /* call_other records no table-6 MAP/UNMAP_PAGES (one each per SSD command). */
            if(kind!=FINE_CALL_ANS_SPTM)
#endif
            record(c,EV_MONITOR,g_elr,x16,s.a0,s.a1);
            if(kind==FINE_CALL_UNMAP_REGION)record(c,EV_UNMAP_REGION,g_elr,s.a1,s.a2,s.a3);
#if SNAP_SPTM_FINE_RETYPE
            if(kind==FINE_CALL_RETYPE)record(c,EV_RETYPE,g_elr,s.a0,(s.a1<<32)|(s.a2&0xffffffffUL),s.a3);
#endif
#if SNAP_SPTM_FINE_KERNEL
            if(kind==FINE_CALL_KERNEL_UNMAP)record(c,EV_UNMAP_REGION,g_elr,s.a1,s.a2,s.a3);
            if(s.aux_note)auxkc_note_leaf(c,AUXKC_KIND_MAP,g_elr,s.aux_va,s.aux_old,s.aux_new);
#endif
            struct sptm_pv_audit *pv=&c->pv_audit,*mine=&f->audit;
#if SNAP_FAST_PAUTH_CALLS
            /* A pointer call has no reference batch: the pending share stays
             * for the next reference call, which clears it at its own entry;
             * its audit share is zero and merges as nothing. */
            if(!FINE_POINTER_CALL(kind))
#endif
            pv->pending=0;
            pv->moved_pointers+=mine->moved_pointers;
            if(mine->remaps) {pv->remaps+=mine->remaps;pv->remap_va=mine->remap_va;
                pv->remap_old=mine->remap_old;pv->remap_next=mine->remap_next;}
            if(mine->duplicate_records) {pv->duplicate_records+=mine->duplicate_records;
                pv->duplicate_root=mine->duplicate_root;pv->duplicate_va=mine->duplicate_va;}
            c->calls++;
            fine_aux_unlock(c);
        }
#if SNAP_SPTM_FINE_RETYPE
        sptm_frame_release(&f->frames);
#endif
#if SNAP_SPTM_FINE_KERNEL
        if(kernel)fine_ticket_unlock(&fine_of(c)->kernel);
#endif
        fine_lockset_release(fine_of(c)->stripes,&f->locks);
        uint64_t t3=service_profile_clock();
        guest_service_leave_shared(&c->services,v->slot);
        if(result!=FINE_DECLINE) {
            struct fine_bucket *b=&f->profile.call[kind];
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
            /* A DART call's device-lock wait is its stripe wait. */
            const uint64_t *dev=FINE_DART_STATE(c)->device_wait[v->slot];
            if(FINE_DART_CALL(kind)) {
                b->entries++;b->gate_wait+=t1-t0;b->stripe_wait+=t2-t1+dev[0];b->aux_wait+=f->aux_wait;
                b->hold+=t3-t2-f->aux_wait-dev[0];b->contended+=waited!=0 || dev[1];
            } else {
#endif
            b->entries++;b->gate_wait+=t1-t0;b->stripe_wait+=t2-t1;b->aux_wait+=f->aux_wait;
            b->hold+=t3-t2-f->aux_wait;b->contended+=waited!=0;
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
            }
#endif
#if SNAP_ANS_CONVERTED
            /* An ANS call's lock wait is its stripe wait, as a DART call's device wait. */
            if(kind==FINE_CALL_ANS_SPTM) {
                const uint64_t *aw=c->root_ext->ans_wait[v->slot];
                b->stripe_wait+=aw[0];b->hold-=aw[0];b->contended+=!waited && aw[1];
            }
#endif
        }
    }
#if SNAP_SPTM_FINE_RETYPE
    else {sptm_frame_release(&f->frames);guest_service_leave_shared(&c->services,v->slot);}
#else
    else guest_service_leave_shared(&c->services,v->slot);
#endif
    if(result==FINE_DECLINE) {f->profile.declined[s.reason]++;return 0;}
    if(result==FINE_FATAL) {
        f->profile.failures++;
        *stop=fine_fatal(c,frame,esr,elr,&s);
        if(*stop && !v->async_captured) {fill_regs(&v->async_regs,frame,esr,*elr,0);v->async_captured=1;}
        return 1;
    }
    /* monitor_request's step_translation_clear (runtime_enter's for this
     * category too), *elr over the call, runtime_leave's stop decision. */
    step_translation_clear(&c->step_translation[v->slot]);
    *elr+=4;
    int stopping=fine_failed(c)!=0;
    if(stopping)guest_service_stop(&c->services,v->slot,SERVICE_STOP_NORMAL);
    *stop=stopping || guest_service_stopped(&c->services)!=0;
    if(*stop && !v->async_captured) {fill_regs(&v->async_regs,frame,esr,*elr,0);v->async_captured=1;}
    return 1;
}
#if SNAP_ANS_CONVERTED
/* xnuboot_trap's converted ANS MMIO call: a 32-bit store from EL1 to the virtual
 * ANS2's I/O SQ doorbell (0x24910) or I/O CQ head doorbell (0x100c), routed as
 * the locked path routes a data abort (fast_idle_poll's classification). The
 * locked path's model_dispatch for it, with the gate shared and the ANS lock
 * held: ans_mmio (queue and poll, never wait: SNAP_ANS_ASYNC), the ANS lines
 * and this vCPU's view of them, the write count; device_models_route_irqs and
 * timer_sync's model scan are skipped (no other model changed, no model
 * deadline moved; the deadline this call may have started is armed through
 * timer_arm). 0: declined, nothing changed. 1: handled, *stop as xnuboot_trap
 * would return. A refusal is terminal with model_dispatch's EV_ANS record,
 * under the token after the gate was left. */
static int fine_ans_mmio(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,int *stop)
{
    if((esr>>26)!=0x24 || (esr&(1UL<<7)))return 0;
    struct dc_access acc=dc_decode(esr);
    if(!acc.valid || !acc.write || acc.size!=4)return 0;
    struct ans_state *st=c->root_ext->ans;
    if(!st)return 0;
    struct vcpu *v=vcpu_of(c);
    const struct params *p=c->params;
    uint64_t spsr,far,hpfar;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2; mrs %2, hpfar_el2":"=r"(spsr),"=r"(far),"=r"(hpfar));
    if((spsr&31)!=4 && (spsr&31)!=5)return 0;
    uint64_t ipa=guest_pa(far),off=0;
    if(!ipa && (hpfar&0x0000fffffffffff0UL))ipa=((hpfar>>4)<<12)|(far&0xfff);
    if(!ipa || dc_window(p->device_pa,p->device_span,p->device_count,ipa,&off)>=0)return 0;
    int index=device_model_find(p->models,p->model_count,ipa,&off);
    if(index<0 || p->models[index].kind!=DEVICE_ANS_NVME_V1 || (off!=0x24910 && off!=0x100c))return 0;
    struct fine_cpu *f=fine_cpu(c);
    if(!fast_admitted(c,v,esr) || !fast_lines_current(v) || fast_reset_latched(c)) {
        f->profile.declined[FINE_NO_STATE]++;return 0;
    }
    uint64_t value=dc_narrow(&acc,acc.reg==31 ? 0 : frame[acc.reg]);
    /* L0, shared: fine_sptm_call's bounded wait (its statements, this CPU's lock and slot named once). */
    uint64_t t0=service_profile_clock(),t1,t2,t3;
    struct guest_service_lock *gl=&c->services;
    unsigned me=(unsigned)v->slot;
    enum guest_service_result gate;
#if SNAP_GATE_WAIT
#if SNAP_PHASE_FAIR_GATE
    unsigned ahead=0;
#endif
    for(int again=0;;again=1) {
#if SNAP_PHASE_FAIR_GATE
        gate=again ? guest_service_wait_shared(gl,me,&ahead) : guest_service_enter_shared(gl,me);
#else
        gate=guest_service_enter_shared(gl,me);
#endif
        uint64_t now=service_profile_clock();
        if(gate!=SERVICE_BUSY) {
            if(again && gate==SERVICE_OK) {
                fine_add(&c->root_ext->gate[0],1);fine_add(&c->root_ext->gate[1],now-t0);
#if SNAP_PHASE_FAIR_GATE
                if(ahead)fine_add(&c->root_ext->gate[4],1);
#endif
            }
            if(gate==SERVICE_STOPPED)fine_add(&c->root_ext->gate[3],1);
            break;
        }
        if((int64_t)(now-t0-p->clock_host_hz/200)>=0 ||
           (v->watchdog_live && (int64_t)(now-v->watchdog_deadline)>=0)) {
#if SNAP_PHASE_FAIR_GATE
            guest_service_leave_shared(gl,me);       /* withdraw the arrival */
#endif
            fine_add(&c->root_ext->gate[2],1);break;
        }
        __asm__ volatile("yield");
    }
#else
    for(unsigned tries=0;;tries++) {
        gate=guest_service_enter_shared(gl,me);
        if(gate!=SERVICE_BUSY || tries>=(1u<<16))break;
        __asm__ volatile("yield");
    }
#endif
    if(gate!=SERVICE_OK) {f->profile.declined[FINE_NO_GATE]++;return 0;}
    t1=service_profile_clock();
    if(!fine_state_admits(c)) {
        guest_service_leave_shared(&c->services,v->slot);
        f->profile.declined[FINE_NO_STATE]++;return 0;
    }
    fine_ans_lock(c);
    t2=service_profile_clock();
    f->aux_wait=0;
    struct ans_ops o=fine_ans_ops(c);
    int r=ans_mmio(st,&o,1,off,4,1,&value);
    if(!r) {
        ans_async_schedule(c);
        if(ans_async_lines(c)!=DEVICE_OK)r=ANS_E_STATE;
    }
    fine_ans_unlock(c);
    t3=service_profile_clock();
    guest_service_leave_shared(&c->services,v->slot);
    const uint64_t *aw=c->root_ext->ans_wait[v->slot];
    struct fine_bucket *b=&f->profile.call[FINE_CALL_ANS_MMIO];
    b->entries++;b->gate_wait+=t1-t0;b->stripe_wait+=aw[0];b->aux_wait+=f->aux_wait;
    b->hold+=t3-t2-f->aux_wait;b->contended+=aw[1];
    if(r) {
        /* model_dispatch's refusal: EV_ANS (reason << 32 | kind), the access, and the stop. */
        f->profile.failures++;
        if(!runtime_enter(c,frame,*elr,0x24)) {*stop=1;return 1;}
        record(c,EV_ANS,*elr,(uint64_t)(r&0xff)<<32|DEVICE_ANS_NVME_V1,ipa,esr);
        fill_regs(&v->async_regs,frame,esr,*elr,ipa);
        v->async_captured=3;
        *stop=runtime_leave(c,1);
        return 1;
    }
    /* model_dispatch's success: the write count, the lines, the next instruction. */
    __atomic_fetch_add(&c->model_writes[index],1,__ATOMIC_RELAXED);
    step_translation_clear(&c->step_translation[v->slot]);
    guest_interrupt_sync(c);
    timer_arm(c,service_profile_clock(),c->fast_timer_due[v->slot].guest);
    *elr+=4;
    /* fine_sptm_call's stop decision. */
    int stopping=fine_failed(c)!=0;
    if(stopping)guest_service_stop(&c->services,v->slot,SERVICE_STOP_NORMAL);
    *stop=stopping || guest_service_stopped(&c->services)!=0;
    if(*stop && !v->async_captured) {fill_regs(&v->async_regs,frame,esr,*elr,0);v->async_captured=1;}
    return 1;
}
#endif
#endif
#if SNAP_PAUTH_EL0_LIVE
/* SNAP_PAUTH_EL0_LIVE. sync_lower's pauth_switch_live left this CPU's EL0 PAC
 * bank installed (the process keys, SCTLR_EL1's address-key enables,
 * HCR_EL2.API): the entry may be an EL0 read that fast_el0_sysreg answers, and
 * only that class runs before the bank is restored. The slot is exactly the
 * lower-EL synchronous one, ESR_EL1 the undefined-instruction syndrome and
 * SPSR_EL1 EL0t: fast_cross_entry sends exactly those to its EL0 branch, which
 * returns whatever it decides (compat/fast-vector.h), so no class that resumes
 * EL1 runs here. Nothing on this path executes a PAC instruction, touches a key
 * register or writes SCTLR_EL1 or HCR_EL2 (tools/test-pauth-el0-live.py audits
 * the built monitor). 1: answered; EL0 resumes with the bank still live
 * (xnuboot_pauth_resume). 0: the bank is restored and the trap continues as
 * before, *crossed set when fast_crossing already declined it, so it is
 * neither counted nor tried twice. -1: the restore failed. */
static __attribute__((noinline)) int el0_live_trap(struct context *c,uint64_t *frame,uint64_t esr,
                                                   uint64_t *elr,int *crossed)
{
    struct vcpu *v=vcpu_of(c);
    struct pauth_switch *bank=&c->pauth_bank[v->slot];
    if(bank->active!=1)return 0;
    const struct params *p=c->params;
    uint64_t esr1,spsr1;
    __asm__ volatile("mrs %0, esr_el1; mrs %1, spsr_el1":"=r"(esr1),"=r"(spsr1));
    if((esr>>26)==0x20 && p->vbar && *elr-p->vbar_va==0x400 &&
       esr1==FAST_EL0_SYSREG_ESR && !(spsr1&31) && !(spsr1>>32)) {
        if(fast_crossing(c,frame,esr,elr)) {
            /* fast_cross_entry read SCTLR_EL1 with the process's enables; record
             * EL1's, which the restore would have installed before it ran. */
            c->pan_entry[v->slot].entry_sctlr=bank->saved_sctlr;
            return 1;
        }
        *crossed=1;
    }
    return pauth_switch_leave(bank) ? -1 : 0;
}
#endif
int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr);
int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)
{
    struct context *c = context_of();
#if SNAP_PAUTH_EL0_LIVE
    int crossed = 0;
    if ((esr >> 26) == 0x20 && c->pauth_bank[vcpu_of(c)->slot].active == 1) {
        int live = el0_live_trap(c, frame, esr, elr, &crossed);
        if (live > 0) return 0;
        if (live < 0) return xnuboot_pauth_failed(frame);
    }
#endif
#if SNAP_SYSREG_CENSUS
    sysreg_census_note(&c->perf.census[vcpu_of(c)->slot],esr);
#endif
#if SNAP_FAST_VCPU_TRAPS
    if (fast_vcpu_trap(c, frame, esr, elr)) return 0;
#endif
#if SNAP_FAST_CROSSINGS
#if SNAP_PAUTH_EL0_LIVE
    if (!crossed && fast_crossing(c, frame, esr, elr)) return 0;
#else
    if (fast_crossing(c, frame, esr, elr)) return 0;
#endif
#endif
#if SNAP_FAST_IDLE_POLL
    if (fast_idle_poll(c, frame, esr, elr)) return 0;
#endif
#if SNAP_FINE_LOCKS
    {
        int stop = 0;
        if (fine_sptm_call(c, frame, esr, elr, &stop)) return stop;
#if SNAP_ANS_CONVERTED
        if (fine_ans_mmio(c, frame, esr, elr, &stop)) return stop;
#endif
    }
#endif
#if SNAP_MULTIPAGE_FAST
    /* agents/sptm-locks/multipage P1/P2: MULTIPAGE's first cleans, off the token; armed for this trap only. */
    multipage_preclean(c, frame, esr);
    if (!runtime_enter(c, frame, *elr, (esr >> 26) & 63)) {multipage_preclean_clear(c);return 1;}
#else
    if (!runtime_enter(c, frame, *elr, (esr >> 26) & 63)) return 1;
#endif
    struct native_call_state *native=&c->native_calls[vcpu_of(c)->slot];
    uint64_t native_before=SNAP_NATIVE_CALLS ? native->calls : 0;
    int stop=xnuboot_trap_locked(frame,esr,elr);
    if(c->kernel_view_failed && !stop) {
        record(c,EV_SPRR_FAILED,*elr,SPRR_VIEW_FAILED,0,0);
        fill_regs(&vcpu_of(c)->async_regs,frame,esr,*elr,0);
        vcpu_of(c)->async_captured=2;stop=1;
    }
    /* SNAP_ERET_SNAPSHOT: an ERET refreshes the snapshot that the unarmed
     * exception_return breakpoint no longer does (writer site 5). */
    if (SNAP_NATIVE_CALLS && !stop &&
        (native_call_snapshot_required(esr,native->calls!=native_before) ||
         (SNAP_ERET_SNAPSHOT && (esr>>26)==0x1a)))
        native_exception_snapshot(c);
    stop=runtime_leave(c,stop);
#if SNAP_ATTR_CLEAN_DEFER
    attr_clean_flush(c);   /* D1: off the token, before this vCPU resumes, stop or not */
#endif
#if SNAP_MULTIPAGE_FAST
    multipage_preclean_clear(c);   /* P2: no pre-clean outlives its trap */
#endif
    /* The new CPU needs this lock to install its register state. Wait only
     * after release, and bound the wait without discarding its reservation. */
    stop = stop || secondary_wait_entry(c);
    /* A peer can request stop while this CPU owns the service lock. Preserve
     * its final return frame instead of falling back to an older last_exc.
     * For emulated instructions *elr is the prospective resume PC. Existing
     * terminal/panic snapshots remain authoritative and are not overwritten. */
    if (stop && !vcpu_of(c)->async_captured) {
        fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, 0);
        vcpu_of(c)->async_captured = 1;
    }
    return stop;
}

#if SNAP_ROOT_CACHE_WIDE
/* Every executor has quiesced: refresh struct context's define-free root
 * cache fields from the live state for host readers (slots 0-63 only; slot
 * 64 and above are visible nowhere else). compat/root-wide.h W8. */
static void root_ext_mirror(struct context *c)
{
    const struct sptm_root_state *s=&c->user_roots;
    struct sptm_root_state_compat *h=&c->user_roots_host;
    for(unsigned n=0;n<SPTM_ROOT_CPUS;n++) {h->active[n]=s->active[n];h->sprr[n]=s->sprr[n];}
    for(unsigned i=0;i<SPTM_ROOT_CACHE_COMPAT;i++)h->cache[i]=s->cache[i];
    h->switches=s->switches;h->user_switches=s->user_switches;h->kernel_switches=s->kernel_switches;
    h->builds=s->builds;h->invalidations=s->invalidations;
    const struct native_shared *ns=&UNS(c);struct native_shared_compat *nh=&c->native_shared_host;
    nh->live=ns->live;nh->created=ns->created;nh->freed=ns->freed;nh->stores=ns->stores;
    nh->linked=ns->linked;nh->unlinked=ns->unlinked;nh->errors=ns->errors;nh->full=ns->full;nh->stale=ns->stale;
    for(unsigned g=0;g<NATIVE_SHARED_GROUPS;g++) {
        const struct native_shared_group *a=&ns->group[g];struct native_shared_group_compat *b=&nh->group[g];
        b->guest=a->guest;b->shared=a->shared;b->va=a->va;b->leaves=a->leaves;b->slots=a->slots.w[0];
        for(unsigned q=0;q<NATIVE_SHARED_PAGES;q++)b->pages[q]=a->pages[q];
    }
    for(unsigned i=0;i<NATIVE_SHARED_INDEX;i++)nh->index[i]=ns->index[i];
    for(unsigned i=0;i<SPTM_ROOT_CACHE_COMPAT;i++) {
        c->user_views[i]=UVIEWS(c)[i];c->root_stamp[i]=USTAMPS(c)[i];
        c->inactive_mirror.budget[i]=UBUDGETS(c)[i];
    }
}
#endif
#if SNAP_TXM_ASPACE_WIDE
/* Every executor has quiesced: refresh the define-free 512-slot TXM registry
 * for host readers. Slots 512 and above are only in the live pages; count is
 * the live high-water mark and may exceed 512 (compat/txm.h A3). */
static void txm_ext_mirror(struct context *c)
{
    const struct txm_registry *r=TXM_REG(c);
    struct txm_registry_compat *h=&c->txm_registry_host;
    for(unsigned i=0;i<TXM_ASPACE_LIMIT_COMPAT;i++) {
        h->root[i]=r->root[i];h->asid[i]=r->asid[i];h->shared[i]=r->shared[i];
        h->region_start[i]=r->region_start[i];h->region_end[i]=r->region_end[i];
        h->bound_shared[i]=r->bound_shared[i];
    }
    h->count=r->count;h->region_sets=r->region_sets;
    h->bindings=r->bindings;h->unbindings=r->unbindings;
}
#endif
#include "xnuboot-terminal.h"
/* Quarantine restores CPU0 only. No peer/shared cleanup, RAM publication or
 * broadcast TLB maintenance is allowed while ownership is unresolved. */
static void xnuboot_restore_host(struct context *c, int shared_safe)
{
    if(SNAP_NATIVE_WRITER_BREAKPOINTS)
        native_writer_debug_restore(&c->writer_debug[vcpu_of(c)->slot],&writer_debug_ops);
    __asm__ volatile("msr mdcr_el2, %0" :: "r"(vcpu_of(c)->save_mdcr));
    __asm__ volatile("msr mdscr_el1, %0" :: "r"(vcpu_of(c)->save_mdscr));
    if (vcpu_of(c)->dbg_oslsr & (1UL << 1)) {
        uint64_t one = 1;
        __asm__ volatile("msr oslar_el1, %0" :: "r"(one));
    }
    watchdog_off(c);
    /* Everything the probe changed, put back. Translation is turned off before
     * the registers behind it are restored, and the TLBs are flushed after, so
     * nothing of the guest's regime can outlive the probe. TPIDR_EL2 is last
     * because it is what `context_of` reads. */
    __asm__ volatile("msr vbar_el2, %0" :: "r"(vcpu_of(c)->save_vbar));
    __asm__ volatile("msr sctlr_el1, xzr; isb");
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(vcpu_of(c)->save_ttbr0));
    __asm__ volatile("msr ttbr1_el1, %0" :: "r"(vcpu_of(c)->save_ttbr1));
    __asm__ volatile("msr mair_el1, %0" :: "r"(vcpu_of(c)->save_mair));
    __asm__ volatile("msr vttbr_el2, %0" :: "r"(vcpu_of(c)->save_vttbr));
    __asm__ volatile("msr vtcr_el2, %0" :: "r"(vcpu_of(c)->save_vtcr));
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(vcpu_of(c)->save_sctlr));
    __asm__ volatile("msr tcr_el1, %0" :: "r"(vcpu_of(c)->save_tcr));
    if (shared_safe)
        __asm__ volatile("dsb ish; tlbi vmalls12e1is; tlbi alle1is; dsb ish; isb");
    else
        __asm__ volatile("dsb nsh; tlbi vmalls12e1; tlbi alle1; dsb nsh; isb");
#if SNAP_NATIVE_PACGA
    native_pacga_restore(c, vcpu_of(c));
#endif
#if SNAP_LEAN_TRAPS == 2
    lean_fgt_restore(c, vcpu_of(c));
#endif
    __asm__ volatile("msr hcr_el2, %0" :: "r"(vcpu_of(c)->save_hcr));
    __asm__ volatile("msr vmpidr_el2, %0" :: "r"(vcpu_of(c)->save_vmpidr));
    if (vcpu_of(c)->clock_saved) {
        __asm__ volatile("msr cntkctl_el1, %0" :: "r"(vcpu_of(c)->save_cntkctl));
        __asm__ volatile("msr cnthctl_el2, %0; isb" :: "r"(vcpu_of(c)->save_cnthctl));
    }
    __asm__ volatile("msr daif, %0" :: "r"(vcpu_of(c)->save_daif));
    uint64_t tpidr = vcpu_of(c)->save_tpidr;
    __asm__ volatile("msr tpidr_el2, %0; isb" :: "r"(tpidr) : "memory");
}

uint64_t xnuboot_report(uint64_t *out);
uint64_t xnuboot_report(uint64_t *out)
{
    struct context *c = context_of();
    struct vcpu *v = vcpu_of(c);
#if SNAP_BOOT_RELOCATE
    boot_relocation_settle(c);   /* vCPU 0's CPU is OFF and q1n1's registers are back */
#endif
    watchdog_off(c);
    enum guest_service_result finished = guest_service_finish(&c->services, v->slot);
    if (finished != SERVICE_OK) v->service_fault = finished;
    int retired = !v->slot && secondary_collect(c);
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
    if (!v->slot) dvfs_cpu_restore(c);   /* C5/U10: also when the ownership check below quarantines */
#endif
    /* Only drained executors may publish a shared report or touch the GPU.
     * A bounded failure returns quarantine; it never steals a peer's token or
     * marks an unresolved executor OFF. The host must not touch/reuse this RAM. */
    if (!retired || !guest_service_reusable(&c->services)) {
        v->service_fault = SERVICE_NOT_QUIESCENT;
        xnuboot_restore_host(c, 0);
        return XNUBOOT_TERMINAL_OWNERSHIP;
    }
    guards_close(c);
    /* No executor remains: publish a budget stop recorded privately while
     * waiting, without writing the shared event log outside ownership. */
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)if(c->service_budget_stops[cpu])
        record(c,EV_WATCHDOG,c->vcpus[cpu].async_regs.pc,0,0,0);
    /* Early stop: release q1n1's call service (never from inside a fault in
     * it) and settle the outcome against the final stop word. */
    if (c->early_stop.host_armed && !c->early_stop.host_in_call && c->params->early_stop.host_call)
        early_stop_host_call(c, EARLY_STOP_HOST_DISARM, 0, 0, 0);
    early_stop_finish(&c->early_stop, guest_service_stopped(&c->services));
    for (unsigned n = 0; n < EARLY_STOP_STATE_WORDS; n++)
        out[OUT_EARLY_STOP + n] = ((const uint64_t *)&c->early_stop)[n];
    for(unsigned n=0;n<A16_THERMAL_REPORT_WORDS;n++)
        out[OUT_THERMAL+n]=c->thermal?((const uint64_t *)c->thermal)[n]:0;
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
    /* Every executor has quiesced: the per-CPU exit words are final. */
    out[OUT_EXIT_PROFILE] = EXIT_PROFILE_MAGIC;
    out[OUT_EXIT_PROFILE + 1] = (uint64_t)SNAP_FAST_EL0_SYSREG | (uint64_t)SNAP_SERVICE_SUBCLASS << 1 |
                                (uint64_t)sizeof(struct exit_profile) << 32;
    for (unsigned n = 0; n < EXIT_PROFILE_WORDS; n++)
        out[OUT_EXIT_PROFILE + 2 + n] = ((const uint64_t *)&c->exit_profile)[n];
#endif
#if SNAP_FINE_LOCKS
    out[OUT_FINE_PROFILE] = FINE_PROFILE_MAGIC;
    out[OUT_FINE_PROFILE + 1] = (uint64_t)SNAP_FINE_SWITCH | (uint64_t)SNAP_FAST_PAUTH_CALLS << 1 |
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
                                UINT64_C(4) |   /* the DART kinds follow the pointer kinds */
#endif
#if SNAP_SPTM_FINE
                                UINT64_C(8) |   /* the SPTM_FINE kinds and declines follow (fine-lock.h) */
#endif
#if SNAP_ANS_CONVERTED
                                UINT64_C(16) |  /* the ANS kinds and the busy decline follow (agents/nvme-async) */
#endif
                                (uint64_t)sizeof(struct fine_profile) << 32;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        for (unsigned n = 0; n < FINE_PROFILE_WORDS; n++)
            out[OUT_FINE_PROFILE + 2 + cpu*FINE_PROFILE_WORDS + n] =
                ((const uint64_t *)&c->root_ext->fine.cpu[cpu].profile)[n];
#endif
#if SNAP_TOKEN_COSTS
    /* compat/token-costs.h struct token_costs_report, word by word. */
    out[OUT_TOKEN_COSTS] = TOKEN_COSTS_MAGIC;
    out[OUT_TOKEN_COSTS + 1] = (uint64_t)SNAP_NEST_FAST | (uint64_t)SNAP_DETACH_FAST << 1 |
        (uint64_t)SNAP_ROOT_INDEX << 2 | (uint64_t)SNAP_OTHER_PROFILE << 3 |
        (uint64_t)SNAP_GATE_WAIT << 4 |
#if SNAP_PHASE_FAIR_GATE
        UINT64_C(1) << 5 |   /* gate[4..6]: phase entries, drains, drain ticks */
#endif
        (uint64_t)sizeof(struct token_costs_report) << 32;
    for (unsigned n = 0; n < TOKEN_COSTS_WORDS; n++) out[OUT_TOKEN_COSTS + 2 + n] = 0;
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    for (unsigned n = 0; n < 16; n++)
        out[OUT_TOKEN_COSTS + 2 + n] = ((const uint64_t *)&c->root_ext->nest_fast)[n];
#endif
#if SNAP_ROOT_INDEX
    for (unsigned n = 0; n < 16; n++)
        out[OUT_TOKEN_COSTS + 2 + 16 + n] = ((const uint64_t *)&c->root_ext->root_index.stats)[n];
#endif
#if SNAP_OTHER_PROFILE
    for (unsigned n = 0; n < 3 * OTHER_CLASSES; n++)
        out[OUT_TOKEN_COSTS + 2 + 32 + n] = ((const uint64_t *)c->root_ext->other.buckets)[n];
#endif
#if SNAP_GATE_WAIT
    for (unsigned n = 0; n < 16; n++)
        out[OUT_TOKEN_COSTS + 2 + 80 + n] = __atomic_load_n(&c->root_ext->gate[n], __ATOMIC_RELAXED);
#endif
#endif
#if SNAP_FAST_TIMER_IRQ
    out[OUT_FAST_IRQ] = FAST_IRQ_MAGIC;
    out[OUT_FAST_IRQ + 1] = (uint64_t)SNAP_WFI_RESUME | (uint64_t)sizeof(struct fast_irq_cpu) << 32;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        for (unsigned n = 0; n < FAST_IRQ_WORDS; n++)
            out[OUT_FAST_IRQ + 2 + cpu*FAST_IRQ_WORDS + n] = ((const uint64_t *)&c->root_ext->fast_irq[cpu])[n];
#endif
#if SNAP_FAST_IPI
    out[OUT_FAST_IPI] = FAST_IPI_MAGIC;
    out[OUT_FAST_IPI + 1] = (uint64_t)sizeof(struct fast_ipi_cpu) << 32;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        for (unsigned n = 0; n < FAST_IPI_WORDS; n++)
            out[OUT_FAST_IPI + 2 + cpu*FAST_IPI_WORDS + n] = ((const uint64_t *)&c->root_ext->fast_ipi[cpu])[n];
#endif
#if SNAP_GUEST_NET
    if (c->guest_net) {   /* setup may have stopped before taking its page */
    out[OUT_GUEST_NET] = GUEST_NET_REPORT_MAGIC;
    out[OUT_GUEST_NET + 1] = (uint64_t)!!(c->params->early_stop.flags & EARLY_STOP_F_NET) |
                             (uint64_t)sizeof(struct guest_net_link) << 32;
    for (unsigned n = 0; n < GUEST_NET_LINK_WORDS; n++)
        out[OUT_GUEST_NET + 2 + n] = ((const uint64_t *)&c->guest_net->link)[n];
    for (unsigned n = 0; n < GUEST_NET_VIEW_WORDS; n++)
        out[OUT_GUEST_NET + 2 + GUEST_NET_LINK_WORDS + n] = ((const uint64_t *)&c->guest_net->view)[n];
    }
#endif
#if SNAP_DART_MEMO
    out[OUT_DART_MEMO] = DART_MEMO_MAGIC;
    out[OUT_DART_MEMO + 1] = (uint64_t)sizeof(struct sptm_dart_memo_stats) << 32;
    for (unsigned n = 0; n < DART_MEMO_STATS_WORDS; n++)
        out[OUT_DART_MEMO + 2 + n] = ((const uint64_t *)&c->root_ext->dart_memo.stats)[n];
    out[OUT_DART_MEMO + 2 + DART_MEMO_STATS_WORDS] = c->root_ext->dart_memo.live;
#endif
#if SNAP_TOKEN_TRIM
    out[OUT_TOKEN_TRIM] = TOKEN_TRIM_MAGIC;
    out[OUT_TOKEN_TRIM + 1] = (uint64_t)sizeof(struct token_trim_stats) << 32;
    for (unsigned n = 0; n < TOKEN_TRIM_WORDS; n++)
        out[OUT_TOKEN_TRIM + 2 + n] = ((const uint64_t *)&c->root_ext->trim.stats)[n];
#endif
#if SNAP_ROOT_CACHE_WIDE
    root_ext_mirror(c);
#endif
#if SNAP_TXM_ASPACE_WIDE
    txm_ext_mirror(c);
#endif
#if SNAP_ADRENO_IB_ASYNC
    /* An IB still in flight at the stop (A5) is polled to its final status, at most hz / 10 and never past its
     * budget, before quiesce halts GPU traffic and polls CB0 faults; then the flight is reported (IBASYNC1). */
    if (c->root_ext) {   /* setup may have stopped before taking its pages */
        struct adreno_ib_flight *f = IB_FLIGHT(c);
        struct adreno_ops o = gpu_ops(c);
        uint64_t ib_va = f->va, ib_dwords = f->dwords;
        int final;
        if ((c->gpu.status & ADRENO_S_ADOPTED) &&
            adreno_ib_flight_drain(&o, &c->params->gpu, &c->gpu, f, c->params->clock_host_hz / 10, &final))
            record(c, EV_GPU_IB, 0, ib_va, ib_dwords << 32 | (uint32_t)final, f->last_ticks);
        out[OUT_IB_ASYNC] = IB_ASYNC_MAGIC;
        out[OUT_IB_ASYNC + 1] = (uint64_t)sizeof(struct adreno_ib_flight) << 32 | ADRENO_IB_POLL_DIVISOR;
        for (unsigned n = 0; n < ADRENO_IB_FLIGHT_WORDS; n++)
            out[OUT_IB_ASYNC + 2 + n] = ((const uint64_t *)f)[n];
    }
#endif
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
    dvfs_stop(c, out);   /* the GPU back to OPP 1 before quiesce; the record OUT_DVFS */
#endif
#if SNAP_ANS_ASYNC
    /* agents/nvme-async N6: every executor has stopped; reap the SSD command in flight (bounded by its timeout)
     * so q1n1 takes the controller back with its I/O queue idle; queued commands are abandoned and counted. */
    if (c->root_ext && c->root_ext->ans) {
        struct ans_ops o = ans_ops_of(c);
        ans_async_stop(c->root_ext->ans, &o);
    }
#endif
    /* GPU DMA halted and the mirror unlinked before the guest's memory is
     * published and handed back (and so before any chainload). */
    if (!gpu_quiesce(c)) {
        xnuboot_restore_host(c, 1);
        return XNUBOOT_TERMINAL_GPU;
    }
    ans_window_stop(c);
    c->gpu.irq_fired=c->gpu.irq.line[0].fired;
    c->gpu.irq_kept=c->gpu.irq.line[0].kept;
    c->gpu.irq_resampled=c->gpu.irq.line[0].resampled;
    c->gpu.irq_spurious=c->gpu.irq.line[0].spurious;
    for (unsigned n=0;n<ADRENO_STATE_WORDS;n++) out[OUT_GPU_FLOW+n]=((const uint64_t *)&c->gpu)[n];
    uint64_t timer_ctl = guest_timer_control(&vcpu_of(c)->timer, clock_counter(c));
    /* Complete guest writes before hashing pixels, USB diagnostics, or a
     * subsequent upload reuses the same physical memory. q1n1 resumes only
     * after this report, so its UI cannot race the framebuffer witness. */
    watchdog_off(c);
    if (vcpu_of(c)->guest_sctlr) {
        publish(c->params->mem_low, c->params->mem_high);
        if (c->fb_observed)
            publish(c->params->fb_pa, c->params->fb_pa + c->fb_observed);
    }
    out[OUT_FRAMEBUFFER + 0] = c->fb_observed;
    out[OUT_FRAMEBUFFER + 1] = c->fb_before;
    out[OUT_FRAMEBUFFER + 2] = c->fb_observed ? framebuffer_hash(c->params) : 0;
    out[OUT_ASYNC_REGS] = vcpu_of(c)->async_captured;
    const uint64_t *async = (const uint64_t *)&vcpu_of(c)->async_regs;
    for (unsigned n = 0; n < GUEST_REGS_WORDS; n++)
        out[OUT_ASYNC_REGS + 1 + n] = async[n];
    out[OUT_EXCEPTION_FLOW + 0] = vcpu_of(c)->kernel_returns;
    out[OUT_EXCEPTION_FLOW + 1] = vcpu_of(c)->pacga_calls;
    out[OUT_EXCEPTION_FLOW + 2] = vcpu_of(c)->last_kernel_return;
    out[OUT_UPDATE_FLOW + 0] = c->update_calls;
    out[OUT_UPDATE_FLOW + 1] = c->update_entries;
    out[OUT_UPDATE_FLOW + 2] = c->region_calls;
    out[OUT_UPDATE_FLOW + 3] = c->region_entries;
    out[OUT_SLIDE_FLOW + 0] = c->slide.calls;
    out[OUT_SLIDE_FLOW + 1] = c->slide.pages;
    out[OUT_SLIDE_FLOW + 2] = c->slide.cursor;
    out[OUT_CLOCK_FLOW + 0] = vcpu_of(c)->clock.reads;
    out[OUT_CLOCK_FLOW + 1] = vcpu_of(c)->clock.first;
    out[OUT_CLOCK_FLOW + 2] = vcpu_of(c)->clock.last;
    out[OUT_CLOCK_FLOW + 3] = vcpu_of(c)->clock.writes;
    out[OUT_CLOCK_FLOW + 4] = vcpu_of(c)->clock.cntkctl;
    out[OUT_CLOCK_FLOW + 5] = vcpu_of(c)->clock_hz;
    uint64_t cntkctl = 0;
    if (vcpu_of(c)->clock_saved)
        __asm__ volatile("mrs %0, cntkctl_el1" : "=r"(cntkctl));
    out[OUT_CLOCK_FLOW + 6] = cntkctl;
    out[OUT_CLOCK_FLOW + 7] = vcpu_of(c)->save_cntkctl;
    out[OUT_CLOCK_ADAPTER + 0] = vcpu_of(c)->clock_rate.host_hz;
    out[OUT_CLOCK_ADAPTER + 1] = vcpu_of(c)->clock_rate.guest_hz;
    out[OUT_CLOCK_ADAPTER + 2] = vcpu_of(c)->save_cnthctl;
    out[OUT_CLOCK_ADAPTER + 3] = vcpu_of(c)->guest_cnthctl;
    out[OUT_CLOCK_ADAPTER + 4] = vcpu_of(c)->wfe_traps;
    out[OUT_CLOCK_ADAPTER + 5] = vcpu_of(c)->event_wakes;
    out[OUT_CLOCK_ADAPTER + 6] = vcpu_of(c)->wfe_early;
    out[OUT_CLOCK_ADAPTER + 7] = vcpu_of(c)->arch_counter_reads;
    out[OUT_CLOCK_ADAPTER + 8] = vcpu_of(c)->clock_raw_first;
    out[OUT_CLOCK_ADAPTER + 9] = vcpu_of(c)->clock_raw_last;
    out[OUT_CLOCK_ADAPTER + 10] = vcpu_of(c)->clock_guest_first;
    out[OUT_CLOCK_ADAPTER + 11] = vcpu_of(c)->clock_guest_last;
    out[OUT_AIC_FLOW + 0] = vcpu_of(c)->model_irq_pending;
    out[OUT_AIC_FLOW + 1] = vcpu_of(c)->model_irq_asserts;
    out[OUT_AIC_FLOW + 2] = vcpu_of(c)->model_irq_clears;
    out[OUT_AIC_FLOW + 3] = vcpu_of(c)->model_irq_vectors;
    uint64_t aic_events = 0;
    for (unsigned i=0; i<c->params->model_count && i<DEVICE_MODEL_MAX; i++)
        aic_events += c->model_state[i].aic.events;
    out[OUT_AIC_FLOW + 4] = aic_events;
    for (unsigned i=0;i<DEVICE_RESET_WORDS;i++)
        out[OUT_WATCHDOG_FLOW+i] = c->device_reset_mask[i];
    out[OUT_OPTIONAL_FLOW] = c->txm_developer_notifications;
    out[OUT_OPTIONAL_FLOW+1] = c->cputrace_queries[0] |
                             ((uint64_t)c->cputrace_queries[1] << 32);
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        const struct vcpu *v = &c->vcpus[n];
        unsigned at = OUT_VCPU_FLOW+n*12;
        out[at+0] = (uint64_t)v;
        out[at+1] = v->slot;
        out[at+2] = v->vmpidr;
        out[at+3] = v->prepared;
        out[at+4] = v->guest_ttbr1;
        out[at+5] = v->timer.reads;
        out[at+6] = v->ipi.requests;
        out[at+7] = v->exceptions;
        out[at+8] = v->stage2_root;
        out[at+9] = vcpu_vttbr(v);
        out[at+10] = v->guard_count;
        out[at+11] = v->open_guards;
    }
    out[OUT_SHARED_FLOW] = c->shadow_tlb_syncs;
    out[OUT_SHARED_FLOW+1] = c->root_checks;
    out[OUT_SHARED_FLOW+2] = c->root_busy_refusals;
    out[OUT_SERVICE_FLOW] = guest_service_owner(&c->services);
    out[OUT_SERVICE_FLOW+1] = guest_service_stopped(&c->services);
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        out[OUT_SERVICE_FLOW+2+n*2] = c->vcpus[n].service_acquires;
        out[OUT_SERVICE_FLOW+3+n*2] = c->vcpus[n].service_fault;
    }
    out[OUT_SERVICE_FLOW+2+GUEST_CPU_COUNT*2] = guest_service_lifecycle(&c->services);
    out[OUT_SERVICE_FLOW+3+GUEST_CPU_COUNT*2] = guest_service_reusable(&c->services);
    for (unsigned n=0; n<GUEST_CPU_COUNT; n++) {
        const struct vcpu *v=&c->vcpus[n];
        unsigned at=OUT_RUNTIME_STORAGE+n*5;
        out[at]=v->vncr_va;
        out[at+1]=n ? v->out_ptr : 0;
        out[at+2]=n && v->el2_sp ? v->el2_sp-GUEST_RUNTIME_STACK : 0;
        out[at+3]=n ? v->el2_sp : 0;
        out[at+4]=v->vncr_va ? *(const volatile uint64_t *)(v->vncr_va+0x78) : 0;
    }
    uint64_t active_vncr;
    __asm__ volatile("mrs %0, s3_4_c2_c2_0" : "=r"(active_vncr));
    out[OUT_RUNTIME_STORAGE+GUEST_CPU_COUNT*5]=active_vncr;
    out[OUT_IPI_FLOW+0]=vcpu_of(c)->ipi.pending;
    out[OUT_IPI_FLOW+1]=vcpu_of(c)->ipi.requests;
    out[OUT_IPI_FLOW+2]=vcpu_of(c)->ipi.reads;
    out[OUT_IPI_FLOW+3]=vcpu_of(c)->ipi.acks;
    out[OUT_IPI_FLOW+4]=vcpu_of(c)->ipi.coalesced;
    out[OUT_IPI_FLOW+5]=vcpu_of(c)->ipi.last_request;
    out[OUT_IPI_FLOW+6]=vcpu_of(c)->ipi_request_pc;
    out[OUT_IPI_FLOW+7]=vcpu_of(c)->ipi_ack_pc;
    out[OUT_CPU_FLOW+0]=c->cpus.registered;
    out[OUT_CPU_FLOW+1]=c->cpus.registrations;
    out[OUT_CPU_FLOW+2]=c->cpus.id_queries;
    out[OUT_CPU_FLOW+3]=c->cpus.output_queries;
    out[OUT_CPU_FLOW+4]=vcpu_of(c)->slot;
    out[OUT_CPU_FLOW+5]=c->cpus.last_affinity;
    out[OUT_CPU_FLOW+6]=c->cpus.last_slot;
    out[OUT_CPU_FLOW+7]=c->cpus.reserved;
    for (unsigned i=0; i<DEVICE_MODEL_MAX; i++) {
        const struct watchdog_state *wd = &c->model_state[i].watchdog;
        out[OUT_WATCHDOG_FLOW+DEVICE_RESET_WORDS+3*i] = wd->current | ((uint64_t)wd->control << 32);
        out[OUT_WATCHDOG_FLOW+DEVICE_RESET_WORDS+1+3*i] = wd->bite | ((uint64_t)wd->reset << 32);
        out[OUT_WATCHDOG_FLOW+DEVICE_RESET_WORDS+2+3*i] = wd->last;
    }
    out[OUT_TIMER_FLOW + 0] = vcpu_of(c)->timer.reads;
    out[OUT_TIMER_FLOW + 1] = vcpu_of(c)->timer.writes;
    out[OUT_TIMER_FLOW + 2] = vcpu_of(c)->timer_irqs;
    out[OUT_TIMER_FLOW + 3] = vcpu_of(c)->timer_asserts;
    out[OUT_TIMER_FLOW + 4] = vcpu_of(c)->timer_clears;
    out[OUT_TIMER_FLOW + 5] = vcpu_of(c)->timer_vectors;
    out[OUT_TIMER_FLOW + 6] = timer_ctl;
    out[OUT_TIMER_FLOW + 7] = vcpu_of(c)->timer.cval;
    out[OUT_TIMER_FLOW + 8] = vcpu_of(c)->timer_irq_pc;
    out[OUT_TIMER_FLOW + 9] = vcpu_of(c)->watchdog_deadline;
    out[OUT_TIMER_FLOW + 10] = vcpu_of(c)->step_exception_repairs;
    out[OUT_DEVICE_FLOW] = c->params->model_count;
    for (unsigned i=0; i<DEVICE_MODEL_MAX; i++) {
        out[OUT_DEVICE_FLOW + 1 + 2*i] = c->model_reads[i];
        out[OUT_DEVICE_FLOW + 2 + 2*i] = c->model_writes[i];
    }
    out[0] = vcpu_of(c)->shadow_root;
    out[1] = c->leaves;
#if SNAP_FAST_VCPU_TRAPS
    /* Every emulated system-register trap, locked or fast. The executors have
     * quiesced, so their private counters are final. */
    {
        uint64_t fast = 0;
        for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) fast += c->perf.fast[n].sysreg;
        out[2] = c->traps + fast;
    }
#else
    out[2] = c->traps;
#endif
    out[3] = c->events;
    out[4] = c->aborts | (c->steps << 32);
    out[5] = vcpu_of(c)->stage2_root;
    /* A syndrome, and nothing else. The only thing that writes it is the
     * failed AT S1E1R in xnuboot_prepare(), which carries PAR_EL1 -- so on a
     * run that entered, this is zero unless something records a fault. */
    out[6] = vcpu_of(c)->fault_esr;
    out[7] = c->calls | (c->console_len << 32);
    uint8_t *console = (uint8_t *)&out[8 + 6 * EVENT_MAX];
    for (unsigned n = 0; n < CONSOLE_MAX; n++) console[n] = c->console[n];
    for (unsigned n = 0; n < EVENT_MAX; n++) {
        out[8 + 6 * n + 0] = c->log[n].kind;
        out[8 + 6 * n + 1] = c->log[n].pc;
        out[8 + 6 * n + 2] = c->log[n].a;
        out[8 + 6 * n + 3] = c->log[n].b;
        out[8 + 6 * n + 4] = c->log[n].c;
        out[8 + 6 * n + 5] = c->log[n].repeats;
    }

    /* The register snapshots, after the console so nothing already parsed
     * moves. probes/run.py reads them at OUT_GUEST_REGS; the two files agree
     * through the _Static_assert below and the same constant on that side. */
    {
        uint64_t *regs_out = &out[OUT_GUEST_REGS];
        regs_out[0] = vcpu_of(c)->exceptions;
        const uint64_t *src = (const uint64_t *)&vcpu_of(c)->first_exc;
        for (unsigned n = 0; n < GUEST_REGS_WORDS; n++) regs_out[1 + n] = src[n];
        src = (const uint64_t *)&vcpu_of(c)->last_exc;
        for (unsigned n = 0; n < GUEST_REGS_WORDS; n++)
            regs_out[1 + GUEST_REGS_WORDS + n] = src[n];

        uint64_t *panic_out = &out[OUT_PANIC_REGS];
        panic_out[0] = vcpu_of(c)->panic_calls;
        src = (const uint64_t *)&vcpu_of(c)->panic_exc;
        for (unsigned n = 0; n < GUEST_REGS_WORDS; n++) panic_out[1 + n] = src[n];

        uint64_t *counters = &out[OUT_COUNTERS];
        counters[0] = c->map_pages;
        counters[1] = c->map_failures;
        counters[2] = c->dispatch_cmds;
        counters[3] = vcpu_of(c)->panic_calls;
        counters[4] = c->undef_skipped;
        counters[5] = c->map_outside;
        counters[6] = c->log_dropped;
        counters[7] = c->console_dropped;
        counters[8] = c->ranges_dropped;
        counters[9] = c->map_device;
        counters[10] = c->mmio_reads;
        counters[11] = c->mmio_writes;
        counters[12] = c->uart_tx;

        out[OUT_EXC_RETURN] = c->exc_return;
        out[OUT_BAD_REGS + 0] = vcpu_of(c)->bad_elr;
        out[OUT_BAD_REGS + 1] = vcpu_of(c)->bad_far;

        /* The terminal word, in the shape of a log entry so the host reads it
         * with the same unpack. Written even when it is empty, so the host
         * never has to distinguish "no event" from "a short read". */
        out[OUT_LAST_EVENT + 0] = c->last.kind;
        out[OUT_LAST_EVENT + 1] = c->last.pc;
        out[OUT_LAST_EVENT + 2] = c->last.a;
        out[OUT_LAST_EVENT + 3] = c->last.b;
        out[OUT_LAST_EVENT + 4] = c->last.c;
        out[OUT_LAST_EVENT + 5] = c->last.repeats;

        /* Sixty-four buckets and the one for everything else. */
        for (unsigned n = 0; n < ENDPOINT_BUCKETS; n++)
            out[OUT_ENDPOINTS + n] = c->endpoint_calls[n];
        out[OUT_ENDPOINTS + ENDPOINT_BUCKETS] = c->endpoint_other;

        /* The span table: how many slots are used, how many spans did not fit,
         * then the slots themselves. Every slot is written, used or not, so a
         * short read cannot be mistaken for an empty one. */
        uint64_t *ranges = &out[OUT_RANGES];
        ranges[0] = c->range_count;
        ranges[1] = c->ranges_dropped;
        for (unsigned n = 0; n < MAP_RANGES; n++) {
            ranges[2 + MAP_RANGE_WORDS * n + 0] = c->ranges[n].va;
            ranges[2 + MAP_RANGE_WORDS * n + 1] = c->ranges[n].pa;
            ranges[2 + MAP_RANGE_WORDS * n + 2] = c->ranges[n].pages;
            ranges[2 + MAP_RANGE_WORDS * n + 3] = c->ranges[n].attrs;
        }

        /* The guest's translation registers, in the order run.py names them. */
        out[OUT_GUEST_SYSREGS + 0] = vcpu_of(c)->guest_ttbr0;
        out[OUT_GUEST_SYSREGS + 1] = vcpu_of(c)->guest_ttbr1;
        out[OUT_GUEST_SYSREGS + 2] = vcpu_of(c)->guest_tcr;
        out[OUT_GUEST_SYSREGS + 3] = vcpu_of(c)->guest_mair;
        out[OUT_GUEST_SYSREGS + 4] = vcpu_of(c)->guest_sctlr;
    }

    xnuboot_restore_host(c, 1);
    return XNUBOOT_TERMINAL_OK;
}
#if SNAP_GATE_WAIT && !defined(GATE_WAIT_BUILT)
#error "SNAP_GATE_WAIT waits on the converted calls' gate: build with the fine locks"
#endif
