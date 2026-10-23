/* SPDX-License-Identifier: MIT */
/* Defaults and prerequisite checks for the native-call, user-view, stepping and
 * service-profile feature flags (the first group; the rest follow the headers).
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
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
