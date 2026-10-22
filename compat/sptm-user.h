/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"

/* Shipped MAP_PAGE returns this without replacing a valid different PA.
 * XNU removes the old mapping and retries through its normal fault path. */
#define SPTM_USER_MAP_CONFLICT 6u

/* The host supplies recorded registers and independently counted active CPU
 * references. Active insertion reserves empty shadow tables before mutation;
 * commit publishes the new leaf and invalidates translations before success.
 * Callback failure stops the caller; commit failure is not recoverable. */
/* A maximum 16K L2 has 2048 entries. Bits select only shared descriptors;
 * holes and ordinary tables within the rounded range remain untouched. */
struct sptm_unnest_plan {
    uint64_t base,span,count,descriptors,leaves,mask[32];
};
#define SPTM_SHARED_DETACH_HISTORY 4096
struct sptm_shared_detach_record {
    uint64_t root,va,slot,child,format,level,parent_count,bindings;
};
_Static_assert(sizeof(struct sptm_shared_detach_record)==64,"shared detach audit stride");
struct sptm_shared_detach_state {
    uint64_t calls;
    struct sptm_shared_detach_record records[SPTM_SHARED_DETACH_HISTORY];
};
struct sptm_shared_update_entry { uint64_t old,next; };
struct sptm_user_backend {
    uint64_t ttbr0, ttbr1;
    struct sptm_aperture aperture;
    struct sptm_moved moved;        /* optional: SLIDE_REGION aliases, see sptm.h */
    unsigned active_refs;
    /* Nonzero only for a root with no active CPU whose cached shadow the host
     * keeps (compat/inactive-mirror.h): MAP_PAGE runs the leaf callbacks for
     * a fresh leaf exactly as for an active root. It never counts as a CPU
     * reference. */
    unsigned mirror;
    int (*prepare_leaf)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    int (*commit_leaf)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    /* Unmap callbacks also run for inactive cached roots. Prepare checks the
     * whole range without mutation; commit removes private leaves and finishes
     * broadcast TLB invalidation before this backend releases references. */
    int (*prepare_unmap)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    int (*commit_unmap)(void *,uint64_t,uint64_t,unsigned,uint64_t,uint64_t);
    int (*prepare_detach)(void *,uint64_t,uint64_t,unsigned,unsigned,uint64_t);
    int (*commit_detach)(void *,uint64_t,uint64_t,unsigned,unsigned,uint64_t);
    /* Retained commpage attachment: reserve/check all private destinations
     * before publication, then install without allocation. Runs for cached
     * inactive roots as well. Child and data refs remain distinct. */
    int (*prepare_attach)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    int (*commit_attach)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    /* Nesting aliases existing shared L3 descriptors, including partial 4K
     * allocation groups. Prepare must cover the entire descriptor range;
     * commit synchronizes active and inactive cached translations. */
    int (*prepare_nest)(void *,uint64_t,uint64_t,uint64_t,unsigned,uint64_t);
    int (*commit_nest)(void *,uint64_t,uint64_t,uint64_t,unsigned,uint64_t);
    /* Existing-leaf updates: preflight cannot mutate; commit publishes every
     * cached/private view and completes broadcast invalidation. */
    int (*prepare_update)(void *,uint64_t,uint64_t,unsigned,uint64_t,uint64_t);
    int (*commit_update)(void *,uint64_t,uint64_t,unsigned,uint64_t,uint64_t);
    /* Shared-root leaves change one source slot but every nested cached view.
     * The backend must cover inactive aliases too and finish broadcast TLBI. */
    int (*prepare_shared_leaf)(void *,uint64_t,uint64_t,unsigned,uint64_t,uint64_t);
    int (*commit_shared_leaf)(void *,uint64_t,uint64_t,unsigned,uint64_t,uint64_t);
    int (*prepare_shared_unmap)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    int (*commit_shared_unmap)(void *,uint64_t,uint64_t,unsigned,uint64_t,uint64_t);
    /* One preflight covers the whole L3 batch, then one commit propagates
     * all changed leaves to every cached alias before refreshing CPU views. */
    int (*prepare_shared_update)(void *,uint64_t,uint64_t,unsigned,uint64_t);
    int (*commit_shared_update)(void *,uint64_t,uint64_t,unsigned,uint64_t,
                                const struct sptm_shared_update_entry *);
    int (*prepare_unnest)(void *,uint64_t,uint64_t,unsigned,const struct sptm_unnest_plan *);
    int (*commit_unnest)(void *,uint64_t,uint64_t,unsigned,const struct sptm_unnest_plan *);
    struct sptm_shared_detach_state *shared_detaches;
    /* Optional witness for completed ordinary same-PA MAP_PAGE changes. */
    struct sptm_user_update_state *map_updates;
    void *ctx;
};

enum sptm_result sptm_mac_unnest_region(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t shared,uint64_t va,uint64_t pages);

struct sptm_user_update_state {
    uint64_t calls,entries,changed,options,result,target,count;
    uint64_t root,va,slot,old,next,shift,flags,last_changed,requested;
};
_Static_assert(sizeof(struct sptm_user_update_state)==128,"user update audit stride");
struct sptm_shared_update_state {
    struct sptm_user_update_state latest,changed;
};
/* Endpoint5 option4 sets nG without changing PA, permissions or ownership.
 * Both DEFAULT NX and USER_EXEC shared leaves are supported. Keep a changed
 * witness separately because subsequent empty batches must not erase it. */
enum sptm_result sptm_mac_shared_ng_pte(uint64_t old,uint64_t requested,
    uint64_t options,uint64_t *next);
enum sptm_result sptm_mac_update_shared_region(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t va,uint64_t count,
    uint64_t templates,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_shared_update_state *state);
/* Endpoint5 user transaction: per-page permission templates, one L3 range.
 * Missing tables/leaves report old zero descriptors. Valid DEFAULT,
 * USER_EXEC, USER_TPRO and device-window (XNU_IO) leaves retain their PA and
 * follow Apple's permission rows for their type; prepare all changes before
 * source publication. A changed SH/AttrIndx (options 0x10/0x20, still under
 * the leaf policy) cleans each data frame once first (memory.clean_frame);
 * the device window has no EL2 alias to clean and keeps its attributes. */
enum sptm_result sptm_mac_update_user_region(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t va,uint64_t count,
    uint64_t templates,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_user_update_state *state);
enum sptm_result sptm_mac_user_update_pte(uint64_t old,uint64_t requested,
    uint64_t options,uint64_t *next);
/* Apple's selection for a leaf of data frame `type` (its descriptor +4
 * policy gates any 4-bit class change). The caller still applies the leaf
 * policy to the result; types without a mapping policy are refused. */
enum sptm_result sptm_mac_user_update_typed(uint64_t old,uint64_t requested,
    uint64_t options,unsigned type,uint64_t *next);
/* DEFAULT NX user aliases, with exact selected permission/history/AF/WIRED
 * and SH/AttrIndx semantics. All records preflight before source
 * publication; a changed SH/AttrIndx cleans target once before the first
 * store. A synchronous backend is permitted even when Apple allows deferred
 * synchronization. */
enum sptm_result sptm_mac_update_user_disjoint(const struct sptm_memory *,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    uint64_t target,uint64_t list,uint64_t count,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_user_update_state *state);

#define SPTM_MIXED_DISJOINT 1
/* The kernel callbacks share the transaction's reference batch; prepare must
 * not publish source, shadow or output. The workspace retains kernel entries
 * at their original input indices until every record has passed preflight. */
struct sptm_mixed_kernel_backend {
    uint64_t root;
    struct sptm_update_workspace *workspace;
    void *ctx;
    enum sptm_result (*prepare)(void *,uint64_t,uint64_t,uint64_t,uint64_t,
                                uint64_t,uint64_t,struct sptm_update_entry *);
    void (*commit)(void *,struct sptm_update_entry *);
};
enum sptm_result sptm_mac_update_mixed_disjoint(const struct sptm_memory *,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    const struct sptm_mixed_kernel_backend *,
    uint64_t target,uint64_t list,uint64_t count,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_user_update_state *state);

enum sptm_result sptm_mac_user_leaf_policy(unsigned flags,unsigned table_type,
    unsigned data_type,uint64_t va,uint64_t pte,const struct sptm_user_geometry *g);
/* Verify a nested descriptor against this root's bound shared address space. */
int sptm_mac_nested_table(const struct sptm_memory *,uint64_t root,uint64_t va,uint64_t pte);
/* The shared-region slot a user root is bound to (metadata byte 8): 0..254, 255 for none, -1 when root is not a
 * user root. SWITCH_ROOT uses it the way SPTM does, to flush a CPU's global shared-cache translations when the
 * incoming root's region differs from the previous one. */
int sptm_mac_root_shared_slot(const struct sptm_memory *,uint64_t root);
/* Identify an installed alias, not just a root bound to the shared region.
 * Success with aliased=0 means this user root does not share this L3 slot. */
enum sptm_result sptm_mac_shared_alias(const struct sptm_memory *,uint64_t root,
    uint64_t shared,uint64_t va,unsigned shift,int *aliased);
enum sptm_result sptm_mac_shared_map_pte(uint64_t old,uint64_t requested,
    uint64_t *next,uint64_t *result);
struct sptm_nest_state {
    uint64_t calls,descriptors,root,shared,va,pages,first,last;
};
_Static_assert(sizeof(struct sptm_nest_state)==64,"nest audit stride");
enum sptm_result sptm_mac_nest_region(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t shared,uint64_t va,uint64_t pages);
enum sptm_result sptm_mac_map_user_table_live(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t va,uint64_t level,uint64_t tte);

/* Measured mac-v1 formats: 0 uses 16K/L1, 1 uses 4K/L0. Metadata and
 * ownership remain per 16K allocation frame. Both admit 47-bit low VA;
 * ARM64_32 roots retain the selected geometry but admit only low 32-bit VAs.
 * Admits ordinary NX user data and COMMPAGE data with audited RO/NX or RX
 * permissions, and NX user leaves of the declared device window (XNU_IO,
 * never dereferenced or counted). DEFAULT/XNU_IO leaves may carry any
 * AttrIndx/SH, as Apple's MAP_PAGE never inspects them. Fresh insert
 * returns guest result 0, identical existing
 * leaf returns 1. Other replacements fail without mutation.
 * MAP_PAGE option bit 0 suppresses output-area writes (SPTM ...f9514).
 * The RX policy here models permissions/references, not TXM code integrity. */
enum sptm_result sptm_mac_map_user_page(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t pte,
    uint64_t options,uint64_t scratch,uint64_t *guest_result);
/* Detach an empty ordinary/shared table or retain a populated commpage table.
 * Bound shared roots are allowed only after all child aliases are unnested:
 * exactly one source link, zero child refs, and a completely empty allocation.
 * Only the parent link and table-link counts change; data refs remain valid.
 * Active roots require source/shadow preflight and removal callbacks, with
 * broadcast invalidation before link references are released. Four 4K
 * descriptors detach as a group with one link decrement. */
enum sptm_result sptm_mac_unmap_user_table(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t level);
/* Condemn changes only the software lifetime bit in an ordinary L3 table's
 * parent descriptor group. Existing leaves and references remain intact.
 * Duplicate/absent condemnation returns guest7; uncondemn requires marked
 * descriptors. MAP_PAGE must report missing while the table is condemned. */
enum sptm_result sptm_mac_condemn_user_table(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t va,unsigned condemn,
    uint64_t *guest_result);
/* Endpoint7: 1..64 ordinary leaves within one L3 table. Always returns old
 * PTEs in scratch, including zeros for absent mappings. Compressed markers
 * (invalid, bits63:61) stay for option0 and are cleared for option1.
 * Commpage tables have a different contract and are rejected here. */
enum sptm_result sptm_mac_unmap_user_region(const struct sptm_memory *,
    const struct sptm_user_backend *,uint64_t root,uint64_t va,uint64_t count,
    uint64_t options,uint64_t scratch);
/* Endpoint8: remove matching aliases of one16K physical frame. Records are
 * {root, VA, template}; only template bits63:61 survive as invalid software
 * state. Return old PTEs, including stale/nonmatching records. All source and
 * private-view checks precede mutation; references survive broadcast TLBI. */
enum sptm_result sptm_mac_unmap_user_disjoint(const struct sptm_memory *,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    uint64_t target,uint64_t list,uint64_t count,uint64_t scratch,
    struct sptm_shared_update_state *state);
/* SNAP_UNMAP_MIXED (opt-in, default 0): one endpoint8 list may name user
 * roots and the kernel root, as UPDATE_DISJOINT's may
 * (docs/MIXED-DISJOINT-20260927.md). installed-fresh-20261017-v39 stopped
 * with BAD_CONFIG on a user-first two-record list for one frame: the dispatch
 * picked the user engine from record 0 and its resolver refuses the root
 * installed in TTBR1. Failure modes, written before the code and each covered
 * by tools/test-unmap-mixed.c (mutants in tools/test-unmap-mixed.py):
 *  M1 either record order refused, or one domain's records skipped;
 *  M2 one domain published before a later record of either domain fails
 *     preflight (every record, both domains, preflights in one reference
 *     batch before any source, shadow or output store);
 *  M3 a kernel record loses the kernel engine's checks: VA range and
 *     alignment, table path, the four canonical shadow descriptors, the
 *     duplicate-slot rule (same VA, later copies see the removed value|0x80);
 *  M4 a user record loses the user engine's checks (resolver, geometry,
 *     table types, leaf policy, cached-shadow preparation);
 *  M5 outputs out of input order, or references released twice/never;
 *  M6 the kernel half returns without the kernel publication and all-VMID
 *     invalidation (the caller treats a mixed list as a kernel one);
 *  M7 a default build changes (the define-off source is token-identical);
 *  M8 a witness the end-of-boot audit refuses: a kernel record in the user
 *     witness (kernel VA, kernel root) or counters that disagree. */
#ifndef SNAP_UNMAP_MIXED
#define SNAP_UNMAP_MIXED 0
#endif
#if SNAP_UNMAP_MIXED
struct sptm_unmap_kernel {
    uint64_t root;           /* the kernel root (TTBR1) */
    struct shadow *shadow;   /* its canonical 4K shadow */
    struct sptm_shared_update_state *state;   /* the kernel records' witness */
};
/* kernel 0: exactly sptm_mac_unmap_user_disjoint. Each domain's records go to
 * its own witness (state: user, kernel->state: kernel), as the separate
 * engines record them, so the end-of-boot audit admits both
 * (tools/audit-unmap-disjoint.py). */
enum sptm_result sptm_mac_unmap_mixed_disjoint(const struct sptm_memory *,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    const struct sptm_unmap_kernel *kernel,
    uint64_t target,uint64_t list,uint64_t count,uint64_t scratch,
    struct sptm_shared_update_state *state);
/* One kernel record's halves (compat/sptm-unmap.c, the kernel engine's own
 * steps): the source slot, then the canonical-shadow check and dry run, then
 * the shadow removal at commit. */
enum sptm_result sptm_kernel_unmap_slot(const struct sptm_memory *,uint64_t root,
    uint64_t va,uint64_t scratch,volatile uint8_t **slot,uint64_t *slot_pa,uint64_t *old);
enum sptm_result sptm_kernel_unmap_check(struct shadow *,uint64_t va,uint64_t target,uint64_t old);
int sptm_kernel_unmap_commit(struct shadow *,uint64_t va);
#endif
