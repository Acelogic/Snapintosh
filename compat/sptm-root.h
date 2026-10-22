/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
#include "sprr.h"
#include "../shadow/shadow.h"
#define SPTM_ROOT_CPUS 6u
/* SNAP_ROOT_CACHE_WIDE (compat/root-wide.h): 192 cached user roots instead of
 * 64. struct context keeps a 64-slot twin of this state at the define-free
 * offsets host readers use; the live state lives in monitor arena pages. */
#ifndef SNAP_ROOT_CACHE_WIDE
#define SNAP_ROOT_CACHE_WIDE 0
#endif
#if SNAP_ROOT_CACHE_WIDE
#define SPTM_ROOT_CACHE 192u
#else
#define SPTM_ROOT_CACHE 64u
#endif
#define SPTM_ROOT_CACHE_COMPAT 64u
/* compat/root-miss.h: the opt-in cheaper cache miss (off: this file and
 * sptm-root.c are token-identical to the code without it). */
#ifndef SNAP_ROOT_MISS_FAST
#define SNAP_ROOT_MISS_FAST 0
#endif
/* compat/user-hw-walk.h: format-1 user roots walked by hardware as XNU's own
 * tables (off: this file and sptm-root.c are token-identical without it). */
#ifndef SNAP_USER_HW_WALK
#define SNAP_USER_HW_WALK 0
#endif
#define SPTM_ROOT_TCR_16K UINT64_C(0x010800336511a511)
#define SPTM_ROOT_TCR_4K  UINT64_C(0x0108003365112511)
struct sptm_root_cached {
    uint64_t root, shadow, leaves, asid, format, flags, valid;
};
struct sptm_root_state {
    uint64_t active[SPTM_ROOT_CPUS];
    struct sptm_root_cached cache[SPTM_ROOT_CACHE];
    uint64_t switches, user_switches, kernel_switches, builds, invalidations;
    struct sprr_state sprr[SPTM_ROOT_CPUS];
};
_Static_assert(sizeof(struct sptm_root_cached)==56,"root audit cache stride");
#if SNAP_ROOT_CACHE_WIDE
/* The define-free host layout of struct sptm_root_state, kept in struct
 * context and refreshed from the live state when the run stops. */
struct sptm_root_state_compat {
    uint64_t active[SPTM_ROOT_CPUS];
    struct sptm_root_cached cache[SPTM_ROOT_CACHE_COMPAT];
    uint64_t switches, user_switches, kernel_switches, builds, invalidations;
    struct sprr_state sprr[SPTM_ROOT_CPUS];
};
#define SPTM_ROOT_STATE_COMPAT sptm_root_state_compat
_Static_assert(__builtin_offsetof(struct sptm_root_state_compat,switches)==3632,
               "root audit counters offset");
_Static_assert(__builtin_offsetof(struct sptm_root_state_compat,sprr)==3672,
               "root SPRR audit offset");
/* A set of cache slots: one bit per slot, SPTM_ROOT_CACHE bits. */
#define SPTM_ROOT_MASK_WORDS (SPTM_ROOT_CACHE/64u)
typedef struct {uint64_t w[SPTM_ROOT_MASK_WORDS];} sptm_root_mask_t;
#define SPTM_ROOT_MASK_HAS(m,i) ((((m).w[(i)>>6])>>((i)&63u))&1u)
#define SPTM_ROOT_MASK_SET(m,i) ((m).w[(i)>>6]|=UINT64_C(1)<<((i)&63u))
#define SPTM_ROOT_MASK_NONE ((sptm_root_mask_t){{0}})
#define SPTM_ROOT_MASK_ONE(i) sptm_root_mask_one(i)
#define SPTM_ROOT_MASK_NE(a,b) sptm_root_mask_ne(a,b)
#define SPTM_ROOT_MASK_ANY(m) sptm_root_mask_any(m)
#define SPTM_ROOT_MASK_LOW(m) ((m).w[0])
static inline sptm_root_mask_t sptm_root_mask_one(unsigned i)
{sptm_root_mask_t m=SPTM_ROOT_MASK_NONE;if(i<SPTM_ROOT_CACHE)SPTM_ROOT_MASK_SET(m,i);return m;}
static inline int sptm_root_mask_ne(sptm_root_mask_t a,sptm_root_mask_t b)
{uint64_t d=0;for(unsigned i=0;i<SPTM_ROOT_MASK_WORDS;i++)d|=a.w[i]^b.w[i];return d!=0;}
static inline int sptm_root_mask_any(sptm_root_mask_t m)
{uint64_t d=0;for(unsigned i=0;i<SPTM_ROOT_MASK_WORDS;i++)d|=m.w[i];return d!=0;}
#else
#define SPTM_ROOT_STATE_COMPAT sptm_root_state
_Static_assert(__builtin_offsetof(struct sptm_root_state,switches)==3632,
               "root audit counters offset");
_Static_assert(__builtin_offsetof(struct sptm_root_state,sprr)==3672,
               "root SPRR audit offset");
typedef uint64_t sptm_root_mask_t;
#define SPTM_ROOT_MASK_HAS(m,i) ((m)&(UINT64_C(1)<<(i)))
#define SPTM_ROOT_MASK_SET(m,i) ((m)|=UINT64_C(1)<<(i))
#define SPTM_ROOT_MASK_NONE 0
#define SPTM_ROOT_MASK_ONE(i) (UINT64_C(1)<<(i))
#define SPTM_ROOT_MASK_NE(a,b) ((a)!=(b))
#define SPTM_ROOT_MASK_ANY(m) (m)
#define SPTM_ROOT_MASK_LOW(m) (m)
#endif
/* active[] tracks user roots only. SWITCH_ROOT installs the kernel root in
 * guest TTBR0 while recording active=0; a CPU not yet switched also has zero. */
static inline int sptm_root_recorded_matches(const struct sptm_root_state *s,
    unsigned cpu,uint64_t ttbr,uint64_t kernel_root)
{
    if(!s || cpu>=SPTM_ROOT_CPUS)return 0;
    uint64_t root=ttbr&UINT64_C(0x0000ffffffffc000);
    if(!s->active[cpu])return !ttbr || ttbr==kernel_root;
    return root==s->active[cpu] && root!=kernel_root;
}
/* All callbacks run with the monitor's global service token held. build may
 * change only an inactive canonical shadow. install publishes tables and
 * performs the CPU register/TLB transaction before returning. A backend with
 * TPRO enabled must derive/install a translated private CPU root from the
 * supplied canonical root; it must never install raw selector9 descriptors.
 * Installation failure is terminal and must prevent guest resumption. */
/* Optional (NULL keeps the original byte-load walk): validate each switched
 * user root with aligned 64-bit descriptor loads; 1 in 64 validations repeats
 * the byte-load walk and must agree (mismatches must stay zero). */
struct sptm_root_validate_stats {uint64_t validations,sampled,mismatches,tables;};
struct sptm_root_backend {
    uint64_t kernel_root, kernel_shadow;
    int (*build)(void *,const struct sptm_memory *,uint64_t,unsigned,unsigned,
                 uint64_t,uint64_t *,uint64_t *);
    void (*install)(void *,uint64_t,uint64_t,uint64_t,unsigned);
    void *ctx;
    struct sptm_root_validate_stats *validate;
    /* Counts cache slots taken from an inactive root when all were in use. */
    uint64_t *evictions;
    /* Optional, requires validate: retained level-3 verdicts for cache-hit
     * switches (sptm-root-memo.h). The owner must feed every published store
     * to sptm_root_memo_publish and set sptm_memory.root_memo for retypes. */
    struct sptm_root_memo *memo;
    /* Optional (SNAP_NATIVE_TABLES audit mode): asked only on a cache hit,
     * nonzero skips that switch's tree walk and the root reference identity
     * it supplies. The owner must keep the cached shadow exact by
     * construction and sample the walk (return 0) at its audit rate. Builds
     * are always walked in full. */
    int (*skip_hit_validation)(void *ctx);
#if SNAP_ROOT_MISS_FAST
    /* compat/root-miss.h. stamp: each slot's last-installation order; a full
     * cache then gives up the least recently installed inactive root (NULL:
     * round robin, as without the define). linked_builds: build() links a
     * 16K root's nested SHARED level-3 tables instead of copying them
     * (sptm_root_build_linked), so a miss's walk may answer those tables,
     * and only those, from memo. */
    const uint64_t *stamp;
    int linked_builds;
#endif
#if SNAP_USER_HW_WALK
    /* compat/user-hw-walk.h. hw_eligible: 1 when this root runs on its own
     * (format 1) tables -- no validation walk, no cache entry, no build, as
     * Apple's SWITCH_ROOT walks nothing either -- and install is then called
     * with shadow 0 for the register transaction (failure latched as
     * always); 0 takes the shadow path exactly as without the define; -1
     * refuses the switch. NULL hw_eligible is the shadow path. */
    int (*hw_eligible)(void *ctx,const struct sptm_memory *,uint64_t root,unsigned asid,
                       unsigned format,unsigned flags);
#endif
};
/* SNAP_NATIVE_SHARED (shadow/native-shared.h). A 16K root links each nested
 * guest level-2 entry -- one naming a SPTM_MAC_PAGE_TABLE_SHARED level-3
 * table -- to that table's shared 4K group instead of copying its leaves.
 * group() finds or creates the child's group (may allocate: builds and
 * prepares only) and returns its index or -1; link() links it into the
 * root's tree at va and reports its 16K leaves; linked() checks that link
 * read-only; unlink() removes it. Each returns nonzero on success. */
struct sptm_root_links {
    int (*group)(void *ctx,uint64_t child,uint64_t va);
    int (*link)(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves);
    int (*linked)(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves);
    int (*unlink)(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves);
    void *ctx;
};
/* The shared level-3 table named by 16K root `root`'s level-2 entry at va
 * (a user root nesting it, or the shared root itself), or 0. Read-only. */
uint64_t sptm_root_shared_child(const struct sptm_memory *,uint64_t root,uint64_t va);
/* sptm_root_build_shadow for a 16K root into a fresh (all-zero) tree:
 * nested entries are linked, everything else is copied as before; *leaves
 * counts both. */
int sptm_root_build_linked(const struct sptm_memory *,struct shadow *,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *);
#if SNAP_ROOT_MISS_FAST
/* The same build, its walk answering SHARED level-3 tables (the ones it
 * links) from memo when it holds their verdict; every copied table is still
 * scanned in full (compat/root-miss.h), including a shared child whose group
 * the build creates: grouped(links ctx, child, va) is nonzero only when
 * links->group will find, not create, that child's group. memo NULL builds
 * as sptm_root_build_linked; memo without grouped is refused. */
int sptm_root_build_linked_memo(const struct sptm_memory *,struct shadow *,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *,
    struct sptm_root_memo *memo,int (*grouped)(void *ctx,uint64_t child,uint64_t va));
#endif
/* NEST_REGION for a cached 16K root: the same checks as prepare/commit_nest
 * (unmapped target, every source leaf native and admitted by this root's
 * policy); prepare creates the groups and the level-2 path, commit links. */
int sptm_root_prepare_nest_linked(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    const struct sptm_root_links *);
int sptm_root_commit_nest_linked(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    const struct sptm_root_links *);
/* UNNEST_REGION: prepare checks every planned descriptor is linked and the
 * groups' leaves equal the plan's; commit (after publication) unlinks. */
struct sptm_unnest_plan;
int sptm_root_prepare_unnest_linked(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *,
    const struct sptm_root_links *);
int sptm_root_commit_unnest_linked(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *,
    const struct sptm_root_links *);
enum sptm_result sptm_mac_switch_root(const struct sptm_memory *,
    struct sptm_root_state *,const struct sptm_root_backend *,unsigned cpu,
    uint64_t root,uint64_t set_flags,uint64_t clear_flags);
#if SNAP_FINE_SWITCH
/* SNAP_FINE_SWITCH (compat/fine-lock.h, phase 1b): sptm_mac_switch_root's
 * two paths that change no cache state -- a switch to the kernel root and a
 * cache hit whose tree walk the owner skips -- for a converted call. The
 * caller holds the gate shared and the stripes of the CPU's current root
 * (if any) and of root. Returns 1 when switched exactly as
 * sptm_mac_switch_root would, 0 when declined with nothing changed: a miss,
 * an identity mismatch, a walk the owner asks for (skip_hit_validation must
 * not count: the token path asks again), any refusal (the token path repeats
 * the call and reports it). Other CPUs' converted switches write their own
 * active[] words, so every active[] word is loaded atomically, this CPU's is
 * stored with release, and the counters are atomic. Failure modes (the note's
 * F4/F7): a cache entry or validity changed under the switch (only the token
 * path writes them), the old root's activity miscounted, a hit installed
 * without its owner's stripe, a decline after install. With
 * SNAP_FINE_SWITCH_HW (compat/fine-lock.h) a third path: a hardware-walk
 * root's install when the backend's hw_eligible answers 1 without attaching
 * (the token path's branch; -1 declines, 0 is the cache-hit path). */
int sptm_mac_switch_root_hit(const struct sptm_memory *,
    struct sptm_root_state *,const struct sptm_root_backend *,unsigned cpu,
    uint64_t root,uint64_t set_flags,uint64_t clear_flags);
#endif
int sptm_root_invalidate(struct sptm_root_state *,uint64_t root,int retire);
/* Table-arena pressure, independent of the slot count. A cached shadow is
 * derived state, so an inactive root may give its tables back and rebuild
 * from its guest tables on its next switch, exactly as after a full-cache
 * eviction. Pick is read-only and returns the slot whose shadow is cheapest
 * to give back, or SPTM_ROOT_CACHE when none qualifies:
 *   1. a slot naming no root that still holds a shadow (retired/evicted);
 *   2. a named root whose entry is already invalid;
 *   3. the valid root with the smallest stamp (least recently installed;
 *      a NULL stamp array orders them round robin from the build count).
 * Never a root recorded active on any CPU and never a slot set in exclude.
 * Callers pick only between transactions: prepare/commit alias masks and
 * reservations name cached slots and must not see one disappear. */
_Static_assert(SPTM_ROOT_CACHE<=8*sizeof(sptm_root_mask_t),"reclaim exclusion mask holds every slot");
unsigned sptm_root_reclaim_pick(const struct sptm_root_state *,
    const uint64_t stamp[SPTM_ROOT_CACHE],sptm_root_mask_t exclude);
/* Make the slot indistinguishable from a never-used one (root, shadow and
 * identity cleared), so no stale shadow address can later alias a page the
 * allocator reissues to another slot, and the next build starts it fresh.
 * The caller completes the all-VMID invalidation and releases the slot's
 * tables before any reuse. Refuses an out-of-range slot or an active root. */
int sptm_root_reclaim_forget(struct sptm_root_state *,unsigned slot);
/* Reuse canonical tables while clearing every old leaf, so ASID/root recycling
 * never carries prior mappings into a new address space. A TPRO-enabled caller
 * must translate this canonical root into private views before installation. */
int sptm_root_build_shadow(const struct sptm_memory *,struct shadow *,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves);
/* Fresh active leaf insertion only. Prepare can add empty private tables;
 * commit re-walks the published guest leaf and cannot allocate. The caller
 * retains its global service token and flushes TLBs before returning to XNU. */
int sptm_root_prepare_leaf(struct sptm_root_cached *,struct shadow *,uint64_t va,unsigned shift);
int sptm_root_commit_leaf(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t va,unsigned shift,uint64_t expected);
/* Same-frame update after prepare_unmap(...,count=1) proves old source/shadow
 * agreement. Source is already published; rewrite attributes without changing
 * the cached leaf count. Caller refreshes private CPU copies and invalidates. */
int sptm_root_commit_update(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t va,unsigned shift,uint64_t old,uint64_t next);
/* Read-only proof that every installed hardware leaf still matches an
 * admitted fixed-SPRR source leaf. No affected TPRO/JIT class may be present.
 * This permits changing unused selector9 state while full TPRO translation
 * remains unsupported. Mapping/activation paths retain their class guards. */
struct sptm_fixed_view {uint64_t tables,pages,classes;};
int sptm_root_fixed_view(const struct sptm_root_cached *,const struct shadow *,
    const struct sptm_memory *,struct sptm_fixed_view *);
/* Source-to-canonical proof admitting configured, typed selector9 pages. This
 * is NOT a proof of installed Arm permissions. Those require private CPU
 * views, full path coverage and the appropriate UPERM/PPERM boundary state. */
int sptm_root_canonical_view(const struct sptm_root_cached *,const struct shadow *,
    const struct sptm_memory *,struct sptm_fixed_view *);
/* SNAP_CANONICAL_VIEW_FAST: the same proof as sptm_root_canonical_view
 * (tpro=1) or sptm_root_fixed_view (tpro=0) -- identical verdict and, on
 * success, identical tables/pages/classes -- computed with whole-table reads
 * of the canonical shadow and one source walk per source page. table(ctx,pa)
 * must return the page's 512 words exactly when every s->read of that page
 * would succeed (and return those words), NULL otherwise. */
struct sptm_view_mapped_stats {uint64_t calls,passed,leaves,walks,span_walks;};
int sptm_root_view_mapped(const struct sptm_root_cached *,const struct shadow *,
    const struct sptm_memory *,struct sptm_fixed_view *,int tpro,
    const volatile uint64_t *(*table)(void *,uint64_t),struct sptm_view_mapped_stats *);
/* Removal preflight compares every source leaf with all corresponding 4K
 * hardware leaves. Commit allocates nothing; caller must publish writes and
 * invalidate translations before releasing source/data references. */
int sptm_root_prepare_unmap(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t va,unsigned shift,uint64_t count);
int sptm_root_commit_unmap(struct sptm_root_cached *,struct shadow *,
    uint64_t va,unsigned shift,uint64_t count,uint64_t removed);
/* Detach a source allocation group. Compare whole subtrees sparsely; retain
 * private table storage but clear any commpage leaves losing their parent. */
int sptm_root_prepare_detach(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t va,unsigned shift,unsigned level,uint64_t removed);
int sptm_root_commit_detach(struct sptm_root_cached *,struct shadow *,
    uint64_t va,unsigned shift,unsigned level,uint64_t removed);
/* Attach a retained L3 commpage allocation. The whole destination must be
 * absent in source and shadow; reserve private storage before publication. */
int sptm_root_prepare_attach(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t va,unsigned shift,uint64_t child);
int sptm_root_commit_attach(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t va,unsigned shift,uint64_t child);
int sptm_root_prepare_nest(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages);
int sptm_root_commit_nest(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages);
/* Snapshot all cached roots actually aliasing the shared L3. The caller
 * serializes source/cache changes through prepare, publication and commit. */
int sptm_root_shared_aliases(const struct sptm_memory *,const struct sptm_root_state *,
    uint64_t shared,uint64_t va,unsigned shift,sptm_root_mask_t *mask);
#if SNAP_USER_HW_WALK
/* The same, where an active root with no cache entry is admitted when
 * walked(ctx, root) says the hardware walks it: it reads the shared tables
 * themselves (no shadow, no copy of a shared table), so it is no alias, and
 * the caller's TLBI (every ASID, every VMID) reaches it. */
int sptm_root_shared_aliases_hw(const struct sptm_memory *,const struct sptm_root_state *,
    uint64_t shared,uint64_t va,unsigned shift,sptm_root_mask_t *mask,
    int (*walked)(void *ctx,uint64_t root),void *ctx);
#endif
struct sptm_unnest_plan;
int sptm_root_prepare_unnest(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *);
int sptm_root_commit_unnest(struct sptm_root_cached *,struct shadow *,
    const struct sptm_memory *,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *);
