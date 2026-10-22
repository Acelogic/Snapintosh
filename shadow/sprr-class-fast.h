/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-class-proof.h"
#include "../compat/audit-sparse.h"

/* SNAP_KERNEL_PPERM_FAST: the TPRO preflight's whole-tree kernel class proof,
 * made incremental. Host replay: tools/test-kernel-pperm-fast.{c,py}.
 *
 * In installed-fresh v33 the kernel PPERM changes held the service lock for
 * 173.5 s of 1800 s (679,190 changes, 255 us each). About 166 s of it was this
 * proof: 16,316 full mapped walks of the ~5,200-table canonical kernel tree
 * (about 8.5 ms each) after a write had invalidated the cached result, plus
 * 1,875 sampled hit verifications through the per-word reader (about 15 ms
 * each). Everything else in a change (snapshot check, variant swap, TTBR1,
 * local TLBI and their sampled audits) was about 6.5 us.
 *
 * A miss now reuses the level-3 summary of every table whose table-memo write
 * generation is unchanged since it was scanned (sprr-class-leaf-memo.h) and
 * rescans levels 0-2 and every changed table. A sampled hit verification
 * re-walks the whole tree through one refusing mapping per table instead of
 * one callback per word. Everything else is the cached proof unchanged:
 * same hit rule, same 1 in 64 hit cadence, same coverage bitmap, same totals,
 * same refusals, same terminal mismatches.
 *
 * Failure modes, written before the code (each has a weakened version in
 * tools/test-kernel-pperm-fast.{c,py} that must fail):
 *
 * 1. A stale level-3 summary: a table changed by a path that did not advance
 *    its write generation, so a class9 leaf (or any other change) is hidden.
 *    Guard: a summary is used only for an allocator-issued page with a nonzero
 *    generation equal to the one recorded when it was scanned. Every arena
 *    write path notes the page first: mem_write before a changed store,
 *    table_alloc_owned before zeroing, sptm_shadow_map for every page an SPTM
 *    transaction may store through (source check). Proofs run only at the top
 *    of a PPERM write or SWITCH_ROOT's install, never between a mapped
 *    pointer's note and its store (call-graph source check). One incremental
 *    walk in 64 rescans every level-3 table and compares it with any summary;
 *    a mismatch poisons the cache, and every later proof, hits included,
 *    refuses: terminal, never repaired.
 * 2. A summary trusted where it does not apply: at another level, for a page
 *    never issued by the allocator (directly carved storage is not noted), or
 *    after the generation source restarted. Guard (leaf memo): only a level-3
 *    traversal consults summaries; only pool pages with a nonzero generation;
 *    the cache resets when the arena identity changes or the clock regresses;
 *    the requested forbidden mask is rechecked against every summary.
 * 3. A structural change hidden by the summaries: a new or removed branch, an
 *    alias, a cycle, the 8,192-table limit, a root upper-half entry, a
 *    misaligned block. Guard: levels 0-2 are rescanned on every walk and every
 *    edge is followed in the original order with the original path and count
 *    checks; only level-3 content is summarized.
 * 4. Incomplete coverage: a summarized table left out of the proof's bitmap,
 *    so a later store to it would not invalidate the cached result. Guard: the
 *    marking mapping runs for every table a miss visits, summarized or not.
 * 5. A weaker hit verification. Guard: the verification walk reads every word
 *    of every table, never consults a summary (so it is independent of 1), and
 *    its mapping refuses a page outside the recorded coverage instead of
 *    marking it: the page-uniform form of the word reader's verify mode (the
 *    monitor's word reader fails only on the allocation bound, alike for every
 *    word of a page). Tables, pages and classes must all equal the saved
 *    result; a difference is a terminal mismatch exactly as before.
 * 6. Drift from the current proof. Guard: with every store made through the
 *    monitor's note paths, the whole proof state (counters, epoch, validity,
 *    coverage bitmap, saved result) and every verdict and output must equal
 *    the production proof's (mapped misses, word-verified hits) after every
 *    operation.
 * 7. A refusal that leaves something behind. Guard: a failed walk writes no
 *    output, leaves the proof invalid and saves no summary of a table that
 *    did not scan clean.
 * 8. Layout or default build. Guard: no context field is added (class_leaf
 *    and table_memo are in every build); the default builds stay byte-identical.
 * 9. Canonical memory. Guard: nothing here stores to a table; the only writes
 *    are this proof's state and the class_leaf entries.
 */

/* sprr_class_proof_map's verify form: the same bounds, but a page outside the
 * recorded coverage is refused, never marked. */
static inline const volatile uint64_t *sprr_class_proof_map_verify(void *ctx,uint64_t pa)
{
    struct sprr_class_proof_map_reader *r=ctx;const struct sprr_class_proof *p=r->proof;
    if((pa&4095) || pa<p->first || pa>=p->limit || p->limit-pa<4096)return 0;
    uint64_t page=(pa-p->first)>>12;
    if(page>=SPRR_CLASS_PROOF_PAGES || !(p->bitmap[page/64]&(1UL<<(page%64))))return 0;
    return r->base(r->base_ctx,pa);
}
/* sprr_class_proof_check_leaf with leaf summaries on a miss and a mapped,
 * refusing re-walk on every 64th hit (every 1024th with SNAP_AUDIT_SPARSE,
 * compat/audit-sparse.h). map is the monitor's whole-page reader
 * (class_table_read); generations is the table memo the leaf cache follows. */
static inline int sprr_class_proof_check_fast(struct sprr_class_proof *p,
    const struct shadow *s,uint64_t forbidden,uint64_t first,uint64_t limit,
    struct sprr_view_classes *out,sprr_table_reader map,void *map_ctx,
    struct sprr_class_walk_stats *walk,struct sprr_class_leaf_cache *leaf,
    const struct sprr_table_memo *generations)
{
    if(!p)return 0;
    p->calls++;
    if(!leaf || !generations || !map || !walk || leaf->stats.poisoned) {
        p->errors++;p->valid=0;return 0;
    }
    if(!s || !s->read || !out || s->txsz!=17 || (forbidden&~0xffffUL) ||
       !first || ((first|limit)&4095) || first>=limit ||
       limit-first>4096UL*SPRR_CLASS_PROOF_PAGES ||
       s->root<first || s->root>=limit || (s->root&4095)) {
        p->errors++;p->valid=0;return 0;
    }
    int hit=p->valid && p->epoch!=UINT64_MAX && p->saved_epoch==p->epoch &&
        p->root==s->root && p->forbidden==forbidden && p->first==first && p->limit==limit;
    if(hit)p->hits++;
    if(hit && (p->hits&AUDIT_SAMPLE_MASK)) {*out=p->result;return 1;}
    if(hit)p->verified++;
    else {
        p->valid=0;p->root=s->root;p->forbidden=forbidden;p->first=first;p->limit=limit;
        p->tracked_pages=0;
        volatile uint64_t *bits=p->bitmap;
        for(unsigned i=0;i<SPRR_CLASS_PROOF_PAGES/64;i++)bits[i]=0;
    }
    struct sprr_class_proof_map_reader mapped={p,map,map_ctx};
    struct shadow direct={.txsz=17,.root=s->root,.ctx=&mapped};
    struct sprr_view_classes full;
    /* The verification walk's own counts stay out of walk (misses only). */
    struct sprr_class_walk_stats audit={0};
    int walked=hit ?
        sprr_views_check_classes_mapped(&direct,forbidden,&full,sprr_class_proof_map_verify,&audit) :
        sprr_class_leaf_check(leaf,&direct,forbidden,generations,&full,sprr_class_proof_map,walk);
    if(!walked ||
       (hit && (full.tables!=p->result.tables || full.pages!=p->result.pages ||
                full.classes!=p->result.classes))) {
        if(hit)p->mismatches++;
        p->errors++;p->valid=0;return 0;
    }
    if(!hit) {
        p->result=full;p->saved_epoch=p->epoch;p->walks++;
        p->valid=p->epoch!=UINT64_MAX;
    }
    *out=full;return 1;
}
