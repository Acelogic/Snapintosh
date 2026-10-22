/* SPDX-License-Identifier: MIT */
#define main baseline_view_tests
#include "test-sprr-view.c"
#undef main
#include "sprr-class-proof.h"

static struct sprr_class_proof proof;
static unsigned reads;
static int counted_read(void *ctx,uint64_t pa,uint64_t *out)
{reads++;return rd(ctx,pa,out);}
static int check(struct shadow *s,struct sprr_view_classes *out)
{return sprr_class_proof_check(&proof,s,1UL<<9,BASE,BASE+BYTES,out);}
static void change(uint64_t pa,uint64_t word)
{
    uint64_t old;CHECK(!rd(0,pa,&old));
    if(old!=word)sprr_class_proof_note(&proof,pa);
    CHECK(!wr(0,pa,word));
}
static void equivalent(struct shadow *s)
{
    struct sprr_view_classes a={0},b={0};
    memcpy(before,ram,sizeof ram);unsigned saved=writes;
    int expected=sprr_views_check_classes(s,1UL<<9,&a),actual=check(s,&b);
    CHECK(expected==actual);
    if(actual)CHECK(!memcmp(&a,&b,sizeof a));
    CHECK(saved==writes && !memcmp(before,ram,sizeof ram));
}
int main(void)
{
    CHECK(!baseline_view_tests());
    struct shadow s;setup(&s);s.read=counted_read;
    struct sprr_view_classes out;
    CHECK(sizeof proof==160+SPRR_CLASS_PROOF_PAGES/8);
    CHECK(check(&s,&out));CHECK(proof.walks==1 && proof.tracked_pages==5);
    reads=0;
    for(unsigned n=0;n<63;n++)CHECK(check(&s,&out));
    CHECK(!reads && proof.hits==63 && !proof.verified);
    CHECK(check(&s,&out));CHECK(reads==5*512 && proof.hits==64 && proof.verified==1);

    /* Every descriptor in every covered page invalidates before its store,
     * including empty entries and a mutation subsequently restored. */
    for(unsigned page=0;page<5;page++)for(unsigned i=0;i<512;i++) {
        uint64_t pa=BASE+page*4096UL+i*8UL,old;CHECK(!rd(0,pa,&old));
        change(pa,old^4);CHECK(!proof.valid);
        change(pa,old);CHECK(check(&s,&out));
    }
    uint64_t epoch=proof.epoch,old;CHECK(!rd(0,BASE,&old));
    change(BASE,old);CHECK(proof.valid && proof.epoch==epoch);
    /* Private/user/stage2 storage outside this tree does not evict it. */
    change(BASE+0xf000,3);CHECK(proof.valid && proof.epoch==epoch);
    sprr_class_proof_note(&proof,BASE-8);sprr_class_proof_note(&proof,BASE+BYTES);
    CHECK(proof.valid && proof.epoch==epoch);

    /* A new branch is untracked until its parent makes it reachable. */
    change(BASE+0x5000,DATA+3+ATTR+PT_PXN+PT_UXN);
    CHECK(proof.valid);
    change(BASE+0x2000+16,BASE+0x5000+3);CHECK(!proof.valid);
    equivalent(&s);CHECK(proof.tracked_pages==6 && proof.result.tables==6);
    change(BASE+0x5000,DATA+3+ATTR+PT_PXN+(2UL<<6)); /* forbidden class9 */
    equivalent(&s);CHECK(!proof.valid);
    change(BASE+0x5000,DATA+3+ATTR+PT_PXN+PT_UXN);equivalent(&s);
    change(BASE+0x2000+16,0);equivalent(&s);CHECK(proof.tracked_pages==5);
    epoch=proof.epoch;change(BASE+0x5000,0);CHECK(proof.epoch==epoch && proof.valid);

    /* Reachable page zeroing/recycling and pointer-based bulk transactions
     * must invalidate before bypassing the ordinary word-store callback. */
    sprr_class_proof_note(&proof,BASE+0x4000);memset(ram+0x4000,0,4096);
    CHECK(!proof.valid);equivalent(&s);
    sprr_class_proof_forget(&proof);
    put(BASE+0x3000,0,DATA+3+ATTR+PT_PXN+(2UL<<6));equivalent(&s);
    CHECK(!proof.valid && proof.wide_invalidations==1);
    put(BASE+0x3000,0,DATA+3+ATTR+PT_PXN+PT_UXN);equivalent(&s);

    /* Independent root, policy and arena identities never share a proof. */
    uint64_t walks=proof.walks;s.root=BASE+0x6000;equivalent(&s);
    CHECK(proof.walks==walks+1 && proof.tracked_pages==1 && !proof.result.pages);
    s.root=BASE;equivalent(&s);
    CHECK(!sprr_class_proof_check(&proof,&s,1UL<<3,BASE,BASE+BYTES,&out));
    CHECK(!proof.valid);equivalent(&s);
    CHECK(sprr_class_proof_check(&proof,&s,0,BASE,BASE+BYTES-4096,&out));
    CHECK(proof.forbidden==0 && proof.limit==BASE+BYTES-4096);equivalent(&s);
    CHECK(!sprr_class_proof_check(&proof,&s,1UL<<16,BASE,BASE+BYTES,&out));
    CHECK(!sprr_class_proof_check(&proof,&s,0,BASE+4096,BASE+BYTES,&out));
    CHECK(!sprr_class_proof_check(&proof,&s,0,BASE,BASE+BYTES+1,&out));
    CHECK(!sprr_class_proof_check(&proof,&s,0,BASE,BASE+4096UL*(SPRR_CLASS_PROOF_PAGES+1),&out));
    s.txsz=16;CHECK(!check(&s,&out));s.txsz=17;equivalent(&s);

    /* Sampled validation reads sources afresh and never repairs a missed
     * notification or incomplete coverage. Both cases fail closed. */
    proof.hits=63;put(BASE+0x3000,1,DATA+4096+3+ATTR+PT_PXN+(2UL<<6));
    unsigned saved=writes;CHECK(!check(&s,&out));
    CHECK(proof.mismatches==1 && !proof.valid && writes==saved);
    put(BASE+0x3000,1,DATA+4096+3+ATTR+PT_PXN+PT_UXN);equivalent(&s);
    proof.hits=127;proof.bitmap[0]&=~(1UL<<4);saved=writes;
    CHECK(!check(&s,&out));CHECK(proof.mismatches==2 && !proof.valid && writes==saved);
    equivalent(&s);proof.hits=191;read_fail=BASE+0x3000+4088;
    CHECK(!check(&s,&out));CHECK(proof.mismatches==3 && !proof.valid);
    read_fail=0;equivalent(&s);
    sprr_class_proof_forget(&proof);read_fail=BASE+4088;
    CHECK(!check(&s,&out) && !proof.valid);read_fail=0;equivalent(&s);

    /* Counts include aliased paths, bitmap contains unique pages. */
    change(BASE+0x2000+16,BASE+0x3000+3);equivalent(&s);
    CHECK(proof.result.tables==6 && proof.tracked_pages==5);
    /* Aligned blocks, cycles, malformed descriptors and upper root half. */
    change(BASE+0x2000+24,DATA+1+ATTR+PT_PXN+PT_UXN);equivalent(&s);
    change(BASE+0x1000+8,BASE+3);equivalent(&s);CHECK(!proof.valid);
    change(BASE+0x1000+8,0);equivalent(&s);
    change(BASE+0x800,BASE+0x1000+3);equivalent(&s);CHECK(!proof.valid);
    change(BASE+0x800,0);equivalent(&s);
    /* Saturation permanently disables reuse, without wrapping to an old key. */
    proof.epoch=UINT64_MAX-1;proof.saved_epoch=proof.epoch;
    sprr_class_proof_note(&proof,BASE);CHECK(proof.epoch==UINT64_MAX && !proof.valid);
    uint64_t hits=proof.hits;walks=proof.walks;
    for(unsigned i=0;i<3;i++) {
        CHECK(check(&s,&out));CHECK(!proof.valid && proof.epoch==UINT64_MAX);
        sprr_class_proof_forget(&proof);
    }
    CHECK(proof.hits==hits && proof.walks==walks+3);
    printf("SPRR canonical class proof: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}
