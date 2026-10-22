/* SPDX-License-Identifier: MIT */
#define SPTM_SHARED_PAGE_TEST_MAIN shared_page_fixture_tests
#include "test-shared-page.c"
#define LIST (BASE+191*PAGE)
#define SCRATCH (BASE+PAGE)
static uint64_t prepared_va;
static int shared_prepare_batch(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    prepared_va=va;
    return prepare_shared_unmap(ctx,root,va,shift,count);
}
static int shared_commit_batch(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    CHECK(va==prepared_va);
    return commit_shared_unmap(ctx,root,va,shift,count,removed);
}
static int resolve_batch(void *ctx,uint64_t root,struct sptm_user_backend *out)
{(void)ctx;if(root!=ROOT)return 0;*out=backend;return 1;}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned active=0;active<=6;active+=6)
    for(unsigned aliases=0;aliases<=2;aliases++) {
        init(fmt,active,aliases);
        uint64_t va=START+geom.page_size,old=DATA|0x00600000000006c3UL,result;
        for(unsigned i=0;i<2;i++) {
            CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va+i*geom.page_size,old,0,OUT,&result));
            setword(LIST+i*24,ROOT);setword(LIST+i*24+8,va+i*geom.page_size);
            setword(LIST+i*24+16,0);
        }
        backend.prepare_shared_unmap=shared_prepare_batch;
        backend.commit_shared_unmap=shared_commit_batch;
        struct sptm_shared_update_state witness={0};
        CHECK(!sptm_mac_unmap_user_disjoint(&m,resolve_batch,0,DATA,LIST,2,SCRATCH,&witness));
        CHECK(word(SCRATCH)==old && word(SCRATCH+8)==old && witness.latest.changed==2);
        CHECK(!word(m.frame_map_pa+((DATA-BASE)>>14)*16+8));
        verify_leaf(va,0);verify_leaf(va+geom.page_size,0);
        CHECK(commits==4 && flushes==4);
        CHECK(witness.changed.root==ROOT && witness.changed.va==va+geom.page_size);
        init(fmt,active,aliases);
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,old,0,OUT,&result));
        setword(LIST,ROOT);setword(LIST+8,va);setword(LIST+16,0);
        backend.prepare_shared_unmap=shared_prepare_batch;
        backend.commit_shared_unmap=shared_commit_batch;
        if(aliases) {
            memcpy(saved,bytes,sizeof(bytes));fail_alias=prepare_count+1;
            CHECK(sptm_mac_unmap_user_disjoint(&m,resolve_batch,0,DATA,LIST,1,SCRATCH,&witness)==SPTM_SHADOW_FAILED);
            CHECK(!memcmp(saved,bytes,sizeof(bytes)));
            verify_leaf(va,old);
        }
    }
    printf("shared UNMAP_DISJOINT: %u checks passed\n",checks);
    return 0;
}
