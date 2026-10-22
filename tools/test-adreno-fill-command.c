/* SPDX-License-Identifier: MIT */
/* Written before the command decoder/resolver. Actual list parser, ownership,
 * cache transport and CP/SMMU model; native IOGPU retain/prepare are fixtures. */
#define ADRENO_FILL_TEST_ENTRY fill_transport_main
#include "test-adreno-fill.c"
#include "adreno-fill-command.h"

static struct adreno_resource destination;
static struct adreno_resource_list resources;
static struct adreno_resource_entry entries[6];
static unsigned retains, prepares, completes, releases, transfers, syncs[3];
static int fail_visibility;
static unsigned char wire_list[96], wire_copy[96], wire_command[32];

static void invalidate_cpu(void *ctx,uint64_t pa,uint64_t bytes)
{
    (void)ctx;
    uint64_t first=ram_offset(pa,bytes)/64, last=ram_offset(pa+bytes-1,1)/64;
    for (uint64_t line=first;line<=last;line++) {
        CHECK(!dirty[line]); /* TO_DEVICE must already have published dirty CPU data. */
        cached[line]=0;
    }
}

static void put32(unsigned char *p, uint32_t x)
{ for (unsigned i=0;i<4;i++) p[i]=(unsigned char)(x>>(i*8)); }
static void put64(unsigned char *p, uint64_t x)
{ for (unsigned i=0;i<8;i++) p[i]=(unsigned char)(x>>(i*8)); }
static void *own(void *ctx, uint32_t id)
{ (void)ctx; if (id!=7) return 0; retains++; return &destination; }
static void disown(void *ctx, void *resource)
{ (void)ctx; CHECK(resource==&destination); releases++; }
static int prepare(void *ctx, void *resource, void **token)
{ (void)ctx; CHECK(resource==&destination); prepares++; *token=resource; return 0; }
static void complete(void *ctx, void *token)
{ (void)ctx; CHECK(token==&destination); completes++; }
static int cache_range(void *ctx, uint64_t address, uint64_t bytes, unsigned direction)
{
    (void)ctx;
    uint64_t regs[]={ADRENO_GUEST_CACHE,address,bytes,direction};
    return adreno_guest_cache(&fill_ops,&P,&S,regs,dart_leaf,0,MEM_LOW,MEM_HIGH);
}
static int synchronize(void *ctx, void *token, unsigned direction)
{
    (void)ctx; CHECK(direction<=2); syncs[direction]++;
    if (direction==2 && fail_visibility) return -1;
    return adreno_resource_cache(token,direction,cache_range,0);
}
static const struct adreno_resource_list_ops list_ops={0,own,disown,prepare,complete,synchronize};
static int resolve(void *ctx, void *resource, void *token,
                   uint64_t offset,uint64_t bytes,uint64_t *address)
{
    (void)ctx; CHECK(resource==&destination && token==&destination);
    return adreno_fill32_resource_range(token,offset,bytes,address);
}
static int transfer(void *ctx,uint64_t address,uint64_t bytes,uint32_t pattern)
{
    (void)ctx; transfers++;
    uint64_t regs[]={ADRENO_GUEST_FILL32,address,bytes,pattern};
    int result=adreno_guest_fill32(&fill_ops,&P,&S,regs,dart_leaf,0,MEM_LOW,MEM_HIGH);
    if (!result && regs[1]!=bytes) return ADRENO_FILL32_E_UNCERTAIN;
    return result;
}
static void command(uint32_t id,uint64_t offset,uint64_t bytes,uint32_t pattern)
{
    put32(wire_command,ADRENO_KCMD_FILL32); put32(wire_command+4,32);
    put32(wire_command+8,id); put32(wire_command+12,pattern);
    put64(wire_command+16,offset); put64(wire_command+24,bytes);
}
static int submit(void)
{
    struct adreno_fill32_request request;
    int result=adreno_fill32_decode(wire_command,sizeof wire_command,&request);
    return result ? result : adreno_fill32_submit(&resources,&list_ops,&request,resolve,transfer,0);
}
static void setup_command(void)
{
    setup_fill();
    fill_ops.invalidate=invalidate_cpu;
    destination=(struct adreno_resource){ADRENO_WINDOW_BASE,0x8000,0x8000,0x8000,
        ADRENO_RESOURCE_RESERVED|ADRENO_RESOURCE_PINNED};
    resources=(struct adreno_resource_list){0};
    memset(entries,0,sizeof entries); memset(wire_list,0,sizeof wire_list);
    retains=prepares=completes=releases=transfers=fail_visibility=0;
    memset(syncs,0,sizeof syncs);
    put32(wire_list+28,1); put32(wire_list+32,7); put32(wire_list+36,7);
    wire_list[80]=1; wire_list[82]=2; wire_list[94]=2;
    CHECK(adreno_resource_list_acquire(&resources,wire_list,sizeof wire_list,
        wire_copy,sizeof wire_copy,entries,6,&list_ops)==0);
    CHECK(adreno_resource_list_prepare(&resources,&list_ops)==0);
    command(7,0x3f00,0x4000,0xff00ff00);
}
static void test_command_path(void)
{
    setup_command();
    CHECK(submit()==0);
    CHECK(transfers==1 && cp_target_writes==4096 && cpu_destination_stores==0);
#if ADRENO_CACHE_SPARSE
    /* Sparse (agents/cache-maint FAILURE-MODES.md C13): both entries validated; the fill's one map (listed twice)
     * is cleaned and invalidated once. With no list cache callbacks here, over its whole extent. */
    CHECK(syncs[0]==2 && syncs[1]==1 && syncs[2]==1);
#else
    /* Design 3.5: every entry is cleaned TO_DEVICE; only the Write-usage entry is invalidated FROM_DEVICE. */
    CHECK(syncs[0]==2 && syncs[1]==2 && syncs[2]==1);
#endif
    unsigned wrong=0;
    for (uint64_t offset=0;offset<GUEST_SIZE;offset+=4) {
        int changed=(offset>=0x3f00 && offset<0x4000) || (offset>=0xc000 && offset<0xff00);
        wrong+=m_rd(0,GUEST_PAGE+offset)!=(changed ? 0xff00ff00 : 0xa55aa55a);
    }
    CHECK(!wrong);
    save_model_artifact("command-model-gpu-destination.bin",GUEST_PAGE,GUEST_SIZE);
    save_model_artifact("command-model-submitted-ring.bin",RING+22*4,(4096+7)*4);
    CHECK(adreno_resource_list_release(&resources,&list_ops)==0);
    CHECK(retains==2 && prepares==2 && completes==2 && releases==2);
}
static void test_command_refusals(void)
{
    for (unsigned bad=0;bad<18;bad++) {
        setup_command();
        switch (bad) {
        case 0: put32(wire_command+8,8); break;
        case 1: entries[1].usage=1; break;
        case 2: resources.ready|=ADRENO_LIST_FROZEN; break;
        case 3: resources.ready=ADRENO_LIST_READY; break;
        case 4: resources.prepared_count--; break;
        case 5: entries[1].preparation=0; break;
        case 6: entries[1].resource=&resources; break;
        case 7: entries[1].preparation=&resources; break;
        case 8: destination.flags|=ADRENO_RESOURCE_FAILED; break;
        case 9: destination.mapped_length-=0x4000; break;
        case 10: destination.logical_length=0x4000; break;
        case 11: command(7,UINT64_MAX-3,16,0); break;
        case 12: destination.address=ADRENO_WINDOW_END-0x4000; break;
        case 13: command(7,1,4,0); break;
        case 14: command(7,0,3,0); break;
        case 15: command(7,0,0,0); break;
        case 16: command(7,0,ADRENO_FILL32_MAX_BYTES+4,0); break;
        case 17: put32(wire_command+8,0); break;
        }
        unsigned before=nlog;
        CHECK(submit()<0);
        CHECK(!transfers && !syncs[0] && !syncs[1] && !cp_target_writes && before==nlog);
        /* The fixtures reset after a refusal; only a real successful release
         * above or preserved frozen ownership below is called lifetime proof. */
    }
    for (unsigned n=0;n<32;n++) {
        setup_command(); struct adreno_fill32_request request;
        CHECK(adreno_fill32_decode(wire_command,n,&request)==ADRENO_SUBMIT_E_FORMAT);
        CHECK(!transfers);
    }
    setup_command(); put32(wire_command+4,36);
    CHECK(submit()==ADRENO_SUBMIT_E_FORMAT && !transfers);
    setup_command(); put32(wire_command,0xffffffffu);
    CHECK(submit()==ADRENO_SUBMIT_E_COMMAND && !transfers);
    setup_command(); destination.logical_length--;
    CHECK(submit()==ADRENO_LIST_E_CACHE && !transfers && !syncs[1]);
}
static void test_command_retirement(void)
{
    setup_command(); r.rptr--;
    CHECK(submit()==ADRENO_SUBMIT_E_INACTIVE && transfers==1 && !cp_target_writes);
    CHECK(!(resources.ready&ADRENO_LIST_FROZEN));
    CHECK(adreno_resource_list_release(&resources,&list_ops)==0);
    for (unsigned bad=0;bad<3;bad++) {
        setup_command();
        if (bad==0) cp_mode=1;
        if (bad==1) cp_mode=3;
        if (bad==2) fail_visibility=1;
        int result=submit();
        CHECK(result==(bad==2 ? ADRENO_LIST_E_VISIBILITY : ADRENO_SUBMIT_E_UNCERTAIN));
        CHECK(resources.ready&ADRENO_LIST_FROZEN);
        CHECK(adreno_resource_list_release(&resources,&list_ops)==ADRENO_LIST_E_BUSY);
        CHECK(completes==0 && releases==0 && resources.prepared_count==2);
        unsigned before=transfers;
        CHECK(submit()<0 && transfers==before);
    }
}
/* Design 3.5 / R4, written before the fix: FROM_DEVICE (an invalidate) belongs only to resources the GPU
 * writes. Failure inventory: (1) a read-only resource that another CPU thread writes while the GPU works loses
 * that store to the post-completion invalidate (the model's invalidate CHECKs dirty lines); (2) a read-only
 * resource the DART maps GPU-read-only makes the monitor refuse FROM_DEVICE (adreno.c: no-write leaf), which
 * returns VISIBILITY, freezes the list and latches the GPU off; (3) the Write entry must still be invalidated. */
static struct adreno_resource usage_writer, usage_reader;
static unsigned usage_syncs[3];
static uint64_t usage_store_pa;
static void *usage_own(void *ctx, uint32_t id)
{ (void)ctx; return id==7 ? (void *)&usage_writer : id==8 ? (void *)&usage_reader : 0; }
static void usage_disown(void *ctx, void *resource)
{ (void)ctx; CHECK(resource==&usage_writer || resource==&usage_reader); }
static int usage_prepare(void *ctx, void *resource, void **token) { (void)ctx; *token=resource; return 0; }
static void usage_complete(void *ctx, void *token) { (void)ctx; (void)token; }
static int usage_sync(void *ctx, void *token, unsigned direction)
{
    (void)ctx; CHECK(direction<=2); usage_syncs[direction]++;
    return adreno_resource_cache(token,direction,cache_range,0);
}
static const struct adreno_resource_list_ops usage_ops={0,usage_own,usage_disown,usage_prepare,usage_complete,usage_sync};
static int usage_store_during_gpu_work(void *ctx)
{
    (void)ctx;
    if (usage_store_pa) m_wr(0,usage_store_pa,0x600dcafe);   /* another CPU thread, same cache */
    return 0;
}
static void usage_list(struct adreno_resource_list *list,struct adreno_resource_entry *slots,
                       unsigned char *wire,unsigned char *copy)
{
    memset(wire,0,96);
    put32(wire+28,1); put32(wire+32,7); put32(wire+36,8);
    wire[80]=2;                                /* id 7: MTLResourceUsageWrite (the fill destination page) */
    wire[82]=1;                                /* id 8: MTLResourceUsageRead */
    wire[94]=2;
    *list=(struct adreno_resource_list){0};
    CHECK(adreno_resource_list_acquire(list,wire,96,copy,96,slots,6,&usage_ops)==0);
    CHECK(adreno_resource_list_prepare(list,&usage_ops)==0);
}
static void test_usage_cache_ownership(void)
{
    struct adreno_resource_list list;
    struct adreno_resource_entry slots[6];
    unsigned char wire[96],copy[96];
    for (unsigned read_only_leaf=0;read_only_leaf<2;read_only_leaf++) {
        setup_fill();
        fill_ops.invalidate=invalidate_cpu;
        if (read_only_leaf) {
            dart[0]=dart_desc(GUEST_PAGE,0,0x4000,1,0);            /* GPU-read-only DART leaf */
            CHECK(mirror(ADRENO_WINDOW_BASE,0x4000)==0);
        }
        usage_reader=(struct adreno_resource){ADRENO_WINDOW_BASE,0x4000,0x4000,0x4000,
            ADRENO_RESOURCE_RESERVED|ADRENO_RESOURCE_PINNED};
        usage_writer=(struct adreno_resource){ADRENO_WINDOW_BASE+0x4000,0x4000,0x4000,0x4000,
            ADRENO_RESOURCE_RESERVED|ADRENO_RESOURCE_PINNED};
        memset(usage_syncs,0,sizeof usage_syncs);
        usage_store_pa=read_only_leaf ? 0 : GUEST_PAGE+0x140;
        usage_list(&list,slots,wire,copy);
        CHECK(adreno_resource_list_submit(&list,&usage_ops,usage_store_during_gpu_work,0)==0);
        CHECK(usage_syncs[0]==2 && usage_syncs[1]==2 && usage_syncs[2]==1);
        CHECK(!(list.ready&ADRENO_LIST_FROZEN));
        if (!read_only_leaf) CHECK(m_rd(0,usage_store_pa)==0x600dcafe);
        CHECK(adreno_resource_list_release(&list,&usage_ops)==0);
    }
}
static void read_exact(const char *path,void *bytes,size_t count)
{
    FILE *file=fopen(path,"rb");
    if (!file || fread(bytes,1,count,file)!=count || fgetc(file)!=EOF) {
        fprintf(stderr,"Invalid native Metal artifact: %s\n",path); exit(2);
    }
    CHECK(fclose(file)==0);
}
static int native_fence_calls;
static int parsed_native_fence(void *context)
{
    (void)context; native_fence_calls++; return 0;
}
static void test_native_metal_payload(void)
{
    const char *payload=getenv("SNAP_METAL_FILL_DESCRIPTORS");
    const char *commands=getenv("SNAP_METAL_FILL_COMMANDS");
    if (!payload && !commands) return;
    if (!payload || !commands) exit(2);
    setup_command();
    CHECK(adreno_resource_list_release(&resources,&list_ops)==0);
    resources=(struct adreno_resource_list){0};
    memset(entries,0,sizeof entries);
    retains=prepares=completes=releases=0;
    unsigned char stream[40];
    read_exact(payload,wire_list,sizeof wire_list);
    read_exact(commands,stream,sizeof stream);
    memcpy(wire_command,stream,sizeof wire_command);
    struct adreno_fill32_request request;
    CHECK(adreno_fill32_decode(stream,sizeof stream,&request)==0);
    CHECK(request.resource_id==7 && request.offset==0x3f00 &&
          request.bytes==0x4000 && request.pattern==0x3c3c3c3c);
    CHECK(adreno_resource_list_acquire(&resources,wire_list,sizeof wire_list,
        wire_copy,sizeof wire_copy,entries,6,&list_ops)==0);
    CHECK(adreno_resource_list_prepare(&resources,&list_ops)==0);
    CHECK(submit()==0);
    CHECK(transfers==1 && cp_target_writes==4096 && cpu_destination_stores==0);
    CHECK(syncs[0]==1 && syncs[1]==1 && syncs[2]==1);
    unsigned wrong=0;
    for (uint64_t offset=0;offset<GUEST_SIZE;offset+=4) {
        int changed=(offset>=0x3f00 && offset<0x4000) ||
                    (offset>=0xc000 && offset<0xff00);
        wrong+=m_rd(0,GUEST_PAGE+offset)!=(changed ? 0x3c3c3c3c : 0xa55aa55a);
    }
    CHECK(!wrong);
    save_model_artifact("native-metal-gpu-destination.bin",GUEST_PAGE,GUEST_SIZE);
    save_model_artifact("native-metal-submitted-ring.bin",RING+22*4,(4096+7)*4);
    /* The fill includes its real modeled GPU marker/RPTR completion. This
     * callback checks only the final native command's dispatch/size; it is
     * deliberately not called a second physical or modeled GPU fence. */
    CHECK(adreno_submit_command(stream+32,8,parsed_native_fence,0)==0);
    CHECK(native_fence_calls==1);
    CHECK(adreno_resource_list_release(&resources,&list_ops)==0);
    CHECK(retains==1 && prepares==1 && completes==1 && releases==1);
    puts("NATIVE_METAL_FILL_MODEL_PASS: production Metal bytes, native resource packing, actual driver parser/cache/fill, modeled GPU readback and canaries");
}
#ifndef ADRENO_FILL_COMMAND_TEST_ENTRY
#define ADRENO_FILL_COMMAND_TEST_ENTRY main
#endif
int ADRENO_FILL_COMMAND_TEST_ENTRY(void)
{
    if (fill_transport_main()) return 1;
    checks=failures=0;
    dram=calloc(1,RAM_SIZE); cache=calloc(1,RAM_SIZE);
    if (!dram || !cache) return 2;
    test_command_path(); test_command_refusals(); test_command_retirement();
    test_usage_cache_ownership();
    test_native_metal_payload();
    free(dram); free(cache);
    printf("%s: %u fill command path checks; resource IDs, preparation, cache ownership, GPU bytes and uncertain retirement\n",
           failures ? "FAIL" : "PASS",checks);
    return failures ? 1 : 0;
}
