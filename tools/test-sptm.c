/* SPDX-License-Identifier: MIT */
/* cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
 *    -Icompat tools/test-sptm.c compat/sptm.c -o build/test-sptm */
#include <stdio.h>
#include <string.h>
#include "sptm.h"

#define BASE 0x90000000UL
#define SIZE 0x20000UL
#define MAP (BASE + 0x1000)
#define PAGE (BASE + 0x8000)
static uint8_t ram[SIZE], before[SIZE];
static unsigned checks, failures, published, mappings;
static uint64_t unavailable;
static uint8_t target_type;
static uint8_t target_level;
static uint16_t target_asid;
static uint8_t target_flags;
static uint8_t target_format;
static int root_busy;
static unsigned retired;
static unsigned aperture_calls;
static int aperture_failure;

static void check(int ok, const char *label)
{
    checks++;
    if (!ok) { failures++; printf("FAIL: %s\n", label); }
}

static int retire_root(void *ctx, uint64_t pa, uint16_t asid)
{
    (void)ctx;
    check(pa == PAGE && asid == target_asid, "host retires exact root and ASID");
    check(!published, "retirement precedes metadata publication");
    if (root_busy) return 0;
    retired++;
    return 1;
}

static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    mappings++;
    if (pa == unavailable || pa < BASE || pa >= BASE + SIZE || size > BASE + SIZE - pa)
        return NULL;
    return ram + (pa - BASE);
}

static void publish(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    uint64_t entry = MAP - BASE + ((PAGE - BASE) >> 14) * 16;
    if ((target_type == SPTM_MAC_PAGE_TABLE || target_type == SPTM_MAC_PAGE_TABLE_ROZONE ||
         target_type == SPTM_MAC_PAGE_TABLE_COMMPAGE ||
         target_type == SPTM_MAC_USER_ROOT_TABLE) && !published) {
        check(pa == PAGE && size == SPTM_MAC_FRAME_SIZE, "page published first");
        check(ram[entry + 2] == 11, "type unchanged until page published");
        uint8_t dirty = 0;
        for (unsigned i = 0; i < SPTM_MAC_FRAME_SIZE; i++) dirty |= ram[PAGE - BASE + i];
        check(!dirty, "every table byte zero before publication");
    } else {
        check(pa == BASE + entry && size == 16, "shared metadata published second");
        check(ram[entry + 2] == target_type, "guest-visible type committed");
        if (target_type == SPTM_MAC_USER_ROOT_TABLE) {
            uint8_t expected[12] = {(uint8_t)target_asid, (uint8_t)(target_asid >> 8),
                                   0, 0, 0xff, 0, target_flags, 0, target_format, 0, 0, 0};
            check(!memcmp(ram + entry + 4, expected, 12), "audited root metadata is published");
        } else {
            uint8_t dirty = 0;
            for (unsigned i = 5; i < 16; i++) dirty |= ram[entry+i];
            check(ram[entry+4] == target_level, "page-table level stored in shared metadata");
            check(!dirty, "old-type private metadata reset before publication");
        }
    }
    published++;
}

static int retype_rozone(void *ctx,uint64_t pa,uint64_t old,uint64_t next_type)
{
    (void)ctx;aperture_calls++;
    uint64_t entry=MAP-BASE+((PAGE-BASE)>>14)*16;
    check(pa==PAGE && ram[entry+2]==old,"aperture transaction sees old frame type");
    check(!published,"aperture transaction precedes type publication");
    check(next_type==target_type,"aperture transaction names requested type");
    return !aperture_failure;
}
static struct sptm_memory reset(void)
{
    memset(ram, 0xa5, sizeof(ram));
    for (unsigned n = 0; n < SIZE / SPTM_MAC_FRAME_SIZE; n++) {
        uint8_t *entry = ram + 0x1000 + 16*n;
        memset(entry, 0, 16);
        entry[2] = 11;
        entry[5] = 0xa5;   /* old-type private state that must be cleared */
    }
    memcpy(before, ram, SIZE);
    published = mappings = 0;
    unavailable = 0;
    target_type = SPTM_MAC_PAGE_TABLE;
    target_level = 0;
    target_flags = 2;
    target_format = 0;
    root_busy = retired = 0;
    aperture_calls=0;aperture_failure=0;
    return (struct sptm_memory){.frame_map_pa = MAP, .frame_low = BASE,
        .frame_high = BASE + SIZE, .alloc_low = PAGE, .alloc_high = BASE + SIZE,
        .map = map, .publish = publish,.retype_rozone=retype_rozone};
}

static void rejected(struct sptm_memory *m, uint64_t pa, uint64_t old,
                     uint64_t new_type, uint64_t opts, enum sptm_result want)
{
    check(sptm_mac_retype(m, pa, old, new_type, opts) == want, "correct rejection reason");
    check(!memcmp(ram, before, SIZE), "rejected operation changed no memory");
    check(!published, "rejected operation published nothing");
}

int main(void)
{
    struct sptm_memory m = reset();
    check(sptm_mac_retype(&m, PAGE, 11, 20, 0) == SPTM_OK, "bootstrap retype succeeds");
    check(published == 2, "exactly two publications");
    uint64_t entry = MAP - BASE + ((PAGE - BASE) >> 14) * 16;
    memset(before + (PAGE - BASE), 0, SPTM_MAC_FRAME_SIZE);
    before[entry + 2] = 20;
    memset(before + entry + 4, 0, 12);
    check(!memcmp(ram, before, SIZE), "only the target page, type and private metadata changed");
    /* Replaying a successful call must not clear a now-live table. */
    ram[PAGE - BASE + 13] = 0x5a;
    memcpy(before, ram, SIZE);
    published = 0;
    rejected(&m, PAGE, 11, 20, 0, SPTM_TYPE_MISMATCH);

    const unsigned data_types[]={SPTM_MAC_KERNEL_RESTRICTED, SPTM_MAC_ROZONE};
    for (unsigned n=0;n<sizeof(data_types)/sizeof(*data_types);n++) {
        unsigned type=data_types[n];
        m = reset(); target_type = type;
        check(sptm_mac_retype(&m, PAGE, 11, type, 0) == SPTM_OK, "audited data retype succeeds");
        check(published == 1, "data retag publishes metadata only");
        before[entry+2] = type; memset(before + entry + 4, 0, 12);
        check(!memcmp(ram, before, SIZE), "data retag preserves payload and other frames");
        published = 0; target_type = SPTM_MAC_DEFAULT;
        check(sptm_mac_retype(&m, PAGE, type, 11, 0) == SPTM_OK,
              "unreferenced data page can return to allocator");
        before[entry+2] = 11;
        check(!memcmp(ram, before, SIZE), "releasing data preserves payload");
        check(aperture_calls==(type==SPTM_MAC_ROZONE ? 2u : 0u),
              "ROZONE acquisition and release both complete the aperture transaction");
    }
    m=reset();target_type=SPTM_MAC_ROZONE;m.retype_rozone=0;
    rejected(&m,PAGE,11,25,0,SPTM_BAD_CONFIG);
    m=reset();target_type=SPTM_MAC_ROZONE;aperture_failure=1;
    rejected(&m,PAGE,11,25,0,SPTM_SHADOW_FAILED);
    check(aperture_calls==1,"failed aperture transaction preserves frame metadata");

    const unsigned table_types[]={SPTM_MAC_PAGE_TABLE, SPTM_MAC_PAGE_TABLE_ROZONE};
    m=reset();target_type=SPTM_MAC_PAGE_TABLE_COMMPAGE;target_level=3;
    check(sptm_mac_retype(&m,PAGE,11,target_type,3)==SPTM_OK,"allocate a commpage leaf table");
    check(published==2,"commpage table payload precedes type publication");
    memset(before+(PAGE-BASE),0,SPTM_MAC_FRAME_SIZE);
    before[entry+2]=target_type;memset(before+entry+4,0,12);before[entry+4]=3;
    check(!memcmp(before,ram,SIZE),"commpage table has zeroed payload and level-three metadata");
    published=0;
    rejected(&m,PAGE,target_type,11,0,SPTM_UNSUPPORTED_RETYPE);
    for(unsigned level=0;level<=4;level++) if(level!=3) {
        m=reset();rejected(&m,PAGE,11,SPTM_MAC_PAGE_TABLE_COMMPAGE,level,SPTM_UNSUPPORTED_OPTIONS);
    }
    const unsigned comm_types[]={SPTM_MAC_COMMPAGE_RW,SPTM_MAC_COMMPAGE_RO,
                                 SPTM_MAC_COMMPAGE_RX};
    for(unsigned n=0;n<3;n++) {
        unsigned type=comm_types[n];m=reset();target_type=type;
        memcpy(ram+(PAGE-BASE),"commpage 64-bit",15);memcpy(before,ram,SIZE);
        check(sptm_mac_retype(&m,PAGE,11,type,0)==SPTM_OK,
              "commpage allocation accepts the audited zero-option constructor");
        check(published==1,"commpage allocation publishes only its frame metadata");
        before[entry+2]=type;memset(before+entry+4,0,12);
        check(!memcmp(ram,before,SIZE),"commpage payload and neighboring frames are preserved");
        published=0;
        rejected(&m,PAGE,11,type,0,SPTM_TYPE_MISMATCH);
        rejected(&m,PAGE,type,11,0,SPTM_UNSUPPORTED_RETYPE);
        m=reset();rejected(&m,PAGE,11,type,1,SPTM_UNSUPPORTED_OPTIONS);
        m=reset();ram[entry+8]=1;memcpy(before,ram,SIZE);
        rejected(&m,PAGE,11,type,0,SPTM_FRAME_BUSY);
        m=reset();ram[entry+12]=1;memcpy(before,ram,SIZE);
        rejected(&m,PAGE,11,type,0,SPTM_FRAME_BUSY);
    }
    for (unsigned t=0;t<sizeof(table_types)/sizeof(*table_types);t++) {
        for (unsigned level = 0; level < 4; level++) {
            m = reset(); target_type=table_types[t]; target_level = level;
            check(sptm_mac_retype(&m, PAGE, 11, table_types[t], level) == SPTM_OK,
                  "page-table level option accepted");
            check(ram[entry+4] == level, "guest reads back the requested level");
        }
    }
    for (unsigned trial=0;trial<5;trial++) {
        m=reset(); target_level=3;
        check(sptm_mac_retype(&m,PAGE,11,20,3)==SPTM_OK,"prepare unused L3 table");
        published=0; target_type=SPTM_MAC_DEFAULT; target_level=0;
        if (trial==0) {
            check(sptm_mac_retype(&m,PAGE,20,11,0)==SPTM_OK,"release empty unreferenced table");
            check(ram[entry+2]==11 && !ram[entry+4],"released table private state cleared");
            continue;
        }
        if (trial==1) ram[entry+6]=1;
        if (trial==2) ram[entry+8]=1;
        if (trial==3) ram[PAGE-BASE]=3;
        if (trial==4) ram[entry+4]=4;
        memcpy(before,ram,SIZE);
        rejected(&m,PAGE,20,11,0,trial<3 ? SPTM_FRAME_BUSY : SPTM_BAD_TABLE);
    }
    const unsigned busy[] = {0, 1, 4, 8, 9, 10, 11, 12, 13, 14, 15};
    for (unsigned i = 0; i < sizeof(busy)/sizeof(*busy); i++) {
        m = reset(); ram[entry+busy[i]] = 1; memcpy(before, ram, SIZE);
        rejected(&m, PAGE, 11, 35, 0, SPTM_FRAME_BUSY);
    }

    const uint64_t bad_pa[] = {PAGE + 1, BASE, PAGE - 0x4000,
        BASE + SIZE, BASE + SIZE + 0x4000, UINT64_MAX, UINT64_MAX - 0x3fff};
    for (unsigned n = 0; n < sizeof(bad_pa)/sizeof(*bad_pa); n++) {
        m = reset(); rejected(&m, bad_pa[n], 11, 20, 0, SPTM_BAD_ADDRESS);
        check(!mappings, "out-of-arena page rejected before physical access");
    }
    const uint64_t bad_type[] = {0, 19, 33, 40, 0x114, UINT64_MAX};
    for (unsigned n = 0; n < sizeof(bad_type)/sizeof(*bad_type); n++) {
        m = reset(); rejected(&m, PAGE, 11, bad_type[n], 0, SPTM_UNSUPPORTED_RETYPE);
    }
    m = reset(); rejected(&m, PAGE, 0x10b, 20, 0, SPTM_UNSUPPORTED_RETYPE);
    m = reset(); rejected(&m, PAGE, 11, 24, 0, SPTM_UNSUPPORTED_OPTIONS);
    m = reset(); rejected(&m, PAGE, 11, 20, 4, SPTM_UNSUPPORTED_OPTIONS);
    m = reset(); rejected(&m, PAGE, 11, 22, 4, SPTM_UNSUPPORTED_OPTIONS);
    m = reset(); rejected(&m, PAGE, 11, 20, 0x100, SPTM_UNSUPPORTED_OPTIONS);
    m = reset(); rejected(&m, PAGE, 11, 35, 1, SPTM_UNSUPPORTED_OPTIONS);
    m = reset(); rejected(&m, PAGE, 11, 25, 1, SPTM_UNSUPPORTED_OPTIONS);
    m = reset(); unavailable = MAP + ((PAGE-BASE) >> 14)*16;
    rejected(&m, PAGE, 11, 20, 0, SPTM_MEMORY_UNAVAILABLE);
    m = reset(); unavailable = PAGE;
    rejected(&m, PAGE, 11, 20, 0, SPTM_MEMORY_UNAVAILABLE);
    m = reset(); ram[entry+2] = 0; memcpy(before, ram, SIZE);
    rejected(&m, PAGE, 11, 20, 0, SPTM_TYPE_MISMATCH);

    for (unsigned n = 0; n < 10; n++) {
        m = reset();
        switch (n) {
        case 0: m.frame_low++; break;
        case 1: m.frame_high++; break;
        case 2: m.alloc_low++; break;
        case 3: m.alloc_high++; break;
        case 4: m.frame_map_pa++; break;
        case 5: m.alloc_low = BASE - 0x4000; break;
        case 6: m.alloc_high = BASE + SIZE + 0x4000; break;
        case 7: m.frame_map_pa = UINT64_MAX - 15; break;
        case 8: m.frame_map_pa = PAGE; break;
        case 9: m.map = NULL; break;
        }
        rejected(&m, PAGE, 11, 20, 0, SPTM_BAD_CONFIG);
        check(!mappings, "bad configuration rejected before physical access");
    }
    for (unsigned controls=0;controls<8;controls++)
    for (unsigned n = 0; n < 15; n++) {
        m = reset(); target_type = SPTM_MAC_USER_ROOT_TABLE;
        target_asid = n%3 == 0 ? 1 : n%3 == 1 ? 0x1234 : 0xffff;
        target_flags = n>=12 ? 6 : n%6<3 ? 2 : 0x22;
        target_flags=(target_flags&~2u)|(controls&1?2:0)|(controls&2?1:0)|(controls&4?8:0);
        target_format = n>=6;
        uint64_t options = ((uint64_t)target_asid << 32) | ((uint64_t)target_flags<<16) | target_format;
        check(sptm_mac_retype(&m, PAGE, 11, 18, options) == SPTM_OK,
              "fresh user root with unique ASID constructed");
        check(published == 2, "user root page published before metadata");
        published = 0; memcpy(before, ram, SIZE);
        rejected(&m, PAGE + 0x4000, 11, 18, options, SPTM_FRAME_BUSY);
        rejected(&m, PAGE, 18, 11, 0, SPTM_BAD_CONFIG);
        m.retire_user_root = retire_root;
        root_busy = 1;
        rejected(&m, PAGE, 18, 11, 0, SPTM_FRAME_BUSY);
        root_busy = 0;
        ram[PAGE-BASE+17]=1; memcpy(before, ram, SIZE);
        rejected(&m, PAGE, 18, 11, 0, SPTM_BAD_TABLE);
        ram[PAGE-BASE+17]=0; memcpy(before, ram, SIZE);
        ram[entry+6]=1; memcpy(before, ram, SIZE);
        rejected(&m, PAGE, 18, 11, 0, SPTM_FRAME_BUSY);
        ram[entry+6]=0; memcpy(before, ram, SIZE);
        ram[entry+10]=0x10; memcpy(before, ram, SIZE);
        rejected(&m, PAGE, 18, 11, 0, SPTM_BAD_TABLE);
        ram[entry+10]=target_flags; memcpy(before, ram, SIZE);
        check(!retired, "invalid roots never retire");
        target_type = SPTM_MAC_DEFAULT;
        check(sptm_mac_retype(&m, PAGE, 18, 11, 0) == SPTM_OK,
              "empty unregistered user root can return to the allocator");
        check(retired == 1 && published == 1, "retirement and type change complete once");
        published = 0; memcpy(before, ram, SIZE);
        rejected(&m, PAGE, 18, 11, 0, SPTM_TYPE_MISMATCH);
        target_type = SPTM_MAC_USER_ROOT_TABLE;
        check(sptm_mac_retype(&m, PAGE, 11, 18, options) == SPTM_OK,
              "retired root and ASID can be reused");
    }
    const uint64_t bad_root_options[] = {0, 0x20000, 0x100020002UL,
        0x100100000UL, 0x100020100UL, 0x1000100020000UL,
        0x100060000UL, 0x100260001UL, UINT64_MAX};
    for (unsigned n = 0; n < sizeof(bad_root_options)/sizeof(*bad_root_options); n++) {
        m = reset();
        rejected(&m, PAGE, 11, 18, bad_root_options[n], SPTM_UNSUPPORTED_OPTIONS);
    }
    m = reset(); unavailable = MAP;
    rejected(&m, PAGE, 11, 18, 0x100020000UL, SPTM_MEMORY_UNAVAILABLE);
    m = reset(); rejected(NULL, PAGE, 11, 20, 0, SPTM_BAD_CONFIG);
    m.publish = NULL; rejected(&m, PAGE, 11, 20, 0, SPTM_BAD_CONFIG);
    printf("%u checks, %u failures\n", checks, failures);
    return failures != 0;
}
