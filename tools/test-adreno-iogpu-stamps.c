/* SPDX-License-Identifier: MIT */
/* test-adreno-iogpu-stamps.c - the pipeline's IOGPU event-machine calls against IOGPUFamily's own machine code
 * (agents/gpu-pipeline FAILURE-MODES.md C2; b12v15's panic).
 *
 *   test-adreno-iogpu-stamps IOGPUFamily.arm64e.kernel      (lipo -thin arm64e.kernel of the KDK 26A428 IOGPUFamily)
 *
 * Copies the slice's __TEXT_EXEC into executable memory on this Mac (Apple silicon) and binds the symbols that
 * gpu/adreno-kext/kext/src/AdrenoIOGPUStamps.h declares (the kext's own declarations) to the KDK's code for them:
 * initEvent, getNumStamps, incrementStampNoRelease, getCurrentStamp, setEventStamp, testEvent. These are leaf code
 * (incrementStampNoRelease calls the scrubber only when a stamp's top two bits change, which the test never reaches).
 * A fake IOGPUEventMachine carries what setStampBaseAddress and init leave there: +0x10 the IOGPU (+0x310 = 0),
 * +0x18 the stamp base, +0x20 the table of stamp-word pointers (base + 4i), +0x28 the stamp count, +0x48 + 16i the
 * current values. Checks:
 *   1. the kext's self-test (adreno_iogpu_selftest) passes and changes nothing in the machine but slot 127's value;
 *   2. 4,096 pipeline cycles as pipeStamp/pipeRetired make them: a queue event set to each new stamp is pending until
 *      the stamp word holds it, then complete; the event keeps one slot for index 127;
 *   3. b12v15: initEvent called as a member (x0 = the machine, the old declaration) overwrites the machine's first 64
 *      bytes and leaves +0x20 = 0x000000ff000000ff, so testEvent's load of table[127] faults at 0xff000004f7, the
 *      panic's far. */
#include <libkern/OSCacheControl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "../gpu/adreno-kext/kext/src/AdrenoIOGPUStamps.h"

uint64_t g_fn[6];
#define TRAMP(sym, i) \
    __asm__(".text\n.globl " sym "\n.p2align 2\n" sym ":\n adrp x16, _g_fn@PAGE\n add x16, x16, _g_fn@PAGEOFF\n" \
            " ldr x16, [x16, #(" #i " * 8)]\n br x16\n");
TRAMP("__ZN17IOGPUEventMachine9initEventEP10IOGPUEvent", 0)
TRAMP("__ZN17IOGPUEventMachine12getNumStampsEv", 1)
TRAMP("__ZN17IOGPUEventMachine23incrementStampNoReleaseEi", 2)
TRAMP("__ZNK17IOGPUEventMachine15getCurrentStampEi", 3)
TRAMP("__ZNK17IOGPUEventMachine13setEventStampEiP10IOGPUEvent", 4)
TRAMP("__ZNK17IOGPUEventMachine9testEventEPK10IOGPUEvent", 5)
static const char *const kSyms[6] = {
    "__ZN17IOGPUEventMachine9initEventEP10IOGPUEvent", "__ZN17IOGPUEventMachine12getNumStampsEv",
    "__ZN17IOGPUEventMachine23incrementStampNoReleaseEi", "__ZNK17IOGPUEventMachine15getCurrentStampEi",
    "__ZNK17IOGPUEventMachine13setEventStampEiP10IOGPUEvent", "__ZNK17IOGPUEventMachine9testEventEPK10IOGPUEvent"};
static const uint8_t kUUID[16] = {0x61, 0x72, 0x53, 0x3F, 0xB1, 0x27, 0x35, 0xE2,
                                  0x90, 0xB8, 0xF7, 0xB3, 0xB1, 0xF2, 0xC5, 0xB7};

static unsigned checks, failures;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
                           printf(__VA_ARGS__); printf("\n"); } } while (0)

enum { NUM = 128, INDEX = NUM - 1, EM_BYTES = 0x2000 };
struct machine {
    uint8_t *em, *gpu;
    uint32_t *base;
    uint32_t **table;
};
static void machine_init(struct machine *m)
{
    m->em = aligned_alloc(64, EM_BYTES);
    m->gpu = aligned_alloc(64, 0x1000);
    m->base = aligned_alloc(16384, 16384);
    m->table = aligned_alloc(64, NUM * sizeof(*m->table));
    memset(m->em, 0xa5, EM_BYTES);
    memset(m->gpu, 0, 0x1000);
    memset(m->base, 0, 16384);
    for (int i = 0; i < NUM; i++) m->table[i] = m->base + i;
    *(uint8_t **)(m->em + 0x10) = m->gpu;
    *(uint32_t **)(m->em + 0x18) = m->base;
    *(uint32_t ***)(m->em + 0x20) = m->table;
    *(int32_t *)(m->em + 0x28) = NUM;
    for (int i = 0; i < NUM; i++) *(uint32_t *)(m->em + 0x48 + 16 * i) = 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s IOGPUFamily.arm64e.kernel\n", argv[0]); return 64; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 66; }
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *file = malloc((size_t)size);
    if (!file || fread(file, 1, (size_t)size, f) != (size_t)size) { fprintf(stderr, "read failed\n"); return 66; }
    fclose(f);
    const struct mach_header_64 *mh = (const void *)file;
    if (mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64) { fprintf(stderr, "not a thin arm64 slice\n"); return 65; }
    const struct segment_command_64 *text = NULL;
    const struct symtab_command *symtab = NULL;
    const uint8_t *uuid = NULL;
    const uint8_t *lc = file + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++, lc += ((const struct load_command *)lc)->cmdsize) {
        const struct load_command *c = (const void *)lc;
        if (c->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)c)->segname, "__TEXT_EXEC"))
            text = (const void *)c;
        else if (c->cmd == LC_SYMTAB) symtab = (const void *)c;
        else if (c->cmd == LC_UUID) uuid = ((const struct uuid_command *)c)->uuid;
    }
    CHECK(uuid && !memcmp(uuid, kUUID, 16), "slice UUID is not IOGPUFamily 26A428's 6172533F-B127-35E2-90B8-F7B3B1F2C5B7");
    if (!text || !symtab || !uuid || memcmp(uuid, kUUID, 16)) { printf("FAIL: wrong input\n"); return 1; }
    uint8_t *code = mmap(NULL, text->vmsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (code == MAP_FAILED) { perror("mmap MAP_JIT"); return 71; }
    pthread_jit_write_protect_np(0);
    memcpy(code, file + text->fileoff, text->filesize);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(code, text->vmsize);
    const struct nlist_64 *syms = (const void *)(file + symtab->symoff);
    const char *strs = (const char *)file + symtab->stroff;
    for (int k = 0; k < 6; k++) {
        for (uint32_t i = 0; i < symtab->nsyms && !g_fn[k]; i++)
            if ((syms[i].n_type & N_TYPE) == N_SECT && !strcmp(strs + syms[i].n_un.n_strx, kSyms[k]))
                g_fn[k] = (uint64_t)(code + (syms[i].n_value - text->vmaddr));
        CHECK(g_fn[k], "symbol %s not found", kSyms[k]);
        if (!g_fn[k]) return 1;
    }
    printf("IOGPUFamily 26A428 __TEXT_EXEC (0x%llx bytes) at %p; initEvent +0x%llx, testEvent +0x%llx\n",
           (unsigned long long)text->vmsize, (void *)code, (unsigned long long)(g_fn[0] - (uint64_t)code),
           (unsigned long long)(g_fn[5] - (uint64_t)code));

    /* 1. the kext's self-test */
    struct machine m;
    machine_init(&m);
    uint8_t *before = malloc(EM_BYTES);
    memcpy(before, m.em, EM_BYTES);
    struct adreno_iogpu_selftest st;
    const int r = adreno_iogpu_selftest(m.em, m.base + INDEX, INDEX, &st);
    CHECK(r == 0, "self-test %d (stamps %d, synced %d, pending %d, after %d, 0x%x -> 0x%x)", r, st.num_stamps, st.synced,
          st.pending, st.after, st.start, st.stamp);
    unsigned changed = 0, outside = 0;
    for (unsigned i = 0; i < EM_BYTES; i++)
        if (before[i] != m.em[i]) { changed++; if (i < 0x48 + 16 * INDEX || i >= 0x48 + 16 * INDEX + 4) outside++; }
    CHECK(!outside, "the self-test changed %u machine bytes outside slot %d's value", outside, INDEX);
    CHECK(m.base[INDEX] == st.stamp && st.stamp == 0x100, "stamp word 0x%x, value 0x%x", m.base[INDEX], st.stamp);
    for (int i = 0; i < NUM - 1; i++) CHECK(!m.base[i], "stamp word %d written", i);
    printf("SELFTEST stamps %d, index %d: synced %d, pending %d, complete %d, stamp 0x%x -> 0x%x; %u machine bytes changed "
           "(slot %d's value only)\n", st.num_stamps, INDEX, st.synced, st.pending, st.after, st.start, st.stamp, changed,
           INDEX);
    const struct adreno_iogpu_selftest bad0 = st;
    struct adreno_iogpu_selftest bad;
    CHECK(adreno_iogpu_selftest(m.em, m.base + NUM, NUM, &bad) == -1 && bad.num_stamps == NUM,
          "an index past getNumStamps() is not refused before any write");
    (void)bad0;

    /* 2. pipeline cycles as pipeStamp (increment, current, setEventStamp into the queue's event) and pipeRetired
     * (the word) make them; IOGPU's merge copies the queue event into the fence, so the queue event is tested. */
    uint32_t queue_event[ADRENO_IOGPU_EVENT_WORDS] __attribute__((aligned(16)));
    AdrenoEMInitEvent(queue_event);
    unsigned bad_cycles = 0;
    uint32_t last = st.stamp;
    for (int k = 0; k < 4096; k++) {
        AdrenoEMIncrementStamp(m.em, INDEX);
        const uint32_t s = AdrenoEMCurrentStamp(m.em, INDEX);
        AdrenoEMSetEventStamp(m.em, INDEX, queue_event);
        const bool pending = !AdrenoEMTestEvent(m.em, queue_event);
        __atomic_store_n(m.base + INDEX, s, __ATOMIC_RELEASE);
        const bool done = AdrenoEMTestEvent(m.em, queue_event);
        if (s != last + 0x100 || !pending || !done) bad_cycles++;
        last = s;
    }
    CHECK(!bad_cycles, "%u of 4096 cycles wrong", bad_cycles);
    CHECK(queue_event[0] == 1u && (queue_event[1] & 0xff) == INDEX, "queue event mask 0x%x slot0 0x%x", queue_event[0],
          queue_event[1]);
    printf("CYCLES 4096: each event pending until its stamp word, then complete; last stamp 0x%x; queue event mask 0x%x, "
           "slot 0x%08x\n", last, queue_event[0], queue_event[1]);

    /* 3. b12v15: the old declaration, initEvent(IOGPUEventMachine *, IOGPUEvent *) */
    struct machine o;
    machine_init(&o);
    uint32_t ev[ADRENO_IOGPU_EVENT_WORDS];
    ((void (*)(void *, void *))g_fn[0])(o.em, ev);
    const uint64_t table = *(uint64_t *)(o.em + 0x20);
    CHECK(table == 0x000000ff000000ffull && table + 8 * INDEX == 0xff000004f7ull,
          "old declaration: em+0x20 = 0x%llx", (unsigned long long)table);
    printf("B12V15 old declaration (x0 = the machine): em+0x10 = 0x%llx, em+0x20 = 0x%llx, table[%d] at 0x%llx (the panic's "
           "far 0xff000004f7), numStamps %d\n", (unsigned long long)*(uint64_t *)(o.em + 0x10), (unsigned long long)table,
           INDEX, (unsigned long long)(table + 8 * INDEX), *(int32_t *)(o.em + 0x28));

    printf("%s: %u IOGPU stamp checks on the KDK's code\n", failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
