/* SPDX-License-Identifier: MIT */
// Load the real plugin, substitute its IOGPU endpoints in this process only,
// and run emitted bytes through the production decoder and existing GPU model.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#define main adreno_existing_model_main
#include "test-adreno.c"
#undef main

static uint8_t command_bytes[64];
static unsigned phase, commits, allocations, begins, ends, current_status;
static int allocation_failure, corrupt_command, completion_error;
static uint32_t completion_value = 0x534e6001;

static NSUInteger queue_status(id self, SEL sel) { (void)self; (void)sel; return current_status; }
static void segment_end(id self, SEL sel) {
    (void)self; (void)sel; ends++;
    CHECK(phase == 3);
    phase = 4;
}
static void *reserve_command(id self, SEL sel, NSUInteger length) {
    (void)self; (void)sel; allocations++;
    CHECK(phase == 0 && length == sizeof(struct adreno_submit_header));
    phase = 2;
    return allocation_failure ? NULL : command_bytes;
}
static void segment_begin(id self, SEL sel, void *pointer) {
    (void)self; (void)sel; begins++;
    CHECK(phase == 2 && pointer == command_bytes); phase = 3;
}
static void native_commit(id self, SEL sel) {
    (void)self; (void)sel;
    if (current_status >= MTLCommandBufferStatusCommitted)
        [NSException raise:NSInvalidArgumentException format:@"model: already committed"];
    commits++;
    CHECK(phase == 4);
    if (corrupt_command) command_bytes[0] = 1;
    completion_error = adreno_submit_command(command_bytes, 8, submit_fence, &completion_value);
    current_status = MTLCommandBufferStatusCommitted;
}
static void reset_case(void) {
    memset(command_bytes, 0, sizeof(command_bytes));
    phase = commits = allocations = begins = ends = current_status = 0;
    allocation_failure = corrupt_command = completion_error = 0;
    clean_disabled = 0;
    guest_fence_setup();
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal\n", argv[0]); return 2; }
    @autoreleasepool {
        if (!dlopen(argv[1], RTLD_NOW | RTLD_LOCAL)) { fprintf(stderr, "%s\n", dlerror()); return 2; }
        Class base = objc_getClass("IOGPUMetalCommandBuffer");
        Class plugin = objc_getClass("AdrenoCommandBuffer");
        if (!base || !plugin) return 2;
        class_replaceMethod(base, @selector(status), (IMP)queue_status, "Q@:");
        class_replaceMethod(base, sel_registerName("endCurrentSegment"), (IMP)segment_end, "v@:");
        class_replaceMethod(base, sel_registerName("_reserveKernelCommandBufferSpace:"), (IMP)reserve_command, "^v@:Q");
        class_replaceMethod(base, sel_registerName("beginSegment:"), (IMP)segment_begin, "v@:^v");
        class_replaceMethod(base, @selector(commit), (IMP)native_commit, "v@:");
        // No native device/queue is created. Keep this inert object until process
        // exit; its native deallocator expects initialized IOGPU storage.
        id object = class_createInstance(plugin, 0);
        dram = calloc(1, RAM_SIZE); cache = calloc(1, RAM_SIZE);
        if (!object || !dram || !cache) return 2;
        void (*commit)(id, SEL) = (void (*)(id, SEL))objc_msgSend;
        reset_case();
        commit(object, @selector(commit));
        CHECK(commits == 1 && allocations == 1 && begins == 1 && ends == 1);
        CHECK(completion_error == 0 && S.fences == 1 && r.rptr == r.wptr);
        CHECK(m_rd(0, GUEST_PAGE+0x200) == completion_value);
        unsigned saved = allocations; uint32_t wptr = r.wptr;
        BOOL threw = NO;
        @try { commit(object, @selector(commit)); } @catch (NSException *e) { (void)e; threw = YES; }
        CHECK(threw && allocations == saved && r.wptr == wptr);
        reset_case(); clean_disabled = 1;
        commit(object, @selector(commit));
        CHECK(commits == 1 && completion_error == ADRENO_E_FENCE && S.fences == 0);
        CHECK(r.rptr != r.wptr);
        reset_case(); corrupt_command = 1;
        commit(object, @selector(commit));
        CHECK(completion_error == ADRENO_SUBMIT_E_COMMAND && S.fences == 0 && r.wptr == 22);
        reset_case(); allocation_failure = 1; threw = NO;
        @try { commit(object, @selector(commit)); } @catch (NSException *e) { (void)e; threw = YES; }
        CHECK(threw && commits == 0 && begins == 0 && S.fences == 0);
        printf("%s: %u plugin-to-decoder-to-SMMU/CP checks; IOGPU endpoints substituted\n",
               failures ? "FAILED" : "PASS", checks);
        fflush(stdout);
        _Exit(failures ? 1 : 0);
    }
}
