/* SPDX-License-Identifier: MIT */
// Host check of the plug-in's early-stop report (AdrenoEarlyStop.m). No accelerator here publishes
// ADRENO_EARLY_STOP_REGISTRY_PROPERTY, so binding must decline, reports must do nothing, and the raise macro must
// still raise exactly what it names. tools/test-early-stop.py builds and runs this; read-only on the host registry.
#define ADRENO_EARLY_STOP_FILE 7u
#import "../AdrenoMetal/AdrenoEarlyStop.h"
#include <assert.h>
#include <stdio.h>

static NSString *raised(void (^work)(void)) {
    @try { work(); return nil; } @catch (NSException *e) { return [NSString stringWithFormat:@"%@|%@", e.name, e.reason]; }
}

int main(void) {
    @autoreleasepool {
        assert(NSClassFromString(@"AdrenoEarlyStop") == [AdrenoEarlyStop class]);
        [AdrenoEarlyStop reportSite:1];                        // unbound: nothing to report to
        [AdrenoEarlyStop bindAccelerator:MACH_PORT_NULL];
        io_service_t platform = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
        assert(platform);
        [AdrenoEarlyStop bindAccelerator:platform];           // no AdrenoEarlyStopABI: declined
        IOObjectRelease(platform);
        NSString *what = raised(^{ ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"fatal %d", 42); });
        assert([what isEqualToString:@"NSInvalidArgumentException|fatal 42"]);
        what = raised(^{ if (1) ADRENO_RAISE_FATAL(NSInternalInconsistencyException, @"%@", @"inner"); });
        assert([what isEqualToString:@"NSInternalInconsistencyException|inner"]);
        printf("PASS: plug-in early-stop report is inert without the launch's opt-in; raises unchanged\n");
    }
    return 0;
}
