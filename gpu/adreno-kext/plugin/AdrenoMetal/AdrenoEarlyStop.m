/* SPDX-License-Identifier: MIT */
// AdrenoEarlyStop.m - see AdrenoEarlyStop.h.
#import "AdrenoEarlyStop.h"
#include "../../include/AdrenoContract.h"
#import <os/log.h>
#include <stdatomic.h>
#include <unistd.h>

static io_service_t gAccelerator;
static atomic_int gBound, gReported;

static os_log_t early_stop_log(void) {
    static os_log_t l; static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("org.snapintosh.adreno", "early-stop"); });
    return l;
}

@implementation AdrenoEarlyStop

+ (void)bindAccelerator:(io_service_t)accelerator
{
    if (!accelerator || atomic_load(&gBound)) return;
    CFTypeRef value = IORegistryEntryCreateCFProperty(accelerator, CFSTR(ADRENO_EARLY_STOP_REGISTRY_PROPERTY),
                                                      kCFAllocatorDefault, 0);
    uint32_t abi = 0;
    if (value && CFGetTypeID(value) == CFNumberGetTypeID()) CFNumberGetValue(value, kCFNumberSInt32Type, &abi);
    if (value) CFRelease(value);
    if (abi != 1) return;                                   // an ordinary launch: nothing to report to
    int expected = 0;
    if (!atomic_compare_exchange_strong(&gBound, &expected, 1)) return;
    IOObjectRetain(accelerator);
    gAccelerator = accelerator;
    os_log(early_stop_log(), "early stop enabled by this launch: the first unrecoverable failure ends the run");
}

+ (void)reportSite:(uint32_t)site
{
    if (!atomic_load(&gBound) || atomic_exchange(&gReported, 1)) return;
    uint64_t detail = (uint64_t)(uint32_t)getpid() << 32 | site;
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &detail);
    kern_return_t result = number ? IORegistryEntrySetCFProperty(gAccelerator, CFSTR(ADRENO_EARLY_STOP_FAILURE_KEY),
                                                                 number) : KERN_RESOURCE_SHORTAGE;
    if (number) CFRelease(number);
    // Logged before the raise that follows, so it reaches disk before the monitor's deadline.
    os_log_error(early_stop_log(), "unrecoverable failure at site 0x%x reported for early stop: 0x%x", site, result);
}

@end
