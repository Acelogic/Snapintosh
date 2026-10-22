/* SPDX-License-Identifier: MIT */
// AdrenoEarlyStop.h - report an unrecoverable plug-in failure to the kext just before raising it, so a launch
// that opted into early stop (compat/early-stop.h) ends a few seconds later instead of at its watchdog.
// Inert unless the accelerator publishes ADRENO_EARLY_STOP_REGISTRY_PROPERTY (AdrenoContract.h).
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

NS_ASSUME_NONNULL_BEGIN
@interface AdrenoEarlyStop : NSObject
// The accelerator the device opened (AdrenoMTLDevice). Reads the registry property once; later calls are ignored.
+ (void)bindAccelerator:(io_service_t)accelerator;
// First report per process only: pid << 32 | site to the kext, which forwards it to the monitor.
+ (void)reportSite:(uint32_t)site;
@end
NS_ASSUME_NONNULL_END

// Site = file tag << 16 | line; a file defines ADRENO_EARLY_STOP_FILE before including this. The class is found
// at run time, so host harnesses that compile an encoder without this file still link, and simply report nothing.
#ifndef ADRENO_EARLY_STOP_FILE
#define ADRENO_EARLY_STOP_FILE 0u
#endif
#define ADRENO_RAISE_FATAL(name, ...) do { \
        [(Class)NSClassFromString(@"AdrenoEarlyStop") \
            reportSite:((uint32_t)ADRENO_EARLY_STOP_FILE << 16) | (uint32_t)__LINE__]; \
        [NSException raise:(name) format:__VA_ARGS__]; \
    } while (0)
