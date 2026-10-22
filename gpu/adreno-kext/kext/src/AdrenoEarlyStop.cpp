/* SPDX-License-Identifier: MIT */
// AdrenoEarlyStop.cpp - see AdrenoEarlyStop.h.
#include "AdrenoEarlyStop.h"
#include "../../../../compat/adreno-guest.h"
#include "../../../../compat/early-stop.h"
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>

static uint32_t gStopABI;        // ADRENO_GUEST_STOP_ABI once configured, else 0
static uint32_t gStopDelay;      // seconds, as the launch advertised
static uint8_t gRequested, gPresented, gClientDied;
static uint64_t gDropped;

static uint32_t nodeWord(IOService *node, const char *name)
{
    OSData *data = OSDynamicCast(OSData, node->getProperty(name));
    uint32_t value = 0;
    if (data && data->getLength() == sizeof(value)) bcopy(data->getBytesNoCopy(), &value, sizeof(value));
    return value;
}

void AdrenoEarlyStopConfigure(IOService *node)
{
    if (!node) return;
    uint32_t abi = nodeWord(node, ADRENO_GUEST_STOP_PROPERTY), delay = nodeWord(node, ADRENO_GUEST_STOP_DELAY_PROPERTY);
    if (abi != ADRENO_GUEST_STOP_ABI || delay > EARLY_STOP_DELAY_LIMIT) return;   // an ordinary launch
    gStopDelay = delay;
    __atomic_store_n(&gStopABI, abi, __ATOMIC_RELEASE);
    IOLog("AdrenoX2: early stop enabled by this launch: first present or plug-in failure stops the run after %us\n",
          delay);
}

bool AdrenoEarlyStopEnabled()
{
    return __atomic_load_n(&gStopABI, __ATOMIC_ACQUIRE) == ADRENO_GUEST_STOP_ABI;
}

int AdrenoEarlyStopRequest(uint32_t reason, uint64_t detail)
{
    if (!AdrenoEarlyStopEnabled()) return EARLY_STOP_E_DISABLED;
    uint8_t first = 0;
    if (!__atomic_compare_exchange_n(&gRequested, &first, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_add_fetch(&gDropped, 1, __ATOMIC_RELAXED);
        return EARLY_STOP_DUPLICATE;
    }
    // The monitor admits this only from this kext's own AuxKC bytes, at EL1 (compat/early-stop.c).
    register uint64_t x0 __asm__("x0") = ADRENO_GUEST_STOP;
    register uint64_t x1 __asm__("x1") = reason;
    register uint64_t x2 __asm__("x2") = gStopDelay;
    register uint64_t x3 __asm__("x3") = detail;
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    IOLog("AdrenoX2: early stop requested: reason %u, detail 0x%llx, delay %us -> status %lld, "
          "accepted %llus, monitor phase %llu, bound %llus\n", reason, detail, gStopDelay, (int64_t)x0, x1, x2, x3);
    return (int)(int64_t)x0;
}

void AdrenoEarlyStopClientDied(uint64_t detail)
{
    uint8_t first = 0;
    if (!AdrenoEarlyStopEnabled() ||
        !__atomic_compare_exchange_n(&gClientDied, &first, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    AdrenoEarlyStopRequest(EARLY_STOP_REASON_CLIENT_DIED, detail);
}

void AdrenoEarlyStopPresented(uint64_t presents)
{
    uint8_t first = 0;
    if (!AdrenoEarlyStopEnabled() ||
        !__atomic_compare_exchange_n(&gPresented, &first, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    AdrenoEarlyStopRequest(EARLY_STOP_REASON_PRESENT, presents);
}
