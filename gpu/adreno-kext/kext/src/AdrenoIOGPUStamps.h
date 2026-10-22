/* SPDX-License-Identifier: MIT */
/* AdrenoIOGPUStamps.h - IOGPUFamily 26A428's event-machine calls as the pipeline makes them (-DADRENO_PIPELINE=1;
 * agents/gpu-pipeline FAILURE-MODES.md C1-C3). C and C++: the kext (AdrenoX2.cpp) and the host test
 * (tools/test-adreno-iogpu-stamps.c, which runs the KDK's own machine code for these functions) share it.
 *
 * Each declaration matches the KDK's arm64e.kernel slice (UUID 6172533F-B127-35E2-90B8-F7B3B1F2C5B7):
 *   initEvent(IOGPUEvent *)            0x1eec4  STATIC: x0 is the event (b12v15 panicked when it was called as a member:
 *                                              it wrote 0 and 15 x 0xff over the event machine's first 64 bytes)
 *   getNumStamps()                     0x1eb88  this+0x28
 *   incrementStampNoRelease(int)       0x1ef7c  this+0x48+16*i += 0x100 (incrementStamp also tail-calls
 *                                              releaseStampIndex: the machine's lock and channel bookkeeping)
 *   getCurrentStamp(int) const         0x1f1e0  this+0x48+16*i
 *   setEventStamp(int, IOGPUEvent *)   0x20184  x0 this, w1 index, x2 event
 *   testEvent(const IOGPUEvent *)      0x1f4c4  x0 this, x1 event: complete when (slot & ~0xff) - *table[index] < 1
 *                                              (table = this+0x20, built by setStampBaseAddress)
 *   signalStamp(int, unsigned)         0x1edf8  x0 this
 * An IOGPUEvent is a mask word and 15 slot words (initEvent): 64 bytes. */
#ifndef ADRENO_IOGPU_STAMPS_H
#define ADRENO_IOGPU_STAMPS_H
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
void AdrenoEMInitEvent(void *event) __asm__("__ZN17IOGPUEventMachine9initEventEP10IOGPUEvent");
int AdrenoEMGetNumStamps(void *em) __asm__("__ZN17IOGPUEventMachine12getNumStampsEv");
void AdrenoEMIncrementStamp(void *em, int index) __asm__("__ZN17IOGPUEventMachine23incrementStampNoReleaseEi");
uint32_t AdrenoEMCurrentStamp(const void *em, int index) __asm__("__ZNK17IOGPUEventMachine15getCurrentStampEi");
void AdrenoEMSetEventStamp(const void *em, int index, void *event)
    __asm__("__ZNK17IOGPUEventMachine13setEventStampEiP10IOGPUEvent");
bool AdrenoEMTestEvent(const void *em, const void *event) __asm__("__ZNK17IOGPUEventMachine9testEventEPK10IOGPUEvent");
void AdrenoEMSignalStamp(void *em, int index, uint32_t value) __asm__("__ZN17IOGPUEventMachine11signalStampEij");
#ifdef __cplusplus
}
#endif

#define ADRENO_IOGPU_EVENT_WORDS 16u

struct adreno_iogpu_selftest {
    int num_stamps;
    bool synced, pending, after;
    uint32_t start, stamp;
};

/* C2: the event machine behaves as the disassembly says, on a local event, before anything is pipelined: it has a stamp
 * slot `index`; with the stamp word synced to the current value an event set to it is complete; after an increment it
 * is pending; once the word holds the new value it is complete again. Returns 0 when all hold. Nothing is written
 * before getNumStamps() says the index exists; the only machine state changed is slot `index`'s current value. */
static inline int adreno_iogpu_selftest(void *em, volatile uint32_t *word, int index, struct adreno_iogpu_selftest *r)
{
    uint32_t event[ADRENO_IOGPU_EVENT_WORDS] __attribute__((aligned(16)));
    r->num_stamps = AdrenoEMGetNumStamps(em);
    r->synced = r->pending = r->after = false;
    r->start = r->stamp = 0;
    if (index < 0 || index >= r->num_stamps) return -1;
    r->start = AdrenoEMCurrentStamp(em, index);
    __atomic_store_n(word, r->start, __ATOMIC_RELEASE);
    AdrenoEMInitEvent(event);
    AdrenoEMSetEventStamp(em, index, event);
    r->synced = AdrenoEMTestEvent(em, event);
    AdrenoEMIncrementStamp(em, index);
    r->stamp = AdrenoEMCurrentStamp(em, index);
    AdrenoEMInitEvent(event);
    AdrenoEMSetEventStamp(em, index, event);
    r->pending = !AdrenoEMTestEvent(em, event);
    __atomic_store_n(word, r->stamp, __ATOMIC_RELEASE);
    r->after = AdrenoEMTestEvent(em, event);
    return (r->synced && r->pending && r->after && r->stamp == r->start + 0x100u) ? 0 : -2;
}
#endif
