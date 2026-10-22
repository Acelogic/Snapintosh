// SPDX-License-Identifier: MIT
//
// Host check for adreno_display_live_copy (AdrenoDisplayPresent.h). The live scanout is Device memory, so the helper
// must reproduce memcpy's result while keeping every access naturally aligned. This compares it with memcpy for every
// 4-byte-aligned source and destination offset within 32 bytes and lengths up to 6000 bytes, including the
// ~1.4 KiB rows of the enlarged shake-to-locate cursor that faulted on the A16.
//
//   cc -O2 -Wall -Igpu/adreno-kext/kext/src -o build/test-adreno-live-copy tools/test-adreno-live-copy.c
//   build/test-adreno-live-copy
#define ADRENO_PRESENT_LIVE_ALIGNED 1
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "AdrenoDisplayPresent.h"

int main(void)
{
    static uint8_t src[8192 + 64], dst[8192 + 64], ref[8192 + 64];
    long cases = 0, mismatches = 0;
    for (size_t i = 0; i < sizeof src; i++)
        src[i] = (uint8_t)(i * 131 + 7);
    for (int so = 0; so < 32; so += 4)
        for (int dof = 0; dof < 32; dof += 4)
            for (int n = 0; n <= 6000; n += n < 128 ? 4 : 68) {
                memset(dst, 0xAA, sizeof dst);
                memset(ref, 0xAA, sizeof ref);
                adreno_display_live_copy(dst + dof, src + so, (size_t)n);
                memcpy(ref + dof, src + so, (size_t)n);
                cases++;
                if (memcmp(dst, ref, sizeof dst))
                    mismatches++;
            }
    printf("adreno_display_live_copy: %ld cases, %ld mismatches\n", cases, mismatches);
    return mismatches != 0;
}
