/* SPDX-License-Identifier: MIT */
#include "adreno-submit.h"

static uint32_t load32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
int adreno_submit_command(const void *command, uint64_t available,
                          int (*fence)(void *), void *context)
{
    if (!command || available < sizeof(struct adreno_submit_header) || !fence)
        return ADRENO_SUBMIT_E_FORMAT;
    const unsigned char *bytes = command;
    uint32_t type = load32(bytes), size = load32(bytes+4);
    if (size < sizeof(struct adreno_submit_header) || (size & 3) || size > available)
        return ADRENO_SUBMIT_E_FORMAT;
    if (type == ADRENO_KCMD_IOGPU_DEBUG_LOG || type == ADRENO_KCMD_IOGPU_TIMESTAMP)
        return ADRENO_SUBMIT_GENERIC;
    if (type != ADRENO_KCMD_FENCE) return ADRENO_SUBMIT_E_COMMAND;
    if (size != sizeof(struct adreno_submit_header)) return ADRENO_SUBMIT_E_FORMAT;
    return fence(context);
}
