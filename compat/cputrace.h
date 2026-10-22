/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_CPUTRACE_H
#define SNAP_COMPAT_CPUTRACE_H
#include <stdint.h>

/* SPTM CPUTRACE table 9: PA_CRV_ADDR (1), PA_CRV_SIZE (2).
 * This backend owns no dedicated physical processor-trace buffer. These
 * no-argument queries return its empty reservation; they do not acknowledge
 * tracing, promise a buffer, or touch host debug hardware. A tracing backend
 * needs its own allocation, protection and stream-lifecycle implementation.
 * Return one if handled, zero otherwise, leaving output unchanged on refusal. */
static inline int cputrace_empty_query(uint64_t endpoint, uint64_t *value)
{
    if (!value || (endpoint != 1 && endpoint != 2)) return 0;
    *value = 0;
    return 1;
}
#endif
