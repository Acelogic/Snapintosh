/* SPDX-License-Identifier: MIT */
#include "cpu-release.h"
int guest_cpu_release_write(struct guest_cpu_release *s,uint64_t allowed,
    uint64_t offset,unsigned width,uint64_t value,
    int (*launch)(void *,unsigned),void *context)
{
    if (!s || !launch || width!=4 || !allowed || allowed&~UINT64_C(0x3e) ||
        s->armed&~allowed || s->issued&~s->armed ||
        (offset!=4 && offset!=8 && offset!=12)) return 0;
    if (!value) return 1; /* the stock loop also writes zero to an idle cluster */
    if (value&(value-1)) return 0;
    /* The global bitmap is packed E0..E3,P0..P1. Cluster registers are
     * local bitmaps: +8 selects E0..E3; +12 selects P0..P1. The stock PMGR
     * loop masks the cluster width, then shifts by that width for the next
     * register. Never interpret a P-local bit as the same numbered E core. */
    uint64_t global=value;
    if (offset==8 && (value&~UINT64_C(0xf))) return 0;
    if (offset==12) {
        if (value&~UINT64_C(3)) return 0;
        global=value<<4;
    }
    if (global&~allowed) return 0;
    if (offset==4) { s->armed|=global;return 1; }
    if (!(s->armed&global) || (s->issued&global)) return 0;
    unsigned slot=(unsigned)__builtin_ctzll(global);
    if (!launch(context,slot)) return 0;
    s->issued|=global;
    return 1;
}
