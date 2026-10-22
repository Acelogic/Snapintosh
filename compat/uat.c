/* SPDX-License-Identifier: MIT */
#include "uat.h"

enum sptm_result uat_get_info(const struct uat_config *c,
    const struct sptm_aperture *a, uint64_t query, uint64_t *value)
{
    if (!c || !value || c->mode != 1 || c->va_bits < 40 || c->va_bits > 48 ||
        !c->segment_limit || c->segment_limit > UINT32_MAX ||
        (c->reserved_pa & 0x3fff)) return SPTM_BAD_CONFIG;
    uint64_t state = sptm_aperture_pointer(a, c->reserved_pa, 0xc000);
    if (!state || (state & 0x3fff)) return SPTM_BAD_ADDRESS;
    uint64_t result;
    /* SPTM ...b6c14 jump table at ...b6e80. The caller only defines x0;
     * x1..x7 may contain unrelated values and are not query arguments. */
    switch (query) {
    case 0: result = c->mode; break;
    case 2: result = state; break;                 /* private-mode state */
    case 3: result = c->va_bits - 1; break;
    case 4: result = ((1UL << (c->va_bits - 1)) - 1) & 0x7ff000000000UL; break;
    case 5: result = c->segment_limit; break;
    case 9: result = state + 0x8000; break;         /* firmware shared L2 */
    default: return SPTM_UNSUPPORTED_OPTIONS;
    }
    *value = result;
    return SPTM_OK;
}

enum sptm_result uat_power_idle(const struct uat_config *c,
    const struct sptm_aperture *a, const struct sptm_memory *m)
{
    uint64_t state=0;
    enum sptm_result r=uat_get_info(c,a,2,&state);
    if (r!=SPTM_OK) return r;
    if (!m || !m->map || c->segment_limit!=64) return SPTM_BAD_CONFIG;
    volatile uint8_t *pages=m->map(m->ctx,c->reserved_pa,0xc000);
    if (!pages) return SPTM_MEMORY_UNAVAILABLE;
    /* No GPU mapping or command producer exists. A future producer must
     * replace this pristine-state admission, not clear owned state. */
    uint64_t l1=state+0x4000,l2=(c->reserved_pa+0x8000)|3;
    for (unsigned i=0;i<0xc000;i++) {
        unsigned expected=0;
        if (i==0) expected=8;
        else if (i>=0x10 && i<0x18) expected=(unsigned)(l1>>(8*(i-0x10)))&255;
        else if (i==0x18) expected=64;
        else if (i==0x1a) expected=2;
        else if (i>=0x4010 && i<0x4018) expected=(unsigned)(l2>>(8*(i-0x4010)))&255;
        if (pages[i]!=expected) return SPTM_FRAME_BUSY;
    }
    return SPTM_OK;
}
