/* SPDX-License-Identifier: MIT */
#ifndef SNAP_SPTM_NX_UPDATE_H
#define SNAP_SPTM_NX_UPDATE_H
#include "sptm.h"

/* Permission rows of the pinned T8140 UPDATE helper ...270fd544, indexed by
 * the 5-bit class (AP[2:1]<<2 | UXN<<1 | PXN | WAS_WRITABLE<<4) of the old
 * descriptor; bit n admits requested 5-bit class n. Extracted verbatim from
 * ...2701a8b8 (applied), ...2701a938 (ignored: no change) and ...2701a9b8
 * (applied only with option800, else ignored). tools/replay-sptm-matrix.py
 * re-reads all three from the image and replays the helper over every row. */
static const uint32_t sptm_update_allowed[32]={
    [3]=0x08080800u,[5]=0x00208000u,[7]=0x80808000u,[9]=0x02008000u,
    [13]=0x00008000u,[19]=0x08000808u,[21]=0x00008020u,[23]=0x80008080u,
    [25]=0x00008200u,[27]=0x00000800u,[31]=0x00008000u};
static const uint32_t sptm_update_ignored[32]={
    [11]=0x08080008u,[15]=0x82a022a0u};
static const uint32_t sptm_update_fault[32]={[27]=0x00000008u,[31]=0x00000080u};

/* Descriptor selection of ...270fd544 for options 1 (WIRED bit58), 2
 * (permissions), 8 (AF), 0x10 (SH), 0x20 (AttrIndx), 0x100 (result5), 0x400
 * and 0x800 (restore a cleared AF or a history-row permission). policy is the
 * data frame type's descriptor +4 bitmap (sptm_mac_type_policy): Apple checks
 * the requested 4-bit class against it whenever the 4-bit class changes,
 * before the rows, so an "ignored" row cannot hide a class the frame type
 * never admits. SH and AttrIndx are copied from the template without any
 * value check (...fd5a8/fd5c0; bit5 too only in XNU_STAGE2_PAGE_TABLE 0x22
 * tables, which no caller walks). A caller admitting a changed SH/AttrIndx
 * owns the data-cache maintenance (sptm_memory.clean_frame). Option 4 (nG)
 * stays unsupported here. Root/type admission, leaf policy and reference
 * accounting remain the caller's responsibility. */
#define SPTM_UPDATE_OPTIONS 0xd3bUL      /* 1,2,8,0x10,0x20,0x100,0x400,0x800 */
#define SPTM_UPDATE_SELECT 0x3bUL        /* ...fe418: one of the 0x3f selectors */
#define SPTM_UPDATE_ATTRS 0x31cUL        /* SH bits9:8 and AttrIndx bits4:2 */
static inline int sptm_update_options_valid(uint64_t options)
{return (options&SPTM_UPDATE_SELECT) && !(options&~SPTM_UPDATE_OPTIONS);}
static inline enum sptm_result sptm_update_select(uint64_t old,
    uint64_t requested,uint64_t options,unsigned policy,uint64_t *next)
{
    if(!next)return SPTM_BAD_CONFIG;
    if(!sptm_update_options_valid(options))return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t value=old;
    if(options&1)value=(value&~(1UL<<58))|(requested&(1UL<<58));
    if(options&8)value=(value&~0x400UL)|
        (requested&0x400UL&((old&0x400UL)||(options&0x800) ? UINT64_MAX:0));
    if(options&0x10)value=(value&~0x300UL)|(requested&0x300UL);
    if(options&0x20)value=(value&~0x1cUL)|(requested&0x1cUL);
    if(options&2) {
        unsigned from4=(unsigned)(((old>>4)&12)|((old>>53)&3));
        unsigned to4=(unsigned)(((requested>>4)&12)|((requested>>53)&3));
        unsigned from=from4|(unsigned)((old>>55)&16),to=to4|(unsigned)((requested>>55)&16);
        /* Apple clears bit51 when it applies a row and never copies it;
         * no Apple-issued descriptor carries it. Keep refusing it. */
        if((old|requested)&(1UL<<51))return SPTM_UNSUPPORTED_OPTIONS;
        if(from4!=to4 && !(policy&0xffffu&(1u<<to4)))return SPTM_UNSUPPORTED_OPTIONS;
        uint32_t bit=1u<<to;
        if(from!=to && !(sptm_update_ignored[from]&bit) &&
           (!(sptm_update_fault[from]&bit) || (options&0x800))) {
            if(!((sptm_update_allowed[from]|sptm_update_fault[from])&bit))
                return SPTM_UNSUPPORTED_OPTIONS;
            /* ...fd818..fd840: AP[2:1], PXN/UXN and WAS_WRITABLE come from
             * the template; bit51 is cleared (validated clear above). */
            uint64_t mask=0x08680000000000c0UL;
            value=(value&~mask)|(requested&mask);
        }
    }
    *next=value;return SPTM_OK;
}
/* Compatibility wrapper: DEFAULT11 user leaves, or kernel leaves restricted
 * to the kernel NX classes 3/11 that the kernel SPRR views enforce natively. */
static inline enum sptm_result sptm_nx_update_pte(uint64_t old,
    uint64_t requested,uint64_t options,uint64_t *next,int user)
{
    return sptm_update_select(old,requested,options,
        user ? sptm_mac_type_policy(SPTM_MAC_DEFAULT) : 0x0808u,next);
}
#endif
