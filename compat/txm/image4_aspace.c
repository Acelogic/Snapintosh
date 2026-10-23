/* SPDX-License-Identifier: MIT */
/* Image4 nonce/digest calls, local key, developer mode, info and the
 * address-space call.
 * Part of compat/txm.c's translation unit, included in order; not compiled on its own. */
enum sptm_result txm_compilation_match_empty(const struct sptm_memory *m,
    const struct txm_service *s,txm_copyin_fn copyin,void *copy_ctx,
    uint64_t selector,const uint64_t args[8],uint64_t *status)
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=30) return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args || !status || !copyin ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    for(unsigned n=3;n<8;n++) if(args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t size=args[2] ? args[2] : 20;
    if(size<20 || size>64) return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[1] || args[1]>UINT64_MAX-size) return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack) return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[64];
    int copied=copyin(copy_ctx,args[1],input,size);
    for(unsigned n=0;n<sizeof(input);n++)((volatile uint8_t *)input)[n]=0;
    if(!copied) return SPTM_BAD_ADDRESS;
    /* ...170398e8 compares the normalized size to the stored size (initially
     * zero). Without an admitted setter it cannot match any valid20..64 input.
     * ...1704035c returns status8 and leaves the output count zero. */
    *status=8;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

enum sptm_result txm_image4_nonce_digest(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_nonce_digest_registry *registry,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=52)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args || !registry || !copyin ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)return SPTM_BAD_ADDRESS;
    /* The shipped setter takes its domain in w0, then indexes with w21. */
    uint32_t domain=(uint32_t)args[1];
    if(domain>=TXM_NONCE_DIGEST_DOMAINS || !args[3] || args[3]>48)
        return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned n=4;n<8;n++)if(args[n])return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[2] || args[2]>UINT64_MAX-args[3])return SPTM_BAD_ADDRESS;
    struct txm_nonce_digest *entry=&registry->entries[domain];
    /* ...170790f4 rejects a second set even when its material is identical.
     * Match that fatal refusal rather than silently overwriting boot state. */
    if(entry->length)return SPTM_FRAME_BUSY;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[48]={0};int copied=copyin(copy_ctx,args[2],input,args[3]);
    if(copied) {
        for(unsigned n=0;n<48;n++)entry->bytes[n]=input[n];
        entry->length=args[3];registry->sets++;
    }
    for(unsigned n=0;n<48;n++)((volatile uint8_t *)input)[n]=0;
    if(!copied)return SPTM_BAD_ADDRESS;
    const uint64_t words[6]={0};reply_words(m,args[0],stack,words,0);
    return SPTM_OK;
}

static enum sptm_result image4_stack(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if (selector!=45) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !args || !s->stack_count ||
        s->stack_count>256 || (s->stacks_pa&(page-1)) ||
        s->stacks_pa>UINT64_MAX-s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if ((args[0]&(page-1)) || args[0]<s->stacks_pa ||
        args[0]>=s->stacks_pa+s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    return SPTM_OK;
}

enum sptm_result txm_image4(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8])
{
    enum sptm_result check=image4_stack(m,s,selector,args);
    if(check!=SPTM_OK)return check;
    if (args[1]!=6 || args[3]!=16) return SPTM_UNSUPPORTED_OPTIONS;
    for (unsigned i=4;i<8;i++) if (args[i]) return SPTM_UNSUPPORTED_OPTIONS;
    if (!args[2] || args[2]>UINT64_MAX-16) return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],SPTM_MAC_FRAME_SIZE);
    if (!stack) return SPTM_MEMORY_UNAVAILABLE;
    /* 26A428 TXM ...1704119c initializes {domain5,errno78}; op6 takes
     * ...170411e0 -> ...170413b0 without reading input or changing policy.
     * XNU unpacks the reply at ...befcbc8 and returns errno at ...befed00.
     * Serve that negative contract so Apple's own fallback can execute. */
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,TXM_IMAGE4_UUID_UNAVAILABLE);
    return SPTM_OK;
}

enum sptm_result txm_image4_release_type(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_release_type *state,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,
    const uint64_t args[8],uint64_t *status)
{
    enum sptm_result check=image4_stack(m,s,selector,args);
    if(check!=SPTM_OK)return check;
    if(!state || !copyin || !status || state->sets>1)return SPTM_BAD_CONFIG;
    if(args[1] || args[3]!=64)return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned i=4;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[2] || args[2]>UINT64_MAX-64)return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],SPTM_MAC_FRAME_SIZE);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[64];
    if(!copyin(copy_ctx,args[2],input,sizeof(input)))return SPTM_BAD_ADDRESS;
    /* ...1706cf88 copies64 bytes and forces byte62 to NUL. Its setter
     * ...1706dd3c stores one bounded string and rejects a second set with37.
     * The caller serializes this state under the monitor's service lock. */
    unsigned error=state->sets ? 37 : 0;
    if(!error) {
        for(unsigned i=0;i<64;i++)state->input[i]=input[i];
        input[62]=0;
        unsigned length=0;while(input[length])length++;
        for(unsigned i=0;i<64;i++)state->value[i]=i<length ? input[i] : 0;
        state->length=length;state->sets=1;
    } else state->rejections++;
    for(unsigned i=0;i<64;i++)((volatile uint8_t *)input)[i]=0;
    *status=error ? ((uint64_t)error<<32)|5 : 0;
    state->calls++;state->last_status=*status;
    state->input_va=args[2];state->stack_pa=args[0];
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

enum sptm_result txm_image4_nonce(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_nonce_registry *registry,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,
    const uint64_t args[8],uint64_t *status)
{
    enum sptm_result check=image4_stack(m,s,selector,args);
    if(check!=SPTM_OK)return check;
    if(!registry || !copyin || !status)return SPTM_BAD_CONFIG;
    if(args[1]!=3 || args[3]!=44)return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned i=4;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[2] || args[2]>UINT64_MAX-44)return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],SPTM_MAC_FRAME_SIZE);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[44];
    if(!copyin(copy_ctx,args[2],input,sizeof(input)))return SPTM_BAD_ADDRESS;
    uint64_t domain=0;
    uint32_t flags=0;
    for(unsigned i=0;i<8;i++)domain|=(uint64_t)input[i]<<(8*i);
    for(unsigned i=0;i<4;i++)flags|=(uint32_t)input[8+i]<<(8*i);
    /* TXM ...1706e0a8 builds this exact registry from ...170901f8.
     * Handler ...1706d0b0 rejects wide IDs, unknown IDs and a second set. */
    static const uint32_t domains[TXM_NONCE_DOMAINS]={
        0x70646d67,0x63707478,0x64766469,0x63316274,0x63316162,0x6331676e,
        0x6331736d,0x64316d61,0x63316765,0x63316572,0x63316169,0x6331616c};
    unsigned index=TXM_NONCE_DOMAINS;
    for(unsigned i=0;i<TXM_NONCE_DOMAINS;i++)if(domain==domains[i])index=i;
    unsigned error=domain>>32 ? 84 : index==TXM_NONCE_DOMAINS ? 2 :
        registry->entries[index].initialized ? 37 : 0;
    if(!error) {
        struct txm_nonce *entry=&registry->entries[index];
        entry->domain=domain;entry->flags=flags&0x7f;
        for(unsigned i=0;i<16;i++) {
            entry->first[i]=input[12+i];entry->second[i]=input[28+i];
        }
        entry->initialized=1;
        registry->sets++;
    } else registry->rejections++;
    /* Erase temporary material after the owned record has been committed. */
    for(unsigned i=0;i<sizeof(input);i++)((volatile uint8_t *)input)[i]=0;
    *status=error ? ((uint64_t)error<<32)|5 : 0;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

enum sptm_result txm_set_local_key(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_local_key *state,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=26)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !state || !copyin || !args ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page || state->sets>1)
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page ||
       !args[1] || args[1]>UINT64_MAX-TXM_LOCAL_KEY_BYTES)
        return SPTM_BAD_ADDRESS;
    for(unsigned i=2;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    /* Native ...17039560 claims a one-time byte, then copies exactly97
     * bytes. A duplicate panics with0x55: stop without publishing success. */
    if(state->sets)return SPTM_FRAME_BUSY;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t value[TXM_LOCAL_KEY_BYTES];
    if(!copyin(copy_ctx,args[1],value,sizeof(value)))return SPTM_BAD_ADDRESS;
    for(unsigned i=0;i<sizeof(value);i++)state->value[i]=value[i];
    state->input_va=args[1];state->stack_pa=args[0];state->sets=1;
    /* The runtime service lock serializes publication with other CPUs. */
    const uint64_t words[6]={0};
    reply_words(m,args[0],stack,words,0);
    return SPTM_OK;
}

enum sptm_result txm_sep_channel_unavailable(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=7)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args ||
       !s->stack_count || s->stack_count>256 || !s->ro_pa ||
       ((s->stacks_pa|s->ro_pa)&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page ||
       s->ro_pa>UINT64_MAX-page ||
       (s->ro_pa>=s->stacks_pa && s->ro_pa<s->stacks_pa+s->stack_count*page))
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)return SPTM_BAD_ADDRESS;
    for(unsigned i=1;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *info=m->map(m->ctx,s->ro_pa,page);
    if(!info)return SPTM_MEMORY_UNAVAILABLE;
    /* Native initializer ...17037778..798 excludes platform class0.
     * Enforce the loader's explicit absent capability, including the empty
     * three-word descriptor. Never hide a configured/partially owned channel. */
    if(info[0xa] || load64(info+0x38) || load64(info+0x40) || load64(info+0x48))
        return SPTM_BAD_CONFIG;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,TXM_SEP_CHANNEL_UNAVAILABLE);
    return SPTM_OK;
}

enum sptm_result txm_developer_mode(const struct sptm_memory *m,
    const struct txm_service *s, uint64_t selector, const uint64_t args[8])
{
    const uint64_t page = SPTM_MAC_FRAME_SIZE;
    if (selector != 31) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !args || !s->stack_count ||
        s->stack_count > 256 || (s->stacks_pa & (page-1)) ||
        s->stacks_pa > UINT64_MAX - s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if ((args[0] & (page-1)) || args[0] < s->stacks_pa ||
        args[0] >= s->stacks_pa + s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    if (args[1] > 1) return SPTM_UNSUPPORTED_OPTIONS;
    for (unsigned n=2; n<8; n++)
        if (args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *stack = m->map(m->ctx, args[0], page);
    if (!stack) return SPTM_MEMORY_UNAVAILABLE;
    /* TXM 26A428 switch slot 30 goes directly to ...1703f4f4: status 0,
     * result count 0, synchronous return. No developer/CSM policy write. */
    const uint64_t words[6] = {0};
    reply_words(m, args[0], stack, words, 0);
    return SPTM_OK;
}

enum sptm_result txm_info_with_trust(const struct sptm_memory *m,
    const struct txm_service *s,const struct txm_trust_cache *tc,
    const struct txm_trust_state *state,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page = SPTM_MAC_FRAME_SIZE;
    if (selector != 1 && selector != 2 && selector != 3) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !args || !s->stack_count ||
        s->stack_count > 256 || (s->stacks_pa | s->log_pa | s->log_va) & (page - 1) ||
        s->stacks_pa > UINT64_MAX - s->stack_count * page ||
        s->log_pa > UINT64_MAX - page || s->log_va > UINT64_MAX - page ||
        (s->log_pa >= s->stacks_pa && s->log_pa < s->stacks_pa + s->stack_count * page))
        return SPTM_BAD_CONFIG;
    if ((args[0] & (page - 1)) || args[0] < s->stacks_pa ||
        args[0] >= s->stacks_pa + s->stack_count * page)
        return SPTM_BAD_ADDRESS;
    for (unsigned n = 1; n < 8; n++)
        if (args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    if (selector == 2) {
        if (!s->rw_va || !s->ro_va ||
            ((s->rw_pa | s->rw_va | s->ro_pa | s->ro_va) & (page - 1)) ||
            s->rw_pa > UINT64_MAX-page || s->ro_pa > UINT64_MAX-page ||
            s->rw_va > UINT64_MAX-page || s->ro_va > UINT64_MAX-page ||
            s->rw_pa == s->ro_pa || s->rw_pa == s->log_pa || s->ro_pa == s->log_pa ||
            (s->rw_pa >= s->stacks_pa && s->rw_pa < s->stacks_pa+s->stack_count*page) ||
            (s->ro_pa >= s->stacks_pa && s->ro_pa < s->stacks_pa+s->stack_count*page))
            return SPTM_BAD_CONFIG;
        if (!m->map(m->ctx, s->rw_pa, page) || !m->map(m->ctx, s->ro_pa, page))
            return SPTM_MEMORY_UNAVAILABLE;
    }
    volatile uint8_t *stack = m->map(m->ctx, args[0], page);
    volatile uint8_t *log = m->map(m->ctx, s->log_pa, page);
    if (!stack || !log) return SPTM_MEMORY_UNAVAILABLE;
    /* The producer has no records. Loader zeroes the log and its head/sync
     * words; this operation never resets state shared with the consumer. */
    uint64_t words[6] = {s->log_va, s->log_va + 0x3ff0, s->log_va + 0x3ff8, 0, 0, 0};
    if (selector == 2) {
        words[0] = s->rw_va; words[1] = s->ro_va + 0x3ff0;
        words[2] = 0; words[5] = s->ro_va;
    } else if (selector == 3) {
        /* GetTrustCacheInfo: runtime, static count, capabilities of each
         * static cache. Native version2 capability table ...1700c3f0 is7.
         * No second static cache or dynamically installed cache is present. */
        for (unsigned n = 0; n < 6; n++) words[n] = 0;
        if(tc && tc->pa) {
            volatile uint8_t *view;
            enum sptm_result result=trust_ready(m,tc,state,&view);
            if(result)return result;
            words[0]=tc->va;words[1]=1;words[2]=7;
        } else if(tc && (tc->va || tc->size))return SPTM_BAD_CONFIG;
    }
    reply_words(m, args[0], stack, words, selector == 1 ? 3 : selector == 2 ? 6 : 4);
    return SPTM_OK;
}

enum sptm_result txm_info(const struct sptm_memory *m,const struct txm_service *s,
    uint64_t selector,const uint64_t args[8])
{
    return txm_info_with_trust(m,s,0,0,selector,args);
}

enum sptm_result txm_aspace(const struct sptm_memory *m,
    const struct txm_service *s, const struct txm_arena *a,
    struct txm_registry *r, uint64_t selector, const uint64_t args[8])
{
    const uint64_t page = SPTM_MAC_FRAME_SIZE;
    if (selector != 35 && selector != 36 && selector != 37) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !a || !r || !args || !sptm_boot_memory_valid(m) ||
        !s->stack_count || s->stack_count > 256 || !a->va ||
        ((s->stacks_pa | a->pa | a->va | m->frame_low | m->frame_high |
          m->alloc_low | m->alloc_high) & (page - 1)) || (m->frame_map_pa & 15) ||
        s->stacks_pa > UINT64_MAX - s->stack_count * page ||
        a->pa > UINT64_MAX - TXM_ASPACE_SIZE || a->va > UINT64_MAX - TXM_ASPACE_SIZE ||
        m->frame_low >= m->frame_high || m->alloc_low >= m->alloc_high ||
        m->alloc_low < m->frame_low || m->alloc_high > m->frame_high ||
        r->count > TXM_ASPACE_LIMIT)
        return SPTM_BAD_CONFIG;
    uint64_t map_size = ((m->frame_high - m->frame_low) / page) * 16;
    const uint64_t arena_end = a->pa + TXM_ASPACE_SIZE, arena_va_end = a->va + TXM_ASPACE_SIZE;
    if (m->frame_map_pa > UINT64_MAX - map_size ||
        (a->pa < m->frame_map_pa + map_size && arena_end > m->frame_map_pa) ||
        (a->pa < s->stacks_pa + s->stack_count * page && arena_end > s->stacks_pa) ||
        (s->log_pa >= a->pa && s->log_pa < arena_end) ||
        (s->rw_pa >= a->pa && s->rw_pa < arena_end) ||
        (s->ro_pa >= a->pa && s->ro_pa < arena_end) ||
        (s->log_va >= a->va && s->log_va < arena_va_end) ||
        (s->rw_va >= a->va && s->rw_va < arena_va_end) ||
        (s->ro_va >= a->va && s->ro_va < arena_va_end))
        return SPTM_BAD_CONFIG;
    for (uint64_t pa = a->pa; pa < arena_end; pa += page)
        if (sptm_managed_frame(m, pa)) return SPTM_BAD_CONFIG;
    if ((args[0] & (page - 1)) || args[0] < s->stacks_pa ||
        args[0] >= s->stacks_pa + s->stack_count * page)
        return SPTM_BAD_ADDRESS;
    for (unsigned n = selector==37 ? 4 : 2; n < 8; n++)
        if (args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t region_start=0,region_end=0;
    if(selector==37) {
        /* Native 1703669c..6bc treats these as scalar VA bounds, not
         * pointers to copy. Do not restrict them to physical guest RAM. */
        if((args[2]|args[3])&(page-1) || !args[2] || !args[3] ||
           args[3]>UINT64_MAX-args[2])return SPTM_BAD_ADDRESS;
        region_start=args[2];region_end=args[2]+args[3];
    }
    unsigned slot = r->count;
    uint64_t asid = args[1];
    unsigned shared=0;
    if (selector == 35) {
        if (!asid || asid > 0xffff) return SPTM_UNSUPPORTED_OPTIONS;
        for (unsigned n = 0; n < r->count; n++) {
            if (!r->shared[n] && r->asid[n] == asid) return SPTM_FRAME_BUSY;
            if (!r->root[n] && slot == r->count) slot = n;
        }
        if (slot == TXM_ASPACE_LIMIT) return SPTM_MEMORY_UNAVAILABLE;
    } else {
        if (args[1] < a->va || args[1] - a->va >= TXM_ASPACE_SIZE ||
            ((args[1] - a->va) % TXM_ASPACE_STRIDE)) return SPTM_BAD_ADDRESS;
        slot = (unsigned)((args[1] - a->va) / TXM_ASPACE_STRIDE);
        if (slot >= r->count || !r->root[slot] || r->shared[slot]>1 ||
            (!r->shared[slot] && !r->asid[slot]))
            return SPTM_BAD_ADDRESS;
        asid = r->asid[slot];
        shared=r->shared[slot];
    }
    uint64_t prior_start=r->region_start[slot],prior_end=r->region_end[slot];
    if(selector==35 && r->bound_shared[slot])return SPTM_BAD_CONFIG;
    if((prior_start || prior_end) && (!shared || !prior_start ||
       prior_end<=prior_start || ((prior_start|prior_end)&(page-1))))return SPTM_BAD_CONFIG;
    if(shared && asid>=SPTM_MAC_SHARED_ROOT_LIMIT)return SPTM_BAD_TABLE;
    if(selector==37) {
        if(!shared)return SPTM_TYPE_MISMATCH;
        if(prior_end)return SPTM_FRAME_BUSY;
        if(r->region_sets==UINT64_MAX)return SPTM_BAD_CONFIG;
    }

    volatile uint8_t *frames = m->map(m->ctx, m->frame_map_pa, map_size);
    if (!frames) return SPTM_MEMORY_UNAVAILABLE;
    uint64_t root = 0;struct sptm_user_geometry geometry;
#if SNAP_ROOT_INDEX
    /* compat/root-index.h: visit only the records the scan's first test
     * admits (type and key), in its order; -1 walks every frame as before. */
    uint64_t listed[SPTM_ROOT_INDEX_LIST];unsigned item=0;
    int count=sptm_root_index_candidates(m->root_index,m,
        shared ? SPTM_ROOT_KEY_SHARED(asid) : SPTM_ROOT_KEY_USER(asid),1,listed);
    for (uint64_t pa=count>=0 ? (count ? listed[0] : m->alloc_high) : sptm_next_frame(m,0); pa<m->alloc_high;
         pa=count>=0 ? (++item<(unsigned)count ? listed[item] : m->alloc_high) : sptm_next_frame(m,pa+page)) {
#else
    for (uint64_t pa=sptm_next_frame(m,0); pa<m->alloc_high; pa=sptm_next_frame(m,pa+page)) {
#endif
        volatile uint8_t *f = frames + ((pa - m->frame_low) / page) * 16;
        if(shared) {
            if(f[2]!=SPTM_MAC_SHARED_ROOT_TABLE || f[8]!=asid)continue;
            if(selector==36 && (f[4] || f[5]))return SPTM_FRAME_BUSY;
            if(f[10] || !sptm_mac_user_geometry(f[12],SPTM_MAC_ROOT_FLAGS_USER,&geometry))
                return SPTM_BAD_TABLE;
        } else {
            if (f[2] != SPTM_MAC_USER_ROOT_TABLE ||
                ((unsigned)f[4] | (unsigned)f[5] << 8) != asid) continue;
            if(!sptm_mac_user_binding_valid(m,f) || (selector==35 && f[8]!=0xff) ||
               !sptm_mac_user_geometry(f[12],f[10],&geometry))
                return SPTM_BAD_TABLE;
            if(selector!=35 && ((f[8]==255)!=(!r->bound_shared[slot]) ||
               (f[8]!=255 && m->shared_regions->slots[f[8]].root!=r->bound_shared[slot])))
                return SPTM_TYPE_MISMATCH;
        }
        if (root) return SPTM_FRAME_BUSY;
        if (f[0] || f[1] || (selector==35 && (f[6] || f[7])) || f[9] || f[11] ||
            f[13] || f[14] || f[15]) return SPTM_BAD_TABLE;
        root = pa;
    }
    if (!root) return SPTM_TABLE_MISSING;
    if(selector!=35 && root!=r->root[slot])return SPTM_TYPE_MISMATCH;
    /* Native17036370..652c destroys the TXM policy object, not its SPTM
     * hierarchy. Retained commpages and other source mappings may remain.
     * Validate our issued policy view below; do not walk, unmap or release
     * PTEs here. The later SPTM lifecycle owns those references. */
    uint64_t offset = slot * TXM_ASPACE_STRIDE;
    volatile uint8_t *object = m->map(m->ctx, a->pa + offset, TXM_ASPACE_STRIDE);
    volatile uint8_t *stack = m->map(m->ctx, args[0], page);
    if (!object || !stack) return SPTM_MEMORY_UNAVAILABLE;
    /* Constructor 1703629c: flags +18=0, packed ASID/type +22,
     * empty mapping object +38. Allocators use sizes 70 and 50 and mark
     * each object's allocated byte +11. Locks and list links start empty.
     * No signing/trust policy or address-space activation is implied. */
    uint8_t expected[TXM_ASPACE_STRIDE];
    empty_object(expected,a->va+offset,(unsigned)asid,shared);
    if(selector!=35 && !object_view(a,r,slot,expected))return SPTM_BAD_CONFIG;
    if(selector!=35 && !object_matches(object,expected))return SPTM_FRAME_BUSY;
    if(selector==36 && shared && load32(expected+TXM_SHARED_REFS))return SPTM_FRAME_BUSY;
    volatile uint8_t *parent_object=0;uint64_t parent_pa=0;
    if(selector==36 && r->bound_shared[slot]) {
        if(r->unbindings==UINT64_MAX)return SPTM_BAD_CONFIG;
        unsigned parent=TXM_ASPACE_LIMIT;
        for(unsigned i=0;i<r->count;i++)if(r->root[i]==r->bound_shared[slot]) {
            if(parent!=TXM_ASPACE_LIMIT)return SPTM_BAD_CONFIG;
            parent=i;
        }
        uint8_t parent_view[256];
        if(parent==TXM_ASPACE_LIMIT || !object_view(a,r,parent,parent_view) ||
           !load32(parent_view+TXM_SHARED_REFS))
            return SPTM_BAD_REFERENCE;
        parent_pa=a->pa+parent*256;parent_object=m->map(m->ctx,parent_pa,256);
        if(!parent_object)return SPTM_MEMORY_UNAVAILABLE;
        if(!object_matches(parent_object,parent_view))return SPTM_FRAME_BUSY;
    }
    if(selector==37) {
        /* 170366e4: preserve identity and mapping pointer, publish only
         * the range, then return zero outputs. All fallible reads precede
         * this commit; callers hold the shared service token throughout. */
        store64(object+0x58,region_start);store64(object+0x60,region_end);
        m->publish(m->ctx,a->pa+offset+0x58,16);
        r->region_start[slot]=region_start;r->region_end[slot]=region_end;
        r->region_sets++;
        uint64_t words[6]={0};reply_words(m,args[0],stack,words,0);
        return SPTM_OK;
    }
    if(parent_object) {
        /* Native170363fc releases only the TXM object's reference. SPTM
         * retains its slot until the later root destructor. */
        store32(parent_object+TXM_SHARED_REFS,load32(parent_object+TXM_SHARED_REFS)-1);
        m->publish(m->ctx,parent_pa+TXM_SHARED_REFS,4);r->unbindings++;
    }
    for (unsigned n = 0; n < TXM_ASPACE_STRIDE; n++)
        object[n] = selector == 35 ? expected[n] : 0;
    m->publish(m->ctx, a->pa + offset, TXM_ASPACE_STRIDE);
    r->root[slot] = selector == 35 ? root : 0;
    r->asid[slot] = selector == 35 ? (uint16_t)asid : 0;
    r->shared[slot]=0;
    r->region_start[slot]=r->region_end[slot]=0;
    r->bound_shared[slot]=0;
    if (slot == r->count) r->count++;
    uint64_t words[6] = {selector == 35 ? a->va + offset : 0, 0, 0, 0, 0, 0};
    reply_words(m, args[0], stack, words, selector == 35 ? 1 : 0);
    return SPTM_OK;
}
