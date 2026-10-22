/* SPDX-License-Identifier: MIT */
#pragma once
#include "sep-sks.h"

#define SEP_SKS_ENDPOINT 3U
#define SEP_SKS_AD_NAME 0x736b7320030000fdUL
#define SEP_SKS_AD_OOL 0x02020202030100fdUL
#define SEP_SKS_PAGES 2U
#define SEP_SKS_BUFFER_BYTES 0x8000U
#define SEP_SKS_REPLY_BYTES 100U

struct sep_sks_endpoint {
    uint64_t ready,advertisements,negotiations,queries,last_request,last_reply;
    uint64_t stage[2],size[2],iova[2],physical[2][SEP_SKS_PAGES];
    struct sep_sks_wire_state wire;
};
struct sep_sks_endpoint_io {
    void *context;
    /* Validate all buffers, bootstrap memory and peer endpoint mappings under
     * the service lock. Return complete physical identities, without writes. */
    int (*bind)(void *,const struct sep_sks_endpoint *,unsigned direction,
                uint64_t iova,uint64_t size,uint64_t physical[SEP_SKS_PAGES]);
    /* Revalidate retained ownership, read the request, and run sep_sks_wire
     * against the supplied staged wire state and reply. No guest/live writes. */
    int (*prepare)(void *,const struct sep_sks_endpoint *,unsigned command,
        unsigned request_bytes,struct sep_sks_wire_state *staged,
        uint8_t reply[SEP_SKS_REPLY_BYTES],uint16_t *reply_bytes,uint8_t *status);
    /* Revalidate all identities, then publish exactly reply_bytes and complete
     * cache visibility before returning. On failure, write nothing. A zero-byte
     * refusal still revalidates ownership. No fallible model work follows this. */
    int (*publish)(void *,const struct sep_sks_endpoint *,const uint8_t *,uint16_t);
};
enum sep_sks_endpoint_result {
    SEP_SKS_ENDPOINT_OK,SEP_SKS_ENDPOINT_UNKNOWN,SEP_SKS_ENDPOINT_BAD_STATE,
    SEP_SKS_ENDPOINT_BAD_REQUEST,SEP_SKS_ENDPOINT_RESOURCE
};
int sep_sks_endpoint_valid(const struct sep_sks_endpoint *);
/* Caller must reserve the response queue slot before invoking this function.
 * The caller holds the same service lock throughout preparation/publication. */
enum sep_sks_endpoint_result sep_sks_endpoint_step(struct sep_sks_endpoint *,
    const struct sep_sks_endpoint_io *,uint64_t request,uint64_t *reply);
