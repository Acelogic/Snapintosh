/* SPDX-License-Identifier: MIT */
#pragma once
#include "aes.h"

#define AES_TRANSFER_MAX 0x100000U
struct aes_slot { struct aes_key key; uint32_t valid,encrypt,mode; };
struct aes_engine {
    uint32_t ready,running,irq_enable,threshold,irq_status,completed_tag;
    uint32_t header,words[8],used,need;
    struct aes_slot keys[2];
    uint8_t iv[4][16];
    uint32_t iv_valid;
    uint64_t commands,transfers,bytes,barriers,iv_exports;
};
/* map must validate a single guest IOVA-page fragment and return a stable
 * CPU-accessible mapping, never host MMIO. Serialize the whole transaction
 * against page-table/ownership changes. publish cannot fail. All mappings
 * are obtained and checked before any data or IV is changed. */
struct aes_dma {
    void *ctx;
    volatile uint8_t *(*map)(void *ctx,uint64_t iova,size_t size,int write);
    void (*publish)(void *ctx,volatile uint8_t *memory,size_t size);
};
enum aes_result { AES_OK,AES_BAD_STATE,AES_BAD_WIDTH,AES_BAD_VALUE,AES_UNKNOWN_REGISTER,AES_UNSUPPORTED,AES_DMA_REFUSED };
void aes_engine_init(struct aes_engine *s);
enum aes_result aes_engine_access(struct aes_engine *s,const struct aes_dma *dma,
    uint64_t offset,unsigned width,int write,uint64_t *value);
int aes_engine_irq(const struct aes_engine *s);
