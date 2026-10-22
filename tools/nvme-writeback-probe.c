/* SPDX-License-Identifier: MIT */
/* Execute the production physical backend through the q1n1 call ABI. */
#include "nvme-host.h"
struct request {
    struct nvmeh_params params;
    struct nvmeh_state state;
    uint64_t lba, count, at;
};
_Static_assert(sizeof(struct nvmeh_params)==128,"params ABI");
_Static_assert(sizeof(struct nvmeh_state)==160,"state ABI");
static const struct nvmeh_ops direct;
__attribute__((section(".text.entry")))
int64_t nvme_writeback_probe(struct request *r,uint64_t action)
{
    if (r->count>UINT32_MAX || r->at>UINT32_MAX) return NVMEH_E_RANGE;
    switch (action) {
    case 0: return nvmeh_adopt(&direct,&r->params,&r->state,0,0);
    case 1: return nvmeh_write(&direct,&r->params,&r->state,r->lba,r->count,r->at);
    case 2: return nvmeh_read(&direct,&r->params,&r->state,r->lba,r->count,r->at);
    case 3: return nvmeh_flush(&direct,&r->params,&r->state);
    default: return NVMEH_E_PARAMS;
    }
}
