/* SPDX-License-Identifier: MIT */
#ifndef SNAP_SEP_XARS_H
#define SNAP_SEP_XARS_H
#include <stdint.h>

/* Explicit virtual xars service. No CPSN/key/app hash or authentication is
 * supplied. Status1 is a non-success byte, not a fabricated identity and not
 * a claim about a named firmware error enum. Native clients propagate it. */
#define SEP_XARS_ENDPOINT 2U
#define SEP_XARS_STATUS_REFUSED 1U
#define SEP_XARS_AD_NAME 0x78617273020000fdUL
#define SEP_XARS_AD_OOL  0x02020202020100fdUL
#define SEP_XARS_PAGES 2U
#define SEP_XARS_SIZE 0x8000UL
/* AppleSEPXART::get_ap_slot_info: slot in byte6, success status0, u16 length
 * in bytes3-4 and slot state in byte6. The 56-byte receive-buffer payload is
 * an 8-byte BNCN followed by a 48-byte commit hash. This virtual SEP has no
 * nonce storage, so both native slots (0 and 1) are empty: state0, all-zero
 * payload. State0 is the value AppleMobileApNonce treats as nothing to delete;
 * no nonce, manifest commitment or boot-slot identity is claimed. */
#define SEP_XARS_SLOT_INFO 0x18U
#define SEP_XARS_SLOT_BYTES 56U
#define SEP_XARS_SLOT_EMPTY 0U
/* AppleSEPXART::getFullEpochs (builder fffffe00099be464): opcode 0x17, no
 * payload, SEPEpoch::EPOCH_COUNT (8) slots of 4 bytes expected back, and the
 * kernel panics unless out_len is exactly 32 ("expected_out_len == out_len").
 * A refusal is therefore not an option. This SEP stores no epochs, so every
 * slot is empty: 32 zero bytes, status 0, like the empty AP-nonce slots. */
#define SEP_XARS_EPOCHS 0x17U
#define SEP_XARS_EPOCH_BYTES 32U

struct sep_xars {
    uint64_t ready, advertisements, negotiations, queries, last_request, last_reply;
    uint64_t stage[2], size[2], iova[2], physical[2][SEP_XARS_PAGES];
};
struct sep_xars_io {
    void *ctx;
    /* Admit both buffers, shared bootstrap memory and peer endpoint buffers
     * together, with disjoint physical pages and retained identity checks.
     * Failure must not mutate target memory or retained resource state. */
    int (*bind)(void *, const struct sep_xars *, unsigned direction,
                uint64_t iova, uint64_t size, uint64_t physical[SEP_XARS_PAGES]);
    /* Revalidate every bound buffer under the same service lock, even though
     * refusal writes no payload. Never return success for stale DMA mappings. */
    int (*validate)(void *, const struct sep_xars *);
    /* Revalidate every bound buffer as validate() does, then write exactly
     * `bytes` zero bytes (SEP_XARS_SLOT_BYTES or SEP_XARS_EPOCH_BYTES) at the
     * start of the receive buffer (direction 1) and publish them before
     * returning success. No guest write on failure. */
    int (*slot)(void *, const struct sep_xars *, unsigned bytes);
};
enum sep_xars_result {
    SEP_XARS_OK, SEP_XARS_UNKNOWN, SEP_XARS_BAD_STATE,
    SEP_XARS_BAD_REQUEST, SEP_XARS_RESOURCE
};
int sep_xars_valid(const struct sep_xars *);
enum sep_xars_result sep_xars_step(struct sep_xars *, const struct sep_xars_io *,
                                  uint64_t request, uint64_t *reply);
#endif
