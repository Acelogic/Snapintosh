/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* An explicitly selected recovery or refusal-only endpoint. No policy
 * signing, persistent storage, keys, or firmware execution is implemented. */
#define SEP_PNON_ENDPOINT 1U
#define SEP_PNON_OS_TYPE 2U
#define SEP_PNON_AD_NAME 0x706e6f6e010000fdUL
#define SEP_PNON_AD_OOL  0x05050707010100fdUL
#define SEP_PNON_QUERY  (32UL<<32|0x201UL)
#define SEP_PNON_REPLY  (36UL<<32|0x201UL)
/* Every BootPolicy command uses kind 0x201 (endpoint 1, request byte 2) with
 * DATA = request length. libbootpolicy's __sep_command always writes the
 * same 32-byte header (magic, command word, 24 zero bytes) and appends any
 * body after it; 26A428 requests span 0x20..0x8168 bytes. The kext copies at
 * most the 112 KiB send buffer and fails a longer request itself. */
#define SEP_PNON_COMMAND_KIND 0x201UL
#define SEP_PNON_REQUEST_MIN 32UL
#define SEP_PNON_REQUEST_MAX 0x1c000UL
/* A well-formed BootPolicy command this model does not implement is answered,
 * not dropped: a 32-byte header with status 0xff, which libbootpolicy's
 * __sep_command returns to its caller as BOOTPOLICY "not supported" (255).
 * Nothing is signed, stored or invented. */
#define SEP_PNON_REFUSED (32UL<<32|0x201UL)
#define SEP_PNON_NOT_SUPPORTED 0xffU
#define SEP_PNON_PAGES 7
struct sep_pnon {
    uint64_t ready,advertisements,negotiations,queries,last_request,last_reply;
    uint64_t stage[2],size[2],iova[2],physical[2][SEP_PNON_PAGES];
};
struct sep_pnon_io {
    void *ctx;
    /* Validate the entire candidate plus existing/shared buffers under the
     * service lock. Return complete physical identity only on success. */
    int (*bind)(void *,const struct sep_pnon *,unsigned direction,
                uint64_t iova,uint64_t size,uint64_t physical[SEP_PNON_PAGES]);
    /* Revalidate both complete bindings and ownership; read the 32-byte
     * request header, generate sep_pnon_reply_sized(header,length), then
     * commit that many reply bytes before return. Returns the reply length
     * (36 or 32), 0 on refusal, which writes nothing to the guest. Queue
     * capacity is checked by the caller; length is already range-checked. */
    int (*query)(void *,const struct sep_pnon *,uint64_t length);
};
enum sep_pnon_result { SEP_PNON_OK,SEP_PNON_UNKNOWN,SEP_PNON_BAD_STATE,
                       SEP_PNON_BAD_REQUEST,SEP_PNON_RESOURCE };
int sep_pnon_valid(const struct sep_pnon *);
enum sep_pnon_result sep_pnon_step(struct sep_pnon *,const struct sep_pnon_io *,
                                  uint64_t request,uint64_t *reply);
/* Exact 26A428 query/reply payloads. Output is untouched on refusal. */
int sep_pnon_os_type(const uint8_t request[32],uint8_t reply[36]);
/* Any 32-byte BootPolicy request: current OS type (0x3e) gets its 36-byte
 * reply; another command with the exact header shape (magic, command word,
 * 24 zero bytes) gets the 32-byte not-supported reply. Returns the reply
 * length, or 0 for a malformed request with the output untouched. */
int sep_pnon_reply(const uint8_t request[32],uint8_t reply[36]);
/* Any command length: a 32-byte request behaves as sep_pnon_reply(); a longer
 * one (header followed by a body this model never reads) with the header
 * shape gets only the 32-byte not-supported reply. Returns 0 with the output
 * untouched for a malformed header or a length outside
 * [SEP_PNON_REQUEST_MIN, SEP_PNON_REQUEST_MAX]. */
int sep_pnon_reply_sized(const uint8_t request[32],uint64_t length,uint8_t reply[36]);
/* Installed-system mode: every well-formed request is unsupported, including
 * the bare OS-type query. No ordinary-recovery OS-type reply is available. */
int sep_pnon_refuse_sized(const uint8_t request[32],uint64_t length,uint8_t reply[36]);
/* True for a BootPolicy command word of any admissible length. */
int sep_pnon_command(uint64_t request);
