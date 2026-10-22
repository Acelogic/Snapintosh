/* SPDX-License-Identifier: MIT */
#ifndef SNAP_SEP_BOOTSTRAP_H
#define SNAP_SEP_BOOTSTRAP_H
#include <stdint.h>
#include <stddef.h>

/* The selected virtual profile has no optional boot manifests. These offsets
 * describe the AP-owned shared buffer; they grant no physical memory access. */
struct sep_bootstrap {
    uint32_t panic_offset, panic_size, flags_offset, scot_offset;
    uint32_t flags[4];
};
struct sep_bootstrap_reader {
    void *ctx;
    int (*read)(void *,uint32_t offset,size_t size,void *out);
};
enum sep_bootstrap_result {
    SEP_BOOTSTRAP_OK, SEP_BOOTSTRAP_BAD_SIZE, SEP_BOOTSTRAP_BAD_DIRECTORY,
    SEP_BOOTSTRAP_BAD_CONTENT, SEP_BOOTSTRAP_READ_FAILED
};
/* Parse the measured PNIC/FLAG/SCOT directory. The caller must first admit
 * the entire DMA extent and serialize reads with mapping/ownership changes.
 * Refusal leaves out untouched. No guest memory is written. */
enum sep_bootstrap_result sep_bootstrap_parse(const struct sep_bootstrap_reader *,
                                             uint64_t size,struct sep_bootstrap *out);
#endif
