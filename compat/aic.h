/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_AIC_H
#define SNAP_COMPAT_AIC_H
#include <stdint.h>

#define AIC_MAX_IRQS 4096
#define AIC_WORDS (AIC_MAX_IRQS/32)
/* One flat-bank die and one delivery endpoint (the boot CPU's cluster).
 * The host owns interrupt injection; this layer never touches host MMIO. */
struct aic_config { uint32_t irqs, revision; uint64_t event; };
/* Zero is the reset state: global disabled, every source masked and low. */
struct aic_state {
    uint32_t control;
    uint32_t unmasked[AIC_WORDS], software[AIC_WORDS], level[AIC_WORDS];
    uint64_t events;
};
enum aic_result {
    AIC_OK, AIC_BAD_CONFIG, AIC_UNKNOWN_REGISTER, AIC_READ_ONLY,
    AIC_BAD_WIDTH, AIC_BAD_VALUE
};
int aic_config_valid(const struct aic_config *config);
int aic_pending(const struct aic_config *config, const struct aic_state *state);
enum aic_result aic_set_level(const struct aic_config *config,
    struct aic_state *state, unsigned irq, int level);
enum aic_result aic_access(const struct aic_config *config,
    struct aic_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value);
#endif
