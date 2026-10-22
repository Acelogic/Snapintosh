/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_TRANSPORT_H
#define SNAP_QCC2072_TRANSPORT_H

#include "qcc2072-firmware.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QCC2072_WINDOW_REGISTER 0x3278U
#define QCC2072_DIRECT_BAR_BYTES 0x80000U
#define QCC2072_PROBE_READ_LIMIT 32U

/* The provider must bound callback duration and implement device-read ordering.
 * Each callback returns zero on success. There is deliberately no write callback.
 * BAR mapping / PCI ownership must already be exclusively admitted by the monitor.
 */
struct qcc2072_probe_io {
    void *context;
    int (*config_read32)(void *context, uint32_t offset, uint32_t *value);
    int (*bar0_read32)(void *context, uint32_t offset, uint32_t *value);
    uint64_t admitted_bar0;
    uint32_t admitted_bar0_bytes;
    uint8_t exclusive_owner;
};

enum qcc2072_probe_register {
    QCC2072_MHI_REGLEN, QCC2072_MHI_VERSION, QCC2072_MHI_CONFIG,
    QCC2072_MHI_CHANNEL_DB, QCC2072_MHI_EVENT_DB,
    QCC2072_MHI_BHI_OFFSET, QCC2072_MHI_BHIE_OFFSET,
    QCC2072_MHI_CONTROL, QCC2072_MHI_STATUS, QCC2072_WINDOW_VALUE,
    QCC2072_BHI_VERSION_MINOR, QCC2072_BHI_VERSION_MAJOR,
    QCC2072_BHI_EXECUTION_ENVIRONMENT, QCC2072_BHI_STATUS,
    QCC2072_BHI_ERROR_CODE, QCC2072_PROBE_REGISTER_COUNT
};
struct qcc2072_probe_snapshot {
    uint32_t pci_id, pci_subsystem, pci_command, pci_class_revision;
    uint64_t bar0;
    uint32_t raw[QCC2072_PROBE_REGISTER_COUNT];
    uint32_t valid_registers, read_count, last_offset;
    uint8_t last_read_was_config;
    uint8_t mhi_state, mhi_state_known, execution_environment_known;
    /* No field called ready: a changing read-only snapshot cannot establish it. */
};

/* Bounded snapshot of a memory-enabled, bus-master-disabled exact endpoint.
 * Returns diagnostics even on failure; valid_registers identifies completed reads.
 * No reset, window switch, firmware load, polling, ring write, or DMA is performed.
 */
int qcc2072_probe_readonly(const struct qcc2072_probe_io *io,
                          struct qcc2072_probe_snapshot *out);
const char *qcc2072_execution_environment_name(uint32_t raw);
const char *qcc2072_mhi_state_name(uint32_t raw);

#ifdef __cplusplus
}
#endif
#endif
