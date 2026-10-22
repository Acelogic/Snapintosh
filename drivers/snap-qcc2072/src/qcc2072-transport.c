/* SPDX-License-Identifier: MIT */
#include "qcc2072-transport.h"

static int read32(const struct qcc2072_probe_io *io,
                  struct qcc2072_probe_snapshot *s, int config,
                  uint32_t offset, uint32_t *value)
{
    int r;
    uint32_t bound = config ? 0x100U : io->admitted_bar0_bytes;
    if ((offset & 3U) || bound < 4U || offset > bound - 4U ||
        (!config && offset > QCC2072_DIRECT_BAR_BYTES - 4U))
        return QCC2072_BAD_REGISTER;
    if (s->read_count >= QCC2072_PROBE_READ_LIMIT) return QCC2072_TOO_LARGE;
    ++s->read_count; s->last_offset = offset;
    s->last_read_was_config = config ? 1U : 0U;
    r = config ? io->config_read32(io->context, offset, value) :
                 io->bar0_read32(io->context, offset, value);
    if (r) return QCC2072_READ_FAILED;
    if (*value == 0xffffffffU || *value == 0xdeadbeefU)
        return QCC2072_BAD_REGISTER;
    return QCC2072_OK;
}

static int sample(const struct qcc2072_probe_io *io,
                  struct qcc2072_probe_snapshot *s, unsigned index, uint32_t offset)
{
    int r = read32(io, s, 0, offset, &s->raw[index]);
    if (r == QCC2072_OK) s->valid_registers |= 1U << index;
    return r;
}

int qcc2072_probe_readonly(const struct qcc2072_probe_io *io,
                          struct qcc2072_probe_snapshot *out)
{
    static const uint32_t offsets[] = {
        0x00U, 0x08U, 0x10U, 0x18U, 0x20U, 0x28U, 0x2cU, 0x38U, 0x48U,
        QCC2072_WINDOW_REGISTER
    };
    static const uint32_t bhi_offsets[] = {0x00U, 0x04U, 0x28U, 0x2cU, 0x30U};
    struct qcc2072_probe_snapshot zero = {0};
    uint32_t low, high, bhi, i;
    int r;
    if (!out) return QCC2072_INVALID_ARGUMENT;
    *out = zero;
    if (!io || !io->config_read32 || !io->bar0_read32 || !io->exclusive_owner ||
        !io->admitted_bar0 || (io->admitted_bar0 & 0xfU) ||
        io->admitted_bar0_bytes < QCC2072_WINDOW_REGISTER + 4U ||
        io->admitted_bar0_bytes > QCC2072_DIRECT_BAR_BYTES)
        return QCC2072_INVALID_ARGUMENT;
    r = read32(io, out, 1, 0x00U, &out->pci_id);
    if (r) return r;
    r = read32(io, out, 1, 0x2cU, &out->pci_subsystem);
    if (r) return r;
    if (out->pci_id != ((QCC2072_DEVICE_ID << 16) | QCC2072_VENDOR_ID) ||
        out->pci_subsystem != ((QCC2072_SUBDEVICE_ID << 16) | QCC2072_SUBVENDOR_ID))
        return QCC2072_WRONG_DEVICE;
    r = read32(io, out, 1, 0x04U, &out->pci_command);
    if (r) return r;
    /* Memory decode is required; active bus mastering implies another owner/state. */
    if ((out->pci_command & 6U) != 2U) return QCC2072_DEVICE_NOT_QUIESCENT;
    r = read32(io, out, 1, 0x08U, &out->pci_class_revision);
    if (r) return r;
    if ((out->pci_class_revision >> 16) != 0x0280U) return QCC2072_WRONG_DEVICE;
    r = read32(io, out, 1, 0x10U, &low);
    if (r) return r;
    if ((low & 7U) != 4U) return QCC2072_BAR_MISMATCH; /* 64-bit memory BAR */
    r = read32(io, out, 1, 0x14U, &high);
    if (r) return r;
    out->bar0 = ((uint64_t)high << 32) | (low & ~0xfU);
    if (out->bar0 != io->admitted_bar0) return QCC2072_BAR_MISMATCH;
    for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        r = sample(io, out, i, offsets[i]);
        if (r) return r;
    }
    if (out->raw[QCC2072_MHI_REGLEN] < 0x4cU ||
        out->raw[QCC2072_MHI_REGLEN] > 0x1000U ||
        (out->raw[QCC2072_MHI_REGLEN] & 3U)) return QCC2072_BAD_REGISTER;
    bhi = out->raw[QCC2072_MHI_BHI_OFFSET];
    if ((bhi & 3U) || bhi < out->raw[QCC2072_MHI_REGLEN] ||
        bhi > io->admitted_bar0_bytes - 0x34U)
        return QCC2072_BAD_REGISTER;
    for (i = 0; i < sizeof(bhi_offsets) / sizeof(bhi_offsets[0]); ++i) {
        r = sample(io, out, QCC2072_BHI_VERSION_MINOR + i, bhi + bhi_offsets[i]);
        if (r) return r;
    }
    out->mhi_state = (uint8_t)((out->raw[QCC2072_MHI_STATUS] >> 8) & 0xffU);
    out->mhi_state_known = (out->mhi_state <= 7U || out->mhi_state == 0xffU);
    out->execution_environment_known =
        out->raw[QCC2072_BHI_EXECUTION_ENVIRONMENT] <= 7U;
    return QCC2072_OK;
}

const char *qcc2072_execution_environment_name(uint32_t raw)
{
    switch (raw) {
    case 0: return "PBL";
    case 1: return "SBL";
    case 2: return "AMSS";
    case 3: return "RDDM";
    case 4: return "WFW";
    case 5: return "PTHRU";
    case 6: return "EDL";
    case 7: return "FP";
    default: return "UNKNOWN";
    }
}
const char *qcc2072_mhi_state_name(uint32_t raw)
{
    switch (raw) {
    case 0: return "RESET";
    case 1: return "READY";
    case 2: return "M0";
    case 3: return "M1";
    case 4: return "M2";
    case 5: return "M3";
    case 6: return "M3_FAST";
    case 7: return "BHI";
    case 0xff: return "SYS_ERR";
    default: return "UNKNOWN";
    }
}
