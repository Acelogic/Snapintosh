/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_FIRMWARE_H
#define SNAP_QCC2072_FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QCC2072_VENDOR_ID 0x17cbU
#define QCC2072_DEVICE_ID 0x1112U
#define QCC2072_SUBVENDOR_ID 0x105bU
#define QCC2072_SUBDEVICE_ID 0xe14fU
#define QCC2072_MAX_FIRMWARE_BYTES (32U * 1024U * 1024U)
#define QCC2072_MAX_BOARD_FILE_BYTES (16U * 1024U * 1024U)
#define QCC2072_MAX_BOARD_BYTES (256U * 1024U)
#define QCC2072_MAX_BOARD_NAME 256U
#define QCC2072_MAX_IES 4096U

enum qcc2072_result {
    QCC2072_OK = 0,
    QCC2072_INVALID_ARGUMENT = -1,
    QCC2072_TOO_LARGE = -2,
    QCC2072_BAD_CONTAINER = -3,
    QCC2072_TRUNCATED = -4,
    QCC2072_DUPLICATE = -5,
    QCC2072_MISSING_IMAGE = -6,
    QCC2072_IDENTITY_UNKNOWN = -7,
    QCC2072_WRONG_DEVICE = -8,
    QCC2072_BOARD_NOT_FOUND = -9,
    QCC2072_READ_FAILED = -10,
    QCC2072_BAD_REGISTER = -11,
    QCC2072_BAR_MISMATCH = -12,
    QCC2072_DEVICE_NOT_QUIESCENT = -13
};

/* No allocations. Input memory must remain immutable and alive for every slice. */
struct qcc2072_slice { const uint8_t *bytes; size_t length; };
struct qcc2072_firmware {
    struct qcc2072_slice amss, m3, aux, features;
    uint32_t timestamp;
    uint32_t ie_count;
    uint8_t timestamp_present;
};

struct qcc2072_board_identity {
    uint16_t vendor, device, subsystem_vendor, subsystem_device;
    uint32_t qmi_chip_id, qmi_board_id;
    uint8_t qmi_chip_id_known, qmi_board_id_known;
    /* Optional literal variant; length is explicit, bytes must be printable ASCII. */
    const char *variant;
    size_t variant_length;
};

struct qcc2072_board_match {
    struct qcc2072_slice name, data;
    uint32_t board_records, board_names;
};

int qcc2072_parse_firmware(const void *bytes, size_t length,
                          struct qcc2072_firmware *out);
/* No generic/subsystem/variant fallback. A parsed board is not radio admission. */
int qcc2072_find_board(const void *bytes, size_t length,
                       const struct qcc2072_board_identity *identity,
                       struct qcc2072_board_match *out);
/* Explicit upstream PCI regulatory record lookup; never a BDF fallback. */
int qcc2072_find_pci_regdb(const void *bytes, size_t length, struct qcc2072_slice *out);
const char *qcc2072_result_name(int result);

#ifdef __cplusplus
}
#endif
#endif
