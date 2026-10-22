/* SPDX-License-Identifier: MIT */
/* Offline executable: actual retained containers enter the same C parser as the kext.
 * The failure inventory predates the implementation. Not a radio or unit test.
 */
#include "../src/qcc2072-firmware.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned char *load(const char *path, size_t maximum, size_t *length)
{
    FILE *f = fopen(path, "rb");
    long size;
    unsigned char *bytes;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0 ||
        (unsigned long)size > maximum || fseek(f, 0, SEEK_SET)) {
        fclose(f); return NULL;
    }
    bytes = malloc(size ? (size_t)size : 1U);
    if (!bytes) { fclose(f); return NULL; }
    if (fread(bytes, 1, (size_t)size, f) != (size_t)size) {
        fclose(f); free(bytes); return NULL;
    }
    fclose(f); *length = (size_t)size; return bytes;
}
static void slice(const char *label, const unsigned char *base,
                  const struct qcc2072_slice *s, int comma)
{
    printf("\"%s\":{\"offset\":%zu,\"bytes\":%zu}%s", label,
           s->length ? (size_t)(s->bytes - base) : 0U, s->length,
           comma ? "," : "");
}
int main(int argc, char **argv)
{
    unsigned char *fw, *bd;
    size_t fw_size, bd_size;
    struct qcc2072_firmware parsed;
    struct qcc2072_board_match board;
    struct qcc2072_board_identity identity = {
        QCC2072_VENDOR_ID, QCC2072_DEVICE_ID,
        QCC2072_SUBVENDOR_ID, QCC2072_SUBDEVICE_ID,
        33U, 24U, 0, 0, NULL, 0
    };
    int r, unknown, missing;
    if (argc != 3) { fprintf(stderr, "usage: transport-artifact firmware-2.bin board-2.bin\n"); return 2; }
    fw = load(argv[1], QCC2072_MAX_FIRMWARE_BYTES, &fw_size);
    bd = load(argv[2], QCC2072_MAX_BOARD_FILE_BYTES, &bd_size);
    if (!fw || !bd) { free(fw); free(bd); return 2; }
    r = qcc2072_parse_firmware(fw, fw_size, &parsed);
    if (r) { fprintf(stderr, "%s\n", qcc2072_result_name(r)); free(fw); free(bd); return 1; }
    unknown = qcc2072_find_board(bd, bd_size, &identity, &board);
    /* 33/24 comes from this file's names. It is NOT a live QMI observation. */
    identity.qmi_chip_id_known = identity.qmi_board_id_known = 1;
    missing = qcc2072_find_board(bd, bd_size, &identity, &board);
    if (missing != QCC2072_BOARD_NOT_FOUND || unknown != QCC2072_IDENTITY_UNKNOWN) {
        fprintf(stderr, "retained board input or parser outcome changed\n");
        free(fw); free(bd); return 1;
    }
    printf("{\"status\":\"OFFLINE_REAL_CONTAINER_REPLAY\",\"hardware_access\":false,");
    printf("\"live_qmi_identity_known\":false,\"native_wifi_runtime_qualified\":false,");
    printf("\"firmware\":{\"bytes\":%zu,\"ie_count\":%u,\"timestamp\":%u,", fw_size, parsed.ie_count, parsed.timestamp);
    slice("amss", fw, &parsed.amss, 1); slice("m3", fw, &parsed.m3, 1);
    slice("aux", fw, &parsed.aux, 1); slice("features", fw, &parsed.features, 0);
    printf("},\"board\":{\"bytes\":%zu,\"records\":%u,\"names\":%u,", bd_size, board.board_records, board.board_names);
    printf("\"unknown_qmi_result\":\"%s\",\"diagnostic_candidate_chip\":33,\"diagnostic_candidate_board\":24,", qcc2072_result_name(unknown));
    printf("\"exact_subsystem_candidate_result\":\"%s\",\"board_data_bytes\":%zu}}\n", qcc2072_result_name(missing), board.data.length);
    free(fw); free(bd); return 0;
}
