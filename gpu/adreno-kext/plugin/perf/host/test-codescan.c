/* SPDX-License-Identifier: MIT */
/* test-codescan: ground truth for the plug-in's store classifier (agents/gpu-perf FAILURE-MODES.md U4): disassemble every AdrenoMetal
 * shader-cache record's machine code with Mesa's ir3 decoder (gpu_id 800) and print, per record, whether the code holds
 * an instruction that writes memory outside the shader's own private/local/const storage, plus the opcode names seen.
 *   shaderstores RECORD.amse...   ->  "<path> <code bytes> <scan bytes> stores=<0|1> <opcodes>" */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "isaspec.h"
#include "ir3-isa.h"
#include "AdrenoCodeScan.h"

static const char *stores[] = {"stg", "stg.a", "stgb", "stib", "stib.b", "atomic", "l2g", "ray_intersection", NULL};

static int is_store(const char *op) {
    for (int i = 0; stores[i]; i++)
        if (!strncmp(op, stores[i], strlen(stores[i])) &&
            (op[strlen(stores[i])] == 0 || op[strlen(stores[i])] == '.' || op[strlen(stores[i])] == ' ')) return 1;
    return 0;
}

int main(int argc, char **argv) {
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        uint8_t *b = malloc(n); fread(b, 1, n, f); fclose(f);
        if (n < 144 || memcmp(b, "AMSE", 4)) { free(b); continue; }
        uint32_t idlen; memcpy(&idlen, b + 8, 4);
        uint64_t sz[4]; memcpy(sz, b + 80, 32);
        uint64_t at = 144 + idlen;
        uint8_t *side = b + at, *blob = side + sz[0], *code = blob + sz[1];
        (void)blob;
        /* constant_data_offset from the sidecar: scan only the instructions */
        char *js = strndup((char *)side, sz[0]);
        uint64_t cdo = 0; char *p = strstr(js, "\"constant_data_offset\":");
        if (p) cdo = strtoull(p + strlen("\"constant_data_offset\":"), NULL, 10);
        uint64_t scan = (cdo && cdo <= sz[2]) ? cdo : sz[2];
        scan &= ~7ull;
        char *text = NULL; size_t tlen = 0;
        FILE *mem = open_memstream(&text, &tlen);
        struct isa_decode_options o = {0};
        o.gpu_id = 800; o.max_errors = 0;
        ir3_isa_disasm(code, (int)scan, mem, &o);
        fclose(mem);
        int st = 0; char ops[4096] = ""; size_t used = 0;
        for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
            char *s = line; while (*s == ' ' || *s == '\t' || *s == ':' || (*s >= '0' && *s <= '9')) s++;
            while (*s == '(') { char *e = strchr(s, ')'); if (!e) break; s = e + 1; while (*s == ' ') s++; }
            char op[64]; int k = 0; while (s[k] && s[k] != ' ' && k < 63) { op[k] = s[k]; k++; } op[k] = 0;
            if (!k) continue;
            if (is_store(op)) st = 1;
            if ((!strncmp(op, "st", 2) || !strncmp(op, "atomic", 6) || !strncmp(op, "ld", 2) || !strncmp(op, "res", 3)) &&
                !strstr(ops, op) && used + k + 2 < sizeof ops) { used += sprintf(ops + used, "%s,", op); }
        }
        int scanflag = adreno_ir3_code_may_store(code, (size_t)scan);
        printf("%s %llu %llu stores=%d scan=%d %s%s\n", argv[a], (unsigned long long)sz[2], (unsigned long long)scan, st, scanflag, ops, (st && !scanflag) ? " FALSE_NEGATIVE" : "");
        free(text); free(js); free(b);
    }
    return 0;
}
