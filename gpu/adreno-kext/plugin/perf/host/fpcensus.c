/* SPDX-License-Identifier: MIT */
/* Which instructions does AdrenoCodeScan.h flag that Mesa decodes as harmless? (development aid for U4) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "isaspec.h"
#include "ir3-isa.h"
#include "AdrenoCodeScan.h"
int main(int argc, char **argv) {
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        uint8_t *b = malloc(n); fread(b, 1, n, f); fclose(f);
        uint32_t idlen; memcpy(&idlen, b + 8, 4); uint64_t sz[4]; memcpy(sz, b + 80, 32);
        uint8_t *side = b + 144 + idlen, *code = side + sz[0] + sz[1];
        char *js = strndup((char *)side, sz[0]); uint64_t cdo = 0; char *p = strstr(js, "\"constant_data_offset\":");
        if (p) cdo = strtoull(p + 23, NULL, 10);
        uint64_t scan = ((cdo && cdo <= sz[2]) ? cdo : sz[2]) & ~7ull;
        for (uint64_t at = 0; at < scan; at += 8) {
            uint64_t w; memcpy(&w, code + at, 8);
            if (!adreno_ir3_instr_may_store(w)) continue;
            char *t = NULL; size_t tl = 0; FILE *m = open_memstream(&t, &tl);
            struct isa_decode_options o = {0}; o.gpu_id = 800;
            ir3_isa_disasm(&w, 8, m, &o); fclose(m);
            char *s = t; while (*s == ' ' || *s == '\t' || *s == ':' || (*s >= '0' && *s <= '9')) s++;
            while (*s == '(') { char *e = strchr(s, ')'); if (!e) break; s = e + 1; while (*s == ' ') s++; }
            char op[64]; int k = 0; while (s[k] && s[k] != ' ' && s[k] != '\n' && k < 63) { op[k] = s[k]; k++; } op[k] = 0;
            printf("%s %016llx opc=%llu opc6=%llu b20=%llu\n", op, (unsigned long long)w, (unsigned long long)((w>>54)&31), (unsigned long long)((w>>14)&63), (unsigned long long)((w>>20)&7));
            free(t);
        }
        free(js); free(b);
    }
    return 0;
}
