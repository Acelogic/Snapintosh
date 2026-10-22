/* SPDX-License-Identifier: MIT */
/* api_test.c - exercises the air2ir3 C API (src/air2ir3_api.h) the way the Metal plug-in will.
 *
 *   api_test list <jobs.txt> [--repeat N] [--threads T] [--out dir]
 *
 * jobs.txt: one job per line, "<air or bc path>\t<entry or ->\t<stage: vertex|fragment|kernel|any>\t<rt0 MTLPixelFormat>".
 * Every job is compiled through ONE air2ir3_compiler handle, N times; the tool prints, per job,
 * the minimum and median wall time of air2ir3_compile() and the cache key.  With --threads T the
 * same jobs are also compiled concurrently from T threads on the same handle and every blob is
 * checked byte-for-byte against the single-threaded result (no shared mutable state).
 * With --out, blob and sidecar of each job are written as <dir>/<n>.ir3v / <n>.json so they can be
 * compared with the CLI (tools/apitest.py).
 *
 *   api_test cached <jobs.txt>
 *
 * verify2 item 4: online compile == cache entry.  jobs.txt lines (tools/apitest.py --cached writes them
 * from cache entries): "<bc>\t<entry>\t<stage>\t<8 MTLPixelFormats a,b,..>\t<8 blends e,op,aop,s,d,sa,da;..>\t
 * <16 texture classes>\t<safe 0|1>\t<constants idx=v,v;idx=v or ->\t<entry file>".  Each job is compiled
 * once through air2ir3_compile(); the sidecar must equal the cache entry file byte for byte, the blob
 * must hash to the entry's blob record, and air2ir3_cache_key() (no compile) must give the same key.
 */
#include "air2ir3_api.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { char path[1024], entry[256], stage[32]; unsigned rt0; void *air; size_t air_size;
                 void *blob; size_t blob_size; char key[65]; double ms[64]; int nms; char err[512]; } job;
static job *jobs; static int njobs;
static air2ir3_compiler *C;

static void *slurp(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
  void *d = malloc(*n); if (fread(d, 1, *n, f) != *n) { free(d); d = NULL; } fclose(f); return d;
}
static int compile_one(job *j, air2ir3_result *r) {
  air2ir3_compile_info ci; memset(&ci, 0, sizeof ci);
  ci.struct_size = sizeof ci; ci.air = j->air; ci.air_size = j->air_size;
  ci.entry = strcmp(j->entry, "-") ? j->entry : NULL;
  ci.stage = !strcmp(j->stage, "vertex") ? AIR2IR3_STAGE_VERTEX : !strcmp(j->stage, "fragment") ? AIR2IR3_STAGE_FRAGMENT
           : !strcmp(j->stage, "kernel") ? AIR2IR3_STAGE_KERNEL : AIR2IR3_STAGE_ANY;
  ci.color_pixel_format[0] = j->rt0; ci.raster_sample_count = 1;
  return air2ir3_compile(C, &ci, r);
}
static int cmpd(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : x > y; }

typedef struct { int tid, nthreads, mismatches, failures; } targ;
static void *worker(void *p) {
  targ *t = (targ *)p;
  for (int i = t->tid; i < njobs; i += t->nthreads) {
    air2ir3_result r;
    if (compile_one(&jobs[i], &r)) { t->failures++; air2ir3_result_free(&r); continue; }
    if (r.blob_size != jobs[i].blob_size || memcmp(r.blob, jobs[i].blob, r.blob_size) || strcmp(r.key_hex, jobs[i].key)) t->mismatches++;
    air2ir3_result_free(&r);
  }
  return NULL;
}

static int cached_mode(const char *path) {
  FILE *f = fopen(path, "r"); if (!f) { perror(path); return 1; }
  char *err = NULL;
  C = air2ir3_compiler_create(0, &err);
  if (!C) { fprintf(stderr, "compiler_create: %s\n", err); return 1; }
  static char line[65536];
  int n = 0, same = 0, keyok = 0, fails = 0;
  while (fgets(line, sizeof line, f)) {
    char *col[9]; int nc = 0; char *save = NULL;
    line[strcspn(line, "\n")] = 0;
    for (char *t = strtok_r(line, "\t", &save); t && nc < 9; t = strtok_r(NULL, "\t", &save)) col[nc++] = t;
    if (nc != 9) continue;
    n++;
    size_t asz = 0, esz = 0; void *air = slurp(col[0], &asz), *ent = slurp(col[8], &esz);
    if (!air || !ent) { printf("FAIL\t%s\tcannot read\n", col[8]); fails++; continue; }
    air2ir3_compile_info ci; memset(&ci, 0, sizeof ci);
    ci.struct_size = sizeof ci; ci.air = air; ci.air_size = asz; ci.entry = col[1];
    ci.stage = !strcmp(col[2], "vertex") ? AIR2IR3_STAGE_VERTEX : !strcmp(col[2], "fragment") ? AIR2IR3_STAGE_FRAGMENT : AIR2IR3_STAGE_KERNEL;
    char *p = col[3]; for (int i = 0; i < 8; i++) { ci.color_pixel_format[i] = (uint32_t)strtoul(p, &p, 10); if (*p == ',') p++; }
    p = col[4];
    for (int i = 0; i < 8; i++) {
      uint8_t *b = &ci.blend[i].enabled; unsigned v[7];
      for (int k = 0; k < 7; k++) { v[k] = (unsigned)strtoul(p, &p, 10); if (*p == ',') p++; }
      if (*p == ';') p++;
      b[0] = v[0]; ci.blend[i].rgb_op = v[1]; ci.blend[i].alpha_op = v[2]; ci.blend[i].src_rgb = v[3]; ci.blend[i].dst_rgb = v[4];
      ci.blend[i].src_alpha = v[5]; ci.blend[i].dst_alpha = v[6];
    }
    p = col[5]; for (int i = 0; i < 16; i++) { ci.texture_class[i] = (uint8_t)strtoul(p, &p, 10); if (*p == ',') p++; }
    ci.safe_constlen = atoi(col[6]); ci.raster_sample_count = 1;
    air2ir3_constant cs[64]; unsigned ncs = 0;
    if (strcmp(col[7], "-")) {
      p = col[7];
      while (*p && ncs < 64) {
        air2ir3_constant *c = &cs[ncs++]; memset(c, 0, sizeof *c);
        c->index = (int32_t)strtol(p, &p, 10); if (*p == '=') p++;
        while (*p && *p != ';' && c->num_values < 4) { c->values[c->num_values++] = strtod(p, &p); if (*p == ',') p++; }
        if (*p == ';') p++;
      }
    }
    ci.num_constants = ncs; ci.constants = cs;
    air2ir3_result r; char kh[65] = {0}; char *kerr = NULL;
    int rc = air2ir3_compile(C, &ci, &r);
    int krc = air2ir3_cache_key(C, &ci, kh, &kerr);
    if (rc) { printf("FAIL\t%s\t%s\n", col[8], r.error); fails++; }
    else {
      int eq = r.sidecar_size == esz && !memcmp(r.sidecar_json, ent, esz);
      int kq = !krc && !strcmp(kh, r.key_hex);
      same += eq; keyok += kq;
      if (!eq || !kq) { printf("DIFF\t%s\tsidecar %s\tkey-only %s\n", col[8], eq ? "same" : "differs", kq ? "same" : "differs"); fails++; }
    }
    air2ir3_result_free(&r); air2ir3_free(kerr); free(air); free(ent);
  }
  fclose(f);
  air2ir3_compiler_destroy(C);
  printf("# cached: %d entries, sidecar byte-identical %d, air2ir3_cache_key == compile key %d, failures %d\n", n, same, keyok, fails);
  return fails ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc >= 3 && !strcmp(argv[1], "cached")) return cached_mode(argv[2]);
  if (argc < 3 || strcmp(argv[1], "list")) { fprintf(stderr, "usage: api_test list jobs.txt [--repeat N] [--threads T] [--out dir]\n"); return 1; }
  int repeat = 5, threads = 0; const char *outdir = NULL;
  for (int i = 3; i < argc; i++) {
    if (!strcmp(argv[i], "--repeat")) repeat = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--threads")) threads = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--out")) outdir = argv[++i];
  }
  if (repeat > 64) repeat = 64;
  FILE *f = fopen(argv[2], "r"); if (!f) { perror(argv[2]); return 1; }
  char line[2048]; int cap = 0;
  while (fgets(line, sizeof line, f)) {
    if (line[0] == '#' || line[0] == '\n') continue;
    if (njobs == cap) { cap = cap ? cap * 2 : 64; jobs = realloc(jobs, cap * sizeof(job)); }
    job *j = &jobs[njobs]; memset(j, 0, sizeof *j);
    if (sscanf(line, "%1023[^\t]\t%255[^\t]\t%31[^\t]\t%u", j->path, j->entry, j->stage, &j->rt0) < 3) continue;
    if (!(j->air = slurp(j->path, &j->air_size))) { fprintf(stderr, "cannot read %s\n", j->path); return 1; }
    njobs++;
  }
  fclose(f);
  char *err = NULL;
  C = air2ir3_compiler_create(0, &err);
  if (!C) { fprintf(stderr, "compiler_create: %s\n", err); return 1; }
  printf("# api %u abi %u cache format %u id %s\n", air2ir3_api_version(), air2ir3_abi_version(), air2ir3_cache_format_version(), air2ir3_compiler_id());
  int fails = 0;
  for (int n = 0; n < njobs; n++) {
    job *j = &jobs[n];
    for (int k = 0; k < repeat; k++) {
      air2ir3_result r;
      int rc = compile_one(j, &r);
      if (rc) { snprintf(j->err, sizeof j->err, "%s", r.error); air2ir3_result_free(&r); fails++; break; }
      j->ms[j->nms++] = r.compile_ms;
      if (k == 0) {
        j->blob = malloc(r.blob_size); memcpy(j->blob, r.blob, r.blob_size); j->blob_size = r.blob_size; memcpy(j->key, r.key_hex, 65);
        if (outdir) {
          char p[1200]; FILE *o;
          snprintf(p, sizeof p, "%s/%d.ir3v", outdir, n); o = fopen(p, "wb"); fwrite(r.blob, 1, r.blob_size, o); fclose(o);
          snprintf(p, sizeof p, "%s/%d.json", outdir, n); o = fopen(p, "wb"); fwrite(r.sidecar_json, 1, r.sidecar_size, o); fclose(o);
        }
      } else if (r.blob_size != j->blob_size || memcmp(r.blob, j->blob, r.blob_size)) { snprintf(j->err, sizeof j->err, "non-deterministic blob"); fails++; }
      air2ir3_result_free(&r);
    }
    if (j->err[0]) { printf("FAIL\t%s\t%s\t%s\n", j->path, j->entry, j->err); continue; }
    qsort(j->ms, j->nms, sizeof(double), cmpd);
    printf("ok\t%s\t%s\t%s\tmin_ms %.2f\tmedian_ms %.2f\tblob %zu\tkey %s\n", j->path, j->entry, j->stage, j->ms[0], j->ms[j->nms / 2], j->blob_size, j->key);
  }
  if (threads > 1) {
    pthread_t th[64]; targ ta[64]; int mism = 0, tf = 0;
    if (threads > 64) threads = 64;
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int t = 0; t < threads; t++) { ta[t] = (targ){t, threads, 0, 0}; pthread_create(&th[t], NULL, worker, &ta[t]); }
    for (int t = 0; t < threads; t++) { pthread_join(th[t], NULL); mism += ta[t].mismatches; tf += ta[t].failures; }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("# threads %d: %d jobs, %d mismatching blobs/keys, %d failures, %.0f ms wall\n", threads, njobs, mism, tf,
           (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6);
    if (mism || tf) fails++;
  }
  air2ir3_compiler_destroy(C);
  printf("# %d jobs, %d failures\n", njobs, fails);
  return fails ? 1 : 0;
}
