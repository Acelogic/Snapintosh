/* SPDX-License-Identifier: MIT */
/* corpus_compile.c - compile a job list through one libAdrenoCompiler.dylib (C API) and print a digest per job,
 * so two compiler builds can be compared output for output (tools/compare-compilers.py).
 *
 *   corpus_compile LIB.dylib JOBS.tsv OUT.tsv [THREADS]
 *
 * JOBS.tsv, one job per line (tab separated):
 *   id  air-path  entry|-  stage(vertex|fragment|kernel|any)  rt-formats(f0,..,f7|-)  constants(k=v[,v..];..|-)
 *   texture-classes(c0,..,c15|-)  blends(e,op,aop,s,d,sa,da;..x8|-)
 * where a constant key is an index or a name. Every job whose sidecar says exceeds_safe_constlen is compiled
 * again with safe_constlen (id suffix "/safe"), as the plug-in and Turnip do.
 * OUT.tsv: id  rc  key  sha256(blob)  sha256(code)  sha256(program json)  sha256(sidecar json)  error
 * The compiler identity string is blanked in both JSON documents before hashing; nothing else is changed.
 */
#include "air2ir3_api.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *line, *id, *path, *entry, *stage, *rt, *consts, *tex, *blend;
  char out[2][1024];
  int safe_done;
} job;

static job *jobs;
static int njobs, next_job;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static air2ir3_compiler *C;
static __typeof__(&air2ir3_compile_program) p_compile_program;
static __typeof__(&air2ir3_result_free) p_result_free;
static __typeof__(&air2ir3_program_result_free) p_program_free;

static void hex_sha(const void *data, size_t n, char out[65]) {
  unsigned char d[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data, (CC_LONG)n, d);
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) sprintf(out + 2 * i, "%02x", d[i]);
}
/* hash a JSON document with the value of every "compiler_id" string blanked */
static void json_sha(const char *doc, size_t n, char out[65]) {
  char *copy = malloc(n + 1);
  size_t w = 0;
  const char *tag = "\"compiler_id\":\"";
  for (size_t i = 0; i < n;) {
    if (!strncmp(doc + i, tag, strlen(tag))) {
      memcpy(copy + w, tag, strlen(tag)); w += strlen(tag); i += strlen(tag);
      while (i < n && doc[i] != '"') i++;
      continue;
    }
    copy[w++] = doc[i++];
  }
  hex_sha(copy, w, out);
  free(copy);
}
static void *slurp(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
  void *d = malloc(*n);
  if (fread(d, 1, *n, f) != *n) { free(d); d = NULL; }
  fclose(f);
  return d;
}

static int run(job *j, int safe, char *out, size_t outn) {
  size_t n = 0;
  void *air = slurp(j->path, &n);
  if (!air) { snprintf(out, outn, "%s%s\t-1\t-\t-\t-\t-\t-\tcannot read input", j->id, safe ? "/safe" : ""); return 0; }
  air2ir3_compile_info ci; memset(&ci, 0, sizeof ci);
  ci.struct_size = sizeof ci; ci.air = air; ci.air_size = n;
  ci.entry = strcmp(j->entry, "-") ? j->entry : NULL;
  ci.stage = !strcmp(j->stage, "vertex") ? AIR2IR3_STAGE_VERTEX : !strcmp(j->stage, "fragment") ? AIR2IR3_STAGE_FRAGMENT
           : !strcmp(j->stage, "kernel") ? AIR2IR3_STAGE_KERNEL : AIR2IR3_STAGE_ANY;
  ci.raster_sample_count = 1;
  ci.safe_constlen = (uint32_t)safe;
  if (strcmp(j->rt, "-")) {
    char *s = strdup(j->rt), *save = NULL; int i = 0;
    for (char *t = strtok_r(s, ",", &save); t && i < 8; t = strtok_r(NULL, ",", &save)) ci.color_pixel_format[i++] = (uint32_t)atoi(t);
    free(s);
  }
  if (strcmp(j->tex, "-")) {
    char *s = strdup(j->tex), *save = NULL; int i = 0;
    for (char *t = strtok_r(s, ",", &save); t && i < 16; t = strtok_r(NULL, ",", &save)) ci.texture_class[i++] = (uint8_t)atoi(t);
    free(s);
  }
  if (strcmp(j->blend, "-")) {
    char *s = strdup(j->blend), *save = NULL; int i = 0;
    for (char *t = strtok_r(s, ";", &save); t && i < 8; t = strtok_r(NULL, ";", &save), i++) {
      unsigned v[7] = {0};
      sscanf(t, "%u,%u,%u,%u,%u,%u,%u", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]);
      ci.blend[i] = (air2ir3_blend){(uint8_t)v[0], (uint8_t)v[1], (uint8_t)v[2], (uint8_t)v[3], (uint8_t)v[4],
                                    (uint8_t)v[5], (uint8_t)v[6], 0};
    }
    free(s);
  }
  air2ir3_constant consts[256]; int nc = 0;
  char *cs = NULL;
  if (strcmp(j->consts, "-")) {
    cs = strdup(j->consts);
    char *save = NULL;
    for (char *t = strtok_r(cs, ";", &save); t && nc < 256; t = strtok_r(NULL, ";", &save)) {
      char *eq = strchr(t, '=');
      if (!eq) continue;
      *eq = 0;
      air2ir3_constant *c = &consts[nc++]; memset(c, 0, sizeof *c);
      char *end = NULL; long idx = strtol(t, &end, 10);
      if (*t && !*end) { c->index = (int32_t)idx; c->name = NULL; } else { c->index = -1; c->name = t; }
      char *save2 = NULL;
      for (char *v = strtok_r(eq + 1, ",", &save2); v && c->num_values < 4; v = strtok_r(NULL, ",", &save2))
        c->values[c->num_values++] = strtod(v, NULL);
    }
  }
  ci.num_constants = (uint32_t)nc; ci.constants = consts;
  air2ir3_result r; memset(&r, 0, sizeof r);
  air2ir3_program_result pr; memset(&pr, 0, sizeof pr);
  int rc = p_compile_program(C, &ci, &r, &pr);
  char blob[65] = "-", code[65] = "-", prog[65] = "-", side[65] = "-";
  int exceeds = 0;
  if (!rc) {
    hex_sha(r.blob, r.blob_size, blob);
    hex_sha(pr.code, pr.code_size, code);
    json_sha(pr.program_json, pr.program_size, prog);
    json_sha(r.sidecar_json, r.sidecar_size, side);
    exceeds = strstr(r.sidecar_json, "\"exceeds_safe_constlen\":true") != NULL;
  }
  char err[160] = "";
  if (r.error) { snprintf(err, sizeof err, "%s", r.error); for (char *e = err; *e; e++) if (*e == '\t' || *e == '\n') *e = ' '; }
  snprintf(out, outn, "%s%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s", j->id, safe ? "/safe" : "", rc, rc ? "-" : r.key_hex, blob, code, prog, side, err);
  p_result_free(&r); p_program_free(&pr);
  free(cs); free(air);
  return exceeds;
}

static void *worker(void *arg) {
  (void)arg;
  for (;;) {
    pthread_mutex_lock(&lock);
    int i = next_job++;
    pthread_mutex_unlock(&lock);
    if (i >= njobs) return NULL;
    if (run(&jobs[i], 0, jobs[i].out[0], sizeof jobs[i].out[0])) {
      run(&jobs[i], 1, jobs[i].out[1], sizeof jobs[i].out[1]);
      jobs[i].safe_done = 1;
    }
  }
}

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: corpus_compile LIB JOBS.tsv OUT.tsv [THREADS]\n"); return 64; }
  void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) { fprintf(stderr, "%s\n", dlerror()); return 2; }
  __typeof__(&air2ir3_compiler_create) p_create = (__typeof__(&air2ir3_compiler_create))dlsym(h, "air2ir3_compiler_create");
  __typeof__(&air2ir3_compiler_id) p_id = (__typeof__(&air2ir3_compiler_id))dlsym(h, "air2ir3_compiler_id");
  p_compile_program = (__typeof__(p_compile_program))dlsym(h, "air2ir3_compile_program");
  p_result_free = (__typeof__(p_result_free))dlsym(h, "air2ir3_result_free");
  p_program_free = (__typeof__(p_program_free))dlsym(h, "air2ir3_program_result_free");
  if (!p_create || !p_id || !p_compile_program || !p_result_free || !p_program_free) { fprintf(stderr, "missing symbols\n"); return 2; }
  char *err = NULL;
  C = p_create(0, &err);
  if (!C) { fprintf(stderr, "create: %s\n", err); return 2; }
  size_t n = 0;
  char *text = slurp(argv[2], &n);
  if (!text) { perror(argv[2]); return 2; }
  text = realloc(text, n + 1); text[n] = 0;
  int cap = 1024;
  jobs = calloc((size_t)cap, sizeof *jobs);
  char *save = NULL;
  for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    if (!*line || *line == '#') continue;
    if (njobs == cap) { cap *= 2; jobs = realloc(jobs, (size_t)cap * sizeof *jobs); memset(jobs + njobs, 0, (size_t)(cap - njobs) * sizeof *jobs); }
    job *j = &jobs[njobs];
    char *f[8] = {0}; int k = 0; char *s2 = NULL;
    for (char *t = strtok_r(line, "\t", &s2); t && k < 8; t = strtok_r(NULL, "\t", &s2)) f[k++] = t;
    if (k != 8) { fprintf(stderr, "bad job line %d\n", njobs + 1); return 2; }
    j->id = f[0]; j->path = f[1]; j->entry = f[2]; j->stage = f[3]; j->rt = f[4]; j->consts = f[5]; j->tex = f[6]; j->blend = f[7];
    njobs++;
  }
  int threads = argc > 4 ? atoi(argv[4]) : 1;
  if (threads < 1) threads = 1;
  pthread_t *t = calloc((size_t)threads, sizeof *t);
  for (int i = 0; i < threads; i++) pthread_create(&t[i], NULL, worker, NULL);
  for (int i = 0; i < threads; i++) pthread_join(t[i], NULL);
  FILE *o = fopen(argv[3], "w");
  if (!o) { perror(argv[3]); return 2; }
  fprintf(o, "# compiler %s\n", p_id());
  int failures = 0;
  for (int i = 0; i < njobs; i++) {
    fprintf(o, "%s\n", jobs[i].out[0]);
    if (jobs[i].safe_done) fprintf(o, "%s\n", jobs[i].out[1]);
    if (strstr(jobs[i].out[0], "\t0\t") == NULL) failures++;
  }
  fclose(o);
  printf("%d jobs, %d not compiled, compiler %s\n", njobs, failures, p_id());
  return 0;
}
