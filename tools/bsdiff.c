/* SPDX-License-Identifier: MIT */
/* bsdiff 4.3 (BSDIFF40) after Colin Percival's algorithm: qsufsort suffix array, approximate
 * matches extended forward/backward, bzip2'd control, diff and extra blocks. Output is applied
 * by any bspatch (/usr/bin/bspatch). Scratch tool for the compiler-runtime transfer size.
 *   cc -O2 -o bsdiff bsdiff.c -lbz2 && ./bsdiff OLD NEW PATCH */
#include <bzlib.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static void split(int64_t *I, int64_t *V, int64_t start, int64_t len, int64_t h) {
    int64_t i, j, k, x, tmp, jj, kk;
    if (len < 16) {
        for (k = start; k < start + len; k += j) {
            j = 1; x = V[I[k] + h];
            for (i = 1; k + i < start + len; i++) {
                if (V[I[k + i] + h] < x) { x = V[I[k + i] + h]; j = 0; }
                if (V[I[k + i] + h] == x) { tmp = I[k + j]; I[k + j] = I[k + i]; I[k + i] = tmp; j++; }
            }
            for (i = 0; i < j; i++) V[I[k + i]] = k + j - 1;
            if (j == 1) I[k] = -1;
        }
        return;
    }
    x = V[I[start + len / 2] + h];
    jj = 0; kk = 0;
    for (i = start; i < start + len; i++) {
        if (V[I[i] + h] < x) jj++;
        if (V[I[i] + h] == x) kk++;
    }
    jj += start; kk += jj;
    i = start; j = 0; k = 0;
    while (i < jj) {
        if (V[I[i] + h] < x) i++;
        else if (V[I[i] + h] == x) { tmp = I[i]; I[i] = I[jj + j]; I[jj + j] = tmp; j++; }
        else { tmp = I[i]; I[i] = I[kk + k]; I[kk + k] = tmp; k++; }
    }
    while (jj + j < kk) {
        if (V[I[jj + j] + h] == x) j++;
        else { tmp = I[jj + j]; I[jj + j] = I[kk + k]; I[kk + k] = tmp; k++; }
    }
    if (jj > start) split(I, V, start, jj - start, h);
    for (i = 0; i < kk - jj; i++) V[I[jj + i]] = kk - 1;
    if (jj == kk - 1) I[jj] = -1;
    if (start + len > kk) split(I, V, kk, start + len - kk, h);
}

static void qsufsort(int64_t *I, int64_t *V, const uint8_t *old, int64_t oldsize) {
    int64_t buckets[256], i, h, len;
    memset(buckets, 0, sizeof buckets);
    for (i = 0; i < oldsize; i++) buckets[old[i]]++;
    for (i = 1; i < 256; i++) buckets[i] += buckets[i - 1];
    for (i = 255; i > 0; i--) buckets[i] = buckets[i - 1];
    buckets[0] = 0;
    for (i = 0; i < oldsize; i++) I[++buckets[old[i]]] = i;
    I[0] = oldsize;
    for (i = 0; i < oldsize; i++) V[i] = buckets[old[i]];
    V[oldsize] = 0;
    for (i = 1; i < 256; i++) if (buckets[i] == buckets[i - 1] + 1) I[buckets[i]] = -1;
    I[0] = -1;
    for (h = 1; I[0] != -(oldsize + 1); h += h) {
        len = 0;
        for (i = 0; i < oldsize + 1;) {
            if (I[i] < 0) { len -= I[i]; i -= I[i]; }
            else {
                if (len) I[i - len] = -len;
                len = V[I[i]] + 1 - i;
                split(I, V, i, len, h);
                i += len; len = 0;
            }
        }
        if (len) I[i - len] = -len;
    }
    for (i = 0; i < oldsize + 1; i++) I[V[i]] = i;
}

static int64_t matchlen(const uint8_t *a, int64_t an, const uint8_t *b, int64_t bn) {
    int64_t i;
    for (i = 0; i < an && i < bn; i++) if (a[i] != b[i]) break;
    return i;
}

static int64_t search(const int64_t *I, const uint8_t *old, int64_t oldsize, const uint8_t *new, int64_t newsize,
                      int64_t st, int64_t en, int64_t *pos) {
    int64_t x, y;
    if (en - st < 2) {
        x = matchlen(old + I[st], oldsize - I[st], new, newsize);
        y = matchlen(old + I[en], oldsize - I[en], new, newsize);
        if (x > y) { *pos = I[st]; return x; }
        *pos = I[en]; return y;
    }
    x = st + (en - st) / 2;
    if (memcmp(old + I[x], new, MIN(oldsize - I[x], newsize)) < 0) return search(I, old, oldsize, new, newsize, x, en, pos);
    return search(I, old, oldsize, new, newsize, st, x, pos);
}

static void offtout(int64_t x, uint8_t *buf) {
    uint64_t y = x < 0 ? (uint64_t)(-x) : (uint64_t)x;
    for (int i = 0; i < 8; i++) { buf[i] = y & 0xff; y >>= 8; }
    if (x < 0) buf[7] |= 0x80;
}

static uint8_t *readfile(const char *path, int64_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) err(1, "%s", path);
    struct stat st;
    if (fstat(fd, &st)) err(1, "%s", path);
    uint8_t *p = malloc((size_t)st.st_size + 1);
    if (!p) err(1, "malloc");
    int64_t got = 0;
    while (got < st.st_size) {
        ssize_t r = read(fd, p + got, (size_t)(st.st_size - got));
        if (r <= 0) err(1, "read %s", path);
        got += r;
    }
    close(fd);
    *size = st.st_size;
    return p;
}

static BZFILE *bzopen(FILE *f) {
    int e;
    BZFILE *b = BZ2_bzWriteOpen(&e, f, 9, 0, 0);
    if (e != BZ_OK) errx(1, "BZ2_bzWriteOpen %d", e);
    return b;
}
static void bzwrite(BZFILE *b, const void *p, int64_t n) {
    int e;
    while (n > 0) {
        int chunk = n > (1 << 30) ? (1 << 30) : (int)n;
        BZ2_bzWrite(&e, b, (void *)p, chunk);
        if (e != BZ_OK) errx(1, "BZ2_bzWrite %d", e);
        p = (const uint8_t *)p + chunk; n -= chunk;
    }
}
static void bzclose(BZFILE *b) {
    int e;
    BZ2_bzWriteClose(&e, b, 0, NULL, NULL);
    if (e != BZ_OK) errx(1, "BZ2_bzWriteClose %d", e);
}

int main(int argc, char **argv) {
    if (argc != 4) errx(1, "usage: %s old new patch", argv[0]);
    int64_t oldsize, newsize;
    uint8_t *old = readfile(argv[1], &oldsize), *new = readfile(argv[2], &newsize);
    int64_t *I = malloc((size_t)(oldsize + 1) * sizeof *I), *V = malloc((size_t)(oldsize + 1) * sizeof *V);
    if (!I || !V) err(1, "malloc");
    qsufsort(I, V, old, oldsize);
    free(V);
    uint8_t *db = malloc((size_t)newsize + 1), *eb = malloc((size_t)newsize + 1);
    if (!db || !eb) err(1, "malloc");
    int64_t dblen = 0, eblen = 0;
    /* control triples are buffered, then written as one bzip2 stream */
    size_t ctrlcap = 1 << 20, ctrllen = 0;
    uint8_t *ctrl = malloc(ctrlcap);
    FILE *pf = fopen(argv[3], "wb");
    if (!pf) err(1, "%s", argv[3]);
    uint8_t header[32];
    memcpy(header, "BSDIFF40", 8);
    offtout(0, header + 8); offtout(0, header + 16); offtout(newsize, header + 24);
    if (fwrite(header, 32, 1, pf) != 1) err(1, "fwrite");

    int64_t scan = 0, len = 0, pos = 0, lastscan = 0, lastpos = 0, lastoffset = 0;
    int64_t oldscore, scsc, s, Sf, lenf, Sb, lenb, overlap, Ss, lens, i;
    while (scan < newsize) {
        oldscore = 0;
        for (scsc = scan += len; scan < newsize; scan++) {
            len = search(I, old, oldsize, new + scan, newsize - scan, 0, oldsize, &pos);
            for (; scsc < scan + len; scsc++)
                if (scsc + lastoffset < oldsize && old[scsc + lastoffset] == new[scsc]) oldscore++;
            if ((len == oldscore && len != 0) || len > oldscore + 8) break;
            if (scan + lastoffset < oldsize && old[scan + lastoffset] == new[scan]) oldscore--;
        }
        if (len != oldscore || scan == newsize) {
            s = 0; Sf = 0; lenf = 0;
            for (i = 0; lastscan + i < scan && lastpos + i < oldsize;) {
                if (old[lastpos + i] == new[lastscan + i]) s++;
                i++;
                if (s * 2 - i > Sf * 2 - lenf) { Sf = s; lenf = i; }
            }
            lenb = 0;
            if (scan < newsize) {
                s = 0; Sb = 0;
                for (i = 1; scan >= lastscan + i && pos >= i; i++) {
                    if (old[pos - i] == new[scan - i]) s++;
                    if (s * 2 - i > Sb * 2 - lenb) { Sb = s; lenb = i; }
                }
            }
            if (lastscan + lenf > scan - lenb) {
                overlap = (lastscan + lenf) - (scan - lenb);
                s = 0; Ss = 0; lens = 0;
                for (i = 0; i < overlap; i++) {
                    if (new[lastscan + lenf - overlap + i] == old[lastpos + lenf - overlap + i]) s++;
                    if (new[scan - lenb + i] == old[pos - lenb + i]) s--;
                    if (s > Ss) { Ss = s; lens = i + 1; }
                }
                lenf += lens - overlap;
                lenb -= lens;
            }
            for (i = 0; i < lenf; i++) db[dblen + i] = new[lastscan + i] - old[lastpos + i];
            for (i = 0; i < (scan - lenb) - (lastscan + lenf); i++) eb[eblen + i] = new[lastscan + lenf + i];
            dblen += lenf;
            eblen += (scan - lenb) - (lastscan + lenf);
            if (ctrllen + 24 > ctrlcap) { ctrlcap *= 2; ctrl = realloc(ctrl, ctrlcap); if (!ctrl) err(1, "realloc"); }
            offtout(lenf, ctrl + ctrllen);
            offtout((scan - lenb) - (lastscan + lenf), ctrl + ctrllen + 8);
            offtout((pos - lenb) - (lastpos + lenf), ctrl + ctrllen + 16);
            ctrllen += 24;
            lastscan = scan - lenb;
            lastpos = pos - lenb;
            lastoffset = pos - scan;
        }
    }
    BZFILE *b = bzopen(pf); bzwrite(b, ctrl, (int64_t)ctrllen); bzclose(b);
    long ctrlend = ftell(pf);
    b = bzopen(pf); bzwrite(b, db, dblen); bzclose(b);
    long diffend = ftell(pf);
    b = bzopen(pf); bzwrite(b, eb, eblen); bzclose(b);
    offtout(ctrlend - 32, header + 8);
    offtout(diffend - ctrlend, header + 16);
    if (fseek(pf, 0, SEEK_SET) || fwrite(header, 32, 1, pf) != 1 || fclose(pf)) err(1, "header");
    fprintf(stderr, "ctrl %ld diff %ld extra %lld bytes compressed total; diff %lld extra %lld raw\n",
            ctrlend - 32, diffend - ctrlend, (long long)0, (long long)dblen, (long long)eblen);
    return 0;
}
