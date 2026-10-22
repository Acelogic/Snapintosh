/* SPDX-License-Identifier: MIT */
/* SNAP_CANONICAL_VIEW_FAST differential shim. Compile an existing suite that
 * proves canonical or fixed user views with
 *   -Dsptm_root_canonical_view=cv_differential_canonical
 *   -Dsptm_root_fixed_view=cv_differential_fixed
 * and link this file (built without those flags) and compat/sptm-root.c. Every
 * proof the suite makes then runs the reference walk and sptm_root_view_mapped
 * on the same state, and any difference in verdict or result aborts. The
 * suite's own expectations are checked against the reference result.
 *
 * The whole-table reader is built from the suite's own s->read: it returns the
 * page's words exactly when all 512 reads succeed, which is the contract the
 * monitor's canonical_table_read meets for kernel_table_read. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-root.h"

int cv_differential_canonical(const struct sptm_root_cached *,const struct shadow *,
    const struct sptm_memory *,struct sptm_fixed_view *);
int cv_differential_fixed(const struct sptm_root_cached *,const struct shadow *,
    const struct sptm_memory *,struct sptm_fixed_view *);

static const struct shadow *current;
static struct sptm_view_mapped_stats stats;
static unsigned long long proofs,passed,table_reads;
/* Each table read gets its own copy, stable for the whole proof as the
 * monitor's arena mapping is; all are released after the proof. */
static uint64_t *copies[65536];
static unsigned live;
static const volatile uint64_t *table_via_read(void *ctx,uint64_t pa)
{
    table_reads++;
    if(!current || current->ctx!=ctx || live>=sizeof copies/sizeof *copies)abort();
    uint64_t *words=malloc(4096);
    if(!words)abort();
    for(unsigned i=0;i<512;i++)if(current->read(ctx,pa+8UL*i,&words[i])) {free(words);return 0;}
    copies[live++]=words;
    return words;
}
static void release(void) {while(live)free(copies[--live]);}
static void report(void)
{
    fprintf(stderr,"canonical-view differential: %llu proofs (%llu passed), %llu leaves, "
            "%llu source-page walks, %llu span walks, %llu table reads, 0 differences\n",
            proofs,passed,(unsigned long long)stats.leaves,(unsigned long long)stats.walks,
            (unsigned long long)stats.span_walks,table_reads);
}
static int differential(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out,int tpro)
{
    static int registered;
    if(!registered) {registered=1;atexit(report);}
    struct sptm_fixed_view reference={0},fast={0};
    int a=tpro ? sptm_root_canonical_view(e,s,m,&reference) : sptm_root_fixed_view(e,s,m,&reference);
    int b;
    current=s;
    b=sptm_root_view_mapped(e,s,m,&fast,tpro,table_via_read,&stats);
    current=0;release();
    proofs++;passed+=(unsigned)a;
    if(a!=b || (a && memcmp(&reference,&fast,sizeof fast))) {
        fprintf(stderr,"canonical-view differential MISMATCH: tpro %d reference %d fast %d "
                "tables %llu/%llu pages %llu/%llu classes %llx/%llx\n",tpro,a,b,
                (unsigned long long)reference.tables,(unsigned long long)fast.tables,
                (unsigned long long)reference.pages,(unsigned long long)fast.pages,
                (unsigned long long)reference.classes,(unsigned long long)fast.classes);
        abort();
    }
    if(a && out)*out=reference;
    return a;
}
int cv_differential_canonical(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out)
{return differential(e,s,m,out,1);}
int cv_differential_fixed(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out)
{return differential(e,s,m,out,0);}
