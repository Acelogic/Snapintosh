#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Nested timing conservation, refusal paths, real wrappers and stopped decoder."""
from pathlib import Path
import os
import runpy
import struct
import subprocess
import tempfile
from source_text import read_source

ROOT=Path(__file__).resolve().parents[1]
HARNESS=r'''
#include "service-detail.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
_Static_assert(sizeof(struct service_detail)==6000,"reader record stride");
struct context { int unused; };
struct sptm_root_cached { int unused; };
struct sprr_state { int unused; };
struct shadow { int unused; };
struct sptm_memory { int unused; };
struct sptm_fixed_view { int unused; };
static unsigned wrapper_begins,wrapper_ends,wrapper_kind;
static int wrapper_result,wrapper_started;
static int detail_begin(struct context *c,unsigned kind)
{CHECK(c!=NULL);wrapper_begins++;wrapper_kind=kind;return wrapper_started;}
static void detail_end(struct context *c,unsigned kind,int started,int result)
{CHECK(c!=NULL && kind==wrapper_kind && started==wrapper_started && result==wrapper_result);wrapper_ends++;}
static int kernel_refresh_impl(struct context *c){(void)c;return wrapper_result;}
static int wrapper_invalidate;
static int kernel_change_pperm_impl(struct context *c,uint64_t p,int invalidate)
{(void)c;CHECK(p==0x123 && invalidate==wrapper_invalidate);return wrapper_result;}
static int user_sync_view_impl(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                              const struct sprr_state *s,int el0)
{(void)c;CHECK(e && s && cpu==5 && el0==1);return wrapper_result;}
static int user_refresh_all_impl(struct context *c,struct sptm_root_cached *e)
{(void)c;CHECK(e!=NULL);return wrapper_result;}
static int sptm_root_canonical_view(const struct sptm_root_cached *e,const struct shadow *s,
                                    const struct sptm_memory *m,struct sptm_fixed_view *v)
{CHECK(e && s && m && v);return wrapper_result;}
static int monitor_call_impl(struct context *c,uint64_t *f,uint64_t *pc)
{(void)c;f[0]=0xabcd;*pc+=4;return wrapper_result;}
/* WRAPPERS */
int main(int argc,char **argv)
{
    CHECK(argc==2);struct service_detail p[2]={{0},{0}};
    for(unsigned i=0;i<200;i++) {
        struct service_detail *v=&p[i%2];uint64_t t=100*i;
        CHECK(service_detail_begin(v,18,t));
        CHECK(service_detail_begin(v,0,t+10));
        CHECK(service_detail_begin(v,3,t+20));
        service_detail_end(v,3,t+40,1);service_detail_end(v,0,t+60,1);
        CHECK(service_detail_begin(v,2,t+65));
        service_detail_end(v,2,t+80,i%3!=0);service_detail_end(v,18,t+90,1);
        /* A UPERM write's proof is an outer interval of its own. */
        CHECK(service_detail_begin(v,DETAIL_USER_VIEW_PROOF,t+92));
        service_detail_end(v,DETAIL_USER_VIEW_PROOF,t+95,1);
        CHECK(!v->depth && !v->errors && v->begins==v->ends);
    }
    for(unsigned i=0;i<2;i++) {
        struct service_detail *v=&p[i];uint64_t total=0;
        CHECK(v->begins==500 && v->outer_ticks==9300 && v->max_depth==3);
        CHECK(v->buckets[DETAIL_USER_VIEW_PROOF].inclusive_ticks==300 &&
              v->buckets[DETAIL_USER_VIEW_PROOF].self_ticks==300);
        CHECK(v->buckets[18].inclusive_ticks==9000 && v->buckets[18].self_ticks==2500);
        CHECK(v->buckets[0].inclusive_ticks==5000 && v->buckets[0].self_ticks==3000);
        CHECK(v->buckets[3].inclusive_ticks==2000 && v->buckets[3].max_ticks==20);
        CHECK(v->buckets[2].inclusive_ticks==1500 && v->buckets[2].max_ticks==15);
        for(unsigned n=0;n<SERVICE_DETAIL_BUCKETS;n++)total+=v->buckets[n].self_ticks;
        CHECK(total==v->outer_ticks);
    }
    CHECK(p[0].buckets[2].failed+p[1].buckets[2].failed==67);
    struct service_detail q={0};
    CHECK(service_detail_begin(&q,4,UINT64_MAX-4));service_detail_end(&q,4,7,1);
    CHECK(q.outer_ticks==12 && !q.errors);
    CHECK(!service_detail_begin(&q,SERVICE_DETAIL_BUCKETS,10) && q.errors==1 && !q.depth);
    service_detail_end(&q,0,20,1);CHECK(q.errors==2 && !q.depth);
    q=(struct service_detail){0};
    for(unsigned n=0;n<SERVICE_DETAIL_DEPTH;n++)CHECK(service_detail_begin(&q,n,10+n));
    CHECK(!service_detail_begin(&q,0,20) && q.errors==1 && q.depth==8);
    for(unsigned n=SERVICE_DETAIL_DEPTH;n--;)service_detail_end(&q,n,30+(8-n),1);
    CHECK(q.begins==8 && q.ends==8 && !q.depth);
    q=(struct service_detail){0};CHECK(service_detail_begin(&q,1,10));
    service_detail_end(&q,2,12,1);CHECK(q.errors==1 && q.depth==1 && !q.ends);
    service_detail_end(&q,1,30,0);CHECK(!q.depth && q.ends==1 && q.buckets[1].failed==1);
    q=(struct service_detail){0};CHECK(service_detail_begin(&q,1,10));
    q.stack[0].children=21;service_detail_end(&q,1,30,1);CHECK(q.errors==1 && !q.ends);
    for(unsigned n=0;n<128;n++)CHECK(service_detail_call_bucket(n)==16+n);
    for(unsigned n=32;n<64;n++)CHECK(service_detail_call_bucket((1UL<<n)|2)==DETAIL_OTHER_CALL);
    CHECK(service_detail_call_bucket(128)==DETAIL_OTHER_CALL);
    struct context c={0};struct sptm_root_cached e={0};struct sprr_state s={0};
    for(wrapper_result=0;wrapper_result<2;wrapper_result++)for(wrapper_started=0;wrapper_started<2;wrapper_started++) {
        uint64_t f[31]={0},pc=0x1000;f[16]=2;
        CHECK(kernel_refresh(&c)==wrapper_result && wrapper_kind==DETAIL_KERNEL_REFRESH);
        wrapper_invalidate=1;
        CHECK(kernel_change_pperm(&c,0x123)==wrapper_result && wrapper_kind==DETAIL_KERNEL_PPERM);
        wrapper_invalidate=0;  /* root installation folds its TLBI into the final one */
        CHECK(kernel_change_pperm_timed(&c,0x123,0)==wrapper_result && wrapper_kind==DETAIL_KERNEL_PPERM);
        CHECK(user_sync_view(&c,&e,5,&s,1)==wrapper_result && wrapper_kind==DETAIL_USER_SYNC);
        CHECK(user_refresh_all(&c,&e)==wrapper_result && wrapper_kind==DETAIL_USER_REFRESH);
        struct shadow sh={0};struct sptm_memory m={0};struct sptm_fixed_view view={0};
        CHECK(user_canonical_proof(&c,&e,&sh,&m,&view)==wrapper_result &&
              wrapper_kind==DETAIL_USER_VIEW_PROOF);
        CHECK(monitor_call(&c,f,&pc)==wrapper_result && wrapper_kind==18);
        CHECK(pc==0x1004 && f[0]==0xabcd && wrapper_begins==wrapper_ends);
    }
    FILE *out=fopen(argv[1],"wb");CHECK(out!=NULL);
    CHECK(fwrite(&p[0],sizeof(p[0]),1,out)==1);CHECK(fclose(out)==0);
    printf("PASS: %u timing and real-wrapper checks\n",checks);return 0;
}
'''

def main():
    source=read_source(ROOT/'probes/xnuboot.c')
    extract=runpy.run_path(str(ROOT/'tools/test-guard-step.py'))['function']
    signatures=[
        'static int kernel_refresh(struct context *c)\n{',
        'static int kernel_change_pperm_timed(struct context *c,uint64_t pperm,int invalidate)\n{',
        'static int kernel_change_pperm(void *ctx,uint64_t pperm)\n{',
        'static int user_sync_view(struct context *c,struct sptm_root_cached *e,unsigned cpu,\n'
        '                          const struct sprr_state *state,int el0)\n{',
        'static int user_refresh_all(struct context *c,struct sptm_root_cached *e)\n{',
        'static int user_canonical_proof(struct context *c,const struct sptm_root_cached *e,\n'
        '    const struct shadow *s,const struct sptm_memory *m,struct sptm_fixed_view *out)\n{',
        'static int monitor_call(struct context *c,uint64_t *frame,uint64_t *elr)\n{']
    wrappers='\n'.join(extract(source,s) for s in signatures)
    reader=runpy.run_path(str(ROOT/'tools/capture-service-profile.py'))
    layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
    for optimization in (['-O1'],['-Os','-flto']):
        with tempfile.TemporaryDirectory(prefix='service-detail-') as directory:
            base=Path(directory);src=base/'test.c';exe=base/'test';dump=base/'state.bin'
            src.write_text(HARNESS.replace('/* WRAPPERS */',wrappers))
            subprocess.run([os.environ.get('CC','cc'),'-std=c11',*optimization,'-Wall','-Wextra',
                            '-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'compat'),
                            str(src),'-o',str(exe)],check=True)
            subprocess.run([str(exe),str(dump)],check=True)
            raw=dump.read_bytes();result=reader['decode_detail'](raw,layout,100,10000)
            assert result['outer_seconds']==93 and result['begins']==500
            assert sum(b['self_seconds'] for b in result['buckets'])==93
            assert [b['name'] for b in result['buckets'] if b['bucket']==5]==['canonical user view proof']
            corruptions=[('depth',1),('errors',1),('max_depth',9),('max_depth',0),
                         ('begins',499),('outer_ticks',10001),('outer_ticks',9299)]
            for field,value in corruptions:
                bad=bytearray(raw);struct.pack_into('<Q',bad,layout.offset('service_detail',field),value)
                try:reader['decode_detail'](bad,layout,100,10000)
                except ValueError:pass
                else:raise AssertionError('corrupt detail accepted: '+field)
            for field,value in [('calls',0),('self_ticks',5001),('max_ticks',5001),('failed',101)]:
                bad=bytearray(raw);off=layout.offset('service_detail','buckets')+layout.offset('service_detail_bucket',field)
                struct.pack_into('<Q',bad,off,value)
                try:reader['decode_detail'](bad,layout,100,10000)
                except ValueError:pass
                else:raise AssertionError('corrupt bucket accepted: '+field)
    print('PASS: real C records decoded; 11 corruptions refused at both optimization levels')

if __name__=='__main__':main()
