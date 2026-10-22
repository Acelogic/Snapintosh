#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute the AArch64 compiler runtime with canaries and guard pages on macOS."""
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HARNESS=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
extern void *snap_probe_memcpy(void *,const void *,size_t);
extern void *snap_probe_memset(void *,int,size_t);
static unsigned checks;
#define CHECK(x) do {checks++; if(!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
int main(void)
{
    unsigned char src[1100], dst[1100], expected[1100];
    for(unsigned i=0;i<sizeof(src);i++)src[i]=(unsigned char)(i*73+19);
    for(unsigned a=0;a<16;a++) for(unsigned b=0;b<16;b++)
        for(unsigned n=0;n<=1024;n=n<32 ? n+1 : n+31) {
            memset(dst,0xa7,sizeof(dst));memcpy(expected,dst,sizeof(dst));
            memcpy(expected+16+b,src+16+a,n);
            CHECK(snap_probe_memcpy(dst+16+b,src+16+a,n)==dst+16+b);
            CHECK(!memcmp(dst,expected,sizeof(dst)));
        }
    int values[]={0,1,255,0x1234,-1,-257};
    for(unsigned a=0;a<16;a++) for(unsigned v=0;v<6;v++) for(unsigned n=0;n<=1024;n++) {
        memset(dst,0xa7,sizeof(dst));memcpy(expected,dst,sizeof(dst));
        memset(expected+16+a,values[v],n);
        CHECK(snap_probe_memset(dst+16+a,values[v],n)==dst+16+a);
        CHECK(!memcmp(dst,expected,sizeof(dst)));
    }
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    unsigned char *s=mmap(0,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0);
    unsigned char *d=mmap(0,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0);
    CHECK(s!=MAP_FAILED && d!=MAP_FAILED);
    CHECK(!mprotect(s+page,page,PROT_READ|PROT_WRITE));
    CHECK(!mprotect(d+page,page,PROT_READ|PROT_WRITE));
    for(size_t i=0;i<page;i++)s[page+i]=(unsigned char)i;
    for(size_t n=0;n<512;n++) {
        unsigned char *sp=s+page*2-n,*dp=d+page*2-n;
        CHECK(snap_probe_memcpy(dp,sp,n)==dp);CHECK(!memcmp(dp,sp,n));
        CHECK(snap_probe_memset(dp,0x1d3,n)==dp);
        for(size_t i=0;i<n;i++)CHECK(dp[i]==0xd3);
        /* Left boundary guards catch accesses before either start. */
        CHECK(snap_probe_memcpy(d+page,s+page,n)==d+page);
        CHECK(!memcmp(d+page,s+page,n));
        CHECK(snap_probe_memset(d+page,0,n)==d+page);
    }
    CHECK(!munmap(s,page*3));CHECK(!munmap(d,page*3));
    printf("PASS: %u native AArch64 memory, alignment, return, canary and guard-page checks\n",checks);
}
'''

def main():
    if platform.system()!='Darwin' or platform.machine()!='arm64':
        raise SystemExit('This native test requires an arm64 macOS host')
    source=(ROOT/'probes/memory.S').read_text()
    # Only ELF/Mach-O symbol syntax differs. Execute the production instructions.
    source=re.sub(r'^\.(?:type|size) .+\n','',source,flags=re.M)
    source=re.sub(r'\bmemcpy\b','_snap_probe_memcpy',source)
    source=re.sub(r'\bmemset\b','_snap_probe_memset',source)
    with tempfile.TemporaryDirectory(prefix='snap-probe-memory-') as tmp:
        path=Path(tmp);(path/'memory.S').write_text(source);(path/'test.c').write_text(HARNESS)
        subprocess.run(['cc','-arch','arm64','-Os','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined',str(path/'memory.S'),str(path/'test.c'),
                        '-o',str(path/'test')],check=True)
        subprocess.run([str(path/'test')],check=True)

if __name__=='__main__':main()
