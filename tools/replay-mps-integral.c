/* SPDX-License-Identifier: MIT */
// Texture-intrinsic adapters for executing captured Apple AIR on the host CPU.
// No replacement reduction algorithm: the kernel body is the captured LLVM IR.
// Failure inventory: docs/ADRENO-COMPUTE-RECOVERY-20261018.md.
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
typedef float Float2 __attribute__((ext_vector_type(2)));
typedef float Float4 __attribute__((ext_vector_type(4)));
typedef int32_t Int2 __attribute__((ext_vector_type(2)));
typedef struct { uint32_t width,height,stride; float *pixels; } Texture;
static unsigned Errors;
unsigned replay_errors(void) { return Errors; }
void replay_reset(void) { Errors=0; }
Float4 replay_sample(Texture *t,void *sampler,Float2 p,bool offsetPresent,Int2 offset,
                     bool explicitLod,float lod,float bias,int minimumLod) {
    (void)sampler;
    // Captured MPS sampler: unnormalized, nearest, clamp-to-zero; lod zero.
    if(!offsetPresent || explicitLod || lod!=0 || bias!=0 || minimumLod!=0 ||
       !isfinite(p.x) || !isfinite(p.y) || floorf(p.x)!=p.x || floorf(p.y)!=p.y){
        ++Errors;return (Float4){0,0,0,0};
    }
    int x=(int)p.x+offset.x,y=(int)p.y+offset.y;
    if(x<0 || y<0 || (unsigned)x>=t->width || (unsigned)y>=t->height)
        return (Float4){0,0,0,0};
    float *v=t->pixels+y*t->stride+x*4;
    return (Float4){v[0],v[1],v[2],v[3]};
}
void replay_write(Texture *t,Int2 p,Float4 value,int level,int access) {
    if(level!=0 || access!=2 || p.x<0 || p.y<0 || (unsigned)p.x>=t->width || (unsigned)p.y>=t->height){
        ++Errors;return;
    }
    float *v=t->pixels+p.y*t->stride+p.x*4;
    for(unsigned c=0;c<4;c++)v[c]=value[c];
}
