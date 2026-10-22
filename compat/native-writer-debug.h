/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WRITER_DEBUG_H
#define SNAP_NATIVE_WRITER_DEBUG_H
#include "native-writer.h"

#define NATIVE_WRITER_BCR UINT64_C(0x1e3)
#define NATIVE_WRITER_MDSCR UINT64_C(0xa000)

/* Per physical CPU. Saved state is retained for post-stop comparison. */
struct native_writer_debug {
    uint64_t saved_value[6],saved_control[6];
    uint64_t observed_value[6],observed_control[6];
    uint64_t dfr0,saved,installed,install_verified,restores,restore_failed;
    uint64_t traps,rejected,stepped,last_pc,last_word;
};
_Static_assert(sizeof(struct native_writer_debug)==280,"writer debug capture ABI");
struct native_writer_debug_ops {
    uint64_t (*read)(void *ctx,unsigned index,int control);
    void (*write)(void *ctx,unsigned index,int control,uint64_t value);
    void (*barrier)(void *ctx);
    void *ctx;
};
static inline int native_writer_debug_ops_valid(const struct native_writer_debug_ops *o)
{return o && o->read && o->write && o->barrier;}

/* Disable the whole bank before changing any address. Restore every register
 * even if a prior readback fails; the caller must preserve failed qualification. */
static inline int native_writer_debug_restore(struct native_writer_debug *s,
    const struct native_writer_debug_ops *o)
{
    if(!s || !native_writer_debug_ops_valid(o))return 0;
    if(!s->saved)return 1;
    for(unsigned i=0;i<6;i++)o->write(o->ctx,i,1,0);
    o->barrier(o->ctx);
    int ok=1;
    for(unsigned i=0;i<6;i++)ok &= o->read(o->ctx,i,1)==0;
    for(unsigned i=0;i<6;i++)o->write(o->ctx,i,0,s->saved_value[i]);
    o->barrier(o->ctx);
    for(unsigned i=0;i<6;i++)o->write(o->ctx,i,1,s->saved_control[i]);
    o->barrier(o->ctx);
    for(unsigned i=0;i<6;i++) {
        s->observed_value[i]=o->read(o->ctx,i,0);
        s->observed_control[i]=o->read(o->ctx,i,1);
        ok &= s->observed_value[i]==s->saved_value[i] &&
              s->observed_control[i]==s->saved_control[i];
    }
    s->installed=0;s->restores++;
    if(!ok)s->restore_failed++;
    return ok;
}
/* armed: one bit per writer site whose comparator is enabled. A site left
 * unarmed keeps its address with a zero control word, and is verified so;
 * every site's terminal write must then be covered some other way
 * (SNAP_ERET_SNAPSHOT for site 5). */
#define NATIVE_WRITER_ARMED_ALL ((1u<<NATIVE_WRITER_SITE_COUNT)-1)
static inline int native_writer_debug_install_armed(struct native_writer_debug *s,
    const struct native_writer_debug_ops *o,uint64_t dfr0,unsigned armed)
{
    if(!s || !native_writer_debug_ops_valid(o) || s->saved || !armed ||
       (armed&~NATIVE_WRITER_ARMED_ALL))return 0;
    s->dfr0=dfr0;
    unsigned version=dfr0&15;
    if(version<6 || version>11 || ((dfr0>>12)&15)<5)return 0;
    for(unsigned i=0;i<6;i++) {
        s->saved_value[i]=o->read(o->ctx,i,0);
        s->saved_control[i]=o->read(o->ctx,i,1);
    }
    s->saved=1;
    for(unsigned i=0;i<6;i++)o->write(o->ctx,i,1,0);
    o->barrier(o->ctx);
    int disabled=1;
    for(unsigned i=0;i<6;i++)disabled &= o->read(o->ctx,i,1)==0;
    if(!disabled) {native_writer_debug_restore(s,o);return 0;}
    for(unsigned i=0;i<6;i++)o->write(o->ctx,i,0,native_writer_sites[i].va);
    o->barrier(o->ctx);
    for(unsigned i=0;i<6;i++)o->write(o->ctx,i,1,(armed>>i)&1 ? NATIVE_WRITER_BCR : 0);
    o->barrier(o->ctx);
    int ok=1;
    for(unsigned i=0;i<6;i++) {
        s->observed_value[i]=o->read(o->ctx,i,0);
        s->observed_control[i]=o->read(o->ctx,i,1);
        ok &= s->observed_value[i]==native_writer_sites[i].va &&
              s->observed_control[i]==((armed>>i)&1 ? NATIVE_WRITER_BCR : 0);
    }
    if(!ok) {native_writer_debug_restore(s,o);return 0;}
    s->installed=s->install_verified=1;
    return 1;
}
static inline int native_writer_debug_install(struct native_writer_debug *s,
    const struct native_writer_debug_ops *o,uint64_t dfr0)
{return native_writer_debug_install_armed(s,o,dfr0,NATIVE_WRITER_ARMED_ALL);}
#endif
