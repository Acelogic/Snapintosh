/* SPDX-License-Identifier: MIT */
#include "sptm-user.h"
#include "sptm-access.h"
#include "sptm-nx-update.h"
#include "sptm-refs.h"
#if SNAP_UNMAP_MIXED
#include "../shadow/shadow.h"
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "nest-fast.h"
#endif
#define PA_MASK 0x0000ffffffffc000UL
#define PAGE_SIZE 0x4000UL

#include "sptm-user/walk_nest.c"
#include "sptm-user/table_map.c"
#include "sptm-user/region_update.c"
