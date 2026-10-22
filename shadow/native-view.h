/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-view.h"
/* SNAP_NATIVE_TABLES user variants (docs/NATIVE-TABLES-DESIGN-20260929.md).
 *
 * A user canonical 4K shadow keeps Apple's raw descriptors and is never
 * installed. Its two permission variants are: w=0 (TPRO pages read-only) and
 * w=1 (TPRO pages writable). Each is the canonical tree with its own copy of
 * the root and of every table on a path to a class 9 leaf; every other table
 * is the canonical one, shared by both variants and by every CPU.
 *
 * Storage is struct sprr_views with copy[w] for w=0/1; copy[2..5] stay zero.
 * The translation is sprr-view.c's user decode with the governing permission
 * fixed to "TPRO write = w": fixed native classes pass through unchanged, a
 * class 9 leaf becomes EL0-accessible, never executable, read-only unless w,
 * and a table pointer names the child's copy when the child has copies.
 *
 * Exactness is maintained per store: every canonical store is followed by
 * native_views_store(), which rewrites the same entry of both copies when the
 * table has copies (O(1)) and refuses a raw class 9 leaf in any table without
 * copies, so hardware can never reach one through a shared table. A new class
 * 9 path is created by native_views_prepare_leaf() BEFORE its leaf is stored;
 * the caller then invalidates walk caches for that VA before the store.
 *
 * umprr is the root's UMPRR (sprr_root_reset): class 9 needs field9 = 0x40000.
 * The caller serializes every call per address space. alloc returns fresh,
 * zeroed pages that alias nothing; write stores into copies only. */
#define NATIVE_VARIANTS 2u
int native_views_init(struct sprr_views *,const struct shadow *,uint64_t umprr);
uint64_t native_views_root(const struct sprr_views *,unsigned w);
/* Index of the copied table whose source is `table`, or -1. */
int native_views_find(const struct sprr_views *,uint64_t table);
/* Copy the path to `va` (4K aligned) where missing and link it into the
 * existing copies. Returns 1 when nothing was added, 2 when a path was
 * linked (the caller must then invalidate walk caches for va before storing
 * a class 9 leaf there), 0 on failure. The canonical level-3 entry for va may
 * be empty or a valid page. */
int native_views_prepare_leaf(struct sprr_views *,const struct shadow *,uint64_t va,uint64_t umprr);
/* Before a canonical store of `value` at `pa`: nonzero unless it would put a
 * raw class 9 leaf into a table without copies, or a value with no
 * translation into a table with copies. O(copied tables). */
int native_views_admit(const struct sprr_views *,uint64_t pa,uint64_t value,uint64_t umprr);
/* After the canonical store of `value` at `pa`. */
int native_views_store(struct sprr_views *,const struct shadow *,uint64_t pa,uint64_t value,
                       uint64_t umprr);
/* Build every missing class 9 path and translate every copy from scratch.
 * For a tree no CPU runs yet (after a build). */
int native_views_sync(struct sprr_views *,const struct shadow *,uint64_t umprr);
/* Audit: every class 9 leaf lies on a copied path, and every copied entry
 * equals the translation of its canonical source. Read-only. */
int native_views_verify(const struct sprr_views *,const struct shadow *,uint64_t umprr);
/* The second half alone (no walk of the whole canonical tree): cheap. */
int native_views_exact(const struct sprr_views *,const struct shadow *,uint64_t umprr);
