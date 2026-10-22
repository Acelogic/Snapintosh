/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Physical AArch64 helper for a 47-bit lower address regime. This is a
 * signing/authentication primitive, not a guest key-selection policy.
 * No host key material is written to the result. The input must be a canonical
 * lower pointer, with a top-byte tag only when TBI applies to its key class.
 * Only the signature just produced here is authenticated: malformed
 * authentication can raise FPAC at EL2. */
struct pauth_native_request {
    uint64_t pointer,modifier,key_lo,key_hi,key,tbi,tbid;
};
struct pauth_native_result { uint64_t signed_pointer,authenticated,restored; };
int pauth_native_user(const struct pauth_native_request *,struct pauth_native_result *);
/* Sign arbitrary bits under the same47-bit PAC composition. Never execute
 * AUT: noncanonical inputs may intentionally produce unauthenticatable values.
 * authenticated is zero; signed_pointer is usable only after restored==15
 * and a zero return. This does not alter guest key-selection policy. */
int pauth_native_sign_user(const struct pauth_native_request *,struct pauth_native_result *);
