/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Portable AES block primitive for software-provided guest keys. No Apple
 * hardware keys, allocation or secret-indexed lookup tables. Encryption may
 * use the CPU's ARMv8 AES instructions once enabled; that path saves and
 * restores the only two vector registers it touches (v0, v1). */
struct aes_key { uint8_t round_key[240]; uint32_t rounds; };
/* Return one on success, zero on invalid input. Refusal changes no output. */
int aes_expand(struct aes_key *key,const uint8_t *bytes,size_t size);
int aes_block(const struct aes_key *key,const uint8_t input[16],uint8_t output[16],int decrypt);
void aes_clear(void *memory,size_t size);
/* Nonzero iff ID_AA64ISAR0_EL1.AES reports the ARMv8 AES instructions. */
int aes_hardware_supported(uint64_t isar0);
/* aes_block(...,0) with AESE/AESMC. Same validation and result; callers must
 * have checked aes_hardware_supported(). */
int aes_encrypt_hardware(const struct aes_key *key,const uint8_t input[16],uint8_t output[16]);
