/* This work is licensed under the terms of the GNU GPL, version 2.  See
 * the GPL-COPYING file in the top-level directory.
 *
 * Copyright (c) 2010-2011 University of Utah and the Flux Group.
 * All rights reserved.
 *
 * KGPU GAES common header
 */

#ifndef __GAES_COMMON_H__
#define __GAES_COMMON_H__

#define HMAC_MAX_KEYLENGTH (64)  // 512 bits - 64 bytes
#define HMAC_MAX_KEYLENGTH_U32 (HMAC_MAX_KEYLENGTH / sizeof(u32))

struct crypto_gctr_config {
    u32 key_length;
    u32 ctr_range;
};

struct crypto_gctr_info {
    u32 key_enc[AES_MAX_KEYLENGTH_U32];
    u32 key_dec[AES_MAX_KEYLENGTH_U32];
    u32 key_length;
    u32 ctr_range;
    u8 padding[24];
    u8 ctrblk[AES_BLOCK_SIZE];
};

#ifndef __KERNEL__
typedef struct {
    u64 a, b;
} be128;
#else
#include <crypto/b128ops.h>
#endif

#define XTS_SECTOR_SIZE 512

struct crypto_xts_info {
    u32 key_enc[AES_MAX_KEYLENGTH_U32];
    u32 key_dec[AES_MAX_KEYLENGTH_U32];
    u32 key_twk[AES_MAX_KEYLENGTH_U32];
    u32 key_hmac[HMAC_MAX_KEYLENGTH_U32];
    u32 key_length;
    u64 tweak;
};

#define AUTHENC_SECTOR_SIZE 4096

struct crypto_authenc_info {
    u32 key_enc[AES_MAX_KEYLENGTH_U32];   /* expanded enc key for plaintext */
    u32 key_dec[AES_MAX_KEYLENGTH_U32];   /* expanded dec key for ciphertext */
    u32 key_twk[AES_MAX_KEYLENGTH_U32];   /* expanded enc key for tweak */
    u32 key_hmac[HMAC_MAX_KEYLENGTH_U32]; /* raw auth key kor hmac */
    u32 keylen_enc;                       /* xts enc/dec key length */
    u32 keylen_auth;                      /* hmac auth key length */
    u64 tweak;                            /* tweak used for xts */
    u32 textlen;                          /* plaintext or ciphertex length */
    u32 authlen;                          /* auth tag length */
};

#endif