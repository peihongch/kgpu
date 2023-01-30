#include "sha.h"
#include "xts.cu"

__device__ void hmac_sha512(const unsigned char* text,
                            int text_len,
                            const unsigned char* aad,
                            int aad_len,
                            const unsigned char* key,
                            int key_len,
                            uint8_t digest[USHAMaxHashSize]) {
    HMACContext ctx;
    hmacReset(&ctx, SHA512, key, key_len) || hmacInput(&ctx, aad, aad_len) ||
        hmacInput(&ctx, text, text_len) || hmacResult(&ctx, digest);
}

/**
 * A cryptographic unit that implements a cryptographic mode
 * within the XTS-HMAC family shall use the XTS-AES-256 procedure
 * as specified in IEEE Std 1619 for confidentiality, and HMAC-SHA-512
 * as specified by NIST FIPS 198 and NIST FIPS 180-2 to generate the MAC,
 * with the following specifications:
 * a) The cipher key length shall be 1024 b (128 B), consisting of
 *   the concatenation of the following parts, in order:
 *   1) An AES key that is 512 b (64 B) in length, used as input into
 *      the XTS-AES-256 procedure (see IEEE Std 1619).
 *   2) An HMAC key that is 512 b (64 B) in length, used as input into
 *      the HMAC-SHA-512 procedure.
 * b) The cryptographic unit shall compute IVs according to 6.5.
 *   The IV is used as the tweak specified in IEEE Std 1619.
 * c) The IV length shall be 128 b (16 B).
 * d) The resulting MAC shall be 512 b (64 B) in length.
 */
__global__ void xts_hmac_encrypt(uint32_t* crypt_key,
                                 uint32_t* tweak_key,
                                 uint32_t* hmac_key,
                                 uint32_t key_len,
                                 uint8_t* data,
                                 const uint64_t tweak,
                                 uint8_t* mac,
                                 uint32_t mac_length) {
    uint32_t nrounds = AES_ROUNDS(key_len / 4);
    uint32_t hmac_key_len = key_len / 2;
    uint64_t aad[2] = {tweak + blockIdx.x, 0};

    xts_encrypt(crypt_key, tweak_key, nrounds, data, tweak);
    hmac_sha512(data + AUTHENC_SECTOR_SIZE * blockIdx.x, AUTHENC_SECTOR_SIZE,
                (unsigned char*)aad, sizeof(aad), (unsigned char*)hmac_key,
                hmac_key_len, mac + mac_length * blockIdx.x);
}

__global__ void xts_hmac_decrypt(uint32_t* crypt_key,
                                 uint32_t* tweak_key,
                                 uint32_t* hmac_key,
                                 uint32_t key_len,
                                 uint8_t* data,
                                 const uint64_t tweak,
                                 uint8_t* mac,
                                 uint32_t mac_length) {
    uint32_t nrounds = AES_ROUNDS(key_len / 4);
    uint32_t hmac_key_len = key_len / 2;
    uint64_t aad[2] = {tweak + blockIdx.x, 0};

    hmac_sha512(data + AUTHENC_SECTOR_SIZE * blockIdx.x, AUTHENC_SECTOR_SIZE,
                (unsigned char*)aad, sizeof(aad), (unsigned char*)hmac_key,
                hmac_key_len, mac + mac_length * blockIdx.x);
    xts_decrypt(crypt_key, tweak_key, nrounds, data, tweak);
}
