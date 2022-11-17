/*
 *  Description:
 *     This file implements an incremental hash function based on the SHA
 * algorithms.
 */

#include "sha.h"

__device__ int ISHAReset(ISHAContext* ctx,
                         SHAversion whichSha,
                         uint8_t state[USHAMaxHashSize]) {
    int i;
    if (ctx) {
        ctx->whichSha = whichSha;
        if (state) {
            ctx->state = state;
        } else {
            ctx->state = ctx->intermediate_hash;
            for (i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x) {
                ctx->state[i] = 0;
            }
        }
        return USHAReset(&ctx->shaContext, whichSha);
    } else {
        return shaNull;
    }
}

__device__ int ISHAInput(ISHAContext* ctx,
                         const uint8_t* bytes,
                         unsigned int bytecount,
                         const uint32_t index) {
    int err, i;
    if (ctx) {
        // tmp = Hash(data || ID)
        err = USHAReset(&ctx->shaContext, ctx->whichSha) ||
              USHAInput(&ctx->shaContext, bytes, bytecount) ||
              USHAInput(&ctx->shaContext, (uint8_t*)&index, sizeof(index)) ||
              USHAResult(&ctx->shaContext, ctx->tmp);
        if (err) {
            return err;
        }

        // h = h XOR tmp
        // for (i = 0; i < USHAMaxHashSize; i++) {
        //     ctx->state[i] ^= ctx->tmp[i];
        // }
        // FIXME: how to make it more general?
        for (i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x) {
            ctx->state[i] ^= ctx->tmp[i];
        }
        return shaSuccess;
    } else {
        return shaNull;
    }
}

__device__ int ISHAUpdate(ISHAContext* ctx,
                          const uint8_t* oldbytes,
                          const uint8_t* newbytes,
                          unsigned int bytecount,
                          const uint32_t index) {
    if (ctx) {
        // h = h XOR Hash(olddata || ID)
        // XOR Hash(newdata || ID) into state
        return ISHAInput(ctx, oldbytes, bytecount, index) ||
               // XOR Hash(newdata || ID) into state
               ISHAInput(ctx, newbytes, bytecount, index);
    } else {
        return shaNull;
    }
}

__device__ int ISHAResult(ISHAContext* ctx,
                          uint8_t Message_Digest[USHAMaxHashSize]) {
    int i;
    if (ctx) {
        for (i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x) {
            Message_Digest[i] = ctx->state[i];
        }
        return shaSuccess;
    } else {
        return shaNull;
    }
}
