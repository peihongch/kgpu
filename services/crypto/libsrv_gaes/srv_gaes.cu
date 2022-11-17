/* This work is licensed under the terms of the GNU GPL, version 2.  See
 * the GPL-COPYING file in the top-level directory.
 *
 * Copyright (c) 2010-2011 University of Utah and the Flux Group.
 * All rights reserved.
 */

#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../../kgpu/gputils.h"
#include "../../../kgpu/kgpu.h"
#include "../gaesu.h"

#define BYTES_PER_BLOCK 1024
#define BYTES_PER_THREAD 4
#define BYTES_PER_GROUP 16
#define THREAD_PER_BLOCK (BYTES_PER_BLOCK / BYTES_PER_THREAD)
#define WORDS_PER_BLOCK (BYTES_PER_BLOCK / 4)

#define BPT_BYTES_PER_BLOCK 4096

struct kgpu_service gecb_enc_srv;
struct kgpu_service gecb_dec_srv;

struct kgpu_service gctr_srv;
struct kgpu_service glctr_srv;

struct kgpu_service bp4t_gecb_enc_srv;
struct kgpu_service bp4t_gecb_dec_srv;

struct kgpu_service gxts_enc_srv;
struct kgpu_service gxts_dec_srv;

struct gecb_data {
    u32* d_key;
    u32* h_key;
    int nrounds;
    int nr_dblks_per_tblk;
};

struct gctr_data {
    u32* d_key;
    u32* h_key;
    u8* d_ctr;
    u8* h_ctr;
    int nrounds;
    int nr_dblks_per_tblk;
};

/*
 * Include device code
 */
#include "ctr.cu"
#include "ecb.cu"
#include "xts_hmac.cu"

int gecb_compute_size_bpt(struct kgpu_service_request* sr) {
    sr->block_x = sr->outsize >= BPT_BYTES_PER_BLOCK ? BPT_BYTES_PER_BLOCK / 16
                                                     : sr->outsize / 16;
    sr->grid_x = sr->outsize / BPT_BYTES_PER_BLOCK
                     ? sr->outsize / BPT_BYTES_PER_BLOCK
                     : 1;
    sr->block_y = 1;
    sr->grid_y = 1;

    return 0;
}

int gecb_compute_size_bp4t(struct kgpu_service_request* sr) {
    sr->block_y = sr->outsize >= BYTES_PER_BLOCK
                      ? BYTES_PER_BLOCK / BYTES_PER_GROUP
                      : (sr->outsize / BYTES_PER_GROUP);
    sr->grid_x =
        sr->outsize / BYTES_PER_BLOCK ? sr->outsize / BYTES_PER_BLOCK : 1;
    sr->block_x = BYTES_PER_GROUP / BYTES_PER_THREAD;
    sr->grid_y = 1;

    return 0;
}

int gecb_launch_bpt(struct kgpu_service_request* sr) {
    struct crypto_aes_ctx* hctx = (struct crypto_aes_ctx*)sr->hdata;
    struct crypto_aes_ctx* dctx = (struct crypto_aes_ctx*)sr->ddata;

    if (sr->s == &gecb_dec_srv)
        aes_decrypt_bpt<<<dim3(sr->grid_x, sr->grid_y),
                          dim3(sr->block_x, sr->block_y), 0,
                          (cudaStream_t)(sr->stream)>>>(
            (u32*)dctx->key_dec, hctx->key_length / 4 + 6, (u8*)sr->dout);
    else
        aes_encrypt_bpt<<<dim3(sr->grid_x, sr->grid_y),
                          dim3(sr->block_x, sr->block_y), 0,
                          (cudaStream_t)(sr->stream)>>>(
            (u32*)dctx->key_enc, hctx->key_length / 4 + 6, (u8*)sr->dout);
    return 0;
}

int gecb_launch_bp4t(struct kgpu_service_request* sr) {
    struct crypto_aes_ctx* hctx = (struct crypto_aes_ctx*)sr->hdata;
    struct crypto_aes_ctx* dctx = (struct crypto_aes_ctx*)sr->ddata;

    if (sr->s == &gecb_dec_srv)
        aes_decrypt_bp4t<<<dim3(sr->grid_x, sr->grid_y),
                           dim3(sr->block_x, sr->block_y), 0,
                           (cudaStream_t)(sr->stream)>>>(
            (u32*)dctx->key_dec, hctx->key_length / 4 + 6, (u8*)sr->dout);
    else
        aes_encrypt_bp4t<<<dim3(sr->grid_x, sr->grid_y),
                           dim3(sr->block_x, sr->block_y), 0,
                           (cudaStream_t)(sr->stream)>>>(
            (u32*)dctx->key_enc, hctx->key_length / 4 + 6, (u8*)sr->dout);

    return 0;
}

int gecb_prepare(struct kgpu_service_request* sr) {
    cudaStream_t s =
        (cudaStream_t)(sr->stream);  // gpu_get_stream(sr->stream_id);

    csc(ah2dcpy(sr->din, sr->hin, sr->insize, s));

    return 0;
}

int gecb_post(struct kgpu_service_request* sr) {
    cudaStream_t s =
        (cudaStream_t)(sr->stream);  // gpu_get_stream(sr->stream_id);

    csc(ad2hcpy(sr->hout, sr->dout, sr->outsize, s));

    return 0;
}

#define gxts_post gecb_post
#define gxts_prepare gecb_prepare

int gxts_compute_size(struct kgpu_service_request* sr) {
    sr->block_x = XTS_SECTOR_SIZE / AES_BLOCK_SIZE;
    sr->grid_x = sr->outsize / XTS_SECTOR_SIZE;
    sr->block_y = 1;
    sr->grid_y = 1;

    return 0;
}

int gxts_launch(struct kgpu_service_request* sr) {
    struct crypto_xts_info* hinfo = (struct crypto_xts_info*)(sr->hdata);
    struct crypto_xts_info* dinfo = (struct crypto_xts_info*)(sr->ddata);

    if (sr->s == &gxts_dec_srv) {
        xts_hmac_decrypt<<<dim3(sr->grid_x, sr->grid_y),
                           dim3(sr->block_x, sr->block_y), 0,
                           (cudaStream_t)(sr->stream)>>>(
            (uint32_t*)dinfo->key_dec, (uint32_t*)dinfo->key_twk,
            (uint32_t*)dinfo->key_hmac, 4 * (uint32_t)hinfo->key_length,
            (uint8_t*)sr->dout, (uint64_t)hinfo->tweak, NULL, 0);
    } else {
        xts_hmac_encrypt<<<dim3(sr->grid_x, sr->grid_y),
                           dim3(sr->block_x, sr->block_y), 0,
                           (cudaStream_t)(sr->stream)>>>(
            (uint32_t*)dinfo->key_enc, (uint32_t*)dinfo->key_twk,
            (uint32_t*)dinfo->key_hmac, 4 * (uint32_t)hinfo->key_length,
            (uint8_t*)sr->dout, (uint64_t)hinfo->tweak, NULL, 0);
    }
    return 0;
}

#define gctr_compute_size gecb_compute_size_bpt
#define gctr_post gecb_post
#define gctr_prepare gecb_prepare

int glctr_compute_size(struct kgpu_service_request* sr) {
    struct crypto_gctr_info* info =
        (struct crypto_gctr_info*)(sr->hdata);
    sr->block_x = info->ctr_range / 16;
    sr->grid_x = sr->outsize / sr->block_x;
    sr->block_y = 1;
    sr->grid_y = 1;

    return 0;
}

int gctr_launch(struct kgpu_service_request* sr) {
    struct crypto_gctr_info* hinfo =
        (struct crypto_gctr_info*)(sr->hdata);
    struct crypto_gctr_info* dinfo =
        (struct crypto_gctr_info*)(sr->ddata);

    aes_ctr_crypt<<<dim3(sr->grid_x, sr->grid_y),
                    dim3(sr->block_x, sr->block_y), 0,
                    (cudaStream_t)(sr->stream)>>>((u32*)dinfo->key_enc,
                                                  hinfo->key_length / 4 + 6,
                                                  (u8*)sr->dout, dinfo->ctrblk);
    return 0;
}

int glctr_launch(struct kgpu_service_request* sr) {
    struct crypto_gctr_info* hinfo =
        (struct crypto_gctr_info*)(sr->hdata);
    struct crypto_gctr_info* dinfo =
        (struct crypto_gctr_info*)(sr->ddata);

    aes_lctr_crypt<<<dim3(sr->grid_x, sr->grid_y),
                     dim3(sr->block_x, sr->block_y), 0,
                     (cudaStream_t)(sr->stream)>>>(
        (u32*)dinfo->key_enc, hinfo->key_length / 4 + 6, (u8*)sr->dout,
        dinfo->ctrblk);
    return 0;
}

/*
 * Naming convention of ciphers:
 * g{algorithm}_{mode}[-({enc}|{dev})]
 *
 * {}  : var value
 * []  : optional
 * (|) : or
 */
extern "C" int init_service(void* lh,
                            int (*reg_srv)(struct kgpu_service*, void*)) {
    int err;
    printf("[libsrv_gaes] Info: init gaes services\n");

    cudaFuncSetCacheConfig(aes_decrypt_bpt, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(aes_encrypt_bpt, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(aes_decrypt_bp4t, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(aes_encrypt_bp4t, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(aes_ctr_crypt, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(aes_lctr_crypt, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(xts_decrypt, cudaFuncCachePreferL1);
    cudaFuncSetCacheConfig(xts_encrypt, cudaFuncCachePreferL1);

    sprintf(gecb_enc_srv.name, "gecb-enc");
    gecb_enc_srv.sid = 0;
    gecb_enc_srv.compute_size = gecb_compute_size_bpt;
    gecb_enc_srv.launch = gecb_launch_bpt;
    gecb_enc_srv.prepare = gecb_prepare;
    gecb_enc_srv.post = gecb_post;

    sprintf(gecb_dec_srv.name, "gecb-dec");
    gecb_dec_srv.sid = 0;
    gecb_dec_srv.compute_size = gecb_compute_size_bpt;
    gecb_dec_srv.launch = gecb_launch_bpt;
    gecb_dec_srv.prepare = gecb_prepare;
    gecb_dec_srv.post = gecb_post;

    sprintf(gctr_srv.name, "gctr");
    gctr_srv.sid = 0;
    gctr_srv.compute_size = gctr_compute_size;
    gctr_srv.launch = gctr_launch;
    gctr_srv.prepare = gctr_prepare;
    gctr_srv.post = gctr_post;

    sprintf(glctr_srv.name, "glctr");
    glctr_srv.sid = 0;
    glctr_srv.compute_size = glctr_compute_size;
    glctr_srv.launch = glctr_launch;
    glctr_srv.prepare = gctr_prepare;
    glctr_srv.post = gctr_post;

    sprintf(gxts_enc_srv.name, "gxts-enc");
    gxts_enc_srv.sid = 0;
    gxts_enc_srv.compute_size = gxts_compute_size;
    gxts_enc_srv.launch = gxts_launch;
    gxts_enc_srv.prepare = gxts_prepare;
    gxts_enc_srv.post = gxts_post;

    sprintf(gxts_dec_srv.name, "gxts-dec");
    gxts_dec_srv.sid = 0;
    gxts_dec_srv.compute_size = gxts_compute_size;
    gxts_dec_srv.launch = gxts_launch;
    gxts_dec_srv.prepare = gxts_prepare;
    gxts_dec_srv.post = gxts_post;

    err = reg_srv(&gecb_enc_srv, lh);
    err |= reg_srv(&gecb_dec_srv, lh);
    err |= reg_srv(&gctr_srv, lh);
    err |= reg_srv(&glctr_srv, lh);
    err |= reg_srv(&gxts_enc_srv, lh);
    err |= reg_srv(&gxts_dec_srv, lh);
    if (err) {
        fprintf(stderr,
                "[libsrv_gaes] Error: failed to register gaes services\n");
    }

    return err;
}

extern "C" int finit_service(void* lh, int (*unreg_srv)(const char*)) {
    int err;
    printf("[libsrv_gaes] Info: finit gaes services\n");

    err = unreg_srv(gecb_enc_srv.name);
    err |= unreg_srv(gecb_dec_srv.name);
    err |= unreg_srv(gctr_srv.name);
    err |= unreg_srv(glctr_srv.name);
    err |= unreg_srv(gxts_enc_srv.name);
    err |= unreg_srv(gxts_dec_srv.name);
    if (err) {
        fprintf(stderr,
                "[libsrv_gaes] Error: failed to unregister gaes services\n");
    }

    return err;
}
