/*
 * Authenc: Simple AEAD wrapper for IPsec
 *
 * Copyright (c) 2007 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "../../../kgpu/kgpu.h"
#include "../gaesk.h"

/* customized log function */
#define g_log(level, ...) kgpu_do_log(level, "gauthenc", ##__VA_ARGS__)
#define dbg(...) g_log(KGPU_LOG_DEBUG, ##__VA_ARGS__)

typedef u8* (*authenc_ahash_t)(struct aead_request* req, unsigned int flags);
typedef int (*crypto_authenc_crypt_gpu_t)(struct aead_request* req,
                                          struct completion* c,
                                          unsigned int data_offset,
                                          unsigned int data_size,
                                          unsigned int tag_offset,
                                          unsigned int tag_size,
                                          int enc);

struct authenc_instance_ctx {
    struct crypto_ahash_spawn auth;
    struct crypto_skcipher_spawn enc;
};

struct crypto_authenc_ctx {
    unsigned int reqoff;
    struct crypto_ahash* auth;
    struct crypto_ablkcipher* enc;
    struct crypto_authenc_info info;
};

struct authenc_request_ctx {
    unsigned int cryptlen;
    struct scatterlist* sg;
    struct scatterlist asg[2];
    struct scatterlist cipher[2];
    crypto_completion_t complete;
    crypto_completion_t update_complete;
    char tail[];
};

struct gauthenc_async_data {
    struct completion* c;             /* async-call completion */
    struct scatterlist *dst, *src;    /* crypt destination and source */
    struct ablkcipher_request* abreq; /* alblkcipher request */
    void* expage;                     /* extra page for calling KGPU, if any */
    unsigned int data_offset;         /* data offset within scatterlists */
    unsigned int tag_offset;          /* tag offset within scatterlists */
    unsigned int data_size;
    unsigned int tag_size;
};

static int zero_copy = 0;
static int split_threshold = 256;
module_param(zero_copy, int, 0444);
MODULE_PARM_DESC(zero_copy, "use GPU mem zero-copy, default 0 (No)");
module_param(split_threshold, int, 0444);
MODULE_PARM_DESC(split_threshold,
                 "size(#pages) threshold for split, default 256");

static void authenc_request_complete(struct aead_request* req, int err) {
    if (err != -EINPROGRESS) {
        aead_request_complete(req, err);
    }
}

static int crypto_authenc_setkey(struct crypto_aead* authenc,
                                 const u8* key,
                                 unsigned int keylen) {
    unsigned int authkeylen;
    unsigned int enckeylen;
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct crypto_aes_ctx aes_ctx;
    struct crypto_ahash* auth = ctx->auth;
    struct crypto_ablkcipher* enc = ctx->enc;
    struct rtattr* rta = (void*)key;
    struct crypto_authenc_key_param* param;
    int err = -EINVAL;

    if (!RTA_OK(rta, keylen))
        goto badkey;
    if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
        goto badkey;
    if (RTA_PAYLOAD(rta) < sizeof(*param))
        goto badkey;

    param = RTA_DATA(rta);
    enckeylen = be32_to_cpu(param->enckeylen);

    key += RTA_ALIGN(rta->rta_len);
    keylen -= RTA_ALIGN(rta->rta_len);

    if (keylen < enckeylen)
        goto badkey;

    authkeylen = keylen - enckeylen;

    crypto_ahash_clear_flags(auth, CRYPTO_TFM_REQ_MASK);
    crypto_ahash_set_flags(
        auth, crypto_aead_get_flags(authenc) & CRYPTO_TFM_REQ_MASK);
    err = crypto_ahash_setkey(auth, key, authkeylen);
    crypto_aead_set_flags(authenc,
                          crypto_ahash_get_flags(auth) & CRYPTO_TFM_RES_MASK);

    if (err)
        goto out;

    crypto_ablkcipher_clear_flags(enc, CRYPTO_TFM_REQ_MASK);
    crypto_ablkcipher_set_flags(
        enc, crypto_aead_get_flags(authenc) & CRYPTO_TFM_REQ_MASK);
    err = crypto_ablkcipher_setkey(enc, key + authkeylen, enckeylen);
    crypto_aead_set_flags(
        authenc, crypto_ablkcipher_get_flags(enc) & CRYPTO_TFM_RES_MASK);

    if (err)
        goto out;

    /* Set key info for gpu auth and enc */

    memcpy(ctx->info.key_hmac, key, authkeylen);
    ctx->info.keylen_auth = authkeylen;

    err = crypto_aes_expand_key(&aes_ctx, key + authkeylen, enckeylen / 2);
    if (err)
        goto out;
    cvt_endian_u32(aes_ctx.key_enc, AES_MAX_KEYLENGTH_U32);
    cvt_endian_u32(aes_ctx.key_dec, AES_MAX_KEYLENGTH_U32);
    memcpy(ctx->info.key_enc, aes_ctx.key_enc, AES_MAX_KEYLENGTH);
    memcpy(ctx->info.key_dec, aes_ctx.key_dec, AES_MAX_KEYLENGTH);
    err = crypto_aes_expand_key(&aes_ctx, key + authkeylen + enckeylen / 2,
                                enckeylen / 2);
    if (err)
        goto out;
    memcpy(ctx->info.key_twk, aes_ctx.key_enc, AES_MAX_KEYLENGTH);
    ctx->info.keylen_enc = aes_ctx.key_length;

out:
    return err;

badkey:
    crypto_aead_set_flags(authenc, CRYPTO_TFM_RES_BAD_KEY_LEN);
    goto out;
}

static void authenc_geniv_ahash_update_done(struct crypto_async_request* areq,
                                            int err) {
    struct aead_request* req = areq->data;
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ahash_request* ahreq = (void*)(areq_ctx->tail + ctx->reqoff);

    if (err)
        goto out;

    ahash_request_set_crypt(ahreq, areq_ctx->sg, ahreq->result,
                            areq_ctx->cryptlen);
    ahash_request_set_callback(
        ahreq, aead_request_flags(req) & CRYPTO_TFM_REQ_MAY_SLEEP,
        areq_ctx->complete, req);

    err = crypto_ahash_finup(ahreq);
    if (err)
        goto out;

    scatterwalk_map_and_copy(ahreq->result, areq_ctx->sg, areq_ctx->cryptlen,
                             crypto_aead_authsize(authenc), 1);

out:
    authenc_request_complete(req, err);
}

static void authenc_geniv_ahash_done(struct crypto_async_request* areq,
                                     int err) {
    struct aead_request* req = areq->data;
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ahash_request* ahreq = (void*)(areq_ctx->tail + ctx->reqoff);

    if (err)
        goto out;

    scatterwalk_map_and_copy(ahreq->result, areq_ctx->sg, areq_ctx->cryptlen,
                             crypto_aead_authsize(authenc), 1);

out:
    aead_request_complete(req, err);
}

static void authenc_verify_ahash_update_done(struct crypto_async_request* areq,
                                             int err) {
    u8* ihash;
    unsigned int authsize;
    struct ablkcipher_request* abreq;
    struct aead_request* req = areq->data;
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ahash_request* ahreq = (void*)(areq_ctx->tail + ctx->reqoff);
    unsigned int cryptlen = req->cryptlen;

    if (err)
        goto out;

    ahash_request_set_crypt(ahreq, areq_ctx->sg, ahreq->result,
                            areq_ctx->cryptlen);
    ahash_request_set_callback(
        ahreq, aead_request_flags(req) & CRYPTO_TFM_REQ_MAY_SLEEP,
        areq_ctx->complete, req);

    err = crypto_ahash_finup(ahreq);
    if (err)
        goto out;

    authsize = crypto_aead_authsize(authenc);
    cryptlen -= authsize;
    ihash = ahreq->result + authsize;
    scatterwalk_map_and_copy(ihash, areq_ctx->sg, areq_ctx->cryptlen, authsize,
                             0);

    err = memcmp(ihash, ahreq->result, authsize) ? -EBADMSG : 0;
    if (err)
        goto out;

    abreq = aead_request_ctx(req);
    ablkcipher_request_set_tfm(abreq, ctx->enc);
    ablkcipher_request_set_callback(abreq, aead_request_flags(req),
                                    req->base.complete, req->base.data);
    ablkcipher_request_set_crypt(abreq, req->src, req->dst, cryptlen, req->iv);

    err = crypto_ablkcipher_decrypt(abreq);

out:
    authenc_request_complete(req, err);
}

static void authenc_verify_ahash_done(struct crypto_async_request* areq,
                                      int err) {
    u8* ihash;
    unsigned int authsize;
    struct ablkcipher_request* abreq;
    struct aead_request* req = areq->data;
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ahash_request* ahreq = (void*)(areq_ctx->tail + ctx->reqoff);
    unsigned int cryptlen = req->cryptlen;

    if (err)
        goto out;

    authsize = crypto_aead_authsize(authenc);
    cryptlen -= authsize;
    ihash = ahreq->result + authsize;
    scatterwalk_map_and_copy(ihash, areq_ctx->sg, areq_ctx->cryptlen, authsize,
                             0);

    err = memcmp(ihash, ahreq->result, authsize) ? -EBADMSG : 0;
    if (err)
        goto out;

    abreq = aead_request_ctx(req);
    ablkcipher_request_set_tfm(abreq, ctx->enc);
    ablkcipher_request_set_callback(abreq, aead_request_flags(req),
                                    req->base.complete, req->base.data);
    ablkcipher_request_set_crypt(abreq, req->src, req->dst, cryptlen, req->iv);

    err = crypto_ablkcipher_decrypt(abreq);

out:
    authenc_request_complete(req, err);
}

static u8* crypto_authenc_ahash_fb(struct aead_request* req,
                                   unsigned int flags) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct crypto_ahash* auth = ctx->auth;
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ahash_request* ahreq = (void*)(areq_ctx->tail + ctx->reqoff);
    u8* hash = areq_ctx->tail;
    int err;

    hash = (u8*)ALIGN((unsigned long)hash + crypto_ahash_alignmask(auth),
                      crypto_ahash_alignmask(auth) + 1);

    ahash_request_set_tfm(ahreq, auth);

    err = crypto_ahash_init(ahreq);
    if (err)
        return ERR_PTR(err);

    ahash_request_set_crypt(ahreq, req->assoc, hash, req->assoclen);
    ahash_request_set_callback(ahreq, aead_request_flags(req) & flags,
                               areq_ctx->update_complete, req);

    err = crypto_ahash_update(ahreq);
    if (err)
        return ERR_PTR(err);

    ahash_request_set_crypt(ahreq, areq_ctx->sg, hash, areq_ctx->cryptlen);
    ahash_request_set_callback(ahreq, aead_request_flags(req) & flags,
                               areq_ctx->complete, req);

    err = crypto_ahash_finup(ahreq);
    if (err)
        return ERR_PTR(err);

    return hash;
}

static u8* crypto_authenc_ahash(struct aead_request* req, unsigned int flags) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct crypto_ahash* auth = ctx->auth;
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ahash_request* ahreq = (void*)(areq_ctx->tail + ctx->reqoff);
    u8* hash = areq_ctx->tail;
    int err;

    hash = (u8*)ALIGN((unsigned long)hash + crypto_ahash_alignmask(auth),
                      crypto_ahash_alignmask(auth) + 1);

    ahash_request_set_tfm(ahreq, auth);
    ahash_request_set_crypt(ahreq, areq_ctx->sg, hash, areq_ctx->cryptlen);
    ahash_request_set_callback(ahreq, aead_request_flags(req) & flags,
                               areq_ctx->complete, req);

    err = crypto_ahash_digest(ahreq);
    if (err)
        return ERR_PTR(err);

    return hash;
}

static int crypto_authenc_genicv(struct aead_request* req,
                                 u8* iv,
                                 unsigned int flags) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct scatterlist* dst = req->dst;
    struct scatterlist* assoc = req->assoc;
    struct scatterlist* cipher = areq_ctx->cipher;
    struct scatterlist* asg = areq_ctx->asg;
    unsigned int ivsize = crypto_aead_ivsize(authenc);
    unsigned int cryptlen = req->cryptlen;
    authenc_ahash_t authenc_ahash_fn = crypto_authenc_ahash_fb;
    struct page* dstp;
    u8* vdst;
    u8* hash;

    dstp = sg_page(dst);
    vdst = PageHighMem(dstp) ? NULL : page_address(dstp) + dst->offset;

    if (ivsize) {
        sg_init_table(cipher, 2);
        sg_set_buf(cipher, iv, ivsize);
        scatterwalk_crypto_chain(cipher, dst, vdst == iv + ivsize, 2);
        dst = cipher;
        cryptlen += ivsize;
    }

    if (req->assoclen && sg_is_last(assoc)) {
        authenc_ahash_fn = crypto_authenc_ahash;
        sg_init_table(asg, 2);
        sg_set_page(asg, sg_page(assoc), assoc->length, assoc->offset);
        scatterwalk_crypto_chain(asg, dst, 0, 2);
        dst = asg;
        cryptlen += req->assoclen;
    }

    areq_ctx->cryptlen = cryptlen;
    areq_ctx->sg = dst;

    areq_ctx->complete = authenc_geniv_ahash_done;
    areq_ctx->update_complete = authenc_geniv_ahash_update_done;

    hash = authenc_ahash_fn(req, flags);
    if (IS_ERR(hash))
        return PTR_ERR(hash);

    scatterwalk_map_and_copy(hash, dst, cryptlen, crypto_aead_authsize(authenc),
                             1);
    return 0;
}

static void crypto_authenc_crypt_gpu_done(struct ablkcipher_request* abreq,
                                          char* buf,
                                          unsigned int data_offset,
                                          unsigned int data_size,
                                          unsigned int tag_offset,
                                          unsigned int tag_size) {
    struct ablkcipher_walk walk;
    struct scatterlist* dst = abreq->dst;
    struct scatterlist* src = abreq->src;
    unsigned int nbytes, cur;
    int err;

    ablkcipher_walk_init(&walk, dst, src, tag_size + tag_offset);
    err = ablkcipher_walk_phys(abreq, &walk);
    cur = 0;
    while ((nbytes = walk.nbytes)) {
        if ((cur >= data_offset && cur < data_offset + data_size) ||
            (cur >= tag_offset && cur < tag_offset + tag_size)) {
            memcpy(
                phys_to_virt((page_to_phys(walk.dst.page) + walk.dst.offset)),
                buf, nbytes);
            buf += nbytes;
        }

        cur += nbytes;
        ablkcipher_walk_done(abreq, &walk, 0);
        if (cur >= tag_size + tag_offset && cur >= data_size + data_offset)
            break;
    }
}

static int crypto_authenc_crypt_gpu_async_callback(struct kgpu_request* req) {
    struct gauthenc_async_data* data = (struct gauthenc_async_data*)req->kdata;

    if (!zero_copy) {
        crypto_authenc_crypt_gpu_done(data->abreq, (char*)req->out,
                                      data->data_offset, data->data_size,
                                      data->tag_offset, data->tag_size);
    }

    complete(data->c);

    if (zero_copy) {
        kgpu_unmap_area(TO_UL(req->in));
    } else {
        kgpu_vfree(req->in);
    }

    if (data->expage) {
        free_page(TO_UL(data->expage));
    }
    kgpu_free_request(req);

    kfree(data);
    return 0;
}

static int crypto_authenc_crypt_gpu_zc(struct aead_request* req,
                                       struct completion* c,
                                       unsigned int data_offset,
                                       unsigned int data_size,
                                       unsigned int tag_offset,
                                       unsigned int tag_size,
                                       int crypt_enc) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ablkcipher_request* abreq = (void*)(areq_ctx->tail + ctx->reqoff);
    struct scatterlist* src = abreq->src;
    struct scatterlist* dst = abreq->dst;

    int err;
    int i, n;
    size_t info_size = sizeof(struct crypto_authenc_info);
    size_t rsz = roundup(data_size + tag_size, PAGE_SIZE);
    int inplace = (sg_virt(dst) == sg_virt(src));

    struct kgpu_request* kreq;
    unsigned long addr;
    unsigned int pgoff;
    struct scatterlist* sg;

    char* data = (char*)__get_free_page(GFP_KERNEL);
    if (!data) {
        g_log(KGPU_LOG_ERROR, "out of memory for data\n");
        return -ENOMEM;
    }

    /**
     * All parts are algned to PAGE_SIZE:
     *
     * | round (data + tag) size | info | [round (data + tag) size] |
     * |<----------- insize ----------->|
     * |<--- inplace outsize --->|
     *                                  |<-- not inplace outsize -->|
     *
     * Note: info can fit in one page.
     */
    addr = kgpu_alloc_mmap_area(PAGE_SIZE + (inplace ? rsz : 2 * rsz));
    if (!addr) {
        free_page(TO_UL(data));
        g_log(KGPU_LOG_ERROR,
              "GPU buffer space is null for size %u inplace %d\n", rsz,
              inplace);
        return -ENOMEM;
    }

    kreq = kgpu_alloc_request();
    if (!kreq) {
        kgpu_free_mmap_area(addr);
        free_page(TO_UL(data));
        g_log(KGPU_LOG_ERROR, "can't allocate request\n");
        return -EFAULT;
    }

    kreq->in = (void*)addr;
    kreq->out = (void*)(inplace ? addr : addr + rsz + PAGE_SIZE);
    kreq->insize = rsz + info_size;
    kreq->outsize = tag_size + data_size;
    kreq->udatasize = info_size;
    kreq->udata = (void*)(addr + rsz);

    memcpy(data, &(ctx->info), sizeof(ctx->info));
    strcpy(kreq->service_name, crypt_enc ? "gauthenc-enc" : "gauthenc-dec");

    pgoff = data_offset >> PAGE_SHIFT;
    n = pgoff + (rsz >> PAGE_SHIFT);
    for_each_sg(src, sg, n, i) {
        if (i >= pgoff) {
            if ((err = kgpu_map_page(sg_page(sg), addr)) < 0)
                goto get_out;
            addr += PAGE_SIZE;
        }
    }

    if ((err = kgpu_map_page(virt_to_page(data), addr)) < 0)
        goto get_out;
    addr += PAGE_SIZE;

    if (!inplace) {
        for_each_sg(dst, sg, n, i) {
            if (i >= pgoff) {
                if ((err = kgpu_map_page(sg_page(sg), addr)) < 0)
                    goto get_out;
                addr += PAGE_SIZE;
            }
        }
    }

    if (c) {
        struct gauthenc_async_data* adata =
            kmalloc(sizeof(struct gauthenc_async_data), GFP_KERNEL);
        if (!adata) {
            g_log(KGPU_LOG_ERROR, "out of mem for async data\n");
            // TODO: do something here
        } else {
            kreq->callback = crypto_authenc_crypt_gpu_async_callback;
            kreq->kdata = adata;

            adata->c = c;
            adata->dst = dst;
            adata->src = src;
            adata->abreq = abreq;
            adata->expage = data;
            adata->data_size = data_size;
            adata->tag_size = tag_size;
            adata->data_offset = data_offset;
            adata->tag_offset = tag_offset;
            kgpu_call_async(kreq);
            return 0;
        }
    } else {
        if (kgpu_call_sync(kreq)) {
            err = -EFAULT;
            g_log(KGPU_LOG_ERROR, "callgpu error\n");
        }

        kgpu_unmap_area(TO_UL(kreq->in));
    get_out:
        kgpu_free_request(kreq);
        free_page(TO_UL(data));
    }

    return err;
}

static int crypto_authenc_crypt_gpu_nzc(struct aead_request* req,
                                        struct completion* c,
                                        unsigned int data_offset,
                                        unsigned int data_size,
                                        unsigned int tag_offset,
                                        unsigned int tag_size,
                                        int crypt_enc) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct ablkcipher_request* abreq = (void*)(areq_ctx->tail + ctx->reqoff);
    struct ablkcipher_walk walk;

    int err = 0;
    size_t info_size = sizeof(struct crypto_authenc_info);
    size_t rsz = roundup(data_size + tag_size, PAGE_SIZE);
    size_t nbytes;
    unsigned int cur;

    struct kgpu_request* kreq;
    char* buf;

    /**
     * All parts are algned to PAGE_SIZE:
     *
     * | round-uped data_size + tag_size | info |
     * |<----------- insize ------------>|
     * |<----------- outsize ----------->|
     *
     * Note: assoc and info can fit in one page.
     */
    buf = kgpu_vmalloc(rsz + info_size);
    if (!buf) {
        g_log(KGPU_LOG_ERROR, "GPU buffer is null.\n");
        return -EFAULT;
    }

    kreq = kgpu_alloc_request();
    if (!kreq) {
        kgpu_vfree(buf);
        g_log(KGPU_LOG_ERROR, "can't allocate request\n");
        return -EFAULT;
    }

    kreq->in = buf;
    kreq->out = buf;
    kreq->insize = rsz + info_size;
    kreq->outsize = data_size + tag_size;
    kreq->udatasize = info_size;
    kreq->udata = buf + rsz;

    /* copy data and tag */
    ablkcipher_walk_init(&walk, abreq->dst, abreq->src,
                         data_size + data_offset);
    err = ablkcipher_walk_phys(abreq, &walk);
    cur = 0;
    while ((nbytes = walk.nbytes)) {
        if (cur >= data_offset) {
            void* wsrc =
                phys_to_virt((page_to_phys(walk.src.page) + walk.src.offset));
            memcpy(buf, wsrc, nbytes);
            buf += nbytes;
        }

        cur += nbytes;
        err = ablkcipher_walk_done(abreq, &walk, 0);
        if (cur >= data_size + data_offset)
            break;
    }

    memcpy(kreq->udata, &ctx->info, info_size);
    strcpy(kreq->service_name, crypt_enc ? "gauthenc-enc" : "gauthenc-dec");

    if (c) {
        struct gauthenc_async_data* adata =
            kmalloc(sizeof(struct gauthenc_async_data), GFP_KERNEL);
        if (!adata) {
            g_log(KGPU_LOG_ERROR, "out of mem for async data\n");
            // TODO: do something here
        } else {
            kreq->callback = crypto_authenc_crypt_gpu_async_callback;
            kreq->kdata = adata;

            adata->c = c;
            adata->abreq = abreq;
            adata->expage = NULL;
            adata->data_size = data_size;
            adata->tag_size = tag_size;
            adata->data_offset = data_offset;
            adata->tag_offset = tag_offset;
            kgpu_call_async(kreq);
            return 0;
        }
    } else {
        if (kgpu_call_sync(kreq)) {
            err = -EFAULT;
            g_log(KGPU_LOG_ERROR, "callgpu error\n");
        } else {
            crypto_authenc_crypt_gpu_done(abreq, (char*)kreq->out, data_offset,
                                          data_size, tag_offset, tag_size);
        }
        kgpu_vfree(kreq->in);
        kgpu_free_request(kreq);
    }

    return err;
}

/**
 * Batch authenticated encryption/decryption of data using GPU.
 *
 * Input/Output Layout:
 * | 4KB data | 64B tag | 4KB data | 64B tag | 4KB data | 64B tag | ...
 *
 */
static int crypto_authenc_crypt_gpu(struct aead_request* req,
                                    int crypt_enc,
                                    crypto_authenc_crypt_gpu_t fn) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    unsigned int authsize = crypto_aead_authsize(authenc);
    unsigned int cryptlen = req->cryptlen;
    struct ablkcipher_request* abreq = (void*)(areq_ctx->tail + ctx->reqoff);
    u8* iv = (u8*)abreq - crypto_ablkcipher_ivsize(ctx->enc);

    ablkcipher_request_set_tfm(abreq, ctx->enc);
    ablkcipher_request_set_callback(abreq, aead_request_flags(req), NULL, req);
    ablkcipher_request_set_crypt(abreq, req->src, req->dst, cryptlen, req->iv);
    memcpy(iv, req->iv, crypto_aead_ivsize(authenc));

    /* pass sector number from abreq to ctx as tweak */
    ctx->info.tweak = *((u64*)(abreq->info));

    if (crypt_enc) {
        /* for auth encrypt, cryptlen does not include tag length */
        ctx->info.textlen = cryptlen;
        ctx->info.authlen = (cryptlen >> PAGE_SHIFT) * authsize;
    } else {
        /* for auth decrypt, cryptlen includes tag length */
        ctx->info.textlen = (cryptlen / (PAGE_SIZE + authsize)) << PAGE_SHIFT;
        ctx->info.authlen = cryptlen - ctx->info.textlen;
    }
    cryptlen = ctx->info.textlen;

    /* split huge dataset and call gpu crypt one by one */
    if ((cryptlen >> PAGE_SHIFT) >= split_threshold + (split_threshold >> 1)) {
        unsigned int remainings = cryptlen;
        int nparts = cryptlen / (split_threshold << (PAGE_SHIFT - 1));
        struct completion* cs;
        int i;
        int ret = 0;

        if (nparts & 0x1)
            nparts++;

        cs = (struct completion*)kmalloc(sizeof(struct completion) * nparts,
                                         GFP_KERNEL);
        if (cs) {
            size_t data_size, tag_size, data_offset, tag_offset;
            size_t data_step = split_threshold << PAGE_SHIFT,
                   tag_step = split_threshold << (ffs(authsize) - 1);
            for (i = 0; i < nparts && remainings; i++) {
                data_size = (i == nparts - 1) ? remainings : data_step;
                data_offset = i * data_step;
                tag_size = (i == nparts - 1)
                               ? remainings >> (PAGE_SHIFT - ffs(authsize) + 1)
                               : tag_step;
                tag_offset = ctx->info.textlen + i * tag_step;

                init_completion(cs + i);
                // reset textlen and authlen according to split parts
                ctx->info.textlen = data_size;
                ctx->info.authlen = tag_size;
                ret = fn(req, cs + i, data_offset, data_size, tag_offset,
                         tag_size, crypt_enc);

                if (ret < 0)
                    break;

                remainings -= data_step;
            }

            for (i = 0; i < nparts; i++)
                wait_for_completion(&cs[i]);
            kfree(cs);
            return ret;
        }
    }

    /* failed to kmalloc completions or no need to split, crypt directly */
    return fn(req, NULL, 0, ctx->info.textlen, cryptlen, ctx->info.authlen,
              crypt_enc);
}

static void crypto_authenc_encrypt_done(struct crypto_async_request* req,
                                        int err) {
    struct aead_request* areq = req->data;

    if (!err) {
        struct crypto_aead* authenc = crypto_aead_reqtfm(areq);
        struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
        struct ablkcipher_request* abreq = aead_request_ctx(areq);
        u8* iv = (u8*)(abreq + 1) + crypto_ablkcipher_reqsize(ctx->enc);

        err = crypto_authenc_genicv(areq, iv, 0);
    }

    authenc_request_complete(areq, err);
}

static int crypto_authenc_encrypt_cpu(struct aead_request* req) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct crypto_ablkcipher* enc = ctx->enc;
    struct scatterlist* dst = req->dst;
    unsigned int cryptlen = req->cryptlen;
    struct ablkcipher_request* abreq = (void*)(areq_ctx->tail + ctx->reqoff);
    u8* iv = (u8*)abreq - crypto_ablkcipher_ivsize(enc);
    int err;

    ablkcipher_request_set_tfm(abreq, enc);
    ablkcipher_request_set_callback(abreq, aead_request_flags(req),
                                    crypto_authenc_encrypt_done, req);
    ablkcipher_request_set_crypt(abreq, req->src, dst, cryptlen, req->iv);

    memcpy(iv, req->iv, crypto_aead_ivsize(authenc));

    err = crypto_ablkcipher_encrypt(abreq);
    if (err)
        return err;

    return crypto_authenc_genicv(req, iv, CRYPTO_TFM_REQ_MAY_SLEEP);
}

static int crypto_authenc_encrypt(struct aead_request* req) {
    if (req->cryptlen < GAUTHENC_SIZE_THRESHOLD) {
        return crypto_authenc_encrypt_cpu(req);
    } else {
        return crypto_authenc_crypt_gpu(req, 1,
                                        zero_copy
                                            ? crypto_authenc_crypt_gpu_zc
                                            : crypto_authenc_crypt_gpu_nzc);
    }
}

static void crypto_authenc_givencrypt_done(struct crypto_async_request* req,
                                           int err) {
    struct aead_request* areq = req->data;

    if (!err) {
        struct skcipher_givcrypt_request* greq = aead_request_ctx(areq);

        err = crypto_authenc_genicv(areq, greq->giv, 0);
    }

    authenc_request_complete(areq, err);
}

static int crypto_authenc_givencrypt(struct aead_givcrypt_request* req) {
    struct crypto_aead* authenc = aead_givcrypt_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct aead_request* areq = &req->areq;
    struct skcipher_givcrypt_request* greq = aead_request_ctx(areq);
    u8* iv = req->giv;
    int err;

    skcipher_givcrypt_set_tfm(greq, ctx->enc);
    skcipher_givcrypt_set_callback(greq, aead_request_flags(areq),
                                   crypto_authenc_givencrypt_done, areq);
    skcipher_givcrypt_set_crypt(greq, areq->src, areq->dst, areq->cryptlen,
                                areq->iv);
    skcipher_givcrypt_set_giv(greq, iv, req->seq);

    err = crypto_skcipher_givencrypt(greq);
    if (err)
        return err;

    return crypto_authenc_genicv(areq, iv, CRYPTO_TFM_REQ_MAY_SLEEP);
}

static int crypto_authenc_verify(struct aead_request* req,
                                 authenc_ahash_t authenc_ahash_fn) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    u8* ohash;
    u8* ihash;
    unsigned int authsize;

    areq_ctx->complete = authenc_verify_ahash_done;
    areq_ctx->update_complete = authenc_verify_ahash_update_done;

    ohash = authenc_ahash_fn(req, CRYPTO_TFM_REQ_MAY_SLEEP);
    if (IS_ERR(ohash))
        return PTR_ERR(ohash);

    authsize = crypto_aead_authsize(authenc);
    ihash = ohash + authsize;
    scatterwalk_map_and_copy(ihash, areq_ctx->sg, areq_ctx->cryptlen, authsize,
                             0);
    return memcmp(ihash, ohash, authsize) ? -EBADMSG : 0;
}

static int crypto_authenc_iverify(struct aead_request* req,
                                  u8* iv,
                                  unsigned int cryptlen) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct authenc_request_ctx* areq_ctx = aead_request_ctx(req);
    struct scatterlist* src = req->src;
    struct scatterlist* assoc = req->assoc;
    struct scatterlist* cipher = areq_ctx->cipher;
    struct scatterlist* asg = areq_ctx->asg;
    unsigned int ivsize = crypto_aead_ivsize(authenc);
    authenc_ahash_t authenc_ahash_fn = crypto_authenc_ahash_fb;
    struct page* srcp;
    u8* vsrc;

    srcp = sg_page(src);
    vsrc = PageHighMem(srcp) ? NULL : page_address(srcp) + src->offset;

    if (ivsize) {
        sg_init_table(cipher, 2);
        sg_set_buf(cipher, iv, ivsize);
        scatterwalk_crypto_chain(cipher, src, vsrc == iv + ivsize, 2);
        src = cipher;
        cryptlen += ivsize;
    }

    if (req->assoclen && sg_is_last(assoc)) {
        authenc_ahash_fn = crypto_authenc_ahash;
        sg_init_table(asg, 2);
        sg_set_page(asg, sg_page(assoc), assoc->length, assoc->offset);
        scatterwalk_crypto_chain(asg, src, 0, 2);
        src = asg;
        cryptlen += req->assoclen;
    }

    areq_ctx->cryptlen = cryptlen;
    areq_ctx->sg = src;

    return crypto_authenc_verify(req, authenc_ahash_fn);
}

static int crypto_authenc_decrypt_cpu(struct aead_request* req) {
    struct crypto_aead* authenc = crypto_aead_reqtfm(req);
    struct crypto_authenc_ctx* ctx = crypto_aead_ctx(authenc);
    struct ablkcipher_request* abreq = aead_request_ctx(req);
    unsigned int cryptlen = req->cryptlen;
    unsigned int authsize = crypto_aead_authsize(authenc);
    u8* iv = req->iv;
    // int err;

    if (cryptlen < authsize)
        return -EINVAL;
    cryptlen -= authsize;

    // TODO : bypass tag authentication for test
    // err = crypto_authenc_iverify(req, iv, cryptlen);
    // if (err)
    // 	return err;

    ablkcipher_request_set_tfm(abreq, ctx->enc);
    ablkcipher_request_set_callback(abreq, aead_request_flags(req),
                                    req->base.complete, req->base.data);
    ablkcipher_request_set_crypt(abreq, req->src, req->dst, cryptlen, iv);

    return crypto_ablkcipher_decrypt(abreq);
}

static int crypto_authenc_decrypt(struct aead_request* req) {
    if (req->cryptlen < GAUTHENC_SIZE_THRESHOLD) {
        return crypto_authenc_decrypt_cpu(req);
    } else {
        return crypto_authenc_crypt_gpu(req, 0,
                                        zero_copy
                                            ? crypto_authenc_crypt_gpu_zc
                                            : crypto_authenc_crypt_gpu_nzc);
    }
}

static int crypto_authenc_init_tfm(struct crypto_tfm* tfm) {
    struct crypto_instance* inst = crypto_tfm_alg_instance(tfm);
    struct authenc_instance_ctx* ictx = crypto_instance_ctx(inst);
    struct crypto_authenc_ctx* ctx = crypto_tfm_ctx(tfm);
    struct crypto_ahash* auth;
    struct crypto_ablkcipher* enc;
    int err;

    auth = crypto_spawn_ahash(&ictx->auth);
    if (IS_ERR(auth))
        return PTR_ERR(auth);

    enc = crypto_spawn_skcipher(&ictx->enc);
    err = PTR_ERR(enc);
    if (IS_ERR(enc))
        goto err_free_ahash;

    ctx->auth = auth;
    ctx->enc = enc;

    ctx->reqoff =
        ALIGN(2 * crypto_ahash_digestsize(auth) + crypto_ahash_alignmask(auth),
              crypto_ahash_alignmask(auth) + 1) +
        crypto_ablkcipher_ivsize(enc);

    tfm->crt_aead.reqsize =
        sizeof(struct authenc_request_ctx) + ctx->reqoff +
        max_t(unsigned int,
              crypto_ahash_reqsize(auth) + sizeof(struct ahash_request),
              sizeof(struct skcipher_givcrypt_request) +
                  crypto_ablkcipher_reqsize(enc));

    return 0;

err_free_ahash:
    crypto_free_ahash(auth);
    return err;
}

static void crypto_authenc_exit_tfm(struct crypto_tfm* tfm) {
    struct crypto_authenc_ctx* ctx = crypto_tfm_ctx(tfm);

    crypto_free_ahash(ctx->auth);
    crypto_free_ablkcipher(ctx->enc);
}

static struct crypto_instance* crypto_authenc_alloc(struct rtattr** tb) {
    struct crypto_attr_type* algt;
    struct crypto_instance* inst;
    struct hash_alg_common* auth;
    struct crypto_alg* auth_base;
    struct crypto_alg* enc;
    struct authenc_instance_ctx* ctx;
    const char* enc_name;
    int err;

    algt = crypto_get_attr_type(tb);
    if (IS_ERR(algt))
        return ERR_CAST(algt);

    if ((algt->type ^ CRYPTO_ALG_TYPE_AEAD) & algt->mask)
        return ERR_PTR(-EINVAL);

    auth =
        ahash_attr_alg(tb[1], CRYPTO_ALG_TYPE_HASH, CRYPTO_ALG_TYPE_AHASH_MASK);
    if (IS_ERR(auth))
        return ERR_CAST(auth);

    auth_base = &auth->base;

    enc_name = crypto_attr_alg_name(tb[2]);
    err = PTR_ERR(enc_name);
    if (IS_ERR(enc_name))
        goto out_put_auth;

    inst = kzalloc(sizeof(*inst) + sizeof(*ctx), GFP_KERNEL);
    err = -ENOMEM;
    if (!inst)
        goto out_put_auth;

    ctx = crypto_instance_ctx(inst);

    err = crypto_init_ahash_spawn(&ctx->auth, auth, inst);
    if (err)
        goto err_free_inst;

    crypto_set_skcipher_spawn(&ctx->enc, inst);
    err = crypto_grab_skcipher(&ctx->enc, enc_name, 0,
                               crypto_requires_sync(algt->type, algt->mask));
    if (err)
        goto err_drop_auth;

    enc = crypto_skcipher_spawn_alg(&ctx->enc);

    err = -ENAMETOOLONG;
    if (snprintf(inst->alg.cra_name, CRYPTO_MAX_ALG_NAME, "gauthenc(%s,%s)",
                 auth_base->cra_name, enc->cra_name) >= CRYPTO_MAX_ALG_NAME)
        goto err_drop_enc;

    if (snprintf(inst->alg.cra_driver_name, CRYPTO_MAX_ALG_NAME,
                 "gauthenc(%s,%s)", auth_base->cra_driver_name,
                 enc->cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
        goto err_drop_enc;

    inst->alg.cra_flags = CRYPTO_ALG_TYPE_AEAD;
    inst->alg.cra_flags |= enc->cra_flags & CRYPTO_ALG_ASYNC;
    inst->alg.cra_priority = enc->cra_priority * 10 + auth_base->cra_priority;
    inst->alg.cra_blocksize = enc->cra_blocksize;
    inst->alg.cra_alignmask = auth_base->cra_alignmask | enc->cra_alignmask;
    inst->alg.cra_type = &crypto_aead_type;

    inst->alg.cra_aead.ivsize = enc->cra_ablkcipher.ivsize;
    inst->alg.cra_aead.maxauthsize = auth->digestsize;

    inst->alg.cra_ctxsize = sizeof(struct crypto_authenc_ctx);

    inst->alg.cra_init = crypto_authenc_init_tfm;
    inst->alg.cra_exit = crypto_authenc_exit_tfm;

    inst->alg.cra_aead.setkey = crypto_authenc_setkey;
    inst->alg.cra_aead.encrypt = crypto_authenc_encrypt;
    inst->alg.cra_aead.decrypt = crypto_authenc_decrypt;
    inst->alg.cra_aead.givencrypt = crypto_authenc_givencrypt;

out:
    crypto_mod_put(auth_base);
    return inst;

err_drop_enc:
    crypto_drop_skcipher(&ctx->enc);
err_drop_auth:
    crypto_drop_ahash(&ctx->auth);
err_free_inst:
    kfree(inst);
out_put_auth:
    inst = ERR_PTR(err);
    goto out;
}

static void crypto_authenc_free(struct crypto_instance* inst) {
    struct authenc_instance_ctx* ctx = crypto_instance_ctx(inst);

    crypto_drop_skcipher(&ctx->enc);
    crypto_drop_ahash(&ctx->auth);
    kfree(inst);
}

static struct crypto_template crypto_authenc_tmpl = {
    .name = "gauthenc",
    .alloc = crypto_authenc_alloc,
    .free = crypto_authenc_free,
    .module = THIS_MODULE,
};

static int __init crypto_authenc_module_init(void) {
    return crypto_register_template(&crypto_authenc_tmpl);
}

static void __exit crypto_authenc_module_exit(void) {
    crypto_unregister_template(&crypto_authenc_tmpl);
}

module_init(crypto_authenc_module_init);
module_exit(crypto_authenc_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple AEAD wrapper (GPU version)");
