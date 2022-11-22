/*
 * Copyright (C) 2003 Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2009 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/rtnetlink.h> /* for struct rtattr and RTA macros only */
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "security"
#define DEFAULT_CIPHER "aes"
#define DEFAULT_CHAINMODE "xts"
#define DEFAULT_IVMODE "plain64"
#define DEFAULT_HASH "sha512"
#define CIPHERMODE DEFAULT_CHAINMODE "(" DEFAULT_CIPHER ")"
#define HMAC "hmac(" DEFAULT_HASH ")"
#define AUTHCIPHER "gauthenc(" HMAC "," CIPHERMODE ")"
#define AUTHSIZE 64

/*
 * context holding the current state of a multi-part conversion
 */
struct convert_context {
    struct completion restart;
    struct bio* bio_in;
    struct bio* bio_out;
    unsigned int offset_in;
    unsigned int offset_out;
    unsigned int idx_in;
    unsigned int idx_out;
    sector_t cc_sector;
    atomic_t cc_pending;
};

/*
 * per bio private data
 */
struct dm_crypt_io {
    struct crypt_config* cc;
    struct bio* base_bio;
    struct work_struct work;

    struct convert_context ctx;

    atomic_t io_pending;
    int error;
    sector_t sector;
    struct dm_crypt_io* base_io;
};

struct dm_crypt_request {
    struct convert_context* ctx;
    struct scatterlist sg_in[2];
    struct scatterlist sg_out[2];
    struct scatterlist sg_assoc;
    sector_t iv_sector;
};

struct crypt_config;

struct crypt_iv_operations {
    int (*generator)(struct crypt_config* cc,
                     u8* iv,
                     struct dm_crypt_request* dmreq);
};

/*
 * Crypt: maps a linear range of a block device
 * and encrypts / decrypts at the same time.
 */
enum flags { DM_CRYPT_SUSPENDED, DM_CRYPT_KEY_VALID };

/*
 * Duplicated per-CPU state for cipher.
 */
struct crypt_cpu {
    struct aead_request* req;
};

/*
 * The fields in here must be read only after initialization,
 * changing state should be in crypt_cpu.
 */
struct crypt_config {
    struct dm_dev* dev;
    sector_t start;

    /*
     * pool for per bio private data, crypto requests and
     * encryption requeusts/buffer pages
     */
    mempool_t* io_pool;
    mempool_t* req_pool;
    mempool_t* page_pool;
    struct bio_set* bs;

    struct workqueue_struct* io_queue;
    struct workqueue_struct* crypt_queue;

    char* cipher_string;

    struct crypt_iv_operations* iv_gen_ops;
    unsigned int iv_size;

    /*
     * Duplicated per cpu state. Access through
     * per_cpu_ptr() only.
     */
    struct crypt_cpu __percpu* cpu;

    struct crypto_aead* tfm;

    /*
     * Layout of each crypto request:
     *
     *   struct aead_request
     *      context
     *      padding
     *   struct dm_crypt_request
     *      padding
     *   IV
     *
     * The padding is added so that dm_crypt_request and the IV are
     * correctly aligned.
     */
    unsigned int dmreq_start;

    unsigned long flags;
    unsigned int key_size;
    unsigned int key_mac_size; /* MAC key size for authenc(...) */

    u8* authenc_key; /* space for keys in authenc() format (if used) */
    u8 key[0];
};

#define MIN_IOS 16
#define MIN_POOL_PAGES 32

static struct kmem_cache* _crypt_io_pool;

static void clone_init(struct dm_crypt_io*, struct bio*);
static void kcryptd_queue_crypt(struct dm_crypt_io* io);
static u8* iv_of_dmreq(struct crypt_config* cc, struct dm_crypt_request* dmreq);

static struct crypt_cpu* this_crypt_config(struct crypt_config* cc) {
    return this_cpu_ptr(cc->cpu);
}

/*
 * Different IV generation algorithms:
 *
 * plain: the initial vector is the 32-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64: the initial vector is the 64-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * null: the initial vector is always zero.  Provides compatibility with
 *       obsolete loop_fish2 devices.  Do not use for new devices.
 */

static int crypt_iv_plain_gen(struct crypt_config* cc,
                              u8* iv,
                              struct dm_crypt_request* dmreq) {
    memset(iv, 0, cc->iv_size);
    *(__le32*)iv = cpu_to_le32(dmreq->iv_sector & 0xffffffff);

    return 0;
}

static int crypt_iv_plain64_gen(struct crypt_config* cc,
                                u8* iv,
                                struct dm_crypt_request* dmreq) {
    memset(iv, 0, cc->iv_size);
    *(__le64*)iv = cpu_to_le64(dmreq->iv_sector);

    return 0;
}

static int crypt_iv_null_gen(struct crypt_config* cc,
                             u8* iv,
                             struct dm_crypt_request* dmreq) {
    memset(iv, 0, cc->iv_size);

    return 0;
}

static struct crypt_iv_operations crypt_iv_plain_ops = {.generator =
                                                            crypt_iv_plain_gen};

static struct crypt_iv_operations crypt_iv_plain64_ops = {
    .generator = crypt_iv_plain64_gen};

static struct crypt_iv_operations crypt_iv_null_ops = {.generator =
                                                           crypt_iv_null_gen};

static void crypt_convert_init(struct crypt_config* cc,
                               struct convert_context* ctx,
                               struct bio* bio_out,
                               struct bio* bio_in,
                               sector_t sector) {
    ctx->bio_in = bio_in;
    ctx->bio_out = bio_out;
    ctx->offset_in = 0;
    ctx->offset_out = 0;
    ctx->idx_in = bio_in ? bio_in->bi_idx : 0;
    ctx->idx_out = bio_out ? bio_out->bi_idx : 0;
    ctx->cc_sector = sector;
    init_completion(&ctx->restart);
}

static struct dm_crypt_request* dmreq_of_req(struct crypt_config* cc,
                                             void* req) {
    return (struct dm_crypt_request*)((char*)req + cc->dmreq_start);
}

static struct aead_request* req_of_dmreq(struct crypt_config* cc,
                                         struct dm_crypt_request* dmreq) {
    return (struct aead_request*)((char*)dmreq - cc->dmreq_start);
}

static u8* iv_of_dmreq(struct crypt_config* cc,
                       struct dm_crypt_request* dmreq) {
    return (u8*)(dmreq + 1);
}

/*
 * For KGPU: convert all blocks together for speedup
 */
static int crypt_convert_blocks(struct crypt_config* cc,
                                struct convert_context* ctx,
                                struct ablkcipher_request* req) {
    struct scatterlist *sgin, *sgout;
    struct bio_vec* bv_in;
    struct bio_vec* bv_out;
    struct dm_crypt_request* dmreq;
    u8* iv = NULL;
    int r = 0;
    unsigned int sz = 0;

    dmreq = dmreq_of_req(cc, req);
    iv = iv_of_dmreq(cc, dmreq);

    // Use the sector number as the IV,
    // it might be wrong when encrypting multiple blocks in a batch.
    dmreq->iv_sector = ctx->cc_sector;
    dmreq->ctx = ctx;

    sgin = kmalloc((ctx->bio_in->bi_vcnt + ctx->bio_out->bi_vcnt) *
                       sizeof(struct scatterlist),
                   GFP_KERNEL);
    if (!sgin) {
        printk("[dm-crypt] Error: out of memory %s:%d\n", __FILE__, __LINE__);
        return -ENOMEM;
    }
    sgout = sgin + ctx->bio_in->bi_vcnt;

    sg_init_table(sgin, ctx->bio_in->bi_vcnt);
    sg_init_table(sgout, ctx->bio_out->bi_vcnt);

    while (ctx->idx_in < ctx->bio_in->bi_vcnt &&
           ctx->idx_out < ctx->bio_out->bi_vcnt) {
        bv_in = bio_iovec_idx(ctx->bio_in, ctx->idx_in);
        bv_out = bio_iovec_idx(ctx->bio_out, ctx->idx_out);

        sg_set_page(sgin + ctx->idx_in, bv_in->bv_page, bv_in->bv_len,
                    bv_in->bv_offset);
        sg_set_page(sgout + ctx->idx_out, bv_out->bv_page, bv_out->bv_len,
                    bv_out->bv_offset);
        ctx->idx_in++;
        ctx->idx_out++;

        sz += bv_in->bv_len;
    }

    if (cc->iv_gen_ops) {
        r = cc->iv_gen_ops->generator(cc, iv, dmreq);
        if (r < 0)
            return r;
    }

    ablkcipher_request_set_crypt(req, sgin, sgout, sz, iv);

    if (bio_data_dir(ctx->bio_in) == WRITE)
        r = crypto_ablkcipher_encrypt(req);
    else
        r = crypto_ablkcipher_decrypt(req);

    kfree(sgin);

    return r;
}

static int crypt_convert_block(struct crypt_config* cc,
                               struct convert_context* ctx,
                               struct aead_request* req) {
    struct bio_vec* bv_in = bio_iovec_idx(ctx->bio_in, ctx->idx_in);
    struct bio_vec* bv_out = bio_iovec_idx(ctx->bio_out, ctx->idx_out);
    struct dm_crypt_request* dmreq;
    u8 *iv, *tag;
    uint64_t* assoc = 0;
    unsigned int tag_size = AUTHSIZE;
    unsigned int assoclen = sizeof(uint64_t);
    int r;

    dmreq = dmreq_of_req(cc, req);
    iv = iv_of_dmreq(cc, dmreq);

    dmreq->iv_sector = ctx->cc_sector;
    dmreq->ctx = ctx;

    assoc = (uint64_t*)kzalloc(assoclen, GFP_KERNEL);
    if (!assoc)
        DMERR("Cannot allocate assoc buffer");

    tag = (u8*)kzalloc(tag_size, GFP_KERNEL);
    if (!tag)
        DMERR("Cannot allocate tag buffer");

    sg_init_table(dmreq->sg_in, 2);
    sg_set_page(&dmreq->sg_in[0], bv_in->bv_page, (1 << SECTOR_SHIFT),
                bv_in->bv_offset + ctx->offset_in);
    sg_set_buf(&dmreq->sg_in[1], tag, tag_size);

    sg_init_table(dmreq->sg_out, 2);
    sg_set_page(&dmreq->sg_out[0], bv_out->bv_page, (1 << SECTOR_SHIFT),
                bv_out->bv_offset + ctx->offset_out);
    sg_set_buf(&dmreq->sg_out[1], tag, tag_size);

    sg_init_one(&dmreq->sg_assoc, assoc, assoclen);

    ctx->offset_in += 1 << SECTOR_SHIFT;
    if (ctx->offset_in >= bv_in->bv_len) {
        ctx->offset_in = 0;
        ctx->idx_in++;
    }

    ctx->offset_out += 1 << SECTOR_SHIFT;
    if (ctx->offset_out >= bv_out->bv_len) {
        ctx->offset_out = 0;
        ctx->idx_out++;
    }

    if (cc->iv_gen_ops) {
        r = cc->iv_gen_ops->generator(cc, iv, dmreq);
        if (r < 0)
            return r;
    }

    aead_request_set_assoc(req, &dmreq->sg_assoc, assoclen);
    if (bio_data_dir(ctx->bio_in) == WRITE) {
        aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
                               (1 << SECTOR_SHIFT), iv);
        r = crypto_aead_encrypt(req);
    } else {
        aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
                               (1 << SECTOR_SHIFT) + tag_size, iv);
        r = crypto_aead_decrypt(req);
    }

    if (r == -EBADMSG)
        DMERR_LIMIT("INTEGRITY AEAD ERROR, sector %llu",
                    (unsigned long long)le64_to_cpu(ctx->cc_sector));

    return r;
}

static void kcryptd_async_done(struct crypto_async_request* async_req,
                               int error);

static void crypt_alloc_req(struct crypt_config* cc,
                            struct convert_context* ctx) {
    struct crypt_cpu* this_cc = this_crypt_config(cc);

    if (!this_cc->req)
        this_cc->req = mempool_alloc(cc->req_pool, GFP_NOIO);

    aead_request_set_tfm(this_cc->req, cc->tfm);
    aead_request_set_callback(
        this_cc->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
        kcryptd_async_done, dmreq_of_req(cc, this_cc->req));
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 */
static int crypt_convert(struct crypt_config* cc, struct convert_context* ctx) {
    struct crypt_cpu* this_cc = this_crypt_config(cc);
    int r;

    atomic_set(&ctx->cc_pending, 1);

    while (ctx->idx_in < ctx->bio_in->bi_vcnt &&
           ctx->idx_out < ctx->bio_out->bi_vcnt) {
        crypt_alloc_req(cc, ctx);

        atomic_inc(&ctx->cc_pending);

        // r = crypt_convert_blocks(cc, ctx, this_cc->req);
        r = crypt_convert_block(cc, ctx, this_cc->req);

        switch (r) {
            /* async */
            /*
             * The request was queued by a crypto driver
             * but the driver request queue is full, let's wait.
             */
            case -EBUSY:
                wait_for_completion(&ctx->restart);
                INIT_COMPLETION(ctx->restart);
                /* fall through*/
            /*
             * The request is queued and processed asynchronously,
             * completion function kcryptd_async_done() will be called.
             */
            case -EINPROGRESS:
                this_cc->req = NULL;
                ctx->cc_sector++;
                continue;

            /* sync */
            /*
             * The request was already processed (synchronously).
             */
            case 0:
                atomic_dec(&ctx->cc_pending);
                ctx->cc_sector++;
                cond_resched();
                continue;

            /*
             * There was a data integrity error.
             */
            case -EBADMSG:
                atomic_dec(&ctx->cc_pending);
                return -EILSEQ;

            /* error */
            default:
                atomic_dec(&ctx->cc_pending);
                return r;
        }
    }

    return 0;
}

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations
 * May return a smaller bio when running out of pages, indicated by
 * *out_of_pages set to 1.
 */
static struct bio* crypt_alloc_buffer(struct dm_crypt_io* io,
                                      unsigned size,
                                      unsigned* out_of_pages) {
    struct crypt_config* cc = io->cc;
    struct bio* clone;
    unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    gfp_t gfp_mask = GFP_NOIO | __GFP_HIGHMEM;
    unsigned i, len;
    struct page* page;

    clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, cc->bs);
    if (!clone)
        return NULL;

    clone_init(io, clone);
    *out_of_pages = 0;

    for (i = 0; i < nr_iovecs; i++) {
        page = mempool_alloc(cc->page_pool, gfp_mask);
        if (!page) {
            *out_of_pages = 1;
            break;
        }

        /*
         * If additional pages cannot be allocated without waiting,
         * return a partially-allocated bio.  The caller will then try
         * to allocate more bios while submitting this partial bio.
         */
        gfp_mask = (gfp_mask | __GFP_NOWARN) & ~__GFP_WAIT;

        len = (size > PAGE_SIZE) ? PAGE_SIZE : size;

        if (!bio_add_page(clone, page, len, 0)) {
            mempool_free(page, cc->page_pool);
            break;
        }

        size -= len;
    }

    if (!clone->bi_size) {
        bio_put(clone);
        return NULL;
    }

    return clone;
}

static void crypt_free_buffer_pages(struct crypt_config* cc,
                                    struct bio* clone) {
    unsigned int i;
    struct bio_vec* bv;

    bio_for_each_segment_all(bv, clone, i) {
        BUG_ON(!bv->bv_page);
        mempool_free(bv->bv_page, cc->page_pool);
        bv->bv_page = NULL;
    }
}

static struct dm_crypt_io* crypt_io_alloc(struct crypt_config* cc,
                                          struct bio* bio,
                                          sector_t sector) {
    struct dm_crypt_io* io;

    io = mempool_alloc(cc->io_pool, GFP_NOIO);
    io->cc = cc;
    io->base_bio = bio;
    io->sector = sector;
    io->error = 0;
    io->base_io = NULL;
    atomic_set(&io->io_pending, 0);

    return io;
}

static void crypt_inc_pending(struct dm_crypt_io* io) {
    atomic_inc(&io->io_pending);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 * If base_io is set, wait for the last fragment to complete.
 */
static void crypt_dec_pending(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    struct bio* base_bio = io->base_bio;
    struct dm_crypt_io* base_io = io->base_io;
    int error = io->error;

    if (!atomic_dec_and_test(&io->io_pending))
        return;

    mempool_free(io, cc->io_pool);

    if (likely(!base_io))
        bio_endio(base_bio, error);
    else {
        if (error && !base_io->error)
            base_io->error = error;
        crypt_dec_pending(base_io);
    }
}

/*
 * kcryptd/kcryptd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * kcryptd performs the actual encryption or decryption.
 *
 * kcryptd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-crypt instances.
 * They should not depend on each other and do not block.
 */
static void crypt_endio(struct bio* clone, int error) {
    struct dm_crypt_io* io = clone->bi_private;
    struct crypt_config* cc = io->cc;
    unsigned rw = bio_data_dir(clone);

    if (unlikely(!bio_flagged(clone, BIO_UPTODATE) && !error))
        error = -EIO;

    /*
     * free the processed pages
     */
    if (rw == WRITE)
        crypt_free_buffer_pages(cc, clone);

    bio_put(clone);

    if (rw == READ && !error) {
        kcryptd_queue_crypt(io);
        return;
    }

    if (unlikely(error))
        io->error = error;

    crypt_dec_pending(io);
}

static void clone_init(struct dm_crypt_io* io, struct bio* clone) {
    struct crypt_config* cc = io->cc;

    clone->bi_private = io;
    clone->bi_end_io = crypt_endio;
    clone->bi_bdev = cc->dev->bdev;
    clone->bi_rw = io->base_bio->bi_rw;
}

static int kcryptd_io_read(struct dm_crypt_io* io, gfp_t gfp) {
    struct crypt_config* cc = io->cc;
    struct bio* base_bio = io->base_bio;
    struct bio* clone;

    /*
     * The block layer might modify the bvec array, so always
     * copy the required bvecs because we need the original
     * one in order to decrypt the whole bio data *afterwards*.
     */
    clone = bio_clone_bioset(base_bio, gfp, cc->bs);
    if (!clone)
        return 1;

    crypt_inc_pending(io);

    clone_init(io, clone);
    clone->bi_sector = cc->start + io->sector;

    generic_make_request(clone);
    return 0;
}

static void kcryptd_io_write(struct dm_crypt_io* io) {
    struct bio* clone = io->ctx.bio_out;
    generic_make_request(clone);
}

static void kcryptd_io(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);

    if (bio_data_dir(io->base_bio) == READ) {
        crypt_inc_pending(io);
        if (kcryptd_io_read(io, GFP_NOIO))
            io->error = -ENOMEM;
        crypt_dec_pending(io);
    } else
        kcryptd_io_write(io);
}

static void kcryptd_queue_io(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;

    INIT_WORK(&io->work, kcryptd_io);
    queue_work(cc->io_queue, &io->work);
}

static void kcryptd_crypt_write_io_submit(struct dm_crypt_io* io, int async) {
    struct bio* clone = io->ctx.bio_out;
    struct crypt_config* cc = io->cc;

    if (unlikely(io->error < 0)) {
        crypt_free_buffer_pages(cc, clone);
        bio_put(clone);
        crypt_dec_pending(io);
        return;
    }

    /* crypt_convert should have filled the clone bio */
    BUG_ON(io->ctx.idx_out < clone->bi_vcnt);

    clone->bi_sector = cc->start + io->sector;

    if (async)
        kcryptd_queue_io(io);
    else
        generic_make_request(clone);
}

static void kcryptd_crypt_write_convert(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    struct bio* clone;
    struct dm_crypt_io* new_io;
    int crypt_finished;
    unsigned out_of_pages = 0;
    unsigned remaining = io->base_bio->bi_size;
    sector_t sector = io->sector;
    int r;

    /*
     * Prevent io from disappearing until this function completes.
     */
    crypt_inc_pending(io);
    crypt_convert_init(cc, &io->ctx, NULL, io->base_bio, sector);

    /*
     * The allocated buffers can be smaller than the whole bio,
     * so repeat the whole process until all the data can be handled.
     */
    while (remaining) {
        clone = crypt_alloc_buffer(io, remaining, &out_of_pages);
        if (unlikely(!clone)) {
            io->error = -ENOMEM;
            break;
        }

        io->ctx.bio_out = clone;
        io->ctx.idx_out = 0;

        remaining -= clone->bi_size;
        sector += bio_sectors(clone);

        crypt_inc_pending(io);

        r = crypt_convert(cc, &io->ctx);
        if (r < 0)
            io->error = -EIO;

        crypt_finished = atomic_dec_and_test(&io->ctx.cc_pending);

        /* Encryption was already finished, submit io now */
        if (crypt_finished) {
            kcryptd_crypt_write_io_submit(io, 0);

            /*
             * If there was an error, do not try next fragments.
             * For async, error is processed in async handler.
             */
            if (unlikely(r < 0))
                break;

            io->sector = sector;
        }

        /*
         * Out of memory -> run queues
         * But don't wait if split was due to the io size restriction
         */
        if (unlikely(out_of_pages))
            congestion_wait(BLK_RW_ASYNC, HZ / 100);

        /*
         * With async crypto it is unsafe to share the crypto context
         * between fragments, so switch to a new dm_crypt_io structure.
         */
        if (unlikely(!crypt_finished && remaining)) {
            new_io = crypt_io_alloc(io->cc, io->base_bio, sector);
            crypt_inc_pending(new_io);
            crypt_convert_init(cc, &new_io->ctx, NULL, io->base_bio, sector);
            new_io->ctx.idx_in = io->ctx.idx_in;
            new_io->ctx.offset_in = io->ctx.offset_in;

            /*
             * Fragments after the first use the base_io
             * pending count.
             */
            if (!io->base_io)
                new_io->base_io = io;
            else {
                new_io->base_io = io->base_io;
                crypt_inc_pending(io->base_io);
                crypt_dec_pending(io);
            }

            io = new_io;
        }
    }

    crypt_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_crypt_io* io) {
    crypt_dec_pending(io);
}

static void kcryptd_crypt_read_convert(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    int r = 0;

    crypt_inc_pending(io);

    crypt_convert_init(cc, &io->ctx, io->base_bio, io->base_bio, io->sector);

    r = crypt_convert(cc, &io->ctx);
    if (r < 0)
        io->error = -EIO;

    if (atomic_dec_and_test(&io->ctx.cc_pending))
        kcryptd_crypt_read_done(io);

    crypt_dec_pending(io);
}

static void kcryptd_async_done(struct crypto_async_request* async_req,
                               int error) {
    struct dm_crypt_request* dmreq = async_req->data;
    struct convert_context* ctx = dmreq->ctx;
    struct dm_crypt_io* io = container_of(ctx, struct dm_crypt_io, ctx);
    struct crypt_config* cc = io->cc;

    if (error == -EINPROGRESS) {
        complete(&ctx->restart);
        return;
    }

    // if (error < 0)
    //     io->error = -EIO;

    mempool_free(req_of_dmreq(cc, dmreq), cc->req_pool);

    if (!atomic_dec_and_test(&ctx->cc_pending))
        return;

    if (bio_data_dir(io->base_bio) == READ)
        kcryptd_crypt_read_done(io);
    else
        kcryptd_crypt_write_io_submit(io, 1);
}

static void kcryptd_crypt(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);

    if (bio_data_dir(io->base_bio) == READ)
        kcryptd_crypt_read_convert(io);
    else
        kcryptd_crypt_write_convert(io);
}

static void kcryptd_queue_crypt(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;

    INIT_WORK(&io->work, kcryptd_crypt);
    queue_work(cc->crypt_queue, &io->work);
}

static void crypt_free_tfm(struct crypt_config* cc) {
    if (!cc->tfm)
        return;

    if (cc->tfm && !IS_ERR(cc->tfm)) {
        crypto_free_aead(cc->tfm);
        cc->tfm = NULL;
    }
}

static int crypt_alloc_tfm(struct crypt_config* cc, char* ciphermode) {
    int err;

    cc->tfm = crypto_alloc_aead(ciphermode, 0, 0);
    if (IS_ERR(cc->tfm)) {
        err = PTR_ERR(cc->tfm);
        crypt_free_tfm(cc);
        return err;
    }

    return 0;
}

static unsigned crypt_authenckey_size(struct crypt_config* cc) {
    return cc->key_size + RTA_SPACE(sizeof(struct crypto_authenc_key_param));
}

/*
 * If AEAD is composed like authenc(hmac(sha512),xts(aes)),
 * the key must be for some reason in special format.
 * This funcion converts cc->key to this special format.
 *
 * | rta length | rta type | enckey length | authkey | enckey |
 *         ↑        ↑              ↑
 *      (little endian)      (big endian)
 */
static void crypt_copy_authenckey(char* p,
                                  const void* key,
                                  unsigned enckeylen,
                                  unsigned authkeylen) {
    struct crypto_authenc_key_param* param;
    struct rtattr* rta;

    rta = (struct rtattr*)p;
    param = RTA_DATA(rta);
    param->enckeylen = cpu_to_be32(enckeylen);
    rta->rta_len = RTA_LENGTH(sizeof(*param));
    rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
    p += RTA_SPACE(sizeof(*param));
    memcpy(p, key + enckeylen, authkeylen);
    p += authkeylen;
    memcpy(p, key, enckeylen);
}

static int crypt_setkey_allcpus(struct crypt_config* cc) {
    int err = 0, r;

    crypt_copy_authenckey(cc->authenc_key, cc->key,
                          cc->key_size - cc->key_mac_size, cc->key_mac_size);
    r = crypto_aead_setkey(cc->tfm, cc->authenc_key, crypt_authenckey_size(cc));
    if (r)
        err = r;
    memzero_explicit(cc->authenc_key, crypt_authenckey_size(cc));

    return err;
}

static int crypt_set_key(struct crypt_config* cc, char* key) {
    int r = -EINVAL;
    int key_string_len = strlen(key);

    /* The key size may not be changed. */
    if (cc->key_size != (key_string_len >> 1))
        goto out;

    /* Hyphen (which gives a key_size of zero) means there is no key. */
    if (!cc->key_size && strcmp(key, "-"))
        goto out;

    if (cc->key_size && hex2bin(cc->key, key, cc->key_size) < 0)
        goto out;

    set_bit(DM_CRYPT_KEY_VALID, &cc->flags);

    r = crypt_setkey_allcpus(cc);

out:
    /* Hex key string not needed after here, so wipe it. */
    memset(key, '0', key_string_len);

    return r;
}

static int crypt_wipe_key(struct crypt_config* cc) {
    clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
    memset(&cc->key, 0, cc->key_size * sizeof(u8));

    return crypt_setkey_allcpus(cc);
}

static void crypt_dtr(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;
    struct crypt_cpu* cpu_cc;
    int cpu;

    ti->private = NULL;

    if (!cc)
        return;

    if (cc->io_queue)
        destroy_workqueue(cc->io_queue);
    if (cc->crypt_queue)
        destroy_workqueue(cc->crypt_queue);

    if (cc->cpu)
        for_each_possible_cpu(cpu) {
            cpu_cc = per_cpu_ptr(cc->cpu, cpu);
            if (cpu_cc->req)
                mempool_free(cpu_cc->req, cc->req_pool);
        }

    crypt_free_tfm(cc);

    if (cc->bs)
        bioset_free(cc->bs);

    if (cc->page_pool)
        mempool_destroy(cc->page_pool);
    if (cc->req_pool)
        mempool_destroy(cc->req_pool);
    if (cc->io_pool)
        mempool_destroy(cc->io_pool);

    if (cc->dev)
        dm_put_device(ti, cc->dev);

    if (cc->cpu)
        free_percpu(cc->cpu);

    kzfree(cc->cipher_string);

    /* Must zero key material before freeing */
    kzfree(cc);
}

/*
 * Workaround to parse HMAC algorithm from AEAD crypto API spec.
 * The HMAC is needed to calculate tag size (HMAC digest size).
 * This should be probably done by crypto-api calls (once available...)
 */
static int crypt_ctr_auth_cipher(struct crypt_config* cc, char* mac_alg) {
    struct crypto_ahash* mac;

    mac = crypto_alloc_ahash(mac_alg, 0, 0);
    if (IS_ERR(mac))
        return PTR_ERR(mac);

    cc->key_mac_size = crypto_ahash_digestsize(mac);
    crypto_free_ahash(mac);

    cc->authenc_key = kmalloc(crypt_authenckey_size(cc), GFP_KERNEL);
    if (!cc->authenc_key)
        return -ENOMEM;

    return 0;
}

static int crypt_ctr_cipher(struct dm_target* ti, char* key) {
    struct crypt_config* cc = ti->private;
    const char* ivmode = DEFAULT_IVMODE;
    int ret = -EINVAL;

    cc->cipher_string = kstrdup(AUTHCIPHER, GFP_KERNEL);
    if (!cc->cipher_string)
        goto bad_mem;

    cc->cpu = __alloc_percpu(sizeof(*(cc->cpu)), __alignof__(struct crypt_cpu));
    if (!cc->cpu) {
        ti->error = "Cannot allocate per cpu state";
        goto bad_mem;
    }

    /* Allocate cipher */
    printk("Auth Cipher : %s\n", AUTHCIPHER);
    ret = crypt_alloc_tfm(cc, AUTHCIPHER);
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        goto bad;
    }

    /* Alloc AEAD, can be used only in new format. */
    ret = crypt_ctr_auth_cipher(cc, HMAC);
    if (ret < 0) {
        ti->error = "Invalid AEAD cipher spec";
        return -ENOMEM;
    }

    /* Initialize IV */
    /* at least a 64 bit sector number should fit in our buffer */
    cc->iv_size = max(crypto_aead_ivsize(cc->tfm),
                      (unsigned int)(sizeof(u64) / sizeof(u8)));

    /* Initialize and set key */
    ret = crypt_set_key(cc, key);
    if (ret < 0) {
        ti->error = "Error decoding and setting key";
        goto bad;
    }

    /* Set authsize */
    ret = crypto_aead_setauthsize(cc->tfm, AUTHSIZE);
    if (ret) {
        ti->error = "Error setting authsize";
        goto bad;
    }

    /* Choose ivmode, see comments at iv code. */
    if (ivmode == NULL)
        cc->iv_gen_ops = NULL;
    else if (strcmp(ivmode, "plain") == 0)
        cc->iv_gen_ops = &crypt_iv_plain_ops;
    else if (strcmp(ivmode, "plain64") == 0)
        cc->iv_gen_ops = &crypt_iv_plain64_ops;
    else if (strcmp(ivmode, "null") == 0)
        cc->iv_gen_ops = &crypt_iv_null_ops;
    else {
        ret = -EINVAL;
        ti->error = "Invalid IV mode";
        goto bad;
    }

    ret = 0;
bad:
    return ret;

bad_mem:
    ti->error = "Cannot allocate cipher strings";
    return -ENOMEM;
}

/*
 * Construct an encryption mapping:
 * <key> <dev_path> <start>
 */
static int crypt_ctr(struct dm_target* ti, unsigned int argc, char** argv) {
    struct crypt_config* cc;
    unsigned int key_size;
    unsigned long long tmpll;
    int ret;
    char dummy;

    if (argc < 3) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

    key_size = strlen(argv[0]) >> 1;

    cc = kzalloc(sizeof(*cc) + key_size * sizeof(u8), GFP_KERNEL);
    if (!cc) {
        ti->error = "Cannot allocate encryption context";
        return -ENOMEM;
    }
    cc->key_size = key_size;

    ti->private = cc;
    ret = crypt_ctr_cipher(ti, argv[0]);
    if (ret < 0)
        goto bad;

    ret = -ENOMEM;
    cc->io_pool = mempool_create_slab_pool(MIN_IOS, _crypt_io_pool);
    if (!cc->io_pool) {
        ti->error = "Cannot allocate crypt io mempool";
        goto bad;
    }

    // FIXME : alignment is removed for quick development
    cc->dmreq_start = sizeof(struct aead_request);
    cc->dmreq_start += crypto_aead_reqsize(cc->tfm);  // tfm ctx

    cc->req_pool = mempool_create_kmalloc_pool(
        MIN_IOS,
        cc->dmreq_start + sizeof(struct dm_crypt_request) + cc->iv_size);
    if (!cc->req_pool) {
        ti->error = "Cannot allocate crypt request mempool";
        goto bad;
    }

    cc->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
    if (!cc->page_pool) {
        ti->error = "Cannot allocate page mempool";
        goto bad;
    }

    cc->bs = bioset_create(MIN_IOS, 0);
    if (!cc->bs) {
        ti->error = "Cannot allocate crypt bioset";
        goto bad;
    }

    ret = -EINVAL;

    if (dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &cc->dev)) {
        ti->error = "Device lookup failed";
        goto bad;
    }

    if (sscanf(argv[2], "%llu%c", &tmpll, &dummy) != 1) {
        ti->error = "Invalid device sector";
        goto bad;
    }
    cc->start = tmpll;

    ret = -ENOMEM;
    cc->io_queue =
        alloc_workqueue("kcryptd_io", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 1);
    if (!cc->io_queue) {
        ti->error = "Couldn't create kcryptd io queue";
        goto bad;
    }

    cc->crypt_queue = alloc_workqueue(
        "kcryptd", WQ_NON_REENTRANT | WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!cc->crypt_queue) {
        ti->error = "Couldn't create kcryptd queue";
        goto bad;
    }

    ti->num_flush_bios = 1;
    ti->discard_zeroes_data_unsupported = true;

    return 0;

bad:
    crypt_dtr(ti);
    return ret;
}

static int crypt_map(struct dm_target* ti, struct bio* bio) {
    struct dm_crypt_io* io;
    struct crypt_config* cc = ti->private;

    /*
     * If bio is REQ_FLUSH or REQ_DISCARD, just bypass crypt queues.
     * - for REQ_FLUSH device-mapper core ensures that no IO is in-flight
     * - for REQ_DISCARD caller must use flush if IO ordering matters
     */
    if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD))) {
        bio->bi_bdev = cc->dev->bdev;
        if (bio_sectors(bio))
            bio->bi_sector = cc->start + dm_target_offset(ti, bio->bi_sector);
        return DM_MAPIO_REMAPPED;
    }

    io = crypt_io_alloc(cc, bio, dm_target_offset(ti, bio->bi_sector));

    if (bio_data_dir(io->base_bio) == READ) {
        if (kcryptd_io_read(io, GFP_NOWAIT))
            kcryptd_queue_io(io);
    } else
        kcryptd_queue_crypt(io);

    return DM_MAPIO_SUBMITTED;
}

static void crypt_status(struct dm_target* ti,
                         status_type_t type,
                         unsigned status_flags,
                         char* result,
                         unsigned maxlen) {
    struct crypt_config* cc = ti->private;
    unsigned i, sz = 0;

    switch (type) {
        case STATUSTYPE_INFO:
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
            DMEMIT("%s ", cc->cipher_string);

            if (cc->key_size > 0)
                for (i = 0; i < cc->key_size; i++)
                    DMEMIT("%02x", cc->key[i]);
            else
                DMEMIT("-");

            DMEMIT(" %s %llu", cc->dev->name, (unsigned long long)cc->start);

            if (ti->num_discard_bios)
                DMEMIT(" 1 allow_discards");

            break;
    }
}

static void crypt_postsuspend(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;

    set_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

static int crypt_preresume(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;

    if (!test_bit(DM_CRYPT_KEY_VALID, &cc->flags)) {
        DMERR("aborting resume - crypt key is not set.");
        return -EAGAIN;
    }

    return 0;
}

static void crypt_resume(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;

    clear_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

/* Message interface
 *      key set <key>
 *      key wipe
 */
static int crypt_message(struct dm_target* ti, unsigned argc, char** argv) {
    struct crypt_config* cc = ti->private;
    int ret = -EINVAL;

    if (argc < 2)
        goto error;

    if (!strcasecmp(argv[0], "key")) {
        if (!test_bit(DM_CRYPT_SUSPENDED, &cc->flags)) {
            DMWARN("not suspended during key manipulation.");
            return -EINVAL;
        }
        if (argc == 3 && !strcasecmp(argv[1], "set")) {
            ret = crypt_set_key(cc, argv[2]);
            if (ret)
                return ret;
            return ret;
        }
        if (argc == 2 && !strcasecmp(argv[1], "wipe")) {
            return crypt_wipe_key(cc);
        }
    }

error:
    DMWARN("unrecognised message received.");
    return -EINVAL;
}

static int crypt_merge(struct dm_target* ti,
                       struct bvec_merge_data* bvm,
                       struct bio_vec* biovec,
                       int max_size) {
    struct crypt_config* cc = ti->private;
    struct request_queue* q = bdev_get_queue(cc->dev->bdev);

    if (!q->merge_bvec_fn)
        return max_size;

    bvm->bi_bdev = cc->dev->bdev;
    bvm->bi_sector = cc->start + dm_target_offset(ti, bvm->bi_sector);

    return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int crypt_iterate_devices(struct dm_target* ti,
                                 iterate_devices_callout_fn fn,
                                 void* data) {
    struct crypt_config* cc = ti->private;

    return fn(ti, cc->dev, cc->start, ti->len, data);
}

static struct target_type crypt_target = {
    .name = "security",
    .version = {1, 12, 1},
    .module = THIS_MODULE,
    .ctr = crypt_ctr,
    .dtr = crypt_dtr,
    .map = crypt_map,
    .status = crypt_status,
    .postsuspend = crypt_postsuspend,
    .preresume = crypt_preresume,
    .resume = crypt_resume,
    .message = crypt_message,
    .merge = crypt_merge,
    .iterate_devices = crypt_iterate_devices,
};

static int __init dm_crypt_init(void) {
    int r;

    _crypt_io_pool = KMEM_CACHE(dm_crypt_io, 0);
    if (!_crypt_io_pool)
        return -ENOMEM;

    r = dm_register_target(&crypt_target);
    if (r < 0) {
        DMERR("register failed %d", r);
        kmem_cache_destroy(_crypt_io_pool);
    }

    return r;
}

static void __exit dm_crypt_exit(void) {
    dm_unregister_target(&crypt_target);
    kmem_cache_destroy(_crypt_io_pool);
}

module_init(dm_crypt_init);
module_exit(dm_crypt_exit);

MODULE_AUTHOR(
    "Christophe Saout <christophe@saout.de>; Weibin Sun <wbsun@cs.utah.edu>; "
    "Peihong Chen <mf21320017@smail.nju.edu.cn>");
MODULE_DESCRIPTION(DM_NAME " target for transparent encryption / decryption");
MODULE_LICENSE("GPL");
