/*
 * Copyright (C) 2003 Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2009 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022-2023 Peihong Chen <mf21320017@smail.nju.edu.cn>
 *
 * This file is released under the GPL.
 */
#include <linux/vmalloc.h>
#include "../trusted-storage/trusted-storage.h"
#include "dm-security.h"

#define DEFAULT_DM_SUPER_BLOCK_SIZE (512)    // 512 bytes
#define DEFAULT_DM_DATA_BLOCK_SIZE (4096)    // 4KB
#define DEFAULT_DM_HASH_BLOCK_SIZE (512)     // 512 bytes
#define DEFAULT_DM_JOURNAL_BLOCK_SIZE (512)  // 512 bytes
#define DEFAULT_DM_METADATA_RATIO (64)       // 64:1
#define DEFAULT_DM_METADATA_RATIO_SHIFT \
    (ffs(DEFAULT_DM_METADATA_RATIO) - 1)  // 2^6
#define DEFAULT_LEAVES_PER_NODE (256)

struct security_iv_operations {
    int (*generator)(struct dm_security* s,
                     u8* iv,
                     struct dm_security_request* dmreq);
};

/*
 * Security: maps a linear range of a block device
 * and do authenticated encryption / decryption at the same time.
 */
enum flags { DM_SECURITY_SUSPENDED, DM_SECURITY_KEY_VALID };

#define MIN_IOS 16
#define MIN_POOL_PAGES 32
#define MIN_LEAVES 256

static struct kmem_cache* _security_io_pool;
static struct kmem_cache* _super_block_io_pool;
static struct kmem_cache* _hash_io_pool;
static struct kmem_cache* _leaf_node_pool;

#define data_size_per_mediate_node_shift(s) \
    ((s)->data_block_bits + (s)->leaves_per_node_bits)
#define data_size_per_mediate_node(s) (1 << data_size_per_mediate_node_shift(s))

static void ksecurityd_queue_security(struct dm_security_io* io);
static u8* iv_of_dmreq(struct dm_security* s,
                       struct dm_security_request* dmreq);

static struct security_cpu* this_security_cpu(struct dm_security* s) {
    return this_cpu_ptr(s->cpu);
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

static int security_iv_plain_gen(struct dm_security* s,
                                 u8* iv,
                                 struct dm_security_request* dmreq) {
    memset(iv, 0, s->iv_size);
    *(__le32*)iv = cpu_to_le32(dmreq->iv_sector & 0xffffffff);

    return 0;
}

static int security_iv_plain64_gen(struct dm_security* s,
                                   u8* iv,
                                   struct dm_security_request* dmreq) {
    memset(iv, 0, s->iv_size);
    *(__le64*)iv = cpu_to_le64(dmreq->iv_sector);

    return 0;
}

static int security_iv_null_gen(struct dm_security* s,
                                u8* iv,
                                struct dm_security_request* dmreq) {
    memset(iv, 0, s->iv_size);

    return 0;
}

static struct security_iv_operations security_iv_plain_ops = {
    .generator = security_iv_plain_gen};

static struct security_iv_operations security_iv_plain64_ops = {
    .generator = security_iv_plain64_gen};

static struct security_iv_operations security_iv_null_ops = {
    .generator = security_iv_null_gen};

static void security_convert_init(struct dm_security* s,
                                  struct convert_context* ctx,
                                  struct bio* bio_out,
                                  struct bio* bio_in,
                                  struct bio* bio_tag,
                                  sector_t sector) {
    ctx->bio_in = bio_in;
    ctx->bio_out = bio_out;
    ctx->bio_tag = bio_tag;
    ctx->offset_in = 0;
    ctx->offset_out = 0;
    ctx->offset_tag = 0;
    ctx->idx_in = bio_in ? bio_in->bi_idx : 0;
    ctx->idx_out = bio_out ? bio_out->bi_idx : 0;
    ctx->idx_tag = bio_tag ? bio_tag->bi_idx : 0;
    ctx->s_sector = sector;
    init_completion(&ctx->restart);
}

static struct dm_security_request* dmreq_of_req(struct dm_security* s,
                                                void* req) {
    return (struct dm_security_request*)((char*)req + s->dmreq_start);
}

static struct aead_request* req_of_dmreq(struct dm_security* s,
                                         struct dm_security_request* dmreq) {
    return (struct aead_request*)((char*)dmreq - s->dmreq_start);
}

static u8* iv_of_dmreq(struct dm_security* s,
                       struct dm_security_request* dmreq) {
    return (u8*)(dmreq + 1);
}

static void security_dec_pending(struct dm_security_io* io);

/*
 * For KGPU: convert all blocks together for speedup
 */
static int security_convert_blocks(struct dm_security* s,
                                   struct convert_context* ctx,
                                   struct aead_request* req) {
    struct bio_vec *bv_in, *bv_out, *bv_tag;
    struct dm_security_request* dmreq;
    uint64_t* assoc = NULL;
    unsigned tag_size = hash_node_size(s);
    unsigned assoclen = sizeof(uint64_t);
    unsigned size = ctx->bio_in->bi_size;
    unsigned blocks = size >> s->data_block_bits;
    u8* iv;
    int r, i;

    dmreq = dmreq_of_req(s, req);
    iv = iv_of_dmreq(s, dmreq);

    // dmreq->iv_sector = ctx->s_sector;
    dmreq->iv_sector = ctx->s_sector >> (s->data_block_bits - SECTOR_SHIFT);
    dmreq->ctx = ctx;

    /* contains iv and sector, but use zeros for test now */
    assoc = (uint64_t*)kzalloc(assoclen, GFP_KERNEL);
    if (!assoc)
        DMERR("Cannot allocate assoc buffer");

    /* sg_in data + sg_in tag + sg_out data + sg_out tag */
    dmreq->sg_in =
        kmalloc((ctx->bio_in->bi_vcnt + ctx->bio_out->bi_vcnt + 2 * blocks) *
                    sizeof(struct scatterlist),
                GFP_KERNEL);
    if (!dmreq->sg_in) {
        DMERR("out of memory %s:%d", __FILE__, __LINE__);
        return -ENOMEM;
    }
    dmreq->sg_out = dmreq->sg_in + ctx->bio_in->bi_vcnt + blocks;

    sg_init_table(dmreq->sg_in, ctx->bio_in->bi_vcnt + blocks);
    sg_init_table(dmreq->sg_out, ctx->bio_out->bi_vcnt + blocks);

    /* set data sg_in and sg_out */
    while (ctx->idx_in < ctx->bio_in->bi_vcnt &&
           ctx->idx_out < ctx->bio_out->bi_vcnt) {
        bv_in = bio_iovec_idx(ctx->bio_in, ctx->idx_in);
        bv_out = bio_iovec_idx(ctx->bio_out, ctx->idx_out);

        sg_set_page(dmreq->sg_in + ctx->idx_in, bv_in->bv_page, bv_in->bv_len,
                    bv_in->bv_offset);
        sg_set_page(dmreq->sg_out + ctx->idx_out, bv_out->bv_page,
                    bv_out->bv_len, bv_out->bv_offset);
        ctx->idx_in++;
        ctx->idx_out++;
    }

    /* set tag sg_in and sg_out */
    for (i = 0; i < blocks; i++) {
        bv_tag = bio_iovec_idx(ctx->bio_tag, ctx->idx_tag);

        sg_set_page(dmreq->sg_in + ctx->bio_in->bi_vcnt + i, bv_tag->bv_page,
                    tag_size, bv_tag->bv_offset + ctx->offset_tag);
        sg_set_page(dmreq->sg_out + ctx->bio_out->bi_vcnt + i, bv_tag->bv_page,
                    tag_size, bv_tag->bv_offset + ctx->offset_tag);

        ctx->offset_tag += tag_size;
        if (ctx->offset_tag >= bv_tag->bv_len) {
            ctx->offset_tag = 0;
            ctx->idx_tag++;
        }
    }

    /* set assoc sg */
    sg_init_one(&dmreq->sg_assoc, assoc, assoclen);

    if (s->iv_gen_ops) {
        r = s->iv_gen_ops->generator(s, iv, dmreq);
        if (r < 0)
            return r;
    }

    aead_request_set_assoc(req, &dmreq->sg_assoc, assoclen);
    if (bio_data_dir(ctx->bio_in) == WRITE) {
        aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out, size, iv);
        r = crypto_aead_encrypt(req);
    } else {
        aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
                               size + tag_size * blocks, iv);
        r = crypto_aead_decrypt(req);
    }

    if (r == -EBADMSG)
        DMERR_LIMIT("INTEGRITY AEAD ERROR, sector %llu",
                    (unsigned long long)le64_to_cpu(ctx->s_sector));

    return r;
}

static void ksecurityd_async_done(struct crypto_async_request* async_req,
                                  int error);

static void security_alloc_req(struct dm_security* s,
                               struct convert_context* ctx) {
    struct security_cpu* this_sc = this_security_cpu(s);

    if (!this_sc->req)
        this_sc->req = mempool_alloc(s->req_pool, GFP_NOIO);

    aead_request_set_tfm(this_sc->req, s->tfm);
    aead_request_set_callback(
        this_sc->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
        ksecurityd_async_done, dmreq_of_req(s, this_sc->req));
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 */
static int security_convert(struct dm_security* s,
                            struct convert_context* ctx) {
    struct security_cpu* this_sc = this_security_cpu(s);
    int r;

    atomic_set(&ctx->s_pending, 1);

    while (ctx->idx_in < ctx->bio_in->bi_vcnt &&
           ctx->idx_tag < ctx->bio_tag->bi_vcnt &&
           ctx->idx_out < ctx->bio_out->bi_vcnt) {
        security_alloc_req(s, ctx);

        atomic_inc(&ctx->s_pending);

        r = security_convert_blocks(s, ctx, this_sc->req);

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
             * completion function ksecurityd_async_done() will be called.
             */
            case -EINPROGRESS:
                this_sc->req = NULL;
                ctx->s_sector++;
                continue;

            /* sync */
            /*
             * The request was already processed (synchronously).
             */
            case 0:
                atomic_dec(&ctx->s_pending);
                ctx->s_sector++;
                cond_resched();
                continue;

            /*
             * There was a data integrity error.
             */
            case -EBADMSG:
                atomic_dec(&ctx->s_pending);
                return -EILSEQ;

            /* error */
            default:
                atomic_dec(&ctx->s_pending);
                return r;
        }
    }

    return 0;
}

/*
 * ksecurityd/ksecurityd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * ksecurityd performs the actual encryption or decryption.
 *
 * ksecurityd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-security instances.
 * They should not depend on each other and do not block.
 */
static void security_endio(struct bio* clone, int error) {
    struct dm_security_io* io = clone->bi_private;
    struct dm_security* s = io->s;
    unsigned rw = bio_data_dir(clone);

    pr_info("security_endio: 1\n");

    if (unlikely(!bio_flagged(clone, BIO_UPTODATE) && !error))
        error = -EIO;

    pr_info(
        "security_endio: 2, clone->bi_sector = %lu, clone->bi_size = %u, error "
        "= %d\n",
        clone->bi_sector, clone->bi_size, error);

    /*
     * free the processed pages
     */
    if (rw == WRITE) {
        pr_info("security_endio: 3, rw = WRITE\n");
        security_free_buffer_pages(s, clone);
    }

    pr_info("security_endio: 4\n");
    bio_put(clone);

    if (rw == READ && !error) {
        pr_info("security_endio: 5, rw = READ\n");
        ksecurityd_queue_security(io);
        return;
    }

    pr_info("security_endio: 6\n");

    if (unlikely(error))
        io->error = error;

    pr_info("security_endio: 7, io->error = %d\n", io->error);

    security_dec_pending(io);

    pr_info("security_endio: 8\n");
}

static void clone_init(struct dm_security_io* io, struct bio* clone) {
    struct dm_security* s = io->s;

    clone->bi_private = io;
    clone->bi_end_io = security_endio;
    clone->bi_bdev = s->dev->bdev;
    clone->bi_rw = io->bio->bi_rw;
}

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations
 * May return a smaller bio when running out of pages, indicated by
 * *out_of_pages set to 1.
 */
static struct bio* security_alloc_buffer(struct dm_security_io* io,
                                         unsigned size,
                                         unsigned* out_of_pages) {
    struct dm_security* s = io->s;
    struct bio* clone;
    unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    gfp_t gfp_mask = GFP_NOIO | __GFP_HIGHMEM;
    unsigned i, len;
    struct page* page;

    clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
    if (!clone)
        return NULL;

    clone_init(io, clone);
    *out_of_pages = 0;

    for (i = 0; i < nr_iovecs; i++) {
        page = mempool_alloc(s->page_pool, gfp_mask);
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
            mempool_free(page, s->page_pool);
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

static struct dm_security_io* security_io_alloc(struct dm_security* s,
                                                struct bio* bio,
                                                sector_t sector) {
    struct dm_security_io* io;
    size_t offset = sector >> (s->data_block_bits - SECTOR_SHIFT);
    size_t count = bio->bi_size >> s->data_block_bits;

    io = mempool_alloc(s->io_pool, GFP_NOIO);
    io->s = s;
    io->bio = bio;
    io->sector = sector;
    io->error = 0;
    io->hash_io = security_hash_io_alloc(s, offset, count);
    io->base_io = NULL;
    atomic_set(&io->io_pending, 0);

    return io;
}

static void security_inc_pending(struct dm_security_io* io) {
    atomic_inc(&io->io_pending);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 * If base_io is set, wait for the last fragment to complete.
 */
static void security_dec_pending(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct bio* bio = io->bio;
    struct dm_security_io* base_io = io->base_io;
    int error = io->error;

    if (!atomic_dec_and_test(&io->io_pending))
        return;

    if (io->hash_bio) {
        security_free_buffer_pages(s, io->hash_bio);
        bio_put(io->hash_bio);
        security_hash_io_free(io->hash_io);
    }

    mempool_free(io, s->io_pool);

    if (likely(!base_io))
        bio_endio(bio, error);
    else {
        if (error && !base_io->error)
            base_io->error = error;
        security_dec_pending(base_io);
    }
}

static int ksecurityd_io_read(struct dm_security_io* io, gfp_t gfp) {
    struct dm_security* s = io->s;
    struct data_blocks_cache* cache = &s->data_blocks_cache;
    struct bio* bio = io->bio;
    struct bio* clone;

    pr_info("ksecurityd_io_read: bio->bi_sector=%lu, bio->bi_size=%u\n",
            bio->bi_sector, bio->bi_size);

    /* check if data present in cache */
    if (!security_cache_lookup(cache, bio)) {
        pr_info("ksecurityd_io_read: cache hit\n");
        bio_endio(bio, 0);
        return 0;
    }

    pr_info("ksecurityd_io_read: cache miss\n");
    security_prefetch_hash_leaves(io->hash_io);

    /*
     * The block layer might modify the bvec array, so always
     * copy the required bvecs because we need the original
     * one in order to decrypt the whole bio data *afterwards*.
     */
    pr_info("ksecurityd_io_read: bio_clone_bioset\n");
    clone = bio_clone_bioset(bio, gfp, s->bs);
    if (!clone)
        return 1;

    pr_info(
        "ksecurityd_io_read: security_alloc_buffer, clone->bi_sector = %lu, "
        "clone->bi_size = %u\n",
        clone->bi_sector, clone->bi_size);

    security_inc_pending(io);

    pr_info("ksecurityd_io_read: clone_init, io->sector = %lu\n", io->sector);
    clone_init(io, clone);
    clone->bi_sector = security_map_data_sector(s, io->sector);

    pr_info(
        "ksecurityd_io_read: generic_make_request, clone->bi_sector = %lu, "
        "clone->bi_size = %u\n",
        clone->bi_sector, clone->bi_size);
    generic_make_request(clone);
    return 0;
}

static void ksecurityd_io_write(struct dm_security_io* io) {
    struct bio* clone = io->ctx.bio_out;
    generic_make_request(clone);
}

static void ksecurityd_io(struct work_struct* work) {
    struct dm_security_io* io = container_of(work, struct dm_security_io, work);

    if (bio_data_dir(io->bio) == READ) {
        security_inc_pending(io);
        if (ksecurityd_io_read(io, GFP_NOIO))
            io->error = -ENOMEM;
        security_dec_pending(io);
    } else
        ksecurityd_io_write(io);
}

static void ksecurityd_queue_io(struct dm_security_io* io) {
    struct dm_security* s = io->s;

    INIT_WORK(&io->work, ksecurityd_io);
    queue_work(s->io_queue, &io->work);
}

static void ksecurityd_security_write_io_submit(struct dm_security_io* io,
                                                int async) {
    struct bio* clone = io->ctx.bio_out;
    struct dm_security* s = io->s;

    if (unlikely(io->error < 0)) {
        security_free_buffer_pages(s, clone);
        bio_put(clone);
        security_dec_pending(io);
        return;
    }

    /* security_convert should have filled the clone bio */
    BUG_ON(io->ctx.idx_out < clone->bi_vcnt);

    clone->bi_sector = s->data_start + io->sector;

    if (async)
        ksecurityd_queue_io(io);
    else
        generic_make_request(clone);
}

static void ksecurityd_security_write_convert(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct bio* clone;
    struct dm_security_io* new_io;
    int security_finished;
    unsigned out_of_pages = 0;
    unsigned remaining = io->bio->bi_size;
    sector_t sector = io->sector;
    int r;

    /*
     * Prevent io from disappearing until this function completes.
     */
    security_inc_pending(io);
    security_convert_init(s, &io->ctx, NULL, io->bio, io->hash_bio, sector);

    /*
     * The allocated buffers can be smaller than the whole bio,
     * so repeat the whole process until all the data can be handled.
     */
    while (remaining) {
        /* clone bio and alloc new pages so as not to modify orignal data */
        clone = security_alloc_buffer(io, remaining, &out_of_pages);
        if (unlikely(!clone)) {
            io->error = -ENOMEM;
            break;
        }

        io->ctx.bio_out = clone;
        io->ctx.idx_out = 0;

        remaining -= clone->bi_size;
        sector += bio_sectors(clone);

        security_inc_pending(io);

        r = security_convert(s, &io->ctx);
        if (r < 0)
            io->error = -EIO;

        security_finished = atomic_dec_and_test(&io->ctx.s_pending);

        /* sync */
        /* Encryption was already finished, submit io now */
        if (security_finished) {
            ksecurityd_security_write_io_submit(io, 0);

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
         * between fragments, so switch to a new dm_security_io structure.
         */
        if (unlikely(!security_finished && remaining)) {
            new_io = security_io_alloc(io->s, io->bio, sector);
            security_inc_pending(new_io);
            security_convert_init(s, &new_io->ctx, NULL, io->bio, io->hash_bio,
                                  sector);
            new_io->ctx.idx_in = io->ctx.idx_in;
            new_io->ctx.idx_tag = io->ctx.idx_tag;
            new_io->ctx.offset_in = io->ctx.offset_in;
            new_io->ctx.offset_tag = io->ctx.offset_tag;

            /*
             * Fragments after the first use the base_io
             * pending count.
             */
            if (!io->base_io)
                new_io->base_io = io;
            else {
                new_io->base_io = io->base_io;
                security_inc_pending(io->base_io);
                security_dec_pending(io);
            }

            io = new_io;
        }
    }

    security_dec_pending(io);
}

static void ksecurityd_security_read_done(struct dm_security_io* io) {
    security_dec_pending(io);
}

static void ksecurityd_security_read_convert(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct security_hash_io* hash_io = io->hash_io;
    struct bio_vec* bv_tag = NULL;
    struct security_leaf_node* ln = NULL;
    unsigned int idx_tag, offset_tag;
    unsigned int tag_size = hash_node_size(s);
    u8 *tag_addr = NULL, *hash_addr = NULL;
    int r = 0, i;

    pr_info("ksecurityd_security_read_convert: 1\n");

    security_inc_pending(io);

    pr_info("ksecurityd_security_read_convert: 2, io->sector = %lu\n",
            io->sector);

    security_convert_init(s, &io->ctx, io->bio, io->bio, io->hash_bio,
                          io->sector);

    pr_info("ksecurityd_security_read_convert: 3\n");

    r = security_convert(s, &io->ctx);

    pr_info("ksecurityd_security_read_convert: 3.1, r = %d\n", r);

    if (r < 0)
        io->error = -EIO;

    pr_info("ksecurityd_security_read_convert: 4\n");
    /* wait for hash prefetch io to complete */
    wait_for_completion(&hash_io->restart);

    /* check if tags match */
    pr_info("ksecurityd_security_read_convert: 5\n");
    idx_tag = offset_tag = 0;
    for (i = 0; i < hash_io->count; i++) {
        bv_tag = bio_iovec_idx(io->hash_bio, idx_tag);
        tag_addr =
            page_address(bv_tag->bv_page) + bv_tag->bv_offset + offset_tag;
        pr_info("ksecurityd_security_read_convert: 6\n");

        ln = cache_get_leaf_node(s, i + hash_io->offset);
        pr_info("ksecurityd_security_read_convert: 7, ln = %p\n", ln);

        if (ln) {
            hash_addr = ln->digest;
            pr_info("ksecurityd_security_read_convert: 7, hash_addr = %p\n",
                    hash_addr);
        } else {
            pr_info(
                "ksecurityd_security_read_convert: leaf node not in cache, "
                "bypass tag checking\n");
            continue;
        }

        if (memcmp(tag_addr, hash_addr, tag_size)) {
            DMERR(
                "tag mismatch at sector %lu, i = %d, expect {%.2x %.2x %.2x "
                "%.2x %.2x %.2x %.2x %.2x}, actual {%.2x %.2x %.2x %.2x %.2x "
                "%.2x %.2x %.2x}",
                io->sector + (i << (s->data_block_bits - SECTOR_SHIFT)), i,
                hash_addr[0], hash_addr[1], hash_addr[2], hash_addr[3],
                hash_addr[4], hash_addr[5], hash_addr[6], hash_addr[7],
                tag_addr[0], tag_addr[1], tag_addr[2], tag_addr[3], tag_addr[4],
                tag_addr[5], tag_addr[6], tag_addr[7]);
            io->error = -EBADMSG;
            goto out;
        }

        pr_info("ksecurityd_security_read_convert: 9\n");
        offset_tag += tag_size;
        if (offset_tag >= bv_tag->bv_len) {
            offset_tag = 0;
            idx_tag++;
        }
    }

out:
    pr_info("ksecurityd_security_read_convert: 10\n");
    if (atomic_dec_and_test(&io->ctx.s_pending))
        ksecurityd_security_read_done(io);

    pr_info("ksecurityd_security_read_convert: 11\n");
    security_dec_pending(io);
    pr_info("ksecurityd_security_read_convert: 12\n");
}

static void ksecurityd_async_done(struct crypto_async_request* async_req,
                                  int error) {
    struct dm_security_request* dmreq = async_req->data;
    struct convert_context* ctx = dmreq->ctx;
    struct dm_security_io* io = container_of(ctx, struct dm_security_io, ctx);
    struct dm_security* s = io->s;

    if (error == -EINPROGRESS) {
        complete(&ctx->restart);
        return;
    }

    if (error < 0)
        io->error = -EIO;

    mempool_free(req_of_dmreq(s, dmreq), s->req_pool);

    if (!atomic_dec_and_test(&ctx->s_pending))
        return;

    if (bio_data_dir(io->bio) == READ)
        ksecurityd_security_read_done(io);
    else
        ksecurityd_security_write_io_submit(io, 1);
}

static void ksecurityd_security(struct work_struct* work) {
    struct dm_security_io* io = container_of(work, struct dm_security_io, work);
    struct security_hash_io* hash_io = io->hash_io;
    struct dm_security* s = io->s;
    struct bio* bio = NULL;
    struct page* page = NULL;
    unsigned remainings = hash_io->count << s->hash_node_bits;
    unsigned nr_iovecs = DIV_ROUND_UP_BITS(remainings, PAGE_SHIFT);
    unsigned len = 0;

    pr_info("ksecurityd_security: start\n");

    /* alloc hash bio to hold generated authentication tags */
    bio = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
    /* NOTE : must set bio->bi_bdev before bio_add_page */
    bio->bi_bdev = s->dev->bdev;

    while (nr_iovecs--) {
        page = mempool_alloc(s->page_pool, GFP_NOIO | __GFP_HIGHMEM);
        len = min(remainings, (unsigned)PAGE_SIZE);
        if (!bio_add_page(bio, page, len, 0)) {
            mempool_free(page, s->page_pool);
            break;
        }
        remainings -= len;
    }
    io->hash_bio = bio;

    if (bio_data_dir(io->bio) == READ)
        ksecurityd_security_read_convert(io);
    else
        ksecurityd_security_write_convert(io);

    pr_info("ksecurityd_security: end\n");
}

static void ksecurityd_queue_security(struct dm_security_io* io) {
    struct dm_security* s = io->s;

    INIT_WORK(&io->work, ksecurityd_security);
    queue_work(s->security_queue, &io->work);
}

static void security_free_tfm(struct dm_security* s) {
    if (!s->tfm)
        return;

    if (s->tfm && !IS_ERR(s->tfm)) {
        crypto_free_aead(s->tfm);
        s->tfm = NULL;
    }
}

static int security_alloc_tfm(struct dm_security* s, char* ciphermode) {
    int err;

    s->tfm = crypto_alloc_aead(ciphermode, 0, 0);
    if (IS_ERR(s->tfm)) {
        err = PTR_ERR(s->tfm);
        security_free_tfm(s);
        return err;
    }

    return 0;
}

static unsigned security_authenckey_size(struct dm_security* s) {
    return s->key_size + RTA_SPACE(sizeof(struct crypto_authenc_key_param));
}

/*
 * If AEAD is composed like authenc(hmac(sha512),xts(aes)),
 * the key must be for some reason in special format.
 * This funcion converts s->key to this special format.
 *
 * | rta length | rta type | enckey length | authkey | enckey |
 *         ↑        ↑              ↑
 *      (little endian)      (big endian)
 */
static void security_copy_authenckey(char* p,
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

static int security_setkey_allcpus(struct dm_security* s) {
    int ret;

    ret = crypto_shash_setkey(
        s->hmac_tfm, s->key + (s->key_size - s->key_mac_size), s->key_mac_size);
    if (ret < 0)
        goto bad;

    security_copy_authenckey(s->authenc_key, s->key,
                             s->key_size - s->key_mac_size, s->key_mac_size);
    ret =
        crypto_aead_setkey(s->tfm, s->authenc_key, security_authenckey_size(s));
    if (ret)
        goto bad;

    ret = 0;
bad:
    memzero_explicit(s->authenc_key, security_authenckey_size(s));
    return ret;
}

static int security_set_key(struct dm_security* s, char* key) {
    int r = -EINVAL;
    int key_string_len = strlen(key);

    /* The key size may not be changed. */
    if (s->key_size != (key_string_len >> 1))
        goto out;

    /* Hyphen (which gives a key_size of zero) means there is no key. */
    if (!s->key_size && strcmp(key, "-"))
        goto out;

    if (s->key_size && hex2bin(s->key, key, s->key_size) < 0)
        goto out;

    set_bit(DM_SECURITY_KEY_VALID, &s->flags);

    r = security_setkey_allcpus(s);

out:
    /* Hex key string not needed after here, so wipe it. */
    memset(key, '0', key_string_len);

    return r;
}

static int security_wipe_key(struct dm_security* s) {
    clear_bit(DM_SECURITY_KEY_VALID, &s->flags);
    memset(&s->key, 0, s->key_size * sizeof(u8));

    return security_setkey_allcpus(s);
}

/*
 * Workaround to parse HMAC algorithm from AEAD crypto API spec.
 * The HMAC is needed to calculate tag size (HMAC digest size).
 * This should be probably done by crypto-api calls (once available...)
 */
static int security_ctr_auth_cipher(struct dm_security* s, char* mac_alg) {
    struct crypto_ahash* mac;

    mac = crypto_alloc_ahash(mac_alg, 0, 0);
    if (IS_ERR(mac))
        return PTR_ERR(mac);

    s->key_mac_size = crypto_ahash_digestsize(mac);
    crypto_free_ahash(mac);

    s->authenc_key = kmalloc(security_authenckey_size(s), GFP_KERNEL);
    if (!s->authenc_key)
        return -ENOMEM;

    return 0;
}

static int security_ctr_hash_cipher(struct dm_security* s, char* inc_hash_alg) {
    struct dm_target* ti = s->ti;
    int ret = 0;

    s->hash_tfm = crypto_alloc_shash(inc_hash_alg, 0, 0);
    if (IS_ERR(s->hash_tfm)) {
        ret = PTR_ERR(s->hash_tfm);
        ti->error = "Cannot allocate SHASH TFM structure";
        goto bad;
    }

    s->hash_desc =
        kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(s->hash_tfm),
                GFP_KERNEL);
    if (IS_ERR(s->hash_desc)) {
        crypto_free_shash(s->hash_tfm);
        ret = -ENOMEM;
        ti->error = "Cannot allocate SHASH Desc structure";
        goto bad;
    }

    s->hash_desc->tfm = s->hash_tfm;
    s->hash_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

bad:
    return ret;
}

static int security_ctr_mac_cipher(struct dm_security* s, char* mac_alg) {
    struct dm_target* ti = s->ti;
    int ret;

    s->hmac_tfm = crypto_alloc_shash(mac_alg, 0, 0);
    if (IS_ERR(s->hmac_tfm)) {
        ti->error = "Cannot initialize hash function";
        ret = PTR_ERR(s->hmac_tfm);
        s->hmac_tfm = NULL;
        goto bad;
    }
    s->hmac_digest_size = crypto_shash_digestsize(s->hmac_tfm);

    ret = -ENOMEM;
    s->hmac_desc =
        kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(s->hmac_tfm),
                GFP_KERNEL);
    if (!s->hmac_desc) {
        ti->error = "Cannot allocate HMAC Desc structure";
        goto bad;
    }

    s->hmac_digest = kzalloc(s->hmac_digest_size, GFP_KERNEL);
    if (!s->hmac_digest) {
        ti->error = "Cannot allocate mintegrity structure";
        goto bad;
    }

    s->hmac_desc->tfm = s->hmac_tfm;
    s->hmac_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

    ret = 0;
bad:
    return ret;
}

static int security_ctr_cipher(struct dm_target* ti, char* key) {
    struct dm_security* s = ti->private;
    const char* ivmode = DEFAULT_IVMODE;
    int ret = -EINVAL;

    s->cipher_string = kstrdup(AUTHCIPHER, GFP_KERNEL);
    if (!s->cipher_string)
        goto bad_mem;

    s->cpu =
        __alloc_percpu(sizeof(*(s->cpu)), __alignof__(struct security_cpu));
    if (!s->cpu) {
        ti->error = "Cannot allocate per cpu state";
        goto bad_mem;
    }

    /* Allocate cipher */
    DMINFO("Auth Cipher : %s", AUTHCIPHER);
    ret = security_alloc_tfm(s, AUTHCIPHER);
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        goto bad;
    }

    /* Alloc AEAD, can be used only in new format. */
    ret = security_ctr_auth_cipher(s, HMAC);
    if (ret < 0) {
        ti->error = "Invalid AEAD cipher spec";
        return -ENOMEM;
    }

    /* Alloc IncHash used for hash tree */
    ret = security_ctr_hash_cipher(s, DEFAULT_INC_HASH);
    if (ret < 0) {
        ti->error = "Invalid IncHash cipher spec";
        return -ENOMEM;
    }

    /* Alloc HMAC used for super block */
    ret = security_ctr_mac_cipher(s, HMAC);
    if (ret < 0) {
        ti->error = "Invalid HMAC cipher spec";
        return -ENOMEM;
    }

    /* Initialize IV */
    /* at least a 64 bit sector number should fit in our buffer */
    s->iv_size = max(crypto_aead_ivsize(s->tfm),
                     (unsigned int)(sizeof(u64) / sizeof(u8)));

    /* Initialize and set key */
    ret = security_set_key(s, key);
    if (ret < 0) {
        ti->error = "Error decoding and setting key";
        goto bad;
    }

    /* Set authsize */
    ret = crypto_aead_setauthsize(s->tfm, AUTHSIZE);
    if (ret) {
        ti->error = "Error setting authsize";
        goto bad;
    }

    /* Choose ivmode, see comments at iv code. */
    if (ivmode == NULL)
        s->iv_gen_ops = NULL;
    else if (strcmp(ivmode, "plain") == 0)
        s->iv_gen_ops = &security_iv_plain_ops;
    else if (strcmp(ivmode, "plain64") == 0)
        s->iv_gen_ops = &security_iv_plain64_ops;
    else if (strcmp(ivmode, "null") == 0)
        s->iv_gen_ops = &security_iv_null_ops;
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

static void security_rebuild_read_convert(struct bio* bio,
                                          struct bio* hash_bio) {
    struct security_rebuild_data* data = bio->bi_private;
    struct dm_security* s = data->s;
    struct convert_context ctx;

    security_convert_init(s, &ctx, bio, bio, hash_bio, bio->bi_sector);

    data->error = security_convert(s, &ctx);
}

static void security_rebuild_endio(struct bio* bio, int error) {
    struct security_rebuild_data* data = bio->bi_private;
    unsigned rw = bio_data_dir(bio);

    if (unlikely(!bio_flagged(bio, BIO_UPTODATE) && !error))
        error = -EIO;

    if (error)
        DMERR(
            "security_rebuild_endio: I/O error %d, bi_sector %lu, bi_size %u, "
            "rw %s",
            error, bio->bi_sector, bio->bi_size, rw == READ ? "READ" : "WRITE");

    if (unlikely(error))
        data->error = error;

    if (rw == WRITE)
        up(&data->sema);

    bio_put(bio);

    if (rw == READ && !error)
        complete(&data->restart);
}

/**
 * Format disk layout during initial construction for dm-security
 */
static int security_metadata_rebuild(struct dm_target* ti, u8* root_hash) {
    struct dm_security* s = ti->private;
    struct security_mediate_node* mn;
    struct security_rebuild_data data;
    struct inc_hash_ctx *mn_ctx = NULL, *ln_ctx = NULL, *ctx;
    struct bio *bio = NULL, *clone = NULL, *hash_bio = NULL;
    struct page* page;
    unsigned totals =
        DIV_ROUND_UP_BITS(s->data_blocks << s->data_block_bits, PAGE_SHIFT);
    unsigned remainings = totals;
    unsigned nr_iovecs;
    unsigned leaves_per_node = (1 << s->leaves_per_node_bits);
    unsigned mn_step =
        DIV_ROUND_UP_BITS((leaves_per_node << s->data_block_bits), PAGE_SHIFT);
    unsigned ln_step = DIV_ROUND_UP_BITS(
        ((leaves_per_node >> 2) << s->data_block_bits), PAGE_SHIFT);
    unsigned digestsize = hash_node_size(s);
    /* make ctx->data in one page */
    size_t ctx_size =
        roundup(sizeof(struct inc_hash_ctx) + digestsize, digestsize);
    sector_t sector = 0;
    gfp_t gfp_mask = GFP_NOIO | __GFP_HIGHMEM;
    int i, j, ret = 0, offset, ln_idx;

    DMINFO("Start device formatting to build metadata");

    /* alloc mediate nodes buffer */
    ret = security_mediate_nodes_init(s);
    if (ret) {
        ti->error = "Cannot allocate mediate nodes";
        goto bad;
    }

    mn_ctx = kmalloc(ctx_size * (ln_step + 1), GFP_KERNEL);
    if (!mn_ctx) {
        ti->error = "Cannot allocate incremental hash context";
        ret = -ENOMEM;
        goto bad;
    }
    mn_ctx->old_len = 0;

    ln_ctx = (void*)mn_ctx + ctx_size;

    data.s = s;
    data.error = 0;
    sema_init(&data.sema, 1);
    /* FIXME : make it more efficient? */
    i = 0;
    offset = 0;
    ln_idx = 0;
    while (remainings) {
        init_completion(&data.restart);
        /* alloc data bio */
        nr_iovecs = min(remainings, ln_step);
        bio = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
        bio->bi_private = &data;
        bio->bi_end_io = security_rebuild_endio;
        bio->bi_bdev = s->dev->bdev;
        bio->bi_sector = sector;
        bio->bi_rw |= READ;
        if (unlikely(!(remainings & ((1 << 15) - 1))))
            pr_info("metadata rebuild progress: [ %u / 100 ]\n",
                    100 * (totals - remainings) / totals);

        for (j = 0; j < nr_iovecs; j++) {
            page = mempool_alloc(s->page_pool, gfp_mask);
            if (!bio_add_page(bio, page, PAGE_SIZE, 0)) {
                mempool_free(page, s->page_pool);
                break;
            }
        }
        offset += nr_iovecs;

        clone = bio_clone_bioset(bio, GFP_NOIO, s->bs);
        if (!clone) {
            ret = -ENOMEM;
            goto bad;
        }
        clone->bi_private = bio->bi_private;
        clone->bi_end_io = bio->bi_end_io;
        clone->bi_bdev = bio->bi_bdev;
        clone->bi_rw = bio->bi_rw;
        clone->bi_sector = security_map_data_sector(s, bio->bi_sector);

        generic_make_request(clone);
        wait_for_completion(&data.restart);

        /* save leaf nodes to hash area */
        hash_bio = bio_alloc_bioset(GFP_KERNEL, nr_iovecs, s->bs);
        if (!hash_bio) {
            ret = -ENOMEM;
            goto bad;
        }
        hash_bio->bi_private = &data;
        hash_bio->bi_end_io = security_rebuild_endio;
        hash_bio->bi_bdev = s->dev->bdev;
        hash_bio->bi_sector = security_map_hash_sector(
            s, leaf_sector_of_block(s, data_block_of_sector(s, sector)));
        hash_bio->bi_rw = WRITE;
        for (j = 0; j < nr_iovecs; j++) {
            ctx = (void*)ln_ctx + j * ctx_size;
            if (!bio_add_page(hash_bio, virt_to_page(ctx->data), digestsize,
                              offset_in_page(ctx->data)))
                break;
        }

        /* decrypt data blocks and output authenticated tag to hash_bio */
        security_rebuild_read_convert(bio, hash_bio);
        /* where is suitable to release pages and bio */
        security_free_buffer_pages(s, bio);
        bio_put(bio);

        if (data.error) {
            ret = data.error;
            goto bad;
        }

        down(&data.sema);
        generic_make_request(hash_bio);

        mn = s->mediate_nodes[i];
        /* calculate mediate node hash value */
        for (j = 0; j < nr_iovecs; j++) {
            ctx = (void*)ln_ctx + j * ctx_size;
            /* use leaf node index as inc hash id instead of block sector */
            ctx->id = ln_idx++;
            ctx->old_len = 0;
            ret = crypto_shash_digest(s->hash_desc, (const u8*)ctx, digestsize,
                                      mn->digest);
            if (ret)
                goto bad;
        }

        remainings -= nr_iovecs;
        sector += ln_step << (PAGE_SHIFT - SECTOR_SHIFT);

        /* calculate root hash step by step using incremental hash function */
        if (offset >= mn_step || remainings == 0) {
            mn_ctx->id = i;
            memcpy(mn_ctx->data, mn->digest, digestsize);
            ret = crypto_shash_digest(s->hash_desc, (const u8*)mn_ctx,
                                      digestsize, root_hash);
            if (ret)
                goto bad;

            offset = 0;
            i++;
        }
    }
    down(&data.sema);

    DMINFO("Root Hash: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x", root_hash[0],
           root_hash[1], root_hash[2], root_hash[3], root_hash[4], root_hash[5],
           root_hash[6], root_hash[7]);

bad:
    if (mn_ctx)
        kfree(mn_ctx);
    return ret;
}

/**
 * Disk layout:
 * | SuperBlock | Hash Area | Data Blocks |
 *
 * Super Block (512B):
 * | Magic | Layout Params | SB HMAC | Padding |
 * |  64B  |      ...      |   64B   | (Rest)  |
 *
 * Note: hash area stores only leaf nodes
 */
static int security_ctr_layout(struct dm_target* ti,
                               char* dev_path,
                               char* start) {
    struct dm_security* s = ti->private;
    struct security_super_block_io* sb_io;
    unsigned long long tmpll;
    unsigned int data_area_size = DEFAULT_DM_DATA_BLOCK_SIZE;
    unsigned int hash_block_size = DEFAULT_DM_HASH_BLOCK_SIZE;
    unsigned int leave_per_node = DEFAULT_LEAVES_PER_NODE;
    unsigned int digestsize = AUTHSIZE;
    u8 *root_hash = NULL, *saved_root_hash = NULL;
    int ret = -EINVAL;
    char dummy;

    if (dm_get_device(ti, dev_path, dm_table_get_mode(ti->table), &s->dev)) {
        ti->error = "Device lookup failed";
        goto bad;
    }

    if (sscanf(start, "%llu%c", &tmpll, &dummy) != 1) {
        ti->error = "Invalid device sector";
        goto bad;
    }
    s->start = tmpll;
    s->sb_start = s->start;

    s->sb =
        (struct security_super_block*)kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
    if (!s->sb) {
        ti->error = "Cannot allocate super block";
        goto bad;
    }

    /* Read super block from device */
    sb_io = security_super_block_io_alloc(s);
    if (!sb_io) {
        ti->error = "Cannot allocate super block read io";
        goto bad;
    }
    ret = ksecurityd_super_block_io_read(sb_io);
    if (ret < 0) {
        security_super_block_io_free(sb_io);
        ti->error = "Cannot read super block";
        goto bad;
    }

    wait_for_completion(&sb_io->restart);

    if (s->sb->magic == DM_SUPER_BLOCK_MAGIC) {
        /* Super block is valid */
        DMINFO("Super block loaded from device sector %lu", s->sb_start);

        // Check super block hmac first
        if (memcmp(s->hmac_digest, s->sb->sb_mac, AUTHSIZE)) {
            DMERR("Super block courrupted, mac not match");
            DMINFO(
                "  Expect MAC : %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
                "%.2x",
                s->sb->sb_mac[0], s->sb->sb_mac[1], s->sb->sb_mac[2],
                s->sb->sb_mac[3], s->sb->sb_mac[4], s->sb->sb_mac[5],
                s->sb->sb_mac[6], s->sb->sb_mac[7]);
            DMINFO(
                "  Actual MAC : %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
                "%.2x",
                s->hmac_digest[0], s->hmac_digest[1], s->hmac_digest[2],
                s->hmac_digest[3], s->hmac_digest[4], s->hmac_digest[5],
                s->hmac_digest[6], s->hmac_digest[7]);
            ti->error = "Super block courrupted";
            goto sb_corrupted;
        }

        // Load device layout params from disk super block
        security_super_block_load(s);

        /* load root hash from trusted storage (emulator) */
        saved_root_hash = kzalloc(hash_node_size(s), GFP_KERNEL);
        if (!saved_root_hash) {
            ti->error = "Cannot allocate saved root hash buffer";
            goto bad;
        }

        ret = trusted_storage_read(s->root_hash_key, saved_root_hash,
                                   hash_node_size(s));
        if (ret) {
            ti->error = "Cannot read saved root hash from trusted storage";
            goto bad;
        }

        goto out;
    }

    /* Super block not available */

    if (!data_area_size || (data_area_size & (data_area_size - 1)) ||
        data_area_size < bdev_logical_block_size(s->dev->bdev) ||
        data_area_size > PAGE_SIZE) {
        ti->error = "Invalid data device block size";
        ret = -EINVAL;
        goto bad;
    }
    s->data_block_bits = ffs(data_area_size) - 1;  // 4KB block

    if (!hash_block_size || (hash_block_size & (hash_block_size - 1)) ||
        hash_block_size < bdev_logical_block_size(s->dev->bdev) ||
        hash_block_size > PAGE_SIZE) {
        ti->error = "Invalid hash device block size";
        ret = -EINVAL;
        goto bad;
    }
    s->hash_block_bits = ffs(hash_block_size) - 1;  // 512B block
    s->hash_node_bits = ffs(AUTHSIZE) - 1;
    s->hash_per_block_bits = ffs(hash_block_size >> s->hash_node_bits) - 1;

    s->leaves_per_node_bits = ffs(leave_per_node) - 1;  // 256 leaves per node

    s->data_blocks = ti->len >> (s->data_block_bits - SECTOR_SHIFT);
    if (s->data_blocks < 1024) {
        ti->error = "Device too small for data blocks";
        goto bad;
    }
    /* 1/64 for super block and hash area */
    s->data_blocks =
        s->data_blocks - (s->data_blocks >> DEFAULT_DM_METADATA_RATIO_SHIFT);
    s->hash_leaf_nodes = s->data_blocks;
    s->hash_mediate_nodes =
        DIV_ROUND_UP_BITS(s->hash_leaf_nodes, s->leaves_per_node_bits);
    s->hash_blocks = s->hash_leaf_nodes >> s->hash_per_block_bits;

    s->data_area_size = s->data_blocks << (s->data_block_bits - SECTOR_SHIFT);
    s->data_start = ti->len - s->data_area_size;  // data area start sector
    s->hash_start = s->sb_start + 1;              // hash area start sector
    s->hash_area_size = s->data_start - s->hash_start;

    s->root_hash_key = trusted_storage_uuid_gen();

    /* Dump device layout params to super block */
    security_super_block_dump(s);

    /* Write super block to device */
    sb_io = security_super_block_io_alloc(s);
    if (!sb_io) {
        ti->error = "Cannot allocate super block write io";
        goto bad;
    }
    ksecurityd_super_block_io_write(sb_io);

    wait_for_completion(&sb_io->restart);
    DMINFO("Super block saved to device sector %lu", s->sb_start);

out:
    /* Set target length to actual data blocks area size */
    ti->len = s->data_area_size;

    /* Rebuild hash tree and save leaf nodes to hash area if necessary */

    /* alloc buffer for root hash */
    root_hash = kzalloc(digestsize, GFP_KERNEL);
    if (!root_hash) {
        ti->error = "Cannot allocate root hash";
        goto bad;
    }
    ret = security_metadata_rebuild(ti, root_hash);
    if (ret < 0) {
        ti->error = "Cannot format deivce";
        goto bad;
    }

    if (likely(saved_root_hash)) {
        /* check if root hashes match if not the first time loading */
        if (memcmp(root_hash, saved_root_hash, hash_node_size(s))) {
            ti->error = "Root hash not match, device data may corrupted";
            ret = -EINVAL;
            goto bad;
        }
    } else {
        /*
         * Now all root hash and mediate nodes ready, and leaf nodes saved to
         * hash area, now save root hash to trusted storage (emulator)
         */
        DMINFO("Save root hash to trusted storage with key [%lu]",
               s->root_hash_key);
        ret = trusted_storage_write(s->root_hash_key, root_hash, digestsize);
        if (ret) {
            ti->error = "Cannot write root hash to trusted storage";
            goto bad;
        }
    }

    ret = 0;

bad:
    DMINFO("===== Disk Layout Params =====");
    DMINFO("Root Hash Key: 0x%.8lx", s->root_hash_key);
    DMINFO("Target Length: %lu", ti->len);
    DMINFO("Target Begin: %lu", ti->begin);
    DMINFO("Super Block Start: %lu", s->sb_start);
    DMINFO("Hash Start: %lu", s->hash_start);
    DMINFO("Hash Area Size: %lu", s->data_start - s->hash_start);
    DMINFO("Data Start: %lu", s->data_start);
    DMINFO("Data Area Size: %lu",
           s->data_blocks << (s->data_block_bits - SECTOR_SHIFT));
    DMINFO("Hash Blocks: %u", s->hash_blocks);
    DMINFO("Data Blocks: %u", s->data_blocks);
    DMINFO("Data Block Size: %u", 1 << s->data_block_bits);
    DMINFO("Hash Block Size: %u", 1 << s->hash_block_bits);
    DMINFO("Hash Per Block: %u", 1 << s->hash_per_block_bits);
    DMINFO("Leaves Per Node: %u", 1 << s->leaves_per_node_bits);
    DMINFO("Hash Tree Leaf Nodes: %u", s->hash_leaf_nodes);
    DMINFO("Hash Tree Mediate Nodes: %u", s->hash_mediate_nodes);
    DMINFO("============ End =============");

sb_corrupted:
    return ret;
}

static void security_dtr(struct dm_target* ti) {
    struct dm_security* s = ti->private;
    struct security_cpu* cpu_sc;
    int cpu;

    ti->private = NULL;

    if (!s)
        return;

    if (s->io_queue) {
        flush_workqueue(s->io_queue);
        destroy_workqueue(s->io_queue);
    }
    if (s->security_queue) {
        flush_workqueue(s->security_queue);
        destroy_workqueue(s->security_queue);
    }
    if (s->hash_queue) {
        flush_workqueue(s->hash_queue);
        destroy_workqueue(s->hash_queue);
    }

    security_hash_task_stop(&s->hash_flusher);
    security_hash_task_stop(&s->hash_prefetcher);

    if (s->cpu)
        for_each_possible_cpu(cpu) {
            cpu_sc = per_cpu_ptr(s->cpu, cpu);
            if (cpu_sc->req)
                mempool_free(cpu_sc->req, s->req_pool);
        }

    security_free_tfm(s);

    if (s->sb)
        kfree(s->sb);

    if (s->bs)
        bioset_free(s->bs);

    if (s->page_pool)
        mempool_destroy(s->page_pool);
    if (s->req_pool)
        mempool_destroy(s->req_pool);
    if (s->io_pool)
        mempool_destroy(s->io_pool);
    if (s->hash_io_pool)
        mempool_destroy(s->hash_io_pool);
    if (s->super_block_io_pool)
        mempool_destroy(s->super_block_io_pool);

    if (s->dev)
        dm_put_device(ti, s->dev);

    if (s->cpu)
        free_percpu(s->cpu);

    security_mediate_nodes_free(s);
    vfree(s->mediate_nodes);

    kzfree(s->cipher_string);
    kfree(s->hash_desc);
    kfree(s->hmac_desc);
    kfree(s->hmac_digest);

    if (s->hash_tfm)
        crypto_free_shash(s->hash_tfm);
    if (s->hmac_tfm)
        crypto_free_shash(s->hmac_tfm);

    /* Must zero key material before freeing */
    kzfree(s);
}

/*
 * Construct an encryption mapping:
 * <key> <dev_path> <start>
 */
static int security_ctr(struct dm_target* ti, unsigned int argc, char** argv) {
    struct dm_security* s;
    unsigned int key_size;
    int ret;

    if (argc < 3) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

    key_size = strlen(argv[0]) >> 1;

    s = kzalloc(sizeof(*s) + key_size * sizeof(u8), GFP_KERNEL);
    if (!s) {
        ti->error = "Cannot allocate encryption context";
        return -ENOMEM;
    }
    s->key_size = key_size;

    ti->private = s;
    s->ti = ti;

    ret = security_ctr_cipher(ti, argv[0]);
    if (ret < 0)
        goto bad;

    ret = -ENOMEM;

    s->io_pool = mempool_create_slab_pool(MIN_IOS, _security_io_pool);
    if (!s->io_pool) {
        ti->error = "Cannot allocate security io mempool";
        goto bad;
    }

    s->super_block_io_pool =
        mempool_create_slab_pool(MIN_IOS, _super_block_io_pool);
    if (!s->super_block_io_pool) {
        ti->error = "Cannot allocate super block io mempool";
        goto bad;
    }

    s->hash_io_pool = mempool_create_slab_pool(MIN_IOS, _hash_io_pool);
    if (!s->hash_io_pool) {
        ti->error = "Cannot allocate hash io mempool";
        goto bad;
    }

    s->leaf_node_pool = mempool_create_slab_pool(MIN_LEAVES, _leaf_node_pool);
    if (!s->leaf_node_pool) {
        ti->error = "Cannot allocate leaf node mempool";
        goto bad;
    }

    // FIXME : alignment is removed for quick development
    s->dmreq_start = sizeof(struct aead_request);
    s->dmreq_start += crypto_aead_reqsize(s->tfm);  // tfm ctx

    s->req_pool = mempool_create_kmalloc_pool(
        MIN_IOS,
        s->dmreq_start + sizeof(struct dm_security_request) + s->iv_size);
    if (!s->req_pool) {
        ti->error = "Cannot allocate security request mempool";
        goto bad;
    }

    s->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
    if (!s->page_pool) {
        ti->error = "Cannot allocate page mempool";
        goto bad;
    }

    s->bs = bioset_create(MIN_IOS, 0);
    if (!s->bs) {
        ti->error = "Cannot allocate security bioset";
        goto bad;
    }

    mutex_init(&s->bio_alloc_lock);

    s->io_queue =
        alloc_workqueue("ksecurityd_io", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 1);
    if (!s->io_queue) {
        ti->error = "Couldn't create ksecurityd io queue";
        goto bad;
    }

    s->hash_queue = alloc_workqueue("ksecurityd_hash",
                                    WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 1);
    if (!s->hash_queue) {
        ti->error = "Couldn't create ksecurityd hash queue";
        goto bad;
    }

    s->security_queue = alloc_workqueue(
        "ksecurityd", WQ_NON_REENTRANT | WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!s->security_queue) {
        ti->error = "Couldn't create ksecurityd queue";
        goto bad;
    }

    ti->num_flush_bios = 1;
    ti->discard_zeroes_data_unsupported = true;

    ret = security_ctr_layout(ti, argv[1], argv[2]);
    if (ret < 0)
        goto bad;

    init_hash_nodes_cache(&s->hash_nodes_cache);
    init_data_blocks_cache(&s->data_blocks_cache, GFP_ATOMIC | GFP_KERNEL);

    ret = security_hash_task_start(&s->hash_flusher, "hash_flusher",
                                   security_hash_flush, NULL);
    if (ret < 0) {
        ti->error = "Cannot start hash flush task";
        goto bad;
    }

    ret = security_hash_task_start(&s->hash_prefetcher, "hash_prefetcher",
                                   security_hash_prefetch,
                                   security_hash_pre_prefetch);
    if (ret < 0) {
        ti->error = "Cannot start hash prefetch task";
        goto bad;
    }

    return 0;

bad:
    security_dtr(ti);
    return ret;
}

static int security_map(struct dm_target* ti, struct bio* bio) {
    struct dm_security_io* io;
    struct dm_security* s = ti->private;

    pr_info("security_map: 1\n");
    /*
     * If bio is REQ_FLUSH or REQ_DISCARD, just bypass crypt queues.
     * - for REQ_FLUSH device-mapper core ensures that no IO is in-flight
     * - for REQ_DISCARD caller must use flush if IO ordering matters
     */
    if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD))) {
        pr_info("security_map: 2\n");
        bio->bi_bdev = s->dev->bdev;
        if (bio_sectors(bio))
            bio->bi_sector = security_map_data_sector(s, bio->bi_sector);
        return DM_MAPIO_REMAPPED;
    }

    pr_info("security_map: 3, bio->bi_sector = %lu, dm_target_offset = %u\n",
            bio->bi_sector, dm_target_offset(ti, bio->bi_sector));
    io = security_io_alloc(s, bio, dm_target_offset(ti, bio->bi_sector));

    pr_info("security_map: 4, io->sector = %lu\n", io->sector);
    if (bio_data_dir(io->bio) == READ) {
        pr_info("security_map: 5\n");
        if (ksecurityd_io_read(io, GFP_NOWAIT)) {
            pr_info("security_map: 6\n");
            ksecurityd_queue_io(io);
        }
    } else {
        pr_info("security_map: 7\n");
        ksecurityd_queue_security(io);
    }

    pr_info("security_map: 8\n");
    return DM_MAPIO_SUBMITTED;
}

static void security_status(struct dm_target* ti,
                            status_type_t type,
                            unsigned status_flags,
                            char* result,
                            unsigned maxlen) {
    struct dm_security* s = ti->private;
    unsigned i, sz = 0;

    switch (type) {
        case STATUSTYPE_INFO:
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
            DMEMIT("%s ", s->cipher_string);

            if (s->key_size > 0)
                for (i = 0; i < s->key_size; i++)
                    DMEMIT("%02x", s->key[i]);
            else
                DMEMIT("-");

            DMEMIT(" %s %llu", s->dev->name, (unsigned long long)s->start);

            if (ti->num_discard_bios)
                DMEMIT(" 1 allow_discards");

            break;
    }
}

static void security_postsuspend(struct dm_target* ti) {
    struct dm_security* s = ti->private;

    set_bit(DM_SECURITY_SUSPENDED, &s->flags);
}

static int security_preresume(struct dm_target* ti) {
    struct dm_security* s = ti->private;

    if (!test_bit(DM_SECURITY_KEY_VALID, &s->flags)) {
        DMERR("aborting resume - security key is not set.");
        return -EAGAIN;
    }

    return 0;
}

static void security_resume(struct dm_target* ti) {
    struct dm_security* s = ti->private;

    clear_bit(DM_SECURITY_SUSPENDED, &s->flags);
}

/* Message interface
 *      key set <key>
 *      key wipe
 */
static int security_message(struct dm_target* ti, unsigned argc, char** argv) {
    struct dm_security* s = ti->private;
    int ret = -EINVAL;

    if (argc < 2)
        goto error;

    if (!strcasecmp(argv[0], "key")) {
        if (!test_bit(DM_SECURITY_SUSPENDED, &s->flags)) {
            DMWARN("not suspended during key manipulation.");
            return -EINVAL;
        }
        if (argc == 3 && !strcasecmp(argv[1], "set")) {
            ret = security_set_key(s, argv[2]);
            if (ret)
                return ret;
            return ret;
        }
        if (argc == 2 && !strcasecmp(argv[1], "wipe")) {
            return security_wipe_key(s);
        }
    }

error:
    DMWARN("unrecognised message received.");
    return -EINVAL;
}

static int security_merge(struct dm_target* ti,
                          struct bvec_merge_data* bvm,
                          struct bio_vec* biovec,
                          int max_size) {
    struct dm_security* s = ti->private;
    struct request_queue* q = bdev_get_queue(s->dev->bdev);

    if (!q->merge_bvec_fn)
        return max_size;

    bvm->bi_bdev = s->dev->bdev;
    bvm->bi_sector = security_map_data_sector(s, bvm->bi_sector);

    return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int security_iterate_devices(struct dm_target* ti,
                                    iterate_devices_callout_fn fn,
                                    void* data) {
    struct dm_security* s = ti->private;

    return fn(ti, s->dev, s->data_start, ti->len, data);
}

/* Set smallest block I/O size to 4KB */
static void security_io_hints(struct dm_target* ti,
                              struct queue_limits* limits) {
    struct dm_security* s = ti->private;

    if (limits->logical_block_size < 1 << s->data_block_bits)
        limits->logical_block_size = 1 << s->data_block_bits;

    if (limits->physical_block_size < 1 << s->data_block_bits)
        limits->physical_block_size = 1 << s->data_block_bits;

    blk_limits_io_min(limits, limits->logical_block_size);
}

static struct target_type security_target = {
    .name = "security",
    .version = {0, 0, 1},
    .module = THIS_MODULE,
    .ctr = security_ctr,
    .dtr = security_dtr,
    .map = security_map,
    .status = security_status,
    .postsuspend = security_postsuspend,
    .preresume = security_preresume,
    .resume = security_resume,
    .message = security_message,
    .merge = security_merge,
    .iterate_devices = security_iterate_devices,
    .io_hints = security_io_hints,
};

static int __init dm_security_init(void) {
    int r;

    _security_io_pool = KMEM_CACHE(dm_security_io, 0);
    if (!_security_io_pool)
        return -ENOMEM;

    _super_block_io_pool = KMEM_CACHE(security_super_block_io, 0);
    if (!_super_block_io_pool)
        return -ENOMEM;

    _hash_io_pool = KMEM_CACHE(security_hash_io, 0);
    if (!_hash_io_pool)
        return -ENOMEM;

    _leaf_node_pool = KMEM_CACHE(security_leaf_node, 0);
    if (!_leaf_node_pool)
        return -ENOMEM;

    r = dm_register_target(&security_target);
    if (r < 0) {
        DMERR("register failed %d", r);
        kmem_cache_destroy(_security_io_pool);
        kmem_cache_destroy(_super_block_io_pool);
        kmem_cache_destroy(_hash_io_pool);
        kmem_cache_destroy(_leaf_node_pool);
    }

    return r;
}

static void __exit dm_security_exit(void) {
    dm_unregister_target(&security_target);
    kmem_cache_destroy(_super_block_io_pool);
    kmem_cache_destroy(_hash_io_pool);
    kmem_cache_destroy(_leaf_node_pool);
}

module_init(dm_security_init);
module_exit(dm_security_exit);

MODULE_AUTHOR("Christophe Saout <christophe@saout.de>");
MODULE_AUTHOR("Peihong Chen <mf21320017@smail.nju.edu.cn>");
MODULE_DESCRIPTION(
    DM_NAME " target for transparent disk confidentiality and integrity");
MODULE_LICENSE("GPL");
