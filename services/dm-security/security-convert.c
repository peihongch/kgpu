#include "dm-security.h"
#include "security-debug.h"

static struct security_cpu* this_security_cpu(struct dm_security* s) {
    return this_cpu_ptr(s->cpu);
}

void security_convert_init(struct dm_security* s,
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

struct dm_security_request* dmreq_of_req(struct dm_security* s, void* req) {
    return (struct dm_security_request*)((char*)req + s->dmreq_start);
}

struct aead_request* req_of_dmreq(struct dm_security* s,
                                  struct dm_security_request* dmreq) {
    return (struct aead_request*)((char*)dmreq - s->dmreq_start);
}

u8* iv_of_dmreq(struct dm_security* s, struct dm_security_request* dmreq) {
    return (u8*)(dmreq + 1);
}

void security_dec_pending(struct dm_security_io* io);

/*
 * For KGPU: convert all blocks together for speedup
 */
int security_convert_blocks(struct dm_security* s,
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

void ksecurityd_async_done(struct crypto_async_request* async_req, int error);

void security_alloc_req(struct dm_security* s, struct convert_context* ctx) {
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
int security_convert(struct dm_security* s, struct convert_context* ctx) {
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
void security_endio(struct bio* clone, int error) {
    struct dm_security_io* io = clone->bi_private;
    struct dm_security* s = io->s;
    struct security_hash_io* hash_io = io->hash_io;
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
        if (hash_io)
            complete(&hash_io->restart);

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

void clone_init(struct dm_security_io* io, struct bio* clone) {
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
struct bio* security_alloc_buffer(struct dm_security_io* io,
                                  unsigned size,
                                  unsigned* out_of_pages) {
    struct dm_security* s = io->s;
    struct bio* clone;
    unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    gfp_t gfp_mask = GFP_NOIO | __GFP_HIGHMEM;
    unsigned i, len;
    struct page* page;

    pr_info("security_alloc_buffer: 1\n");

    clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
    if (!clone)
        return NULL;

    pr_info("security_alloc_buffer: 2\n");
    clone_init(io, clone);
    *out_of_pages = 0;

    for (i = 0; i < nr_iovecs; i++) {
        pr_info("security_alloc_buffer: 3\n");
        page = mempool_alloc(s->page_pool, gfp_mask);
        if (!page) {
            pr_info("security_alloc_buffer: 4\n");
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

        pr_info("security_alloc_buffer: 5\n");
        if (!bio_add_page(clone, page, len, 0)) {
            mempool_free(page, s->page_pool);
            pr_info("security_alloc_buffer:6\n");
            break;
        }

        size -= len;
    }

    pr_info("security_alloc_buffer: 7\n");
    if (!clone->bi_size) {
        pr_info("security_alloc_buffer: 8\n");
        bio_put(clone);
        return NULL;
    }

    pr_info("security_alloc_buffer: 9\n");
    return clone;
}

struct dm_security_io* security_io_alloc(struct dm_security* s,
                                         struct bio* bio,
                                         sector_t sector) {
    struct dm_security_io* io;

    io = mempool_alloc(s->io_pool, GFP_NOIO);
    io->s = s;
    io->bio = bio;
    io->sector = sector;
    io->error = 0;
    io->hash_io = NULL;
    io->base_io = NULL;
    atomic_set(&io->io_pending, 0);

    return io;
}

int ksecurityd_io_read(struct dm_security_io* io, gfp_t gfp) {
    struct dm_security* s = io->s;
    struct security_hash_io* hash_io;
    struct bio* bio = io->bio;
    struct bio* clone;
    size_t offset = bio->bi_sector >> (s->data_block_bits - SECTOR_SHIFT);
    size_t count = bio->bi_size >> s->data_block_bits;

    pr_info("ksecurityd_io_read: io->sector = %lu\n", io->sector);

    /**
     * Check if data present in cache.
     * Always use io->sector here, not bio->bi_sector
     */
    if (!security_cache_lookup(s, io)) {
        pr_info("ksecurityd_io_read: data present in cache, io->sector = %lu\n",
                io->sector);
        bio_endio(bio, 0);
        return 0;
    }

    hash_io = security_hash_io_alloc(s, offset, count);

    security_io_bind(io, hash_io);

    pr_info("ksecurityd_io_read: prefetch hash_leaves, hash_io->offset = %lu\n",
            hash_io->offset);
    security_prefetch_hash_leaves(hash_io);

    /*
     * The block layer might modify the bvec array, so always
     * copy the required bvecs because we need the original
     * one in order to decrypt the whole bio data *afterwards*.
     */
    clone = bio_clone_bioset(bio, gfp, s->bs);
    if (!clone)
        return 1;

    security_inc_pending(io);

    clone_init(io, clone);
    clone->bi_sector = security_map_data_sector(s, io->sector);

    pr_info("ksecurityd_io_read: generic_make_request, bio->bi_sector = %lu\n",
            clone->bi_sector);
    generic_make_request(clone);
    return 0;
}

void ksecurityd_io_write(struct dm_security_io* io) {
    struct bio* clone = io->ctx.bio_out;
    generic_make_request(clone);
}

void ksecurityd_io(struct work_struct* work) {
    struct dm_security_io* io = container_of(work, struct dm_security_io, work);

    if (bio_data_dir(io->bio) == READ) {
        security_inc_pending(io);
        if (ksecurityd_io_read(io, GFP_NOIO))
            io->error = -ENOMEM;
        security_dec_pending(io);
    } else
        ksecurityd_io_write(io);
}

void ksecurityd_queue_io(struct dm_security_io* io) {
    struct dm_security* s = io->s;

    INIT_WORK(&io->work, ksecurityd_io);
    queue_work(s->io_queue, &io->work);
}

void ksecurityd_security_write_io_submit(struct dm_security_io* io, int async) {
    struct bio* clone = io->ctx.bio_out;
    struct dm_security* s = io->s;

    pr_info("ksecurityd_security_write_io_submit: start\n");

    if (unlikely(io->error < 0)) {
        pr_info("ksecurityd_security_write_io_submit: error = %d\n", io->error);
        security_free_buffer_pages(s, clone);
        bio_put(clone);
        security_dec_pending(io);
        return;
    }

    /* security_convert should have filled the clone bio */
    BUG_ON(io->ctx.idx_out < clone->bi_vcnt);

    clone->bi_sector = security_map_data_sector(s, io->sector);
    pr_info(
        "ksecurityd_security_write_io_submit: io->sector = %lu, "
        "clone->bi_sector = %lu\n",
        io->sector, clone->bi_sector);

    if (async) {
        pr_info(
            "ksecurityd_security_write_io_submit: async -> "
            "ksecurityd_queue_io\n");
        ksecurityd_queue_io(io);
    } else {
        pr_info(
            "ksecurityd_security_write_io_submit: sync -> "
            "generic_make_request\n");
        generic_make_request(clone);
    }

    pr_info("ksecurityd_security_write_io_submit: end\n");
}

void ksecurityd_security_write_convert(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct bio *clone, *hash_bio = io->hash_bio;
    struct dm_security_io* new_io;
    struct security_hash_io* hash_io = io->hash_io;
    int security_finished;
    unsigned out_of_pages = 0;
    unsigned remaining = io->bio->bi_size;
    sector_t sector = io->sector;
    int r;

    pr_info("ksecurityd_security_write_convert: start\n");

    /*
     * Prevent io from disappearing until this function completes.
     */
    security_inc_pending(io);
    security_convert_init(s, &io->ctx, NULL, io->bio, hash_bio, sector);
    pr_info("ksecurityd_security_write_convert: 1\n");
    print_bio(io->bio);
    msleep(1000);

    /*
     * The allocated buffers can be smaller than the whole bio,
     * so repeat the whole process until all the data can be handled.
     */
    while (remaining) {
        pr_info("ksecurityd_security_write_convert: 2\n");
        /* clone bio and alloc new pages so as not to modify orignal data */
        clone = security_alloc_buffer(io, remaining, &out_of_pages);
        print_bio(clone);
        msleep(1000);
        if (unlikely(!clone)) {
            pr_info("ksecurityd_security_write_convert: 3\n");
            io->error = -ENOMEM;
            break;
        }
        pr_info("ksecurityd_security_write_convert: 4\n");

        io->ctx.bio_out = clone;
        io->ctx.idx_out = 0;

        remaining -= clone->bi_size;
        sector += bio_sectors(clone);

        security_inc_pending(io);

        pr_info("ksecurityd_security_write_convert: 5\n");
        r = 0;
        msleep(1000);
        print_convert_context(&io->ctx);
        msleep(1000);

        // r = security_convert(s, &io->ctx);
        // if (r < 0)
        //     io->error = -EIO;

        pr_info("ksecurityd_security_write_convert: 6\n");
        security_finished = atomic_dec_and_test(&io->ctx.s_pending);

        /* sync */
        /* Encryption was already finished, submit io now */
        pr_info("ksecurityd_security_write_convert: 7\n");
        if (security_finished) {
            pr_info("ksecurityd_security_write_convert: security finished\n");
            ksecurityd_queue_hash(hash_io);

            /*
             * If there was an error, do not try next fragments.
             * For async, error is processed in async handler.
             */
            pr_info("ksecurityd_security_write_convert: 8\n");
            if (unlikely(r < 0))
                break;

            io->sector = sector;
        }

        /*
         * Out of memory -> run queues
         * But don't wait if split was due to the io size restriction
         */
        pr_info("ksecurityd_security_write_convert: 9\n");
        if (unlikely(out_of_pages))
            congestion_wait(BLK_RW_ASYNC, HZ / 100);

        /*
         * With async crypto it is unsafe to share the crypto context
         * between fragments, so switch to a new dm_security_io structure.
         */
        pr_info("ksecurityd_security_write_convert: 10\n");
        if (unlikely(!security_finished && remaining)) {
            pr_info("ksecurityd_security_write_convert: 11\n");
            new_io = security_io_alloc(io->s, io->bio, sector);
            security_inc_pending(new_io);
            security_convert_init(s, &new_io->ctx, NULL, io->bio, hash_bio,
                                  sector);
            new_io->ctx.idx_in = io->ctx.idx_in;
            new_io->ctx.idx_tag = io->ctx.idx_tag;
            new_io->ctx.offset_in = io->ctx.offset_in;
            new_io->ctx.offset_tag = io->ctx.offset_tag;

            /*
             * Fragments after the first use the base_io
             * pending count.
             */
            pr_info("ksecurityd_security_write_convert: 12\n");
            if (!io->base_io)
                new_io->base_io = io;
            else {
                pr_info("ksecurityd_security_write_convert: 14\n");
                new_io->base_io = io->base_io;
                security_inc_pending(io->base_io);
                security_dec_pending(io);
            }

            pr_info("ksecurityd_security_write_convert: 15\n");
            io = new_io;
        }

        pr_info("ksecurityd_security_write_convert: 16\n");
    }

    pr_info("ksecurityd_security_write_convert: security_dec_pending\n");

    security_dec_pending(io);

    pr_info("ksecurityd_security_write_convert: end\n");
}

void ksecurityd_security_read_done(struct dm_security_io* io) {
    security_dec_pending(io);
}

void ksecurityd_security_read_convert(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct security_hash_io* hash_io = io->hash_io;
    struct bio_vec* bv_tag = NULL;
    struct security_leaf_node* ln = NULL;
    unsigned idx_tag, offset_tag;
    unsigned tag_size = hash_node_size(s);
    sector_t bs = 1 << (s->data_block_bits - SECTOR_SHIFT);
    u8* tag_addr = NULL;
    int r = 0, i;

    pr_info("ksecurityd_security_read_convert: 1\n");

    security_inc_pending(io);

    security_convert_init(s, &io->ctx, io->bio, io->bio, io->hash_bio,
                          io->sector);

    pr_info("ksecurityd_security_read_convert: 2\n");
    r = security_convert(s, &io->ctx);
    if (r < 0)
        io->error = -EIO;

    pr_info("ksecurityd_security_read_convert: 3\n");
    /* wait for hash prefetch io to complete */
    wait_for_completion(&hash_io->restart);

    idx_tag = offset_tag = 0;
    pr_info("ksecurityd_security_read_convert: 4\n");
    for (i = 0; i < hash_io->count; i++) {
        bv_tag = bio_iovec_idx(io->hash_bio, idx_tag);

        /* check if corresponding data block in cache */
        pr_info("ksecurityd_security_read_convert: 5, i = %d\n", i);
        if (!security_cache_lookup_one(s, io->sector + i * bs)) {
            /* if not in cache, check if tags match */
            pr_info("ksecurityd_security_read_convert: 6, block->start = %lu\n",
                    io->sector + i * bs);
            ln = security_get_leaf_node(s, i + hash_io->offset);
            tag_addr =
                page_address(bv_tag->bv_page) + bv_tag->bv_offset + offset_tag;

            pr_info("ksecurityd_security_read_convert: 6.2\n");
            mutex_lock(&ln->lock);
            BUG_ON(!ln || !ln->verified);
            if (ln->corrupted || memcmp(tag_addr, ln->digest, tag_size)) {
                u8* hash_addr = ln->digest;
                DMERR(
                    "tag mismatch at sector %lu, i = %d, expect {%.2x %.2x "
                    "%.2x "
                    "%.2x %.2x %.2x %.2x %.2x}, actual {%.2x %.2x %.2x %.2x "
                    "%.2x "
                    "%.2x %.2x %.2x}",
                    io->sector + (i << (s->data_block_bits - SECTOR_SHIFT)), i,
                    hash_addr[0], hash_addr[1], hash_addr[2], hash_addr[3],
                    hash_addr[4], hash_addr[5], hash_addr[6], hash_addr[7],
                    tag_addr[0], tag_addr[1], tag_addr[2], tag_addr[3],
                    tag_addr[4], tag_addr[5], tag_addr[6], tag_addr[7]);
                mutex_unlock(&ln->lock);
                io->error = -EBADMSG;
                goto out;
            }
            mutex_unlock(&ln->lock);
            pr_info("ksecurityd_security_read_convert: 6.3\n");

            /* enable leaf node to be reclaimed */
            security_put_leaf_node(ln);
            pr_info("ksecurityd_security_read_convert: 6.4\n");
        }
        pr_info("ksecurityd_security_read_convert: 7\n");

        offset_tag += tag_size;
        if (offset_tag >= bv_tag->bv_len) {
            offset_tag = 0;
            idx_tag++;
        }
    }

    /* put data into data blocks cache */
    pr_info("ksecurityd_security_read_convert: 8\n");
    security_cache_merge(s, io);

    pr_info("ksecurityd_security_read_convert: 9\n");

out:
    if (atomic_dec_and_test(&io->ctx.s_pending))
        ksecurityd_security_read_done(io);

    pr_info("ksecurityd_security_read_convert: 10\n");
    security_dec_pending(io);
}

void ksecurityd_async_done(struct crypto_async_request* async_req, int error) {
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

void ksecurityd_security(struct work_struct* work) {
    struct dm_security_io* io = container_of(work, struct dm_security_io, work);
    struct security_hash_io* hash_io = io->hash_io;
    struct dm_security* s = io->s;
    struct bio *bio = io->bio, *hash_bio = NULL;
    struct page* page = NULL;
    unsigned remainings = hash_io->count << s->hash_node_bits;
    unsigned nr_iovecs = DIV_ROUND_UP_BITS(remainings, PAGE_SHIFT);
    unsigned len = 0;

    pr_info("ksecurityd_security: start, nr_iovecs = %u\n", nr_iovecs);

    /* alloc hash bio to hold generated authentication tags */
    hash_bio = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
    /* NOTE : must set hash_bio->bi_bdev before bio_add_page */
    hash_bio->bi_bdev = s->dev->bdev;
    hash_bio->bi_rw |= bio_data_dir(bio);

    pr_info("ksecurityd_security: 1\n");

    while (nr_iovecs--) {
        page = mempool_alloc(s->page_pool, GFP_NOIO | __GFP_HIGHMEM);
        len = min(remainings, (unsigned)PAGE_SIZE);
        pr_info("ksecurityd_security: 2\n");
        if (!bio_add_page(hash_bio, page, len, 0)) {
            pr_info("ksecurityd_security: 3\n");
            mempool_free(page, s->page_pool);
            break;
        }
        pr_info("ksecurityd_security: 4\n");
        remainings -= len;
    }
    io->hash_bio = hash_bio;
    hash_io->base_io = io;

    pr_info("ksecurityd_security: 5\n");
    if (bio_data_dir(io->bio) == READ)
        ksecurityd_security_read_convert(io);
    else
        ksecurityd_security_write_convert(io);

    pr_info("ksecurityd_security: end\n");
}

void ksecurityd_queue_security(struct dm_security_io* io) {
    struct dm_security* s = io->s;

    INIT_WORK(&io->work, ksecurityd_security);
    queue_work(s->security_queue, &io->work);
}