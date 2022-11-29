#include "dm-security.h"

static void security_super_block_endio(struct bio* bio, int error) {
    struct security_super_block_io* io = bio->bi_private;
    struct dm_security* s = io->s;
    struct security_super_block* sb = s->sb;
    int err;
    unsigned rw = bio_data_dir(bio);

    if (unlikely(!bio_flagged(bio, BIO_UPTODATE) && !error))
        error = -EIO;

    if (rw == WRITE) {
        // do nothing now
    }

    bio_put(bio);

    if (rw == READ && !error) {
        err = crypto_shash_digest(
            s->hmac_desc, (const u8*)&sb->journal_area_size,
            sizeof(sb->journal_area_size) + sizeof(sb->hash_area_size) +
                sizeof(sb->data_block_size),
            s->hmac_digest);
        if (err)
            DMWARN("Failed to calculate super block mac");
    }

    if (unlikely(error))
        io->error = error;
    complete(&io->restart);

    if (!atomic_dec_and_test(&io->io_pending))
        return;
    mempool_free(io, s->super_block_io_pool);
}

static void super_block_bio_init(struct security_super_block_io* io,
                                 struct bio* bio) {
    struct dm_security* s = io->s;

    bio->bi_private = io;
    bio->bi_end_io = security_super_block_endio;
    bio->bi_bdev = s->dev->bdev;
    bio->bi_sector = s->sb_start;
}

static struct security_super_block_io* security_super_block_io_alloc(
    struct dm_security* s) {
    struct security_super_block_io* io;
    struct bio* bio;

    bio = bio_alloc_bioset(GFP_NOIO, 1, s->bs);
    if (!bio)
        return NULL;

    io = mempool_alloc(s->super_block_io_pool, GFP_NOIO);
    io->s = s;
    io->base_bio = bio;
    io->error = 0;
    io->base_io = NULL;

    super_block_bio_init(io, bio);

    atomic_set(&io->io_pending, 0);

    return io;
}

static void security_super_block_io_free(struct security_super_block_io* io) {
    if (!io)
        return;
    if (io->base_bio)
        bio_put(io->base_bio);
    mempool_free(io, io->s->super_block_io_pool);
}

static int ksecurityd_super_block_io_read(struct security_super_block_io* io) {
    struct dm_security* s = io->s;
    struct bio* bio = io->base_bio;
    int ret = 0;

    if (!virt_addr_valid(s->sb)) {
        ret = -EINVAL;
        goto bad;
    }
    if (!bio_add_page(bio, virt_to_page(s->sb), (1 << SECTOR_SHIFT),
                      virt_to_phys(s->sb) & (PAGE_SIZE - 1))) {
        ret = -EINVAL;
        goto bad;
    }

    atomic_inc(&io->io_pending);

    bio->bi_rw |= READ;
    init_completion(&io->restart);
    generic_make_request(bio);
    ret = 0;
bad:
    return ret;
}

static void ksecurityd_super_block_io_write(
    struct security_super_block_io* io) {
    struct dm_security* s = io->s;
    struct security_super_block* sb = s->sb;
    struct bio* bio = io->base_bio;
    int ret;

    if (!virt_addr_valid(sb)) {
        ret = -EINVAL;
        goto bad;
    }
    if (!bio_add_page(bio, virt_to_page(sb), (1 << SECTOR_SHIFT),
                      virt_to_phys(sb) & (PAGE_SIZE - 1))) {
        ret = -EINVAL;
        goto bad;
    }

    /* Calculate super block mac :
     * | JA Size | HA Size | DB Size |
     * |   8B    |   8B    |   8B    |
     */
    ret = crypto_shash_digest(s->hmac_desc, (const u8*)&sb->journal_area_size,
                              sizeof(sb->journal_area_size) +
                                  sizeof(sb->hash_area_size) +
                                  sizeof(sb->data_block_size),
                              sb->sb_mac);
    if (ret) {
        DMERR("Failed to calculate super block mac");
        goto bad;
    }

    atomic_inc(&io->io_pending);

    bio->bi_rw |= WRITE;
    init_completion(&io->restart);
    generic_make_request(bio);

    ret = 0;
bad:
    return ret;
}

static void ksecurityd_super_block(struct work_struct* work) {
    struct security_super_block_io* io =
        container_of(work, struct security_super_block_io, work);

    if (bio_data_dir(io->base_bio) == READ) {
        ksecurityd_super_block_io_read(io);
    } else {
        ksecurityd_super_block_io_write(io);
    }
}
