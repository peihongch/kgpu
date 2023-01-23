#include "dm-security.h"

void security_super_block_dump(struct dm_security* s) {
    struct security_super_block* sb = s->sb;

    if (unlikely(!sb))
        return;

    sb->magic = DM_SUPER_BLOCK_MAGIC;
    sb->data_start = s->data_start;
    sb->hash_start = s->hash_start;
    sb->data_area_size = s->data_area_size;
    sb->hash_area_size = s->hash_area_size;
    sb->data_blocks = s->data_blocks;
    sb->hash_blocks = s->hash_blocks;
    sb->data_block_bits = s->data_block_bits;
    sb->hash_block_bits = s->hash_block_bits;
    sb->hash_node_bits = s->hash_node_bits;
    sb->hash_per_block_bits = s->hash_per_block_bits;
    sb->leaves_per_node_bits = s->leaves_per_node_bits;
    sb->hash_leaf_nodes = s->hash_leaf_nodes;
    sb->hash_mediate_nodes = s->hash_mediate_nodes;
}

void security_super_block_load(struct dm_security* s) {
    struct security_super_block* sb = s->sb;

    if (unlikely(!sb))
        return;

    s->data_start = sb->data_start;
    s->hash_start = sb->hash_start;
    s->data_area_size = sb->data_area_size;
    s->hash_area_size = sb->hash_area_size;
    s->data_blocks = sb->data_blocks;
    s->hash_blocks = sb->hash_blocks;
    s->data_block_bits = sb->data_block_bits;
    s->hash_block_bits = sb->hash_block_bits;
    s->hash_node_bits = sb->hash_node_bits;
    s->hash_per_block_bits = sb->hash_per_block_bits;
    s->leaves_per_node_bits = sb->leaves_per_node_bits;
    s->hash_leaf_nodes = sb->hash_leaf_nodes;
    s->hash_mediate_nodes = sb->hash_mediate_nodes;
}

void security_super_block_endio(struct bio* bio, int error) {
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
        err = crypto_shash_digest(s->hmac_desc, (const u8*)sb,
                                  offsetof(struct security_super_block, sb_mac),
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

void super_block_bio_init(struct security_super_block_io* io, struct bio* bio) {
    struct dm_security* s = io->s;

    bio->bi_private = io;
    bio->bi_end_io = security_super_block_endio;
    bio->bi_bdev = s->dev->bdev;
    bio->bi_sector = s->sb_start;
}

struct security_super_block_io* security_super_block_io_alloc(
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

void security_super_block_io_free(struct security_super_block_io* io) {
    if (!io)
        return;
    if (io->base_bio)
        bio_put(io->base_bio);
    mempool_free(io, io->s->super_block_io_pool);
}

int ksecurityd_super_block_io_read(struct security_super_block_io* io) {
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

void ksecurityd_super_block_io_write(struct security_super_block_io* io) {
    struct dm_security* s = io->s;
    struct security_super_block* sb = s->sb;
    struct bio* bio = io->base_bio;
    int ret;

    if (!virt_addr_valid(sb)) {
        ret = -EINVAL;
        goto out;
    }
    if (!bio_add_page(bio, virt_to_page(sb), (1 << SECTOR_SHIFT),
                      virt_to_phys(sb) & (PAGE_SIZE - 1))) {
        ret = -EINVAL;
        goto out;
    }

    /* Calculate super block mac from */
    ret = crypto_shash_digest(s->hmac_desc, (const u8*)sb,
                              offsetof(struct security_super_block, sb_mac),
                              sb->sb_mac);
    if (ret) {
        DMERR("Failed to calculate super block mac");
        goto out;
    }

    atomic_inc(&io->io_pending);

    bio->bi_rw |= WRITE;
    init_completion(&io->restart);
    generic_make_request(bio);

out:
    return;
}

void ksecurityd_super_block(struct work_struct* work) {
    struct security_super_block_io* io =
        container_of(work, struct security_super_block_io, work);

    if (bio_data_dir(io->base_bio) == READ) {
        ksecurityd_super_block_io_read(io);
    } else {
        ksecurityd_super_block_io_write(io);
    }
}
