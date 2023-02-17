#include "dm-security.h"

void security_io_bind(struct dm_security_io* io,
                      struct security_hash_io* hash_io) {
    if (io)
        io->hash_io = hash_io;
    if (hash_io)
        hash_io->base_io = io;
}

void security_free_buffer_pages(struct dm_security* s, struct bio* bio) {
    unsigned int i;
    struct bio_vec* bv;

    bio_for_each_segment_all(bv, bio, i) {
        BUG_ON(!bv->bv_page);
        mempool_free(bv->bv_page, s->page_pool);
        bv->bv_page = NULL;
    }
}

void security_inc_pending(struct dm_security_io* io) {
    atomic_inc(&io->io_pending);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 * If base_io is set, wait for the last fragment to complete.
 */
void security_dec_pending(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct bio* bio = io->bio;
    struct dm_security_io* base_io = io->base_io;
    int error = io->error;

    if (!atomic_dec_and_test(&io->io_pending))
        return;

    security_hash_io_free(io->hash_io);

    mempool_free(io, s->io_pool);

    if (bio_data_dir(bio) == READ) {
        if (likely(!base_io))
            bio_endio(bio, error);
        else {
            if (error && !base_io->error)
                base_io->error = error;
            security_dec_pending(base_io);
        }
    }
}

sector_t security_map_data_sector(struct dm_security* s, sector_t bi_sector) {
    /* Translate data io sector to target device sector. */
    return s->data_start + dm_target_offset(s->ti, bi_sector);
}

sector_t security_map_hash_sector(struct dm_security* s, sector_t bi_sector) {
    /* Translate hash io sector to target device sector. */
    return s->hash_start + bi_sector;
}