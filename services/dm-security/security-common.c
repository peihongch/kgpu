#include "dm-security.h"

void security_free_buffer_pages(struct dm_security* s, struct bio* bio) {
    unsigned int i;
    struct bio_vec* bv;

    bio_for_each_segment_all(bv, bio, i) {
        BUG_ON(!bv->bv_page);
        mempool_free(bv->bv_page, s->page_pool);
        bv->bv_page = NULL;
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