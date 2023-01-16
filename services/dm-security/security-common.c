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
