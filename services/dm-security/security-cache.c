#include "dm-security.h"

/**
 * @return 0 on success, -errno on failure
 */
static int security_cache_lookup(struct data_blocks_cache* cache,
                                 sector_t start,
                                 sector_t sectors,
                                 struct bio* bio_out) {
    struct dm_security* s =
        container_of(cache, struct dm_security, data_blocks_cache);
    sector_t cur = start, step = 1 << (s->data_block_bits - SECTOR_SHIFT);
    size_t bs = 1 << s->data_block_bits;
    struct radix_tree_iter iter;
    struct security_data_block* block;
    struct bio_vec* bvec;
    void** slot;
    int i, j, idx, offset, ret = 0;

    mutex_lock(&cache->lock);

    idx = offset = 0;
    radix_tree_for_each_slot(slot, &cache->rt_root, &iter, start) {
        block = *slot;
        if (block->sector >= start + sectors)
            break;
        else if (block->sector < start)
            continue;

        if (block->sector != cur) {
            ret = -EIO;
            break;
        }

        /* copy cached data to bio */
        j = bs;
        while (j) {
            bvec = bio_iovec_idx(bio_out, idx);
            memcpy(page_address(bvec->bv_page) + bvec->bv_offset + offset,
                   block->buf, min(j, bvec->bv_len));
            j -= bvec->bv_len;
            offset += j;
            if (offset >= bvec->bv_len) {
                offset = 0;
                idx++;
            }
        }

        cur += step;
    }

    mutex_unlock(&cache->lock);

    return ret;
}
