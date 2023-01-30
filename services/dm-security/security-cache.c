#include "dm-security.h"

/**
 * @return 0 on success, -errno on failure
 */
int security_cache_lookup(struct data_blocks_cache* cache, struct bio* bio) {
    struct dm_security* s =
        container_of(cache, struct dm_security, data_blocks_cache);
    sector_t start = bio->bi_sector, sectors = bio->bi_size >> SECTOR_SHIFT;
    sector_t cur = start, step = 1 << (s->data_block_bits - SECTOR_SHIFT);
    size_t bs = 1 << s->data_block_bits;
    struct radix_tree_iter iter;
    struct security_data_block* block;
    struct bio_vec* bvec;
    void** slot;
    unsigned i, idx, offset, len, ret = 0;

    mutex_lock(&cache->lock);

    if (!cache->size) {
        ret = -EIO;
        goto out;
    }

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

        /* update lru cache */
        list_move_tail(&block->lru_item, &cache->lru_list);

        /* copy cached data to bio */
        i = bs;
        while (i) {
            bvec = bio_iovec_idx(bio, idx);
            len = min(i, bvec->bv_len);
            memcpy(page_address(bvec->bv_page) + bvec->bv_offset + offset,
                   block->buf, len);
            i -= len;
            offset += len;
            if (offset >= bvec->bv_len) {
                offset = 0;
                idx++;
            }
        }

        cur += step;
    }

out:
    mutex_unlock(&cache->lock);

    return ret;
}
