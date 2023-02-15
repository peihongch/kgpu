#include "dm-security.h"

struct security_data_block* security_data_block_alloc(struct dm_security* s,
                                                      sector_t sector,
                                                      unsigned long long ts) {
    struct security_data_block* block = NULL;

    block = kmalloc(sizeof(struct security_data_block), GFP_NOIO);
    if (!block)
        goto out;

    /* make buf in single page */
    block->buf = kmalloc(1 << s->data_block_bits, GFP_NOIO);
    if (!block->buf)
        goto bad;

    block->timestamp = ts;
    block->start = sector;
    block->dirty = true;
    atomic_set(&block->ref_count, 1);
    mutex_init(&block->lock);

    return block;
bad:
    security_data_block_free(block);
out:
    return block;
}

void security_data_block_free(struct security_data_block* data_block) {
    if (!data_block)
        return;

    if (data_block->buf)
        kfree(data_block->buf);

    kfree(data_block);
}

void security_data_block_inc_ref(struct security_data_block* data_block) {
    atomic_inc(&data_block->ref_count);
}

void security_data_block_dec_ref(struct security_data_block* data_block) {
    if (atomic_dec_and_test(&data_block->ref_count))
        security_data_block_free(data_block);
}

/**
 * @return 0 on success, -errno on failure
 */
int security_cache_lookup(struct dm_security* s, struct dm_security_io* io) {
    struct data_blocks_cache* cache = &s->data_blocks_cache;
    struct radix_tree_iter iter;
    struct security_data_block* block;
    struct bio* bio = io->bio;
    struct bio_vec* bvec;
    void** slot;
    sector_t sectors = bio->bi_size >> SECTOR_SHIFT;
    sector_t start = bio->bi_sector;
    sector_t cur = start;
    sector_t step = 1 << (s->data_block_bits - SECTOR_SHIFT);
    size_t bs = 1 << s->data_block_bits;
    unsigned i, idx, offset, len, ret = 0;

    /* Firstly, check if all data blocks in cache */
    idx = offset = 0;
    rcu_read_lock();
    radix_tree_for_each_slot(slot, &cache->rt_root, &iter, start) {
        block = *slot;
        if ((block->start != cur) || (block->start >= start + sectors))
            break;
        cur += step;
    }
    rcu_read_unlock();

    if (cur != start + sectors) {
        ret = -EIO;
        goto out;
    }

    /* Copy cached data to bio if all data blocks exist */
    idx = offset = 0;
    mutex_lock(&cache->lock);
    radix_tree_for_each_slot(slot, &cache->rt_root, &iter, start) {
        block = *slot;
        if (block->start >= start + sectors)
            break;

        /* update lru cache */
        list_move_tail(&block->lru_item, &cache->lru_list);
        synchronize_rcu();

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
    }
    mutex_unlock(&cache->lock);

out:
    return ret;
}

/**
 * @return 0 on success, -errno on failure
 */
int security_cache_evict(struct dm_security* s, block_t blocks) {
    struct data_blocks_cache* cache = &s->data_blocks_cache;
    struct security_hash_task* flusher = &s->hash_flusher;
    struct security_data_block* block;
    int ret = 0;

    mutex_lock(&cache->lock);

    if (!cache->size)
        goto out;

    list_for_each_entry_rcu(block, &cache->lru_list, lru_item) {
        if (block->dirty)
            continue;

        radix_tree_delete(&cache->rt_root, block->start);
        list_del_rcu(&block->lru_item);
        synchronize_rcu();
        security_data_block_free(block);
        cache->size--;

        if (blocks-- == 0)
            break;
    }

    if (blocks)
        complete(&flusher->wait);
out:
    mutex_unlock(&cache->lock);
    return ret;
}

/**
 * @return 0 on success, -errno on failure
 */
int security_cache_insert(struct dm_security* s,
                          struct dm_security_io* io,
                          unsigned long long ts) {
    struct data_blocks_cache* cache = &s->data_blocks_cache;
    struct security_data_block *block = NULL, *tmp;
    struct bio* bio = io->bio;
    struct bio_vec* bvec;
    block_t i, blocks = bio->bi_size >> s->data_block_bits;
    sector_t cur = bio->bi_sector,
             step = 1 << (s->data_block_bits - SECTOR_SHIFT);
    size_t bs = 1 << s->data_block_bits, size;
    unsigned idx, offset, len, ret = 0;

    idx = offset = 0;
    cur = bio->bi_sector;
    for (i = 0; i < blocks; i++) {
        /* allocate new data block */
        block = security_data_block_alloc(s, cur, ts);
        if (!block) {
            ret = -ENOMEM;
            goto out;
        }

        /* copy bio data into new data block */
        size = bs;
        while (size) {
            bvec = bio_iovec_idx(bio, idx);
            len = min(size, (size_t)bvec->bv_len);
            memcpy(block->buf,
                   page_address(bvec->bv_page) + bvec->bv_offset + offset, len);
            size -= len;
            offset += len;
            if (offset >= bvec->bv_len) {
                offset = 0;
                idx++;
            }
        }

        mutex_lock(&cache->lock);

        /* check if data block already in cache */
        if (radix_tree_lookup(&cache->rt_root, cur)) {
            radix_tree_delete(&cache->rt_root, cur);
            list_for_each_entry_rcu(tmp, &cache->lru_list, lru_item) {
                if (tmp->start == cur) {
                    list_del_rcu(&tmp->lru_item);
                    break;
                }
            }
        } else {
            /* make sure cache can hold the new data block */
            while (cache->size >= cache->capacity) {
                mutex_unlock(&cache->lock);
                if (security_cache_evict(s, 1))
                    cond_resched();
                mutex_lock(&cache->lock);
            }
        }

        /* insert new data block into cache */
        radix_tree_insert(&cache->rt_root, cur, block);
        list_add_tail_rcu(&block->lru_item, &cache->lru_list);
        synchronize_rcu();

        cache->size++;

        mutex_unlock(&cache->lock);

        cur += step;
    }

out:
    return ret;
}

void security_queue_cache(struct dm_security_io* io) {
    struct dm_security* s = io->s;
    struct security_cache_task* sct = &s->cache_transferer;
    struct cache_transfer_item* item = NULL;
    ktime_t ktime = ktime_get();

    item = kzalloc(sizeof(*item), GFP_NOIO);
    if (!item)
        return;
    item->io = io;
    item->timestamp = ktime_to_ns(ktime);
    mutex_init(&item->lock);

    mutex_lock(&sct->queue_lock);
    list_add_tail_rcu(&item->list, &sct->queue);
    synchronize_rcu();
    mutex_unlock(&sct->queue_lock);

    complete(&sct->wait);
}

int security_cache_transfer(void* data) {
    struct security_cache_task* sht = data;
    struct dm_security* s =
        container_of(sht, struct dm_security, cache_transferer);
    struct cache_transfer_item* item = NULL;
    struct dm_security_io* io = NULL;
    int ret;

    DMINFO("Security cache transferer started (pid %d)", current->pid);

    while (1) {
        wait_for_completion_timeout(&sht->wait, CACHE_TRANSFER_TIMEOUT);
        reinit_completion(&sht->wait);

        rcu_read_lock();
        if (kthread_should_stop() && list_empty(&sht->queue)) {
            rcu_read_unlock();
            /* Exit prefetch thread */
            sht->stopped = true;
            ret = 0;
            goto out;
        }

        /* 1. Get one item from queue */
        item = list_first_or_null_rcu(&sht->queue, struct cache_transfer_item,
                                      list);
        rcu_read_unlock();
        if (!item)
            continue;

        mutex_lock(&item->lock);
        list_del_rcu(&item->list);
        synchronize_rcu();
        mutex_unlock(&item->lock);

        /* 2. Insert bio to cache */
        io = item->io;
        ret = security_cache_insert(s, io, item->timestamp);
        if (ret) {
            DMERR("Failed to insert cache");
            mutex_lock(&sht->queue_lock);
            list_add_tail_rcu(&item->list, &sht->queue);
            synchronize_rcu();
            mutex_unlock(&sht->queue_lock);
            continue;
        }

        /* 3. Go ahead processing */
        bio_endio(io->bio, 0);

        /**
         * Prefetch hash leaves and do security convertion at the same time
         */
        security_prefetch_hash_leaves(io->hash_io);
        ksecurityd_queue_security(io);

        kfree(item);
    }

out:
    DMINFO("Security cache transferer stopped (pid %d)", current->pid);
    return ret;
}

int security_cache_task_start(struct security_cache_task* sht,
                              void* owner,
                              char* name,
                              int (*fn)(void* data)) {
    int ret = 0;

    if (!sht)
        goto out;

    sht->stopped = false;
    init_completion(&sht->wait);
    INIT_LIST_HEAD(&sht->queue);
    mutex_init(&sht->queue_lock);

    sht->task = kthread_run(fn, sht, "dms_%s-%p", name, owner);
    if (sht->task == ERR_PTR(-ENOMEM))
        ret = -ENOMEM;

out:
    return ret;
}

void security_cache_task_stop(struct security_cache_task* sht) {
    if (!sht)
        return;

    if (sht->task)
        kthread_stop(sht->task);
}
