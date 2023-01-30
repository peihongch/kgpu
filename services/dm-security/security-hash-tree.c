#include <linux/delay.h>
#include "../crypto/inc-hash/inc-hash.h"
#include "dm-security.h"

inline struct security_mediate_node* security_get_mediate_node(
    struct dm_security* s,
    sector_t sector) {
    return sector >= data_area_sectors(s)
               ? NULL
               : mediate_node_of_block(s, data_block_of_sector(s, sector));
}

struct security_leaf_node* cache_get_leaf_node(struct dm_security* s,
                                               size_t index) {
    struct security_mediate_node* mn;

    if (index >= s->hash_leaf_nodes)
        return NULL;

    mn = mediate_node_of_block(s, index);
    /* check if leaf node in cache */
    if (!mn->leaves)
        return NULL;

    return leaf_node_of_block(s, index);
}

/**
 * Get a number of consecutive hash tree leaves by data blocks range.
 */
int security_prefetch_hash_leaves(struct security_hash_io* io) {
    struct dm_security* s = io->s;
    struct security_hash_task* prefetcher = &s->hash_prefetcher;
    struct hash_prefetch_item* item = NULL;
    unsigned leaves_per_node = 1 << s->leaves_per_node_bits;
    size_t start, count;
    int ret = 0;

    pr_info("security_prefetch_hash_leaves: offset=%lu, count=%lu\n",
            io->offset, io->count);
    item = kmalloc(sizeof(struct hash_prefetch_item), GFP_NOIO);
    if (!item) {
        pr_info("security_prefetch_hash_leaves: kmalloc failed\n");
        ret = -ENOMEM;
        goto out;
    }

    pr_info("security_prefetch_hash_leaves: after kmalloc\n");
    start = UMASK_BITS(io->offset, s->leaves_per_node_bits);
    if (UMASK_BITS(io->offset + io->count, s->leaves_per_node_bits) == start)
        count = leaves_per_node;
    else
        count =
            DIV_ROUND_UP_BITS(io->offset + io->count - start, leaves_per_node);

    pr_info(
        "security_prefetch_hash_leaves: init_hash_prefetch_item, start = %lu, "
        "count = %lu\n",
        start, count);

    init_hash_prefetch_item(item, start, count);
    list_add_tail(&io->list, &item->wait_list);

    pr_info("security_prefetch_hash_leaves: mutex_lock\n");
    mutex_lock(&prefetcher->pre_queue_lock);
    list_add_tail(&item->list, &prefetcher->pre_queue);
    mutex_unlock(&prefetcher->pre_queue_lock);
    pr_info("security_prefetch_hash_leaves: mutex_unlock\n");

    complete(&prefetcher->pre_wait);
    pr_info("security_prefetch_hash_leaves: complete\n");

out:
    return ret;
}

void security_hash_endio(struct bio* bio, int error) {
    struct security_hash_io* io = bio->bi_private;
    struct dm_security* s = io->s;
    struct security_mediate_node* mn;
    struct security_leaf_node* ln;
    unsigned rw = bio_data_dir(bio);
    size_t i;

    if (unlikely(!bio_flagged(bio, BIO_UPTODATE) && !error))
        error = -EIO;

    pr_info(
        "security_hash_endio: bio->bi_sector: %lu, bio->bi_size: %u, "
        "io->offset: %lu, io->count = %lu, error: %d\n",
        bio->bi_sector, bio->bi_size, io->offset, io->count, error);

    if (rw == WRITE && !error) {
        pr_info("security_hash_endio: 1\n");
        for (i = io->offset; i < io->count + io->offset; i++) {
            ln = leaf_node_of_block(s, i);
            mutex_lock(&ln->lock);
            ln->dirty = false;
            mutex_unlock(&ln->lock);

            mn = ln->parent;
            mutex_lock(&mn->lock);
            mn->dirty--;
            mutex_unlock(&mn->lock);
        }

        bio_put(bio);
    }

    pr_info("security_hash_endio: 2\n");

    /* queue hash io to verify leaf node using related mediate node */
    if (rw == READ && !error) {
        // pr_info("security_hash_endio: ksecurityd_queue_hash(io);\n");
        ksecurityd_queue_hash(io);
        return;
    }

    pr_info("security_hash_endio: 3\n");

    if (unlikely(error))
        io->error = error;

    pr_info("security_hash_endio: io->error = %d\n", io->error);
}

void hash_bio_init(struct security_hash_io* io, struct bio* bio) {
    struct dm_security* s = io->s;

    bio->bi_private = io;
    bio->bi_end_io = security_hash_endio;
    bio->bi_bdev = s->dev->bdev;
}

int security_hash_alloc_buffer(struct security_hash_io* io) {
    struct dm_security* s = io->s;
    struct bio* bio;
    size_t size = io->count << s->hash_node_bits;
    size_t nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    gfp_t gfp_mask = GFP_NOIO | __GFP_HIGHMEM;
    unsigned i, len, remaining_size;
    bool out_of_pages = false;
    struct page* page;
    int ret = 0;

    pr_info("security_hash_alloc_buffer: size=%lu, nr_iovecs=%lu\n", size,
            nr_iovecs);

retry:
    if (unlikely(out_of_pages))
        mutex_lock(&s->bio_alloc_lock);

    pr_info("security_hash_alloc_buffer: 1\n");
    bio = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
    if (!bio) {
        pr_info("security_hash_alloc_buffer: 2\n");
        ret = -ENOMEM;
        goto out;
    }

    hash_bio_init(io, bio);
    io->base_bio = bio;

    remaining_size = size;

    pr_info("security_hash_alloc_buffer: 3\n");
    for (i = 0; i < nr_iovecs; i++) {
        page = mempool_alloc(s->page_pool, gfp_mask);
        if (!page) {
            pr_info("security_hash_alloc_buffer: 4\n");
            security_free_buffer_pages(s, bio);
            bio_put(bio);
            out_of_pages = true;
            goto retry;
        }

        len = min(remaining_size, (unsigned)PAGE_SIZE);

        if (!bio_add_page(bio, page, len, 0)) {
            pr_info("security_hash_alloc_buffer: 5\n");
            security_free_buffer_pages(s, bio);
            bio_put(bio);
            goto retry;
        }

        remaining_size -= len;
        pr_info("security_hash_alloc_buffer: 6\n");
    }

    ret = 0;
out:
    pr_info("security_hash_alloc_buffer: 7\n");
    if (unlikely(out_of_pages)) {
        mutex_unlock(&s->bio_alloc_lock);
    }

    pr_info("security_hash_alloc_buffer: 8\n");
    return ret;
}

void security_hash_io_free(struct security_hash_io* io) {
    if (!io)
        return;

    if (io->base_bio) {
        security_free_buffer_pages(io->s, io->base_bio);
        bio_put(io->base_bio);
    }

    mempool_free(io, io->s->hash_io_pool);
}

struct security_hash_io* security_hash_io_alloc(struct dm_security* s,
                                                size_t offset,
                                                size_t count) {
    struct security_hash_io* io;

    io = mempool_alloc(s->hash_io_pool, GFP_NOIO);
    io->s = s;
    io->offset = offset;
    io->count = count;
    io->error = 0;
    io->prefetch = NULL;
    io->base_bio = NULL;
    init_completion(&io->restart);
    atomic_set(&io->io_pending, 1);

    return io;
}

inline void hash_prefetch_item_merge(struct hash_prefetch_item* item,
                                     struct hash_prefetch_item* new_item) {
    if (item->count == 0) {
        item->start = new_item->start;
        item->count = new_item->count;
    } else {
        item->count =
            max(item->start + item->count, new_item->start + new_item->count) -
            min(item->start, new_item->start);
        item->start = min(item->start, new_item->start);
    }
    list_splice(&new_item->wait_list, &item->wait_list);
}

int ksecurityd_hash_io_read(struct security_hash_io* io, gfp_t gfp) {
    struct dm_security* s = io->s;
    struct bio* bio = io->base_bio;

    bio->bi_sector = security_map_hash_sector(
        s, io->offset >> (SECTOR_SHIFT - s->hash_node_bits));

    pr_info(
        "ksecurityd_hash_io_read: bio->bi_sector=%lu, bio->bi_size = %u, "
        "io->offset=%lu, io->count=%lu\n",
        bio->bi_sector, bio->bi_size, io->offset, io->count);

    generic_make_request(bio);
    return 0;
}

void ksecurityd_hash_io_write(struct security_hash_io* io) {
    struct dm_security* s = io->s;
    struct bio* bio = io->base_bio;

    bio->bi_sector = security_map_hash_sector(
        s, io->offset >> (SECTOR_SHIFT - s->hash_node_bits));

    generic_make_request(bio);
}

void ksecurityd_hash_io(struct work_struct* work) {
    struct security_hash_io* io =
        container_of(work, struct security_hash_io, work);

    if (bio_data_dir(io->base_bio) == READ) {
        if (ksecurityd_hash_io_read(io, GFP_NOIO))
            io->error = -ENOMEM;
    } else
        ksecurityd_hash_io_write(io);
}

void ksecurityd_hash_queue_io(struct security_hash_io* io) {
    struct dm_security* s = io->s;

    INIT_WORK(&io->work, ksecurityd_hash_io);
    queue_work(s->io_queue, &io->work);
}

void ksecurityd_hash_write_io_submit(struct security_hash_io* io, int async) {
    // TODO
}

void ksecurityd_hash_write_convert(struct security_hash_io* io) {
    // TODO
}

struct security_leaf_node** security_leaves_cache_alloc(
    struct security_mediate_node* mn) {
    struct dm_security* s = mn->s;
    struct hash_nodes_cache* cache = &s->hash_nodes_cache;
    struct security_mediate_node* evict_mn = NULL;
    struct security_leaf_node** leaves = NULL;
    size_t leaves_per_node = 1 << s->leaves_per_node_bits;
    size_t i;

    mutex_lock(&mn->lock);
    if (mn->leaves)
        leaves = mn->leaves;
    mutex_unlock(&mn->lock);

    if (leaves)
        goto out;

    mutex_lock(&cache->lock);
    if (cache->size == cache->capacity) {
        evict_mn = list_first_entry(&cache->lru_list,
                                    struct security_mediate_node, lru_item);
        mutex_lock(&evict_mn->lock);
        while (evict_mn->dirty) {
            mutex_unlock(&evict_mn->lock);
            cond_resched();
            mutex_lock(&evict_mn->lock);
        }
        list_del(&evict_mn->lru_item);
        leaves = evict_mn->leaves;
        evict_mn->leaves = NULL;
        evict_mn->cached = false;
        mutex_unlock(&evict_mn->lock);
        cache->size--;
    }
    mutex_unlock(&cache->lock);

    if (!leaves) {
        leaves = kzalloc(sizeof(struct security_leaf_node*) * leaves_per_node,
                         GFP_NOIO);
        if (!leaves)
            goto nomem;
        for (i = 0; i < leaves_per_node; i++) {
            leaves[i] = kmalloc(sizeof(struct security_leaf_node), GFP_NOIO);
            if (!leaves[i])
                goto nomem;
        }
    }

out:
    return leaves;

nomem:
    pr_info("security_leaves_cache_alloc: nomem\n");
    for (i = 0; i < leaves_per_node; i++) {
        if (!leaves[i])
            break;
        security_leaf_node_free(leaves[i]);
    }
    if (leaves)
        kfree(leaves);
    return NULL;
}

void security_leaves_cache_add(struct security_mediate_node* mn,
                               struct security_leaf_node** leaves) {
    struct dm_security* s = mn->s;
    struct hash_nodes_cache* cache = &s->hash_nodes_cache;

    mutex_lock(&mn->lock);

    mn->leaves = leaves;

    mutex_lock(&cache->lock);

    /* del before add to avoid "list_add double add: xxx" bug */
    if (mn->cached)
        list_del(&mn->lru_item);
    else {
        mn->cached = true;
        cache->size++;
    }
    list_add_tail(&mn->lru_item, &cache->lru_list);

    mutex_unlock(&cache->lock);

    mutex_unlock(&mn->lock);
}

void security_leaves_cache_clean(struct security_mediate_node* mn) {
    struct dm_security* s = mn->s;
    size_t leaves_per_node = 1 << s->leaves_per_node_bits;
    size_t i;

    if (!mn || !mn->leaves)
        return;
    for (i = 0; i < leaves_per_node; i++) {
        security_leaf_node_free(mn->leaves[i]);
    }
    kfree(mn->leaves);
    mn->leaves = NULL;
}

void security_leaf_node_init(struct security_leaf_node* ln,
                             struct security_mediate_node* mn,
                             size_t index) {
    ln->parent = mn;
    ln->index = index;
    ln->dirty = false;
    ln->ref_count = 0;
    mutex_init(&ln->lock);
}

void security_leaf_node_free(struct security_leaf_node* ln) {
    struct security_mediate_node* mn;
    struct dm_security* s;

    if (!ln || !(mn = ln->parent) || !(s = mn->s))
        return;

    mempool_free(ln, s->leaf_node_pool);
}

void security_mediate_node_init(struct security_mediate_node* mn) {
    mn->dirty = 0;
    mn->corrupted = false;
    mn->cached = false;
    mutex_init(&mn->lock);
    mn->leaves = NULL;
    memset(mn->digest, 0, sizeof(mn->digest));
}

int security_mediate_nodes_init(struct dm_security* s) {
    struct security_mediate_node* mn;
    int i, ret;

    ret = -ENOMEM;
    s->mediate_nodes =
        vmalloc(sizeof(struct security_mediate_node*) * s->hash_mediate_nodes);
    if (!s->mediate_nodes)
        goto bad;

    for (i = 0; i < s->hash_mediate_nodes; i++) {
        s->mediate_nodes[i] =
            kmalloc(sizeof(struct security_mediate_node), GFP_KERNEL);
        if (!s->mediate_nodes[i])
            goto bad;

        mn = s->mediate_nodes[i];
        mn->index = i;
        mn->s = s;
        security_mediate_node_init(mn);
    }

    ret = 0;
bad:
    return ret;
}

void security_mediate_node_free(struct security_mediate_node* mn) {
    if (!mn || !mn->leaves)
        return;
    security_leaves_cache_clean(mn);
    kfree(mn);
}

void security_mediate_nodes_free(struct dm_security* s) {
    int i;

    if (!s->mediate_nodes)
        return;

    for (i = 0; i < s->hash_mediate_nodes; i++) {
        security_mediate_node_free(s->mediate_nodes[i]);
    }
    vfree(s->mediate_nodes);
    s->mediate_nodes = NULL;
}

/* verify leaves using in-mem mediate node */
void ksecurityd_hash_read_convert(struct security_hash_io* io) {
    struct dm_security* s = io->s;
    struct hash_prefetch_item* item = io->prefetch;
    struct security_hash_io* pos;
    struct bio* bio = io->base_bio;
    struct bio_vec* bvec;
    struct page* page;
    struct security_mediate_node* mn = NULL;
    struct security_leaf_node* ln;
    struct security_leaf_node** leaves;
    struct inc_hash_ctx* ctx = NULL;
    size_t digest_size = hash_node_size(s);
    u8 digest[AUTHSIZE];
    unsigned int len, offset;
    size_t i, j, idx, size = 0;

    pr_info(
        "ksecurityd_hash_read_convert: bio->bi_sector = %lu, bio->bi_size = "
        "%u, "
        "io->offset = %u, io->count = %lu\n",
        bio->bi_sector, bio->bi_size, io->offset, io->count);

    /* 1. Place leaves to cache in corresponding mediate nodes */

    i = 0;
    bio_for_each_segment_all(bvec, bio, idx) {
        page = bvec->bv_page;
        len = bvec->bv_len;
        offset = bvec->bv_offset;
        while (i < io->count && offset < len) {
            mn = mediate_node_of_block(s, io->offset + i);
            leaves = security_leaves_cache_alloc(mn);
            size += digest_size;

            ln = leaves[MASK_BITS(io->offset + i, s->leaves_per_node_bits)];
            security_leaf_node_init(ln, mn, io->offset + i);
            memcpy(ln->digest, page_address(page) + offset, digest_size);
            security_leaves_cache_add(mn, leaves);

            offset += digest_size;
            i++;
        }
    }

    /* 2. Verify leaves using corresponding mediate node if possible */

    pr_info("ksecurityd_hash_read_convert: 1\n");

    ctx = kmalloc(sizeof(struct inc_hash_ctx) + digest_size, GFP_NOIO);
    if (!ctx) {
        io->error = -ENOMEM;
        goto out;
    }
    ctx->old_len = 0;

    pr_info("ksecurityd_hash_read_convert: 2\n");
    i = 0;
    while (i < io->count) {
        memset(digest, 0, digest_size);

        mn = mediate_node_of_block(s, io->offset + i);

        mutex_lock(&mn->lock);

        for (j = 0; j < (1 << s->leaves_per_node_bits); j++) {
            ln = mn->leaves[j];

            mutex_lock(&ln->lock);

            /* Verify the hash value of leaf node */
            ctx->id = ln->index;
            memcpy(ctx->data, ln->digest, sizeof(ln->digest));
            crypto_shash_digest(s->hash_desc, (const u8*)ctx, digest_size,
                                digest);

            mutex_unlock(&ln->lock);
        }

        mn->corrupted = memcmp(digest, mn->digest, digest_size) ? true : false;
        if (unlikely(mn->corrupted)) {
            pr_info("ksecurityd_hash_read_convert: mn[%p] corrupted = %d\n", mn,
                    mn->corrupted);
            pr_info("digest: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
                    digest[0], digest[1], digest[2], digest[3], digest[4],
                    digest[5], digest[6], digest[7]);
            pr_info("mn->dg: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
                    mn->digest[0], mn->digest[1], mn->digest[2], mn->digest[3],
                    mn->digest[4], mn->digest[5], mn->digest[6], mn->digest[7]);
        }

        mutex_unlock(&mn->lock);

        i += (1 << s->leaves_per_node_bits);
    }

    pr_info("ksecurityd_hash_read_convert: 3\n");

out:
    if (ctx)
        kfree(ctx);

    pr_info("ksecurityd_hash_read_convert: 4\n");

    list_for_each_entry(pos, &item->wait_list, list) {
        pr_info("ksecurityd_hash_read_convert: 5\n");
        complete(&pos->restart);
    }
    pr_info("ksecurityd_hash_read_convert: 6\n");

    security_hash_io_free(io);
    pr_info("ksecurityd_hash_read_convert: 7\n");
}

void ksecurityd_hash(struct work_struct* work) {
    struct security_hash_io* io =
        container_of(work, struct security_hash_io, work);

    if (bio_data_dir(io->base_bio) == READ) {
        ksecurityd_hash_read_convert(io);
    } else {
        ksecurityd_hash_write_convert(io);
    }
}

void ksecurityd_queue_hash(struct security_hash_io* io) {
    struct dm_security* s = io->s;

    INIT_WORK(&io->work, ksecurityd_hash);
    queue_work(s->hash_queue, &io->work);
}

int security_hash_flush(void* data) {
    struct security_hash_task* sht = data;
    struct dm_security* s = container_of(sht, struct dm_security, hash_flusher);
    struct security_leaf_node *ln, *tmp;
    struct security_hash_io* io;
    struct bio* bio;
    struct rb_node *node, *start, *end;
    size_t offset, count = 0, index;
    int ret;

    DMINFO("Security hash flusher started (pid %d)", current->pid);

    while (1) {
        pr_info("hash_flush wait for completion...\n");
        init_completion(&sht->wait);
        wait_for_completion_timeout(&sht->wait, HASH_FLUSH_TIMEOUT);

        mutex_lock(&sht->queue_lock);

        /* Exit prefetch thread */
        if (kthread_should_stop() && list_empty(&sht->queue)) {
            sht->stopped = true;
            mutex_unlock(&sht->queue_lock);
            ret = 0;
            goto out;
        }

        /* 1. Get one item from queue */

        ln = list_first_entry_or_null(&sht->queue, struct security_leaf_node,
                                      flush_list);
        if (!ln) {
            mutex_unlock(&sht->queue_lock);
            continue;
        }

        /* 2. Walk through hash rbtree to get adjacent items */

        /* Traverse left side of leaf node */
        offset = index = ln->index;
        start = &ln->flush_rb_node;
        end = rb_next(&ln->flush_rb_node);
        for (node = &ln->flush_rb_node; node; node = rb_prev(node)) {
            tmp = rb_entry(node, struct security_leaf_node, flush_rb_node);
            if (tmp->index != index)
                break;
            start = node;
            index = offset = tmp->index;
        }
        /* Traverse right side of leaf node */
        index = ln->index;
        for (node = &ln->flush_rb_node; node; node = rb_next(node)) {
            tmp = rb_entry(node, struct security_leaf_node, flush_rb_node);
            index = tmp->index;
            if (tmp->index != index) {
                end = node;
                count = tmp->index - offset;
                break;
            }
        }

        /* 3. Remove all adjacent items from both queue and rbtree */

        count = index - offset;
        io = security_hash_io_alloc(s, offset, count);
        bio = bio_alloc_bioset(GFP_NOIO, count, s->bs);
        if (!bio) {
            ret = -ENOMEM;
            mutex_unlock(&sht->queue_lock);
            goto nomem;
        }
        hash_bio_init(io, bio);

        for (node = start; node != end; node = rb_next(node)) {
            ln = rb_entry(node, struct security_leaf_node, flush_rb_node);

            rb_erase(node, &sht->rbtree_root);
            list_del(&ln->flush_list);

            bio_add_page(bio, virt_to_page(ln->digest), sizeof(ln->digest),
                         offset_in_page(ln->digest));
        }

        /* 4. Go ahead process */

        bio->bi_rw |= WRITE;
        io->base_bio = bio;
        ksecurityd_hash_queue_io(io);

        mutex_unlock(&sht->queue_lock);
    }

    ret = 0;

nomem:
    if (io)
        security_hash_io_free(io);
out:
    DMINFO("Security hash flusher stopped (pid %d)", current->pid);
    return ret;
}

/**
 * Check if hash_io already in prefetch_queue, and add to queue those hash_io
 * parts not in.
 */
int security_hash_pre_prefetch(void* data) {
    struct security_hash_task* sht = data;
    struct dm_security* s =
        container_of(sht, struct dm_security, hash_prefetcher);
    struct security_mediate_node* mn;
    struct security_hash_io *io, *next;
    struct hash_prefetch_item *item, *tmp = NULL;
    struct rb_node *parent, **new;
    size_t leaves_per_node = 1 << s->leaves_per_node_bits;
    block_t offset;
    bool cache_hit = true;
    int ret;

    DMINFO("Security hash pre-prefetcher started (pid %d)", current->pid);

    while (1) {
        pr_info("hash_pre-prefetcher wait for completion...\n");
        wait_for_completion_timeout(&sht->pre_wait, HASH_PREFETCH_TIMEOUT);
        reinit_completion(&sht->pre_wait);

        pr_info("hash_pre-prefetcher: 0\n");

        mutex_lock(&sht->pre_queue_lock);

        pr_info("hash_pre-prefetcher: 1\n");

        /* Exit prefetch thread */
        if (kthread_should_stop() && list_empty(&sht->pre_queue)) {
            sht->stopped = true;
            mutex_unlock(&sht->pre_queue_lock);
            ret = 0;
            goto out;
        }
        pr_info("hash_pre-prefetcher: 2\n");

        /* 1. Pop one item from queue */

        item = list_first_entry_or_null(&sht->pre_queue,
                                        struct hash_prefetch_item, list);
        if (item) {
            pr_info("hash_pre-prefetcher: 3\n");
            list_del(&item->list);
        } else {
            pr_info("hash_pre-prefetcher: 4\n");
            mutex_unlock(&sht->pre_queue_lock);
            continue;
        }
        mutex_unlock(&sht->pre_queue_lock);

        /* 2. Quickly check if already in cache */
        pr_info("hash_pre-prefetcher: 5\n");

        offset = item->start;
        for (offset = item->start;
             offset < min((block_t)(item->start + item->count), s->data_blocks);
             offset += leaves_per_node) {
            pr_info("hash_pre-prefetcher: 6\n");
            mn = mediate_node_of_block(s, offset);
            mutex_lock(&mn->lock);
            cache_hit = mn->cached;
            mutex_unlock(&mn->lock);
            pr_info("hash_pre-prefetcher: 7\n");
            if (!cache_hit)
                goto cache_miss;
        }

        /* Now all hash block in cache */
        list_for_each_entry_safe(io, next, &item->wait_list, list) {
            pr_info("hash_pre-prefetcher: 8\n");
            list_del(&io->list);
            complete(&io->restart);
        }

        /* reclaim item as it won't be used any more */
        kfree(item);
        continue;

        /* 3. Check if already in prefetch_queue */
        pr_info("hash_pre-prefetcher: 9\n");

    cache_miss:
        mutex_lock(&sht->queue_lock);

        new = &(sht->rbtree_root.rb_node);
        parent = NULL;
        while (*new) {
            pr_info("hash_pre-prefetcher: 10\n");
            tmp = rb_entry(*new, struct hash_prefetch_item, rb_node);
            parent = *new;
            if (item->start < tmp->start) {
                new = &((*new)->rb_left);
            } else if (item->start > tmp->start) {
                new = &((*new)->rb_right);
            } else {
                /* There is an intersection between item and tmp */
                break;
            }
        }

        pr_info("hash_pre-prefetcher: 11\n");
        if (*new) {
            /* 4.a Merge item to existing one (tmp) */
            hash_prefetch_item_merge(tmp, item);
            kfree(item);
            pr_info("hash_pre-prefetcher: 11.1\n");
        } else {
            /* 4.b Add to prefetch_queue directly */
            list_add_tail(&item->list, &sht->queue);
            /* Add new node and rebalance tree. */
            rb_link_node(&item->rb_node, parent, new);
            rb_insert_color(&item->rb_node, &sht->rbtree_root);
            pr_info(
                "hash_pre-prefetcher: 11.2, item->start = %lu, item->count = "
                "%lu\n",
                item->start, item->count);
        }

        pr_info("hash_pre-prefetcher: 12\n");

        mutex_unlock(&sht->queue_lock);

        complete(&sht->wait);
        pr_info("hash_pre-prefetcher: 13\n");
    }

    ret = 0;
out:
    DMINFO("Security hash pre-prefetcher stopped (pid %d)", current->pid);
    return ret;
}

int security_hash_prefetch(void* data) {
    struct security_hash_task* sht = data;
    struct dm_security* s =
        container_of(sht, struct dm_security, hash_prefetcher);
    struct security_hash_io* io;
    struct hash_prefetch_item *item, *tmp, *merged;
    struct rb_node *node, *start, *end;
    int ret;

    DMINFO("Security hash prefetcher started (pid %d)", current->pid);

    while (1) {
        pr_info("hash_prefetcher wait for completion...\n");

        wait_for_completion_timeout(&sht->wait, HASH_PREFETCH_TIMEOUT);
        reinit_completion(&sht->wait);

        pr_info("hash_prefetcher: 0\n");

        mutex_lock(&sht->queue_lock);

        pr_info("hash_prefetcher: 1\n");

        /* Exit prefetch thread */
        if (kthread_should_stop() && list_empty(&sht->queue) && sht->stopped) {
            mutex_unlock(&sht->queue_lock);
            ret = 0;
            goto out;
        }

        pr_info("hash_prefetcher: 2\n");

        /* 1. Get one item from queue */
        item = list_first_entry_or_null(&sht->queue, struct hash_prefetch_item,
                                        list);
        if (!item) {
            pr_info("hash_prefetcher: 3\n");
            mutex_unlock(&sht->queue_lock);
            continue;
        }

        /* 2. Walk through hash rbtree to get adjacent items */

        pr_info("hash_prefetcher: 4, item->start = %lu, item->count = %lu\n",
                item->start, item->count);

        /* Traverse left side of io */
        start = &item->rb_node;
        end = rb_next(&item->rb_node);
        for (node = &item->rb_node; node; node = rb_prev(node)) {
            tmp = rb_entry(node, struct hash_prefetch_item, rb_node);
            if (tmp->start + tmp->count < item->start)
                break;
            start = node;
        }
        pr_info("hash_prefetcher: 5\n");
        /* Traverse right side of io */
        for (node = &item->rb_node; node; node = rb_next(node)) {
            tmp = rb_entry(node, struct hash_prefetch_item, rb_node);
            if (tmp->start > item->start + item->count) {
                end = node;
                break;
            }
        }

        /* 3. Remove all adjacent items from both queue and rbtree */
        pr_info("hash_prefetcher: 6\n");
        merged = kmalloc(sizeof(struct hash_prefetch_item), GFP_KERNEL);
        if (unlikely(!merged)) {
            ret = -ENOMEM;
            goto out;
        }
        init_hash_prefetch_item(merged, 0, 0);

        pr_info("hash_prefetcher: 7\n");
        for (node = start; node != end; node = rb_next(node)) {
            tmp = rb_entry(node, struct hash_prefetch_item, rb_node);
            hash_prefetch_item_merge(merged, tmp);
            rb_erase(node, &sht->rbtree_root);
            list_del(&tmp->list);
            kfree(tmp);
        }

        mutex_unlock(&sht->queue_lock);

        pr_info(
            "hash_prefetcher: 7.1, merged->start = %lu, merged->count = %lu\n",
            merged->start, merged->count);

        /* 4. Go ahead process */
        pr_info("hash_prefetcher: 8\n");
        io = security_hash_io_alloc(s, merged->start, merged->count);
        io->prefetch = merged;

        pr_info("hash_prefetcher: 9\n");
        ret = security_hash_alloc_buffer(io);
        if (unlikely(ret))
            goto out;

        pr_info(
            "hash_prefetcher: 10, bio->bi_sector = %lu, bio->bi_size = %u, "
            "io->offset = %u, io->count = %lu\n",
            io->base_bio->bi_sector, io->base_bio->bi_size, io->offset,
            io->count);
        io->base_bio->bi_rw |= READ;
        ksecurityd_hash_queue_io(io);

        pr_info("hash_prefetcher: 11\n");
    }

out:
    DMINFO("Security hash prefetcher stopped (pid %d)", current->pid);
    return ret;
}

int security_hash_task_start(struct security_hash_task* sht,
                             char* name,
                             int (*fn)(void* data),
                             int (*pre_fn)(void* data)) {
    struct dm_security* s =
        container_of(sht, struct dm_security, hash_prefetcher);
    int ret;

    if (!sht)
        goto out;

    sht->stopped = false;
    sht->rbtree_root = RB_ROOT;
    init_completion(&sht->pre_wait);
    init_completion(&sht->wait);
    INIT_LIST_HEAD(&sht->pre_queue);
    INIT_LIST_HEAD(&sht->queue);
    mutex_init(&sht->pre_queue_lock);
    mutex_init(&sht->queue_lock);

    if (pre_fn) {
        sht->pre_task = kthread_run(pre_fn, sht, "dms_%s-%p", name, s);
        if (sht->task == ERR_PTR(-ENOMEM)) {
            ret = -ENOMEM;
            goto bad;
        }
    }

    sht->task = kthread_run(fn, sht, "dms_%s-%p", name, s);
    if (sht->task == ERR_PTR(-ENOMEM)) {
        ret = -ENOMEM;
        goto bad;
    }

out:
    ret = 0;
bad:
    return ret;
}

void security_hash_task_stop(struct security_hash_task* sht) {
    if (!sht)
        return;

    if (sht->pre_task)
        kthread_stop(sht->pre_task);
    if (sht->task)
        kthread_stop(sht->task);

    // complete_all(&sht->pre_wait);
    // complete_all(&sht->wait);
}
