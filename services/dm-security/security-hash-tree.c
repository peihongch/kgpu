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

/**
 * Get a number of consecutive hash tree leaves by data blocks range.
 */
int security_prefetch_hash_leaves(struct security_hash_io* io) {
    struct dm_security* s = io->s;
    struct security_hash_task* prefetcher = &s->hash_prefetcher;
    struct hash_prefetch_item* item;
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

    pr_info("security_prefetch_hash_leaves: offset=%lu, count=%lu\n",
            io->offset, io->count);
    start = io->offset & (1 << s->leaves_per_node_bits);
    if (((io->offset + io->count) & (1 << s->leaves_per_node_bits)) == start)
        count = io->offset + io->count - start;
    else
        count = 2 << s->leaves_per_node_bits;

    pr_info("security_prefetch_hash_leaves: init_hash_prefetch_item\n");
    init_hash_prefetch_item(item, io->offset, io->count);
    list_add(&item->wait_list, &io->list);

    pr_info("security_prefetch_hash_leaves: mutex_lock\n");
    mutex_lock(&prefetcher->pre_queue_lock);
    pr_info("security_prefetch_hash_leaves: list_add\n");
    list_add(&item->list, &prefetcher->pre_queue);
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

    if (rw == WRITE && !error) {
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
    }

    bio_put(bio);

    /* queue hash io to verify leaf node using related mediate node */
    if (rw == READ && !error) {
        ksecurityd_queue_hash(io);
        return;
    }

    if (unlikely(error))
        io->error = error;
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
    int ret;

retry:
    if (unlikely(out_of_pages))
        mutex_lock(&s->bio_alloc_lock);

    bio = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
    if (!bio) {
        ret = -ENOMEM;
        goto out;
    }

    hash_bio_init(io, bio);
    io->base_bio = bio;

    remaining_size = size;

    for (i = 0; i < nr_iovecs; i++) {
        page = mempool_alloc(s->page_pool, gfp_mask);
        if (!page) {
            security_free_buffer_pages(s, bio);
            bio_put(bio);
            out_of_pages = true;
            goto retry;
        }

        len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

        bio_add_page(bio, page, len, 0);

        remaining_size -= len;
    }

    ret = 0;
out:
    if (unlikely(out_of_pages))
        mutex_unlock(&s->bio_alloc_lock);

    return ret;
}

void security_hash_io_free(struct security_hash_io* io) {
    if (!io)
        return;
    if (io->base_bio)
        bio_put(io->base_bio);
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

    if (io->base_io) { /* io read for mediate nodes */
        bio->bi_sector =
            s->hash_start + (io->offset >> (SECTOR_SHIFT - s->hash_node_bits));
    } else { /* io read for leaf nodes */
        bio->bi_sector =
            s->hash_start + ((s->hash_mediate_nodes + io->offset) >>
                             (SECTOR_SHIFT - s->hash_node_bits));
    }

    generic_make_request(bio);
    return 0;
}

void ksecurityd_hash_io_write(struct security_hash_io* io) {
    struct bio* bio = io->base_bio;
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

void security_leaves_cache_alloc(struct security_mediate_node* mn) {
    struct dm_security* s = mn->s;
    struct hash_nodes_cache* cache = &s->hash_nodes_cache;
    struct security_mediate_node* evict_mn = NULL;

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
        mutex_unlock(&evict_mn->lock);
        list_del(&evict_mn->lru_item);
        cache->size--;
    }

    if (!mn->leaves) {
        mutex_lock(&mn->lock);
        if (evict_mn) {
            mn->leaves = evict_mn->leaves;
            evict_mn->leaves = NULL;
        } else {
            mn->leaves = kzalloc(sizeof(struct security_leaf_node*) *
                                     (1 << s->leaves_per_node_bits),
                                 GFP_NOIO);
        }
        mutex_unlock(&mn->lock);
    }

    list_add_tail(&mn->lru_item, &cache->lru_list);
    cache->size++;

    mutex_unlock(&cache->lock);
}

void security_leaves_cache_clean(struct security_mediate_node* mn) {
    struct dm_security* s = mn->s;
    size_t i;

    if (!mn || !mn->leaves)
        return;
    for (i = 0; i < (1 << s->leaves_per_node_bits); i++) {
        security_leaf_node_free(&mn->leaves[i]);
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

/**
 * Update the leaf node already in radix tree cache in mediate node
 */
void security_leaf_node_update(struct security_leaf_node* ln,
                               struct security_hash_io* io) {
    struct bio* bio = io->base_bio;
    struct bio_vec* bvec;
    struct page* page;
    void* src;
    unsigned int i, len, offset = 0;

    bio_for_each_segment(bvec, bio, i) {
        page = bvec->bv_page;
        len = bvec->bv_len;
        src = page_address(page) + offset_in_page(page);
        memcpy(ln->digest + offset, src, len);
        offset += len;
    }
}

/* verify leaves using in-mem mediate node */
void ksecurityd_hash_read_convert(struct security_hash_io* io) {
    struct dm_security* s = io->s;
    struct hash_prefetch_item* item = io->prefetch;
    struct bio* bio = io->base_bio;
    struct bio_vec* bvec;
    struct page* page;
    struct security_mediate_node* mn;
    struct security_leaf_node* ln;
    struct inc_hash_ctx* ctx;
    size_t digest_size = hash_node_size(s);
    u8 digest[AUTHSIZE];
    unsigned int len, offset;
    size_t i, j, idx;

    /* 1. Place leaves to cache in corresponding mediate nodes */

    i = 0;
    bio_for_each_segment_all(bvec, bio, idx) {
        BUG_ON(!bvec->bv_page);
        page = bvec->bv_page;
        len = bvec->bv_len;
        offset = bvec->bv_offset;
        while (i < io->count && offset < len) {
            mn = mediate_node_of_block(s, io->offset + i);
            security_leaves_cache_alloc(mn);

            ln = leaf_node_of_block(s, io->offset + i);
            security_leaf_node_init(ln, mn, io->offset + i);
            memcpy(ln->digest, page_address(page) + offset, digest_size);
            offset += digest_size;
            i++;
        }
    }

    /* 2. Verify leaves using corresponding mediate node if possible */

    ctx = kmalloc(sizeof(struct inc_hash_ctx) + digest_size, GFP_NOIO);
    if (!ctx) {
        io->error = -ENOMEM;
        goto out;
    }
    ctx->old_len = 0;

    i = 0;
    while (i < io->count) {
        memset(digest, 0, digest_size);

        mn = mediate_node_of_block(s, io->offset + i);

        mutex_lock(&mn->lock);

        for (j = 0; j < (1 << s->leaves_per_node_bits); j++) {
            ln = &mn->leaves[j];

            mutex_lock(&ln->lock);

            /* Verify the hash value of leaf node */
            ctx->id = ln->index;
            memcpy(ctx->data, ln->digest, sizeof(ln->digest));
            crypto_shash_digest(s->hash_desc, (const u8*)ctx, digest_size,
                                digest);

            mutex_unlock(&ln->lock);
        }

        mn->corrupted = memcmp(digest, mn->digest, digest_size) ? true : false;

        mutex_unlock(&mn->lock);

        i += (1 << s->leaves_per_node_bits);
    }

out:
    list_for_each_entry(io, &item->wait_list, list) {
        complete(&io->restart);
    }
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

    DMINFO("Security hash flusher started (pid %d)\n", current->pid);

    while (1) {
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
    DMINFO("Security hash flusher stopped (pid %d)\n", current->pid);
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
    struct hash_prefetch_item *item, *tmp;
    struct rb_node *parent, **new;
    block_t offset, end;
    int ret;

    DMINFO("Security hash pre-prefetcher started (pid %d)\n", current->pid);

    while (1) {
        init_completion(&sht->pre_wait);
        wait_for_completion_timeout(&sht->pre_wait, HASH_PREFETCH_TIMEOUT);

        mutex_lock(&sht->pre_queue_lock);

        /* Exit prefetch thread */
        if (kthread_should_stop() && list_empty(&sht->pre_queue)) {
            sht->stopped = true;
            mutex_unlock(&sht->pre_queue_lock);
            ret = 0;
            goto out;
        }

        /* 1. Pop one item from queue */

        item = list_first_entry_or_null(&sht->pre_queue,
                                        struct hash_prefetch_item, list);
        if (item) {
            list_del(&item->list);
        } else {
            mutex_unlock(&sht->pre_queue_lock);
            continue;
        }
        mutex_unlock(&sht->pre_queue_lock);

        /* 2. Quickly check if already in cache */

        mutex_lock(&sht->queue_lock);
        offset = item->start;
        end = item->start + item->count;
        while (offset < end && offset < s->data_blocks) {
            mn = mediate_node_of_block(s, offset);
            mutex_lock(&mn->lock);
            if (!mn->leaves)
                goto cache_miss;
            mutex_unlock(&mn->lock);
        }

        /* Now all hash block in cache */
        list_for_each_entry_safe(io, next, &item->wait_list, list) {
            list_del(&io->list);
            complete_all(&io->restart);
        }

        mutex_unlock(&sht->queue_lock);
        continue;

        /* 3. Check if already in prefetch_queue */

    cache_miss:
        new = &(sht->rbtree_root.rb_node);
        parent = NULL;
        while (*new) {
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

        if (*new) {
            /* 4.a Merge item to existing one */
            hash_prefetch_item_merge(tmp, item);
            kfree(item);
        } else {
            /* 4.b Add to prefetch_queue directly */
            list_add(&item->list, &sht->queue);
            /* Add new node and rebalance tree. */
            rb_link_node(&item->rb_node, parent, new);
            rb_insert_color(&item->rb_node, &sht->rbtree_root);
        }

        mutex_unlock(&sht->queue_lock);

        complete(&sht->wait);
    }

    ret = 0;
out:
    DMINFO("Security hash pre-prefetcher stopped (pid %d)\n", current->pid);
    return ret;
}

int security_hash_prefetch(void* data) {
    struct security_hash_task* sht = data;
    struct dm_security* s =
        container_of(sht, struct dm_security, hash_prefetcher);
    struct security_hash_io* io;
    struct hash_prefetch_item *item, *tmp, *merged;
    struct bio* bio;
    struct rb_node *node, *start, *end;
    int ret;

    DMINFO("Security hash prefetcher started (pid %d)\n", current->pid);

    while (1) {
        init_completion(&sht->wait);
        wait_for_completion_timeout(&sht->wait, HASH_PREFETCH_TIMEOUT);

        mutex_lock(&sht->queue_lock);

        /* Exit prefetch thread */
        if (kthread_should_stop() && list_empty(&sht->queue) && sht->stopped) {
            mutex_unlock(&sht->queue_lock);
            ret = 0;
            goto out;
        }

        /* 1. Get one item from queue */
        item = list_first_entry_or_null(&sht->queue, struct hash_prefetch_item,
                                        list);
        if (item) {
            list_del(&item->list);
        } else {
            mutex_unlock(&sht->queue_lock);
            continue;
        }
        mutex_unlock(&sht->queue_lock);

        /* 2. Walk through hash rbtree to get adjacent items */

        /* Traverse left side of io */
        start = &item->rb_node;
        end = rb_next(&item->rb_node);
        for (node = &item->rb_node; node; node = rb_prev(node)) {
            tmp = rb_entry(node, struct hash_prefetch_item, rb_node);
            if (tmp->start + tmp->count < item->start)
                break;
            start = node;
        }
        /* Traverse right side of io */
        for (node = &item->rb_node; node; node = rb_next(node)) {
            tmp = rb_entry(node, struct hash_prefetch_item, rb_node);
            if (tmp->start > item->start + item->count) {
                end = node;
                break;
            }
        }

        /* 3. Remove all adjacent items from both queue and rbtree */
        merged = kmalloc(sizeof(struct hash_prefetch_item), GFP_KERNEL);
        if (unlikely(!merged)) {
            ret = -ENOMEM;
            goto out;
        }
        init_hash_prefetch_item(merged, 0, 0);

        for (node = start; node != end; node = rb_next(node)) {
            tmp = rb_entry(node, struct hash_prefetch_item, rb_node);
            hash_prefetch_item_merge(merged, tmp);
            rb_erase(node, &sht->rbtree_root);
            list_del(&tmp->list);
            kfree(tmp);
        }

        mutex_unlock(&sht->queue_lock);

        /* 4. Go ahead process */
        io = security_hash_io_alloc(s, merged->start, merged->count);
        io->prefetch = merged;

        ret = security_hash_alloc_buffer(io);
        if (unlikely(!ret))
            goto out;

        bio->bi_rw |= READ;
        ksecurityd_hash_queue_io(io);
    }

out:
    DMINFO("Security hash prefetcher stopped (pid %d)\n", current->pid);
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
    complete_all(&sht->pre_wait);
    complete_all(&sht->wait);
}
