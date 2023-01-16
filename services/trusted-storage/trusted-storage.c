#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>

#include "trusted-storage.h"

#define MODULE_NAME "trusted-storage"

struct trusted_storage;

struct trusted_storage_ops {
    int (*read)(struct trusted_storage* ts,
                unsigned long key,
                void* out_buf,
                size_t len);
    int (*write)(struct trusted_storage* ts,
                 unsigned long key,
                 void* in_buf,
                 size_t len);
    int (*init)(struct trusted_storage* ts);
    void (*exit)(struct trusted_storage* ts);
};

struct trusted_storage {
    struct trusted_storage_ops* ops;
    struct radix_tree_root root;
    struct mutex lock;
    size_t max_buf_size;
    bool stopped;
};

static int trusted_storage_read_fn(struct trusted_storage* ts,
                                   unsigned long key,
                                   void* out_buf,
                                   size_t len) {
    void* buf = NULL;
    size_t size = max(len, ts->max_buf_size);
    int ret = 0;

    mutex_lock(&ts->lock);
    if (ts->stopped) {
        ret = TRUSTED_STORAGE_STOPPED;
        goto out;
    }

    buf = radix_tree_lookup(&ts->root, key);
    if (!buf) {
        ret = TRUSTED_STORAGE_NOT_FOUND;
        goto out;
    }
    memcpy(out_buf, buf, size);

out:
    mutex_unlock(&ts->lock);
    return ret;
}

static int trusted_storage_write_fn(struct trusted_storage* ts,
                                    unsigned long key,
                                    void* in_buf,
                                    size_t len) {
    void* buf;
    size_t size = max(len, ts->max_buf_size);
    int ret = 0;

    mutex_lock(&ts->lock);
    if (ts->stopped) {
        ret = TRUSTED_STORAGE_STOPPED;
        goto out;
    }

    buf = radix_tree_lookup(&ts->root, key);
    if (buf) {
        memcpy(buf, in_buf, size);
        ret = TRUSTED_STORAGE_EXIST;
        goto out;
    }

    buf = kmalloc(size, GFP_ATOMIC);
    memcpy(buf, in_buf, size);
    radix_tree_insert(&ts->root, key, buf);

out:
    mutex_unlock(&ts->lock);
    return ret;
}

static int trusted_storage_init_fn(struct trusted_storage* ts) {
    mutex_init(&ts->lock);
    INIT_RADIX_TREE(&ts->root, GFP_ATOMIC);
    ts->stopped = false;
    return 0;
}

static void trusted_storage_exit_fn(struct trusted_storage* ts) {
    struct radix_tree_iter iter;
    void** slot;
    void* buf;

    mutex_lock(&ts->lock);
    ts->stopped = true;
    mutex_unlock(&ts->lock);

    /* free all bufs */
    radix_tree_for_each_slot(slot, &ts->root, &iter, 0) {
        buf = radix_tree_deref_slot(slot);
        kfree(buf);
        radix_tree_delete(&ts->root, iter.index);
    }

    mutex_destroy(&ts->lock);
}

static struct trusted_storage_ops ts_ops = {
    .read = trusted_storage_read_fn,
    .write = trusted_storage_write_fn,
    .init = trusted_storage_init_fn,
    .exit = trusted_storage_exit_fn,
};

static struct trusted_storage ts = {
    .ops = &ts_ops,
    .max_buf_size = 64,
};

static int __init trusted_storage_init(void) {
    pr_info("trusted_storage: init\n");

    ts.ops->init(&ts);

    return 0;
}

static void __exit trusted_storage_exit(void) {
    pr_info("trusted_storage: exit\n");

    ts.ops->exit(&ts);
}

int trusted_storage_read(unsigned long key, void* out_buf, size_t len) {
    return ts.ops->read(&ts, key, out_buf, len);
}
EXPORT_SYMBOL_GPL(trusted_storage_read);

int trusted_storage_write(unsigned long key, void* in_buf, size_t len) {
    return ts.ops->write(&ts, key, in_buf, len);
}
EXPORT_SYMBOL_GPL(trusted_storage_write);

module_init(trusted_storage_init);
module_exit(trusted_storage_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peihong Chen <mf21320017@smail.nju.edu.cn>");
MODULE_DESCRIPTION("Trusted Storage Emulator (tse)");
