#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "trusted-storage.h"

#define MODULE_NAME "trusted-storage"
#define PROCFS_DIR "tse"
#define PROCFS_ENTRY "all"

static int len = 1;

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
    struct proc_dir_entry* proc_dir;
    struct mutex lock;
    size_t max_buf_size;
    size_t size;
    bool stopped;
};

/***************** External Functions *******************/

extern void get_random_bytes(void* buf, int nbytes);

/***************** Procfs Functions *******************/

static int open_proc(struct inode* inode, struct file* file);
static int release_proc(struct inode* inode, struct file* file);
static ssize_t read_proc(struct file* filp,
                         char __user* buffer,
                         size_t length,
                         loff_t* offset);
static ssize_t write_proc(struct file* filp,
                          const char* buff,
                          size_t len,
                          loff_t* off);

/***************** Trusted Storage Functions *******************/

static int trusted_storage_read_fn(struct trusted_storage* ts,
                                   unsigned long key,
                                   void* out_buf,
                                   size_t len);
static int trusted_storage_write_fn(struct trusted_storage* ts,
                                    unsigned long key,
                                    void* in_buf,
                                    size_t len);
static int trusted_storage_init_fn(struct trusted_storage* ts);
static void trusted_storage_exit_fn(struct trusted_storage* ts);

static struct trusted_storage_ops ts_ops = {
    .read = trusted_storage_read_fn,
    .write = trusted_storage_write_fn,
    .init = trusted_storage_init_fn,
    .exit = trusted_storage_exit_fn,
};

static struct trusted_storage ts = {
    .ops = &ts_ops,
    .size = 0,
    .max_buf_size = 64,
    .stopped = false,
};

/*
 * procfs operation sturcture
 */
static struct file_operations proc_fops = {
    .open = open_proc,
    .read = read_proc,
    .write = write_proc,
    .release = release_proc,
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
    char entry_name[20] = {0};
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

    // buf = kmalloc(size, GFP_ATOMIC);
    buf = kmalloc(ts->max_buf_size, GFP_ATOMIC);
    memcpy(buf, in_buf, size);
    radix_tree_insert(&ts->root, key, buf);

    /*Creating Proc entry under "/proc/tse/" */
    sprintf(entry_name, "0x%lx", key);
    proc_create_data(entry_name, 0444, ts->proc_dir, &proc_fops, buf);

out:
    mutex_unlock(&ts->lock);
    return ret;
}

static int trusted_storage_init_fn(struct trusted_storage* ts) {
    mutex_init(&ts->lock);
    INIT_RADIX_TREE(&ts->root, GFP_ATOMIC);

    /*Create proc directory. It will create a directory under "/proc" */
    ts->proc_dir = proc_mkdir_data(PROCFS_DIR, 0444, NULL, ts);

    if (!ts->proc_dir) {
        pr_err("Error creating proc entry " PROCFS_DIR);
        return -1;
    }

    return 0;
}

static void trusted_storage_exit_fn(struct trusted_storage* ts) {
    struct radix_tree_iter iter;
    void** slot;
    void* buf;

    mutex_lock(&ts->lock);
    ts->stopped = true;
    proc_remove(ts->proc_dir);
    ts->proc_dir = NULL;
    mutex_unlock(&ts->lock);

    /* free all bufs */
    radix_tree_for_each_slot(slot, &ts->root, &iter, 0) {
        buf = radix_tree_deref_slot(slot);
        kfree(buf);
        radix_tree_delete(&ts->root, iter.index);
    }

    mutex_destroy(&ts->lock);
}

/***************** Procfs Functions *******************/

static int open_proc(struct inode* inode, struct file* file) {
    return 0;
}

static int release_proc(struct inode* inode, struct file* file) {
    return 0;
}

static ssize_t read_proc(struct file* filp,
                         char __user* buffer,
                         size_t length,
                         loff_t* offset) {
    u8* buf = PDE_DATA(file_inode(filp));
    u8 hex_buf[32] = {0};

    if (len) {
        len = 0;
    } else {
        len = 1;
        return 0;
    }

    // if (copy_to_user(buffer, buf, ts.max_buf_size)) {
    //     pr_err(MODULE_NAME " Data Send : Err!\n");
    // }

    sprintf(hex_buf, "%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n", buf[0],
            buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    if (copy_to_user(buffer, hex_buf, strlen(hex_buf))) {
        pr_err(MODULE_NAME " Data Send : Err!\n");
    }

    return length;
}

static ssize_t write_proc(struct file* filp,
                          const char* buff,
                          size_t len,
                          loff_t* off) {
    return len;
}

static int __init trusted_storage_init(void) {
    pr_info("trusted_storage: init\n");

    return ts.ops->init(&ts);
}

static void __exit trusted_storage_exit(void) {
    pr_info("trusted_storage: exit\n");

    ts.ops->exit(&ts);
}

unsigned long trusted_storage_uuid_gen(void) {
    unsigned long uuid = 0;

    while (1) {
        get_random_bytes(&uuid, sizeof(uuid));
        if (likely(!radix_tree_lookup(&ts.root, uuid)))
            break;
    }

    return uuid;
}
EXPORT_SYMBOL_GPL(trusted_storage_uuid_gen);

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