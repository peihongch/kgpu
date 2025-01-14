#ifndef __DM_SECURITY_H_
#define __DM_SECURITY_H_

#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>

#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rculist.h>
#include <linux/rtnetlink.h> /* for struct rtattr and RTA macros only */
#include <linux/rwsem.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <linux/device-mapper.h>

#include "../crypto/inc-hash/inc-hash.h"
#include "../trusted-storage/trusted-storage.h"

#define DM_SUPER_BLOCK_MAGIC (cpu_to_be64(0x5345435552495459ULL))  // "SECURITY"
#define DM_MSG_PREFIX "security"
#define DEFAULT_CIPHER "aes"
#define DEFAULT_CHAINMODE "xts"
#define DEFAULT_IVMODE "plain64"
#define DEFAULT_HASH "sha512"
#define DEFAULT_INC_HASH "inc_hash-sha512"
#define CIPHERMODE DEFAULT_CHAINMODE "(" DEFAULT_CIPHER ")"
#define HMAC "hmac(" DEFAULT_HASH ")"
#define AUTHCIPHER "gauthenc(" HMAC "," CIPHERMODE ")"
#define AUTHSIZE (64)

#define HASH_FLUSH_TIMEOUT (1 * HZ)
#define HASH_PREFETCH_TIMEOUT (1 * HZ)
#define CACHE_TRANSFER_TIMEOUT (1 * HZ)

#define HASH_NODES_CACHE_CAPACITY (256)         // 256 nodes = 4MB
#define DATA_BLOCKS_CACHE_CAPACITY (256 * 128)  // 256 * 64 blocks = 64MB

typedef unsigned int block_t;

/*
 * Data structure for dm-security device super block
 */
struct security_super_block {
    u64 magic;               /* super block identifier - SECURITY */
    u64 root_hash_key;       /* key of root hash in trusted storage */
    u64 data_start;          /* data offset in 512B sectors */
    u64 hash_start;          /* hash offert in 512B sectors */
    u64 data_area_size;      /* data area size in 512B sectors */
    u64 hash_area_size;      /* hash area size in 512B sectors */
    u32 data_blocks;         /* number of data blocks */
    u32 hash_blocks;         /* number of hash blocks */
    u8 data_block_bits;      /* log2(data blocksize) */
    u8 hash_block_bits;      /* log2(hash blocksize) */
    u8 hash_node_bits;       /* log2(hash leaf/mediate node size) */
    u8 hash_per_block_bits;  /* log2(hashes in hash block) */
    u8 leaves_per_node_bits; /* log2(leaves per mediate node) */
    u32 hash_leaf_nodes;     /* number of hash tree leaves */
    u32 hash_mediate_nodes;  /* number of hash tree mediate nodes */
    u8 sb_mac[AUTHSIZE];     /* hmac of super block */
    u8 padding[0];

    /* private fields used only during runtime */
    struct mutex lock;
};

/* Data structure for dm-security device hash tree mediate node */
struct security_mediate_node {
    size_t index;
    size_t dirty;   /* Number of modified leaf nodes in cache */
    bool corrupted; /* Indicate if leaf nodes in cache passed verification */
    bool cached;    /* Indicate if leaf nodes in cache */
    struct dm_security* s;
    struct mutex lock;
    struct list_head lru_item;
    struct security_leaf_node** leaves; /* Cached leaf nodes if not NULL */
    /*
     * TODO : Make the digests of all mediate nodes continuous in physical
     * memory to gain better IO performance ?
     */
    u8 digest[AUTHSIZE];
};

/* Data structure for dm-security device hash tree leaf node */
struct security_leaf_node {
    size_t index;   /* Index of leaf node in hash tree */
    bool dirty;     /* Indicate if leaf nodes in cache modified */
    bool verified;  /* Indicate if leaf nodes in cache verified */
    bool corrupted; /* Indicate if leaf nodes in cache passed verification */
    struct security_mediate_node* parent;
    struct list_head flush_list;  /* List of leaf nodes to be flushed */
    struct rb_node flush_rb_node; /* Red-black tree node for flush list */
    struct mutex lock;
    atomic_t ref_count; /* Reference count of leaf node */
    u8 digest[AUTHSIZE];
};

/* Data structure for dm-security device data block */
struct security_data_block {
    sector_t start;            /* Start sector number of data block */
    struct mutex lock;         /* Lock for data block */
    struct list_head lru_item; /* List item for LRU list */
    atomic_t ref_count;        /* Reference count of data block */
    bool dirty;                /* Indicate if data block modified */
    void* buf;                 /* buffer for data block */
};

struct hash_prefetch_item {
    struct list_head list;      /* list_head for prefetch queue */
    struct list_head wait_list; /* set of hash io waiting for prefetch item */
    struct rb_node rb_node;     /* rbtree node for prefetch rbtree */
    struct mutex lock;          /* lock for hash prefetch item */
    size_t start;               /* start index of hash blocks to prefetch */
    size_t count;               /* number of hash blocks to prefetch */
};

struct mediate_node_hash_delta {
    struct list_head list;
    size_t index;
    u8 digest[AUTHSIZE];
};

struct hash_update_item {
    struct list_head list;            /* list_head for update queue */
    struct list_head delta_list;      /* list of mediate node hash deltas */
    struct mutex lock;                /* lock for hash update item */
    struct security_hash_io* base_io; /* base hash io for update */
};

struct cache_transfer_item {
    struct list_head list;     /* list_head for transfer queue */
    struct dm_security_io* io; /* io to transfer */
};

/*
 * private data hold by format bio
 */
struct security_rebuild_data {
    struct dm_security* s;
    struct completion restart; /* used for data blocks read io */
    struct semaphore sema;     /* used for leaf nodes write io */
    int error;
};

/*
 * context holding the current state of a multi-part conversion
 */
struct convert_context {
    struct completion restart;
    struct bio* bio_in;
    struct bio* bio_out;
    struct bio* bio_tag;
    unsigned int offset_in;
    unsigned int offset_out;
    unsigned int offset_tag;
    unsigned int idx_in;
    unsigned int idx_out;
    unsigned int idx_tag;
    sector_t s_sector;
    atomic_t s_pending;
};

/*
 * per super block bio private data
 */
struct security_super_block_io {
    struct dm_security* s;
    struct bio* base_bio;
    struct work_struct work;

    atomic_t io_pending;
    int error;
    struct completion restart;
    struct security_super_block_io* base_io;
};

/*
 * per hash tree node bio private data
 */
struct security_hash_io {
    struct dm_security* s;
    struct bio* bio;
    struct work_struct work;
    struct list_head list;
    struct hash_prefetch_item* prefetch;

    atomic_t io_pending;
    int error;
    size_t offset; /* leaf node index of hash tree */
    size_t count;  /* number of leaf nodes to read/write */
    struct completion restart;
    struct dm_security_io* base_io;
};

/*
 * per bio private data
 */
struct dm_security_io {
    struct dm_security* s;
    struct bio* bio;
    struct bio* hash_bio;
    struct work_struct work;

    struct convert_context ctx;

    atomic_t io_pending;
    int error;
    sector_t sector; /* start sector in data area */
    struct security_hash_io* hash_io;
    struct dm_security_io* base_io;
};

struct dm_security_request {
    struct convert_context* ctx;
    struct scatterlist* sg_in;
    struct scatterlist* sg_out;
    struct scatterlist sg_assoc;
    sector_t iv_sector;
};

/*
 * Duplicated per-CPU state for cipher.
 */
struct security_cpu {
    struct aead_request* req;
};

struct security_hash_task {
    struct task_struct* task;
    struct task_struct* pre_task;
    struct completion pre_wait;
    struct completion wait;
    struct list_head pre_queue;
    struct list_head queue;
    struct mutex pre_queue_lock;
    struct mutex queue_lock;
    struct rb_root rbtree_root;
    bool stopped;
};

struct security_cache_task {
    struct task_struct* task;
    struct completion wait;
    struct list_head queue;
    struct mutex queue_lock;
    bool stopped;
};

struct hash_nodes_cache {
    struct mutex lock;         /* lock for hash nodes cache */
    struct list_head lru_list; /* LRU list for hash nodes */
    size_t size;               /* number of hash nodes in cache */
    size_t capacity;           /* capacity of hash nodes cache */
};

struct data_blocks_cache {
    struct mutex lock;              /* lock for radix tree */
    struct radix_tree_root rt_root; /* radix tree cache for data blocks */
    struct list_head lru_list;      /* LRU list for data blocks */
    size_t size;                    /* number of data blocks in cache */
    size_t capacity;                /* capacity of data blocks cache */
};

/*
 * The fields in here must be read only after initialization,
 * changing state should be in security_cpu.
 */
struct dm_security {
    struct dm_dev* dev;
    struct dm_target* ti;
    sector_t start;

    struct mutex root_hash_lock; /* lock for root hash */
    u8 root_hash[AUTHSIZE];      /* root hash of hash tree */

    struct security_super_block* sb;
    struct security_mediate_node** mediate_nodes;
    struct security_hash_task hash_flusher;
    struct security_hash_task hash_prefetcher;
    struct security_cache_task cache_transferer;
    struct hash_nodes_cache hash_nodes_cache;
    struct data_blocks_cache data_blocks_cache;

    unsigned long root_hash_key;       /* key of root hash in trusted storage */
    sector_t sb_start;                 /* super block start in 512B sectors */
    sector_t data_start;               /* data offset in 512B sectors */
    sector_t hash_start;               /* hash offert in 512B sectors */
    sector_t data_area_size;           /* data area size in 512B sectors */
    sector_t hash_area_size;           /* hash area size in 512B sectors */
    block_t data_blocks;               /* number of data blocks */
    block_t hash_blocks;               /* number of hash blocks */
    unsigned char data_block_bits;     /* log2(data blocksize) */
    unsigned char hash_block_bits;     /* log2(hash blocksize) */
    unsigned char hash_node_bits;      /* log2(hash leaf/mediate node size) */
    unsigned char hash_per_block_bits; /* log2(hashes in hash block) */
    unsigned char leaves_per_node_bits; /* log2(leaves per mediate node) */
    unsigned int hash_leaf_nodes;       /* number of hash tree leaves */
    unsigned int hash_mediate_nodes;    /* number of hash tree mediate nodes */

    /*
     * pool for per bio private data, crypto requests and
     * encryption requeusts/buffer pages
     */
    mempool_t* io_pool;
    mempool_t* super_block_io_pool;
    mempool_t* hash_io_pool;
    mempool_t* req_pool;
    mempool_t* page_pool;
    mempool_t* leaf_node_pool;

    struct bio_set* bs;
    struct mutex bio_alloc_lock;

    struct workqueue_struct* io_queue;
    struct workqueue_struct* hash_queue;
    struct workqueue_struct* security_queue;

    char* cipher_string;

    struct security_iv_operations* iv_gen_ops;
    unsigned int iv_size;

    /*
     * Duplicated per cpu state. Access through
     * per_cpu_ptr() only.
     */
    struct security_cpu __percpu* cpu;

    struct crypto_aead* tfm;       /* AEAD used for data blocks */
    struct crypto_shash* hash_tfm; /* Hash Function used for hash tree */
    struct crypto_shash* hmac_tfm; /* HMAC used for super block */
    struct shash_desc* hash_desc;  /* Hash Function shash object */
    struct shash_desc* hmac_desc;  /* HMAC shash object */

    uint8_t* hmac_digest;      /* HMAC digest */
    uint32_t hmac_digest_size; /* HMAC hash digest size */

    /*
     * Layout of each crypto request:
     *
     *   struct aead_request
     *      context
     *      (no padding)
     *   struct dm_security_request
     *      (no padding)
     *   IV
     *
     * The padding is removed for convenient test.
     */
    unsigned int dmreq_start;

    unsigned long flags;
    unsigned int key_size;
    unsigned int key_mac_size; /* MAC key size for authenc(...) */

    u8* authenc_key; /* space for keys in authenc() format (if used) */
    u8 key[0];
};

struct security_iv_operations {
    int (*generator)(struct dm_security* s,
                     u8* iv,
                     struct dm_security_request* dmreq);
};

#define init_hash_nodes_cache(cache)                   \
    do {                                               \
        mutex_init(&(cache)->lock);                    \
        INIT_LIST_HEAD(&(cache)->lru_list);            \
        (cache)->size = 0;                             \
        (cache)->capacity = HASH_NODES_CACHE_CAPACITY; \
    } while (0)

#define init_data_blocks_cache(cache, mask)             \
    do {                                                \
        mutex_init(&(cache)->lock);                     \
        INIT_RADIX_TREE(&(cache)->rt_root, (mask));     \
        INIT_LIST_HEAD(&(cache)->lru_list);             \
        (cache)->size = 0;                              \
        (cache)->capacity = DATA_BLOCKS_CACHE_CAPACITY; \
    } while (0)

#define init_hash_prefetch_item(item, s, c) \
    do {                                    \
        INIT_LIST_HEAD(&(item)->wait_list); \
        mutex_init(&(item)->lock);          \
        (item)->start = (s);                \
        (item)->count = (c);                \
    } while (0)

#define DIV_ROUND_UP_BITS(x, bits) (((x) + (1 << (bits)) - 1) >> (bits))
#define MASK_BITS(x, bits) ((x) & ((1 << (bits)) - 1))
#define UMASK_BITS(x, bits) ((x) & ~((1 << (bits)) - 1))

#define mediate_node_idx_of_block(s, block) \
    ((block) / (1 << (s)->leaves_per_node_bits))
#define mediate_node_of_block(s, block) \
    ((s)->mediate_nodes[mediate_node_idx_of_block((s), (block))])
#define leaf_node_of_block(s, block)     \
    (mediate_node_of_block((s), (block)) \
         ->leaves[((block) & ((1 << (s)->leaves_per_node_bits) - 1))])
/* leaf sector in hash area */
#define leaf_sector_of_block(s, block) ((block) >> (s)->hash_per_block_bits)

#define hash_node_size(s) (1 << (s)->hash_node_bits)

#define data_area_size(s) ((s)->data_blocks << (s)->data_block_bits)
#define data_area_sectors(s) \
    ((s)->data_blocks << ((s)->data_block_bits - SECTOR_SHIFT))
#define data_block_of_sector(s, sector) \
    ((sector) >> ((s)->data_block_bits - SECTOR_SHIFT))

/* dm-security generic operations */

void security_io_bind(struct dm_security_io* io,
                      struct security_hash_io* hash_io);
void security_free_buffer_pages(struct dm_security* s, struct bio* bio);
void security_inc_pending(struct dm_security_io* io);
void security_dec_pending(struct dm_security_io* io);
sector_t security_map_data_sector(struct dm_security* s, sector_t bi_sector);
sector_t security_map_hash_sector(struct dm_security* s, sector_t bi_sector);

/* dm-security super block related operations */

void security_super_block_dump(struct dm_security* s);
void security_super_block_load(struct dm_security* s);
struct security_super_block_io* security_super_block_io_alloc(
    struct dm_security* s);
void security_super_block_io_free(struct security_super_block_io* io);
int ksecurityd_super_block_io_read(struct security_super_block_io* io);
void ksecurityd_super_block_io_write(struct security_super_block_io* io);

/* dm-security hash tree related operations */

inline struct security_mediate_node* security_get_mediate_node(
    struct dm_security* s,
    sector_t sector);
struct security_leaf_node* security_get_leaf_node(struct dm_security* s,
                                                  size_t index);
void security_put_leaf_node(struct security_leaf_node* ln);
int security_prefetch_hash_leaves(struct security_hash_io* io);
int security_hash_alloc_buffer(struct security_hash_io* io);
void security_hash_io_free(struct security_hash_io* io);
struct security_hash_io* security_hash_io_alloc(struct dm_security* s,
                                                size_t offset,
                                                size_t count);
void security_hash_io_merge(struct security_hash_io* io,
                            struct security_hash_io* new_io,
                            bool fast);
struct security_hash_io* security_hash_io_split(struct security_hash_io* io,
                                                size_t offset,
                                                bool discard);
int security_mediate_nodes_init(struct dm_security* s);
void security_mediate_nodes_free(struct dm_security* s);
void security_leaf_node_inc_ref(struct security_leaf_node* ln);
void security_leaf_node_dec_ref(struct security_leaf_node* ln);
void security_leaf_node_init(struct security_leaf_node* ln,
                             struct security_mediate_node* mn,
                             size_t index);
void security_leaf_node_free(struct security_leaf_node* ln);
void security_leaf_node_cache(struct security_leaf_node* ln);
void security_leaf_node_update(struct security_leaf_node* ln,
                               struct security_hash_io* io);
void security_leaves_cache_clean(struct security_mediate_node* mn);
void security_leaves_cache_add(struct security_mediate_node* mn,
                               struct security_leaf_node** leaves);
void ksecurityd_queue_hash(struct security_hash_io* io);
int security_hash_flush(void* data);
int security_hash_pre_prefetch(void* data);
int security_hash_prefetch(void* data);
int security_hash_update(void* data);
int security_hash_task_start(struct security_hash_task* sht,
                             void* owner,
                             char* name,
                             int (*fn)(void* data),
                             int (*pre_fn)(void* data));
void security_hash_task_stop(struct security_hash_task* sht);

/* dm-security data blocks cache related operations */

struct security_data_block* security_data_block_alloc(struct dm_security* s,
                                                      sector_t sector);
void security_data_block_free(struct security_data_block* data_block);
int security_cache_lookup_one(struct dm_security* s, sector_t start);
int security_cache_lookup(struct dm_security* s, struct dm_security_io* io);
int security_cache_evict(struct dm_security* s, block_t blocks);
int security_cache_merge(struct dm_security* s, struct dm_security_io* io);
int security_cache_insert(struct dm_security* s, struct dm_security_io* io);
void security_queue_cache(struct dm_security_io* io);
int security_cache_transfer(void* data);
int security_cache_task_start(struct security_cache_task* sht,
                              void* owner,
                              char* name,
                              int (*fn)(void* data));
void security_cache_task_stop(struct security_cache_task* sht);

/* dm-security convertion logic related operations */
void security_convert_init(struct dm_security* s,
                           struct convert_context* ctx,
                           struct bio* bio_out,
                           struct bio* bio_in,
                           struct bio* bio_tag,
                           sector_t sector);
int security_convert(struct dm_security* s, struct convert_context* ctx);
struct dm_security_io* security_io_alloc(struct dm_security* s,
                                         struct bio* bio,
                                         sector_t sector);
int ksecurityd_io_read(struct dm_security_io* io, gfp_t gfp);
void ksecurityd_queue_io(struct dm_security_io* io);
void ksecurityd_queue_security(struct dm_security_io* io);
void ksecurityd_security_write_io_submit(struct dm_security_io* io, int async);

#endif /* DM_SECURITY_H */