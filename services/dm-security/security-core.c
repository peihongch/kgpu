/*
 * Copyright (C) 2003 Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2009 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022-2023 Peihong Chen <mf21320017@smail.nju.edu.cn>
 *
 * This file is released under the GPL.
 */
#include <linux/vmalloc.h>
#include "dm-security.h"

#define DEFAULT_DM_SUPER_BLOCK_SIZE (512)    // 512 bytes
#define DEFAULT_DM_DATA_BLOCK_SIZE (4096)    // 4KB
#define DEFAULT_DM_HASH_BLOCK_SIZE (512)     // 512 bytes
#define DEFAULT_DM_JOURNAL_BLOCK_SIZE (512)  // 512 bytes
#define DEFAULT_DM_METADATA_RATIO (64)       // 64:1
#define DEFAULT_DM_METADATA_RATIO_SHIFT \
    (ffs(DEFAULT_DM_METADATA_RATIO) - 1)  // 2^6
#define DEFAULT_LEAVES_PER_NODE (256)

/*
 * Security: maps a linear range of a block device
 * and do authenticated encryption / decryption at the same time.
 */
enum flags { DM_SECURITY_SUSPENDED, DM_SECURITY_KEY_VALID };

#define MIN_IOS 16
#define MIN_POOL_PAGES 32
#define MIN_LEAVES 256

static struct kmem_cache* _security_io_pool;
static struct kmem_cache* _super_block_io_pool;
static struct kmem_cache* _hash_io_pool;
static struct kmem_cache* _leaf_node_pool;

#define data_size_per_mediate_node_shift(s) \
    ((s)->data_block_bits + (s)->leaves_per_node_bits)
#define data_size_per_mediate_node(s) (1 << data_size_per_mediate_node_shift(s))

/*
 * Different IV generation algorithms:
 *
 * plain: the initial vector is the 32-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64: the initial vector is the 64-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * null: the initial vector is always zero.  Provides compatibility with
 *       obsolete loop_fish2 devices.  Do not use for new devices.
 */

static int security_iv_plain_gen(struct dm_security* s,
                                 u8* iv,
                                 struct dm_security_request* dmreq) {
    memset(iv, 0, s->iv_size);
    *(__le32*)iv = cpu_to_le32(dmreq->iv_sector & 0xffffffff);

    return 0;
}

static int security_iv_plain64_gen(struct dm_security* s,
                                   u8* iv,
                                   struct dm_security_request* dmreq) {
    memset(iv, 0, s->iv_size);
    *(__le64*)iv = cpu_to_le64(dmreq->iv_sector);

    return 0;
}

static int security_iv_null_gen(struct dm_security* s,
                                u8* iv,
                                struct dm_security_request* dmreq) {
    memset(iv, 0, s->iv_size);

    return 0;
}

static struct security_iv_operations security_iv_plain_ops = {
    .generator = security_iv_plain_gen};

static struct security_iv_operations security_iv_plain64_ops = {
    .generator = security_iv_plain64_gen};

static struct security_iv_operations security_iv_null_ops = {
    .generator = security_iv_null_gen};

static void security_free_tfm(struct dm_security* s) {
    if (!s->tfm)
        return;

    if (s->tfm && !IS_ERR(s->tfm)) {
        crypto_free_aead(s->tfm);
        s->tfm = NULL;
    }
}

static int security_alloc_tfm(struct dm_security* s, char* ciphermode) {
    int err;

    s->tfm = crypto_alloc_aead(ciphermode, 0, 0);
    if (IS_ERR(s->tfm)) {
        err = PTR_ERR(s->tfm);
        security_free_tfm(s);
        return err;
    }

    return 0;
}

static unsigned security_authenckey_size(struct dm_security* s) {
    return s->key_size + RTA_SPACE(sizeof(struct crypto_authenc_key_param));
}

/*
 * If AEAD is composed like authenc(hmac(sha512),xts(aes)),
 * the key must be for some reason in special format.
 * This funcion converts s->key to this special format.
 *
 * | rta length | rta type | enckey length | authkey | enckey |
 *         ↑        ↑              ↑
 *      (little endian)      (big endian)
 */
static void security_copy_authenckey(char* p,
                                     const void* key,
                                     unsigned enckeylen,
                                     unsigned authkeylen) {
    struct crypto_authenc_key_param* param;
    struct rtattr* rta;

    rta = (struct rtattr*)p;
    param = RTA_DATA(rta);
    param->enckeylen = cpu_to_be32(enckeylen);
    rta->rta_len = RTA_LENGTH(sizeof(*param));
    rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
    p += RTA_SPACE(sizeof(*param));
    memcpy(p, key + enckeylen, authkeylen);
    p += authkeylen;
    memcpy(p, key, enckeylen);
}

static int security_setkey_allcpus(struct dm_security* s) {
    int ret;

    ret = crypto_shash_setkey(
        s->hmac_tfm, s->key + (s->key_size - s->key_mac_size), s->key_mac_size);
    if (ret < 0)
        goto bad;

    security_copy_authenckey(s->authenc_key, s->key,
                             s->key_size - s->key_mac_size, s->key_mac_size);
    ret =
        crypto_aead_setkey(s->tfm, s->authenc_key, security_authenckey_size(s));
    if (ret)
        goto bad;

    ret = 0;
bad:
    memzero_explicit(s->authenc_key, security_authenckey_size(s));
    return ret;
}

static int security_set_key(struct dm_security* s, char* key) {
    int r = -EINVAL;
    int key_string_len = strlen(key);

    /* The key size may not be changed. */
    if (s->key_size != (key_string_len >> 1))
        goto out;

    /* Hyphen (which gives a key_size of zero) means there is no key. */
    if (!s->key_size && strcmp(key, "-"))
        goto out;

    if (s->key_size && hex2bin(s->key, key, s->key_size) < 0)
        goto out;

    set_bit(DM_SECURITY_KEY_VALID, &s->flags);

    r = security_setkey_allcpus(s);

out:
    /* Hex key string not needed after here, so wipe it. */
    memset(key, '0', key_string_len);

    return r;
}

static int security_wipe_key(struct dm_security* s) {
    clear_bit(DM_SECURITY_KEY_VALID, &s->flags);
    memset(&s->key, 0, s->key_size * sizeof(u8));

    return security_setkey_allcpus(s);
}

/*
 * Workaround to parse HMAC algorithm from AEAD crypto API spec.
 * The HMAC is needed to calculate tag size (HMAC digest size).
 * This should be probably done by crypto-api calls (once available...)
 */
static int security_ctr_auth_cipher(struct dm_security* s, char* mac_alg) {
    struct crypto_ahash* mac;

    mac = crypto_alloc_ahash(mac_alg, 0, 0);
    if (IS_ERR(mac))
        return PTR_ERR(mac);

    s->key_mac_size = crypto_ahash_digestsize(mac);
    crypto_free_ahash(mac);

    s->authenc_key = kmalloc(security_authenckey_size(s), GFP_KERNEL);
    if (!s->authenc_key)
        return -ENOMEM;

    return 0;
}

static int security_ctr_hash_cipher(struct dm_security* s, char* inc_hash_alg) {
    struct dm_target* ti = s->ti;
    int ret = 0;

    s->hash_tfm = crypto_alloc_shash(inc_hash_alg, 0, 0);
    if (IS_ERR(s->hash_tfm)) {
        ret = PTR_ERR(s->hash_tfm);
        ti->error = "Cannot allocate SHASH TFM structure";
        goto bad;
    }

    s->hash_desc =
        kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(s->hash_tfm),
                GFP_KERNEL);
    if (IS_ERR(s->hash_desc)) {
        crypto_free_shash(s->hash_tfm);
        ret = -ENOMEM;
        ti->error = "Cannot allocate SHASH Desc structure";
        goto bad;
    }

    s->hash_desc->tfm = s->hash_tfm;
    s->hash_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

bad:
    return ret;
}

static int security_ctr_mac_cipher(struct dm_security* s, char* mac_alg) {
    struct dm_target* ti = s->ti;
    int ret;

    s->hmac_tfm = crypto_alloc_shash(mac_alg, 0, 0);
    if (IS_ERR(s->hmac_tfm)) {
        ti->error = "Cannot initialize hash function";
        ret = PTR_ERR(s->hmac_tfm);
        s->hmac_tfm = NULL;
        goto bad;
    }
    s->hmac_digest_size = crypto_shash_digestsize(s->hmac_tfm);

    ret = -ENOMEM;
    s->hmac_desc =
        kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(s->hmac_tfm),
                GFP_KERNEL);
    if (!s->hmac_desc) {
        ti->error = "Cannot allocate HMAC Desc structure";
        goto bad;
    }

    s->hmac_digest = kzalloc(s->hmac_digest_size, GFP_KERNEL);
    if (!s->hmac_digest) {
        ti->error = "Cannot allocate mintegrity structure";
        goto bad;
    }

    s->hmac_desc->tfm = s->hmac_tfm;
    s->hmac_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

    ret = 0;
bad:
    return ret;
}

static int security_ctr_cipher(struct dm_target* ti, char* key) {
    struct dm_security* s = ti->private;
    const char* ivmode = DEFAULT_IVMODE;
    int ret = -EINVAL;

    s->cipher_string = kstrdup(AUTHCIPHER, GFP_KERNEL);
    if (!s->cipher_string)
        goto bad_mem;

    s->cpu =
        __alloc_percpu(sizeof(*(s->cpu)), __alignof__(struct security_cpu));
    if (!s->cpu) {
        ti->error = "Cannot allocate per cpu state";
        goto bad_mem;
    }

    /* Allocate cipher */
    DMINFO("Auth Cipher : %s", AUTHCIPHER);
    ret = security_alloc_tfm(s, AUTHCIPHER);
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        goto bad;
    }

    /* Alloc AEAD, can be used only in new format. */
    ret = security_ctr_auth_cipher(s, HMAC);
    if (ret < 0) {
        ti->error = "Invalid AEAD cipher spec";
        return -ENOMEM;
    }

    /* Alloc IncHash used for hash tree */
    ret = security_ctr_hash_cipher(s, DEFAULT_INC_HASH);
    if (ret < 0) {
        ti->error = "Invalid IncHash cipher spec";
        return -ENOMEM;
    }

    /* Alloc HMAC used for super block */
    ret = security_ctr_mac_cipher(s, HMAC);
    if (ret < 0) {
        ti->error = "Invalid HMAC cipher spec";
        return -ENOMEM;
    }

    /* Initialize IV */
    /* at least a 64 bit sector number should fit in our buffer */
    s->iv_size = max(crypto_aead_ivsize(s->tfm),
                     (unsigned int)(sizeof(u64) / sizeof(u8)));

    /* Initialize and set key */
    ret = security_set_key(s, key);
    if (ret < 0) {
        ti->error = "Error decoding and setting key";
        goto bad;
    }

    /* Set authsize */
    ret = crypto_aead_setauthsize(s->tfm, AUTHSIZE);
    if (ret) {
        ti->error = "Error setting authsize";
        goto bad;
    }

    /* Choose ivmode, see comments at iv code. */
    if (ivmode == NULL)
        s->iv_gen_ops = NULL;
    else if (strcmp(ivmode, "plain") == 0)
        s->iv_gen_ops = &security_iv_plain_ops;
    else if (strcmp(ivmode, "plain64") == 0)
        s->iv_gen_ops = &security_iv_plain64_ops;
    else if (strcmp(ivmode, "null") == 0)
        s->iv_gen_ops = &security_iv_null_ops;
    else {
        ret = -EINVAL;
        ti->error = "Invalid IV mode";
        goto bad;
    }

    ret = 0;
bad:
    return ret;

bad_mem:
    ti->error = "Cannot allocate cipher strings";
    return -ENOMEM;
}

static void security_rebuild_read_convert(struct bio* bio,
                                          struct bio* hash_bio) {
    struct security_rebuild_data* data = bio->bi_private;
    struct dm_security* s = data->s;
    struct convert_context ctx;

    security_convert_init(s, &ctx, bio, bio, hash_bio, bio->bi_sector);

    data->error = security_convert(s, &ctx);
}

static void security_rebuild_endio(struct bio* bio, int error) {
    struct security_rebuild_data* data = bio->bi_private;
    unsigned rw = bio_data_dir(bio);

    if (unlikely(!bio_flagged(bio, BIO_UPTODATE) && !error))
        error = -EIO;

    if (error)
        DMERR(
            "security_rebuild_endio: I/O error %d, bi_sector %lu, bi_size %u, "
            "rw %s",
            error, bio->bi_sector, bio->bi_size, rw == READ ? "READ" : "WRITE");

    if (unlikely(error))
        data->error = error;

    if (rw == WRITE)
        up(&data->sema);

    bio_put(bio);

    if (rw == READ && !error)
        complete(&data->restart);
}

/**
 * Format disk layout during initial construction for dm-security
 */
static int security_metadata_rebuild(struct dm_target* ti, u8* root_hash) {
    struct dm_security* s = ti->private;
    struct security_mediate_node* mn;
    struct security_rebuild_data data;
    struct inc_hash_ctx *mn_ctx = NULL, *ln_ctx = NULL, *ctx;
    struct bio *bio = NULL, *clone = NULL, *hash_bio = NULL;
    struct page* page;
    unsigned totals =
        DIV_ROUND_UP_BITS(s->data_blocks << s->data_block_bits, PAGE_SHIFT);
    unsigned remainings = totals;
    unsigned nr_iovecs;
    unsigned leaves_per_node = (1 << s->leaves_per_node_bits);
    unsigned mn_step =
        DIV_ROUND_UP_BITS((leaves_per_node << s->data_block_bits), PAGE_SHIFT);
    unsigned ln_step = DIV_ROUND_UP_BITS(
        ((leaves_per_node >> 2) << s->data_block_bits), PAGE_SHIFT);
    unsigned digestsize = hash_node_size(s);
    /* make ctx->data in one page */
    size_t ctx_size =
        roundup(sizeof(struct inc_hash_ctx) + digestsize, digestsize);
    sector_t sector = 0;
    gfp_t gfp_mask = GFP_NOIO | __GFP_HIGHMEM;
    int i, j, ret = 0, offset, ln_idx;

    DMINFO("Start device formatting to build metadata");

    /* alloc mediate nodes buffer */
    ret = security_mediate_nodes_init(s);
    if (ret) {
        ti->error = "Cannot allocate mediate nodes";
        goto bad;
    }

    mn_ctx = kmalloc(ctx_size * (ln_step + 1), GFP_KERNEL);
    if (!mn_ctx) {
        ti->error = "Cannot allocate incremental hash context";
        ret = -ENOMEM;
        goto bad;
    }
    mn_ctx->old_len = 0;

    ln_ctx = (void*)mn_ctx + ctx_size;

    data.s = s;
    data.error = 0;
    sema_init(&data.sema, 1);
    /* FIXME : make it more efficient? */
    i = 0;
    offset = 0;
    ln_idx = 0;
    while (remainings) {
        init_completion(&data.restart);
        /* alloc data bio */
        nr_iovecs = min(remainings, ln_step);
        bio = bio_alloc_bioset(GFP_NOIO, nr_iovecs, s->bs);
        bio->bi_private = &data;
        bio->bi_end_io = security_rebuild_endio;
        bio->bi_bdev = s->dev->bdev;
        bio->bi_sector = sector;
        bio->bi_rw |= READ;
        if (unlikely(!(remainings & ((1 << 15) - 1))))
            DMINFO("metadata rebuild progress: [ %u / 100 ]",
                   100 * (totals - remainings) / totals);

        for (j = 0; j < nr_iovecs; j++) {
            page = mempool_alloc(s->page_pool, gfp_mask);
            if (!bio_add_page(bio, page, PAGE_SIZE, 0)) {
                mempool_free(page, s->page_pool);
                break;
            }
        }
        offset += nr_iovecs;

        clone = bio_clone_bioset(bio, GFP_NOIO, s->bs);
        if (!clone) {
            ret = -ENOMEM;
            goto bad;
        }
        clone->bi_private = bio->bi_private;
        clone->bi_end_io = bio->bi_end_io;
        clone->bi_bdev = bio->bi_bdev;
        clone->bi_rw = bio->bi_rw;
        clone->bi_sector = security_map_data_sector(s, bio->bi_sector);

        generic_make_request(clone);
        wait_for_completion(&data.restart);

        /* save leaf nodes to hash area */
        hash_bio = bio_alloc_bioset(GFP_KERNEL, nr_iovecs, s->bs);
        if (!hash_bio) {
            ret = -ENOMEM;
            goto bad;
        }
        hash_bio->bi_private = &data;
        hash_bio->bi_end_io = security_rebuild_endio;
        hash_bio->bi_bdev = s->dev->bdev;
        hash_bio->bi_sector = security_map_hash_sector(
            s, leaf_sector_of_block(s, data_block_of_sector(s, sector)));
        hash_bio->bi_rw = WRITE;
        for (j = 0; j < nr_iovecs; j++) {
            ctx = (void*)ln_ctx + j * ctx_size;
            if (!bio_add_page(hash_bio, virt_to_page(ctx->data), digestsize,
                              offset_in_page(ctx->data)))
                break;
        }

        /* decrypt data blocks and output authenticated tag to hash_bio */
        security_rebuild_read_convert(bio, hash_bio);
        /* where is suitable to release pages and bio */
        security_free_buffer_pages(s, bio);
        bio_put(bio);

        if (data.error) {
            ret = data.error;
            goto bad;
        }

        down(&data.sema);
        generic_make_request(hash_bio);

        mn = s->mediate_nodes[i];
        /* calculate mediate node hash value */
        for (j = 0; j < nr_iovecs; j++) {
            ctx = (void*)ln_ctx + j * ctx_size;
            /* use leaf node index as inc hash id instead of block sector */
            ctx->id = ln_idx++;
            ctx->old_len = 0;
            ret = crypto_shash_digest(s->hash_desc, (const u8*)ctx, digestsize,
                                      mn->digest);
            if (ret)
                goto bad;
        }

        remainings -= nr_iovecs;
        sector += ln_step << (PAGE_SHIFT - SECTOR_SHIFT);

        /* calculate root hash step by step using incremental hash function */
        if (offset >= mn_step || remainings == 0) {
            mn_ctx->id = i;
            memcpy(mn_ctx->data, mn->digest, digestsize);
            ret = crypto_shash_digest(s->hash_desc, (const u8*)mn_ctx,
                                      digestsize, root_hash);
            if (ret)
                goto bad;

            offset = 0;
            i++;
        }
    }
    down(&data.sema);

    DMINFO("Root Hash: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x", root_hash[0],
           root_hash[1], root_hash[2], root_hash[3], root_hash[4], root_hash[5],
           root_hash[6], root_hash[7]);

bad:
    if (mn_ctx)
        kfree(mn_ctx);
    return ret;
}

/**
 * Disk layout:
 * | SuperBlock | Hash Area | Data Blocks |
 *
 * Super Block (512B):
 * | Magic | Layout Params | SB HMAC | Padding |
 * |  64B  |      ...      |   64B   | (Rest)  |
 *
 * Note: hash area stores only leaf nodes
 */
static int security_ctr_layout(struct dm_target* ti,
                               char* dev_path,
                               char* start) {
    struct dm_security* s = ti->private;
    struct security_super_block_io* sb_io;
    unsigned long long tmpll;
    unsigned int data_area_size = DEFAULT_DM_DATA_BLOCK_SIZE;
    unsigned int hash_block_size = DEFAULT_DM_HASH_BLOCK_SIZE;
    unsigned int leave_per_node = DEFAULT_LEAVES_PER_NODE;
    unsigned int digestsize = AUTHSIZE;
    u8* saved_root_hash = NULL;
    int ret = -EINVAL;
    char dummy;

    if (dm_get_device(ti, dev_path, dm_table_get_mode(ti->table), &s->dev)) {
        ti->error = "Device lookup failed";
        goto bad;
    }

    if (sscanf(start, "%llu%c", &tmpll, &dummy) != 1) {
        ti->error = "Invalid device sector";
        goto bad;
    }
    s->start = tmpll;
    s->sb_start = s->start;

    s->sb =
        (struct security_super_block*)kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
    if (!s->sb) {
        ti->error = "Cannot allocate super block";
        goto bad;
    }

    /* Read super block from device */
    sb_io = security_super_block_io_alloc(s);
    if (!sb_io) {
        ti->error = "Cannot allocate super block read io";
        goto bad;
    }
    ret = ksecurityd_super_block_io_read(sb_io);
    if (ret < 0) {
        security_super_block_io_free(sb_io);
        ti->error = "Cannot read super block";
        goto bad;
    }

    wait_for_completion(&sb_io->restart);

    if (s->sb->magic == DM_SUPER_BLOCK_MAGIC) {
        /* Super block is valid */
        DMINFO("Super block loaded from device sector %lu", s->sb_start);

        // Check super block hmac first
        if (memcmp(s->hmac_digest, s->sb->sb_mac, AUTHSIZE)) {
            DMERR("Super block courrupted, mac not match");
            DMINFO(
                "  Expect MAC : %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
                "%.2x",
                s->sb->sb_mac[0], s->sb->sb_mac[1], s->sb->sb_mac[2],
                s->sb->sb_mac[3], s->sb->sb_mac[4], s->sb->sb_mac[5],
                s->sb->sb_mac[6], s->sb->sb_mac[7]);
            DMINFO(
                "  Actual MAC : %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
                "%.2x",
                s->hmac_digest[0], s->hmac_digest[1], s->hmac_digest[2],
                s->hmac_digest[3], s->hmac_digest[4], s->hmac_digest[5],
                s->hmac_digest[6], s->hmac_digest[7]);
            ti->error = "Super block courrupted";
            goto sb_corrupted;
        }

        // Load device layout params from disk super block
        security_super_block_load(s);

        /* load root hash from trusted storage (emulator) */
        saved_root_hash = kzalloc(hash_node_size(s) * 2, GFP_KERNEL);
        if (!saved_root_hash) {
            ti->error = "Cannot allocate saved root hash buffer";
            goto bad;
        }

        ret = trusted_storage_read(s->root_hash_key, saved_root_hash,
                                   hash_node_size(s) * 2);
        if (ret) {
            ti->error = "Cannot read saved root hash from trusted storage";
            goto bad;
        }

        goto out;
    }

    /* Super block not available */

    if (!data_area_size || (data_area_size & (data_area_size - 1)) ||
        data_area_size < bdev_logical_block_size(s->dev->bdev) ||
        data_area_size > PAGE_SIZE) {
        ti->error = "Invalid data device block size";
        ret = -EINVAL;
        goto bad;
    }
    s->data_block_bits = ffs(data_area_size) - 1;  // 4KB block

    if (!hash_block_size || (hash_block_size & (hash_block_size - 1)) ||
        hash_block_size < bdev_logical_block_size(s->dev->bdev) ||
        hash_block_size > PAGE_SIZE) {
        ti->error = "Invalid hash device block size";
        ret = -EINVAL;
        goto bad;
    }
    s->hash_block_bits = ffs(hash_block_size) - 1;  // 512B block
    s->hash_node_bits = ffs(AUTHSIZE) - 1;
    s->hash_per_block_bits = ffs(hash_block_size >> s->hash_node_bits) - 1;

    s->leaves_per_node_bits = ffs(leave_per_node) - 1;  // 256 leaves per node

    s->data_blocks = ti->len >> (s->data_block_bits - SECTOR_SHIFT);
    if (s->data_blocks < 1024) {
        ti->error = "Device too small for data blocks";
        goto bad;
    }
    /* 1/64 for super block and hash area */
    s->data_blocks =
        s->data_blocks - (s->data_blocks >> DEFAULT_DM_METADATA_RATIO_SHIFT);
    s->hash_leaf_nodes = s->data_blocks;
    s->hash_mediate_nodes =
        DIV_ROUND_UP_BITS(s->hash_leaf_nodes, s->leaves_per_node_bits);
    s->hash_blocks = s->hash_leaf_nodes >> s->hash_per_block_bits;

    s->data_area_size = s->data_blocks << (s->data_block_bits - SECTOR_SHIFT);
    s->data_start = ti->len - s->data_area_size;  // data area start sector
    s->hash_start = s->sb_start + 1;              // hash area start sector
    s->hash_area_size = s->data_start - s->hash_start;

    s->root_hash_key = trusted_storage_uuid_gen();

    /* Dump device layout params to super block */
    security_super_block_dump(s);

    /* Write super block to device */
    sb_io = security_super_block_io_alloc(s);
    if (!sb_io) {
        ti->error = "Cannot allocate super block write io";
        goto bad;
    }
    ksecurityd_super_block_io_write(sb_io);

    wait_for_completion(&sb_io->restart);
    DMINFO("Super block saved to device sector %lu", s->sb_start);

out:
    /* Set target length to actual data blocks area size */
    ti->len = s->data_area_size;

    /* Rebuild hash tree and save leaf nodes to hash area if necessary */

    memset(s->root_hash, 0, sizeof(s->root_hash));
    ret = security_metadata_rebuild(ti, s->root_hash);
    if (ret < 0) {
        ti->error = "Cannot format deivce";
        goto bad;
    }

    if (likely(saved_root_hash)) {
        /* check if root hashes match if not the first time loading */
        if (memcmp(s->root_hash, saved_root_hash, hash_node_size(s)) &&
            memcmp(s->root_hash, saved_root_hash + hash_node_size(s),
                   hash_node_size(s))) {
            ti->error =
                "Both root hash and backup root hash not match, device data "
                "may corrupted";
            ret = -EINVAL;
            goto bad;
        }
    } else {
        /*
         * Now all root hash and mediate nodes ready, and leaf nodes saved to
         * hash area, now save root hash to trusted storage (emulator)
         */
        DMINFO("Save root hash to trusted storage with key [%lu]",
               s->root_hash_key);
        ret = trusted_storage_write(s->root_hash_key, s->root_hash, digestsize);
        if (ret) {
            ti->error = "Cannot write root hash to trusted storage";
            goto bad;
        }
    }

    ret = 0;

bad:
    DMINFO("===== Disk Layout Params =====");
    DMINFO("Root Hash Key: 0x%.8lx", s->root_hash_key);
    DMINFO("Target Length: %lu", ti->len);
    DMINFO("Target Begin: %lu", ti->begin);
    DMINFO("Super Block Start: %lu", s->sb_start);
    DMINFO("Hash Start: %lu", s->hash_start);
    DMINFO("Hash Area Size: %lu", s->data_start - s->hash_start);
    DMINFO("Data Start: %lu", s->data_start);
    DMINFO("Data Area Size: %lu",
           s->data_blocks << (s->data_block_bits - SECTOR_SHIFT));
    DMINFO("Hash Blocks: %u", s->hash_blocks);
    DMINFO("Data Blocks: %u", s->data_blocks);
    DMINFO("Data Block Size: %u", 1 << s->data_block_bits);
    DMINFO("Hash Block Size: %u", 1 << s->hash_block_bits);
    DMINFO("Hash Per Block: %u", 1 << s->hash_per_block_bits);
    DMINFO("Leaves Per Node: %u", 1 << s->leaves_per_node_bits);
    DMINFO("Hash Tree Leaf Nodes: %u", s->hash_leaf_nodes);
    DMINFO("Hash Tree Mediate Nodes: %u", s->hash_mediate_nodes);
    DMINFO("============ End =============");

sb_corrupted:
    return ret;
}

static void security_dtr(struct dm_target* ti) {
    struct dm_security* s = ti->private;
    struct security_cpu* cpu_sc;
    int cpu;

    ti->private = NULL;

    if (!s)
        return;

    if (s->io_queue) {
        flush_workqueue(s->io_queue);
        destroy_workqueue(s->io_queue);
    }
    if (s->security_queue) {
        flush_workqueue(s->security_queue);
        destroy_workqueue(s->security_queue);
    }
    if (s->hash_queue) {
        flush_workqueue(s->hash_queue);
        destroy_workqueue(s->hash_queue);
    }

    security_hash_task_stop(&s->hash_flusher);
    security_hash_task_stop(&s->hash_prefetcher);
    security_cache_task_stop(&s->cache_transferer);

    if (s->cpu)
        for_each_possible_cpu(cpu) {
            cpu_sc = per_cpu_ptr(s->cpu, cpu);
            if (cpu_sc->req)
                mempool_free(cpu_sc->req, s->req_pool);
        }

    security_free_tfm(s);

    if (s->sb)
        kfree(s->sb);

    if (s->bs)
        bioset_free(s->bs);

    if (s->page_pool)
        mempool_destroy(s->page_pool);
    if (s->req_pool)
        mempool_destroy(s->req_pool);
    if (s->io_pool)
        mempool_destroy(s->io_pool);
    if (s->hash_io_pool)
        mempool_destroy(s->hash_io_pool);
    if (s->super_block_io_pool)
        mempool_destroy(s->super_block_io_pool);

    if (s->dev)
        dm_put_device(ti, s->dev);

    if (s->cpu)
        free_percpu(s->cpu);

    security_mediate_nodes_free(s);
    vfree(s->mediate_nodes);

    kzfree(s->cipher_string);
    kfree(s->hash_desc);
    kfree(s->hmac_desc);
    kfree(s->hmac_digest);

    if (s->hash_tfm)
        crypto_free_shash(s->hash_tfm);
    if (s->hmac_tfm)
        crypto_free_shash(s->hmac_tfm);

    /* Must zero key material before freeing */
    kzfree(s);
}

/*
 * Construct an encryption mapping:
 * <key> <dev_path> <start>
 */
static int security_ctr(struct dm_target* ti, unsigned int argc, char** argv) {
    struct dm_security* s;
    unsigned int key_size;
    int ret;

    if (argc < 3) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

    key_size = strlen(argv[0]) >> 1;

    s = kzalloc(sizeof(*s) + key_size * sizeof(u8), GFP_KERNEL);
    if (!s) {
        ti->error = "Cannot allocate encryption context";
        return -ENOMEM;
    }
    s->key_size = key_size;

    ti->private = s;
    s->ti = ti;

    ret = security_ctr_cipher(ti, argv[0]);
    if (ret < 0)
        goto bad;

    ret = -ENOMEM;

    s->io_pool = mempool_create_slab_pool(MIN_IOS, _security_io_pool);
    if (!s->io_pool) {
        ti->error = "Cannot allocate security io mempool";
        goto bad;
    }

    s->super_block_io_pool =
        mempool_create_slab_pool(MIN_IOS, _super_block_io_pool);
    if (!s->super_block_io_pool) {
        ti->error = "Cannot allocate super block io mempool";
        goto bad;
    }

    s->hash_io_pool = mempool_create_slab_pool(MIN_IOS, _hash_io_pool);
    if (!s->hash_io_pool) {
        ti->error = "Cannot allocate hash io mempool";
        goto bad;
    }

    s->leaf_node_pool = mempool_create_slab_pool(MIN_LEAVES, _leaf_node_pool);
    if (!s->leaf_node_pool) {
        ti->error = "Cannot allocate leaf node mempool";
        goto bad;
    }

    // FIXME : alignment is removed for quick development
    s->dmreq_start = sizeof(struct aead_request);
    s->dmreq_start += crypto_aead_reqsize(s->tfm);  // tfm ctx

    s->req_pool = mempool_create_kmalloc_pool(
        MIN_IOS,
        s->dmreq_start + sizeof(struct dm_security_request) + s->iv_size);
    if (!s->req_pool) {
        ti->error = "Cannot allocate security request mempool";
        goto bad;
    }

    s->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
    if (!s->page_pool) {
        ti->error = "Cannot allocate page mempool";
        goto bad;
    }

    s->bs = bioset_create(MIN_IOS, 0);
    if (!s->bs) {
        ti->error = "Cannot allocate security bioset";
        goto bad;
    }

    mutex_init(&s->bio_alloc_lock);
    mutex_init(&s->root_hash_lock);

    s->io_queue =
        alloc_workqueue("ksecurityd_io", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 1);
    if (!s->io_queue) {
        ti->error = "Couldn't create ksecurityd io queue";
        goto bad;
    }

    s->hash_queue = alloc_workqueue("ksecurityd_hash",
                                    WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 1);
    if (!s->hash_queue) {
        ti->error = "Couldn't create ksecurityd hash queue";
        goto bad;
    }

    s->security_queue = alloc_workqueue(
        "ksecurityd", WQ_NON_REENTRANT | WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!s->security_queue) {
        ti->error = "Couldn't create ksecurityd queue";
        goto bad;
    }

    ti->num_flush_bios = 1;
    ti->discard_zeroes_data_unsupported = true;

    ret = security_ctr_layout(ti, argv[1], argv[2]);
    if (ret < 0)
        goto bad;

    init_hash_nodes_cache(&s->hash_nodes_cache);
    init_data_blocks_cache(&s->data_blocks_cache, GFP_ATOMIC | GFP_KERNEL);

    ret = security_hash_task_start(&s->hash_flusher, s, "hash_flusher",
                                   security_hash_flush, NULL);
    if (ret < 0) {
        ti->error = "Cannot start hash flush task";
        goto bad;
    }

    ret = security_hash_task_start(&s->hash_prefetcher, s, "hash_prefetcher",
                                   security_hash_prefetch,
                                   security_hash_pre_prefetch);
    if (ret < 0) {
        ti->error = "Cannot start hash prefetch task";
        goto bad;
    }

    ret = security_cache_task_start(&s->cache_transferer, s, "cache_transferer",
                                    security_cache_transfer);
    if (ret < 0) {
        ti->error = "Cannot start cache transfer task";
        goto bad;
    }

    return 0;

bad:
    security_dtr(ti);
    return ret;
}

static int security_map(struct dm_target* ti, struct bio* bio) {
    struct dm_security_io* io;
    struct dm_security* s = ti->private;

    pr_info("security_map: 1\n");

    /*
     * If bio is REQ_FLUSH or REQ_DISCARD, just bypass crypt queues.
     * - for REQ_FLUSH device-mapper core ensures that no IO is in-flight
     * - for REQ_DISCARD caller must use flush if IO ordering matters
     */
    if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD))) {
        pr_info("security_map: 2\n");
        bio->bi_bdev = s->dev->bdev;
        if (bio_sectors(bio))
            bio->bi_sector = security_map_data_sector(s, bio->bi_sector);
        return DM_MAPIO_REMAPPED;
    }

    io = security_io_alloc(s, bio, dm_target_offset(ti, bio->bi_sector));
    pr_info(
        "security_map: 3, rw = %s, bio->bi_sector = %lu, bio->bi_size = %u, "
        "dm_target_offset = %u, io->sector = %lu\n",
        bio->bi_rw == READ ? "READ" : "WRITE", bio->bi_sector, bio->bi_size,
        dm_target_offset(ti, bio->bi_sector), io->sector);

    if (bio_data_dir(io->bio) == READ) {
        pr_info("security_map: 4\n");
        if (ksecurityd_io_read(io, GFP_NOWAIT)) {
            pr_info("security_map: 5\n");
            ksecurityd_queue_io(io);
        }
    } else {
        pr_info("security_map: 6\n");
        security_queue_cache(io);
    }

    pr_info("security_map: 7\n");
    return DM_MAPIO_SUBMITTED;
}

static void security_status(struct dm_target* ti,
                            status_type_t type,
                            unsigned status_flags,
                            char* result,
                            unsigned maxlen) {
    struct dm_security* s = ti->private;
    unsigned i, sz = 0;

    switch (type) {
        case STATUSTYPE_INFO:
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
            DMEMIT("%s ", s->cipher_string);

            if (s->key_size > 0)
                for (i = 0; i < s->key_size; i++)
                    DMEMIT("%02x", s->key[i]);
            else
                DMEMIT("-");

            DMEMIT(" %s %llu", s->dev->name, (unsigned long long)s->start);

            if (ti->num_discard_bios)
                DMEMIT(" 1 allow_discards");

            break;
    }
}

static void security_postsuspend(struct dm_target* ti) {
    struct dm_security* s = ti->private;

    set_bit(DM_SECURITY_SUSPENDED, &s->flags);
}

static int security_preresume(struct dm_target* ti) {
    struct dm_security* s = ti->private;

    if (!test_bit(DM_SECURITY_KEY_VALID, &s->flags)) {
        DMERR("aborting resume - security key is not set.");
        return -EAGAIN;
    }

    return 0;
}

static void security_resume(struct dm_target* ti) {
    struct dm_security* s = ti->private;

    clear_bit(DM_SECURITY_SUSPENDED, &s->flags);
}

/* Message interface
 *      key set <key>
 *      key wipe
 */
static int security_message(struct dm_target* ti, unsigned argc, char** argv) {
    struct dm_security* s = ti->private;
    int ret = -EINVAL;

    if (argc < 2)
        goto error;

    if (!strcasecmp(argv[0], "key")) {
        if (!test_bit(DM_SECURITY_SUSPENDED, &s->flags)) {
            DMWARN("not suspended during key manipulation.");
            return -EINVAL;
        }
        if (argc == 3 && !strcasecmp(argv[1], "set")) {
            ret = security_set_key(s, argv[2]);
            if (ret)
                return ret;
            return ret;
        }
        if (argc == 2 && !strcasecmp(argv[1], "wipe")) {
            return security_wipe_key(s);
        }
    }

error:
    DMWARN("unrecognised message received.");
    return -EINVAL;
}

static int security_merge(struct dm_target* ti,
                          struct bvec_merge_data* bvm,
                          struct bio_vec* biovec,
                          int max_size) {
    struct dm_security* s = ti->private;
    struct request_queue* q = bdev_get_queue(s->dev->bdev);

    if (!q->merge_bvec_fn)
        return max_size;

    bvm->bi_bdev = s->dev->bdev;
    bvm->bi_sector = security_map_data_sector(s, bvm->bi_sector);

    return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int security_iterate_devices(struct dm_target* ti,
                                    iterate_devices_callout_fn fn,
                                    void* data) {
    struct dm_security* s = ti->private;

    return fn(ti, s->dev, s->data_start, ti->len, data);
}

/* Set smallest block I/O size to 4KB */
static void security_io_hints(struct dm_target* ti,
                              struct queue_limits* limits) {
    struct dm_security* s = ti->private;

    if (limits->logical_block_size < 1 << s->data_block_bits)
        limits->logical_block_size = 1 << s->data_block_bits;

    if (limits->physical_block_size < 1 << s->data_block_bits)
        limits->physical_block_size = 1 << s->data_block_bits;

    blk_limits_io_min(limits, limits->logical_block_size);
}

static struct target_type security_target = {
    .name = "security",
    .version = {0, 0, 1},
    .module = THIS_MODULE,
    .ctr = security_ctr,
    .dtr = security_dtr,
    .map = security_map,
    .status = security_status,
    .postsuspend = security_postsuspend,
    .preresume = security_preresume,
    .resume = security_resume,
    .message = security_message,
    .merge = security_merge,
    .iterate_devices = security_iterate_devices,
    .io_hints = security_io_hints,
};

static int __init dm_security_init(void) {
    int r;

    _security_io_pool = KMEM_CACHE(dm_security_io, 0);
    if (!_security_io_pool)
        return -ENOMEM;

    _super_block_io_pool = KMEM_CACHE(security_super_block_io, 0);
    if (!_super_block_io_pool)
        return -ENOMEM;

    _hash_io_pool = KMEM_CACHE(security_hash_io, 0);
    if (!_hash_io_pool)
        return -ENOMEM;

    _leaf_node_pool = KMEM_CACHE(security_leaf_node, 0);
    if (!_leaf_node_pool)
        return -ENOMEM;

    r = dm_register_target(&security_target);
    if (r < 0) {
        DMERR("register failed %d", r);
        kmem_cache_destroy(_security_io_pool);
        kmem_cache_destroy(_super_block_io_pool);
        kmem_cache_destroy(_hash_io_pool);
        kmem_cache_destroy(_leaf_node_pool);
    }

    return r;
}

static void __exit dm_security_exit(void) {
    dm_unregister_target(&security_target);
    kmem_cache_destroy(_super_block_io_pool);
    kmem_cache_destroy(_hash_io_pool);
    kmem_cache_destroy(_leaf_node_pool);
}

module_init(dm_security_init);
module_exit(dm_security_exit);

MODULE_AUTHOR("Christophe Saout <christophe@saout.de>");
MODULE_AUTHOR("Peihong Chen <mf21320017@smail.nju.edu.cn>");
MODULE_DESCRIPTION(
    DM_NAME " target for transparent disk confidentiality and integrity");
MODULE_LICENSE("GPL");
