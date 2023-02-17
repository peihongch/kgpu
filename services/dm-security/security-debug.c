#include "security-debug.h"

void print_bio(struct bio* bio) {
    pr_info("bio: %p\n", bio);
    if (!bio)
        return;

    pr_info("  bio->bi_sector: %lu\n", bio->bi_sector);
    pr_info("  bio->bi_size: %u\n", bio->bi_size);
    pr_info("  bio->bi_vcnt: %u\n", bio->bi_vcnt);
}

void print_convert_context(struct convert_context* ctx) {
    pr_info("convert_context: %p\n", ctx);
    if (!ctx)
        return;

    pr_info("  ctx->s_sector: %lu\n", ctx->s_sector);
    pr_info("  ctx->io_pending: %d\n", atomic_read(&ctx->s_pending));
    pr_info("  ctx->offset_in: %u\n", ctx->offset_in);
    pr_info("  ctx->offset_out: %u\n", ctx->offset_out);
    pr_info("  ctx->offset_tag: %u\n", ctx->offset_tag);
    pr_info("  ctx->idx_in: %u\n", ctx->idx_in);
    pr_info("  ctx->idx_out: %u\n", ctx->idx_out);
    pr_info("  ctx->idx_tag: %u\n", ctx->idx_tag);

    pr_info("  ctx->bio_in: %p\n", ctx->bio_in);
    if (ctx->bio_in) {
        pr_info("    bio_in->bi_sector: %lu\n", ctx->bio_in->bi_sector);
        pr_info("    bio_in->bi_size: %u\n", ctx->bio_in->bi_size);
        pr_info("    bio_in->bi_vcnt: %u\n", ctx->bio_in->bi_vcnt);
    }

    pr_info("  ctx->bio_out: %p\n", ctx->bio_out);
    if (ctx->bio_out) {
        pr_info("    bio_out->bi_sector: %lu\n", ctx->bio_out->bi_sector);
        pr_info("    bio_out->bi_size: %u\n", ctx->bio_out->bi_size);
        pr_info("    bio_out->bi_vcnt: %u\n", ctx->bio_out->bi_vcnt);
    }

    pr_info("  ctx->bio_tag: %p\n", ctx->bio_tag);
    if (ctx->bio_tag) {
        pr_info("    bio_tag->bi_sector: %lu\n", ctx->bio_tag->bi_sector);
        pr_info("    bio_tag->bi_size: %u\n", ctx->bio_tag->bi_size);
        pr_info("    bio_tag->bi_vcnt: %u\n", ctx->bio_tag->bi_vcnt);
    }
}
