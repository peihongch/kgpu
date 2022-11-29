#ifndef __INC_HASH_H_
#define __INC_HASH_H_

struct inc_hash_ctx {
    uint32_t id;
    uint32_t old_len;
    /**
     * The actual data:
     * |   old_data   |   new_data   |
     */
    uint8_t data[0];
};

#endif /* __INC_HASH_H_ */