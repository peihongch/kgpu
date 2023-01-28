#ifndef __TRUSTED_STORAGE_H_
#define __TRUSTED_STORAGE_H_

#define TRUSTED_STORAGE_STOPPED (1)
#define TRUSTED_STORAGE_NOT_FOUND (2)
#define TRUSTED_STORAGE_EXIST (3)

unsigned long trusted_storage_uuid_gen(void);

int trusted_storage_read(unsigned long key, void* out_buf, size_t len);

int trusted_storage_write(unsigned long key, void* in_buf, size_t len);

#endif
