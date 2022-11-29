#include "trusted-storage.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define MODULE_NAME "trusted-storage"

static int __init trusted_storage_init(void) {
    pr_info("trusted_storage: init\n");
    return 0;
}

static void __exit trusted_storage_exit(void) {
    pr_info("trusted_storage: exit\n");
}

module_init(trusted_storage_init);
module_exit(trusted_storage_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peihong Chen <mf21320017@smail.nju.edu.cn>");
MODULE_DESCRIPTION("Trusted Storage Emulator (tse)");
