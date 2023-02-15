#
# Makefile for the Linux 3.10 dm-security
#

obj-m += dm-security.o

dm-security-objs := security-common.o security-debug.o security-convert.o security-cache.o security-hash-tree.o security-super-block.o security-core.o

# 
# 内核模块编译时搜索Module.symvers的路径是：
# 1. kernel source path, e.g. /lib/modules/$(shell uname -r)/build
# 2. makefile中M=所指定的路径, 它等效于变量KBUILD_EXTMOD的值
# 3. 变量KBUILD_EXTRA_SYMBOLS的值（必须是绝对路径）
#
# 由于dm-security依赖trusted-storage模块中的导出符号，因此需要增加KBUILD_EXTRA_SYMBOLS变量，
# 该变量的值是trusted-storage模块的Module.symvers文件的路径
#

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) KBUILD_EXTRA_SYMBOLS=$(shell pwd)/../trusted-storage/Module.symvers modules
	$(if $(BUILD_DIR), cp dm-security.ko $(BUILD_DIR)/ )

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) KBUILD_EXTRA_SYMBOLS=$(shell pwd)/../trusted-storage/Module.symvers modules
	$(if $(BUILD_DIR), cp dm-security.ko $(BUILD_DIR)/ ) -DCONFIG_SECURITY_DEBUG

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) KBUILD_EXTRA_SYMBOLS=$(shell pwd)/../trusted-storage/Module.symvers clean
