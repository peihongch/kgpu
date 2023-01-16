#
# Makefile for the Linux 3.10 dm-security
#

obj-m += dm-security.o

dm-security-objs := security-cache.o security-hash-tree.o security-super-block.o security-core.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	$(if $(BUILD_DIR), cp dm-security.ko $(BUILD_DIR)/ ) 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
