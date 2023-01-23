SUBDIRS = crypto trusted-storage dm-security
# SUBDIRS = crypto dm-security ecryptfs raid6 test

all: $(SUBDIRS)

.PHONY: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET) kv=$(kv) BUILD_DIR=$(BUILD_DIR)

clean:
	$(MAKE) all TARGET=clean
