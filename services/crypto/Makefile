SUBDIRS = libsrv_gaes gxts gauthenc inc-hash
# SUBDIRS = callaes libsrv_gaes gauthenc ghmac gecb gctr gxts

all: $(SUBDIRS)

.PHONY: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET) BUILD_DIR=$(BUILD_DIR)

clean:
	$(MAKE) all TARGET=clean