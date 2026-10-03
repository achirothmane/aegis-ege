CLANG ?= clang
ARCH_INCLUDE ?= /usr/include/$(shell uname -m)-linux-gnu
BUILD_DIR ?= build
CONNECT_OBJECT := $(BUILD_DIR)/aegis_connect.bpf.o
TAINT_OBJECT := $(BUILD_DIR)/aegis_taint.bpf.o

.PHONY: all clean

all: $(CONNECT_OBJECT) $(TAINT_OBJECT)

$(CONNECT_OBJECT): aegis_connect.bpf.c include/aegis_abi.h
	mkdir -p $(BUILD_DIR)
	$(CLANG) -O2 -g -Wall -Werror -target bpf \
		-I$(ARCH_INCLUDE) \
		-I. \
		-c aegis_connect.bpf.c \
		-o $(CONNECT_OBJECT)

$(TAINT_OBJECT): aegis_taint.bpf.c include/aegis_taint_abi.h
	mkdir -p $(BUILD_DIR)
	$(CLANG) -O2 -g -Wall -Werror -target bpf \
		-I$(ARCH_INCLUDE) \
		-I. \
		-c aegis_taint.bpf.c \
		-o $(TAINT_OBJECT)

clean:
	rm -rf $(BUILD_DIR)
