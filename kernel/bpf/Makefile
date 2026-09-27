CLANG ?= clang
ARCH_INCLUDE ?= /usr/include/$(shell uname -m)-linux-gnu
BUILD_DIR ?= build
BPF_OBJECT := $(BUILD_DIR)/aegis_connect.bpf.o

.PHONY: all clean

all: $(BPF_OBJECT)

$(BPF_OBJECT): aegis_connect.bpf.c include/aegis_abi.h
	mkdir -p $(BUILD_DIR)
	$(CLANG) -O2 -g -Wall -Werror -target bpf \
		-I$(ARCH_INCLUDE) \
		-I. \
		-c aegis_connect.bpf.c \
		-o $(BPF_OBJECT)

clean:
	rm -rf $(BUILD_DIR)
