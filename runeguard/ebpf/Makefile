CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),x86_64)
BPF_ARCH := x86
else
BPF_ARCH := x86
endif

SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build

BPF_OBJ := $(BUILD_DIR)/runeguard.bpf.o
SKEL := $(BUILD_DIR)/runeguard.skel.h
LOADER := $(BUILD_DIR)/runeguard-ebpf-loader
VMLINUX := $(BUILD_DIR)/vmlinux.h

.PHONY: all clean install-package

all: $(LOADER)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): $(SRC_DIR)/runeguard.bpf.c $(INCLUDE_DIR)/events.h $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I$(BUILD_DIR) -I$(INCLUDE_DIR) \
		-c $(SRC_DIR)/runeguard.bpf.c -o $(BPF_OBJ)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

$(LOADER): $(SRC_DIR)/runeguard_loader.c $(INCLUDE_DIR)/events.h $(SKEL)
	$(CC) -g -O2 -I$(BUILD_DIR) -I$(INCLUDE_DIR) \
		$(SRC_DIR)/runeguard_loader.c -lbpf -lelf -lz -o $(LOADER)

install-package: $(LOADER)
	cp $(LOADER) ../runeguard/ebpf/runeguard-ebpf-loader
	cp $(BPF_OBJ) ../runeguard/ebpf/runeguard.bpf.o

clean:
	rm -rf $(BUILD_DIR)
