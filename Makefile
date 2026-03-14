# Variables for compilers and flags
CC := clang
BPF_CC := clang

# General flags
CFLAGS := -g -O2 -Wall
LDFLAGS := -lbpf -lelf -lz

# BPF specific flags
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wno-missing-declarations

# Source and object files
TARGET := kvm_trace
USER_SRCS := main.c kvm_impl.c
USER_HDRS := msr_names.h trace.h cpuid_names.h
BPF_C_SRC := kvm_trace.bpf.c
BPF_C_OBJ := $(BPF_C_SRC:.bpf.c=.bpf.o)
SKELETON := $(BPF_C_SRC:.bpf.c=.skel.h)
VMLINUX_H := vmlinux.h

.PHONY: all clean run install-deps

# Default target
all: $(TARGET)

# Link the final executable
$(TARGET): $(USER_SRCS) $(SKELETON) $(USER_HDRS)
	$(CC) $(CFLAGS) $(USER_SRCS) -o $@ $(LDFLAGS)

# Generate BPF skeleton header
$(SKELETON): $(BPF_C_OBJ)
	bpftool gen skeleton $< > $@

# Compile BPF C code
$(BPF_C_OBJ): $(BPF_C_SRC) $(VMLINUX_H) trace.h
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

# Generate vmlinux.h from BTF info
$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# clean up generated files
clean:
	rm -f $(TARGET) $(BPF_C_OBJ) $(SKELETON) $(VMLINUX_H)

run: all #assumes sudo
	sudo ./$(TARGET) -dm

run_simple: all # assumes sudo
	sudo ./$(TARGET) -dm --no-mtrr --no-mc

# install deps for arch, assumes sudo
install-deps:
	sudo pacman -Syu --noconfirm clang gcc linux-headers libbpf elfutils zlib
