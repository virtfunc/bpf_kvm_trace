#!/bin/bash
set -e

# 0. Install dependencies for Arch Linux, checking if they are already installed
dependencies=("clang" "gcc" "linux-headers" "libbpf" "elfutils" "zlib")
for dep in "${dependencies[@]}"; do
    if ! pacman -Qsq "$dep" >/dev/null; then
        echo "Installing $dep..."
        sudo pacman -Syu --noconfirm "$dep"
    fi
done

# 1. Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF object
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c kvm_trace.bpf.c -o kvm_trace.bpf.o

# 3. Generate Skeleton
bpftool gen skeleton kvm_trace.bpf.o > kvm_trace.skel.h

# 4. Compile Userspace
clang -g -O2 -Wall main.c kvm_impl.c -lbpf -lelf -lz -o kvm_trace

# 5. Run
sudo ./kvm_trace -d -c
