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
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c msr_trace.bpf.c -o msr_trace.bpf.o
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c cpuid_trace.bpf.c -o cpuid_trace.bpf.o

# 3. Generate Skeleton
bpftool gen skeleton msr_trace.bpf.o > msr_trace.skel.h
bpftool gen skeleton cpuid_trace.bpf.o > cpuid_trace.skel.h

# 4. Compile Userspace
clang -g -O2 -Wall main.c msr_impl.c -lbpf -lelf -lz -o msr_trace
clang -g -O2 -Wall main.c cpuid_impl.c -lbpf -lelf -lz -o cpuid_trace

# 5. Run
sudo ./msr_trace -d
