#!/bin/bash
set -e

# 1. Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF object
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c msr_trace.bpf.c -o msr_trace.bpf.o

# 3. Generate Skeleton
bpftool gen skeleton msr_trace.bpf.o > msr_trace.skel.h

# 4. Compile Userspace
gcc -g -O2 -Wall msr_trace.c -lbpf -lelf -lz -o msr_trace

# 5. Run
sudo ./msr_trace -d
