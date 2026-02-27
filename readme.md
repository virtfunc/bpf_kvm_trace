a simple sloppy program to trace the RD/WRMSR inside a KVM virtual machine using BPF.

# build
`$ ./build.sh`

# dedupe mode
works with msr and cpuid trace modes.
`# kvm_trace -d`

# cpuid mode
`# kvm_trace -c`

# msr mode
`# kvm_trace -m`

# simple shell script (older)

`# ./msr_trace_kvm.sh`