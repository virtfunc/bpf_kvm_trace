a simple sloppy program to trace the RD/WRMSR and CPUID inside a KVM virtual machine using BPF.

# build
`$ make`

To install dependencies on Arch Linux:
`$ make install-deps`

# dedupe mode (works with msr and cpuid trace modes)
`# kvm_trace -d`

# cpuid mode
`# kvm_trace -c`

# msr mode
`# kvm_trace -m`

# filtering (msr mode)
`# kvm_trace -m --no-mtrr`
`# kvm_trace -m --no-mc`

# simple shell script (older)

`# ./msr_trace_kvm.sh`