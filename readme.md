a simple sloppy program to trace the RD/WRMSR inside a KVM virtual machine using BPF.

# build
`$ ./build.sh`

# dedupe mode
`# kvm_trace -d`

# default mode
`# kvm_trace`

# simple shell script, log only

`# ./msr_trace_kvm.sh`