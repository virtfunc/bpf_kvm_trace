a simple sloppy program to trace the RD/WRMSR inside a KVM virtual machine using BPF.

# build
`$ ./build.sh`

# dedupe mode
`# msr_trace -d`

# default mode
`# msr_trace`

# simple shell script, log only

`# ./msr_trace_kvm.sh`