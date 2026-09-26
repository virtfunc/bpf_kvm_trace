A simple TUI program to trace the RD/WRMSR, CPUID, and IO ports inside a KVM virtual machine using BPF.

# build
`$ make`

To install dependencies on Arch Linux:
`$ make install-deps`

# dedupe mode (works for any of the below logged vmexit sources)
`# kvm_trace -d`

# cpuid mode
`# kvm_trace -c`

# msr mode
`# kvm_trace -m`

# IO port mode
`# kvm_trace -i`

## verbose msr mode (shows all traced MSRs)
`# kvm_trace -m --verbose`

# simple shell script (older)

`# ./msr_trace_kvm.sh`

## notes
was designed for use in a tty, outputting to a file may not work as expected in dedupe mode. (especially reported times)
