A simple TUI program to trace RD/WRMSR, CPUID, IO ports, and PCIe ECAM reads/writes inside a KVM virtual machine using BPF.

# build
`$ make`

To install dependencies on Arch Linux:
`$ make install-deps`

## dedupe mode (works for any of the below logged vmexit sources)
`# kvm_trace -d`

## cpuid mode
`# kvm_trace -c`

## msr mode
`# kvm_trace -m`

## IO port mode
`# kvm_trace -i`

## ECAM mode (PCIe config space reads/writes via MMIO, default base: 0xe0000000)
`# kvm_trace -e`

### custom ECAM base address
`# kvm_trace -e 0xb0000000`

### verbose msr mode (shows all traced MSRs)
`# kvm_trace -m --verbose`

## simple shell script (older)

`# ./msr_trace_kvm.sh`

## notes
was designed for use in a tty, outputting to a file may not work as expected in dedupe mode. (especially reported times)
