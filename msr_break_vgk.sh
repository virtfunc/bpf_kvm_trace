#!/usr/bin/env bpftrace

// 1. When the VM exits to KVM, save the current guest instruction pointer (RIP) for this thread
tracepoint:kvm:kvm_exit
{
    @guest_rip[tid] = args->guest_rip;
}

// 2. When the MSR read tracepoint fires, check if it's our target
tracepoint:kvm:kvm_msr
/args->write == 0 && args->ecx == 0x4b564d00/
{
    $rip = @guest_rip[tid];

    // The 'rdmsr' instruction is 2 bytes long.
    // The next instruction will be executed at RIP + 2.
    printf("\nTarget MSR 0x%x read intercepted!\n", args->ecx);
    printf("Guest RIP at exit: 0x%lx\n", $rip);
    printf("Next instruction starts at: 0x%lx\n", $rip + 2);

    // Pause the VM
    signal("SIGSTOP");
    printf("QEMU PID: %d\n", pid);
    printf("vCPU TID: %d\n", tid);
}

// 3. Clean up the map to prevent memory leaks in long-running traces
tracepoint:kvm:kvm_entry
{
    delete(@guest_rip[tid]);
}
