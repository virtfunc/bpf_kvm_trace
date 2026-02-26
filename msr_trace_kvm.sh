sudo bpftrace -e '
BEGIN {
    @modes[(uint64)0] = "READ";
    @modes[(uint64)1] = "WRITE";
}
tracepoint:kvm:kvm_msr {
    @pending[tid] = (elapsed, args->ecx, args->data, args->write);
}
tracepoint:kvm:kvm_inj_exception {
    $d = @pending[tid];
    if ($d.0) {
        $prefix = "*";
        if (@seen[$d.1]) {
            $prefix = " ";
        } else {
            @seen[$d.1] = 1;
        }
        printf("%s[Time: %8u ms]  MSR: 0x%08x  Value: 0x%016lx  Mode: %-5s  Result: FAULT (Exception %2d)\n",
               $prefix, $d.0 / 1000000, $d.1, $d.2, @modes[$d.3], args->exception);
        delete(@pending[tid]);
    }
}
tracepoint:kvm:kvm_entry {
    $d = @pending[tid];
    if ($d.0) {
        $prefix = "*";
        if (@seen[$d.1]) {
            $prefix = " ";
        } else {
            @seen[$d.1] = 1;
        }
        printf("%s[Time: %8u ms]  MSR: 0x%08x  Value: 0x%016lx  Mode: %-5s  Result: OK\n",
               $prefix, $d.0 / 1000000, $d.1, $d.2, @modes[$d.3]);
        delete(@pending[tid]);
    }
}
' | tee msr_trace.log
