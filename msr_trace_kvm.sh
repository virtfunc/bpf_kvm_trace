sudo bpftrace -e '
BEGIN {
    @modes[0] = "RDMSR";
    @modes[1] = "WRMSR";
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
        printf("%s[Time: %8u ms]  %s: 0x%08x  Value: FAULT (Except #%2d)\n",
               $prefix, $d.0 / 1000000, @modes[(int32)$d.3], $d.1, args->exception);
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
        printf("%s[Time: %8u ms]  %s: 0x%08x  Value: 0x%016lx\n",
               $prefix, $d.0 / 1000000, @modes[(int32)$d.3], $d.1, $d.2);
        delete(@pending[tid]);
    }
}
' | tee msr_trace.log
