#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace.h"

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_kvm_cpuid {
    struct trace_entry ent;
    u32 func;
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
    bool found;
};

struct trace_event_raw_kvm_exit {
    struct trace_entry ent;
    u32 exit_reason;
    unsigned long rip;
    u32 isa;
    u64 info1;
    u64 info2;
};

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Dropped events
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} dropped SEC(".maps");

// Exit RIP map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} exit_rip SEC(".maps");

SEC("tracepoint/kvm/kvm_exit")
int tp_kvm_exit(struct trace_event_raw_kvm_exit *args)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 rip = args->rip;
    bpf_map_update_elem(&exit_rip, &tid, &rip, BPF_ANY);
    return 0;
}

SEC("tracepoint/kvm/kvm_cpuid")
int tp_kvm_cpuid(struct trace_event_raw_kvm_cpuid *args)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        u32 key = 0;
        u64 *val = bpf_map_lookup_elem(&dropped, &key);
        if (val) __sync_fetch_and_add(val, 1);
        return 0;
    }

    e->ts = bpf_ktime_get_ns();
    e->index = args->func;
    e->value = (u64)args->eax | ((u64)args->ebx << 32);
    e->value_extra = (u64)args->ecx | ((u64)args->edx << 32);
    e->type = 0; // Read
    e->result = 0; // Always OK for tracepoint
    e->exception = 0;

    u64 *rip = bpf_map_lookup_elem(&exit_rip, &tid);
    if (rip) {
        e->rip = *rip;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}