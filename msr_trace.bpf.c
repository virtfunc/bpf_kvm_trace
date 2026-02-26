#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "msr_trace.h"

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_kvm_msr {
	struct trace_entry ent;
	u8 write;
	u32 ecx;
	u64 data;
	u8 exception;
};

struct trace_event_raw_kvm_inj_exception {
	struct trace_entry ent;
	u8 exception;
	u8 has_error_code;
	u32 error_code;
};

struct trace_event_raw_kvm_entry {
	struct trace_entry ent;
	u32 vcpu_id;
	unsigned long rip;
};

// Map to correlate kvm_msr with kvm_entry/kvm_inj_exception
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // tid
    __type(value, struct event);
} pending SEC(".maps");

// Ring buffer to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to count dropped events
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} dropped SEC(".maps");

SEC("tracepoint/kvm/kvm_msr")
int tp_kvm_msr(struct trace_event_raw_kvm_msr *args)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct event e = {};

    e.ts = bpf_ktime_get_ns();
    e.msr = args->ecx;
    e.value = args->data;
    e.is_write = args->write;

    bpf_map_update_elem(&pending, &tid, &e, BPF_ANY);
    return 0;
}

static void submit_event(struct event *e, int result, int exception)
{
    struct event *out;

    e->result = result;
    e->exception = exception;

    out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
    if (!out) {
        u32 key = 0;
        u64 *val = bpf_map_lookup_elem(&dropped, &key);
        if (val)
            __sync_fetch_and_add(val, 1);
        return;
    }
    *out = *e;
    bpf_ringbuf_submit(out, 0);
}

SEC("tracepoint/kvm/kvm_inj_exception")
int tp_kvm_inj_exception(struct trace_event_raw_kvm_inj_exception *args)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct event *e;

    e = bpf_map_lookup_elem(&pending, &tid);
    if (e) {
        // Result 1 = FAULT
        submit_event(e, 1, args->exception);
        bpf_map_delete_elem(&pending, &tid);
    }
    return 0;
}

SEC("tracepoint/kvm/kvm_entry")
int tp_kvm_entry(struct trace_event_raw_kvm_entry *args)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct event *e;

    e = bpf_map_lookup_elem(&pending, &tid);
    if (e) {
        // Result 0 = OK
        submit_event(e, 0, 0);
        bpf_map_delete_elem(&pending, &tid);
    }
    return 0;
}
