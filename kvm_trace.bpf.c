#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace.h"

char LICENSE[] SEC("license") = "GPL";

volatile const bool verbose = false;

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

struct trace_event_raw_kvm_exit {
    struct trace_entry ent;
    u32 exit_reason;
    unsigned long rip;
    u32 isa;
    u64 info1;
    u64 info2;
};

struct trace_event_raw_kvm_cpuid {
    struct trace_entry ent;
    u32 func;
    u64 eax;
    u64 ebx;
    u64 ecx;
    u64 edx;
    bool found;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} exit_rip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct event);
} pending_msr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} filter_msr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} filter_config SEC(".maps");

SEC("tracepoint/kvm/kvm_exit")
int tp_kvm_exit(struct trace_event_raw_kvm_exit *args) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 rip = args->rip;
    bpf_map_update_elem(&exit_rip, &tid, &rip, BPF_ANY);
    return 0;
}

SEC("tracepoint/kvm/kvm_msr")
int tp_kvm_msr(struct trace_event_raw_kvm_msr *args) {
	u32 index = args->ecx;
	u32 key0 = 0;
	u32 *filter_enabled = bpf_map_lookup_elem(&filter_config, &key0);

	if (filter_enabled && *filter_enabled) {
		u8 *allowed = bpf_map_lookup_elem(&filter_msr, &index);
		if (!allowed) return 0;
	} else {
		if (!verbose) {
			// MSR_MTRR_CAP, MSR_PAT, MSR_MTRR_DEF_TYPE, and ranges for variable and fixed MTRRs
			if ((index >= 0x200 && index <= 0x2FF) || index == 0xFE) {
				return 0;
			}
			// MCG_CAP, MCG_STATUS, MCG_CTL and MCi_* banks + AMD MCA banks (0xC0002000->0xC0002FFF)
			if ((index >= 0x179 && index <= 0x17B) || (index >= 0x400 && index < (0x400 + 4 * 32)) || (index >= 0xC0002000 && index < 0xC0002FFF)) {
				return 0;
			}
		}
	}

    u32 tid = bpf_get_current_pid_tgid();
    struct event e = {};
    e.ts = bpf_ktime_get_ns();
	e.index = index;
    e.value = args->data;
    e.type = args->write ? WRMSR : RDMSR;
    u64 *rip = bpf_map_lookup_elem(&exit_rip, &tid);
    if (rip) e.rip = *rip;
    bpf_map_update_elem(&pending_msr, &tid, &e, BPF_ANY);
    return 0;
}

static void submit_msr(struct event *e, int result, int exception) {
    struct event *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
    if (!out) {
        u32 key = 0;
        u64 *val = bpf_map_lookup_elem(&dropped, &key);
        if (val) __sync_fetch_and_add(val, 1);
        return;
    }
    *out = *e;
    if (result) {
        if (out->type == RDMSR) {
            out->type = RDMSR_FAULT;
        } else if (out->type == WRMSR) {
            out->type = WRMSR_FAULT;
        } else if (out->type == CPUID) {
            out->type = CPUID_FAULT;
        }
    }
    out->exception = exception;
    bpf_ringbuf_submit(out, 0);
}

SEC("tracepoint/kvm/kvm_inj_exception")
int tp_kvm_inj_exception(struct trace_event_raw_kvm_inj_exception *args) {
    u32 tid = bpf_get_current_pid_tgid();
    struct event *e = bpf_map_lookup_elem(&pending_msr, &tid);
    if (e) { submit_msr(e, 1, args->exception); bpf_map_delete_elem(&pending_msr, &tid); }
    return 0;
}

SEC("tracepoint/kvm/kvm_entry")
int tp_kvm_entry(struct trace_event_raw_kvm_entry *args) {
    u32 tid = bpf_get_current_pid_tgid();
    struct event *e = bpf_map_lookup_elem(&pending_msr, &tid);
    if (e) { if (e->rip == 0) e->rip = args->rip; submit_msr(e, 0, 0); bpf_map_delete_elem(&pending_msr, &tid); }
    bpf_map_delete_elem(&exit_rip, &tid);
    return 0;
}

SEC("tracepoint/kvm/kvm_cpuid")
int tp_kvm_cpuid(struct trace_event_raw_kvm_cpuid *args) {
    struct event e = {};
    e.ts = bpf_ktime_get_ns();
    e.index = args->func;
    e.value = (u64)(u32)args->eax | ((u64)(u32)args->ebx << 32);
    e.value_extra = (u64)(u32)args->ecx | ((u64)(u32)args->edx << 32);
    e.type = CPUID;
    u32 tid = bpf_get_current_pid_tgid();
    u64 *rip = bpf_map_lookup_elem(&exit_rip, &tid);
    if (rip) e.rip = *rip;
    submit_msr(&e, 0, 0); // Reuse submit logic
    return 0;
}