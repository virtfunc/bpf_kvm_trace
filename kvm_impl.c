#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace.h"
#include "kvm_trace.skel.h"

static struct kvm_trace_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

struct ring_buffer *trace_init_rb(handle_event_t handler, int flags)
{
    int err;

    skel = kvm_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton (Do you have permissions?)\n");
        return NULL;
    }

    err = kvm_trace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton (Do you have permissions?)\n");
        kvm_trace_bpf__destroy(skel);
        return NULL;
    }

    if (flags & TRACE_MSR) {
        skel->links.tp_kvm_msr = bpf_program__attach(skel->progs.tp_kvm_msr);
        skel->links.tp_kvm_inj_exception = bpf_program__attach(skel->progs.tp_kvm_inj_exception);
        skel->links.tp_kvm_entry = bpf_program__attach(skel->progs.tp_kvm_entry);
    }
    
    if (flags & TRACE_CPUID) {
        skel->links.tp_kvm_cpuid = bpf_program__attach(skel->progs.tp_kvm_cpuid);
    }

    if (flags & (TRACE_MSR | TRACE_CPUID)) {
        skel->links.tp_kvm_exit = bpf_program__attach(skel->progs.tp_kvm_exit);
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        kvm_trace_bpf__destroy(skel);
        return NULL;
    }

    return rb;
}

void trace_cleanup(void)
{
    if (rb) ring_buffer__free(rb);
    if (skel) kvm_trace_bpf__destroy(skel);
}

int trace_get_dropped_fd(void)
{
    if (!skel) return -1;
    return bpf_map__fd(skel->maps.dropped);
}

void trace_print(struct event *e, char prefix, unsigned long long current_time_ns)
{
    unsigned int ago_ms = (current_time_ns - e->ts) / 1000000;
    
    if (e->kind == EVENT_KIND_MSR) {
        const char *mode = e->type ? "WR" : "RD";
        if (e->result) {
            printf("%c%sMSR: 0x%08x RIP: 0x%016llx Value: FAULT (Except #%d) -> %u ms ago\n",
                   prefix, mode, e->index, e->rip, e->exception, ago_ms);
        } else {
            printf("%c%sMSR: 0x%08x RIP: 0x%016llx Value: 0x%016llx -> %u ms ago\n",
                   prefix, mode, e->index, e->rip, e->value, ago_ms);
        } 
    } else if (e->kind == EVENT_KIND_CPUID) {
        printf("%cCPUID Leaf: 0x%08x RIP: 0x%016llx ", prefix, e->index, e->rip);
        printf(" EAX: 0x%08llx EBX: 0x%08llx ECX: 0x%08llx EDX: 0x%08llx -> %u ms ago\n",
               e->value & 0xFFFFFFFF, e->value >> 32, e->value_extra & 0xFFFFFFFF, e->value_extra >> 32, ago_ms);
    }
}