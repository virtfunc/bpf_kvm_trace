#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace.h"
#include "kvm_trace.skel.h"
#include "msr_names.h"
#include "cpuid_names.h"

static struct kvm_trace_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

struct ring_buffer *trace_init_rb(handle_event_t handler, int flags, int verbose)
{
    int err;

    skel = kvm_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton (Do you have permissions?)\n");
        return NULL;
    }

    skel->rodata->verbose = verbose;

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

void trace_apply_filters(unsigned int *filters, int count)
{
    if (!skel || count <= 0) return;

    int config_fd = bpf_map__fd(skel->maps.filter_config);
    __u32 key = 0;
    __u32 val = 1;
    bpf_map_update_elem(config_fd, &key, &val, BPF_ANY);

    int map_fd = bpf_map__fd(skel->maps.filter_msr);
    __u8 allowed = 1;
    for (int i = 0; i < count; i++) {
        __u32 msr_index = filters[i];
        bpf_map_update_elem(map_fd, &msr_index, &allowed, BPF_ANY);
    }
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

void trace_print(struct event *e, char prefix, unsigned long long current_time_ns, int dedupe_mode)
{
    unsigned int ago_ms = (current_time_ns - e->ts) / 1000000;
    double ts_sec = (double)e->ts / 1000000000.0;
    const char *name = "";
    char buf[256];
    
    switch (e->kind) {
        case EVENT_KIND_MSR: {
            const char *mode = e->type ? "WR" : "RD";
            name = get_msr_name(e->index);
            if (e->result) {
                snprintf(buf, sizeof(buf), "%c%sMSR: 0x%08x RIP: 0x%016llx FAULT (Except #%d) EAX: 0x%08llx EDX: 0x%08llx Value: 0x%016llx",
                         prefix, mode, e->index, e->rip, e->exception,
                         e->value & 0xFFFFFFFF, e->value >> 32, e->value);
            } else {
                snprintf(buf, sizeof(buf), "%c%sMSR: 0x%08x RIP: 0x%016llx EAX: 0x%08llx EDX: 0x%08llx Value: 0x%016llx",
                         prefix, mode, e->index, e->rip,
                         e->value & 0xFFFFFFFF, e->value >> 32, e->value);
            } 
            break;
        }
        case EVENT_KIND_CPUID: {
            name = get_cpuid_name(e->index);
            snprintf(buf, sizeof(buf), "%cCPUID: 0x%08x RIP: 0x%016llx EAX: 0x%08llx EBX: 0x%08llx ECX: 0x%08llx EDX: 0x%08llx",
                     prefix, e->index, e->rip,
                     e->value & 0xFFFFFFFF, e->value >> 32,
                     e->value_extra & 0xFFFFFFFF, e->value_extra >> 32);
            break;
        }
    }

    // print trailing information, pad to 106 columns so arrows align
    if (dedupe_mode) printf("%-106s -> %7u ms ago (%s)\n", buf, ago_ms, name);
    else printf("%-106s -> [%.6f] (%s)\n", buf, ts_sec, name);
}