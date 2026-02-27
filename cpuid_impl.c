#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace.h"
#include "cpuid_trace.skel.h"

static struct cpuid_trace_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

struct ring_buffer *trace_init_rb(handle_event_t handler)
{
    int err;

    skel = cpuid_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return NULL;
    }

    err = cpuid_trace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        cpuid_trace_bpf__destroy(skel);
        return NULL;
    }

    err = cpuid_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        cpuid_trace_bpf__destroy(skel);
        return NULL;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        cpuid_trace_bpf__destroy(skel);
        return NULL;
    }

    return rb;
}

void trace_cleanup(void)
{
    if (rb) ring_buffer__free(rb);
    if (skel) cpuid_trace_bpf__destroy(skel);
}

int trace_get_dropped_fd(void)
{
    if (!skel) return -1;
    return bpf_map__fd(skel->maps.dropped);
}

void trace_print(struct event *e, char prefix, unsigned long long current_time_ns)
{
    unsigned int ago_ms = (current_time_ns - e->ts) / 1000000;
    printf("%cCPUID Leaf: 0x%08x RIP: 0x%016llx\n", prefix, e->index, e->rip);
    printf("       EAX: 0x%08llx EBX: 0x%08llx ECX: 0x%08llx EDX: 0x%08llx -> %u ms ago\n",
           e->value & 0xFFFFFFFF, e->value >> 32, e->value_extra & 0xFFFFFFFF, e->value_extra >> 32, ago_ms);
}