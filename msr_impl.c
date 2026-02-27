#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace.h"
#include "msr_trace.skel.h"

static struct msr_trace_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

struct ring_buffer *trace_init_rb(handle_event_t handler)
{
    int err;

    skel = msr_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return NULL;
    }

    err = msr_trace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        msr_trace_bpf__destroy(skel);
        return NULL;
    }

    err = msr_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        msr_trace_bpf__destroy(skel);
        return NULL;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        msr_trace_bpf__destroy(skel);
        return NULL;
    }

    return rb;
}

void trace_cleanup(void)
{
    if (rb) ring_buffer__free(rb);
    if (skel) msr_trace_bpf__destroy(skel);
}

int trace_get_dropped_fd(void)
{
    if (!skel) return -1;
    return bpf_map__fd(skel->maps.dropped);
}

void trace_print(struct event *e, char prefix, unsigned long long current_time_ns)
{
    unsigned int ago_ms = (current_time_ns - e->ts) / 1000000;
    const char *mode = e->type ? "WR" : "RD";

    if (e->result == 0) {
        printf("%c%sMSR: 0x%08x RIP: 0x%016llx Value: 0x%016llx -> %u ms ago\n",
               prefix, mode, e->index, e->rip, e->value, ago_ms);
    } else {
        printf("%c%sMSR: 0x%08x RIP: 0x%016llx Value: FAULT (Except #%2d) -> %u ms ago\n",
               prefix, mode, e->index, e->rip, e->exception, ago_ms);
    }
}