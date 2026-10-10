#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace.h"
#include "kvm_trace.skel.h"
#include "msr_names.h"
#include "cpuid_names.h"
#include "io_port_names.h"
#include "pci_names.h"

static struct kvm_trace_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

struct ring_buffer *trace_init_rb(handle_event_t handler, int flags, int verbose, unsigned long long ecam_base)
{
    int err;

    skel = kvm_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton (Do you have permissions?)\n");
        return NULL;
    }

    skel->rodata->verbose = verbose;
    skel->rodata->ecam_base = ecam_base;
    skel->rodata->ecam_size = 0x10000000ULL;

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

    if (flags & TRACE_IO) {
        skel->links.tp_kvm_pio = bpf_program__attach(skel->progs.tp_kvm_pio);
    }

    if (flags & TRACE_ECAM) {
        skel->links.tp_kvm_mmio = bpf_program__attach(skel->progs.tp_kvm_mmio);
    }

    if (flags & (TRACE_MSR | TRACE_CPUID | TRACE_IO | TRACE_ECAM)) {
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
    const char *type = "";
    char value[128] = "";
    char buf[256];

    switch (e->type) {
    case RDMSR:
    case WRMSR: {
        name = get_msr_name(e->index);
        type = (e->type == RDMSR) ? "RDMSR" : "WRMSR";
        snprintf(value, sizeof(value), "EAX=0x%08x EDX=0x%08x VAL=0x%016llx",e->eax,e->edx, ((unsigned long long)e->edx << 32) | e->eax);
        break;
    }
    case RDMSR_FAULT:
    case WRMSR_FAULT:
        name = get_msr_name(e->index);
        type = (e->type == RDMSR_FAULT) ? "RDMSR" : "WRMSR";
        snprintf(value, sizeof(value), "Fault #%u", e->exception);
        break;
    case CPUID:
    case CPUID_FAULT:
        name = get_cpuid_name(e->index);
        type = "CPUID";
        (e->type == CPUID_FAULT)
        ? (void)snprintf(value, sizeof(value), "Fault #%u", e->exception)
        : (void)snprintf(value, sizeof(value), "EAX=0x%08x EBX=0x%08x ECX=0x%08x EDX=0x%08x", e->eax, e->ebx, e->ecx, e->edx);
        break;
    case IO_IN:
    case IO_OUT:
        name = get_io_port_name(e->index);
        type = (e->type == IO_IN) ? "IN" : "OUT";
        snprintf(value, sizeof(value), "VAL=0x%08x SIZE=%u COUNT=%u", e->eax, e->size, e->count);
        break;
    case ECAM_READ:
    case ECAM_WRITE: {
        unsigned int bus = (e->ebx >> 16) & 0xff;
        unsigned int dev = (e->ebx >> 8) & 0x1f;
        unsigned int func = e->ebx & 0x07;
        unsigned int reg = e->ecx & 0xfff;
        unsigned long long val = ((unsigned long long)e->edx << 32) | e->eax;
        name = get_pci_reg_name(reg);
        type = (e->type == ECAM_READ) ? "ECAM_R" : "ECAM_W";
        if (e->size == 8) {
            snprintf(value, sizeof(value), "BDF=%02x:%02x.%x ADDR=0x%03x VAL=0x%016llx SIZE=%u",
                     bus, dev, func, reg, val, e->size);
        } else {
            snprintf(value, sizeof(value), "BDF=%02x:%02x.%x ADDR=0x%03x VAL=0x%08llx SIZE=%u",
                     bus, dev, func, reg, val, e->size);
        }
        break;
    }
    default: exit(TRACE_UNKNOWN_TYPE); //something went horribly wrong
    }
    if (e->type == ECAM_READ || e->type == ECAM_WRITE) {
        if (e->gpa > 0xffffffffULL) {
            snprintf(buf, sizeof(buf), "%c%-6s 0x%016llx RIP=0x%016llx %s", prefix, type, e->gpa, e->rip, value);
        } else {
            snprintf(buf, sizeof(buf), "%c%-6s 0x%08x RIP=0x%016llx %s", prefix, type, (unsigned int)e->gpa, e->rip, value);
        }
    } else {
        snprintf(buf, sizeof(buf), "%c%-6s0x%08x RIP=0x%016llx %s", prefix, type, e->index, e->rip, value);
    }
    dedupe_mode //flame the style all you want
        ? (void)printf("%-106s -> %7u ms ago (%s)\033[K\n", buf, ago_ms, name)
        : (void)printf("%-106s -> [%.6f] (%s)\n", buf, ts_sec, name);
}