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

static const char *get_msr_name(unsigned int index)
{
    switch (index) {
        case 0x00000010: return "MSR_IA32_TSC";
        case 0x0000001B: return "MSR_IA32_APICBASE";
        case 0x0000003A: return "MSR_IA32_FEATURE_CONTROL";
        case 0x00000174: return "MSR_IA32_SYSENTER_CS";
        case 0x00000175: return "MSR_IA32_SYSENTER_ESP";
        case 0x00000176: return "MSR_IA32_SYSENTER_EIP";
        case 0x000001A0: return "MSR_IA32_MISC_ENABLE";
        case 0x00000277: return "MSR_IA32_CR_PAT";
        case 0x4b564d00: return "MSR_KVM_WALL_CLOCK";
        case 0x4b564d01: return "MSR_KVM_SYSTEM_TIME";
        case 0x4b564d02: return "MSR_KVM_ASYNC_PF_EN";
        case 0x4b564d03: return "MSR_KVM_STEAL_TIME";
        case 0x4b564d04: return "MSR_KVM_PV_EOI_EN";
        case 0xC0000080: return "MSR_EFER";
        case 0xC0000081: return "MSR_STAR";
        case 0xC0000082: return "MSR_LSTAR";
        case 0xC0000083: return "MSR_CSTAR";
        case 0xC0000084: return "MSR_SYSCALL_MASK";
        case 0xC0000100: return "MSR_FS_BASE";
        case 0xC0000101: return "MSR_GS_BASE";
        case 0xC0000102: return "MSR_KERNEL_GS_BASE";
        case 0xC0000103: return "MSR_TSC_AUX";
        default: return "UNKNOWN";
    }
}

void trace_print(struct event *e, char prefix, unsigned long long current_time_ns)
{
    unsigned int ago_ms = (current_time_ns - e->ts) / 1000000;
    
    if (e->kind == EVENT_KIND_MSR) {
        const char *mode = e->type ? "WR" : "RD";
        const char *msr_name = get_msr_name(e->index);
        if (e->result) {
            printf("%c%sMSR: 0x%08x (%s) RIP: 0x%016llx Value: FAULT (Except #%d) -> %u ms ago\n",
                   prefix, mode, e->index, msr_name, e->rip, e->exception, ago_ms);
        } else {
            printf("%c%sMSR: 0x%08x (%s) RIP: 0x%016llx Value: 0x%016llx -> %u ms ago\n",
                   prefix, mode, e->index, msr_name, e->rip, e->value, ago_ms);
        } 
    } else if (e->kind == EVENT_KIND_CPUID) {
        printf("%cCPUID Leaf: 0x%08x RIP: 0x%016llx ", prefix, e->index, e->rip);
        printf(" EAX: 0x%08llx EBX: 0x%08llx ECX: 0x%08llx EDX: 0x%08llx -> %u ms ago\n",
               e->value & 0xFFFFFFFF, e->value >> 32, e->value_extra & 0xFFFFFFFF, e->value_extra >> 32, ago_ms);
    }
}