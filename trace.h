#ifndef __TRACE_H
#define __TRACE_H

#define TRACE_MSR   (1 << 0)
#define TRACE_CPUID (1 << 1)
#define TRACE_IO    (1 << 2)
#define TRACE_ECAM  (1 << 3)
#define TRACE_UNKNOWN_TYPE 1234

enum event_type {
    RDMSR = 0,
    WRMSR = 1,
    RDMSR_FAULT = 2,
    WRMSR_FAULT = 3,
    CPUID = 4,
    CPUID_FAULT = 5,
    IO_IN = 6,
    IO_OUT = 7,
    ECAM_READ = 8,
    ECAM_WRITE = 9
};

struct event {
    unsigned long long ts;
    unsigned int index;      // Generic index (e.g., MSR ECX, CPUID leaf, IO port, or ECAM offset)
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    enum event_type type;    // Combines type, kind, result
    unsigned int exception;
    unsigned long long rip;
    unsigned int size;       // Access size (1, 2, 4, or 8 bytes)
    unsigned int count;      // IO repeat count
    unsigned long long gpa;  // MMIO GPA for ECAM
};

#ifndef __BPF_HELPERS__
#include <stddef.h>

typedef int (*handle_event_t)(void *ctx, void *data, size_t data_sz);

struct ring_buffer;

struct ring_buffer *trace_init_rb(handle_event_t handler, int flags, int verbose, unsigned long long ecam_base);
void trace_cleanup(void);
void trace_print(struct event *e, char prefix, unsigned long long current_time_ns, int dedupe_mode);
int trace_get_dropped_fd(void);

#endif
#endif