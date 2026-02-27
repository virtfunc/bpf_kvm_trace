#ifndef __TRACE_H
#define __TRACE_H

#define TRACE_MSR   (1 << 0)
#define TRACE_CPUID (1 << 1)

struct event {
    unsigned long long ts;
    unsigned int index;      // Generic index (e.g., MSR ECX or CPUID leaf)
    unsigned long long value;
    unsigned long long value_extra;
    unsigned int type;       // Generic type (e.g., 0=RD, 1=WR)
    enum event_kind {
        EVENT_KIND_MSR = 0,
        EVENT_KIND_CPUID = 1,
    } kind; // 0=MSR, 1=CPUID
    unsigned int result;     // 0 = OK, 1 = FAULT
    unsigned int exception;
    unsigned long long rip;
};

#ifndef __BPF_HELPERS__
#include <stddef.h>

typedef int (*handle_event_t)(void *ctx, void *data, size_t data_sz);

struct ring_buffer;

struct ring_buffer *trace_init_rb(handle_event_t handler, int flags);
void trace_cleanup(void);
void trace_print(struct event *e, char prefix, unsigned long long current_time_ns);
int trace_get_dropped_fd(void);

#endif
#endif