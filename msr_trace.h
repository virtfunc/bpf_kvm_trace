#ifndef __MSR_TRACE_H
#define __MSR_TRACE_H

struct event {
    unsigned long long ts;
    unsigned int msr;
    unsigned long long value;
    unsigned int is_write;
    unsigned int result; // 0 = OK, 1 = FAULT
    unsigned int exception;
    unsigned long long rip;
};

#endif