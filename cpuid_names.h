#ifndef __CPUID_NAMES_H
#define __CPUID_NAMES_H

#include <stdio.h>
#include <stddef.h>

struct cpuid_def {
    unsigned int leaf;
    const char *name;
};

static const struct cpuid_def cpuid_names[] = {
    /* Standard CPUID Leaves */
    { 0x00000000, "Vendor ID and Largest Standard Function" },
    { 0x00000001, "Processor Info and Feature Bits" },
    { 0x00000002, "Cache and TLB Descriptor Information" },
    { 0x00000004, "Deterministic Cache Parameters" },
    { 0x00000005, "MONITOR/MWAIT" },
    { 0x00000006, "Thermal and Power Management" },
    { 0x00000007, "Structured Extended Feature Flags" },
    { 0x0000000A, "Architectural Performance Monitoring" },
    { 0x0000000D, "Processor Extended States" },

    /* Hypervisor CPUID Leaves */
    { 0x40000000, "Hypervisor CPUID Information" },
    { 0x40000001, "Hypervisor Interface" },
    { 0x40000100, "KVM CPUID Features" },

    /* Extended CPUID Leaves */
    { 0x80000000, "Largest Extended Function" },
    { 0x80000001, "Extended Processor Info and Feature Bits" },
    { 0x80000002, "Processor Brand String" },
    { 0x80000003, "Processor Brand String" },
    { 0x80000004, "Processor Brand String" },
    { 0x80000005, "L1 Cache and TLB Identifiers" },
    { 0x80000006, "Extended L2 Cache Features" },
    { 0x80000007, "Advanced Power Management Information" },
    { 0x80000008, "Virtual and Physical Address Sizes" },
};

static inline const char *get_cpuid_name(unsigned int leaf) {
    int left = 0, right = sizeof(cpuid_names)/sizeof(cpuid_names[0]) - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (cpuid_names[mid].leaf == leaf) return cpuid_names[mid].name;
        if (cpuid_names[mid].leaf < leaf) left = mid + 1;
        else right = mid - 1;
    }
    if (leaf >= 0x40000000 && leaf <= 0x4000FFFF) return "HV_UNKNOWN";
    return "UNKNOWN";
}

#endif // __CPUID_NAMES_H
