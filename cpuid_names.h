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
    // { 0x00000003, "RESERVED on AMD" },
    { 0x00000004, "Deterministic Cache Parameters" },
    { 0x00000005, "MONITOR/MWAIT" },
    { 0x00000006, "Thermal and Power Management" },
    { 0x00000007, "Structured Extended Feature Flags" },
    // { 0x00000008, "RESERVED on AMD" },
    // { 0x00000009, "RESERVED on AMD" },
    { 0x0000000A, "Architectural Performance Monitoring" },
    { 0x0000000B, "Extended Topology Enumeration" },
    // { 0x0000000C, "RESERVED on AMD" },
    { 0x0000000D, "Processor Extended States" },
    // { 0x0000000E, "RESERVED on AMD" },
    { 0x0000000F, "PQOS Monitoring" },
    { 0x00000010, "PQOS Enforcement" },

    /* Hypervisor CPUID Leaves */
    { 0x40000000, "Hypervisor CPUID Information" },
    { 0x40000001, "Hypervisor Interface" },
    { 0x40000100, "KVM CPUID Features" },

    /* Extended CPUID Leaves */
    { 0x80000000, "Maximum Extended Function & Vendor String" },
    { 0x80000001, "Extended Processor & Feature ID" },
    { 0x80000002, "Extended Processor Name String" },
    { 0x80000003, "Extended Processor Name String" },
    { 0x80000004, "Extended Processor Name String" },
    { 0x80000005, "L1 & TLB Info" },
    { 0x80000006, "L2 + L3 Cache & TLB Info" },
    { 0x80000007, "Processor Power MGMT & RAS Capabilities" },
    { 0x80000008, "Processor Capacity Param & Extd Feature ID" },
    // { 0x80000009, "RESERVED" },
    { 0x8000000A, "SVM Features" },
    // { 0x8000000B, "RESERVED" },
    // { 0x8000000C, "RESERVED" },
    // { 0x8000000D, "RESERVED" },
    // { 0x8000000E, "RESERVED" },
    // { 0x8000000F, "RESERVED" },
    // { 0x80000010, "RESERVED" },
    // { 0x80000011, "RESERVED" },
    // { 0x80000012, "RESERVED" },
    // { 0x80000013, "RESERVED" },
    // { 0x80000014, "RESERVED" },
    // { 0x80000015, "RESERVED" },
    // { 0x80000016, "RESERVED" },
    // { 0x80000017, "RESERVED" },
    // { 0x80000018, "RESERVED" },
    { 0x80000019, "TLB Characteristics for 1GB pages" },
    { 0x8000001A, "Instruction Optimizations" },
    { 0x8000001B, "Instruction-Based Sampling Capabilities" },
    { 0x8000001C, "Lightweight Profiling Capabilities" },
    { 0x8000001D, "Cache Topology Information" },
    { 0x8000001E, "Processor Topology Information" },
    { 0x8000001F, "SEV Capabilities" },
    { 0x80000020, "PQOS Extended Features" },
    { 0x80000021, "Extended Feature ID 2" },
    { 0x80000022, "Extended Performance Monitoring & Debug" },
    { 0x80000023, "Multi-Key Encrypted Memory Capabilties" },
    { 0x80000024, "RESERVED" },
    { 0x80000025, "SEV Capabilities 2" },
    { 0x80000026, "Extended CPU Topology" },
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
