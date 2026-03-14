#ifndef __MSR_NAMES_H
#define __MSR_NAMES_H

#include <stdio.h>
#include <stddef.h>

struct msr_def {
    unsigned int index;
    const char *name;
};

static const struct msr_def msr_names[] = {
    /* Standard x86 MSRs */
    { 0x00000000, "MSR_IA32_P5_MC_ADDR" }, // should return 0 on the metal, legacy now undocumented on amd.
    { 0x00000010, "MSR_IA32_TSC" },
    { 0x0000001B, "MSR_IA32_APICBASE" },
    { 0x0000003A, "MSR_IA32_FEATURE_CONTROL" },
    { 0x000000FE, "MSR_IA32_MTRRCAP" },
    { 0x00000174, "MSR_IA32_SYSENTER_CS" },
    { 0x00000175, "MSR_IA32_SYSENTER_ESP" },
    { 0x00000176, "MSR_IA32_SYSENTER_EIP" },
    { 0x000001A0, "MSR_IA32_MISC_ENABLE" },
    { 0x00000277, "MSR_IA32_CR_PAT" },
    { 0x00000179, "MSR_MCG_CAP" },
    { 0x0000017A, "MSR_MCG_STATUS" },
    { 0x0000017B, "MSR_MCG_CTL" },

    /* MTRRs */
    { 0x00000250, "MSR_IA32_MTRR_FIX64K_00000" },
    { 0x00000258, "MSR_IA32_MTRR_FIX16K_80000" },
    { 0x00000259, "MSR_IA32_MTRR_FIX16K_A0000" },
    { 0x00000268, "MSR_IA32_MTRR_FIX4K_C0000" },
    { 0x00000269, "MSR_IA32_MTRR_FIX4K_C8000" },
    { 0x0000026A, "MSR_IA32_MTRR_FIX4K_D0000" },
    { 0x0000026B, "MSR_IA32_MTRR_FIX4K_D8000" },
    { 0x0000026C, "MSR_IA32_MTRR_FIX4K_E0000" },
    { 0x0000026D, "MSR_IA32_MTRR_FIX4K_E8000" },
    { 0x0000026E, "MSR_IA32_MTRR_FIX4K_F0000" },
    { 0x0000026F, "MSR_IA32_MTRR_FIX4K_F8000" },
    { 0x000002FF, "MSR_IA32_MTRR_DEF_TYPE" },

    /* Software Debug MSR */
    { 0x000001D9, "MSR_DEBUGCTL" },
    { 0x000001DB, "MSR_LASTBRANCHFROMIP" },
    { 0x000001DC, "MSR_LASTBRANCHTOIP" },
    { 0x000001DD, "MSR_LASTINTFROMIP" },
    { 0x000001DE, "MSR_LASTINTTOIP" },
    { 0xC0001027, "DR0_ADDR_MASK" },
    { 0xC0001019, "DR1_ADDR_MASK" },
    { 0xC000101A, "DR2_ADDR_MASK" },
    { 0xC000101B, "DR3_ADDR_MASK" },



    /* KVM MSRs */
    { 0x4b564d00, "MSR_KVM_WALL_CLOCK" },
    { 0x4b564d01, "MSR_KVM_SYSTEM_TIME" },
    { 0x4b564d02, "MSR_KVM_ASYNC_PF_EN" },
    { 0x4b564d03, "MSR_KVM_STEAL_TIME" },
    { 0x4b564d04, "MSR_KVM_PV_EOI_EN" },
    { 0x4b564d05, "MSR_KVM_POLL_CONTROL" },
    { 0x4b564d06, "MSR_KVM_ASYNC_PF_INT" },
    { 0x4b564d07, "MSR_KVM_ASYNC_PF_ACK" },

    /* Hyper-V MSRs */
    { 0x40000000, "HV_X64_MSR_GUEST_OS_ID" },
    { 0x40000001, "HV_X64_MSR_HYPERCALL" },
    { 0x40000002, "HV_X64_MSR_VP_INDEX" },
    { 0x40000003, "HV_X64_MSR_RESET" },
    { 0x40000004, "HV_X64_MSR_VP_RUNTIME" },
    { 0x40000005, "HV_X64_MSR_TIME_REF_COUNT" },
    { 0x40000020, "HV_X64_MSR_REFERENCE_TSC" },
    { 0x40000021, "HV_X64_MSR_TSC_FREQUENCY" },
    { 0x40000022, "HV_X64_MSR_APIC_FREQUENCY" },
    { 0x40000080, "HV_X64_MSR_SCONTROL" },
    { 0x40000081, "HV_X64_MSR_SVERSION" },
    { 0x40000082, "HV_X64_MSR_SIEFP" },
    { 0x40000083, "HV_X64_MSR_SIMP" },
    { 0x40000084, "HV_X64_MSR_EOM" },
    { 0x40000090, "HV_X64_MSR_SINT0" },
    { 0x40000091, "HV_X64_MSR_SINT1" },
    { 0x40000092, "HV_X64_MSR_SINT2" },
    { 0x40000093, "HV_X64_MSR_SINT3" },
    { 0x40000094, "HV_X64_MSR_SINT4" },
    { 0x40000095, "HV_X64_MSR_SINT5" },
    { 0x40000096, "HV_X64_MSR_SINT6" },
    { 0x40000097, "HV_X64_MSR_SINT7" },
    { 0x40000098, "HV_X64_MSR_SINT8" },
    { 0x40000099, "HV_X64_MSR_SINT9" },
    { 0x4000009A, "HV_X64_MSR_SINT10" },
    { 0x4000009B, "HV_X64_MSR_SINT11" },
    { 0x4000009C, "HV_X64_MSR_SINT12" },
    { 0x4000009D, "HV_X64_MSR_SINT13" },
    { 0x4000009E, "HV_X64_MSR_SINT14" },
    { 0x4000009F, "HV_X64_MSR_SINT15" },
    { 0x400000A0, "HV_X64_MSR_STIMER0_CONFIG" },
    { 0x400000A1, "HV_X64_MSR_STIMER0_COUNT" },
    { 0x400000A2, "HV_X64_MSR_STIMER1_CONFIG" },
    { 0x400000A3, "HV_X64_MSR_STIMER1_COUNT" },
    { 0x400000A4, "HV_X64_MSR_STIMER2_CONFIG" },
    { 0x400000A5, "HV_X64_MSR_STIMER2_COUNT" },
    { 0x400000A6, "HV_X64_MSR_STIMER3_CONFIG" },
    { 0x400000A7, "HV_X64_MSR_STIMER3_COUNT" },
    { 0x40000110, "HV_X64_MSR_CRASH_P0" },
    { 0x40000111, "HV_X64_MSR_CRASH_P1" },
    { 0x40000112, "HV_X64_MSR_CRASH_P2" },
    { 0x40000113, "HV_X64_MSR_CRASH_P3" },
    { 0x40000114, "HV_X64_MSR_CRASH_P4" },
    { 0x40000115, "HV_X64_MSR_CRASH_CTL" },

    /* AMD / Common MSRs */
    { 0xC0000080, "MSR_EFER" },
    { 0xC0000081, "MSR_STAR" },
    { 0xC0000082, "MSR_LSTAR" },
    { 0xC0000083, "MSR_CSTAR" },
    { 0xC0000084, "MSR_SYSCALL_MASK" },
    { 0xC0000100, "MSR_FS_BASE" },
    { 0xC0000101, "MSR_GS_BASE" },
    { 0xC0000102, "MSR_KERNEL_GS_BASE" },
    { 0xC0000103, "MSR_TSC_AUX" },
    { 0xC0010010, "MSR_SYSCFG" },
};

static inline const char *get_msr_name(unsigned int index)
{
    for (size_t i = 0; i < sizeof(msr_names) / sizeof(msr_names[0]); i++) {
        if (msr_names[i].index == index) {
            return msr_names[i].name;
        }
    }
    
    // Variable MTRRs
    if (index >= 0x200 && index <= 0x21F) {
        static char mtrr_name[32];
        unsigned int bank = (index - 0x200) / 2;
        if (index % 2 == 0) {
            snprintf(mtrr_name, sizeof(mtrr_name), "MSR_IA32_MTRR_PHYSBASE%u", bank);
        } else {
            snprintf(mtrr_name, sizeof(mtrr_name), "MSR_IA32_MTRR_PHYSMASK%u", bank);
        }
        return mtrr_name;
    }

    // Machine Check Architecture MSRs (IA32_MCi_*)
    if (index >= 0x400 && index < (0x400 + 4 * 32)) { // Support up to 32 MC banks
        static char mc_msr_name[32];
        unsigned int bank = (index - 0x400) / 4;
        unsigned int type = index % 4;
        const char *type_name;

        switch (type) {
            case 0: type_name = "CTL"; break;
            case 1: type_name = "STATUS"; break;
            case 2: type_name = "ADDR"; break;
            case 3: type_name = "MISC"; break;
            default: type_name = "???"; break; // Should not happen
        }
        snprintf(mc_msr_name, sizeof(mc_msr_name), "MSR_IA32_MC%u_%s", bank, type_name);
        return mc_msr_name;
    }

    if (index >= 0x40000000 && index <= 0x4000FFFF) return "HV_UNKNOWN";
    if (index >= 0x4b564d00 && index <= 0x4b564dFF) return "KVM_UNKNOWN";
    
    return "UNKNOWN";
}

#endif // __MSR_NAMES_H