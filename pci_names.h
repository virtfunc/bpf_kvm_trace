#ifndef __PCI_NAMES_H
#define __PCI_NAMES_H

#include <stddef.h>

static inline const char *get_pci_reg_name(unsigned int reg) {
    if (reg <= 0x01) return "PCI_VENDOR_ID";
    if (reg >= 0x02 && reg <= 0x03) return "PCI_DEVICE_ID";
    if (reg >= 0x04 && reg <= 0x05) return "PCI_COMMAND";
    if (reg >= 0x06 && reg <= 0x07) return "PCI_STATUS";
    if (reg == 0x08) return "PCI_REVISION_ID";
    if (reg == 0x09) return "PCI_PROG_IF";
    if (reg == 0x0A) return "PCI_SUB_CLASS";
    if (reg == 0x0B) return "PCI_BASE_CLASS";
    if (reg == 0x0C) return "PCI_CACHE_LINE_SIZE";
    if (reg == 0x0D) return "PCI_LATENCY_TIMER";
    if (reg == 0x0E) return "PCI_HEADER_TYPE";
    if (reg == 0x0F) return "PCI_BIST";
    if (reg >= 0x10 && reg <= 0x13) return "PCI_BAR0";
    if (reg >= 0x14 && reg <= 0x17) return "PCI_BAR1";
    if (reg >= 0x18 && reg <= 0x1B) return "PCI_BAR2";
    if (reg >= 0x1C && reg <= 0x1F) return "PCI_BAR3";
    if (reg >= 0x20 && reg <= 0x23) return "PCI_BAR4";
    if (reg >= 0x24 && reg <= 0x27) return "PCI_BAR5";
    if (reg >= 0x28 && reg <= 0x2B) return "PCI_CARDBUS_CIS";
    if (reg >= 0x2C && reg <= 0x2D) return "PCI_SUBSYSTEM_VENDOR_ID";
    if (reg >= 0x2E && reg <= 0x2F) return "PCI_SUBSYSTEM_ID";
    if (reg >= 0x30 && reg <= 0x33) return "PCI_ROM_ADDRESS";
    if (reg >= 0x34 && reg <= 0x3B) return "PCI_CAPABILITY_PTR";
    if (reg == 0x3C) return "PCI_INTERRUPT_LINE";
    if (reg == 0x3D) return "PCI_INTERRUPT_PIN";
    if (reg == 0x3E) return "PCI_MIN_GNT";
    if (reg == 0x3F) return "PCI_MAX_LAT";
    if (reg >= 0x40 && reg < 0x100) return "PCI_CAP_SPACE";
    if (reg >= 0x100) return "PCIe_EXT_CAP_SPACE";
    return "PCI_CONFIG";
}

#endif // __PCI_NAMES_H
