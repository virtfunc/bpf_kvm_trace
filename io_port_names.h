#ifndef __IO_PORT_NAMES_H
#define __IO_PORT_NAMES_H

#include <stddef.h>

struct io_port_def {
    unsigned int port;
    const char *name;
};

/* Sorted by port number for binary search */
static const struct io_port_def io_port_names[] = {
    { 0x0020, "PIC1_CMD" },
    { 0x0021, "PIC1_DATA" },
    { 0x0040, "PIT_CH0" },
    { 0x0041, "PIT_CH1" },
    { 0x0042, "PIT_CH2" },
    { 0x0043, "PIT_CMD" },
    { 0x0060, "KBD_DATA" },
    { 0x0061, "KBD_CTRL_B" },
    { 0x0064, "KBD_STATUS" },
    { 0x0070, "CMOS_ADDR" },
    { 0x0071, "CMOS_DATA" },
    { 0x0080, "DIAG_POST" },
    { 0x00A0, "PIC2_CMD" },
    { 0x00A1, "PIC2_DATA" },
    { 0x00B2, "APM_CNT" },
    { 0x00B3, "APM_STS" },
    { 0x00CF8, "PCI_CONFIG_ADDR" },
    { 0x00CFC, "PCI_CONFIG_DATA" },
    { 0x00CFD, "PCI_CONFIG_DATA+1" },
    { 0x00CFE, "PCI_CONFIG_DATA+2" },
    { 0x00CFF, "PCI_CONFIG_DATA+3" },
    { 0x00F0, "FPU_IRQ_CLR" },
    { 0x01F0, "IDE1_DATA" },
    { 0x01F7, "IDE1_STATUS" },
    { 0x02F8, "COM2_DATA" },
    { 0x02F9, "COM2_IER" },
    { 0x02FA, "COM2_IIR" },
    { 0x02FB, "COM2_LCR" },
    { 0x02FC, "COM2_MCR" },
    { 0x02FD, "COM2_LSR" },
    { 0x03D4, "VGA_CRTC_ADDR" },
    { 0x03D5, "VGA_CRTC_DATA" },
    { 0x03F8, "COM1_DATA" },
    { 0x03F9, "COM1_IER" },
    { 0x03FA, "COM1_IIR" },
    { 0x03FB, "COM1_LCR" },
    { 0x03FC, "COM1_MCR" },
    { 0x03FD, "COM1_LSR" },
    { 0x04D0, "ELCR1" },
    { 0x04D1, "ELCR2" },
    { 0x0510, "FW_CFG_PORT" },
    { 0x0511, "FW_CFG_DATA" },
    { 0x0514, "FW_CFG_DMA" },
    { 0x0600, "ACPI_PM1_STS" },
    { 0x0604, "ACPI_PM1_CNT" },
    { 0x0608, "ACPI_PM_TMR" },
    { 0x0620, "ACPI_GPE0_STS" },
    { 0x0628, "ACPI_GPE0_EN" },
    { 0xAE00, "PVPANIC" },
    { 0xC000, "VIRTIO_PCI_0" },
    { 0xC040, "VIRTIO_PCI_1" },
    { 0xC080, "VIRTIO_PCI_2" },
    { 0xC0C0, "VIRTIO_PCI_3" },
};

static inline const char *get_io_port_name(unsigned int port) {
    int left = 0, right = sizeof(io_port_names)/sizeof(io_port_names[0]) - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (io_port_names[mid].port == port) return io_port_names[mid].name;
        if (io_port_names[mid].port < port) left = mid + 1;
        else right = mid - 1;
    }

    /* Check well-known port ranges */
    if (port >= 0x03F8 && port <= 0x03FF) return "COM1";
    if (port >= 0x02F8 && port <= 0x02FF) return "COM2";
    if (port >= 0x03E8 && port <= 0x03EF) return "COM3";
    if (port >= 0x02E8 && port <= 0x02EF) return "COM4";
    if (port >= 0x01F0 && port <= 0x01F7) return "IDE1";
    if (port >= 0x0170 && port <= 0x0177) return "IDE2";
    if (port >= 0xC000 && port <= 0xC0FF) return "VIRTIO_PCI";

    return "UNKNOWN";
}

#endif // __IO_PORT_NAMES_H
