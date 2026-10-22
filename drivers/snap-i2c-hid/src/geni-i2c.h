/* SPDX-License-Identifier: MIT */
/*
 * Polled GENI serial-engine I2C master in FIFO mode.
 *
 * Hardware independent: every register access, clock read and delay goes
 * through struct geni_i2c_io, so the kext (src/SnapI2CHID.cpp) and the host
 * test (tools/test-snap-i2c-hid.c) compile this same file unchanged.
 *
 * Register offsets and bit meanings are interface facts from Linux's
 * include/linux/soc/qcom/geni-se.h (SHA256 30f381b6...) and
 * drivers/i2c/busses/i2c-qcom-geni.c (SHA256 53b3db09...); no Linux code is
 * copied. The transfer discipline is the one the A16 tools exercised on the
 * physical IC20 controller (tools/read-a16-hid-descriptor.py,
 * tools/read-a16-hid-report-descriptor.py): explicit transfer length, WRITE
 * (optionally with STOP_STRETCH) then READ, drain the receive FIFO by its word
 * count only, accept DONE once every word is consumed, recheck for late
 * errors, and on failure cancel then abort, both bounded. Clock, packing, DMA,
 * watermark and pin settings belong to firmware: they are checked, never
 * written. The only registers this file writes are TX/RX transfer length,
 * M_CMD0, M_CMD_CTRL, M_IRQ_EN, M_IRQ_CLEAR and the TX FIFO -- the same
 * writable set the physical tools used.
 */
#ifndef SNAP_GENI_I2C_H
#define SNAP_GENI_I2C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Byte offsets. Every register the driver touches lies in the first page. */
#define GENI_STATUS             0x040u
#define GENI_SER_M_CLK_CFG      0x048u
#define GENI_IF_DISABLE_RO      0x064u
#define GENI_FW_REVISION_RO     0x068u
#define GENI_BYTE_GRAN          0x254u
#define GENI_DMA_MODE_EN        0x258u
#define GENI_TX_PACKING_CFG0    0x260u
#define GENI_TX_PACKING_CFG1    0x264u
#define GENI_I2C_TX_TRANS_LEN   0x26cu
#define GENI_I2C_RX_TRANS_LEN   0x270u
#define GENI_I2C_SCL_COUNTERS   0x278u
#define GENI_RX_PACKING_CFG0    0x284u
#define GENI_RX_PACKING_CFG1    0x288u
#define GENI_M_CMD0             0x600u
#define GENI_M_CMD_CTRL         0x604u
#define GENI_M_IRQ_STATUS       0x610u
#define GENI_M_IRQ_EN           0x614u
#define GENI_M_IRQ_CLEAR        0x618u
#define GENI_TX_FIFO            0x700u
#define GENI_RX_FIFO            0x780u
#define GENI_TX_FIFO_STATUS     0x800u
#define GENI_RX_FIFO_STATUS     0x804u
#define GENI_RX_WATERMARK       0x810u
#define GENI_RX_RFR_WATERMARK   0x814u
#define GENI_IOS                0x908u
#define GENI_HW_PARAM_0         0xe24u
#define GENI_HW_PARAM_1         0xe28u
#define GENI_WINDOW_BYTES       0x1000u

/* GENI_STATUS */
#define GENI_M_ACTIVE           (1u << 0)
#define GENI_S_ACTIVE           (1u << 12)
/* M_CMD0: opcode in bits 31:27, parameters in bits 26:0. */
#define GENI_OPCODE_SHIFT       27
#define GENI_I2C_OP_WRITE       1u
#define GENI_I2C_OP_READ        2u
#define GENI_I2C_STOP_STRETCH   (1u << 2)
#define GENI_I2C_ADDR_SHIFT     9
/* M_CMD_CTRL */
#define GENI_CMD_ABORT          (1u << 1)
#define GENI_CMD_CANCEL         (1u << 2)
/* M_IRQ_STATUS, M_IRQ_EN and M_IRQ_CLEAR share one layout. */
#define GENI_IRQ_DONE           (1u << 0)
#define GENI_IRQ_OVERRUN        (1u << 1)
#define GENI_IRQ_ILLEGAL_CMD    (1u << 2)
#define GENI_IRQ_FAILURE        (1u << 3)
#define GENI_IRQ_CANCEL         (1u << 4)
#define GENI_IRQ_ABORT          (1u << 5)
#define GENI_IRQ_GP0            (1u << 9)
#define GENI_IRQ_NACK           (1u << 10)  /* GP_IRQ_1: address or data NACK */
#define GENI_IRQ_BUS_PROTO      (1u << 12)  /* GP_IRQ_3 */
#define GENI_IRQ_ARB_LOST       (1u << 13)  /* GP_IRQ_4 */
#define GENI_IRQ_RX_RD_ERR      (1u << 24)
#define GENI_IRQ_RX_WR_ERR      (1u << 25)
#define GENI_IRQ_RX_WM          (1u << 26)
#define GENI_IRQ_RX_LAST        (1u << 27)
#define GENI_IRQ_TX_RD_ERR      (1u << 28)
#define GENI_IRQ_TX_WR_ERR      (1u << 29)
#define GENI_IRQ_TX_WM          (1u << 30)
#define GENI_IRQ_FIFO_ERRORS    (GENI_IRQ_RX_RD_ERR | GENI_IRQ_RX_WR_ERR | \
                                 GENI_IRQ_TX_RD_ERR | GENI_IRQ_TX_WR_ERR)
#define GENI_IRQ_ERRORS         (GENI_IRQ_OVERRUN | GENI_IRQ_ILLEGAL_CMD | GENI_IRQ_FAILURE | \
                                 GENI_IRQ_GP0 | GENI_IRQ_NACK | GENI_IRQ_BUS_PROTO | \
                                 GENI_IRQ_ARB_LOST | GENI_IRQ_FIFO_ERRORS)
#define GENI_IRQ_EVENTS         (GENI_IRQ_DONE | GENI_IRQ_CANCEL | GENI_IRQ_ABORT | \
                                 GENI_IRQ_RX_WM | GENI_IRQ_RX_LAST | GENI_IRQ_TX_WM | \
                                 GENI_IRQ_ERRORS)
/* FIFO status */
#define GENI_TX_FIFO_WC_MASK    0x0fffffffu
#define GENI_RX_FIFO_WC_MASK    0x01ffffffu
#define GENI_RX_LAST            (1u << 31)
#define GENI_RX_LAST_BYTES_SHIFT 28
#define GENI_RX_LAST_BYTES_MASK 7u
/* Firmware state this driver requires (all observed on IC20, generations 54-59). */
#define GENI_PROTOCOL_I2C       3u
#define GENI_PACKING_CFG0       0x0007f8feu  /* 8-bit bytes, four per word, byte 0 in bits 7:0 */
#define GENI_PACKING_CFG1       0x000ffefeu

enum geni_i2c_result {
    GENI_I2C_OK = 0,
    GENI_I2C_NACK,          /* address or data byte not acknowledged */
    GENI_I2C_BUS_ERROR,     /* bus protocol error or arbitration lost */
    GENI_I2C_CONTROLLER,    /* overrun, illegal command, failure, GP0 or FIFO access error */
    GENI_I2C_TIMEOUT,       /* no completion before the deadline */
    GENI_I2C_SHORT,         /* completion before the requested byte count */
    GENI_I2C_EXCESS,        /* more words than requested, impossible occupancy, bad last word */
    GENI_I2C_BUSY,          /* engine active or FIFOs not empty when a transfer should begin */
    GENI_I2C_CONFIG,        /* firmware left the engine in a mode this driver does not drive */
    GENI_I2C_WEDGED,        /* cleanup could not return to idle and empty: no further MMIO */
    GENI_I2C_INVALID,       /* argument out of range, or not started */
    GENI_I2C_RESULT_COUNT
};

enum geni_i2c_irq_policy {
    /* Saved enable | GENI_IRQ_EVENTS: exactly what the physical tools wrote. */
    GENI_I2C_IRQ_EVENTS = 0,
    /* Enable register 0 so the engine can never raise its interrupt line.
     * Requires M_IRQ_STATUS to latch without enables; the generation54-57
     * surveys suggest it does (bit 7 latched while its enable was clear) but
     * this is qualified only by the hardware check in
     * docs/A16-INPUT-DRIVER-20260928.md. */
    GENI_I2C_IRQ_MASKED = 1,
};

struct geni_i2c_io {
    void *ctx;
    uint32_t (*read32)(void *ctx, uint32_t offset);
    void (*write32)(void *ctx, uint32_t offset, uint32_t value);
    uint64_t (*now_us)(void *ctx);                       /* monotonic microseconds */
    void (*delay_us)(void *ctx, uint32_t microseconds);  /* may sleep */
};

struct geni_i2c_stats {
    uint32_t writes, reads, ok;
    uint32_t nacks, bus_errors, controller_errors, timeouts, shorts, excess, busy;
    uint32_t cancels, aborts, stale_events, late_errors, discarded_words;
    uint32_t recoveries, recovered_words;
};

struct geni_i2c {
    struct geni_i2c_io io;
    uint32_t bus_hz;
    uint32_t tx_fifo_words, rx_fifo_words;
    uint32_t irq_policy;
    /* Firmware values restored by geni_i2c_stop. */
    uint32_t saved_irq_en, saved_tx_len, saved_rx_len;
    /* Firmware state observed at start, for diagnostics. */
    uint32_t initial_status, initial_ios, clock_cfg, scl_counters;
    /* The failing transfer's evidence. */
    uint32_t last_status, last_tx_fifo, last_rx_fifo, last_result;
    /* What geni_i2c_start found when the engine was not idle and empty
     * (GENI_STATUS, M_IRQ_STATUS, M_IRQ_EN, TX and RX FIFO status), whether
     * it then refused or recovered; read before any write. */
    uint32_t found_status, found_irq, found_irq_en, found_tx_fifo, found_rx_fifo;
    uint8_t started, wedged, recovered;
    struct geni_i2c_stats stats;
};

/* Validate firmware state, save the three writable settings and apply the
 * interrupt-enable policy. Performs no write unless every check passes.
 *
 * One exception, for a controller a previous SnapI2CHID run left behind
 * without geni_i2c_stop (a panic or a monitor stop mid-run, then a chainload:
 * the QUP keeps its registers): with the masked policy, M_IRQ_EN == 0 (this
 * driver's own programming; firmware leaves its enables set and the q1n1
 * tools restore them) and every firmware-owned setting as checked, an engine
 * that is busy, holds receive words or a latched error is recovered: let an
 * in-flight transfer finish (servicing a full receive FIFO), else cancel then
 * abort, bounded; discard exactly the receive words the FIFO reports; clear
 * the latched status; then require idle, empty and error-free. Leftover
 * transmit words, the secondary engine, or any state with other enables is
 * refused as before. Recovery that cannot reach idle returns GENI_I2C_WEDGED. */
int geni_i2c_start(struct geni_i2c *c, const struct geni_i2c_io *io, uint32_t bus_hz,
                   uint32_t irq_policy);
/* Restore the saved settings when the engine is idle and empty. */
int geni_i2c_stop(struct geni_i2c *c);
/* One WRITE of 1..4*tx_fifo_words bytes. stop_stretch holds the bus for a
 * following READ (repeated START), as I2C-HID register reads require. */
int geni_i2c_write(struct geni_i2c *c, uint8_t addr, const uint8_t *data, uint32_t len,
                   int stop_stretch);
/* One READ of 1..65535 bytes, draining the receive FIFO while it runs. */
int geni_i2c_read(struct geni_i2c *c, uint8_t addr, uint8_t *data, uint32_t len);
const char *geni_i2c_result_name(int result);

#ifdef __cplusplus
}
#endif

#endif
