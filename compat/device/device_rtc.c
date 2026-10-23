/* SPDX-License-Identifier: MIT */
/* The SPMI controller model that serves the PMU RTC and scratch registers.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */
/* Extended packet forms carry a register address in EXTRA. The stock
 * payloadless register-zero form uses opcode80 and its seven-bit byte at
 * bits31:24, with no following FIFO payload. Stock short reads use opcode60
 * and the five-bit register at bits20:16. Stock short writes use opcode40:
 * 26A428 AppleSPMIController::registerReadWriteCommand (...9a14858) takes
 * opcode table ...769fc08 index 5, requires register <= 0x1f and length 1,
 * and ORs the data byte at bits31:24 -- one header, no FIFO payload.
 * executeCommand (...9a15624) refuses types above 11, so 0x14..0x1b are never
 * issued; they and newer XSPMI extensions remain refused.
 * A missing slave produces a reply with no ACK and no valid read frames. */
static int spmi_packet(uint32_t command, unsigned *input, unsigned *output)
{
    unsigned op=command & 255;
    if (command & 0x7000) return 0;
    if ((op <= 0x0f || (op >= 0x20 && op <= 0x2f)) && (command >> 24)) return 0;
    if (((op >= 0x10 && op <= 0x13) || op == 0x1c) && (command >> 16)) return 0;
    if (op == 0x80 && (command & 0x80ff0000U)) return 0;
    if (op == 0x60 && (command & 0xffe00000U)) return 0;
    if (op == 0x40 && (command & 0x00e00000U)) return 0;
    *input=*output=0;
    if (op <= 0x0f) *input=(op & 15)+1;
    else if (op >= 0x20 && op <= 0x2f) *output=(op & 15)+1;
    else if (op >= 0x30 && op <= 0x37) *input=(op & 7)+1;
    else if (op >= 0x38 && op <= 0x3f) *output=(op & 7)+1;
    else if (op == 0x1c) *output=10;
    else if (op == 0x60) *output=1;
    else if (op != 0x80 && op != 0x40 && (op < 0x10 || op > 0x13)) return 0;
    return 1;
}

static void spmi_complete(const struct device_model *d, struct device_state *s, uint64_t now)
{
    unsigned input=0, output=0;
    spmi_packet(s->spmi.command,&input,&output);
    uint8_t data[16]={0};
#if SNAP_SPMI_SCRATCH
    /* Scratch first: it never claims an RTC byte, and a served scratch
     * command must not count as an RTC rejection. */
    int success=d->kind==DEVICE_SPMI_PMU_RTC_V1 &&
        (pmu_scratch_transfer(&s->pmu_scratch,s->spmi.command,
                              (const uint8_t *)s->spmi.payload,data) ||
         pmu_rtc_transfer(&s->pmu_rtc,s->spmi.command,now,
                          (const uint8_t *)s->spmi.payload,data));
#else
    int success=d->kind==DEVICE_SPMI_PMU_RTC_V1 &&
        pmu_rtc_transfer(&s->pmu_rtc,s->spmi.command,now,
                         (const uint8_t *)s->spmi.payload,data);
#endif
    unsigned words=1+(output+3)/4;
    for (unsigned i=0; i<words; i++) {
        unsigned slot=(s->spmi.rx_head+s->spmi.rx_count++) % DEVICE_SPMI_FIFO_MAX;
        uint32_t value=s->spmi.command&0xfff;
        if (!i && success) value|=output ? ((1U<<output)-1)<<16 : 1U<<15;
        if (i) {
            value=0;
            for (unsigned j=0;j<4;j++) value|=(uint32_t)data[(i-1)*4+j]<<(8*j);
        }
        s->spmi.rx[slot]=value;
    }
    /* IRQ bank 8: failed read / missing write ACK; ALERT only on request. */
    if (!success) s->spmi.flags[8] |= 1U << (output ? 6 : 7);
    if (s->spmi.command & 0x8000) s->spmi.flags[8] |= 1;
    s->spmi.tx_words=s->spmi.tx_need=0;
}

static enum device_result spmi_access(const struct device_model *d,
    struct device_state *s, uint64_t now, uint64_t offset, unsigned width, int write, uint64_t *value)
{
    if (!s) return DEVICE_BAD_CONFIG;
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (write && *value > UINT32_MAX) return DEVICE_BAD_VALUE;
    uint64_t reg;
    if (offset >= d->config[0]) reg=offset-d->config[0];
    else if (offset == d->config[1] || offset == d->config[1]+8) {
        /* AppleSPMIController::dumpFaultQueue uses descriptor +30/+38,
         * separately from queuePop's +08/+18 response FIFO. Aliasing them
         * lets the fault IRQ handler steal the caller's negative reply.
         * This virtual empty bus has no diagnostic fault-record producer;
         * NACK/invalid-frame completion and its IRQ flags remain real. */
        if (write) return DEVICE_READ_ONLY;
        if (offset != d->config[1]) return DEVICE_BAD_VALUE;
        *value=1U<<24; /* independent fault queue: RX_EMPTY */
        return DEVICE_OK;
    }
    else return DEVICE_UNKNOWN_REGISTER;
    if (reg == 0) {
        if (write) return DEVICE_READ_ONLY;
        *value=(s->spmi.tx_words ? s->spmi.tx_words : 1U<<8) |
            (s->spmi.rx_count ? (s->spmi.rx_count & 255U)<<16 : 1U<<24) |
            (s->spmi.rx_count == DEVICE_SPMI_FIFO_MAX ? 1U<<25 : 0);
        return DEVICE_OK;
    }
    if (reg == 4) {
        if (!write) return DEVICE_READ_ONLY;
        if (s->spmi.tx_words) {
            s->spmi.payload[s->spmi.tx_words-1]=(uint32_t)*value;
            if (++s->spmi.tx_words == s->spmi.tx_need) spmi_complete(d,s,now);
            return DEVICE_OK;
        }
        unsigned input, output;
        if (!spmi_packet((uint32_t)*value,&input,&output)) return DEVICE_BAD_VALUE;
        /* Reserve the entire reply before accepting any part of a command. */
        if (1+(output+3)/4 > DEVICE_SPMI_FIFO_MAX-s->spmi.rx_count)
            return DEVICE_BAD_VALUE;
        s->spmi.command=(uint32_t)*value;
        s->spmi.tx_words=1; s->spmi.tx_need=1+(input+3)/4;
        if (s->spmi.tx_need == 1) spmi_complete(d,s,now);
        return DEVICE_OK;
    }
    if (reg == 8) {
        if (write) return DEVICE_READ_ONLY;
        if (!s->spmi.rx_count) return DEVICE_BAD_VALUE;
        *value=s->spmi.rx[s->spmi.rx_head];
        s->spmi.rx_head=(s->spmi.rx_head+1)%DEVICE_SPMI_FIFO_MAX;
        s->spmi.rx_count--;
        return DEVICE_OK;
    }
    if (reg >= 0x20 && reg <= 0x40) {
        unsigned bank=(reg-0x20)/4;
        if (write) s->spmi.enable[bank]=(uint32_t)*value;
        else *value=s->spmi.enable[bank];
        return DEVICE_OK;
    }
    if (reg >= 0x60 && reg <= 0x80) {
        unsigned bank=(reg-0x60)/4;
        if (write) s->spmi.flags[bank] &= ~(uint32_t)*value;
        else *value=s->spmi.flags[bank];
        return DEVICE_OK;
    }
    if (reg == 0xa0) {
        /* The selected gen-3 driver saves this word, writes zero, drains or
         * clears FIFOs, and restores it. This virtual bus owns no physical
         * master modes, so only its declared quiescent boot value zero is
         * supported. Do not adopt another SoC's undocumented mode bits.
         * Configuration writes alone never consume or acknowledge a reply. */
        if (write) {
            if (*value) return DEVICE_BAD_VALUE;
            if (s->spmi_recovery.config_writes != UINT32_MAX)
                s->spmi_recovery.config_writes++;
        } else {
            *value=0;
            if (s->spmi_recovery.config_reads != UINT32_MAX)
                s->spmi_recovery.config_reads++;
        }
        return DEVICE_OK;
    }
    if (reg == 0xa4) {
        if (!write) { *value=0; return DEVICE_OK; }
        if (*value > 1) return DEVICE_BAD_VALUE;
        if (*value) {
            s->spmi.rx_head=s->spmi.rx_count=0;
            s->spmi.tx_words=s->spmi.tx_need=0;
            if (s->spmi_recovery.fifo_clears != UINT32_MAX)
                s->spmi_recovery.fifo_clears++;
        }
        return DEVICE_OK;
    }
    return DEVICE_UNKNOWN_REGISTER;
}

