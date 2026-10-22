/* SPDX-License-Identifier: MIT */
#ifndef SNAP_PMU_RTC_H
#define SNAP_PMU_RTC_H
#include <stdint.h>
#define PMU_RTC_CONTRACT UINT64_C(0xf715f704f802000e)
#define PMU_RTC_LIMIT_US ((UINT64_C(1)<<32)*1000000-1)

/* Common initial sequence with spmi_recovery, in the existing device union. */
struct device_pmu_rtc {
    uint32_t config_reads, config_writes, fifo_clears, ready;
    uint64_t epoch_us, start, frequency, last_now, last_ticks;
    uint64_t counter_reads, offset_reads, offset_writes, rejected;
    uint64_t last_command, last_length;
    uint8_t offset[6]; /* legacy seconds at f704; fractional ticks at f715 */
};
static inline int pmu_rtc_start(struct device_pmu_rtc *s, uint64_t epoch_us,
                                uint64_t now, uint64_t frequency)
{
    *s=(struct device_pmu_rtc){0};
    if (!epoch_us || epoch_us>PMU_RTC_LIMIT_US || !frequency || frequency>UINT32_MAX) return 0;
    s->epoch_us=epoch_us; s->start=s->last_now=now; s->frequency=frequency;
    s->ready=1; return 1;
}
/* Native six-byte f802 reads drop bit 0, giving unsigned 47-bit 32768-Hz
 * ticks. Advance from the host UTC seed only with the monotonic counter. */
static inline int pmu_rtc_sample(struct device_pmu_rtc *s, uint64_t now, uint64_t *ticks)
{
    if (!s->ready || !s->frequency || s->frequency>UINT32_MAX ||
        !s->epoch_us || s->epoch_us>PMU_RTC_LIMIT_US || now<s->last_now || now<s->start) return 0;
    uint64_t seed=(s->epoch_us/1000000)*32768+(s->epoch_us%1000000)*32768/1000000;
    uint64_t delta=now-s->start, seconds=delta/s->frequency;
    uint64_t limit=(UINT64_C(1)<<47)-1;
    if (seconds>(limit-seed)/32768) return 0;
    uint64_t value=seed+seconds*32768+(delta%s->frequency)*32768/s->frequency;
    if (value>limit) return 0;
    s->last_now=now; s->last_ticks=value; *ticks=value; return 1;
}
/* Only SID 14's counter and two offset fields exist. Unknown registers,
 * alarms, power commands and other slaves NACK. Validate the complete packet
 * before changing offset bytes; each counter packet takes one snapshot. */
static inline int pmu_rtc_transfer(struct device_pmu_rtc *s, uint32_t command,
                                   uint64_t now, const uint8_t *input, uint8_t *output)
{
    unsigned op=command&255, sid=(command>>8)&15, address=command>>16;
    unsigned read=op>=0x38 && op<=0x3f, write=op>=0x30 && op<=0x37, n=(op&7)+1;
    s->last_command=command; s->last_length=n;
    if (!s->ready || sid!=14 || (!read && !write)) goto refused;
    if (address>=0xf802 && address<=0xf807 && n<=0xf808-address) {
        uint64_t ticks;
        if (!read || !pmu_rtc_sample(s,now,&ticks)) goto refused;
        uint64_t raw=ticks<<1;
        for (unsigned i=0;i<n;i++) output[i]=(uint8_t)(raw>>(8*(address-0xf802+i)));
        s->counter_reads++; return 1;
    }
    unsigned at;
    if (address>=0xf704 && address<=0xf707 && n<=0xf708-address) at=address-0xf704;
    else if (address>=0xf715 && address<=0xf716 && n<=0xf717-address) at=4+address-0xf715;
    else goto refused;
    if (read) {
        for (unsigned i=0;i<n;i++) output[i]=s->offset[at+i];
        s->offset_reads++;
    } else {
        for (unsigned i=0;i<n;i++) s->offset[at+i]=input[i];
        s->offset_writes++;
    }
    return 1;
refused:
    s->rejected++; return 0;
}

/* SNAP_SPMI_SCRATCH (opt-in, default 0). The stock AppleDialogSPMIPMU
 * (26A428 ...9a20f24 and its caller) re-reads SID 14's legacy scratchpad
 * (info-leg_scrpad f700: f701, f708/4, f702, f718, f719/2, f700) and the LPM
 * log/control words (info-scrpad_lpm_log 8f80: 8f84/4; info-scrpad_lpm_ctrl
 * 8fdc/4) on every boot/LPM property refresh. Refused, each read is a reply
 * without valid frames: AppleSPMIController::extendedReadWriteCommand logs
 * "parity error" plus one line per byte, AppleDialogPMU::_readRegs logs and
 * IOSleep(1)s, four times (pmu-spmi-retry 3, pmu-spmi-delay 1: DT defaults).
 * With the option these two windows are volatile bytes, zero at model start,
 * i.e. a PMU whose scratchpad holds no boot-error or LPM record: long reads
 * return the stored bytes with valid frames, long writes are ACKed and kept.
 * Nothing is persisted and no PMU action follows a write. The RTC offset
 * fields keep their model; accesses that overlap them, all other addresses,
 * other slaves and other command forms still NACK exactly as before. */
#ifndef SNAP_SPMI_SCRATCH
#define SNAP_SPMI_SCRATCH 0
#endif
#if SNAP_SPMI_SCRATCH
struct device_pmu_scratch {
    uint8_t rtc[sizeof(struct device_pmu_rtc)]; /* pmu_rtc's bytes: never accessed here */
    uint8_t legacy[0x100], lpm[0x80];           /* f700..f7ff, 8f80..8fff */
    uint32_t reads, writes;
};
static inline void pmu_scratch_start(struct device_pmu_scratch *s)
{
    for (unsigned i=0;i<sizeof(s->legacy);i++) s->legacy[i]=0;
    for (unsigned i=0;i<sizeof(s->lpm);i++) s->lpm[i]=0;
    s->reads=s->writes=0;
}
static inline int pmu_scratch_transfer(struct device_pmu_scratch *s, uint32_t command,
                                       const uint8_t *input, uint8_t *output)
{
    unsigned op=command&255, sid=(command>>8)&15, address=command>>16;
    unsigned read=op>=0x38 && op<=0x3f, write=op>=0x30 && op<=0x37, n=(op&7)+1;
    uint8_t *bytes;
    if (sid!=14 || (!read && !write)) return 0;
    if (address>=0xf700 && address+n<=0xf800) {
        if ((address<0xf708 && address+n>0xf704) || (address<0xf717 && address+n>0xf715))
            return 0;
        bytes=s->legacy+(address-0xf700);
    } else if (address>=0x8f80 && address+n<=0x9000) bytes=s->lpm+(address-0x8f80);
    else return 0;
    for (unsigned i=0;i<n;i++) {
        if (read) output[i]=bytes[i];
        else bytes[i]=input[i];
    }
    if (read) { if (s->reads!=UINT32_MAX) s->reads++; }
    else if (s->writes!=UINT32_MAX) s->writes++;
    return 1;
}
#endif
#endif
