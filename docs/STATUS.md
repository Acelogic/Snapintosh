# Status & Validation

Hardware validation status for the ASUS Zenbook A16 (X2E-96-100) running macOS 27 (build 26A428),
identified limitations, and ongoing engineering milestones. Metrics reflect validated desktop sessions (25–30 minutes duration).

## What works

| Area | State |
| --- | --- |
| Boot | The stock J700/T8140 kernel boots on six vCPUs from macOS installed on the internal NVMe. It reaches launchd, WindowServer, the login window and the desktop. |
| Graphics | The desktop renders on the Adreno X2-90 through AdrenoMetal, AdrenoX2 and air2ir3, with no software fallback. A pixel probe over 14 desktop scenes (36 frames) passes with 0 mismatching tiles. Core Animation effects, icons and app content render. |
| Display | AdrenoDisplay drives the internal 2880x1800 panel at 60 Hz. With `--present-beam`, presentation is locked to the panel's vblank and is tear-free. |
| GPU | Asynchronous IB execution, pipelined WindowServer submissions, GPU recovery after an overrunning IB, a 15 GiB GPU address window, and GPU DVFS. Sessions have run at a 1185 MHz ceiling without GPU errors, below 72 °C. |
| Input | The keyboard and the touchpad (precision mode, presented as an Apple multitouch device). Window drags, scrolling, trackpad gestures, Mission Control and Cmd-Tab app switching all work. |
| Storage | The emulated ANS2 controller on the real NVMe, with asynchronous command completion (`--nvme-async`). |
| Wi-Fi | Through the host-proxy harness: scan, a WPA2-PSK connection, DHCP and ping. See below for the macOS side. |
| Stability | Full desktop sessions end on a requested stop, with no panic and no WindowServer crash in the latest configuration. |

## Known issues

- **Frame pacing and latency:** Desktop interaction is functional but exhibits timing jitter under load. Recent sessions demonstrate a median of 46–60 presentations/sec during active periods, with 1.7% to 5% of frame intervals exceeding 34 ms. Contributing factors:
  - *Present-gate deferrals:* Pipelined WindowServer updates can swap a surface while GPU execution is in-flight, deferring the display blit to the subsequent refresh interval.
  - *Periodic execution stalls (100–350 ms):* Non-GPU latency spikes correlated with verbose serial console logging and timer lateness.
  - *Monitor lock contention:* Synchronization latency during select SPTM calls, primarily page-attribute cache state transitions.
- **CPU DVFS ceilings:** Requests above intermediate performance states are restricted by system firmware, preventing CPU clusters from reaching theoretical maximum clocks.
- **Displays preference pane:** Redraw cycles within the Displays preference pane cause visual tearing, and certain system icons fail to composite.
- **Wi-Fi menu association:** The native QCC2072 controller attaches successfully in the guest kernel, but CoreWLAN / AirPort menu association is pending user-facing daemon integration.
- **GPU blit bounds:** Block memory copies exceeding 1 MiB can fault the Adreno CP engine; blits are segmented to <= 1 MiB with GPU watchdog recovery handling timeouts.
- **Unsupported subsystems:** Audio codecs, integrated cameras, Bluetooth controllers, S3/S0ix sleep states, external display outputs, and native 120 Hz refresh rates.
- **Tethered host dependency:** Execution currently requires a host Mac driving `tools/cycle.py` over USB-C NCM; standalone bootloader development is underway.

## Roadmap

In rough order:

1. **Frame pacing to a steady 60 Hz.** Event-driven GPU completion instead of
   a polling timer. The display copy happens at the earliest tear-free moment
   after completion, and WindowServer's work is prioritised over other
   clients'.
2. **Settings and display modes.** Make AdrenoDisplay's mode, property and
   notification handling complete, so that the Displays pane works, and fix
   the missing icons.
3. **Monitor overhead.** Move the remaining hot SPTM endpoints off the global
   lock, and find out why the CPU performance requests are capped.
4. **Wi-Fi from the macOS menu.** Connect the native controller to the macOS
   Wi-Fi stack, so that joining a network works without the host harness.
5. **Higher clocks.** Allow GPU operating points above 1185 MHz, with the
   thermal guard on.
6. **120 Hz.** Drive the panel at its native refresh rate once 60 Hz is steady.

## History

[GUI-BOOT-ROADMAP.md](GUI-BOOT-ROADMAP.md) describes how the project got from
the first kernel instruction to the desktop.
[KERNEL-PATCHES.md](KERNEL-PATCHES.md) lists the opt-in kernel patches.
