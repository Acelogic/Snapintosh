# Status

What works on the ASUS Zenbook A16 (X2E-96-100) with macOS 27 build 26A428,
what is known to be wrong, and what comes next. The numbers come from the most
recent full desktop sessions, which ran about 25 to 30 minutes each.

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

- **Smoothness.** Interaction is usable but not yet smooth. Recent sessions
  show a median of about 46 to 60 presents per second in busy periods, with
  1.7 to 5 % of frame intervals longer than 34 ms. The main causes:
  - *Present-gate deferrals.* With pipelining, WindowServer can swap a
    surface whose GPU work is still running. The display then waits one full
    refresh before copying it.
  - *Occasional long stalls* (100 to 350 ms) that are not GPU time. They
    coincide with heavy console output and timer lateness.
  - *Contention on the monitor's global lock* for some SPTM calls. In
    particular, page-attribute updates on buffers whose cache mode changes
    are slow; the plug-in now reuses write-back buffers to avoid most of them.
- **CPU clocks.** The CPU governor's requests above a certain performance
  level are not granted by the firmware, so the CPU clusters do not reach
  their top clocks.
- **System Settings.** The Displays pane redraws badly ("accordions") and
  glitches the screen, and icons inside some Settings panes are missing.
- **Wi-Fi in macOS.** The native QCC2072 controller loads in the guest, but
  the Wi-Fi menu cannot join a network yet.
- **Large blits.** A single 4 MiB `CP_MEMCPY` hung the GPU. The plug-in now
  splits blits into chunks of at most 1 MiB, and GPU recovery handles other
  overruns. Other hang triggers may exist.
- **Not supported:** audio, cameras, Bluetooth, sleep and wake, external
  displays, the 120 Hz panel mode, and any other machine or macOS build.
- **Host required.** Every boot is driven from a Mac over USB-C through q1n1.
  There is no standalone boot path.

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
