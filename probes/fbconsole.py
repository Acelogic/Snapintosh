#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Put XNU's console on the A16's own display.

The console text already comes back over USB -- XNU's panics arrive one
character at a time through `SPTM_FN_SERIAL_PUTC`, which this hypervisor
implements. That is enough to debug with and not enough to *look* at: the
machine running the kernel shows nothing, and the only evidence it is doing
anything is a terminal on a different computer.

q1n1 captured the GOP framebuffer before ExitBootServices and publishes it in
its boot info, so the panel is a flat array of pixels that the proxy can write
to like any other memory. This renders the console into it.

Two details make it simpler than it looks. The text is drawn white on black, so
the pixel format does not matter: every channel gets the same value and the byte
order stops being a question anybody has to answer. And the framebuffer is
written as whole rows through the existing `writemem`, so there is no new
transport and nothing to keep in sync.

    python3 probes/fbconsole.py --demo        # prove the path with a test page
"""
import argparse
import pathlib
import struct
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:                                     # pragma: no cover
    Image = None

# Candidates in preference order: a real monospace face, then whatever Pillow
# can find. A HiDPI panel makes the default bitmap font unreadable, so a scalable
# one matters more here than it usually would.
FONTS = ['/System/Library/Fonts/SFNSMono.ttf',
         '/System/Library/Fonts/Menlo.ttc',
         '/System/Library/Fonts/Supplemental/Andale Mono.ttf',
         '/Library/Fonts/Courier New.ttf']

# The panel is OLED, and this draws a static page that then sits there for as
# long as the machine is left alone. That is the shape of the problem burn-in
# comes from: the same sub-pixels lit at the same coordinates for hours.
#
# Three things are done about it, cheapest first.
#
# The background is black, so most of the panel is genuinely off rather than
# displaying black -- which is the one real advantage OLED has here and it costs
# nothing to keep.
#
# Peak white is backed off. A boot log does not need 255; the header was the
# brightest thing on screen and had no reason to be.
#
# And the whole page moves. Each draw picks a different offset, far enough that
# a lit pixel in one draw is unlit in the next: a character stroke at this size
# is about three pixels across, so steps of eight guarantee no overlap. The
# offsets walk a grid rather than jittering randomly, so over a session every
# pixel in the text band gets roughly equal duty rather than some unlucky
# coordinate being lit every time.
HEADER_RGB = 0xC0
BODY_RGB = 0xA8
DIM_RGB = 0x68

SHIFT_STEP = 8                  # > a stroke width, so draws do not overlap
SHIFT_GRID = 5                  # 5x5 positions, +-16px about centre
SHIFT_FILE = 'build/.fbshift'   # so consecutive runs do not repeat a position


def _state(root):
    """(counter, height last drawn). Missing or corrupt reads as a fresh start."""
    try:
        counter, band = (pathlib.Path(root) / SHIFT_FILE).read_text().split()
        return int(counter), int(band)
    except (OSError, ValueError):
        return 0, 0


def _save_state(root, counter, band):
    try:
        path = pathlib.Path(root) / SHIFT_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'{counter} {band}')
    except OSError:
        pass                    # a read-only tree is not a reason to fail a run


def next_shift(counter):
    """Position `counter` on the grid."""
    half = SHIFT_GRID // 2
    x = (counter % SHIFT_GRID) - half
    y = ((counter // SHIFT_GRID) % SHIFT_GRID) - half
    return x * SHIFT_STEP, y * SHIFT_STEP


def load_font(size):
    for path in FONTS:
        if pathlib.Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def render(text, width, height, scale=2, header=None, shift=(0, 0)):
    """The console as an 8-bit greyscale image the size of the panel.

    Returns (image, used_height) so the caller can write only the band that has
    anything in it."""
    image = Image.new('L', (width, height), 0)
    draw = ImageDraw.Draw(image)
    size = 13 * scale
    font = load_font(size)
    # The margin has to clear the largest shift, or a page nudged up and left
    # loses its first line off the top of the panel.
    margin = 8 * scale + (SHIFT_GRID // 2) * SHIFT_STEP
    line_height = int(size * 1.35)
    dx, dy = shift
    margin_x = margin + dx
    y = margin + dy

    if header:
        draw.text((margin_x, y), header, font=load_font(size + 2 * scale),
                  fill=HEADER_RGB)
        y += line_height + 4 * scale
        draw.line((margin_x, y, width - margin + dx, y), fill=DIM_RGB,
                  width=max(1, scale // 2))
        y += 6 * scale

    # Wrap on the panel, not on the source: a panic line is long and truncating
    # it would hide the part that names the file.
    columns = max(20, (width - 2 * margin) // max(1, int(size * 0.62)))
    for raw in text.splitlines() or ['']:
        chunks = [raw[i:i + columns] for i in range(0, len(raw), columns)] or ['']
        for n, chunk in enumerate(chunks):
            if y + line_height > height - margin:
                return image, height
            draw.text((margin_x + (0 if n == 0 else int(size * 1.2)), y), chunk,
                      font=font, fill=BODY_RGB if raw.strip() else DIM_RGB)
            y += line_height
    return image, min(height, y + margin)


def show(proxy, info, text, header=None, scale=2, shift=None,
         clear_below=True, root=None):
    """Draw `text` onto the A16's panel. Returns the number of bytes written.

    `shift` defaults to the next position on the anti-burn-in grid."""
    root = root or pathlib.Path(__file__).resolve().parents[1]
    if Image is None:
        raise SystemExit('Pillow is needed to render the console: pip3 install pillow')
    base, width, height = info['fb_base'], info['fb_width'], info['fb_height']
    stride, size = info['fb_stride'], info['fb_size']
    if not base or not width or not height:
        raise SystemExit('q1n1 reports no framebuffer')
    depth = size // (stride * height)
    if depth != 4:
        raise SystemExit(f'{depth} bytes per pixel is not handled')

    counter, previous = _state(root)
    counter += 1
    shift = next_shift(counter) if shift is None else shift
    image, used = render(text, width, height, scale=scale, header=header,
                         shift=shift)
    grey = image.tobytes()

    # Only the band that has anything in it, plus room for the shift to move
    # the text around inside it. Writing the whole panel is 20 MiB over a USB
    # proxy for the sake of eighteen million black pixels that are already
    # black; the band is a fraction of that, and it is what makes redrawing
    # often enough to matter practical at all.
    band = min(height, used + SHIFT_GRID * SHIFT_STEP)

    written = 0
    row = bytearray(stride * 4)
    for y in range(band):
        line = grey[y * width:(y + 1) * width]
        for x, v in enumerate(line):
            o = x * 4
            row[o] = row[o + 1] = row[o + 2] = v
            row[o + 3] = 0xFF
        proxy.writemem(base + y * stride * 4, bytes(row))
        written += len(row)

    # Only as far down as something was last lit. A previous, taller page would
    # otherwise leave its tail on screen forever, which is the exact thing being
    # avoided -- but clearing the whole panel every time is 20 MiB over USB to
    # blank rows that are already black.
    # A zero means we do not know what is down there -- a fresh checkout, or a
    # panel someone else drew on -- so the whole thing gets cleared that once.
    stale = height if previous == 0 else min(previous, height)
    if clear_below and band < stale:
        blank = bytes(stride * 4)
        for y in range(band, stale):
            proxy.writemem(base + y * stride * 4, blank)
            written += len(blank)
    _save_state(root, counter, band)
    return written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default='/dev/cu.usbmodemA16_Q1N1_EL2B1')
    ap.add_argument('--scale', type=int, default=2)
    ap.add_argument('--demo', action='store_true', help='draw a test page')
    ap.add_argument('--watch', type=float, metavar='SECONDS',
                    help='redraw at this interval, each time a step further '
                         'along the grid, for a panel left showing one page')
    ap.add_argument('--text', help='draw this instead (use - for stdin)')
    args = ap.parse_args()

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'q1n1' / 'tools'))
    import q1n1proxy as q1n1
    proxy = q1n1.Proxy(q1n1.Link(args.device, timeout=5.0))
    info = proxy.bootinfo()

    if args.text == '-':
        body = sys.stdin.read()
    elif args.text:
        body = args.text
    else:
        body = ('panic: this is the framebuffer path, not XNU\\n'
                'If you can read this on the A16, the console can be displayed.\\n')
    if args.watch:
        # Nothing runs on the target between probe runs, so a page drawn once
        # sits there until something else draws. On OLED that is the whole
        # problem. This keeps nudging it from the host, which is the only side
        # with a scheduler.
        import time
        print(f'redrawing every {args.watch}s; ctrl-c to stop')
        try:
            while True:
                n = show(proxy, info, body, header='Snapintosh',
                         scale=args.scale)
                print(f'  {n:,} bytes', flush=True)
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print('\nstopped')
        return 0

    n = show(proxy, info, body, header='Snapintosh', scale=args.scale)
    print(f'{n:,} bytes to {info["fb_base"]:#x} '
          f'({info["fb_width"]}x{info["fb_height"]})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
