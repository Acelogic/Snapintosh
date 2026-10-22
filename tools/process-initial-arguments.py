# SPDX-License-Identifier: MIT
"""Read the pinned kernel's initial argument strings before libSystem is ready.

The native procargs2 handler loads proc+588 (argslen), +58c (argc), +590
(user_stack). Its string range ends at user_stack and starts with
executable_path=. Only the executable path and argc argument strings are read;
the following environment and Apple strings are never traversed or saved.
This is the initial stack string layout used by procargs2, not an argv-vector
lookup; the first argument must be nonempty to distinguish it from padding.
Call only for a stopped, audited, process-bound user address space.
"""
import struct

FIELDS = 0x588
PREFIX = b'executable_path='
WITNESSES = (
    (0xfffffe000bedd498, 0x52800024),
    (0xfffffe000bedd49c, 0x97fffdf1),
    (0xfffffe000bedccd4, 0x97ff8578),
    (0xfffffe000bedccdc, 0xaa0003f7),
    (0xfffffe000bedce78, 0xf942caf6),
    (0xfffffe000bedce7c, 0xb4000596),
    (0xfffffe000bedce80, 0xb9858ef4),
    (0xfffffe000bedce84, 0xb9458af8),
    (0xfffffe000bedce88, 0xd0fd8f00),
    (0xfffffe000bedce8c, 0x9102c800),
    (0xfffffe000bedce90, 0x97e65340),
    (0xfffffe000bedce94, 0xcb00030b),
)


def make_reader(read_kernel, kernel_u32):
    for address, word in WITNESSES:
        if kernel_u32(address) != word:
            raise ValueError('native initial-argument layout witness differs')
    # Bind the literal used by the selected native procargs2 routine as well.
    for offset in range(0, len(PREFIX), 4):
        if kernel_u32(0xfffffe00070be0b2+offset) != int.from_bytes(PREFIX[offset:offset+4], 'little'):
            raise ValueError('native executable argument prefix differs')

    def collect(proc, pid, read_user):
        if not isinstance(proc, int) or not 0xffff000000000000 <= proc < (1 << 64)-0xea8 or proc & 7:
            raise ValueError('invalid initial-argument process address')
        if not isinstance(pid, int) or not 0 < pid <= 256:
            raise ValueError('invalid initial-argument PID')
        identity = read_kernel(proc+0x60, 4)
        raw = read_kernel(proc+FIELDS, 16)
        if len(identity) != 4 or len(raw) != 16 or struct.unpack('<I', identity)[0] != pid:
            raise ValueError('initial-argument process identity differs')
        size, argc, top = struct.unpack('<IiQ', raw)
        if not 1 <= argc <= 64 or not len(PREFIX)+2 <= size <= 1 << 20:
            raise ValueError('invalid initial-argument count or size')
        if not size < top < 1 << 47 or top & 7:
            raise ValueError('invalid initial-argument stack bounds')
        begin = top-size
        cursor, consumed = begin, 0

        def get(address, length):
            nonlocal consumed
            if not begin <= address < address+length <= top:
                raise ValueError('initial-argument read outside string block')
            consumed += length
            if consumed > 8192:
                raise ValueError('initial-argument read budget exhausted')
            value = read_user(address, length)
            if len(value) != length:
                raise ValueError('short initial-argument read')
            return value

        def string(limit):
            nonlocal cursor
            value = bytearray()
            # Stop at the terminator without requesting the next string's bytes.
            for _ in range(limit):
                byte = get(cursor, 1); cursor += 1
                if byte == b'\0':return bytes(value)
                value.extend(byte)
            raise ValueError('unterminated or oversized initial argument')

        if get(cursor, len(PREFIX)) != PREFIX:
            raise ValueError('initial executable prefix differs')
        cursor += len(PREFIX)
        executable = string(1024)
        if not executable.startswith(b'/'):
            raise ValueError('initial executable path is not absolute')
        padding = 0
        while get(cursor, 1) == b'\0':
            cursor += 1; padding += 1
            if padding > 15:
                raise ValueError('excessive initial argument padding')
        arguments = [string(512) for _ in range(argc)]
        if (read_kernel(proc+0x60, 4) != identity or
                read_kernel(proc+FIELDS, 16) != raw):
            raise ValueError('initial-argument metadata changed')
        return dict(argc=argc, argv=[x.decode('utf-8', 'strict') for x in arguments],
                    executable=executable.decode('utf-8', 'strict'),
                    raw_arguments_hex=[x.hex() for x in arguments],
                    fields_address=hex(proc+FIELDS), fields_hex=raw.hex(),
                    string_start=hex(begin), user_stack=hex(top), argslen=size,
                    alignment_padding=padding, bytes_read=consumed,
                    layout_witnesses=[dict(address=hex(a), word=hex(w)) for a,w in WITNESSES],
                    boundary='Initial procargs2 string layout with a nonempty first argument; '
                             'not an argv-vector lookup. No guest execution, environment traversal '
                             'or library initialization assumption.')
    return collect
