# SPDX-License-Identifier: MIT
"""Native monitor completion is a separate contract from the guest exit report."""
XNUBOOT_TERMINAL_OK = 0
XNUBOOT_TERMINAL_OWNERSHIP = 0x51554e01
XNUBOOT_TERMINAL_GPU = 0x51554e02


class XnubootQuarantined(RuntimeError):
    def __init__(self, result):
        self.result = result
        reason = {XNUBOOT_TERMINAL_OWNERSHIP: 'guest executor/service ownership unresolved',
                  XNUBOOT_TERMINAL_GPU: 'GPU isolation not proved'}.get(result, 'unrecognized native terminal')
        super().__init__(f'known native quarantine {result:#x}: {reason}; '
                         'no further target I/O or RAM reuse; external recovery required')


def require_xnuboot_terminal(result):
    if type(result) is not int or result != XNUBOOT_TERMINAL_OK:
        if type(result) is not int:
            raise RuntimeError('malformed native terminal; no further target I/O')
        raise XnubootQuarantined(result)
