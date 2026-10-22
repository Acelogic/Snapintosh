# SPDX-License-Identifier: MIT
"""Command-only GPI9 STOP/START candidate. No hardware connector or ring DMA."""
from a16_fan_gpi import require
from a16_fan_dma import identity_plan

BASE = 0xA34000
COMMAND = BASE + 0x3008
CHANNEL_IRQ = BASE + 0x3090
CHANNEL_CLEAR = BASE + 0x30a0
STATE_MASK = 15 << 20


def snapshot_plan():
    result = [(name.removeprefix('firmware_gpi9.'), address)
              for name, address in identity_plan() if name.startswith('firmware_gpi9.')]
    result += [('channel_irq_mask', BASE + 0x3098), ('event_irq_mask', BASE + 0x309c),
               ('ieob_status', BASE + 0x30b0), ('ieob_mask', BASE + 0x30b8),
               ('ic10_status', 0xA84040), ('ic10_io', 0xA84908)]
    return result


class CommandRoundTrip:
    """bus supplies guarded read32/write32/time_us/freeze; never cleans up on error."""
    def __init__(self, bus, evidence, generation, image_base):
        self.bus, self.evidence = bus, evidence
        self.generation, self.image_base = generation, image_base
        self.result = dict(status='STARTING', snapshots=[], commands=[],
                           hardware_lease_admitted=False, dma_admitted=False,
                           outstanding_command=None, target_cleanup_after_failure=False)
        self.deadline = None

    def _time(self):
        require(self.bus.time_us() < self.deadline, 'handoff overall deadline')

    def _snapshot(self, label):
        values = {}
        self.result['snapshots'].append(dict(label=label, values=values))
        for name, address in snapshot_plan():
            self._time()
            values[name] = self.bus.read32(address)
        return values

    @staticmethod
    def _idle(values, expected_state):
        require(values['ic10_status'] == 0 and values['ic10_io'] == 7, 'IC10 not idle/high')
        for name in ('irq_type', 'ch_irq', 'event_irq', 'global_irq', 'general_irq',
                     'error_log', 'ieob_status'):
            require(values[name] == 0, 'preexisting/persistent status: ' + name)
        require(values['channel_irq_mask'] & 3 == 3 and values['irq_mask'] & 1,
                'existing channel completion routing is not enabled')
        require((values['event.config'] >> 20) & 15 == 1, 'event ring not allocated')
        for channel in (0, 1):
            prefix = f'ch{channel}.'
            require((values[prefix + 'config'] >> 20) & 15 == expected_state,
                    'unexpected channel state')
            require(values[prefix + 'config'] >> 24 == 16, 'unexpected channel element size')
            scratch = values[prefix + 'scratch0']
            require(scratch & 7 == 1 and (scratch >> 4) & 15 == 3 and
                    (scratch >> 16) & 31 == 1 - channel, 'pair is not IC10 I2C')
            base = values[prefix + 'base_low'] | values[prefix + 'base_high'] << 32
            size = values[prefix + 'length']
            rp = values[prefix + 'rp_low'] | values[prefix + 'rp_high'] << 32
            wp = values[prefix + 'wp_low'] | values[prefix + 'wp_high'] << 32
            require(base and base % 16 == 0 and 32 <= size <= 4096 and size % 16 == 0,
                    'invalid retained ring geometry')
            require(rp == wp and base <= rp < base + size and (rp - base) % 16 == 0,
                    'retained channel has queued work/invalid pointers')

    @staticmethod
    def _same(before, after, state):
        expected = dict(before)
        for channel in (0, 1):
            name = f'ch{channel}.config'
            expected[name] = (expected[name] & ~STATE_MASK) | state << 20
        require(after == expected, 'ring/config/status changed; snapshot cannot restore hardware state')

    def _command(self, opcode, channel):
        self._time()
        require(self.bus.read32(CHANNEL_IRQ) == 0, 'unowned prior channel completion')
        row = dict(opcode=opcode, channel=channel, polls=[], completed=False)
        self.result['commands'].append(row)
        self.result['outstanding_command'] = dict(opcode=opcode, channel=channel)
        deadline = min(self.deadline, self.bus.time_us() + 250000)
        self.bus.write32(COMMAND, opcode << 24 | channel)
        expected = 3 if opcode == 2 else 2
        for _ in range(64):
            require(self.bus.time_us() < deadline, 'command deadline; do not retry')
            irq = self.bus.read32(CHANNEL_IRQ)
            state = (self.bus.read32(BASE + channel * 0x80) >> 20) & 15
            row['polls'].append(dict(irq=irq, state=state))
            require(irq & ~(1 << channel) == 0, 'unowned completion during command')
            require(state != 15, 'channel error during command')
            if irq & (1 << channel):
                require(state == expected or (opcode == 2 and state == 4),
                        'command completion has unexpected state')
                self.bus.write32(CHANNEL_CLEAR, 1 << channel)
                if state == expected:
                    row['completed'] = True
                    self.result['outstanding_command'] = None
                    return
        raise RuntimeError('command poll bound; completion uncertain')

    def run(self):
        self.deadline = self.bus.time_us() + 15000000
        try:
            require(self.evidence.get('generation') == self.generation and
                    self.evidence.get('image_base') == self.image_base, 'exclusion evidence identity mismatch')
            for key in ('cpu0_sole_operator', 'other_17_cpus_off', 'exit_boot_services_completed',
                        'ncm_smem_clients_do_not_use_ic10', 'exclusive_host_client'):
                require(self.evidence.get(key) is True, 'missing exclusion evidence: ' + key)
            require(self.evidence.get('receipt_sha256'), 'missing exclusion receipt provenance')
            before = self._snapshot('initial')
            self._idle(before, 2)
            confirm = self._snapshot('fresh_confirm')
            require(before == confirm, 'initial hardware state is changing')
            self._idle(confirm, 2)
            self._command(2, 0)
            self._command(2, 1)
            stopped = self._snapshot('stopped')
            self._idle(stopped, 3)
            self._same(before, stopped, 3)
            self.result['temporary_control_established'] = True
            self._command(1, 0)
            self._command(1, 1)
            final = self._snapshot('returned')
            self._idle(final, 2)
            self._same(before, final, 2)
            self.result.update(status='ROUNDTRIP_VERIFIED', initial_state_restored=True,
                               retained_lease=False)
            return self.result
        except BaseException as exc:
            self.result.update(status='FROZEN_REFUSAL', error=f'{type(exc).__name__}: {exc}')
            self.bus.freeze(self.result['error'])
            raise
