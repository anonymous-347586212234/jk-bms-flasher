"""Observed JK bootloader packet codec and strict no-retry flash state machine."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from .domain import (
    ApprovedPreflight,
    DeviceIdentity,
    DeviceProfile,
    FirmwareImage,
    FlashEvent,
    FlashResult,
    FlashState,
    ProtocolError,
    SafetyError,
)
from .interfaces import EventSink, FlashProtocol

DATA_FIELD_SIZE: Final = 128
REGULAR_PACKET_SIZE: Final = 132
FINAL_PACKET_SIZE: Final = 135
FINAL_MARKER: Final = b"\x04\x04\x04"
FINAL_RESPONSE: Final = b"\x06\x06\r\n->Tran-End\r\n\r\n->Jump to app...\r\n"


@dataclass(frozen=True, slots=True)
class TransferPacket:
    """One fully encoded observed bootloader transfer packet."""

    sequence: int
    data_size: int
    final: bool
    raw: bytes


def build_transfer_packet(sequence: int, data: bytes, *, final: bool = False) -> bytes:
    """Encode one bootloader packet with sequence complement and byte sum."""

    if not 0 <= sequence <= 0xFF:
        raise ValueError("firmware packet sequence must fit in one byte")
    if final:
        # Vendor disassembly establishes that a full 128-byte final block gets
        # the end marker without padding; retained captures cover partial finals.
        if not 1 <= len(data) <= DATA_FIELD_SIZE:
            raise SafetyError("final packet requires 1..128 real data bytes")
        field = data + b"\xff" * (DATA_FIELD_SIZE - len(data))
    else:
        if len(data) != DATA_FIELD_SIZE:
            raise ValueError("regular firmware packets require exactly 128 data bytes")
        field = data

    prefix = bytes((0x01, sequence, sequence ^ 0xFF)) + field
    packet = prefix + bytes((sum(prefix) & 0xFF,))
    if final:
        packet += FINAL_MARKER
    return packet


def packetize_transfer_body(body: bytes) -> tuple[TransferPacket, ...]:
    """Packetize a validated transfer body using the two captured rules only."""

    if not body:
        raise SafetyError("firmware transfer body must not be empty")
    full_blocks, remainder_size = divmod(len(body), DATA_FIELD_SIZE)
    regular_count = full_blocks if remainder_size else full_blocks - 1

    packets: list[TransferPacket] = []
    for index in range(regular_count):
        sequence = (index + 1) & 0xFF
        data = body[index * DATA_FIELD_SIZE : (index + 1) * DATA_FIELD_SIZE]
        packets.append(
            TransferPacket(
                sequence=sequence,
                data_size=DATA_FIELD_SIZE,
                final=False,
                raw=build_transfer_packet(sequence, data),
            )
        )

    final_data = body[regular_count * DATA_FIELD_SIZE :]
    final_sequence = (regular_count + 1) & 0xFF
    packets.append(
        TransferPacket(
            sequence=final_sequence,
            data_size=len(final_data),
            final=True,
            raw=build_transfer_packet(final_sequence, final_data, final=True),
        )
    )
    return tuple(packets)


_APPROVAL_SEAL = object()


@dataclass(frozen=True, slots=True)
class _BoundApproval:
    identity: DeviceIdentity
    decoded_digest: str
    transfer_digest: str
    suffix_digest: str
    transfer_length: int
    model: str
    version: str
    seal: object


def _issue_approval(identity: DeviceIdentity, image: FirmwareImage) -> ApprovedPreflight:
    """Create an opaque approval bound to one identity and inspected image."""

    approval = _BoundApproval(
        identity=identity,
        decoded_digest=hashlib.sha256(image.decoded).hexdigest(),
        transfer_digest=hashlib.sha256(image.transfer_body).hexdigest(),
        suffix_digest=hashlib.sha256(image.suffix).hexdigest(),
        transfer_length=len(image.transfer_body),
        model=image.model,
        version=image.version,
        seal=_APPROVAL_SEAL,
    )
    return ApprovedPreflight(approval)


def _require_approval(
    approval: ApprovedPreflight,
    identity: DeviceIdentity,
    image: FirmwareImage,
) -> None:
    if not isinstance(approval, _BoundApproval) or approval.seal is not _APPROVAL_SEAL:
        raise SafetyError("flash requires an opaque, successful preflight approval")
    if approval.identity != identity:
        raise SafetyError("preflight approval belongs to a different device identity")
    if (
        approval.decoded_digest != hashlib.sha256(image.decoded).hexdigest()
        or approval.transfer_digest != hashlib.sha256(image.transfer_body).hexdigest()
        or approval.suffix_digest != hashlib.sha256(image.suffix).hexdigest()
        or approval.transfer_length != len(image.transfer_body)
        or approval.model != image.model
        or approval.version != image.version
    ):
        raise SafetyError("preflight approval belongs to a different firmware image")


class FirmwareFlasher:
    """Execute the captured happy path and stop on the first uncertainty.

    There are deliberately no retry, resume, duplicate-packet, or guessed
    recovery paths.  Once boot entry has been sent, any exception is converted
    to ``RECOVERY_REQUIRED`` and no further bytes are transmitted.
    """

    def __init__(
        self,
        protocol: FlashProtocol,
        profile: DeviceProfile,
        *,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
        preboot_quiet_interval: float = 0.75,
        post_query_quiet_interval: float = 0.75,
        post_boot_delay: float = 0.6,
        transfer_ack_timeout: float = 120.0,
        transfer_deadline: float | None = None,
        max_flash_current: float = 1.0,
        min_state_of_charge: int = 15,
    ) -> None:
        if preboot_quiet_interval <= 0:
            raise ValueError("pre-boot quiet interval must be positive")
        if post_query_quiet_interval <= 0:
            raise ValueError("post-flash query quiet interval must be positive")
        if post_boot_delay < 0:
            raise ValueError("post-boot delay must not be negative")
        if transfer_ack_timeout <= 0:
            raise ValueError("transfer ack timeout must be positive")
        if transfer_deadline is not None and transfer_deadline <= 0:
            raise ValueError("transfer deadline must be positive")
        if max_flash_current < 0:
            raise ValueError("max flash current must not be negative")
        if not 0 <= min_state_of_charge <= 100:
            raise ValueError("minimum state of charge must be in the range 0..100")
        self.protocol = protocol
        self.profile = profile
        self._sleep = sleep
        self._now = now
        # The two successful desktop traces waited 499.038 ms and
        # 689.712 ms after the final telemetry ACK before boot entry.  This
        # evidence-anchored floor exceeds both while remaining a pre-boot,
        # one-shot delay; it is not a retry or a claimed family-wide minimum.
        self.preboot_quiet_interval = preboot_quiet_interval
        # The device ignored a second post-flash identity request sent only
        # 0.219 ms after the first response. Normal monitoring uses an observed
        # ~0.8 s cadence, so post-flash verification uses the same conservative
        # 750 ms floor between otherwise valid one-shot queries.
        self.post_query_quiet_interval = post_query_quiet_interval
        self.post_boot_delay = post_boot_delay
        # The vendor sets no ACK timeout at all during transfer (a slow
        # bootloader erase must not self-abort); this widens the bound
        # instead of removing it. The overall deadline is a backstop so a
        # device that keeps ACKing just under that bound cannot hang forever.
        self.transfer_ack_timeout = transfer_ack_timeout
        self.transfer_deadline = transfer_deadline
        self.max_flash_current = max_flash_current
        self.min_state_of_charge = min_state_of_charge
        self.verified_identity: DeviceIdentity | None = None

    def flash(
        self,
        expected_identity: DeviceIdentity,
        image: FirmwareImage,
        approval: ApprovedPreflight,
        event_sink: EventSink | None = None,
    ) -> FlashResult:
        sink = event_sink or (lambda _event: None)
        self.verified_identity = None
        _require_approval(approval, expected_identity, image)
        self._validate_image_binding(image)
        packets = packetize_transfer_body(image.transfer_body)

        sink(FlashEvent(FlashState.PREFLIGHT, "Reading two fresh device identities"))
        first = self.protocol.read_identity()
        second = self.protocol.read_identity()
        if first != second:
            raise SafetyError("device identity was not stable across two fresh reads")
        if first != expected_identity:
            raise SafetyError("fresh identity differs from the preflight identity")

        boot_entry_attempted = False
        try:
            sink(
                FlashEvent(
                    FlashState.ENTERING_BOOTLOADER,
                    "Entering the validated bootloader capability",
                    total_blocks=len(packets),
                )
            )
            sink(
                FlashEvent(
                    FlashState.PREFLIGHT,
                    "Reading pack telemetry before boot entry",
                )
            )
            pre_boot_telemetry = self.protocol.read_telemetry(first.max_cells)
            telemetry_completed_at = self._now()
            self._verify_preflight_telemetry(
                pre_boot_telemetry,
                first.max_cells,
                blocking_fault_mask=self.profile.flash_blocking_fault_mask,
                max_flash_current=self.max_flash_current,
                min_state_of_charge=self.min_state_of_charge,
            )
            sink(
                FlashEvent(
                    FlashState.PREFLIGHT,
                    "Waiting for the evidence-backed pre-boot quiet interval",
                )
            )
            self._await_preboot_quiet(telemetry_completed_at)
            sink(
                FlashEvent(
                    FlashState.ENTERING_BOOTLOADER,
                    "Entering bootloader; waiting for the validated banner",
                    total_blocks=len(packets),
                )
            )

            # Keep this after every callback and read that can delay it, with
            # no intervening operation before the state-changing command.
            from .firmware import validate_transfer_suffix

            validate_transfer_suffix(image.suffix)

            # A failed write may still have placed a prefix of the command on
            # the wire. From this point onward the device state is uncertain.
            boot_entry_attempted = True
            self.protocol.send_enter_bootloader()

            transfer_started = self._now()
            deadline = self.transfer_deadline if self.transfer_deadline is not None else max(300.0, len(packets) * 2.0)
            deadline_at = transfer_started + deadline
            with self.protocol.transfer_read_timeout(self._remaining_transfer_timeout(transfer_started, deadline)):
                self.protocol.read_boot_ready(
                    self.profile.boot_banner,
                    deadline=deadline_at,
                    now=self._now,
                )

            sink(
                FlashEvent(
                    FlashState.TRANSFERRING,
                    "Bootloader ready; starting transfer",
                    total_blocks=len(packets),
                )
            )
            for completed, packet in enumerate(packets[:-1], 1):
                self._require_transfer_time(transfer_started, deadline)
                self.protocol.write_packet(packet.raw)
                with self.protocol.transfer_read_timeout(self._remaining_transfer_timeout(transfer_started, deadline)):
                    self.protocol.read_ack_byte()
                sink(
                    FlashEvent(
                        FlashState.TRANSFERRING,
                        f"Transferred block {completed} of {len(packets)}",
                        completed_blocks=completed,
                        total_blocks=len(packets),
                    )
                )

            self._require_transfer_time(transfer_started, deadline)
            final = packets[-1]
            self.protocol.write_packet(final.raw)
            with self.protocol.transfer_read_timeout(self._remaining_transfer_timeout(transfer_started, deadline)):
                completion = self.protocol.read_exact(
                    len(FINAL_RESPONSE),
                    deadline=deadline_at,
                    now=self._now,
                )
            self._require_transfer_time(transfer_started, deadline)

            if completion != FINAL_RESPONSE:
                raise ProtocolError("bootloader completion response did not match the capture")

            sink(
                FlashEvent(
                    FlashState.VERIFYING,
                    "Transfer completed; verifying the running application twice",
                    completed_blocks=len(packets),
                    total_blocks=len(packets),
                )
            )
            self._sleep(self.post_boot_delay)
            post_first = self.protocol.read_identity()
            post_first_completed_at = self._now()
            self._await_post_query_quiet(post_first_completed_at)
            post_second = self.protocol.read_identity()
            post_second_completed_at = self._now()
            self._verify_post_identity(first, post_first, post_second, image)
            self._await_post_query_quiet(post_second_completed_at)
            telemetry = self.protocol.read_telemetry(post_first.max_cells)
            self._verify_post_telemetry(telemetry, post_first.max_cells)
            self.verified_identity = post_first
        except Exception as error:
            if not boot_entry_attempted:
                raise
            message = f"Transfer stopped at first uncertainty: {error}"
            sink(
                FlashEvent(
                    FlashState.RECOVERY_REQUIRED,
                    message,
                    total_blocks=len(packets),
                )
            )
            return FlashResult(FlashState.RECOVERY_REQUIRED, message)

        message = f"Verified {image.model} {image.version} on the original device"
        sink(
            FlashEvent(
                FlashState.SUCCEEDED,
                message,
                completed_blocks=len(packets),
                total_blocks=len(packets),
            )
        )
        return FlashResult(FlashState.SUCCEEDED, message)

    def _await_preboot_quiet(self, telemetry_completed_at: float) -> None:
        """Wait once until the captured telemetry-to-boot floor has elapsed."""

        self._await_quiet_interval(telemetry_completed_at, self.preboot_quiet_interval)

    def _await_post_query_quiet(self, query_completed_at: float) -> None:
        """Space strict post-flash queries without retrying any request."""

        self._await_quiet_interval(query_completed_at, self.post_query_quiet_interval)

    def _await_quiet_interval(self, completed_at: float, interval: float) -> None:
        elapsed = self._now() - completed_at
        remaining = interval - elapsed
        if remaining > 0:
            self._sleep(remaining)

    def _remaining_transfer_timeout(self, started: float, deadline: float) -> float:
        remaining = deadline - (self._now() - started)
        if remaining <= 0:
            raise ProtocolError("firmware transfer exceeded its overall deadline without completing")
        return min(self.transfer_ack_timeout, remaining)

    def _require_transfer_time(self, started: float, deadline: float) -> None:
        self._remaining_transfer_timeout(started, deadline)

    @staticmethod
    def _validate_image_binding(image: FirmwareImage) -> None:
        if image.transfer_body + image.suffix != image.decoded:
            raise SafetyError("firmware transfer body and suffix do not reconstruct the image")
        if not image.transfer_body:
            raise SafetyError("firmware transfer body is empty")

    @staticmethod
    def _verify_post_identity(
        before: DeviceIdentity,
        first: DeviceIdentity,
        second: DeviceIdentity,
        image: FirmwareImage,
    ) -> None:
        if first != second:
            raise SafetyError("post-flash identity was not stable across two reads")
        if (
            first.address != before.address
            or first.model != before.model
            or first.hardware != before.hardware
            or first.serial != before.serial
            or first.max_cells != before.max_cells
        ):
            raise SafetyError("post-flash identity is not the original physical device")
        if first.software.strip().upper() != image.version.strip().upper():
            raise SafetyError("post-flash software version does not match the embedded target version")

    @staticmethod
    def _verify_post_telemetry(telemetry: object, max_cells: int) -> None:
        FirmwareFlasher._check_cell_and_pack_plausibility(telemetry, max_cells, when="post-flash")

    @staticmethod
    def _verify_preflight_telemetry(
        telemetry: object,
        max_cells: int,
        *,
        blocking_fault_mask: int = 0xFFFFFFFF,
        max_flash_current: float,
        min_state_of_charge: int,
    ) -> None:
        """Require a safe electrical state before any bootloader command is sent.

        Losing MOSFET/protection control during an active charge or discharge,
        during an active fault, or on a pack too low to survive the transfer
        without browning out, is a hazard the wire protocol itself cannot
        detect. This check runs before boot entry so a failure is fully
        recoverable: no device state has changed yet.
        """

        FirmwareFlasher._check_cell_and_pack_plausibility(telemetry, max_cells, when="pre-flash")
        pack_current = getattr(telemetry, "pack_current", None)
        fault_mask = getattr(telemetry, "fault_mask", None)
        state_of_charge = getattr(telemetry, "state_of_charge", None)
        if not isinstance(pack_current, (int, float)) or abs(float(pack_current)) > max_flash_current:
            raise SafetyError(
                f"pack current {pack_current} A exceeds the {max_flash_current} A pre-flash "
                "limit; remove charge/load connections before flashing"
            )
        if not isinstance(fault_mask, int):
            raise SafetyError("the protection-fault field is unavailable")
        blocking_faults = fault_mask & blocking_fault_mask
        if blocking_faults:
            raise SafetyError(
                f"active blocking protection fault(s) 0x{blocking_faults:08X}; resolve them before flashing"
            )
        if not isinstance(state_of_charge, int) or state_of_charge < min_state_of_charge:
            raise SafetyError(f"state of charge is below the {min_state_of_charge}% pre-flash floor")

    @staticmethod
    def _check_cell_and_pack_plausibility(telemetry: object, max_cells: int, *, when: str) -> None:
        raw_cells = getattr(telemetry, "cell_voltages", None)
        pack_voltage = getattr(telemetry, "pack_voltage", None)
        if not isinstance(raw_cells, (tuple, list)) or not raw_cells or len(raw_cells) > max_cells:
            raise SafetyError(f"{when} telemetry has an implausible active-cell count")
        cells: list[float] = []
        for cell in raw_cells:
            if not isinstance(cell, (int, float)) or not 1.0 <= float(cell) <= 5.5:
                raise SafetyError(f"{when} telemetry contains an implausible cell voltage")
            cells.append(float(cell))
        summed = sum(cells)
        if not isinstance(pack_voltage, (int, float)) or not 0.5 * summed <= pack_voltage <= 1.5 * summed:
            raise SafetyError(f"{when} pack voltage is inconsistent with cell telemetry")


# Natural names for codec-focused callers.
FlashStateMachine = FirmwareFlasher
build_firmware_packet = build_transfer_packet
packetize_firmware = packetize_transfer_body
