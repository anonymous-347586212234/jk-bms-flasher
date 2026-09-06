from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from jkflash.application import JkApplication, create_ui_services
from jkflash.domain import (
    DeviceIdentity,
    FirmwareError,
    FirmwareImage,
    FlashResult,
    FlashState,
    PortConfig,
    PortInfo,
    ProtocolError,
    SafetyError,
    TelemetrySnapshot,
    ValidationReport,
)
from jkflash.flasher import (
    FINAL_MARKER,
    FINAL_RESPONSE,
    FirmwareFlasher,
    _issue_approval,
    build_transfer_packet,
    packetize_transfer_body,
)
from jkflash.profiles import PB_V19
from jkflash.protocol import IDENTITY_REGISTER, TELEMETRY_REGISTER, append_modbus_crc, write_register_command
from jkflash.transport import SerialPortProvider, SerialTransportFactory


def identity(version: str = "19.26", serial: str = "SERIAL") -> DeviceIdentity:
    return DeviceIdentity(5, "JK-PB1A16S20P", 16, "19A", version, serial)


def firmware(body: bytes) -> FirmwareImage:
    suffix = b"\x00" * 12
    return FirmwareImage(
        path=Path("target.jkbms"),
        container_sha256="a" * 64,
        decoded_sha256="b" * 64,
        decoded=body + suffix,
        transfer_body=body,
        suffix=suffix,
        model="JK-PB1A16S20P",
        version="19.31",
        initial_sp=0x20001000,
        reset_vector=0x08010001,
    )


def safe_telemetry(max_cells: int = 16) -> TelemetrySnapshot:
    cells = (3.3,) * max_cells
    return TelemetrySnapshot(
        cells,
        sum(cells),
        0.0,
        50,
        100,
        25.0,
        25.0,
        25.0,
        0.0,
        0,
        True,
        True,
        10.0,
        20.0,
        1,
        60,
        0,
    )


class FakeProtocol:
    def __init__(self, identities: list[DeviceIdentity]) -> None:
        self.identities = deque(identities)
        self.calls: list[str] = []
        self.packets: list[bytes] = []
        self.fail_ack = False
        self.completion = FINAL_RESPONSE
        self.read_timeout = 2.0
        self.timeout_calls: list[float] = []
        self.telemetry_override: TelemetrySnapshot | None = None

    @contextmanager
    def transfer_read_timeout(self, seconds: float):
        self.timeout_calls.append(seconds)
        previous = self.read_timeout
        self.read_timeout = seconds
        try:
            yield
        finally:
            self.read_timeout = previous

    def read_identity(self) -> DeviceIdentity:
        self.calls.append("identity")
        return self.identities.popleft()

    def send_enter_bootloader(self) -> None:
        self.calls.append("enter")

    def read_boot_ready(
        self,
        expected_banner: bytes,
        *,
        limit: int = 512,
        deadline: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> bytes:
        self.calls.append("ready")
        assert limit == 512
        assert deadline is not None
        assert now is not None
        assert expected_banner == PB_V19.boot_banner
        return b"banner\x15"

    def write_packet(self, packet: bytes) -> None:
        self.calls.append("packet")
        self.packets.append(packet)

    def read_ack_byte(self) -> None:
        self.calls.append("ack")
        if self.fail_ack:
            raise ProtocolError("NAK")

    def read_exact(
        self,
        size: int,
        *,
        deadline: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> bytes:
        self.calls.append("complete")
        assert deadline is not None
        assert now is not None
        assert size == len(FINAL_RESPONSE)
        return self.completion

    def read_telemetry(self, max_cells: int) -> TelemetrySnapshot:
        self.calls.append("telemetry")
        if self.telemetry_override is not None:
            return self.telemetry_override
        return safe_telemetry(max_cells)


def test_packet_codec_regular_and_final_fields() -> None:
    data = bytes(range(128))
    regular = build_transfer_packet(1, data)
    assert len(regular) == 132
    assert regular[:3] == b"\x01\x01\xfe"
    assert regular[3:131] == data
    assert regular[131] == sum(regular[:131]) & 0xFF

    final = build_transfer_packet(0, b"abc", final=True)
    assert len(final) == 135
    assert final[:3] == b"\x01\x00\xff"
    assert final[3:6] == b"abc"
    assert final[6:131] == b"\xff" * 125
    assert final[131] == sum(final[:131]) & 0xFF
    assert final[-3:] == FINAL_MARKER


def test_packetizer_sequence_wrap_and_exact_aligned_final_packet() -> None:
    body = bytes(index & 0xFF for index in range(255 * 128 + 1))
    packets = packetize_transfer_body(body)
    assert packets[0].sequence == 1
    assert packets[254].sequence == 255
    assert packets[-1].sequence == 0
    assert packets[-1].data_size == 1
    assert packets[-1].final
    aligned = packetize_transfer_body(b"x" * 128)
    assert len(aligned) == 1
    assert aligned[0].final
    assert aligned[0].data_size == 128
    assert aligned[0].raw == build_transfer_packet(1, b"x" * 128, final=True)
    with pytest.raises(SafetyError, match="empty"):
        packetize_transfer_body(b"")


@pytest.mark.parametrize(
    ("capture", "regular_count", "final_real", "address"),
    [
        ("2026-08-09-v19_27", 766, 67, 5),
        ("2026-08-09-v19_31", 767, 75, 5),
        ("2026-08-09-v19_34", 774, 47, 1),
    ],
)
def test_packetizer_reproduces_golden_capture_exactly(
    capture: str, regular_count: int, final_real: int, address: int
) -> None:
    root = Path(__file__).parents[1]
    wire = (root / "implementation_details" / "captures" / capture / "upgrade-only.tx.bin").read_bytes()
    assert wire[:11] == write_register_command(address, 0x1626)
    packets_wire = wire[11:]
    regular = [packets_wire[index * 132 : (index + 1) * 132] for index in range(regular_count)]
    final = packets_wire[regular_count * 132 :]
    assert len(final) == 135
    body = b"".join(packet[3:131] for packet in regular) + final[3 : 3 + final_real]
    encoded = b"".join(packet.raw for packet in packetize_transfer_body(body))
    assert encoded == packets_wire


def test_strict_flash_happy_path_and_post_identity_verification() -> None:
    before = identity()
    after = identity("19.31")
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, after, after])
    events = []
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    result = flasher.flash(before, image, _issue_approval(before, image), events.append)

    assert result.state is FlashState.SUCCEEDED
    assert [len(packet) for packet in protocol.packets] == [132, 135]
    assert protocol.calls == [
        "identity",
        "identity",
        "telemetry",
        "enter",
        "ready",
        "packet",
        "ack",
        "packet",
        "complete",
        "identity",
        "identity",
        "telemetry",
    ]
    assert events[0].state is FlashState.PREFLIGHT
    assert events[-1].state is FlashState.SUCCEEDED
    assert flasher.verified_identity == after
    assert protocol.timeout_calls == [flasher.transfer_ack_timeout] * 3
    assert protocol.read_timeout == 2.0


def test_preboot_quiet_gate_is_anchored_to_telemetry_and_precedes_boot() -> None:
    before = identity()
    after = identity("19.31")
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, after, after])
    clock = {"value": 10.0}
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["value"] += seconds
        protocol.calls.append("quiet" if seconds >= 0.75 else "post-boot-delay")

    flasher = FirmwareFlasher(
        protocol,
        PB_V19,
        sleep=sleep,
        now=lambda: clock["value"],
    )
    result = flasher.flash(before, image, _issue_approval(before, image))

    assert result.state is FlashState.SUCCEEDED
    assert sleeps == pytest.approx([0.75, 0.6, 0.75, 0.75])
    assert protocol.calls.index("telemetry") < protocol.calls.index("quiet") < protocol.calls.index("enter")
    assert protocol.calls.count("enter") == 1
    quiet_indices = [index for index, call in enumerate(protocol.calls) if call == "quiet"]
    identity_indices = [index for index, call in enumerate(protocol.calls) if call == "identity"]
    assert identity_indices[2] < quiet_indices[1] < identity_indices[3]
    assert identity_indices[3] < quiet_indices[2] < protocol.calls.index("telemetry", identity_indices[3])


def test_preboot_quiet_gate_does_not_sleep_when_interval_already_elapsed() -> None:
    sleeps: list[float] = []
    flasher = FirmwareFlasher(
        FakeProtocol([]),
        PB_V19,
        sleep=sleeps.append,
        now=lambda: 2.0,
        preboot_quiet_interval=0.75,
    )

    flasher._await_preboot_quiet(1.0)

    assert sleeps == []


def test_preboot_quiet_gate_exceeds_both_retained_successful_boundaries() -> None:
    root = Path(__file__).parents[1] / "implementation_details" / "captures"
    measured: list[float] = []
    for capture in ("2026-08-09-v19_27", "2026-08-09-v19_31"):
        events = [json.loads(line) for line in (root / capture / "preboot-boundary.jsonl").read_text().splitlines()]
        acknowledgement = next(event for event in events if event.get("direction") == "RX" and event.get("size") == 8)
        boot = next(
            event for event in events if event.get("direction") == "TX" and " 16 26 " in f" {event.get('hex', '')} "
        )
        measured.append(
            (
                datetime.fromisoformat(boot["timestamp_utc"]) - datetime.fromisoformat(acknowledgement["timestamp_utc"])
            ).total_seconds()
        )

    assert measured == pytest.approx([0.689712, 0.499038])
    assert FirmwareFlasher(FakeProtocol([]), PB_V19).preboot_quiet_interval > max(measured)


@pytest.mark.parametrize(
    ("telemetry", "message"),
    [
        (SimpleNamespace(cell_voltages=(), pack_voltage=0.0), "cell count"),
        (SimpleNamespace(cell_voltages=(6.0,), pack_voltage=6.0), "cell voltage"),
        (SimpleNamespace(cell_voltages=(3.3, 3.3), pack_voltage=40.0), "inconsistent"),
    ],
)
def test_post_flash_telemetry_plausibility_rejects_bad_data(telemetry: object, message: str) -> None:
    with pytest.raises(SafetyError, match=message):
        FirmwareFlasher._verify_post_telemetry(telemetry, 16)


def test_post_flash_telemetry_rejects_too_many_active_cells() -> None:
    telemetry = SimpleNamespace(cell_voltages=(3.3,) * 17, pack_voltage=56.1)
    with pytest.raises(SafetyError, match="cell count"):
        FirmwareFlasher._verify_post_telemetry(telemetry, 16)


def test_transfer_widens_ack_timeout_only_during_transfer_and_restores_it() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, identity("19.31"), identity("19.31")])
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None, transfer_ack_timeout=45.0)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.SUCCEEDED
    assert protocol.timeout_calls == [45.0] * 3
    assert protocol.read_timeout == 2.0


@pytest.mark.parametrize(
    ("telemetry", "message"),
    [
        (replace(safe_telemetry(), pack_current=5.0), "pack current"),
        (replace(safe_telemetry(), fault_mask=1), "protection fault"),
        (replace(safe_telemetry(), state_of_charge=5), "state of charge"),
    ],
)
def test_preflight_battery_state_gate_blocks_boot_entry_before_any_bytes_are_sent(
    telemetry: TelemetrySnapshot, message: str
) -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before])
    protocol.telemetry_override = telemetry
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    with pytest.raises(SafetyError, match=message):
        flasher.flash(before, image, _issue_approval(before, image))
    assert protocol.calls == ["identity", "identity", "telemetry"]
    assert "enter" not in protocol.calls
    assert protocol.packets == []


def test_preflight_battery_state_gate_thresholds_are_configurable() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, identity("19.31"), identity("19.31")])
    protocol.telemetry_override = replace(safe_telemetry(), pack_current=2.0)
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None, max_flash_current=3.0)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.SUCCEEDED


def test_vendor_advisory_alarm_bits_do_not_impersonate_protection_faults() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, identity("19.31"), identity("19.31")])
    protocol.telemetry_override = replace(safe_telemetry(), fault_mask=0x00080000)
    result = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None).flash(
        before,
        image,
        _issue_approval(before, image),
    )
    assert result.state is FlashState.SUCCEEDED


def test_transfer_deadline_stops_a_stalling_device_without_retry() -> None:
    before = identity()
    image = firmware(bytes(index & 0xFF for index in range(3 * 128 + 1)))
    protocol = FakeProtocol([before, before])
    clock = iter([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 100.0])
    flasher = FirmwareFlasher(
        protocol,
        PB_V19,
        sleep=lambda _seconds: None,
        now=lambda: next(clock),
        transfer_deadline=10.0,
    )
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.RECOVERY_REQUIRED
    assert "deadline" in result.message
    assert len(protocol.packets) < 4
    assert protocol.calls.count("complete") == 0


def test_transfer_stops_on_first_bad_ack_without_retry_or_more_writes() -> None:
    before = identity()
    image = firmware(b"x" * 257)
    protocol = FakeProtocol([before, before])
    protocol.fail_ack = True
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.RECOVERY_REQUIRED
    assert len(protocol.packets) == 1
    assert protocol.calls.count("ack") == 1
    assert protocol.calls.count("identity") == 2


def test_pre_identity_instability_blocks_boot_entry() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, identity(serial="OTHER")])
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    with pytest.raises(SafetyError, match="stable"):
        flasher.flash(before, image, _issue_approval(before, image))
    assert "enter" not in protocol.calls


def test_post_version_mismatch_requires_recovery() -> None:
    before = identity()
    wrong = identity("19.30")
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, wrong, wrong])
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.RECOVERY_REQUIRED
    assert "version" in result.message


def test_approval_is_opaque_and_bound_to_device_image_and_body() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([])
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    with pytest.raises(SafetyError, match="opaque"):
        flasher.flash(before, image, object())  # type: ignore[arg-type]
    with pytest.raises(SafetyError, match="device"):
        flasher.flash(identity(serial="OTHER"), image, _issue_approval(before, image))


def test_image_body_and_suffix_must_reconstruct_decoded_image() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    broken = FirmwareImage(
        path=image.path,
        container_sha256=image.container_sha256,
        decoded_sha256=image.decoded_sha256,
        decoded=b"wrong",
        transfer_body=image.transfer_body,
        suffix=image.suffix,
        model=image.model,
        version=image.version,
        initial_sp=image.initial_sp,
        reset_vector=image.reset_vector,
    )
    flasher = FirmwareFlasher(FakeProtocol([]), PB_V19, sleep=lambda _seconds: None)
    with pytest.raises(SafetyError, match="reconstruct"):
        flasher.flash(before, broken, _issue_approval(before, broken))


def test_transfer_packet_argument_validation() -> None:
    with pytest.raises(ValueError, match="sequence"):
        build_transfer_packet(256, b"x" * 128)
    with pytest.raises(ValueError, match="exactly 128"):
        build_transfer_packet(1, b"short")
    with pytest.raises(SafetyError, match="1..128"):
        build_transfer_packet(1, b"", final=True)
    assert build_transfer_packet(1, b"x" * 128, final=True)[-3:] == FINAL_MARKER


def test_flasher_constructor_and_approval_image_binding() -> None:
    with pytest.raises(ValueError, match="quiet interval"):
        FirmwareFlasher(FakeProtocol([]), PB_V19, preboot_quiet_interval=0)
    with pytest.raises(ValueError, match="post-flash query"):
        FirmwareFlasher(FakeProtocol([]), PB_V19, post_query_quiet_interval=0)
    with pytest.raises(ValueError, match="delay"):
        FirmwareFlasher(FakeProtocol([]), PB_V19, post_boot_delay=-1)  # type: ignore[arg-type]
    before = identity()
    first = firmware(bytes(range(129)))
    mutated_body = bytes((first.transfer_body[0] ^ 0xFF,)) + first.transfer_body[1:]
    alterations = (
        replace(
            first,
            decoded=mutated_body + first.suffix,
            transfer_body=mutated_body,
        ),
        replace(first, model="JK-PB2A16S20P"),
        replace(first, version="19.32"),
    )
    approval = _issue_approval(before, first)

    for altered in alterations:
        # Caller-provided digest strings and transfer length are deliberately
        # copied. Approval binding must derive its own values from the bytes and
        # include the embedded compatibility identity.
        assert altered.container_sha256 == first.container_sha256
        assert altered.decoded_sha256 == first.decoded_sha256
        assert len(altered.transfer_body) == len(first.transfer_body)
        protocol = FakeProtocol([])
        flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
        with pytest.raises(SafetyError, match="firmware image"):
            flasher.flash(before, altered, approval)
        assert protocol.calls == []


def test_positive_footer_expiry_is_rechecked_immediately_before_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timestamp_ms = 2_000_000_000_000
    suffix = timestamp_ms.to_bytes(8, "little", signed=True) + (1).to_bytes(4, "little", signed=True)
    base = firmware(bytes(range(129)))
    expiring = replace(
        base,
        decoded=base.transfer_body + suffix,
        suffix=suffix,
    )
    before = identity()
    now_ms = {"value": timestamp_ms}

    class ExpireDuringTelemetry(FakeProtocol):
        def read_telemetry(self, max_cells: int) -> TelemetrySnapshot:
            telemetry = super().read_telemetry(max_cells)
            now_ms["value"] = timestamp_ms + 3_600_001
            return telemetry

    protocol = ExpireDuringTelemetry([before, before])
    monkeypatch.setattr(
        "jkflash.firmware.time.time",
        lambda: now_ms["value"] / 1000,
    )

    with pytest.raises(FirmwareError, match="not active"):
        FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None).flash(
            before, expiring, _issue_approval(before, expiring)
        )

    assert protocol.calls == ["identity", "identity", "telemetry"]
    assert protocol.packets == []
    assert "enter" not in protocol.calls


def test_fresh_identity_change_blocks_boot_even_if_two_reads_are_stable() -> None:
    before = identity()
    changed = identity("19.27")
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([changed, changed])
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    with pytest.raises(SafetyError, match="preflight identity"):
        flasher.flash(before, image, _issue_approval(before, image))
    assert "enter" not in protocol.calls


def test_bad_exact_completion_stops_before_post_queries() -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before])
    protocol.completion = b"x" * len(FINAL_RESPONSE)
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.RECOVERY_REQUIRED
    assert protocol.calls.count("identity") == 2


def test_boot_command_write_failure_is_recovery_uncertain() -> None:
    before = identity()
    image = firmware(bytes(range(129)))

    class EnterFailure(FakeProtocol):
        def send_enter_bootloader(self) -> None:
            raise ProtocolError("port closed")

    flasher = FirmwareFlasher(EnterFailure([before, before]), PB_V19, sleep=lambda _seconds: None)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.RECOVERY_REQUIRED
    assert "port closed" in result.message


@pytest.mark.parametrize(
    "posts",
    [
        (identity("19.31"), identity("19.31", serial="OTHER")),
        (identity("19.31", serial="OTHER"), identity("19.31", serial="OTHER")),
    ],
)
def test_post_identity_instability_or_physical_change_requires_recovery(
    posts: tuple[DeviceIdentity, DeviceIdentity],
) -> None:
    before = identity()
    image = firmware(bytes(range(129)))
    protocol = FakeProtocol([before, before, *posts])
    flasher = FirmwareFlasher(protocol, PB_V19, sleep=lambda _seconds: None)
    result = flasher.flash(before, image, _issue_approval(before, image))
    assert result.state is FlashState.RECOVERY_REQUIRED


def test_empty_transfer_body_is_rejected_even_when_decoded_is_only_suffix() -> None:
    before = identity()
    image = firmware(b"")
    flasher = FirmwareFlasher(FakeProtocol([]), PB_V19, sleep=lambda _seconds: None)
    with pytest.raises(SafetyError, match="empty"):
        flasher.flash(before, image, _issue_approval(before, image))


def _native_identity_frame(value: DeviceIdentity) -> bytes:
    frame = bytearray(300)
    frame[:6] = bytes.fromhex("55 AA EB 90 03 01")
    frame[6:21] = value.model.encode().ljust(15, b"\0")[:15]
    frame[0x15] = value.max_cells
    frame[22:30] = value.hardware.encode().ljust(8, b"\0")
    frame[30:38] = value.software.encode().ljust(8, b"\0")
    frame[86:102] = value.serial.encode().ljust(16, b"\0")[:16]
    frame[-1] = sum(frame[:-1]) & 0xFF
    return bytes(frame)


def _native_telemetry_frame() -> bytes:
    frame = bytearray(300)
    frame[:6] = bytes.fromhex("55 AA EB 90 02 01")
    for index in range(16):
        frame[6 + index * 2 : 8 + index * 2] = (3300 + index).to_bytes(2, "little")
    frame[0x46:0x4A] = ((1 << 16) - 1).to_bytes(4, "little")
    frame[150:154] = (52_000).to_bytes(4, "little")
    frame[-1] = sum(frame[:-1]) & 0xFF
    return bytes(frame)


class DiscoveryTransport:
    def __init__(self, responders: dict[int, DeviceIdentity]) -> None:
        self.responders = responders
        self.pending = bytearray()
        self.addresses: list[int] = []
        self.closed = False
        self.read_timeout = 2.0

    def write(self, data: bytes) -> int:
        address = data[0]
        register = int.from_bytes(data[2:4], "big")
        self.addresses.append(address)
        if address in self.responders and register in (
            IDENTITY_REGISTER,
            TELEMETRY_REGISTER,
        ):
            frame = (
                _native_identity_frame(self.responders[address])
                if register == IDENTITY_REGISTER
                else _native_telemetry_frame()
            )
            ack = append_modbus_crc(bytes((address, 0x10)) + register.to_bytes(2, "big") + b"\x00\x01")
            self.pending.extend(frame + ack)
        return len(data)

    def read(self, size: int = 1) -> bytes:
        if not self.pending:
            return b""
        result = bytes(self.pending[:size])
        del self.pending[:size]
        return result

    def close(self) -> None:
        self.closed = True

    def get_read_timeout(self) -> float:
        return self.read_timeout

    def set_read_timeout(self, seconds: float) -> None:
        self.read_timeout = seconds


class OnePortProvider:
    def list(self) -> tuple[PortInfo, ...]:
        return (PortInfo("COM5", "CH340", "USB"),)


class OneTransportFactory:
    def __init__(self, transport: DiscoveryTransport) -> None:
        self.transport = transport
        self.configs = []

    def open(self, config: PortConfig) -> DiscoveryTransport:
        self.configs.append(config)
        return self.transport


def _application(
    transport: DiscoveryTransport,
    *,
    evaluator: object | None = None,
    inspector: object | None = None,
) -> JkApplication:
    return JkApplication(
        OnePortProvider(),
        OneTransportFactory(transport),
        compatibility_evaluator=evaluator,  # type: ignore[arg-type]
        firmware_inspector=inspector,  # type: ignore[arg-type]
        sleep=lambda _seconds: None,
    )


def test_application_discovers_only_selected_address_and_monitors() -> None:
    connected = identity()
    transport = DiscoveryTransport({5: connected})
    app = _application(transport)
    assert app.list_ports()[0].device == "COM5"
    assert app.connect(PortInfo("COM5"), 5) == connected
    assert transport.addresses[:1] == [5]
    assert 0 not in transport.addresses
    assert app.selected_profile is PB_V19
    assert app.read_identity() == connected
    snapshot = app.read_telemetry(16)
    assert snapshot.pack_voltage == pytest.approx(52.0)
    assert len(snapshot.cell_voltages) == 16
    with pytest.raises(SafetyError, match="cell count"):
        app.read_telemetry(15)
    app.close()
    assert transport.closed
    assert app.connected_identity is None


def test_application_rejects_missing_selected_address() -> None:
    # Ensure generated response identities report the scanned address.
    transport = DiscoveryTransport({})
    app = _application(transport)
    with pytest.raises(SafetyError, match="no JK responder"):
        app.connect(PortInfo("COM5"), 5)
    assert transport.closed


@pytest.mark.parametrize("address", [0, 248])
def test_application_never_accepts_out_of_modbus_range(address: int) -> None:
    app = _application(DiscoveryTransport({}))
    with pytest.raises(SafetyError, match="1..247"):
        app.connect(PortInfo("COM5"), address)


def test_generic_capability_supports_non_v19_jk_models() -> None:
    unknown = DeviceIdentity(5, "JK-PB1A16S20P", 16, "18A", "18.9", "SERIAL")
    app = _application(DiscoveryTransport({5: unknown}))
    assert app.connect(PortInfo("COM5"), 5) == unknown
    assert app.selected_profile is PB_V19
    assert app.read_telemetry(16).pack_voltage == pytest.approx(52.0)


def test_application_lists_inspects_preflights_and_consumes_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    first_path = tmp_path / "A.jkbms"
    second_path = nested / "b.JKBMS"
    ignored = nested / "note.txt"
    first_path.write_bytes(b"x")
    second_path.write_bytes(b"x")
    ignored.write_bytes(b"x")

    connected = identity()
    image = firmware(bytes(range(129)))
    inspected: list[tuple[Path, object]] = []

    def inspector(path: Path, profile: object) -> FirmwareImage:
        inspected.append((path, profile))
        return image

    confirmations: list[bool] = []

    def evaluator(
        device: DeviceIdentity,
        target: FirmwareImage,
        profile: object,
        *,
        same_version_confirmed: bool,
        downgrade_confirmed: bool,
    ) -> ValidationReport:
        assert device == connected and target == image and profile is PB_V19
        confirmations.append(same_version_confirmed)
        assert not downgrade_confirmed
        return ValidationReport()

    app = _application(DiscoveryTransport({5: connected}), evaluator=evaluator, inspector=inspector)
    app.connect(PortInfo("COM5"), 5)
    assert app.list_firmware(tmp_path) == (first_path, second_path)
    assert app.list_firmware(tmp_path / "missing") == ()
    assert app.inspect_firmware(first_path) == image
    assert inspected == [(first_path, PB_V19)]
    assert app.preflight(connected, image, same_version_confirmed=True).allowed
    assert confirmations == [True]

    verified = identity("19.31")

    class StubFlasher:
        def __init__(self, protocol: object, profile: object, **kwargs: object) -> None:
            assert protocol is not None and profile is PB_V19
            assert "sleep" in kwargs
            self.verified_identity = verified

        def flash(
            self,
            device: DeviceIdentity,
            target: FirmwareImage,
            approval: object,
            event_sink: object,
        ) -> FlashResult:
            assert device == connected and target == image and approval is not None
            return FlashResult(FlashState.SUCCEEDED, "done")

    monkeypatch.setattr("jkflash.application.FirmwareFlasher", StubFlasher)
    assert app.flash(connected, image, lambda _event: None).state is FlashState.SUCCEEDED
    assert app.connected_identity == verified
    with pytest.raises(SafetyError, match="preflight"):
        app.flash(verified, image, lambda _event: None)


def test_application_preflight_denial_and_changed_identity_clear_or_block_approval() -> None:
    connected = identity()
    image = firmware(bytes(range(129)))
    app = _application(
        DiscoveryTransport({5: connected}),
        evaluator=lambda *_args, **_kwargs: ValidationReport(),
        inspector=lambda _path, _profile: image,
    )
    app.connect(PortInfo("COM5"), 5)
    with pytest.raises(SafetyError, match="not the connected"):
        app.preflight(identity(serial="OTHER"), image)

    # A physical-identity change is detected even though software changes are
    # allowed after a verified flash.
    assert isinstance(app._transport, DiscoveryTransport)
    app._transport.responders[5] = identity(serial="OTHER")
    with pytest.raises(SafetyError, match="physical identity changed"):
        app.read_identity()


def test_application_requires_connection_services_and_unambiguous_profiles() -> None:
    app = _application(DiscoveryTransport({}))
    with pytest.raises(SafetyError, match="connect"):
        app.read_identity()
    with pytest.raises(SafetyError, match="connect"):
        app.preflight(identity(), firmware(bytes(range(129))))
    with pytest.raises(ValueError, match="profile"):
        JkApplication(OnePortProvider(), OneTransportFactory(DiscoveryTransport({})), profiles=())


def test_default_ui_service_composition_is_lazy_and_concrete() -> None:
    app = create_ui_services()
    assert isinstance(app, JkApplication)
    assert isinstance(app.port_provider, SerialPortProvider)
    assert isinstance(app.transport_factory, SerialTransportFactory)
