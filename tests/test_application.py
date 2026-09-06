from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

import jkflash.application as application_module
from jkflash.application import JkApplication
from jkflash.domain import (
    DeviceIdentity,
    DeviceProfile,
    FirmwareImage,
    FlashResult,
    FlashState,
    PortConfig,
    PortInfo,
    SafetyError,
    TelemetrySnapshot,
    ValidationReport,
)
from jkflash.profiles import PB_V19
from jkflash.protocol import ProtocolTimeout
from jkflash.safety import evaluate_compatibility

DEVICE = DeviceIdentity(5, "JK-PB2A16S20P", 16, "19A", "19.26", "SERIAL")


class Provider:
    def list(self) -> tuple[PortInfo, ...]:
        return (PortInfo("COM5"),)


class Transport:
    def __init__(self) -> None:
        self.closed = False
        self.read_timeout = 2.0

    def write(self, data: bytes) -> int:
        return len(data)

    def read(self, size: int = 1) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True

    def get_read_timeout(self) -> float:
        return self.read_timeout

    def set_read_timeout(self, seconds: float) -> None:
        self.read_timeout = seconds


class Factory:
    def __init__(self) -> None:
        self.transport = Transport()
        self.configs = []

    def open(self, config: PortConfig) -> Transport:
        self.configs.append(config)
        return self.transport


def image() -> FirmwareImage:
    body = b"x" * 129
    suffix = b"s" * 12
    return FirmwareImage(
        Path("firmware.jkbms"),
        "a" * 64,
        "b" * 64,
        body + suffix,
        body,
        suffix,
        "JK-PB2A16S20P",
        "19.31",
        0x20001000,
        0x08010001,
    )


def install_protocol_stub(
    monkeypatch: pytest.MonkeyPatch,
    responders: dict[int, DeviceIdentity],
    *,
    telemetry_layouts: list[str] | None = None,
) -> list[int]:
    seen: list[int] = []

    class ProtocolStub:
        def __init__(
            self, transport: object, address: int, *, telemetry_layout: str = "JK02_32S", **_registers: object
        ) -> None:
            self.address = address
            self.telemetry_layout = telemetry_layout
            if telemetry_layouts is not None:
                telemetry_layouts.append(telemetry_layout)

        def read_identity(self) -> DeviceIdentity:
            seen.append(self.address)
            if self.address not in responders:
                raise ProtocolTimeout("none")
            return responders[self.address]

        def read_telemetry(self, max_cells: int) -> TelemetrySnapshot:
            return TelemetrySnapshot(
                (3.3,) * max_cells,
                52.8,
                1.0,
                80,
                99,
                25.0,
                24.0,
                23.0,
                0.0,
                0,
                True,
                True,
                100.0,
                200.0,
                10,
                1000,
                0,
            )

    monkeypatch.setattr(application_module, "JkProtocol", ProtocolStub)
    return seen


def test_discovery_queries_only_the_operator_selected_address_and_selects_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layouts: list[str] = []
    seen = install_protocol_stub(monkeypatch, {5: DEVICE}, telemetry_layouts=layouts)
    factory = Factory()
    app = JkApplication(Provider(), factory)
    assert app.connect(PortInfo("COM5"), 5) == DEVICE
    assert seen == [5]
    assert app.selected_profile is PB_V19
    assert layouts[-1] == "JK02_32S"
    assert app.read_telemetry(16).pack_voltage == 52.8
    identity, telemetry = app.read_dashboard(16)
    assert identity == DEVICE
    assert telemetry.pack_voltage == 52.8
    assert seen == [5]
    app.close()
    assert factory.transport.closed


def test_connect_closes_transport_when_selected_address_does_not_respond(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_protocol_stub(monkeypatch, {})
    factory = Factory()
    with pytest.raises(SafetyError, match="no JK responder"):
        JkApplication(Provider(), factory).connect(PortInfo("COM5"), 5)
    assert factory.transport.closed


def test_generic_capability_profile_enables_matching_jk_families(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unknown = DeviceIdentity(5, "JK-PB1A8S10P", 8, "18A", "18.1", "SERIAL")
    layouts: list[str] = []
    install_protocol_stub(monkeypatch, {5: unknown}, telemetry_layouts=layouts)
    app = JkApplication(Provider(), Factory())
    app.connect(PortInfo("COM5"), 5)
    assert app.selected_profile is PB_V19
    assert layouts[-1] == "JK02_32S"
    assert app.read_telemetry(8).pack_voltage == 52.8


def test_unknown_non_jk_identity_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    unknown = DeviceIdentity(5, "OTHER-BMS", 8, "18A", "18.1", "SERIAL")
    install_protocol_stub(monkeypatch, {5: unknown})
    app = JkApplication(Provider(), Factory())
    app.connect(PortInfo("COM5"), 5)
    assert app.selected_profile is None
    with pytest.raises(SafetyError, match="identity-only"):
        app.read_telemetry(8)


def test_legacy_24_slot_capability_is_monitoring_only(monkeypatch: pytest.MonkeyPatch) -> None:
    legacy = DeviceIdentity(5, "JK-B1A24S", 24, "18A", "18.1", "SERIAL")
    install_protocol_stub(monkeypatch, {5: legacy})
    app = JkApplication(Provider(), Factory())
    assert app.connect(PortInfo("COM5"), 5) == legacy
    assert app.selected_profile is not None
    assert app.selected_profile.telemetry_layout == "JK02_24S"
    assert app.read_telemetry(24).pack_voltage == 52.8
    with pytest.raises(SafetyError, match="monitoring but not firmware flashing"):
        app.preflight(legacy, image())


def test_app_configured_high_modbus_address_is_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    high = DeviceIdentity(247, DEVICE.model, DEVICE.max_cells, DEVICE.hardware, DEVICE.software, DEVICE.serial)
    seen = install_protocol_stub(monkeypatch, {247: high})
    app = JkApplication(Provider(), Factory())
    assert app.connect(PortInfo("COM5"), 247) == high
    assert seen == [247]


def test_inspection_preflight_and_flash_are_bound_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    install_protocol_stub(monkeypatch, {5: DEVICE})
    target = image()
    inspected: list[tuple[Path, DeviceProfile]] = []

    def inspect(path: Path, profile: DeviceProfile) -> FirmwareImage:
        inspected.append((path, profile))
        return target

    def evaluate(
        identity: DeviceIdentity,
        firmware: FirmwareImage,
        profile: DeviceProfile,
        *,
        same_version_confirmed: bool,
        downgrade_confirmed: bool,
    ) -> ValidationReport:
        assert (identity, firmware, profile) == (DEVICE, target, PB_V19)
        assert same_version_confirmed
        assert not downgrade_confirmed
        return ValidationReport()

    app = JkApplication(
        Provider(),
        Factory(),
        firmware_inspector=inspect,
        compatibility_evaluator=evaluate,
        transcript_dir=tmp_path / "logs",
    )
    app.connect(PortInfo("COM5"), 5)
    assert app.inspect_firmware(target.path) == target
    assert inspected == [(target.path, PB_V19)]
    assert app.preflight(DEVICE, target, same_version_confirmed=True).allowed

    class FlasherStub:
        def __init__(self, protocol: object, profile: DeviceProfile, **kwargs: object) -> None:
            self.verified_identity = None

        def flash(self, *args: object) -> FlashResult:
            return FlashResult(FlashState.SUCCEEDED, "done")

    monkeypatch.setattr(application_module, "FirmwareFlasher", FlasherStub)
    assert app.flash(DEVICE, target, lambda _event: None).state is FlashState.SUCCEEDED
    transcripts = list((tmp_path / "logs").glob("flash-*.jsonl"))
    assert len(transcripts) == 1
    transcript = transcripts[0].read_text(encoding="utf-8")
    assert target.container_sha256 in transcript
    assert DEVICE.serial not in transcript
    with pytest.raises(SafetyError, match="preflight"):
        app.flash(DEVICE, target, lambda _event: None)

    assert app.preflight(DEVICE, target, same_version_confirmed=True).allowed
    real_write = application_module.write_audit
    write_calls = 0

    def fail_only_final_write(path: Path, records: Iterable[application_module.AuditRecord]) -> None:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 2:
            raise OSError("disk became unavailable")
        real_write(path, records)

    monkeypatch.setattr(application_module, "write_audit", fail_only_final_write)
    assert app.flash(DEVICE, target, lambda _event: None).state is FlashState.SUCCEEDED
    assert write_calls == 2


def test_downgrade_cannot_mint_application_approval_without_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = DeviceIdentity(5, "JK-PB2A16S20P", 16, "19A", "19.34", "SERIAL")
    install_protocol_stub(monkeypatch, {5: installed})
    body = b"x" * 65_537
    suffix = b"\x00" * 12
    target = FirmwareImage(
        Path("downgrade.jkbms"),
        "caller-container-hash",
        "caller-decoded-hash",
        body + suffix,
        body,
        suffix,
        installed.model,
        "19.31",
        0x20001000,
        0x08010001,
    )
    app = JkApplication(Provider(), Factory(), compatibility_evaluator=evaluate_compatibility)
    app.connect(PortInfo("COM5"), 5)

    denied = app.preflight(installed, target)
    assert not denied.allowed
    assert {issue.code for issue in denied.issues} == {"downgrade_confirmation_required"}
    assert app._approval is None
    with pytest.raises(SafetyError, match="successful preflight"):
        app.flash(installed, target, lambda _event: None)

    approved = app.preflight(installed, target, downgrade_confirmed=True)
    assert approved.allowed
    assert app._approval is not None


def test_missing_services_conflicting_profiles_and_baudrates_are_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_protocol_stub(monkeypatch, {5: DEVICE})
    app = JkApplication(Provider(), Factory())
    app.connect(PortInfo("COM5"), 5)
    with pytest.raises(SafetyError, match="inspection service"):
        app.inspect_firmware(Path("x"))
    with pytest.raises(SafetyError, match="evaluator"):
        app.preflight(DEVICE, image())

    other_baud = DeviceProfile(
        "other",
        PB_V19.model_pattern,
        19,
        19,
        9600,
        b"banner",
        "JK02_32S",
    )
    with pytest.raises(SafetyError, match="baudrate"):
        JkApplication(Provider(), Factory(), profiles=(PB_V19, other_baud)).connect(PortInfo("COM5"), 5)

    duplicate = DeviceProfile(
        "duplicate",
        PB_V19.model_pattern,
        19,
        19,
        115_200,
        b"banner",
        "JK02_32S",
    )
    with pytest.raises(SafetyError, match="multiple capability"):
        JkApplication(Provider(), Factory(), profiles=(PB_V19, duplicate)).connect(PortInfo("COM5"), 5)
