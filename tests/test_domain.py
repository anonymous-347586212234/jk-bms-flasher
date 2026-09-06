from pathlib import Path

import pytest

from jkflash.domain import (
    DeviceIdentity,
    DeviceProfile,
    FirmwareError,
    FirmwareImage,
    FlashEvent,
    FlashResult,
    FlashState,
    JkFlashError,
    PortConfig,
    PortInfo,
    ProtocolError,
    SafetyError,
    Severity,
    TelemetrySnapshot,
    ValidationIssue,
    ValidationReport,
)
from jkflash.profiles import PB_V19, SUPPORTED_PROFILES


def test_domain_values_and_telemetry_derivations() -> None:
    assert PortInfo("COM1").device == "COM1"
    assert PortConfig("COM1", 5).baudrate == 115_200
    identity = DeviceIdentity(5, "JK-PB2A16S30P", 16, "19A", "19.31", "secret")
    assert identity.max_cells == 16
    snapshot = TelemetrySnapshot(
        cell_voltages=(3.2, 3.3),
        pack_voltage=6.5,
        pack_current=-2.0,
        state_of_charge=50,
        state_of_health=99,
        mos_temperature=25.0,
        temperature_1=24.0,
        temperature_2=23.0,
        balance_current=-0.1,
        balance_state=2,
        charge_mos=True,
        discharge_mos=False,
        remaining_capacity=10.0,
        full_capacity=20.0,
        cycles=3,
        runtime_seconds=60,
        fault_mask=0,
    )
    assert snapshot.power == -13.0
    assert snapshot.minimum_cell == 3.2
    assert snapshot.maximum_cell == 3.3
    assert snapshot.average_cell == pytest.approx(3.25)
    assert snapshot.cell_delta == pytest.approx(0.1)


def test_validation_and_flash_types() -> None:
    assert ValidationReport().allowed
    warning = ValidationIssue("warn", "warning", Severity.WARNING)
    assert ValidationReport((warning,)).allowed
    error = ValidationIssue("bad", "failure")
    assert not ValidationReport((error,)).allowed
    event = FlashEvent(FlashState.TRANSFERRING, "block", 1, 2)
    result = FlashResult(FlashState.SUCCEEDED, "done")
    assert event.completed_blocks == 1
    assert result.state is FlashState.SUCCEEDED


def test_firmware_profile_and_error_hierarchy() -> None:
    image = FirmwareImage(
        Path("firmware.jkbms"),
        "a",
        "b",
        b"decoded",
        b"body",
        b"suffix",
        "JK-PB2A16S30P",
        "19.31",
        0x20001000,
        0x08010001,
    )
    assert image.transfer_body == b"body"
    profile = DeviceProfile("family", r"JKPB.*", 19, 19, 115200, b"boot", "layout")
    assert profile.max_supported_cells == 32
    assert SUPPORTED_PROFILES[0] is PB_V19
    assert len(SUPPORTED_PROFILES) == 2
    assert SUPPORTED_PROFILES[1].flash_supported is False
    for error_type in (ProtocolError, FirmwareError, SafetyError):
        assert isinstance(error_type("safe"), JkFlashError)
