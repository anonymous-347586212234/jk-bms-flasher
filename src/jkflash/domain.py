"""Dependency-free domain contracts shared by all layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import NewType


@dataclass(frozen=True, slots=True)
class PortInfo:
    device: str
    description: str = ""
    hwid: str = ""
    manufacturer: str = ""
    product: str = ""
    interface: str = ""
    location: str = ""
    vid: int | None = None
    pid: int | None = None
    serial_number: str = ""


@dataclass(frozen=True, slots=True)
class PortConfig:
    device: str
    address: int
    baudrate: int = 115_200
    read_timeout: float = 2.0
    write_timeout: float = 2.0


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    address: int
    model: str
    max_cells: int
    hardware: str
    software: str
    serial: str


@dataclass(frozen=True, slots=True)
class TelemetrySnapshot:
    cell_voltages: tuple[float, ...]
    pack_voltage: float
    pack_current: float
    state_of_charge: int
    state_of_health: int
    mos_temperature: float
    temperature_1: float
    temperature_2: float
    balance_current: float
    balance_state: int
    charge_mos: bool
    discharge_mos: bool
    remaining_capacity: float
    full_capacity: float
    cycles: int
    runtime_seconds: int
    fault_mask: int

    @property
    def power(self) -> float:
        return self.pack_voltage * self.pack_current

    @property
    def minimum_cell(self) -> float:
        return min(self.cell_voltages)

    @property
    def maximum_cell(self) -> float:
        return max(self.cell_voltages)

    @property
    def average_cell(self) -> float:
        return sum(self.cell_voltages) / len(self.cell_voltages)

    @property
    def cell_delta(self) -> float:
        return self.maximum_cell - self.minimum_cell


@dataclass(frozen=True, slots=True)
class FirmwareImage:
    path: Path
    container_sha256: str
    decoded_sha256: str
    decoded: bytes = field(repr=False)
    transfer_body: bytes = field(repr=False)
    suffix: bytes = field(repr=False)
    model: str
    version: str
    initial_sp: int
    reset_vector: int


class Severity(Enum):
    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    message: str
    severity: Severity = Severity.ERROR


@dataclass(frozen=True, slots=True)
class ValidationReport:
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def allowed(self) -> bool:
        return not any(issue.severity is Severity.ERROR for issue in self.issues)


class FlashState(Enum):
    PREFLIGHT = auto()
    ENTERING_BOOTLOADER = auto()
    TRANSFERRING = auto()
    VERIFYING = auto()
    SUCCEEDED = auto()
    RECOVERY_REQUIRED = auto()


@dataclass(frozen=True, slots=True)
class FlashEvent:
    state: FlashState
    message: str
    completed_blocks: int = 0
    total_blocks: int = 0


@dataclass(frozen=True, slots=True)
class FlashResult:
    state: FlashState
    message: str


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    name: str
    model_pattern: str
    hardware_major: int | None
    firmware_major: int | None
    baudrate: int
    boot_banner: bytes
    telemetry_layout: str
    identity_register: int = 0x161C
    telemetry_register: int = 0x1620
    boot_register: int = 0x1626
    protocol_version: str = "JK-BXAXS-XP/300"
    evidence: str = "generalized; captured on a subset of matching devices"
    flash_supported: bool = True
    max_supported_cells: int = 32
    flash_blocking_fault_mask: int = 0xFFFFFFFF
    min_decoded_size: int = 65_536
    max_decoded_size: int = 262_144
    sram_start: int = 0x20000000
    sram_end: int = 0x20010000
    app_flash_start: int = 0x08000000
    app_flash_end: int = 0x08040000


ApprovedPreflight = NewType("ApprovedPreflight", object)


class JkFlashError(Exception):
    """Base error with a user-safe message."""


class ProtocolError(JkFlashError):
    pass


class FirmwareError(JkFlashError):
    pass


class SafetyError(JkFlashError):
    pass
