"""Ports connecting application logic to external I/O."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol

from .domain import (
    DeviceIdentity,
    FirmwareImage,
    FlashEvent,
    PortConfig,
    PortInfo,
    TelemetrySnapshot,
)


class PortProvider(Protocol):
    def list(self) -> Sequence[PortInfo]: ...


class ByteTransport(Protocol):
    def write(self, data: bytes) -> int: ...
    def read(self, size: int = 1) -> bytes: ...
    def close(self) -> None: ...
    def get_read_timeout(self) -> float: ...
    def set_read_timeout(self, seconds: float) -> None: ...


class TransportFactory(Protocol):
    def open(self, config: PortConfig) -> ByteTransport: ...


class BmsProtocol(Protocol):
    def read_identity(self) -> DeviceIdentity: ...
    def read_telemetry(self, max_cells: int) -> TelemetrySnapshot: ...


class FlashProtocol(BmsProtocol, Protocol):
    def send_enter_bootloader(self) -> None: ...
    def read_boot_ready(
        self,
        expected_banner: bytes,
        *,
        limit: int = 512,
        deadline: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> bytes: ...
    def transfer_read_timeout(self, seconds: float) -> AbstractContextManager[None]: ...
    def read_ack_byte(self) -> None: ...
    def read_exact(
        self,
        size: int,
        *,
        deadline: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> bytes: ...
    def write_packet(self, packet: bytes) -> None: ...


class FirmwareRepository(Protocol):
    def list(self) -> Sequence[Path]: ...
    def inspect(self, path: Path) -> FirmwareImage: ...


EventSink = Callable[[FlashEvent], None]
