"""Dependency-injected application services for monitoring and attended flashing."""

from __future__ import annotations

import contextlib
import re
import threading
from collections.abc import Callable, Sequence
from pathlib import Path

from .audit import AuditRecord, transcript_path, write_audit
from .domain import (
    ApprovedPreflight,
    DeviceIdentity,
    DeviceProfile,
    FirmwareImage,
    FlashEvent,
    FlashResult,
    PortConfig,
    PortInfo,
    SafetyError,
    TelemetrySnapshot,
    ValidationReport,
)
from .flasher import FirmwareFlasher, _issue_approval
from .interfaces import ByteTransport, PortProvider, TransportFactory
from .profiles import SUPPORTED_PROFILES
from .protocol import JkProtocol, ProtocolTimeout
from .transport import SerialPortProvider, SerialTransportFactory

CompatibilityEvaluator = Callable[..., ValidationReport]
FirmwareInspector = Callable[[Path, DeviceProfile], FirmwareImage]


class JkApplication:
    """Stateful service used by the attended UI.

    Discovery queries the operator-selected Modbus address directly. Address
    zero is never used. Physical isolation remains mandatory because software
    cannot detect two devices configured to the same address.
    """

    def __init__(
        self,
        port_provider: PortProvider,
        transport_factory: TransportFactory,
        *,
        firmware_inspector: FirmwareInspector | None = None,
        compatibility_evaluator: CompatibilityEvaluator | None = None,
        profiles: Sequence[DeviceProfile] = SUPPORTED_PROFILES,
        sleep: Callable[[float], None] | None = None,
        transcript_dir: Path | None = None,
    ) -> None:
        self.port_provider = port_provider
        self.transport_factory = transport_factory
        self.firmware_inspector = firmware_inspector
        self.compatibility_evaluator = compatibility_evaluator
        self.profiles = tuple(profiles)
        if not self.profiles:
            raise ValueError("at least one capability profile is required")
        self._sleep = sleep
        self.transcript_dir = transcript_dir
        self._serial_lock = threading.RLock()
        self._transport: ByteTransport | None = None
        self._protocol: JkProtocol | None = None
        self._identity: DeviceIdentity | None = None
        self._profile: DeviceProfile | None = None
        self._approval: ApprovedPreflight | None = None

    @property
    def connected_identity(self) -> DeviceIdentity | None:
        return self._identity

    @property
    def selected_profile(self) -> DeviceProfile | None:
        return self._profile

    def list_ports(self) -> Sequence[PortInfo]:
        return self.port_provider.list()

    def capability_status(self) -> str:
        if self._profile is None:
            return "No selected monitoring or flashing capability"
        return (
            f"{self._profile.name}; {self._profile.evidence}. "
            "Live framing and boot handshake are validated before transfer."
        )

    def connect(self, port: PortInfo, address: int) -> DeviceIdentity:
        """Open a port and query the explicitly selected device address."""

        with self._serial_lock:
            return self._connect_locked(port, address)

    def _connect_locked(self, port: PortInfo, address: int) -> DeviceIdentity:

        if not 1 <= address <= 247:
            raise SafetyError("JK application address must be in the range 1..247")
        self._close_locked()
        baudrate = self.profiles[0].baudrate
        if any(profile.baudrate != baudrate for profile in self.profiles):
            raise SafetyError("discovery capabilities disagree on serial baudrate")
        transport = self.transport_factory.open(PortConfig(device=port.device, address=address, baudrate=baudrate))
        try:
            identity = self._discover_sole_responder(transport, selected_address=address)
            profile = self._select_profile(identity)
            protocol = JkProtocol(
                transport,
                identity.address,
                telemetry_layout=(profile.telemetry_layout if profile else "UNKNOWN"),
                identity_register=(profile.identity_register if profile else self.profiles[0].identity_register),
                telemetry_register=(profile.telemetry_register if profile else self.profiles[0].telemetry_register),
                boot_register=(profile.boot_register if profile else self.profiles[0].boot_register),
            )
        except Exception:
            transport.close()
            raise

        self._transport = transport
        self._protocol = protocol
        self._identity = identity
        self._profile = profile
        self._approval = None
        return identity

    def close(self) -> None:
        with self._serial_lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._transport is not None:
            self._transport.close()
        self._transport = None
        self._protocol = None
        self._identity = None
        self._profile = None
        self._approval = None

    def read_identity(self) -> DeviceIdentity:
        with self._serial_lock:
            return self._read_identity_locked()

    def _read_identity_locked(self) -> DeviceIdentity:
        protocol = self._require_protocol()
        identity = protocol.read_identity()
        if self._identity is not None and _physical_identity(identity) != _physical_identity(self._identity):
            raise SafetyError("the connected physical identity changed")
        self._identity = identity
        return identity

    def read_telemetry(self, max_cells: int) -> TelemetrySnapshot:
        with self._serial_lock:
            return self._read_telemetry_locked(max_cells)

    def read_dashboard(self, max_cells: int) -> tuple[DeviceIdentity, TelemetrySnapshot]:
        """Read telemetry and return it with the established identity.

        The observed JK monitoring loop sends only the telemetry request at its
        roughly 0.8-second cadence.  Re-querying identity before every sample
        creates an unobserved back-to-back request pattern.  Identity is still
        queried during connection and twice immediately before boot entry.
        """

        with self._serial_lock:
            identity = self._require_identity()
            telemetry = self._read_telemetry_locked(max_cells)
            return identity, telemetry

    def _read_telemetry_locked(self, max_cells: int) -> TelemetrySnapshot:
        protocol = self._require_protocol()
        identity = self._require_identity()
        profile = self._require_known_profile("telemetry")
        if profile.telemetry_layout not in {"JK02_24S", "JK02_32S"}:
            raise SafetyError("the selected telemetry layout is read-only/unimplemented")
        if max_cells != identity.max_cells:
            raise SafetyError("telemetry cell count must match the connected model")
        return protocol.read_telemetry(max_cells)

    def list_firmware(self, directory: Path) -> Sequence[Path]:
        """List candidate containers; opening/compatibility happens separately."""

        if not directory.exists() or not directory.is_dir():
            return ()
        return tuple(
            sorted(
                (path for path in directory.rglob("*.jkbms") if path.is_file()),
                key=lambda path: str(path).casefold(),
            )
        )

    def inspect_firmware(self, path: Path) -> FirmwareImage:
        profile = self._require_known_profile("firmware inspection")
        if self.firmware_inspector is None:
            raise SafetyError("firmware inspection service is not configured")
        image = self.firmware_inspector(path, profile)
        self._approval = None
        return image

    def preflight(
        self,
        identity: DeviceIdentity,
        image: FirmwareImage,
        *,
        same_version_confirmed: bool = False,
        downgrade_confirmed: bool = False,
    ) -> ValidationReport:
        """Evaluate compatibility and cache an opaque approval only on success."""

        connected = self._require_identity()
        profile = self._require_known_profile("firmware flashing")
        if identity != connected:
            raise SafetyError("preflight identity is not the connected identity")
        if self.compatibility_evaluator is None:
            raise SafetyError("compatibility evaluator is not configured")
        report = self.compatibility_evaluator(
            identity,
            image,
            profile,
            same_version_confirmed=same_version_confirmed,
            downgrade_confirmed=downgrade_confirmed,
        )
        self._approval = _issue_approval(identity, image) if report.allowed else None
        return report

    def flash(
        self,
        identity: DeviceIdentity,
        image: FirmwareImage,
        event_sink: Callable[[FlashEvent], None],
    ) -> FlashResult:
        """Run an already-approved attended flash, bound to identity and hashes."""

        with self._serial_lock:
            return self._flash_locked(identity, image, event_sink)

    def _flash_locked(
        self,
        identity: DeviceIdentity,
        image: FirmwareImage,
        event_sink: Callable[[FlashEvent], None],
    ) -> FlashResult:

        connected = self._require_identity()
        profile = self._require_known_profile("firmware flashing")
        protocol = self._require_protocol()
        if identity != connected:
            raise SafetyError("flash identity is not the connected identity")
        if self._approval is None:
            raise SafetyError("run a successful preflight immediately before flashing")

        flasher = (
            FirmwareFlasher(protocol, profile)
            if self._sleep is None
            else FirmwareFlasher(protocol, profile, sleep=self._sleep)
        )
        approval = self._approval
        # Consume the one-shot approval before entering any bootloader state.
        self._approval = None
        records = [
            AuditRecord(
                event="flash_started",
                model=identity.model,
                hardware=identity.hardware,
                software=identity.software,
                firmware_sha256=image.container_sha256,
            )
        ]

        def recorded_sink(event: FlashEvent) -> None:
            records.append(
                AuditRecord(
                    event=event.state.name.lower(),
                    model=identity.model,
                    hardware=identity.hardware,
                    software=identity.software,
                    firmware_sha256=image.container_sha256,
                    packet=event.completed_blocks or None,
                    status="state transition",
                )
            )
            event_sink(event)

        transcript_file = None
        if self.transcript_dir is not None:
            transcript_file = transcript_path(self.transcript_dir, image.container_sha256)
            # Establish transcript availability before changing device state.
            write_audit(transcript_file, records)
        try:
            result = flasher.flash(identity, image, approval, recorded_sink)
            records.append(
                AuditRecord(
                    event="flash_finished",
                    model=identity.model,
                    hardware=identity.hardware,
                    software=image.version,
                    firmware_sha256=image.container_sha256,
                    status=result.state.name.lower(),
                )
            )
        except Exception as error:
            records.append(
                AuditRecord(
                    event="flash_blocked",
                    model=identity.model,
                    hardware=identity.hardware,
                    software=identity.software,
                    firmware_sha256=image.container_sha256,
                    status=f"{type(error).__name__}: {error}"[:256],
                )
            )
            raise
        finally:
            if transcript_file is not None:
                # A post-transfer filesystem problem must never rewrite the
                # physical device result as a flash failure.
                with contextlib.suppress(Exception):
                    write_audit(transcript_file, records)
        if flasher.verified_identity is not None:
            self._identity = flasher.verified_identity
        return result

    def _discover_sole_responder(self, transport: ByteTransport, *, selected_address: int) -> DeviceIdentity:
        protocol = JkProtocol(
            transport,
            selected_address,
            identity_register=self.profiles[0].identity_register,
        )
        try:
            return protocol.read_identity()
        except ProtocolTimeout as exc:
            raise SafetyError(f"no JK responder found at selected address {selected_address}") from exc

    def _select_profile(self, identity: DeviceIdentity) -> DeviceProfile | None:
        canonical = _canonical_wire_model(identity.model)
        hardware_major = _leading_integer(identity.hardware)
        software_major = _leading_integer(identity.software)
        matches = [
            profile
            for profile in self.profiles
            if re.fullmatch(profile.model_pattern, canonical)
            and (profile.hardware_major is None or hardware_major == profile.hardware_major)
            and (profile.firmware_major is None or software_major == profile.firmware_major)
            and identity.max_cells <= profile.max_supported_cells
        ]
        if len(matches) > 1:
            raise SafetyError("device identity selected multiple capability profiles")
        return matches[0] if matches else None

    def _require_protocol(self) -> JkProtocol:
        if self._protocol is None:
            raise SafetyError("connect to exactly one JK device first")
        return self._protocol

    def _require_identity(self) -> DeviceIdentity:
        if self._identity is None:
            raise SafetyError("connect to exactly one JK device first")
        return self._identity

    def _require_known_profile(self, operation: str) -> DeviceProfile:
        if self._profile is None:
            raise SafetyError(
                f"connected identity has no known capability for {operation}; the connection remains identity-only"
            )
        if "flashing" in operation and not self._profile.flash_supported:
            raise SafetyError(f"selected capability supports monitoring but not {operation}")
        return self._profile


def create_ui_services() -> JkApplication:
    """Build the local attended UI services without opening any serial port."""

    from .firmware import inspect_firmware
    from .safety import evaluate_compatibility

    return JkApplication(
        SerialPortProvider(),
        SerialTransportFactory(),
        firmware_inspector=inspect_firmware,
        compatibility_evaluator=evaluate_compatibility,
        transcript_dir=Path("logs"),
    )


def _canonical_wire_model(value: str) -> str:
    # Profile patterns are applied to a normalized spelling, while actual
    # device/firmware equality remains the stricter safety evaluator's job.
    return value.rstrip("\x00").strip().upper().replace("-", "").replace("_", "")


def _leading_integer(value: str) -> int | None:
    match = re.match(r"\s*(\d+)", value)
    return int(match.group(1)) if match else None


def _physical_identity(identity: DeviceIdentity) -> tuple[object, ...]:
    return (
        identity.address,
        identity.model,
        identity.max_cells,
        identity.hardware,
        identity.serial,
    )


# Natural service-layer alias.
Application = JkApplication
