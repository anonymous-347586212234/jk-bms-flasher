"""JK native-frame and Modbus RTU protocol codecs.

Normal PB communication is deliberately treated as two adjacent protocols: a
fixed 300-byte JK native frame followed by an independent eight-byte Modbus
write acknowledgement.  Firmware data packets are implemented in
``jkflash.flasher``; they are not Modbus or JK native frames.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Final

from .domain import DeviceIdentity, ProtocolError, TelemetrySnapshot
from .interfaces import ByteTransport

NATIVE_MAGIC: Final = b"\x55\xaa\xeb\x90"
NATIVE_FRAME_SIZE: Final = 300
MODBUS_ACK_SIZE: Final = 8

IDENTITY_REGISTER: Final = 0x161C
TELEMETRY_REGISTER: Final = 0x1620
ENTER_BOOTLOADER_REGISTER: Final = 0x1626


class ProtocolTimeout(ProtocolError):
    """A transport returned no bytes before its configured timeout."""


def crc16_modbus(data: bytes) -> int:
    """Return CRC-16/MODBUS (poly 0xA001, init 0xFFFF)."""

    crc = 0xFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def append_modbus_crc(data: bytes) -> bytes:
    """Append a low-byte-first Modbus CRC."""

    return data + crc16_modbus(data).to_bytes(2, "little")


def write_register_command(address: int, register: int, value: int = 0) -> bytes:
    """Build the observed function-0x10, one-register write request."""

    if not 1 <= address <= 247:
        raise ValueError("Modbus address must be in the range 1..247")
    if not 0 <= register <= 0xFFFF:
        raise ValueError("register must fit in 16 bits")
    if not 0 <= value <= 0xFFFF:
        raise ValueError("register value must fit in 16 bits")
    payload = bytes((address, 0x10))
    payload += register.to_bytes(2, "big")
    payload += b"\x00\x01\x02"
    payload += value.to_bytes(2, "big")
    return append_modbus_crc(payload)


def validate_modbus_ack(ack: bytes, address: int, register: int) -> None:
    """Validate an exact function-0x10 acknowledgement and its own CRC."""

    if len(ack) != MODBUS_ACK_SIZE:
        raise ProtocolError(f"Modbus acknowledgement must be exactly {MODBUS_ACK_SIZE} bytes")
    expected_crc = crc16_modbus(ack[:-2])
    remote_crc = int.from_bytes(ack[-2:], "little")
    if remote_crc != expected_crc:
        raise ProtocolError("Modbus acknowledgement CRC mismatch")
    expected = bytes((address, 0x10)) + register.to_bytes(2, "big") + b"\x00\x01"
    if ack[:-2] != expected:
        raise ProtocolError("Modbus acknowledgement does not match the request")


@dataclass(frozen=True, slots=True)
class NativeFrame:
    """One validated, fixed-size JK native response frame."""

    code: int
    counter: int
    raw: bytes


class NativeFrameParser:
    """Bounded streaming parser for fragmented 300-byte JK native frames.

    The parser searches for the magic sequence, validates the frame code and
    the native additive checksum, and never retains more than ``max_buffer``
    bytes.  A short tail after a decoded frame is retained so callers can take
    the separate Modbus acknowledgement with :meth:`take_pending`.
    """

    def __init__(
        self,
        *,
        expected_code: int | None = None,
        max_buffer: int = NATIVE_FRAME_SIZE * 2,
    ) -> None:
        if expected_code is not None and not 0 <= expected_code <= 0xFF:
            raise ValueError("expected frame code must fit in one byte")
        if max_buffer < NATIVE_FRAME_SIZE:
            raise ValueError("parser buffer must hold one complete native frame")
        self.expected_code = expected_code
        self.max_buffer = max_buffer
        self._buffer = bytearray()

    @property
    def buffered(self) -> int:
        return len(self._buffer)

    def take_pending(self) -> bytes:
        """Take bytes following the last complete frame (normally the ACK)."""

        pending = bytes(self._buffer)
        self._buffer.clear()
        return pending

    def feed(self, data: bytes) -> tuple[NativeFrame, ...]:
        """Consume a transport fragment and return every validated frame."""

        if not data:
            return ()

        frames: list[NativeFrame] = []
        view = memoryview(data)
        cursor = 0
        while cursor < len(view):
            available = self.max_buffer - len(self._buffer)
            if available <= 0:
                self._discard_unusable_prefix()
                available = self.max_buffer - len(self._buffer)
                if available <= 0:
                    # A full buffer beginning with magic is necessarily a bad
                    # candidate if it was not consumed by _parse_available.
                    del self._buffer[0]
                    available = 1
            amount = min(available, len(view) - cursor)
            self._buffer.extend(view[cursor : cursor + amount])
            cursor += amount
            frames.extend(self._parse_available())
        return tuple(frames)

    def _discard_unusable_prefix(self) -> None:
        marker = self._buffer.find(NATIVE_MAGIC)
        if marker < 0:
            del self._buffer[: max(0, len(self._buffer) - len(NATIVE_MAGIC) + 1)]
        elif marker:
            del self._buffer[:marker]

    def _parse_available(self) -> list[NativeFrame]:
        frames: list[NativeFrame] = []
        while len(self._buffer) >= NATIVE_FRAME_SIZE:
            marker = self._buffer.find(NATIVE_MAGIC)
            if marker < 0:
                # Retain only the longest possible partial magic prefix.
                del self._buffer[: len(self._buffer) - len(NATIVE_MAGIC) + 1]
                break
            if marker:
                del self._buffer[:marker]
                if len(self._buffer) < NATIVE_FRAME_SIZE:
                    break

            raw = bytes(self._buffer[:NATIVE_FRAME_SIZE])
            code = raw[4]
            valid_code = self.expected_code is None or code == self.expected_code
            valid_checksum = raw[-1] == (sum(raw[:-1]) & 0xFF)
            if not (valid_code and valid_checksum):
                # Discard one byte only, then resynchronize.  A later valid
                # magic sequence in the same transport fragment is preserved.
                del self._buffer[0]
                continue

            frames.append(NativeFrame(code=code, counter=raw[5], raw=raw))
            del self._buffer[:NATIVE_FRAME_SIZE]
        return frames


def parse_identity_frame(frame: bytes, address: int) -> DeviceIdentity:
    """Decode the common JK 300-byte device-info layout.

    The serial number begins at native-frame offset ``0x56``.  It is not the
    repeated device-name field at offset ``0x2E``.
    """

    _validate_native_frame(frame, expected_code=0x03)
    model = _ascii_field(frame, 0x06, 15, "model")
    max_cells = frame[0x15]
    hardware = _ascii_field(frame, 0x16, 8, "hardware")
    software = _ascii_field(frame, 0x1E, 8, "software")
    serial = _ascii_field(frame, 0x56, 16, "serial")
    if not 1 <= max_cells <= 32:
        raise ProtocolError("device maxCells is outside JK02 bounds")
    return DeviceIdentity(
        address=address,
        model=model,
        max_cells=max_cells,
        hardware=hardware,
        software=software,
        serial=serial,
    )


def parse_jk02_32s_telemetry(frame: bytes, max_cells: int) -> TelemetrySnapshot:
    """Decode named/scaled fields from the known JK02_32S runtime layout."""

    _validate_native_frame(frame, expected_code=0x02)
    if not 1 <= max_cells <= 32:
        raise ProtocolError("JK02_32S cell count must be in the range 1..32")

    def u16(offset: int) -> int:
        return int.from_bytes(frame[offset : offset + 2], "little")

    def i16(offset: int) -> int:
        return int.from_bytes(frame[offset : offset + 2], "little", signed=True)

    def u32(offset: int) -> int:
        return int.from_bytes(frame[offset : offset + 4], "little")

    def i32(offset: int) -> int:
        return int.from_bytes(frame[offset : offset + 4], "little", signed=True)

    enabled_mask = u32(0x46)
    enabled_indices = tuple(index for index in range(32) if enabled_mask & (1 << index))
    if not enabled_indices or any(index >= max_cells for index in enabled_indices):
        raise ProtocolError("enabled-cell mask conflicts with device maxCells")
    cells = tuple(u16(6 + index * 2) * 0.001 for index in enabled_indices)
    return TelemetrySnapshot(
        cell_voltages=cells,
        pack_voltage=i32(150) * 0.001,
        pack_current=i32(158) * 0.001,
        state_of_charge=frame[173],
        state_of_health=frame[190],
        mos_temperature=i16(144) * 0.1,
        temperature_1=i16(162) * 0.1,
        temperature_2=i16(164) * 0.1,
        balance_current=i16(170) * 0.001,
        balance_state=frame[172],
        charge_mos=bool(frame[198]),
        discharge_mos=bool(frame[199]),
        remaining_capacity=u32(174) * 0.001,
        full_capacity=u32(178) * 0.001,
        cycles=u32(182),
        runtime_seconds=u32(194),
        fault_mask=u32(166),
    )


def parse_jk02_24s_telemetry(frame: bytes, max_cells: int) -> TelemetrySnapshot:
    """Decode the distinct JK02 24-slot metadata layout."""

    _validate_native_frame(frame, expected_code=0x02)
    if not 1 <= max_cells <= 24:
        raise ProtocolError("JK02_24S cell count must be in the range 1..24")

    def integer(offset: int, size: int, *, signed: bool = False) -> int:
        return int.from_bytes(frame[offset : offset + size], "little", signed=signed)

    enabled_mask = integer(0x36, 4)
    enabled_indices = tuple(index for index in range(24) if enabled_mask & (1 << index))
    if not enabled_indices or any(index >= max_cells for index in enabled_indices):
        raise ProtocolError("enabled-cell mask conflicts with device maxCells")
    cells = tuple(integer(6 + index * 2, 2) * 0.001 for index in enabled_indices)
    return TelemetrySnapshot(
        cell_voltages=cells,
        pack_voltage=integer(118, 4, signed=True) * 0.001,
        pack_current=integer(126, 4, signed=True) * 0.001,
        state_of_charge=frame[141],
        state_of_health=frame[158],
        mos_temperature=integer(134, 2, signed=True) * 0.1,
        temperature_1=integer(130, 2, signed=True) * 0.1,
        temperature_2=integer(132, 2, signed=True) * 0.1,
        balance_current=integer(138, 2, signed=True) * 0.001,
        balance_state=frame[140],
        charge_mos=bool(frame[166]),
        discharge_mos=bool(frame[167]),
        remaining_capacity=integer(142, 4) * 0.001,
        full_capacity=integer(146, 4) * 0.001,
        cycles=integer(150, 4),
        runtime_seconds=integer(162, 4),
        fault_mask=integer(136, 2),
    )


class JkProtocol:
    """Synchronous JK PB application-protocol endpoint."""

    def __init__(
        self,
        transport: ByteTransport,
        address: int,
        *,
        telemetry_layout: str = "JK02_32S",
        identity_register: int = IDENTITY_REGISTER,
        telemetry_register: int = TELEMETRY_REGISTER,
        boot_register: int = ENTER_BOOTLOADER_REGISTER,
    ) -> None:
        if not 1 <= address <= 247:
            raise ValueError("Modbus address must be in the range 1..247")
        self.transport = transport
        self.address = address
        self.telemetry_layout = telemetry_layout
        self.identity_register = identity_register
        self.telemetry_register = telemetry_register
        self.boot_register = boot_register

    def read_identity(self) -> DeviceIdentity:
        frame = self._query(self.identity_register, expected_code=0x03)
        return parse_identity_frame(frame, self.address)

    def read_telemetry(self, max_cells: int) -> TelemetrySnapshot:
        if self.telemetry_layout not in {"JK02_24S", "JK02_32S"}:
            raise ProtocolError(f"telemetry layout {self.telemetry_layout!r} is not implemented")
        frame = self._query(self.telemetry_register, expected_code=0x02)
        if self.telemetry_layout == "JK02_24S":
            return parse_jk02_24s_telemetry(frame, max_cells)
        return parse_jk02_32s_telemetry(frame, max_cells)

    def send_enter_bootloader(self) -> None:
        """Transmit only the observed boot-entry command.

        The response is a bootloader banner, not a Modbus acknowledgement.
        """

        self._write_all(write_register_command(self.address, self.boot_register))

    def read_boot_ready(
        self,
        expected_banner: bytes,
        *,
        limit: int = 512,
        deadline: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> bytes:
        """Require a recognizable expected banner ending with sync byte 0x15."""

        if limit <= 0:
            raise ValueError("boot banner limit must be positive")
        clock = now or time.monotonic
        timeout_ceiling = self.transport.get_read_timeout() if deadline is not None else 0.0
        received = bytearray()
        while len(received) < limit:
            self._cap_read_timeout(deadline, clock, timeout_ceiling)
            # The bootloader uses 0x15 as an event that starts transfer. Read a
            # byte at a time so pySerial returns on that event immediately;
            # requesting a large fixed count can wait while later sync bytes
            # accumulate and make an OS read boundary look like protocol data.
            chunk = self.transport.read(1)
            if not chunk:
                raise ProtocolTimeout("timed out waiting for the bootloader banner")
            received.extend(chunk)
            if chunk == b"\x15":
                banner = bytes(received[:-1])
                if not _banner_matches(banner, expected_banner):
                    raise ProtocolError("bootloader banner did not match the selected capability")
                return bytes(received)
        raise ProtocolError("bootloader banner exceeded the bounded receive limit")

    @contextmanager
    def transfer_read_timeout(self, seconds: float) -> Iterator[None]:
        """Temporarily widen the transport read timeout for the transfer phase.

        The vendor sets no ACK timeout at all for this phase (a slow bootloader
        erase must not self-abort the transfer); this raises the bound to
        ``seconds`` instead of removing it, and always restores the prior value.
        """

        previous = self.transport.get_read_timeout()
        self.transport.set_read_timeout(seconds)
        try:
            yield
        finally:
            self.transport.set_read_timeout(previous)

    def read_ack_byte(self) -> None:
        ack = self.transport.read(1)
        if not ack:
            raise ProtocolTimeout("timed out waiting for firmware block acknowledgement")
        if ack != b"\x06":
            raise ProtocolError(f"unexpected firmware block response 0x{ack[0]:02X}")

    def read_exact(
        self,
        size: int,
        *,
        deadline: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> bytes:
        """Read exactly ``size`` bytes or fail without retrying a command."""

        if size < 0:
            raise ValueError("read size must not be negative")
        clock = now or time.monotonic
        timeout_ceiling = self.transport.get_read_timeout() if deadline is not None else 0.0
        received = bytearray()
        while len(received) < size:
            self._cap_read_timeout(deadline, clock, timeout_ceiling)
            chunk = self.transport.read(size - len(received))
            if not chunk:
                raise ProtocolTimeout(f"timed out after {len(received)} of {size} bytes")
            if len(chunk) > size - len(received):
                raise ProtocolError("transport returned more bytes than requested")
            received.extend(chunk)
        return bytes(received)

    def _cap_read_timeout(
        self,
        deadline: float | None,
        now: Callable[[], float],
        timeout_ceiling: float,
    ) -> None:
        if deadline is None:
            return
        remaining = deadline - now()
        if remaining <= 0:
            raise ProtocolTimeout("firmware transfer exceeded its overall deadline without completing")
        self.transport.set_read_timeout(min(timeout_ceiling, remaining))

    def write_packet(self, packet: bytes) -> None:
        self._write_all(packet)

    def _query(self, register: int, *, expected_code: int) -> bytes:
        self._write_all(write_register_command(self.address, register))
        parser = NativeFrameParser(expected_code=expected_code)
        decoded: NativeFrame | None = None
        while decoded is None:
            chunk = self.transport.read(NATIVE_FRAME_SIZE + MODBUS_ACK_SIZE)
            if not chunk:
                raise ProtocolTimeout("timed out waiting for a JK native response")
            frames = parser.feed(chunk)
            if len(frames) > 1:
                raise ProtocolError("received multiple native frames for one request")
            if frames:
                decoded = frames[0]

        acknowledgement = bytearray(parser.take_pending())
        if len(acknowledgement) > MODBUS_ACK_SIZE:
            raise ProtocolError("unexpected bytes followed the Modbus acknowledgement")
        while len(acknowledgement) < MODBUS_ACK_SIZE:
            chunk = self.transport.read(MODBUS_ACK_SIZE - len(acknowledgement))
            if not chunk:
                raise ProtocolTimeout("timed out waiting for the Modbus acknowledgement")
            if len(chunk) > MODBUS_ACK_SIZE - len(acknowledgement):
                raise ProtocolError("transport returned more acknowledgement bytes than requested")
            acknowledgement.extend(chunk)
        validate_modbus_ack(bytes(acknowledgement), self.address, register)
        return decoded.raw

    def _write_all(self, data: bytes) -> None:
        written = self.transport.write(data)
        if written != len(data):
            raise ProtocolError(f"short serial write ({written} of {len(data)} bytes)")


def _validate_native_frame(frame: bytes, *, expected_code: int) -> None:
    if len(frame) != NATIVE_FRAME_SIZE:
        raise ProtocolError("JK native frame must be exactly 300 bytes")
    if frame[:4] != NATIVE_MAGIC:
        raise ProtocolError("JK native frame magic mismatch")
    if frame[4] != expected_code:
        raise ProtocolError(f"unexpected JK native frame code 0x{frame[4]:02X}; expected 0x{expected_code:02X}")
    if frame[-1] != (sum(frame[:-1]) & 0xFF):
        raise ProtocolError("JK native frame additive checksum mismatch")


def _ascii_field(frame: bytes, offset: int, size: int, name: str) -> str:
    raw = frame[offset : offset + size].split(b"\x00", 1)[0].rstrip(b" ")
    if not raw:
        raise ProtocolError(f"device {name} field is empty")
    if any(value < 0x20 or value > 0x7E for value in raw):
        raise ProtocolError(f"device {name} field is not printable ASCII")
    return raw.decode("ascii")


def _banner_matches(received: bytes, expected: bytes) -> bool:
    if not expected:
        return False
    received_upper = received.upper()
    expected_upper = expected.upper()
    if expected_upper in received_upper:
        return True

    # Profiles name capabilities concisely (for example ``... V2.0.4``),
    # while the observed banner spells that as ``(Version 2.0.4)``.
    version = re.search(rb"V(?:ERSION)?\s*([0-9]+(?:\.[0-9]+)+)", expected_upper)
    if version is None or version.group(1) not in received_upper:
        return False
    required_words = [word for word in (b"STM32F103X", b"BOOTLOADER") if word in expected_upper]
    return all(word in received_upper for word in required_words)


# Natural compatibility aliases for callers that prefer command-specific names.
build_write_register = write_register_command
parse_telemetry_frame = parse_jk02_32s_telemetry
