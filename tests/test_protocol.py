from __future__ import annotations

from collections import deque

import pytest

from jkflash.domain import ProtocolError
from jkflash.protocol import (
    ENTER_BOOTLOADER_REGISTER,
    IDENTITY_REGISTER,
    TELEMETRY_REGISTER,
    JkProtocol,
    NativeFrameParser,
    ProtocolTimeout,
    append_modbus_crc,
    crc16_modbus,
    parse_identity_frame,
    parse_jk02_24s_telemetry,
    parse_jk02_32s_telemetry,
    validate_modbus_ack,
    write_register_command,
)


def native_frame(code: int) -> bytearray:
    frame = bytearray(300)
    frame[:6] = bytes.fromhex("55 AA EB 90") + bytes((code, 0x42))
    frame[-1] = sum(frame[:-1]) & 0xFF
    return frame


def finish(frame: bytearray) -> bytes:
    frame[-1] = sum(frame[:-1]) & 0xFF
    return bytes(frame)


def populate_identity(
    frame: bytearray,
    *,
    model: bytes = b"JK-PB1A16S20P",
    max_cells: int = 16,
    hardware: bytes = b"19A",
    software: bytes = b"19.31",
    serial: bytes = b"SERIAL1234",
) -> None:
    """Populate the current 15/1/8/8/16 byte identity layout."""

    frame[0x06:0x15] = model.ljust(15, b"\0")[:15]
    frame[0x15] = max_cells
    frame[0x16:0x1E] = hardware.ljust(8, b"\0")[:8]
    frame[0x1E:0x26] = software.ljust(8, b"\0")[:8]
    frame[0x56:0x66] = serial.ljust(16, b"\0")[:16]


def modbus_ack(address: int, register: int) -> bytes:
    return append_modbus_crc(bytes((address, 0x10)) + register.to_bytes(2, "big") + b"\x00\x01")


class FakeTransport:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = deque(chunks)
        self.writes: list[bytes] = []
        self.closed = False
        self.timeout = 2.0

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def read(self, size: int = 1) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.popleft()
        if len(chunk) > size:
            self.chunks.appendleft(chunk[size:])
            return chunk[:size]
        return chunk

    def close(self) -> None:
        self.closed = True

    def get_read_timeout(self) -> float:
        return self.timeout

    def set_read_timeout(self, seconds: float) -> None:
        self.timeout = seconds


@pytest.mark.parametrize(
    ("register", "expected"),
    [
        (TELEMETRY_REGISTER, "05 10 16 20 00 01 02 00 00 E4 31"),
        (IDENTITY_REGISTER, "05 10 16 1C 00 01 02 00 00 E1 0D"),
        (ENTER_BOOTLOADER_REGISTER, "05 10 16 26 00 01 02 00 00 E4 57"),
    ],
)
def test_observed_modbus_commands_are_exact(register: int, expected: str) -> None:
    assert write_register_command(5, register) == bytes.fromhex(expected)


def test_crc16_modbus_known_vector_and_validation() -> None:
    payload = bytes.fromhex("05 10 16 20 00 01 02 00 00")
    assert crc16_modbus(payload) == 0x31E4
    ack = bytes.fromhex("05 10 16 20 00 01 05 CF")
    validate_modbus_ack(ack, 5, TELEMETRY_REGISTER)
    with pytest.raises(ProtocolError, match="CRC"):
        validate_modbus_ack(ack[:-1] + b"\x00", 5, TELEMETRY_REGISTER)
    with pytest.raises(ProtocolError, match="match"):
        validate_modbus_ack(modbus_ack(5, IDENTITY_REGISTER), 5, TELEMETRY_REGISTER)


@pytest.mark.parametrize("address", [0, 248])
def test_modbus_request_rejects_invalid_addresses(address: int) -> None:
    with pytest.raises(ValueError, match="address"):
        write_register_command(address, IDENTITY_REGISTER)


def test_modbus_request_supports_high_app_configured_address() -> None:
    command = write_register_command(247, IDENTITY_REGISTER)
    assert command[0] == 247
    assert command == append_modbus_crc(b"\xf7\x10\x16\x1c\x00\x01\x02\x00\x00")


def test_native_parser_handles_fragmentation_noise_and_separate_ack_tail() -> None:
    raw = finish(native_frame(3))
    parser = NativeFrameParser(expected_code=3)
    assert parser.feed(b"noise" + raw[:17]) == ()
    assert parser.feed(raw[17:217]) == ()
    frames = parser.feed(raw[217:] + b"12345678")
    assert len(frames) == 1
    assert frames[0].raw == raw
    assert frames[0].code == 3
    assert parser.take_pending() == b"12345678"


def test_native_parser_resynchronizes_after_bad_checksum_and_is_bounded() -> None:
    bad = native_frame(3)
    bad[-1] ^= 0x80
    good = finish(native_frame(3))
    parser = NativeFrameParser(expected_code=3)
    frames = parser.feed(bytes(bad) + good)
    assert tuple(frame.raw for frame in frames) == (good,)

    parser.feed(b"x" * 10_000)
    assert parser.buffered <= parser.max_buffer


def test_native_parser_rejects_wrong_code_and_invalid_configuration() -> None:
    parser = NativeFrameParser(expected_code=2)
    assert parser.feed(finish(native_frame(3))) == ()
    with pytest.raises(ValueError):
        NativeFrameParser(expected_code=256)
    with pytest.raises(ValueError):
        NativeFrameParser(max_buffer=299)


def test_identity_schema_uses_serial_at_offset_0x56() -> None:
    frame = native_frame(3)
    populate_identity(frame, model=b"JK_PB2A16S20P", serial=b"SERIAL1234")
    frame[0x2E : 0x2E + 16] = b"NOT-THE-SERIAL!".ljust(16, b"\0")
    identity = parse_identity_frame(finish(frame), address=7)
    assert identity.address == 7
    assert identity.model == "JK_PB2A16S20P"
    assert identity.max_cells == 16
    assert identity.hardware == "19A"
    assert identity.software == "19.31"
    assert identity.serial == "SERIAL1234"


def test_identity_rejects_invalid_max_cell_count() -> None:
    frame = native_frame(3)
    populate_identity(frame, max_cells=0)
    with pytest.raises(ProtocolError, match="maxCells"):
        parse_identity_frame(finish(frame), 1)


def test_jk02_32s_telemetry_offsets_and_scales() -> None:
    frame = native_frame(2)
    for index in range(16):
        frame[6 + index * 2 : 8 + index * 2] = (3290 + index).to_bytes(2, "little")
    frame[0x46:0x4A] = ((1 << 16) - 1).to_bytes(4, "little")
    frame[144:146] = (-25).to_bytes(2, "little", signed=True)
    frame[150:154] = (52_345).to_bytes(4, "little")
    frame[158:162] = (-12_345).to_bytes(4, "little", signed=True)
    frame[162:164] = (253).to_bytes(2, "little", signed=True)
    frame[164:166] = (-52).to_bytes(2, "little", signed=True)
    frame[166:170] = (0x81234567).to_bytes(4, "little")
    frame[170:172] = (-321).to_bytes(2, "little", signed=True)
    frame[172] = 2
    frame[173] = 87
    frame[174:178] = (123_456).to_bytes(4, "little")
    frame[178:182] = (200_000).to_bytes(4, "little")
    frame[182:186] = (4321).to_bytes(4, "little")
    frame[190] = 96
    frame[194:198] = (987_654).to_bytes(4, "little")
    frame[198:200] = b"\x01\x00"

    snapshot = parse_jk02_32s_telemetry(finish(frame), 16)
    assert snapshot.cell_voltages[:2] == pytest.approx((3.290, 3.291))
    assert len(snapshot.cell_voltages) == 16
    assert snapshot.pack_voltage == pytest.approx(52.345)
    assert snapshot.pack_current == pytest.approx(-12.345)
    assert snapshot.mos_temperature == pytest.approx(-2.5)
    assert snapshot.temperature_1 == pytest.approx(25.3)
    assert snapshot.temperature_2 == pytest.approx(-5.2)
    assert snapshot.balance_current == pytest.approx(-0.321)
    assert snapshot.balance_state == 2
    assert snapshot.state_of_charge == 87
    assert snapshot.state_of_health == 96
    assert snapshot.remaining_capacity == pytest.approx(123.456)
    assert snapshot.full_capacity == pytest.approx(200.0)
    assert snapshot.cycles == 4321
    assert snapshot.runtime_seconds == 987_654
    assert snapshot.fault_mask == 0x81234567
    assert snapshot.charge_mos is True
    assert snapshot.discharge_mos is False


def test_jk02_24s_uses_its_distinct_offsets_and_enabled_mask() -> None:
    frame = native_frame(2)
    frame[6:10] = (3300).to_bytes(2, "little") + (3310).to_bytes(2, "little")
    frame[0x36:0x3A] = (0b11).to_bytes(4, "little")
    frame[118:122] = (6610).to_bytes(4, "little", signed=True)
    frame[126:130] = (-1500).to_bytes(4, "little", signed=True)
    frame[130:132] = (250).to_bytes(2, "little", signed=True)
    frame[132:134] = (260).to_bytes(2, "little", signed=True)
    frame[134:136] = (270).to_bytes(2, "little", signed=True)
    frame[136:138] = (0x1234).to_bytes(2, "little")
    frame[138:140] = (-200).to_bytes(2, "little", signed=True)
    frame[140:142] = bytes((2, 75))
    frame[142:146] = (50_000).to_bytes(4, "little")
    frame[146:150] = (100_000).to_bytes(4, "little")
    frame[150:154] = (42).to_bytes(4, "little")
    frame[158] = 98
    frame[162:166] = (3600).to_bytes(4, "little")
    frame[166:168] = b"\x01\x00"

    snapshot = parse_jk02_24s_telemetry(finish(frame), 24)
    assert snapshot.cell_voltages == pytest.approx((3.3, 3.31))
    assert snapshot.pack_voltage == pytest.approx(6.61)
    assert snapshot.pack_current == pytest.approx(-1.5)
    assert snapshot.mos_temperature == pytest.approx(27.0)
    assert snapshot.balance_current == pytest.approx(-0.2)
    assert snapshot.fault_mask == 0x1234
    assert snapshot.state_of_charge == 75
    assert snapshot.state_of_health == 98
    assert snapshot.charge_mos and not snapshot.discharge_mos


def test_protocol_query_accepts_fragmented_frame_and_exact_separate_ack() -> None:
    frame = native_frame(3)
    populate_identity(frame, model=b"JK-PB1A8S10P", max_cells=8, software=b"19.26", serial=b"ABC123")
    raw = finish(frame)
    response = raw + modbus_ack(5, IDENTITY_REGISTER)
    transport = FakeTransport([response[:51], response[51:]])
    protocol = JkProtocol(transport, 5)
    identity = protocol.read_identity()
    assert identity.model == "JK-PB1A8S10P"
    assert transport.writes == [write_register_command(5, IDENTITY_REGISTER)]


def test_protocol_rejects_bad_separate_ack_and_short_write() -> None:
    raw = finish(native_frame(3))
    transport = FakeTransport([raw + b"\x00" * 8])
    with pytest.raises(ProtocolError, match="CRC"):
        JkProtocol(transport, 5).read_identity()

    class ShortWrite(FakeTransport):
        def write(self, data: bytes) -> int:
            return len(data) - 1

    with pytest.raises(ProtocolError, match="short serial write"):
        JkProtocol(ShortWrite([]), 5).send_enter_bootloader()


def test_protocol_timeouts_and_boot_banner_validation() -> None:
    protocol = JkProtocol(FakeTransport([]), 5)
    with pytest.raises(ProtocolTimeout):
        protocol.read_identity()

    valid = JkProtocol(
        FakeTransport([b"->JKBMS STM32F103x  bootloader (Version 2.0.4)\r\n\x15"]),
        5,
    )
    assert valid.read_boot_ready(b"STM32F103x BOOTLOADER V2.0.4").endswith(b"\x15")

    invalid = JkProtocol(FakeTransport([b"wrong bootloader\x15"]), 5)
    with pytest.raises(ProtocolError, match="banner"):
        invalid.read_boot_ready(b"STM32F103x BOOTLOADER V2.0.4")


def test_protocol_codec_validation_edges() -> None:
    with pytest.raises(ValueError, match="register"):
        write_register_command(1, -1)
    with pytest.raises(ValueError, match="register value"):
        write_register_command(1, 1, 0x1_0000)
    with pytest.raises(ProtocolError, match="exactly"):
        validate_modbus_ack(b"short", 1, 1)
    assert NativeFrameParser().feed(b"") == ()

    with pytest.raises(ValueError, match="address"):
        JkProtocol(FakeTransport([]), 0)
    unsupported = JkProtocol(FakeTransport([]), 1, telemetry_layout="UNKNOWN")
    with pytest.raises(ProtocolError, match="not implemented"):
        unsupported.read_telemetry(16)


@pytest.mark.parametrize("cells", [0, 33])
def test_telemetry_rejects_cell_count_outside_layout(cells: int) -> None:
    with pytest.raises(ProtocolError, match="cell count"):
        parse_jk02_32s_telemetry(finish(native_frame(2)), cells)


def test_identity_and_native_frame_validation_edges() -> None:
    with pytest.raises(ProtocolError, match="exactly"):
        parse_identity_frame(b"short", 1)

    wrong_magic = native_frame(3)
    wrong_magic[:4] = b"nope"
    with pytest.raises(ProtocolError, match="magic"):
        parse_identity_frame(finish(wrong_magic), 1)

    with pytest.raises(ProtocolError, match="code"):
        parse_identity_frame(finish(native_frame(2)), 1)

    checksum = native_frame(3)
    checksum[-1] ^= 1
    with pytest.raises(ProtocolError, match="checksum"):
        parse_identity_frame(bytes(checksum), 1)

    empty = native_frame(3)
    populate_identity(empty, model=b"", software=b"19.1", serial=b"SN1")
    with pytest.raises(ProtocolError, match="model field is empty"):
        parse_identity_frame(finish(empty), 1)

    invalid_ascii = native_frame(3)
    populate_identity(invalid_ascii, software=b"19.1", serial=b"SN1")
    invalid_ascii[0x16:0x1E] = b"\x0119A".ljust(8, b"\0")
    with pytest.raises(ProtocolError, match="printable"):
        parse_identity_frame(finish(invalid_ascii), 1)

    too_many = native_frame(3)
    populate_identity(too_many, max_cells=33, software=b"19.1", serial=b"SN1")
    with pytest.raises(ProtocolError, match="outside"):
        parse_identity_frame(finish(too_many), 1)


def test_boot_and_raw_io_strict_edges() -> None:
    protocol = JkProtocol(FakeTransport([]), 1)
    with pytest.raises(ValueError, match="limit"):
        protocol.read_boot_ready(b"x", limit=0)
    with pytest.raises(ProtocolTimeout, match="banner"):
        protocol.read_boot_ready(b"x")
    with pytest.raises(ValueError, match="size"):
        protocol.read_exact(-1)
    with pytest.raises(ProtocolTimeout):
        protocol.read_exact(1)
    with pytest.raises(ProtocolTimeout, match="acknowledgement"):
        protocol.read_ack_byte()

    coalesced = FakeTransport([b"banner\x15extra"])
    extra_after_sync = JkProtocol(coalesced, 1)
    assert extra_after_sync.read_boot_ready(b"banner") == b"banner\x15"
    with pytest.raises(ProtocolError, match="unexpected"):
        extra_after_sync.read_ack_byte()
    too_long = JkProtocol(FakeTransport([b"12345678"]), 1)
    with pytest.raises(ProtocolError, match="exceeded"):
        too_long.read_boot_ready(b"banner", limit=8)

    success_transport = FakeTransport([b"\x06", b"a", b"bc"])
    success = JkProtocol(success_transport, 1)
    success.read_ack_byte()
    assert success.read_exact(3) == b"abc"
    success.write_packet(b"packet")
    assert success_transport.writes == [b"packet"]

    unexpected = JkProtocol(FakeTransport([b"\x15"]), 1)
    with pytest.raises(ProtocolError, match="unexpected"):
        unexpected.read_ack_byte()

    exact_banner = JkProtocol(FakeTransport([b"exact\x15"]), 1)
    assert exact_banner.read_boot_ready(b"exact") == b"exact\x15"
    empty_expected = JkProtocol(FakeTransport([b"exact\x15"]), 1)
    with pytest.raises(ProtocolError, match="banner"):
        empty_expected.read_boot_ready(b"")


def test_fragmented_reads_consume_one_absolute_deadline() -> None:
    class TimedTransport(FakeTransport):
        def __init__(self, chunks: list[bytes]) -> None:
            super().__init__(chunks)
            self.timeout = 2.0
            self.timeout_updates: list[float] = []

        def get_read_timeout(self) -> float:
            return self.timeout

        def set_read_timeout(self, seconds: float) -> None:
            self.timeout = seconds
            self.timeout_updates.append(seconds)

    transport = TimedTransport([b"a", b"b", b"c"])
    moments = iter((0.0, 0.5, 1.1))
    protocol = JkProtocol(transport, 1)
    with pytest.raises(ProtocolTimeout, match="overall deadline"):
        protocol.read_exact(3, deadline=1.0, now=lambda: next(moments))
    assert transport.timeout_updates == [1.0, 0.5]


def test_query_rejects_multiple_frames_extra_tail_and_missing_ack() -> None:
    class NoLimitTransport(FakeTransport):
        def read(self, size: int = 1) -> bytes:
            return self.chunks.popleft() if self.chunks else b""

    raw = finish(native_frame(3))
    multiple = JkProtocol(NoLimitTransport([raw + raw]), 5)
    with pytest.raises(ProtocolError, match="multiple"):
        multiple.read_identity()

    extra = JkProtocol(NoLimitTransport([raw + b"x" * 9]), 5)
    with pytest.raises(ProtocolError, match="unexpected bytes"):
        extra.read_identity()

    missing = JkProtocol(FakeTransport([raw]), 5)
    with pytest.raises(ProtocolTimeout, match="Modbus"):
        missing.read_identity()

    fragmented_ack = JkProtocol(
        FakeTransport([raw, modbus_ack(5, IDENTITY_REGISTER)[:3], modbus_ack(5, IDENTITY_REGISTER)[3:]]),
        5,
    )
    with pytest.raises(ProtocolError, match="model field"):
        # The exchange succeeds, then the intentionally empty identity fails.
        fragmented_ack.read_identity()


def test_transport_returning_more_than_requested_is_rejected() -> None:
    class OverRead(FakeTransport):
        def read(self, size: int = 1) -> bytes:
            return b"x" * (size + 1)

    protocol = JkProtocol(OverRead([]), 1)
    with pytest.raises(ProtocolError, match="more bytes"):
        protocol.read_exact(2)
