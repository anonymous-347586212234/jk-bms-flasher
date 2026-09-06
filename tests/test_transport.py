from __future__ import annotations

from types import SimpleNamespace

import pytest

from jkflash.domain import PortConfig
from jkflash.transport import SerialPortProvider, SerialTransport, SerialTransportFactory


class FakeSerial:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.reads = [b"ab"]
        self.writes: list[bytes] = []
        self.closed = False
        self.is_open = True

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def read(self, size: int) -> bytes:
        return self.reads.pop(0)[:size] if self.reads else b""

    def close(self) -> None:
        self.closed = True
        self.is_open = False


def test_port_enumeration_maps_fields_and_sorts() -> None:
    provider = SerialPortProvider(
        lambda: [
            SimpleNamespace(device="COM10", description=None, hwid="B"),
            SimpleNamespace(
                device="com2",
                description="CH340",
                hwid=None,
                manufacturer="WCH",
                product="USB serial",
                interface="RS485",
                location="1-2",
                vid=0x1A86,
                pid=0x7523,
                serial_number="PRIVATE-ADAPTER-ID",
            ),
        ]
    )
    ports = provider.list()
    assert [port.device for port in ports] == ["COM10", "com2"]
    assert ports[0].description == ""
    assert ports[1].description == "CH340"
    assert ports[1].hwid == ""
    assert ports[1].manufacturer == "WCH"
    assert (ports[1].vid, ports[1].pid) == (0x1A86, 0x7523)
    assert ports[1].serial_number == "PRIVATE-ADAPTER-ID"


def test_factory_opens_115200_8n1_with_configured_timeouts() -> None:
    opened: list[FakeSerial] = []

    def factory(**kwargs: object) -> FakeSerial:
        serial = FakeSerial(**kwargs)
        opened.append(serial)
        return serial

    transport = SerialTransportFactory(factory).open(PortConfig("COM5", 5, read_timeout=1.25, write_timeout=3.5))
    assert opened[0].kwargs == {
        "port": "COM5",
        "baudrate": 115_200,
        "bytesize": 8,
        "parity": "N",
        "stopbits": 1,
        "timeout": 1.25,
        "write_timeout": 3.5,
    }
    assert transport.write(b"xyz") == 3
    assert transport.read(2) == b"ab"
    assert transport.is_open
    transport.close()
    assert opened[0].closed
    assert not transport.is_open


@pytest.mark.parametrize(
    "config",
    [
        PortConfig("", 1),
        PortConfig("COM1", 0),
        PortConfig("COM1", 1, baudrate=0),
        PortConfig("COM1", 1, read_timeout=0),
        PortConfig("COM1", 1, write_timeout=0),
    ],
)
def test_factory_rejects_invalid_configuration(config: PortConfig) -> None:
    with pytest.raises(ValueError):
        SerialTransportFactory(FakeSerial).open(config)


def test_transport_rejects_negative_read_size() -> None:
    with pytest.raises(ValueError):
        SerialTransport(FakeSerial()).read(-1)
