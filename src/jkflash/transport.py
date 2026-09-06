"""PySerial adapters for JK BMS communication."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from .domain import PortConfig, PortInfo


class SerialTransport:
    """Small ``ByteTransport`` wrapper around an open pyserial instance."""

    def __init__(self, serial_port: Any) -> None:
        self._serial = serial_port

    def write(self, data: bytes) -> int:
        return int(self._serial.write(data))

    def read(self, size: int = 1) -> bytes:
        if size < 0:
            raise ValueError("serial read size must not be negative")
        return bytes(self._serial.read(size))

    def close(self) -> None:
        self._serial.close()

    @property
    def is_open(self) -> bool:
        return bool(getattr(self._serial, "is_open", True))

    def get_read_timeout(self) -> float:
        return float(self._serial.timeout)

    def set_read_timeout(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("read timeout must be positive")
        self._serial.timeout = seconds


class SerialPortProvider:
    """Enumerate available serial devices without opening them."""

    def __init__(self, comports: Callable[[], Sequence[Any]] | None = None) -> None:
        self._comports = comports

    def list(self) -> tuple[PortInfo, ...]:
        comports = self._comports
        if comports is None:
            from serial.tools.list_ports import comports as pyserial_comports

            comports = pyserial_comports
        ports = (
            PortInfo(
                device=str(port.device),
                description=str(getattr(port, "description", "") or ""),
                hwid=str(getattr(port, "hwid", "") or ""),
                manufacturer=str(getattr(port, "manufacturer", "") or ""),
                product=str(getattr(port, "product", "") or ""),
                interface=str(getattr(port, "interface", "") or ""),
                location=str(getattr(port, "location", "") or ""),
                vid=getattr(port, "vid", None),
                pid=getattr(port, "pid", None),
                serial_number=str(getattr(port, "serial_number", "") or ""),
            )
            for port in comports()
        )
        return tuple(sorted(ports, key=lambda item: item.device.casefold()))


class SerialTransportFactory:
    """Open a configured 8N1 serial transport using pyserial."""

    def __init__(self, serial_class: Callable[..., Any] | None = None) -> None:
        self._serial_class = serial_class

    def open(self, config: PortConfig) -> SerialTransport:
        if not config.device:
            raise ValueError("serial device must not be empty")
        if not 1 <= config.address <= 247:
            raise ValueError("Modbus address must be in the range 1..247")
        if config.baudrate <= 0:
            raise ValueError("baudrate must be positive")
        if config.read_timeout <= 0 or config.write_timeout <= 0:
            raise ValueError("serial timeouts must be positive")

        serial_class = self._serial_class
        if serial_class is None:
            import serial

            serial_class = serial.Serial
            eight_bits = serial.EIGHTBITS
            parity_none = serial.PARITY_NONE
            one_stop_bit = serial.STOPBITS_ONE
        else:
            # Pyserial's public constants have these wire-equivalent values.
            # Keeping the injected path independent makes it straightforward to
            # verify that no serial port is touched in offline tests.
            eight_bits = 8
            parity_none = "N"
            one_stop_bit = 1

        port = serial_class(
            port=config.device,
            baudrate=config.baudrate,
            bytesize=eight_bits,
            parity=parity_none,
            stopbits=one_stop_bit,
            timeout=config.read_timeout,
            write_timeout=config.write_timeout,
        )
        return SerialTransport(port)


# Concise aliases used by application composition roots.
PySerialPortProvider = SerialPortProvider
PySerialTransportFactory = SerialTransportFactory
