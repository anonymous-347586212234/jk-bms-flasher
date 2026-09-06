from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from textual.widgets import Button, Input, OptionList, Static

from jkflash.domain import (
    DeviceIdentity,
    FirmwareImage,
    FlashEvent,
    FlashResult,
    FlashState,
    PortInfo,
    TelemetrySnapshot,
    ValidationReport,
)
from jkflash.ui import DashboardScreen, FirmwareScreen, JkFlashApp, PortScreen, ProgressScreen


class FakeServices:
    def __init__(self, ports: tuple[PortInfo, ...] = (PortInfo("COM9", "USB RS485"),)) -> None:
        self.ports = ports
        self.identity = DeviceIdentity(42, "JK-GENERIC", 4, "20A", "20.3", "SECRET-SERIAL")
        self.image = FirmwareImage(
            Path("fixtures/update.jkbms"),
            "a" * 64,
            "b" * 64,
            b"decoded",
            b"body",
            b"suffix",
            "JK-GENERIC",
            "20.2",
            0x20001000,
            0x08001001,
        )
        self.connect_calls: list[tuple[PortInfo, int]] = []
        self.identity_reads = 0
        self.flash_calls = 0
        self.dashboard_calls = 0
        self.telemetry_error: str | None = None

    def list_ports(self):
        return self.ports

    def connect(self, port, address):
        self.connect_calls.append((port, address))
        self.identity = replace(self.identity, address=address)
        return self.identity

    def read_identity(self):
        self.identity_reads += 1
        return self.identity

    def read_telemetry(self, max_cells):
        assert max_cells == 4
        return TelemetrySnapshot(
            (3.20, 3.21, 3.22, 3.23),
            12.86,
            -2.5,
            72,
            97,
            25.0,
            24.0,
            24.5,
            0.0,
            0,
            True,
            True,
            72.0,
            100.0,
            12,
            1800,
            0,
        )

    def read_dashboard(self, max_cells):
        self.dashboard_calls += 1
        if self.telemetry_error:
            raise RuntimeError(self.telemetry_error)
        return self.read_identity(), self.read_telemetry(max_cells)

    def capability_status(self):
        return "Generic capability selected; transfer checks remain active."

    def list_firmware(self, directory):
        return (self.image.path,)

    def inspect_firmware(self, path):
        assert path == self.image.path
        return self.image

    def preflight(self, identity, image, *, same_version_confirmed=False, downgrade_confirmed=False):
        assert 1 <= identity.address <= 247
        assert image == self.image
        return ValidationReport()

    def flash(self, identity, image, event_sink):
        self.flash_calls += 1
        event_sink(FlashEvent(FlashState.TRANSFERRING, "Writing block", 1, 2))
        return FlashResult(FlashState.SUCCEEDED, "identity and version verified")


def text(widget: Static) -> str:
    return str(widget.render())


@pytest.mark.asyncio
async def test_keyboard_flow_port_dashboard_firmware_progress_and_return() -> None:
    services = FakeServices()
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(132, 52)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, PortScreen)
        port = app.screen.query_one("#port-list", OptionList)
        assert port.option_count == 1
        app.screen.query_one("#device-address", Input).value = "42"
        await pilot.press("enter")
        await pilot.pause(1.0)
        assert isinstance(app.screen, DashboardScreen)
        assert services.connect_calls == [(PortInfo("COM9", "USB RS485"), 42)]
        # Dashboard test doubles still pair their synthetic identity with each
        # telemetry sample; connection itself must not add another read.
        assert services.identity_reads == services.dashboard_calls
        assert "JK-GENERIC" in text(app.screen.query_one("#identity-table", Static))
        assert "SECRET-SERIAL" not in text(app.screen.query_one("#identity-table", Static))
        assert "12.86 V" in text(app.screen.query_one("#telemetry-table", Static))
        assert "Cell  1: 3.200 V" in text(app.screen.query_one("#cell-table", Static))

        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FirmwareScreen)
        await pilot.press("enter")
        await pilot.pause()
        assert "Preflight passed" in text(app.screen.query_one("#preflight-status", Static))
        assert str(app.screen.query_one("#flash-button", Button).label) == "FLASH FIRMWARE"
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ProgressScreen)
        await pilot.pause(0.2)
        assert "Completed:" in text(app.screen.query_one("#transfer-status", Static))
        assert services.flash_calls == 1
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)


@pytest.mark.asyncio
async def test_port_screen_handles_no_ports_and_validates_full_modbus_range() -> None:
    app = JkFlashApp(FakeServices(()), Path("fixtures"))
    async with app.run_test(size=(76, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, PortScreen)
        assert "No serial ports detected" in text(app.screen.query_one("#port-status", Static))
        app.screen.query_one("#device-address", Input).value = "0"
        app.screen.action_connect()
        assert "Select a serial port" in text(app.screen.query_one("#port-status", Static))

    services = FakeServices()
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(76, 24)) as pilot:
        await pilot.pause()
        app.screen.query_one("#device-address", Input).value = "248"
        await pilot.press("enter")
        assert "range 1 through 247" in text(app.screen.query_one("#port-status", Static))
        app.screen.query_one("#device-address", Input).value = "abc"
        await pilot.press("enter")
        assert "whole number" in text(app.screen.query_one("#port-status", Static))


@pytest.mark.asyncio
async def test_narrow_and_wide_terminal_layouts_keep_keyboard_actions_reachable() -> None:
    for size in ((54, 18), (160, 62)):
        app = JkFlashApp(FakeServices(), Path("fixtures"))
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, PortScreen)
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            assert app.screen.query_one("#dashboard-actions", OptionList).highlighted_option is not None
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, FirmwareScreen)
            assert app.screen.query_one("#firmware-list", OptionList).option_count == 1
