from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from tests.test_ui import FakeServices, text
from textual.widgets import Button, Static

from jkflash.domain import (
    DeviceIdentity,
    FlashResult,
    FlashState,
    PortInfo,
    Severity,
    TelemetrySnapshot,
    ValidationIssue,
    ValidationReport,
)
from jkflash.ui import (
    DashboardScreen,
    FirmwareScreen,
    JkFlashApp,
    ProgressScreen,
    UnconfiguredUiServices,
    default_ui_services,
    format_identity,
    format_port,
    format_telemetry,
)


def test_dashboard_formatters_mask_identity_and_preserve_units() -> None:
    identity = DeviceIdentity(7, "JK-ANY", 2, "", "1.2", "PRIVATE-1234")
    assert "PRIVATE-1234" not in format_identity(identity)
    assert "Hardware    unavailable" in format_identity(identity)
    snapshot = TelemetrySnapshot(
        (3.1, 3.3), 6.4, -2.5, 50, 98, 25.0, 24.0, 23.0, 0.0, 1, True, False, 50.0, 100.0, 3, 30, 0x10
    )
    rendered = format_telemetry(snapshot)
    assert "6.40 V" in rendered and "-2.50 A" in rendered and "-16.0 W" in rendered
    assert format_telemetry(None) == "Telemetry unavailable"


def test_port_formatter_shows_cross_platform_metadata_and_masks_serial() -> None:
    port = PortInfo(
        "/dev/ttyUSB0",
        "USB-RS485",
        "ignored",
        "WCH",
        "CH343",
        "Interface 0",
        "1-2.3",
        0x1A86,
        0x55D3,
        "PRIVATE-ADAPTER-ID",
    )
    rendered = format_port(port)
    assert "/dev/ttyUSB0" in rendered
    assert "WCH" in rendered and "CH343" in rendered
    assert "USB 1A86:55D3" in rendered and "at 1-2.3" in rendered
    assert "PRIVATE-ADAPTER-ID" not in rendered
    assert format_port(port, compact=True) == "/dev/ttyUSB0  USB-RS485"


def test_unconfigured_service_stays_safe() -> None:
    service = UnconfiguredUiServices()
    with pytest.raises(RuntimeError, match="not configured"):
        service.list_ports()
    assert callable(default_ui_services().list_ports)


@pytest.mark.asyncio
async def test_firmware_screen_shows_safety_summary_and_clear_flash_button() -> None:
    services = FakeServices()
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(110, 46)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FirmwareScreen)
        await pilot.press("enter")
        await pilot.pause()
        assert "remain present" in text(app.screen.query_one("#operator-safety", Static))
        button = app.screen.query_one("#flash-button", Button)
        assert not button.disabled
        assert str(button.label) == "FLASH FIRMWARE"
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ProgressScreen)
        await pilot.pause(0.2)
        assert services.flash_calls == 1


@pytest.mark.asyncio
async def test_preflight_errors_never_enter_progress_screen() -> None:
    services = FakeServices()
    services.preflight = Mock(
        return_value=ValidationReport((ValidationIssue("model", "wrong family", Severity.ERROR),))
    )
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(112, 48)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FirmwareScreen)
        assert "blocking items" in text(app.screen.query_one("#preflight-status", Static))
        assert app.screen.query_one("#flash-button", Button).disabled
        await pilot.press("enter")
        assert isinstance(app.screen, FirmwareScreen)
        assert services.flash_calls == 0


@pytest.mark.asyncio
async def test_confirmation_required_downgrade_reruns_preflight_before_flash() -> None:
    services = FakeServices()
    initial = ValidationReport(
        (ValidationIssue("downgrade_confirmation_required", "confirm downgrade", Severity.ERROR),)
    )
    services.preflight = Mock(side_effect=(initial, ValidationReport()))
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(112, 48)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FirmwareScreen)
        assert "CONFIRM DOWNGRADE" in str(app.screen.query_one("#flash-button", Button).label)
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, ProgressScreen)
        assert services.preflight.call_args_list[-1].kwargs["downgrade_confirmed"] is True


@pytest.mark.asyncio
async def test_reinstall_with_optional_v_prefix_reruns_confirmation_preflight() -> None:
    services = FakeServices()
    services.identity = replace(services.identity, software="V20.2")
    initial = ValidationReport(
        (ValidationIssue("reinstall_confirmation_required", "confirm reinstall", Severity.ERROR),)
    )
    services.preflight = Mock(side_effect=(initial, ValidationReport()))
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(112, 48)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert "CONFIRM REINSTALL" in str(app.screen.query_one("#flash-button", Button).label)
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, ProgressScreen)
        assert services.preflight.call_args_list[-1].kwargs["same_version_confirmed"] is True


@pytest.mark.asyncio
async def test_escape_is_blocked_while_transfer_is_active_or_result_is_visible() -> None:
    services = FakeServices()
    services.flash = Mock(return_value=FlashResult(FlashState.RECOVERY_REQUIRED, "link lost"))
    app = JkFlashApp(services, Path("fixtures"))
    app.identity = services.identity
    async with app.run_test(size=(100, 42)) as pilot:
        app.push_screen(ProgressScreen(services.identity, services.image))
        await pilot.pause(0.2)
        assert isinstance(app.screen, ProgressScreen)
        await pilot.press("escape")
        assert isinstance(app.screen, ProgressScreen)
        assert "Escape is disabled" in text(app.screen.query_one("#transfer-status", Static))
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, ProgressScreen)


@pytest.mark.asyncio
async def test_preboot_flash_error_is_reported_as_not_started() -> None:
    services = FakeServices()
    services.flash = Mock(side_effect=RuntimeError("telemetry timed out"))
    app = JkFlashApp(services, Path("fixtures"))
    app.identity = services.identity
    async with app.run_test(size=(100, 42)) as pilot:
        app.push_screen(ProgressScreen(services.identity, services.image))
        await pilot.pause(0.2)
        assert "Update stopped: Update did not start: telemetry timed out" in text(
            app.screen.query_one("#transfer-status", Static)
        )


@pytest.mark.asyncio
async def test_transient_refresh_keeps_last_good_data_and_upgrade_stops_polling() -> None:
    services = FakeServices()
    app = JkFlashApp(services, Path("fixtures"))
    async with app.run_test(size=(110, 46)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause(1.0)
        assert isinstance(app.screen, DashboardScreen)
        dashboard = app.screen
        before = text(dashboard.query_one("#telemetry-table", Static))
        services.telemetry_error = "temporary timeout"
        dashboard.refresh_dashboard()
        await pilot.pause(0.2)
        assert text(dashboard.query_one("#telemetry-table", Static)) == before
        assert "showing last good telemetry" in text(dashboard.query_one("#dashboard-status", Static))
        services.telemetry_error = None
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, FirmwareScreen)
        calls_after_suspend = services.dashboard_calls
        await pilot.pause(1.0)
        assert services.dashboard_calls == calls_after_suspend
        await pilot.press("escape")
        await pilot.pause(1.0)
        assert isinstance(app.screen, DashboardScreen)
        assert services.dashboard_calls > calls_after_suspend


@pytest.mark.asyncio
async def test_dashboard_accepts_only_version_change_on_same_physical_device() -> None:
    services = FakeServices()
    original = services.identity
    app = JkFlashApp(services, Path("fixtures"))
    app.identity = original
    async with app.run_test(size=(110, 46)) as pilot:
        app.push_screen(DashboardScreen(original))
        services.identity = replace(original, software="20.4")
        await pilot.pause(1.0)
        assert isinstance(app.screen, DashboardScreen)
        assert app.screen.identity.software == "20.4"
        assert "20.4" in text(app.screen.query_one("#identity-table", Static))
        assert "12.86 V" in text(app.screen.query_one("#telemetry-table", Static))

        services.identity = replace(services.identity, serial="OTHER-PHYSICAL-DEVICE")
        app.screen.refresh_dashboard()
        await pilot.pause(0.2)
        assert "Device identity changed" in text(app.screen.query_one("#dashboard-status", Static))


@pytest.mark.asyncio
async def test_ctrl_c_exits_safe_screen_but_is_blocked_during_transfer() -> None:
    safe_app = JkFlashApp(FakeServices(), Path("fixtures"))
    async with safe_app.run_test(size=(90, 32)) as pilot:
        await pilot.pause()
        await pilot.press("ctrl+c")
        await pilot.pause()
        assert not safe_app.is_running

    release = threading.Event()
    services = FakeServices()

    def blocking_flash(*_args, **_kwargs):
        release.wait(timeout=2)
        return FlashResult(FlashState.SUCCEEDED, "done")

    services.flash = blocking_flash
    app = JkFlashApp(services, Path("fixtures"))
    app.identity = services.identity
    async with app.run_test(size=(90, 32)) as pilot:
        app.push_screen(ProgressScreen(services.identity, services.image))
        await pilot.pause(0.1)
        await pilot.press("ctrl+c")
        await pilot.pause()
        assert app.is_running
        assert isinstance(app.screen, ProgressScreen)
        assert "Quit is disabled" in text(app.screen.query_one("#transfer-status", Static))
        release.set()
        await pilot.pause(0.2)
