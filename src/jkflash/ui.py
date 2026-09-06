"""Keyboard-first, attended terminal UI for :mod:`jkflash`.

The screen layout deliberately mirrors an operator console: choose a serial
port, inspect one battery, choose firmware, then watch a single transfer.  It
keeps all serial and firmware work behind ``UiServices``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol, cast

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Label, OptionList, ProgressBar, Static
from textual.widgets.option_list import Option

from .audit import masked_identifier
from .domain import (
    DeviceIdentity,
    FirmwareImage,
    FlashEvent,
    FlashResult,
    FlashState,
    PortInfo,
    TelemetrySnapshot,
    ValidationReport,
)


class UiServices(Protocol):
    """Application operations consumed by the attended UI."""

    def list_ports(self) -> Sequence[PortInfo]: ...
    def connect(self, port: PortInfo, address: int) -> DeviceIdentity: ...
    def read_identity(self) -> DeviceIdentity: ...
    def read_telemetry(self, max_cells: int) -> TelemetrySnapshot: ...
    def read_dashboard(self, max_cells: int) -> tuple[DeviceIdentity, TelemetrySnapshot]: ...
    def list_firmware(self, directory: Path) -> Sequence[Path]: ...
    def inspect_firmware(self, path: Path) -> FirmwareImage: ...
    def preflight(
        self,
        identity: DeviceIdentity,
        image: FirmwareImage,
        *,
        same_version_confirmed: bool = False,
        downgrade_confirmed: bool = False,
    ) -> ValidationReport: ...
    def flash(
        self, identity: DeviceIdentity, image: FirmwareImage, event_sink: Callable[[FlashEvent], None]
    ) -> FlashResult: ...
    def capability_status(self) -> str: ...


class UnconfiguredUiServices:
    """Safe fallback used only if the production application cannot import."""

    def _unavailable(self, *_: object, **__: object) -> object:
        raise RuntimeError("The local JK Flash service is not configured.")

    list_ports = _unavailable
    connect = _unavailable
    read_identity = _unavailable
    read_telemetry = _unavailable
    read_dashboard = _unavailable
    list_firmware = _unavailable
    inspect_firmware = _unavailable
    preflight = _unavailable
    flash = _unavailable
    capability_status = _unavailable


def default_ui_services() -> UiServices:
    """Delay importing production serial support until the interactive app runs."""

    try:
        from .application import create_ui_services
    except ImportError:
        return cast(UiServices, UnconfiguredUiServices())
    return create_ui_services()


def format_identity(identity: DeviceIdentity | None) -> str:
    """Format non-sensitive identity fields for the dashboard table."""

    if identity is None:
        return "Not connected"
    return "\n".join(
        (
            f"Model       {identity.model}",
            f"Hardware    {identity.hardware or 'unavailable'}",
            f"Software    {identity.software or 'unavailable'}",
            f"Address     {identity.address}",
            f"Identity    {masked_identifier(identity.serial) or 'unavailable'}",
        )
    )


def format_port(port: PortInfo, *, compact: bool = False) -> str:
    """Render cross-platform adapter details without exposing a full serial."""

    name = port.description or port.product or "Serial port"
    if compact:
        return f"{port.device}  {name}"
    details: list[str] = []
    maker = port.manufacturer.strip()
    product = port.product.strip()
    if maker and maker.casefold() not in name.casefold():
        details.append(maker)
    if product and product.casefold() not in name.casefold():
        details.append(product)
    if port.vid is not None and port.pid is not None:
        details.append(f"USB {port.vid:04X}:{port.pid:04X}")
    if port.interface:
        details.append(port.interface)
    if port.location:
        details.append(f"at {port.location}")
    if port.serial_number:
        details.append(f"serial {masked_identifier(port.serial_number)}")
    suffix = f"  |  {'  |  '.join(details)}" if details else ""
    return f"{port.device:<14} {name}{suffix}"


def format_telemetry(snapshot: TelemetrySnapshot | None, *, compact: bool = False) -> str:
    """Format known telemetry only; unavailable values are never invented."""

    if snapshot is None:
        return "Telemetry unavailable"
    cells = "unavailable"
    if snapshot.cell_voltages:
        cells = (
            f"{len(snapshot.cell_voltages)} cells  min {snapshot.minimum_cell:.3f} V  "
            f"max {snapshot.maximum_cell:.3f} V  delta {snapshot.cell_delta:.3f} V"
        )
    if compact:
        return "\n".join(
            (
                f"Pack  {snapshot.pack_voltage:.2f} V  {snapshot.pack_current:.2f} A  {snapshot.power:.1f} W",
                f"SOC/SOH  {snapshot.state_of_charge}% / {snapshot.state_of_health}%",
                f"Cells  {cells}",
                f"Temp  MOS {snapshot.mos_temperature:.1f} C  T1 {snapshot.temperature_1:.1f} C  "
                f"T2 {snapshot.temperature_2:.1f} C",
                f"Capacity  {snapshot.remaining_capacity:.1f} / {snapshot.full_capacity:.1f} Ah",
                f"Status  balance {snapshot.balance_state}; "
                f"charge {'on' if snapshot.charge_mos else 'off'}; "
                f"discharge {'on' if snapshot.discharge_mos else 'off'}",
                f"Fault  0x{snapshot.fault_mask:X}; cycles {snapshot.cycles}; runtime {snapshot.runtime_seconds} s",
            )
        )
    return "\n".join(
        (
            f"Pack        {snapshot.pack_voltage:.2f} V     {snapshot.pack_current:.2f} A     {snapshot.power:.1f} W",
            f"SOC / SOH   {snapshot.state_of_charge}% / {snapshot.state_of_health}%",
            f"Cells       {cells}",
            f"Temperature MOS {snapshot.mos_temperature:.1f} C  T1 {snapshot.temperature_1:.1f} C  "
            f"T2 {snapshot.temperature_2:.1f} C",
            f"Capacity    {snapshot.remaining_capacity:.1f} / {snapshot.full_capacity:.1f} Ah   "
            f"cycles {snapshot.cycles}",
            f"Status      balance {snapshot.balance_state} ({snapshot.balance_current:.2f} A)  "
            f"charge {'on' if snapshot.charge_mos else 'off'}  "
            f"discharge {'on' if snapshot.discharge_mos else 'off'}",
            f"Fault mask  0x{snapshot.fault_mask:X}     runtime {snapshot.runtime_seconds} s",
        )
    )


def _numeric_version(value: str) -> tuple[int, ...] | None:
    text = value.strip().upper().removeprefix("V")
    parts = text.split(".")
    return tuple(map(int, parts)) if parts and all(part.isdigit() for part in parts) else None


class PortScreen(Screen[None]):
    """First screen: an uncluttered serial-port list and selected Modbus ID."""

    BINDINGS = [("r", "refresh_ports", "Refresh"), ("enter", "connect", "Connect"), ("q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="port-page"):
            yield Label("JK Flash", classes="screen-title")
            yield Static("Select the RS485 serial port.  Enter connects.", id="port-help")
            yield OptionList(id="port-list")
            with Horizontal(classes="compact-row"):
                yield Label("Modbus device ID (1–247):")
                yield Input("1", id="device-address", type="integer")
            yield Static("Scanning serial ports…", id="port-status")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_ports()
        self.query_one("#port-list", OptionList).focus()

    def action_refresh_ports(self) -> None:
        self.refresh_ports()

    def refresh_ports(self) -> None:
        app = cast(JkFlashApp, self.app)
        options = self.query_one("#port-list", OptionList)
        try:
            ports = app.services.list_ports()
        except Exception as error:
            app.ports = {}
            options.clear_options()
            self._status(f"Unable to list serial ports: {error}")
            return
        app.ports = {port.device: port for port in ports}
        compact = self.size.width < 92
        options.set_options(Option(format_port(port, compact=compact), id=port.device) for port in ports)
        if ports:
            options.highlighted = 0
            self._status(f"{len(ports)} serial port(s).  Up/Down selects; Enter connects.")
        else:
            self._status("No serial ports detected. Connect an RS485 adapter, then press r to refresh.")

    def on_resize(self, _event: object) -> None:
        # Re-render metadata when the terminal crosses the compact breakpoint.
        self.refresh_ports()

    def action_connect(self) -> None:
        app = cast(JkFlashApp, self.app)
        port_list = self.query_one("#port-list", OptionList)
        selected = port_list.highlighted_option
        if selected is None or selected.id is None:
            self._status("Select a serial port before connecting.")
            return
        try:
            address = int(self.query_one("#device-address", Input).value)
        except ValueError:
            self._status("Modbus device ID must be a whole number from 1 through 247.")
            return
        if not 1 <= address <= 247:
            self._status("Modbus device ID must be in the range 1 through 247; 0 is broadcast.")
            return
        port = app.ports.get(str(selected.id))
        if port is None:
            self._status("The selected serial port disappeared. Press r to refresh.")
            return
        self._status(f"Connecting to {port.device} at device ID {address}…")
        self._connect_worker(port, address)

    @work(thread=True, exclusive=True)
    def _connect_worker(self, port: PortInfo, address: int) -> None:
        app = cast(JkFlashApp, self.app)
        try:
            identity = app.services.connect(port, address)
        except Exception as error:
            app.call_from_thread(self._connection_failed, str(error))
            return
        app.call_from_thread(self._connected, identity)

    def _connection_failed(self, error: str) -> None:
        cast(JkFlashApp, self.app).identity = None
        self._status(f"Connection unavailable: {error}")

    def _connected(self, identity: DeviceIdentity) -> None:
        app = cast(JkFlashApp, self.app)
        app.identity = identity
        app.push_screen(DashboardScreen(identity))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "port-list":
            self.action_connect()

    def _status(self, message: str) -> None:
        self.query_one("#port-status", Static).update(message)


class DashboardScreen(Screen[None]):
    """Compact monitor screen with one keyboard-selectable Upgrade action."""

    BINDINGS = [
        ("r", "refresh_dashboard", "Refresh"),
        ("enter", "activate", "Select"),
        ("escape", "back", "Ports"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, identity: DeviceIdentity) -> None:
        super().__init__()
        self.identity = identity
        self._poll_timer = None
        self.snapshot: TelemetrySnapshot | None = None
        self._poll_inflight = False
        self._accept_polls = False

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="dashboard-page"):
            yield Label("Battery details", classes="screen-title")
            yield Static(format_identity(self.identity), id="identity-table", classes="table")
            yield Static("Capability unavailable", id="capability-status", classes="muted")
            yield Static("Loading telemetry…", id="telemetry-table", classes="table")
            yield Label("Cell voltages", classes="section-title")
            yield Static("Loading…", id="cell-table", classes="table")
            yield OptionList(Option("Upgrade firmware", id="upgrade"), id="dashboard-actions", compact=True)
            yield Static("Up/Down + Enter to select. r refreshes telemetry.", id="dashboard-status", classes="muted")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#dashboard-actions", OptionList).focus()
        self._poll_timer = self.set_interval(0.8, self.refresh_dashboard, pause=True)
        self._resume_polling()

    def on_screen_suspend(self) -> None:
        self._pause_polling()

    def on_screen_resume(self) -> None:
        self._resume_polling()

    def on_unmount(self) -> None:
        self._pause_polling()

    def _pause_polling(self) -> None:
        self._accept_polls = False
        if self._poll_timer is not None:
            self._poll_timer.pause()

    def _resume_polling(self) -> None:
        self._accept_polls = True
        if self._poll_timer is not None:
            self._poll_timer.resume()

    def action_refresh_dashboard(self) -> None:
        self.refresh_dashboard()

    def action_activate(self) -> None:
        selected = self.query_one("#dashboard-actions", OptionList).highlighted_option
        if selected is not None and selected.id == "upgrade":
            # Stop producing sensor requests before the firmware workflow can
            # acquire the application's exclusive serial-session lock.
            self._pause_polling()
            self.app.push_screen(FirmwareScreen(self.identity))

    def action_back(self) -> None:
        self._pause_polling()
        self.app.pop_screen()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "dashboard-actions":
            self.action_activate()

    def refresh_dashboard(self) -> None:
        if self._poll_inflight:
            return
        self._poll_inflight = True
        self._poll_worker()

    @work(thread=True, exclusive=True)
    def _poll_worker(self) -> None:
        app = cast(JkFlashApp, self.app)
        try:
            fresh, snapshot = app.services.read_dashboard(self.identity.max_cells)
            if fresh != self.identity and not _same_physical_identity(fresh, self.identity):
                app.call_from_thread(self._identity_changed)
                return
        except Exception as error:
            app.call_from_thread(self._poll_failed, str(error))
            return
        app.call_from_thread(self._poll_succeeded, fresh, snapshot)

    def _identity_changed(self) -> None:
        self._poll_inflight = False
        if self._accept_polls:
            self.query_one("#dashboard-status", Static).update(
                "Device identity changed; return to the port list and reconnect."
            )

    def _poll_failed(self, error: str) -> None:
        self._poll_inflight = False
        if not self._accept_polls:
            return
        if self.snapshot is None:
            self.query_one("#telemetry-table", Static).update("Telemetry unavailable")
            self.query_one("#cell-table", Static).update("Telemetry unavailable")
            message = f"Telemetry unavailable: {error}"
        else:
            message = f"Refresh failed; showing last good telemetry: {error}"
        self.query_one("#dashboard-status", Static).update(message)

    def _poll_succeeded(self, fresh: DeviceIdentity, snapshot: TelemetrySnapshot) -> None:
        self._poll_inflight = False
        if not self._accept_polls:
            return
        app = cast(JkFlashApp, self.app)
        app.identity = fresh
        self.identity = fresh
        self.snapshot = snapshot
        self.query_one("#identity-table", Static).update(format_identity(fresh))
        capability = getattr(app.services, "capability_status", None)
        try:
            text = str(capability()) if callable(capability) else "Capability will be validated before flashing."
        except Exception:
            text = "Capability unavailable"
        self.query_one("#capability-status", Static).update(text)
        self._render_snapshot(snapshot)
        self.query_one("#dashboard-status", Static).update("Live telemetry.  Up/Down + Enter selects Upgrade firmware.")

    def on_resize(self, _event: object) -> None:
        if self.snapshot is not None:
            self._render_snapshot(self.snapshot)

    def _render_snapshot(self, snapshot: TelemetrySnapshot) -> None:
        compact = self.size.width < 92
        self.query_one("#telemetry-table", Static).update(format_telemetry(snapshot, compact=compact))
        self.query_one("#cell-table", Static).update(_format_cells(snapshot, compact=compact))


def _format_cells(snapshot: TelemetrySnapshot, *, compact: bool = False) -> str:
    if not snapshot.cell_voltages:
        return "Cell voltages unavailable"
    values = [f"Cell {index + 1:>2}: {value:.3f} V" for index, value in enumerate(snapshot.cell_voltages)]
    columns = 2 if compact else 4
    return "\n".join("   ".join(values[index : index + columns]) for index in range(0, len(values), columns))


def _same_physical_identity(first: DeviceIdentity, second: DeviceIdentity) -> bool:
    """Allow only the expected software-version change after a verified flash."""

    return (
        first.address,
        first.model,
        first.max_cells,
        first.hardware,
        first.serial,
    ) == (
        second.address,
        second.model,
        second.max_cells,
        second.hardware,
        second.serial,
    )


class FirmwareScreen(Screen[None]):
    """Firmware selection and all pre-boot confirmations in one compact screen."""

    BINDINGS = [
        ("r", "reload_files", "Reload"),
        ("escape", "back", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, identity: DeviceIdentity) -> None:
        super().__init__()
        self.identity = identity
        self.image: FirmwareImage | None = None
        self.report: ValidationReport | None = None

    def compose(self) -> ComposeResult:
        app = cast(JkFlashApp, self.app)
        with VerticalScroll(id="firmware-page"):
            yield Label("Firmware update", classes="screen-title")
            yield Static(
                "OWN RISK: an update can leave equipment unusable. Do not continue unless you can recover the BMS.",
                id="own-risk",
            )
            with Horizontal(classes="compact-row"):
                yield Label("Directory:")
                yield Input(str(app.firmware_dir), id="firmware-directory")
            yield OptionList(id="firmware-list")
            yield Input(placeholder="Custom firmware path (press Enter to inspect)", id="custom-firmware-path")
            yield Static("Select a firmware file, or type a custom path.", id="firmware-status", classes="muted")
            yield Static("", id="firmware-evidence", classes="table")
            yield Static(
                "Before flashing: remain present, keep BMS power and RS485 stable, "
                "isolate this BMS from other RS485 devices, remove charge/load activity, "
                "and keep a settings backup and recovery firmware available.\n\n"
                "Selecting FLASH FIRMWARE confirms these conditions and any clearly "
                "displayed reinstall or downgrade.",
                id="operator-safety",
                classes="table",
            )
            yield Static("Inspect a file before the flash confirmations become available.", id="preflight-status")
            yield Button("FLASH FIRMWARE", id="flash-button", variant="error", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.reload_files()
        self.query_one("#firmware-list", OptionList).focus()

    def action_reload_files(self) -> None:
        self.reload_files()

    def reload_files(self) -> None:
        app = cast(JkFlashApp, self.app)
        self.image = None
        self.report = None
        self._reset_flash_button()
        directory = Path(self.query_one("#firmware-directory", Input).value).expanduser()
        try:
            paths = app.services.list_firmware(directory)
        except Exception as error:
            self._status(f"Firmware directory unavailable: {error}")
            return
        app.firmware_dir = directory
        self.query_one("#firmware-list", OptionList).set_options(Option(path.name, id=str(path)) for path in paths)
        if paths:
            self.query_one("#firmware-list", OptionList).highlighted = 0
        self._status(f"{len(paths)} firmware file(s). Select one and press Enter.")

    def action_select_or_flash(self) -> None:
        if self.report is not None:
            self.start_flash()
        else:
            self.inspect_and_preflight()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "firmware-list":
            self.inspect_and_preflight()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "flash-button":
            self.start_flash()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "custom-firmware-path":
            self.inspect_and_preflight()
        elif event.input.id == "firmware-directory":
            self.reload_files()

    def inspect_and_preflight(self) -> None:
        self._reset_flash_button()
        path = self._selected_path()
        if path is None:
            self._status("Select a firmware file or enter a custom path.")
            return
        app = cast(JkFlashApp, self.app)
        try:
            image = app.services.inspect_firmware(path)
            report = app.services.preflight(self.identity, image)
        except Exception as error:
            self.image = None
            self.report = None
            self.query_one("#preflight-status", Static).update(f"Inspection or preflight unavailable: {error}")
            return
        self.image, self.report = image, report
        self.query_one("#firmware-evidence", Static).update(
            "\n".join(
                (
                    f"Target model   {image.model}",
                    f"Target version {image.version}",
                    f"Container SHA  {image.container_sha256}",
                    f"Decoded SHA    {image.decoded_sha256}",
                )
            )
        )
        confirmation_codes = {
            "reinstall_confirmation_required",
            "downgrade_confirmation_required",
        }
        blocking = any(
            issue.severity.name == "ERROR" and issue.code not in confirmation_codes for issue in report.issues
        )
        issues = "\n".join(f"{issue.severity.name}: {issue.message}" for issue in report.issues)
        outcome = "passed" if not blocking else "has blocking items"
        self.query_one("#preflight-status", Static).update(
            f"Preflight {outcome}. {issues or 'Review the safety conditions, then select FLASH FIRMWARE.'}"
        )
        button = self.query_one("#flash-button", Button)
        button.disabled = blocking
        issue_codes = {issue.code for issue in report.issues}
        if "downgrade_confirmation_required" in issue_codes:
            button.label = "FLASH FIRMWARE — CONFIRM DOWNGRADE"
        elif "reinstall_confirmation_required" in issue_codes:
            button.label = "FLASH FIRMWARE — CONFIRM REINSTALL"
        else:
            button.label = "FLASH FIRMWARE"
        if not blocking:
            button.focus()
            self._status("Firmware inspected. Review the summary, then select the red flash button.")
        else:
            self._status("Firmware inspection found blocking compatibility or integrity errors.")

    def start_flash(self) -> None:
        if self.image is None or self.report is None:
            self._status("Select and inspect firmware first.")
            return
        confirmation_codes = {
            "reinstall_confirmation_required",
            "downgrade_confirmation_required",
        }
        blocking = any(
            issue.severity.name == "ERROR" and issue.code not in confirmation_codes for issue in self.report.issues
        )
        if blocking:
            self._status("Preflight has blocking items; flashing is unavailable.")
            return
        installed, target = _numeric_version(self.identity.software), _numeric_version(self.image.version)
        issue_codes = {issue.code for issue in self.report.issues}
        same_version = (
            installed is not None and target is not None and installed == target
        ) or "reinstall_confirmation_required" in issue_codes
        downgraded = (
            installed is not None and target is not None and target < installed
        ) or "downgrade_confirmation_required" in issue_codes
        if same_version or downgraded:
            try:
                self.report = cast(JkFlashApp, self.app).services.preflight(
                    self.identity,
                    self.image,
                    same_version_confirmed=same_version,
                    downgrade_confirmed=downgraded,
                )
            except Exception as error:
                self._status(f"Preflight unavailable: {error}")
                return
            if not self.report.allowed:
                self._status("Preflight has blocking items; flashing is unavailable.")
                return
        qualifier = " Downgrade confirmed by operator." if downgraded else ""
        if same_version:
            qualifier = " Reinstall confirmed by operator."
        self.app.push_screen(ProgressScreen(self.identity, self.image, qualifier))

    def action_back(self) -> None:
        self.app.pop_screen()

    def _selected_path(self) -> Path | None:
        custom = self.query_one("#custom-firmware-path", Input).value.strip()
        if custom:
            return Path(custom).expanduser()
        selected = self.query_one("#firmware-list", OptionList).highlighted_option
        return Path(str(selected.id)) if selected is not None and selected.id is not None else None

    def _status(self, message: str) -> None:
        self.query_one("#firmware-status", Static).update(message)

    def _reset_flash_button(self) -> None:
        button = self.query_one("#flash-button", Button)
        button.disabled = True
        button.label = "FLASH FIRMWARE"


class ProgressScreen(Screen[None]):
    """Bootloader operation screen. Escape is deliberately disabled here."""

    BINDINGS = [("enter", "return_dashboard", "Return after result"), ("q", "blocked_quit", "Flash active")]

    def __init__(self, identity: DeviceIdentity, image: FirmwareImage, note: str = "") -> None:
        super().__init__()
        self.identity, self.image, self.note = identity, image, note
        self.result: FlashResult | None = None

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="progress-page"):
            yield Label("Firmware transfer", classes="screen-title")
            yield Static(f"Updating {self.identity.model} to {self.image.version}.{self.note}", id="transfer-summary")
            yield ProgressBar(total=100, show_eta=False, id="flash-progress")
            yield Static("Preparing transfer…", id="transfer-status")
        yield Footer()

    def on_mount(self) -> None:
        self._flash_worker()

    @work(thread=True, exclusive=True)
    def _flash_worker(self) -> None:
        app = cast(JkFlashApp, self.app)
        try:
            result = app.services.flash(self.identity, self.image, self._event_from_worker)
        except Exception as error:
            # FirmwareFlasher converts every post-boot uncertainty into a
            # RECOVERY_REQUIRED result. An exception reaching this boundary is
            # therefore a safe pre-boot block, not evidence of a bricked BMS.
            result = FlashResult(FlashState.PREFLIGHT, f"Update did not start: {error}")
        app.call_from_thread(self._finished, result)

    def _event_from_worker(self, event: FlashEvent) -> None:
        self.app.call_from_thread(self._event, event)

    def _event(self, event: FlashEvent) -> None:
        if event.total_blocks:
            self.query_one("#flash-progress", ProgressBar).update(
                progress=100 * event.completed_blocks / event.total_blocks
            )
        self.query_one("#transfer-status", Static).update(event.message)

    def _finished(self, result: FlashResult) -> None:
        self.result = result
        if result.state is FlashState.SUCCEEDED:
            text = f"Completed: {result.message}  Press Enter to return to battery details."
        elif result.state is FlashState.RECOVERY_REQUIRED:
            text = f"Recovery required: {result.message}  Press Enter after resolving the connection."
        else:
            text = f"Update stopped: {result.message}  Press Enter to return to battery details."
        self.query_one("#transfer-status", Static).update(text)

    def action_return_dashboard(self) -> None:
        if self.result is None:
            self.query_one("#transfer-status", Static).update(
                "Transfer is active. Escape and quit are disabled until it finishes."
            )
            return
        self.app.pop_screen()
        self.app.pop_screen()

    def action_blocked_quit(self) -> None:
        self.query_one("#transfer-status", Static).update("Transfer is active. Quit is disabled until it finishes.")

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key == "escape":
            event.stop()
            self.query_one("#transfer-status", Static).update(
                "Transfer is active. Escape is disabled until it finishes."
            )


class JkFlashApp(App[None]):
    """An attended TUI with no unattended flashing command."""

    TITLE = "JK Flash"
    BINDINGS = [Binding("ctrl+c", "safe_quit", "Quit", priority=True)]
    CSS = """
    Screen { padding: 1 2; }
    .screen-title { text-style: bold; color: $accent; margin-bottom: 1; }
    .section-title { text-style: bold; margin-top: 1; }
    .table { border: round $primary; padding: 1; margin: 1 0; }
    .muted { color: $text-muted; }
    .compact-row { height: auto; margin: 1 0; }
    #device-address { width: 12; margin-left: 1; }
    #port-list, #firmware-list { height: 1fr; min-height: 7; border: round $primary; }
    #dashboard-page, #firmware-page, #progress-page { height: 1fr; }
    #own-risk { color: $warning; text-style: bold; margin-bottom: 1; }
    #flash-button { width: 100%; margin-top: 1; text-style: bold; }
    #flash-progress { margin: 2 0 1 0; }
    """

    def __init__(self, services: UiServices | None = None, firmware_dir: Path | None = None) -> None:
        super().__init__()
        self.services = services or default_ui_services()
        self.firmware_dir = firmware_dir or Path.cwd() / "firmware"
        self.ports: dict[str, PortInfo] = {}
        self.identity: DeviceIdentity | None = None

    def on_mount(self) -> None:
        self.push_screen(PortScreen())

    def action_safe_quit(self) -> None:
        """Honor Ctrl-C except while firmware bytes may be in flight."""

        screen = self.screen
        if isinstance(screen, ProgressScreen) and screen.result is None:
            screen.action_blocked_quit()
            return
        self.exit()


def run(services: UiServices | None = None, firmware_dir: Path | None = None) -> None:
    """Launch the deliberately attended terminal interface."""

    JkFlashApp(services=services, firmware_dir=firmware_dir).run()
