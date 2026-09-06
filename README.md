# JK Flash

Open source and platform independant tool to Flash JK BMS'es.

> **ENTIRELY AT YOUR OWN RISK:** Firmware updates can make a BMS unusable. Stay with the equipment, keep BMS power and the RS485 connection stable, isolate the target BMS, and have a settings backup and recovery plan before starting.

JK Flash is a keyboard-first terminal application for inspecting one JK BMS and performing an attended firmware update. It has no batch, scheduled, or unattended flash command.

Run it from this source checkout:

```console
python main.py
```

`python -m jkflash` launches the same interface after the package is available on Python's import path. `--firmware-dir PATH` selects the initial firmware directory.

## Operator flow

The interface is deliberately compact, in the style of a terminal operations console.

1. Startup shows only the detected serial ports. Each row includes the adapter description and, when the operating system supplies them, manufacturer/product, USB VID:PID, interface, physical location, and a masked adapter serial. Use Up/Down and Enter to select a port. Enter a Modbus device ID from 1 through 247 when the BMS has been configured in the vendor application; address 0 is never used because it is broadcast. Press `r` to refresh. If no ports exist, the screen explains how to reconnect and refresh.
2. The battery screen shows a columnated summary of identity, pack voltage/current/power, SOC/SOH, temperature, capacity, states, faults, and enabled cell voltages. Select **Upgrade firmware** with Up/Down and Enter. Press `r` to refresh telemetry. A transient timeout leaves the last valid readings visible and marks them as stale instead of blanking the dashboard.
3. The firmware screen lists files from `firmware/` (or a chosen directory) and accepts a custom path. Select a file and press Enter to inspect it and run preflight. It displays embedded model/version and content hashes, all preflight findings, and the required attended-operation checks.
4. Review the displayed safety conditions and select the red **FLASH FIRMWARE** button. The button is disabled when compatibility or integrity checks fail and explicitly names a downgrade or reinstall when applicable. Selecting it confirms the displayed attended-operation conditions. Dashboard polling stops before the firmware workflow and all serial operations are mutually exclusive. A dedicated transfer screen displays progress and the final result. Escape, `q`, and Ctrl-C are disabled only while transfer is active; Ctrl-C exits normally on safe screens. Press Enter after the result to return to the live battery screen and resume monitoring.

The layout scrolls on short terminals and keeps the selected action keyboard reachable on narrow and wide terminals. No device serial number is displayed or written to normal logs.

## Compatibility and safety

The application discovers the connected identity instead of asking the operator to select a product profile. It applies live identity, container, embedded metadata, image structure, and bootloader-capability checks before it may transfer firmware. These checks are generalized from limited protocol evidence; generic validation does not authenticate a firmware payload and cannot eliminate every risk.

Downgrades and reinstalls are supported only when the flash button explicitly identifies that operation and confirmation-aware preflight succeeds again. A blocking compatibility, integrity, live-identity, electrical-state, or bootloader check prevents transfer.

JK Monitor's Force Upgrade password is a host-side UI unlock; it is not transmitted to the BMS. This tool uses explicit local downgrade/reinstall confirmations instead. Normal and Force upgrades use the same on-wire transfer, while model, hardware, image-integrity, and boot-handshake checks remain non-bypassable here.

Use only one BMS on the RS485 link during an update. Remove charge/load connections as appropriate while keeping the BMS itself powered. Do not remove power or the serial cable until the tool reports a terminal result.

## Project layout

- `src/jkflash/` — TUI, serial transport, protocol, firmware inspection, safety checks, and flashing services.
- `firmware/` — default location for firmware containers; a custom file path is also supported.
- `tests/` — unit, protocol replay, safety, privacy, and keyboard UI tests.
- `implementation_details/` — sanitized captures, research notes, decode tools, and evidence retained separately from the application.

The research material does not contain local device serials, personal names, email addresses, local system paths, or raw monitoring captures.
