from __future__ import annotations

import runpy
import sys
from pathlib import Path
from typing import cast

import pytest

import jkflash.__main__ as cli
import jkflash.ui as ui


def test_main_dispatches_firmware_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path | None] = []
    monkeypatch.setattr(cli, "run", lambda *, firmware_dir=None: calls.append(firmware_dir))
    monkeypatch.setattr(sys, "argv", ["jkflash", "--firmware-dir", "images"])
    cli.main()
    assert calls == [Path("images")]


def test_main_dispatches_default_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path | None] = []
    monkeypatch.setattr(cli, "run", lambda *, firmware_dir=None: calls.append(firmware_dir))
    monkeypatch.setattr(sys, "argv", ["jkflash"])
    cli.main()
    assert calls == [None]


@pytest.mark.parametrize("argument, expected", [("--help", "attended JK Flash"), ("--version", "jkflash 0.1.0")])
def test_help_and_version_do_not_launch_ui(
    argument: str,
    expected: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    launch = MockLaunch()
    monkeypatch.setattr(cli, "run", launch)
    monkeypatch.setattr(sys, "argv", ["jkflash", argument])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == 0
    assert expected in capsys.readouterr().out
    assert launch.calls == 0


class MockLaunch:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **_: object) -> None:
        self.calls += 1


def test_module_guard_calls_main(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path | None] = []
    monkeypatch.setattr(ui, "run", lambda *, firmware_dir=None: calls.append(firmware_dir))
    monkeypatch.setattr(sys, "argv", ["jkflash"])
    sys.modules.pop("jkflash.__main__", None)
    runpy.run_module("jkflash.__main__", run_name="__main__")
    assert calls == [None]


def test_ui_run_constructs_and_launches_app(monkeypatch: pytest.MonkeyPatch) -> None:
    launched: list[tuple[object, Path | None]] = []

    class FakeApp:
        def __init__(self, services=None, firmware_dir=None) -> None:
            launched.append((services, firmware_dir))

        def run(self) -> None:
            launched.append(("run", None))

    marker = object()
    monkeypatch.setattr(ui, "JkFlashApp", FakeApp)
    ui.run(cast(ui.UiServices, marker), Path("firmware"))
    assert launched == [(marker, Path("firmware")), ("run", None)]
