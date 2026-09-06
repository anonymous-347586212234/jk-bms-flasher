"""Command-line entry point for the attended Textual application."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .ui import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="jkflash", description="Launch the attended JK Flash terminal interface.")
    parser.add_argument("--version", action="version", version=f"jkflash {__version__}")
    parser.add_argument(
        "--firmware-dir",
        type=Path,
        help="Initial directory to browse for firmware files in the TUI.",
    )
    args = parser.parse_args()
    run(firmware_dir=args.firmware_dir)


if __name__ == "__main__":
    main()
