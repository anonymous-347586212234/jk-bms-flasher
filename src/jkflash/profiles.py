"""Explicitly supported hardware/protocol profiles."""

from .domain import DeviceProfile

JK_GENERIC = DeviceProfile(
    name="JK generic / JK-BXAXS-XP 32-slot capability",
    model_pattern=r"(?!JKB1A24SP?$)JK[A-Z0-9]+",
    hardware_major=None,
    firmware_major=None,
    baudrate=115_200,
    boot_banner=b"STM32F103x BOOTLOADER V2.0.4",
    telemetry_layout="JK02_32S",
    # Vendor JK-BXAXS-XP metadata marks bit 4 (fully charged), bit 18
    # (GPS disconnected), and bit 19 (password-change reminder) as advisory.
    # Every protection, hardware, remote-lock, and undefined bit remains a
    # pre-flash blocker.
    flash_blocking_fault_mask=0xFFF3FFEF,
    app_flash_start=0x08010000,
    max_decoded_size=0x30000 + 12,
)

JK02_24S_MONITOR = DeviceProfile(
    name="JK legacy / JK02 24-slot monitoring capability",
    model_pattern=r"JKB1A24SP?",
    hardware_major=None,
    firmware_major=None,
    baudrate=115_200,
    boot_banner=b"",
    telemetry_layout="JK02_24S",
    max_supported_cells=24,
    flash_supported=False,
    evidence="binary metadata-derived monitoring layout; firmware transfer unverified",
)

# Backward-compatible import name; it no longer imposes a V19 runtime gate.
PB_V19 = JK_GENERIC
SUPPORTED_PROFILES = (JK_GENERIC, JK02_24S_MONITOR)
