"""Non-bypassable compatibility checks for inspected JK PB firmware."""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import zip_longest

from .domain import (
    DeviceIdentity,
    DeviceProfile,
    FirmwareError,
    FirmwareImage,
    Severity,
    ValidationIssue,
    ValidationReport,
)

_MODEL_RE = re.compile(
    r"JK[-_]PB(?P<balancing>[12])A(?P<cells>\d+)S(?:[-_]?(?P<current>\d+)P)",
    re.ASCII,
)
_CANONICAL_MODEL_RE = re.compile(r"JKPB(?P<balancing>[12])A(?P<cells>\d+)S(?P<current>\d+)P", re.ASCII)
_GENERIC_MODEL_RE = re.compile(r"JK[A-Z0-9_-]{3,}", re.ASCII)
_HARDWARE_RE = re.compile(r"V?(?P<major>\d+)[A-Z]*", re.ASCII)
_VERSION_RE = re.compile(r"V?(?P<numbers>\d+\.\d+)(?P<suffix>[A-Z])?", re.ASCII)


@dataclass(frozen=True, slots=True)
class ModelComponents:
    canonical: str
    family: str
    balancing_current_amps: int
    max_cells: int
    current_class: int


@dataclass(frozen=True, slots=True)
class _Release:
    numbers: tuple[int, ...]
    suffix: str

    @property
    def major(self) -> int:
        return self.numbers[0]


def canonicalize_model(value: str) -> str:
    """Validate a JK model and remove only documented naming separators."""

    normalized = value.rstrip("\x00").strip().upper()
    if _GENERIC_MODEL_RE.fullmatch(normalized) is None:
        raise ValueError(f"unrecognized JK model syntax: {value!r}")
    return normalized.replace("-", "").replace("_", "")


def parse_model_components(value: str) -> ModelComponents:
    """Return safety-relevant capabilities encoded in a JK PB model name."""

    canonical = canonicalize_model(value)
    match = _CANONICAL_MODEL_RE.fullmatch(canonical)
    if match is None:
        raise ValueError(f"JK model does not encode PB capabilities: {value!r}")
    cells = int(match.group("cells"))
    current = int(match.group("current"))
    if cells < 1 or current < 1:
        raise ValueError(f"JK PB model contains a zero capability: {value!r}")
    return ModelComponents(
        canonical=canonical,
        family="JKPB",
        balancing_current_amps=int(match.group("balancing")),
        max_cells=cells,
        current_class=current,
    )


def _parse_hardware(value: str) -> int:
    normalized = value.rstrip("\x00").strip().upper()
    match = _HARDWARE_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"invalid hardware version: {value!r}")
    return int(match.group("major"))


def _parse_release(value: str) -> _Release:
    normalized = value.rstrip("\x00").strip().upper()
    match = _VERSION_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"invalid software version: {value!r}")
    return _Release(
        tuple(int(part) for part in match.group("numbers").split(".")),
        match.group("suffix") or "",
    )


def _numeric_compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    for left_part, right_part in zip_longest(left, right, fillvalue=0):
        if left_part != right_part:
            return -1 if left_part < right_part else 1
    return 0


def evaluate_compatibility(
    device: DeviceIdentity,
    image: FirmwareImage,
    profile: DeviceProfile,
    same_version_confirmed: bool = False,
    downgrade_confirmed: bool = False,
) -> ValidationReport:
    """Evaluate generic, data-driven device/image compatibility.

    Downgrades are allowed.  Reinstallation of the same numeric release is a
    hard gate until the caller records an explicit confirmation.  SHA-256 values
    and filenames never participate in this decision.
    """

    issues: list[ValidationIssue] = []

    device_canonical: str | None = None
    image_canonical: str | None = None
    try:
        device_canonical = canonicalize_model(device.model)
    except ValueError as exc:
        issues.append(ValidationIssue("device_model_invalid", str(exc)))
    try:
        image_canonical = canonicalize_model(image.model)
    except ValueError as exc:
        issues.append(ValidationIssue("firmware_model_invalid", str(exc)))

    if device_canonical is not None:
        if re.fullmatch(profile.model_pattern, device_canonical, re.ASCII) is None:
            issues.append(
                ValidationIssue(
                    "model_not_supported",
                    f"device model {device.model!r} is outside profile {profile.name!r}",
                )
            )
        if not 1 <= device.max_cells <= profile.max_supported_cells:
            issues.append(
                ValidationIssue(
                    "cell_count_not_supported",
                    f"device reports {device.max_cells} cells; profile supports at most {profile.max_supported_cells}",
                )
            )
        try:
            device_components = parse_model_components(device.model)
        except ValueError:
            device_components = None
        if device_components is not None and device.max_cells != device_components.max_cells:
            issues.append(
                ValidationIssue(
                    "device_cell_count_mismatch",
                    f"device reports {device.max_cells} cells but model encodes {device_components.max_cells}",
                )
            )

    if image_canonical is not None and re.fullmatch(profile.model_pattern, image_canonical, re.ASCII) is None:
        issues.append(
            ValidationIssue(
                "firmware_model_not_supported",
                f"firmware model {image.model!r} is outside profile {profile.name!r}",
            )
        )

    if device_canonical is not None and image_canonical is not None and device_canonical != image_canonical:
        issues.append(
            ValidationIssue(
                "model_mismatch",
                f"device model {device.model!r} does not exactly match firmware model "
                f"{image.model!r} after separator canonicalization",
            )
        )

    hardware_major: int | None = None
    device_release: _Release | None = None
    image_release: _Release | None = None
    try:
        hardware_major = _parse_hardware(device.hardware)
    except ValueError as exc:
        issues.append(ValidationIssue("hardware_version_invalid", str(exc)))
    try:
        device_release = _parse_release(device.software)
    except ValueError as exc:
        issues.append(ValidationIssue("device_software_version_invalid", str(exc)))
    try:
        image_release = _parse_release(image.version)
    except ValueError as exc:
        issues.append(ValidationIssue("firmware_version_invalid", str(exc)))

    if hardware_major is not None and profile.hardware_major is not None and hardware_major != profile.hardware_major:
        issues.append(
            ValidationIssue(
                "hardware_major_not_supported",
                f"device hardware major {hardware_major} does not match profile major {profile.hardware_major}",
            )
        )
    if (
        device_release is not None
        and profile.firmware_major is not None
        and device_release.major != profile.firmware_major
    ):
        issues.append(
            ValidationIssue(
                "device_software_major_not_supported",
                f"installed software major {device_release.major} does not match profile "
                f"major {profile.firmware_major}",
            )
        )
    if (
        image_release is not None
        and profile.firmware_major is not None
        and image_release.major != profile.firmware_major
    ):
        issues.append(
            ValidationIssue(
                "firmware_major_not_supported",
                f"firmware major {image_release.major} does not match profile major {profile.firmware_major}",
            )
        )
    if hardware_major is not None and device_release is not None and hardware_major != device_release.major:
        issues.append(
            ValidationIssue(
                "device_major_mismatch",
                f"hardware major {hardware_major} and installed software major {device_release.major} differ",
            )
        )
    if hardware_major is not None and image_release is not None and hardware_major != image_release.major:
        issues.append(
            ValidationIssue(
                "firmware_hardware_major_mismatch",
                f"hardware major {hardware_major} and firmware major {image_release.major} differ",
            )
        )

    if not profile.min_decoded_size <= len(image.decoded) <= profile.max_decoded_size:
        issues.append(
            ValidationIssue(
                "image_size_out_of_range",
                f"decoded size {len(image.decoded)} is outside profile range "
                f"{profile.min_decoded_size}..{profile.max_decoded_size}",
            )
        )
    if not profile.sram_start <= image.initial_sp < profile.sram_end or image.initial_sp % 4:
        issues.append(
            ValidationIssue(
                "initial_sp_invalid",
                f"initial stack pointer 0x{image.initial_sp:08X} is invalid for profile SRAM",
            )
        )
    if image.reset_vector & 1 == 0:
        issues.append(
            ValidationIssue(
                "reset_vector_not_thumb",
                f"reset vector 0x{image.reset_vector:08X} does not select Thumb state",
            )
        )
    reset_address = image.reset_vector & ~1
    if not profile.app_flash_start <= reset_address < profile.app_flash_end:
        issues.append(
            ValidationIssue(
                "reset_vector_out_of_range",
                f"reset vector 0x{image.reset_vector:08X} is outside application flash",
            )
        )
    if len(image.suffix) != 12 or image.decoded[-12:] != image.suffix:
        issues.append(
            ValidationIssue(
                "firmware_suffix_invalid",
                "firmware must retain its exact decoded 12-byte suffix",
            )
        )
    else:
        try:
            from .firmware import validate_transfer_suffix

            validate_transfer_suffix(image.suffix)
        except FirmwareError as exc:
            issues.append(ValidationIssue("firmware_suffix_metadata_invalid", str(exc)))
    if not image.transfer_body or image.decoded[:-12] != image.transfer_body:
        issues.append(
            ValidationIssue(
                "transfer_body_invalid",
                "transfer body must be the decoded image excluding exactly 12 suffix bytes",
            )
        )
    elif len(image.transfer_body) > profile.app_flash_end - profile.app_flash_start:
        issues.append(
            ValidationIssue(
                "transfer_body_exceeds_flash",
                "firmware transfer body exceeds the selected capability's application region",
            )
        )

    if device_release is not None and image_release is not None:
        direction = _numeric_compare(image_release.numbers, device_release.numbers)
        if direction < 0:
            if not downgrade_confirmed:
                issues.append(
                    ValidationIssue(
                        "downgrade_confirmation_required",
                        f"target {image.version} is older than installed {device.software}; "
                        "explicit downgrade confirmation is required",
                    )
                )
            else:
                issues.append(
                    ValidationIssue(
                        "downgrade",
                        f"target {image.version} is older than installed {device.software}",
                        Severity.WARNING,
                    )
                )
        elif direction == 0:
            if not same_version_confirmed:
                issues.append(
                    ValidationIssue(
                        "reinstall_confirmation_required",
                        f"target {image.version} matches installed {device.software}; explicit "
                        "reinstall confirmation is required",
                    )
                )
            else:
                issues.append(
                    ValidationIssue(
                        "reinstall",
                        f"target {image.version} matches installed {device.software}",
                        Severity.WARNING,
                    )
                )

    return ValidationReport(tuple(issues))


__all__ = [
    "ModelComponents",
    "canonicalize_model",
    "evaluate_compatibility",
    "parse_model_components",
]
