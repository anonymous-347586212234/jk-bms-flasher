"""Strict inspection of encrypted JK firmware containers.

This module deliberately makes no trust decision from a filename.  A container
is decrypted, bounded, structurally validated, and inspected using fields from
the decoded image before a :class:`~jkflash.domain.FirmwareImage` is returned.
"""

from __future__ import annotations

import hashlib
import re
import time
import zlib
from pathlib import Path

from Crypto.Cipher import AES

from .domain import DeviceProfile, FirmwareError, FirmwareImage
from .profiles import JK_GENERIC
from .safety import canonicalize_model

FIRMWARE_KEY = b"A39FF3F613F94FDD957EC22EF642ADA9"
ZERO_IV = b"\x00" * AES.block_size
MAX_DECODED_SIZE = 0x1400000
MAX_CONTAINER_OVERHEAD = 65_536

VERSION_OFFSET = 0x200
MODEL_OFFSETS = (0x250, 0x280, 0x2A8)
IDENTITY_FIELD_SIZE = 16
TRANSFER_SUFFIX_SIZE = 12
TRANSFER_BLOCK_SIZE = 128

_VERSION_RE = re.compile(r"\d+\.\d+[A-Z]?", re.ASCII)


def _error(message: str) -> FirmwareError:
    return FirmwareError(message)


def decode_firmware_container(blob: bytes, *, max_output: int = MAX_DECODED_SIZE) -> bytes:
    """Decode one JK AES/zlib container with a strict output bound.

    ``max_output`` is enforced from the declared length before decompression and
    again against actual output.  Padding is removed before zlib processing, so
    any byte after the one complete zlib stream is rejected as trailing data.
    """

    if max_output < 0 or max_output > MAX_DECODED_SIZE:
        raise _error(f"invalid decoded-size limit: {max_output}")
    container_limit = max_output + MAX_CONTAINER_OVERHEAD
    if len(blob) > container_limit:
        raise _error(f"encrypted container exceeds limit {container_limit}")
    if not blob or len(blob) % AES.block_size:
        raise _error("encrypted length must be a non-zero multiple of 16 bytes")

    plaintext = AES.new(FIRMWARE_KEY, AES.MODE_CBC, ZERO_IV).decrypt(blob)
    padding_size = plaintext[-1]
    if not 1 <= padding_size <= AES.block_size:
        raise _error("invalid PKCS#7 padding length")
    if plaintext[-padding_size:] != bytes((padding_size,)) * padding_size:
        raise _error("invalid PKCS#7 padding bytes")

    unpadded = plaintext[:-padding_size]
    if len(unpadded) < 4:
        raise _error("decrypted container is shorter than its size field")
    declared_size = int.from_bytes(unpadded[:4], "little")
    if declared_size > max_output:
        raise _error(f"declared decoded size {declared_size} exceeds limit {max_output}")

    inflater = zlib.decompressobj()
    try:
        # The extra byte lets us distinguish an exact-bound result from output
        # that would exceed it without ever allocating unbounded decompressed data.
        decoded = inflater.decompress(unpadded[4:], max_output + 1)
    except zlib.error as exc:
        raise _error("invalid zlib stream") from exc

    if len(decoded) > max_output or inflater.unconsumed_tail:
        raise _error(f"decoded data exceeds limit {max_output}")
    if not inflater.eof:
        raise _error("incomplete zlib stream")
    if inflater.unused_data:
        raise _error("trailing data follows the zlib stream")
    if len(decoded) != declared_size:
        raise _error(f"declared decoded size {declared_size} does not match actual {len(decoded)}")
    return decoded


def _fixed_ascii(image: bytes, offset: int, label: str) -> str:
    field = image[offset : offset + IDENTITY_FIELD_SIZE]
    if len(field) != IDENTITY_FIELD_SIZE:
        raise _error(f"decoded image is missing {label} at offset 0x{offset:X}")
    terminator = field.find(b"\x00")
    if terminator < 1:
        raise _error(f"decoded {label} is empty or not NUL-terminated")
    try:
        return field[:terminator].decode("ascii")
    except UnicodeDecodeError as exc:
        raise _error(f"decoded {label} is not ASCII") from exc


def _inspect_identity(decoded: bytes) -> tuple[str, str]:
    version = _fixed_ascii(decoded, VERSION_OFFSET, "version").upper()
    if _VERSION_RE.fullmatch(version) is None:
        raise _error(f"decoded firmware version has invalid syntax: {version!r}")

    models = tuple(_fixed_ascii(decoded, offset, f"model field 0x{offset:X}") for offset in MODEL_OFFSETS)
    try:
        canonical_models = tuple(canonicalize_model(model) for model in models)
    except ValueError as exc:
        raise _error(f"decoded firmware model has invalid syntax: {exc}") from exc
    if len(set(canonical_models)) != 1:
        rendered = ", ".join(repr(model) for model in models)
        raise _error(f"decoded firmware model fields conflict: {rendered}")
    return models[0], version


def _validate_profile_image(
    decoded: bytes,
    model: str,
    profile: DeviceProfile,
) -> tuple[int, int, bytes, bytes]:
    if not profile.min_decoded_size <= len(decoded) <= profile.max_decoded_size:
        raise _error(
            f"decoded image size {len(decoded)} is outside profile range "
            f"{profile.min_decoded_size}..{profile.max_decoded_size}"
        )

    canonical_model = canonicalize_model(model)
    if re.fullmatch(profile.model_pattern, canonical_model, flags=re.ASCII) is None:
        raise _error(f"decoded model {model!r} is not supported by profile {profile.name!r}")

    initial_sp = int.from_bytes(decoded[0:4], "little")
    reset_vector = int.from_bytes(decoded[4:8], "little")
    if not profile.sram_start <= initial_sp < profile.sram_end:
        raise _error(f"initial stack pointer 0x{initial_sp:08X} is outside profile SRAM")
    if initial_sp % 4:
        raise _error(f"initial stack pointer 0x{initial_sp:08X} is not word-aligned")
    if reset_vector & 1 == 0:
        raise _error(f"reset vector 0x{reset_vector:08X} does not select Thumb state")
    reset_address = reset_vector & ~1
    if not profile.app_flash_start <= reset_address < profile.app_flash_end:
        raise _error(f"reset vector 0x{reset_vector:08X} is outside application flash")

    transfer_body = decoded[:-TRANSFER_SUFFIX_SIZE]
    suffix = decoded[-TRANSFER_SUFFIX_SIZE:]
    flash_capacity = profile.app_flash_end - profile.app_flash_start
    if len(transfer_body) > flash_capacity:
        raise _error(f"transfer body {len(transfer_body)} bytes exceeds application flash capacity {flash_capacity}")
    validate_transfer_suffix(suffix)
    return initial_sp, reset_vector, transfer_body, suffix


def validate_transfer_suffix(suffix: bytes, *, now_ms: int | None = None) -> tuple[int, int]:
    """Validate the vendor footer: epoch milliseconds and validity hours."""

    if len(suffix) != TRANSFER_SUFFIX_SIZE:
        raise _error("firmware transfer suffix must be exactly 12 bytes")
    timestamp_ms = int.from_bytes(suffix[:8], "little", signed=True)
    validity_hours = int.from_bytes(suffix[8:], "little", signed=True)
    if validity_hours < 0:
        raise _error("firmware validity-hours field must not be negative")
    if validity_hours > 0:
        current = int(time.time() * 1000) if now_ms is None else now_ms
        earliest = timestamp_ms - 7_200_000
        latest = timestamp_ms + validity_hours * 3_600_000
        if timestamp_ms <= 0 or not earliest <= current <= latest:
            raise _error("firmware validity window is not active")
    return timestamp_ms, validity_hours


def inspect_firmware(path: Path, profile: DeviceProfile) -> FirmwareImage:
    """Inspect ``path`` using decoded contents and the supplied profile.

    The suffix and filename are not used as authenticity evidence.  Hashes are
    returned for operator visibility and audit logs only.
    """

    path = Path(path)
    max_output = min(MAX_DECODED_SIZE, profile.max_decoded_size)
    container_limit = max_output + MAX_CONTAINER_OVERHEAD
    try:
        with path.open("rb") as stream:
            container = stream.read(container_limit + 1)
    except OSError as exc:
        raise _error(f"cannot read firmware file {path}: {exc}") from exc

    if len(container) > container_limit:
        raise _error(f"encrypted container exceeds limit {container_limit}")

    decoded = decode_firmware_container(
        container,
        max_output=max_output,
    )
    model, version = _inspect_identity(decoded)
    initial_sp, reset_vector, transfer_body, suffix = _validate_profile_image(decoded, model, profile)
    return FirmwareImage(
        path=path,
        container_sha256=hashlib.sha256(container).hexdigest(),
        decoded_sha256=hashlib.sha256(decoded).hexdigest(),
        decoded=decoded,
        transfer_body=transfer_body,
        suffix=suffix,
        model=model,
        version=version,
        initial_sp=initial_sp,
        reset_vector=reset_vector,
    )


class FirmwareDirectoryRepository:
    """List packaged firmware while permitting inspection of any chosen path."""

    def __init__(self, root: Path, profile: DeviceProfile = JK_GENERIC) -> None:
        self.root = Path(root)
        self.profile = profile

    def list(self) -> tuple[Path, ...]:
        if not self.root.is_dir():
            return ()
        return tuple(
            sorted(
                (path for path in self.root.rglob("*") if path.is_file() and path.suffix.casefold() == ".jkbms"),
                key=lambda path: str(path).casefold(),
            )
        )

    def inspect(self, path: Path) -> FirmwareImage:
        # Deliberately do not constrain custom selections to ``root`` and do not
        # infer anything from the extension or filename.
        return inspect_firmware(Path(path), self.profile)


__all__ = [
    "FIRMWARE_KEY",
    "FirmwareDirectoryRepository",
    "MAX_CONTAINER_OVERHEAD",
    "MAX_DECODED_SIZE",
    "decode_firmware_container",
    "inspect_firmware",
]
