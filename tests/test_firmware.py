from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import replace
from pathlib import Path

import pytest
from Crypto.Cipher import AES

from jkflash.domain import FirmwareError
from jkflash.firmware import (
    FIRMWARE_KEY,
    MAX_CONTAINER_OVERHEAD,
    MAX_DECODED_SIZE,
    FirmwareDirectoryRepository,
    decode_firmware_container,
    inspect_firmware,
    validate_transfer_suffix,
)
from jkflash.profiles import PB_V19

ZERO_IV = b"\x00" * 16
MODEL_OFFSETS = (0x250, 0x280, 0x2A8)


def _field(image: bytearray, offset: int, value: str) -> None:
    encoded = value.encode("ascii")
    assert len(encoded) < 16
    image[offset : offset + 16] = encoded + b"\x00" * (16 - len(encoded))


def make_image(
    *,
    size: int = 65_549,
    model: str = "JK-PB2A16S30P",
    version: str = "19.34",
    initial_sp: int = 0x20001000,
    reset_vector: int = 0x08010001,
    suffix: bytes = b"\x00" * 12,
) -> bytes:
    assert len(suffix) == 12
    image = bytearray(size)
    struct.pack_into("<II", image, 0, initial_sp, reset_vector)
    _field(image, 0x200, version)
    for offset in MODEL_OFFSETS:
        _field(image, offset, model)
    image[-12:] = suffix
    return bytes(image)


def _encrypt_unpadded(unpadded: bytes) -> bytes:
    padding_size = 16 - len(unpadded) % 16
    plaintext = unpadded + bytes((padding_size,)) * padding_size
    return AES.new(FIRMWARE_KEY, AES.MODE_CBC, ZERO_IV).encrypt(plaintext)


def make_container(image: bytes) -> bytes:
    return _encrypt_unpadded(len(image).to_bytes(4, "little") + zlib.compress(image, 9))


def write_container(path: Path, image: bytes) -> bytes:
    container = make_container(image)
    path.write_bytes(container)
    return container


def test_inspect_accepts_structural_profile_match_with_no_expiry_footer(tmp_path):
    image_bytes = make_image(suffix=b"\x00" * 12)
    path = tmp_path / "deliberately-unrelated-name.bin"
    container = write_container(path, image_bytes)

    image = inspect_firmware(path, PB_V19)

    assert image.path == path
    assert image.model == "JK-PB2A16S30P"
    assert image.version == "19.34"
    assert image.decoded == image_bytes
    assert image.transfer_body == image_bytes[:-12]
    assert image.suffix == b"\x00" * 12
    assert image.initial_sp == 0x20001000
    assert image.reset_vector == 0x08010001
    assert image.container_sha256 == hashlib.sha256(container).hexdigest()
    assert image.decoded_sha256 == hashlib.sha256(image_bytes).hexdigest()


def test_all_supplied_releases_including_19_34_are_accepted():
    root = Path(__file__).resolve().parents[1] / "implementation_details" / "firmware" / "JK-PB2A16S30P"
    versions = []
    for path in sorted(root.glob("*.jkbms")):
        versions.append(inspect_firmware(path, PB_V19).version)
    assert versions == ["19.27", "19.31", "19.34"]


def test_letter_suffixed_embedded_version_is_accepted(tmp_path):
    path = tmp_path / "lettered.jkbms"
    write_container(path, make_image(version="19.31B"))
    assert inspect_firmware(path, PB_V19).version == "19.31B"


def test_repository_lists_root_recursively_and_inspects_arbitrary_custom_path(tmp_path):
    root = tmp_path / "packaged"
    nested = root / "nested"
    nested.mkdir(parents=True)
    first = root / "a.JKBMS"
    second = nested / "B.jkbms"
    ignored = root / "notes.txt"
    first.write_bytes(b"listed only")
    second.write_bytes(b"listed only")
    ignored.write_bytes(b"not firmware")
    custom = tmp_path / "outside.custom"
    write_container(custom, make_image())

    repository = FirmwareDirectoryRepository(root, PB_V19)

    assert repository.list() == (first, second)
    assert repository.inspect(custom).version == "19.34"
    assert FirmwareDirectoryRepository(tmp_path / "missing").list() == ()


@pytest.mark.parametrize("blob", [b"", b"not block aligned"])
def test_decode_rejects_empty_or_non_block_aligned_ciphertext(blob):
    with pytest.raises(FirmwareError, match="non-zero multiple of 16"):
        decode_firmware_container(blob)


def test_decode_rejects_invalid_pkcs7_padding():
    valid = make_container(make_image())
    plaintext = bytearray(AES.new(FIRMWARE_KEY, AES.MODE_CBC, ZERO_IV).decrypt(valid))
    plaintext[-1] = 0
    malformed = AES.new(FIRMWARE_KEY, AES.MODE_CBC, ZERO_IV).encrypt(plaintext)

    with pytest.raises(FirmwareError, match="PKCS#7"):
        decode_firmware_container(malformed)


def test_decode_rejects_inconsistent_pkcs7_bytes_and_too_short_plaintext():
    bad_padding = AES.new(FIRMWARE_KEY, AES.MODE_CBC, ZERO_IV).encrypt(b"\x00" * 14 + b"\x01\x02")
    with pytest.raises(FirmwareError, match="padding bytes"):
        decode_firmware_container(bad_padding)

    with pytest.raises(FirmwareError, match="shorter than its size field"):
        decode_firmware_container(_encrypt_unpadded(b"abc"))


def test_decode_rejects_invalid_zlib_and_actual_output_over_limit():
    with pytest.raises(FirmwareError, match="invalid zlib"):
        decode_firmware_container(_encrypt_unpadded(b"\x00\x00\x00\x00not-zlib"))

    actual = b"x" * 101
    declares_only_100 = _encrypt_unpadded((100).to_bytes(4, "little") + zlib.compress(actual))
    with pytest.raises(FirmwareError, match="decoded data exceeds limit"):
        decode_firmware_container(declares_only_100, max_output=100)


def test_decode_rejects_incomplete_zlib_stream():
    image = make_image()
    compressed = zlib.compress(image)[:-1]
    malformed = _encrypt_unpadded(len(image).to_bytes(4, "little") + compressed)

    with pytest.raises(FirmwareError, match="incomplete zlib"):
        decode_firmware_container(malformed)


def test_decode_rejects_any_material_after_zlib_and_before_padding():
    image = make_image()
    malformed = _encrypt_unpadded(len(image).to_bytes(4, "little") + zlib.compress(image) + b"trailing")

    with pytest.raises(FirmwareError, match="trailing data"):
        decode_firmware_container(malformed)


def test_decode_rejects_declared_size_mismatch():
    image = make_image()
    malformed = _encrypt_unpadded((len(image) - 1).to_bytes(4, "little") + zlib.compress(image))

    with pytest.raises(FirmwareError, match="does not match actual"):
        decode_firmware_container(malformed)


def test_decode_enforces_global_and_caller_output_limits_before_inflation():
    global_overrun = _encrypt_unpadded((MAX_DECODED_SIZE + 1).to_bytes(4, "little") + zlib.compress(b""))
    with pytest.raises(FirmwareError, match="exceeds limit"):
        decode_firmware_container(global_overrun)

    image = make_image()
    with pytest.raises(FirmwareError, match="exceeds limit"):
        decode_firmware_container(make_container(image), max_output=len(image) - 1)
    with pytest.raises(FirmwareError, match="invalid decoded-size limit"):
        decode_firmware_container(make_container(image), max_output=MAX_DECODED_SIZE + 1)

    with pytest.raises(FirmwareError, match="encrypted container exceeds limit"):
        decode_firmware_container(b"\x00" * (MAX_CONTAINER_OVERHEAD + 16), max_output=0)


def test_inspect_rejects_conflicting_embedded_models(tmp_path):
    image = bytearray(make_image())
    _field(image, 0x280, "JK-PB2A16S20P")
    path = tmp_path / "firmware"
    write_container(path, bytes(image))

    with pytest.raises(FirmwareError, match="model fields conflict"):
        inspect_firmware(path, PB_V19)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (b"\x00" * 16, "empty or not NUL-terminated"),
        (b"A" * 16, "empty or not NUL-terminated"),
        (b"\xff\x00" + b"\x00" * 14, "not ASCII"),
        (b"NOT-A-JK-MODEL\x00\x00", "model has invalid syntax"),
    ],
)
def test_inspect_rejects_malformed_fixed_model_fields(tmp_path, replacement, message):
    assert len(replacement) == 16
    image = bytearray(make_image())
    image[0x250:0x260] = replacement
    path = tmp_path / "firmware"
    write_container(path, bytes(image))

    with pytest.raises(FirmwareError, match=message):
        inspect_firmware(path, PB_V19)


def test_inspect_rejects_image_truncated_inside_last_model_field(tmp_path):
    image = bytearray(make_image())[: 0x2A8 + 15]
    path = tmp_path / "firmware"
    write_container(path, bytes(image))
    permissive_size_profile = replace(PB_V19, min_decoded_size=0)

    with pytest.raises(FirmwareError, match="missing model field 0x2A8"):
        inspect_firmware(path, permissive_size_profile)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: _field(data, 0x200, "release19"), "version has invalid syntax"),
        (lambda data: struct.pack_into("<I", data, 0, 0x10001000), "outside profile SRAM"),
        (lambda data: struct.pack_into("<I", data, 0, 0x20001002), "not word-aligned"),
        (lambda data: struct.pack_into("<I", data, 4, 0x08010000), "Thumb state"),
        (lambda data: struct.pack_into("<I", data, 4, 0x09000001), "application flash"),
    ],
)
def test_inspect_rejects_invalid_identity_or_vectors(tmp_path, mutation, message):
    image = bytearray(make_image())
    mutation(image)
    path = tmp_path / "firmware"
    write_container(path, bytes(image))

    with pytest.raises(FirmwareError, match=message):
        inspect_firmware(path, PB_V19)


def test_inspect_enforces_profile_model_and_size(tmp_path):
    path = tmp_path / "firmware"
    write_container(path, make_image())
    wrong_family = replace(PB_V19, model_pattern=r"OTHER")
    with pytest.raises(FirmwareError, match="not supported by profile"):
        inspect_firmware(path, wrong_family)

    too_small = replace(PB_V19, min_decoded_size=70_000)
    with pytest.raises(FirmwareError, match="outside profile range"):
        inspect_firmware(path, too_small)


def test_inspect_accepts_body_exactly_divisible_by_128(tmp_path):
    image = make_image(size=65_536 + 12)
    assert len(image[:-12]) % 128 == 0
    path = tmp_path / "firmware"
    write_container(path, image)

    inspected = inspect_firmware(path, PB_V19)
    assert len(inspected.transfer_body) % 128 == 0


def test_inspect_rejects_transfer_body_larger_than_application_flash_region(
    tmp_path,
):
    capacity = PB_V19.app_flash_end - PB_V19.app_flash_start
    image = make_image(size=capacity + 1 + 12)
    roomy_profile = replace(PB_V19, max_decoded_size=len(image))
    path = tmp_path / "oversized-transfer.jkbms"
    write_container(path, image)

    with pytest.raises(FirmwareError, match="exceeds application flash capacity"):
        inspect_firmware(path, roomy_profile)


def test_transfer_footer_validity_rules_cover_no_expiry_expired_negative_and_live_windows() -> None:
    assert validate_transfer_suffix(b"\x00" * 12, now_ms=0) == (0, 0)
    with pytest.raises(FirmwareError, match="must not be negative"):
        validate_transfer_suffix((1).to_bytes(8, "little", signed=True) + (-1).to_bytes(4, "little", signed=True))
    with pytest.raises(FirmwareError, match="not active"):
        validate_transfer_suffix(
            (1).to_bytes(8, "little", signed=True) + (1).to_bytes(4, "little", signed=True),
            now_ms=10_000_000,
        )
    timestamp = 1_700_000_000_000
    suffix = timestamp.to_bytes(8, "little", signed=True) + (24).to_bytes(4, "little", signed=True)
    assert validate_transfer_suffix(suffix, now_ms=timestamp + 3_600_000) == (timestamp, 24)


def test_inspect_wraps_file_errors(tmp_path):
    with pytest.raises(FirmwareError, match="cannot read firmware file"):
        inspect_firmware(tmp_path / "missing", PB_V19)


def test_inspect_reads_container_with_a_profile_driven_bound(tmp_path):
    path = tmp_path / "oversized"
    path.write_bytes(b"\x00" * (MAX_CONTAINER_OVERHEAD + 17))
    tiny_profile = replace(PB_V19, min_decoded_size=0, max_decoded_size=0)
    with pytest.raises(FirmwareError, match="encrypted container exceeds limit"):
        inspect_firmware(path, tiny_profile)
