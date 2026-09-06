from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from jkflash.domain import DeviceIdentity, FirmwareImage, Severity
from jkflash.profiles import PB_V19
from jkflash.safety import (
    canonicalize_model,
    evaluate_compatibility,
    parse_model_components,
)


def make_device(**changes) -> DeviceIdentity:
    values = {
        "address": 5,
        "model": "JK_PB2A16S30P",
        "max_cells": 16,
        "hardware": "19A",
        "software": "19.31",
        "serial": "serial",
    }
    values.update(changes)
    return DeviceIdentity(**values)


def make_image(**changes) -> FirmwareImage:
    decoded = b"\x00" * 65_537 + b"\x00" * 12
    values = {
        "path": Path("meaningless-name.custom"),
        "container_sha256": "not-an-allowlisted-container-hash",
        "decoded_sha256": "not-an-allowlisted-decoded-hash",
        "decoded": decoded,
        "transfer_body": decoded[:-12],
        "suffix": decoded[-12:],
        "model": "JK-PB2A16S30P",
        "version": "19.34",
        "initial_sp": 0x20001000,
        "reset_vector": 0x08010001,
    }
    values.update(changes)
    return FirmwareImage(**values)


def codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


@pytest.mark.parametrize(
    "model",
    ["JK_PB2A16S30P", "JK-PB2A16S30P", "jk-pb2a16s-30p"],
)
def test_canonicalize_model_allows_only_documented_separator_variants(model):
    assert canonicalize_model(model) == "JKPB2A16S30P"


@pytest.mark.parametrize("model", ["JK", "JK PB", "OTHER-PB2A16S30P", "JK/TEST"])
def test_canonicalize_model_rejects_non_jk_or_non_printable_syntax(model):
    with pytest.raises(ValueError, match="unrecognized JK model"):
        canonicalize_model(model)


@pytest.mark.parametrize("model", ["JKPB2A16S30P", "JK-PB3A16S30P", "JK-BX8S-200P"])
def test_canonicalize_model_accepts_generic_jk_model_spellings(model):
    assert canonicalize_model(model).startswith("JK")


def test_parse_model_components_extracts_all_safety_capabilities():
    components = parse_model_components("JK-PB1A24S-15P")
    assert components.canonical == "JKPB1A24S15P"
    assert components.family == "JKPB"
    assert components.balancing_current_amps == 1
    assert components.max_cells == 24
    assert components.current_class == 15

    with pytest.raises(ValueError, match="zero capability"):
        parse_model_components("JK-PB2A0S30P")


def test_exact_canonical_model_and_arbitrary_hashes_are_compatible():
    report = evaluate_compatibility(make_device(), make_image(), PB_V19)
    assert report.allowed
    assert report.issues == ()


def test_current_class_difference_is_a_hard_model_mismatch():
    report = evaluate_compatibility(make_device(model="JK-PB2A16S20P"), make_image(), PB_V19)
    assert not report.allowed
    assert "model_mismatch" in codes(report)


def test_invalid_device_and_firmware_models_are_reported_not_raised():
    report = evaluate_compatibility(make_device(model="fuzzy model"), make_image(model="wrong image"), PB_V19)
    assert {"device_model_invalid", "firmware_model_invalid"} <= codes(report)
    assert not report.allowed


def test_model_cell_count_must_match_device_and_profile_capability():
    device_mismatch = evaluate_compatibility(make_device(max_cells=15), make_image(), PB_V19)
    assert "device_cell_count_mismatch" in codes(device_mismatch)
    assert not device_mismatch.allowed

    eight_cell_profile = replace(PB_V19, max_supported_cells=8)
    unsupported = evaluate_compatibility(make_device(), make_image(), eight_cell_profile)
    assert "cell_count_not_supported" in codes(unsupported)
    assert not unsupported.allowed


@pytest.mark.parametrize(
    ("device_changes", "image_changes", "expected"),
    [
        ({"hardware": "15A"}, {}, "device_major_mismatch"),
        ({"software": "15.4"}, {}, "device_major_mismatch"),
        ({}, {"version": "15.9"}, "firmware_hardware_major_mismatch"),
        ({"hardware": "bad"}, {}, "hardware_version_invalid"),
        ({"software": "19"}, {}, "device_software_version_invalid"),
        ({}, {"version": "release"}, "firmware_version_invalid"),
    ],
)
def test_hardware_and_release_fields_are_validated_without_a_v19_gate(device_changes, image_changes, expected):
    report = evaluate_compatibility(make_device(**device_changes), make_image(**image_changes), PB_V19)
    assert expected in codes(report)
    assert not report.allowed


def test_profile_model_pattern_is_data_driven():
    restricted = replace(PB_V19, model_pattern=r"JKPB1A\d+S\d+P")
    report = evaluate_compatibility(make_device(), make_image(), restricted)
    assert {"model_not_supported", "firmware_model_not_supported"} <= codes(report)
    assert not report.allowed


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        (make_image(initial_sp=0x10000000), "initial_sp_invalid"),
        (make_image(reset_vector=0x08010000), "reset_vector_not_thumb"),
        (make_image(reset_vector=0x09000001), "reset_vector_out_of_range"),
        (make_image(decoded=b"short"), "image_size_out_of_range"),
        (make_image(suffix=b"short"), "firmware_suffix_invalid"),
        (make_image(transfer_body=b"wrong"), "transfer_body_invalid"),
    ],
)
def test_forged_firmware_image_cannot_bypass_image_sanity(image, expected):
    report = evaluate_compatibility(make_device(), image, PB_V19)
    assert expected in codes(report)
    assert not report.allowed


def test_128_byte_aligned_transfer_body_is_accepted_with_a_full_final_packet():
    body = b"\x00" * 65_536
    suffix = b"\x00" * 12
    image = make_image(decoded=body + suffix, transfer_body=body, suffix=suffix)
    report = evaluate_compatibility(make_device(), image, PB_V19)
    assert report.allowed


def test_downgrade_requires_explicit_confirmation_then_is_allowed_with_a_warning():
    unconfirmed = evaluate_compatibility(make_device(software="19.34"), make_image(version="19.27"), PB_V19)
    assert not unconfirmed.allowed
    assert "downgrade_confirmation_required" in codes(unconfirmed)

    confirmed = evaluate_compatibility(
        make_device(software="19.34"),
        make_image(version="19.27"),
        PB_V19,
        downgrade_confirmed=True,
    )
    assert confirmed.allowed
    downgrade = next(issue for issue in confirmed.issues if issue.code == "downgrade")
    assert downgrade.severity is Severity.WARNING


def test_lettered_release_compares_by_numeric_components() -> None:
    image = make_image(version="19.31B")
    device = make_device(software="19.31")
    blocked = evaluate_compatibility(device, image, PB_V19)
    assert "reinstall_confirmation_required" in codes(blocked)

    confirmed = evaluate_compatibility(
        device,
        image,
        PB_V19,
        same_version_confirmed=True,
    )
    assert confirmed.allowed
    assert "reinstall" in codes(confirmed)


def test_transfer_body_cannot_exceed_profile_application_flash_region():
    capacity = PB_V19.app_flash_end - PB_V19.app_flash_start
    body = b"\x00" * (capacity + 1)
    suffix = b"\x00" * 12
    roomy_profile = replace(PB_V19, max_decoded_size=len(body) + len(suffix))
    oversized = make_image(
        decoded=body + suffix,
        transfer_body=body,
        suffix=suffix,
        version="19.35",
    )

    report = evaluate_compatibility(make_device(), oversized, roomy_profile)

    assert not report.allowed
    assert "transfer_body_exceeds_flash" in codes(report)


def test_same_version_requires_explicit_confirmation_then_remains_visible_as_warning():
    device = make_device(software="19.34")
    image = make_image(version="19.34")

    unconfirmed = evaluate_compatibility(device, image, PB_V19)
    assert not unconfirmed.allowed
    assert "reinstall_confirmation_required" in codes(unconfirmed)

    confirmed = evaluate_compatibility(device, image, PB_V19, same_version_confirmed=True)
    assert confirmed.allowed
    reinstall = next(issue for issue in confirmed.issues if issue.code == "reinstall")
    assert reinstall.severity is Severity.WARNING
