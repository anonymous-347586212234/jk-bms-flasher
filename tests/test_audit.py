from jkflash.audit import AuditRecord, masked_identifier, transcript_path, write_audit


def test_identifier_is_stable_and_not_disclosed() -> None:
    secret = "DEVICE-SERIAL-SENTINEL"
    masked = masked_identifier(secret)
    assert masked == masked_identifier(secret)
    assert secret not in masked
    assert len(masked) == 12
    assert masked_identifier("") == ""


def test_audit_only_writes_allowlisted_fields(tmp_path) -> None:
    output = tmp_path / "nested" / "audit.jsonl"
    write_audit(output, [AuditRecord(event="block_ack", model="JKPB", packet=3)])
    text = output.read_text(encoding="utf-8")
    assert "block_ack" in text
    assert '"packet": 3' in text
    assert "serial" not in text.lower()


def test_transcript_name_contains_only_timestamp_and_hash(tmp_path) -> None:
    path = transcript_path(tmp_path, "a" * 64)
    assert path.parent == tmp_path
    assert path.name.startswith("flash-")
    assert path.name.endswith("-aaaaaaaaaaaa.jsonl")
    assert transcript_path(tmp_path, "").name.endswith("-unknown.jsonl")
