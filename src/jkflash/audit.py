"""Privacy-preserving operational event records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AuditRecord:
    event: str
    model: str = ""
    hardware: str = ""
    software: str = ""
    firmware_sha256: str = ""
    packet: int | None = None
    status: str = ""
    timestamp_utc: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


def masked_identifier(value: str) -> str:
    """Return a stable, non-reversible short identifier for in-memory identity."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def write_audit(path: Path, records: Iterable[AuditRecord]) -> None:
    """Write records containing only explicitly allow-listed fields."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(asdict(record), sort_keys=True) + "\n")


def transcript_path(directory: Path, firmware_sha256: str) -> Path:
    """Create a non-identifying, collision-resistant transcript filename."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    digest = firmware_sha256[:12] if firmware_sha256 else "unknown"
    return directory / f"flash-{stamp}-{digest}.jsonl"
