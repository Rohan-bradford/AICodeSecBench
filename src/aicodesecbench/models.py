from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Sample:
    sample_id: str
    path: Path
    language: str
    source_label: str
    prompt_family: str
    expected_cwes: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    cwe: str
    language: str
    file: str
    line: int
    severity: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)

