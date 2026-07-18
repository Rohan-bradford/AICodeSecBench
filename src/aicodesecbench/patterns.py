from __future__ import annotations

import re
from os import PathLike
from pathlib import Path

from .models import Finding, Sample


RULES = {
    "python": [
        (
            "PY-SHELL-TRUE",
            "CWE-78",
            "high",
            re.compile(r"subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True", re.S),
            "subprocess call uses shell=True",
        ),
        (
            "PY-SQL-FSTRING",
            "CWE-89",
            "high",
            re.compile(r"\.execute\(\s*f[\"']", re.S),
            "SQL query built with an f-string",
        ),
        (
            "PY-FLASK-DEBUG",
            "CWE-489",
            "medium",
            re.compile(r"\.run\([^)]*debug\s*=\s*True", re.S),
            "Flask debug mode enabled",
        ),
        (
            "PY-HARDCODED-SECRET",
            "CWE-798",
            "high",
            re.compile(r"(api[_-]?key|secret|password)\s*=\s*[\"'][^\"']{8,}[\"']", re.I),
            "hardcoded credential-like value",
        ),
        (
            "PY-WEAK-HASH",
            "CWE-327",
            "medium",
            re.compile(r"hashlib\.(md5|sha1)\("),
            "weak hash algorithm",
        ),
        (
            "PY-PICKLE-LOADS",
            "CWE-502",
            "high",
            re.compile(r"pickle\.loads?\("),
            "unsafe pickle deserialization",
        ),
    ],
    "javascript": [
        (
            "JS-CHILD-EXEC",
            "CWE-78",
            "high",
            re.compile(r"child_process\.(exec|execSync)\("),
            "child_process exec with command string",
        ),
        (
            "JS-EVAL",
            "CWE-95",
            "high",
            re.compile(r"\beval\s*\("),
            "eval executes dynamic code",
        ),
        (
            "JS-XSS-INNERHTML",
            "CWE-79",
            "medium",
            re.compile(r"\.innerHTML\s*="),
            "innerHTML assignment can introduce XSS",
        ),
        (
            "JS-HARDCODED-SECRET",
            "CWE-798",
            "high",
            re.compile(r"(apiKey|secret|password)\s*=\s*[\"'][^\"']{8,}[\"']", re.I),
            "hardcoded credential-like value",
        ),
    ],
    "typescript": [
        (
            "TS-CHILD-EXEC",
            "CWE-78",
            "high",
            re.compile(r"execSync\("),
            "execSync with command string",
        ),
        (
            "TS-ANY-PARSER",
            "CWE-20",
            "medium",
            re.compile(r":\s*any\b"),
            "unvalidated any-typed input",
        ),
        (
            "TS-HARDCODED-SECRET",
            "CWE-798",
            "high",
            re.compile(r"(apiKey|secret|password)\s*(?::\s*[\w<>\[\]]+)?\s*=\s*[\"'][^\"']{8,}[\"']", re.I),
            "hardcoded credential-like value",
        ),
    ],
}


def line_for_offset(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def scan_sample(sample: Sample, repo_root: PathLike) -> list[Finding]:
    source = sample.path.read_text(encoding="utf-8")
    sample_path = sample.path.resolve()
    root_path = Path(repo_root).resolve()
    try:
        relative = str(sample_path.relative_to(root_path)).replace("\\", "/")
    except ValueError:
        relative = str(sample.path).replace("\\", "/")
    findings: list[Finding] = []
    for rule_id, cwe, severity, pattern, message in RULES.get(sample.language, []):
        for match in pattern.finditer(source):
            findings.append(
                Finding(
                    tool="internal-patterns",
                    rule_id=rule_id,
                    cwe=cwe,
                    language=sample.language,
                    file=relative,
                    line=line_for_offset(source, match.start()),
                    severity=severity,
                    message=message,
                )
            )
    return findings


def scan_samples(samples: list[Sample], repo_root: PathLike) -> list[Finding]:
    findings: list[Finding] = []
    for sample in samples:
        findings.extend(scan_sample(sample, repo_root))
    return findings
