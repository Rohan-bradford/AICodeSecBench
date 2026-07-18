from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import Finding

BANDIT_CWE_MAP = {
    "B102": "CWE-78",
    "B105": "CWE-798",
    "B106": "CWE-798",
    "B303": "CWE-327",
    "B301": "CWE-502",
    "B602": "CWE-78",
    "B608": "CWE-89",
  }


def run_command(command: list[str], cwd: Path) -> tuple[int, str, str]:
    process = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    return process.returncode, process.stdout, process.stderr


def run_bandit(dataset_dir: Path, output_path: Path) -> bool:
    if shutil.which("bandit") is None:
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    code, stdout, stderr = run_command(
        ["bandit", "-r", str(dataset_dir), "-f", "json", "-o", str(output_path)],
        cwd=dataset_dir.parent,
    )
    if not output_path.exists() and stdout:
        output_path.write_text(stdout, encoding="utf-8")
    return code in {0, 1} or output_path.exists() or bool(stderr)


def run_semgrep(dataset_dir: Path, rules_dir: Path, output_path: Path) -> bool:
    if shutil.which("semgrep") is None:
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    code, stdout, _stderr = run_command(
        [
            "semgrep",
            "scan",
            "--config",
            str(rules_dir),
            "--json",
            "--output",
            str(output_path),
            str(dataset_dir),
        ],
        cwd=dataset_dir.parent,
    )
    if not output_path.exists() and stdout:
        output_path.write_text(stdout, encoding="utf-8")
    return code in {0, 1} or output_path.exists()


def load_bandit_findings(path: Path, repo_root: Path) -> list[Finding]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for item in data.get("results", []):
        filename = str(Path(item["filename"]))
        language = "python"
        test_id = item.get("test_id", "bandit")
        findings.append(
            Finding(
                tool="bandit",
                rule_id=test_id,
                cwe=BANDIT_CWE_MAP.get(test_id, "CWE-unknown"),
                language=language,
                file=relative_path(filename, repo_root),
                line=int(item.get("line_number", 1)),
                severity=str(item.get("issue_severity", "unknown")).lower(),
                message=item.get("issue_text", ""),
            )
        )
    return findings


def load_semgrep_findings(path: Path, repo_root: Path) -> list[Finding]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(
            Finding(
                tool="semgrep",
                rule_id=item.get("check_id", "semgrep"),
                cwe=metadata.get("cwe", "CWE-unknown"),
                language=metadata.get("language", language_from_file(item.get("path", ""))),
                file=relative_path(item.get("path", ""), repo_root),
                line=int(item.get("start", {}).get("line", 1)),
                severity=str(extra.get("severity", "INFO")).lower(),
                message=extra.get("message", ""),
            )
        )
    return findings


def load_sarif_findings(path: Path, repo_root: Path, tool_name: str = "codeql") -> list[Finding]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules = {
            rule.get("id"): rule
            for tool in [run.get("tool", {})]
            for driver in [tool.get("driver", {})]
            for rule in driver.get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "sarif")
            rule = rules.get(rule_id, {})
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = location.get("artifactLocation", {}).get("uri", "")
            region = location.get("region", {})
            properties = rule.get("properties", {})
            tags = properties.get("tags", [])
            cwe = next((tag.upper() for tag in tags if str(tag).lower().startswith("cwe-")), "CWE-unknown")
            findings.append(
                Finding(
                    tool=tool_name,
                    rule_id=rule_id,
                    cwe=cwe,
                    language=language_from_file(artifact),
                    file=relative_path(artifact, repo_root),
                    line=int(region.get("startLine", 1)),
                    severity=properties.get("security-severity", result.get("level", "warning")),
                    message=result.get("message", {}).get("text", rule.get("shortDescription", {}).get("text", "")),
                )
            )
    return findings


def language_from_file(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    return "unknown"


def relative_path(path: str, repo_root: Path) -> str:
    candidate = Path(path)
    try:
        return str(candidate.resolve().relative_to(repo_root.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        return str(candidate).replace("\\", "/")

