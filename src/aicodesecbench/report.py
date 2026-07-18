from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, Sample


def summarize(samples: list[Sample], findings: list[Finding]) -> dict:
    by_language = defaultdict(lambda: {"files": 0, "findings": 0, "cwes": Counter()})
    for sample in samples:
        by_language[sample.language]["files"] += 1
    for finding in findings:
        item = by_language[finding.language]
        item["findings"] += 1
        item["cwes"][finding.cwe] += 1

    return {
        "files": len(samples),
        "findings": len(findings),
        "unique_cwes": len({finding.cwe for finding in findings}),
        "by_language": {
            language: {
                "files": value["files"],
                "findings": value["findings"],
                "findings_per_file": round(value["findings"] / value["files"], 2)
                if value["files"]
                else 0,
                "top_cwes": dict(value["cwes"].most_common(5)),
            }
            for language, value in sorted(by_language.items())
        },
        "by_tool": dict(Counter(finding.tool for finding in findings)),
        "by_cwe": dict(Counter(finding.cwe for finding in findings).most_common()),
    }


def build_report(samples: list[Sample], findings: list[Finding]) -> dict:
    return {
        "tool": {"name": "AICodeSecBench", "version": "0.1.0"},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "type": "synthetic-ai-attributed",
            "files": [
                {
                    "id": sample.sample_id,
                    "path": str(sample.path).replace("\\", "/"),
                    "language": sample.language,
                    "source_label": sample.source_label,
                    "prompt_family": sample.prompt_family,
                    "expected_cwes": list(sample.expected_cwes),
                }
                for sample in samples
            ],
        },
        "summary": summarize(samples, findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def markdown_report(report: dict) -> str:
    lines = [
        "# AICodeSecBench Report",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "## Summary",
        "",
        f"- Dataset type: `{report['dataset']['type']}`",
        f"- Files: `{report['summary']['files']}`",
        f"- Findings: `{report['summary']['findings']}`",
        f"- Unique CWEs: `{report['summary']['unique_cwes']}`",
        "",
        "## Findings By Language",
        "",
        "Language | Files | Findings | Findings/File | Top CWEs",
        "--- | --- | --- | --- | ---",
    ]
    for language, item in report["summary"]["by_language"].items():
        top_cwes = ", ".join(f"{cwe}: {count}" for cwe, count in item["top_cwes"].items()) or "-"
        lines.append(
            f"{language} | {item['files']} | {item['findings']} | "
            f"{item['findings_per_file']} | {top_cwes}"
        )

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "Tool | CWE | Language | Severity | Location | Message",
            "--- | --- | --- | --- | --- | ---",
        ]
    )
    for finding in report["findings"]:
        lines.append(
            " | ".join(
                [
                    finding["tool"],
                    finding["cwe"],
                    finding["language"],
                    str(finding["severity"]),
                    f"`{finding['file']}:{finding['line']}`",
                    finding["message"].replace("|", "\\|"),
                ]
            )
        )
    return "\n".join(lines) + "\n"


def html_dashboard(report: dict) -> str:
    cards = [
        ("Files", report["summary"]["files"]),
        ("Findings", report["summary"]["findings"]),
        ("Unique CWEs", report["summary"]["unique_cwes"]),
        ("Languages", len(report["summary"]["by_language"])),
    ]
    rows = "\n".join(
        f"<tr><td>{escape(lang)}</td><td>{v['files']}</td><td>{v['findings']}</td>"
        f"<td>{v['findings_per_file']}</td><td>{escape(v['top_cwes'])}</td></tr>"
        for lang, v in report["summary"]["by_language"].items()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AICodeSecBench Dashboard</title>
  <style>
    body {{ margin:0; font-family:Segoe UI,Arial,sans-serif; background:#0f172a; color:#e2e8f0; }}
    header {{ padding:32px 42px; background:#111827; border-bottom:1px solid #334155; }}
    main {{ padding:32px 42px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:28px; }}
    .card {{ background:#1e293b; border:1px solid #334155; border-radius:14px; padding:18px; }}
    .card strong {{ display:block; font-size:34px; margin-top:8px; }}
    table {{ width:100%; border-collapse:collapse; background:#111827; border-radius:14px; overflow:hidden; }}
    th,td {{ text-align:left; padding:12px 14px; border-bottom:1px solid #253145; }}
    th {{ background:#1e293b; color:#cbd5e1; }}
  </style>
</head>
<body>
  <header>
    <h1>AICodeSecBench Dashboard</h1>
    <p>Static analysis comparison for a synthetic AI-attributed code dataset.</p>
  </header>
  <main>
    <section class="grid">
      {''.join(f"<div class='card'>{escape(label)}<strong>{value}</strong></div>" for label, value in cards)}
    </section>
    <table>
      <thead><tr><th>Language</th><th>Files</th><th>Findings</th><th>Findings/File</th><th>Top CWEs</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </main>
</body>
</html>"""


def escape(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_reports(report: dict, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "aicodesecbench-report.json"
    md_path = output_dir / "aicodesecbench-report.md"
    html_path = output_dir / "aicodesecbench-dashboard.html"
    csv_path = output_dir / "aicodesecbench-findings.csv"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown_report(report), encoding="utf-8")
    html_path.write_text(html_dashboard(report), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["tool", "rule_id", "cwe", "language", "file", "line", "severity", "message"])
        for finding in report["findings"]:
            writer.writerow(
                [
                    finding["tool"],
                    finding["rule_id"],
                    finding["cwe"],
                    finding["language"],
                    finding["file"],
                    finding["line"],
                    finding["severity"],
                    finding["message"],
                ]
            )
    return [json_path, md_path, html_path, csv_path]

