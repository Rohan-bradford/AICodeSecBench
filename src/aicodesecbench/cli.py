from __future__ import annotations

import argparse
from pathlib import Path

from .dataset import load_samples
from .external import (
    load_bandit_findings,
    load_sarif_findings,
    load_semgrep_findings,
    run_bandit,
    run_semgrep,
)
from .patterns import scan_samples
from .report import build_report, write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aicodesecbench",
        description="Static analysis benchmark for AI-attributed code snippets.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="run benchmark analysis")
    run.add_argument("--dataset", type=Path, default=Path("dataset"), help="Dataset directory")
    run.add_argument("--out", type=Path, default=Path("reports"), help="Output report directory")
    run.add_argument("--with-bandit", action="store_true", help="Run Bandit if installed")
    run.add_argument("--with-semgrep", action="store_true", help="Run Semgrep if installed")
    run.add_argument("--semgrep-rules", type=Path, default=Path("rules/semgrep"))
    run.add_argument("--codeql-sarif", type=Path, help="Optional CodeQL SARIF file to import")
    run.add_argument("--fail-on-findings", action="store_true", help="Exit 2 when findings exist")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path.cwd()

    if args.command == "run":
        samples = load_samples(args.dataset)
        findings = scan_samples(samples, repo_root)
        raw_dir = args.out / "raw"

        if args.with_bandit:
            bandit_path = raw_dir / "bandit.json"
            if run_bandit(args.dataset, bandit_path):
                findings.extend(load_bandit_findings(bandit_path, repo_root))

        if args.with_semgrep:
            semgrep_path = raw_dir / "semgrep.json"
            if run_semgrep(args.dataset, args.semgrep_rules, semgrep_path):
                findings.extend(load_semgrep_findings(semgrep_path, repo_root))

        if args.codeql_sarif:
            findings.extend(load_sarif_findings(args.codeql_sarif, repo_root, tool_name="codeql"))

        report = build_report(samples, findings)
        written = write_reports(report, args.out)
        print(f"Analysed {len(samples)} sample file(s).")
        print(f"Findings: {len(findings)}")
        for path in written:
            print(f"Wrote {path}")

        if args.fail_on_findings and findings:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

