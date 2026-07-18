from pathlib import Path

from aicodesecbench.dataset import load_samples
from aicodesecbench.patterns import scan_samples
from aicodesecbench.report import build_report, markdown_report


def test_report_groups_by_language() -> None:
    samples = load_samples(Path("dataset"))
    findings = scan_samples(samples, Path.cwd())
    report = build_report(samples, findings)
    assert report["summary"]["by_language"]["python"]["findings"] > 0
    assert "Findings By Language" in markdown_report(report)

