from pathlib import Path

from aicodesecbench.dataset import load_samples
from aicodesecbench.patterns import scan_samples


def test_internal_patterns_find_expected_cwes() -> None:
    samples = load_samples(Path("dataset"))
    findings = scan_samples(samples, Path.cwd())
    cwes = {finding.cwe for finding in findings}
    assert {"CWE-78", "CWE-89", "CWE-798", "CWE-502", "CWE-79"}.issubset(cwes)
    assert len(findings) >= 10

