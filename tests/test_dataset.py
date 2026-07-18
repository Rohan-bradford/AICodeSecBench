from pathlib import Path

from aicodesecbench.dataset import load_samples


def test_load_samples() -> None:
    samples = load_samples(Path("dataset"))
    assert len(samples) == 5
    assert {sample.language for sample in samples} == {"python", "javascript", "typescript"}

