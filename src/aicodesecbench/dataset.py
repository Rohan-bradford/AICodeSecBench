from __future__ import annotations

import json
from pathlib import Path

from .models import Sample


def load_samples(dataset_dir: Path) -> list[Sample]:
    metadata_path = dataset_dir / "metadata.json"
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    samples = []
    for item in data["samples"]:
        samples.append(
            Sample(
                sample_id=item["id"],
                path=dataset_dir / item["path"],
                language=item["language"],
                source_label=item["source_label"],
                prompt_family=item["prompt_family"],
                expected_cwes=tuple(item.get("expected_cwes", [])),
            )
        )
    return samples

