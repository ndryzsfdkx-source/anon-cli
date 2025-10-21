"""Write detections and predictions as JSON Lines records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from packages.schema.models import Detection, Prediction


def write_jsonl(
    path: Path,
    detections: Iterable[Detection],
    predictions: Iterable[Prediction],
    threshold: float,
    model_name: str,
) -> None:
    det_list = list(detections)
    pred_list = list(predictions)
    if len(det_list) != len(pred_list):
        raise ValueError("detections and predictions must be the same length")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for det, pred in zip(det_list, pred_list):
            record = {
                "detection": det.model_dump(),
                "prediction": pred.model_dump(),
                "threshold": threshold,
                "model": model_name,
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


__all__ = ["write_jsonl"]
