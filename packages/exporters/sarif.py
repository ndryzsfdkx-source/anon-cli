
"""SARIF exporter for iacsec detections."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Iterable, List

from packages.schema.models import Detection, Prediction


_LEVEL_MAP = {
    "low": "note",
    "medium": "warning",
    "high": "error",
}


def to_sarif(
    detections: Iterable[Detection],
    predictions: Iterable[Prediction],
    *,
    tool_name: str = "iacsec",
    tool_version: str = "0.1.0",
) -> Dict[str, object]:
    det_list = list(detections)
    pred_list = list(predictions)
    if len(det_list) != len(pred_list):
        raise ValueError("detections and predictions must be the same length")

    rules = _build_rules(det_list)
    results = _build_results(det_list, pred_list)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "conversion": {
                    "invocationTimeUtc": "1970-01-01T00:00:00Z",
                },
            }
        ],
    }


def _build_rules(detections: List[Detection]) -> Dict[str, Dict[str, object]]:
    rules: Dict[str, Dict[str, object]] = {}
    for det in detections:
        if det.rule_id in rules:
            continue
        rules[det.rule_id] = {
            "id": det.rule_id,
            "name": det.rule_id,
            "shortDescription": {"text": det.message},
            "properties": {
                "smell": det.smell,
                "tech": det.tech,
            },
        }
    return rules


def _build_results(
    detections: List[Detection], predictions: List[Prediction]
) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for det, pred in zip(detections, predictions):
        level = _LEVEL_MAP.get(det.severity, "warning")
        message = det.message
        if pred.rationale:
            message = f"{message} — {pred.rationale}"

        results.append(
            {
                "ruleId": det.rule_id,
                "level": level,
                "message": {"text": message},
                "properties": {
                    "prediction": pred.label,
                    "score": pred.score,
                    "evidence": det.evidence,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": det.file},
                            "region": {"startLine": det.line},
                        }
                    }
                ],
            }
        )
    return results


__all__ = ["to_sarif"]
