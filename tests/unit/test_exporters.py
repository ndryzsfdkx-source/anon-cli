
import json
from pathlib import Path

import pytest

from packages.exporters.jsonl import write_jsonl
from packages.exporters.sarif import to_sarif
from packages.exporters.csv import write_csv
from packages.schema.models import Detection, Prediction


def sample_detection(**overrides):
    data = {
        "rule_id": "HTTP_NO_TLS",
        "smell": "http",
        "tech": "ansible",
        "file": "roles/web/tasks/main.yml",
        "line": 12,
        "snippet": "get_url: url=http://example",
        "message": "HTTP used without TLS",
        "severity": "medium",
        "evidence": {"keys": ["url"]},
    }
    data.update(overrides)
    return Detection(**data)


def sample_prediction(**overrides):
    data = {"label": "TP", "score": 0.9, "rationale": "score>=threshold"}
    data.update(overrides)
    return Prediction(**data)


def test_write_jsonl(tmp_path):
    detections = [sample_detection()]
    predictions = [sample_prediction()]
    out = tmp_path / "out.jsonl"

    write_jsonl(out, detections, predictions, threshold=0.62, model_name="IntelliSA-220m")

    lines = out.read_text().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["threshold"] == 0.62
    assert payload["model"] == "IntelliSA-220m"
    assert payload["detection"]["rule_id"] == "HTTP_NO_TLS"
    assert payload["prediction"]["label"] == "TP"


def test_write_jsonl_mismatched_lengths(tmp_path):
    with pytest.raises(ValueError):
        write_jsonl(
            tmp_path / "mismatch.jsonl",
            [sample_detection()],
            [],
            threshold=0.1,
            model_name="m",
        )


def test_to_sarif_structure():
    detection = sample_detection()
    prediction = sample_prediction()

    sarif = to_sarif([detection], [prediction], tool_name="iacsec", tool_version="0.1.0")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "HTTP_NO_TLS"
    assert rules[0]["properties"]["smell"] == "http"

    result = run["results"][0]
    assert result["ruleId"] == "HTTP_NO_TLS"
    assert result["level"] == "warning"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "roles/web/tasks/main.yml"
    assert result["properties"]["prediction"] == "TP"
    assert "invocationTimeUtc" in run["conversion"]


def test_write_csv(tmp_path):
    rows = [("file.yml", 10, "HTTP"), ("other.yml", 0, "none")]
    out = tmp_path / "out.csv"
    write_csv(out, rows)
    content = out.read_text().splitlines()
    assert content[0] == "PATH,LINE,CATEGORY"
    assert content[1] == "file.yml,10,HTTP"
    assert content[2] == "other.yml,0,none"
