
import hashlib
import json
from pathlib import Path

import pytest

from packages.postfilter_llm import engine
from packages.schema.models import Detection


def make_registry(tmp_path: Path, *, sha: str, uri: str) -> Path:
    registry = {
        "models": [
            {
                "name": "stub-model",
                "version": "1.0.0",
                "uri": uri,
                "sha256": sha,
                "framework": "torch",
                "default_threshold": 0.5,
                "labels": ["TP", "FP"],
            }
        ]
    }
    path = tmp_path / "registry.yaml"
    path.write_text(json.dumps(registry))
    return path


def test_load_model_downloads_and_verifies(monkeypatch, tmp_path):
    payload = b"weights"
    sha = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "weights.bin"
    source.write_bytes(payload)
    registry_path = make_registry(tmp_path, sha=sha, uri=source.as_uri())

    monkeypatch.setattr(engine, "_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(engine, "_DEFAULT_CACHE", tmp_path / "cache")

    handle = engine.load_model("stub-model")
    assert handle.name == "stub-model"
    assert handle.version == "1.0.0"
    assert handle.default_threshold == 0.5
    assert handle.path.exists()
    assert handle.path.read_bytes() == payload
    assert handle.thresholds == {}
    assert handle.tokenizer_dir is None


def test_predict_is_deterministic(monkeypatch, tmp_path):
    payload = b"abc"
    sha = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "weights.bin"
    source.write_bytes(payload)
    registry_path = make_registry(tmp_path, sha=sha, uri=source.as_uri())

    monkeypatch.setattr(engine, "_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(engine, "_DEFAULT_CACHE", tmp_path / "cache")

    engine.load_model("stub-model")

    detection = Detection(
        rule_id="HTTP_NO_TLS",
        smell="http",
        tech="ansible",
        file="roles/web/tasks/main.yml",
        line=5,
        snippet="get_url: url=http://example.com",
        message="msg",
        severity="medium",
        evidence={},
    )

    preds = engine.predict([detection], tmp_path, threshold=None)
    assert preds[0].label in {"TP", "FP"}
    assert 0.0 <= preds[0].score <= 1.0

    preds_again = engine.predict([detection], tmp_path, threshold=0.5)
    assert preds_again[0].score == preds[0].score
    assert preds_again[0].label == preds[0].label


def test_predict_without_model_raises():
    engine._LOADED_MODEL = None
    with pytest.raises(RuntimeError):
        engine.predict([], Path("."), None)
