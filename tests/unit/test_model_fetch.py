from pathlib import Path

import pytest

from intellisa.models.fetch import fetch_model
from packages.postfilter_llm.engine import ModelHandle


def make_handle(tmp_path: Path, framework: str = "torch") -> ModelHandle:
    dummy_path = tmp_path / "weights.safetensors"
    dummy_path.write_bytes(b"stub")
    return ModelHandle(
        name="IntelliSA-220m",
        version="1",
        path=dummy_path,
        framework=framework,
        default_threshold=0.5,
        labels=["TP", "FP"],
    )


def test_fetch_model_success(monkeypatch, tmp_path):
    handle = make_handle(tmp_path)

    monkeypatch.setattr("packages.postfilter_llm.engine.load_model", lambda name: handle)
    monkeypatch.setattr(
        "packages.postfilter_llm.engine._load_hf_artifacts",  # type: ignore[attr-defined]
        lambda handle: (object(), object(), "cpu"),
    )

    rc = fetch_model("IntelliSA-220m")
    assert rc == 0


def test_fetch_model_stub(monkeypatch, tmp_path):
    handle = make_handle(tmp_path, framework="stub")

    monkeypatch.setattr("packages.postfilter_llm.engine.load_model", lambda name: handle)
    monkeypatch.setattr(
        "packages.postfilter_llm.engine._load_hf_artifacts",  # type: ignore[attr-defined]
        lambda handle: None,
    )

    rc = fetch_model("IntelliSA-220m")
    assert rc == 3


def test_fetch_model_error(monkeypatch):
    monkeypatch.setattr(
        "packages.postfilter_llm.engine.load_model",
        lambda name: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    rc = fetch_model("IntelliSA-220m")
    assert rc == 1
