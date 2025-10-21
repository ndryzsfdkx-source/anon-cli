
"""Encoder post-filter loader/predictor facade."""
from __future__ import annotations

import hashlib
import logging
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

try:
    import torch
    from transformers import AutoTokenizer, T5ForSequenceClassification
    try:
        from safetensors.torch import load_file as load_safetensors
    except Exception:  # pragma: no cover - safetensors optional fallback
        load_safetensors = None
    try:
        from transformers import AutoConfig
    except Exception:  # pragma: no cover - optional import
        AutoConfig = None
except Exception:  # pragma: no cover - transformers optional in test environments
    torch = None
    AutoTokenizer = None
    T5ForSequenceClassification = None
    load_safetensors = None
    AutoConfig = None

from packages.schema.models import Detection, Prediction

_LOG = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "models" / "registry.yaml"
_DEFAULT_CACHE = Path(os.environ.get("INTELLISA_MODEL_CACHE", str(Path.home() / ".cache/intellisa")))
_LOADED_MODEL: Optional["ModelHandle"] = None


@dataclass(frozen=True)
class ModelHandle:
    """Metadata describing a loaded encoder model."""

    name: str
    version: str
    path: Path
    framework: str
    default_threshold: float
    labels: List[str]
    tokenizer_dir: Optional[Path] = None
    thresholds: Dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "path": str(self.path),
            "framework": self.framework,
        }


def load_model(name: str) -> ModelHandle:
    """Resolve and cache the requested model, returning a handle."""

    registry = _load_registry()
    if name not in registry:
        raise KeyError(f"Model '{name}' not found in registry at {_REGISTRY_PATH}")

    entry = registry[name]
    uri = entry["uri"]
    local_source = _resolve_local_source(uri)
    expected_sha = entry.get("sha256")
    should_verify = _is_hex_digest(expected_sha)

    if local_source is not None:
        target_path = local_source
        if should_verify and not _verify_sha(target_path, expected_sha):  # type: ignore[arg-type]
            raise RuntimeError(f"Checksum mismatch for model '{name}' (local source).")
    else:
        target_path = _target_path(entry)
        if not target_path.exists() or (should_verify and not _verify_sha(target_path, expected_sha)):  # type: ignore[arg-type]
            _download_file(uri, target_path)
            if should_verify and not _verify_sha(target_path, expected_sha):  # type: ignore[arg-type]
                raise RuntimeError(
                    f"Checksum mismatch for model '{name}' after download."
                )

    thresholds = {}
    thresholds_ref = entry.get("thresholds")
    if thresholds_ref:
        thresholds_path = _resolve_registry_path(str(thresholds_ref))
        thresholds = yaml.safe_load(thresholds_path.read_text()) or {}

    tokenizer_dir = entry.get("tokenizer")
    resolved_tokenizer = _resolve_registry_path(tokenizer_dir) if tokenizer_dir else None

    handle = ModelHandle(
        name=name,
        version=str(entry.get("version", "0")),
        path=target_path,
        framework=str(entry.get("framework", "unknown")),
        default_threshold=float(entry.get("default_threshold", 0.5)),
        labels=list(entry.get("labels", [])),
        tokenizer_dir=resolved_tokenizer,
        thresholds={k: float(v) for k, v in thresholds.items()},
    )

    global _LOADED_MODEL
    _LOADED_MODEL = handle
    return handle


def predict(
    detections: List[Detection],
    code_dir: Path,
    threshold: Optional[float],
) -> List[Prediction]:
    """Produce predictions for detections using the active model."""

    if _LOADED_MODEL is None:
        raise RuntimeError("No model loaded. Call load_model() before predict().")

    model = _LOADED_MODEL

    if not detections:
        return []

    artifacts = _load_hf_artifacts(model)
    if artifacts is None:
        global _BACKEND_MODE
        _BACKEND_MODE = "stub"
        return _predict_statically(detections, code_dir, threshold, model)

    _BACKEND_MODE = "hf"
    tokenizer, classifier, device = artifacts
    batch_size = int(os.environ.get("INTELLISA_POSTFILTER_BATCH", "16")) or 16
    texts = [_format_detection(det) for det in detections]

    import torch

    predictions: List[Prediction] = []
    for idx in range(0, len(texts), batch_size):
        batch_texts = texts[idx : idx + batch_size]
        encoding = tokenizer(
            batch_texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        )
        encoding = {k: v.to(device) for k, v in encoding.items()}
        with torch.no_grad():
            outputs = classifier(**encoding)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)

        for det, prob in zip(detections[idx : idx + batch_size], probs):
            positive_idx = _positive_index(classifier)
            score = float(prob[positive_idx].item())
            effective_threshold = _resolve_threshold(det, threshold, model)
            meets_threshold = score >= effective_threshold
            label = "TP" if meets_threshold else "FP"
            rationale = "score>=threshold" if meets_threshold else "score<threshold"
            if _DEF_INVERT_FLAG:
                label = "FP" if meets_threshold else "TP"
                rationale = "inverted:" + rationale
            predictions.append(
                Prediction(label=label, score=score, rationale=rationale)
            )

    return predictions


def _stable_score(det: Detection, code_dir: Path, model: ModelHandle) -> float:
    payload = json.dumps(
        {
            "model": model.name,
            "version": model.version,
            "rule": det.rule_id,
            "file": det.file,
            "snippet": det.snippet,
            "code_dir": str(code_dir),
        },
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    value = int.from_bytes(digest[:8], "big")
    return value / float(1 << 64)

_HF_CACHE: Dict[str, tuple] = {}


_BACKEND_MODE = "unknown"




_DEF_INVERT_FLAG = os.environ.get("IACSEC_INVERT_POSTFILTER", "").lower() in {"1", "true", "yes"}


def _load_hf_artifacts(handle: ModelHandle):
    if AutoTokenizer is None or T5ForSequenceClassification is None or torch is None:
        return None
    if handle.name.endswith("-stub") or handle.tokenizer_dir is None:
        return None

    cache_key = f"{handle.name}:{handle.version}:{handle.path}"  # unique per weight file
    if cache_key in _HF_CACHE:
        return _HF_CACHE[cache_key]

    model_dir = handle.tokenizer_dir or handle.path.parent
    tokenizer = AutoTokenizer.from_pretrained(str(model_dir))

    classifier = None
    if handle.path.exists() and handle.path.is_file():
        if load_safetensors is not None and handle.path.suffix == ".safetensors":
            state_dict = load_safetensors(str(handle.path))
        else:  # pragma: no cover - fallback path
            state_dict = torch.load(handle.path, map_location="cpu")
        if AutoConfig is None:
            raise RuntimeError("transformers AutoConfig unavailable; cannot load safetensors")
        config = AutoConfig.from_pretrained(str(model_dir))
        classifier = T5ForSequenceClassification(config)
        missing, unexpected = classifier.load_state_dict(state_dict, strict=False)
        if missing or unexpected:
            _LOG.debug("Model state load with missing=%s unexpected=%s", missing, unexpected)
    else:
        classifier = T5ForSequenceClassification.from_pretrained(str(model_dir))

    if not classifier.config.label2id or "TP" not in classifier.config.label2id:
        classifier.config.label2id = {"FP": 0, "TP": 1}
        classifier.config.id2label = {0: "FP", 1: "TP"}

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    classifier.to(device)
    classifier.eval()

    _HF_CACHE[cache_key] = (tokenizer, classifier, device)
    return _HF_CACHE[cache_key]




def _predict_statically(
    detections: List[Detection],
    code_dir: Path,
    threshold: Optional[float],
    model: ModelHandle,
) -> List[Prediction]:
    predictions: List[Prediction] = []
    for det in detections:
        effective_threshold = _resolve_threshold(det, threshold, model)
        score = _stable_score(det, code_dir, model)
        meets_threshold = score >= effective_threshold
        label = "TP" if meets_threshold else "FP"
        rationale = "score>=threshold" if meets_threshold else "score<threshold"
        if _DEF_INVERT_FLAG:
            label = "FP" if meets_threshold else "TP"
            rationale = "inverted:" + rationale
        predictions.append(
            Prediction(label=label, score=score, rationale=rationale)
        )
    return predictions


def _format_detection(det: Detection) -> str:
    """Prepare encoder input using only the GLITCH-highlighted snippet."""

    return det.snippet or "<empty>"


def _positive_index(classifier: "T5ForSequenceClassification") -> int:
    config = classifier.config
    if config.label2id and "TP" in config.label2id:
        return int(config.label2id["TP"])
    return 1


def _resolve_threshold(det: Detection, override: Optional[float], model: ModelHandle) -> float:
    if override is not None:
        return override
    if model.thresholds:
        tech_threshold = model.thresholds.get(det.tech)
        if tech_threshold is not None:
            return tech_threshold
    return model.default_threshold


def _load_registry() -> Dict[str, Dict[str, object]]:
    if not _REGISTRY_PATH.exists():
        raise FileNotFoundError(f"Registry file missing: {_REGISTRY_PATH}")
    data = yaml.safe_load(_REGISTRY_PATH.read_text()) or {}
    entries: Dict[str, Dict[str, object]] = {}
    for entry in data.get("models", []):
        entries[entry["name"]] = entry
    return entries


def _resolve_registry_path(ref: Optional[str]) -> Optional[Path]:
    if not ref:
        return None
    candidate = Path(ref)
    if not candidate.is_absolute():
        candidate = (_REGISTRY_PATH.parent / candidate).resolve()
    return candidate


def _resolve_local_source(uri: str) -> Optional[Path]:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme in {"", "file"}:
        path = parsed.path if parsed.scheme else uri
        candidate = Path(urllib.parse.unquote(path))
        if not candidate.is_absolute():
            candidate = (_REGISTRY_PATH.parent / candidate).resolve()
        return candidate
    return None


def _cache_dir() -> Path:
    override = os.environ.get("INTELLISA_MODEL_CACHE")
    if override:
        path = Path(override)
    else:
        path = _DEFAULT_CACHE
    path.mkdir(parents=True, exist_ok=True)
    return path


def _target_path(entry: Dict[str, object]) -> Path:
    cache_dir = _cache_dir()
    uri = str(entry["uri"])
    name = entry["name"]
    version = str(entry.get("version", "0"))
    parsed = urllib.parse.urlparse(uri)
    filename = Path(parsed.path).name or f"{name}-{version}.bin"
    return cache_dir / filename


def _download_file(uri: str, target_path: Path) -> None:
    parsed = urllib.parse.urlparse(uri)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if parsed.scheme in {"", "file"}:
        source_path = _resolve_local_source(uri)
        if source_path is None or not source_path.exists():
            raise FileNotFoundError(f"Model source file not found: {uri}")
        target_path.write_bytes(source_path.read_bytes())
        return

    try:
        with urllib.request.urlopen(uri) as response:  # nosec - trusted sources configured in registry
            data = response.read()
    except Exception as exc:  # pragma: no cover - network/IO errors
        raise RuntimeError(f"Failed to download model from {uri}: {exc}") from exc

    target_path.write_bytes(data)


def _verify_sha(path: Path, expected: str) -> bool:
    if not path.exists():
        return False
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest() == expected


def _is_hex_digest(value: Optional[str]) -> bool:
    if not value or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True





def is_stub_backend() -> bool:
    """Return True if the most recent predict() call used the deterministic stub."""

    return _BACKEND_MODE == "stub"


__all__ = ["ModelHandle", "load_model", "predict", "is_stub_backend"]
