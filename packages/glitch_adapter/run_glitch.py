"""Adapter that invokes vendored GLITCH and normalises detections."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import sys

import yaml
from importlib.resources import files

from packages.schema.models import Detection

_LOG = logging.getLogger(__name__)

_RULES_MAP_PATH = Path(__file__).with_name("rules_map.yaml")
_GLITCH_ROOT = Path(__file__).resolve().parents[1] / "glitch_core"
if _GLITCH_ROOT.exists() and str(_GLITCH_ROOT) not in sys.path:
    sys.path.insert(0, str(_GLITCH_ROOT))

_RAW_RULES: Dict[str, Dict[str, str]] = yaml.safe_load(_RULES_MAP_PATH.read_text())
IGNORE_RULES = {'sec_hard_user', 'sec_hard_pass'}

_VALID_TECH = {"ansible", "chef", "puppet"}
_TECH_EXTS = {
    "ansible": {".yml", ".yaml"},
    "chef": {".rb"},
    "puppet": {".pp"},
}


def run_glitch(path: str, tech: str) -> List[Detection]:
    """Run GLITCH on ``path`` and convert the results into ``Detection`` objects."""

    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Scan target not found: {path}")

    techs = _resolve_techs(root, tech)
    detections: List[Detection] = []
    seen_keys: set[tuple[str, str, int]] = set()

    for resolved_tech in techs:
        for error in _collect_errors(root, resolved_tech):
            if error.code in IGNORE_RULES:
                continue
            mapping = _RAW_RULES.get(error.code)
            if not mapping:
                continue

            file_path = Path(error.path)
            rel_path = _relative_to_root(root, file_path)
            line_no = error.line if getattr(error, "line", 0) and error.line > 0 else 1
            snippet = _extract_line(file_path, line_no)
            evidence = {"glitch_code": error.code}
            if mapping.get("postfilter"):
                evidence["postfilter"] = True
            if hasattr(error, "repr") and isinstance(error.repr, str):
                detail = error.repr.strip()
                if detail:
                    evidence["detail"] = detail

            detection = Detection(
                rule_id=mapping["rule_id"],
                smell=mapping["smell"],
                tech=resolved_tech,
                file=rel_path,
                line=line_no,
                snippet=snippet,
                message=mapping["message"],
                severity=mapping["severity"],
                evidence=evidence,
            )
            key = (detection.rule_id, detection.file, detection.line)
            if key not in seen_keys:
                seen_keys.add(key)
                detections.append(detection)

    # Sort for deterministic output across different file systems
    detections.sort(key=lambda d: (d.file, d.line, d.rule_id))
    return detections


def _resolve_techs(root: Path, tech: str) -> Sequence[str]:
    if tech != "auto":
        if tech not in _VALID_TECH:
            raise ValueError(f"Unsupported tech '{tech}'. Expected one of {_VALID_TECH | {'auto'}}")
        return (tech,)

    detected: set[str] = set()
    iterable = [root] if root.is_file() else root.rglob("*")
    for candidate in iterable:
        if candidate.is_file():
            suffix = candidate.suffix.lower()
            for name, extensions in _TECH_EXTS.items():
                if suffix in extensions:
                    detected.add(name)
    if not detected:
        return ("ansible",)
    return tuple(sorted(detected))


def _collect_errors(root: Path, tech: str):  # pragma: no cover - patched in tests
    from glitch.analysis.security import SecurityVisitor
    from glitch.parsers.cmof import AnsibleParser, ChefParser, PuppetParser
    from glitch.repr.inter import UnitBlockType
    from glitch.tech import Tech

    parser_map = {
        "ansible": AnsibleParser,
        "chef": ChefParser,
        "puppet": PuppetParser,
    }
    parser_cls = parser_map[tech]
    parser = parser_cls()

    config_path = str(files("glitch").joinpath("configs/default.ini"))
    visitor = SecurityVisitor(Tech(tech))
    visitor.config(config_path)

    targets = list(_iter_files(root, tech))
    errors = []
    for target in targets:
        try:
            inter = parser.parse(str(target), UnitBlockType.unknown, False)
        except Exception as exc:  # pragma: no cover - defensive logging
            _LOG.debug("GLITCH parser failed on %s: %s", target, exc)
            continue
        if inter is None:
            continue
        try:
            errors.extend(visitor.check(inter))
        except Exception as exc:  # pragma: no cover - defensive logging
            _LOG.debug("GLITCH visitor failed on %s: %s", target, exc)
    unique = {}
    for err in errors:
        key = (err.code, err.path, err.line)
        unique[key] = err
    return list(unique.values())


def _iter_files(root: Path, tech: str) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    extensions = _TECH_EXTS.get(tech, set())
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if not extensions or file_path.suffix.lower() in extensions:
            yield file_path


def _relative_to_root(root: Path, file_path: Path) -> str:
    root = root.resolve()
    file_path = file_path.resolve()
    candidates = [root]
    if root.is_file():
        candidates.append(root.parent)
    for base in candidates:
        try:
            return str(file_path.relative_to(base))
        except ValueError:
            continue
    return file_path.as_posix()


def _extract_line(path: Path, line_no: int) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for idx, text in enumerate(handle, start=1):
                if idx == line_no:
                    return text.rstrip("\n")
    except FileNotFoundError:
        return ""
    return ""


__all__ = ["run_glitch"]
