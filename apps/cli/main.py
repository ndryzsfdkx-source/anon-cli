
"""Typer CLI entrypoint for intellisa scans."""
from __future__ import annotations

import json
import logging
import sys
import warnings
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

import typer

# Suppress pkg_resources deprecation warnings from vendored GLITCH
warnings.filterwarnings("ignore", message=".*pkg_resources.*deprecated.*")

# Suppress PLY token warnings from puppetparser by filtering stderr during import
class _SuppressPLYWarnings:
    """Context manager to suppress PLY token warnings from puppetparser."""
    def __enter__(self):
        self._original_stderr = sys.stderr
        self._stderr_capture = StringIO()
        sys.stderr = self._stderr_capture
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        captured = self._stderr_capture.getvalue()
        sys.stderr = self._original_stderr
        # Only suppress PLY token warnings, pass through other stderr
        for line in captured.splitlines():
            if not (line.startswith("WARNING: Token") or 
                    line.startswith("WARNING: There are") and "unused tokens" in line):
                print(line, file=sys.stderr)
from rich.console import Console
from rich.table import Table

from packages.exporters.jsonl import write_jsonl
from packages.exporters.sarif import to_sarif
from packages.exporters.csv import write_csv, Row as CSVRow
from packages.glitch_adapter.run_glitch import run_glitch
import logging
from packages.postfilter_llm.engine import ModelHandle, load_model, predict, is_stub_backend
from packages.schema.models import Detection, Prediction

app = typer.Typer(add_completion=False)
console = Console()

_LOG = logging.getLogger(__name__)


class DebugLogger:
    """JSONL debug trace writer used during CLI runs."""

    def __init__(self, path: Optional[Path]):
        self._handle = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = path.open("w", encoding="utf-8")

    @property
    def enabled(self) -> bool:
        return self._handle is not None

    def log(self, event: str, payload: Optional[dict] = None, **extra: object) -> None:
        if not self._handle:
            return
        entry: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        if payload:
            entry.update(payload)
        if extra:
            entry.update(extra)
        self._handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._handle.flush()

    def close(self) -> None:
        if self._handle:
            self._handle.close()
            self._handle = None

CATEGORY_LABELS = {
    "HTTP_NO_TLS": "Use of HTTP without SSL/TLS",
    "WEAK_CRYPTO": "Weak cryptography algorithm",
    "HARDCODED_SECRET": "Hard-coded secret",
    "SUSPICIOUS_COMMENT": "Suspicious comment",
    "ADMIN_DEFAULT": "Admin by default",
    "EMPTY_PASSWORD": "Empty password",
    "INVALID_BIND": "Unrestricted IP Address",
    "NO_INTEGRITY_CHECK": "No integrity check",
    "MISSING_DEFAULT_SWITCH": "Missing default switch",
}

_FILE_EXTENSIONS = {
    "ansible": {".yml", ".yaml"},
    "chef": {".rb"},
    "puppet": {".pp"},
}


_VALID_TECH = {"auto", "ansible", "chef", "puppet"}
_VALID_FORMATS = {"sarif", "json", "table", "csv"}
_DEFAULT_RULES = "http,weak-crypto,hardcoded-secret,suspicious-comment,admin-by-default,empty-password,invalid-bind,no-integrity-check,missing-default-switch"


def _normalize_formats(values: Sequence[str]) -> List[str]:
    if not values:
        return ["sarif"]
    normalized = []
    for value in values:
        fmt = value.lower()
        if fmt not in _VALID_FORMATS:
            raise typer.BadParameter(
                f"Unsupported format '{value}'. Choose from {sorted(_VALID_FORMATS)}"
            )
        if fmt not in normalized:
            normalized.append(fmt)
    return normalized


def _normalize_rules(rules_option: str) -> List[str]:
    return [part.strip() for part in rules_option.split(",") if part.strip()]


@app.command()
def scan(
    path: Path = typer.Option(Path("."), "--path", help="Path to scan"),
    tech: str = typer.Option("auto", "--tech", help="auto|ansible|chef|puppet"),
    rules: str = typer.Option(
        _DEFAULT_RULES,
        "--rules",
        help="Comma-separated smell types to detect (default: all)",
        show_default=False,
    ),
    postfilter: str = typer.Option("IntelliSA-220m", "--postfilter", help="Post-filter model name"),
    threshold: Optional[float] = typer.Option(None, "--threshold", help="Override model default"),
    format: List[str] = typer.Option(
        ["sarif"], "--format", help="Repeatable option: sarif, json, csv, table"
    ),
    out: Path = typer.Option(Path("artifacts/intellisa"), "--out", help="Base output path for all formats (directory or filename prefix)"),
    fail_on_high: bool = typer.Option(
        False,
        "--fail-on-high",
        help="Treat only high-severity TPs as blocking findings",
    ),
    debug_log: Optional[Path] = typer.Option(
        None,
        "--debug-log",
        help="Write debug trace JSONL to this path",
    ),
) -> None:
    """Scan IaC files for security vulnerabilities using rule-based detection combined with neural inference."""

    debug = DebugLogger(debug_log)

    try:
        if tech not in _VALID_TECH:
            raise typer.BadParameter(
                f"Unsupported tech '{tech}'. Choose from {sorted(_VALID_TECH)}"
            )

        formats = _normalize_formats(format)
        selected_rules = _normalize_rules(rules)
        console.log(
            f"Starting scan: path={path} tech={tech} rules={selected_rules} formats={formats}"
        )
        debug.log("start", {
            "path": str(path),
            "tech": tech,
            "rules": selected_rules,
            "formats": formats,
        })

        try:
            # Suppress PLY warnings from puppetparser during rule-based detection
            with _SuppressPLYWarnings():
                raw_detections = run_glitch(str(path), tech)
        except Exception as exc:  # pragma: no cover - defensive logging
            console.print(f"[red]Rule-based detection failed: {exc}[/]")
            debug.log("error", {"stage": "glitch", "message": str(exc)})
            raise typer.Exit(code=2) from exc

        debug.log("glitch_detections", {
            "count": len(raw_detections),
            "detections": [det.model_dump() for det in raw_detections],
        })

        # Filter detections by selected rules
        filtered_detections = [
            det for det in raw_detections
            if det.smell in selected_rules
        ]
        
        if filtered_detections != raw_detections:
            console.log(
                f"Filtered to {len(filtered_detections)} detections matching rules: {selected_rules}"
            )

        category_a: list[Detection] = []
        category_a_preds: list[Prediction] = []
        category_b: list[Detection] = []

        for det in filtered_detections:
            needs_postfilter = bool(det.evidence.pop("postfilter", False))
            if needs_postfilter:
                category_b.append(det)
            else:
                category_a.append(det)
                category_a_preds.append(
                    Prediction(label="TP", score=1.0, rationale="glitch-accepted")
                )

        console.log(
            "Rule-based detection found %s issues (high-confidence=%s, neural-inference=%s)"
            % (len(filtered_detections), len(category_a), len(category_b))
        )
        debug.log("detector_split", {
            "total": len(filtered_detections),
            "total_before_filter": len(raw_detections),
            "accepted": len(category_a),
            "postfilter": len(category_b),
        })

        try:
            model = load_model(postfilter)
        except Exception as exc:  # pragma: no cover
            console.print(f"[red]Failed to load model '{postfilter}': {exc}[/]")
            debug.log("error", {"stage": "load_model", "message": str(exc)})
            raise typer.Exit(code=2) from exc

        effective_threshold = threshold if threshold is not None else model.default_threshold
        if category_b:
            debug.log("postfilter_inputs", {
                "model": model.name,
                "threshold": effective_threshold,
                "examples": [
                    {
                        "detection": det.model_dump(),
                        "snippet": det.snippet or "<empty>",
                    }
                    for det in category_b
                ],
            })

        try:
            postfiltered = predict(category_b, path, threshold)
        except Exception as exc:  # pragma: no cover
            console.print(f"[red]Post-filtering failed: {exc}[/]")
            debug.log("error", {"stage": "predict", "message": str(exc)})
            raise typer.Exit(code=2) from exc

        if is_stub_backend():
            message = "falling back to deterministic stub model; install torch+transformers for IntelliSA-220m."
            console.print(f"[yellow]Warning:[/] {message}")
            _LOG.warning(message)
            debug.log("warning", {"stage": "postfilter", "message": "using stub model"})

        if category_b:
            debug.log("postfilter_outputs", {
                "model": model.name,
                "threshold": effective_threshold,
                "results": [
                    {
                        "detection": det.model_dump(),
                        "prediction": pred.model_dump(),
                    }
                    for det, pred in zip(category_b, postfiltered)
                ],
            })

        # Merge and sort by original detection order for deterministic output
        det_pred_pairs = list(zip(category_a, category_a_preds)) + list(zip(category_b, postfiltered))
        det_pred_pairs.sort(key=lambda pair: (pair[0].file, pair[0].line, pair[0].rule_id))
        detections = [d for d, p in det_pred_pairs]
        predictions = [p for d, p in det_pred_pairs]

        console.log(
            f"Post-filter complete: threshold={effective_threshold:.2f}"
            f" TP={sum(1 for p in predictions if p.label == 'TP')}"
        )
        debug.log("final_results", {
            "threshold": effective_threshold,
            "results": [
                {
                    "detection": det.model_dump(),
                    "prediction": pred.model_dump(),
                }
                for det, pred in zip(detections, predictions)
            ],
        })

        outputs = _export_results(
            detections,
            predictions,
            formats=formats,
            out=out,
            model=model,
            threshold=effective_threshold,
            scan_root=path,
            tech=tech,
        )

        blocking = _blocking_findings(detections, predictions, fail_on_high)
        debug.log("exports", {"paths": {k: str(v) for k, v in outputs.items()}})
        debug.log("blocking_summary", {
            "blocking": len(blocking),
            "fail_on_high": fail_on_high,
        })

        if blocking:
            console.print(f"[red]{len(blocking)} blocking finding(s) detected[/]")
            debug.log("exit", {"code": 1, "blocking": len(blocking)})
            raise typer.Exit(code=1)

        console.print("[green]No blocking findings identified[/]")
        debug.log("exit", {"code": 0, "blocking": 0})
        raise typer.Exit(code=0)

    finally:
        debug.close()



def _collect_candidate_files(root: Path, tech: str) -> Set[str]:
    resolved_root = root.resolve()
    if resolved_root.is_file():
        return {resolved_root.name}

    if tech == "auto":
        extensions = set().union(*_FILE_EXTENSIONS.values())
    else:
        extensions = set()
        if tech in _FILE_EXTENSIONS:
            extensions.update(_FILE_EXTENSIONS[tech])
        if not extensions:
            extensions = set().union(*_FILE_EXTENSIONS.values())

    candidates: Set[str] = set()
    if not resolved_root.exists():
        return candidates

    for path in resolved_root.rglob("*"):
        if not path.is_file():
            continue
        if extensions and path.suffix.lower() not in extensions:
            continue
        try:
            relative = path.relative_to(resolved_root)
            candidates.add(relative.as_posix())
        except ValueError:
            candidates.add(path.name)
    return candidates


def _build_csv_rows(
    root: Path,
    tech: str,
    detections: List[Detection],
    predictions: List[Prediction],
) -> List[CSVRow]:
    rows: List[CSVRow] = []
    seen_files: Set[str] = set()

    for det, pred in zip(detections, predictions):
        if pred.label != "TP":
            continue
        category = CATEGORY_LABELS.get(det.rule_id, det.message)
        rows.append((det.file, det.line, category))
        seen_files.add(det.file)

    for candidate in sorted(_collect_candidate_files(root, tech)):
        if candidate not in seen_files:
            rows.append((candidate, 0, "none"))

    rows.sort(key=lambda row: (row[0], row[1]))
    return rows

def _blocking_findings(
    detections: Iterable[Detection],
    predictions: Iterable[Prediction],
    fail_on_high: bool,
) -> List[tuple[Detection, Prediction]]:
    pairs = list(zip(detections, predictions))
    if fail_on_high:
        return [
            (det, pred)
            for det, pred in pairs
            if pred.label == "TP" and det.severity == "high"
        ]
    return [(det, pred) for det, pred in pairs if pred.label == "TP"]




def _export_results(
    detections: List[Detection],
    predictions: List[Prediction],
    *,
    formats: Sequence[str],
    out: Path,
    model: ModelHandle,
    threshold: float,
    scan_root: Path,
    tech: str,
) -> dict[str, Path]:
    fmt_set = set(formats)
    model_descriptor = f"{model.name}@{model.version}"

    outputs: dict[str, Path] = {}
    
    # Determine if --out is a directory or file base
    if out.is_dir() or (not out.exists() and out.suffix == ""):
        # Directory: use default filename with appropriate extensions
        base_name = "intellisa"
        output_dir = out
    else:
        # File base: use the filename without extension as base
        base_name = out.stem
        output_dir = out.parent

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    if "sarif" in fmt_set:
        sarif_obj = to_sarif(
            detections,
            predictions,
            tool_name="intellisa",
            tool_version=str(model.version),
        )
        sarif_path = output_dir / f"{base_name}.sarif"
        with sarif_path.open("w", encoding="utf-8") as handle:
            json.dump(sarif_obj, handle, indent=2)
            handle.write("\n")
        outputs["sarif"] = sarif_path

    if "json" in fmt_set:
        json_path = output_dir / f"{base_name}.jsonl"
        write_jsonl(json_path, detections, predictions, threshold, model_descriptor)
        outputs["json"] = json_path

    if "csv" in fmt_set:
        csv_path = output_dir / f"{base_name}.csv"
        rows = _build_csv_rows(scan_root, tech, detections, predictions)
        write_csv(csv_path, rows)
        outputs["csv"] = csv_path

    if "table" in fmt_set:
        table = Table(title="intellisa findings")
        table.add_column("Rule")
        table.add_column("Severity")
        table.add_column("Prediction")
        table.add_column("Score", justify="right")
        table.add_column("Location")
        for det, pred in zip(detections, predictions):
            location = f"{det.file}:{det.line}"
            table.add_row(
                det.rule_id,
                det.severity,
                pred.label,
                f"{pred.score:.2f}",
                location,
            )
        console.print(table)

    return outputs

if __name__ == "__main__":  # pragma: no cover - manual execution
    app()
