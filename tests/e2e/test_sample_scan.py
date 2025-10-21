
import json
from pathlib import Path

from typer.testing import CliRunner

from apps.cli.main import app


def read_json(path: Path):
    return json.loads(path.read_text())


def read_lines(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_sample_repo_scan_matches_golden(tmp_path, monkeypatch):
    runner = CliRunner()
    out_sarif = tmp_path / "intellisa.sarif"
    result = runner.invoke(
        app,
        [
            "--path",
            "examples/sample_repo",
            "--tech",
            "ansible",
            "--out",
            str(out_sarif),
            "--format",
            "sarif",
            "--format",
            "json",
            "--postfilter",
            "stub",
        ],
        env={"INTELLISA_MODEL_CACHE": str(tmp_path / "model_cache")},
    )

    # Blocking findings expected -> exit code 1
    assert result.exit_code == 1, result.stdout

    golden_dir = Path("tests/e2e/golden")
    golden_sarif = golden_dir / "sample.sarif"
    golden_jsonl = golden_dir / "sample.jsonl"

    assert read_json(out_sarif) == read_json(golden_sarif)
    out_jsonl = out_sarif.with_suffix(".jsonl")
    assert read_lines(out_jsonl) == read_lines(golden_jsonl)
