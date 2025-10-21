import json
from pathlib import Path

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schema.models import Detection, Prediction


runner = CliRunner()


def _dummy_detection(*, postfilter: bool, rule_id: str = "HTTP_NO_TLS", **overrides) -> Detection:
    evidence = {"glitch_code": "sec_https" if postfilter else "sec_empty_pass"}
    if postfilter:
        evidence["postfilter"] = True
    data = {
        "rule_id": rule_id,
        "smell": "http" if postfilter else "empty-password",
        "tech": "ansible",
        "file": "roles/web/tasks/main.yml",
        "line": 10,
        "snippet": "get_url: url=http://example.com" if postfilter else "password: """,
        "message": "HTTP used without TLS" if postfilter else "Empty password detected",
        "severity": "medium" if postfilter else "high",
        "evidence": evidence,
    }
    data.update(overrides)
    return Detection(**data)


def _dummy_prediction(**overrides) -> Prediction:
    data = {"label": "TP", "score": 0.9, "rationale": "score>=threshold"}
    data.update(overrides)
    return Prediction(**data)


class DummyModel:
    def __init__(self, name: str = "stub", version: str = "1.0.0", threshold: float = 0.5):
        self.name = name
        self.version = version
        self.default_threshold = threshold
        self.path = Path("/tmp/model.bin")
        self.framework = "torch"
        self.labels = ["TP", "FP"]
        self.thresholds = {}
        self.tokenizer_dir = None


def _touch_detection_file(tmp_path: Path) -> None:
    target = tmp_path / "roles" / "web" / "tasks"
    target.mkdir(parents=True, exist_ok=True)
    (target / "main.yml").write_text("content")


def test_scan_writes_sarif_and_json(monkeypatch, tmp_path):
    detection = _dummy_detection(postfilter=True)
    prediction = _dummy_prediction()

    monkeypatch.setattr("apps.cli.main.run_glitch", lambda path, tech: [detection])
    monkeypatch.setattr("apps.cli.main.load_model", lambda name: DummyModel(name=name))
    monkeypatch.setattr("apps.cli.main.predict", lambda dets, code_dir, threshold: [prediction])

    _touch_detection_file(tmp_path)

    out_path = tmp_path / "intellisa.sarif"
    result = runner.invoke(
        app,
        [
            "--path",
            str(tmp_path),
            "--out",
            str(out_path),
            "--format",
            "sarif",
            "--format",
            "json",
            "--format",
            "csv",
        ],
    )

    assert result.exit_code == 1
    sarif_data = json.loads(out_path.read_text())
    assert sarif_data["runs"][0]["results"][0]["ruleId"] == "HTTP_NO_TLS"
    jsonl_path = out_path.with_suffix(".jsonl")
    lines = jsonl_path.read_text().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["model"].startswith("IntelliSA-220m@")
    csv_path = out_path.with_suffix(".csv")
    csv_lines = csv_path.read_text().splitlines()
    assert csv_lines[0] == "PATH,LINE,CATEGORY"
    assert csv_lines[1] == "roles/web/tasks/main.yml,10,Use of HTTP without SSL/TLS"


def test_scan_returns_zero_when_no_blocking(monkeypatch, tmp_path):
    detection = _dummy_detection(postfilter=False, rule_id="EMPTY_PASSWORD")
    monkeypatch.setattr("apps.cli.main.run_glitch", lambda path, tech: [detection])
    monkeypatch.setattr("apps.cli.main.load_model", lambda name: DummyModel(name=name))

    def fake_predict(dets, code_dir, threshold):
        assert dets == []
        return []

    monkeypatch.setattr("apps.cli.main.predict", fake_predict)

    _touch_detection_file(tmp_path)

    out_path = tmp_path / "scan.sarif"
    result = runner.invoke(
        app,
        [
            "--path",
            str(tmp_path),
            "--out",
            str(out_path),
            "--format",
            "sarif",
            "--format",
            "csv",
        ],
    )

    assert result.exit_code == 1
    assert out_path.exists()
    sarif_payload = json.loads(out_path.read_text())
    result_entry = sarif_payload["runs"][0]["results"][0]
    assert result_entry["properties"]["prediction"] == "TP"
    assert result_entry["message"]["text"].endswith("glitch-accepted")
    csv_path = out_path.with_suffix(".csv")
    csv_lines = csv_path.read_text().splitlines()
    assert csv_lines[0] == "PATH,LINE,CATEGORY"
    assert csv_lines[1] == "roles/web/tasks/main.yml,10,Empty password"


def test_scan_debug_log(monkeypatch, tmp_path):
    detection_accept = _dummy_detection(postfilter=False, rule_id="EMPTY_PASSWORD")
    detection_model = _dummy_detection(postfilter=True)

    monkeypatch.setattr("apps.cli.main.run_glitch", lambda path, tech: [detection_accept, detection_model])
    monkeypatch.setattr("apps.cli.main.load_model", lambda name: DummyModel(name=name, threshold=0.5))

    model_predictions = [_dummy_prediction(label="FP", score=0.40, rationale="score<threshold")]
    monkeypatch.setattr("apps.cli.main.predict", lambda dets, code_dir, threshold: model_predictions)

    _touch_detection_file(tmp_path)

    out_path = tmp_path / "out.sarif"
    debug_path = tmp_path / "debug.jsonl"
    result = runner.invoke(
        app,
        [
            "--path",
            str(tmp_path),
            "--out",
            str(out_path),
            "--format",
            "sarif",
            "--format",
            "csv",
            "--debug-log",
            str(debug_path),
        ],
    )

    assert result.exit_code == 1
    assert debug_path.exists()
    entries = [json.loads(line) for line in debug_path.read_text().splitlines()]
    events = {entry["event"] for entry in entries}
    assert {"glitch_detections", "detector_split", "postfilter_inputs", "postfilter_outputs", "final_results", "exit"}.issubset(events)

    post_inputs = next(entry for entry in entries if entry["event"] == "postfilter_inputs")
    assert post_inputs["examples"][0]["snippet"] == detection_model.snippet

    post_outputs = next(entry for entry in entries if entry["event"] == "postfilter_outputs")
    assert post_outputs["results"][0]["prediction"]["label"] == "FP"

    final_results = next(entry for entry in entries if entry["event"] == "final_results")
    assert len(final_results["results"]) == 2
    assert final_results["results"][1]["prediction"]["label"] == "FP"

    exit_entry = next(entry for entry in entries if entry["event"] == "exit")
    assert exit_entry["code"] == 1


def test_scan_warns_when_stub_model_used(monkeypatch, tmp_path):
    detection = _dummy_detection(postfilter=True)

    monkeypatch.setattr("apps.cli.main.run_glitch", lambda path, tech: [detection])

    def stub_model(name):
        model = DummyModel(name=name, threshold=0.5)
        model.framework = "stub"
        return model

    monkeypatch.setattr("apps.cli.main.load_model", stub_model)

    def stub_predict(dets, code_dir, threshold):
        return [_dummy_prediction(label="FP", score=0.2, rationale="score<threshold")]

    monkeypatch.setattr("apps.cli.main.predict", stub_predict)
    monkeypatch.setattr("apps.cli.main.is_stub_backend", lambda: True)

    _touch_detection_file(tmp_path)

    debug_path = tmp_path / "debug.jsonl"
    result = runner.invoke(
        app,
        [
            "--path",
            str(tmp_path),
            "--out",
            str(tmp_path / "out.sarif"),
            "--format",
            "sarif",
            "--debug-log",
            str(debug_path),
        ],
    )

    assert "falling back to deterministic stub model" in result.stdout
    entries = [json.loads(line) for line in debug_path.read_text().splitlines()]
    warning_events = [entry for entry in entries if entry["event"] == "warning"]
    assert warning_events and warning_events[0]["message"] == "using stub model"
