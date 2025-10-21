from pathlib import Path

import pytest

from packages.glitch_adapter import run_glitch


def test_rules_map_contains_required_entries():
    expected = {"sec_https", "sec_weak_crypt", "sec_hard_secr", "sec_susp_comm", "sec_def_admin", "sec_empty_pass", "sec_invalid_bind", "sec_no_int_check", "sec_no_default_switch"}
    assert expected.issubset(run_glitch._RAW_RULES.keys())  # type: ignore[attr-defined]
    for key in expected:
        meta = run_glitch._RAW_RULES[key]  # type: ignore[attr-defined]
        assert set(meta) >= {"rule_id", "smell", "severity", "message", "postfilter"}


def test_run_glitch_converts_errors(monkeypatch, tmp_path):
    target_file = tmp_path / "roles" / "web" / "tasks" / "main.yml"
    target_file.parent.mkdir(parents=True)
    target_file.write_text("line1\nline2\n")

    class DummyError:
        code = "sec_https"
        path = str(target_file)
        line = 2
        repr = "line2"

    calls = []

    def fake_collect(root: Path, tech: str):
        calls.append((root, tech))
        return [DummyError()]

    monkeypatch.setattr(run_glitch, "_collect_errors", fake_collect)
    detections = run_glitch.run_glitch(str(tmp_path), "ansible")
    assert len(detections) == 1
    det = detections[0]
    assert det.rule_id == "HTTP_NO_TLS"
    assert det.snippet == "line2"
    assert det.file == "roles/web/tasks/main.yml"
    assert det.severity == "medium"
    assert det.tech == "ansible"
    assert det.evidence["glitch_code"] == "sec_https"
    assert det.evidence.get("postfilter") is True
    assert calls[0][1] == "ansible"


def test_auto_mode_detects_all_present_tech(monkeypatch, tmp_path):
    (tmp_path / "play.yml").write_text("")
    (tmp_path / "recipe.rb").write_text("")
    (tmp_path / "module.pp").write_text("")

    seen = []

    def fake_collect(root: Path, tech: str):
        seen.append(tech)
        return []

    monkeypatch.setattr(run_glitch, "_collect_errors", fake_collect)
    detections = run_glitch.run_glitch(str(tmp_path), "auto")
    assert detections == []
    assert set(seen) == {"ansible", "chef", "puppet"}


def test_invalid_tech_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        run_glitch.run_glitch(str(tmp_path), "terraform")
