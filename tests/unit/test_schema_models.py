
import json

import pytest
from pydantic import ValidationError

from packages.schema.models import Detection, Prediction


def sample_detection() -> Detection:
    return Detection(
        rule_id="HTTP_NO_TLS",
        smell="http",
        tech="ansible",
        file="roles/web/tasks/main.yml",
        line=42,
        snippet="get_url: url=http://example.com/app.tar.gz",
        message="HTTP used without TLS",
        severity="medium",
        evidence={"keys": ["url"], "values": ["http://example.com/app.tar.gz"]},
    )


def test_detection_round_trip() -> None:
    det = sample_detection()
    payload = det.model_dump()
    cloned = Detection.model_validate(payload)
    assert cloned == det


def test_prediction_round_trip_and_score_bounds() -> None:
    pred = Prediction(label="TP", score=0.62, rationale="meets policy")
    payload = json.loads(pred.model_dump_json())
    reconstructed = Prediction.model_validate(payload)
    assert reconstructed == pred

    with pytest.raises(ValidationError):
        Prediction(label="TP", score=1.5)

    with pytest.raises(ValidationError):
        Prediction(label="TP", score=-0.1)


def test_model_json_schema_contains_expected_fields() -> None:
    schema = Detection.model_json_schema()
    props = schema["properties"]
    assert set(props) >= {
        "rule_id",
        "smell",
        "tech",
        "file",
        "line",
        "snippet",
        "message",
        "severity",
        "evidence",
    }

    pred_schema = Prediction.model_json_schema()
    assert pred_schema["properties"]["label"]["enum"] == ["TP", "FP"]


def test_detection_rejects_extra_fields() -> None:
    payload = sample_detection().model_dump()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        Detection.model_validate(payload)

def test_detection_accepts_extended_smells() -> None:
    Detection(
        rule_id="SEC_ADMIN",
        smell="admin-by-default",
        tech="chef",
        file="cookbooks/default.rb",
        line=3,
        snippet="default['app']['user'] = 'admin'",
        message="Admin by default",
        severity="medium",
        evidence={},
    )

