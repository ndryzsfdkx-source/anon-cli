
"""Core schema models shared across detectors, post-filter, and exporters."""
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Smell = Literal[
    "http",
    "weak-crypto",
    "hardcoded-secret",
    "suspicious-comment",
    "admin-by-default",
    "empty-password",
    "invalid-bind",
    "no-integrity-check",
    "missing-default-switch",
]
Tech = Literal["ansible", "chef", "puppet"]
Severity = Literal["low", "medium", "high"]
Label = Literal["TP", "FP"]


class Detection(BaseModel):
    """Normalized GLITCH finding shared across the pipeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    smell: Smell
    tech: Tech
    file: str
    line: int = Field(ge=1)
    snippet: str
    message: str
    severity: Severity
    evidence: Dict[str, Any] = Field(default_factory=dict)


class Prediction(BaseModel):
    """Post-filter judgement for an individual detection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label: Label
    score: float = Field(ge=0.0, le=1.0)
    rationale: Optional[str] = None

