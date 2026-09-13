"""Explainable Milestone 3 risk scoring.

The score is an operational prioritization score (0-100), not a probability.
Default weights follow the Milestone 3 brief and are configurable.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

DEFAULT_WEIGHTS = {
    "threat_severity": 0.25,
    "ml_confidence": 0.25,
    "asset_criticality": 0.20,
    "vulnerability_exposure": 0.20,
    "threat_intelligence": 0.10,
}
ASSET_CRITICALITY = {"Critical": 100.0, "High": 75.0, "Medium": 50.0, "Low": 25.0}
SEVERITY_SCORE = {
    "Critical Threat": 100.0, "Critical": 100.0,
    "High Threat": 80.0, "High": 80.0,
    "Medium Threat": 60.0, "Moderate": 60.0,
    "Low Threat": 40.0, "Low": 20.0,
    "Normal": 0.0,
}
IOC_SCORE = {"malicious": 100.0, "high": 80.0, "suspicious": 60.0, "unknown": 0.0, "clean": 0.0, "none": 0.0}

def clamp(v: float, lo=0.0, hi=100.0) -> float:
    return max(lo, min(hi, float(v)))

def number(v: Any, default=0.0) -> float:
    try:
        if v is None or v == "":
            return default
        return float(v)
    except (TypeError, ValueError):
        return default

def severity_component(value: Any) -> float:
    if isinstance(value, (int, float)):
        return clamp(number(value) if number(value) > 10 else number(value) * 10)
    return SEVERITY_SCORE.get(str(value).strip(), 0.0)

def vulnerability_component(cvss: Any, vulnerability_count: Any = 0, exploit_available: Any = False) -> float:
    base = clamp(number(cvss) * 10.0)
    count_bonus = min(15.0, max(0.0, number(vulnerability_count)) * 5.0)
    exploit_bonus = 10.0 if str(exploit_available).lower() in {"yes", "true", "1"} else 0.0
    # Keep this component normalized to 0-100.
    return clamp(base + count_bonus + exploit_bonus)

def calculate_risk(*, threat_severity: Any, ml_confidence: Any,
                   asset_criticality: Any, vulnerability_exposure: Any,
                   threat_intelligence: Any, weights: dict[str, float] | None = None) -> dict[str, Any]:
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    total_weight = sum(float(x) for x in w.values())
    if total_weight <= 0:
        raise ValueError("Risk weights must have a positive total.")
    # Normalize custom weights so changing them cannot accidentally push score >100.
    w = {k: float(v) / total_weight for k, v in w.items()}
    components = {
        "threat_severity": clamp(severity_component(threat_severity)),
        "ml_confidence": clamp(number(ml_confidence)),
        "asset_criticality": clamp(ASSET_CRITICALITY.get(str(asset_criticality).title(), number(asset_criticality))),
        "vulnerability_exposure": clamp(number(vulnerability_exposure)),
        "threat_intelligence": clamp(number(threat_intelligence)),
    }
    score = sum(components[k] * w[k] for k in components)
    score = round(clamp(score), 2)
    if score <= 20: level = "Low"
    elif score <= 40: level = "Medium"
    elif score <= 60: level = "Moderate"
    elif score <= 80: level = "High"
    else: level = "Critical"
    return {"risk_score": score, "risk_level": level, "components": components, "weights": w}
