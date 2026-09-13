"""Threat prioritization helpers for Milestone 3."""
from __future__ import annotations
PRIORITY_BY_LEVEL = {"Critical": "Immediate", "High": "High", "Moderate": "Medium", "Medium": "Medium", "Low": "Low"}
def priority_for(level: str, score: float) -> str:
    if float(score) >= 90: return "Immediate"
    return PRIORITY_BY_LEVEL.get(level, "Medium")
def sort_incidents(items):
    return sorted(items, key=lambda x: (float(x.get("risk_score", 0)), x.get("created_at", "")), reverse=True)
