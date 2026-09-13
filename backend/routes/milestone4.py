"""Milestone 4 integration/presentation APIs.

M4 intentionally composes M1 source data, M2 predictions and M3 risk incidents
instead of introducing a second data model or hardcoded dashboard numbers.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import json

from flask import Blueprint, jsonify, request, Response

from database.queries import (
    get_security_events,
    get_assets,
    get_vulnerabilities,
    get_threats,
    get_mitre,
)
from database.mongodb import get_db, is_mongodb_connected
from milestone2_engine.database.repository import repository
from milestone2_engine.config import MODEL_VERSION
from services.risk_service import RiskService

m4_bp = Blueprint("milestone4", __name__)
risk_service = RiskService()
DATA_DIR = Path(__file__).resolve().parents[1] / "data"
FEEDBACK_FILE = DATA_DIR / "analyst_feedback.json"


def _num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _dt(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None


def _risk_items():
    """Use the same M2 -> M3 path used by the existing M3 routes."""
    return risk_service.build(repository.all(2000))


def _event_key(e):
    return str(e.get("event_id") or "")


def _latest_timestamp(events):
    dates = [d for d in (_dt(e.get("timestamp")) for e in events) if d]
    return max(dates) if dates else None


def _within_range(timestamp, latest, days):
    if not latest or not timestamp:
        return True
    return (latest - timestamp).total_seconds() <= days * 86400


def _apply_filters(events, args):
    severity = args.get("severity", "").strip().lower()
    event_type = args.get("threat_type", args.get("event_type", "")).strip().lower()
    asset = args.get("asset", "").strip().lower()
    department = args.get("department", "").strip().lower()
    technique = args.get("mitre_technique", "").strip().lower()
    cve = args.get("cve", "").strip().lower()
    ip = args.get("ip", "").strip().lower()
    status = args.get("status", "").strip().lower()
    search = args.get("search", "").strip().lower()
    out = []
    for e in events:
        if search and search not in str(e).lower():
            continue
        if severity and str(e.get("severity", "")).lower() != severity:
            continue
        if event_type and event_type not in str(e.get("event_type", e.get("threat_type", ""))).lower():
            continue
        if asset and asset not in str(e.get("asset_name", e.get("device_name", ""))).lower():
            continue
        if department and department not in str(e.get("department", "")).lower():
            continue
        if technique and technique not in str(e.get("mitre_technique", "")).lower():
            continue
        if cve and cve not in str(e.get("cve_id", e.get("vulnerability_id", ""))).lower():
            continue
        if ip and ip not in f"{e.get('source_ip','')} {e.get('destination_ip','')}".lower():
            continue
        if status and status not in str(e.get("event_status", e.get("status", ""))).lower():
            continue
        out.append(e)
    return out


def _posture(events, incidents, vulnerabilities):
    total = max(len(events), 1)
    critical_vulns = sum(str(v.get("severity", "")).lower() == "critical" and str(v.get("status", "")).lower() not in {"closed", "resolved", "patched"} for v in vulnerabilities)
    active_incidents = sum(str(i.get("status", "Open")) not in {"Resolved", "False Positive", "Closed"} for i in incidents)
    high_risk_assets = len({i.get("affected_asset") for i in incidents if _num(i.get("risk_score")) >= 61 and i.get("affected_asset")})
    unresolved_threats = sum(str(e.get("severity", "")).lower() in {"critical", "high"} for e in events)
    # Components are normalized and capped so the posture remains 0..100.
    penalty = min(100, critical_vulns * 8 + active_incidents * 2 + high_risk_assets * 2 + (unresolved_threats / total) * 50)
    score = round(max(0, min(100, 100 - penalty)), 1)
    label = "Excellent" if score >= 85 else "Good" if score >= 70 else "Needs Attention" if score >= 50 else "Critical Attention"
    return {"score": score, "label": label, "factors": {
        "critical_vulnerabilities": critical_vulns,
        "active_incidents": active_incidents,
        "high_risk_assets": high_risk_assets,
        "unresolved_high_critical_events": unresolved_threats,
    }}


def _build_overview(args):
    events = get_security_events()
    vulnerabilities = get_vulnerabilities()
    assets = get_assets()
    threats = get_threats()
    predictions = repository.all(2000)
    incidents = _risk_items()
    filtered = _apply_filters(events, args)

    latest = _latest_timestamp(events)
    range_days = int(args.get("range", 30) or 30)
    if range_days == 24:
        ranged_events = [e for e in filtered if (not latest or not _dt(e.get("timestamp")) or (latest - _dt(e.get("timestamp"))).total_seconds() <= 86400)]
    else:
        ranged_events = [e for e in filtered if _within_range(_dt(e.get("timestamp")), latest, range_days)]
    event_ids = {_event_key(e) for e in ranged_events}
    ranged_predictions = [p for p in predictions if _event_key(p) in event_ids]
    ranged_incidents = [i for i in incidents if any(eid in event_ids for eid in i.get("event_ids", []))]

    severity = Counter(str(e.get("severity") or "Unknown") for e in ranged_events)
    threat_types = Counter(str(e.get("event_type") or "Unknown") for e in ranged_events)
    event_status = Counter(str(e.get("event_status") or "Unknown") for e in ranged_events)
    protocols = Counter(str(e.get("protocol") or "Unknown") for e in ranged_events)
    countries = Counter(str(e.get("source_country") or "Unknown") for e in ranged_events)
    incident_status = Counter(str(i.get("status") or "Open") for i in ranged_incidents)

    risk_points = []
    for i in sorted(ranged_incidents, key=lambda x: x.get("created_at", "")):
        risk_points.append({"timestamp": i.get("created_at"), "risk_score": _num(i.get("risk_score")), "incident_id": i.get("incident_id")})

    posture = _posture(ranged_events, ranged_incidents, vulnerabilities)
    affected_assets = len({e.get("asset_name") or e.get("device_name") for e in ranged_events if e.get("asset_name") or e.get("device_name")})
    critical_threats = sum(str(e.get("severity", "")).lower() == "critical" for e in ranged_events)
    detected = sum(p.get("prediction") != "Normal" for p in ranged_predictions)
    high_risk = sum(_num(i.get("risk_score")) >= 61 for i in ranged_incidents)
    active = sum(str(i.get("status", "Open")) not in {"Resolved", "False Positive", "Closed"} for i in ranged_incidents)

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "range_days": range_days,
        "model_version": MODEL_VERSION,
        "source": "M1 security_events + M2 predictions + M3 risk incidents",
        "kpis": {
            "total_security_events": len(ranged_events),
            "detected_threats": detected,
            "critical_threats": critical_threats,
            "high_risk_incidents": high_risk,
            "active_incidents": active,
            "affected_assets": affected_assets,
        },
        "security_posture": posture,
        "distributions": {
            "severity": [{"name": k, "value": severity[k]} for k in ("Critical", "High", "Medium", "Low") if severity[k]],
            "threat_type": [{"name": k, "value": v} for k, v in threat_types.most_common(10)],
            "event_status": [{"name": k, "value": v} for k, v in event_status.most_common()],
            "incident_status": [{"name": k, "value": v} for k, v in incident_status.most_common()],
            "protocol": [{"name": k, "value": v} for k, v in protocols.most_common(10)],
            "source_country": [{"name": k, "value": v} for k, v in countries.most_common(10)],
        },
        "risk_trend": risk_points,
        "critical_incidents": sorted(ranged_incidents, key=lambda x: _num(x.get("risk_score")), reverse=True)[:10],
        "predictions": ranged_predictions[:100],
        "counts": {
            "vulnerabilities": len(vulnerabilities),
            "critical_vulnerabilities": sum(str(v.get("severity", "")).lower() == "critical" for v in vulnerabilities),
            "high_vulnerabilities": sum(str(v.get("severity", "")).lower() == "high" for v in vulnerabilities),
            "threat_intelligence": len(threats),
            "assets": len(assets),
        },
    }


@m4_bp.get("/overview")
def overview():
    try:
        return jsonify(_build_overview(request.args))
    except Exception as exc:
        return jsonify({"error": "Unable to build M4 overview", "detail": str(exc)}), 500


@m4_bp.get("/attack-techniques")
def attack_techniques():
    incidents = _risk_items()
    counter = Counter()
    names = {}
    for incident in incidents:
        for technique in incident.get("mitre_techniques", []) or []:
            counter[technique] += 1
        chain = incident.get("related_events", []) or []
        for e in chain:
            if e.get("mitre_technique"):
                names[e["mitre_technique"]] = e.get("mitre_technique_name") or e.get("mitre_technique")
    mapping = get_mitre()
    for m in mapping:
        if m.get("mitre_id"):
            names.setdefault(m["mitre_id"], m.get("technique_name") or m["mitre_id"])
    rows = [{"technique": k, "name": names.get(k, k), "events": v,
             "risk": "Critical" if v >= 20 else "High" if v >= 10 else "Medium"} for k, v in counter.most_common()]
    return jsonify(rows)


@m4_bp.get("/attack-chains")
def attack_chains():
    incidents = _risk_items()
    chains = []
    for incident in incidents:
        chain = incident.get("attack_chain") or {}
        events = chain.get("events", []) or []
        details = {str(e.get("event_id")): {
            "event_id": e.get("event_id"), "timestamp": e.get("timestamp"),
            "source": e.get("source_ip"), "destination": e.get("destination_ip"),
            "user": e.get("user_id") or e.get("username"), "mitre_technique": e.get("mitre_technique"),
            "risk": _num(e.get("risk_score")), "stage": e.get("mitre_tactic") or "Investigation"
        } for e in incident.get("related_events", [])}
        chains.append({"incident_id": incident.get("incident_id"), "risk_score": incident.get("risk_score"),
                       "stages": chain.get("stages", []), "techniques": chain.get("techniques", []),
                       "events": [details.get(str(e), {"event_id": e}) for e in events]})
    return jsonify(chains)


@m4_bp.get("/posture")
def posture():
    data = _build_overview({"range": request.args.get("range", "30")})
    return jsonify(data["security_posture"])


def _read_feedback():
    if is_mongodb_connected():
        return list(get_db()["analyst_feedback"].find({}, {"_id": 0}).sort("timestamp", -1).limit(1000))
    if FEEDBACK_FILE.exists():
        try:
            return json.loads(FEEDBACK_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


@m4_bp.post("/feedback")
def feedback():
    body = request.get_json(silent=True) or {}
    required = ("event_id", "prediction", "actual_feedback")
    if any(not str(body.get(k, "")).strip() for k in required):
        return jsonify({"error": "event_id, prediction and actual_feedback are required"}), 422
    if body["actual_feedback"] not in {"Correct", "False Positive"}:
        return jsonify({"error": "actual_feedback must be Correct or False Positive"}), 422
    doc = {"event_id": str(body["event_id"]), "prediction": str(body["prediction"]),
           "actual_feedback": body["actual_feedback"], "analyst": str(body.get("analyst") or "Unknown"),
           "timestamp": datetime.utcnow().isoformat() + "Z"}
    if is_mongodb_connected():
        get_db()["analyst_feedback"].insert_one(doc)
        storage = "mongodb"
    else:
        current = _read_feedback(); current.append(doc)
        FEEDBACK_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
        storage = "local-file-fallback"
    return jsonify({"status": "stored", "storage": storage, "feedback": doc}), 201


@m4_bp.get("/feedback")
def feedback_list():
    return jsonify(_read_feedback())


@m4_bp.get("/report")
def report():
    data = _build_overview({"range": request.args.get("range", "30")})
    incidents = data["critical_incidents"]
    vulns = get_vulnerabilities()
    techniques = attack_techniques().get_json()
    return jsonify({
        "report_date": datetime.utcnow().isoformat() + "Z",
        "security_posture": data["security_posture"],
        "summary": data["kpis"],
        "vulnerabilities": {
            "total": len(vulns),
            "critical": sum(str(v.get("severity", "")).lower() == "critical" for v in vulns),
            "high": sum(str(v.get("severity", "")).lower() == "high" for v in vulns),
            "records": vulns,
        },
        "top_threats": data["distributions"]["threat_type"],
        "top_mitre_techniques": techniques[:10],
        "critical_incidents": incidents,
        "recommendations": [r for i in incidents for r in (i.get("recommendations") or [])][:15],
    })


@m4_bp.get("/report.csv")
def report_csv():
    import csv
    import io
    data = _build_overview({"range": request.args.get("range", "30")})
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Metric", "Value"])
    for key, value in data["kpis"].items():
        writer.writerow([key, value])
    writer.writerow(["security_posture", data["security_posture"]["score"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=security-m4-report.csv"})
