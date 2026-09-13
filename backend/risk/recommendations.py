"""Human-review response recommendations. No destructive action is automated."""
from __future__ import annotations

def recommendations(threat_type: str, event: dict, ioc_status: str = "Unknown") -> list[str]:
    text = f"{threat_type} {event.get('event_type', '')}".lower()
    out = []
    if "brute" in text or "login" in text or "credential" in text:
        out += ["Investigate affected account", "Review authentication logs", "Investigate source IP"]
        if event.get("after_hours_activity") in (1, 1.0, True) or event.get("event_status") == "Failed":
            out.append("Consider temporary account protection and verify MFA policy")
    elif "malware" in text:
        out += ["Isolate the affected endpoint for analyst review", "Run an approved malware scan", "Investigate file hash and related processes"]
    elif "exfil" in text or "transfer" in text:
        out += ["Investigate destination", "Review data transfer logs", "Restrict suspicious connection if validated by the SOC"]
    elif "lateral" in text:
        out += ["Review authentication and remote-service activity", "Investigate source and destination assets"]
    else:
        out += ["Investigate the affected asset", "Review related security events", "Validate the alert with available telemetry"]
    if str(ioc_status).lower() in {"malicious", "high"}:
        out.append("Investigate the malicious IOC and related activity")
    out.append("Escalate to SOC Level 2 if the threat is confirmed")
    return list(dict.fromkeys(out))
