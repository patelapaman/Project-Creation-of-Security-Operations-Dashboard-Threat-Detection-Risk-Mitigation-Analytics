"""Simple deterministic event correlation and attack-chain identification."""
from __future__ import annotations
from datetime import datetime, timezone
from collections import defaultdict

STAGE = {
    "brute force": ("Credential Access", "T1110"),
    "failed login": ("Credential Access", "T1110"),
    "successful login": ("Initial Access", "T1078"),
    "phishing": ("Initial Access", "T1566"),
    "privilege escalation": ("Privilege Escalation", "T1068"),
    "lateral movement": ("Lateral Movement", "T1021"),
    "remote service": ("Lateral Movement", "T1021"),
    "data exfiltration": ("Exfiltration", "T1041"),
    "large data transfer": ("Exfiltration", "T1041"),
}
ORDER = {"Initial Access": 1, "Credential Access": 2, "Privilege Escalation": 3, "Lateral Movement": 4, "Exfiltration": 5}

def dt(v):
    if isinstance(v, datetime): return v
    s = str(v or "")
    try: return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
    except Exception: return datetime.min.replace(tzinfo=timezone.utc)

def fields_match(a,b):
    keys=("user_id","user","username","source_ip","asset_id","asset","destination_ip")
    matches=0
    for k in keys:
        av=str(a.get(k) or "").strip().lower()
        bv=str(b.get(k) or "").strip().lower()
        if av and bv and av != "unknown" and av != "n/a" and av == bv: matches += 1
    return matches

def correlate_events(events, window_minutes=30):
    """Return groups where events share a meaningful identity/asset field in a time window."""
    rows=sorted(events,key=lambda x:dt(x.get("timestamp")))
    groups=[]
    used=set()
    for i,base in enumerate(rows):
        if base.get("event_id") in used: continue
        group=[base]
        for other in rows[i+1:]:
            delta=(dt(other.get("timestamp"))-dt(base.get("timestamp"))).total_seconds()/60
            if delta > window_minutes: break
            if fields_match(base,other) >= 1:
                group.append(other)
        if len(group) > 1:
            ids={x.get("event_id") for x in group}
            used.update(ids)
            groups.append(group)
    return groups

def attack_chain(group):
    ordered=[]
    for e in sorted(group,key=lambda x:dt(x.get("timestamp"))):
        raw=str(e.get("event_type") or e.get("threat_type") or "").lower()
        stage_tech=None
        for key,val in STAGE.items():
            if key in raw: stage_tech=val; break
        mitre=e.get("mitre_technique") or e.get("mitre_id")
        stage = e.get("mitre_tactic") or (stage_tech[0] if stage_tech else None)
        tech = mitre or (stage_tech[1] if stage_tech else None)
        if stage:
            ordered.append((ORDER.get(stage,99),stage,tech,e.get("event_id")))
    ordered.sort()
    # De-duplicate consecutive stages while retaining all event IDs.
    stages=[]; techniques=[]; ids=[]
    for _,s,t,eid in ordered:
        if s not in stages: stages.append(s)
        if t and t not in techniques: techniques.append(t)
        if eid: ids.append(eid)
    return {"stages": stages, "techniques": techniques, "events": ids,
            "stage": stages[-1] if stages else "Investigation",
            "confidence": min(99, 60 + len(ids)*6 + len(stages)*5)}

def build_attack_chains(events, window_minutes=30):
    return [attack_chain(g) for g in correlate_events(events, window_minutes) if len(attack_chain(g)["stages"]) >= 2]
