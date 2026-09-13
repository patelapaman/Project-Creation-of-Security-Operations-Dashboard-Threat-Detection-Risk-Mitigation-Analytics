import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from risk.risk_score import calculate_risk, vulnerability_component
from risk.correlation import correlate_events, attack_chain
from risk.recommendations import recommendations
from services.risk_service import RiskService

def test_reference_risk_score():
    r=calculate_risk(threat_severity=90, ml_confidence=92, asset_criticality="Critical",
                     vulnerability_exposure=95, threat_intelligence=80)
    assert r["risk_score"] == 92.5
    assert r["risk_level"] == "Critical"

def test_score_bounds_and_asset_mapping():
    assert calculate_risk(threat_severity=999, ml_confidence=999, asset_criticality="Critical",
                          vulnerability_exposure=999, threat_intelligence=999)["risk_score"] == 100
    assert calculate_risk(threat_severity=0, ml_confidence=0, asset_criticality="Low",
                          vulnerability_exposure=0, threat_intelligence=0)["risk_score"] == 5

def test_vulnerability_normalization():
    assert vulnerability_component(9.8) == 98
    assert vulnerability_component(9.0, 2, True) == 100

def test_event_correlation_window():
    base={"event_id":"A","timestamp":"2026-08-26T10:00:00Z","user":"u1","source_ip":"1.1.1.1","asset":"DB"}
    near={**base,"event_id":"B","timestamp":"2026-08-26T10:20:00Z","event_type":"Privilege Escalation"}
    far={**base,"event_id":"C","timestamp":"2026-08-26T10:45:00Z"}
    groups=correlate_events([base,near,far],30)
    assert len(groups)==1 and {x["event_id"] for x in groups[0]}=={"A","B"}

def test_attack_chain_stages():
    group=[
      {"event_id":"1","timestamp":"2026-08-26T10:00:00Z","event_type":"Brute Force"},
      {"event_id":"2","timestamp":"2026-08-26T10:05:00Z","event_type":"Privilege Escalation"},
      {"event_id":"3","timestamp":"2026-08-26T10:10:00Z","event_type":"Lateral Movement"},
      {"event_id":"4","timestamp":"2026-08-26T10:15:00Z","event_type":"Data Exfiltration"},
    ]
    chain=attack_chain(group)
    assert chain["stages"]==["Credential Access","Privilege Escalation","Lateral Movement","Exfiltration"]

def test_recommendations_are_non_destructive():
    out=recommendations("Brute Force",{"event_type":"Brute Force","after_hours_activity":1},"Malicious")
    assert any("source IP" in x for x in out)
    assert not any(x.lower().startswith(("delete","format","shutdown")) for x in out)

def test_service_loads_bundled_enrichment():
    svc=RiskService()
    assert svc.assets and svc.vulnerabilities and svc.iocs and svc.mitre
    result=svc.calculate({"event":{"event_id":"T","event_type":"Brute Force","asset":"Production Database","cvss_score":9.2,
                                   "failed_login_attempts":25,"source_ip":"185.91.22.14","user":"u","timestamp":"2026-08-26T10:00:00Z"},
                          "prediction":"Suspicious","threat_type":"Brute Force","confidence_score":92,
                          "severity":"High Threat","reasons":[]})
    assert result["risk_score"] > 70
    assert result["ioc_status"] in {"High","Malicious"}
    assert result["mitre_technique"]=="T1110"
