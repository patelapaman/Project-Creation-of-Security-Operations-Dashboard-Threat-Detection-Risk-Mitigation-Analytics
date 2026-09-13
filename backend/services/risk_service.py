"""Milestone 3 orchestration: Milestone 2 output -> enrichment -> correlation -> risk -> incident."""
from __future__ import annotations
from pathlib import Path
import pandas as pd
from risk.risk_score import calculate_risk, vulnerability_component
from risk.prioritization import priority_for, sort_incidents
from risk.recommendations import recommendations
from risk.correlation import correlate_events, build_attack_chains

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

class RiskService:
    def __init__(self):
        self.assets = self._read("assets.csv")
        self.vulnerabilities = self._read("vulnerabilities.csv")
        self.iocs = self._read("threat_intelligence.csv")
        self.mitre = self._read("mitre_attack_mapping.csv")
        self.cache = []
        self.incidents = {}
        self.status_overrides = {}

    def _read(self, name):
        p=DATA_DIR/name
        if not p.exists():
            return []
        frame = pd.read_csv(p)
        frame = frame.astype(object).where(pd.notna(frame), None)
        return frame.to_dict("records")

    def _asset(self, e):
        aid=str(e.get("asset_id") or "")
        an=str(e.get("asset") or e.get("asset_name") or "")
        for a in self.assets:
            if aid and str(a.get("asset_id")) == aid: return a
            if an and str(a.get("asset_name","")).lower() == an.lower(): return a
        low=an.lower()
        if any(x in low for x in ("database","production","payment")): c="Critical"
        elif any(x in low for x in ("server","application")): c="High"
        elif any(x in low for x in ("test", "testing")): c="Low"
        else: c="Medium"
        return {"asset_id": aid or an or "UNKNOWN", "asset_name": an or "Unknown Asset", "criticality": c, "department": e.get("department","Unknown")}

    def _vuln(self,e):
        cvss=float(e.get("cvss_score") or 0)
        vid=str(e.get("vulnerability_id") or e.get("event",{}).get("vulnerability_id") or "")
        found=None
        for v in self.vulnerabilities:
            if vid and str(v.get("vulnerability_id"))==vid: found=v; break
            if str(v.get("cve_id")) == str(e.get("cve_id")) and e.get("cve_id"): found=v; break
        if found:
            cvss=max(cvss,float(found.get("cvss_score") or 0))
        return found, vulnerability_component(cvss, e.get("vulnerability_count",0), found.get("exploit_available") if found else False)

    def _ioc(self,e):
        vals={str(e.get("source_ip") or ""),str(e.get("destination_ip") or "")}
        for x in self.iocs:
            if str(x.get("indicator_value") or "") in vals:
                return x
        return None

    def _mitre(self,e):
        event_type=str(e.get("event_type") or e.get("threat_type") or "")
        for m in self.mitre:
            if str(m.get("event_type","")).lower() == event_type.lower(): return m
        # Milestone 3 examples for common threat names.
        low=event_type.lower()
        defaults=[("brute", "T1110","Brute Force","Credential Access"),("phish","T1566","Phishing","Initial Access"),
                  ("lateral","T1021","Remote Services","Lateral Movement"),("exfil","T1041","Exfiltration Over C2 Channel","Exfiltration"),
                  ("privilege","T1068","Exploitation for Privilege Escalation","Privilege Escalation")]
        for k,mid,name,tactic in defaults:
            if k in low: return {"mitre_id":mid,"technique_name":name,"tactic":tactic}
        return {}

    def enrich(self,prediction):
        e=dict(prediction.get("event") or {})
        # Normalize Milestone 2 naming without altering the original prediction.
        out={**e, **prediction}
        out["user_id"]=e.get("user_id") or e.get("user") or e.get("username") or "Unknown"
        out["asset_id"]=e.get("asset_id") or e.get("asset") or e.get("asset_name") or "UNKNOWN"
        asset=self._asset(e); vuln,vscore=self._vuln(e); ioc=self._ioc(e); mitre=self._mitre(e)
        out["asset_criticality"]=asset.get("criticality","Medium")
        out["asset_name"]=asset.get("asset_name") or asset.get("hostname") or out["asset_id"]
        out["department"]=e.get("department") or asset.get("department","Unknown")
        out["vulnerability_exposure"]=round(vscore,2)
        out["cve_id"]=(vuln or {}).get("cve_id") or e.get("cve_id")
        out["ioc_status"]=(ioc or {}).get("severity","Malicious" if ioc else "Unknown")
        out["threat_actor"]=(ioc or {}).get("threat_actor")
        out["mitre_technique"]=mitre.get("mitre_id")
        out["mitre_technique_name"]=mitre.get("technique_name")
        out["mitre_tactic"]=mitre.get("tactic")
        out["ioc_indicator"]=(ioc or {}).get("indicator_value")
        out["ioc_confidence"]=(ioc or {}).get("confidence")
        return out

    def calculate(self,prediction):
        e=self.enrich(prediction)
        r=calculate_risk(threat_severity=e.get("severity"),ml_confidence=e.get("confidence_score",0),
                         asset_criticality=e.get("asset_criticality"),vulnerability_exposure=e.get("vulnerability_exposure",0),
                         threat_intelligence={"malicious":100,"high":80,"suspicious":60}.get(str(e.get("ioc_status","")).lower(),0))
        e.update(r)
        e["priority"]=priority_for(e["risk_level"],e["risk_score"])
        reasons=[]
        c=e["components"]
        if c["asset_criticality"]>=75: reasons.append(f"{e['asset_criticality']} asset")
        if c["ml_confidence"]>=80: reasons.append("High ML confidence")
        if c["vulnerability_exposure"]>=70: reasons.append("High vulnerability exposure")
        if c["threat_intelligence"]>=80: reasons.append("Malicious/high-confidence IOC")
        reasons += [x for x in prediction.get("reasons",[]) if x not in reasons]
        if e.get("mitre_technique"): reasons.append(f"MITRE {e['mitre_technique']} — {e.get('mitre_technique_name') or e.get('mitre_tactic')}")
        e["reasons"]=list(dict.fromkeys(reasons))
        e["recommendations"]=recommendations(e.get("threat_type","Security Event"),e,e.get("ioc_status","Unknown"))
        return e

    def build(self,predictions):
        enriched=[self.calculate(p) for p in predictions if p.get("prediction")!="Normal"]
        # Correlate enriched events; one incident per cluster, plus single-event incidents.
        groups=correlate_events(enriched,30)
        grouped={x.get("event_id") for g in groups for x in g}
        incidents=[]
        seq=1
        for group in groups:
            incidents.append(self._incident(group,seq)); seq+=1
        for e in enriched:
            if e.get("event_id") not in grouped:
                incidents.append(self._incident([e],seq)); seq+=1
        incidents=sort_incidents(incidents)
        old_by_events={tuple(sorted(x.get("event_ids",[]))):x.get("status","Open") for x in self.cache}
        for i,x in enumerate(incidents,1):
            x["incident_id"]=f"INC-M3-{i:04d}"
            signature=tuple(sorted(x.get("event_ids",[])))
            x["status"]=self.status_overrides.get(x["incident_id"], old_by_events.get(signature,"Open"))
        self.cache=incidents
        self.incidents={x["incident_id"]:x for x in incidents}
        return incidents

    def _incident(self,group,seq):
        top=max(group,key=lambda x:float(x.get("risk_score",0)))
        ids=[x.get("event_id") for x in group if x.get("event_id")]
        chain=build_attack_chains(group,30)
        attack=chain[0] if chain else {"stages":[x.get("mitre_tactic") for x in group if x.get("mitre_tactic")],"techniques":list(dict.fromkeys(x.get("mitre_technique") for x in group if x.get("mitre_technique"))),"events":ids,"stage":top.get("mitre_tactic") or "Investigation","confidence":min(99,60+len(group)*5)}
        return {
            "incident_id":f"INC-M3-TEMP-{seq:04d}","event_ids":ids,
            "threat_type":("Possible Multi-Stage Attack" if len(group)>1 and len(attack.get("stages",[]))>=2 else top.get("threat_type","Security Event")),
            "risk_score":top.get("risk_score",0),"risk_level":top.get("risk_level","Low"),"priority":top.get("priority","Low"),
            "asset_id":top.get("asset_id"),"affected_asset":top.get("asset_name"),"asset_criticality":top.get("asset_criticality","Medium"),
            "department":top.get("department"),"affected_user":top.get("user_id"),"ml_confidence":top.get("confidence_score",0),
            "cve_id":top.get("cve_id"),"ioc_indicator":top.get("ioc_indicator"),"mitre_tactic":top.get("mitre_tactic"),
            "cvss_score":top.get("cvss_score",0),"vulnerability_exposure":top.get("vulnerability_exposure",0),
            "ioc_status":top.get("ioc_status","Unknown"),"threat_actor":top.get("threat_actor"),
            "mitre_techniques":list(dict.fromkeys(x.get("mitre_technique") for x in group if x.get("mitre_technique"))),
            "status":"Open","recommendations":top.get("recommendations",[]),
            "reasons":top.get("reasons",[])+([f"{len(group)} related events correlated within 30 minutes"] if len(group)>1 else []),
            "related_events":group,"attack_chain":attack,
            "created_at":str(top.get("prediction_timestamp") or top.get("timestamp") or "")
        }

    def summary(self):
        if not self.cache: self.build([])
        levels={x:0 for x in ("Critical","High","Medium","Low")}
        for i in self.cache:
            level=i.get("risk_level","Low")
            if level=="Moderate": level="Medium"
            levels[level]=levels.get(level,0)+1
        return {"total_incidents":len(self.cache),"critical":levels["Critical"],"high":levels["High"],"medium":levels["Medium"],"low":levels["Low"],
                "open_incidents":sum(i.get("status")=="Open" for i in self.cache),"risk_distribution":[{"name":k,"value":v} for k,v in levels.items()],
                "risk_trend":[{"timestamp":i.get("created_at"),"risk_score":i.get("risk_score"),"incident_id":i.get("incident_id")} for i in sorted(self.cache,key=lambda x:x.get("created_at",""))]}
