"""Milestone 3 Risk Intelligence API (Flask implementation integrated with existing app)."""
from flask import Blueprint, jsonify, request
from services.risk_service import RiskService
from milestone2_engine.database.repository import repository
from database.mongodb import get_db, is_mongodb_connected

risk_bp=Blueprint("risk_m3",__name__)
service=RiskService()

def current():
    return service.build(repository.all(2000))

def persist(incident):
    if not is_mongodb_connected(): return False
    db=get_db()
    doc=dict(incident); doc.pop("_id",None)
    db["incidents"].replace_one({"incident_id":doc["incident_id"]},doc,upsert=True)
    return True

@risk_bp.get("/calculate")
def calculate_info():
    # GET is useful for smoke tests; POST is the documented calculation contract.
    return jsonify({"method":"POST","endpoint":"/api/v1/risk/calculate","formula":"25% severity + 25% ML confidence + 20% asset criticality + 20% vulnerability exposure + 10% threat intelligence"})

@risk_bp.post("/calculate")
def calculate():
    body=request.get_json(silent=True) or {}
    # Accept either a raw Milestone-2 prediction or a direct event-like object.
    prediction=body if "event" in body else {"event":body,"prediction":body.get("prediction","Suspicious"),
        "threat_type":body.get("threat_type",body.get("event_type","Security Event")),
        "confidence_score":body.get("confidence_score",body.get("ml_confidence",0)),
        "severity":body.get("severity","Medium Threat"),"reasons":[]}
    result=service.calculate(prediction)
    return jsonify(result)

@risk_bp.get("/high")
def high():
    items=current()
    return jsonify([x for x in items if float(x.get("risk_score",0))>=61])

@risk_bp.get("/summary")
def summary():
    current()
    return jsonify(service.summary())

@risk_bp.get("/incidents")
def incidents():
    items=current()
    # Persist generated M3 incidents when MongoDB is available.
    for i in items: persist(i)
    return jsonify(items)



@risk_bp.post("/incidents")
def create_incident():
    body=request.get_json(silent=True) or {}
    # Preferred input is a Milestone-2 prediction object. This keeps M-3 an extension,
    # not a replacement, of the detection layer.
    if "event" in body:
        result=service.calculate(body)
    else:
        event=body.get("event",body)
        result=service.calculate({"event":event,"prediction":"Suspicious","threat_type":body.get("threat_type",event.get("event_type","Security Event")),
                                  "confidence_score":body.get("confidence_score",0),"severity":body.get("severity","Medium Threat"),"reasons":[]})
    incident=service._incident([result],len(service.cache)+1)
    incident["incident_id"]=f"INC-M3-{len(service.cache)+1:04d}"
    service.incidents[incident["incident_id"]]=incident
    service.cache.append(incident)
    persist(incident)
    return jsonify(incident),201

@risk_bp.get("/incidents/<incident_id>")
def incident_detail(incident_id):
    items=current()
    found=next((x for x in items if x["incident_id"]==incident_id),None)
    if not found and is_mongodb_connected():
        found=get_db()["incidents"].find_one({"incident_id":incident_id},{"_id":0})
    if not found: return jsonify({"error":"Incident not found"}),404
    return jsonify(found)

@risk_bp.get("/attack-chains")
def attack_chains():
    items=current()
    chains=[]
    for i in items:
        ac=i.get("attack_chain",{})
        if len(ac.get("events",[]))>1:
            chains.append({"attack_chain_id":f"AC-{i['incident_id'].replace('INC-M3-','')}","incident_id":i["incident_id"],**ac,"risk_score":i["risk_score"]})
    return jsonify(chains)

@risk_bp.get("/recommendations/<incident_id>")
def recs(incident_id):
    items=current()
    found=next((x for x in items if x["incident_id"]==incident_id),None)
    if not found: return jsonify({"error":"Incident not found"}),404
    return jsonify({"incident_id":incident_id,"recommendations":found.get("recommendations",[])})

@risk_bp.get("/intelligence")
def intelligence():
    items=current()
    return jsonify([{"incident_id":x["incident_id"],"cve_id":x.get("cve_id"),"cvss_score":x.get("cvss_score"),
                     "vulnerability_exposure":x.get("vulnerability_exposure"),"ioc_status":x.get("ioc_status"),
                     "ioc_indicator":x.get("ioc_indicator"),"threat_actor":x.get("threat_actor"),
                     "mitre_technique":x.get("mitre_technique"),"mitre_technique_name":x.get("mitre_technique_name"),
                     "asset":x.get("affected_asset")} for x in items])

@risk_bp.patch("/incidents/<incident_id>/status")
def update_status(incident_id):
    body=request.get_json(silent=True) or {}
    status=body.get("status")
    allowed={"Open","Investigating","Resolved","False Positive"}
    if status not in allowed: return jsonify({"error":"Invalid status","allowed":sorted(allowed)}),422
    items=current(); found=next((x for x in items if x["incident_id"]==incident_id),None)
    if not found: return jsonify({"error":"Incident not found"}),404
    found["status"]=status
    service.status_overrides[incident_id]=status
    service.incidents[incident_id]=found
    persist(found)
    return jsonify(found)
