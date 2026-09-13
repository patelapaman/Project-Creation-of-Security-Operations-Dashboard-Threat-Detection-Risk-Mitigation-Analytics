"""Dashboard data queries with MongoDB-first, CSV fallback behavior."""
from pathlib import Path
import pandas as pd
from database.mongodb import get_db, is_mongodb_connected

DATA_DIR=Path(__file__).resolve().parents[1]/"data"
CSV_MAP={"assets":"assets.csv","vulnerabilities":"vulnerabilities.csv","security_events":"security_events.csv",
         "threat_intelligence":"threat_intelligence.csv","incident_history":"incident_history.csv","mitre_mapping":"mitre_attack_mapping.csv",
         "enriched_events":None,"mapped_events":None,"engineered_features":None}

def get_collection(collection_name):
    if is_mongodb_connected():
        return list(get_db()[collection_name].find({},{"_id":0}))
    filename=CSV_MAP.get(collection_name)
    if filename:
        p=DATA_DIR/filename
        if p.exists():
            frame=pd.read_csv(p)
            frame=frame.astype(object).where(pd.notna(frame),None)
            return frame.to_dict("records")
    return []

def get_assets(): return get_collection("assets")
def get_vulnerabilities(): return get_collection("vulnerabilities")
def get_security_events(): return get_collection("security_events")
def get_incidents(): return get_collection("incident_history")
def get_threats(): return get_collection("threat_intelligence")
def get_mitre(): return get_collection("mitre_mapping")
def get_enriched_events(): return get_collection("enriched_events")
def get_mapped_events(): return get_collection("mapped_events")
def get_features(): return get_collection("engineered_features")

def get_high_risk_assets():
    if is_mongodb_connected():
        return list(get_db()["engineered_features"].find({"risk_category":{"$in":["High","Critical"]}},{"_id":0}))
    return []

def get_dashboard_summary():
    if is_mongodb_connected():
        db=get_db()
        return {"assets":db["assets"].count_documents({}),"vulnerabilities":db["vulnerabilities"].count_documents({}),
                "security_events":db["security_events"].count_documents({}),"incidents":db["incident_history"].count_documents({}),
                "threats":db["threat_intelligence"].count_documents({}),"mapped_events":db["mapped_events"].count_documents({}),
                "high_risk_assets":db["engineered_features"].count_documents({"risk_category":{"$in":["High","Critical"]}})}
    return {"assets":len(get_assets()),"vulnerabilities":len(get_vulnerabilities()),"security_events":len(get_security_events()),
            "incidents":len(get_incidents()),"threats":len(get_threats()),"mapped_events":0,"high_risk_assets":0}
