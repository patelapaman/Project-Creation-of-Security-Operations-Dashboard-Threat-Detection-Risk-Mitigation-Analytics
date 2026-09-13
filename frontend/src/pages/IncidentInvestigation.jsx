import React,{useEffect,useState} from "react";
import {useNavigate,useParams} from "react-router-dom";
import DashboardLayout from "../components/layout/DashboardLayout";
import {getM3Incident,updateM3IncidentStatus} from "../services/api";
import "./RiskIntelligence.css";

export default function IncidentInvestigation(){
 const {id}=useParams(), nav=useNavigate(), [item,setItem]=useState(null), [error,setError]=useState("");
 useEffect(()=>{getM3Incident(id).then(x=>{if(x?.error)setError(x.error);else setItem(x)}).catch(e=>setError(e.message))},[id]);
 if(error) return <DashboardLayout pageTitle="Incident Investigation"><div className="ri-empty">{error}</div></DashboardLayout>;
 if(!item) return <DashboardLayout pageTitle="Incident Investigation"><div className="ri-loading">Loading incident...</div></DashboardLayout>;
 const update=async e=>{const x=await updateM3IncidentStatus(id,e.target.value);setItem(x)};
 return <DashboardLayout pageTitle="Incident Investigation"><div className="ri-page">
  <button className="ri-back" onClick={()=>nav("/dashboard/risk-intelligence")}>← Back to Risk Intelligence</button>
  <div className="ri-hero"><div><div className="ri-eyebrow">INCIDENT INVESTIGATION</div><h1>{item.incident_id}</h1><p>{item.threat_type}</p></div><div className={`ri-big-score ${String(item.risk_level).toLowerCase()}`}><strong>{item.risk_score}</strong><span>/ 100 · {item.risk_level}</span></div></div>
  <div className="ri-detail-grid">
   <Info title="Affected Asset" value={item.affected_asset||item.asset_id}/><Info title="User" value={item.affected_user||"Unknown"}/><Info title="ML Confidence" value={`${item.ml_confidence}%`}/><Info title="CVSS" value={item.cvss_score||"—"}/><Info title="IOC" value={item.ioc_status||"Unknown"}/><Info title="MITRE" value={(item.mitre_techniques||[]).join(", ")||"—"}/>
  </div>
  <div className="ri-grid">
   <section className="ri-card"><h2>Why is this risk high?</h2><ul className="ri-list">{(item.reasons||[]).map((x,i)=><li key={i}>{x}</li>)}</ul></section>
   <section className="ri-card"><h2>Recommended Actions</h2><ol className="ri-list">{(item.recommendations||[]).map((x,i)=><li key={i}>{x}</li>)}</ol><div className="ri-note">Recommendations are for analyst review; no destructive security action is automated.</div></section>
  </div>
  <section className="ri-card"><h2>Attack Chain</h2><p>Related events and MITRE stages detected within the correlation window.</p><div className="ri-chain">{(item.attack_chain?.stages||[]).map((s,i)=><React.Fragment key={s}><div className="ri-stage"><span>{i+1}</span><b>{s}</b>{item.attack_chain?.techniques?.[i]&&<small>{item.attack_chain.techniques[i]}</small>}</div>{i<(item.attack_chain?.stages?.length||0)-1&&<div className="ri-arrow">↓</div>}</React.Fragment>)}</div></section>
  <section className="ri-card"><div className="ri-status-row"><div><h2>Related Events</h2><p>{item.event_ids?.length||0} event(s) correlated.</p></div><select value={item.status} onChange={update}><option>Open</option><option>Investigating</option><option>Resolved</option><option>False Positive</option></select></div><div className="ri-table-wrap"><table className="ri-table"><thead><tr><th>Event</th><th>Type</th><th>Prediction</th><th>Confidence</th><th>Asset</th><th>MITRE</th><th>Time</th></tr></thead><tbody>{(item.related_events||[]).map(e=><tr key={e.event_id}><td className="mono">{e.event_id}</td><td>{e.event_type}</td><td>{e.prediction}</td><td>{e.confidence_score}%</td><td>{e.asset_name||e.asset_id||e.asset}</td><td>{e.mitre_technique||"—"}</td><td>{String(e.timestamp).replace("T"," ").replace("Z","")}</td></tr>)}</tbody></table></div></section>
 </div></DashboardLayout>
}
function Info({title,value}){return <div className="ri-info"><span>{title}</span><strong>{value}</strong></div>}
