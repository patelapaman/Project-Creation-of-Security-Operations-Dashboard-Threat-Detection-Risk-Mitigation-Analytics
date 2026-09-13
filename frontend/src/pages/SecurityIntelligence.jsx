import React,{useEffect,useState} from "react";
import DashboardLayout from "../components/layout/DashboardLayout";
import {getM3AttackChains,getM3Intelligence} from "../services/api";
import "./RiskIntelligence.css";

export default function SecurityIntelligence(){
 const [chains,setChains]=useState([]),[intel,setIntel]=useState([]),[loading,setLoading]=useState(true);
 useEffect(()=>{Promise.all([getM3AttackChains(),getM3Intelligence()]).then(([a,b])=>{setChains(a||[]);setIntel(b||[])}).finally(()=>setLoading(false))},[]);
 if(loading)return <DashboardLayout pageTitle="Security Intelligence"><div className="ri-loading">Loading threat intelligence...</div></DashboardLayout>;
 return <DashboardLayout pageTitle="Security Intelligence"><div className="ri-page">
  <div className="ri-hero"><div><div className="ri-eyebrow">MILESTONE 3 · ENRICHMENT & CORRELATION</div><h1>Security Intelligence</h1><p>Review MITRE ATT&CK context, CVE/CVSS exposure, IOC enrichment and correlated attack chains.</p></div></div>
  <section className="ri-card"><h2>Attack Chains</h2><p>Possible multi-stage activity correlated inside the 30-minute window.</p><div className="ri-chain-list">{chains.length?chains.map(c=><div className="ri-chain-row" key={c.attack_chain_id}><div><b>{c.attack_chain_id}</b><span>{c.incident_id}</span></div><strong>{c.risk_score}</strong><div className="ri-stage-line">{(c.stages||[]).map((s,i)=><React.Fragment key={s}><span>{s}</span>{i<c.stages.length-1&&<em>→</em>}</React.Fragment>)}</div><small>Techniques: {(c.techniques||[]).join(", ")||"—"} · Events: {(c.events||[]).length}</small></div>):<div className="ri-empty">No multi-stage chains detected.</div>}</div></section>
  <section className="ri-card"><h2>Threat Intelligence Enrichment</h2><p>Incident-linked vulnerability and IOC context.</p><div className="ri-table-wrap"><table className="ri-table"><thead><tr><th>Incident</th><th>Asset</th><th>CVE</th><th>CVSS</th><th>Exposure</th><th>IOC</th><th>Actor</th><th>MITRE</th></tr></thead><tbody>{intel.map(x=><tr key={x.incident_id}><td className="mono">{x.incident_id}</td><td>{x.asset||"—"}</td><td>{x.cve_id||"—"}</td><td>{x.cvss_score||"—"}</td><td>{x.vulnerability_exposure??"—"}</td><td>{x.ioc_status||"Unknown"}</td><td>{x.threat_actor||"—"}</td><td>{x.mitre_technique||"—"} {x.mitre_technique_name?`· ${x.mitre_technique_name}`:""}</td></tr>)}</tbody></table></div></section>
 </div></DashboardLayout>
}
