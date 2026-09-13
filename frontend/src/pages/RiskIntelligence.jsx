import React, {useEffect, useMemo, useState} from "react";
import {useNavigate} from "react-router-dom";
import DashboardLayout from "../components/layout/DashboardLayout";
import {getM3Incidents, getM3Summary} from "../services/api";
import {ResponsiveContainer, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid} from "recharts";
import "./RiskIntelligence.css";

const LEVELS=["All","Critical","High","Medium","Moderate","Low"];

export default function RiskIntelligence(){
  const [items,setItems]=useState([]), [summary,setSummary]=useState(null), [level,setLevel]=useState("All"), [status,setStatus]=useState("All"), [loading,setLoading]=useState(true);
  const navigate=useNavigate();
  const load=()=>{setLoading(true); Promise.all([getM3Incidents(),getM3Summary()]).then(([a,b])=>{setItems(a||[]);setSummary(b||{});}).finally(()=>setLoading(false));};
  useEffect(load,[]);
  const filtered=useMemo(()=>items.filter(x=>(level==="All"||x.risk_level===level)&&(status==="All"||x.status===status)),[items,level,status]);
  if(loading) return <DashboardLayout pageTitle="Risk Intelligence"><div className="ri-loading">Loading Milestone 3 risk engine...</div></DashboardLayout>;
  return <DashboardLayout pageTitle="Risk Intelligence"><div className="ri-page">
    <div className="ri-hero"><div><div className="ri-eyebrow">MILESTONE 3 · SECURITY INTELLIGENCE & DECISION MAKING</div><h1>Risk Prioritization</h1><p>Milestone 2 suspicious events are enriched with asset criticality, CVE/CVSS, MITRE ATT&CK and IOC intelligence before prioritization.</p></div><button className="ri-refresh" onClick={load}>Refresh intelligence</button></div>
    <div className="ri-kpis">
      <Kpi label="Total Incidents" value={summary?.total_incidents??0}/>
      <Kpi label="Critical" value={summary?.critical??0} tone="critical"/>
      <Kpi label="High" value={summary?.high??0} tone="high"/>
      <Kpi label="Medium" value={summary?.medium??0} tone="medium"/>
      <Kpi label="Low" value={summary?.low??0} tone="low"/>
      <Kpi label="Open" value={summary?.open_incidents??0}/>
    </div>
    <div className="ri-grid">
      <section className="ri-card ri-chart"><h2>Risk Distribution</h2><p>Current prioritized incident population.</p><div className="ri-chart-box"><ResponsiveContainer><BarChart data={summary?.risk_distribution||[]}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="name"/><YAxis allowDecimals={false}/><Tooltip/><Bar dataKey="value" fill="var(--accent)" radius={[5,5,0,0]}/></BarChart></ResponsiveContainer></div></section>
      <section className="ri-card"><h2>Risk Trend</h2><p>Risk scores across the prioritized incident timeline.</p><div className="ri-chart-box"><ResponsiveContainer><LineChart data={summary?.risk_trend||[]}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="timestamp" tickFormatter={x=>String(x).slice(5,16)}/><YAxis domain={[0,100]}/><Tooltip/><Line type="monotone" dataKey="risk_score" stroke="var(--accent)" strokeWidth={2}/></LineChart></ResponsiveContainer></div></section>
      <section className="ri-card"><h2>Risk Method</h2><p>Explainable, deterministic scoring aligned with the M-3 brief.</p><div className="ri-formula"><span>Severity</span><b>25%</b><span>ML Confidence</span><b>25%</b><span>Asset Criticality</span><b>20%</b><span>Vulnerability Exposure</span><b>20%</b><span>Threat Intelligence</span><b>10%</b></div><div className="ri-note">The final score is an operational prioritization score from 0–100, not a probability. Related events can be grouped into a possible attack chain.</div></section>
    </div>
    <section className="ri-card"><div className="ri-table-head"><div><h2>Top Priority Incidents</h2><p>Sorted by risk score descending.</p></div><div className="ri-filters"><select value={level} onChange={e=>setLevel(e.target.value)}>{LEVELS.map(x=><option key={x}>{x}</option>)}</select><select value={status} onChange={e=>setStatus(e.target.value)}><option>All</option><option>Open</option><option>Investigating</option><option>Resolved</option><option>False Positive</option></select></div></div>
      <div className="ri-table-wrap"><table className="ri-table"><thead><tr><th>Incident</th><th>Threat</th><th>Risk</th><th>Asset</th><th>Priority</th><th>Status</th><th>Events</th><th></th></tr></thead><tbody>{filtered.slice(0,100).map(x=><tr key={x.incident_id}><td className="mono">{x.incident_id}</td><td>{x.threat_type}</td><td><span className={`ri-risk ${String(x.risk_level).toLowerCase()}`}>{x.risk_score}</span></td><td>{x.affected_asset||x.asset_id}</td><td>{x.priority}</td><td><span className="ri-status">{x.status}</span></td><td>{x.event_ids?.length||0}</td><td><button className="ri-open" onClick={()=>navigate(`/dashboard/risk-intelligence/incidents/${x.incident_id}`)}>Investigate</button></td></tr>)}</tbody></table></div>
      {!filtered.length&&<div className="ri-empty">No incidents match the selected filters.</div>}
    </section>
  </div></DashboardLayout>;
}
function Kpi({label,value,tone=""}){return <div className={`ri-kpi ${tone}`}><span>{label}</span><strong>{value}</strong></div>}
