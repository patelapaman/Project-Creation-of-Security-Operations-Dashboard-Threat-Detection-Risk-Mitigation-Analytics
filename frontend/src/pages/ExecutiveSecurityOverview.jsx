import React, { useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bug, FileText, Server, ShieldCheck } from "lucide-react";
import { AreaChart, Area, BarChart, Bar, CartesianGrid, Tooltip, ResponsiveContainer, XAxis, YAxis } from "recharts";
import DashboardLayout from "../components/layout/DashboardLayout";
import { getM4Report } from "../services/api";
import "./SecuritySections.css";
import "./ExecutiveSecurityOverview.css";

export default function ExecutiveSecurityOverview() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { getM4Report().then((x) => x?.summary ? setReport(x) : setError("Unable to load executive security data.")); }, []);
  if (error) return <DashboardLayout pageTitle="Executive Security Overview"><div className="exec-state">{error}</div></DashboardLayout>;
  if (!report) return <DashboardLayout pageTitle="Executive Security Overview"><div className="exec-state">Loading executive security overview…</div></DashboardLayout>;
  const s = report.summary || {}, p = report.security_posture || {};
  return <DashboardLayout pageTitle="Executive Security Overview"><div className="exec-page">
    <header className="exec-hero"><div><span className="exec-kicker"><ShieldCheck size={14}/> MANAGEMENT VIEW</span><h1>Executive Security Overview</h1><p>A concise posture view built from the same M1–M3 evidence used by the SOC dashboard.</p></div><div className="exec-score"><span>SECURITY POSTURE</span><strong>{Math.round(p.score || 0)}</strong><small>{p.label}</small></div></header>
    <div className="exec-kpis"><Metric icon={Activity} label="Security Events" value={s.total_security_events}/><Metric icon={AlertTriangle} label="Critical Threats" value={s.critical_threats}/><Metric icon={Server} label="Active Incidents" value={s.active_incidents}/><Metric icon={Bug} label="High-Risk Incidents" value={s.high_risk_incidents}/></div>
    <div className="exec-grid"><section className="section-card"><h3>Threat Trend</h3><p className="helper">M3 risk scores from correlated incidents.</p><div className="exec-chart"><ResponsiveContainer><AreaChart data={report.critical_incidents || []}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="incident_id" hide/><YAxis domain={[0,100]}/><Tooltip/><Area dataKey="risk_score" type="monotone" stroke="var(--accent)" fill="var(--accent-dim)" animationDuration={650}/></AreaChart></ResponsiveContainer></div></section>
    <section className="section-card"><h3>Top Threat Categories</h3><p className="helper">Highest-volume event categories in the current telemetry.</p><div className="exec-chart"><ResponsiveContainer><BarChart data={report.top_threats || []} layout="vertical"><CartesianGrid strokeDasharray="3 3" horizontal={false}/><XAxis type="number"/><YAxis type="category" dataKey="name" width={110} tick={{fontSize:10}}/><Tooltip/><Bar dataKey="value" fill="var(--accent)" radius={[0,5,5,0]} animationDuration={650}/></BarChart></ResponsiveContainer></div></section>
    <section className="section-card exec-wide"><h3>Priority Actions</h3><p className="helper">Recommendations produced by the M3 risk engine for the highest-risk incidents.</p><div className="exec-actions">{(report.recommendations || []).slice(0,10).map((x,i)=><div key={`${x}-${i}`}><span>{String(i+1).padStart(2,"0")}</span><strong>{x}</strong></div>)}</div></section></div>
    <div className="exec-note"><FileText size={15}/><span>Report generated from API-connected project data. No executive metrics are hardcoded.</span></div>
  </div></DashboardLayout>;
}
function Metric({icon:Icon,label,value}){return <div className="exec-metric"><Icon size={17}/><span>{label}</span><strong>{Number(value||0).toLocaleString()}</strong></div>}
