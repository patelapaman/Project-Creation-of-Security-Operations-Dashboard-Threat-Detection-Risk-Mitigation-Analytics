import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity, AlertTriangle, BrainCircuit, Bug, ChevronRight, CircleCheck,
  Database, Filter, RefreshCw, Search, Server, ShieldCheck, Siren, Sparkles,
  Target, Wifi, X, Zap,
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, CartesianGrid, Cell, Legend, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import DashboardLayout from "../components/layout/DashboardLayout";
import { getM4Overview } from "../services/api";
import "./Dashboard.css";

const severityClass = {
  Critical: "critical", High: "high", Medium: "medium", Low: "low",
};

function clean(v) { return String(v ?? "").trim(); }

function formatNumber(v) {
  return Number(v || 0).toLocaleString();
}

function MetricCard({ icon: Icon, label, value, detail, tone = "accent", delay = 0 }) {
  return (
    <article className={`m4-metric m4-tone-${tone}`} style={{ "--delay": `${delay}ms` }}>
      <div className="m4-metric-icon"><Icon size={18} /></div>
      <div className="m4-metric-copy">
        <span>{label}</span>
        <strong>{formatNumber(value)}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

function Panel({ title, eyebrow, action, children, className = "" }) {
  return (
    <section className={`m4-panel ${className}`}>
      <div className="m4-panel-head">
        <div>
          {eyebrow && <span className="m4-eyebrow">{eyebrow}</span>}
          <h3>{title}</h3>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function State({ type, message, onRetry }) {
  return (
    <div className={`m4-state ${type}`}>
      {type === "loading" ? <RefreshCw className="spin" size={22} /> : <AlertTriangle size={22} />}
      <strong>{message}</strong>
      {onRetry && <button className="m4-ghost-btn" onClick={onRetry}><RefreshCw size={14} /> Retry</button>}
    </div>
  );
}

function RiskMeter({ score, label }) {
  const safeScore = Math.max(0, Math.min(100, Number(score || 0)));
  return (
    <div className="m4-posture">
      <div className="m4-posture-ring" style={{ "--score": `${safeScore * 3.6}deg` }}>
        <div><strong>{Math.round(safeScore)}</strong><span>/100</span></div>
      </div>
      <div>
        <span className="m4-eyebrow">SECURITY POSTURE</span>
        <h4>{label || "Needs Attention"}</h4>
        <p>Calculated from the current telemetry, incidents, vulnerabilities and unresolved threat volume.</p>
      </div>
    </div>
  );
}

export default function Dashboard({ searchQuery = "" }) {
  const [range, setRange] = useState(30);
  const [filters, setFilters] = useState({ severity: "", threat_type: "", asset: "", department: "", mitre_technique: "", cve: "", ip: "", status: "" });
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    try {
      const result = await getM4Overview({ ...filters, range, search: searchQuery });
      if (!result || !result.kpis) throw new Error("Unable to load threat telemetry.");
      setData(result);
    } catch (e) {
      setError(e.message || "Unable to load threat telemetry.");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [range, JSON.stringify(filters), searchQuery]); // eslint-disable-line react-hooks/exhaustive-deps

  const filterCount = Object.values(filters).filter(Boolean).length + (searchQuery ? 1 : 0);
  const threatTypes = useMemo(() => data?.distributions?.threat_type || [], [data]);
  const trend = useMemo(() => (data?.risk_trend || []).map((x, i) => ({ ...x, label: x.incident_id || `#${i + 1}` })), [data]);

  const update = (key, value) => setFilters((prev) => ({ ...prev, [key]: value }));
  const reset = () => setFilters({ severity: "", threat_type: "", asset: "", department: "", mitre_technique: "", cve: "", ip: "", status: "" });

  if (loading && !data) return <DashboardLayout pageTitle="Security Operations Center"><div className="m4-page"><State type="loading" message="Loading security telemetry…" /></div></DashboardLayout>;
  if (error && !data) return <DashboardLayout pageTitle="Security Operations Center"><div className="m4-page"><State type="error" message={error} onRetry={load} /></div></DashboardLayout>;

  const d = data || { kpis: {}, distributions: {}, critical_incidents: [], security_posture: {}, counts: {}, model_version: "—" };
  const k = d.kpis;

  return (
    <DashboardLayout pageTitle="Security Operations Center">
      <div className="m4-page">
        <header className="m4-hero">
          <div className="m4-hero-grid" aria-hidden="true" />
          <div className="m4-hero-copy">
            <div className="m4-kicker"><ShieldCheck size={14} /> INFOSYS SPRINGBOARD 7.0 · FINAL INTEGRATION</div>
            <h1>Security Operations <span>Threat Detection</span></h1>
            <p>Real-time security monitoring, explainable risk intelligence and incident response with risk mitigation analytics — composed from M1, M2 and M3.</p>
            <div className="m4-status-row">
              <span className="m4-status live"><i /> AI ENGINE ACTIVE</span>
              <span className="m4-status"><i /> TELEMETRY CONNECTED</span>
              <span className="m4-status"><i /> MODEL {d.model_version}</span>
            </div>
          </div>
          <div className="m4-hero-orbit"><div className="orbit-ring one" /><div className="orbit-ring two" /><div className="orbit-core"><BrainCircuit size={34} /></div></div>
        </header>

        <div className="m4-metrics-grid">
          <MetricCard icon={Activity} label="Security Events" value={k.total_security_events} detail={range === 24 ? "Last 24 hours" : `Last ${range} days`} delay={0} />
          <MetricCard icon={BrainCircuit} label="Detected Threats" value={k.detected_threats} detail="M2 anomaly classifications" tone="high" delay={60} />
          <MetricCard icon={AlertTriangle} label="Critical Threats" value={k.critical_threats} detail="Critical severity telemetry" tone="critical" delay={120} />
          <MetricCard icon={Siren} label="High-Risk Incidents" value={k.high_risk_incidents} detail="M3 risk ≥ 61" tone="high" delay={180} />
          <MetricCard icon={Wifi} label="Active Incidents" value={k.active_incidents} detail="Open / investigating" tone="medium" delay={240} />
          <MetricCard icon={Server} label="Affected Assets" value={k.affected_assets} detail="Unique monitored assets" tone="safe" delay={300} />
        </div>

        <div className="m4-toolbar">
          <div className="m4-range" role="group" aria-label="Risk trend range">
            {[24, 7, 30].map((x) => <button key={x} className={range === x ? "active" : ""} onClick={() => setRange(x)}>{x === 24 ? "24 Hours" : `${x} Days`}</button>)}
          </div>
          <div className="m4-toolbar-meta"><span><Filter size={14} /> {filterCount} active filters</span><button className="m4-ghost-btn" onClick={reset} disabled={!filterCount}><X size={14} /> Reset</button><button className="m4-ghost-btn" onClick={load}><RefreshCw size={14} /> Refresh</button></div>
        </div>

        <Panel title="Threat Investigation Console" eyebrow="LIVE FILTERS" className="m4-filter-panel">
          <div className="m4-filter-grid">
            <label>Severity<select value={filters.severity} onChange={(e) => update("severity", e.target.value)}><option value="">All severities</option>{["Critical", "High", "Medium", "Low"].map(x => <option key={x}>{x}</option>)}</select></label>
            <label>Threat type<select value={filters.threat_type} onChange={(e) => update("threat_type", e.target.value)}><option value="">All threat types</option>{threatTypes.map(x => <option key={x.name}>{x.name}</option>)}</select></label>
            <label>Asset<input value={filters.asset} onChange={(e) => update("asset", e.target.value)} placeholder="Production / DB-01" /></label>
            <label>Department<input value={filters.department} onChange={(e) => update("department", e.target.value)} placeholder="Engineering" /></label>
            <label>MITRE technique<input value={filters.mitre_technique} onChange={(e) => update("mitre_technique", e.target.value)} placeholder="T1110" /></label>
            <label>CVE<input value={filters.cve} onChange={(e) => update("cve", e.target.value)} placeholder="CVE-…" /></label>
            <label>IP address<div className="m4-input-icon"><Search size={14} /><input value={filters.ip} onChange={(e) => update("ip", e.target.value)} placeholder="Source / destination" /></div></label>
            <label>Event status<select value={filters.status} onChange={(e) => update("status", e.target.value)}><option value="">All statuses</option><option>Open</option><option>Investigating</option><option>Resolved</option><option>Failed</option><option>Success</option></select></label>
          </div>
          <div className="m4-match-count"><span>{formatNumber(k.total_security_events)} matching security events</span><span>Data source: M1 → M2 → M3 → M4 API pipeline</span></div>
        </Panel>

        <div className="m4-main-grid">
          <Panel title="Security Posture" eyebrow="EXECUTIVE SIGNAL" className="m4-posture-panel">
            <RiskMeter score={d.security_posture?.score} label={d.security_posture?.label} />
            <div className="m4-posture-factors">
              <span><b>{d.security_posture?.factors?.critical_vulnerabilities || 0}</b> critical CVEs</span>
              <span><b>{d.security_posture?.factors?.active_incidents || 0}</b> active incidents</span>
              <span><b>{d.security_posture?.factors?.high_risk_assets || 0}</b> high-risk assets</span>
            </div>
          </Panel>

          <Panel title="Threat Severity" eyebrow="DETECTION DISTRIBUTION">
            <div className="m4-chart"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={d.distributions?.severity || []} dataKey="value" nameKey="name" innerRadius={58} outerRadius={92} paddingAngle={3} animationDuration={650}>{(d.distributions?.severity || []).map((x) => <Cell key={x.name} fill={`var(--signal-${severityClass[x.name] || "medium"})`} />)}</Pie><Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 10 }} /><Legend /></PieChart></ResponsiveContainer></div>
          </Panel>

          <Panel title="Risk Trend" eyebrow={`LAST ${range === 24 ? "24 HOURS" : `${range} DAYS`}`} className="m4-wide-panel">
            {trend.length ? <div className="m4-chart tall"><ResponsiveContainer><AreaChart data={trend}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--accent)" stopOpacity={0.35} /><stop offset="100%" stopColor="var(--accent)" stopOpacity={0} /></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" /><XAxis dataKey="label" hide /><YAxis domain={[0, 100]} tick={{ fill: "var(--text-muted)", fontSize: 11 }} /><Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 10 }} /><Area type="monotone" dataKey="risk_score" stroke="var(--accent)" fill="url(#riskFill)" strokeWidth={2.5} animationDuration={700} /></AreaChart></ResponsiveContainer></div> : <State type="empty" message="No correlated risk incidents in this range." />}
          </Panel>

          <Panel title="Threat Categories" eyebrow="TOP SIGNALS">
            <div className="m4-chart"><ResponsiveContainer><BarChart data={threatTypes} layout="vertical" margin={{ left: 15, right: 15 }}><CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} /><XAxis type="number" allowDecimals={false} tick={{ fill: "var(--text-muted)", fontSize: 10 }} /><YAxis type="category" dataKey="name" width={105} tick={{ fill: "var(--text-secondary)", fontSize: 10 }} /><Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 10 }} /><Bar dataKey="value" fill="var(--accent)" radius={[0, 5, 5, 0]} animationDuration={650} /></BarChart></ResponsiveContainer></div>
          </Panel>
        </div>

        <Panel title="Critical Incident Queue" eyebrow="ANALYST FOCUS" action={<Link className="m4-panel-link" to="/dashboard/incidents">Open incident manager <ChevronRight size={14} /></Link>}>
          {d.critical_incidents?.length ? <div className="m4-table-wrap"><table className="m4-table"><thead><tr><th>Incident</th><th>Threat</th><th>Asset</th><th>Risk</th><th>Priority</th><th>Status</th><th /></tr></thead><tbody>{d.critical_incidents.map((i) => <tr key={i.incident_id}><td className="mono">{i.incident_id}</td><td><strong>{i.threat_type}</strong></td><td>{i.affected_asset || "Unknown"}</td><td><span className={`m4-risk ${severityClass[i.risk_level] || "medium"}`}>{Math.round(i.risk_score)}</span></td><td>{i.priority}</td><td><span className={`m4-status-pill ${clean(i.status).toLowerCase().replaceAll(" ", "-")}`}>{i.status}</span></td><td><Link className="m4-icon-link" aria-label={`Investigate ${i.incident_id}`} to={`/dashboard/risk-intelligence/incidents/${encodeURIComponent(i.incident_id)}`}><ChevronRight size={16} /></Link></td></tr>)}</tbody></table></div> : <State type="empty" message="No high-risk incidents detected in the current range." />}
        </Panel>

        <div className="m4-footer-grid">
          <div className="m4-pipeline"><span>DATA FLOW</span><b>M1 Security Data</b><ChevronRight size={15} /><b>M2 ML Detection</b><ChevronRight size={15} /><b>M3 Risk Engine</b><ChevronRight size={15} /><b>M4 Final Dashboard</b></div>
          <div className="m4-source"><Database size={14} /> API-connected · no synthetic dashboard metrics</div>
        </div>
      </div>
    </DashboardLayout>
  );
}
