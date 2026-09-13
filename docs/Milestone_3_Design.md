# Milestone 3 Design — Risk Prioritization & Security Intelligence

## 1. Input Data
Milestone 3 consumes the existing Milestone 2 prediction output; it does not replace or retrain the Milestone 2 model. The normalized event fields include `event_id`, `event_type`, `timestamp`, `user/user_id`, `asset/asset_id`, severity, prediction, confidence, anomaly score, CVSS, source/destination IPs and related telemetry.

## 2. Enrichment
Each suspicious Milestone 2 result is enriched from the bundled datasets:
- `assets.csv` — asset criticality and department
- `vulnerabilities.csv` — CVE/CVSS and vulnerability exposure
- `mitre_attack_mapping.csv` — ATT&CK technique/tactic
- `threat_intelligence.csv` — IOC, actor, confidence and severity

When an asset is not explicitly present in the asset register, the engine uses deterministic name-based classification for database/production/payment (Critical), application/server (High), test/testing (Low), and otherwise Medium. This is documented fallback logic, not a random assignment.

## 3. Risk Scoring Formula
Default weights are the starting configuration from the Milestone 3 brief:

`Risk = Severity×0.25 + ML Confidence×0.25 + Asset Criticality×0.20 + Vulnerability Exposure×0.20 + Threat Intelligence×0.10`

**Arithmetic verification note:** the brief's example lists a result of 92.1, but the supplied values and stated formula calculate to **92.5** (22.5 + 23 + 20 + 19 + 8). The implementation follows the formula rather than the inconsistent example total.

Components are normalized to 0–100. Asset criticality is Critical=100, High=75, Medium=50, Low=25. CVSS is converted to a component (`CVSS × 10`) with bounded bonuses for vulnerability count and exploit availability. A malicious/high IOC contributes 100/80 respectively.

The final value is rounded to two decimals and clamped to 0–100. It is an operational prioritization score, **not a mathematically proven probability**.

## 4. Risk Categories
- 0–20: Low
- 21–40: Medium
- 41–60: Moderate
- 61–80: High
- 81–100: Critical

Priority mapping: Critical or score >=90 → Immediate; High → High; Moderate/Medium → Medium; Low → Low.

## 5. Event Correlation Logic
Suspicious events are correlated within a 30-minute window when they share at least one meaningful identity/asset field: user, source IP, destination IP, asset, or destination asset. MITRE tactic order is used to identify multi-stage chains.

## 6. Incident Creation Logic
Every suspicious event is represented in the risk population. Related events are grouped into one incident. The highest-risk event drives the incident risk while all correlated events are retained under `related_events`. Multi-stage groups are labeled `Possible Multi-Stage Attack`.

Incident lifecycle:
`Open → Investigating → Resolved`
with optional `False Positive`.

MongoDB collection: `incidents`.

## 7. Recommendation Logic
Recommendations are deterministic analyst guidance based on threat type and IOC context. They never automatically isolate, block, delete, disable, or otherwise perform destructive security actions.

## 8. API Design
- `POST /api/v1/risk/calculate`
- `GET /api/v1/risk/high`
- `GET /api/v1/risk/summary`
- `GET /api/v1/incidents`
- `POST /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `PATCH /api/v1/incidents/{incident_id}/status`
- `GET /api/v1/attack-chains`
- `GET /api/v1/recommendations/{incident_id}`
- `GET /api/v1/intelligence`

The project already uses Flask as its integrated backend; these REST endpoints are therefore implemented in the existing Flask process instead of creating a competing second application.

## 9. Frontend Screens
1. Risk Overview — KPI cards, distribution chart, scoring method and priority incidents.
2. Incident Investigation — score, reasons, asset/CVE/IOC/MITRE context, related events, status and recommendations.
3. Attack Chain — stage-by-stage MITRE/tactic visualization inside incident investigation.
4. Security Intelligence — CVE/IOC/MITRE fields are exposed by the intelligence API and shown as incident context.

## 10. Testing Strategy
- Unit test the exact 92.1 reference calculation from the brief.
- Validate score boundaries and category thresholds.
- Validate asset and CVSS normalization.
- Validate correlation with same user/IP within 30 minutes and separation beyond the window.
- Validate recommendation generation.
- Validate Flask endpoint registration and response contracts when dependencies are installed.
- Build the React frontend with `npm run build`.
