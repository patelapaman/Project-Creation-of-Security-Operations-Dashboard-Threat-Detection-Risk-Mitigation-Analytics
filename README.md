# Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics — Final Integrated Project

This repository is the **actual integration of the original final dashboard and Milestone 2**. The original dashboard modules remain available, while Milestone 2 adds Isolation Forest anomaly detection, explainable rule evidence, threat summaries, model evaluation, event investigation, and live prediction.

## Integrated features
- **Milestone 3 — Risk Prioritization & Security Intelligence**
  - Explainable 0–100 risk scoring using severity, ML confidence, asset criticality, vulnerability exposure and threat intelligence
  - Asset criticality, CVE/CVSS, MITRE ATT&CK and IOC enrichment
  - 30-minute event correlation and possible multi-stage attack chains
  - Threat prioritization and analyst response recommendations
  - MongoDB `incidents` collection with status lifecycle
  - REST APIs under `/api/v1`
  - Risk overview, filters, priority table and incident investigation UI
  - Regression/unit tests for Milestone 2 and Milestone 3


### Original dashboard
- Login and registration
- Overview dashboard
- Security Events
- Threat Intelligence
- Vulnerabilities
- Incidents
- Reports
- Settings and profile
- Existing preprocessing, enrichment, MITRE mapping, analytics and notification services

### Milestone 2
- Isolation Forest anomaly detection
- 18-feature ML pipeline
- Explainable security-rule evidence
- Threat prediction API
- Threat summary KPIs
- Model performance endpoint
- Event investigation page
- Live prediction page
- Bundled processed dataset and trained model

## Project structure

```text
AI-Assisted-Threat-Detection-Merged/
├── backend/
│   ├── app.py
│   ├── routes/
│   │   └── milestone2.py
│   ├── services/
│   ├── preprocessing/
│   ├── database/
│   ├── models/
│   │   ├── isolation_forest_pipeline.pkl
│   │   └── model_metadata.json
│   ├── data/
│   │   └── processed_security_events.csv
│   ├── milestone2_engine/
│   ├── requirements.txt
│   ├── train_model.py
│   ├── seed.py
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── pages/                 # original dashboard pages
│   │   └── milestone2/            # integrated Milestone 2 UI
│   ├── package.json
│   └── vite.config.js
├── docs/
└── .gitignore
```

## Requirements

- Python 3.11+
- Node.js 20+
- npm 10+
- MongoDB is recommended for persistent login/profile data and the original dashboard database.
- If MongoDB is unavailable, the backend automatically uses local in-memory demo storage for the original dashboard and Milestone 2 prediction repository. This lets the project run for demonstration without a MongoDB server.

## Run in VS Code

### 1. Open the correct folder

Open the folder containing `backend` and `frontend` directly in VS Code:

```text
AI-Assisted-Threat-Detection-Merged
```

Do **not** run `cd backend` from a parent folder that contains another nested project folder.

### 2. Backend

Open Terminal 1:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Copy `.env.example` to `.env` if you want custom settings.

Start the backend:

```powershell
python -m flask --app app run --host 0.0.0.0 --port 5000 --debug
```

Alternative:

```powershell
python app.py

Optional model commands:

```powershell
python train_model.py
python seed.py
```
```

Backend URLs:

- Health: `http://127.0.0.1:5000/health`
- Milestone 2 health: `http://127.0.0.1:5000/api/milestone2/health`

### 3. Frontend

Keep Terminal 1 running. Open Terminal 2:

```powershell
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite, normally:

```text
http://localhost:5173
```

### 4. Test the integrated Milestone 2 UI

1. Login/register in the original application.
2. Open **AI Detection** from the left sidebar.
3. Confirm the Milestone 2 dashboard loads prediction data.
4. Use search and severity filters.
5. Click a prediction to open **Event Investigation**.
6. Open **Live Prediction** and submit the pre-filled demo event.
7. Confirm a prediction, severity, confidence and reasons are returned.

## API endpoints

### Original dashboard

```text
GET  /health
POST /api/auth/login
POST /api/auth/register
GET  /api/dashboard/
GET  /api/events/
GET  /api/threats/
GET  /api/vulnerabilities/
GET  /api/incidents/
GET  /api/assets/
GET  /api/analytics/
```

### Milestone 2

```text
GET  /api/milestone2/health
GET  /api/milestone2/predictions
GET  /api/milestone2/predictions/<event_id>
GET  /api/milestone2/anomalies
GET  /api/milestone2/threat-summary
GET  /api/milestone2/model-performance
POST /api/milestone2/predict
```

## Run backend tests

From `backend`:

```powershell
python -m pytest -q
```

The integrated tests cover backend health, Milestone 2 engine readiness, seeded predictions, summary KPIs, and a live high-risk prediction.

The project also includes the original Milestone 2 test file under the integrated engine documentation/source set.

## Frontend production build

From `frontend`:

```powershell
npm install
npm run build
```

A successful build creates `frontend/dist/`.

## GitHub upload

Do not upload generated environments or dependencies:

- `backend/.venv/`
- `frontend/node_modules/`
- `.env`
- `frontend/dist/`

They are already ignored by `.gitignore`.

The bundled trained model and project datasets are intentionally included because they are part of the application demo. The model is pinned to scikit-learn 1.8.0 and automatically retrains if its runtime version or dataset fingerprint changes.

## Important integration note

The original dashboard is Flask-based and runs on **port 5000**. Milestone 2 was originally FastAPI-based on a separate port; its ML engine and endpoints were integrated into the existing Flask application under `/api/milestone2/*`. Therefore, the final project uses **one backend process and one frontend process**, avoiding the need to run two competing API servers.

## Security Section Analytics

Threat Intelligence, Vulnerabilities, Incidents and Reports now use the shared `/api/section-analytics` endpoint. See `docs/SECTION_ANALYTICS_UPDATE.md` for the data sources, visualizations and files involved.


## Latest UI/UX and data integration update

See `docs/FINAL_UI_UX_UPDATE.md` for the complete change log. The Overview and AI Detection dashboards now use the same 1,800-row `backend/data/security_events.csv` telemetry source. The UI also includes dynamic severity/event-type filters, date/month/year filtering, source/destination IP search, Light/Dark mode, animated INFOSYS SPRINGBOARD 7.0 login, and expanded analytics for Threat Distribution, Vulnerabilities, Incidents and Reports.

## MongoDB persistence

MongoDB is the project's required persistence layer. The backend imports the bundled CSV datasets into `ThreatDetectionDB` on first startup when the collections are empty. Dashboard APIs read the stored MongoDB collections, so the data shown in Overview, Threat Distribution, Vulnerabilities and Incidents is backed by the database rather than an in-memory fallback.

Use MongoDB Compass to view the stored documents. The backend exposes `GET /api/database/status` for a quick collection/count check.


## Milestone 3 — Risk Intelligence

The Milestone 3 implementation **extends the existing Milestone 2 engine**. It consumes its prediction repository rather than replacing the model or dataset.

Flow:

`Milestone 2 Prediction → Enrichment → Correlation → Risk Score → Priority → Incident → Recommendation → API → Dashboard`

### M-3 APIs

```text
POST /api/v1/risk/calculate
GET  /api/v1/risk/high
GET  /api/v1/risk/summary
GET  /api/v1/incidents
POST /api/v1/incidents
GET  /api/v1/incidents/{incident_id}
PATCH /api/v1/incidents/{incident_id}/status
GET  /api/v1/attack-chains
GET  /api/v1/recommendations/{incident_id}
GET  /api/v1/intelligence
```

### M-3 UI

Use **Risk Intelligence** in the sidebar. The page provides:
- Total/Critical/High/Medium/Low/Open KPIs
- Risk distribution chart
- documented scoring method
- risk and status filters
- top-priority incident table
- incident investigation
- explainable risk reasons
- CVE/CVSS, IOC and MITRE context
- related-event table
- attack-chain stage visualization
- analyst recommendations
- incident status lifecycle

### M-3 test case

The reference calculation from the brief is supported:

`90×0.25 + 92×0.25 + 100×0.20 + 95×0.20 + 80×0.10 = 92.5`

The source brief states 92.1 for this example, but the arithmetic from its own formula is 92.5; the project follows the formula. The implementation intentionally does not claim this score is a probability.

### MongoDB

When MongoDB is available, source CSV collections are seeded as before and generated M-3 incidents are stored in the new `incidents` collection. For easy VS Code demonstration without a local MongoDB server, the default is now `REQUIRE_MONGODB=False`; set it to `True` in `.env` to enforce MongoDB availability.

See `docs/Milestone_3_Design.md` and `docs/MILESTONE_3_VERIFICATION.md` for the complete design and verification procedure.

## Milestone 4
The final M4 integration is documented in `MILESTONE_4_COMPLETE.md`. The main SOC overview is `/dashboard`, and the executive view is `/dashboard/executive`.

### Clean frontend install
From `frontend/` run:
```bash
npm install
npm run build
npm run dev
```
This repository intentionally does not ship `node_modules`; install dependencies on the target operating system so Vite/Rollup native optional dependencies match the platform.
