# INFOSYS SPRINGBOARD 7.0 — Milestone 3 Completion Checklist

## Implemented
- [x] Milestone 2 output consumed as the M-3 input
- [x] Asset criticality normalization (Critical 100 / High 75 / Medium 50 / Low 25)
- [x] Vulnerability/CVE/CVSS enrichment
- [x] MITRE ATT&CK mapping
- [x] IOC/threat-intelligence enrichment
- [x] Explainable 0–100 risk engine with documented weights
- [x] Risk categories and priority mapping
- [x] 30-minute event correlation
- [x] Multi-stage attack-chain identification
- [x] Incident generation
- [x] MongoDB `incidents` collection and indexes
- [x] Analyst recommendation engine
- [x] Incident lifecycle: Open / Investigating / Resolved / False Positive
- [x] M-3 REST APIs under `/api/v1`
- [x] Risk overview UI
- [x] Risk distribution and trend
- [x] Priority incident table
- [x] Risk/status filters
- [x] Incident investigation UI
- [x] Risk explanation
- [x] Attack-chain visualization
- [x] Security intelligence page
- [x] M-2 regression tests preserved
- [x] M-3 unit tests added
- [x] VS Code run documentation updated

## Verification performed in the build environment
- Python compilation of all backend `.py` files: **PASS**
- Milestone 3 unit tests: **7/7 PASS**
- Bundled-data M-3 service smoke test: **PASS**
- Frontend production build: **not executable in this isolated build environment because the required npm packages were not locally available and network access was unavailable**. The project retains its package manifest/lockfile so `npm install` followed by `npm run build` can be performed in VS Code.

## Important accuracy note
The Milestone 3 brief's worked example says the supplied formula produces 92.1. Recalculating the exact supplied values gives **92.5**. This project follows the stated formula, and the test validates 92.5 rather than reproducing the arithmetic inconsistency.

## Architecture note
The existing project is Flask-based. To avoid breaking the working Milestone 2 integration or creating two competing backends, the requested M-3 REST contract is implemented in the existing Flask process under `/api/v1`. It remains a REST API and uses the existing application architecture.

## MongoDB note
MongoDB persistence is used when MongoDB is available. The default local configuration permits a CSV/in-memory demonstration so the project can be started without a local MongoDB service. Set `REQUIRE_MONGODB=True` in `.env` when MongoDB must be mandatory.
