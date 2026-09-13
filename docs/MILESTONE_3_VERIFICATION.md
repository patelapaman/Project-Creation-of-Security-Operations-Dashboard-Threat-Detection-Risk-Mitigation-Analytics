# Milestone 3 Verification

## Automated checks included
- `backend/tests/test_milestone3.py`
- Existing Milestone 2 regression tests remain in `backend/tests/test_milestone2.py`.

## Required commands
Backend:
```powershell
cd backend
python -m pip install -r requirements.txt
python -m pytest -q
```

Frontend:
```powershell
cd frontend
npm install
npm run build
```

## Manual end-to-end test
1. Start MongoDB if persistent storage is required.
2. Start Flask on port 5000.
3. Open the Vite frontend.
4. Sign in.
5. Open **Risk Intelligence**.
6. Confirm incident counts and risk distribution appear.
7. Open the highest-risk incident.
8. Confirm risk score, reasons, asset criticality, CVSS, IOC, MITRE and recommendations.
9. Change status to `Investigating`; refresh and confirm it persists when MongoDB is connected.
10. Verify the related-event table and attack-chain stages.
11. Test filters for risk level and status.
12. Open AI Detection and confirm Milestone 2 remains available.

## Important environment note
MongoDB is optional for local demonstration. If MongoDB is not reachable, the M-3 risk engine continues to operate from the bundled Milestone 2 prediction/data sources; MongoDB persistence is used automatically when a connection is available. Set `REQUIRE_MONGODB=True` in `.env` when a hard MongoDB requirement is desired.
