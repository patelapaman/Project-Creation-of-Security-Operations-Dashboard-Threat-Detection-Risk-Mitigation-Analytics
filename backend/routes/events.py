from flask import Blueprint, jsonify, request
from database.queries import get_security_events


events_bp = Blueprint("events", __name__)


@events_bp.route("/", methods=["GET"])
def get_events():
    """Return security events with safe filtering, search and pagination."""
    try:
        events = get_security_events()
        severity = request.args.get("severity", "").strip().lower()
        event_type = request.args.get("threat_type", request.args.get("event_type", "")).strip().lower()
        asset = request.args.get("asset", "").strip().lower()
        status = request.args.get("status", "").strip().lower()
        search = request.args.get("search", "").strip().lower()

        filtered = []
        for event in events:
            if severity and str(event.get("severity", "")).lower() != severity:
                continue
            if event_type and event_type not in str(event.get("event_type", event.get("threat_type", ""))).lower():
                continue
            if asset and asset not in str(event.get("asset_name", event.get("asset", event.get("device_name", "")))).lower():
                continue
            if status and status not in str(event.get("event_status", event.get("status", ""))).lower():
                continue
            if search and search not in str(event).lower():
                continue
            filtered.append(event)

        try:
            page = max(1, int(request.args.get("page", "1")))
            page_size = min(200, max(1, int(request.args.get("page_size", "50"))))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid pagination parameters."}), 422

        total = len(filtered)
        start = (page - 1) * page_size
        items = filtered[start:start + page_size]
        return jsonify({
            "success": True,
            "data": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": (total + page_size - 1) // page_size,
            },
        })
    except Exception:
        return jsonify({"success": False, "error": "Unable to retrieve security events. Please try again."}), 503
