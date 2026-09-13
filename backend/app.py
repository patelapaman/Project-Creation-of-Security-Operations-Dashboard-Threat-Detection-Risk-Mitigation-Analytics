import os
from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Config
from database.mongodb import connect_db

# Existing Blueprints
from routes.assets import assets_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.threats import threats_bp
from routes.incidents import incidents_bp
from routes.analytics import analytics_bp
from routes.dashboard import dashboard_bp
from routes.events import events_bp
from routes.database import database_bp

# New Blueprints
from routes.profile import profile_bp
from routes.notifications import notification_bp
from routes.preferences import preferences_bp
from routes.auth import auth_bp
from routes.milestone2 import milestone2_bp
from routes.section_analytics import section_analytics_bp
from milestone2_engine.runtime import runtime as milestone2_runtime
from routes.risk_routes import risk_bp
from routes.milestone4 import m4_bp

# Create outputs folder
OUTPUT_FOLDER = "outputs"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enable CORS
    CORS(app)

    # Consistent, frontend-safe error responses for malformed/unknown requests.
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"success": False, "error": "Invalid request. Please check the submitted information."}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"success": False, "error": "The requested resource was not found."}), 404

    @app.errorhandler(413)
    def request_too_large(error):
        return jsonify({"success": False, "error": "Request is too large."}), 413

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception("Unhandled server error: %s", error)
        return jsonify({"success": False, "error": "Unable to process the request. Please try again."}), 500

    # Connect MongoDB
    connect_db(app)

    # Register Existing APIs
    app.register_blueprint(assets_bp, url_prefix="/api/assets")
    app.register_blueprint(vulnerabilities_bp, url_prefix="/api/vulnerabilities")
    app.register_blueprint(threats_bp, url_prefix="/api/threats")
    app.register_blueprint(incidents_bp, url_prefix="/api/incidents")
    app.register_blueprint(analytics_bp, url_prefix="/api/analytics")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(events_bp, url_prefix="/api/events")
    app.register_blueprint(database_bp, url_prefix="/api/database")

    # Register New APIs
    app.register_blueprint(profile_bp, url_prefix="/api/profile")
    app.register_blueprint(notification_bp, url_prefix="/api/notifications")
    app.register_blueprint(preferences_bp, url_prefix="/api/preferences")
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(milestone2_bp, url_prefix="/api/milestone2")
    app.register_blueprint(section_analytics_bp, url_prefix="/api/section-analytics")
    # Milestone 3: Risk Prioritization & Security Intelligence
    app.register_blueprint(risk_bp, url_prefix="/api/v1")
    app.register_blueprint(m4_bp, url_prefix="/api/m4")

    # Initialize the Milestone 2 ML engine. If the local model cannot be loaded,
    # the API remains available and the /api/milestone2/health endpoint reports the error.
    try:
        milestone2_runtime.initialize()
        print("Milestone 2 ML engine initialized successfully")
    except Exception as exc:
        print(f"Milestone 2 ML engine initialization deferred: {exc}")

    @app.route("/")
    def home():
        return jsonify({
            "project": Config.API_TITLE,
            "version": "1.0.0",
            "status": "Running"
        })

    @app.route("/health")
    def health():
        from database.mongodb import db, is_mongodb_connected
        database_status = "MongoDB Connected" if is_mongodb_connected() else "Local demo storage"
        return jsonify({
            "status": "Healthy",
            "database": database_status,
            "database_name": db.name if db is not None else "LocalDemo",
            "milestone2": "Ready" if milestone2_runtime.ready else "Unavailable"
        }), 200

    @app.route("/api/pipeline/run")
    def run_pipeline():
        return jsonify({
            "message": "Pipeline executed successfully."
        })

    # Print all registered routes
    print("\n========== REGISTERED ROUTES ==========")
    print(app.url_map)
    print("=======================================\n")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )