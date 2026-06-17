"""API package exports and blueprint composition."""

from flask import Blueprint

from .ai_routes import ai_bp
from .analysis_routes import analysis_bp
from .admin_routes import admin_bp
from .asset_routes import asset_bp
from .auth_routes import auth_bp
from .ml_routes import ml_bp
from .risk_routes import risk_bp
from .scan_routes import scan_bp

api_bp = Blueprint("api", __name__)
api_bp.register_blueprint(auth_bp)
api_bp.register_blueprint(admin_bp)
api_bp.register_blueprint(scan_bp)
api_bp.register_blueprint(asset_bp)
api_bp.register_blueprint(analysis_bp)
api_bp.register_blueprint(risk_bp)
api_bp.register_blueprint(ai_bp)
api_bp.register_blueprint(ml_bp)

__all__ = ["api_bp"]
