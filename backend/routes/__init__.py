from .auth_routes import auth_bp
from .admin_routes import admin_bp
from .document_routes import document_bp
from .audit_routes import audit_bp
from .attack_routes import attack_bp

__all__ = ["auth_bp", "admin_bp", "document_bp", "audit_bp", "attack_bp"]
