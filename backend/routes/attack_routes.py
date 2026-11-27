"""
attack_routes.py — Attack Lab endpoints
Blueprint prefix: /api/attacks

Any authenticated user may run the simulations: they execute against an
isolated sandbox authority and return only verdicts and timings, never keys.
"""
from flask import Blueprint, jsonify, request, g

from utils.auth import require_auth
from crypto.attack_simulator import AttackSimulator, ATTACK_CATALOG
from crypto.service import CryptoService

attack_bp = Blueprint("attacks", __name__)

_simulator = None


def _get_simulator() -> AttackSimulator:
    global _simulator
    if _simulator is None:
        _simulator = AttackSimulator(CryptoService.get_instance().engine)
    return _simulator


@attack_bp.route("", methods=["GET"])
@require_auth
def list_attacks():
    return jsonify({"attacks": ATTACK_CATALOG})


@attack_bp.route("/<attack_id>/run", methods=["POST"])
@require_auth
def run_attack(attack_id):
    sim = _get_simulator()
    try:
        result = sim.run(attack_id)
    except KeyError:
        return jsonify({"error": "NotFound", "message": f"Unknown attack '{attack_id}'."}), 404

    CryptoService.get_instance().log_audit(
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        action="ATTACK_SIMULATION",
        status="SUCCESS" if result["outcome"] == "BLOCKED" else "FAILED",
        details=f"Sandbox attack '{result['name']}' -> {result['outcome']} ({result['duration_ms']} ms)",
        ip_address=request.remote_addr,
    )
    return jsonify(result), 200
