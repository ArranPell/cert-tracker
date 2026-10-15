"""Small JSON API: a health check for monitoring, and the AD CS import used by the export script."""
import hmac

from flask import Blueprint, abort, current_app, jsonify, request
from sqlalchemy import select

from . import adcs
from .models import JobRun, utcnow

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/health")
def health():
    session = current_app.session_factory()
    last = session.scalars(
        select(JobRun).where(JobRun.job == "daily", JobRun.finished_at.is_not(None)).order_by(JobRun.id.desc())
    ).first()
    stale = last is None or (utcnow() - last.finished_at).total_seconds() > 36 * 3600
    body = {
        "ok": not stale and bool(last and last.ok),
        "last_daily_run": last.finished_at.isoformat() + "Z" if last else None,
        "last_daily_ok": last.ok if last else None,
    }
    # 503 lets a monitor (Uptime Kuma, PRTG, etc.) alert if the daily run stops happening.
    return jsonify(body), (200 if body["ok"] else 503)


@bp.route("/import/adcs", methods=["POST"])
def import_adcs():
    token = current_app.config["API_TOKEN"]
    supplied = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token or not hmac.compare_digest(supplied, token):
        abort(401)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("certificates"), list):
        abort(400, "Expected JSON: {\"ca\": \"name\", \"certificates\": [...]}")
    session = current_app.session_factory()
    counts = adcs.import_rows(session, payload["certificates"], ca_name=payload.get("ca"))
    session.commit()
    return jsonify(counts)
