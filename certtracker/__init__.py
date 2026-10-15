"""Cert Tracker: an inventory of TLS certificates, where they are installed, and when they expire."""
import logging
import secrets
from zoneinfo import ZoneInfo

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import load_config
from .models import make_session_factory

__version__ = "0.1.0"


def create_app(overrides=None):
    app = Flask(__name__)
    cfg = load_config()
    cfg.update(overrides or {})
    app.config.update(cfg)
    if not app.config["SECRET_KEY"]:
        if app.config["AUTH_MODE"] != "none":
            raise RuntimeError("Set SECRET_KEY (any long random string).")
        app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    )
    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app.session_factory = make_session_factory(app.config["DATABASE_URL"])

    @app.teardown_appcontext
    def _remove_session(_exc):
        app.session_factory.remove()

    tz = ZoneInfo(app.config["TIMEZONE"])

    @app.template_filter("local")
    def _local(dt, fmt="%Y-%m-%d %H:%M"):
        if not dt:
            return ""
        return dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz).strftime(fmt)

    from . import api, auth, views
    auth.init_auth(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(api.bp)
    return app
