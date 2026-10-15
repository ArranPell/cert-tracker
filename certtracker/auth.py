"""Sign-in with Microsoft Entra ID (OpenID Connect), plus CSRF protection for forms."""
import hmac
import secrets

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, abort, current_app, g, redirect, request, session, url_for

bp = Blueprint("auth", __name__)
oauth = OAuth()

PUBLIC_ENDPOINTS = {"auth.login", "auth.callback", "auth.logout", "static", "api.health", "api.import_adcs"}


def init_auth(app):
    mode = app.config["AUTH_MODE"]
    if mode == "entra":
        missing = [k for k in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET") if not app.config[k]]
        if missing:
            raise RuntimeError(f"AUTH_MODE=entra needs {', '.join(missing)}.")
        oauth.init_app(app)
        oauth.register(
            "entra",
            client_id=app.config["ENTRA_CLIENT_ID"],
            client_secret=app.config["ENTRA_CLIENT_SECRET"],
            server_metadata_url=(
                f"https://login.microsoftonline.com/{app.config['ENTRA_TENANT_ID']}/v2.0/.well-known/openid-configuration"
            ),
            client_kwargs={"scope": "openid profile email"},
        )
    elif mode != "none":
        raise RuntimeError("AUTH_MODE must be 'entra' or 'none'.")

    @app.before_request
    def _require_login():
        g.user = session.get("user")
        if app.config["AUTH_MODE"] == "none":
            g.user = {"name": "Local user", "email": "local"}
        elif not g.user and request.endpoint not in PUBLIC_ENDPOINTS:
            return redirect(url_for("auth.login", next=request.full_path))
        if request.method == "POST" and not (request.endpoint or "").startswith("api."):
            sent = request.form.get("csrf_token", "")
            if not sent or not hmac.compare_digest(sent, session.get("csrf_token", "")):
                abort(400, "The form expired. Go back, reload the page and try again.")

    @app.context_processor
    def _csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf_token"], "current_user": g.get("user")}


def actor():
    user = g.get("user") or {}
    return user.get("email") or user.get("name") or "unknown"


def _safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for("views.index")


@bp.route("/login")
def login():
    if current_app.config["AUTH_MODE"] == "none":
        return redirect(url_for("views.index"))
    session["login_next"] = _safe_next(request.args.get("next"))
    redirect_uri = current_app.config["BASE_URL"] + url_for("auth.callback")
    return oauth.entra.authorize_redirect(redirect_uri)


@bp.route("/auth/callback")
def callback():
    token = oauth.entra.authorize_access_token()
    claims = token.get("userinfo") or {}
    allowed_group = current_app.config["ENTRA_ALLOWED_GROUP_ID"]
    if allowed_group and allowed_group not in (claims.get("groups") or []):
        abort(403, "Your account is not in the group allowed to use Cert Tracker.")
    next_url = session.pop("login_next", None)
    session.clear()
    session["user"] = {
        "name": claims.get("name") or claims.get("preferred_username"),
        "email": claims.get("preferred_username") or claims.get("email"),
    }
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(_safe_next(next_url))


@bp.route("/logout")
def logout():
    session.clear()
    if current_app.config["AUTH_MODE"] == "entra":
        tenant = current_app.config["ENTRA_TENANT_ID"]
        return redirect(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout"
                        f"?post_logout_redirect_uri={current_app.config['BASE_URL']}/")
    return redirect(url_for("views.index"))
