"""Configuration, read from environment variables (see .env.example)."""
import os


def _bool(name, default=False):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _list(name, default=""):
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def load_config():
    base_url = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
    thresholds = sorted({int(t) for t in _list("ALERT_THRESHOLDS", "60,30,14,7")}, reverse=True)
    return {
        "SECRET_KEY": os.environ.get("SECRET_KEY", ""),
        "DATABASE_URL": os.environ.get("DATABASE_URL", "sqlite:////data/certtracker.db"),
        "BASE_URL": base_url,
        "TIMEZONE": os.environ.get("TZ", "America/St_Johns"),
        # Authentication: "entra" (Microsoft Entra ID sign-in) or "none" (local testing only).
        "AUTH_MODE": os.environ.get("AUTH_MODE", "entra").strip().lower(),
        "ENTRA_TENANT_ID": os.environ.get("ENTRA_TENANT_ID", ""),
        "ENTRA_CLIENT_ID": os.environ.get("ENTRA_CLIENT_ID", ""),
        "ENTRA_CLIENT_SECRET": os.environ.get("ENTRA_CLIENT_SECRET", ""),
        "ENTRA_ALLOWED_GROUP_ID": os.environ.get("ENTRA_ALLOWED_GROUP_ID", ""),
        # Bearer token for the import API used by the AD CS export script.
        "API_TOKEN": os.environ.get("API_TOKEN", ""),
        # Email
        "SMTP_HOST": os.environ.get("SMTP_HOST", ""),
        "SMTP_PORT": int(os.environ.get("SMTP_PORT", "25")),
        "SMTP_STARTTLS": _bool("SMTP_STARTTLS"),
        "SMTP_USERNAME": os.environ.get("SMTP_USERNAME", ""),
        "SMTP_PASSWORD": os.environ.get("SMTP_PASSWORD", ""),
        "MAIL_FROM": os.environ.get("MAIL_FROM", "cert-tracker@localhost"),
        "DIGEST_TO": _list("DIGEST_TO"),
        # Alerting and schedule
        "ALERT_THRESHOLDS": thresholds or [60, 30, 14, 7],
        "DAILY_RUN_TIME": os.environ.get("DAILY_RUN_TIME", "06:30"),
        # 0 = Monday ... 6 = Sunday. The weekly summary is sent even when nothing is wrong,
        # so a silent inbox never means "the tracker died".
        "SUMMARY_WEEKDAY": int(os.environ.get("SUMMARY_WEEKDAY", "0")),
        "SCAN_TIMEOUT": float(os.environ.get("SCAN_TIMEOUT", "8")),
        "SCAN_WORKERS": int(os.environ.get("SCAN_WORKERS", "8")),
        "CT_ENABLED": _bool("CT_ENABLED", True),
        "SESSION_COOKIE_SECURE": _bool("SESSION_COOKIE_SECURE", base_url.startswith("https://")),
        "TRUST_PROXY": _bool("TRUST_PROXY"),
    }
