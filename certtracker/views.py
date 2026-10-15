"""Web pages."""
import csv
import io
import ssl
import threading
from datetime import datetime

from flask import (Blueprint, Response, abort, current_app, flash, redirect, render_template, request,
                   url_for)
from sqlalchemy import func, or_, select

from . import adcs, jobs, models, notify
from .auth import actor
from .certs import apply_parsed, apply_renewal, get_or_create, load_certificates, pick_certificates, same_certificate
from .models import Certificate, JobRun, Location, WatchedDomain, log_event, utcnow
from .scanner import apply_result, fetch_certificate, scan_locations

bp = Blueprint("views", __name__)

STATE_LABELS = {
    models.STATE_UNCHECKED: ("muted", "Not checked yet"),
    models.STATE_OK: ("ok", "Installed"),
    models.STATE_PENDING: ("warn", "Renewed — not confirmed here yet"),
    models.STATE_NEWER: ("warn", "Serving a newer certificate"),
    models.STATE_OLDER: ("bad", "Serving an older certificate"),
    models.STATE_MISMATCH: ("bad", "Serving a different certificate"),
    models.STATE_ERROR: ("bad", "Could not connect"),
}

FOUND_VIA = {"ct": "public CT logs", "adcs": "internal CA import", "scan": "endpoint scan",
             "upload": "upload", "fetch": "read from server", "manual": "entered by hand"}


def db():
    return current_app.session_factory()


def get_cert(cert_id):
    cert = db().get(Certificate, cert_id)
    if cert is None:
        abort(404)
    return cert


def get_location(loc_id):
    loc = db().get(Location, loc_id)
    if loc is None:
        abort(404)
    return loc


def expiry_badge(cert, now=None):
    if cert.status in (models.REPLACED, models.RETIRED, models.IGNORED):
        return "muted", cert.status.capitalize()
    days = cert.days_left(now)
    window = max(current_app.config["ALERT_THRESHOLDS"])
    if days < 0:
        ago = cert.days_expired(now)
        return "bad", "Expired today" if ago == 0 else f"Expired {ago}d ago"
    if days <= 14:
        return "bad", f"{days}d left"
    if days <= 30:
        return "warn", f"{days}d left"
    if days <= window:
        return "soon", f"{days}d left"
    return "ok", f"{days}d left"


@bp.app_context_processor
def _helpers():
    return {"expiry_badge": expiry_badge, "STATE_LABELS": STATE_LABELS, "SOURCES": models.SOURCES,
            "FOUND_VIA": FOUND_VIA,
            "review_count": db().scalar(select(func.count()).where(Certificate.status == models.UNREVIEWED))}


def _text(name, limit=None):
    value = (request.form.get(name) or "").strip()
    return value[:limit] if limit else value


def _port(value, default=443):
    try:
        port = int(value or default)
    except ValueError as exc:
        raise ValueError("Port must be a number.") from exc
    if not 0 < port < 65536:
        raise ValueError("Port must be between 1 and 65535.")
    return port


def _read_upload():
    """Certificate bytes from the file input or the paste box."""
    upload = request.files.get("file")
    if upload and upload.filename:
        return upload.read()
    return _text("pem").encode()


# ---------------------------------------------------------------- list

VIEWS = {
    "active": ("Active", [models.ACTIVE]),
    "attention": ("Needs attention", [models.ACTIVE]),
    "review": ("To review", [models.UNREVIEWED]),
    "history": ("Replaced & retired", [models.REPLACED, models.RETIRED]),
    "ignored": ("Ignored", [models.IGNORED]),
}


def _needs_attention(cert, now, window):
    return cert.days_left(now) <= window or bool(cert.problem_locations)


@bp.route("/")
def index():
    view = request.args.get("view", "active")
    if view not in VIEWS:
        view = "active"
    q = request.args.get("q", "").strip()
    stmt = select(Certificate).where(Certificate.status.in_(VIEWS[view][1]))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(
            Certificate.name.ilike(like), Certificate.common_name.ilike(like), Certificate.sans_json.ilike(like),
            Certificate.owner.ilike(like), Certificate.serial.ilike(like), Certificate.sha1.ilike(like),
            Certificate.issuer.ilike(like), Certificate.template.ilike(like),
            Certificate.locations.any(or_(Location.host.ilike(like), Location.name.ilike(like))),
        ))
    certs = db().scalars(stmt.order_by(Certificate.not_after)).all()
    now = utcnow()
    window = max(current_app.config["ALERT_THRESHOLDS"])
    if view == "attention":
        certs = [c for c in certs if _needs_attention(c, now, window)]
    active = db().scalars(select(Certificate).where(Certificate.status == models.ACTIVE)).all()
    stats = {
        "active": len(active),
        "expired": sum(1 for c in active if c.days_left(now) < 0),
        "due": sum(1 for c in active if 0 <= c.days_left(now) <= window),
        "problems": sum(len(c.problem_locations) for c in active),
        "attention": sum(1 for c in active if _needs_attention(c, now, window)),
    }
    return render_template("index.html", certs=certs, view=view, views=VIEWS, q=q, stats=stats, now=now,
                           window=window)


@bp.route("/certs/bulk", methods=["POST"])
def bulk():
    action = request.form.get("action")
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    status = {"accept": models.ACTIVE, "ignore": models.IGNORED}.get(action)
    if not status or not ids:
        flash("Select at least one certificate.", "error")
        return redirect(url_for("views.index", view="review"))
    session = db()
    for cert in session.scalars(select(Certificate).where(Certificate.id.in_(ids))).all():
        cert.status = status
        log_event(session, cert, action, "Accepted for tracking." if status == models.ACTIVE else "Ignored.", actor())
    session.commit()
    flash(f"{len(ids)} certificate(s) {'accepted' if status == models.ACTIVE else 'ignored'}.", "ok")
    return redirect(url_for("views.index", view="review"))


# ---------------------------------------------------------------- add

def _parsed_from_form(mode):
    """Returns (parsed certs, warnings, endpoint tuple or None)."""
    if mode == "upload":
        parsed, warnings = load_certificates(_read_upload(), request.form.get("password") or None)
        return pick_certificates(parsed, bool(request.form.get("include_chain"))), warnings, None
    if mode == "fetch":
        host = _text("host", 255)
        if not host:
            raise ValueError("Enter a host name or IP address.")
        port = _port(request.form.get("port"))
        sni = _text("sni", 255) or None
        try:
            served = fetch_certificate(host, port, sni, current_app.config["SCAN_TIMEOUT"])
        except (OSError, ssl.SSLError) as exc:
            raise ValueError(f"Could not read a certificate from {host}:{port}: {exc}") from exc
        return [served], [], (host, port, sni)
    raise ValueError("Unknown form.")


def _apply_common_fields(cert):
    for field in ("owner", "renewal_notes", "notes"):
        value = _text(field)
        if value:
            setattr(cert, field, value)
    source = request.form.get("source")
    if source in models.SOURCES:
        cert.source = source


@bp.route("/certs/new", methods=["GET", "POST"])
def new_cert():
    if request.method == "GET":
        return render_template("new.html", form={}, mode=request.args.get("mode", "upload"))
    mode = request.form.get("mode", "upload")
    session = db()
    if mode == "manual":
        try:
            cert = _manual_cert()
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("new.html", form=request.form, mode=mode), 400
        session.add(cert)
        session.flush()
        log_event(session, cert, "created", "Added manually (no certificate file).", actor())
        session.commit()
        flash("Certificate added. Now record where it is installed.", "ok")
        return redirect(url_for("views.cert_detail", cert_id=cert.id))

    try:
        picked, warnings, endpoint = _parsed_from_form(mode)
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("new.html", form=request.form, mode=mode), 400

    name = _text("name", 255)
    first = None
    for p in picked:
        cert, created = get_or_create(session, p, name=name if len(picked) == 1 and name else None,
                                      discovered_via=mode)
        session.flush()
        if created:
            _apply_common_fields(cert)
            log_event(session, cert, "created", "Added from " + (
                f"{endpoint[0]}:{endpoint[1]}" if endpoint else "an uploaded file") + ".", actor())
        elif cert.status in (models.UNREVIEWED, models.IGNORED):
            cert.status = models.ACTIVE
            if name and len(picked) == 1:
                cert.name = name
            _apply_common_fields(cert)
            log_event(session, cert, "accept", "Accepted for tracking (it had been discovered already).", actor())
            flash(f"“{cert.name}” was already discovered; it is now being tracked.", "ok")
        else:
            flash(f"“{cert.name}” is already on record.", "ok")
        if endpoint and not any(l.kind == "endpoint" and l.host == endpoint[0] and l.port == endpoint[1]
                                for l in cert.locations):
            loc = Location(certificate=cert, kind="endpoint", host=endpoint[0], port=endpoint[1], sni=endpoint[2],
                           name=_text("location_name", 255) or None)
            session.add(loc)
            session.flush()
            apply_result(session, loc, p)
        first = first or cert
    session.commit()
    for w in dict.fromkeys(warnings):
        flash(w, "warn")
    return redirect(url_for("views.cert_detail", cert_id=first.id))


def _manual_cert():
    name = _text("name", 255)
    expires = _text("not_after")
    if not name or not expires:
        raise ValueError("A name and an expiry date are required.")
    try:
        not_after = datetime.strptime(expires, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("Expiry date must be YYYY-MM-DD.") from exc
    cert = Certificate(name=name, not_after=not_after, discovered_via="manual", status=models.ACTIVE,
                       common_name=_text("common_name", 255) or None, issuer=_text("issuer") or None,
                       serial=None)
    _apply_common_fields(cert)
    return cert


# ---------------------------------------------------------------- detail

@bp.route("/certs/<int:cert_id>")
def cert_detail(cert_id):
    cert = get_cert(cert_id)
    session = db()
    previous = session.scalars(select(Certificate).where(Certificate.replaced_by_id == cert.id)).all()
    newer_candidates = []
    if cert.status == models.ACTIVE:
        names = {n.lower() for n in [cert.common_name, *cert.sans] if n}
        newer_candidates = [
            c for c in session.scalars(
                select(Certificate).where(Certificate.status.in_([models.UNREVIEWED, models.ACTIVE]),
                                          Certificate.id != cert.id, Certificate.not_after > cert.not_after)
                .order_by(Certificate.not_after.desc())).all()
            if names & {n.lower() for n in [c.common_name, *c.sans] if n}
        ]
    now = utcnow()
    renewal_due = cert.days_left(now) <= max(current_app.config["ALERT_THRESHOLDS"])
    return render_template("cert.html", cert=cert, previous=previous, newer_candidates=newer_candidates,
                           now=now, renewal_due=renewal_due)


@bp.route("/certs/<int:cert_id>/edit", methods=["POST"])
def edit_cert(cert_id):
    cert = get_cert(cert_id)
    session = db()
    changed = []
    for field, limit in (("name", 255), ("owner", 255), ("renewal_notes", None), ("notes", None)):
        value = _text(field, limit) or None
        if field == "name" and not value:
            continue
        if value != getattr(cert, field):
            setattr(cert, field, value)
            changed.append(field.replace("_", " "))
    source = request.form.get("source")
    if source in models.SOURCES and source != cert.source:
        cert.source = source
        changed.append("source")
    if not cert.pem and _text("not_after"):
        try:
            not_after = datetime.strptime(_text("not_after"), "%Y-%m-%d")
        except ValueError:
            flash("Expiry date must be YYYY-MM-DD.", "error")
            return redirect(url_for("views.cert_detail", cert_id=cert.id))
        if not_after.date() != cert.not_after.date():
            cert.not_after = not_after
            cert.alert_level = None  # new date, so alerts start over
            changed.append("expiry date")
    if changed:
        log_event(session, cert, "edited", "Changed " + ", ".join(changed) + ".", actor())
        session.commit()
        flash("Saved.", "ok")
    return redirect(url_for("views.cert_detail", cert_id=cert.id))


STATUS_ACTIONS = {
    "accept": (models.ACTIVE, "Accepted for tracking."),
    "reactivate": (models.ACTIVE, "Marked active again."),
    "ignore": (models.IGNORED, "Ignored (not tracked)."),
    "retire": (models.RETIRED, "Retired: no longer in use."),
}


@bp.route("/certs/<int:cert_id>/status", methods=["POST"])
def set_status(cert_id):
    cert = get_cert(cert_id)
    action = request.form.get("action")
    if action not in STATUS_ACTIONS:
        abort(400)
    status, message = STATUS_ACTIONS[action]
    cert.status = status
    log_event(db(), cert, action, message, actor())
    db().commit()
    flash(message, "ok")
    return redirect(url_for("views.cert_detail", cert_id=cert.id))


@bp.route("/certs/<int:cert_id>/note", methods=["POST"])
def add_note(cert_id):
    cert = get_cert(cert_id)
    note = _text("note")
    if note:
        log_event(db(), cert, "note", note, actor())
        db().commit()
    return redirect(url_for("views.cert_detail", cert_id=cert.id) + "#history")


@bp.route("/certs/<int:cert_id>/pem")
def download_pem(cert_id):
    cert = get_cert(cert_id)
    if not cert.pem:
        abort(404)
    filename = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (cert.common_name or "certificate"))
    return Response(cert.pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={filename}.crt"})


@bp.route("/certs/<int:cert_id>/attach", methods=["POST"])
def attach_file(cert_id):
    """Fill in a hand-entered (or imported) record from the actual certificate file."""
    cert = get_cert(cert_id)
    session = db()
    try:
        parsed, warnings = load_certificates(_read_upload(), request.form.get("password") or None)
        picked = pick_certificates(parsed)
        if len(picked) != 1:
            raise ValueError("Provide just the one certificate.")
        p = picked[0]
        existing = models.find_existing(session, sha256=p.sha256, sha1=p.sha1, serial=p.serial)
        if existing and existing.id != cert.id:
            raise ValueError(f"That certificate is already on record as #{existing.id} ({existing.name}).")
        if cert.serial and cert.serial != p.serial:
            raise ValueError("That file is a different certificate (serial number does not match). "
                             "If it is the renewal, use “Record a renewal” instead.")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.cert_detail", cert_id=cert.id))
    apply_parsed(cert, p)
    cert.alert_level = None
    log_event(session, cert, "edited", "Details filled in from the certificate file.", actor())
    session.commit()
    for w in dict.fromkeys(warnings):
        flash(w, "warn")
    flash("Certificate details filled in from the file.", "ok")
    return redirect(url_for("views.cert_detail", cert_id=cert.id))


def _rescan(cert):
    session = db()
    scan_locations(session, cert.locations, timeout=current_app.config["SCAN_TIMEOUT"],
                   workers=current_app.config["SCAN_WORKERS"])


@bp.route("/certs/<int:cert_id>/check", methods=["POST"])
def check_cert(cert_id):
    cert = get_cert(cert_id)
    _rescan(cert)
    db().commit()
    flash("Endpoints checked.", "ok")
    return redirect(url_for("views.cert_detail", cert_id=cert.id))


@bp.route("/certs/<int:cert_id>/renew", methods=["POST"])
def renew(cert_id):
    old = get_cert(cert_id)
    session = db()
    mode = request.form.get("mode", "upload")
    try:
        if mode == "existing":
            new = session.get(Certificate, int(request.form.get("new_id") or 0))
            if new is None:
                raise ValueError("Pick the certificate that replaces this one.")
        else:
            picked, warnings, endpoint = _parsed_from_form(mode)
            for w in dict.fromkeys(warnings):
                flash(w, "warn")
            if len(picked) != 1:
                raise ValueError("Provide just the new certificate (the file contained several).")
            if same_certificate(old, picked[0]):
                raise ValueError("That is the same certificate, not a renewal.")
            new, _created = get_or_create(session, picked[0], discovered_via=mode)
            session.flush()
        if new.id == old.id:
            raise ValueError("That is the same certificate, not a renewal.")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.cert_detail", cert_id=old.id) + "#renew")
    if new.not_after <= old.not_after:
        flash("Note: the new certificate does not expire later than the old one.", "warn")
    apply_renewal(session, old, new, actor())
    _rescan(new)
    session.commit()
    flash("Renewal recorded. Endpoints were re-checked; confirm the manual locations once installed.", "ok")
    return redirect(url_for("views.cert_detail", cert_id=new.id))


# ---------------------------------------------------------------- locations

@bp.route("/certs/<int:cert_id>/locations", methods=["POST"])
def add_location(cert_id):
    cert = get_cert(cert_id)
    session = db()
    kind = "manual" if request.form.get("kind") == "manual" else "endpoint"
    loc = Location(certificate=cert, kind=kind, name=_text("name", 255) or None, notes=_text("notes") or None)
    if kind == "endpoint":
        try:
            loc.host = _text("host", 255)
            if not loc.host:
                raise ValueError("Enter the host name or IP address to check.")
            loc.port = _port(request.form.get("port"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("views.cert_detail", cert_id=cert.id) + "#locations")
        loc.sni = _text("sni", 255) or None
    else:
        if not loc.name:
            flash("Describe where the certificate is installed.", "error")
            return redirect(url_for("views.cert_detail", cert_id=cert.id) + "#locations")
        loc.check_state = models.STATE_OK
        loc.confirmed_at = utcnow()
        loc.confirmed_by = actor()
    session.add(loc)
    session.flush()
    log_event(session, cert, "location_added", f"Location added: {loc.label}.", actor())
    if kind == "endpoint":
        scan_locations(session, [loc], timeout=current_app.config["SCAN_TIMEOUT"])
    session.commit()
    return redirect(url_for("views.cert_detail", cert_id=cert.id) + "#locations")


@bp.route("/locations/<int:loc_id>/check", methods=["POST"])
def check_location(loc_id):
    loc = get_location(loc_id)
    scan_locations(db(), [loc], timeout=current_app.config["SCAN_TIMEOUT"])
    db().commit()
    return redirect(url_for("views.cert_detail", cert_id=loc.certificate_id) + "#locations")


@bp.route("/locations/<int:loc_id>/confirm", methods=["POST"])
def confirm_location(loc_id):
    loc = get_location(loc_id)
    if loc.kind != "manual":
        abort(400)
    loc.check_state = models.STATE_OK
    loc.confirmed_at = utcnow()
    loc.confirmed_by = actor()
    log_event(db(), loc.certificate, "confirmed", f"{loc.label}: confirmed installed.", actor())
    db().commit()
    return redirect(url_for("views.cert_detail", cert_id=loc.certificate_id) + "#locations")


@bp.route("/locations/<int:loc_id>/adopt", methods=["POST"])
def adopt_newer(loc_id):
    """The endpoint serves a newer certificate: record it as the renewal."""
    loc = get_location(loc_id)
    session = db()
    served = models.find_existing(session, sha256=loc.last_seen_sha256) if loc.last_seen_sha256 else None
    if served is None or loc.check_state != models.STATE_NEWER:
        flash("Re-check the endpoint first.", "error")
        return redirect(url_for("views.cert_detail", cert_id=loc.certificate_id))
    old = loc.certificate
    apply_renewal(session, old, served, actor())
    _rescan(served)
    session.commit()
    flash("Recorded as the renewal. Check the other locations below.", "ok")
    return redirect(url_for("views.cert_detail", cert_id=served.id))


@bp.route("/locations/<int:loc_id>/delete", methods=["POST"])
def delete_location(loc_id):
    loc = get_location(loc_id)
    cert = loc.certificate
    log_event(db(), cert, "location_removed", f"Location removed: {loc.label}.", actor())
    db().delete(loc)
    db().commit()
    return redirect(url_for("views.cert_detail", cert_id=cert.id) + "#locations")


# ---------------------------------------------------------------- settings & tools

@bp.route("/settings")
def settings():
    session = db()
    return render_template(
        "settings.html",
        domains=session.scalars(select(WatchedDomain).order_by(WatchedDomain.domain)).all(),
        runs=session.scalars(select(JobRun).order_by(JobRun.id.desc()).limit(10)).all(),
        config=current_app.config,
    )


@bp.route("/settings/domains", methods=["POST"])
def add_domain():
    domain = _text("domain", 255).lower().lstrip("*.").strip(".")
    if not domain or "." not in domain or " " in domain:
        flash("Enter a domain such as example.ca.", "error")
    elif db().scalar(select(WatchedDomain).where(WatchedDomain.domain == domain)):
        flash("Already watched.", "ok")
    else:
        db().add(WatchedDomain(domain=domain))
        db().commit()
        flash(f"Watching {domain}. It will be checked on the next daily run.", "ok")
    return redirect(url_for("views.settings"))


@bp.route("/settings/domains/<int:domain_id>/delete", methods=["POST"])
def delete_domain(domain_id):
    wd = db().get(WatchedDomain, domain_id)
    if wd:
        db().delete(wd)
        db().commit()
    return redirect(url_for("views.settings"))


@bp.route("/settings/test-email", methods=["POST"])
def test_email():
    try:
        notify.send_email(current_app.config, "[Cert Tracker] Test email",
                          f"This is a test from Cert Tracker, sent by {actor()}.\n{current_app.config['BASE_URL']}/")
        flash(f"Test email sent to {', '.join(current_app.config['DIGEST_TO'])}.", "ok")
    except Exception as exc:  # noqa: BLE001 - report SMTP problems to the user
        flash(f"Sending failed: {exc}", "error")
    return redirect(url_for("views.settings"))


@bp.route("/settings/run-now", methods=["POST"])
def run_now():
    config = dict(current_app.config)
    threading.Thread(target=jobs.run_daily, args=(current_app.session_factory, config), daemon=True).start()
    flash("Daily checks started in the background. Refresh this page in a minute to see the result.", "ok")
    return redirect(url_for("views.settings"))


@bp.route("/settings/adcs", methods=["POST"])
def upload_adcs():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose the CSV produced by Export-AdcsCertificates.ps1.", "error")
        return redirect(url_for("views.settings"))
    try:
        rows = adcs.parse_csv(upload.read().decode("utf-8-sig", errors="replace"))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.settings"))
    counts = adcs.import_rows(db(), rows, ca_name=_text("ca", 255) or None)
    db().commit()
    flash(f"Imported: {counts['added']} new, {counts['updated']} updated, {counts['unchanged']} already known, "
          f"{counts['skipped_expired']} expired skipped, {counts['invalid']} unreadable.", "ok")
    return redirect(url_for("views.index", view="review") if counts["added"] else url_for("views.settings"))


@bp.route("/export.csv")
def export_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "name", "status", "source", "common_name", "sans", "issuer", "serial", "sha1_thumbprint",
                     "not_before", "not_after", "owner", "template", "locations", "renewal_notes"])
    for c in db().scalars(select(Certificate).order_by(Certificate.not_after)).all():
        writer.writerow([c.id, c.name, c.status, c.source, c.common_name, " ".join(c.sans), c.issuer, c.serial,
                         c.sha1, c.not_before, c.not_after, c.owner, c.template,
                         "; ".join(f"{l.label} [{l.check_state}]" for l in c.locations), c.renewal_notes])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=certificates.csv"})
