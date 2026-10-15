"""The email digest.

Daily: sent only when something needs attention — a certificate crossed an alert threshold
(60/30/14/7 days by default), is inside the final threshold or expired, a location has a
problem, or discoveries are waiting for review.
Weekly: always sent, listing everything upcoming, so a quiet inbox means "all fine" rather
than "the tracker stopped running".
"""
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from html import escape

from sqlalchemy import select

from . import models
from .models import Certificate, JobRun, Location, utcnow


def threshold_level(days_left, thresholds):
    """Smallest threshold the certificate is inside, or None."""
    inside = [t for t in thresholds if days_left <= t]
    return min(inside) if inside else None


@dataclass
class Digest:
    crossed: list = field(default_factory=list)       # (cert, level) newly crossed a threshold
    urgent: list = field(default_factory=list)        # inside the final threshold or expired
    upcoming: list = field(default_factory=list)      # weekly: everything inside the largest threshold
    problems: list = field(default_factory=list)      # locations with a problem
    unreviewed: list = field(default_factory=list)
    unreviewed_total: int = 0
    weekly: bool = False
    failed_jobs: list = field(default_factory=list)

    @property
    def actionable(self):
        return bool(self.crossed or self.urgent or self.problems or self.unreviewed or self.failed_jobs)

    @property
    def should_send(self):
        return self.weekly or self.actionable


def build_digest(session, thresholds, weekly=False, now=None):
    now = now or utcnow()
    thresholds = sorted(thresholds, reverse=True)
    d = Digest(weekly=weekly)
    active = session.scalars(
        select(Certificate).where(Certificate.status == models.ACTIVE).order_by(Certificate.not_after)
    ).all()
    for cert in active:
        days = cert.days_left(now)
        level = threshold_level(days, thresholds)
        if level is None:
            continue
        if cert.alert_level is None or level < cert.alert_level:
            d.crossed.append((cert, level))
        elif days <= min(thresholds):
            d.urgent.append(cert)
        if weekly:
            d.upcoming.append(cert)
    d.problems = session.scalars(
        select(Location).join(Certificate)
        .where(Certificate.status == models.ACTIVE, Location.check_state.in_(models.PROBLEM_STATES))
        .order_by(Certificate.name)
    ).all()
    unreviewed = session.scalars(
        select(Certificate).where(Certificate.status == models.UNREVIEWED).order_by(Certificate.not_after)
    ).all()
    d.unreviewed_total = len(unreviewed)
    d.unreviewed = unreviewed[:25]
    last = session.scalars(
        select(JobRun).where(JobRun.job == "daily", JobRun.finished_at.is_not(None)).order_by(JobRun.id.desc())
    ).first()
    if last and last.ok is False:
        d.failed_jobs.append(last)
    return d


def mark_sent(session, digest):
    for cert, level in digest.crossed:
        cert.alert_level = level


def _when(cert, now):
    days = cert.days_left(now)
    if days < 0:
        ago = cert.days_expired(now)
        return "EXPIRED today" if ago == 0 else f"EXPIRED {ago} day(s) ago"
    if days == 0:
        return "expires TODAY"
    return f"{days} day(s) left"


STATE_TEXT = {
    models.STATE_PENDING: "renewed, not yet confirmed installed",
    models.STATE_NEWER: "serving a newer certificate than recorded",
    models.STATE_OLDER: "serving an older certificate",
    models.STATE_MISMATCH: "serving a different certificate",
    models.STATE_ERROR: "could not connect",
}


def subject_line(d, now=None):
    now = now or utcnow()
    expired = sum(1 for c, _ in d.crossed if c.days_left(now) < 0) + sum(1 for c in d.urgent if c.days_left(now) < 0)
    bits = []
    if expired:
        bits.append(f"{expired} EXPIRED")
    due = len(d.crossed) + len(d.urgent) - expired
    if due:
        bits.append(f"{due} expiring")
    if d.problems:
        bits.append(f"{len(d.problems)} location problem(s)")
    if d.unreviewed_total:
        bits.append(f"{d.unreviewed_total} to review")
    prefix = "Weekly certificate summary" if d.weekly else "Certificate alert"
    return f"[Cert Tracker] {prefix}: " + (", ".join(bits) if bits else "nothing needs attention")


def render(d, base_url, now=None):
    """Returns (text, html)."""
    now = now or utcnow()
    sections = []

    def cert_rows(items):
        return [(f"{base_url}/certs/{c.id}", c.name, c.common_name or "", c.not_after.strftime("%Y-%m-%d"),
                 _when(c, now), c.owner or "") for c in items]

    crossed_and_urgent = sorted([c for c, _ in d.crossed] + d.urgent, key=lambda c: c.not_after)
    if crossed_and_urgent:
        sections.append(("Needs renewing", cert_rows(crossed_and_urgent)))
    if d.problems:
        sections.append(("Location problems", [
            (f"{base_url}/certs/{loc.certificate_id}", loc.certificate.name, loc.label,
             STATE_TEXT.get(loc.check_state, loc.check_state), loc.last_error or "", "")
            for loc in d.problems]))
    if d.unreviewed:
        title = "Discovered, waiting for review"
        if d.unreviewed_total > len(d.unreviewed):
            title += f" (showing {len(d.unreviewed)} of {d.unreviewed_total})"
        sections.append((title, cert_rows(d.unreviewed)))
    if d.weekly:
        sections.append(("Everything expiring in the alert window", cert_rows(d.upcoming)))
    if d.failed_jobs:
        sections.append(("Tracker problems", [
            (f"{base_url}/settings", "Last daily run failed", j.summary or "", "", "", "") for j in d.failed_jobs]))

    text_lines = [subject_line(d, now), ""]
    html = [f"<div style='font-family:Segoe UI,Arial,sans-serif;font-size:14px'>"
            f"<h2 style='font-size:18px'>{escape(subject_line(d, now))}</h2>"]
    if not sections or (d.weekly and not d.actionable and not d.upcoming):
        text_lines.append("Nothing is expiring inside the alert window and no problems were found.")
        html.append("<p>Nothing is expiring inside the alert window and no problems were found.</p>")
    for title, rows in sections:
        text_lines.append(title.upper())
        html.append(f"<h3 style='font-size:15px;margin-top:20px'>{escape(title)}</h3>")
        if not rows:
            text_lines.append("  (none)")
            html.append("<p>(none)</p>")
            continue
        html.append("<table cellpadding='6' style='border-collapse:collapse;border:1px solid #ccc'>")
        # Drop columns that are empty in every row of this section.
        width = max(max((i for i, c in enumerate(r) if c), default=0) for r in rows) + 1
        for link, *cols in (r[:width] for r in rows):
            text_lines.append("  - " + " | ".join(c for c in cols if c) + f"\n    {link}")
            cells = f"<td style='border:1px solid #ccc'><a href='{escape(link)}'>{escape(cols[0])}</a></td>"
            cells += "".join(f"<td style='border:1px solid #ccc'>{escape(c)}</td>" for c in cols[1:])
            html.append(f"<tr>{cells}</tr>")
        html.append("</table>")
        text_lines.append("")
    text_lines.append(f"Open Cert Tracker: {base_url}/")
    html.append(f"<p style='margin-top:20px'><a href='{escape(base_url)}/'>Open Cert Tracker</a></p></div>")
    return "\n".join(text_lines), "".join(html)


def send_email(config, subject, text, html=None, to=None):
    recipients = to or config["DIGEST_TO"]
    if not config["SMTP_HOST"]:
        raise RuntimeError("SMTP_HOST is not configured.")
    if not recipients:
        raise RuntimeError("DIGEST_TO is not configured.")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config["MAIL_FROM"]
    msg["To"] = ", ".join(recipients)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"], timeout=30) as smtp:
        if config["SMTP_STARTTLS"]:
            smtp.starttls()
        if config["SMTP_USERNAME"]:
            smtp.login(config["SMTP_USERNAME"], config["SMTP_PASSWORD"])
        smtp.send_message(msg)
