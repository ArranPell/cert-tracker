"""Scheduled work: scan endpoints, check CT logs, send the digest."""
import logging
import time
import traceback
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select

from . import ct, models, notify
from .models import Certificate, JobRun, Location, utcnow
from .scanner import scan_locations

log = logging.getLogger("certtracker.jobs")


def scan_all(session, config):
    locations = session.scalars(
        select(Location).join(Certificate).where(
            Location.kind == "endpoint", Certificate.status.in_([models.ACTIVE, models.UNREVIEWED]))
    ).all()
    results = scan_locations(session, locations, timeout=config["SCAN_TIMEOUT"], workers=config["SCAN_WORKERS"])
    session.commit()
    problems = sum(1 for state in results.values() if state in models.PROBLEM_STATES)
    return f"scanned {len(results)} endpoint(s), {problems} with problems"


def send_digest(session, config, now=None, force_weekly=None):
    now = now or utcnow()
    local_now = now.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo(config["TIMEZONE"]))
    weekly = local_now.weekday() == config["SUMMARY_WEEKDAY"] if force_weekly is None else force_weekly
    digest = notify.build_digest(session, config["ALERT_THRESHOLDS"], weekly=weekly, now=now)
    if not digest.should_send:
        return "nothing to report; no email sent"
    text, html = notify.render(digest, config["BASE_URL"], now=now)
    notify.send_email(config, notify.subject_line(digest, now), text, html)
    notify.mark_sent(session, digest)
    session.commit()
    return f"digest sent to {', '.join(config['DIGEST_TO'])}"


def run_daily(session_factory, config):
    """Run every daily step, recording the outcome. One failing step does not stop the others."""
    session = session_factory()
    run = JobRun(job="daily")
    session.add(run)
    session.commit()
    summary, ok = [], True
    steps = [("scan", lambda: scan_all(session, config))]
    if config["CT_ENABLED"]:
        steps.append(("ct", lambda: "; ".join(ct.check_watched_domains(session)) or "no watched domains"))
    steps.append(("digest", lambda: send_digest(session, config)))
    for name, step in steps:
        try:
            summary.append(f"{name}: {step()}")
        except Exception as exc:  # noqa: BLE001 - keep going and report it
            session.rollback()
            ok = False
            log.error("daily step %s failed\n%s", name, traceback.format_exc())
            summary.append(f"{name}: FAILED ({exc})")
    run = session.get(JobRun, run.id)
    run.finished_at = utcnow()
    run.ok = ok
    run.summary = "\n".join(summary)
    session.commit()
    session_factory.remove()
    log.info("daily run finished ok=%s\n%s", ok, run.summary)
    return run


def next_run_after(now_local, run_time):
    hour, minute = (int(x) for x in run_time.split(":"))
    candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now_local:
        candidate += timedelta(days=1)
    return candidate


def scheduler_loop(session_factory, config):
    """Run the daily job at DAILY_RUN_TIME local time. If the container was down at that
    time, catch up as soon as it starts."""
    tz = ZoneInfo(config["TIMEZONE"])
    log.info("scheduler started; daily run at %s %s", config["DAILY_RUN_TIME"], config["TIMEZONE"])
    while True:
        now_local = datetime.now(tz)
        todays = next_run_after(now_local, config["DAILY_RUN_TIME"]) - timedelta(days=1)
        session = session_factory()
        last = session.scalars(select(JobRun).where(JobRun.job == "daily").order_by(JobRun.id.desc())).first()
        session_factory.remove()
        last_start = last.started_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz) if last else None
        if last_start is None or last_start < todays:
            run_daily(session_factory, config)
            continue
        wait = (next_run_after(now_local, config["DAILY_RUN_TIME"]) - now_local).total_seconds()
        time.sleep(min(max(wait, 1), 600))
