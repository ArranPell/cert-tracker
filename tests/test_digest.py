from datetime import timedelta

from certtracker import jobs, models, notify
from certtracker.models import Certificate, Location, utcnow

THRESHOLDS = [60, 30, 14, 7]


def _cert(session, name, days, **kw):
    c = Certificate(name=name, not_after=utcnow() + timedelta(days=days, hours=1), status=models.ACTIVE, **kw)
    session.add(c)
    session.commit()
    return c


def test_threshold_level():
    assert notify.threshold_level(90, THRESHOLDS) is None
    assert notify.threshold_level(60, THRESHOLDS) == 60
    assert notify.threshold_level(20, THRESHOLDS) == 30
    assert notify.threshold_level(-3, THRESHOLDS) == 7


def test_alerts_once_per_threshold(session):
    c = _cert(session, "intranet", 45)
    _cert(session, "far away", 200)
    d = notify.build_digest(session, THRESHOLDS)
    assert [x.name for x, _ in d.crossed] == ["intranet"] and d.should_send
    notify.mark_sent(session, d)
    assert c.alert_level == 60

    # Next day, still inside 60 but not yet 30: nothing new.
    d = notify.build_digest(session, THRESHOLDS)
    assert not d.should_send

    # Missed a few days (container down): still alerts at the lower threshold.
    c.not_after = utcnow() + timedelta(days=12, hours=1)
    d = notify.build_digest(session, THRESHOLDS)
    assert d.crossed == [(c, 14)]


def test_daily_inside_final_threshold(session):
    c = _cert(session, "urgent", 3)
    c.alert_level = 7
    session.commit()
    d = notify.build_digest(session, THRESHOLDS)
    assert d.urgent == [c]


def test_weekly_always_sends(session):
    d = notify.build_digest(session, THRESHOLDS, weekly=True)
    assert d.should_send and not d.actionable
    text, html = notify.render(d, "https://certs.example.ca")
    assert "no problems were found" in text


def test_location_problems_and_review_queue(session):
    c = _cert(session, "lb", 200)
    session.add(Location(certificate=c, kind="endpoint", host="lb1", port=443, check_state=models.STATE_ERROR,
                         last_error="Timed out connecting."))
    session.add(Certificate(name="found", not_after=utcnow() + timedelta(days=80), status=models.UNREVIEWED))
    session.commit()
    d = notify.build_digest(session, THRESHOLDS)
    assert len(d.problems) == 1 and d.unreviewed_total == 1
    subject = notify.subject_line(d)
    assert "1 location problem" in subject and "1 to review" in subject
    text, html = notify.render(d, "https://certs.example.ca")
    assert "https://certs.example.ca/certs/" in text and "<table" in html


def test_expired_subject(session):
    _cert(session, "gone", -2)
    d = notify.build_digest(session, THRESHOLDS)
    assert "1 EXPIRED" in notify.subject_line(d)


def test_send_digest_uses_smtp(app, session, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append({"host": host})
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def starttls(self):
            pass
        def login(self, u, p):
            pass
        def send_message(self, msg):
            sent[-1]["msg"] = msg

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    c = _cert(session, "mail test", 20)
    result = jobs.send_digest(session, app.config, force_weekly=False)
    assert "digest sent" in result
    assert sent[0]["host"] == "smtp.test"
    assert sent[0]["msg"]["To"] == "certs@example.ca"
    assert "mail test" in sent[0]["msg"].get_body(("plain",)).get_content()
    assert c.alert_level == 30
    # Nothing new: no second email.
    assert jobs.send_digest(session, app.config, force_weekly=False).startswith("nothing")
    assert len(sent) == 1


def test_run_daily_records_failures(app, session, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("smtp down")
    monkeypatch.setattr(notify, "send_email", boom)
    _cert(session, "x", 5)
    run = jobs.run_daily(app.session_factory, app.config)
    assert run.ok is False and "digest: FAILED (smtp down)" in run.summary
    # The next digest reports that the previous run failed.
    d = notify.build_digest(app.session_factory(), THRESHOLDS)
    assert d.failed_jobs


def test_expired_day_count(session):
    c = _cert(session, "gone", -3)  # expired 3 days (less an hour) ago
    c.not_after = utcnow() - timedelta(days=3, minutes=5)
    assert notify._when(c, utcnow()) == "EXPIRED 3 day(s) ago"
    c.not_after = utcnow() - timedelta(minutes=5)
    assert notify._when(c, utcnow()) == "EXPIRED today"
