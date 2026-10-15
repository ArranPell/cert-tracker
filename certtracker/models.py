"""Database models. All datetimes are stored as naive UTC."""
import json
import time
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, event, or_, select,
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, scoped_session, sessionmaker


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


# Certificate.status values
ACTIVE = "active"          # tracked; expiry alerts are sent
UNREVIEWED = "unreviewed"  # found by a scan, CT log or AD CS import; waiting for someone to triage
IGNORED = "ignored"        # triaged as "not ours to track"
REPLACED = "replaced"      # superseded by a renewal
RETIRED = "retired"        # no longer in use

SOURCES = {"internal": "Internal CA", "public": "Public CA", "other": "Other / self-signed"}


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default=ACTIVE, index=True)
    source: Mapped[str] = mapped_column(String(20), default="other")
    discovered_via: Mapped[str] = mapped_column(String(20), default="manual")

    common_name: Mapped[str | None] = mapped_column(String(255))
    subject: Mapped[str | None] = mapped_column(Text)
    sans_json: Mapped[str] = mapped_column(Text, default="[]")
    issuer: Mapped[str | None] = mapped_column(Text)
    serial: Mapped[str | None] = mapped_column(String(80), index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), index=True)
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime)
    not_after: Mapped[datetime] = mapped_column(DateTime, index=True)
    key_info: Mapped[str | None] = mapped_column(String(80))
    template: Mapped[str | None] = mapped_column(String(255))
    is_ca: Mapped[bool] = mapped_column(Boolean, default=False)
    pem: Mapped[str | None] = mapped_column(Text)

    owner: Mapped[str | None] = mapped_column(String(255))
    renewal_notes: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)

    replaced_by_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"))
    # Smallest alert threshold (in days) already emailed for this certificate.
    alert_level: Mapped[int | None] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    locations: Mapped[list["Location"]] = relationship(
        back_populates="certificate", order_by="Location.id", cascade="all, delete-orphan")
    events: Mapped[list["Event"]] = relationship(
        back_populates="certificate", order_by="Event.at.desc()", cascade="all, delete-orphan")
    replaced_by: Mapped["Certificate | None"] = relationship(remote_side=[id])

    @property
    def sans(self):
        return json.loads(self.sans_json or "[]")

    @sans.setter
    def sans(self, value):
        self.sans_json = json.dumps(list(value or []))

    def days_left(self, now=None):
        """Whole days remaining (rounded down); negative once expired."""
        now = now or utcnow()
        return int((self.not_after - now).total_seconds() // 86400)

    def days_expired(self, now=None):
        """Whole days since expiry (0 on the day it expired)."""
        now = now or utcnow()
        return max(0, (now - self.not_after).days)

    @property
    def problem_locations(self):
        return [loc for loc in self.locations if loc.has_problem]


# Location.check_state values
STATE_UNCHECKED = "unchecked"
STATE_OK = "ok"
STATE_PENDING = "pending"    # certificate was renewed; new one not yet confirmed here
STATE_NEWER = "newer"        # endpoint serves a newer certificate than the one on record
STATE_OLDER = "older"        # endpoint serves an older certificate than the one on record
STATE_MISMATCH = "mismatch"  # endpoint serves some other certificate
STATE_ERROR = "error"        # could not connect

PROBLEM_STATES = {STATE_PENDING, STATE_NEWER, STATE_OLDER, STATE_MISMATCH, STATE_ERROR}


class Location(Base):
    """Somewhere a certificate is installed."""
    __tablename__ = "locations"

    id: Mapped[int] = mapped_column(primary_key=True)
    certificate_id: Mapped[int] = mapped_column(ForeignKey("certificates.id"), index=True)
    # "endpoint" locations are scanned over the network; "manual" ones are confirmed by a person.
    kind: Mapped[str] = mapped_column(String(20), default="endpoint")
    name: Mapped[str | None] = mapped_column(String(255))
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    sni: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)

    check_state: Mapped[str] = mapped_column(String(20), default=STATE_UNCHECKED)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_seen_sha256: Mapped[str | None] = mapped_column(String(64))
    last_seen_not_after: Mapped[datetime | None] = mapped_column(DateTime)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime)
    confirmed_by: Mapped[str | None] = mapped_column(String(255))

    certificate: Mapped[Certificate] = relationship(back_populates="locations")

    @property
    def label(self):
        if self.kind == "endpoint":
            target = f"{self.host}:{self.port}"
            if self.sni and self.sni != self.host:
                target += f" (SNI {self.sni})"
            return f"{self.name} — {target}" if self.name else target
        return self.name or "(unnamed location)"

    @property
    def has_problem(self):
        return self.check_state in PROBLEM_STATES


class Event(Base):
    """History: who did what, and what the scanner noticed."""
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    kind: Mapped[str] = mapped_column(String(40))
    message: Mapped[str] = mapped_column(Text)

    certificate: Mapped[Certificate | None] = relationship(back_populates="events")


class WatchedDomain(Base):
    """A domain checked against public Certificate Transparency logs."""
    __tablename__ = "watched_domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)


class JobRun(Base):
    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    job: Mapped[str] = mapped_column(String(40), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    ok: Mapped[bool | None] = mapped_column(Boolean)
    summary: Mapped[str | None] = mapped_column(Text)


def make_session_factory(database_url):
    engine = create_engine(database_url, future=True)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            # WAL lets the web app and the scheduler process share the file safely.
            cur.execute("PRAGMA busy_timeout=10000")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    # Several web workers start at once; if two race to create a table, the loser retries
    # and then finds it there.
    for attempt in range(5):
        try:
            Base.metadata.create_all(engine)
            break
        except OperationalError as exc:
            if "already exists" not in str(exc) or attempt == 4:
                raise
            time.sleep(0.2 * (attempt + 1))
    return scoped_session(sessionmaker(bind=engine, expire_on_commit=False))


def log_event(session, cert, kind, message, actor="system"):
    session.add(Event(certificate=cert, kind=kind, message=message, actor=actor))


def find_existing(session, *, sha256=None, sha1=None, serial=None):
    """Find a certificate already on record by fingerprint or serial number."""
    clauses = []
    if sha256:
        clauses.append(Certificate.sha256 == sha256)
    if sha1:
        clauses.append(Certificate.sha1 == sha1)
    if serial:
        clauses.append(Certificate.serial == serial)
    if not clauses:
        return None
    return session.scalars(select(Certificate).where(or_(*clauses)).order_by(Certificate.id)).first()
