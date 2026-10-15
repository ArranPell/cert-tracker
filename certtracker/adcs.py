"""Import issued certificates from the internal Microsoft CA (AD CS).

The data comes from scripts/Export-AdcsCertificates.ps1, either posted to the API or uploaded
as a CSV. Records are matched on serial number so re-importing is safe.
"""
import csv
import io
from datetime import datetime, timezone

from . import models
from .certs import normalize_serial, normalize_thumbprint
from .models import Certificate, log_event, utcnow

FIELDS = ("RequestID", "Requester", "CommonName", "NotBefore", "NotAfter", "Serial", "Template", "Thumbprint")


def _parse_dt(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _clean(value):
    value = (value or "").strip()
    return None if value in ("", "EMPTY") else value


def import_rows(session, rows, ca_name=None, now=None):
    """rows: iterable of dicts with the FIELDS keys. Returns counts."""
    now = now or utcnow()
    counts = {"added": 0, "updated": 0, "skipped_expired": 0, "unchanged": 0, "invalid": 0}
    for row in rows:
        row = {k: (str(row.get(k)) if row.get(k) is not None else None) for k in FIELDS}
        serial = normalize_serial(_clean(row["Serial"]))
        try:
            not_after = _parse_dt(_clean(row["NotAfter"]))
            not_before = _parse_dt(_clean(row["NotBefore"]))
        except ValueError:
            not_after = None
        if not serial or not not_after:
            counts["invalid"] += 1
            continue
        if not_after < now:
            counts["skipped_expired"] += 1
            continue
        thumb = normalize_thumbprint(_clean(row["Thumbprint"]))
        existing = models.find_existing(session, serial=serial)
        if existing:
            if thumb and not existing.sha1:
                existing.sha1 = thumb
                counts["updated"] += 1
            else:
                counts["unchanged"] += 1
            continue
        cn = _clean(row["CommonName"]) or f"Request {row['RequestID']}"
        details = [f"Requester: {_clean(row['Requester']) or 'unknown'}", f"Request ID: {_clean(row['RequestID'])}"]
        if ca_name:
            details.append(f"CA: {ca_name}")
        cert = Certificate(
            name=cn, status=models.UNREVIEWED, source="internal", discovered_via="adcs",
            common_name=cn, serial=serial, sha1=thumb, not_before=not_before, not_after=not_after,
            template=_clean(row["Template"]), issuer=ca_name, notes="\n".join(details),
        )
        session.add(cert)
        session.flush()
        log_event(session, cert, "discovered", f"Imported from the internal CA{f' ({ca_name})' if ca_name else ''}.")
        counts["added"] += 1
    return counts


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    missing = [f for f in ("Serial", "NotAfter") if f not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(
            "This does not look like output from Export-AdcsCertificates.ps1 "
            f"(missing columns: {', '.join(missing)})."
        )
    return list(reader)
