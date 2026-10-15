"""Certificate Transparency: find public certificates issued for our domains via crt.sh.

Every publicly trusted certificate is logged, so this catches certificates someone bought or
renewed without recording them here.
"""
from datetime import datetime

import requests

from . import models
from .certs import normalize_serial
from .models import Certificate, WatchedDomain, log_event, utcnow

CRT_SH_URL = "https://crt.sh/"


def query_crtsh(domain, timeout=120):
    resp = requests.get(
        CRT_SH_URL,
        params={"q": domain, "output": "json", "exclude": "expired", "deduplicate": "Y"},
        timeout=timeout,
        headers={"User-Agent": "cert-tracker (+self-hosted certificate inventory)"},
    )
    resp.raise_for_status()
    return resp.json()


def _matches_domain(names, domain):
    domain = domain.lower().lstrip("*.")
    for name in names:
        name = name.lower().lstrip("*.")
        if name == domain or name.endswith("." + domain):
            return True
    return False


def import_ct_records(session, domain, records, now=None):
    """Add unexpired certificates we have not seen before as 'unreviewed'. Returns how many were new."""
    now = now or utcnow()
    added = 0
    seen = set()
    for rec in records:
        serial = normalize_serial(rec.get("serial_number"))
        if not serial or serial in seen:
            continue
        seen.add(serial)
        names = [n.strip() for n in str(rec.get("name_value", "")).splitlines() if n.strip()]
        if not _matches_domain(names + [str(rec.get("common_name", ""))], domain):
            continue
        try:
            not_after = datetime.fromisoformat(rec["not_after"])
            not_before = datetime.fromisoformat(rec["not_before"]) if rec.get("not_before") else None
        except (KeyError, ValueError):
            continue
        if not_after < now:
            continue
        if models.find_existing(session, serial=serial):
            continue
        common_name = rec.get("common_name") or (names[0] if names else domain)
        cert = Certificate(
            name=common_name, status=models.UNREVIEWED, source="public", discovered_via="ct",
            common_name=common_name, issuer=rec.get("issuer_name"), serial=serial,
            not_before=not_before, not_after=not_after,
            notes=f"Found in Certificate Transparency logs: https://crt.sh/?id={rec.get('id')}",
        )
        cert.sans = names
        session.add(cert)
        session.flush()
        log_event(session, cert, "discovered", f"Issued for {domain} (found in public CT logs, crt.sh id {rec.get('id')}).")
        added += 1
    return added


def check_watched_domains(session, timeout=120):
    summary = []
    for wd in session.query(WatchedDomain).order_by(WatchedDomain.domain).all():
        wd.last_checked_at = utcnow()
        try:
            records = query_crtsh(wd.domain, timeout=timeout)
        except (requests.RequestException, ValueError) as exc:
            wd.last_error = str(exc)[:500]
            summary.append(f"{wd.domain}: error ({wd.last_error})")
            session.commit()
            continue
        wd.last_error = None
        added = import_ct_records(session, wd.domain, records)
        session.commit()
        summary.append(f"{wd.domain}: {added} new")
    return summary
