"""Connects to endpoints and checks which certificate they actually serve."""
import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509

from . import models
from .certs import apply_parsed, get_or_create, parse_certificate, same_certificate
from .models import log_event, utcnow


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def fetch_certificate(host, port=443, sni=None, timeout=8.0):
    """Return the certificate an endpoint presents. Trust is deliberately not checked:
    we are inspecting the certificate, not relying on it, and internal or expired ones
    are exactly what we want to see."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Old appliances (BMCs, printers, UPS cards) often only speak old TLS versions.
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    server_name = sni or (None if _is_ip(host) else host)
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("The endpoint did not present a certificate.")
    return parse_certificate(x509.load_der_x509_certificate(der))


def _describe_error(exc):
    if isinstance(exc, socket.timeout):
        return "Timed out connecting."
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused (nothing listening on that port?)."
    if isinstance(exc, socket.gaierror):
        return "Host name could not be resolved."
    return str(exc) or exc.__class__.__name__


def apply_result(session, loc, served, error=None):
    """Update a location from a scan result. `served` is a ParsedCert or None on error."""
    prev = loc.check_state
    now = utcnow()
    loc.last_checked_at = now
    expected = loc.certificate
    if error is not None:
        message = _describe_error(error)
        loc.check_state = models.STATE_ERROR
        if prev != models.STATE_ERROR or loc.last_error != message:
            log_event(session, expected, "scan_error", f"{loc.label}: could not read the certificate: {message}")
        loc.last_error = message
        return loc.check_state

    loc.last_error = None
    loc.last_seen_sha256 = served.sha256
    loc.last_seen_not_after = served.not_after

    if same_certificate(expected, served):
        if not expected.pem:
            apply_parsed(expected, served)
        loc.check_state = models.STATE_OK
        loc.confirmed_at = now
        loc.confirmed_by = "scanner"
        if prev != models.STATE_OK:
            suffix = " Renewal confirmed installed." if prev == models.STATE_PENDING else ""
            log_event(session, expected, "scan_ok", f"{loc.label}: serving this certificate.{suffix}")
        return loc.check_state

    other, created = get_or_create(session, served, status=models.UNREVIEWED, discovered_via="scan",
                                   source=expected.source)
    session.flush()
    if created:
        log_event(session, other, "discovered", f"Found being served at {loc.label} (on record there: #{expected.id}).")
    if served.not_after > expected.not_after:
        state = models.STATE_NEWER
        detail = f"serving a newer certificate (#{other.id}, expires {served.not_after:%Y-%m-%d}). Probably renewed without being recorded."
    elif served.not_after < expected.not_after:
        state = models.STATE_OLDER
        if expected.status == models.ACTIVE and other.replaced_by_id == expected.id:
            detail = f"still serving the old certificate #{other.id}. The renewal has not been installed here."
        else:
            detail = f"serving an older certificate (#{other.id}, expires {served.not_after:%Y-%m-%d})."
    else:
        state = models.STATE_MISMATCH
        detail = f"serving a different certificate (#{other.id})."
    loc.check_state = state
    if prev != state:
        log_event(session, expected, f"scan_{state}", f"{loc.label}: {detail}")
    return state


def scan_locations(session, locations, timeout=8.0, workers=8):
    """Scan endpoint locations in parallel; database updates happen on this thread."""
    targets = [loc for loc in locations if loc.kind == "endpoint" and loc.host and loc.port]
    if not targets:
        return {}

    def work(loc):
        try:
            return loc.id, fetch_certificate(loc.host, loc.port, loc.sni, timeout), None
        except (OSError, ssl.SSLError, ValueError) as exc:
            return loc.id, None, exc

    by_id = {loc.id: loc for loc in targets}
    results = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for loc_id, served, error in pool.map(work, targets):
            results[loc_id] = apply_result(session, by_id[loc_id], served, error)
    return results
