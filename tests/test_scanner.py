import socket

from certtracker import jobs, models
from certtracker.certs import apply_renewal, get_or_create, parse_certificate
from certtracker.models import Certificate, Location
from certtracker.scanner import fetch_certificate, scan_locations

from .conftest import make_cert


def _tracked(session, cert, port):
    record, _ = get_or_create(session, parse_certificate(cert))
    loc = Location(certificate=record, kind="endpoint", host="127.0.0.1", port=port)
    session.add(loc)
    session.commit()
    return record, loc


def test_fetch_certificate(tls_server):
    cert, key = make_cert("served.example.local")
    srv = tls_server(cert, key)
    p = fetch_certificate("127.0.0.1", srv.port, timeout=3)
    assert p.common_name == "served.example.local"


def test_match_then_newer_then_adopt(session, tls_server):
    old, old_key = make_cert("app.example.local", days=10)
    srv = tls_server(old, old_key)
    record, loc = _tracked(session, old, srv.port)

    scan_locations(session, [loc], timeout=3)
    assert loc.check_state == models.STATE_OK

    # Someone renews and installs the certificate without telling the tracker.
    new, new_key = make_cert("app.example.local", days=200)
    srv.set_cert(new, new_key)
    scan_locations(session, [loc], timeout=3)
    session.commit()
    assert loc.check_state == models.STATE_NEWER
    discovered = session.query(Certificate).filter_by(status=models.UNREVIEWED).one()
    assert discovered.serial == format(new.serial_number, "X")

    apply_renewal(session, record, discovered, "tester")
    scan_locations(session, discovered.locations, timeout=3)
    session.commit()
    assert record.status == models.REPLACED and discovered.status == models.ACTIVE
    assert loc.certificate_id == discovered.id and loc.check_state == models.STATE_OK


def test_renewal_not_installed_everywhere(session, tls_server):
    old, old_key = make_cert("wild.example.local", days=5)
    srv_a = tls_server(old, old_key)
    srv_b = tls_server(old, old_key)
    record, loc_a = _tracked(session, old, srv_a.port)
    loc_b = Location(certificate=record, kind="endpoint", host="127.0.0.1", port=srv_b.port)
    manual = Location(certificate=record, kind="manual", name="Appliance", check_state=models.STATE_OK)
    session.add_all([loc_b, manual])
    session.commit()

    new, new_key = make_cert("wild.example.local", days=200)
    new_record, _ = get_or_create(session, parse_certificate(new))
    session.flush()
    apply_renewal(session, record, new_record, "tester")
    srv_a.set_cert(new, new_key)  # installed on A only
    scan_locations(session, new_record.locations, timeout=3)
    session.commit()

    assert loc_a.check_state == models.STATE_OK
    assert loc_b.check_state == models.STATE_OLDER
    assert manual.check_state == models.STATE_PENDING
    messages = " ".join(e.message for e in new_record.events)
    assert "renewal has not been installed here" in messages


def test_connection_error(session):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listening now
    cert, _ = make_cert()
    record, loc = _tracked(session, cert, port)
    scan_locations(session, [loc], timeout=2)
    assert loc.check_state == models.STATE_ERROR
    assert "refused" in loc.last_error.lower()


def test_scan_all_skips_retired(app, session, tls_server):
    cert, key = make_cert()
    srv = tls_server(cert, key)
    record, loc = _tracked(session, cert, srv.port)
    record.status = models.RETIRED
    session.commit()
    assert jobs.scan_all(session, app.config).startswith("scanned 0")
