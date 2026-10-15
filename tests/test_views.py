import io

from certtracker import models
from certtracker.models import Certificate, Location

from .conftest import key_pem, make_cert, pem


def post(client, url, data=None, **kw):
    data = dict(data or {})
    data.setdefault("csrf_token", client.csrf)
    return client.post(url, data=data, **kw)


def test_pages_render(client):
    for url in ("/", "/?view=attention", "/?view=review", "/?view=history", "/certs/new",
                "/certs/new?mode=fetch", "/certs/new?mode=manual", "/settings", "/export.csv"):
        assert client.get(url).status_code == 200, url


def test_csrf_required(client):
    assert client.post("/certs/new", data={"mode": "manual", "name": "x", "not_after": "2030-01-01"}).status_code == 400


def test_manual_add_and_edit(client, session):
    r = post(client, "/certs/new", {"mode": "manual", "name": "Payroll SAML signing", "not_after": "2027-03-01",
                                    "owner": "Apps team", "source": "other"})
    assert r.status_code == 302
    cert = session.query(Certificate).one()
    assert cert.owner == "Apps team" and cert.pem is None
    cert.alert_level = 30
    session.commit()
    post(client, f"/certs/{cert.id}/edit", {"name": cert.name, "not_after": "2029-03-01", "owner": "Apps team"})
    session.expire_all()
    cert = session.get(Certificate, cert.id)
    assert cert.not_after.year == 2029 and cert.alert_level is None
    page = client.get(f"/certs/{cert.id}").get_data(as_text=True)
    assert "Payroll SAML signing" in page and "Changed expiry date" in page


def test_upload_strips_key_and_renewal_flow(client, session):
    old, key = make_cert("intranet.corp.local", days=20)
    r = post(client, "/certs/new", {"mode": "upload", "pem": (pem(old) + key_pem(key)).decode(),
                                    "name": "Intranet", "source": "internal",
                                    "renewal_notes": "Request from WebServer template"})
    assert r.status_code == 302
    cert = session.query(Certificate).one()
    assert "PRIVATE" not in cert.pem and cert.source == "internal"
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "ignored and not stored" in page

    post(client, f"/certs/{cert.id}/locations", {"kind": "manual", "name": "Reverse proxy appliance"})
    session.expire_all()
    assert session.query(Location).one().check_state == models.STATE_OK

    new, _ = make_cert("intranet.corp.local", days=200)
    r = post(client, f"/certs/{cert.id}/renew", {"mode": "upload", "file": (io.BytesIO(pem(new)), "new.cer")},
             content_type="multipart/form-data")
    assert r.status_code == 302
    session.expire_all()
    old_rec = session.get(Certificate, cert.id)
    new_rec = old_rec.replaced_by
    assert old_rec.status == models.REPLACED and new_rec.name == "Intranet"
    assert new_rec.renewal_notes == "Request from WebServer template"
    loc = session.query(Location).one()
    assert loc.certificate_id == new_rec.id and loc.check_state == models.STATE_PENDING

    post(client, f"/locations/{loc.id}/confirm")
    session.expire_all()
    assert session.get(Location, loc.id).check_state == models.STATE_OK
    assert "Previous certificates" in client.get(f"/certs/{new_rec.id}").get_data(as_text=True)


def test_renewing_with_same_cert_is_rejected(client, session):
    cert, _ = make_cert()
    post(client, "/certs/new", {"mode": "upload", "pem": pem(cert).decode()})
    rec = session.query(Certificate).one()
    r = post(client, f"/certs/{rec.id}/renew", {"mode": "upload", "pem": pem(cert).decode()})
    assert r.status_code == 302
    session.expire_all()
    assert session.get(Certificate, rec.id).status == models.ACTIVE


def test_fetch_creates_endpoint_location(client, session, tls_server):
    cert, key = make_cert("svc.corp.local")
    srv = tls_server(cert, key)
    r = post(client, "/certs/new", {"mode": "fetch", "host": "127.0.0.1", "port": str(srv.port),
                                    "location_name": "SVC01"})
    assert r.status_code == 302
    loc = session.query(Location).one()
    assert loc.kind == "endpoint" and loc.check_state == models.STATE_OK and loc.name == "SVC01"


def test_fetch_error_shows_message(client):
    r = post(client, "/certs/new", {"mode": "fetch", "host": "127.0.0.1", "port": "1"})
    assert r.status_code == 400 and "Could not read a certificate" in r.get_data(as_text=True)


def test_bulk_review(client, session):
    from datetime import timedelta
    from certtracker.models import utcnow
    a = Certificate(name="a", not_after=utcnow() + timedelta(days=50), status=models.UNREVIEWED)
    b = Certificate(name="b", not_after=utcnow() + timedelta(days=50), status=models.UNREVIEWED)
    session.add_all([a, b])
    session.commit()
    post(client, "/certs/bulk", {"action": "accept", "ids": [str(a.id)]})
    post(client, "/certs/bulk", {"action": "ignore", "ids": [str(b.id)]})
    session.expire_all()
    assert session.get(Certificate, a.id).status == models.ACTIVE
    assert session.get(Certificate, b.id).status == models.IGNORED


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 503 and r.get_json()["last_daily_run"] is None


def test_search_by_host(client, session):
    from datetime import timedelta
    from certtracker.models import utcnow
    c = Certificate(name="lb cert", not_after=utcnow() + timedelta(days=300), status=models.ACTIVE)
    session.add(c)
    session.add(Location(certificate=c, kind="endpoint", host="f5-vip-01", port=443))
    session.commit()
    assert "lb cert" in client.get("/?q=f5-vip").get_data(as_text=True)
    assert "lb cert" not in client.get("/?q=nothing-here").get_data(as_text=True)


def test_renewal_candidates_share_a_name(client, session):
    from datetime import timedelta
    from certtracker.models import utcnow
    cur = Certificate(name="rdg", common_name="rdg.corp.local", not_after=utcnow() + timedelta(days=9),
                      status=models.ACTIVE)
    same = Certificate(name="rdg new", common_name="rdg.corp.local", not_after=utcnow() + timedelta(days=365),
                       status=models.UNREVIEWED)
    other = Certificate(name="grafana", common_name="grafana.corp.local", not_after=utcnow() + timedelta(days=700),
                        status=models.UNREVIEWED)
    session.add_all([cur, same, other])
    session.commit()
    page = client.get(f"/certs/{cur.id}").get_data(as_text=True)
    assert f"#{same.id} rdg new" in page and "grafana" not in page
