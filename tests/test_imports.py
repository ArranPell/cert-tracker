from datetime import timedelta

from certtracker import ct, models
from certtracker.models import Certificate, utcnow


def _iso(days):
    return (utcnow() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(serial, cn="app01.corp.local", days=300, template="WebServer"):
    return {"RequestID": "42", "Requester": "CORP\\admin", "CommonName": cn, "NotBefore": _iso(-1),
            "NotAfter": _iso(days), "Serial": serial, "Template": template,
            "Thumbprint": "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd"}


def test_adcs_api_requires_token(client):
    assert client.post("/api/import/adcs", json={"certificates": []}).status_code == 401
    r = client.post("/api/import/adcs", json={"certificates": []}, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_adcs_api_import_is_idempotent(client, session):
    payload = {"ca": "CORP-CA", "certificates": [_row("1a0000000a"), _row("1a0000000b", days=-5)]}
    headers = {"Authorization": "Bearer secret-token"}
    r = client.post("/api/import/adcs", json=payload, headers=headers)
    assert r.get_json() == {"added": 1, "updated": 0, "skipped_expired": 1, "unchanged": 0, "invalid": 0}
    r = client.post("/api/import/adcs", json=payload, headers=headers)
    assert r.get_json()["unchanged"] == 1
    cert = session.query(Certificate).one()
    assert cert.status == models.UNREVIEWED and cert.source == "internal"
    assert cert.serial == "1A0000000A" and cert.sha1 == "AABBCCDDEEFF00112233445566778899AABBCCDD"
    assert cert.issuer == "CORP-CA" and cert.template == "WebServer"


def test_adcs_csv_upload(client, session):
    csv_text = "RequestID,Requester,CommonName,NotBefore,NotAfter,Serial,Template,Thumbprint\n" \
               f"7,CORP\\svc,sql01.corp.local,{_iso(-1)},{_iso(100)},61000000071234,WebServer,\n"
    r = client.post("/settings/adcs", data={"csrf_token": client.csrf, "file": (__import__("io").BytesIO(
        csv_text.encode("utf-8-sig")), "issued.csv")}, content_type="multipart/form-data")
    assert r.status_code == 302
    assert session.query(Certificate).one().common_name == "sql01.corp.local"


CRT_SH_SAMPLE = [
    {"issuer_ca_id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "www.example.ca",
     "name_value": "example.ca\nwww.example.ca", "id": 111, "not_before": "2026-09-01T00:00:00",
     "not_after": "2099-12-01T00:00:00", "serial_number": "03aabbccdd"},
    # same serial again (precertificate entry)
    {"issuer_ca_id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "www.example.ca",
     "name_value": "example.ca\nwww.example.ca", "id": 112, "not_before": "2026-09-01T00:00:00",
     "not_after": "2099-12-01T00:00:00", "serial_number": "03aabbccdd"},
    # unrelated domain that merely contains the text
    {"issuer_ca_id": 1, "issuer_name": "X", "common_name": "notexample.ca", "name_value": "notexample.ca",
     "id": 113, "not_before": "2026-09-01T00:00:00", "not_after": "2099-12-01T00:00:00", "serial_number": "ff"},
    {"issuer_ca_id": 1, "issuer_name": "X", "common_name": "old.example.ca", "name_value": "old.example.ca",
     "id": 114, "not_before": "2020-01-01T00:00:00", "not_after": "2021-01-01T00:00:00", "serial_number": "ee"},
]


def test_ct_import(session):
    assert ct.import_ct_records(session, "example.ca", CRT_SH_SAMPLE) == 1
    cert = session.query(Certificate).one()
    assert cert.sans == ["example.ca", "www.example.ca"]
    assert cert.status == models.UNREVIEWED and cert.source == "public"
    assert "crt.sh/?id=111" in cert.notes
    assert ct.import_ct_records(session, "example.ca", CRT_SH_SAMPLE) == 0
