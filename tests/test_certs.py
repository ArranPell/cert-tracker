import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from certtracker.certs import load_certificates, normalize_serial, pick_certificates

from .conftest import key_pem, make_cert, pem


def test_pem_round_trip():
    cert, _ = make_cert("web.example.local", days=30, sans=["web.example.local", "alt.example.local"])
    [p], warnings = load_certificates(pem(cert))
    assert p.common_name == "web.example.local"
    assert p.sans == ["web.example.local", "alt.example.local"]
    assert p.serial == format(cert.serial_number, "X")
    assert len(p.sha1) == 40 and len(p.sha256) == 64
    assert p.key_info == "EC secp256r1"
    assert not warnings


def test_der():
    cert, _ = make_cert()
    [p], _ = load_certificates(cert.public_bytes(serialization.Encoding.DER))
    assert p.common_name == "test.example.local"


def test_private_key_is_dropped():
    cert, key = make_cert()
    parsed, warnings = load_certificates(pem(cert) + key_pem(key))
    assert len(parsed) == 1
    assert "private key" in warnings[0]
    assert "PRIVATE" not in parsed[0].pem


def test_chain_keeps_leaf_by_default():
    ca, ca_key = make_cert("Test Root CA", days=3650, ca=True)
    leaf, _ = make_cert("leaf.example.local", issuer_key=ca_key, issuer_name=ca.subject)
    parsed, _ = load_certificates(pem(leaf) + pem(ca))
    assert [p.common_name for p in pick_certificates(parsed)] == ["leaf.example.local"]
    assert len(pick_certificates(parsed, include_chain=True)) == 2
    assert parsed[0].issuer == ca.subject.rfc4514_string()


def test_pfx_with_password():
    cert, key = make_cert("pfx.example.local")
    blob = pkcs12.serialize_key_and_certificates(
        b"x", key, cert, None, serialization.BestAvailableEncryption(b"hunter2"))
    parsed, warnings = load_certificates(blob, "hunter2")
    assert parsed[0].common_name == "pfx.example.local"
    assert any("private key" in w for w in warnings)
    with pytest.raises(ValueError):
        load_certificates(blob, "wrong")


def test_garbage_rejected():
    with pytest.raises(ValueError):
        load_certificates(b"not a certificate")
    with pytest.raises(ValueError):
        load_certificates(b"   ")


def test_serial_normalisation():
    assert normalize_serial("00:0a:1B") == "A1B"
    assert normalize_serial("009519f5a4e91bec34") == normalize_serial("9519F5A4E91BEC34")
    assert normalize_serial("") is None
