import datetime as dt
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from certtracker import create_app


def make_cert(cn="test.example.local", days=90, sans=None, ca=False, issuer_key=None, issuer_name=None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=max(1, 30 - days)))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in (sans or [cn])]), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class TLSServer:
    """A local TLS server whose certificate can be swapped, to simulate renewals."""

    def __init__(self, tmp_path, cert, key):
        self.tmp_path = tmp_path
        self.set_cert(cert, key)
        import socket
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def set_cert(self, cert, key):
        cert_file = self.tmp_path / f"srv-{cert.serial_number}.pem"
        key_file = self.tmp_path / f"srv-{cert.serial_number}.key"
        cert_file.write_bytes(pem(cert))
        key_file.write_bytes(key_pem(key))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        self.ctx = ctx

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    def close(self):
        self.running = False
        self.sock.close()


@pytest.fixture
def tls_server(tmp_path):
    servers = []

    def start(cert, key):
        srv = TLSServer(tmp_path, cert, key)
        servers.append(srv)
        return srv

    yield start
    for srv in servers:
        srv.close()


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "America/St_Johns")
    app = create_app({
        "DATABASE_URL": f"sqlite:///{tmp_path / 'test.db'}",
        "AUTH_MODE": "none",
        "SECRET_KEY": "test",
        "API_TOKEN": "secret-token",
        "SMTP_HOST": "smtp.test",
        "DIGEST_TO": ["certs@example.ca"],
        "BASE_URL": "https://certs.example.ca",
        "CT_ENABLED": False,
        "SCAN_TIMEOUT": 3,
    })
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    client = app.test_client()
    client.get("/")  # creates the CSRF token
    with client.session_transaction() as s:
        client.csrf = s["csrf_token"]
    return client


@pytest.fixture
def session(app):
    return app.session_factory()
