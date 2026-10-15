"""Parsing certificate files and the renewal workflow."""
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from . import models
from .models import Certificate, log_event

CT_POISON_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")


def normalize_serial(value):
    """Serial numbers come as hex in many spellings ("0A:1B", "0a1b", "a1b"); compare them as one."""
    if value is None:
        return None
    cleaned = str(value).replace(":", "").replace(" ", "").replace("-", "").strip()
    if not cleaned:
        return None
    try:
        return format(int(cleaned, 16), "X")
    except ValueError:
        return cleaned.upper()


def normalize_thumbprint(value):
    if not value:
        return None
    cleaned = "".join(ch for ch in str(value) if ch.isalnum()).upper()
    return cleaned or None


@dataclass
class ParsedCert:
    subject: str
    common_name: str
    sans: list
    issuer: str
    serial: str
    sha1: str
    sha256: str
    not_before: datetime
    not_after: datetime
    key_info: str
    is_ca: bool
    template: str | None
    pem: str
    warnings: list = field(default_factory=list)


def _key_info(cert):
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size}"
    return type(key).__name__


def _ms_template(cert):
    """Microsoft certificate template name or OID, if the cert came from AD CS."""
    v1 = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2")   # szOID_ENROLL_CERTTYPE_EXTENSION
    v2 = x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7")   # szOID_CERTIFICATE_TEMPLATE
    for ext in cert.extensions:
        if ext.oid == v1 and isinstance(ext.value, x509.UnrecognizedExtension):
            raw = ext.value.value
            # DER BMPString: tag 0x1E, length, UTF-16BE text
            if len(raw) > 2 and raw[0] == 0x1E:
                return raw[2:].decode("utf-16-be", errors="replace")
        if ext.oid == v2 and isinstance(ext.value, x509.UnrecognizedExtension):
            raw = ext.value.value
            # SEQUENCE { OID templateID, ... }: decode just the OID
            try:
                if raw[0] == 0x30 and raw[2] == 0x06:
                    oid_bytes = raw[4:4 + raw[3]]
                    return _decode_oid(oid_bytes)
            except IndexError:
                pass
    return None


def _decode_oid(data):
    first = data[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def parse_certificate(cert: x509.Certificate) -> ParsedCert:
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [str(v) for v in san_ext.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in san_ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    try:
        is_ca = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    subject = cert.subject.rfc4514_string()
    common_name = str(cn_attrs[0].value) if cn_attrs else (sans[0] if sans else subject or "(no subject)")
    warnings = []
    try:
        cert.extensions.get_extension_for_oid(CT_POISON_OID)
        warnings.append("This is a CT precertificate, not the certificate a server would present.")
    except x509.ExtensionNotFound:
        pass
    return ParsedCert(
        subject=subject,
        common_name=common_name,
        sans=sans,
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "X"),
        sha1=cert.fingerprint(hashes.SHA1()).hex().upper(),
        sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
        not_before=cert.not_valid_before_utc.replace(tzinfo=None),
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        key_info=_key_info(cert),
        is_ca=is_ca,
        template=_ms_template(cert),
        pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        warnings=warnings,
    )


def load_certificates(data: bytes, password: str | None = None):
    """Read every certificate in a PEM, DER, PKCS#7 (.p7b) or PKCS#12 (.pfx) blob.

    Private keys are never kept. Returns (certificates, warnings).
    """
    if not data or not data.strip():
        raise ValueError("No certificate data was provided.")
    warnings = []
    certs = []
    stripped = data.strip()
    if b"-----BEGIN" in stripped:
        if b"PRIVATE KEY-----" in stripped:
            warnings.append("The pasted text contained a private key. It was ignored and not stored.")
        if b"-----BEGIN PKCS7-----" in stripped:
            certs = pkcs7.load_pem_pkcs7_certificates(stripped)
        elif b"-----BEGIN CERTIFICATE-----" in stripped or b"-----BEGIN TRUSTED CERTIFICATE-----" in stripped:
            certs = x509.load_pem_x509_certificates(stripped.replace(b"TRUSTED CERTIFICATE", b"CERTIFICATE"))
        else:
            raise ValueError("No certificate found in the PEM text (only keys or requests?).")
    else:
        loaders = [
            lambda: [x509.load_der_x509_certificate(stripped)],
            lambda: pkcs7.load_der_pkcs7_certificates(stripped),
        ]
        for loader in loaders:
            try:
                certs = loader()
                break
            except ValueError:
                continue
        if not certs:
            try:
                pw = password.encode() if password else None
                key, cert, extra = pkcs12.load_key_and_certificates(stripped, pw)
            except ValueError as exc:
                raise ValueError(
                    "Could not read the file as a certificate. If it is a .pfx, check the password."
                ) from exc
            if key is not None:
                warnings.append("The .pfx contained a private key. It was ignored and not stored.")
            certs = ([cert] if cert else []) + list(extra or [])
    if not certs:
        raise ValueError("No certificates found.")
    parsed = [parse_certificate(c) for c in certs]
    for p in parsed:
        warnings.extend(p.warnings)
    return parsed, warnings


def pick_certificates(parsed, include_chain=False):
    """From an uploaded bundle, keep the end-entity certificate(s) unless the chain is wanted."""
    if include_chain:
        return parsed
    leaves = [p for p in parsed if not p.is_ca]
    return leaves or parsed[:1]


def apply_parsed(cert: Certificate, p: ParsedCert):
    cert.common_name = p.common_name
    cert.subject = p.subject
    cert.sans = p.sans
    cert.issuer = p.issuer
    cert.serial = p.serial
    cert.sha1 = p.sha1
    cert.sha256 = p.sha256
    cert.not_before = p.not_before
    cert.not_after = p.not_after
    cert.key_info = p.key_info
    cert.is_ca = p.is_ca
    cert.template = p.template or cert.template
    cert.pem = p.pem


def guess_source(p: ParsedCert):
    if p.subject == p.issuer:
        return "other"
    if p.template:
        return "internal"
    return "public"


def certificate_from_parsed(p: ParsedCert, *, name=None, status=models.ACTIVE, discovered_via="upload",
                            source=None):
    cert = Certificate(name=name or p.common_name, status=status, discovered_via=discovered_via,
                       source=source or guess_source(p))
    apply_parsed(cert, p)
    return cert


def get_or_create(session, p: ParsedCert, **kwargs):
    """Return (certificate, created). Matches an existing record by fingerprint or serial."""
    existing = models.find_existing(session, sha256=p.sha256, sha1=p.sha1, serial=p.serial)
    if existing:
        if not existing.pem:
            # Records from AD CS or CT logs have no file; fill in the detail now we have it.
            apply_parsed(existing, p)
        return existing, False
    cert = certificate_from_parsed(p, **kwargs)
    session.add(cert)
    return cert, True


def same_certificate(record: Certificate, p: ParsedCert):
    if record.sha256 and record.sha256 == p.sha256:
        return True
    if record.sha1 and record.sha1 == p.sha1:
        return True
    return bool(record.serial and record.serial == p.serial)


def apply_renewal(session, old: Certificate, new: Certificate, actor):
    """Record that `new` replaces `old`: carry over the details people typed in and move every
    location to the new certificate, marked pending until a scan or a person confirms it."""
    if old.id == new.id:
        raise ValueError("A certificate cannot replace itself.")
    new.name = old.name
    new.owner = new.owner or old.owner
    new.renewal_notes = new.renewal_notes or old.renewal_notes
    new.notes = new.notes or old.notes
    new.source = old.source
    new.status = models.ACTIVE
    old.status = models.REPLACED
    old.replaced_by = new
    moved = list(old.locations)
    for loc in moved:
        loc.certificate = new
        loc.check_state = models.STATE_PENDING
        loc.confirmed_at = None
        loc.confirmed_by = None
    session.flush()
    expiry = new.not_after.strftime("%Y-%m-%d")
    log_event(session, old, "replaced", f"Renewed: replaced by #{new.id} (expires {expiry}).", actor)
    log_event(session, new, "renewal",
              f"Renewal of #{old.id}. {len(moved)} location(s) moved here and marked pending until confirmed.",
              actor)
    return moved
