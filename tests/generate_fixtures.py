#!/usr/bin/env python3
"""Regenerate the committed test fixtures under tests/fixtures/.

The fixtures are checked into the repository so the regression tests never
need network access, a system trust store, or even this script. Re-run only
when a fixture must change; the certificates use fixed serial numbers and
fixed validity windows so regeneration is deterministic except for the key
material (new keys change the fingerprints, so update tests accordingly is
NOT needed -- fingerprints are derived from the committed DER at test time).
"""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def make_self_signed(name, not_before, not_after, serial):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def main():
    import datetime

    FIXTURES.mkdir(exist_ok=True)
    utc = datetime.timezone.utc

    valid_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trustpeek Test Org"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
            x509.NameAttribute(NameOID.COMMON_NAME, "valid.example.test"),
        ]
    )
    key, valid = make_self_signed(
        valid_name,
        datetime.datetime(2020, 1, 1, tzinfo=utc),
        datetime.datetime(2040, 1, 1, tzinfo=utc),
        serial=0x1001,
    )
    der = valid.public_bytes(serialization.Encoding.DER)
    (FIXTURES / "valid.der").write_bytes(der)
    (FIXTURES / "valid.pem").write_bytes(
        valid.public_bytes(serialization.Encoding.PEM)
    )
    (FIXTURES / "private_key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (FIXTURES / "public_key.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    expired_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trustpeek Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.test"),
        ]
    )
    _, expired = make_self_signed(
        expired_name,
        datetime.datetime(2000, 1, 1, tzinfo=utc),
        datetime.datetime(2001, 1, 1, tzinfo=utc),
        serial=0x1002,
    )
    (FIXTURES / "expired.pem").write_bytes(
        expired.public_bytes(serialization.Encoding.PEM)
    )
    (FIXTURES / "expired.der").write_bytes(
        expired.public_bytes(serialization.Encoding.DER)
    )


if __name__ == "__main__":
    main()
