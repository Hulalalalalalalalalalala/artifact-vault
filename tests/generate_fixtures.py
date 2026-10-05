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

    # A certificate whose subject name carries the PEM begin/end markers as
    # ordinary attribute text. The encoding detection must look at the file
    # structure, not at this text: the DER file is still DER.
    marker_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trustpeek Test Org"),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "marker -----BEGIN CERTIFICATE----- and "
                "-----END CERTIFICATE----- test",
            ),
        ]
    )
    _, marker = make_self_signed(
        marker_name,
        datetime.datetime(2021, 1, 1, tzinfo=utc),
        datetime.datetime(2041, 1, 1, tzinfo=utc),
        serial=0x1003,
    )
    (FIXTURES / "marker.der").write_bytes(
        marker.public_bytes(serialization.Encoding.DER)
    )
    (FIXTURES / "marker.pem").write_bytes(
        marker.public_bytes(serialization.Encoding.PEM)
    )

    # A certificate whose subject and issuer differ and both carry complex
    # names: Chinese and other non-ASCII values, a repeated attribute type
    # (two OU entries that must not be merged), a multi-valued RDN whose
    # member value itself contains a plus sign, values containing a comma,
    # a backslash and leading/trailing spaces, and an attribute with no
    # known short name (displayed as a dotted OID).
    issuer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "示例科技有限公司"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "São Paulo"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发部"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "平台组"),
            x509.NameAttribute(NameOID.COMMON_NAME, "根 CA 证书"),
            x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4.5"), "自定义属性"),
        ]
    )
    subject_name = x509.Name(
        [
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.COUNTRY_NAME, "CN")]
            ),
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Comma, Co.")]
            ),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "plus+inside"),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, "dev"
                    ),
                ]
            ),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, "back\\slash"
                    )
                ]
            ),
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.COMMON_NAME, " 边缘节点 ")]
            ),
        ]
    )
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(0x1004)
        .not_valid_before(datetime.datetime(2022, 1, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2042, 1, 1, tzinfo=utc))
        .sign(issuer_key, hashes.SHA256())
    )
    (FIXTURES / "names.der").write_bytes(
        names.public_bytes(serialization.Encoding.DER)
    )
    (FIXTURES / "names.pem").write_bytes(
        names.public_bytes(serialization.Encoding.PEM)
    )


if __name__ == "__main__":
    main()
