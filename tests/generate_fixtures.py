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
from cryptography.x509.oid import NameOID, ObjectIdentifier

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# An OID with no short name in OpenSSL; inspect must fall back to its dotted
# form instead of dropping the attribute.
CUSTOM_NAME_OID = ObjectIdentifier("1.2.3.4.5.6.7")

# Unknown OIDs long enough to overflow any fixed textual buffer. Dotted text
# length (not the DER encoding) is what matters here: OBJ_obj2txt used to be
# handed an 80-byte buffer and silently truncated at 79 characters. The DER
# content of an OID is capped around 63 bytes, but multi-digit arcs still cost
# one content byte each while adding three text characters, so 189-char dotted
# names remain perfectly legal.
#
# Exact boundary lengths 79 and 80, a 189-char "very long" OID, and two OIDs
# whose first 79 characters are byte-identical and which diverge only in a
# later arc are all exercised so truncation can never merge two attributes.
OID_NAME_79 = ObjectIdentifier("1.2" + ".1" * 38)          # 79 chars
OID_NAME_80 = ObjectIdentifier("1.2.10" + ".1" * 37)       # 80 chars
_OID_PREFIX_79 = "1.2.10" + ".1" * 36 + "."                # 79 chars, '.' last
OID_NAME_PAIR_A = ObjectIdentifier(_OID_PREFIX_79 + "10")  # 81 chars
OID_NAME_PAIR_B = ObjectIdentifier(_OID_PREFIX_79 + "20")  # 81 chars, differs late
OID_NAME_LONG = ObjectIdentifier("1.2" + ".39" * 62)       # 189 chars


def rdn(oid, value):
    return x509.RelativeDistinguishedName(
        [x509.NameAttribute(oid, value)]
    )


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

    # A certificate whose subject and issuer deliberately differ and each
    # carry complex names, so the name rendering cannot pass on a self-signed
    # certificate where both lines are identical. The names exercise:
    #   - Chinese and other non-ASCII values (UTF-8 preserved);
    #   - repeated attribute types (two OU entries must not collapse);
    #   - multi-valued RDNs joined with "+" (order fixed by the DER SET);
    #   - values containing ",", "+" and "\\" (escaped so they cannot be
    #     mistaken for attribute or group separators);
    #   - leading and trailing spaces inside values;
    #   - an attribute type without a known short name (dotted OID).
    complex_issuer = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "示例科技有限公司"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发部"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "质量,组+A\\B"),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "上海"),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, "上海+市,测试"
                    ),
                ]
            ),
            rdn(CUSTOM_NAME_OID, "未知属性值"),
            rdn(NameOID.COMMON_NAME, " 颁发,者+根\\CA "),
        ]
    )
    complex_subject = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "信任网络科技（北京）有限公司"),
            x509.RelativeDistinguishedName(
                [
                    # The group separator "+" appears both between these two
                    # attributes and inside each value.
                    x509.NameAttribute(NameOID.COMMON_NAME, "a+b,c\\d"),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, "平台+事业群"
                    ),
                ]
            ),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "安全组"),
            rdn(NameOID.TITLE, "Köln/München 工程部"),
            rdn(NameOID.COMMON_NAME, " 终端用户证书 "),
        ]
    )
    complex_issuer_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    complex_subject_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    complex_cert = (
        x509.CertificateBuilder()
        .subject_name(complex_subject)
        .issuer_name(complex_issuer)
        .public_key(complex_subject_key.public_key())
        .serial_number(0x2001)
        .not_valid_before(datetime.datetime(2022, 6, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2042, 6, 1, tzinfo=utc))
        .sign(complex_issuer_key, hashes.SHA256())
    )
    (FIXTURES / "names.der").write_bytes(
        complex_cert.public_bytes(serialization.Encoding.DER)
    )
    (FIXTURES / "names.pem").write_bytes(
        complex_cert.public_bytes(serialization.Encoding.PEM)
    )

    # A certificate whose subject and issuer carry unknown dotted OIDs at and
    # beyond the old 79-character truncation boundary. Every long OID must be
    # shown in full, next to its own value:
    #   - OIDs of exactly 79 and 80 text characters (the boundary);
    #   - two 81-char OIDs sharing the first 79 chars, differing only in the
    #     last arc (one grouped with CN via "+", the other a standalone RDN);
    #   - a 189-char OID;
    #   - a short unknown OID alongside the long ones;
    #   - known short names C/OU/CN mixed in, repeated CN, Chinese values and
    #     escaped ",", "+" and "\\" so lengthening the name cannot shift the
    #     boundaries between neighbouring attributes.
    # Subject and issuer are different so each name is rendered separately.
    long_subject = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发部"),
            rdn(OID_NAME_79, "长度79的OID值"),
            rdn(OID_NAME_80, "长度80的OID值,含逗号+加号\\反斜杠"),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(OID_NAME_PAIR_A, "配对A值"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "组内CN"),
                ]
            ),
            rdn(OID_NAME_PAIR_B, "配对B值"),
            rdn(CUSTOM_NAME_OID, "短未知OID"),
            rdn(OID_NAME_LONG, " 超长OID值 "),
            rdn(NameOID.COMMON_NAME, "结尾CN"),
        ]
    )
    long_issuer = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "长OID颁发机构"),
            rdn(OID_NAME_LONG, "颁发者长OID"),
            rdn(OID_NAME_PAIR_A, "颁发者配对A"),
            rdn(NameOID.COMMON_NAME, "Long OID Root CA"),
        ]
    )
    long_subject_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    long_issuer_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    long_cert = (
        x509.CertificateBuilder()
        .subject_name(long_subject)
        .issuer_name(long_issuer)
        .public_key(long_subject_key.public_key())
        .serial_number(0x3001)
        .not_valid_before(datetime.datetime(2023, 1, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2043, 1, 1, tzinfo=utc))
        .sign(long_issuer_key, hashes.SHA256())
    )
    (FIXTURES / "long_oid.der").write_bytes(
        long_cert.public_bytes(serialization.Encoding.DER)
    )
    (FIXTURES / "long_oid.pem").write_bytes(
        long_cert.public_bytes(serialization.Encoding.PEM)
    )


if __name__ == "__main__":
    main()
