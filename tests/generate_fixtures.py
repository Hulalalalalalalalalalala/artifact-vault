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

# Three unknown OIDs whose dotted-decimal text is exactly 79, exactly 80 and
# 87 characters long. The 79-char one equals the first 79 characters of the
# other two (they only extend the final numeric arc), so an implementation
# that clips the dotted form at 79 characters renders all three as the same
# attribute name even though the arcs (9 vs 90 vs 900000000) differ.
LONG_OID_79 = ObjectIdentifier(
    "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20."
    "21.22.23.24.25.26.27.28.29.9"
)
LONG_OID_80 = ObjectIdentifier(LONG_OID_79.dotted_string + "0")
LONG_OID_87 = ObjectIdentifier(LONG_OID_79.dotted_string + "00000000")
assert len(LONG_OID_79.dotted_string) == 79
assert len(LONG_OID_80.dotted_string) == 80
assert len(LONG_OID_87.dotted_string) == 87
assert LONG_OID_80.dotted_string[:79] == LONG_OID_79.dotted_string
assert LONG_OID_87.dotted_string[:79] == LONG_OID_79.dotted_string


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

    # A certificate whose names carry unknown OIDs with dotted text of
    # exactly 79, exactly 80 and 87 characters, the longer two sharing the
    # full 79-char prefix of the shortest (arcs 9 / 90 / 900000000). The
    # complete dotted OID must survive for all three with its own value;
    # clipping at a fixed buffer width would print all three identically and
    # merge them visually into one attribute type. They appear alongside
    # known short names (C/OU/CN/...), a shorter unknown OID, repeated OUs,
    # a multi-valued RDN group, Chinese values, escaped ",+\\" characters
    # and leading/trailing spaces; subject and issuer are different names.
    long_oid_subject = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发一部"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发二部"),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "主体\\+分组\\,测试A"
                    ),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, "组内OU"
                    ),
                ]
            ),
            rdn(CUSTOM_NAME_OID, "短未知属性值"),
            rdn(LONG_OID_79, "79位OID值甲"),
            rdn(LONG_OID_80, "80位OID值乙"),
            rdn(LONG_OID_87, "87位OID值丙"),
            rdn(NameOID.COMMON_NAME, " 末端用户 "),
        ]
    )
    long_oid_issuer = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "长OID测试根CA"),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "北京"),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, "北京\\,市+区\\\\根"
                    ),
                ]
            ),
            rdn(LONG_OID_79, "颁发者79位值"),
            rdn(LONG_OID_80, "颁发者80位值"),
            rdn(LONG_OID_87, "颁发者87位值"),
            rdn(CUSTOM_NAME_OID, "颁发者短未知值"),
            rdn(NameOID.COMMON_NAME, " 颁发,者+根\\CA "),
        ]
    )
    long_oid_issuer_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    long_oid_subject_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    long_oid_cert = (
        x509.CertificateBuilder()
        .subject_name(long_oid_subject)
        .issuer_name(long_oid_issuer)
        .public_key(long_oid_subject_key.public_key())
        .serial_number(0x3001)
        .not_valid_before(datetime.datetime(2023, 6, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2043, 6, 1, tzinfo=utc))
        .sign(long_oid_issuer_key, hashes.SHA256())
    )
    (FIXTURES / "longoid.der").write_bytes(
        long_oid_cert.public_bytes(serialization.Encoding.DER)
    )
    (FIXTURES / "longoid.pem").write_bytes(
        long_oid_cert.public_bytes(serialization.Encoding.PEM)
    )


if __name__ == "__main__":
    main()
