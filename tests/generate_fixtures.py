#!/usr/bin/env python3
"""Regenerate the committed test fixtures under tests/fixtures/.

The fixtures are checked into the repository so the regression tests never
need network access, a system trust store, or even this script. Re-run only
when a fixture must change; the certificates use fixed serial numbers and
fixed validity windows so regeneration is deterministic except for the key
material (new keys change the fingerprints, so update tests accordingly is
NOT needed -- fingerprints are derived from the committed DER at test time).
"""

import base64
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


# --- Minimal DER helpers for crafting the validity time fields ------------
#
# The public builder API cannot express every time case the regression suite
# pins: it refuses not_before values before 1950, picks each time tag from
# the year itself (so the "reverse" tag order cannot be built), and cannot
# emit a syntactically well-formed but impossible date (February 30). The
# validity is the fifth element of the tbsCertificate SEQUENCE (right after
# version, serial, signature algorithm and issuer), so a signed certificate
# can have just that one SEQUENCE rewritten. The rewritten signature is
# cryptographically invalid, which is irrelevant: inspect never verifies
# signatures and must display these certificates exactly like any other.


def der_tlv(tag, content):
    length = len(content)
    if length < 0x80:
        length_bytes = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        length_bytes = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length_bytes + content


def iter_der_elements(data):
    position = 0
    elements = []
    while position < len(data):
        tag = data[position]
        position += 1
        first = data[position]
        position += 1
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            length = int.from_bytes(data[position:position + count], "big")
            position += count
        elements.append((tag, data[position:position + length]))
        position += length
    assert position == len(data)
    return elements


def utc_time_tlv(text):
    # UTCTime content such as "490601123045Z"; the 2-digit year century pivot
    # (00-49 -> 2000s, 50-99 -> 1900s) belongs to the reader, not this text.
    return der_tlv(0x17, text.encode("ascii"))


def generalized_time_tlv(text):
    # GeneralizedTime content such as "20500101000000Z" (4-digit year).
    return der_tlv(0x18, text.encode("ascii"))


def replace_validity(der, not_before_tlv, not_after_tlv):
    outer = iter_der_elements(der)
    assert len(outer) == 1 and outer[0][0] == 0x30
    cert_children = iter_der_elements(outer[0][1])
    tbs_children = iter_der_elements(cert_children[0][1])
    first = 1 if tbs_children[0][0] == 0xA0 else 0
    validity_index = first + 3  # serial, signature, issuer then validity
    assert tbs_children[validity_index][0] == 0x30
    rewritten_tbs_children = (
        tbs_children[:validity_index]
        + [(0x30, not_before_tlv + not_after_tlv)]
        + tbs_children[validity_index + 1:]
    )
    rewritten_tbs = der_tlv(
        0x30, b"".join(der_tlv(t, c) for t, c in rewritten_tbs_children)
    )
    rebuilt = rewritten_tbs + b"".join(
        der_tlv(t, c) for t, c in cert_children[1:]
    )
    return der_tlv(0x30, rebuilt)


def pem_from_der(der):
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE-----\n"
    ).encode("ascii")


def write_cert_pair(stem, der):
    (FIXTURES / f"{stem}.der").write_bytes(der)
    (FIXTURES / f"{stem}.pem").write_bytes(pem_from_der(der))


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

    # A certificate whose names carry real C0 control characters (bytes below
    # 0x20) inside DirectoryString values, next to ordinary text. The reader
    # keeps every attribute and renders such a byte as a backslash plus two
    # uppercase hex digits, so the name stays one single-line field:
    #   * LF / CR / TAB render as \0A / \0D / \09 and must not break the line;
    #   * a NUL in the middle of a value renders \00 with the text on BOTH
    #     sides intact (the byte is length-delimited, never NUL-terminated);
    #   * control bytes at the very start/end of a value render the same way
    #     and must not be mistaken for surrounding whitespace and trimmed;
    #   * every other byte below 0x20 follows the same rule (\01, \1F, ...);
    #   * the three-character literal text backslash+"0A" is a different value
    #     from a real newline: the backslash itself is escaped, giving \\0A.
    # Chinese text, the repeated OU attribute, the comma/plus/backslash value
    # separators, the "+"-joined multi-valued RDN and the dotted unknown OID
    # all appear in the same names, so escaping a control byte must never
    # create a new attribute or change attribute order/grouping. Subject and
    # issuer deliberately differ; the validity window is fixed and valid.
    ctrl_subject = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "信任网络\n科技（北京）有限公司"),
            x509.RelativeDistinguishedName(
                [
                    # NUL in the middle: both "ab" and "cd" must survive;
                    # TAB in the grouped OU must not touch the "+" grouping.
                    x509.NameAttribute(NameOID.COMMON_NAME, "ab\x00cd"),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, "平台\t事业群"
                    ),
                ]
            ),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "安全组"),
            # 0x01 at the very end, adjacent to non-ASCII text: same escape,
            # no trimming.
            rdn(NameOID.TITLE, "Köln/München 工程部\x01"),
            # Literal backslash + "0A" (three ordinary characters) next to a
            # real newline in another attribute: renders as \\0A, never \0A.
            rdn(CUSTOM_NAME_OID, "字面\\0A文本"),
            # LF at the start and CR at the end, each next to an ordinary
            # space: control bytes are not surrounding whitespace.
            rdn(NameOID.COMMON_NAME, "\n 终端用户证书 \r"),
        ]
    )
    ctrl_issuer = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "示例\x1f科技有限公司"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发部"),
            # 0x01 between escaped separators and Chinese text.
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "a,b+c\\d\x01端"),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "上\r海"),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, "省\n测\t试"
                    ),
                ]
            ),
            # NUL in the middle with Chinese text on both sides.
            rdn(CUSTOM_NAME_OID, "未知\x00属性值"),
            # NUL at both ends plus escaped comma/plus/backslash in between.
            rdn(NameOID.COMMON_NAME, "\x00颁发,者+根\\CA\x00"),
        ]
    )
    ctrl_issuer_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    ctrl_subject_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    ctrl_cert = (
        x509.CertificateBuilder()
        .subject_name(ctrl_subject)
        .issuer_name(ctrl_issuer)
        .public_key(ctrl_subject_key.public_key())
        .serial_number(0x5001)
        .not_valid_before(datetime.datetime(2024, 6, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2044, 6, 1, tzinfo=utc))
        .sign(ctrl_issuer_key, hashes.SHA256())
    )
    (FIXTURES / "ctrlnames.der").write_bytes(
        ctrl_cert.public_bytes(serialization.Encoding.DER)
    )
    (FIXTURES / "ctrlnames.pem").write_bytes(
        ctrl_cert.public_bytes(serialization.Encoding.PEM)
    )

    # --- Validity-time fixtures -----------------------------------------
    #
    # These pin how inspect renders the two X.509 time tags:
    #   * UTCTime (tag 0x17) stores a 2-digit year; RFC 5280 puts the pivot
    #     between 49 and 50 (YY 00-49 -> 20YY, YY 50-99 -> 19YY);
    #   * GeneralizedTime (tag 0x18) stores the full 4-digit year and is
    #     required from year 2050 on.
    # The certificate builder tags each boundary naturally, so the first
    # three certs below need no DER surgery; the last two (a tag order the
    # builder cannot express, and an impossible date) are rewritten.
    def time_name(cn):
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   "Trustpeek Test Org"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

    # Both fields are UTCTime with 2-digit years: "50" must read as 1950 (not
    # 2050), and the notAfter is the valid leap day 1952-02-29 with hours,
    # minutes and seconds preserved. The certificate has expired long ago,
    # which still displays normally with exit code 0.
    century_name = time_name("century-pivot-1950.example.test")
    _, century = make_self_signed(
        century_name,
        datetime.datetime(1950, 1, 1, 0, 0, 0, tzinfo=utc),
        datetime.datetime(1952, 2, 29, 23, 59, 59, tzinfo=utc),
        serial=0x4001,
    )
    write_cert_pair("century", century.public_bytes(serialization.Encoding.DER))

    # The two fields use different tags on the same certificate: notBefore is
    # UTCTime "49" (-> 2049), notAfter is GeneralizedTime 2050. The moments
    # sit on either side of the 2049/2050 New-Year boundary (with nonzero
    # seconds), so in a timezone ahead of UTC the notBefore crosses into
    # 2050 local time and in a timezone behind UTC the notAfter crosses back
    # into 2049 local time; the UTC output must stay fixed either way.
    mixed_name = time_name("mixed-year-tags-49-2050.example.test")
    _, mixed = make_self_signed(
        mixed_name,
        datetime.datetime(2049, 12, 31, 23, 30, 45, tzinfo=utc),
        datetime.datetime(2050, 1, 1, 0, 30, 59, tzinfo=utc),
        serial=0x4002,
    )
    write_cert_pair("mixedyears", mixed.public_bytes(serialization.Encoding.DER))

    # Both fields are GeneralizedTime with full 4-digit years at/after 2050:
    # the notBefore is the valid leap day 2052-02-29 (with every time unit
    # nonzero) and the notAfter reaches 2100, so a 2-digit rendering or a
    # dropped century would be visible. This certificate is not yet valid;
    # that changes nothing for display.
    generalized_name = time_name("generalized-2050.example.test")
    _, generalized = make_self_signed(
        generalized_name,
        datetime.datetime(2052, 2, 29, 3, 4, 5, tzinfo=utc),
        datetime.datetime(2100, 12, 31, 23, 59, 59, tzinfo=utc),
        serial=0x4003,
    )
    write_cert_pair(
        "generalized", generalized.public_bytes(serialization.Encoding.DER)
    )

    # Reverse tag order versus mixedyears: notBefore is GeneralizedTime 1949
    # and notAfter is UTCTime "50" (-> 1950). The builder cannot produce a
    # date before 1950 nor this tag ordering, so the validity is rewritten in
    # DER after signing. Each line must follow its OWN tag: rendering by
    # position (assuming the first field is always UTCTime) either fails or
    # swaps the two years.
    reverse_name = time_name("reverse-tag-order.example.test")
    _, reverse_base = make_self_signed(
        reverse_name,
        datetime.datetime(2030, 1, 1, tzinfo=utc),
        datetime.datetime(2040, 1, 1, tzinfo=utc),
        serial=0x4004,
    )
    reverse_der = replace_validity(
        reverse_base.public_bytes(serialization.Encoding.DER),
        generalized_time_tlv("19490101000000Z"),
        utc_time_tlv("500615120000Z"),
    )
    write_cert_pair("reverseorder", reverse_der)

    # Structurally complete certificate whose notAfter claims February 30:
    # the GeneralizedTime text is well formed but no such date exists. d2i
    # accepts the structure (so this is certificate CONTENT trouble rather
    # than an unreadable file) and inspect must fail while converting the
    # time, reporting "invalid certificate" with exit 1 and empty stdout.
    baddate_name = time_name("invalid-february-30.example.test")
    _, baddate_base = make_self_signed(
        baddate_name,
        datetime.datetime(2030, 1, 1, tzinfo=utc),
        datetime.datetime(2040, 1, 1, tzinfo=utc),
        serial=0x4005,
    )
    baddate_der = replace_validity(
        baddate_base.public_bytes(serialization.Encoding.DER),
        utc_time_tlv("490228000000Z"),
        generalized_time_tlv("20500230000000Z"),
    )
    write_cert_pair("baddate", baddate_der)


if __name__ == "__main__":
    main()
