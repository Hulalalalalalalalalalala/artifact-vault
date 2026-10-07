#!/usr/bin/env python3
"""Regenerate the committed test fixtures under tests/fixtures/.

Only the PEM samples (*.pem) are checked into the repository. The matching
DER files are NOT committed: they are derived offline at build/test time by
tests/prepare_fixtures.sh, which base64-decodes each certificate PEM body
byte-for-byte (same certificate, same key, names, validity and signature).
The regression tests therefore need no network access, no system trust
store and neither this script nor the third-party `cryptography` package.

Re-run this script only when a fixture must change (an optional maintenance
operation requiring `cryptography`). It rewrites the PEM samples with fixed
serial numbers and fixed validity windows; regeneration is deterministic
except for the key material. New keys change the fingerprints, but nothing
has to be updated by hand: the build regenerates the DER copies and the test
script derives the expected fingerprints from those DER bytes at run time.
After regenerating, reconfigure/rebuild so prepare_fixtures.sh re-derives
the DER copies in the build tree.
"""

import base64
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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


def tamper_signature(der):
    """Flip one bit in the signatureValue of an already-signed certificate.

    The tbsCertificate (subject, issuer, validity, public key and the
    signature algorithm) stays byte-for-byte identical; only the signature
    CONTENT changes, so the result is still a complete, fully parseable
    X.509 certificate whose signature genuinely fails verification. inspect
    reads certificate information without verifying signatures, so this
    certificate must display exactly like the original -- only its SHA-256
    fingerprint differs, because the signature is part of the certificate
    bytes. The caller must assert the verification outcomes (original
    verifies, tampered fails) with real cryptography.
    """
    outer = iter_der_elements(der)
    assert len(outer) == 1 and outer[0][0] == 0x30
    cert_children = iter_der_elements(outer[0][1])
    assert len(cert_children) == 3
    signature_tag, signature_content = cert_children[2]
    assert signature_tag == 0x03  # BIT STRING
    assert signature_content[0] == 0  # zero unused bits
    tampered = bytearray(signature_content)
    tampered[-1] ^= 0x01
    rebuilt = b"".join(
        der_tlv(tag, content) for tag, content in cert_children[:2]
    ) + der_tlv(0x03, bytes(tampered))
    return der_tlv(0x30, rebuilt)


def assert_signature_outcomes(original_der, tampered_der, verifier_key=None):
    """Prove the tampered certificate's signature really is invalid.

    Both certificates must share the same tbsCertificate bytes (same
    subject, issuer, validity, public key and signature algorithm) while
    the original's signature verifies and the tampered one's does not, so
    the invalid signature is a genuine property of the fixture input rather
    than a stand-in such as self-signedness, matching names or expiry.
    Works for both RSA (PKCS#1 v1.5) and EC (ECDSA) keys; the verifier key
    type selects the verification primitive.

    verifier_key is the public key that signs the certificate. A
    self-signed certificate omits it (the certificate's own public key
    verifies it); a certificate signed by a separate issuer (the EC leaf)
    must pass that issuer's public key explicitly.
    """
    original = x509.load_der_x509_certificate(original_der)
    tampered = x509.load_der_x509_certificate(tampered_der)
    assert tampered.tbs_certificate_bytes == original.tbs_certificate_bytes
    assert tampered.signature != original.signature
    public_key = (
        verifier_key if verifier_key is not None else original.public_key()
    )

    def verify(certificate):
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # ECDSA carries the hash inside its signature algorithm object.
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        else:
            raise AssertionError("unsupported verifier public key type")

    verify(original)
    try:
        verify(tampered)
    except InvalidSignature:
        return
    raise AssertionError("tampered signature unexpectedly verifies")


# --- DER surgery for DirectoryString name-value encodings ----------------
#
# The certificate builder only emits UTF8String (tag 0x0C) name values. X.509
# DirectoryString also permits BMPString (tag 0x1E, 16-bit big-endian UCS-2
# code units) and UniversalString (tag 0x1C, 32-bit big-endian UCS-4 code
# units) for the same text. inspect must turn all three encodings of one
# text into the same UTF-8. The builder API cannot select those tags, so the
# subject/issuer Name SEQUENCEs are rewritten in DER after signing. The
# rewritten signature is cryptographically invalid, which is irrelevant:
# inspect never verifies signatures and must display these certificates like
# any other. Two rewritten values deliberately hold a structurally malformed
# string (an odd BMPString length; a UniversalString length that is not a
# multiple of four) to pin the invalid-certificate rejection.

TAG_UTF8_STRING = 0x0C
TAG_BMP_STRING = 0x1E
TAG_UNIVERSAL_STRING = 0x1C


def encode_oid_bytes(oid):
    arcs = [int(arc) for arc in oid.dotted_string.split(".")]
    encoded = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append((arc & 0x7F) | 0x80)
            arc >>= 7
        encoded.extend(reversed(chunks))
    return bytes(encoded)


def bmp_string_content(text):
    # One 16-bit big-endian UCS-2 code unit per character. The BMP fixtures
    # only use BMP-representable text; supplementary characters are covered
    # via UniversalString (and UTF8String), never encoded as BMP surrogates.
    return b"".join(ord(ch).to_bytes(2, "big") for ch in text)


def universal_string_content(text):
    # One 32-bit big-endian UCS-4 code unit per character, covering the whole
    # Unicode range including supplementary-plane characters.
    return b"".join(ord(ch).to_bytes(4, "big") for ch in text)


def name_value(oid, encoding, text):
    """Build an (oid, tag, content) DirectoryString attribute value."""
    if encoding == "utf8":
        return (oid, TAG_UTF8_STRING, text.encode("utf-8"))
    if encoding == "bmp":
        assert all(ord(ch) <= 0xFFFF for ch in text), text
        return (oid, TAG_BMP_STRING, bmp_string_content(text))
    if encoding == "universal":
        return (oid, TAG_UNIVERSAL_STRING, universal_string_content(text))
    raise ValueError(f"unknown name value encoding: {encoding!r}")


def name_attribute_tlv(oid, tag, content):
    return der_tlv(
        0x30, der_tlv(0x06, encode_oid_bytes(oid)) + der_tlv(tag, content)
    )


def single_rdn_name(attributes):
    """Name content with each attribute tuple in its own (single) RDN SET."""
    return [[attribute] for attribute in attributes]


def name_content(rdns):
    """Content bytes of an X.501 Name SEQUENCE.

    rdns is a list of RDNs; each RDN is a list of (oid, tag, content)
    attributes that share one SET (a multi-valued RDN).
    """
    parts = []
    for attributes in rdns:
        parts.append(
            der_tlv(0x31, b"".join(
                name_attribute_tlv(*attribute) for attribute in attributes))
        )
    return b"".join(parts)


def replace_names(der, subject_content, issuer_content):
    """Rewrite both Name SEQUENCE contents of an already-signed certificate.

    The issuer Name is the fourth tbsCertificate element and the subject Name
    the sixth (right after/around the validity), accounting for the optional
    explicit-version [0] wrapper. Only the two Name SEQUENCEs change; the
    outer certificate stays a complete Certificate with its signature intact
    structurally.
    """
    outer = iter_der_elements(der)
    assert len(outer) == 1 and outer[0][0] == 0x30
    cert_children = iter_der_elements(outer[0][1])
    tbs_children = iter_der_elements(cert_children[0][1])
    first = 1 if tbs_children[0][0] == 0xA0 else 0
    issuer_index = first + 2   # serial, signature algorithm, then issuer
    subject_index = first + 4  # issuer, validity, then subject
    assert tbs_children[issuer_index][0] == 0x30
    assert tbs_children[subject_index][0] == 0x30
    rewritten = (
        tbs_children[:issuer_index]
        + [(0x30, issuer_content)]
        + tbs_children[issuer_index + 1:subject_index]
        + [(0x30, subject_content)]
        + tbs_children[subject_index + 1:]
    )
    rewritten_tbs = der_tlv(
        0x30, b"".join(der_tlv(t, c) for t, c in rewritten)
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


def write_cert_pem(stem, der):
    """Write only the committed PEM sample for one certificate.

    The matching DER is derived at build time by prepare_fixtures.sh
    (base64-decoding exactly this PEM body), so it must not be written here.
    """
    (FIXTURES / f"{stem}.pem").write_bytes(pem_from_der(der))


def write_pem_body_trailing_fixtures(der):
    """Single PEM blocks whose base64 body holds more than one certificate.

    Both files look like an ordinary one-block PEM from the outside: one
    BEGIN/END CERTIFICATE pair, no text outside the block, and base64 that
    decodes completely. The decoded payload, however, is not exactly one
    certificate:

      * pem_body_trailing_nul.pem  -> the DER certificate plus one zero byte;
      * pem_body_trailing_cert.pem -> the DER certificate followed by another
        complete, byte-identical certificate.

    A reader that accepts whatever certificate parses from the START of the
    payload would wrongly report success; the trailing content is hidden
    inside the base64 rather than visible as a second block or text outside
    the markers. Both bodies have a base64 length that is a multiple of four
    with padding only at the very end (the NUL case happens to need none), so
    the whole body decodes cleanly and the rejection can only come from its
    extra content, never from a truncated encoding.
    """
    (FIXTURES / "pem_body_trailing_nul.pem").write_bytes(
        pem_from_der(der + b"\x00")
    )
    (FIXTURES / "pem_body_trailing_cert.pem").write_bytes(
        pem_from_der(der + der)
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


def write_ctrlchars_fixtures():
    """Write the ctrlchars.{der,pem} pair (also runnable on its own)."""
    import datetime

    utc = datetime.timezone.utc

    # A certificate whose subject and issuer names carry real control
    # characters (every byte below 0x20 renders as "\" + two uppercase hex
    # digits, so a name can never grow extra output lines). Subject and
    # issuer differ and each mixes the control characters with Chinese text,
    # the ",+" separators and a literal backslash. The names exercise:
    #   - LF, CR, TAB and NUL inside values -> \0A, \0D, \09, \00;
    #   - a NUL in the MIDDLE of a value with text kept on both sides;
    #   - control characters at the very start/end of a value (they must be
    #     escaped, never trimmed like surrounding whitespace);
    #   - the remaining sub-0x20 bytes (0x01, 0x07, 0x0B, 0x0C, 0x1F) under
    #     the same visible-escape rule;
    #   - a real LF ("\n" -> \0A) versus the three literal characters
    #     backslash, "0", "A" (the backslash itself escapes -> \\0A), which
    #     must not render identically;
    #   - repeated attributes and a multi-valued RDN group whose "+" joining
    #     and attribute order survive alongside the escaped bytes.
    ctrl_subject = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "控制字符测试组织"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "研发\t部\n一组"),
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "质量\r组"),
            x509.RelativeDistinguishedName(
                [
                    # Control character at the start of a value, inside a
                    # "+"-joined RDN group.
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "\n沪上"),
                    # Control character at the end of a value.
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, "北京\t"
                    ),
                ]
            ),
            # NUL in the middle: the text on both sides must survive.
            rdn(NameOID.COMMON_NAME, "中\x00文"),
            # A real newline ...
            rdn(NameOID.COMMON_NAME, "真实\n换行"),
            # ... versus the literal three characters "\0A": the backslash
            # itself is escaped, so this renders as \\0A, never as \0A.
            rdn(NameOID.COMMON_NAME, "字面\\0A文字"),
            # The remaining sub-0x20 bytes follow the same escape rule.
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "甲\x01\x07\x0b\x1f乙"),
            # Separators and a control character inside one value: the
            # escaped bytes must not turn into new attributes.
            rdn(NameOID.COMMON_NAME, "分,隔+符\\与\x0b中文"),
        ]
    )
    ctrl_issuer = x509.Name(
        [
            rdn(NameOID.COUNTRY_NAME, "CN"),
            rdn(NameOID.ORGANIZATION_NAME, "颁发\t机构"),
            # Control character at the end of a value.
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "CA中心\r"),
            # Control character at the start of a value.
            rdn(NameOID.ORGANIZATIONAL_UNIT_NAME, "\n起始"),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "北京"),
                    # NUL at the very start of a value.
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, "\x00起点"
                    ),
                ]
            ),
            # Literal backslash + "0D" (not a real CR) -> \\0D.
            rdn(NameOID.COMMON_NAME, "根\\0D证书"),
            # NUL at the very end of a value.
            rdn(NameOID.COMMON_NAME, "尾\x00"),
            rdn(NameOID.TITLE, "换\x0c页"),
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
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2044, 1, 1, tzinfo=utc))
        .sign(ctrl_issuer_key, hashes.SHA256())
    )
    write_cert_pem("ctrlchars", ctrl_cert.public_bytes(serialization.Encoding.DER))


# The same name text expressed in the three DirectoryString encodings the
# regression compares: Chinese, accented Latin letters and plain ASCII, all
# representable by BMPString as well as the other two (no supplementary-plane
# character here, so BMPString is on equal footing).
ENC_ORG = "示例科技CaféOne"
ENC_OU = "研发部NaïveGroup"
ENC_CN = "用户Renée01"


def country_name_attribute():
    # countryName is a PrintableString (tag 0x13), not a DirectoryString.
    return (NameOID.COUNTRY_NAME, 0x13, b"CN")


def write_name_string_encoding_fixtures():
    """PEM fixtures pinning UTF8String/BMPString/UniversalString name display.

    All but the two deliberately malformed certificates are self-contained
    complete certificates; their signatures are cryptographically invalid
    after the name surgery, which inspect never checks. The set:

      namesenc_utf8 / namesenc_bmp / namesenc_universal
          One self-signed base certificate (same key, serial, validity) whose
          subject and issuer carry the same text re-tagged as UTF8String,
          BMPString and UniversalString. BMP/Universal encodings of ordinary
          characters contain zero bytes (e.g. "中" -> 00 4D...), which must
          NOT surface as NUL escapes. All three render verbatim identically.
      nameenc_cross
          Subject values are BMPString while issuer values are UTF8String and
          the two names carry DIFFERENT text, so a render that lets one field
          leak into the other is caught.
      nameenc_nul
          The same value containing a REAL NUL ("中\\x00文Aé") is a BMPString
          in the subject and a UniversalString in the issuer; both must show
          the visible \\00 escape with the following text kept, while the
          zero bytes those wide encodings use for ordinary characters stay
          invisible. Each name adds its own NUL-bearing CN.
      nameenc_supplementary
          A supplementary-plane character (😀) shared by a UTF8String subject
          and a UniversalString issuer; both must show the character whole.
      namebad_bmp / namebad_universal
          Structurally complete certificates whose subject carries a
          BMPString with an odd content length, or a UniversalString whose
          content length is not a multiple of four. Both are certificate
          CONTENT errors: exit 1, "invalid certificate" naming the path,
          empty stdout, for PEM and DER alike.
    """
    import datetime

    utc = datetime.timezone.utc

    def common_attributes(encoding):
        return [
            country_name_attribute(),
            name_value(NameOID.ORGANIZATION_NAME, encoding, ENC_ORG),
            name_value(NameOID.ORGANIZATIONAL_UNIT_NAME, encoding, ENC_OU),
            name_value(NameOID.COMMON_NAME, encoding, ENC_CN),
        ]

    # One base certificate; only the name value tags differ between the
    # variants, so key material, serial and validity stay identical.
    common_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ENC_ORG),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ENC_OU),
            x509.NameAttribute(NameOID.COMMON_NAME, ENC_CN),
        ]
    )
    _, enc_base = make_self_signed(
        common_name,
        datetime.datetime(2024, 3, 1, tzinfo=utc),
        datetime.datetime(2044, 3, 1, tzinfo=utc),
        serial=0x6001,
    )
    enc_der = enc_base.public_bytes(serialization.Encoding.DER)
    write_cert_pem("namesenc_utf8", enc_der)
    bmp_content = name_content(single_rdn_name(common_attributes("bmp")))
    write_cert_pem(
        "namesenc_bmp", replace_names(enc_der, bmp_content, bmp_content)
    )
    universal_content = name_content(
        single_rdn_name(common_attributes("universal"))
    )
    write_cert_pem(
        "namesenc_universal",
        replace_names(enc_der, universal_content, universal_content),
    )

    # Subject (BMPString) and issuer (UTF8String) carry different text, so
    # the two lines must not borrow each other's values.
    placeholder = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "placeholder")]
    )
    cross_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cross_base = (
        x509.CertificateBuilder()
        .subject_name(placeholder)
        .issuer_name(placeholder)
        .public_key(cross_key.public_key())
        .serial_number(0x6002)
        .not_valid_before(datetime.datetime(2024, 4, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2044, 4, 1, tzinfo=utc))
        .sign(cross_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    cross_subject = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.ORGANIZATION_NAME, "bmp", "主体公司Subject"),
        name_value(NameOID.ORGANIZATIONAL_UNIT_NAME, "bmp", "终端部门EndEntity"),
        name_value(NameOID.COMMON_NAME, "bmp", "最终用户UserBMP"),
    ]))
    cross_issuer = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.ORGANIZATION_NAME, "utf8", "颁发机构Issuer"),
        name_value(NameOID.COMMON_NAME, "utf8", "根CA-Root"),
    ]))
    write_cert_pem(
        "nameenc_cross", replace_names(cross_base, cross_subject, cross_issuer)
    )

    # A real NUL in the middle of a value: BMPString subject vs UniversalString
    # issuer for the shared organization value, plus a distinct NUL-bearing CN
    # on each side. The wide encodings' structural zero bytes must never be
    # mistaken for the NUL.
    nul_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nul_base = (
        x509.CertificateBuilder()
        .subject_name(placeholder)
        .issuer_name(placeholder)
        .public_key(nul_key.public_key())
        .serial_number(0x6003)
        .not_valid_before(datetime.datetime(2024, 5, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2044, 5, 1, tzinfo=utc))
        .sign(nul_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    nul_shared = "中\x00文Aé"
    nul_subject = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.ORGANIZATION_NAME, "bmp", nul_shared),
        name_value(NameOID.COMMON_NAME, "bmp", "主体\x00Nul"),
    ]))
    nul_issuer = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.ORGANIZATION_NAME, "universal", nul_shared),
        name_value(NameOID.COMMON_NAME, "universal", "颁发\x00Root"),
    ]))
    write_cert_pem(
        "nameenc_nul", replace_names(nul_base, nul_subject, nul_issuer)
    )

    # Supplementary-plane character: UTF8String subject, UniversalString
    # issuer, the same whole value on both lines.
    supplementary_text = "Smile😀笑"
    sup_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sup_base = (
        x509.CertificateBuilder()
        .subject_name(placeholder)
        .issuer_name(placeholder)
        .public_key(sup_key.public_key())
        .serial_number(0x6004)
        .not_valid_before(datetime.datetime(2024, 6, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2044, 6, 1, tzinfo=utc))
        .sign(sup_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    sup_subject = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.COMMON_NAME, "utf8", supplementary_text),
    ]))
    sup_issuer = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.COMMON_NAME, "universal", supplementary_text),
    ]))
    write_cert_pem(
        "nameenc_supplementary",
        replace_names(sup_base, sup_subject, sup_issuer),
    )

    # Malformed name strings on otherwise complete certificates: an odd
    # BMPString length ("中" = 4E 2D plus one stray 0x65) and a
    # UniversalString length of 6 (one complete code unit plus half of one).
    bad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good_issuer_content = name_content(single_rdn_name([
        country_name_attribute(),
        name_value(NameOID.COMMON_NAME, "utf8", "good issuer"),
    ]))
    bad_specs = [
        ("namebad_bmp", TAG_BMP_STRING, b"\x4e\x2d\x65"),
        ("namebad_universal", TAG_UNIVERSAL_STRING,
         b"\x00\x00\x4e\x2d\x00\x00"),
    ]
    for stem, tag, raw_content in bad_specs:
        bad_base = (
            x509.CertificateBuilder()
            .subject_name(placeholder)
            .issuer_name(placeholder)
            .public_key(bad_key.public_key())
            .serial_number(0x6005)
            .not_valid_before(datetime.datetime(2024, 7, 1, tzinfo=utc))
            .not_valid_after(datetime.datetime(2044, 7, 1, tzinfo=utc))
            .sign(bad_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        bad_subject = name_content(single_rdn_name([
            country_name_attribute(),
            (NameOID.COMMON_NAME, tag, raw_content),
        ]))
        write_cert_pem(
            stem, replace_names(bad_base, bad_subject, good_issuer_content)
        )


def write_ec_fixtures():
    """Write the elliptic-curve fixtures: ec_issuer/ec_valid/ec_badsign.

    inspect never restricts the certificate's public key type and never
    verifies signatures, so its information display must work for an EC
    certificate exactly as it does for the RSA samples:

      ec_issuer
          A self-signed P-256 CA certificate (ECDSA with SHA-256). It exists
          as the fixed carrier of the ISSUER's public key: ec_valid is not
          self-signed, so its signature cannot be checked against a key in
          the leaf itself. The pure-stdlib regression proof parses this
          certificate to obtain the issuer point that verifies the leaf.
      ec_valid
          A complete certificate carrying a P-256 subject public key, signed
          by a DIFFERENT P-256 key (ec_issuer's) with ECDSA and SHA-256.
          Subject and issuer are distinct fixed names; serial and validity
          are fixed.
      ec_badsign
          The same leaf with one byte of its ECDSA signatureValue flipped
          after signing. The tbsCertificate (subject, issuer, validity,
          public key and signature algorithm) is byte-identical to ec_valid;
          the result is still a complete, parseable X.509 certificate whose
          signature genuinely fails. The caller asserts the verification
          outcomes with real elliptic-curve cryptography.

    As with every other fixture, only the PEM is committed and the DER is
    derived at build time; regeneration rotates the key material but the
    tests derive the expected fingerprints from the prepared DER bytes.
    """
    import datetime

    utc = datetime.timezone.utc

    issuer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               "Trustpeek EC Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               "Elliptic Curve Issuer"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ec-issuer.example.test"),
        ]
    )
    leaf_subject_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               "Trustpeek EC Test Org"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               "Elliptic Curve End Entity"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ec-valid.example.test"),
        ]
    )

    issuer_key = ec.generate_private_key(ec.SECP256R1())
    subject_key = ec.generate_private_key(ec.SECP256R1())

    not_before = datetime.datetime(2025, 3, 1, tzinfo=utc)
    not_after = datetime.datetime(2035, 3, 1, tzinfo=utc)

    # A self-signed issuer certificate: a complete, inspectable certificate
    # in its own right and the fixed source of the issuer public key for the
    # offline ECDSA verification proof in the regression suite.
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(0x7000)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(issuer_key, hashes.SHA256())
    )

    # The leaf carries a P-256 public key but is signed by the separate
    # issuer P-256 key; subject and issuer therefore differ by construction.
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(0x7001)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    assert leaf.subject != leaf.issuer
    assert leaf.issuer == issuer_cert.subject
    assert isinstance(leaf.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(leaf.public_key().curve, ec.SECP256R1)
    assert leaf.signature_hash_algorithm.name == "sha256"
    assert leaf.signature_algorithm_oid == ObjectIdentifier(
        "1.2.840.10045.4.3.2"
    )

    leaf_badsign_der = tamper_signature(leaf_der)
    # The leaf is signed by the separate issuer key, not by its own P-256
    # subject key, so verification must use the issuer public key.
    assert_signature_outcomes(
        leaf_der, leaf_badsign_der, issuer_cert.public_key()
    )

    write_cert_pem(
        "ec_issuer", issuer_cert.public_bytes(serialization.Encoding.DER)
    )
    write_cert_pem("ec_valid", leaf_der)
    write_cert_pem("ec_badsign", leaf_badsign_der)


def main():
    import datetime

    FIXTURES.mkdir(exist_ok=True)
    # DER files are derived artifacts, never source samples: drop any stale
    # *.der left in the source fixture tree so regeneration leaves exactly
    # the committed PEM set (the next build re-derives DER in its own tree).
    for stale_der in FIXTURES.glob("*.der"):
        stale_der.unlink()

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
    (FIXTURES / "valid.pem").write_bytes(
        valid.public_bytes(serialization.Encoding.PEM)
    )
    # A certificate identical to valid.pem in subject, issuer, validity,
    # public key and signature algorithm, whose signature CONTENT was altered
    # after signing so verification genuinely fails. Both are complete X.509
    # certificates; inspect reads information without verifying signatures,
    # so both must display and exit 0, with different SHA-256 fingerprints
    # (the signature is part of the certificate bytes).
    badsign_der = tamper_signature(der)
    assert_signature_outcomes(der, badsign_der)
    write_cert_pem("badsign", badsign_der)
    # Single-block PEM files whose base64 body is not exactly one certificate
    # (one trailing zero byte, or a second complete identical certificate).
    write_pem_body_trailing_fixtures(der)
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
    (FIXTURES / "longoid.pem").write_bytes(
        long_oid_cert.public_bytes(serialization.Encoding.PEM)
    )

    write_ctrlchars_fixtures()
    write_name_string_encoding_fixtures()
    write_ec_fixtures()

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
    write_cert_pem("century", century.public_bytes(serialization.Encoding.DER))

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
    write_cert_pem("mixedyears", mixed.public_bytes(serialization.Encoding.DER))

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
    write_cert_pem(
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
    write_cert_pem("reverseorder", reverse_der)

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
    write_cert_pem("baddate", baddate_der)


if __name__ == "__main__":
    main()
