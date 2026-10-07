#!/bin/sh
# Regression test runner for `trustpeek inspect`.
#
# Usage: run_case.sh <trustpeek-binary> <fixtures-dir> <case-name>
#
# Each case checks the real outcome of invoking the CLI: exit code, the full
# stdout, and the stderr diagnostics. A case exits 0 on pass and 1 on fail,
# printing the reason, so both direct execution and `ctest` report clearly.

set -u

BIN=$1
FIXTURES=$2
CASE=$3

# Symlink targets resolve relative to the link's own directory, so keep the
# fixtures path absolute regardless of the caller's working directory.
case "$FIXTURES" in
    /*) ;;
    *) FIXTURES=$PWD/$FIXTURES ;;
esac

TMP=$(mktemp -d)
# A staged FIFO writer (read_fifo_with_writer) stays blocked in open() until
# reaped; kill it on every exit path so a failing assertion cannot leak it.
writer=
cleanup() {
    if [ -n "$writer" ]; then
        kill "$writer" 2>/dev/null
        wait "$writer" 2>/dev/null
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

# Used by the special-file cases to prove inspect never blocks opening a
# FIFO. GNU coreutils and busybox both provide `timeout`; skip when absent.
TIMEOUT=$(command -v timeout || true)

NOTE='Note: this output displays certificate information only; reading the file successfully does not verify the signature or establish trust.'

# The fingerprints are derived from the prepared DER fixtures: each DER is
# produced by base64-decoding the body of the matching committed PEM, so the
# expected values stay in sync with the original certificates on disk and
# never silently become an empty string when a DER fixture is missing.
fingerprint_of() {
    der=$1
    # Fail loudly instead of deriving an empty expected fingerprint: the
    # prepare_fixtures step must have produced this file from the committed
    # PEM, so its absence means test data preparation is broken, not that
    # the certificate has no fingerprint.
    if [ ! -e "$der" ]; then
        echo "FAIL: $CASE: missing DER fixture '$der' (the prepare_fixtures step should have created it from the committed PEM)" >&2
        exit 1
    fi
    if [ ! -f "$der" ]; then
        echo "FAIL: $CASE: DER fixture '$der' is not a regular file" >&2
        exit 1
    fi
    if [ ! -r "$der" ]; then
        echo "FAIL: $CASE: DER fixture '$der' is not readable" >&2
        exit 1
    fi
    if [ ! -s "$der" ]; then
        echo "FAIL: $CASE: DER fixture '$der' is empty; refusing to use an empty expected fingerprint" >&2
        exit 1
    fi
    hash=$(sha256sum "$der" 2>/dev/null | cut -d' ' -f1)
    if [ "${#hash}" -ne 64 ]; then
        echo "FAIL: $CASE: cannot compute the 64-hex-char SHA-256 fingerprint of DER fixture '$der' (got '${hash}')" >&2
        exit 1
    fi
    case "$hash" in
        *[!0-9a-fA-F]*)
            echo "FAIL: $CASE: SHA-256 fingerprint of '$der' is not hexadecimal: '$hash'" >&2
            exit 1
            ;;
    esac
    printf '%s' "$hash" |
        tr 'a-f' 'A-F' | sed 's/\(..\)/\1:/g; s/:$//'
}
FINGERPRINT=$(fingerprint_of "$FIXTURES/valid.der")
BADSIGN_FINGERPRINT=$(fingerprint_of "$FIXTURES/badsign.der")
EXPIRED_FINGERPRINT=$(fingerprint_of "$FIXTURES/expired.der")
MARKER_FINGERPRINT=$(fingerprint_of "$FIXTURES/marker.der")
NAMES_FINGERPRINT=$(fingerprint_of "$FIXTURES/names.der")
LONGOID_FINGERPRINT=$(fingerprint_of "$FIXTURES/longoid.der")
CTRLCHARS_FINGERPRINT=$(fingerprint_of "$FIXTURES/ctrlchars.der")
NAMESENC_UTF8_FINGERPRINT=$(fingerprint_of "$FIXTURES/namesenc_utf8.der")
NAMESENC_BMP_FINGERPRINT=$(fingerprint_of "$FIXTURES/namesenc_bmp.der")
NAMESENC_UNIVERSAL_FINGERPRINT=$(fingerprint_of "$FIXTURES/namesenc_universal.der")
NAMEENC_CROSS_FINGERPRINT=$(fingerprint_of "$FIXTURES/nameenc_cross.der")
NAMEENC_NUL_FINGERPRINT=$(fingerprint_of "$FIXTURES/nameenc_nul.der")
NAMEENC_SUP_FINGERPRINT=$(fingerprint_of "$FIXTURES/nameenc_supplementary.der")
CENTURY_FINGERPRINT=$(fingerprint_of "$FIXTURES/century.der")
MIXED_FINGERPRINT=$(fingerprint_of "$FIXTURES/mixedyears.der")
GENERALIZED_FINGERPRINT=$(fingerprint_of "$FIXTURES/generalized.der")
REVERSE_FINGERPRINT=$(fingerprint_of "$FIXTURES/reverseorder.der")
EC_FINGERPRINT=$(fingerprint_of "$FIXTURES/ec.der")
EC_BADSIGN_FINGERPRINT=$(fingerprint_of "$FIXTURES/ec_badsign.der")
EC_BADSTRUCTURE_FINGERPRINT=$(fingerprint_of "$FIXTURES/ec_badstructure.der")

VALID_SUBJECT='C=CN, O=Trustpeek Test Org, OU=Engineering, CN=valid.example.test'
EXPIRED_SUBJECT='C=CN, O=Trustpeek Test Org, CN=expired.example.test'
MARKER_SUBJECT='C=CN, O=Trustpeek Test Org, CN=marker -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- test'

# Subject and issuer of the P-256/ECDSA certificate (tests/fixtures/ec.*).
# The subject public key is an EC point on P-256 and the issuer is a
# DIFFERENT P-256 key, so this is not a self-signed stand-in; inspect prints
# no key-type-specific field, so the output keeps exactly the same seven
# lines and field order as every RSA certificate.
EC_SUBJECT='C=CN, O=Trustpeek EC Test Org, OU=Engineering, CN=ec-leaf.example.test'
EC_ISSUER='C=CN, O=Trustpeek EC Test Org, OU=Certificate Authority, CN=ec-issuer.example.test'

# Subject and issuer of the deliberately non-self-signed complex-name
# certificate (tests/fixtures/names.{pem,der}). Every attribute, its order,
# the multi-valued-RDN grouping and the DN escaping is pinned verbatim:
#   - repeated OU must not collapse into one;
#   - the two attributes of one RDN are joined with a bare "+" while pluses
#     inside values stay escaped as "\+";
#   - commas and backslashes inside values stay escaped;
#   - leading/trailing value spaces survive as "\ ";
#   - the unknown OID is shown in dotted form;
#   - Chinese and other non-ASCII text stays as UTF-8.
NAMES_SUBJECT='C=CN, O=信任网络科技（北京）有限公司, CN=a\+b\,c\\d+OU=平台\+事业群, OU=安全组, title=Köln/München 工程部, CN=\ 终端用户证书\ '
NAMES_ISSUER='C=CN, O=示例科技有限公司, OU=研发部, OU=质量\,组\+A\\B, L=上海+ST=上海\+市\,测试, 1.2.3.4.5.6.7=未知属性值, CN=\ 颁发\,者\+根\\CA\ '

# Unknown OIDs whose dotted text is exactly 79, exactly 80 and 87 characters;
# the longer two share the complete 79-char prefix of the shortest and differ
# only in the final arc (9 / 90 / 900000000). A renderer that clips the dotted
# form at 79 characters prints all three as the same attribute name.
OID_79='1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28.29.9'
OID_80="$OID_79"0
OID_87="$OID_79"00000000

# Subject and issuer of the long-OID certificate (tests/fixtures/longoid.*).
# Every long OID must appear in full immediately followed by its own value;
# known short names, the short unknown OID, the repeated OUs, the "+"-joined
# RDN group and the DN escaping all keep the same rules as the names fixture.
LONGOID_SUBJECT='C=CN, OU=研发一部, OU=研发二部, OU=组内OU+CN=主体\\\+分组\\\,测试A, 1.2.3.4.5.6.7=短未知属性值, '"$OID_79"'=79位OID值甲, '"$OID_80"'=80位OID值乙, '"$OID_87"'=87位OID值丙, CN=\ 末端用户\ '
LONGOID_ISSUER='C=CN, O=长OID测试根CA, L=北京+ST=北京\\\,市\+区\\\\根, '"$OID_79"'=颁发者79位值, '"$OID_80"'=颁发者80位值, '"$OID_87"'=颁发者87位值, 1.2.3.4.5.6.7=颁发者短未知值, CN=\ 颁发\,者\+根\\CA\ '

# Subject and issuer of the control-character certificate
# (tests/fixtures/ctrlchars.{pem,der}). Every byte below 0x20 in a name value
# renders as "\" plus two uppercase hex digits, so a name can never grow
# extra output lines; the byte-for-byte comparison pins:
#   - LF/CR/TAB/NUL inside values as \0A, \0D, \09, \00;
#   - the NUL in the middle of "中\00文" with both sides kept;
#   - control characters at a value's start/end escaped, never trimmed;
#   - the other sub-0x20 bytes (0x01, 0x07, 0x0B, 0x0C, 0x1F) escaped alike;
#   - a real LF ("真实\0A换行") versus the literal characters backslash,
#     "0", "A" ("字面\\0A文字": the backslash itself escapes) -- the two must
#     never render identically;
#   - repeated attributes, the "+"-joined RDN groups and the escaped ",+\"
#     separators intact alongside the control bytes.
CTRL_SUBJECT='C=CN, O=控制字符测试组织, OU=研发\09部\0A一组, OU=质量\0D组, L=\0A沪上+ST=北京\09, CN=中\00文, CN=真实\0A换行, CN=字面\\0A文字, OU=甲\01\07\0B\1F乙, CN=分\,隔\+符\\与\0B中文'
CTRL_ISSUER='C=CN, O=颁发\09机构, OU=CA中心\0D, OU=\0A起始, L=北京+ST=\00起点, CN=根\\0D证书, CN=尾\00, title=换\0C页'

# The same name text stored once each as UTF8String, BMPString and
# UniversalString (tests/fixtures/namesenc_{utf8,bmp,universal}.*). BMPString
# and UniversalString hold zero bytes merely to encode ordinary characters
# (e.g. "中" -> 00 4E 2D in BMPString), which must never be shown as \00:
# after conversion all three render this one text verbatim. Chinese,
# accented Latin letters and plain ASCII are all present.
NAMEENC_SAME='C=CN, O=示例科技CaféOne, OU=研发部NaïveGroup, CN=用户Renée01'

# Subject and issuer of nameenc_cross use different encodings (subject values
# are BMPString, issuer values UTF8String) AND different text, proving the two
# lines cannot borrow each other's converted values.
NAMEENC_CROSS_SUBJECT='C=CN, O=主体公司Subject, OU=终端部门EndEntity, CN=最终用户UserBMP'
NAMEENC_CROSS_ISSUER='C=CN, O=颁发机构Issuer, CN=根CA-Root'

# Real NULs inside name values (nameenc_nul): the subject carries them as
# BMPString, the issuer as UniversalString. The genuine NUL renders as the
# visible \00 escape with the following text kept, while the wide encodings'
# structural zero bytes stay invisible. The shared organization value appears
# verbatim on both lines; each side has its own NUL-bearing CN.
NAMEENC_NUL_SUBJECT='C=CN, O=中\00文Aé, CN=主体\00Nul'
NAMEENC_NUL_ISSUER='C=CN, O=中\00文Aé, CN=颁发\00Root'

# A supplementary-plane character (😀) in a UTF8String subject and a
# UniversalString issuer: the 4-byte UTF-8 sequence must survive whole from
# both encodings rather than being split or dropped.
NAMEENC_SUP_NAME='C=CN, CN=Smile😀笑'

# Subjects of the validity-time fixtures (all self-signed).
CENTURY_SUBJECT='C=CN, O=Trustpeek Test Org, CN=century-pivot-1950.example.test'
MIXED_SUBJECT='C=CN, O=Trustpeek Test Org, CN=mixed-year-tags-49-2050.example.test'
GENERALIZED_SUBJECT='C=CN, O=Trustpeek Test Org, CN=generalized-2050.example.test'
REVERSE_SUBJECT='C=CN, O=Trustpeek Test Org, CN=reverse-tag-order.example.test'

write_expected_valid() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$VALID_SUBJECT"
        printf 'Issuer: %s\n' "$VALID_SUBJECT"
        printf 'Not Before: 2020-01-01T00:00:00Z\n'
        printf 'Not After: 2040-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# The tampered-signature certificate (badsign.*) shares every informational
# field with valid.* -- same subject, issuer, validity, public key and
# signature algorithm; only the signature content (and therefore the
# fingerprint) differs.
write_expected_badsign() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$VALID_SUBJECT"
        printf 'Issuer: %s\n' "$VALID_SUBJECT"
        printf 'Not Before: 2020-01-01T00:00:00Z\n'
        printf 'Not After: 2040-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$BADSIGN_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# The P-256 leaf certificate (ec.*): EC subject public key, ECDSA-with-SHA256
# signature from a distinct P-256 issuer key, distinct subject and issuer.
# inspect is key-type agnostic, so the output has the very same seven fields
# in the same order as every RSA certificate.
write_expected_ec() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$EC_SUBJECT"
        printf 'Issuer: %s\n' "$EC_ISSUER"
        printf 'Not Before: 2025-01-01T00:00:00Z\n'
        printf 'Not After: 2035-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$EC_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# The tampered-ECDSA certificate (ec_badsign.*) shares every informational
# field with ec.* -- same subject, issuer, validity, EC public key and
# signature algorithm; only the signature content (and therefore the
# fingerprint) differs.
write_expected_ec_badsign() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$EC_SUBJECT"
        printf 'Issuer: %s\n' "$EC_ISSUER"
        printf 'Not Before: 2025-01-01T00:00:00Z\n'
        printf 'Not After: 2035-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$EC_BADSIGN_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# The structurally-non-ECDSA certificate (ec_badstructure.*) likewise shares
# every informational field with ec.* -- same subject, issuer, validity, EC
# public key and signature algorithm. The difference from ec_badsign is
# inside the signature only: the carrying BIT STRING is intact and readable
# but its content cannot be interpreted as an ECDSA signature (one of the two
# required INTEGERs is missing). inspect neither verifies nor decodes the
# signature, so the certificate still displays, with its own fingerprint.
write_expected_ec_badstructure() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$EC_SUBJECT"
        printf 'Issuer: %s\n' "$EC_ISSUER"
        printf 'Not Before: 2025-01-01T00:00:00Z\n'
        printf 'Not After: 2035-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$EC_BADSTRUCTURE_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

write_expected_marker() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$MARKER_SUBJECT"
        printf 'Issuer: %s\n' "$MARKER_SUBJECT"
        printf 'Not Before: 2021-01-01T00:00:00Z\n'
        printf 'Not After: 2041-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$MARKER_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

write_expected_names() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$NAMES_SUBJECT"
        printf 'Issuer: %s\n' "$NAMES_ISSUER"
        printf 'Not Before: 2022-06-01T00:00:00Z\n'
        printf 'Not After: 2042-06-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$NAMES_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

write_expected_longoid() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$LONGOID_SUBJECT"
        printf 'Issuer: %s\n' "$LONGOID_ISSUER"
        printf 'Not Before: 2023-06-01T00:00:00Z\n'
        printf 'Not After: 2043-06-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$LONGOID_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

write_expected_ctrlchars() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$CTRL_SUBJECT"
        printf 'Issuer: %s\n' "$CTRL_ISSUER"
        printf 'Not Before: 2024-01-01T00:00:00Z\n'
        printf 'Not After: 2044-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$CTRLCHARS_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# Builds the full expected output of one name-encoding fixture:
# $1 = encoding, $2 = output file, $3 = Subject, $4 = Issuer,
# $5 = Not Before, $6 = Not After, $7 = SHA-256 fingerprint.
write_expected_nameenc() {
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$3"
        printf 'Issuer: %s\n' "$4"
        printf 'Not Before: %s\n' "$5"
        printf 'Not After: %s\n' "$6"
        printf 'SHA-256 Fingerprint: %s\n' "$7"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# Builds the full expected output of one self-signed validity-time fixture:
# $1 = encoding, $2 = output file, $3 = subject, $4 = Not Before,
# $5 = Not After, $6 = SHA-256 fingerprint.
write_expected_time() {
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$3"
        printf 'Issuer: %s\n' "$3"
        printf 'Not Before: %s\n' "$4"
        printf 'Not After: %s\n' "$5"
        printf 'SHA-256 Fingerprint: %s\n' "$6"
        printf '%s\n' "$NOTE"
    } >"$2"
}

write_expected_century() {  # $1 = encoding, $2 = output file
    write_expected_time "$1" "$2" "$CENTURY_SUBJECT" \
        '1950-01-01T00:00:00Z' '1952-02-29T23:59:59Z' "$CENTURY_FINGERPRINT"
}

write_expected_mixed() {  # $1 = encoding, $2 = output file
    write_expected_time "$1" "$2" "$MIXED_SUBJECT" \
        '2049-12-31T23:30:45Z' '2050-01-01T00:30:59Z' "$MIXED_FINGERPRINT"
}

write_expected_generalized() {  # $1 = encoding, $2 = output file
    write_expected_time "$1" "$2" "$GENERALIZED_SUBJECT" \
        '2052-02-29T03:04:05Z' '2100-12-31T23:59:59Z' "$GENERALIZED_FINGERPRINT"
}

write_expected_reverse() {  # $1 = encoding, $2 = output file
    write_expected_time "$1" "$2" "$REVERSE_SUBJECT" \
        '1949-01-01T00:00:00Z' '1950-06-15T12:00:00Z' "$REVERSE_FINGERPRINT"
}

# Structural guards for the EC certificate output ($1 = captured stdout
# file). inspect reads X.509 information without caring about the public key
# type, so an EC certificate must render with the exact same seven labeled
# fields in the exact same order as an RSA one: no key-type-specific line is
# added and no field is dropped. These checks also pin the distinct subject
# and issuer, the UTC time shape, the uppercase colon-separated fingerprint,
# and the fact that a verifiable signature never turns into a trust claim.
assert_ec_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" = "$EC_SUBJECT" ] ||
        fail "EC subject rendered incompletely or reordered"
    [ "$issuer" = "$EC_ISSUER" ] ||
        fail "EC issuer rendered incompletely or reordered"
    [ "$subject" != "$issuer" ] ||
        fail "the EC certificate must have different subject and issuer"
    [ "$(grep -c '^Subject: ' "$out")" -eq 1 ] ||
        fail "Subject must occupy exactly one line"
    [ "$(grep -c '^Issuer: ' "$out")" -eq 1 ] ||
        fail "Issuer must occupy exactly one line"
    [ "$(wc -l <"$out")" -eq 7 ] ||
        fail "EC output must have exactly 7 lines (an EC key must not add fields)"

    # Field labels must appear in exactly this order -- no extra key-type
    # line (e.g. a "Public Key" row) and no missing row.
    set -- 'Encoding: ' 'Subject: ' 'Issuer: ' 'Not Before: ' \
           'Not After: ' 'SHA-256 Fingerprint: ' 'Note:'
    line_no=1
    for prefix in "$@"; do
        sed -n "${line_no}p" "$out" | grep -qF "$prefix" ||
            fail "line $line_no must start with '$prefix' for an EC certificate too"
        line_no=$((line_no + 1))
    done

    before=$(sed -n 's/^Not Before: //p' "$out")
    after=$(sed -n 's/^Not After: //p' "$out")
    bad=$(printf '%s\n%s\n' "$before" "$after" |
              grep -vcE '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
    [ "$bad" -eq 0 ] ||
        fail "EC validity times must be full YYYY-MM-DDTHH:MM:SSZ UTC strings"

    fingerprint=$(sed -n 's/^SHA-256 Fingerprint: //p' "$out")
    printf '%s\n' "$fingerprint" |
        grep -qE '^([0-9A-F]{2}:){31}[0-9A-F]{2}$' ||
        fail "EC fingerprint must be 32 uppercase colon-separated hex bytes"

    # A successful read must never claim the signature is valid/trusted.
    # The Note itself only denies verification, so any trust claim is a
    # regression even for a certificate whose signature really verifies.
    if grep -iqE 'trusted|signature (is )?(valid|verified)' "$out"; then
        fail "EC output must not state or imply that the signature is trusted"
    fi
    grep -qF "$NOTE" "$out" ||
        fail "output must keep the no-trust-verification Note"
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"
}

# Test-setup guard for the precise truncation cases ($1 = truncated DER file):
# the file must still begin with an outer SEQUENCE whose tbsCertificate and
# signatureAlgorithm are fully present, and the cut must land INSIDE the
# signatureValue BIT STRING so that its DECLARED content length overruns the
# bytes actually remaining in the file. This is the "certificate file itself
# is incomplete" boundary -- distinct from a complete certificate whose
# signature content merely is not a legal ECDSA value. The rejection that
# follows must therefore be invalid-certificate content, never a read failure.
assert_signature_bitstring_overruns() {
    python3 - "$1" <<'EOF'
import sys

d = open(sys.argv[1], "rb").read()
if not d or d[0] != 0x30:
    sys.exit("not an outer SEQUENCE")


def header(pos):
    first = d[pos + 1]
    content_start = pos + 2
    if first < 0x80:
        return content_start, first
    count = first & 0x7F
    declared = int.from_bytes(d[content_start:content_start + count], "big")
    return content_start + count, declared


# Skip the outer SEQUENCE header, then the whole tbsCertificate and the
# signatureAlgorithm; the next element must be the signatureValue BIT STRING.
pos, _ = header(0)
for expected_tag in (0x30, 0x30):
    if pos >= len(d) or d[pos] != expected_tag:
        sys.exit("cut lands before the signature BIT STRING")
    start, length = header(pos)
    pos = start + length
if pos >= len(d) or d[pos] != 0x03:
    sys.exit("signatureValue element is not a BIT STRING")
start, declared = header(pos)
remaining = len(d) - start
if remaining >= declared:
    sys.exit("the BIT STRING declared length does not overrun the file")
EOF
    [ $? -eq 0 ] ||
        fail "test setup: truncation does not make the signature BIT STRING overrun the file"
}

# Structural guards for a validity-time output ($1 = captured stdout file,
# $2 = expected Not Before, $3 = expected Not After). The byte-for-byte
# comparison already pins everything; these restate the time-specific
# properties by name so a regression is explained rather than shown as a raw
# diff: the two moments stay on their own lines in certificate order, and
# each line has the full canonical YYYY-MM-DDTHH:MM:SSZ shape.
assert_time_structure() {
    out=$1
    want_before=$2
    want_after=$3
    before=$(sed -n 's/^Not Before: //p' "$out")
    after=$(sed -n 's/^Not After: //p' "$out")
    [ "$before" = "$want_before" ] ||
        fail "Not Before rendered as '$before', expected '$want_before'"
    [ "$after" = "$want_after" ] ||
        fail "Not After rendered as '$after', expected '$want_after'"
    [ "$before" != "$after" ] ||
        fail "Not Before and Not After must not collapse into one line"
    bad=$(printf '%s\n%s\n' "$before" "$after" |
              grep -vcE '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
    [ "$bad" -eq 0 ] ||
        fail "validity times must be full YYYY-MM-DDTHH:MM:SSZ UTC strings"
    grep -qF "$NOTE" "$out" ||
        fail "output must keep the no-trust-verification Note"
}

# Structural guards for the long-OID output ($1 = captured stdout file).
# Beyond the byte-for-byte expected comparison, these prove that no long
# dotted OID is clipped at a fixed width: the three prefix-sharing OIDs must
# each render in full and stay paired with their own value.
assert_longoid_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" != "$issuer" ] ||
        fail "subject and issuer must render different names"

    # Sanity on the constants: the dotted forms really are 79/80/87 chars and
    # the 79-char one is the exact prefix of the longer two.
    [ "$(printf '%s' "$OID_79" | wc -c)" -eq 79 ] ||
        fail "test setup: OID_79 must be exactly 79 characters"
    [ "$(printf '%s' "$OID_80" | wc -c)" -eq 80 ] ||
        fail "test setup: OID_80 must be exactly 80 characters"
    [ "$(printf '%s' "$OID_87" | wc -c)" -eq 87 ] ||
        fail "test setup: OID_87 must be 87 characters long"

    # Each full dotted OID must appear, joined to its OWN value; neither the
    # longer OID may collapse into the 79-char name nor steal another value.
    for token in "$OID_79=79位OID值甲" "$OID_80=80位OID值乙" \
                  "$OID_87=87位OID值丙" "$OID_79=颁发者79位值" \
                  "$OID_80=颁发者80位值" "$OID_87=颁发者87位值"; do
        case "$subject $issuer" in
            *"$token"*) ;;
            *) fail "long OID clipped or paired with the wrong value: $token" ;;
        esac
    done

    # The rendered OID names must be distinct: exactly one "=" follows each
    # full dotted form, and the 79-char name must not appear as the 80/87
    # names. Count occurrences of each complete "<OID>=" token.
    for pair in "$OID_79 2" "$OID_80 2" "$OID_87 2"; do
        oid=${pair% *}
        expected_count=${pair#* }
        count=$(printf '%s\n%s\n' "$subject" "$issuer" |
                    grep -oF "$oid=" | wc -l)
        [ "$count" -eq "$expected_count" ] ||
            fail "expected $expected_count occurrences of $oid= , got $count"
    done

    # The 80- and 87-char OIDs must show their trailing arc after the common
    # 79-char prefix; the final arc markers must be present in full.
    case "$subject" in
        *"$OID_80=80位"*"$OID_87=87位"*) ;;
        *) fail "80/87-char OID tails lost in subject" ;;
    esac
    case "$issuer" in
        *"$OID_80=颁发者80位"*"$OID_87=颁发者87位"*) ;;
        *) fail "80/87-char OID tails lost in issuer" ;;
    esac

    # Known short names and the short unknown OID survive alongside the long
    # ones, repeated OU stays repeated, and the "+"-grouped RDN is intact.
    for token in 'C=CN' 'OU=研发一部' 'OU=研发二部' 'CN=\ 末端用户\ ' \
                  '1.2.3.4.5.6.7=短未知属性值' '1.2.3.4.5.6.7=颁发者短未知值' \
                  'O=长OID测试根CA' 'CN=\ 颁发\,者\+根\\CA\ '; do
        case "$subject $issuer" in
            *"$token"*) ;;
            *) fail "missing or altered attribute token: $token" ;;
        esac
    done
    [ "$(printf '%s' "$subject" | grep -o 'OU=' | wc -l)" -eq 3 ] ||
        fail "subject must keep all three OU attributes"
    case "$subject" in
        *'OU=组内OU+CN='*) ;;
        *) fail "subject multi-valued RDN grouping broken" ;;
    esac
    case "$issuer" in
        *'L=北京+ST='*) ;;
        *) fail "issuer multi-valued RDN grouping broken" ;;
    esac

    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"
}

# Structural guards for the complex-name output ($1 = captured stdout file).
# The byte-for-byte expected comparison already pins everything; these checks
# document and independently re-prove the properties the fixture exists for,
# so a future change that loses attributes, mangles characters or breaks the
# RDN grouping is explained by name rather than a raw diff.
assert_names_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    # Subject and issuer are different names and render on separate lines.
    [ "$subject" != "$issuer" ] ||
        fail "subject and issuer must render different names"
    [ "$subject" = "$NAMES_SUBJECT" ] ||
        fail "complex subject rendered incompletely or reordered"
    [ "$issuer" = "$NAMES_ISSUER" ] ||
        fail "complex issuer rendered incompletely or reordered"

    # Whole name, including the non-ASCII values, must remain valid UTF-8.
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"

    # All attributes survive: known short names (incl. lowercase "title"),
    # the dotted unknown OID, and both repeated OU entries.
    for token in 'C=CN' 'O=示例科技有限公司' 'OU=研发部' 'OU=质量\,组\+A\\B' \
                  'L=上海' 'ST=上海\+市\,测试' '1.2.3.4.5.6.7=未知属性值' \
                  'CN=\ 颁发\,者\+根\\CA\ ' 'O=信任网络科技（北京）有限公司' \
                  'CN=a\+b\,c\\d' 'OU=平台\+事业群' 'OU=安全组' \
                  'title=Köln/München 工程部' 'CN=\ 终端用户证书\ '; do
        case "$subject $issuer" in
            *"$token"*) ;;
            *) fail "missing or altered attribute token: $token" ;;
        esac
    done
    [ "$(printf '%s' "$issuer" | grep -o 'OU=' | wc -l)" -eq 2 ] ||
        fail "repeated OU attribute must not be merged or overwritten"
    [ "$(printf '%s' "$subject" | grep -o 'CN=' | wc -l)" -eq 2 ] ||
        fail "both subject CN attributes (grouped and trailing) must survive"

    # A bare "+" joins the attributes of one RDN group; the pluses inside the
    # values are escaped, so the grouping stays distinguishable from content.
    case "$issuer" in
        *'L=上海+ST=上海\+市\,测试'*) ;;
        *) fail "issuer multi-valued RDN grouping broken" ;;
    esac
    case "$subject" in
        *'CN=a\+b\,c\\d+OU=平台\+事业群'*) ;;
        *) fail "subject group separator confused with in-value plus" ;;
    esac
    [ "$(printf '%s' "$subject" | LC_ALL=C grep -oE '[^\\]\+' | wc -l)" -eq 1 ] ||
        fail "subject must have exactly one unescaped group '+'"
    [ "$(printf '%s' "$issuer" | LC_ALL=C grep -oE '[^\\]\+' | wc -l)" -eq 1 ] ||
        fail "issuer must have exactly one unescaped group '+'"

    # Leading/trailing value spaces are preserved via "\ " and must not be
    # trimmed into the ", " separator between RDN groups.
    case "$subject" in
        *', CN=\ 终端用户证书\ ') ;;
        *) fail "leading/trailing spaces of final value must be preserved" ;;
    esac
}

# Structural guards for the control-character name output ($1 = captured
# stdout file). The byte-for-byte expected comparison already pins
# everything; these checks re-prove by name the properties the fixture
# exists for, so a regression (a raw control byte breaking the line
# structure, a trimmed value edge, a collapsed attribute) is explained
# rather than shown as a raw diff.
assert_ctrlchars_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    # Subject and issuer are different names, each on exactly one line: the
    # control characters inside the values must not grow extra lines.
    [ "$subject" != "$issuer" ] ||
        fail "subject and issuer must render different names"
    [ "$(grep -c '^Subject: ' "$out")" -eq 1 ] ||
        fail "Subject must occupy exactly one line"
    [ "$(grep -c '^Issuer: ' "$out")" -eq 1 ] ||
        fail "Issuer must occupy exactly one line"
    [ "$(wc -l <"$out")" -eq 7 ] ||
        fail "output must have exactly 7 lines (no line split by a name)"
    [ "$subject" = "$CTRL_SUBJECT" ] ||
        fail "control-character subject rendered incompletely or reordered"
    [ "$issuer" = "$CTRL_ISSUER" ] ||
        fail "control-character issuer rendered incompletely or reordered"

    # No raw control byte may leak into the output: the only bytes below
    # 0x20 (plus DEL) in the whole stream are the 7 line-ending newlines.
    ctrl_bytes=$(LC_ALL=C tr -cd '\000-\037\177' <"$out" | wc -c)
    [ "$ctrl_bytes" -eq 7 ] ||
        fail "output carries $ctrl_bytes raw control bytes, expected only the 7 newlines"

    # Whole name, including the non-ASCII values, must remain valid UTF-8.
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"

    # The visible escapes for LF, CR, TAB and NUL appear in both names.
    for token in '\0A' '\0D' '\09' '\00'; do
        case "$subject$issuer" in
            *"$token"*) ;;
            *) fail "missing visible escape: $token" ;;
        esac
    done

    # A NUL in the middle of a value keeps the text on both sides.
    case "$subject" in
        *'CN=中\00文'*) ;;
        *) fail "text around a mid-value NUL must survive" ;;
    esac

    # Control characters at a value's start/end are escaped, never trimmed
    # away like surrounding whitespace.
    for token in 'L=\0A沪上' 'ST=北京\09' 'OU=\0A起始' 'OU=CA中心\0D' \
                  'ST=\00起点' 'CN=尾\00'; do
        case "$subject $issuer" in
            *"$token"*) ;;
            *) fail "control character at value edge trimmed or altered: $token" ;;
        esac
    done

    # A real newline renders as \0A while the literal three characters
    # backslash, "0", "A" render as \\0A (the backslash itself escaped);
    # the two must stay distinguishable.
    case "$subject" in
        *'CN=真实\0A换行'*) ;;
        *) fail "real LF must render as \\0A" ;;
    esac
    case "$subject" in
        *'CN=字面\\0A文字'*) ;;
        *) fail "literal backslash-0-A must render as \\\\0A" ;;
    esac
    case "$issuer" in
        *'CN=根\\0D证书'*) ;;
        *) fail "literal backslash-0-D must render as \\\\0D" ;;
    esac

    # The remaining sub-0x20 bytes follow the same visible-escape rule.
    case "$subject" in
        *'OU=甲\01\07\0B\1F乙'*) ;;
        *) fail "sub-0x20 bytes must each render as \\XX" ;;
    esac
    case "$issuer" in
        *'title=换\0C页'*) ;;
        *) fail "form feed must render as \\0C" ;;
    esac

    # Attribute structure survives the escaped bytes: repeated attributes
    # stay repeated, the "+"-joined RDN groups keep their single bare "+",
    # and the escaped ",+\" inside a value cannot become new attributes.
    [ "$(printf '%s' "$subject" | grep -o 'OU=' | wc -l)" -eq 3 ] ||
        fail "subject must keep all three OU attributes"
    [ "$(printf '%s' "$subject" | grep -o 'CN=' | wc -l)" -eq 4 ] ||
        fail "subject must keep all four CN attributes"
    [ "$(printf '%s' "$issuer" | grep -o 'OU=' | wc -l)" -eq 2 ] ||
        fail "issuer must keep both OU attributes"
    case "$subject" in
        *'L=\0A沪上+ST=北京\09'*) ;;
        *) fail "subject multi-valued RDN grouping broken" ;;
    esac
    case "$issuer" in
        *'L=北京+ST=\00起点'*) ;;
        *) fail "issuer multi-valued RDN grouping broken" ;;
    esac
    [ "$(printf '%s' "$subject" | LC_ALL=C grep -oE '[^\\]\+' | wc -l)" -eq 1 ] ||
        fail "subject must have exactly one unescaped group '+'"
    [ "$(printf '%s' "$issuer" | LC_ALL=C grep -oE '[^\\]\+' | wc -l)" -eq 1 ] ||
        fail "issuer must have exactly one unescaped group '+'"
    case "$subject" in
        *'CN=分\,隔\+符\\与\0B中文') ;;
        *) fail "escaped separators in a value must not become attributes" ;;
    esac

    grep -qF "$NOTE" "$out" ||
        fail "output must keep the no-trust-verification Note"
}

# Structural guards shared by the name-encoding equivalence cases
# ($1 = captured stdout file). Beyond the byte-for-byte expected comparison,
# these prove by name that: UTF8String/BMPString/UniversalString of the same
# text render verbatim identically (wide-encoding zero bytes never become
# \00); Subject and Issuer each occupy their own single line and remain valid
# UTF-8; and the no-trust Note is still printed.
assert_nameenc_same_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" = "$NAMEENC_SAME" ] ||
        fail "converted name does not match the shared text"
    [ "$issuer" = "$NAMEENC_SAME" ] ||
        fail "converted issuer name does not match the shared text"

    # Chinese, accented Latin and plain ASCII all survive.
    for token in '示例科技CaféOne' '研发部NaïveGroup' '用户Renée01'; do
        case "$subject$issuer" in
            *"$token"*) ;;
            *) fail "name text truncated or mangled: $token" ;;
        esac
    done

    # The wide encodings contain zero bytes for ordinary characters, but none
    # of those may surface as a NUL escape: there is no real NUL in this name.
    case "$subject$issuer" in
        *'\00'*) fail "structural zero byte of a wide encoding shown as \\00" ;;
    esac

    [ "$(grep -c '^Subject: ' "$out")" -eq 1 ] ||
        fail "Subject must occupy exactly one line"
    [ "$(grep -c '^Issuer: ' "$out")" -eq 1 ] ||
        fail "Issuer must occupy exactly one line"
    [ "$(wc -l <"$out")" -eq 7 ] ||
        fail "output must have exactly 7 lines (no line split by a name)"
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"
    grep -qF "$NOTE" "$out" ||
        fail "output must keep the no-trust-verification Note"
}

# Structural guards for the field-isolation case (nameenc_cross): a
# BMPString subject and a UTF8String issuer carry different text, so each
# converted value must stay on its own line and never appear on the other.
assert_nameenc_cross_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" = "$NAMEENC_CROSS_SUBJECT" ] ||
        fail "BMPString subject rendered incompletely or reordered"
    [ "$issuer" = "$NAMEENC_CROSS_ISSUER" ] ||
        fail "UTF8String issuer rendered incompletely or reordered"
    [ "$subject" != "$issuer" ] ||
        fail "subject and issuer must render different names"

    for token in '主体公司Subject' '终端部门EndEntity' '最终用户UserBMP'; do
        case "$subject" in *"$token"*) ;; *) fail "missing subject value: $token" ;;
        esac
        case "$issuer" in
            *"$token"*) fail "subject value leaked into the issuer line: $token" ;;
        esac
    done
    for token in '颁发机构Issuer' '根CA-Root'; do
        case "$issuer" in *"$token"*) ;; *) fail "missing issuer value: $token" ;;
        esac
        case "$subject" in
            *"$token"*) fail "issuer value leaked into the subject line: $token" ;;
        esac
    done

    [ "$(grep -c '^Subject: ' "$out")" -eq 1 ] ||
        fail "Subject must occupy exactly one line"
    [ "$(grep -c '^Issuer: ' "$out")" -eq 1 ] ||
        fail "Issuer must occupy exactly one line"
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"
}

# Structural guards for the real-NUL case (nameenc_nul): a genuine NUL in a
# BMPString or UniversalString value renders as visible \00 with the text
# after it kept, while the encodings' structural zero bytes never do. The
# shared organization value is identical on both differently-encoded lines.
assert_nameenc_nul_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" = "$NAMEENC_NUL_SUBJECT" ] ||
        fail "BMPString NUL subject rendered incompletely or reordered"
    [ "$issuer" = "$NAMEENC_NUL_ISSUER" ] ||
        fail "UniversalString NUL issuer rendered incompletely or reordered"

    # The real NUL shows as \00 with text kept on both sides (BMP subject and
    # Universal issuer agree on the shared organization value).
    for line in "$subject" "$issuer"; do
        case "$line" in
            *'O=中\00文Aé'*) ;;
            *) fail "real NUL must render as \\00 with following text kept" ;;
        esac
        # Ordinary wide-encoding code units contribute no other \00: each
        # line has exactly two (one in O, one in CN).
        count=$(printf '%s' "$line" | grep -oF '\00' | wc -l)
        [ "$count" -eq 2 ] ||
            fail "expected exactly two real-NUL \\00 escapes per name, got $count"
    done
    # Each side keeps its own distinct NUL-bearing CN (no field cross-talk).
    case "$subject" in *'CN=主体\00Nul'*) ;; *) fail "subject NUL CN lost" ;;
    esac
    case "$issuer" in *'CN=颁发\00Root'*) ;; *) fail "issuer NUL CN lost" ;;
    esac
    case "$subject" in
        *'颁发\00Root'*) fail "issuer CN leaked into subject line" ;;
    esac

    [ "$(grep -c '^Subject: ' "$out")" -eq 1 ] ||
        fail "Subject must occupy exactly one line"
    [ "$(grep -c '^Issuer: ' "$out")" -eq 1 ] ||
        fail "Issuer must occupy exactly one line"
    [ "$(wc -l <"$out")" -eq 7 ] ||
        fail "output must have exactly 7 lines (no line split by a NUL)"
    # No raw NUL byte may reach stdout; the only sub-0x20 bytes are newlines.
    nul_count=$(LC_ALL=C tr -cd '\000' <"$out" | wc -c)
    [ "$nul_count" -eq 0 ] || fail "a raw NUL byte leaked into the output"
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"
}

# Structural guards for the supplementary-plane case (nameenc_supplementary):
# the same astral character is whole in a UTF8String and a UniversalString.
assert_nameenc_sup_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" = "$NAMEENC_SUP_NAME" ] ||
        fail "UTF8String supplementary-character subject rendered incompletely"
    [ "$issuer" = "$NAMEENC_SUP_NAME" ] ||
        fail "UniversalString supplementary-character issuer rendered incompletely"
    # The 4-byte UTF-8 encoding of U+1F600 appears whole on both lines, kept
    # together with its surrounding BMP text.
    count=$(grep -oF '😀' "$out" | wc -l)
    [ "$count" -eq 2 ] ||
        fail "supplementary-plane character must appear whole on both lines, got $count"
    case "$subject$issuer" in
        *'Smile😀笑'*) ;;
        *) fail "text around the supplementary-plane character must survive" ;;
    esac
    [ "$(wc -l <"$out")" -eq 7 ] ||
        fail "output must have exactly 7 lines"
    iconv -f UTF-8 -t UTF-8 "$out" >/dev/null ||
        fail "output is not valid UTF-8"
}


# asserting the PEM-integrity preconditions shared by the body-content cases:
# exactly one begin/end marker pair, only whitespace outside the block, and a
# body whose base64 decodes completely. When this passes, any rejection of the
# file must come from excess content INSIDE the decoded payload -- not from
# text outside the block, damaged markers or a truncated encoding.
decode_single_pem_body() {
    pem=$1
    out=$2
    # CRLF is accepted whitespace around and between PEM lines, so analyze a
    # CR-stripped copy; the base64 alphabet contains no CR anyway.
    tr -d '\r' <"$pem" >"$TMP/pem.normalized"
    begin_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$TMP/pem.normalized")
    end_count=$(grep -c '^-----END CERTIFICATE-----$' "$TMP/pem.normalized")
    [ "$begin_count" -eq 1 ] ||
        fail "fixture must contain exactly one BEGIN CERTIFICATE marker, got $begin_count"
    [ "$end_count" -eq 1 ] ||
        fail "fixture must contain exactly one END CERTIFICATE marker, got $end_count"
    outside=$(awk '
        /^-----BEGIN CERTIFICATE-----$/ { in_block = 1; next }
        /^-----END CERTIFICATE-----$/ { in_block = 0; next }
        in_block { next }
        { print }' "$TMP/pem.normalized" | tr -d '[:space:]')
    [ -z "$outside" ] ||
        fail "fixture must have no non-whitespace content outside the PEM block"
    sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p' "$TMP/pem.normalized" |
        sed '1d;$d' | tr -d '[:space:]' | base64 -d >"$out" ||
        fail "PEM body base64 must decode completely (no truncated encoding)"
}

fail() {
    echo "FAIL: $CASE: $1" >&2
    exit 1
}

# Run `trustpeek inspect $2` with TZ=$1; leaves the result in rc and the
# captured streams in $TMP/stdout / $TMP/stderr (same layout as
# expect_success so the usual assertions can follow).
run_with_tz() {
    tz=$1
    file=$2
    TZ="$tz" "$BIN" inspect "$file" >"$TMP/stdout" 2>"$TMP/stderr"
    rc=$?
}

# Run `trustpeek inspect $1` and require exit 0, empty stderr, and stdout
# exactly matching the expected file $2.
expect_success() {
    file=$1
    expected=$2
    "$BIN" inspect "$file" >"$TMP/stdout" 2>"$TMP/stderr"
    rc=$?
    [ "$rc" -eq 0 ] || fail "expected exit 0, got $rc (stderr: $(cat "$TMP/stderr"))"
    [ -s "$TMP/stderr" ] && fail "expected empty stderr, got: $(cat "$TMP/stderr")"
    if ! cmp -s "$expected" "$TMP/stdout"; then
        diff -u "$expected" "$TMP/stdout" >&2
        fail "stdout does not match expected certificate info"
    fi
}

# Run `trustpeek inspect $1` and require exit 1, empty stdout, and a stderr
# diagnostic that reports invalid certificate content and names the path.
expect_invalid() {
    file=$1
    "$BIN" inspect "$file" >"$TMP/stdout" 2>"$TMP/stderr"
    rc=$?
    [ "$rc" -eq 1 ] || fail "expected exit 1, got $rc"
    [ -s "$TMP/stdout" ] && fail "stdout must be empty on failure, got: $(cat "$TMP/stdout")"
    grep -q "invalid certificate" "$TMP/stderr" ||
        fail "stderr should report invalid certificate content, got: $(cat "$TMP/stderr")"
    grep -qF "$file" "$TMP/stderr" ||
        fail "stderr should name the input path '$file', got: $(cat "$TMP/stderr")"
}

# Asserts an already-finished run ($rc, $TMP/stdout, $TMP/stderr) is a file
# READ failure: exit 1, empty stdout, a stderr diagnostic distinct from
# invalid-certificate content that names the path and carries a real reason
# rather than a stale errno ("Success" belongs to no failing operation).
assert_read_failure_result() {
    file=$1
    detail_pattern=${2:-}
    [ "$rc" -eq 1 ] || fail "expected exit 1, got $rc (stderr: $(cat "$TMP/stderr"))"
    [ -s "$TMP/stdout" ] && fail "stdout must be empty on read failure, got: $(cat "$TMP/stdout")"
    grep -q "failed to read file" "$TMP/stderr" ||
        fail "stderr should report a file read failure, got: $(cat "$TMP/stderr")"
    grep -qF "$file" "$TMP/stderr" ||
        fail "stderr should name the input path '$file', got: $(cat "$TMP/stderr")"
    if grep -q "invalid certificate" "$TMP/stderr"; then
        fail "read failure must not be classified as invalid certificate content: $(cat "$TMP/stderr")"
    fi
    if grep -qF ": Success" "$TMP/stderr"; then
        fail "read failure must explain the real reason, not 'Success': $(cat "$TMP/stderr")"
    fi
    if [ -n "$detail_pattern" ]; then
        grep -q "$detail_pattern" "$TMP/stderr" ||
            fail "stderr should explain the cause ($detail_pattern), got: $(cat "$TMP/stderr")"
    fi
}

# Run `trustpeek inspect $1` and require exit 1, empty stdout, and a stderr
# diagnostic that reports a file READ failure (distinct from invalid
# certificate content), names the path, and carries a real reason.
expect_read_failure() {
    file=$1
    detail_pattern=${2:-}
    "$BIN" inspect "$file" >"$TMP/stdout" 2>"$TMP/stderr"
    rc=$?
    assert_read_failure_result "$file" "$detail_pattern"
}

# Same as expect_read_failure, but run under timeout so a path that wrongly
# blocks on open (e.g. a FIFO without a writer) fails the case instead of
# hanging the whole test suite.
expect_read_failure_timed() {
    file=$1
    detail_pattern=${2:-}
    if [ -z "$TIMEOUT" ]; then
        echo "PASS: $CASE (skipped: timeout utility unavailable)"
        exit 0
    fi
    $TIMEOUT 5 "$BIN" inspect "$file" >"$TMP/stdout" 2>"$TMP/stderr"
    rc=$?
    [ "$rc" -eq 124 ] && fail "inspect blocked on '$file' instead of rejecting its type"
    assert_read_failure_result "$file" "$detail_pattern"
}

case "$CASE" in
    pem_basic)
        write_expected_valid PEM "$TMP/expected"
        expect_success "$FIXTURES/valid.pem" "$TMP/expected"
        ;;

    der_basic)
        write_expected_valid DER "$TMP/expected"
        expect_success "$FIXTURES/valid.der" "$TMP/expected"
        ;;

    pem_der_same_fields)
        # Same certificate in both encodings: every field except the
        # Encoding line must be identical.
        "$BIN" inspect "$FIXTURES/valid.pem" >"$TMP/pem.out" 2>/dev/null ||
            fail "PEM input failed"
        "$BIN" inspect "$FIXTURES/valid.der" >"$TMP/der.out" 2>/dev/null ||
            fail "DER input failed"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on subject/issuer/validity/fingerprint"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        ;;

    pem_wrong_extension)
        cp "$FIXTURES/valid.pem" "$TMP/cert.der"
        write_expected_valid PEM "$TMP/expected"
        expect_success "$TMP/cert.der" "$TMP/expected"
        ;;

    der_wrong_extension)
        cp "$FIXTURES/valid.der" "$TMP/cert.pem"
        write_expected_valid DER "$TMP/expected"
        expect_success "$TMP/cert.pem" "$TMP/expected"
        ;;

    pem_surrounding_whitespace)
        # Spaces, tabs, blank lines and CRLF around a valid PEM block.
        {
            printf '  \t\n\n \t \n'
            sed 's/$/\r/' "$FIXTURES/valid.pem"
            printf '\n\t\n  \n'
        } >"$TMP/whitespace.pem"
        write_expected_valid PEM "$TMP/expected"
        expect_success "$TMP/whitespace.pem" "$TMP/expected"
        ;;

    expired_ok)
        # An expired but complete certificate still displays and exits 0.
        {
            printf 'Encoding: PEM\n'
            printf 'Subject: %s\n' "$EXPIRED_SUBJECT"
            printf 'Issuer: %s\n' "$EXPIRED_SUBJECT"
            printf 'Not Before: 2000-01-01T00:00:00Z\n'
            printf 'Not After: 2001-01-01T00:00:00Z\n'
            printf 'SHA-256 Fingerprint: %s\n' "$EXPIRED_FINGERPRINT"
            printf '%s\n' "$NOTE"
        } >"$TMP/expected"
        expect_success "$FIXTURES/expired.pem" "$TMP/expected"
        ;;

    self_signed_ok)
        # A self-signed certificate is displayed like any other; the Note
        # still states that no signature verification or trust is implied.
        "$BIN" inspect "$FIXTURES/valid.pem" >"$TMP/stdout" 2>"$TMP/stderr" ||
            fail "self-signed certificate should exit 0"
        subject=$(sed -n 's/^Subject: //p' "$TMP/stdout")
        issuer=$(sed -n 's/^Issuer: //p' "$TMP/stdout")
        [ "$subject" = "$issuer" ] ||
            fail "fixture should be self-signed (subject == issuer)"
        grep -qF "$NOTE" "$TMP/stdout" ||
            fail "output must keep the no-trust-verification Note"
        ;;

    # --- Invalid signature still displays -------------------------------
    # badsign.* is a complete X.509 certificate identical to valid.* in
    # subject, issuer, validity, public key and signature algorithm; only
    # the signature content was altered after signing, so verification
    # genuinely fails (proven by badsign_signature_really_invalid). inspect
    # reads information without verifying signatures: both certificates
    # must display and exit 0, and neither output may claim the signature
    # is valid or trusted -- the byte-for-byte expected files pin the exact
    # output, including the closing no-trust Note.

    badsign_pem)
        write_expected_badsign PEM "$TMP/expected"
        expect_success "$FIXTURES/badsign.pem" "$TMP/expected"
        ;;

    badsign_der)
        write_expected_badsign DER "$TMP/expected"
        expect_success "$FIXTURES/badsign.der" "$TMP/expected"
        ;;

    badsign_pem_der_same_fields)
        # The invalid-signature certificate saved as PEM and as DER: the
        # Encoding line reports the real format, everything else agrees.
        "$BIN" inspect "$FIXTURES/badsign.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/badsign.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on subject/issuer/validity/fingerprint"
        grep -qF "$NOTE" "$TMP/pem.out" ||
            fail "output must keep the no-trust-verification Note"
        ;;

    badsign_same_fields_as_valid)
        # The two certificates share subject, issuer, validity, public key
        # and signature algorithm: those rendered lines must be identical,
        # while the SHA-256 fingerprints differ because the signature is
        # part of the certificate bytes each fingerprint is computed over.
        "$BIN" inspect "$FIXTURES/valid.pem" >"$TMP/valid.out" 2>"$TMP/valid.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "valid.pem inspect failed with $rc"
        [ -s "$TMP/valid.err" ] &&
            fail "valid.pem stderr not empty: $(cat "$TMP/valid.err")"
        "$BIN" inspect "$FIXTURES/badsign.pem" >"$TMP/badsign.out" 2>"$TMP/badsign.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "badsign.pem inspect failed with $rc"
        [ -s "$TMP/badsign.err" ] &&
            fail "badsign.pem stderr not empty: $(cat "$TMP/badsign.err")"
        sed -n '2,5p' "$TMP/valid.out" >"$TMP/valid.fields"
        sed -n '2,5p' "$TMP/badsign.out" >"$TMP/badsign.fields"
        cmp -s "$TMP/valid.fields" "$TMP/badsign.fields" ||
            fail "subject/issuer/validity lines must be identical for the two certificates"
        grep -qx "SHA-256 Fingerprint: $FINGERPRINT" "$TMP/valid.out" ||
            fail "valid.pem must show the fingerprint of its own complete DER encoding"
        grep -qx "SHA-256 Fingerprint: $BADSIGN_FINGERPRINT" "$TMP/badsign.out" ||
            fail "badsign.pem must show the fingerprint of its own complete DER encoding"
        [ "$FINGERPRINT" != "$BADSIGN_FINGERPRINT" ] ||
            fail "the two certificates must have different SHA-256 fingerprints"
        grep -qF "$NOTE" "$TMP/valid.out" ||
            fail "valid.pem output must keep the no-trust-verification Note"
        grep -qF "$NOTE" "$TMP/badsign.out" ||
            fail "badsign.pem output must keep the no-trust-verification Note"
        ;;

    badsign_signature_really_invalid)
        # The invalid signature must be a genuine property of the fixture
        # input -- self-signedness, identical names or expiry cannot stand
        # in for it. Prove offline, with the Python standard library only
        # (no cryptography package, no network, no system trust store, no
        # dependence on the current date), that:
        #   * both certificates carry the SAME tbsCertificate bytes (same
        #     subject, issuer, validity, public key, signature algorithm)
        #     and differ only in the signature content;
        #   * valid.der's signature verifies under its own RSA public key
        #     (PKCS#1 v1.5 with SHA-256);
        #   * badsign.der's signature does NOT verify under the same key.
        if ! python3 - "$FIXTURES/valid.der" "$FIXTURES/badsign.der" <<'EOF'
import hashlib
import sys


def fail(message):
    print(f"fixture precondition failed: {message}", file=sys.stderr)
    sys.exit(1)


def read_tlv(data, pos):
    start = pos
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    return tag, data[pos:end], data[start:end], end


def parse_cert(path):
    with open(path, "rb") as handle:
        der = handle.read()
    tag, content, _, end = read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        fail(f"{path}: outer SEQUENCE must span the whole file")
    children = []
    pos = 0
    while pos < len(content):
        child_tag, child_content, child_tlv, pos = read_tlv(content, pos)
        children.append((child_tag, child_content, child_tlv))
    if len(children) != 3:
        fail(f"{path}: a certificate must have exactly 3 top-level elements")
    return children


valid = parse_cert(sys.argv[1])
badsign = parse_cert(sys.argv[2])

# tbsCertificate (index 0) and signatureAlgorithm (index 1) must be
# byte-identical; only the signatureValue BIT STRING (index 2) may differ.
if valid[0][2] != badsign[0][2]:
    fail("the two certificates must share the same tbsCertificate bytes")
if valid[1][2] != badsign[1][2]:
    fail("the two certificates must use the same signature algorithm")
if valid[2][1] == badsign[2][1]:
    fail("the signature content must differ between the two certificates")

tbs_tlv = valid[0][2]
# sha256WithRSAEncryption (1.2.840.113549.1.1.11) is what the RSA check
# below implements.
if b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" not in valid[1][1]:
    fail("fixtures must be signed with sha256WithRSAEncryption")

# SubjectPublicKeyInfo is the seventh tbsCertificate element (after the
# explicit version tag, serial number, signature algorithm, issuer,
# validity and subject).
tbs_children = []
pos = 0
while pos < len(valid[0][1]):
    child_tag, child_content, _, pos = read_tlv(valid[0][1], pos)
    tbs_children.append((child_tag, child_content))
if tbs_children[0][0] != 0xA0 or len(tbs_children) < 7:
    fail("unexpected tbsCertificate layout")
spki = tbs_children[6][1]
_, _, _, pos = read_tlv(spki, 0)  # algorithm identifier
tag, bit_string, _, pos = read_tlv(spki, pos)
if tag != 0x03 or pos != len(spki) or bit_string[0] != 0:
    fail("unexpected subjectPublicKey BIT STRING")
# RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
tag, key_content, _, _ = read_tlv(bit_string, 1)
if tag != 0x30:
    fail("unexpected RSAPublicKey structure")
tag, modulus, _, pos = read_tlv(key_content, 0)
tag2, exponent, _, pos2 = read_tlv(key_content, pos)
if tag != 0x02 or tag2 != 0x02 or pos2 != len(key_content):
    fail("unexpected RSAPublicKey structure")
n = int.from_bytes(modulus, "big")
e = int.from_bytes(exponent, "big")

DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_pkcs1v15_verifies(signature_bit_string):
    if signature_bit_string[0] != 0:
        fail("signature BIT STRING must have zero unused bits")
    signature = int.from_bytes(signature_bit_string[1:], "big")
    key_size = (n.bit_length() + 7) // 8
    em = pow(signature, e, n).to_bytes(key_size, "big")
    expected = (
        b"\x00\x01"
        + b"\xff" * (key_size - len(DIGEST_INFO_PREFIX) - 32 - 3)
        + b"\x00"
        + DIGEST_INFO_PREFIX
        + hashlib.sha256(tbs_tlv).digest()
    )
    return em == expected


if not rsa_pkcs1v15_verifies(valid[2][1]):
    fail("the original certificate's signature must verify")
if rsa_pkcs1v15_verifies(badsign[2][1]):
    fail("the tampered certificate's signature must NOT verify")
EOF
        then
            fail "the badsign fixture's invalid signature is not a genuine input property"
        fi
        ;;

    badsign_der_truncated)
        # Allowing an invalid signature must not blur the boundary with
        # corrupted data: a truncated, no longer parseable certificate is
        # still a content error (exit 1, empty stdout, invalid-certificate
        # diagnostic naming the path), never a successful read.
        size=$(wc -c <"$FIXTURES/badsign.der")
        head -c $((size / 2)) "$FIXTURES/badsign.der" >"$TMP/truncated.der"
        expect_invalid "$TMP/truncated.der"
        ;;

    # --- Elliptic-curve (P-256 / ECDSA-SHA256) certificate -----------
    # ec.* is a complete certificate with a P-256 subject public key,
    # signed by a DIFFERENT P-256 key with ECDSA and SHA-256; subject and
    # issuer are different names and the validity window is fixed. inspect
    # only reads X.509 information: it neither restricts the public key
    # type nor verifies any signature, so this certificate must display in
    # PEM and DER with exactly the same fields, order, UTC times, fingerprint
    # format and closing Note as every RSA sample. ec_badsign.* keeps the
    # identical tbsCertificate (same subject, issuer, validity, EC public
    # key and signature algorithm) but carries a well-formed ECDSA signature
    # that genuinely fails verification; it must still display, with the
    # fingerprint of its OWN complete DER.

    ec_pem)
        write_expected_ec PEM "$TMP/expected"
        expect_success "$FIXTURES/ec.pem" "$TMP/expected"
        assert_ec_structure "$TMP/expected"
        ;;

    ec_der)
        write_expected_ec DER "$TMP/expected"
        expect_success "$FIXTURES/ec.der" "$TMP/expected"
        assert_ec_structure "$TMP/expected"
        ;;

    ec_pem_der_same_fields)
        # The same EC certificate saved as PEM and as DER: the Encoding line
        # reports the real format, everything else agrees verbatim.
        "$BIN" inspect "$FIXTURES/ec.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/ec.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree outside the Encoding line"
        assert_ec_structure "$TMP/der.out"
        # Guard against weakening the fixture into a self-signed cert.
        pem_subject=$(sed -n 's/^Subject: //p' "$TMP/pem.out")
        pem_issuer=$(sed -n 's/^Issuer: //p' "$TMP/pem.out")
        [ "$pem_subject" != "$pem_issuer" ] ||
            fail "ec fixture must have different subject and issuer"
        ;;

    ec_badsign_pem)
        write_expected_ec_badsign PEM "$TMP/expected"
        expect_success "$FIXTURES/ec_badsign.pem" "$TMP/expected"
        assert_ec_structure "$TMP/expected"
        ;;

    ec_der_badsign)
        write_expected_ec_badsign DER "$TMP/expected"
        expect_success "$FIXTURES/ec_badsign.der" "$TMP/expected"
        assert_ec_structure "$TMP/expected"
        ;;

    ec_badsign_pem_der_same_fields)
        # The invalid-ECDSA certificate saved as PEM and as DER: the Encoding
        # line reports the real format, everything else (including the
        # fingerprint of the tampered bytes) agrees.
        "$BIN" inspect "$FIXTURES/ec_badsign.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/ec_badsign.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree outside the Encoding line"
        assert_ec_structure "$TMP/der.out"
        ;;

    ec_badsign_same_fields_as_ec)
        # The two EC certificates share subject, issuer, validity, public key
        # and signature algorithm: those rendered lines must be identical,
        # while the SHA-256 fingerprints differ because the signature is part
        # of the certificate bytes each fingerprint is computed over. The
        # tampered certificate must not reuse the original's fingerprint.
        "$BIN" inspect "$FIXTURES/ec.pem" >"$TMP/ec.out" 2>"$TMP/ec.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "ec.pem inspect failed with $rc"
        [ -s "$TMP/ec.err" ] &&
            fail "ec.pem stderr not empty: $(cat "$TMP/ec.err")"
        "$BIN" inspect "$FIXTURES/ec_badsign.pem" >"$TMP/badsign.out" 2>"$TMP/badsign.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "ec_badsign.pem inspect failed with $rc"
        [ -s "$TMP/badsign.err" ] &&
            fail "ec_badsign.pem stderr not empty: $(cat "$TMP/badsign.err")"
        sed -n '2,5p' "$TMP/ec.out" >"$TMP/ec.fields"
        sed -n '2,5p' "$TMP/badsign.out" >"$TMP/badsign.fields"
        cmp -s "$TMP/ec.fields" "$TMP/badsign.fields" ||
            fail "subject/issuer/validity lines must be identical for the two EC certificates"
        grep -qx "SHA-256 Fingerprint: $EC_FINGERPRINT" "$TMP/ec.out" ||
            fail "ec.pem must show the fingerprint of its own complete DER encoding"
        grep -qx "SHA-256 Fingerprint: $EC_BADSIGN_FINGERPRINT" "$TMP/badsign.out" ||
            fail "ec_badsign.pem must show the fingerprint of its own complete DER encoding"
        [ "$EC_FINGERPRINT" != "$EC_BADSIGN_FINGERPRINT" ] ||
            fail "the two EC certificates must have different SHA-256 fingerprints"
        grep -q "$EC_FINGERPRINT" "$TMP/badsign.out" &&
            fail "the tampered EC certificate must not reuse the original's fingerprint"
        grep -qF "$NOTE" "$TMP/ec.out" ||
            fail "ec.pem output must keep the no-trust-verification Note"
        grep -qF "$NOTE" "$TMP/badsign.out" ||
            fail "ec_badsign.pem output must keep the no-trust-verification Note"
        assert_ec_structure "$TMP/ec.out"
        assert_ec_structure "$TMP/badsign.out"
        ;;

    ec_signature_really_invalid)
        # The two signature states must be genuine cryptographic properties
        # of the fixture inputs -- not self-signedness, matching names or
        # expiry. Prove offline, with the Python standard library only (no
        # cryptography package, no network, no system trust store, no
        # dependence on the current date), that:
        #   * both certificates carry the SAME tbsCertificate bytes (same
        #     subject, issuer, validity, EC public key, signature algorithm)
        #     and differ only in the signatureValue;
        #   * both subject and issuer keys are P-256 EC keys (id-ecPublicKey
        #     + prime256v1), and they are DIFFERENT keys;
        #   * both signatures are well-formed canonical ECDSA values
        #     (SEQUENCE of two in-range INTEGERs);
        #   * ec.der's ECDSA signature verifies under the issuer key;
        #   * ec_badsign.der's signature does NOT verify under that key.
        if ! python3 - "$FIXTURES/ec.der" "$FIXTURES/ec_badsign.der" "$FIXTURES/ec_issuer_public.pem" <<'EOF'
import base64
import hashlib
import sys


def fail(message):
    print(f"fixture precondition failed: {message}", file=sys.stderr)
    sys.exit(1)


def read_tlv(data, pos):
    start = pos
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    return tag, data[pos:end], data[start:end], end


def parse_children(content):
    children = []
    pos = 0
    while pos < len(content):
        child = read_tlv(content, pos)
        children.append(child)
        pos = child[3]
    if pos != len(content):
        fail("a DER structure must end exactly at its declared length")
    return children


def parse_cert(path):
    with open(path, "rb") as handle:
        der = handle.read()
    tag, content, _, end = read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        fail(f"{path}: outer SEQUENCE must span the whole file")
    children = parse_children(content)
    if len(children) != 3:
        fail(f"{path}: a certificate must have exactly 3 top-level elements")
    return children, content


def read_pem_der(path):
    lines = []
    with open(path, "rb") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith(b"-----"):
                continue
            lines.append(line)
    return base64.b64decode(b"".join(lines))


# --- P-256 domain parameters (FIPS 186-4 / SEC 2) -------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (GX, GY)


def point_add(point1, point2):
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    x1, y1 = point1
    x2, y2 = point2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if point1 == point2:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mult(point, scalar):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def ecdsa_p256_verifies(point, tbs, signature_bytes):
    # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    tag, seq_content, _, end = read_tlv(signature_bytes, 0)
    if tag != 0x30 or end != len(signature_bytes):
        fail("signature must be one DER SEQUENCE spanning all its bytes")
    integers = parse_children(seq_content)
    if len(integers) != 2 or integers[0][0] != 0x02 or integers[1][0] != 0x02:
        fail("ECDSA signature must contain exactly two INTEGERs r and s")
    values = []
    for _, raw, tlv, _ in integers:
        if not raw:
            fail("ECDSA INTEGER must not be empty")
        # DER minimal encoding: a positive INTEGER whose high bit is set
        # needs exactly one leading 0x00 sign byte; any other leading zero
        # is non-minimal.
        if len(raw) > 1 and raw[0] == 0 and not (raw[1] & 0x80):
            fail("ECDSA INTEGER must be minimally encoded")
        value = int.from_bytes(raw, "big")
        if not 1 <= value < N:
            fail("ECDSA r and s must be in the range [1, n-1]")
        values.append(value)
    r, s = values
    z = int.from_bytes(hashlib.sha256(tbs).digest(), "big")
    w = pow(s, N - 2, N)
    u1 = z * w % N
    u2 = r * w % N
    point1 = scalar_mult(G, u1)
    point2 = scalar_mult(point, u2)
    x_y = point_add(point1, point2)
    if x_y is None:
        return False
    return x_y[0] % N == r


def parse_spki_point(spki_der, where):
    tag, content, _, end = read_tlv(spki_der, 0)
    if tag != 0x30 or end != len(spki_der):
        fail(f"{where}: SubjectPublicKeyInfo must be one whole SEQUENCE")
    children = parse_children(content)
    if len(children) != 2 or children[1][0] != 0x03:
        fail(f"{where}: unexpected SubjectPublicKeyInfo layout")
    # AlgorithmIdentifier for an EC P-256 key is exactly
    # SEQUENCE { OID id-ecPublicKey (1.2.840.10045.2.1),
    #            OID prime256v1  (1.2.840.10045.3.1.7) }.
    EC_ALGORITHM = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    if children[0][2] != EC_ALGORITHM:
        fail(f"{where}: key must be id-ecPublicKey with prime256v1 (P-256)")
    bit_content = children[1][1]
    if bit_content[0] != 0 or len(bit_content) != 66 or bit_content[1] != 0x04:
        fail(f"{where}: EC point must be a 65-byte uncompressed point")
    x = int.from_bytes(bit_content[2:34], "big")
    y = int.from_bytes(bit_content[34:66], "big")
    if not (0 < x < P and 0 < y < P):
        fail(f"{where}: EC point coordinates out of range")
    return x, y, bit_content[1:]


ec_children, ec_outer = parse_cert(sys.argv[1])
bad_children, bad_outer = parse_cert(sys.argv[2])

# tbsCertificate (index 0) and signatureAlgorithm (index 1) must be
# byte-identical; only the signatureValue BIT STRING (index 2) may differ.
if ec_children[0][2] != bad_children[0][2]:
    fail("the two EC certificates must share the same tbsCertificate bytes")
if ec_children[1][2] != bad_children[1][2]:
    fail("the two EC certificates must use the same signature algorithm")
if ec_children[2][1] == bad_children[2][1]:
    fail("the signature content must differ between the two EC certificates")

# ecdsa-with-SHA256 (1.2.840.10045.4.3.2) is the declared algorithm.
ECDSA_SHA256_OID = bytes.fromhex("06082a8648ce3d040302")
if ECDSA_SHA256_OID not in ec_children[1][1]:
    fail("EC fixtures must be signed with ecdsa-with-SHA256")

# SubjectPublicKeyInfo is the seventh tbsCertificate element.
tbs_children = parse_children(ec_children[0][1])
if tbs_children[0][0] != 0xA0 or len(tbs_children) < 7:
    fail("unexpected tbsCertificate layout")
leaf_der = tbs_children[6][2]
leaf_x, leaf_y, leaf_point = parse_spki_point(leaf_der, sys.argv[1])

# The issuer public key comes from its own committed SPKI sample (the names
# differ, so nothing in the leaf certificate could supply the issuer key).
issuer_der = read_pem_der(sys.argv[3])
issuer_x, issuer_y, issuer_point = parse_spki_point(issuer_der, sys.argv[3])
if issuer_point == leaf_point:
    fail("the leaf must be signed by a DIFFERENT EC key, not its own key")

tbs_tlv = ec_children[0][2]
if not ecdsa_p256_verifies((issuer_x, issuer_y), tbs_tlv,
                           ec_children[2][1][1:]):
    fail("the original EC certificate's signature must verify")
if ecdsa_p256_verifies((issuer_x, issuer_y), tbs_tlv,
                       bad_children[2][1][1:]):
    fail("the tampered EC certificate's signature must NOT verify")
EOF
        then
            fail "the ec_badsign fixture's invalid signature is not a genuine input property"
        fi
        ;;

    ec_badsign_der_truncated)
        # Signature-invalid vs format-corrupt must stay distinct for EC too:
        # a truncated EC certificate (here the already-signature-invalid one)
        # is no longer a complete X.509 object -- exit 1, empty stdout,
        # invalid-certificate diagnostic naming the path, never displayed as
        # an "invalid signature" certificate.
        size=$(wc -c <"$FIXTURES/ec_badsign.der")
        head -c $((size / 2)) "$FIXTURES/ec_badsign.der" >"$TMP/truncated.der"
        expect_invalid "$TMP/truncated.der"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a truncated EC certificate is bad content, not a read failure"
        ;;

    ec_badsign_pem_truncated)
        # Same boundary in PEM: cutting the one CERTIFICATE block short leaves
        # no complete certificate, so it must be a content error rather than a
        # displayable signature-invalid EC certificate.
        size=$(wc -c <"$FIXTURES/ec_badsign.pem")
        # Keep the BEGIN marker and part of the body but drop the end of the
        # base64 body and the END marker: no complete block can decode.
        head -c $((size / 2)) "$FIXTURES/ec_badsign.pem" >"$TMP/truncated.pem"
        expect_invalid "$TMP/truncated.pem"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a truncated EC PEM is bad content, not a read failure"
        ;;

    # --- EC certificate whose signature is not interpretable as ECDSA ---
    # ec_badstructure.* shares the byte-identical tbsCertificate with ec.*
    # (subject, issuer, validity, P-256 public key, signature algorithm) and
    # keeps the complete, readable X.509 outer layer: the signatureValue BIT
    # STRING is intact and consistent with zero unused bits and no trailing
    # bytes, but its CONTENT can no longer be read as an ECDSA signature --
    # the inner SEQUENCE is missing one of its two required INTEGERs. This is
    # the immediate neighbour of ec_badsign (a well-formed but wrong ECDSA
    # signature): inspect neither verifies nor decodes the signature, so this
    # certificate must still display in PEM and DER with exit 0 and an empty
    # stderr, exactly the same information, the no-trust Note and the
    # fingerprint of its own complete DER. It is NOT a truncated certificate:
    # the precise outer-truncation rejection is pinned by the *_truncated
    # cases immediately below.

    ec_badstructure_pem)
        write_expected_ec_badstructure PEM "$TMP/expected"
        expect_success "$FIXTURES/ec_badstructure.pem" "$TMP/expected"
        assert_ec_structure "$TMP/expected"
        ;;

    ec_badstructure_der)
        write_expected_ec_badstructure DER "$TMP/expected"
        expect_success "$FIXTURES/ec_badstructure.der" "$TMP/expected"
        assert_ec_structure "$TMP/expected"
        ;;

    ec_badstructure_pem_der_same_fields)
        # The same structurally-non-ECDSA certificate saved as PEM and DER:
        # the Encoding line reports the real format and everything else,
        # including the fingerprint computed over these exact DER bytes,
        # agrees verbatim.
        "$BIN" inspect "$FIXTURES/ec_badstructure.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/ec_badstructure.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree outside the Encoding line"
        assert_ec_structure "$TMP/der.out"
        ;;

    ec_badstructure_same_fields_as_ec)
        # The readable-but-not-ECDSA certificate must render subject, issuer
        # and both UTC times byte-for-byte identically to the normal ec
        # certificate; only the signature (hence the fingerprint) differs.
        # The fingerprint must be that of THIS complete DER, must differ from
        # ec's, and the output must keep the no-verification Note without any
        # trust conclusion.
        "$BIN" inspect "$FIXTURES/ec.pem" >"$TMP/ec.out" 2>"$TMP/ec.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "ec.pem inspect failed with $rc"
        [ -s "$TMP/ec.err" ] &&
            fail "ec.pem stderr not empty: $(cat "$TMP/ec.err")"
        "$BIN" inspect "$FIXTURES/ec_badstructure.pem" >"$TMP/bad.out" 2>"$TMP/bad.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "ec_badstructure.pem inspect failed with $rc"
        [ -s "$TMP/bad.err" ] &&
            fail "ec_badstructure.pem stderr not empty: $(cat "$TMP/bad.err")"
        sed -n '2,5p' "$TMP/ec.out" >"$TMP/ec.fields"
        sed -n '2,5p' "$TMP/bad.out" >"$TMP/bad.fields"
        cmp -s "$TMP/ec.fields" "$TMP/bad.fields" ||
            fail "subject/issuer/validity lines must be identical to the normal certificate"
        grep -qx "SHA-256 Fingerprint: $EC_FINGERPRINT" "$TMP/ec.out" ||
            fail "ec.pem must show the fingerprint of its own complete DER encoding"
        grep -qx "SHA-256 Fingerprint: $EC_BADSTRUCTURE_FINGERPRINT" "$TMP/bad.out" ||
            fail "ec_badstructure.pem must show the fingerprint of its own complete DER encoding"
        [ "$EC_FINGERPRINT" != "$EC_BADSTRUCTURE_FINGERPRINT" ] ||
            fail "the two EC certificates must have different SHA-256 fingerprints"
        grep -q "$EC_FINGERPRINT" "$TMP/bad.out" &&
            fail "the structurally-non-ECDSA certificate must not reuse the original's fingerprint"
        grep -qF "$NOTE" "$TMP/bad.out" ||
            fail "ec_badstructure.pem output must keep the no-trust-verification Note"
        if grep -iqE 'trusted|signature (is )?(valid|verified)' "$TMP/bad.out"; then
            fail "the output must not add a trust conclusion for an unreadable signature"
        fi
        assert_ec_structure "$TMP/bad.out"
        ;;

    ec_badstructure_signature_not_ecdsa)
        # The displayed certificate's oddity must be a genuine property of
        # the input, proven offline with the Python standard library only (no
        # cryptography package, no network, no system trust store, no current
        # date):
        #   * ec.der and ec_badstructure.der share the SAME tbsCertificate
        #     bytes and signature algorithm; both subject and issuer keys are
        #     P-256 and DIFFERENT, and the declared algorithm is
        #     ecdsa-with-SHA256;
        #   * ec.der's signature is a canonical SEQUENCE of two in-range
        #     INTEGERs and really verifies under the independent issuer key;
        #   * ec_badstructure.der is still a complete outer certificate: the
        #     committed PEM body decodes to exactly the DER fixture (no
        #     truncation, no trailing bytes), and the signatureValue BIT
        #     STRING itself is whole and consistent (zero unused bits);
        #   * inside that intact BIT STRING the ECDSA SEQUENCE holds exactly
        #     ONE INTEGER (a valid r) and is missing the required second
        #     INTEGER s, so the content cannot be interpreted as an ECDSA
        #     signature at all -- distinct from a well-formed ECDSA value
        #     that merely fails the math and from a truncated certificate.
        if ! python3 - "$FIXTURES/ec.der" "$FIXTURES/ec_badstructure.der" \
                    "$FIXTURES/ec_issuer_public.pem" "$FIXTURES/ec_badstructure.pem" <<'EOF'
import base64
import hashlib
import sys


def fail(message):
    print(f"fixture precondition failed: {message}", file=sys.stderr)
    sys.exit(1)


def read_tlv(data, pos):
    start = pos
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    return tag, data[pos:end], data[start:end], end


def parse_children(content):
    children = []
    pos = 0
    while pos < len(content):
        child = read_tlv(content, pos)
        children.append(child)
        pos = child[3]
    if pos != len(content):
        fail("a DER structure must end exactly at its declared length")
    return children


def parse_cert(path):
    with open(path, "rb") as handle:
        der = handle.read()
    tag, content, _, end = read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        fail(f"{path}: outer SEQUENCE must span the whole file with no trailing bytes")
    return parse_children(content), der, content


def read_pem_body(path, marker):
    lines = []
    in_block = False
    begin = f"-----BEGIN {marker}-----".encode()
    end = f"-----END {marker}-----".encode()
    with open(path, "rb") as handle:
        for raw in handle:
            line = raw.strip()
            if line == begin:
                in_block = True
                continue
            if line == end:
                in_block = False
                continue
            if in_block and line:
                lines.append(line)
    return base64.b64decode(b"".join(lines))


# --- P-256 domain parameters (FIPS 186-4 / SEC 2) -------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (GX, GY)


def point_add(point1, point2):
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    x1, y1 = point1
    x2, y2 = point2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if point1 == point2:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mult(point, scalar):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def ecdsa_p256_verifies(point, tbs, signature_bytes):
    tag, seq_content, _, end = read_tlv(signature_bytes, 0)
    if tag != 0x30 or end != len(signature_bytes):
        fail("the normal certificate's signature must be one whole DER SEQUENCE")
    integers = parse_children(seq_content)
    if len(integers) != 2 or integers[0][0] != 0x02 or integers[1][0] != 0x02:
        fail("the normal certificate's ECDSA signature must contain two INTEGERs")
    values = []
    for _, raw, _, _ in integers:
        if not raw:
            fail("ECDSA INTEGER must not be empty")
        if len(raw) > 1 and raw[0] == 0 and not (raw[1] & 0x80):
            fail("ECDSA INTEGER must be minimally encoded")
        value = int.from_bytes(raw, "big")
        if not 1 <= value < N:
            fail("ECDSA r and s must be in the range [1, n-1]")
        values.append(value)
    r, s = values
    z = int.from_bytes(hashlib.sha256(tbs).digest(), "big")
    w = pow(s, N - 2, N)
    u1 = z * w % N
    u2 = r * w % N
    x_y = point_add(scalar_mult(G, u1), scalar_mult(point, u2))
    return x_y is not None and x_y[0] % N == r


def parse_spki_point(spki_der, where):
    tag, content, _, end = read_tlv(spki_der, 0)
    if tag != 0x30 or end != len(spki_der):
        fail(f"{where}: SubjectPublicKeyInfo must be one whole SEQUENCE")
    children = parse_children(content)
    if len(children) != 2 or children[1][0] != 0x03:
        fail(f"{where}: unexpected SubjectPublicKeyInfo layout")
    EC_ALGORITHM = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    if children[0][2] != EC_ALGORITHM:
        fail(f"{where}: key must be id-ecPublicKey with prime256v1 (P-256)")
    bit_content = children[1][1]
    if bit_content[0] != 0 or len(bit_content) != 66 or bit_content[1] != 0x04:
        fail(f"{where}: EC point must be a 65-byte uncompressed point")
    x = int.from_bytes(bit_content[2:34], "big")
    y = int.from_bytes(bit_content[34:66], "big")
    if not (0 < x < P and 0 < y < P):
        fail(f"{where}: EC point coordinates out of range")
    return x, y, bit_content[1:]


ec_children, ec_der, ec_content = parse_cert(sys.argv[1])
bad_children, bad_der, bad_content = parse_cert(sys.argv[2])

# The two certificates differ ONLY in the signatureValue: tbsCertificate and
# signatureAlgorithm are byte-identical, both declare ecdsa-with-SHA256.
if ec_children[0][2] != bad_children[0][2]:
    fail("the two certificates must share the same tbsCertificate bytes")
if ec_children[1][2] != bad_children[1][2]:
    fail("the two certificates must use the same signature algorithm")
if ec_children[2][1] == bad_children[2][1]:
    fail("the signature content must differ between the two certificates")
ECDSA_SHA256_OID = bytes.fromhex("06082a8648ce3d040302")
if ECDSA_SHA256_OID not in ec_children[1][1]:
    fail("the EC fixtures must be signed with ecdsa-with-SHA256")

# The committed PEM must decode to exactly the complete DER fixture: a whole
# certificate, not a truncated block and not DER plus trailing content.
pem_der = read_pem_body(sys.argv[4], "CERTIFICATE")
if pem_der != bad_der:
    fail("the ec_badstructure PEM body must decode to exactly the DER fixture")

# The normal certificate's ECDSA signature is canonical and really verifies.
tbs_children = parse_children(ec_children[0][1])
leaf_der = tbs_children[6][2]
leaf_x, leaf_y, leaf_point = parse_spki_point(leaf_der, sys.argv[1])
issuer_der = read_pem_body(sys.argv[3], "PUBLIC KEY")
issuer_x, issuer_y, issuer_point = parse_spki_point(issuer_der, sys.argv[3])
if issuer_point == leaf_point:
    fail("the leaf must be signed by a DIFFERENT EC key, not its own key")
tbs_tlv = ec_children[0][2]
if not ecdsa_p256_verifies((issuer_x, issuer_y), tbs_tlv,
                           ec_children[2][1][1:]):
    fail("the normal EC certificate's signature must verify")

# The damaged certificate's BIT STRING is itself complete and readable:
# it is the last of exactly three top-level elements, runs exactly to the
# outer SEQUENCE boundary (nothing is cut off at the file layer), has zero
# unused bits, and its payload is one SEQUENCE TLV that itself ends exactly
# on the BIT STRING boundary.
if len(bad_children) != 3:
    fail("a certificate must still have exactly three top-level elements")
bs_tag, bs_content, bs_tlv, bs_end = bad_children[2]
if bs_tag != 0x03:
    fail("the signature must be carried by a BIT STRING")
if bs_end != len(bad_content):
    fail("the signature BIT STRING must be complete and reach the outer SEQUENCE end")
if bs_content[0] != 0:
    fail("the signature BIT STRING must declare zero unused bits")
inner_tag, inner_content, _, inner_end = read_tlv(bs_content, 1)
if inner_tag != 0x30 or inner_end != len(bs_content):
    fail("the BIT STRING must contain exactly one complete inner SEQUENCE")
inner_integers = parse_children(inner_content)
if len(inner_integers) != 1 or inner_integers[0][0] != 0x02:
    fail("the fixture must contain exactly one INTEGER so the missing-ECDSA-INTEGER boundary is pinned")
r = int.from_bytes(inner_integers[0][1], "big")
if not 1 <= r < N:
    fail("the surviving INTEGER must be a valid r; only s is missing")

# A normal ECDSA signature at the neighbour boundary still has two INTEGERs.
normal_integers = parse_children(
    read_tlv(ec_children[2][1], 1)[1])
if len(normal_integers) != 2:
    fail("test setup: the normal EC signature must contain two INTEGERs")
EOF
        then
            fail "the ec_badstructure fixture's missing-ECDSA-INTEGER property is not genuine"
        fi
        ;;

    ec_badstructure_der_truncated)
        # The adjacent rejection boundary for an incomplete certificate FILE:
        # drop trailing bytes so the signatureValue BIT STRING's declared
        # length overruns the actual content (the outer SEQUENCE is cut off
        # too). The file reads fine, but it is malformed certificate content:
        # exit 1, empty stdout, "invalid certificate" naming the path, never
        # a read failure and never a displayable certificate.
        size=$(wc -c <"$FIXTURES/ec_badstructure.der")
        [ "$size" -gt 20 ] || fail "test setup: truncated fixture unexpectedly small"
        head -c $((size - 10)) "$FIXTURES/ec_badstructure.der" >"$TMP/truncated.der"
        # Guard the construction: the cut must land INSIDE the signature BIT
        # STRING (the final top-level element), not somewhere earlier.
        cut_size=$(wc -c <"$TMP/truncated.der")
        [ "$cut_size" -lt "$size" ] || fail "test setup: truncation produced no change"
        assert_signature_bitstring_overruns "$TMP/truncated.der"
        expect_invalid "$TMP/truncated.der"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a certificate whose signature BIT STRING overruns the file is bad content, not a read failure"
        ;;

    ec_badstructure_pem_truncated)
        # Same precise boundary through PEM: the one CERTIFICATE block and
        # its base64 text are complete and decode without error, but the
        # decoded certificate is the outer-truncated one whose signature BIT
        # STRING declared length exceeds the actual bytes. Cutting the PEM
        # text itself would be a different (encoding) failure and must not be
        # used as a stand-in.
        size=$(wc -c <"$FIXTURES/ec_badstructure.der")
        head -c $((size - 10)) "$FIXTURES/ec_badstructure.der" >"$TMP/truncated.der"
        assert_signature_bitstring_overruns "$TMP/truncated.der"
        {
            printf '%s\n' '-----BEGIN CERTIFICATE-----'
            base64 "$TMP/truncated.der"
            printf '%s\n' '-----END CERTIFICATE-----'
        } >"$TMP/truncated.pem"
        # The block itself must decode completely; only the decoded content
        # is invalid, so this is not an undecodable-PEM stand-in.
        sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p' \
            "$TMP/truncated.pem" | sed '1d;$d' | base64 -d >"$TMP/redumped.der"
        cmp -s "$TMP/redumped.der" "$TMP/truncated.der" ||
            fail "test setup: truncated PEM body must decode to exactly the truncated DER"
        expect_invalid "$TMP/truncated.pem"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a PEM carrying an outer-truncated certificate is bad content, not a read failure"
        ;;

    der_marker_in_name)
        # The subject name carries the PEM begin/end markers as ordinary
        # attribute text. The file is still DER and must display normally.
        write_expected_marker DER "$TMP/expected"
        expect_success "$FIXTURES/marker.der" "$TMP/expected"
        ;;

    pem_marker_in_name)
        # The same certificate saved as PEM: reported as PEM, and every
        # field except the Encoding line matches the DER run.
        write_expected_marker PEM "$TMP/expected"
        expect_success "$FIXTURES/marker.pem" "$TMP/expected"
        "$BIN" inspect "$FIXTURES/marker.der" >"$TMP/der.out" 2>/dev/null ||
            fail "DER input failed"
        tail -n +2 "$TMP/expected" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on subject/issuer/validity/fingerprint"
        ;;

    der_marker_trailing_newline)
        # A trailing newline still invalidates the DER file; the marker text
        # inside the certificate must not turn it into acceptable "PEM".
        { cat "$FIXTURES/marker.der"; printf '\n'; } >"$TMP/trailing.der"
        expect_invalid "$TMP/trailing.der"
        ;;

    der_marker_trailing_pem_block)
        # A DER certificate followed by a PEM block of the same certificate
        # is neither a whole-file DER nor a single PEM block: reject.
        cat "$FIXTURES/marker.der" "$FIXTURES/marker.pem" >"$TMP/mixed.bin"
        expect_invalid "$TMP/mixed.bin"
        ;;

    pem_marker_second_block)
        # The single-certificate limit still applies to the marker cert.
        cat "$FIXTURES/marker.pem" "$FIXTURES/marker.pem" >"$TMP/two.pem"
        expect_invalid "$TMP/two.pem"
        ;;

    der_complex_names)
        # DER form of the non-self-signed certificate with complex subject
        # and issuer: full output, exit 0, empty stderr.
        write_expected_names DER "$TMP/expected"
        expect_success "$FIXTURES/names.der" "$TMP/expected"
        assert_names_structure "$TMP/expected"
        ;;

    pem_complex_names)
        # The same certificate as PEM: reported as PEM while the Subject and
        # Issuer lines stay byte-for-byte identical to the DER rendering.
        write_expected_names PEM "$TMP/expected"
        expect_success "$FIXTURES/names.pem" "$TMP/expected"
        assert_names_structure "$TMP/expected"
        ;;

    pem_der_complex_names_same)
        # PEM vs DER of one certificate: Encoding reports the real format,
        # everything else (both complex names included) must agree verbatim.
        "$BIN" inspect "$FIXTURES/names.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/names.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on the complex name fields"
        assert_names_structure "$TMP/der.out"
        # Guard against weakening the fixture into another self-signed cert.
        pem_subject=$(sed -n 's/^Subject: //p' "$TMP/pem.out")
        pem_issuer=$(sed -n 's/^Issuer: //p' "$TMP/pem.out")
        [ "$pem_subject" != "$pem_issuer" ] ||
            fail "names fixture must have different subject and issuer"
        ;;

    der_long_oids)
        # DER form with unknown OIDs of exactly 79, exactly 80 and 87 dotted
        # characters (the longer two sharing the 79-char prefix): each must
        # render in full with its own value; exit 0, empty stderr.
        write_expected_longoid DER "$TMP/expected"
        expect_success "$FIXTURES/longoid.der" "$TMP/expected"
        assert_longoid_structure "$TMP/expected"
        ;;

    pem_long_oids)
        # The same certificate as PEM: byte-for-byte identical Subject and
        # Issuer lines to the DER rendering, long OIDs unclipped.
        write_expected_longoid PEM "$TMP/expected"
        expect_success "$FIXTURES/longoid.pem" "$TMP/expected"
        assert_longoid_structure "$TMP/expected"
        ;;

    pem_der_long_oids_same)
        # PEM vs DER of one certificate: Encoding reports the real format;
        # everything else, including every complete long dotted OID, agrees.
        "$BIN" inspect "$FIXTURES/longoid.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/longoid.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on the long-OID name fields"
        assert_longoid_structure "$TMP/der.out"
        pem_subject=$(sed -n 's/^Subject: //p' "$TMP/pem.out")
        pem_issuer=$(sed -n 's/^Issuer: //p' "$TMP/pem.out")
        [ "$pem_subject" != "$pem_issuer" ] ||
            fail "longoid fixture must have different subject and issuer"
        ;;

    der_control_chars)
        # DER form of the certificate whose subject and issuer carry real
        # control characters (LF/CR/TAB/NUL and other sub-0x20 bytes): each
        # renders as "\" plus two uppercase hex digits, so both names stay
        # on their own single lines; exit 0, empty stderr.
        write_expected_ctrlchars DER "$TMP/expected"
        expect_success "$FIXTURES/ctrlchars.der" "$TMP/expected"
        assert_ctrlchars_structure "$TMP/expected"
        ;;

    pem_control_chars)
        # The same certificate as PEM: reported as PEM while the Subject and
        # Issuer lines stay byte-for-byte identical to the DER rendering.
        write_expected_ctrlchars PEM "$TMP/expected"
        expect_success "$FIXTURES/ctrlchars.pem" "$TMP/expected"
        assert_ctrlchars_structure "$TMP/expected"
        ;;

    pem_der_control_chars_same)
        # PEM vs DER of one certificate: Encoding reports the real format,
        # everything else (both control-character names included) agrees.
        "$BIN" inspect "$FIXTURES/ctrlchars.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/ctrlchars.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on the control-character name fields"
        assert_ctrlchars_structure "$TMP/der.out"
        # Guard against weakening the fixture into another self-signed cert.
        pem_subject=$(sed -n 's/^Subject: //p' "$TMP/pem.out")
        pem_issuer=$(sed -n 's/^Issuer: //p' "$TMP/pem.out")
        [ "$pem_subject" != "$pem_issuer" ] ||
            fail "ctrlchars fixture must have different subject and issuer"
        ;;

    # --- UTF8String/BMPString/UniversalString name encodings ---------

    der_names_enc_utf8)
        # Reference encoding: the shared name text as UTF8String.
        write_expected_nameenc DER "$TMP/expected" "$NAMEENC_SAME" "$NAMEENC_SAME" \
            '2024-03-01T00:00:00Z' '2044-03-01T00:00:00Z' "$NAMESENC_UTF8_FINGERPRINT"
        expect_success "$FIXTURES/namesenc_utf8.der" "$TMP/expected"
        assert_nameenc_same_structure "$TMP/expected"
        ;;

    pem_names_enc_utf8)
        write_expected_nameenc PEM "$TMP/expected" "$NAMEENC_SAME" "$NAMEENC_SAME" \
            '2024-03-01T00:00:00Z' '2044-03-01T00:00:00Z' "$NAMESENC_UTF8_FINGERPRINT"
        expect_success "$FIXTURES/namesenc_utf8.pem" "$TMP/expected"
        assert_nameenc_same_structure "$TMP/expected"
        ;;

    der_names_enc_bmp)
        # The same text as BMPString must convert to the identical UTF-8;
        # its 16-bit code units' zero bytes must not truncate the value.
        write_expected_nameenc DER "$TMP/expected" "$NAMEENC_SAME" "$NAMEENC_SAME" \
            '2024-03-01T00:00:00Z' '2044-03-01T00:00:00Z' "$NAMESENC_BMP_FINGERPRINT"
        expect_success "$FIXTURES/namesenc_bmp.der" "$TMP/expected"
        assert_nameenc_same_structure "$TMP/expected"
        ;;

    pem_names_enc_bmp)
        write_expected_nameenc PEM "$TMP/expected" "$NAMEENC_SAME" "$NAMEENC_SAME" \
            '2024-03-01T00:00:00Z' '2044-03-01T00:00:00Z' "$NAMESENC_BMP_FINGERPRINT"
        expect_success "$FIXTURES/namesenc_bmp.pem" "$TMP/expected"
        assert_nameenc_same_structure "$TMP/expected"
        ;;

    der_names_enc_universal)
        # The same text as UniversalString converts to the identical UTF-8;
        # its 32-bit code units' zero bytes must not truncate the value.
        write_expected_nameenc DER "$TMP/expected" "$NAMEENC_SAME" "$NAMEENC_SAME" \
            '2024-03-01T00:00:00Z' '2044-03-01T00:00:00Z' "$NAMESENC_UNIVERSAL_FINGERPRINT"
        expect_success "$FIXTURES/namesenc_universal.der" "$TMP/expected"
        assert_nameenc_same_structure "$TMP/expected"
        ;;

    pem_names_enc_universal)
        write_expected_nameenc PEM "$TMP/expected" "$NAMEENC_SAME" "$NAMEENC_SAME" \
            '2024-03-01T00:00:00Z' '2044-03-01T00:00:00Z' "$NAMESENC_UNIVERSAL_FINGERPRINT"
        expect_success "$FIXTURES/namesenc_universal.pem" "$TMP/expected"
        assert_nameenc_same_structure "$TMP/expected"
        ;;

    names_enc_three_agree)
        # The three encodings express the same name text: in BOTH Subject and
        # Issuer the converted attribute values must agree verbatim across
        # UTF8String, BMPString and UniversalString (checked in PEM and DER).
        for stem in namesenc_utf8 namesenc_bmp namesenc_universal; do
            for ext in pem der; do
                "$BIN" inspect "$FIXTURES/$stem.$ext" >"$TMP/$stem.$ext.out" 2>"$TMP/$stem.$ext.err"
                rc=$?
                [ "$rc" -eq 0 ] || fail "$stem.$ext inspect failed with $rc"
                [ -s "$TMP/$stem.$ext.err" ] &&
                    fail "$stem.$ext stderr not empty: $(cat "$TMP/$stem.$ext.err")"
                sed -n 's/^Subject: //p' "$TMP/$stem.$ext.out" >"$TMP/$stem.$ext.subject"
                sed -n 's/^Issuer: //p' "$TMP/$stem.$ext.out" >"$TMP/$stem.$ext.issuer"
            done
        done
        for field in subject issuer; do
            for ext in pem der; do
                cmp -s "$TMP/namesenc_utf8.$ext.$field" "$TMP/namesenc_bmp.$ext.$field" ||
                    fail "UTF8String and BMPString $field text differs ($ext)"
                cmp -s "$TMP/namesenc_utf8.$ext.$field" "$TMP/namesenc_universal.$ext.$field" ||
                    fail "UTF8String and UniversalString $field text differs ($ext)"
            done
        done
        ;;

    der_nameenc_cross)
        # BMPString subject vs UTF8String issuer, different text: each value
        # stays on its own line.
        write_expected_nameenc DER "$TMP/expected" \
            "$NAMEENC_CROSS_SUBJECT" "$NAMEENC_CROSS_ISSUER" \
            '2024-04-01T00:00:00Z' '2044-04-01T00:00:00Z' "$NAMEENC_CROSS_FINGERPRINT"
        expect_success "$FIXTURES/nameenc_cross.der" "$TMP/expected"
        assert_nameenc_cross_structure "$TMP/expected"
        ;;

    pem_nameenc_cross)
        write_expected_nameenc PEM "$TMP/expected" \
            "$NAMEENC_CROSS_SUBJECT" "$NAMEENC_CROSS_ISSUER" \
            '2024-04-01T00:00:00Z' '2044-04-01T00:00:00Z' "$NAMEENC_CROSS_FINGERPRINT"
        expect_success "$FIXTURES/nameenc_cross.pem" "$TMP/expected"
        assert_nameenc_cross_structure "$TMP/expected"
        ;;

    pem_der_nameenc_cross_same)
        # PEM and DER of the cross-encoding certificate agree in every field
        # except Encoding.
        "$BIN" inspect "$FIXTURES/nameenc_cross.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/nameenc_cross.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' || fail "PEM not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' || fail "DER not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree outside the Encoding line"
        assert_nameenc_cross_structure "$TMP/der.out"
        ;;

    der_nameenc_nul)
        # A real NUL in BMPString values renders as visible \00 with the text
        # after it kept; the encoding's structural zero bytes do not.
        write_expected_nameenc DER "$TMP/expected" \
            "$NAMEENC_NUL_SUBJECT" "$NAMEENC_NUL_ISSUER" \
            '2024-05-01T00:00:00Z' '2044-05-01T00:00:00Z' "$NAMEENC_NUL_FINGERPRINT"
        expect_success "$FIXTURES/nameenc_nul.der" "$TMP/expected"
        assert_nameenc_nul_structure "$TMP/expected"
        ;;

    pem_nameenc_nul)
        # The issuer NULs live in UniversalString values here.
        write_expected_nameenc PEM "$TMP/expected" \
            "$NAMEENC_NUL_SUBJECT" "$NAMEENC_NUL_ISSUER" \
            '2024-05-01T00:00:00Z' '2044-05-01T00:00:00Z' "$NAMEENC_NUL_FINGERPRINT"
        expect_success "$FIXTURES/nameenc_nul.pem" "$TMP/expected"
        assert_nameenc_nul_structure "$TMP/expected"
        ;;

    pem_der_nameenc_nul_same)
        "$BIN" inspect "$FIXTURES/nameenc_nul.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/nameenc_nul.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' || fail "PEM not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' || fail "DER not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree outside the Encoding line"
        assert_nameenc_nul_structure "$TMP/der.out"
        ;;

    der_nameenc_supplementary)
        # A supplementary-plane character in UTF8String (subject) and
        # UniversalString (issuer) is shown whole from both encodings.
        write_expected_nameenc DER "$TMP/expected" \
            "$NAMEENC_SUP_NAME" "$NAMEENC_SUP_NAME" \
            '2024-06-01T00:00:00Z' '2044-06-01T00:00:00Z' "$NAMEENC_SUP_FINGERPRINT"
        expect_success "$FIXTURES/nameenc_supplementary.der" "$TMP/expected"
        assert_nameenc_sup_structure "$TMP/expected"
        ;;

    pem_nameenc_supplementary)
        write_expected_nameenc PEM "$TMP/expected" \
            "$NAMEENC_SUP_NAME" "$NAMEENC_SUP_NAME" \
            '2024-06-01T00:00:00Z' '2044-06-01T00:00:00Z' "$NAMEENC_SUP_FINGERPRINT"
        expect_success "$FIXTURES/nameenc_supplementary.pem" "$TMP/expected"
        assert_nameenc_sup_structure "$TMP/expected"
        ;;

    pem_der_nameenc_supplementary_same)
        "$BIN" inspect "$FIXTURES/nameenc_supplementary.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/nameenc_supplementary.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' || fail "PEM not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' || fail "DER not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree outside the Encoding line"
        assert_nameenc_sup_structure "$TMP/der.out"
        ;;

    namebad_bmp_der)
        # A BMPString value with an odd content length is malformed name
        # content inside a complete certificate: exit 1, invalid-certificate
        # diagnostic naming the path, empty stdout (never a read failure).
        expect_invalid "$FIXTURES/namebad_bmp.der"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a malformed BMPString is bad certificate content, not a read failure"
        ;;

    namebad_bmp_pem)
        # Same content served as PEM must be classified identically.
        expect_invalid "$FIXTURES/namebad_bmp.pem"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a malformed BMPString is bad certificate content, not a read failure"
        ;;

    namebad_universal_der)
        # A UniversalString value whose length is not a multiple of four is
        # malformed name content inside a complete certificate.
        expect_invalid "$FIXTURES/namebad_universal.der"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a malformed UniversalString is bad certificate content, not a read failure"
        ;;

    namebad_universal_pem)
        expect_invalid "$FIXTURES/namebad_universal.pem"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a malformed UniversalString is bad certificate content, not a read failure"
        ;;

    # --- Validity-time rendering -------------------------------------

    time_century_utc_der)
        # Both fields are UTCTime 2-digit years: YY=50 must be 1950 and the
        # valid leap day 1952-02-29 keeps its hours/minutes/seconds. The
        # certificate is long expired yet still displays with exit 0.
        write_expected_century DER "$TMP/expected"
        expect_success "$FIXTURES/century.der" "$TMP/expected"
        assert_time_structure "$TMP/expected" \
            '1950-01-01T00:00:00Z' '1952-02-29T23:59:59Z'
        ;;

    time_century_utc_pem)
        # Same certificate as PEM: reported PEM, every other field identical.
        write_expected_century PEM "$TMP/expected"
        expect_success "$FIXTURES/century.pem" "$TMP/expected"
        assert_time_structure "$TMP/expected" \
            '1950-01-01T00:00:00Z' '1952-02-29T23:59:59Z'
        ;;

    time_pivot_49_and_50)
        # The RFC 5280 century pivot sits between 49 and 50. Across the two
        # fixtures both boundary years appear as UTCTime: 49 -> 2049 (in
        # mixedyears) and 50 -> 1950 (in century); pin each line so a reader
        # using a wrong pivot (e.g. 1970) fails.
        "$BIN" inspect "$FIXTURES/mixedyears.der" >"$TMP/mixed.out" 2>/dev/null ||
            fail "mixedyears inspect failed"
        "$BIN" inspect "$FIXTURES/century.der" >"$TMP/century.out" 2>/dev/null ||
            fail "century inspect failed"
        grep -qx 'Not Before: 2049-12-31T23:30:45Z' "$TMP/mixed.out" ||
            fail "UTCTime year 49 must render as 2049"
        grep -qx 'Not After: 2050-01-01T00:30:59Z' "$TMP/mixed.out" ||
            fail "GeneralizedTime 2050 must render with its full year"
        grep -qx 'Not Before: 1950-01-01T00:00:00Z' "$TMP/century.out" ||
            fail "UTCTime year 50 must render as 1950, not 2050"
        ;;

    time_mixed_tags_der)
        # One certificate, two time tags: notBefore UTCTime "49" (2049),
        # notAfter GeneralizedTime 2050. Each line must follow its OWN tag,
        # in certificate order; the seconds are nonzero on both lines.
        write_expected_mixed DER "$TMP/expected"
        expect_success "$FIXTURES/mixedyears.der" "$TMP/expected"
        assert_time_structure "$TMP/expected" \
            '2049-12-31T23:30:45Z' '2050-01-01T00:30:59Z'
        ;;

    time_mixed_tags_pem)
        write_expected_mixed PEM "$TMP/expected"
        expect_success "$FIXTURES/mixedyears.pem" "$TMP/expected"
        assert_time_structure "$TMP/expected" \
            '2049-12-31T23:30:45Z' '2050-01-01T00:30:59Z'
        ;;

    time_mixed_tags_not_swapped)
        # The two lines must not be interpreted by one shared year rule or
        # emitted in swapped order: line 4 is Not Before (2049 UTCTime) and
        # line 5 is Not After (2050 GeneralizedTime), exact and ordered.
        "$BIN" inspect "$FIXTURES/mixedyears.der" >"$TMP/out" 2>/dev/null ||
            fail "mixedyears inspect failed"
        sed -n '4p' "$TMP/out" | grep -qx 'Not Before: 2049-12-31T23:30:45Z' ||
            fail "line 4 must be the UTCTime Not Before (2049), got: $(sed -n '4p' "$TMP/out")"
        sed -n '5p' "$TMP/out" | grep -qx 'Not After: 2050-01-01T00:30:59Z' ||
            fail "line 5 must be the GeneralizedTime Not After (2050), got: $(sed -n '5p' "$TMP/out")"
        # Reversing the tag order (GeneralizedTime first, UTCTime second)
        # must render each line by its own tag as well.
        write_expected_reverse DER "$TMP/reverse.expected"
        expect_success "$FIXTURES/reverseorder.der" "$TMP/reverse.expected"
        assert_time_structure "$TMP/reverse.expected" \
            '1949-01-01T00:00:00Z' '1950-06-15T12:00:00Z'
        ;;

    time_generalized_der)
        # Full 4-digit years at/after 2050 (GeneralizedTime): the valid leap
        # day 2052-02-29 with nonzero h/m/s, and 2100. Not yet valid -> still
        # displayed, exit 0.
        write_expected_generalized DER "$TMP/expected"
        expect_success "$FIXTURES/generalized.der" "$TMP/expected"
        assert_time_structure "$TMP/expected" \
            '2052-02-29T03:04:05Z' '2100-12-31T23:59:59Z'
        ;;

    time_generalized_pem)
        write_expected_generalized PEM "$TMP/expected"
        expect_success "$FIXTURES/generalized.pem" "$TMP/expected"
        assert_time_structure "$TMP/expected" \
            '2052-02-29T03:04:05Z' '2100-12-31T23:59:59Z'
        ;;

    time_pem_der_same_fields)
        # Same certificate saved as PEM and DER: identical times and all
        # other public fields, differing only in the Encoding line.
        for stem in century mixedyears generalized reverseorder; do
            "$BIN" inspect "$FIXTURES/$stem.pem" >"$TMP/$stem.pem.out" 2>"$TMP/$stem.pem.err"
            rc=$?
            [ "$rc" -eq 0 ] || fail "$stem PEM inspect failed with $rc"
            [ -s "$TMP/$stem.pem.err" ] && fail "$stem PEM stderr not empty: $(cat "$TMP/$stem.pem.err")"
            "$BIN" inspect "$FIXTURES/$stem.der" >"$TMP/$stem.der.out" 2>"$TMP/$stem.der.err"
            rc=$?
            [ "$rc" -eq 0 ] || fail "$stem DER inspect failed with $rc"
            [ -s "$TMP/$stem.der.err" ] && fail "$stem DER stderr not empty: $(cat "$TMP/$stem.der.err")"
            head -n 1 "$TMP/$stem.pem.out" | grep -qx 'Encoding: PEM' ||
                fail "$stem PEM not reported as PEM"
            head -n 1 "$TMP/$stem.der.out" | grep -qx 'Encoding: DER' ||
                fail "$stem DER not reported as DER"
            tail -n +2 "$TMP/$stem.pem.out" >"$TMP/$stem.pem.fields"
            tail -n +2 "$TMP/$stem.der.out" >"$TMP/$stem.der.fields"
            cmp -s "$TMP/$stem.pem.fields" "$TMP/$stem.der.fields" ||
                fail "$stem PEM and DER runs disagree outside the Encoding line"
        done
        ;;

    time_timezone_invariant)
        # The complete stdout must be identical under UTC, a timezone ahead
        # of UTC and one behind UTC. The moments straddle the 2049/2050 New
        # Year boundary: ahead-of-UTC local time pushes the Not Before over
        # the year boundary, behind-UTC local time pulls the Not After back.
        # POSIX TZ strings need no tzdata: UTC-14 is 14h AHEAD of UTC and
        # UTC+05:30 is 5h30 BEHIND UTC; half-hour offsets and the boundary
        # crossings are part of the guarantee.
        write_expected_mixed DER "$TMP/expected"
        first=
        for tz in UTC UTC-14 UTC+05:30 UTC+14; do
            run_with_tz "$tz" "$FIXTURES/mixedyears.der"
            [ "$rc" -eq 0 ] ||
                fail "inspect under TZ=$tz exited $rc (stderr: $(cat "$TMP/stderr"))"
            [ -s "$TMP/stderr" ] &&
                fail "inspect under TZ=$tz wrote stderr: $(cat "$TMP/stderr")"
            cmp -s "$TMP/expected" "$TMP/stdout" ||
                fail "output under TZ=$tz differs from the UTC expectation"
            if [ -z "$first" ]; then
                first=$tz
                cp "$TMP/stdout" "$TMP/tz.first"
            else
                cmp -s "$TMP/tz.first" "$TMP/stdout" ||
                    fail "output under TZ=$tz differs from TZ=$first"
            fi
        done
        # The UTC dates must survive even though local dates cross a
        # boundary: prove the chosen offsets really cross it in local time.
        [ "$(TZ=UTC-14 date -d '2049-12-31 23:30:45 UTC' '+%Y')" = 2050 ] ||
            fail "test setup: UTC-14 must push 2049-12-31T23:30:45Z into 2050 local"
        [ "$(TZ=UTC+05:30 date -d '2050-01-01 00:30:59 UTC' '+%Y')" = 2049 ] ||
            fail "test setup: UTC+05:30 must pull 2050-01-01T00:30:59Z back to 2049 local"
        grep -qx 'Not Before: 2049-12-31T23:30:45Z' "$TMP/tz.first" &&
            grep -qx 'Not After: 2050-01-01T00:30:59Z' "$TMP/tz.first" ||
            fail "UTC dates must be unchanged despite local boundary crossings"
        ;;

    time_expired_and_not_yet_valid_ok)
        # An already expired cert (century, both times in 1950-1952) and a
        # not-yet-valid cert (generalized, starts 2052) both display and
        # return 0, with empty stderr and the closing Note. The outcomes are
        # fixed by the certificates, never by the run date.
        for pair in "century.der 1950-01-01T00:00:00Z 1952-02-29T23:59:59Z" \
                    "generalized.der 2052-02-29T03:04:05Z 2100-12-31T23:59:59Z"; do
            # shellcheck disable=SC2086
            set -- $pair
            "$BIN" inspect "$FIXTURES/$1" >"$TMP/out" 2>"$TMP/err"
            rc=$?
            [ "$rc" -eq 0 ] || fail "$1 should display and exit 0, got $rc"
            [ -s "$TMP/err" ] && fail "$1 wrote stderr: $(cat "$TMP/err")"
            grep -qx "Not Before: $2" "$TMP/out" ||
                fail "$1 Not Before mismatch"
            grep -qx "Not After: $3" "$TMP/out" ||
                fail "$1 Not After mismatch"
            grep -qF "$NOTE" "$TMP/out" ||
                fail "$1 must keep the no-trust-verification Note"
        done
        ;;

    time_impossible_date_der)
        # February 30 cannot name a real day. The file is readable and the
        # rest of the certificate is structurally complete, so this is
        # invalid certificate CONTENT (exit 1, stderr names it and the path,
        # stdout completely empty), never a read failure.
        expect_invalid "$FIXTURES/baddate.der"
        # expect_invalid leaves the last run's streams in $TMP/stdout|stderr.
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "an impossible date is bad certificate content, not a read failure"
        ;;

    time_impossible_date_pem)
        # Same content served as PEM must be classified identically.
        expect_invalid "$FIXTURES/baddate.pem"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "an impossible date is bad certificate content, not a read failure"
        ;;

    empty_file)
        : >"$TMP/empty"
        expect_invalid "$TMP/empty"
        ;;

    whitespace_only)
        printf ' \t\n\r\n  \n' >"$TMP/blank"
        expect_invalid "$TMP/blank"
        ;;

    pem_truncated)
        head -c 500 "$FIXTURES/valid.pem" >"$TMP/truncated.pem"
        expect_invalid "$TMP/truncated.pem"
        ;;

    der_truncated)
        size=$(wc -c <"$FIXTURES/valid.der")
        head -c $((size / 2)) "$FIXTURES/valid.der" >"$TMP/truncated.der"
        expect_invalid "$TMP/truncated.der"
        ;;

    pem_second_block)
        cat "$FIXTURES/valid.pem" "$FIXTURES/valid.pem" >"$TMP/two.pem"
        expect_invalid "$TMP/two.pem"
        ;;

    pem_text_before)
        { printf 'see also: https://example.test\n'; cat "$FIXTURES/valid.pem"; } >"$TMP/text-before.pem"
        expect_invalid "$TMP/text-before.pem"
        ;;

    pem_text_after)
        { cat "$FIXTURES/valid.pem"; printf 'trailing comment\n'; } >"$TMP/text-after.pem"
        expect_invalid "$TMP/text-after.pem"
        ;;

    pem_body_trailing_nul)
        # From the outside this is one ordinary PEM block: a single marker
        # pair, nothing but whitespace outside it, and base64 that decodes to
        # the end. The decoded body is the complete certificate PLUS ONE ZERO
        # BYTE, so it is not exactly one certificate. inspect must not accept
        # merely because a certificate parses from the start of the body:
        # exit 1, empty stdout, invalid-certificate diagnostic naming the
        # path -- and a content error, not a file read failure.
        f=$FIXTURES/pem_body_trailing_nul.pem
        decode_single_pem_body "$f" "$TMP/body.bin"
        cert_size=$(wc -c <"$FIXTURES/valid.der")
        body_size=$(wc -c <"$TMP/body.bin")
        [ "$body_size" -eq $((cert_size + 1)) ] ||
            fail "decoded body must be the certificate plus exactly one byte, got $body_size vs $cert_size"
        cmp -s "$FIXTURES/valid.der" "$TMP/body.bin" &&
            fail "test setup: decoded body must carry more than the certificate"
        head -c "$cert_size" "$TMP/body.bin" | cmp -s "$FIXTURES/valid.der" - ||
            fail "decoded body must start with the complete certificate"
        last_byte=$(tail -c 1 "$TMP/body.bin" | od -An -tu1 | tr -d ' ')
        [ "$last_byte" -eq 0 ] ||
            fail "the single extra byte must be a zero byte, got $last_byte"
        expect_invalid "$f"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "trailing body content is bad certificate content, not a read failure"
        ;;

    pem_body_trailing_cert)
        # Same trap with a complete second certificate hidden in the one
        # block's base64 body -- byte-identical to the first, which must still
        # count as excess content: no "show the first and ignore the tail",
        # and no read-failure classification.
        f=$FIXTURES/pem_body_trailing_cert.pem
        decode_single_pem_body "$f" "$TMP/body.bin"
        cert_size=$(wc -c <"$FIXTURES/valid.der")
        body_size=$(wc -c <"$TMP/body.bin")
        [ "$body_size" -eq $((cert_size * 2)) ] ||
            fail "decoded body must be two certificates, got $body_size vs $((cert_size * 2))"
        head -c "$cert_size" "$TMP/body.bin" >"$TMP/body.first"
        tail -c "$cert_size" "$TMP/body.bin" >"$TMP/body.second"
        cmp -s "$TMP/body.first" "$FIXTURES/valid.der" ||
            fail "first half of the body must be the complete certificate"
        cmp -s "$TMP/body.second" "$FIXTURES/valid.der" ||
            fail "second half must be another complete certificate"
        cmp -s "$TMP/body.first" "$TMP/body.second" ||
            fail "the hidden second certificate is meant to be identical to the first"
        expect_invalid "$f"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "a second certificate in the PEM body is bad content, not a read failure"
        ;;

    pem_body_exact_with_whitespace)
        # Adjacent success condition: a single block whose body IS exactly one
        # complete certificate, with only supported spaces, tabs and blank
        # lines (including CRLF) around it. It must display as PEM with the
        # certificate's normal fields and the closing no-trust Note; the same
        # certificate as DER must match in every field except Encoding.
        {
            printf ' \t  \n\n\t\n'
            sed 's/$/\r/' "$FIXTURES/valid.pem"
            printf '  \n\t \n\n  '
        } >"$TMP/exact-body.pem"
        decode_single_pem_body "$TMP/exact-body.pem" "$TMP/body.bin"
        cmp -s "$TMP/body.bin" "$FIXTURES/valid.der" ||
            fail "decoded body must be exactly the one certificate, no extra bytes"
        write_expected_valid PEM "$TMP/expected"
        expect_success "$TMP/exact-body.pem" "$TMP/expected"
        "$BIN" inspect "$FIXTURES/valid.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        tail -n +2 "$TMP/expected" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM with surrounding whitespace and DER must agree outside Encoding"
        head -n 1 "$TMP/expected" | grep -qx 'Encoding: PEM' ||
            fail "the wrapped file must still report its real encoding as PEM"
        grep -qF "$NOTE" "$TMP/expected" ||
            fail "output must keep the no-trust-verification Note"
        ;;

    pem_whitespace_hugging_markers)
        # The outer whitespace may also hug the markers on their own lines:
        # spaces and tabs directly before the BEGIN marker and directly
        # after the END marker, mixed with whitespace-only lines and CRLF
        # endings, and the file need not end with a newline. The certificate
        # content is untouched, so the output must match the plain PEM run
        # verbatim and the DER run in every field except Encoding.
        sed 's/$/\r/' "$FIXTURES/valid.pem" | head -c -2 >"$TMP/block.pem"
        {
            printf ' \t\n\t\n'
            printf '  \t'
            cat "$TMP/block.pem"
            printf ' \t\n'
            printf '\t \n  \t'
        } >"$TMP/hugging.pem"
        write_expected_valid PEM "$TMP/expected"
        expect_success "$TMP/hugging.pem" "$TMP/expected"
        "$BIN" inspect "$FIXTURES/valid.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        tail -n +2 "$TMP/expected" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM with hugging whitespace and DER must agree outside Encoding"
        head -n 1 "$TMP/expected" | grep -qx 'Encoding: PEM' ||
            fail "the wrapped file must still report its real encoding as PEM"
        grep -qF "$NOTE" "$TMP/expected" ||
            fail "output must keep the no-trust-verification Note"
        ;;

    pem_whitespace_hugging_second_block)
        # The outer-whitespace allowance does not extend to a second
        # certificate block, even one byte-identical to the first.
        {
            printf '  \t'
            cat "$FIXTURES/valid.pem"
            printf '\t \n  '
            cat "$FIXTURES/valid.pem"
            printf ' \t'
        } >"$TMP/two-hugging.pem"
        expect_invalid "$TMP/two-hugging.pem"
        ;;

    pem_whitespace_hugging_text_outside)
        # Any non-whitespace text outside the block stays a content error,
        # before or after, even when the whitespace itself hugs the markers.
        {
            printf 'see also: https://example.test\n  \t'
            cat "$FIXTURES/valid.pem"
        } >"$TMP/text-before-hugging.pem"
        expect_invalid "$TMP/text-before-hugging.pem"
        {
            printf '\t  '
            head -c -1 "$FIXTURES/valid.pem"
            printf '  \t\ntrailing comment\n'
        } >"$TMP/text-after-hugging.pem"
        expect_invalid "$TMP/text-after-hugging.pem"
        ;;

    der_trailing_whitespace)
        # DER gets no textual-whitespace allowance: even one trailing
        # whitespace byte after a complete certificate is rejected.
        { cat "$FIXTURES/valid.der"; printf '\n'; } >"$TMP/trailing-ws.der"
        expect_invalid "$TMP/trailing-ws.der"
        ;;

    der_trailing_cert)
        cat "$FIXTURES/valid.der" "$FIXTURES/valid.der" >"$TMP/two.der"
        expect_invalid "$TMP/two.der"
        ;;

    der_trailing_bytes)
        { cat "$FIXTURES/valid.der"; printf '\000\001\002'; } >"$TMP/trailing.der"
        expect_invalid "$TMP/trailing.der"
        ;;

    public_key_only)
        expect_invalid "$FIXTURES/public_key.pem"
        ;;

    private_key_only)
        expect_invalid "$FIXTURES/private_key.pem"
        ;;

    read_directory)
        # A directory opens successfully on POSIX but cannot be read as a
        # certificate file: it must be diagnosed as a read failure with the
        # directory reason, never as an empty/malformed certificate.
        mkdir -p "$TMP/certs"
        expect_read_failure "$TMP/certs" "[Dd]irectory"
        ;;

    read_nonexistent)
        expect_read_failure "$TMP/does-not-exist.pem" "[Nn]o such"
        ;;

    read_permission_denied)
        # Mode 000 denies read; root bypasses permission checks, so the case
        # is only meaningful for an unprivileged runner.
        if [ "$(id -u)" -eq 0 ]; then
            echo "PASS: $CASE (skipped for root)"
            exit 0
        fi
        cp "$FIXTURES/valid.pem" "$TMP/locked.pem"
        chmod 000 "$TMP/locked.pem"
        expect_read_failure "$TMP/locked.pem" "[Pp]ermission"
        ;;

    read_directory_path_with_space)
        # Paths containing spaces and non-ASCII text must survive verbatim in
        # the read-failure diagnostic.
        mkdir -p "$TMP/dir with space/证书目录"
        expect_read_failure "$TMP/dir with space/证书目录" "[Dd]irectory"
        ;;

    read_fifo_no_writer)
        # A FIFO with no writer must be rejected by file type without ever
        # blocking in open(): the run is wrapped in timeout so the old
        # open-first behavior fails here instead of hanging the suite.
        mkfifo "$TMP/pipe.pem"
        expect_read_failure_timed "$TMP/pipe.pem" "[Pp]ipe"
        ;;

    read_fifo_with_writer)
        # Even with a writer already prepared to deliver a complete, valid
        # PEM certificate, a FIFO is rejected by type and never read. A
        # broken implementation would open the pipe, receive the valid PEM
        # and print certificate info; the writer stays blocked in open()
        # until the (correct) rejection. exec makes the background job the
        # cat itself (so $! is the blocked writer the EXIT trap can reap),
        # instead of a wrapper subshell that leaves an orphaned cat behind.
        mkfifo "$TMP/pipe-ready.pem"
        (exec cat "$FIXTURES/valid.pem" >"$TMP/pipe-ready.pem") &
        writer=$!
        sleep 1
        expect_read_failure_timed "$TMP/pipe-ready.pem" "[Pp]ipe"
        kill "$writer" 2>/dev/null
        wait "$writer" 2>/dev/null
        writer=
        ;;

    read_character_device)
        # /dev/null is a character device whose reads return immediate EOF:
        # it must be a read failure ("not a regular file"), never an empty
        # certificate.
        [ -e /dev/null ] || { echo "PASS: $CASE (skipped: /dev/null unavailable)"; exit 0; }
        expect_read_failure /dev/null "[Cc]haracter device"
        ;;

    read_block_device)
        # Block devices are rejected by type too. stat() needs no read
        # permission, so the rejection happens even when open() would be
        # denied; skip in environments that expose no block device nodes.
        blkdev=$(find /dev -maxdepth 2 -type b 2>/dev/null | head -n 1)
        [ -n "$blkdev" ] || { echo "PASS: $CASE (skipped: no block device under /dev)"; exit 0; }
        expect_read_failure_timed "$blkdev" "[Bb]lock device"
        ;;

    read_socket)
        # A local (Unix-domain) socket node cannot be a certificate file and
        # must be rejected without opening/connecting to it.
        python3 - "$TMP/local.sock" <<'EOF'
import socket
import sys
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(sys.argv[1])
EOF
        expect_read_failure_timed "$TMP/local.sock" "[Ss]ocket"
        ;;

    symlink_to_regular)
        # A symlink (even through a chain) to a readable regular file works
        # exactly like inspecting the target file directly.
        ln -s "$FIXTURES/valid.pem" "$TMP/target-link.pem"
        ln -s "$TMP/target-link.pem" "$TMP/chain-link.pem"
        write_expected_valid PEM "$TMP/expected"
        expect_success "$TMP/chain-link.pem" "$TMP/expected"
        ;;

    symlink_to_directory)
        # A link to a directory is rejected according to the target type;
        # the diagnostic keeps the link path the user actually passed.
        mkdir -p "$TMP/real-dir"
        ln -s "$TMP/real-dir" "$TMP/dir-link"
        expect_read_failure "$TMP/dir-link" "[Dd]irectory"
        ;;

    symlink_to_fifo)
        # A link to a writer-less FIFO follows to the FIFO, is rejected by
        # type, and must not block.
        mkfifo "$TMP/real-fifo"
        ln -s "$TMP/real-fifo" "$TMP/fifo-link"
        expect_read_failure_timed "$TMP/fifo-link" "[Pp]ipe"
        ;;

    symlink_to_character_device)
        # A link to /dev/null is rejected as a character device (never as an
        # empty certificate), with the link path in the diagnostic.
        [ -e /dev/null ] || { echo "PASS: $CASE (skipped: /dev/null unavailable)"; exit 0; }
        ln -s /dev/null "$TMP/null-link"
        expect_read_failure "$TMP/null-link" "[Cc]haracter device"
        ;;

    symlink_dangling)
        # A link whose target does not exist is a read failure naming the
        # link path and explaining the missing target.
        ln -s "$TMP/missing-target.pem" "$TMP/dangling-link"
        expect_read_failure "$TMP/dangling-link" "[Nn]o such"
        ;;

    symlink_to_unreadable)
        # A link to an existing regular file without read permission is a
        # read failure (permission reason), still naming the link path; root
        # bypasses permission checks, so skip when running as root.
        if [ "$(id -u)" -eq 0 ]; then
            echo "PASS: $CASE (skipped for root)"
            exit 0
        fi
        cp "$FIXTURES/valid.pem" "$TMP/locked-target.pem"
        chmod 000 "$TMP/locked-target.pem"
        ln -s "$TMP/locked-target.pem" "$TMP/locked-link"
        expect_read_failure "$TMP/locked-link" "[Pp]ermission"
        ;;

    *)
        echo "FAIL: unknown case '$CASE'" >&2
        exit 1
        ;;
esac

echo "PASS: $CASE"
