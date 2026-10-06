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

# The fingerprints are derived from the committed DER fixtures, so the
# expected values stay in sync with the certificates on disk.
fingerprint_of() {
    sha256sum "$1" | cut -d' ' -f1 |
        tr 'a-f' 'A-F' | sed 's/\(..\)/\1:/g; s/:$//'
}
FINGERPRINT=$(fingerprint_of "$FIXTURES/valid.der")
EXPIRED_FINGERPRINT=$(fingerprint_of "$FIXTURES/expired.der")
MARKER_FINGERPRINT=$(fingerprint_of "$FIXTURES/marker.der")
NAMES_FINGERPRINT=$(fingerprint_of "$FIXTURES/names.der")
LONGOID_FINGERPRINT=$(fingerprint_of "$FIXTURES/longoid.der")
CTRLCHARS_FINGERPRINT=$(fingerprint_of "$FIXTURES/ctrlchars.der")
CENTURY_FINGERPRINT=$(fingerprint_of "$FIXTURES/century.der")
MIXED_FINGERPRINT=$(fingerprint_of "$FIXTURES/mixedyears.der")
GENERALIZED_FINGERPRINT=$(fingerprint_of "$FIXTURES/generalized.der")
REVERSE_FINGERPRINT=$(fingerprint_of "$FIXTURES/reverseorder.der")

VALID_SUBJECT='C=CN, O=Trustpeek Test Org, OU=Engineering, CN=valid.example.test'
EXPIRED_SUBJECT='C=CN, O=Trustpeek Test Org, CN=expired.example.test'
MARKER_SUBJECT='C=CN, O=Trustpeek Test Org, CN=marker -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- test'

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

# Proves a PEM rejection fixture fails on HIDDEN PAYLOAD CONTENT rather than
# on a packaging defect. $1 = fixture, $2 = expected surplus byte count. The
# file must contain exactly one CERTIFICATE block whose exterior is only
# supported whitespace (space/tab/CR/LF), and its base64 body must be the
# canonical, FULL encoding (complete decode, no truncation or stray padding)
# of the complete valid certificate DER followed by exactly $2 surplus
# bytes. A regression in how the body is read therefore cannot be hidden by
# a broken marker, outside-block text or an encoding error.
assert_pem_hidden_content_shape() {
    fixture=$1
    surplus=$2
    if ! python3 - "$fixture" "$FIXTURES/valid.der" "$surplus" <<'EOF'
import base64
import re
import sys

fixture, der_path, surplus = sys.argv[1], sys.argv[2], int(sys.argv[3])
raw = open(fixture, "rb").read()
der = open(der_path, "rb").read()
begin = b"-----BEGIN CERTIFICATE-----"
end = b"-----END CERTIFICATE-----"

assert raw.count(begin) == 1 and raw.count(end) == 1, \
    "must contain exactly one begin and one end marker"
match = re.fullmatch(
    rb"[ \t\r\n]*" + re.escape(begin) + rb"\r?\n(.*?)"
    + re.escape(end) + rb"\r?\n?[ \t\r\n]*", raw, re.S)
assert match, "markers must be intact with only whitespace outside the block"

body = b"".join(line.strip() for line in match.group(1).splitlines())
assert body and len(body) % 4 == 0, "base64 body must be a complete multiple of four"
assert re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", body), \
    "base64 body must contain only base64 characters and terminal padding"
# validate=True rejects non-alphabet/garbage; re-encoding the decoded bytes
# must reproduce the body exactly, proving the decode is complete and the
# padding is canonical (nothing is cut off, no padding hides data).
decoded = base64.b64decode(body, validate=True)
assert base64.b64encode(decoded) == body, "base64 body must decode completely and canonically"

assert decoded[:len(der)] == der, "payload must begin with the complete valid certificate DER"
assert len(decoded) - len(der) == surplus and surplus > 0, \
    f"payload must hide exactly {surplus} surplus bytes beyond the one certificate"
EOF
    then
        fail "fixture '$fixture' lacks the intended single-block, fully-decoded cert-plus-surplus shape"
    fi
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
        # The surrounding whitespace must not alter any field: the same
        # certificate saved directly as DER reports DER but matches this PEM
        # run on subject, issuer, both UTC times, fingerprint and the Note.
        "$BIN" inspect "$FIXTURES/valid.der" >"$TMP/der.out" 2>"$TMP/der.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "DER input failed with $rc"
        [ -s "$TMP/der.err" ] && fail "DER stderr not empty: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/expected" | grep -qx 'Encoding: PEM' ||
            fail "whitespace-wrapped PEM must still be reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/expected" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "whitespace-wrapped PEM and DER runs disagree outside the Encoding line"
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

    pem_body_trailing_nul)
        # The file looks like exactly one PEM CERTIFICATE block -- one pair
        # of intact markers, only whitespace outside the block, and a base64
        # body that decodes completely -- but the decoded payload is the
        # complete certificate DER plus a single zero byte. A reader that
        # accepts as soon as a certificate parses from the body's start would
        # wrongly succeed: the surplus NUL must make this invalid certificate
        # content, exit 1, empty stdout, never a read failure.
        fixture=$FIXTURES/pembody_trailing_nul.pem
        assert_pem_hidden_content_shape "$fixture" 1
        expect_invalid "$fixture"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "hidden payload content is bad certificate content, not a read failure"
        ;;

    pem_body_trailing_cert)
        # Same single-block, fully-decodable packaging, but the payload is a
        # complete certificate followed by another COMPLETE certificate --
        # byte-for-byte identical to the first. The identical twin is still
        # surplus content: inspect must neither show only the first and
        # ignore the tail nor treat this as a file read failure.
        fixture=$FIXTURES/pembody_trailing_cert.pem
        cert_size=$(wc -c <"$FIXTURES/valid.der")
        assert_pem_hidden_content_shape "$fixture" "$cert_size"
        expect_invalid "$fixture"
        grep -q "failed to read file" "$TMP/stderr" &&
            fail "hidden payload content is bad certificate content, not a read failure"
        # The second certificate really is the same bytes as the first, so
        # the fixture cannot sneak by as "two distinct certificates" logic.
        python3 - "$fixture" "$FIXTURES/valid.der" <<'EOF' || fail "fixture setup: payload must be two identical certificates"
import base64
import re
import sys
raw = open(sys.argv[1], "rb").read()
der = open(sys.argv[2], "rb").read()
body = b"".join(re.search(rb"-----BEGIN CERTIFICATE-----\n(.*?)-----END",
                          raw, re.S).group(1).split())
payload = base64.b64decode(body, validate=True)
assert payload == der + der
EOF
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
