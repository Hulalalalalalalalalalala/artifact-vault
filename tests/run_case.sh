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

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

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
LONG_OID_FINGERPRINT=$(fingerprint_of "$FIXTURES/long_oid.der")

# Concatenate $1 exactly $2 times (used to spell out the long dotted OIDs,
# which are regular repeated-arc sequences far too long to paste by hand).
repeat() {
    token=$1
    count=$2
    i=0
    result=''
    while [ "$i" -lt "$count" ]; do
        result="$result$token"
        i=$((i + 1))
    done
    printf '%s' "$result"
}

# Unknown OIDs carried by tests/fixtures/long_oid.{pem,der}. Their dotted text
# lengths straddle the old 79-character fixed-buffer boundary:
#   OID79:  exactly 79 chars (fills the old buffer without truncating);
#   OID80:  exactly 80 chars (first one that used to lose its last arc);
#   PA/PB:  two 81-char OIDs whose FIRST 79 characters are byte-identical;
#           they diverge only in the final arc ("10" vs "20") and must never
#           be rendered as the same attribute name;
#   OLONG:  189 chars (multi-digit arcs keep it legal in DER);
#   PREFIX: their shared 79-char prefix, ending in '.'; truncation would show
#           this prefix followed directly by '='.
OID79="1.2$(repeat '.1' 38)"
OID80="1.2.10$(repeat '.1' 37)"
PA_PREFIX="1.2.10$(repeat '.1' 36)."
OID_PA="${PA_PREFIX}10"
OID_PB="${PA_PREFIX}20"
OID_LONG="1.2$(repeat '.39' 62)"
[ "${#OID79}" -eq 79 ] || fail_helper=oid79
[ "${#OID80}" -eq 80 ] || fail_helper=oid80
[ "${#OID_PA}" -eq 81 ] && [ "${#OID_PB}" -eq 81 ] || fail_helper=pair
[ "$OID_PA" != "$OID_PB" ] || fail_helper=pair_distinct
[ "${#OID_LONG}" -eq 189 ] || fail_helper=olong
[ "$(printf '%s' "$OID_PA" | cut -c1-79)" = "$(printf '%s' "$OID_PB" | cut -c1-79)" ] ||
    fail_helper=prefix
if [ -n "${fail_helper:-}" ]; then
    echo "FAIL: internal OID test constant mismatch ($fail_helper)" >&2
    exit 1
fi

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

# Subject and issuer of the long-unknown-OID certificate
# (tests/fixtures/long_oid.{pem,der}). Every dotted OID must appear in full,
# each followed by its own value; escapes inside values and the "+' grouping
# are identical in meaning to the complex-name fixture. Built from the OID
# constants above so the enormous keys never have to be typed out.
LONG_SUBJECT="C=CN, OU=研发部, ${OID79}=长度79的OID值, ${OID80}=长度80的OID值\,含逗号\+加号\\\\反斜杠, CN=组内CN+${OID_PA}=配对A值, ${OID_PB}=配对B值, 1.2.3.4.5.6.7=短未知OID, ${OID_LONG}=\ 超长OID值\ , CN=结尾CN"
LONG_ISSUER="C=CN, O=长OID颁发机构, ${OID_LONG}=颁发者长OID, ${OID_PA}=颁发者配对A, CN=Long OID Root CA"

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

write_expected_long_oid() {  # $1 = encoding, $2 = output file
    {
        printf 'Encoding: %s\n' "$1"
        printf 'Subject: %s\n' "$LONG_SUBJECT"
        printf 'Issuer: %s\n' "$LONG_ISSUER"
        printf 'Not Before: 2023-01-01T00:00:00Z\n'
        printf 'Not After: 2043-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$LONG_OID_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
}

# Structural guards for the long-OID output ($1 = captured stdout file).
# The byte-for-byte expected comparison already pins everything; these checks
# independently re-prove the specific truncation hazards the fixture exists
# for, by name rather than by raw diff.
assert_long_oid_structure() {
    out=$1
    subject=$(sed -n 's/^Subject: //p' "$out")
    issuer=$(sed -n 's/^Issuer: //p' "$out")

    [ "$subject" != "$issuer" ] ||
        fail "subject and issuer must render different names"
    [ "$subject" = "$LONG_SUBJECT" ] ||
        fail "long-OID subject rendered incompletely or reordered"
    [ "$issuer" = "$LONG_ISSUER" ] ||
        fail "long-OID issuer rendered incompletely or reordered"

    # Each long OID must appear followed directly by '=' and by its OWN value,
    # proving no trailing arc was dropped and no attribute was swallowed.
    for pair in "${OID79}=长度79的OID值" \
                "${OID80}=长度80的OID值" \
                "${OID_PA}=配对A值" "${OID_PB}=配对B值" \
                "${OID_LONG}=颁发者长OID" \
                "1.2.3.4.5.6.7=短未知OID" \
                "CN=结尾CN" "OU=研发部"; do
        case "$subject $issuer" in
            *"$pair"*) ;;
            *) fail "missing or truncated OID/value pair: ${pair%%=*}" ;;
        esac
    done

    # The 189-char OID must survive whole in BOTH names (subject and issuer
    # carry it with different values).
    [ "$(printf '%s' "$subject$issuer" | grep -oF "$OID_LONG" | wc -l)" -eq 2 ] ||
        fail "189-char OID must appear in full in subject and issuer"

    # Two OIDs sharing their first 79 chars must render as DISTINCT names:
    # each full OID present, neither collapsed into the shared prefix+'='.
    case "$subject" in
        *"${OID_PA}=配对A值"*"${OID_PB}=配对B值"*) ;;
        *) fail "prefix-sharing OIDs must keep distinct names and values" ;;
    esac
    case "$subject" in
        *"${PA_PREFIX}="*) fail "OID was truncated at 79 chars (dangling '.')" ;;
        *) ;;
    esac

    # Known short names keep working alongside the long dotted OIDs, and the
    # multi-valued RDN still joins with a bare '+'.
    case "$subject" in
        *"CN=组内CN+${OID_PA}=配对A值"*) ;;
        *) fail "multi-valued RDN grouping with long OID broken" ;;
    esac

    # Escaped punctuation inside a value whose key is very long must still be
    # escaped exactly once, and leading/trailing spaces as '\ '. The expected
    # substrings are held in single-quoted variables (literal backslashes) and
    # quoted again inside the pattern so glob escaping cannot interfere.
    esc_punct='长度80的OID值\,含逗号\+加号\\反斜杠'
    esc_spaces=", ${OID_LONG}=\\ 超长OID值\\ "
    case "$subject" in
        *"$esc_punct"*) ;;
        *) fail "escapes lost next to a long OID key" ;;
    esac
    case "$subject" in
        *"$esc_spaces"*) ;;
        *) fail "leading/trailing spaces not preserved for long OID value" ;;
    esac
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

fail() {
    echo "FAIL: $CASE: $1" >&2
    exit 1
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

# Run `trustpeek inspect $1` and require exit 1, empty stdout, and a stderr
# diagnostic that reports a file READ failure (distinct from invalid
# certificate content), names the path, and carries a real reason rather than
# a stale errno ("Success" belongs to no failing operation).
expect_read_failure() {
    file=$1
    detail_pattern=${2:-}
    "$BIN" inspect "$file" >"$TMP/stdout" 2>"$TMP/stderr"
    rc=$?
    [ "$rc" -eq 1 ] || fail "expected exit 1, got $rc"
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

    der_long_oid)
        # Unknown dotted OIDs at 79/80/81/189 chars, including two that share
        # their first 79 chars: every OID and value rendered in full, exit 0,
        # empty stderr.
        write_expected_long_oid DER "$TMP/expected"
        expect_success "$FIXTURES/long_oid.der" "$TMP/expected"
        assert_long_oid_structure "$TMP/expected"
        ;;

    pem_long_oid)
        # The same certificate as PEM: reported as PEM while both long-OID
        # name lines stay byte-for-byte identical to the DER rendering.
        write_expected_long_oid PEM "$TMP/expected"
        expect_success "$FIXTURES/long_oid.pem" "$TMP/expected"
        assert_long_oid_structure "$TMP/expected"
        ;;

    pem_der_long_oid_same)
        # PEM vs DER of one certificate: Encoding reports the real format and
        # everything else (long OIDs, values, fingerprint) agrees verbatim.
        "$BIN" inspect "$FIXTURES/long_oid.pem" >"$TMP/pem.out" 2>"$TMP/pem.err"
        rc=$?
        [ "$rc" -eq 0 ] || fail "PEM input failed with $rc"
        [ -s "$TMP/pem.err" ] && fail "PEM stderr not empty: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/long_oid.der" >"$TMP/der.out" 2>"$TMP/der.err"
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
        assert_long_oid_structure "$TMP/der.out"
        pem_subject=$(sed -n 's/^Subject: //p' "$TMP/pem.out")
        pem_issuer=$(sed -n 's/^Issuer: //p' "$TMP/pem.out")
        [ "$pem_subject" != "$pem_issuer" ] ||
            fail "long-OID fixture must have different subject and issuer"
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

    *)
        echo "FAIL: unknown case '$CASE'" >&2
        exit 1
        ;;
esac

echo "PASS: $CASE"
