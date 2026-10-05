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

VALID_SUBJECT='C=CN, O=Trustpeek Test Org, OU=Engineering, CN=valid.example.test'
EXPIRED_SUBJECT='C=CN, O=Trustpeek Test Org, CN=expired.example.test'
MARKER_SUBJECT='C=CN, O=Trustpeek Test Org, CN=marker -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- test'
# The names fixture has distinct subject and issuer names exercising the
# full name-rendering surface: Chinese and other non-ASCII UTF-8 values, a
# repeated attribute type (two OU entries), a multi-valued RDN joined with
# '+' whose CN value itself contains an escaped plus, values with an
# escaped comma and backslash, a value with escaped leading/trailing
# spaces, and an attribute with no known short name shown as a dotted OID.
NAMES_SUBJECT='C=CN, O=Comma\, Co., OU=dev+CN=plus\+inside, OU=back\\slash, CN=\ 边缘节点\ '
NAMES_ISSUER='C=CN, O=示例科技有限公司, L=São Paulo, OU=研发部, OU=平台组, CN=根 CA 证书, 1.2.3.4.5=自定义属性'

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
        printf 'Not Before: 2022-01-01T00:00:00Z\n'
        printf 'Not After: 2042-01-01T00:00:00Z\n'
        printf 'SHA-256 Fingerprint: %s\n' "$NAMES_FINGERPRINT"
        printf '%s\n' "$NOTE"
    } >"$2"
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

    names_pem)
        # Complex names with distinct subject and issuer, saved as PEM:
        # the full output must match byte for byte, including the escaped
        # characters, the '+'-joined multi-valued RDN, the repeated OU
        # attributes, the UTF-8 values and the dotted-OID attribute.
        write_expected_names PEM "$TMP/expected"
        expect_success "$FIXTURES/names.pem" "$TMP/expected"
        ;;

    names_der)
        # The same certificate as DER: identical names and fields, only
        # the Encoding line differs.
        write_expected_names DER "$TMP/expected"
        expect_success "$FIXTURES/names.der" "$TMP/expected"
        ;;

    names_pem_der_identical)
        # Subject and Issuer of the same certificate must be byte-identical
        # between the PEM and DER runs, with each encoding line reporting
        # the actual format. Both runs exit 0 with empty stderr.
        "$BIN" inspect "$FIXTURES/names.pem" >"$TMP/pem.out" 2>"$TMP/pem.err" ||
            fail "PEM input failed"
        [ -s "$TMP/pem.err" ] && fail "PEM run wrote to stderr: $(cat "$TMP/pem.err")"
        "$BIN" inspect "$FIXTURES/names.der" >"$TMP/der.out" 2>"$TMP/der.err" ||
            fail "DER input failed"
        [ -s "$TMP/der.err" ] && fail "DER run wrote to stderr: $(cat "$TMP/der.err")"
        head -n 1 "$TMP/pem.out" | grep -qx 'Encoding: PEM' ||
            fail "PEM input not reported as PEM"
        head -n 1 "$TMP/der.out" | grep -qx 'Encoding: DER' ||
            fail "DER input not reported as DER"
        tail -n +2 "$TMP/pem.out" >"$TMP/pem.fields"
        tail -n +2 "$TMP/der.out" >"$TMP/der.fields"
        cmp -s "$TMP/pem.fields" "$TMP/der.fields" ||
            fail "PEM and DER runs disagree on subject/issuer/validity/fingerprint"
        ;;

    names_subject_issuer_distinct)
        # The two name lines must not be collapsed into one another: the
        # subject line carries exactly the subject attributes and the
        # issuer line exactly the issuer attributes, in certificate order.
        "$BIN" inspect "$FIXTURES/names.pem" >"$TMP/stdout" 2>"$TMP/stderr" ||
            fail "inspect failed"
        [ -s "$TMP/stderr" ] && fail "expected empty stderr, got: $(cat "$TMP/stderr")"
        subject=$(sed -n 's/^Subject: //p' "$TMP/stdout")
        issuer=$(sed -n 's/^Issuer: //p' "$TMP/stdout")
        [ "$subject" = "$NAMES_SUBJECT" ] ||
            fail "subject line mismatch: '$subject'"
        [ "$issuer" = "$NAMES_ISSUER" ] ||
            fail "issuer line mismatch: '$issuer'"
        [ "$subject" != "$issuer" ] ||
            fail "subject and issuer must keep their distinct names"
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

    *)
        echo "FAIL: unknown case '$CASE'" >&2
        exit 1
        ;;
esac

echo "PASS: $CASE"
