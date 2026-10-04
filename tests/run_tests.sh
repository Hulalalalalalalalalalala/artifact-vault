#!/usr/bin/env bash
#
# Regression tests for `trustpeek inspect`.
#
# The tests drive the real command line against stable, checked-in
# certificates under tests/fixtures and assert on the user-visible result:
# exit code, full standard output and standard error. They never use the
# network or the system trust store, and expected output is pinned in
# tests/expected.
#
# Run directly:
#   tests/run_tests.sh                         # uses ./build/trustpeek
#   TRUSTPEEK=/path/to/trustpeek tests/run_tests.sh
# Or through ctest after building:
#   ctest --output-on-failure
set -u

export LC_ALL=C.UTF-8
export TZ=UTC

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FIX="$SCRIPT_DIR/fixtures"
EXP="$SCRIPT_DIR/expected"
BIN="${TRUSTPEEK:-$SCRIPT_DIR/../build/trustpeek}"

if [[ ! -x "$BIN" ]]; then
    echo "error: trustpeek binary not found at $BIN" >&2
    echo "build it first (cmake -S . -B build && cmake --build build)" >&2
    exit 2
fi
for required in main.pem main.der second.pem second.der expired.pem expired.der \
                root.pem root.der public-key.pem private-key.pem; do
    if [[ ! -s "$FIX/$required" ]]; then
        echo "error: missing fixture $FIX/$required" >&2
        echo "run $SCRIPT_DIR/generate_fixtures.sh once (requires openssl)" >&2
        exit 2
    fi
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
FAILED_NAMES=()
CASE=""
RC=0
OUT=""
ERR=""
ASSERT=""

NOTE='Note: this output displays certificate information only; reading the file successfully does not verify the signature or establish trust.'

# --- low-level helpers -------------------------------------------------------

run_inspect() {  # $1 = case name, remaining args = inspect arguments
    CASE=$1
    shift
    OUT="$WORK/$CASE.out"
    ERR="$WORK/$CASE.err"
    RC=0
    "$BIN" inspect "$@" >"$OUT" 2>"$ERR" || RC=$?
}

fail_assert() { ASSERT=$1; return 1; }

expect_rc() {
    [[ $RC == "$1" ]] || { fail_assert "expected exit code $1, got $RC"; return; }
}
expect_stdout_file() {
    cmp -s "$OUT" "$1" \
        || { fail_assert "stdout differs from $1"; return; }
}
expect_stdout_empty() {
    [[ ! -s "$OUT" ]] || { fail_assert "stdout must be empty"; return; }
}
expect_stderr_contains() {
    grep -Fq -- "$1" "$ERR" \
        || { fail_assert "stderr does not contain: $1"; return; }
}
expect_stdout_contains() {
    grep -Fq -- "$1" "$OUT" \
        || { fail_assert "stdout does not contain: $1"; return; }
}
expect_stdout_linecount() {
    local n
    n=$(wc -l < "$OUT")
    [[ $n == "$1" ]] || { fail_assert "expected $1 output lines, got $n"; return; }
}

# t <name> <function> — run one case function and record the result.
t() {
    local name=$1 fn=$2
    ASSERT=""
    "$fn"
    if [[ $? -eq 0 ]]; then
        PASS=$((PASS + 1))
        printf 'ok\t%s\n' "$name"
    else
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
        printf 'not ok\t%s\n' "$name"
        printf '    reason: %s\n' "$ASSERT"
        printf '    -- exit code: %s\n' "$RC"
        printf '    -- stdout (vs expected):\n'
        if [[ -s "$OUT" ]]; then sed 's/^/        /' "$OUT" | head -20; fi
        printf '    -- stderr:\n'
        if [[ -s "$ERR" ]]; then sed 's/^/        /' "$ERR" | head -10; fi
    fi
}

# Expected DER output is the pinned PEM output with only the Encoding line
# changed; every other field must be byte identical.
sed '1s/^Encoding: PEM$/Encoding: DER/' "$EXP/main.out" > "$WORK/exp-main.der.out"
sed '1s/^Encoding: PEM$/Encoding: DER/' "$EXP/expired.out" > "$WORK/exp-expired.der.out"

# --- cases: successful display ------------------------------------------------

case_pem_ok() {
    run_inspect pem-ok "$FIX/main.pem"
    expect_rc 0 && expect_stdout_file "$EXP/main.out"
}

case_der_ok() {
    run_inspect der-ok "$FIX/main.der"
    expect_rc 0 && expect_stdout_file "$WORK/exp-main.der.out"
}

# The PEM and DER runs of the same certificate must differ ONLY on the
# Encoding line; subject, issuer, both dates and fingerprint must match.
case_pem_der_equivalence() {
    run_inspect eq-pem "$FIX/main.pem"
    [[ $RC == 0 ]] || { fail_assert "pem inspect failed"; return; }
    local pem_out=$OUT
    run_inspect eq-der "$FIX/main.der"
    local der_out=$OUT
    [[ $RC == 0 ]] || { fail_assert "der inspect failed"; return; }
    head -n1 "$pem_out" | grep -Fxq 'Encoding: PEM' \
        || { fail_assert "PEM run did not report Encoding: PEM"; return; }
    head -n1 "$der_out" | grep -Fxq 'Encoding: DER' \
        || { fail_assert "DER run did not report Encoding: DER"; return; }
    tail -n +2 "$pem_out" > "$WORK/eq.pem.rest"
    tail -n +2 "$der_out" > "$WORK/eq.der.rest"
    cmp -s "$WORK/eq.pem.rest" "$WORK/eq.der.rest" \
        || { fail_assert $'PEM/DER outputs differ beyond the Encoding line:\n'"$(diff -u "$pem_out" "$der_out" | head -30)"; return; }
    # the tail contains subject, issuer, both dates, fingerprint and Note
    grep -Fq 'Subject: ' "$WORK/eq.pem.rest" \
        && grep -Fq 'Issuer: ' "$WORK/eq.pem.rest" \
        && grep -Fq 'Not Before: ' "$WORK/eq.pem.rest" \
        && grep -Fq 'Not After: ' "$WORK/eq.pem.rest" \
        && grep -Fq 'SHA-256 Fingerprint: ' "$WORK/eq.pem.rest" \
        && grep -Fq "$NOTE" "$WORK/eq.pem.rest" \
        || { fail_assert "success output is missing a required field"; return; }
}

# Encoding is decided by content, never by the file name/extension.
case_pem_with_der_extension() {
    cp "$FIX/main.pem" "$WORK/mislabeled.der"
    run_inspect pem-as-der "$WORK/mislabeled.der"
    expect_rc 0 && expect_stdout_file "$EXP/main.out"
}
case_der_with_pem_extension() {
    cp "$FIX/main.der" "$WORK/mislabeled.pem"
    run_inspect der-as-pem "$WORK/mislabeled.pem"
    expect_rc 0 && expect_stdout_file "$WORK/exp-main.der.out"
}

# Whitespace (spaces, tabs, blank lines, CRLF) before and after the PEM
# block is fine.
case_pem_padding_lf() {
    {
        printf '  \t \n'
        printf '\n\t\n'
        cat "$FIX/main.pem"
        printf '\n  \t\n'
        printf '   '          # trailing spaces without final newline
    } > "$WORK/padding-lf.pem"
    run_inspect pem-padding-lf "$WORK/padding-lf.pem"
    expect_rc 0 && expect_stdout_file "$EXP/main.out"
}
case_pem_padding_crlf() {
    {
        printf '\r\n  \t\r\n'
        sed -e 's/$/\r/' "$FIX/main.pem"
        printf '\r\n\t \r\n  \r\n'
    } > "$WORK/padding-crlf.pem"
    run_inspect pem-padding-crlf "$WORK/padding-crlf.pem"
    expect_rc 0 && expect_stdout_file "$EXP/main.out"
}
case_pem_final_newline_optional() {
    # A complete PEM block without any trailing newline is valid.
    printf '%s' "$(cat "$FIX/main.pem")" > "$WORK/no-final-newline.pem"
    run_inspect pem-no-final-newline "$WORK/no-final-newline.pem"
    expect_rc 0 && expect_stdout_file "$EXP/main.out"
}

# Reading success is not a trust decision: expired and self-signed certs are
# still displayed in full with exit code 0.
case_expired_pem() {
    run_inspect expired-pem "$FIX/expired.pem"
    expect_rc 0 && expect_stdout_file "$EXP/expired.out"
}
case_expired_der() {
    run_inspect expired-der "$FIX/expired.der"
    expect_rc 0 && expect_stdout_file "$WORK/exp-expired.der.out"
}
case_expired_dates_shown() {
    run_inspect expired-dates "$FIX/expired.pem"
    [[ $RC == 0 ]] || { fail_assert "expired cert rejected"; return; }
    expect_stdout_contains 'Not Before: 2000-01-01T00:00:00Z' \
        && expect_stdout_contains 'Not After: 2001-01-01T00:00:00Z'
}
case_selfsigned_pem() {
    run_inspect selfsigned-pem "$FIX/root.pem"
    [[ $RC == 0 ]] || { fail_assert "self-signed cert rejected"; return; }
    expect_stdout_contains 'Encoding: PEM' \
        && expect_stdout_contains 'Subject: C=CN, O=示例科技有限公司, OU=研发部, CN=中文示例证书' \
        && expect_stdout_contains "$NOTE" \
        && expect_stdout_linecount 7
    local subj issr
    subj=$(sed -n 's/^Subject: //p' "$OUT")
    issr=$(sed -n 's/^Issuer: //p' "$OUT")
    [[ -n "$subj" && "$subj" == "$issr" ]] \
        || { fail_assert "self-signed cert should have Subject == Issuer"; return; }
    grep -Eq '^SHA-256 Fingerprint: ([0-9A-F]{2}:){31}[0-9A-F]{2}$' "$OUT" \
        || { fail_assert "fingerprint line malformed"; return; }
    # both validity fields present in UTC form
    grep -Eq '^Not Before: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z$' "$OUT" \
        && grep -Eq '^Not After: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z$' "$OUT" \
        || { fail_assert "validity fields missing or non-UTC"; return; }
}
case_selfsigned_der() {
    run_inspect selfsigned-der "$FIX/root.der"
    expect_rc 0
    expect_stdout_contains 'Encoding: DER'
    expect_stdout_contains "$NOTE"
}

# --- cases: exactly-one-certificate boundary ----------------------------------

# Shared checks for every "invalid certificate content" failure.
expect_invalid_cert_failure() {  # $1 = path that must appear in stderr
    expect_rc 1 \
        && expect_stdout_empty \
        && expect_stderr_contains 'invalid certificate' \
        && expect_stderr_contains "$1"
}

case_two_pem_blocks() {
    cat "$FIX/main.pem" "$FIX/second.pem" > "$WORK/two-blocks.pem"
    run_inspect two-blocks "$WORK/two-blocks.pem"
    expect_invalid_cert_failure "$WORK/two-blocks.pem"
}
case_two_pem_blocks_no_trailing_newline() {
    # second block with no final newline must still be detected
    { cat "$FIX/main.pem"; printf '%s' "$(cat "$FIX/second.pem")"; } > "$WORK/two-blocks-nonewline.pem"
    run_inspect two-blocks-nonewline "$WORK/two-blocks-nonewline.pem"
    expect_invalid_cert_failure "$WORK/two-blocks-nonewline.pem"
}
case_text_before_block() {
    { printf 'this is not a certificate\n'; cat "$FIX/main.pem"; } \
        > "$WORK/text-before.pem"
    run_inspect text-before "$WORK/text-before.pem"
    expect_invalid_cert_failure "$WORK/text-before.pem"
}
case_text_after_block() {
    { cat "$FIX/main.pem"; printf 'extra text after the block\n'; } \
        > "$WORK/text-after.pem"
    run_inspect text-after "$WORK/text-after.pem"
    expect_invalid_cert_failure "$WORK/text-after.pem"
}
case_pem_garbage_body() {
    cat > "$WORK/garbage-body.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
@@@@@@@@@@@@@@@@@@@@@@@@@@@@
-----END CERTIFICATE-----
EOF
    run_inspect garbage-body "$WORK/garbage-body.pem"
    expect_invalid_cert_failure "$WORK/garbage-body.pem"
}
case_pem_body_not_a_cert() {
    # Valid base64 and valid markers, but the payload is not a certificate.
    {
        echo '-----BEGIN CERTIFICATE-----'
        head -c 60 "$FIX/main.der" | base64 -w0; echo
        echo '-----END CERTIFICATE-----'
    } > "$WORK/body-not-cert.pem"
    run_inspect body-not-cert "$WORK/body-not-cert.pem"
    expect_invalid_cert_failure "$WORK/body-not-cert.pem"
}

case_der_then_second_cert() {
    cat "$FIX/main.der" "$FIX/second.der" > "$WORK/der-two-certs.der"
    run_inspect der-two-certs "$WORK/der-two-certs.der"
    expect_invalid_cert_failure "$WORK/der-two-certs.der"
}

# DER gets no textual-whitespace allowance: even one extra byte after the
# complete certificate must be rejected (whitespace or otherwise).
der_trailing_case() {  # invoked as a case body via closure over $BYTE/$LABEL
    { cat "$FIX/main.der"; printf "$BYTE"; } > "$WORK/der-trail-$LABEL.der"
    run_inspect "der-trail-$LABEL" "$WORK/der-trail-$LABEL.der"
    expect_invalid_cert_failure "$WORK/der-trail-$LABEL.der"
}

case_empty_file() {
    : > "$WORK/empty"
    run_inspect empty "$WORK/empty"
    expect_invalid_cert_failure "$WORK/empty"
}
case_whitespace_only_spaces() {
    printf '   \n\t \n  \t \n' > "$WORK/ws-spaces"
    run_inspect ws-spaces "$WORK/ws-spaces"
    expect_invalid_cert_failure "$WORK/ws-spaces"
}
case_whitespace_only_crlf() {
    printf '\r\n  \t\r\n\r\n' > "$WORK/ws-crlf"
    run_inspect ws-crlf "$WORK/ws-crlf"
    expect_invalid_cert_failure "$WORK/ws-crlf"
}

case_pem_truncated_body() {
    local len
    len=$(wc -c < "$FIX/main.pem")
    head -c $((len * 2 / 3)) "$FIX/main.pem" > "$WORK/pem-truncated.pem"
    run_inspect pem-truncated "$WORK/pem-truncated.pem"
    expect_invalid_cert_failure "$WORK/pem-truncated.pem"
}
case_pem_missing_end_marker() {
    sed '/^-----END CERTIFICATE-----$/d' "$FIX/main.pem" \
        > "$WORK/pem-no-end.pem"
    run_inspect pem-no-end "$WORK/pem-no-end.pem"
    expect_invalid_cert_failure "$WORK/pem-no-end.pem"
}

case_public_key_only() {
    run_inspect public-key "$FIX/public-key.pem"
    expect_invalid_cert_failure "$FIX/public-key.pem"
}
case_private_key_only() {
    run_inspect private-key "$FIX/private-key.pem"
    expect_invalid_cert_failure "$FIX/private-key.pem"
}

case_plain_text() {
    printf 'this is definitely not a certificate\n' > "$WORK/plain.txt"
    run_inspect plain-text "$WORK/plain.txt"
    expect_invalid_cert_failure "$WORK/plain.txt"
}

case_missing_file() {
    run_inspect missing "$WORK/does-not-exist.bin"
    expect_rc 1 \
        && expect_stdout_empty \
        && expect_stderr_contains 'failed to read file' \
        && expect_stderr_contains "$WORK/does-not-exist.bin"
}

# --- run ----------------------------------------------------------------------

t 'pem: full expected output incl all fields and Note'      case_pem_ok
t 'der: full expected output incl all fields and Note'      case_der_ok
t 'pem and der differ only in Encoding, fingerprint equal'  case_pem_der_equivalence
t 'pem content named .der is reported as PEM'               case_pem_with_der_extension
t 'der content named .pem is reported as DER'               case_der_with_pem_extension
t 'pem tolerates spaces/tabs/blank lines around block'      case_pem_padding_lf
t 'pem tolerates CRLF around and inside the file'           case_pem_padding_crlf
t 'pem without a trailing newline is accepted'              case_pem_final_newline_optional
t 'expired pem is shown in full with rc 0'                  case_expired_pem
t 'expired der is shown in full with rc 0'                  case_expired_der
t 'expired cert shows its fixed validity window'            case_expired_dates_shown
t 'self-signed pem is shown in full with rc 0 and Note'     case_selfsigned_pem
t 'self-signed der is shown with rc 0 and Note'             case_selfsigned_der
t 'pem with a second certificate block is rejected'         case_two_pem_blocks
t 'second pem block without trailing newline is rejected'   case_two_pem_blocks_no_trailing_newline
t 'non-whitespace text before pem block is rejected'        case_text_before_block
t 'non-whitespace text after pem block is rejected'         case_text_after_block
t 'pem block with garbage base64 body is rejected'          case_pem_garbage_body
t 'pem block whose payload is not a cert is rejected'       case_pem_body_not_a_cert
t 'der followed by another cert is rejected'                case_der_then_second_cert

# trailing bytes after a complete DER certificate
for spec in 'space: ' 'tab:\t' 'lf:\n' 'cr:\r' 'letter:A' 'nul:\x00' '0xff:\xff'; do
    LABEL=${spec%%:*}
    BYTE=${spec#*:}
    t "der plus one trailing byte ($LABEL) is rejected" der_trailing_case
done

t 'empty file is rejected'                                  case_empty_file
t 'whitespace-only file (spaces/tabs/lf) is rejected'       case_whitespace_only_spaces
t 'whitespace-only file (crlf) is rejected'                 case_whitespace_only_crlf
t 'truncated pem body is rejected'                          case_pem_truncated_body
t 'pem without END marker is rejected'                      case_pem_missing_end_marker
t 'public key only is rejected'                             case_public_key_only
t 'private key only is rejected'                            case_private_key_only
t 'plain text without any marker is rejected'               case_plain_text

# truncated DER at several cut points
der_len=$(wc -c < "$FIX/main.der")
for cut in 1 10 50 $((der_len / 2)) $((der_len - 1)); do
    make_trunc_der() {
        head -c "$cut" "$FIX/main.der" > "$WORK/der-cut-$cut.der"
        run_inspect "der-cut-$cut" "$WORK/der-cut-$cut.der"
        expect_invalid_cert_failure "$WORK/der-cut-$cut.der"
    }
    t "truncated der (first $cut of $der_len bytes) is rejected" make_trunc_der
done

t 'missing file: rc 1, empty stdout, path in stderr'        case_missing_file

# --- summary ------------------------------------------------------------------

echo "------------------------------------------------------------------------"
echo "$PASS passed, $FAIL failed"
if (( FAIL > 0 )); then
    printf 'failed cases:\n'
    for name in "${FAILED_NAMES[@]}"; do printf '  - %s\n' "$name"; done
    exit 1
fi
exit 0
