#!/bin/sh
# Prepare the regression-test certificate fixtures from the committed PEM
# samples.
#
# Usage: prepare_fixtures.sh <source-fixtures-dir> <prepared-fixtures-dir>
#
# Only the PEM samples (*.pem) are committed to the repository. The
# regression cases that feed DER files and that derive the expected
# fingerprints need the exact DER bytes too. Those are prepared offline at
# build (and test) time from the PEM samples themselves: for every
# certificate sample listed in CERT_STEMS, the body of its single
# CERTIFICATE PEM block is base64-decoded and written as <stem>.der. The
# DER bytes are therefore byte-for-byte identical to the PEM body of the
# one, original certificate -- no key is generated, no certificate is
# re-signed, and names, validity windows and signatures never change. The
# deliberately anomalous inputs (the impossible-date certificate still
# decodes to DER like every other certificate; the PEM-only files carrying
# a trailing NUL byte or a second certificate in one block body, plus the
# key-only samples) are copied verbatim and never decoded, so the content
# checks keep rejecting them.
#
# A missing or unreadable PEM sample, a malformed PEM envelope, or a body
# whose base64 text does not decode COMPLETELY and canonically is a fatal
# error: this script names the sample and the reason, exits nonzero and
# leaves no prepared directory behind, so no case can ever run against an
# empty DER file or an empty expected fingerprint.
#
# Requirements: a POSIX shell, coreutils (tr/sed/grep/awk/base64/cmp/mktemp)
# and cp/rm/mkdir/mv. No network, no Python, no OpenSSL and no system trust
# store are involved.

set -u

SRC=$1
OUT=$2

if [ "$#" -ne 2 ]; then
    echo "prepare_fixtures: usage: $0 <source-fixtures-dir> <prepared-fixtures-dir>" >&2
    exit 2
fi
if [ -z "$SRC" ] || [ -z "$OUT" ]; then
    echo "prepare_fixtures: fixture directories must not be empty" >&2
    exit 2
fi
if [ ! -d "$SRC" ]; then
    echo "prepare_fixtures: source fixture directory '$SRC' does not exist or is not a directory" >&2
    exit 1
fi
if [ "$SRC" = "$OUT" ]; then
    echo "prepare_fixtures: refusing to prepare in place: source and output directories are both '$SRC'" >&2
    exit 2
fi

# Every committed certificate PEM that has a corresponding DER case. These
# are decoded; everything else found as *.pem is copied verbatim.
CERT_STEMS='
valid
badsign
expired
marker
names
longoid
ctrlchars
namesenc_utf8
namesenc_bmp
namesenc_universal
nameenc_cross
nameenc_nul
nameenc_supplementary
namebad_bmp
namebad_universal
century
mixedyears
generalized
reverseorder
baddate
ec
ec_badsign
ec_badsign_inner
'

TMP=$(mktemp -d "${TMPDIR:-/tmp}/trustpeek-fixtures.XXXXXX") || {
    echo "prepare_fixtures: cannot create temporary directory" >&2
    exit 1
}
STAGE=$OUT.stage

cleanup_tmp() {
    rm -rf "$TMP"
}
die() {
    echo "prepare_fixtures: $*" >&2
    rm -rf "$STAGE"
    cleanup_tmp
    exit 1
}
trap 'cleanup_tmp' 0
trap 'rm -rf "$STAGE"; cleanup_tmp; exit 130' 1 2 3 15

rm -rf "$STAGE" || die "cannot remove stale staging directory '$STAGE'"
mkdir -p "$STAGE" || die "cannot create staging directory '$STAGE'"

# Copy every committed PEM sample byte-for-byte. The anomalous one-block
# bodies (trailing NUL / second certificate) and the key-only inputs must
# reach the tests unchanged; they are never decoded here.
pem_count=0
for pem in "$SRC"/*.pem; do
    [ -e "$pem" ] || die "no PEM samples (*.pem) found in '$SRC'"
    [ -f "$pem" ] || die "PEM sample '$pem' is not a regular file"
    [ -r "$pem" ] || die "PEM sample '$pem' exists but is not readable"
    cp -- "$pem" "$STAGE/" || die "cannot copy PEM sample '$pem'"
    pem_count=$((pem_count + 1))
done
[ "$pem_count" -gt 0 ] || die "no PEM samples (*.pem) found in '$SRC'"

# Decode one committed certificate PEM ($1 = stem) into $STAGE/<stem>.der,
# asserting every precondition that makes the DER trustworthy:
#   * exactly one BEGIN/END CERTIFICATE marker pair;
#   * nothing but whitespace outside the block;
#   * a non-empty base64 body that decodes completely (GNU coreutils and
#     busybox base64 both reject a truncated final quantum or non-alphabet
#     bytes);
#   * canonical encoding: re-encoding the decoded bytes must reproduce the
#     body text exactly, so no silently ignored extra alphabet characters
#     (e.g. a trailing fifth character of a quantum) can hide excess bytes.
# The impossible-date certificate is included here on purpose: its PEM body
# decodes to complete DER bytes; its invalidity is certificate CONTENT that
# only `trustpeek inspect` must reject, not a preparation error. The two
# malformed-name certificates (an odd-length BMPString and a
# UniversalString whose length is not a multiple of four) are the same: the
# bytes are complete, canonical DER that decode cleanly here, and only
# inspect's certificate parsing must reject them as invalid content.
# ec_badsign_inner is complete canonical DER too: its outer X.509 structure
# and signatureValue BIT STRING are whole, even though the DER SEQUENCE
# inside that BIT STRING is missing one of the two INTEGERs ECDSA requires.
# That is signature CONTENT inspect deliberately does not inspect (it
# never verifies signatures), so this file must decode here exactly like
# any other complete certificate.
prepare_cert_der() {
    stem=$1
    pem="$SRC/$stem.pem"
    norm="$TMP/$stem.normalized"
    body="$TMP/$stem.body"
    err="$TMP/$stem.err"
    der="$STAGE/$stem.der"
    reencoded="$TMP/$stem.reencoded"

    [ -f "$pem" ] || die "required PEM sample '$pem' is missing or not a regular file"
    [ -r "$pem" ] || die "required PEM sample '$pem' is not readable"

    # CRLF is accepted PEM whitespace and carries no base64 meaning.
    if ! tr -d '\r' < "$pem" > "$norm" 2>"$err"; then
        die "cannot read PEM sample '$pem': $(cat "$err")"
    fi

    begin_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$norm" 2>/dev/null || true)
    end_count=$(grep -c '^-----END CERTIFICATE-----$' "$norm" 2>/dev/null || true)
    [ "$begin_count" = 1 ] ||
        die "'$pem': expected exactly one '-----BEGIN CERTIFICATE-----' marker, found ${begin_count:-0}"
    [ "$end_count" = 1 ] ||
        die "'$pem': expected exactly one '-----END CERTIFICATE-----' marker, found ${end_count:-0}"

    outside=$(awk '
        /^-----BEGIN CERTIFICATE-----$/ { in_block = 1; next }
        /^-----END CERTIFICATE-----$/ { in_block = 0; next }
        in_block { next }
        { print }' "$norm" | tr -d '[:space:]')
    [ -z "$outside" ] ||
        die "'$pem': non-whitespace content outside the single CERTIFICATE PEM block"

    if ! sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p' "$norm" |
            sed '1d;$d' | tr -d '[:space:]' > "$body" 2>"$err"; then
        die "'$pem': cannot extract the PEM body: $(cat "$err")"
    fi
    [ -s "$body" ] || die "'$pem': the CERTIFICATE PEM block has an empty body"

    if ! base64 -d < "$body" > "$der" 2>"$err"; then
        die "'$pem': PEM body base64 does not decode completely: $(tr '\n' ' ' < "$err")"
    fi
    [ -s "$der" ] || die "'$pem': PEM body decoded to an empty DER file"

    # Canonical re-encoding: strip the 76-column wrapping GNU base64 adds
    # (busybox emits a single line); both must equal the extracted body.
    if ! base64 "$der" 2>"$err" | tr -d '\n' > "$reencoded"; then
        die "'$pem': cannot re-encode decoded DER for verification: $(cat "$err")"
    fi
    cmp -s "$reencoded" "$body" ||
        die "'$pem': base64 body is not the exact, complete encoding of one DER object (trailing or non-canonical base64 text after the certificate)"
}

for stem in $CERT_STEMS; do
    prepare_cert_der "$stem"
done

# Publish atomically so a concurrent or interrupted run never exposes a
# half-populated fixture directory to the tests.
mkdir -p "$(dirname "$OUT")" || die "cannot create output parent directory '$(dirname "$OUT")'"
rm -rf "$OUT" || die "cannot replace stale prepared fixture directory '$OUT'"
mv "$STAGE" "$OUT" || die "cannot publish prepared fixtures to '$OUT'"

echo "prepare_fixtures: prepared $pem_count PEM samples and the DER copies in '$OUT'"
