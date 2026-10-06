#!/bin/sh
# Prepare regression-test certificate data from the committed PEM samples.
#
# Usage: prepare_fixtures.sh <source-fixtures-dir> <staging-fixtures-dir>
#
# The repository ships every certificate sample as PEM (the single source of
# truth); the regression suite additionally needs the byte-identical DER form
# of the one-certificate samples -- both for the DER cases and to derive the
# expected SHA-256 fingerprints from. This script performs that preparation at
# build time, fully offline: each DER is produced by decoding the base64 body
# of the corresponding PEM and is therefore the exact raw bytes of the
# original certificate. Nothing is regenerated, re-signed or otherwise
# altered: the impossible-date certificate and the deliberately malformed
# single-block PEMs keep every anomalous byte.
#
# Preparation fails loudly instead of producing empty/placeholder data when a
# PEM sample is missing, unreadable or not one completely-decodable
# CERTIFICATE block.

set -u

SRC=${1:-}
DST=${2:-}

BASE64=${BASE64:-}
[ -n "$BASE64" ] || BASE64=$(command -v base64 2>/dev/null) || BASE64=

die() {
    echo "prepare_fixtures: $*" >&2
    exit 1
}

[ -n "$SRC" ] || die "usage: $0 <source-fixtures-dir> <staging-fixtures-dir>"
[ -n "$DST" ] || die "usage: $0 <source-fixtures-dir> <staging-fixtures-dir>"
[ -d "$SRC" ] ||
    die "sample source directory not found: $SRC"
[ -n "$BASE64" ] ||
    die "the 'base64' utility is required to decode PEM samples but was not found"

# Every <stem>.pem in this list must contain exactly one complete CERTIFICATE
# PEM block; its decoded body is written as <stem>.der. The two
# pem_body_trailing_* samples are intentionally not listed: their bodies hold
# more than one certificate and must be copied through unchanged so the
# content-error cases keep exercising them.
CERT_STEMS='
    baddate
    century
    ctrlchars
    expired
    generalized
    longoid
    marker
    mixedyears
    names
    reverseorder
    valid
'

mkdir -p "$DST" ||
    die "cannot create staging directory: $DST"

# Copy every committed sample verbatim (PEMs, key-only samples, malformed
# inputs). Derived DERs written below replace any stale copies afterwards, so
# they can never survive merely because an old file was copied.
cp -a "$SRC"/. "$DST"/ ||
    die "cannot copy samples from $SRC to $DST"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/trustpeek-fixtures.XXXXXX") ||
    die "cannot create temporary directory"
trap 'rm -rf "$TMP"' EXIT INT TERM

# Decode the single CERTIFICATE block of $SRC/<stem>.pem into
# $DST/<stem>.der, enforcing the PEM-integrity preconditions explicitly so a
# broken sample names itself and the reason instead of yielding an empty DER.
decode_cert_pem() {
    stem=$1
    pem=$SRC/$stem.pem
    norm=$TMP/$stem.normalized
    der=$DST/$stem.der
    der_tmp=$TMP/$stem.der

    [ -e "$pem" ] ||
        die "certificate sample missing: $pem (a PEM sample is required; DER files are derived at build time)"
    [ -f "$pem" ] ||
        die "certificate sample is not a regular file: $pem"
    [ -r "$pem" ] ||
        die "certificate sample is not readable: $pem"
    [ -s "$pem" ] ||
        die "certificate sample is empty: $pem"

    # CRLF line endings are acceptable; the base64 alphabet contains no CR.
    tr -d '\r' <"$pem" >"$norm" ||
        die "cannot read certificate sample: $pem"

    begin_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$norm")
    end_count=$(grep -c '^-----END CERTIFICATE-----$' "$norm")
    [ "$begin_count" -eq 1 ] ||
        die "$pem: expected exactly one '-----BEGIN CERTIFICATE-----' line, found $begin_count"
    [ "$end_count" -eq 1 ] ||
        die "$pem: expected exactly one '-----END CERTIFICATE-----' line, found $end_count"

    # Concatenate the raw lines between the marker pair (newlines are not part
    # of the base64 body).
    body=$(awk '
        /^-----BEGIN CERTIFICATE-----$/ { in_block = 1; next }
        /^-----END CERTIFICATE-----$/   { in_block = 0; next }
        in_block                        { printf "%s", $0 }
    ' "$norm")
    [ -n "$body" ] ||
        die "$pem: PEM block has an empty base64 body"

    # The body must be pure base64 with padding only at the very end.
    case "$body" in
        *[!A-Za-z0-9+/=]*)
            die "$pem: PEM block body contains characters outside the base64 alphabet"
            ;;
    esac
    core=${body%%=*}
    case "$core" in
        *=*) die "$pem: base64 padding '=' may only appear at the end of the body" ;;
    esac
    pads=$(printf '%s' "$body" | tr -cd '=' | wc -c | tr -d ' ')
    [ "$pads" -le 2 ] ||
        die "$pem: base64 body has $pads trailing '=' padding characters (at most 2 are valid)"
    len=$(printf '%s' "$body" | wc -c | tr -d ' ')
    [ $((len % 4)) -eq 0 ] ||
        die "$pem: base64 body length $len is not a multiple of 4 (truncated encoding)"

    # Decode the whole body; a tolerant decoder must not hide a damaged body,
    # so re-encode the decoded bytes and require the canonical base64 back
    # exactly. base64's wrapped output is unwrapped for the comparison.
    if ! printf '%s' "$body" | "$BASE64" -d >"$der_tmp" 2>"$TMP/$stem.decode-err"; then
        reason=$(tr '\n' ' ' <"$TMP/$stem.decode-err")
        die "$pem: PEM body could not be completely base64-decoded: $reason"
    fi
    [ -s "$der_tmp" ] ||
        die "$pem: decoded certificate body is empty"
    reencoded=$("$BASE64" <"$der_tmp" | tr -d '\n')
    [ "$reencoded" = "$body" ] ||
        die "$pem: PEM body did not decode cleanly (re-encoding the decoded bytes did not reproduce the original body)"

    rm -f "$der"
    cp "$der_tmp" "$der" ||
        die "cannot write derived DER sample: $der"
}

for stem in $CERT_STEMS; do
    decode_cert_pem "$stem"
done

# Sanity: none of the DERs the regression suite reads may be missing/empty.
for stem in $CERT_STEMS; do
    [ -s "$DST/$stem.der" ] ||
        die "internal error: derived DER sample missing or empty: $DST/$stem.der"
done

echo "Prepared regression certificate fixtures in $DST (DER decoded from the committed PEM samples)."
