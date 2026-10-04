#!/usr/bin/env bash
#
# Regenerate the deterministic certificates used by run_tests.sh.
#
# Layout:
#   root.*    self-signed CA, generated once (like the keys) and then reused;
#             serves as the "self-signed certificate" test case
#   main.*    leaf issued by root with a Chinese DN and fixed validity dates,
#             serial 01; reproduces byte for byte on every run
#   second.*  distinct leaf (own key), serial 02
#   expired.* leaf with notBefore 2000 / notAfter 2001, serial 03
#
# Stability guarantees:
#   - private keys and the self-signed root are created once and reused;
#   - leaf serials come from a reset serial file and validity dates are fixed;
#   - DNs come from static config files with a fixed attribute order;
#   - signatures use deterministic PKCS#1 v1.5 padding.
#
# Re-running the script (OpenSSL 3.x) reproduces every leaf byte for byte, so
# the checked-in files and expected outputs stay in sync. No network access or
# system trust store is involved.
set -euo pipefail

OPENSSL=${OPENSSL:-openssl}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FIX="$SCRIPT_DIR/fixtures"
EXP="$SCRIPT_DIR/expected"
mkdir -p "$FIX" "$EXP"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

# --- OpenSSL configuration ---------------------------------------------------

cat > root-req.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
utf8 = yes
x509_extensions = v3_root

[dn]
C = CN
O = 示例科技有限公司
OU = 研发部
CN = 中文示例证书

[v3_root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > leaf-main-req.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
utf8 = yes

[dn]
C = CN
O = 示例科技有限公司
OU = 研发部
CN = 中文示例证书
EOF

cat > leaf-expired-req.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
utf8 = yes

[dn]
C = CN
O = trustpeek test
CN = expired.example
EOF

# Minimal CA configuration. Policy attribute order is also the order the CA
# emits RDNs in, so it mirrors the [dn] sections above.
cat > ca.cnf <<'EOF'
[ca]
default_ca = CA_default

[CA_default]
dir = ./ca
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir/newcerts
default_md = sha256
policy = policy_any
email_in_dn = no
unique_subject = no
x509_extensions = v3_leaf

[policy_any]
countryName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional

[v3_leaf]
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

# --- helpers -----------------------------------------------------------------

ensure_key() {  # $1 = key path
    if [[ ! -s "$1" ]]; then
        "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
            -out "$1" 2>/dev/null
    fi
}

reset_ca() {
    rm -rf ca
    mkdir -p ca/newcerts
    : > ca/index.txt
}

# Issue a leaf from a CSR through the committed root. Dates are OpenSSL's
# YYMMDDHHMMSSZ form; serial comes from ca/serial. Output is a pure PEM block.
issue_leaf() {  # $1=key(csr) $2=req-cnf $3=serial(hex) $4=start $5=end $6=out
    reset_ca
    echo "$3" > ca/serial
    "$OPENSSL" req -new -key "$1" -out csr.pem -config "$2" 2>/dev/null
    "$OPENSSL" ca -batch -utf8 -config ca.cnf \
        -cert "$FIX/root.pem" -keyfile "$FIX/root.key.pem" \
        -in csr.pem -out issued.pem \
        -startdate "$4" -enddate "$5" >/dev/null 2>&1
    "$OPENSSL" x509 -in issued.pem -out "$6"
}

sha256_colon() {  # SHA-256 of a file as AA:BB:... uppercase
    local hex
    hex=$("$OPENSSL" dgst -sha256 -hex "$1" | sed 's/^.*= *//;s/[[:space:]]//g')
    echo "$hex" | tr 'a-f' 'A-F' | sed 's/\(..\)/\1:/g; s/:$//'
}

write_expected() {  # $1=der $2=subject $3=issuer $4=not-before $5=not-after $6=out
    {
        echo "Encoding: PEM"
        echo "Subject: $2"
        echo "Issuer: $3"
        echo "Not Before: $4"
        echo "Not After: $5"
        echo "SHA-256 Fingerprint: $(sha256_colon "$1")"
        echo "Note: this output displays certificate information only; reading the file successfully does not verify the signature or establish trust."
    } > "$6"
}

ROOT_DN="C=CN, O=示例科技有限公司, OU=研发部, CN=中文示例证书"

# --- self-signed root (created once) -----------------------------------------

ensure_key "$FIX/root.key.pem"
if [[ ! -s "$FIX/root.pem" ]]; then
    "$OPENSSL" req -x509 -new -key "$FIX/root.key.pem" \
        -config root-req.cnf -set_serial 1 -days 3650 \
        -out "$FIX/root.pem" 2>/dev/null
fi
"$OPENSSL" x509 -in "$FIX/root.pem" -outform DER -out "$FIX/root.der"

# --- main leaf: Chinese DN, fixed validity, serial 01 ------------------------

ensure_key "$FIX/main.key.pem"
issue_leaf "$FIX/main.key.pem" leaf-main-req.cnf 01 \
    261004164027Z 361001164027Z "$FIX/main.pem"
"$OPENSSL" x509 -in "$FIX/main.pem" -outform DER -out "$FIX/main.der"
write_expected "$FIX/main.der" "$ROOT_DN" "$ROOT_DN" \
    "2026-10-04T16:40:27Z" "2036-10-01T16:40:27Z" "$EXP/main.out"

# --- second leaf: different key, serial 02 -----------------------------------

ensure_key "$FIX/second.key.pem"
issue_leaf "$FIX/second.key.pem" leaf-main-req.cnf 02 \
    261004164027Z 361001164027Z "$FIX/second.pem"
"$OPENSSL" x509 -in "$FIX/second.pem" -outform DER -out "$FIX/second.der"

# --- expired leaf: valid structure, validity 2000-2001, serial 03 ------------

ensure_key "$FIX/expired.key.pem"
issue_leaf "$FIX/expired.key.pem" leaf-expired-req.cnf 03 \
    000101000000Z 010101000000Z "$FIX/expired.pem"
"$OPENSSL" x509 -in "$FIX/expired.pem" -outform DER -out "$FIX/expired.der"
write_expected "$FIX/expired.der" \
    "C=CN, O=trustpeek test, CN=expired.example" "$ROOT_DN" \
    "2000-01-01T00:00:00Z" "2001-01-01T00:00:00Z" "$EXP/expired.out"

# --- non-certificate material ------------------------------------------------

"$OPENSSL" pkey -in "$FIX/main.key.pem" -pubout -out "$FIX/public-key.pem" 2>/dev/null
cp "$FIX/main.key.pem" "$FIX/private-key.pem"

echo "fixtures generated in $FIX"
