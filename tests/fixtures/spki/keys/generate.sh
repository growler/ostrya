#!/usr/bin/env bash
#
# Key fixtures for the tests of the spki signature engine.
#
# Usage: OPENSSL=<path of OpenSSL 3> generate.sh
#
# The script writes RSA keys of the sizes that the tests use, an RSA key of
# three primes, an RSA-PSS key, and a test vector: a buffer and the signature
# of `openssl dgst -sha256 -sign` over it. The tests read these files and make
# no key. Each run makes new keys, so the files are committed, and the script
# runs only to replace them. It changes no other directory.
#
# OpenSSL 3 is necessary. LibreSSL cannot make a key of more than two primes.

set -euo pipefail
shopt -s inherit_errexit
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
O="${OPENSSL:-openssl}"

die() {
    echo "error: $*" >&2
    exit 1
}

# The OpenSSL build reads no configuration file. No step needs one.
export OPENSSL_CONF=/dev/null
version=$("$O" version) || die "cannot run '$O'"
[[ $version == "OpenSSL 3."* ]] || die "OpenSSL 3 is necessary, '$O' is '$version'"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Prints the number of bits of the modulus of the key file $1.
modulus_bits() {
    "$O" pkey -in "$1" -text -noout | sed -n '1s/^.*(\([0-9]*\) bit.*$/\1/p'
}

# The two-prime RSA keys, PKCS#8 PRIVATE KEY and PUBLIC KEY blocks. 2047 bits
# is outside the range of the engine by one bit. For the sizes 4097, 8193,
# and 16385 bits, OpenSSL 3.6.4 writes a key of one bit less, so 16386 bits
# is the smallest size above the range that it writes.
for bits in 1024 2047 2048 8192 16384 16386; do
    "$O" genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" -out "rsa-$bits.pem"
    [ "$(modulus_bits "rsa-$bits.pem")" = "$bits" ] ||
        die "rsa-$bits.pem has $(modulus_bits "rsa-$bits.pem") bits"
    "$O" pkey -in "rsa-$bits.pem" -pubout -out "rsa-$bits.pub.pem"
done
# The 2048-bit key as a PKCS#1 RSA PRIVATE KEY block.
"$O" pkey -in rsa-2048.pem -traditional -out rsa-2048.pkcs1.pem

# A key of three primes, in the PKCS#8 and the PKCS#1 form, and its public key.
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_primes:3 \
    -out rsa-3prime.pem
"$O" pkey -in rsa-3prime.pem -text -noout | grep -q '^prime3:' ||
    die "rsa-3prime.pem has no third prime"
"$O" pkey -in rsa-3prime.pem -traditional -out rsa-3prime.pkcs1.pem
"$O" pkey -in rsa-3prime.pem -pubout -out rsa-3prime.pub.pem

# An RSA-PSS key, key type id-RSASSA-PSS.
"$O" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out rsa-pss.pem
"$O" pkey -in rsa-pss.pem -pubout -out rsa-pss.pub.pem

# The test vector: RSA PKCS#1 v1.5 with SHA-256 over a fixed buffer.
printf 'ostrya spki RSA test vector\n' >vector.data
"$O" dgst -sha256 -sign rsa-2048.pem -out rsa-2048.vector.sig vector.data
[ "$("$O" dgst -sha256 -verify rsa-2048.pub.pem -signature rsa-2048.vector.sig \
    vector.data)" = "Verified OK" ] || die "openssl does not verify the test vector"

cat >MANIFEST <<EOF
# Key fixtures of the spki engine for the ostree Rust port, written by
# spki/keys/generate.sh. The keys are random, so a run gives new bytes.
openssl=$version
EOF

cp ./* "$SCRIPT_DIR/"
echo "wrote $SCRIPT_DIR"
