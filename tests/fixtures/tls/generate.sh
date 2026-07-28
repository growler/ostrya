#!/usr/bin/env bash
#
# Test certificates for the fetcher tests.
#
# The fetcher's TLS path needs a server the test client can verify and a client
# certificate the test server can verify, so ALPN, HTTP/2, and mutual TLS are
# exercised over a real handshake. One certificate authority signs both leaves;
# the client trusts the CA through TrustRoots::Pem and the server verifies
# client certificates against the same CA.
#
# The certificates are committed, so this script runs only when they need to be
# replaced. Validity is 100 years: a fixture that expires turns into a test
# failure years later with no code change to explain it.
#
# Keys are ECDSA P-256, which the graviola crypto provider signs and verifies.
# The leaves carry subjectAltName (webpki ignores the common name) and the
# matching extendedKeyUsage.

set -euo pipefail

cd "$(dirname "$0")"

days=36500

cat > openssl.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
CN = ostrya test

[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1

[client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:ostrya-test-client
EOF

# Some builds resolve the default configuration path relative to the working
# directory, so point every invocation at the config written above.
export OPENSSL_CONF="$PWD/openssl.cnf"

# The certificate authority.
openssl ecparam -name prime256v1 -genkey -noout -out ca.key.pem
openssl req -new -x509 -sha256 -key ca.key.pem -out ca.pem -days "$days" \
    -subj "/CN=ostrya test ca" -extensions ca -config openssl.cnf

# The server and client leaves, both signed by the authority.
for leaf in server client; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$leaf.key.pem"
    openssl req -new -key "$leaf.key.pem" -subj "/CN=ostrya test $leaf" \
        -out "$leaf.csr"
    openssl x509 -req -sha256 -in "$leaf.csr" -CA ca.pem -CAkey ca.key.pem \
        -set_serial "0x$(openssl rand -hex 8)" -days "$days" \
        -extensions "$leaf" -extfile openssl.cnf -out "$leaf.pem"
    rm -f "$leaf.csr"
done

# The keys are stored in PKCS#8, which rustls-pemfile decodes.
for leaf in ca server client; do
    openssl pkcs8 -topk8 -nocrypt -in "$leaf.key.pem" -out "$leaf.key.pk8.pem"
    mv "$leaf.key.pk8.pem" "$leaf.key.pem"
done

rm -f openssl.cnf
echo "wrote ca.pem server.pem server.key.pem client.pem client.key.pem"
