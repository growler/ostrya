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
#
# Three more server leaves each fail one check and pass the others, so a test
# of the TLS verification bypass states which check the bypass dropped:
#
#   server-othername  Signed by the fixture authority, valid, and carrying a
#                     subjectAltName that covers neither `localhost` nor
#                     `127.0.0.1`. The host name check is the only failure.
#   server-untrusted  Carrying the same subjectAltName as `server`, valid, and
#                     signed by a second authority. The chain is the only
#                     failure. That authority signs this one leaf and is not
#                     committed, because nothing verifies against it.
#   server-expired    Signed by the fixture authority, carrying the same
#                     subjectAltName as `server`, and out of validity since
#                     2020. Expiry is the only failure. LibreSSL's `x509 -req`
#                     refuses a `-days` value below 1, so this leaf is signed
#                     through `openssl ca`, which takes an explicit
#                     `-startdate` and `-enddate`.
#
# Three more copies of the client key carry the same key under an encryption
# the fetcher has to read or refuse:
#
#   client.key.enc.pem     PKCS#8 under PBES2 with AES-256-CBC. The fetcher
#                          decrypts this one with the passphrase below.
#   client.key.legacy.pem  The legacy OpenSSL traditional PEM, which carries a
#                          `Proc-Type: 4,ENCRYPTED` header. The fetcher refuses
#                          this form and names the conversion.
#   client.key.pbes1.pem   PKCS#8 under PBES1 with pbeWithMD5AndDES-CBC. The
#                          fetcher refuses this form and names PBES1.
#
# All three take the passphrase `ostrya test passphrase`, which the tests
# supply.
#
# `ca.pem`, `server.pem`, and `client.pem` were committed before the subject
# handling below was written, so all three carry the common name `ostrya test`.
# A full re-run gives each certificate a subject of its own. No test asserts a
# subject: the client verifies against the authority's key and holds the leaf
# to its subjectAltName, so the replacement changes nothing any test reads.

set -euo pipefail

cd "$(dirname "$0")"

days=36500

# The passphrase of the three encrypted copies of the client key. The tests
# hold the same text.
passphrase='ostrya test passphrase'

# The configuration every invocation reads. LibreSSL's `req` takes the subject
# from the `[dn]` section and ignores `-subj`, while GNU OpenSSL lets `-subj`
# win, so a `-subj` on the command line gives the two openssls two different
# subjects. The subject comes from `[dn]` alone and this function rewrites that
# section before each `req`, so either openssl writes the same subjects. The
# extension sections are the same under every subject.
write_cnf() {
    cat > openssl.cnf <<CNF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = $1

[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1

[server_othername]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:not-the-test-host.invalid

[client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:ostrya-test-client
CNF
}

# `openssl ca` takes its settings from a section named by `[ca] default_ca`,
# and the section name `ca` is already the extension section of the authority
# certificate above. A second file keeps the two apart.
cat > backdate.cnf <<'EOF'
[ca]
default_ca = backdate

[backdate]
new_certs_dir = backdate.db
database = backdate.db/index.txt
serial = backdate.db/serial
default_md = sha256
policy = anything
email_in_dn = no
unique_subject = no

[anything]
commonName = optional
countryName = optional
stateOrProvinceName = optional
organizationName = optional
organizationalUnitName = optional
EOF

# Some builds resolve the default configuration path relative to the working
# directory, so point every invocation at the config written above.
export OPENSSL_CONF="$PWD/openssl.cnf"

# The certificate authority.
write_cnf "ostrya test ca"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key.pem
openssl req -new -x509 -sha256 -key ca.key.pem -out ca.pem -days "$days" \
    -extensions ca -config openssl.cnf

# The second authority. It signs `server-untrusted` and is then discarded. Its
# subject differs from the fixture authority's, so the untrusted leaf names an
# issuer no anchor the tests hold carries.
write_cnf "ostrya test other ca"
openssl ecparam -name prime256v1 -genkey -noout -out other-ca.key.pem
openssl req -new -x509 -sha256 -key other-ca.key.pem -out other-ca.pem \
    -days "$days" -extensions ca -config openssl.cnf

# The server and client leaves, both signed by the authority.
for leaf in server client; do
    write_cnf "ostrya test $leaf"
    openssl ecparam -name prime256v1 -genkey -noout -out "$leaf.key.pem"
    openssl req -new -key "$leaf.key.pem" -config openssl.cnf -out "$leaf.csr"
    openssl x509 -req -sha256 -in "$leaf.csr" -CA ca.pem -CAkey ca.key.pem \
        -set_serial "0x$(openssl rand -hex 8)" -days "$days" \
        -extensions "$leaf" -extfile openssl.cnf -out "$leaf.pem"
    rm -f "$leaf.csr"
done

# The leaf whose name covers neither address the tests reach.
write_cnf "ostrya test other name"
openssl ecparam -name prime256v1 -genkey -noout -out server-othername.key.pem
openssl req -new -key server-othername.key.pem -config openssl.cnf \
    -out server-othername.csr
openssl x509 -req -sha256 -in server-othername.csr -CA ca.pem \
    -CAkey ca.key.pem -set_serial "0x$(openssl rand -hex 8)" -days "$days" \
    -extensions server_othername -extfile openssl.cnf \
    -out server-othername.pem
rm -f server-othername.csr

# The leaf the second authority signed.
write_cnf "ostrya test untrusted"
openssl ecparam -name prime256v1 -genkey -noout -out server-untrusted.key.pem
openssl req -new -key server-untrusted.key.pem -config openssl.cnf \
    -out server-untrusted.csr
openssl x509 -req -sha256 -in server-untrusted.csr -CA other-ca.pem \
    -CAkey other-ca.key.pem -set_serial "0x$(openssl rand -hex 8)" \
    -days "$days" -extensions server -extfile openssl.cnf \
    -out server-untrusted.pem
rm -f server-untrusted.csr other-ca.pem other-ca.key.pem

# The leaf that is out of validity.
write_cnf "ostrya test expired"
mkdir -p backdate.db
: > backdate.db/index.txt
echo 01 > backdate.db/serial
openssl ecparam -name prime256v1 -genkey -noout -out server-expired.key.pem
openssl req -new -key server-expired.key.pem -config openssl.cnf \
    -out server-expired.csr
openssl ca -batch -notext -config backdate.cnf -cert ca.pem -keyfile ca.key.pem \
    -in server-expired.csr -out server-expired.pem \
    -startdate 20200101000000Z -enddate 20200201000000Z \
    -extensions server -extfile openssl.cnf
rm -rf server-expired.csr backdate.db

# The keys are stored in PKCS#8, which rustls-pemfile decodes.
for leaf in ca server client server-othername server-untrusted server-expired; do
    openssl pkcs8 -topk8 -nocrypt -in "$leaf.key.pem" -out "$leaf.key.pk8.pem"
    mv "$leaf.key.pk8.pem" "$leaf.key.pem"
done

# The encrypted copies of the client key. The first is PKCS#8 under PBES2 with
# AES-256-CBC, which the fetcher decrypts. The second is the legacy OpenSSL
# traditional PEM, which the fetcher refuses: `openssl ec` writes that form,
# and it carries the `Proc-Type: 4,ENCRYPTED` header the refusal reads.
openssl pkcs8 -topk8 -v2 aes-256-cbc -in client.key.pem \
    -out client.key.enc.pem -passout "pass:$passphrase"
openssl ec -in client.key.pem -aes256 -out client.key.legacy.pem \
    -passout "pass:$passphrase"

# The third copy is PKCS#8 under PBES1, which the fetcher refuses as well.
# PBES1 derives its key with PBKDF1, which GNU OpenSSL 3 holds in the legacy
# provider. LibreSSL carries no `-provider` option and reaches PBKDF1 without
# one. Both openssls write the same algorithm, pbeWithMD5AndDES-CBC.
pbes1_provider=()
if ! openssl version | grep -q LibreSSL; then
    pbes1_provider=(-provider legacy -provider default)
fi
openssl pkcs8 -topk8 -v1 PBE-MD5-DES -in client.key.pem \
    -out client.key.pbes1.pem -passout "pass:$passphrase" \
    "${pbes1_provider[@]}"

rm -f openssl.cnf backdate.cnf
echo "wrote ca.pem server.pem server.key.pem client.pem client.key.pem" \
    "client.key.enc.pem client.key.legacy.pem client.key.pbes1.pem" \
    "server-othername.pem server-othername.key.pem" \
    "server-untrusted.pem server-untrusted.key.pem" \
    "server-expired.pem server-expired.key.pem"
