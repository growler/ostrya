#!/usr/bin/env bash
#
# Test fixtures for the spki signature engine.
#
# Usage: generate.sh <key type>
#
# The script drives the `ostree` tool as a black box. It signs the commit of
# tests/fixtures/generated/archive/repo with a new key, writes a signed static
# delta and a signed summary, and puts the result in spki/<key type>/. Each run
# makes a new key, and ECDSA takes a random nonce for each signature, so a run
# cannot give the same bytes again. The fixtures are committed, and the script
# runs only to replace one key type. It changes no other directory.
#
# The commit carries two signatures. The first has a low s, the second has a
# high s (s > n/2). The tests read the s of each signature, so the order is
# part of the fixture.
#
# The tool verifies some blobs that no key signed. For this reason `openssl`
# verifies each signature again over the bytes that it signs.

set -euo pipefail
shopt -s inherit_errexit nullglob dotglob
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="$SCRIPT_DIR/../generated/archive/repo"
BRANCH=test/main
TRIES=64

die() {
    echo "error: $*" >&2
    exit 1
}

# One case for each key type. `order` is the order n of the curve in hex.
case "${1:-}" in
    p256)
        genkey=(genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1
            -pkeyopt ec_param_enc:named_curve)
        order=FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        ;;
    *)
        echo "usage: $0 <key type>, where the key type is p256" >&2
        exit 2
        ;;
esac
TYPE=$1
OUT="$SCRIPT_DIR/$TYPE"

# The checks before the script writes a file.
command -v ostree >/dev/null || die "the 'ostree' tool is not on PATH"
features=$(ostree --version)
grep -qx -- ' *- openssl' <<<"$features" && grep -qx -- ' *- sign-spki' <<<"$features" ||
    die "an spki-capable ostree build is needed (openssl and sign-spki in 'ostree --version')"
command -v openssl >/dev/null || die "the 'openssl' command is not on PATH"
command -v python3 >/dev/null || die "the 'python3' command is not on PATH"
[ -d "$ARCHIVE" ] || die "$ARCHIVE is missing: run tests/fixtures/generate.sh first"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# LibreSSL warns when it finds no configuration file. No step needs one.
export OPENSSL_CONF=/dev/null

# The helper reads the `ostree.sign.spki` blobs of an `a{sv}` file or of a
# signed superblock `(taya{sv})`. It writes each blob to <dir>/sig<i>.der, and
# for a superblock it writes the signed superblock bytes to <dir>/payload. It
# reads each blob as a strict DER ECDSA-Sig-Value and prints the s class of
# each blob, `low` or `high`, in blob order.
cat >"$WORK/sigs.py" <<'PY'
import sys

path, outdir, order = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)

def fail(msg):
    sys.exit(f"{path}: {msg}")

def offset_size(n):
    return 1 if n <= 0xFF else 2 if n <= 0xFFFF else 4

def read_offset(buf, pos, size):
    return int.from_bytes(buf[pos:pos + size], "little")

def align8(n):
    return (n + 7) & ~7

# The elements of a GVariant array of variable-size elements.
def elements(buf, align):
    if not buf:
        return []
    size = offset_size(len(buf))
    start_of_offsets = read_offset(buf, len(buf) - size, size)
    if (len(buf) - start_of_offsets) % size:
        fail("bad array framing")
    items, start = [], 0
    for pos in range(start_of_offsets, len(buf), size):
        end = read_offset(buf, pos, size)
        items.append(buf[start:end])
        start = align(end)
    return items

# The `ostree.sign.spki` blobs of an `a{sv}` dict.
def spki_blobs(buf):
    for entry in elements(buf, align8):
        size = offset_size(len(entry))
        key_end = read_offset(entry, len(entry) - size, size)
        if entry[:key_end] != b"ostree.sign.spki\0":
            continue
        variant = entry[align8(key_end):len(entry) - size]
        nul = variant.rindex(0)
        if variant[nul + 1:] != b"aay":
            fail("ostree.sign.spki is not an aay")
        return elements(variant[:nul], lambda n: n)
    fail("no ostree.sign.spki entry")

def s_class(der):
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        fail("bad DER SEQUENCE")
    pos, ints = 2, []
    for _ in range(2):
        if der[pos] != 0x02 or not 0 < der[pos + 1] < 0x80:
            fail("bad DER INTEGER")
        value = der[pos + 2:pos + 2 + der[pos + 1]]
        if len(value) != der[pos + 1] or value[0] & 0x80:
            fail("bad DER INTEGER")
        if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
            fail("DER INTEGER is not minimal")
        ints.append(int.from_bytes(value, "big"))
        pos += 2 + len(value)
    if pos != len(der):
        fail("trailing bytes after the DER SEQUENCE")
    r, s = ints
    if not (0 < r < order and 0 < s < order):
        fail("r or s out of range")
    return "high" if s > order // 2 else "low"

data = open(path, "rb").read()
if data.startswith(b"OSTSGNDT"):
    size = offset_size(len(data))
    payload_end = read_offset(data, len(data) - size, size)
    open(f"{outdir}/payload", "wb").write(data[8:payload_end])
    data = data[align8(payload_end):len(data) - size]
classes = []
for i, blob in enumerate(spki_blobs(data)):
    open(f"{outdir}/sig{i}.der", "wb").write(blob)
    classes.append(s_class(blob))
print(" ".join(classes))
PY

# Prints the s classes of the blobs in the file $1.
classify() {
    rm -rf "$WORK/blobs" && mkdir "$WORK/blobs"
    python3 "$WORK/sigs.py" "$1" "$WORK/blobs" "$order"
}

# Prints the s classes of the blobs in the file $1, after `openssl` verifies
# each blob over the file $2. Without $2, the data is the signed superblock
# payload.
verify() {
    local classes sig
    classes=$(classify "$1")
    for sig in "$WORK"/blobs/sig*.der; do
        [ "$(openssl dgst -sha256 -verify "$WORK/public.pem" -signature "$sig" \
            "${2:-$WORK/blobs/payload}")" = "Verified OK" ] ||
            die "openssl does not verify $sig of $1"
    done
    echo "$classes"
}

# The key pair.
openssl "${genkey[@]}" -out "$WORK/secret.pem"
[ "$(head -n1 "$WORK/secret.pem")" = "-----BEGIN PRIVATE KEY-----" ] ||
    die "openssl did not write a PKCS#8 PRIVATE KEY block"
openssl pkey -in "$WORK/secret.pem" -pubout -out "$WORK/public.pem"
B64=$(sed '1d;$d' "$WORK/secret.pem" | tr -d '\n')

REPO="$WORK/repo"
cp -a "$ARCHIVE" "$REPO"
C=$(cat "$REPO/refs/heads/$BRANCH")
OBJ="$REPO/objects/${C:0:2}/${C:2}.commit"
META="$REPO/objects/${C:0:2}/${C:2}.commitmeta"
sign() { ostree --repo="$REPO" sign -s spki --keys-file="$WORK/secret.pem" "$C"; }

# The commit signatures: one with a low s, then one with a high s. The tool
# appends each signature to the detached metadata.
for ((i = 1; ; i++)); do
    ((i <= TRIES)) || die "no low-s signature in $TRIES tries"
    rm -f "$META"
    sign
    classes=$(classify "$META")
    [ "$classes" = low ] && break
done
cp "$META" "$WORK/meta.low"
for ((i = 1; ; i++)); do
    ((i <= TRIES)) || die "no high-s signature in $TRIES tries"
    cp "$WORK/meta.low" "$META"
    sign
    classes=$(classify "$META")
    [ "$classes" = "low high" ] && break
done
commit_classes=$(verify "$META" "$OBJ")

# The delta from scratch, in the default layout of a superblock and parts.
ostree --repo="$REPO" static-delta generate --empty --to="$C" \
    --sign-type=spki --sign="$B64" >/dev/null
DELTA=$(ostree --repo="$REPO" static-delta list)
[ "$DELTA" = "$C" ] || die "unexpected static delta list: $DELTA"
[ "$(ostree --repo="$REPO" static-delta verify --sign-type=spki \
    --keys-file="$WORK/public.pem" "$DELTA")" = "Verification OK" ] ||
    die "the tool does not verify the static delta"
SUPERBLOCK=$(find "$REPO/deltas" -name superblock)
delta_class=$(verify "$SUPERBLOCK")
[[ $delta_class = low || $delta_class = high ]] ||
    die "the superblock does not hold one spki signature: '$delta_class'"

# The summary, after the delta.
ostree --repo="$REPO" summary -u --sign-type=spki --sign="$B64"
summary_class=$(verify "$REPO/summary.sig" "$REPO/summary")
[[ $summary_class = low || $summary_class = high ]] ||
    die "summary.sig does not hold one spki signature: '$summary_class'"

ostree --repo="$REPO" fsck >/dev/null

# The output.
for entry in "$REPO"/*; do
    case "${entry##*/}" in
        config | objects | refs | deltas | delta-indexes | summary | summary.sig) ;;
        tmp | state | extensions | .lock) ;;
        *) die "unexpected entry in the repository: ${entry##*/}" ;;
    esac
done
rm -rf "$OUT"
mkdir -p "$OUT/repo"
for entry in config objects refs deltas delta-indexes summary summary.sig; do
    if [ -e "$REPO/$entry" ]; then
        cp -a "$REPO/$entry" "$OUT/repo/"
    fi
done
cp "$WORK/secret.pem" "$WORK/public.pem" "$OUT/"
cat >"$OUT/MANIFEST" <<EOF
# spki test fixtures for the ostree Rust port, written by spki/generate.sh.
# Generator: ostree $(sed -n "s/^ *Version: '\(.*\)'$/\1/p" <<<"$features") (black box).
# The key and the ECDSA nonces are random, so a run gives new bytes.
key_type=$TYPE
openssl=$(openssl version)
branch=$BRANCH
commit=$C
delta=$DELTA
commit_signatures=$commit_classes
summary_signature=$summary_class
delta_signature=$delta_class
EOF

echo "wrote $OUT"
echo "commit=$C commit_signatures=\"$commit_classes\""
echo "delta=$DELTA delta_signature=$delta_class summary_signature=$summary_class"
