#!/usr/bin/env bash
#
# Golden-fixture generator for the ostree Rust port.
#
# Drives the `ostree` tool as a black box to emit reference bytes into
# tests/fixtures/generated/. The output is the correctness reference the port
# is checked against: the tool must read what the port writes, and the port
# must read what the tool wrote here.
#
# Determinism. A fixed branch, a fixed commit timestamp, owner 0:0, no xattrs,
# and explicit file modes make every content-addressed object and every ref
# byte-stable, so re-running yields byte-identical tracked files. (The bare
# epoch form `--timestamp=1700000000` is rejected by the tool; the `@epoch`
# form is used instead.)
#
# Storage. Archive and bare fixtures are emitted as plain trees. The
# bare-user-family fixtures (bare-user, canon, xattr) store each file's logical
# metadata in a user.ostreemeta xattr, which git does not track, so they are
# emitted as xattr-preserving tarballs (generated/<name>.tar). A fresh checkout
# unpacks the tarball rather than regenerating, so consumers need no ostree.
#
# Invariant. Object identity, and therefore the dirtree and commit checksums,
# are independent of repository mode. The script commits the same tree in each
# mode and fails if the resulting commit checksums are not identical.
#
# Clean-room note. The `ostree` tool is treated purely as a black box: only its
# command output and the bytes it writes on disk inform the port. Its source is
# never consulted. See CLAUDE.md, "Licensing and clean-room discipline".

set -euo pipefail

# --- deterministic knobs ---
BRANCH="test/main"
SUBJECT="fixture commit"
TIMESTAMP="@1700000000" # 2023-11-14 22:13:20 UTC
OWNER_UID=0
OWNER_GID=0
MODES=(archive bare-user)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/generated"

if ! command -v ostree >/dev/null 2>&1; then
    echo "error: the 'ostree' tool is not on PATH; cannot generate fixtures" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- build the deterministic source tree ---
# A regular file, an empty file, a nested regular file, and a symlink exercise
# the file-object, empty-payload, nested-dirtree, and symlink paths.
SRC="$WORK/tree"
mkdir -p "$SRC/subdir"
printf 'hello ostree\n' >"$SRC/hello.txt"
: >"$SRC/empty.txt"
printf 'nested\n' >"$SRC/subdir/nested.txt"
ln -s hello.txt "$SRC/link"
chmod 0644 "$SRC/hello.txt" "$SRC/empty.txt" "$SRC/subdir/nested.txt"
chmod 0755 "$SRC/subdir"

# --- regenerate output from scratch ---
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Emit a repository's deterministic parts (config, objects, refs) as a plain
# tree under generated/<name>/repo. The lock file and tmp staging are transient
# and are left out.
emit_tree() {
    local src="$1" name="$2"
    local dst="$OUT_DIR/$name/repo"
    mkdir -p "$dst"
    cp -a "$src/config" "$dst/config"
    cp -a "$src/objects" "$dst/objects"
    cp -a "$src/refs" "$dst/refs"
}

# Emit a repository's deterministic parts as an xattr-preserving tarball at
# generated/<name>.tar, with the same config/objects/refs selection as
# emit_tree. The tarball is byte-reproducible: a fixed mtime, owner 0:0,
# name-sorted entries, and dropped volatile pax timestamps make regeneration on
# any host yield an identical archive. cp -a preserves the user.ostreemeta xattr
# into the staging tree, and --xattrs stores it in the archive.
emit_tar() {
    local src="$1" name="$2"
    local stage
    stage="$(mktemp -d)"
    mkdir -p "$stage/repo"
    cp -a "$src/config" "$stage/repo/config"
    cp -a "$src/objects" "$stage/repo/objects"
    cp -a "$src/refs" "$stage/repo/refs"
    tar --xattrs --xattrs-include='user.*' --sort=name --format=posix \
        --mtime="$TIMESTAMP" --owner=0 --group=0 --numeric-owner \
        --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' \
        -C "$stage" -cf "$OUT_DIR/$name.tar" repo
    rm -rf "$stage"
}

declare -A CHECKSUM
for mode in "${MODES[@]}"; do
    repo="$WORK/repo-$mode"
    ostree --repo="$repo" init "--mode=$mode" >/dev/null
    checksum="$(ostree --repo="$repo" commit \
        --branch="$BRANCH" --subject="$SUBJECT" \
        --owner-uid="$OWNER_UID" --owner-gid="$OWNER_GID" \
        --no-xattrs --timestamp="$TIMESTAMP" "$SRC")"
    CHECKSUM["$mode"]="$checksum"

    # archive is a plain tree; bare-user stores logical metadata in
    # user.ostreemeta and is tarred.
    case "$mode" in
        bare-user) emit_tar "$repo" "$mode" ;;
        *) emit_tree "$repo" "$mode" ;;
    esac
done

# --- assert the cross-mode commit-identity invariant ---
first="${MODES[0]}"
for mode in "${MODES[@]}"; do
    if [[ "${CHECKSUM[$mode]}" != "${CHECKSUM[$first]}" ]]; then
        echo "error: cross-mode commit identity broken:" >&2
        for m in "${MODES[@]}"; do echo "  $m = ${CHECKSUM[$m]}" >&2; done
        exit 1
    fi
done

# --- tar export fixture (Phase 10) ---
# The tool's `ostree export` of the shared commit: a plain filesystem tar of the
# tree (the root is the member `./`, every other member a bare relative path,
# every mtime the commit timestamp, identical content coalesced into hardlinks).
# The Phase 10 import path reads this to prove tool -> port tree fidelity.
ostree --repo="$WORK/repo-$first" export "${CHECKSUM[$first]}" >"$OUT_DIR/export.tar"

# --- bare fixture for the write path ---
# Bare mode stores the logical uid/gid/mode on the object inode, so a faithful
# write needs to own those ids. The owner is the invoking uid/gid so that an
# unprivileged test can reproduce the ownership the tool applies. Its object
# checksums therefore depend on the invoking user and are not part of the
# cross-mode identity invariant above; the write-path test cross-checks bare
# against a repository the tool builds at test time.
BARE_UID="$(id -u)"
BARE_GID="$(id -g)"
bare_repo="$WORK/repo-bare"
ostree --repo="$bare_repo" init --mode=bare >/dev/null
ostree --repo="$bare_repo" commit \
    --branch="$BRANCH" --subject="$SUBJECT" \
    --owner-uid="$BARE_UID" --owner-gid="$BARE_GID" \
    --no-xattrs --timestamp="$TIMESTAMP" "$SRC" >/dev/null
emit_tree "$bare_repo" "bare"

# --- canonical-permissions fixture (Phase 7c) ---
# A tree of assorted modes committed with --canonical-permissions. The tool
# forces owner 0:0 and reduces each permission set to `perm & 0755` (group and
# other write and the setuid/setgid/sticky bits are dropped), so the objects are
# deterministic and owner-independent. --no-xattrs keeps them free of host
# SELinux labels. See format-reference.md, "Commit modifier".
CANON_SRC="$WORK/canon-src"
mkdir -p "$CANON_SRC/dir0775"
printf 'a' >"$CANON_SRC/f0664"
printf 'b' >"$CANON_SRC/f0755"
printf 'c' >"$CANON_SRC/f4755"
chmod 0664 "$CANON_SRC/f0664"
chmod 0755 "$CANON_SRC/f0755"
chmod 4755 "$CANON_SRC/f4755"
chmod 0775 "$CANON_SRC/dir0775"
ln -s f0664 "$CANON_SRC/link"
canon_repo="$WORK/repo-canon"
ostree --repo="$canon_repo" init --mode=bare-user >/dev/null
CANON_COMMIT="$(ostree --repo="$canon_repo" commit \
    --branch="$BRANCH" --subject="$SUBJECT" \
    --canonical-permissions --no-xattrs --timestamp="$TIMESTAMP" "$CANON_SRC")"
emit_tar "$canon_repo" "canon"

# --- user.* xattr fixture (Phase 7c) ---
# A bare-user commit capturing a user.demo xattr (committed without --no-xattrs).
# Owner is fixed to 0:0 so the object identity is host-independent. Generated on
# a host without SELinux labeling, so the only captured xattr is user.demo.
XATTR_SRC="$WORK/xattr-src"
mkdir -p "$XATTR_SRC"
printf 'labeled\n' >"$XATTR_SRC/hello.txt"
chmod 0644 "$XATTR_SRC/hello.txt"
setfattr -n user.demo -v value "$XATTR_SRC/hello.txt"
xattr_repo="$WORK/repo-xattr"
ostree --repo="$xattr_repo" init --mode=bare-user >/dev/null
XATTR_COMMIT="$(ostree --repo="$xattr_repo" commit \
    --branch="$BRANCH" --subject="$SUBJECT" \
    --owner-uid=0 --owner-gid=0 --timestamp="$TIMESTAMP" "$XATTR_SRC")"
emit_tar "$xattr_repo" "xattr"

# --- archive size-generation fixture (Phase 7d) ---
# The deterministic source tree committed into an archive repo with
# --generate-sizes. The tool records an ostree.sizes metadata key covering every
# object reachable in the commit -- content objects and the dirtree/dirmeta
# metadata objects alike, each carrying its own object-type byte -- so the commit
# object differs from the sizes-free archive fixture. Archive mode stores no
# xattrs, so this is a plain tree. See format-reference.md, "Commit -- the
# ostree.sizes key".
sizes_repo="$WORK/repo-sizes"
ostree --repo="$sizes_repo" init --mode=archive-z2 >/dev/null
SIZES_COMMIT="$(ostree --repo="$sizes_repo" commit \
    --branch="$BRANCH" --subject="$SUBJECT" \
    --owner-uid="$OWNER_UID" --owner-gid="$OWNER_GID" \
    --no-xattrs --generate-sizes --timestamp="$TIMESTAMP" "$SRC")"
emit_tree "$sizes_repo" "sizes"

# --- composefs / EROFS export fixture (Phase 9) ---
# ostree built with composefs exports a commit's tree to an EROFS image whose
# fs-verity digest (SHA-256, 4096-byte block, 0 salt) is the value it stores in
# commit metadata under ostree.composefs.digest.v0 and verifies at boot. The
# image is derived from the commit's tree alone: it is byte-identical whether or
# not the commit carries the digest metadata. This fixture commits with
# --generate-composefs-metadata so the commit's stored digest cross-checks the
# image's measured fs-verity digest. See format-reference.md, "composefs".
#
# --composefs writes the verity image (the boot-verified artifact); it computes
# the backing-object digests in-process, so it needs no kernel fs-verity
# support. ostree opens the export's O_TMPFILE relative to the current directory
# and links it next to the destination, so the checkout must run with a working
# directory on the destination's filesystem; it runs inside $WORK, and the
# finished image is copied into the project tree afterward.
COMPOSEFS_COMMIT=""
COMPOSEFS_DIGEST=""
COMPOSEFS_RICH_COMMIT=""
COMPOSEFS_RICH_DIGEST=""
if ostree --version | grep -q composefs && command -v composefs-info >/dev/null 2>&1; then
    mkdir -p "$OUT_DIR/composefs"

    cfs_repo="$WORK/repo-composefs"
    ostree --repo="$cfs_repo" init --mode=bare-user >/dev/null
    COMPOSEFS_COMMIT="$(ostree --repo="$cfs_repo" commit \
        --branch="$BRANCH" --subject="$SUBJECT" \
        --owner-uid="$OWNER_UID" --owner-gid="$OWNER_GID" \
        --no-xattrs --timestamp="$TIMESTAMP" \
        --generate-composefs-metadata "$SRC")"
    ( cd "$WORK" && TMPDIR="$WORK" \
        ostree --repo="$cfs_repo" checkout --composefs \
        "$COMPOSEFS_COMMIT" "$WORK/tree.cfs" )
    cp "$WORK/tree.cfs" "$OUT_DIR/composefs/tree.cfs"
    composefs-info dump "$WORK/tree.cfs" >"$OUT_DIR/composefs/tree.dump"
    COMPOSEFS_DIGEST="$(composefs-info measure-file "$WORK/tree.cfs")"

    # --- rich composefs fixture ---
    # A second export that drives the writer branches the minimal tree above
    # leaves untested: shared xattrs promoted to the shared table, inline
    # xattrs, a multi-block directory with an inline dirent tail, and a long
    # inline symlink near the block boundary. It is committed without
    # --no-xattrs so the user.* xattrs are captured, so like the xattr fixture
    # it must be generated on a host that applies no SELinux labels; owner 0:0
    # keeps the object identity host-independent. The symlink target is 4063
    # bytes, the largest the tool accepts before it aborts promoting a no-xattr
    # symlink to a data block, so the fixture bounds the symlink at the
    # reachable inline maximum.
    CFS_RICH="$WORK/cfs-rich"
    mkdir -p "$CFS_RICH/bigdir" "$CFS_RICH/shared" "$CFS_RICH/nested/deep" \
        "$CFS_RICH/attrs"
    # A multi-block directory: 300 identical-content files (one backing object,
    # heavily shared metacopy/redirect xattrs) whose dirents span two blocks.
    for i in $(seq -w 0 299); do
        printf 'x' >"$CFS_RICH/bigdir/d$i"
        chmod 0644 "$CFS_RICH/bigdir/d$i"
    done
    chmod 0755 "$CFS_RICH/bigdir"
    setfattr -n user.dirattr -v bigdirvalue "$CFS_RICH/bigdir"
    # user.shared on six inodes across three directories -> shared table.
    for f in s1 s2 s3 s4; do
        printf '%s\n' "$f" >"$CFS_RICH/shared/$f.txt"
        chmod 0644 "$CFS_RICH/shared/$f.txt"
        setfattr -n user.shared -v commonvalue "$CFS_RICH/shared/$f.txt"
    done
    printf 'deep\n' >"$CFS_RICH/nested/deep/g.txt"
    chmod 0644 "$CFS_RICH/nested/deep/g.txt"
    setfattr -n user.shared -v commonvalue "$CFS_RICH/nested/deep/g.txt"
    printf 'top\n' >"$CFS_RICH/shared.txt"
    chmod 0644 "$CFS_RICH/shared.txt"
    setfattr -n user.shared -v commonvalue "$CFS_RICH/shared.txt"
    # Mixed shared+local on one inode, and an inline-only xattr on another.
    setfattr -n user.uniq -v onlyhere "$CFS_RICH/shared/s1.txt"
    printf 'u\n' >"$CFS_RICH/uniq.txt"
    chmod 0644 "$CFS_RICH/uniq.txt"
    setfattr -n user.uniq -v onlyhere "$CFS_RICH/uniq.txt"
    # Small dirs whose xattr values vary in length (varying xattr_size mod 32).
    for n in 1 5 13 21 29; do
        d="$CFS_RICH/attrs/a$n"
        mkdir -p "$d"
        chmod 0755 "$d"
        printf 'c' >"$d/f"
        chmod 0644 "$d/f"
        setfattr -n user.v -v "$(printf 'v%.0s' $(seq 1 "$n"))" "$d/f"
    done
    # A long inline symlink near the block boundary.
    ln -s "$(printf 'z%.0s' $(seq 1 4063))" "$CFS_RICH/longlink"

    rich_repo="$WORK/repo-composefs-rich"
    ostree --repo="$rich_repo" init --mode=bare-user >/dev/null
    COMPOSEFS_RICH_COMMIT="$(ostree --repo="$rich_repo" commit \
        --branch="$BRANCH" --subject="$SUBJECT" \
        --owner-uid="$OWNER_UID" --owner-gid="$OWNER_GID" \
        --timestamp="$TIMESTAMP" \
        --generate-composefs-metadata "$CFS_RICH")"
    ( cd "$WORK" && TMPDIR="$WORK" \
        ostree --repo="$rich_repo" checkout --composefs \
        "$COMPOSEFS_RICH_COMMIT" "$WORK/tree-rich.cfs" )
    cp "$WORK/tree-rich.cfs" "$OUT_DIR/composefs/tree-rich.cfs"
    composefs-info dump "$WORK/tree-rich.cfs" >"$OUT_DIR/composefs/tree-rich.dump"
    COMPOSEFS_RICH_DIGEST="$(composefs-info measure-file "$WORK/tree-rich.cfs")"
else
    echo "warning: ostree lacks composefs or composefs-info missing;" \
         "skipping composefs fixture" >&2
fi

# --- summary fixtures (Phase 14) ---
# Two golden summaries the tool wrote, for the byte-identity gate. The tool's
# ostree.summary.last-modified is wall-clock, so it is patched to the fixed
# TIMESTAMP epoch to keep regeneration byte-reproducible; the port is asked to
# reproduce that same epoch. Each fixture ships the repository as a plain tree
# (config/objects/refs, no summary) so the port regenerates the summary itself.
SUMMARY_EPOCH="${TIMESTAMP#@}"

# Rewrite the 8-byte big-endian ostree.summary.last-modified value in place.
patch_summary_last_modified() { # file epoch
    python3 - "$1" "$2" <<'PY'
import struct, sys
path, epoch = sys.argv[1], int(sys.argv[2])
data = bytearray(open(path, "rb").read())
key = b"ostree.summary.last-modified"
i = data.find(key)
assert i >= 0, "last-modified key not found in summary"
# The variant value is the 8 bytes preceding the "\x00t" variant type marker.
j = data.find(b"\x00\x74", i)
assert j >= 0, "last-modified variant marker not found"
data[j - 8:j] = struct.pack(">Q", epoch)
open(path, "wb").write(data)
PY
}

# Non-collection: two refs (one carrying a version), plain archive tree.
summary_repo="$WORK/repo-summary"
ostree --repo="$summary_repo" init --mode=archive-z2 >/dev/null
ostree --repo="$summary_repo" commit --branch=main --subject="$SUBJECT" \
    --add-metadata-string=version=1.0 --owner-uid="$OWNER_UID" \
    --owner-gid="$OWNER_GID" --no-xattrs --timestamp="$TIMESTAMP" "$SRC" >/dev/null
ostree --repo="$summary_repo" commit --branch=other --subject="$SUBJECT" \
    --owner-uid="$OWNER_UID" --owner-gid="$OWNER_GID" \
    --no-xattrs --timestamp="$TIMESTAMP" "$SRC" >/dev/null
emit_tree "$summary_repo" summary
ostree --repo="$summary_repo" summary -u >/dev/null
cp "$summary_repo/summary" "$OUT_DIR/summary/summary"
patch_summary_last_modified "$OUT_DIR/summary/summary" "$SUMMARY_EPOCH"

# Collection: the repository is captured before `summary -u`, so the port
# generates the ostree-metadata anchor commit (first generation, parentless).
# The anchor commit timestamp is pinned with SOURCE_DATE_EPOCH.
SUMMARY_COLLECTION_ID="org.ostrya.Test"
summary_coll_repo="$WORK/repo-summary-collection"
ostree --repo="$summary_coll_repo" init --mode=archive-z2 \
    --collection-id="$SUMMARY_COLLECTION_ID" >/dev/null
ostree --repo="$summary_coll_repo" commit --branch=main --subject="$SUBJECT" \
    --owner-uid="$OWNER_UID" --owner-gid="$OWNER_GID" \
    --no-xattrs --timestamp="$TIMESTAMP" "$SRC" >/dev/null
emit_tree "$summary_coll_repo" summary-collection
SOURCE_DATE_EPOCH="$SUMMARY_EPOCH" \
    ostree --repo="$summary_coll_repo" summary -u >/dev/null
cp "$summary_coll_repo/summary" "$OUT_DIR/summary-collection/summary"
patch_summary_last_modified "$OUT_DIR/summary-collection/summary" "$SUMMARY_EPOCH"
SUMMARY_ANCHOR_COMMIT="$(cat "$summary_coll_repo/refs/heads/ostree-metadata")"

COMMIT="${CHECKSUM[$first]}"
CONTENT="$(ostree --repo="$WORK/repo-$first" show "$COMMIT" |
    sed -n 's/^ContentChecksum:[[:space:]]*//p')"
OSTREE_VERSION="$(ostree --version | awk -F"'" '/Version:/ {print $2}')"

cat >"$OUT_DIR/MANIFEST" <<EOF
# Golden fixtures for the ostree Rust port, generated by generate.sh.
# Generator: ostree ${OSTREE_VERSION} (black box).
# Deterministic inputs: branch=${BRANCH} timestamp=${TIMESTAMP} owner=${OWNER_UID}:${OWNER_GID} no-xattrs.
# The bare/ fixture uses owner=${BARE_UID}:${BARE_GID} (the invoking user) and is
# therefore owner-specific, not part of the cross-mode commit-identity guarantee.
branch=${BRANCH}
commit=${COMMIT}
content_checksum=${CONTENT}
modes=${MODES[*]}
bare_owner=${BARE_UID}:${BARE_GID}
canon_commit=${CANON_COMMIT}
xattr_commit=${XATTR_COMMIT}
sizes_commit=${SIZES_COMMIT}
composefs_commit=${COMPOSEFS_COMMIT}
composefs_digest=${COMPOSEFS_DIGEST}
composefs_rich_commit=${COMPOSEFS_RICH_COMMIT}
composefs_rich_digest=${COMPOSEFS_RICH_DIGEST}
summary_last_modified=${SUMMARY_EPOCH}
summary_collection_id=${SUMMARY_COLLECTION_ID}
summary_anchor_commit=${SUMMARY_ANCHOR_COMMIT}
EOF

# The generator wipes and rebuilds OUT_DIR, so it also writes the .gitattributes
# that marks the binary fixtures (xattr tarballs and the composefs image).
cat >"$OUT_DIR/.gitattributes" <<'EOF'
# Fixture tarballs carry user.* xattrs and must not be line-ending normalized
# or diffed as text.
*.tar binary
# The composefs EROFS image is a binary golden fixture.
*.cfs binary
# The golden summaries are serialized GVariant, not text.
summary/summary binary
summary-collection/summary binary
EOF

echo "generated fixtures in ${OUT_DIR}"
echo "  commit (identical across ${MODES[*]}): ${COMMIT}"
echo "  bare/ fixture owner ${BARE_UID}:${BARE_GID} (owner-specific)"
