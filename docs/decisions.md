# Ostrya -- Design Decisions

This document records the design decisions of the port and the alternatives
that were rejected, with the reason for each. The on-disk format is in
`format-reference.md`. The observed behavior of the `ostree` command is in
`conformance/cli-behavior.md`, and each difference from it is in
`conformance/cli-surface.md`. The rustdoc of each crate documents the API.

## Dependency policy

The port is pure Rust. The Rust crate ecosystem is in scope, and C libraries
are excluded. `CLAUDE.md`, "Goals", states the two exceptions: `liblzma` for
xz, and PCRE2 in the `ostrya-cli` binary alone. Each is built from source and
linked statically under its feature, and needs no C runtime beyond the libc
that `std` links.

These C libraries are excluded, with the Rust path that replaces each:

- `openssl-sys` -- TLS through `rustls` with the `rustls-graviola` provider,
  and ECDSA through `p256`.
- `libgpg-error` and `gpgme` -- GPG signing through the system `gpg` binary,
  and GPG verification through the `pgp` crate.
- `libcurl` and `libsoup` -- HTTP through `hyper`.
- `libarchive` -- tar through `smol-tar`.
- `libcomposefs` -- composefs images through `ostrya-composefs`.
- `glib` -- GVariant through `ostrya-gvariant`, and the key file through
  `ostrya-core`.

Two CI steps in `.github/workflows/ci.yml` hold the rules over the whole
graph. One step holds the permissive-license rule. The other step fails on a
package that declares a `links` key and is not on its allowlist. The comments
of the two steps state their rules.

## Foundation crates

The workspace crates take these external crates directly. `CLAUDE.md` has an
"Authorized" section for each crate it marks so, with the terms of its
feature set and its graph.

- `rustix` -- the syscalls that a portable async file API cannot express:
  fd-relative open, stat, link, rename, readlink and mkdir, xattrs, statx,
  statvfs, FICLONE, O_TMPFILE with linkat, record locks, and fsync and
  syncfs.
- `smol` -- the default runtime backend, in `ostrya-rt` alone.
- `tokio` -- the optional runtime backend, in `ostrya-rt` alone.
- `futures-io` and `futures-lite` -- the async traits and the combinators
  that the library is written against.
- `pin-project-lite` -- pin projection for the stream wrapper types.
- `sha2` -- SHA-256, for object checksums, for fs-verity digests, and for
  the SigV4 signer of the `s3` feature of `ostrya-remote`.
- `hmac` -- HMAC-SHA256 for the SigV4 signer, in `ostrya-remote` under its
  `s3` feature. See "SigV4 and the AWS credentials".
- `miniz_oxide` -- the raw DEFLATE encoder of archive-mode content objects.
  `ostrya-core` takes it directly, so the stored `.filez` bytes for a given
  `[archive] zlib-level` are the same under each feature set. The golden
  SHA-256 vectors in `crates/ostrya-core/src/deflate.rs`, one for each level
  from 1 to 9, fail the test suite if a new version writes other bytes.
- `async-compression` -- streaming DEFLATE inflate of archive-mode content
  objects, and streaming xz of static-delta parts.
- `liblzma` -- the xz codec behind `async-compression`.
- `bsdiff` -- bspatch stream generation for static deltas. It has no
  dependencies and no `unsafe`. The port reads the streams with its own
  bspatch.
- `smol-tar` -- async tar import and export.
- `ed25519-dalek` -- the ed25519 sign engine, in `ostrya-sign`.
- `p256` -- the spki sign engine, in `ostrya-sign`.
- `pgp` -- OpenPGP keyring parsing and signature verification.
- `hyper` -- the HTTP/1.1 and HTTP/2 engine of `ostrya-fetch` and
  `ostrya-server`. Both crates take version 1.11.1 or later. Version 1.11.0
  can keep the last chunk of a response body in its write buffer when the
  first poll of the body is pending, and then the response does not end.
- `rustls`, `rustls-graviola`, `futures-rustls`, `rustls-native-certs` and
  `rustls-pemfile` -- TLS. See "TLS stack".
- `url` and `pkcs8` -- in `ostrya-fetch`.
- `getrandom` and `x509-cert` -- in `ostrya-server`.
- `thiserror` -- the error types.
- `libc` -- in `ostrya-sys`, `ostrya-remote` and `ostrya-sign`.
- `clap` -- command-line parsing, in `ostrya-cli` and `ostrya-mountd`.
- `pcre2` -- the `commit --tar-pathname-filter` expression, in `ostrya-cli`
  alone. See "The expression engine of `--tar-pathname-filter`".
- `indicatif` -- the progress bar of `push` and `push-tree`, in `ostrya-cli`.

## The repository lock

The lock on `<repo>/.lock` is a classic `fcntl` record lock (`F_SETLK`,
through `rustix::fs::fcntl_lock`). An OFD lock was rejected: `rustix` does
not expose the OFD commands, and a raw OFD call needs the `libc` crate and
`unsafe` code.

A record lock and an OFD lock share one lock space. Thus the port and the
`ostree` command exclude each other on the same repository. This was
verified in both directions: each side held its lock while the other side
tried to get the lock.

A record lock belongs to the process, and the kernel releases it when the
process closes any descriptor of the file. Thus a process-global registry,
keyed by the `(device, inode)` of the lock file, keeps one descriptor and one
reference count for each repository. `crates/ostrya/src/lock.rs` documents
the registry.

## The GVariant codec

`ostrya-gvariant` is a GVariant codec written in the tree for the fixed type
set of ostree. No crate was taken, because the port needs byte-exact normal
form and decode with no heap allocation on the read paths.

Each object type has a hand-written codec impl. A proc-macro derive was
rejected. The set of object types is small and fixed, and a derive adds a
proc-macro crate together with `syn`, `quote` and `proc-macro2`. A derive
needs a dependency proposal under the confirmation rule of `CLAUDE.md`.

## The composefs writer

`ostrya-composefs` writes the composefs EROFS image. It is written in the
tree because no crate writes byte-exact composefs images under the no-C
rule. These crates were examined and rejected:

- `erofs/erofs-rs` and `Dreamacro/erofs-rs` read EROFS images and do not
  write them. Neither knows composefs.
- `composefs` (`containers/composefs-rs`, MIT OR Apache-2.0) writes images
  that are byte-identical to `mkcomposefs`. It has a non-optional `zstd`,
  which links C through `zstd-sys`, and a full `tokio`. No feature turns
  either off.
- `am-fs-erofs` writes generic EROFS images. It has no overlay xattrs and no
  fs-verity, and its byte layout is different from composefs.
- `lamfold-erofs`, `gobblytes-erofs`, `liberofs`, `erofs` and `nydus-rs`
  read images only, are stubs, or are container-image stacks.

`ostrya-composefs` writes only the metadata subset that composefs uses, and
no EROFS compression.

The fs-verity digest is a SHA-256 Merkle calculation over `sha2`. The
`fs-verity` crate was rejected because it takes `libc` with no condition.

The XATTR_FILTER field hashes each xattr name with xxHash32. The xxHash32 in
`crates/ostrya-composefs/src/xxhash.rs` is written in the tree to add no
crate. The golden filter bytes verify it.

## The composefs image object

The port stores the composefs image of a commit as an object of the type 100
(`format-reference.md`, "The composefs image object"). The `ostree` command
does not know this type. A read of a port repository that holds images by
the `ostree` command is not a goal. The cross-checks in which the `ostree`
command reads the output of the port cover repositories and static deltas
with no image. The port reads the repositories and the static deltas of the
`ostree` command.

## The mount daemon

`ostrya-mountd` mounts a commit as composefs for a caller in a user
namespace of its own. The kernel forced these choices:

- Each request runs in a worker process, the daemon binary run again. The
  kernel refuses `setns(CLONE_NEWUSER)` in a process with more than one
  thread. A process that enters a user namespace cannot go back to its
  parent namespace. Thus a thread of the runtime pool cannot do the steps
  on the side of the caller.
- The worker gives the daemon `open_tree(OPEN_TREE_CLONE)` copies of the
  repository directory and of `objects`. overlayfs takes a layer only from
  the mount namespace of the mounter or from a detached mount, and the
  daemon mounts in its own mount namespace.
- The worker makes an `open_tree(OPEN_TREE_CLONE)` copy of the composefs
  mount of the daemon. overlayfs takes a detached layer only from a process
  with `CAP_SYS_ADMIN` in the user namespace that owns the detached mount.
  The daemon makes the composefs mount in the initial user namespace, so the
  top overlay of the worker on the detached mount of the daemon fails with
  EPERM. The copy belongs to the user namespace of the caller.

The daemon checks that the sent user namespace owns the sent mount
namespace, and that it is not the initial user namespace. It does not check
that the peer is a member of the namespaces that it sends. A client such as
ostree-podman sends the namespaces of podman, which are not its own.

## The spki sign engine

The spki engine is pure Rust over `p256`: deterministic ECDSA on NIST P-256
with SHA-256. The `ostree` command builds this engine only with OpenSSL.
The engine is behind the `sign-spki` feature, so a build without it has no
ECDSA crate tree.

No available build of the `ostree` command has spki. The maintainer decided
to cross-check the engine against the `openssl` command in both directions.
`format-reference.md`, "Signing details", marks the spki facts as a design
target. The test `spki_tool_cross_verify_pending` skips until a build of the
`ostree` command with spki is available.

## GPG

Signing runs the system `gpg` binary as a subprocess over its `--status-fd`
interface. Thus keys in an agent and keys on a hardware token work through
`gpg` with no code of their own, and the private key stays with `gpg`.

Verification is in the process, over the `pgp` crate. `sequoia-openpgp` was
rejected for its LGPL license. The port owns the trust policy: issuer
resolution, subkey bindings, expiry, revocation, the signature class and the
digest policy. No fallback to the `gpgv` binary exists, so one engine and one
policy give each verdict.

## TLS stack

The fetcher uses `rustls` 0.23 with `rustls-graviola` 0.4 as the crypto
provider. The provider is Rust together with formally verified assembly from
s2n-bignum, so the build needs no C compiler and no `cc` build dependency.
The provider supports x86_64 and aarch64 alone. A build for another target
needs a different provider in `crates/ostrya-fetch/src/tls.rs`.

`rustls-native-certs` reads the trust store of the host. `webpki-roots` was
rejected: its license, CDLA-Permissive-2.0, is not on the permissive list.

`h2` puts `tokio` and `tokio-util` into the graph under the `smol` backend
too. The fetcher uses only their I/O traits and codec framing, and drives no
tokio runtime.

## The HTTP adapters

The adapters between `hyper` and `futures-io` keep `forbid(unsafe_code)`.
They fill the read cursor of `hyper` through its safe `put_slice`. This
costs one copy for each read, because a read into the uninitialized buffer
needs `unsafe` code.

The request body is a `Body` type of the fetcher, so `http-body-util` is not
a dependency. The `basic` authorization header is encoded by
`ostrya-core::base64`, so no base64 crate is a dependency.

## Request signing in the fetcher

`ostrya_fetch::RequestSigner` is a hook that adds headers to each attempt.
The fetcher calls it after it takes the connection, for each retry, each
round, and each redirect hop at the origin that the route names. A hop at
another origin gets no signature. A signer is a credential: the fetcher
refuses it beside basic-auth credentials, a bearer token, or an
`Authorization` header, and toward a cleartext mirror without the permission
of the caller. The same refusal applies to these credentials on a fetch or
an upload: the request fails before admission, and the signer is not called.
Each header value of the signer is marked sensitive, so an HTTP/2
connection never adds it to its header compression table.

A presigned query for each target was rejected, for three reasons:

- A signature with a date must be fresh when the request leaves. A retry
  after a backoff, or a request that waits for a connection, needs a new
  date. The hook signs each attempt.
- The signature stays in a credential header, which the fetcher marks
  sensitive and keeps from other origins. A presigned signature is part of
  the URL, and each error message of the fetcher prints the URL.
- A signed `PUT` with the signature in its headers signs the hash of the
  body.

The signer gets a body given whole as a slice of the request body, with no
copy, and hashes it on the task of the request, on each call. On the
development host, the SHA-256 of 8 MiB takes about 4.8 ms in a release build.
This is less than the limit of 10 ms for work on the task, so the fetcher
gives the signer the bytes and does not hash the body itself. A streamed body
reaches the signer as `SignPayload::Streamed`, with no bytes.

## SigV4 and the AWS credentials

`ostrya_remote::s3::SigV4` is the AWS Signature Version 4 code, written in
the tree over `sha2` and the `hmac` crate 0.12.1. The algorithm is a fixed
sequence of hashes and string joins, and the AWS documentation gives worked
examples with full inputs and outputs. The unit tests check the signer
against these examples. `hmac` was in `Cargo.lock` before the feature, so no
package entered the graph. Two alternatives were rejected:

- HMAC-SHA256 written in the tree too, over `sha2`. It adds no manifest
  entry, but it is cryptographic code that the RustCrypto crate `hmac`
  already supplies, and that crate is in the graph.
- A SigV4 crate, for example `aws-sigv4` or `rusty-s3`. Each one brings
  packages that are not in `Cargo.lock`, and `rusty-s3` makes presigned URLs
  alone, which "Request signing in the fetcher" rejects.

`ostrya_remote::s3::resolve` reads static key pairs alone: the environment
variables, then the shared credentials file, then the shared config file,
with an optional session token. A profile section that names another source
(`role_arn`, `source_profile`, `credential_process`, `web_identity_token_file`,
or a key that starts with `sso_`) is refused with an error that names the
file, the section, and the key. The chain does not skip to the next source,
so the port never signs with an identity other than the one that the profile
names. If the environment gives the key pair, these keys are not read. The
full chain of the AWS SDKs, with STS, IMDSv2, and the container endpoint, was
rejected: it is a large part of the work, and each source needs a test
server of its own.

A profile that the caller names skips the key pair, the region, and the
endpoint of the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`,
`AWS_ENDPOINT_URL_S3`, and `AWS_ENDPOINT_URL`). The chain reads the shared
files for that profile alone. Without this rule, a named profile `prod` with
`AWS_ENDPOINT_URL` set for a test server sends requests that the key of
`prod` signs to the test server, and `AWS_ACCESS_KEY_ID` wins over the named
profile. A profile from `AWS_PROFILE`, or the profile `default`, keeps the
order of the AWS documentation, where the keys of the environment win. The
order of the AWS documentation in all cases was rejected for these two
reasons.

When no source gives a region, the region is `us-east-1`. SigV4 puts the
region into the scope of each signature, so each request carries a region.
A server that does not check the region then needs an endpoint alone. A
server that checks its own region, and an AWS bucket outside `us-east-1`,
needs a region from the caller, the environment, or the config file. The
region changes no byte of the repository, only the signature. A default
that applies only with an endpoint of the caller was rejected.

## Error responses of a fetch

`ostrya_fetch::FetchRequest::max_error_body` asks a fetch to keep the
unsuccessful response that it reports. `Error::HttpStatus` then carries an
`ErrorResponse` with the headers of that response, and its body if the whole
body is within the cap. A fetch that does not set the field reads no error
body, as before. The bucket client of S3 needs the field: the code and the
message of an S3 error, and the region of a bucket, are in the body and in
the headers of the error response.

- A fetch reads the body of a failure only if the failure order can make it
  the reported failure. So it reads at most two bodies, one retryable and
  one definitive, and keeps the body of the failure that it reports.
- The read has one progress window from the arrival of the response head.
  A body over the cap, a coded body, a stalled body, and a body that fails
  in transit give the headers alone. The fetch keeps no part of a body.
- The declared length of a body is a claim of the server, so the read
  reserves at most 64 KiB before the body arrives. The capacity of a kept
  body never passes the cap. A cap of `u64::MAX` and a response that
  declares 1 PiB then cost no allocation of 1 PiB.
- The read never changes the retry class of a status, and the kept bytes do
  not count in the received counters.
- `ostrya::Error::HttpStatus` does not carry the response. Its conversion
  from the fetch error drops it, so the error type of the library keeps its
  shape.
- `Error::HttpStatus` of `ostrya-fetch` has no `#[non_exhaustive]`. A caller
  outside the crate can build each variant, and a pattern names the new
  field or ends in `..`.

These alternatives were rejected:

- `UploadMethod::Get`, a `GET` through `Fetcher::upload`, which gives each
  final status with its headers and a capped body. The bucket client then
  owns the retries of its `GET` requests, and a streamed object loses the
  refetch of a failed body and the low-speed rule of a fetch. The
  maintainer chose the change of the fetch.
- A `Fetched::Status` variant, which makes each caller of `fetch` match an
  unsuccessful status as a success.
- A new `Error` variant for a status with a response. Each caller that
  matches `Error::HttpStatus` then also matches the new variant.
- A per-request switch of redirect following. `max_redirects` of the
  fetcher already gives each redirect as a status at the limit of zero.
- A truncated prefix of a body over the cap. The caller cannot tell a
  truncated XML document from a malformed one.

An upload gives each final status as an `Uploaded`. An answer other than
2xx whose body declares a coding, or a `Content-Length` over
`max_response`, keeps its status and its headers, and the upload withholds
the body: `Uploaded::body_withheld` returns `true`, and the body reads as
empty. A 2xx answer with such a body fails the upload with
`Error::UploadInterrupted`. So a definitive refusal, for example
a 403 behind a proxy that compresses it, keeps its status, and the bucket
client of S3 does not send it again as an interrupted upload. An
interrupted upload in place of the status was rejected: the caller loses
the status, and repeats a request that the server refused.

## The S3 bucket client

`ostrya_remote::s3::Bucket` is the client of a bucket repository, in the
module `s3` of `ostrya-remote`, under the feature `s3`. `ostrya-remote`
holds the transports of push and pull and the type `Endpoint`, so the
client side of S3 goes there with the signer and the credential chain. A
new published crate `ostrya-s3` was rejected: it needs a `README.md`, a place
in the release sequence, and the same dependencies.

The XML bodies of the S3 responses are read with the crate `quick-xml`
0.42.0, with no feature. The reader of the port refuses a `DOCTYPE`, accepts
the five predefined entities and the character references of XML 1.0, and
refuses each other reference. It refuses a body with an open element at its
end, a second root, or an element deeper than 32 levels, and it reads at
most 4 MiB of UTF-8. Two alternatives were rejected:

- The crate `xml` 1.4.0. It reads the definitions of internal entities and
  expands them, up to 1,000,000 bytes for each expansion. Its time is
  quadratic in the depth of the elements: 40,000 levels took 831 ms, and a
  body of 4 MiB of nested elements took more than 5 minutes. In a test
  program, it cost 151,312 bytes of a stripped release binary, and
  `quick-xml` cost 45,528 bytes. On a listing of 4 MiB, `quick-xml` took
  22 ms and `xml` took 122 ms.
- A reader written in the tree. `quick-xml` gives each event and each
  reference to the caller, so the rules of the port are a short walker over
  the events. A tokenizer of its own adds the code of the lexical rules of
  XML, which the crate already has.

The fetch, the stream, and the lists of the client are fetches with
`max_error_body` of 4 MiB, and the fetcher of the client follows no redirect.
So the client sees the `x-amz-bucket-region` header and the S3 `Error`
document of each unsuccessful response. A region other than the region of
the signature, from the header or from the `Region` element, gives
`Error::S3Region`, which names both regions. A redirect of S3 to another
region is never followed, because a hop to another origin carries no
signature. The retries of a `GET` are the retries of the fetcher. The
client sends a `PUT` and a `DELETE` again itself, after an interrupted
upload and after a 408, 429, or 5xx, because an upload is never repeated by
the fetcher. `UploadBody::try_clone` gives the second request the bytes of
the first one with no copy.

A 404 is an absent key only if its body arrived whole and holds the code
`NoSuchKey` or no S3 code. A 404 with `NoSuchBucket` is an error, so a
missing bucket never reads as an empty repository. A 404 whose body did not
arrive, for example a body that stalls or fails in transit, can come from
a missing bucket too, so it is an error with no code. The absent-key rule
runs before the region check: a server that does not check the region of
the signature, and names another region in the header of a 404, still
gives an absent key. A region check on 301, 307, 400, and 403 alone was
rejected, because S3 can name the region of a bucket with another status.

A conditional `PUT` (`If-None-Match: *`) gives `PutIfAbsent::Created` only
when a request of the call got a 2xx. A request whose outcome is not known,
then a 412 or a failed request, makes the client read the key and compare
its SHA-256 with the SHA-256 of the body. The same bytes give
`PutIfAbsent::Matches`, other bytes give `PutIfAbsent::Present`, and an
absent key after a failed request sends the request again. `Matches`
states that the key holds the bytes of the body, and no answer names the
writer. So a writer lock that sends its own body again tells a 2xx of its
own request from bytes that the key held before the call. `rclone serve s3` 1.75.1 does not honor `If-None-Match: *`: a second
conditional `PUT` writes over the object.

The compare reads the object as a stream in chunks of 64 KiB, and holds no
copy of the object. A response that declares a length other than the
length of the body holds other bytes, and the client reads none of it. The
client hashes the body of the request only for a compare, on the blocking
pool of the runtime, so a `PUT` with no compare hashes its body once, in
the signer.

Each page of a list must move forward, or the list fails. Each key and
common prefix of a page of `ListObjectsV2` comes after each one of the
earlier pages, in the byte order of UTF-8. S3 can give a truncated page
with no key and no common prefix, for example over many delete markers of a
versioned bucket. The client follows such a page if its continuation token
is new since the last page with a key or a common prefix. The client keeps
the tokens of that run in a set, and a page with a key or a common prefix
clears the set. A run of more than 1000 truncated pages with no key and no
common prefix fails the list. So a server that gives the same page again,
or empty pages with new tokens and no end, fails the list. A cap on the
number of all pages was rejected: a repository has no fixed upper limit of
keys. The cap on a run of empty pages bounds the set and the time of a
list, and it does not limit the number of keys.

For `ListMultipartUploads`, the `NextKeyMarker` of each truncated page does
not come before the key marker of the page before it, in the byte order of
UTF-8. While the key marker stays the same, the `NextUploadIdMarker` is one
that no earlier page gave for that key marker. The set of these upload id
markers clears when the key marker moves forward. S3 sorts the uploads of
one key by the time of their start, and not by the upload id, so the
upload id markers of one key have no order. A rule that the pair of the
markers increases was rejected: it refuses a key with more than one page of
incomplete multipart uploads.

The request path of a key encodes each byte outside `A-Z a-z 0-9 - . _ ~ /`
as `%XX`, which is the canonical URI of SigV4. So a `+` of a delta key goes
as `%2B`, and the signature does not depend on how a server reads a raw `+`
of a path. A listing asks for the encoding type `url`, and the client
decodes `%XX` and reads a `+` as a space, as S3 and `rclone serve s3` write
a space in that encoding.

The deletion of a key is one `DELETE` for each key. `DeleteObjects`
(`POST ?delete`) was rejected: AWS requires a `Content-MD5` or a checksum
header on it, and the first one needs the crate `md-5` in a manifest.

`Bucket::put_stream` writes an object from a reader. A body of at most
one part goes in one `PUT`, and a longer body goes in a multipart upload.
The call holds one part buffer, and the parts of one object go one after
the other. The first buffer starts at 8 KiB and doubles up to the part
size, so a small object takes a small buffer. After a full part, the call
reads one byte more, so a body of exactly one part goes in one `PUT`.

After each part, the call takes the buffer back with `UploadBody::into_vec`
of `ostrya-fetch`, and reads the next part into it with no fill of zeros.
The retries of a part share its buffer, so the buffer comes back after the
last request of the part. If the fetcher still holds the bytes, the next
part takes a new buffer with the capacity of one part. Its length doubles
from 8 KiB while the bytes arrive, so a short last part does not fill a
whole part with zeros.

`s3::part_size` gives the part size of an object of `N` bytes: the larger
of 8 MiB and `(2N + 1 MiB) / 10,000`, rounded up to a whole MiB. A `.filez`
of a file with `N` bytes of content is smaller than `2N + 1 MiB`, so
10,000 parts hold it. The part size is 8 MiB up to 41,942,515,712 bytes.
A part size over 5 GiB, the S3 limit of a part, gives
`Error::LimitExceeded`. No value is clamped. A body that is longer than
10,000 parts aborts the upload and gives `Error::LimitExceeded`.

`put_stream` refuses a part size below 5 MiB or above 5 GiB. No test hook
gives smaller parts. `rclone serve s3` 1.75.1 does not enforce the 5 MiB
minimum, but SeaweedFS 4.36 refuses a small part at the completion with
400 `EntityTooSmall`. The multipart tests use parts of 5 MiB.

The retries of a multipart upload differ for each request:

- The `POST` that starts the upload and each part are sent again after an
  interrupted request and after a 408, 429, or 5xx, as a `PUT` is. A part
  goes again with the same bytes.
- The `POST` that starts the upload is also sent again after a 2xx whose
  body did not arrive. Such an answer is an interrupted request, because
  the client does not get the upload id. An interrupted start can leave an
  upload that the client does not know. Such an upload holds storage until
  an abort or a lifecycle rule of the bucket removes it, and this is
  accepted.
- The `POST` that completes the upload is also sent again after a 2xx
  whose body cannot be read, and after a 200 whose body is an S3 `Error`
  document. The AWS API reference states that a completion can fail after
  the head of a 200.
- An answer to a part with no `ETag` fails the upload, because the
  completion cannot name the part.

The client takes an upload id and an `ETag` of a part of at most 1 KiB
each. A longer upload id fails the start, and the client sends no part. A
longer `ETag` fails the upload as a missing `ETag` does, and the client
aborts the upload. So the list of the `ETag` values holds at most 10,000
values of 1 KiB, and the completion document has a limit.

The outcome of a completion is unknown after an interrupted request,
after a 408, 429, or 5xx, and after a 2xx that cannot be used. A gateway
or a load balancer can give a 408, 429, or 5xx after the server completed
the upload. A later request can then get a 404 with the code
`NoSuchUpload`, because the earlier request completed the upload:
`rclone serve s3` 1.75.1 gives this answer to a second completion, and
SeaweedFS 4.36 gives 200 with the same `ETag`. After such a 404, the
client reads the key, and accepts the object if the declared
`Content-Length` equals the number of bytes of the parts. It reads no byte
of the object. A compare of the bytes was rejected, because it reads the
whole object again and the client holds one part alone. The completion has
the default timeout of the fetcher.

The check compares the length alone. It is sound for a key whose name sets
its content, such as a content-addressed object or a static delta. For a
key whose content changes, an older object of the same length passes the
check. The check runs for each key, and this limit is accepted. An absent
object and an object of another length give `Error::Transport`, whose
message states that the completion got 404 `NoSuchUpload` and what the key
holds. A failed read of the key gives the error of `Bucket::get_stream`.

After each failure that comes after the start of an upload, the client
sends one `DELETE KEY?uploadId=ID` and ignores its outcome, so the error of
the failure is the error of the call. If the last answer to a request of
the upload is a 404 `NoSuchUpload`, the server holds no such upload, and
the client sends no abort. This is the case after the check of the key
that follows such an answer to a completion. A dropped future sends no
abort.
`Bucket::abort_upload` takes a 404 `NoSuchUpload` as success: after a
refused completion, `rclone serve s3` 1.75.1 removes the upload and gives
404 `NoSuchUpload` to each later request of it, but `ListMultipartUploads`
still gives the upload. SeaweedFS 4.36 keeps the upload after a refused
completion.

`Bucket::abort_upload` refuses an empty upload id with
`Error::InvalidInput`, and sends no request. `rclone serve s3` 1.75.1 reads
`DELETE KEY?uploadId=` with an empty value as a `DeleteObject`: it gave 204
and removed the object.

The answer that starts an upload has the root
`InitiateMultipartUploadResult` in the AWS API reference and on SeaweedFS
4.36, and `InitiateMultipartUpload` with no namespace on `rclone serve s3`
1.75.1. The reader takes both roots, and refuses an absent or empty
`UploadId`. An `ETag` of the completion result that is empty or white space
alone reads as absent, so the `ETag` header of the answer applies.

The completion document gives the `ETag` of each part as the answer to the
part gave it, with its quotes, and with `&`, `<`, and `>` escaped. Both
servers take an `ETag` with quotes, with no quotes, and with `&quot;`.

The `ETag` that `put_stream` returns is not compared with the `ETag` of a
later read. For an object of several parts, the completion gives
`"<MD5 of the MD5 values of the parts>-N"` on both servers. A later read
on `rclone serve s3` 1.75.1 gives the MD5 of the whole object, and
SeaweedFS 4.36 keeps the value with `-N`.

The signer hashes each part on the task of the call, as for each body of
bytes (`SignPayload::Bytes`). The SHA-256 of 8 MiB takes about 4.8 ms on
the dev host, about 1674 MiB/s. A part over about 16.7 MiB passes 10 ms.
`s3::part_size` gives such a part to an object over about 78 GiB. This time
is accepted.

`Endpoint` of `ostrya-remote` has `#[non_exhaustive]`, and the variant
`Endpoint::S3` is behind the feature `s3`. Cargo features are additive, so
without the attribute a crate that matches each variant compiles alone and
fails when another crate of the same build turns `s3` on. A variant with no
feature gate was rejected: `S3Endpoint` and the types that it holds then
compile in each build. The push session constructors refuse `Endpoint::S3`.
`PullSession::connect` opens an HTTP pull session to it, with the fetcher
options of `S3Endpoint::pull_options`. `Endpoint::parse` refuses an `s3://`
address, because the endpoint needs credentials that the parse does not
read.

## The S3 pull

`resolve_pull` gives `Endpoint::S3` for an `s3://` address, and the variant
is the mark of a pull from a bucket repository. `Endpoint::Http` with a
signer was rejected: such an endpoint has no mark of S3, and the pull needs
the mark for two rules. The pull reads the root files through the bucket
client, and `Repo::pull_collection` refuses the remote.

The fetcher of the pull has the one mirror of the repository URL, the SigV4
signer, and `max_redirects` set to 0. A redirect to another origin carries
no signature, so a redirect of S3 to the region of the bucket fails at the
other origin. With no redirect, the pull fails at the first answer, and the
bucket client names the region.

`summary.sig`, `summary`, and `config` go through `s3::Bucket::get`, and the
objects, the deltas, and the ref files go through the signed fetcher of the
pull. A fetch keeps no body of an error response, so through the fetcher a
wrong secret key is a bare 403, and a 404 of an absent bucket reads as a
repository with no summary. The bucket client reads the S3 error document.
Thus a wrong secret key gives `Error::S3` with the code
`SignatureDoesNotMatch`, a bucket of another region gives `Error::S3Region`,
and 404 `NoSuchBucket` is an error. `ostrya::Error::Remote` carries each of
them. `s3::Bucket::from_fetcher` opens the bucket client over a clone of
the fetcher of the pull, so the pull builds one fetcher: one read of the
trust store and one connection pool. A second fetcher from
`s3::Bucket::new` was rejected: it reads the trust store again and opens its
own connections. The bucket client names each request by its URL under the
bucket URL, so it reads the keys of the repository through the fetcher
whose mirror is the repository URL. The clone has no byte counter, so these
reads do not count in `PullStats::bytes_transferred`, as the reads of the
root files over HTTP do not.

A pull from a bucket repository needs the permissions `s3:GetObject` and
`s3:ListBucket` on the bucket. Without `s3:ListBucket`, AWS answers the read
of an absent key with 403 `AccessDenied` in place of 404. The pull then fails
at an absent optional file, for example `summary.sig` or the `.commitmeta`
of a commit. A 403 stays an error: the same answer comes for a present key
that the credentials cannot read, and a pull that reads it as absent
continues without a signature or a file that the bucket holds.

`EndpointOverrides` gets four fields with no feature gate: `s3_region`,
`s3_endpoint`, `s3_addressing`, and `s3_profile`, each an `Option<String>`.
A build without the feature `s3` has the same struct, so a caller that
builds it compiles with and without the feature. `s3_addressing` is text,
because the type `s3::Addressing` is behind the feature. The pull reads it
with `Addressing::from_name` and refuses another value by the name
`s3-addressing`. The keys of the same names follow the same rule. A field
of the caller wins over its key, and `s3::resolve` gives each other source.

An S3 field or an S3 key with an address that is not S3 is refused. An
`s3://` address in the key `url` is refused, in each build, as an ssh
address there is refused: the `ostree` command also reads `url`.

`resolve_pull` refuses an `http://` S3 endpoint without
`allow_cleartext_credentials`, because the signature is a credential. The
check comes after the resolution, because the endpoint can come from the
environment or from a profile. The rule applies to an S3 endpoint alone,
and the resolution of a pull from an HTTP address does not change.

`Repo::pull_collection` refuses an S3 remote before it resolves the
endpoint, so the refusal reads no AWS variable and no AWS file. A bucket
repository holds no collection ref, and no server answers `_ostrya/refs/v1`
for it. `Repo::pull` does not send that request.

## The client access of `ostrya serve`

- The reader of the PROXY protocol, v1 and v2, is written in the tree, with
  no crate. The CIDR match of `trusted-proxy` and of a `net:` item is
  `std::net::IpAddr` and a prefix length, with no crate.
- A forwarded certificate in base64 DER is decoded by `ostrya::base64`, so
  no base64 crate is a dependency.
- The server keeps each verified forwarded certificate in a cache. One
  verification costs 23 to 52 µs of CPU, and each request from a proxy
  carries the certificate, each object `GET` included.

## The protocol versions

Protocol version 1 changed in place for the client groups, the server
commit, the collection selectors of the ref listing, and the object type
100. No deployment ran version 1 when these changes came, so the version
number did not change. Thus a receiver that does not take the type 100
refuses a sender that sends an image.

## GC anchor keys

- `Repo::prune` reads `[ex-ostrya] gc-root-metadata-keys` and merges the
  keys of the caller into the list. The config key is the policy of the
  repository, and it only adds roots. Thus a library caller cannot remove a
  config key from a run, and a run keeps at least what the same run with no
  config key keeps.
- A commit write refuses a value of an anchor key that a prune refuses.
  Else the commit enters the store, and each later prune that reaches it
  fails.
- The library does not know where an entry of a metadata dict comes from.
  Thus the check cannot exempt a value that `ostrya commit --keep-metadata`
  copies from the parent commit.

## The pull scheduler

`crates/ostrya/src/pull/drive.rs` is a poll core of the port.
`FuturesUnordered` was rejected: `futures-lite` has no unordered join, and
`futures-util` is not in the graph.

## The expression engine of `--tar-pathname-filter`

`commit --tar-pathname-filter` compiles its expression with PCRE2, the
library that the `ostree` command compiles it with. This follows rule 2 of
`CLAUDE.md`, "CLI compatibility is functional, not literal". Two other
engines were rejected on measurements:

- A backtracking matcher written in the tree. A review found three
  constructs that it read differently from PCRE, and three paths with no
  bound on the work.
- The `regex` crate. It read the POSIX class names as ASCII, and `$` as the
  end of the text. Thus one command line wrote two different commits.

## `#[non_exhaustive]` on the public types

The attribute marks a type that a caller matches over and does not build,
when the port owns its set of members and expects the set to grow.

- `ostrya::Error` has the attribute. Its variants are the error vocabulary of
  the port, and a new failure mode adds a variant.
- `TrustRoots` has the attribute. The port owns the set of trust settings.
- `ostrya_fetch::UploadMethod` and `ostrya_fetch::SignPayload` have the
  attribute. The fetcher owns the set of upload methods and the set of body
  forms that a signer gets.
- `ostrya_remote::s3::Origin` and `ostrya_remote::s3::Resolved` have the
  attribute. The port owns the set of sources of an S3 setting, and the set
  of resolved settings grows with the S3 support.
- `ostrya_remote::transport::Endpoint` has the attribute, and
  `Endpoint::S3` is behind the feature `s3`. A match outside
  `ostrya-remote` needs a wildcard arm, so the build compiles with and
  without the feature. "The S3 bucket client" states the reason.
- `ostrya_remote::s3::S3Endpoint`, `Object`, `PutIfAbsent`, `Listing`,
  `Listed`, and `Upload` have the attribute, and so do the variants
  `ostrya_remote::Error::S3` and `ostrya_remote::Error::S3Region`. The bucket
  client builds them, and the set of fields grows with the S3 support. A
  caller builds an `S3Endpoint` with `S3Endpoint::new` and sets its fields.
- No option struct of the `ostrya` crate has the attribute: `PruneOptions`,
  `PullOptions`, `TarExportOptions`, `TarImportOptions` and the others. The
  attribute stops a struct expression outside the defining crate,
  `..Default::default()` included. Thus a new field in one of these option
  structs is a breaking change, and it takes a minor version before 1.0.
- `ostrya_server::ServeOptions` and `ostrya_mount::MountOptions` have the
  attribute. A caller starts from `Default::default()` and sets the fields.
- `ostrya_gvariant::Type` and `ostrya_gvariant::Value` do not have the
  attribute. The GVariant serialization specification closes the type
  alphabet, and the two enums name all of it. An exhaustive `match` over
  either enum is the gate that makes each site answer for a new type
  character. A new variant in either enum takes a major version.
