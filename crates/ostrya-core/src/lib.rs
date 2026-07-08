#![forbid(unsafe_code)]

//! ostree object model, checksums, and on-disk format primitives.
//!
//! Builds on the ostrya-gvariant codec to serialize and parse commits,
//! dirtrees, dirmeta, and file headers, and provides the checksum type, LEB128
//! varint, loose-path derivation, `ostree.sizes` packing, and xattr
//! canonicalization.
//!
//! These primitives land in phases 2 and 3 of the port plan (see
//! `docs/port-plan.md`).
