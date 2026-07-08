#![forbid(unsafe_code)]

//! Byte-exact GVariant codec for the ostree on-disk format.
//!
//! This crate has no ostree knowledge. It serializes and deserializes the fixed
//! set of GVariant type signatures ostree uses, in GVariant normal form. The
//! checksum of every metadata object is the hash of these bytes, so byte
//! exactness here is the bedrock for every downstream phase.
//!
//! The codec implementation lands in phase 1 of the port plan (see
//! `docs/port-plan.md`).
