use std::fmt;

/// Errors produced by the codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The type signature string is not one this codec accepts.
    InvalidTypeString {
        signature: String,
        offset: usize,
        reason: &'static str,
    },
    /// The value's shape does not match the type it is serialized as.
    TypeMismatch {
        expected: String,
        found: &'static str,
    },
    /// The value cannot be represented in GVariant.
    InvalidValue(&'static str),
    /// The serialized bytes are not normal-form GVariant of the expected type.
    NotNormal(&'static str),
    /// Container nesting exceeds the codec's depth limit.
    DepthExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTypeString {
                signature,
                offset,
                reason,
            } => write!(
                f,
                "invalid type signature {signature:?} at offset {offset}: {reason}"
            ),
            Error::TypeMismatch { expected, found } => {
                write!(f, "value of kind {found} does not match type {expected:?}")
            }
            Error::InvalidValue(reason) => write!(f, "unrepresentable value: {reason}"),
            Error::NotNormal(reason) => write!(f, "data is not normal-form GVariant: {reason}"),
            Error::DepthExceeded => write!(f, "container nesting exceeds the supported depth"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
