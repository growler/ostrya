use std::fmt;

/// An error of the GVariant codec.
///
/// The functions that encode and decode GVariant bytes return it.
/// [`Type::parse`], [`to_text`], and [`to_text_unannotated`] also return it.
/// [`from_text`] returns a [`TextError`].
///
/// [`Type::parse`]: crate::Type::parse
/// [`to_text`]: crate::to_text
/// [`to_text_unannotated`]: crate::to_text_unannotated
/// [`from_text`]: crate::from_text
/// [`TextError`]: crate::TextError
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A type signature string that [`Type::parse`] refuses.
    ///
    /// [`Type::parse`]: crate::Type::parse
    InvalidTypeString {
        /// The signature string that the caller gave.
        signature: String,
        /// The byte offset in `signature` at which the parse fails.
        offset: usize,
        /// The reason for the failure.
        ///
        /// [`Type::parse`] lists each reason.
        ///
        /// [`Type::parse`]: crate::Type::parse
        reason: &'static str,
    },
    /// The value does not match its type.
    ///
    /// [`to_bytes`], [`to_text`], and [`to_text_unannotated`] return it.
    ///
    /// [`to_bytes`]: crate::to_bytes
    /// [`to_text`]: crate::to_text
    /// [`to_text_unannotated`]: crate::to_text_unannotated
    TypeMismatch {
        /// The signature of the type that the caller paired with the value.
        expected: String,
        /// The kind of the value, for example `array` or `tuple of a different
        /// arity`.
        found: &'static str,
    },
    /// GVariant cannot represent the value.
    ///
    /// This crate returns it for a string that holds an interior NUL byte.
    /// The field holds the reason.
    InvalidValue(&'static str),
    /// The serialized bytes are not normal-form GVariant of the expected type.
    ///
    /// The field names the deviation.
    NotNormal(&'static str),
    /// The container nesting exceeds the depth limit of 128 levels.
    ///
    /// Each variant, array, maybe, tuple, and dict entry adds one level.
    /// [`from_bytes`], [`validate`], [`tuple_field_from_bytes`], and
    /// [`to_bytes`] return it. The decode of a [`Variant`] returns it through
    /// [`from_bytes`]. [`Type::parse`] applies the same limit to a signature
    /// and returns [`Error::InvalidTypeString`].
    ///
    /// [`Variant`]: crate::Variant
    /// [`from_bytes`]: crate::from_bytes
    /// [`validate`]: crate::validate
    /// [`tuple_field_from_bytes`]: crate::tuple_field_from_bytes
    /// [`to_bytes`]: crate::to_bytes
    /// [`Type::parse`]: crate::Type::parse
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

/// The result type of the codec.
pub type Result<T> = std::result::Result<T, Error>;
