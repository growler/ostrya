//! The reader of the GVariant text form.
//!
//! `MAX_NESTING` bounds the depth of the node tree. This limit also bounds the
//! recursion of type inference, of value construction, and of the drop of the
//! tree.

use std::fmt;

use crate::{Type, Value};

/// The nesting level at which the parser refuses a value.
///
/// A container, a `just`, a variant, a type declaration, and a type keyword
/// each add one level. The parser refuses the value at this level with
/// `variant nested too deeply`.
const MAX_NESTING: usize = 128;

/// A half-open byte range of the input text that a [`TextError`] names.
///
/// [`fmt::Display`] writes `start` for a zero-width span, and `start-end`
/// for every other span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// The byte offset at which the range starts.
    pub start: usize,
    /// The byte offset one past the end of the range.
    ///
    /// It equals [`start`](Span::start) for the zero-width position that an
    /// `expected ...` refusal reports.
    pub end: usize,
}

impl Span {
    fn new(start: usize, end: usize) -> Span {
        Span { start, end }
    }

    /// The zero-width position ahead of a token.
    ///
    /// An `expected ...` refusal reports this position.
    fn point(at: usize) -> Span {
        Span { start: at, end: at }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// The error for a GVariant text form that [`from_text`] refuses.
///
/// It holds the spans of the input that the refusal names, and the reason.
/// [`fmt::Display`] writes the pair as `<spans>:<reason>`, the form that the
/// `ostree` command reports. A comma separates two spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextError {
    /// The ranges of the input that the refusal names.
    ///
    /// The ranges are in the order of the message. Most refusals hold one
    /// span. If the reason names a pair that disagrees, the field holds two
    /// spans, for example the two elements that a container cannot unify.
    pub spans: Vec<Span>,
    /// The refusal text, without the spans and without the separating colon.
    pub reason: String,
}

impl TextError {
    fn new(span: Span, reason: impl Into<String>) -> TextError {
        TextError {
            spans: vec![span],
            reason: reason.into(),
        }
    }
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, span) in self.spans.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{span}")?;
        }
        write!(f, ":{}", self.reason)
    }
}

impl std::error::Error for TextError {}

type TextResult<T> = std::result::Result<T, TextError>;

/// The reason for the refusal of a literal that states no type.
///
/// [`value_type`] widens the span of this error to the whole value. The
/// `ostree` command reports the refusal at that span.
const CANNOT_INFER: &str = "unable to infer type";

/// Reads one GVariant text form and returns the type it states and the value.
///
/// [`to_text`](crate::to_text) writes this form. The reader parses, types, and builds the
/// first value. Then it checks the text for trailing input.
///
/// The rules and every refusal message come from the `ostree` command, run as
/// a black box. `ostree commit --add-metadata=KEY=VALUE` stored each value,
/// and `ostree show -B --print-metadata-key` read it back.
///
/// # Type inference
///
/// - A value takes its type from its literal. An integer literal with no
///   other context is `i`, and a literal with a fraction is `d`.
/// - If the literal cannot state the type, a declaration (`@ms 'x'`) or a
///   keyword (`uint32 42`) states it.
/// - A container with no declaration unifies the types of its elements.
///   `[2, 1.5]` is `ad`, and `['a', @ms 'b']` is `ams`.
/// - A declaration drives the check down into the members. The error for
///   `@as [1]` names the element `1` and the type `s`.
/// - The reader refuses a literal that states no type and has no context,
///   for example `[]`, `{}`, or `nothing`. The reason is
///   `unable to infer type`.
///
/// # Depth limit
///
/// A container, a `just`, a variant, a type declaration, and a type keyword
/// each add one level. A value can nest inside at most 127 levels. If the
/// text reaches level 128, the reader refuses it with
/// `variant nested too deeply`.
///
/// A declared type counts its own levels, with the leaf as one level, from
/// the level of the declaration. The empty tuple `()` holds no leaf, so it
/// counts as zero levels. If the sum is more than 128, the reader
/// refuses the declaration with `type declaration recurses too deeply`.
///
/// # Errors
///
/// If the reader refuses the text, it returns a [`TextError`]. The error for
/// a fault in the first value has priority over the error for trailing input.
/// For example, `nothing 5` reports the type that the reader cannot infer.
/// `@i 'x' 5` reports the member that does not fit.
///
/// # Examples
///
/// ```
/// use ostrya_gvariant::{from_text, to_text};
///
/// let (ty, value) = from_text("{'version': <'1'>}")?;
/// assert_eq!(ty.signature(), "a{sv}");
/// assert_eq!(to_text(&ty, &value)?, "{'version': <'1'>}");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn from_text(text: &str) -> TextResult<(Type, Value)> {
    let mut parser = Parser::new(text);
    let node = parser.value()?;
    let ty = value_type(&node)?;
    let value = build(&node, &ty)?;
    parser.expect_end()?;
    Ok((ty, value))
}

// --- tokens ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Open(char),
    Close(char),
    Comma,
    Colon,
    /// `@` and the characters that follow it.
    ///
    /// The parser checks these characters as a type after the lexer scans the
    /// token.
    TypeDecl(String),
    Word(String),
    Number(String),
    Str(String),
    ByteString(Vec<u8>),
    End,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    span: Span,
}

struct Lexer<'a> {
    text: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Lexer<'a> {
        Lexer {
            text: text.as_bytes(),
            pos: 0,
        }
    }

    fn skip_space(&mut self) {
        while matches!(self.text.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn next(&mut self) -> TextResult<Token> {
        self.skip_space();
        let start = self.pos;
        let Some(&c) = self.text.get(start) else {
            return Ok(Token {
                tok: Tok::End,
                span: Span::point(start),
            });
        };
        let tok =
            match c {
                b'(' | b'[' | b'{' | b'<' => {
                    self.pos += 1;
                    Tok::Open(c as char)
                }
                b')' | b']' | b'}' | b'>' => {
                    self.pos += 1;
                    Tok::Close(c as char)
                }
                b',' => {
                    self.pos += 1;
                    Tok::Comma
                }
                b':' => {
                    self.pos += 1;
                    Tok::Colon
                }
                b'@' => {
                    self.pos += 1;
                    self.declaration();
                    Tok::TypeDecl(self.slice(start + 1, self.pos))
                }
                b'\'' | b'"' => return self.string(start, c, false),
                b'b' if matches!(self.text.get(start + 1), Some(b'\'' | b'"')) => {
                    let quote = self.text[start + 1];
                    self.pos += 1;
                    return self.string(start, quote, true);
                }
                b'0'..=b'9' | b'-' | b'+' | b'.' => {
                    self.pos += 1;
                    while self.text.get(self.pos).is_some_and(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-')
                    }) {
                        self.pos += 1;
                    }
                    Tok::Number(self.slice(start, self.pos))
                }
                b'a'..=b'z' => {
                    while self
                        .text
                        .get(self.pos)
                        .is_some_and(u8::is_ascii_alphanumeric)
                    {
                        self.pos += 1;
                    }
                    Tok::Word(self.slice(start, self.pos))
                }
                // Every other character is a one-character token. No keyword has
                // one character, so the parser reports the token as a place where
                // it expected a value.
                _ => {
                    self.pos += 1;
                    Tok::Word(self.slice(start, self.pos))
                }
            };
        Ok(Token {
            tok,
            span: Span::new(start, self.pos),
        })
    }

    /// Scans the body of a `@` declaration.
    ///
    /// The scan stops at the first character that can close something around
    /// the declaration. These characters are white space, `,`, `:`, `>`, `]`,
    /// and an unmatched `)` or `}`. The scan reads all of `@i5` and `@**`,
    /// and the parser reports each as one bad declaration. The scan of `@i)`
    /// stops at the bracket.
    fn declaration(&mut self) {
        let mut depth = 0usize;
        while let Some(&c) = self.text.get(self.pos) {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' | b',' | b':' | b'>' | b']' => break,
                b')' | b'}' if depth == 0 => break,
                b')' | b'}' => depth -= 1,
                b'(' | b'{' => depth += 1,
                _ => {}
            }
            self.pos += 1;
        }
    }

    /// Scans a quoted literal from `start`, with `quote` as its opening quote.
    ///
    /// A bytestring keeps its bytes. The scan decodes a string as UTF-8.
    fn string(&mut self, start: usize, quote: u8, bytestring: bool) -> TextResult<Token> {
        self.pos += 1; // the opening quote
        let mut raw = Vec::new();
        loop {
            let Some(&c) = self.text.get(self.pos) else {
                self.pos = self.text.len();
                return Err(TextError::new(
                    Span::new(start, self.pos),
                    "unterminated string constant",
                ));
            };
            self.pos += 1;
            if c == quote {
                break;
            }
            if c != b'\\' {
                // A string value carries no NUL, so the scan refuses a raw NUL
                // in a string at its position. A bytestring keeps the NUL, and
                // its value ends there. An octal escape that names NUL has the
                // same result.
                if c == 0 && !bytestring {
                    return Err(TextError::new(
                        Span::new(self.pos - 1, self.pos),
                        "NUL byte in string constant",
                    ));
                }
                raw.push(c);
                continue;
            }
            let Some(&escaped) = self.text.get(self.pos) else {
                self.pos = self.text.len();
                return Err(TextError::new(
                    Span::new(start, self.pos),
                    "unterminated string constant",
                ));
            };
            self.pos += 1;
            match escaped {
                b'a' => raw.push(0x07),
                b'b' => raw.push(0x08),
                b'f' => raw.push(0x0c),
                b'n' => raw.push(b'\n'),
                b'r' => raw.push(b'\r'),
                b't' => raw.push(b'\t'),
                b'v' => raw.push(0x0b),
                b'0'..=b'7' if bytestring => {
                    // A bytestring reads a maximum of three octal digits. The
                    // printer writes this escape for a bytestring.
                    let mut value = u32::from(escaped - b'0');
                    for _ in 0..2 {
                        match self.text.get(self.pos) {
                            Some(&d @ b'0'..=b'7') => {
                                value = value * 8 + u32::from(d - b'0');
                                self.pos += 1;
                            }
                            _ => break,
                        }
                    }
                    raw.push(value as u8);
                }
                b'u' if !bytestring => self.unicode_escape(4, &mut raw)?,
                b'U' if !bytestring => self.unicode_escape(8, &mut raw)?,
                // A backslash before a line feed is a line continuation. Both
                // characters leave the value. A string and a bytestring use the
                // same rule.
                b'\n' => {}
                // Every other escape drops the backslash and keeps the byte.
                other => raw.push(other),
            }
        }
        let span = Span::new(start, self.pos);
        if bytestring {
            // A bytestring literal names a NUL-terminated byte array, so the
            // value ends at the first NUL that its escapes produce. Then the
            // value gets one terminator of its own.
            if let Some(nul) = raw.iter().position(|&b| b == 0) {
                raw.truncate(nul);
            }
            raw.push(0);
            return Ok(Token {
                tok: Tok::ByteString(raw),
                span,
            });
        }
        match String::from_utf8(raw) {
            Ok(text) => Ok(Token {
                tok: Tok::Str(text),
                span,
            }),
            Err(_) => Err(TextError::new(span, "invalid character in string constant")),
        }
    }

    /// Reads a `\u` or `\U` escape of `digits` hexadecimal digits.
    ///
    /// It appends the named character to `raw` in UTF-8. A refusal names the
    /// digits that are present. If no digits are present, the refusal names a
    /// zero-width position.
    fn unicode_escape(&mut self, digits: usize, raw: &mut Vec<u8>) -> TextResult<()> {
        let start = self.pos;
        let mut count = 0;
        while count < digits
            && self
                .text
                .get(start + count)
                .is_some_and(u8::is_ascii_hexdigit)
        {
            count += 1;
        }
        let bad = || {
            TextError::new(
                Span::new(start, start + count),
                format!("invalid {digits}-character unicode escape"),
            )
        };
        if count < digits {
            return Err(bad());
        }
        let text = std::str::from_utf8(&self.text[start..start + digits]).map_err(|_| bad())?;
        let code = u32::from_str_radix(text, 16).map_err(|_| bad())?;
        // A string value carries no NUL, so this check refuses U+0000. It uses
        // the words and the offset of the `ostree` command. This check also
        // refuses a surrogate and a code point past U+10FFFF. For these, the
        // `ostree` command builds a string that is not UTF-8 and aborts.
        let ch = char::from_u32(code)
            .filter(|&c| c != '\0')
            .ok_or_else(bad)?;
        self.pos = start + digits;
        let mut buf = [0u8; 4];
        raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        Ok(())
    }

    fn slice(&self, start: usize, end: usize) -> String {
        String::from_utf8_lossy(&self.text[start..end]).into_owned()
    }
}

// --- the syntax tree ---------------------------------------------------------

#[derive(Debug, Clone)]
struct Node {
    ast: Ast,
    span: Span,
}

#[derive(Debug, Clone)]
enum Ast {
    Bool(bool),
    /// A numeric literal, kept as its text.
    ///
    /// Its value depends on the type that it gets. For example, `@d 017` is
    /// 17.0, and `017` alone is 15.
    Number(String),
    Str(String),
    ByteString(Vec<u8>),
    /// A value under a `@type` declaration or a type keyword.
    Typed(Type, Box<Node>),
    /// `just <value>`, or `nothing`.
    Maybe(Option<Box<Node>>),
    Array(Vec<Node>),
    /// `{key: value, ...}`, an array of dict entries.
    Dict(Vec<(Node, Node)>),
    /// `{key, value}`, one dict entry.
    Entry(Box<Node>, Box<Node>),
    Tuple(Vec<Node>),
    Variant(Box<Node>),
}

/// Returns `true` if a token has the shape of a keyword.
///
/// A keyword has two or more characters, and its first two characters are
/// letters. If a token has this shape and is not a known keyword, the parser
/// reports `unknown keyword`. The parser reports a shorter token, or a token
/// with a digit as its second character, with `expected value`.
fn is_keyword_shaped(word: &str) -> bool {
    let bytes = word.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1].is_ascii_alphabetic()
}

/// The type keywords that a value can carry in place of a `@` declaration.
fn keyword_type(word: &str) -> Option<Type> {
    Some(match word {
        "boolean" => Type::Bool,
        "byte" => Type::Byte,
        "int16" => Type::I16,
        "uint16" => Type::U16,
        "int32" => Type::I32,
        "handle" => Type::Handle,
        "uint32" => Type::U32,
        "int64" => Type::I64,
        "uint64" => Type::U64,
        "double" => Type::Double,
        "string" => Type::Str,
        "objectpath" => Type::ObjectPath,
        "signature" => Type::Signature,
        _ => return None,
    })
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    /// The next token, or the error from the lexer for that token.
    ///
    /// When the parser consumes the token, the error surfaces.
    ahead: TextResult<Token>,
    /// The end offset of the token that the parser consumed last.
    ///
    /// It closes the span of a container.
    last_end: usize,
    /// The number of levels of container, `just`, variant, or declaration
    /// around the value that the parser reads.
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Parser<'a> {
        let mut lexer = Lexer::new(text);
        let ahead = lexer.next();
        Parser {
            lexer,
            ahead,
            last_end: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<&Tok> {
        self.ahead.as_ref().ok().map(|token| &token.tok)
    }

    /// The offset at which the next token starts.
    ///
    /// An `expected ...` refusal reports this offset.
    fn ahead_start(&self) -> usize {
        self.ahead
            .as_ref()
            .map_or(self.last_end, |token| token.span.start)
    }

    fn bump(&mut self) -> TextResult<Token> {
        let next = self.lexer.next();
        let token = std::mem::replace(&mut self.ahead, next)?;
        self.last_end = token.span.end;
        Ok(token)
    }

    fn expect_end(&mut self) -> TextResult<()> {
        match &self.ahead {
            Ok(token) if token.tok == Tok::End => Ok(()),
            Ok(token) => Err(TextError::new(
                Span::point(token.span.start),
                "expected end of input",
            )),
            Err(error) => Err(error.clone()),
        }
    }

    /// Reads one value nested inside the current value, one level deeper.
    fn nested(&mut self) -> TextResult<Node> {
        self.depth += 1;
        let node = self.value();
        self.depth -= 1;
        node
    }

    fn value(&mut self) -> TextResult<Node> {
        if self.depth >= MAX_NESTING {
            return Err(TextError::new(
                Span::point(self.ahead_start()),
                "variant nested too deeply",
            ));
        }
        let token = self.bump()?;
        let start = token.span.start;
        match token.tok {
            Tok::Str(text) => Ok(Node {
                ast: Ast::Str(text),
                span: token.span,
            }),
            Tok::ByteString(bytes) => Ok(Node {
                ast: Ast::ByteString(bytes),
                span: token.span,
            }),
            Tok::Number(text) => Ok(Node {
                ast: Ast::Number(text),
                span: token.span,
            }),
            Tok::TypeDecl(signature) => {
                // The parser reads a declaration in three steps. First, the
                // signature must spell one complete type. Next, that type must
                // fit in the nesting that is left at this level. Last, the type
                // must be definite.
                let parsed = Type::parse(&signature).ok();
                let levels = match &parsed {
                    Some(ty) => type_depth(ty),
                    None => match classify_declaration(&signature) {
                        Declaration::Indefinite(levels) => levels,
                        Declaration::Invalid => {
                            return Err(TextError::new(token.span, "invalid type declaration"));
                        }
                    },
                };
                // The levels of the declared type count from the level of the
                // declaration. The deeper the declaration is, the fewer
                // levels its type can have.
                if self.depth + levels > MAX_NESTING {
                    return Err(TextError::new(
                        token.span,
                        "type declaration recurses too deeply",
                    ));
                }
                let Some(ty) = parsed else {
                    return Err(TextError::new(
                        token.span,
                        "type declarations must be definite",
                    ));
                };
                let child = self.nested()?;
                let end = child.span.end;
                Ok(Node {
                    ast: Ast::Typed(ty, Box::new(child)),
                    span: Span::new(start, end),
                })
            }
            // A keyword has two or more characters and starts with two
            // letters. The parser reports any other word as a place where it
            // expected a value.
            Tok::Word(word) if is_keyword_shaped(&word) => self.word(&word, token.span),
            Tok::Open('[') => self.array(start),
            Tok::Open('{') => self.dict(start),
            Tok::Open('(') => self.tuple(start),
            Tok::Open('<') => {
                let child = self.nested()?;
                self.close('>', "expected '>' to follow variant value")?;
                Ok(Node {
                    ast: Ast::Variant(Box::new(child)),
                    span: Span::new(start, self.last_end),
                })
            }
            _ => Err(TextError::new(Span::point(start), "expected value")),
        }
    }

    fn word(&mut self, word: &str, span: Span) -> TextResult<Node> {
        match word {
            "true" => Ok(Node {
                ast: Ast::Bool(true),
                span,
            }),
            "false" => Ok(Node {
                ast: Ast::Bool(false),
                span,
            }),
            // The two numeric literals that are words. `infinity` is a value
            // only after a sign, for example `-infinity`.
            "nan" | "inf" => Ok(Node {
                ast: Ast::Number(word.to_owned()),
                span,
            }),
            "nothing" => Ok(Node {
                ast: Ast::Maybe(None),
                span,
            }),
            "just" => {
                let child = self.nested()?;
                let end = child.span.end;
                Ok(Node {
                    ast: Ast::Maybe(Some(Box::new(child))),
                    span: Span::new(span.start, end),
                })
            }
            _ => match keyword_type(word) {
                Some(ty) => {
                    let child = self.nested()?;
                    let end = child.span.end;
                    Ok(Node {
                        ast: Ast::Typed(ty, Box::new(child)),
                        span: Span::new(span.start, end),
                    })
                }
                None => Err(TextError::new(span, "unknown keyword")),
            },
        }
    }

    fn array(&mut self, start: usize) -> TextResult<Node> {
        let mut items = Vec::new();
        if matches!(self.peek(), Some(Tok::Close(']'))) {
            self.bump()?;
            return Ok(Node {
                ast: Ast::Array(items),
                span: Span::new(start, self.last_end),
            });
        }
        loop {
            items.push(self.nested()?);
            match self.peek() {
                Some(Tok::Comma) => {
                    self.bump()?;
                }
                Some(Tok::Close(']')) => {
                    self.bump()?;
                    break;
                }
                _ => {
                    return Err(TextError::new(
                        Span::point(self.ahead_start()),
                        "expected ',' or ']' to follow array element",
                    ));
                }
            }
        }
        Ok(Node {
            ast: Ast::Array(items),
            span: Span::new(start, self.last_end),
        })
    }

    fn dict(&mut self, start: usize) -> TextResult<Node> {
        if matches!(self.peek(), Some(Tok::Close('}'))) {
            self.bump()?;
            return Ok(Node {
                ast: Ast::Dict(Vec::new()),
                span: Span::new(start, self.last_end),
            });
        }
        let first_key = self.nested()?;
        // `{key, value}` is one dict entry. `{key: value, ...}` is an array of
        // dict entries.
        if matches!(self.peek(), Some(Tok::Comma)) {
            self.bump()?;
            let value = self.nested()?;
            self.close('}', "expected '}' at end of dictionary entry")?;
            return Ok(Node {
                ast: Ast::Entry(Box::new(first_key), Box::new(value)),
                span: Span::new(start, self.last_end),
            });
        }
        if !matches!(self.peek(), Some(Tok::Colon)) {
            return Err(TextError::new(
                Span::point(self.ahead_start()),
                "expected ':' or ',' to follow dictionary entry key",
            ));
        }
        self.bump()?;
        let mut entries = vec![(first_key, self.nested()?)];
        loop {
            match self.peek() {
                Some(Tok::Comma) => {
                    self.bump()?;
                }
                Some(Tok::Close('}')) => {
                    self.bump()?;
                    break;
                }
                _ => {
                    return Err(TextError::new(
                        Span::point(self.ahead_start()),
                        "expected ',' or '}' to follow dictionary entry",
                    ));
                }
            }
            let key = self.nested()?;
            if !matches!(self.peek(), Some(Tok::Colon)) {
                return Err(TextError::new(
                    Span::point(self.ahead_start()),
                    "expected ':' to follow dictionary entry key",
                ));
            }
            self.bump()?;
            entries.push((key, self.nested()?));
        }
        Ok(Node {
            ast: Ast::Dict(entries),
            span: Span::new(start, self.last_end),
        })
    }

    fn tuple(&mut self, start: usize) -> TextResult<Node> {
        let mut items = Vec::new();
        if matches!(self.peek(), Some(Tok::Close(')'))) {
            self.bump()?;
            return Ok(Node {
                ast: Ast::Tuple(items),
                span: Span::new(start, self.last_end),
            });
        }
        // The text form of a one-member tuple is `(x,)`. The comma after the
        // first element is necessary, and the parser refuses `(x)`.
        items.push(self.nested()?);
        if !matches!(self.peek(), Some(Tok::Comma)) {
            return Err(TextError::new(
                Span::point(self.ahead_start()),
                "expected ',' after first tuple element",
            ));
        }
        self.bump()?;
        if matches!(self.peek(), Some(Tok::Close(')'))) {
            self.bump()?;
            return Ok(Node {
                ast: Ast::Tuple(items),
                span: Span::new(start, self.last_end),
            });
        }
        loop {
            items.push(self.nested()?);
            match self.peek() {
                Some(Tok::Comma) => {
                    self.bump()?;
                }
                Some(Tok::Close(')')) => {
                    self.bump()?;
                    break;
                }
                _ => {
                    return Err(TextError::new(
                        Span::point(self.ahead_start()),
                        "expected ',' or ')' to follow tuple element",
                    ));
                }
            }
        }
        Ok(Node {
            ast: Ast::Tuple(items),
            span: Span::new(start, self.last_end),
        })
    }

    fn close(&mut self, bracket: char, reason: &str) -> TextResult<()> {
        if matches!(self.peek(), Some(Tok::Close(c)) if *c == bracket) {
            self.bump()?;
            return Ok(());
        }
        Err(TextError::new(Span::point(self.ahead_start()), reason))
    }
}

// --- type declarations -------------------------------------------------------

/// The class of a `@` declaration that the [`Type`] parser refused.
enum Declaration {
    /// One complete type that names `r`, `*`, or `?`.
    ///
    /// The field holds the levels of the type, as [`type_depth`] counts them.
    Indefinite(usize),
    /// Not one complete type.
    Invalid,
}

/// The maximum nesting of a declaration scan.
///
/// If a declaration is deeper, the scan reports it as invalid. This value is
/// the depth that the [`Type`] parser accepts. If the scanner reads a
/// declaration to the end, the parser refused that declaration for a
/// different reason.
const MAX_DECLARATION_DEPTH: usize = crate::de::MAX_VALUE_DEPTH;

/// The number of levels that a declared type carries.
///
/// A value under the type takes up the same number of levels of nesting. A
/// leaf is one level. Each container adds one level over its deepest member.
/// For example, `y` is one level, `aay` is three, and `(y(y))` is three.
///
/// The empty tuple has no member, so it is zero levels. `a{s()}` is two
/// levels, and `a{sy}` is three. A dict entry measures its value, because its
/// key is always a leaf of one level.
///
/// [`Type::parse`] limits the type to [`MAX_DECLARATION_DEPTH`] levels of
/// container. That limit also bounds the recursion of this function.
fn type_depth(ty: &Type) -> usize {
    match ty {
        Type::Maybe(elem) | Type::Array(elem) => 1 + type_depth(elem),
        Type::Tuple(members) => members
            .iter()
            .map(|member| 1 + type_depth(member))
            .max()
            .unwrap_or(0),
        Type::DictEntry(_, value) => 1 + type_depth(value),
        _ => 1,
    }
}

/// Sorts a refused declaration into an indefinite type or an invalid text.
///
/// Only a declaration that [`Type::parse`] refused gets to this function.
fn classify_declaration(signature: &str) -> Declaration {
    let bytes = signature.as_bytes();
    let mut pos = 0;
    let mut indefinite = false;
    match scan_declared_type(bytes, &mut pos, 0, &mut indefinite) {
        Some(levels) if pos == bytes.len() && indefinite => Declaration::Indefinite(levels),
        _ => Declaration::Invalid,
    }
}

/// Scans one type and gives the levels that it carries.
///
/// The scan accepts the indefinite characters. If no complete type is
/// present, it returns `None`. It counts the levels as [`type_depth`] counts
/// them. The parser then reports a declaration that is too deep in the same
/// way, definite or indefinite.
fn scan_declared_type(
    sig: &[u8],
    pos: &mut usize,
    depth: usize,
    indefinite: &mut bool,
) -> Option<usize> {
    if depth > MAX_DECLARATION_DEPTH {
        return None;
    }
    let &c = sig.get(*pos)?;
    *pos += 1;
    match c {
        b'b' | b'y' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'h' | b'd' | b's' | b'o'
        | b'g' | b'v' => Some(1),
        b'r' | b'*' | b'?' => {
            *indefinite = true;
            Some(1)
        }
        b'm' | b'a' => Some(1 + scan_declared_type(sig, pos, depth + 1, indefinite)?),
        b'(' => {
            let mut levels = 0;
            while sig.get(*pos) != Some(&b')') {
                let member = scan_declared_type(sig, pos, depth + 1, indefinite)?;
                levels = levels.max(1 + member);
            }
            *pos += 1;
            Some(levels)
        }
        b'{' => {
            scan_declared_type(sig, pos, depth + 1, indefinite)?;
            let value = scan_declared_type(sig, pos, depth + 1, indefinite)?;
            if sig.get(*pos) != Some(&b'}') {
                return None;
            }
            *pos += 1;
            Some(1 + value)
        }
        _ => None,
    }
}

// --- numeric literals --------------------------------------------------------

/// The type that a numeric literal names without context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumberKind {
    Integer,
    Double,
}

/// Splits the leading `-` of a numeric literal from its body.
///
/// The `ostree` command reads the sign itself and gives the rest to the
/// integer reader. A second sign inside the body belongs to the body.
fn split_sign(text: &str) -> (bool, &str) {
    match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    }
}

/// Returns `true` if the body of a numeric literal spells an infinity or a NaN.
///
/// The spelling is lower case. The reader reads `-INF` as an integer and
/// refuses it.
fn is_special_double(body: &str) -> bool {
    matches!(body, "inf" | "infinity" | "nan")
        || matches!(body.strip_prefix('+'), Some("inf" | "infinity" | "nan"))
}

/// Returns the reader that takes a literal with no stated type.
///
/// A body with a fraction, a decimal exponent, or a special spelling is a
/// double. Every other body is an integer. A hexadecimal body must have a `.`
/// to be a double. `0x1e5` is 485, `0x1.8p1` is 3.0, and the reader refuses
/// `0x1p3`.
fn number_kind(text: &str) -> NumberKind {
    let (_, body) = split_sign(text);
    if is_special_double(body) {
        return NumberKind::Double;
    }
    let digits = body.strip_prefix('+').unwrap_or(body);
    let hex = digits.starts_with("0x") || digits.starts_with("0X");
    let fractional = if hex {
        digits.contains('.')
    } else {
        digits.contains(['.', 'e'])
    };
    if fractional {
        NumberKind::Double
    } else {
        NumberKind::Integer
    }
}

/// The result of the integer reader for a literal body.
///
/// It holds the value, the end of the read, and a flag that is `true` if the
/// magnitude passed 64 bits.
struct IntegerScan {
    value: u64,
    end: usize,
    overflow: bool,
}

/// Reads an unsigned integer in the same way as the `ostree` command.
///
/// The body is an optional sign, then a run of digits. The run is `0x`
/// hexadecimal, `0b` binary, leading-`0` octal, or decimal. If the body has
/// no digits, the result is zero and reports that the reader read nothing.
fn scan_integer(body: &str) -> IntegerScan {
    let bytes = body.as_bytes();
    let mut pos = 0;
    let mut negate = false;
    match bytes.first() {
        Some(b'+') => pos = 1,
        Some(b'-') => {
            negate = true;
            pos = 1;
        }
        _ => {}
    }
    let (radix, start) = if bytes.get(pos) == Some(&b'0')
        && matches!(bytes.get(pos + 1), Some(b'x' | b'X'))
        && bytes.get(pos + 2).is_some_and(u8::is_ascii_hexdigit)
    {
        (16u32, pos + 2)
    } else if bytes.get(pos) == Some(&b'0')
        && matches!(bytes.get(pos + 1), Some(b'b' | b'B'))
        && matches!(bytes.get(pos + 2), Some(b'0' | b'1'))
    {
        (2, pos + 2)
    } else if bytes.get(pos) == Some(&b'0') {
        (8, pos)
    } else {
        (10, pos)
    };
    let mut end = start;
    let mut value: u64 = 0;
    let mut overflow = false;
    while let Some(digit) = bytes.get(end).and_then(|c| char::from(*c).to_digit(radix)) {
        match value
            .checked_mul(u64::from(radix))
            .and_then(|v| v.checked_add(u64::from(digit)))
        {
            Some(next) => value = next,
            None => overflow = true,
        }
        end += 1;
    }
    if end == start {
        return IntegerScan {
            value: 0,
            end: 0,
            overflow: false,
        };
    }
    if negate {
        value = value.wrapping_neg();
    }
    IntegerScan {
        value,
        end,
        overflow,
    }
}

/// Reads a numeric literal as an integer and gives its sign and magnitude.
fn integer_literal(text: &str, span: Span) -> TextResult<(bool, u64)> {
    let (negative, body) = split_sign(text);
    let offset = text.len() - body.len();
    let scan = scan_integer(body);
    if scan.end != body.len() {
        let at = span.start + offset + scan.end;
        return Err(TextError::new(
            Span::new(at, at + 1),
            "invalid character in number",
        ));
    }
    if scan.overflow {
        return Err(TextError::new(span, "integer too big for any type"));
    }
    Ok((negative, scan.value))
}

/// A double read from a literal.
struct DoubleScan {
    /// The value of the literal, rounded to the nearest double.
    value: f64,
    /// The end of the read.
    ///
    /// If the reader cannot start on a body, it reads nothing.
    end: usize,
    /// `true` if the double holds the literal exactly.
    ///
    /// A decimal body reports `false`, because the decimal reader gives only
    /// the value.
    exact: bool,
}

/// Reads a numeric literal as a double.
fn scan_double(text: &str) -> DoubleScan {
    let bytes = text.as_bytes();
    let mut pos = 0;
    let mut negative = false;
    match bytes.first() {
        Some(b'-') => {
            negative = true;
            pos = 1;
        }
        Some(b'+') => pos = 1,
        _ => {}
    }
    let signed = |value: f64| if negative { -value } else { value };
    let rest = &text[pos..];
    for (word, value) in [
        ("infinity", f64::INFINITY),
        ("inf", f64::INFINITY),
        ("nan", f64::NAN),
    ] {
        if rest.len() >= word.len() && rest[..word.len()].eq_ignore_ascii_case(word) {
            return DoubleScan {
                value: signed(value),
                end: pos + word.len(),
                exact: true,
            };
        }
    }
    if bytes.get(pos) == Some(&b'0') && matches!(bytes.get(pos + 1), Some(b'x' | b'X')) {
        return match scan_hex_double(bytes, pos + 2) {
            Some(scan) => DoubleScan {
                value: signed(scan.value),
                ..scan
            },
            None => nothing_read(),
        };
    }
    let mut end = pos;
    let mut integer = String::new();
    while let Some(&c) = bytes.get(end).filter(|c| c.is_ascii_digit()) {
        integer.push(char::from(c));
        end += 1;
    }
    let mut fraction = String::new();
    if bytes.get(end) == Some(&b'.') {
        let mut after = end + 1;
        while let Some(&c) = bytes.get(after).filter(|c| c.is_ascii_digit()) {
            fraction.push(char::from(c));
            after += 1;
        }
        end = after;
    }
    if integer.is_empty() && fraction.is_empty() {
        return nothing_read();
    }
    let mut exponent = String::new();
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        let mut after = end + 1;
        if matches!(bytes.get(after), Some(b'+' | b'-')) {
            exponent.push(char::from(bytes[after]));
            after += 1;
        }
        let digits = after;
        while let Some(&c) = bytes.get(after).filter(|c| c.is_ascii_digit()) {
            exponent.push(char::from(c));
            after += 1;
        }
        if after > digits {
            end = after;
        } else {
            exponent.clear();
        }
    }
    if integer.is_empty() {
        integer.push('0');
    }
    if fraction.is_empty() {
        fraction.push('0');
    }
    if exponent.is_empty() {
        exponent.push('0');
    }
    let value: f64 = format!("{integer}.{fraction}e{exponent}")
        .parse()
        .unwrap_or(f64::INFINITY);
    DoubleScan {
        value: signed(value),
        end,
        exact: false,
    }
}

/// The scan result for a body that the double reader cannot start on.
fn nothing_read() -> DoubleScan {
    DoubleScan {
        value: 0.0,
        end: 0,
        exact: false,
    }
}

/// The largest mantissa into which the accumulator takes one more hex digit.
///
/// A digit past this cap goes into the sticky bit. With 124 bits of mantissa
/// in the accumulator, the sticky bit keeps the rounding correct.
const HEX_MANTISSA_CAP: u128 = (u128::MAX - 15) / 16;

/// Reads the body of a `0x` double.
///
/// The body is hexadecimal digits, an optional fraction, and an optional
/// binary exponent. The mantissa in the accumulator and the sticky bit
/// together state the value. `round_binary` rounds that value.
fn scan_hex_double(bytes: &[u8], start: usize) -> Option<DoubleScan> {
    let mut end = start;
    let mut mantissa: u128 = 0;
    let mut sticky = false;
    let mut digits = 0usize;
    let mut shift: i32 = 0;
    while let Some(&c) = bytes.get(end).filter(|c| c.is_ascii_hexdigit()) {
        let value = u128::from(char::from(c).to_digit(16).expect("a hexadecimal digit"));
        if mantissa <= HEX_MANTISSA_CAP {
            mantissa = mantissa * 16 + value;
        } else {
            shift = shift.saturating_add(4);
            sticky |= value != 0;
        }
        digits += 1;
        end += 1;
    }
    if bytes.get(end) == Some(&b'.') {
        let mut after = end + 1;
        while let Some(&c) = bytes.get(after).filter(|c| c.is_ascii_hexdigit()) {
            let value = u128::from(char::from(c).to_digit(16).expect("a hexadecimal digit"));
            if mantissa <= HEX_MANTISSA_CAP {
                mantissa = mantissa * 16 + value;
                shift = shift.saturating_sub(4);
            } else {
                sticky |= value != 0;
            }
            digits += 1;
            after += 1;
        }
        end = after;
    }
    if digits == 0 {
        return None;
    }
    if matches!(bytes.get(end), Some(b'p' | b'P')) {
        let mut after = end + 1;
        let mut negative = false;
        match bytes.get(after) {
            Some(b'-') => {
                negative = true;
                after += 1;
            }
            Some(b'+') => after += 1,
            _ => {}
        }
        let first = after;
        let mut exponent: i32 = 0;
        while let Some(&c) = bytes.get(after).filter(|c| c.is_ascii_digit()) {
            exponent = exponent
                .saturating_mul(10)
                .saturating_add(i32::from(c - b'0'));
            after += 1;
        }
        if after > first {
            shift = if negative {
                shift.saturating_sub(exponent)
            } else {
                shift.saturating_add(exponent)
            };
            end = after;
        }
    }
    let (value, exact) = round_binary(mantissa, sticky, shift);
    Some(DoubleScan { value, end, exact })
}

/// Rounds `mantissa * 2^shift` to the nearest double, ties to even.
///
/// `sticky` states that a digit past the end of the mantissa held a bit. That
/// bit moves the value past a tie. The second member of the result is `true`
/// if the double holds the value exactly. A magnitude over the double range gives an
/// infinity.
fn round_binary(mantissa: u128, sticky: bool, shift: i32) -> (f64, bool) {
    if mantissa == 0 {
        return (0.0, true);
    }
    let width = i64::from(128 - mantissa.leading_zeros());
    // `top` is the weight of the top bit of the mantissa. `lowest` is the
    // weight of the lowest bit that a double holds at that magnitude. A
    // subnormal stops at 2^-1074.
    let top = i64::from(shift) + width - 1;
    let lowest = (top - 52).max(-1074);
    let drop = lowest - i64::from(shift);
    let (mut significand, inexact) = if drop <= 0 {
        // The mantissa fits with bits to spare, so the double holds every bit.
        (mantissa << (-drop) as u32, sticky)
    } else if drop > 128 {
        // Every bit is less than half of the lowest bit that a double holds.
        (0u128, true)
    } else {
        let dropped = drop as u32;
        let (kept, rest) = if dropped == 128 {
            (0, mantissa)
        } else {
            (mantissa >> dropped, mantissa & ((1u128 << dropped) - 1))
        };
        let half = 1u128 << (dropped - 1);
        let up = rest > half || (rest == half && (sticky || kept & 1 == 1));
        (kept + u128::from(up), rest != 0 || sticky)
    };
    if significand == 0 {
        return (0.0, !inexact);
    }
    let mut lowest = lowest;
    if significand == 1u128 << 53 {
        // The rounding carries into a new bit.
        significand >>= 1;
        lowest += 1;
    }
    let bits = if significand < 1u128 << 52 {
        // A subnormal. Its encoding is the count of 2^-1074 units in it.
        significand as u64
    } else {
        let biased = lowest + 1075;
        if biased >= 2047 {
            return (f64::INFINITY, false);
        }
        ((biased as u64) << 52) | ((significand - (1u128 << 52)) as u64)
    };
    (f64::from_bits(bits), !inexact)
}

/// Reads a numeric literal as a double.
///
/// The reader refuses a magnitude that the double range cannot hold. It keeps
/// a hexadecimal literal that states a subnormal exactly. It refuses every
/// other value that rounds to a subnormal. It keeps a value that underflows
/// all the way to zero. If the binary exponent of a body leaves the range of
/// the shift, the reader clamps the shift to its range.
fn double_literal(text: &str, span: Span) -> TextResult<f64> {
    let scan = scan_double(text);
    if scan.end != text.len() {
        let at = span.start + scan.end;
        return Err(TextError::new(
            Span::new(at, at + 1),
            "invalid character in number",
        ));
    }
    let value = scan.value;
    let subnormal = value != 0.0 && value.abs() < f64::MIN_POSITIVE;
    let (_, body) = split_sign(text);
    if !is_special_double(body) && (!value.is_finite() || (subnormal && !scan.exact)) {
        return Err(TextError::new(span, "number too big for any type"));
    }
    Ok(value)
}

// --- type inference ----------------------------------------------------------

/// A type under construction.
///
/// A literal that states no type yet is `Any`. An integer literal is `Int`
/// until a sibling or a declaration makes it concrete. A literal with a
/// fraction is `Decimal`.
#[derive(Debug, Clone)]
enum Guess {
    Any(Span),
    Int,
    Decimal,
    /// A quoted literal.
    ///
    /// It is a string until an object path or a signature beside it gives a
    /// different type.
    StringLit,
    Basic(Type),
    Variant,
    Maybe(Box<Guess>),
    Array(Box<Guess>),
    Tuple(Vec<Guess>),
    Entry(Box<Guess>, Box<Guess>),
}

impl Guess {
    /// The guess that a stated type sets exactly.
    fn of(ty: &Type) -> Guess {
        match ty {
            Type::Variant => Guess::Variant,
            Type::Maybe(elem) => Guess::Maybe(Box::new(Guess::of(elem))),
            Type::Array(elem) => Guess::Array(Box::new(Guess::of(elem))),
            Type::Tuple(members) => Guess::Tuple(members.iter().map(Guess::of).collect()),
            Type::DictEntry(key, value) => {
                Guess::Entry(Box::new(Guess::of(key)), Box::new(Guess::of(value)))
            }
            basic => Guess::Basic(basic.clone()),
        }
    }
}

/// Returns `true` if a type holds a number.
///
/// An integer literal can become only a type of this group.
fn is_numeric(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Byte
            | Type::I16
            | Type::U16
            | Type::I32
            | Type::U32
            | Type::I64
            | Type::U64
            | Type::Handle
            | Type::Double
    )
}

/// Returns the one type on which two guesses agree.
///
/// If the guesses agree on no type, it returns `None`. A maybe absorbs the
/// value beside it, so `'a'` and `@ms 'b'` agree on `ms`.
fn unify(left: &Guess, right: &Guess) -> Option<Guess> {
    match (left, right) {
        (Guess::Any(_), other) | (other, Guess::Any(_)) => Some(other.clone()),
        (Guess::Int, Guess::Int) => Some(Guess::Int),
        (Guess::Int, Guess::Decimal) | (Guess::Decimal, Guess::Int) => Some(Guess::Decimal),
        (Guess::Decimal, Guess::Decimal) => Some(Guess::Decimal),
        (Guess::StringLit, Guess::StringLit) => Some(Guess::StringLit),
        (Guess::StringLit, Guess::Basic(ty)) | (Guess::Basic(ty), Guess::StringLit)
            if matches!(ty, Type::Str | Type::ObjectPath | Type::Signature) =>
        {
            Some(Guess::Basic(ty.clone()))
        }
        (Guess::Int, Guess::Basic(ty)) | (Guess::Basic(ty), Guess::Int) if is_numeric(ty) => {
            Some(Guess::Basic(ty.clone()))
        }
        (Guess::Decimal, Guess::Basic(Type::Double))
        | (Guess::Basic(Type::Double), Guess::Decimal) => Some(Guess::Basic(Type::Double)),
        (Guess::Basic(a), Guess::Basic(b)) if a == b => Some(Guess::Basic(a.clone())),
        (Guess::Variant, Guess::Variant) => Some(Guess::Variant),
        (Guess::Maybe(a), Guess::Maybe(b)) => Some(Guess::Maybe(Box::new(unify(a, b)?))),
        (Guess::Maybe(a), other) | (other, Guess::Maybe(a)) => {
            Some(Guess::Maybe(Box::new(unify(a, other)?)))
        }
        (Guess::Array(a), Guess::Array(b)) => Some(Guess::Array(Box::new(unify(a, b)?))),
        (Guess::Tuple(a), Guess::Tuple(b)) if a.len() == b.len() => {
            let mut members = Vec::with_capacity(a.len());
            for (x, y) in a.iter().zip(b) {
                members.push(unify(x, y)?);
            }
            Some(Guess::Tuple(members))
        }
        (Guess::Entry(ka, va), Guess::Entry(kb, vb)) => Some(Guess::Entry(
            Box::new(unify(ka, kb)?),
            Box::new(unify(va, vb)?),
        )),
        _ => None,
    }
}

/// Returns the type that a guess names.
///
/// An integer literal with no other context is `i`, and a fractional literal
/// is `d`. The function refuses a literal that states no type.
fn resolve(guess: &Guess) -> TextResult<Type> {
    Ok(match guess {
        Guess::Any(span) => return Err(TextError::new(*span, CANNOT_INFER)),
        Guess::Int => Type::I32,
        Guess::Decimal => Type::Double,
        Guess::StringLit => Type::Str,
        Guess::Basic(ty) => ty.clone(),
        Guess::Variant => Type::Variant,
        Guess::Maybe(elem) => Type::Maybe(Box::new(resolve(elem)?)),
        Guess::Array(elem) => Type::Array(Box::new(resolve(elem)?)),
        Guess::Tuple(members) => {
            Type::Tuple(members.iter().map(resolve).collect::<TextResult<_>>()?)
        }
        Guess::Entry(key, value) => {
            Type::DictEntry(Box::new(resolve(key)?), Box::new(resolve(value)?))
        }
    })
}

/// Returns the type that one whole value states.
///
/// If a literal inside the value states no type, the error names the whole
/// value. The `ostree` command names the same span. The child of a variant is a whole
/// value of its own, so the error for `[<[]>]` names the `[]`.
fn value_type(node: &Node) -> TextResult<Type> {
    let guess = infer(node)?;
    resolve(&guess).map_err(|error| {
        if error.reason == CANNOT_INFER {
            TextError::new(node.span, CANNOT_INFER)
        } else {
            error
        }
    })
}

fn cannot_parse(span: Span, ty: &Type) -> TextError {
    TextError::new(
        span,
        format!("can not parse as value of type '{}'", ty.signature()),
    )
}

/// The refusal of a container whose members state types that do not unify.
///
/// It names two members: the member that settled the type, and the member
/// that broke it.
fn no_common_type(first: Span, other: Span) -> TextError {
    TextError {
        spans: vec![first, other],
        reason: "unable to find a common type".to_owned(),
    }
}

fn infer(node: &Node) -> TextResult<Guess> {
    Ok(match &node.ast {
        Ast::Bool(_) => Guess::Basic(Type::Bool),
        Ast::Number(text) => match number_kind(text) {
            NumberKind::Integer => Guess::Int,
            NumberKind::Double => Guess::Decimal,
        },
        Ast::Str(_) => Guess::StringLit,
        Ast::ByteString(_) => Guess::Array(Box::new(Guess::Basic(Type::Byte))),
        // A declaration states the type directly. Construction checks the
        // value against it, member by member. If a member does not fit,
        // construction names the same member as the `ostree` command.
        Ast::Typed(ty, _) => Guess::of(ty),
        Ast::Maybe(None) => Guess::Maybe(Box::new(Guess::Any(node.span))),
        Ast::Maybe(Some(child)) => Guess::Maybe(Box::new(infer(child)?)),
        Ast::Array(items) => {
            let Some((first, rest)) = items.split_first() else {
                return Ok(Guess::Array(Box::new(Guess::Any(node.span))));
            };
            let mut common = infer(first)?;
            for item in rest {
                let found = infer(item)?;
                common =
                    unify(&common, &found).ok_or_else(|| no_common_type(first.span, item.span))?;
            }
            Guess::Array(Box::new(common))
        }
        Ast::Dict(entries) => {
            let Some(((first_key, first_value), rest)) = entries.split_first() else {
                return Ok(Guess::Array(Box::new(Guess::Entry(
                    Box::new(Guess::Any(node.span)),
                    Box::new(Guess::Any(node.span)),
                ))));
            };
            let mut key = infer(first_key)?;
            // Only the first entry settles the value type. Construction reads
            // every later value against that type, so a later value states
            // nothing here. If a key does not unify with the settled key type,
            // the error has the same form as for an array.
            let value = infer(first_value)?;
            for (k, _) in rest {
                let found = infer(k)?;
                key = unify(&key, &found).ok_or_else(|| no_common_type(first_key.span, k.span))?;
            }
            check_basic_key(&key, node.span)?;
            Guess::Array(Box::new(Guess::Entry(Box::new(key), Box::new(value))))
        }
        Ast::Entry(key, value) => {
            let key = infer(key)?;
            check_basic_key(&key, node.span)?;
            Guess::Entry(Box::new(key), Box::new(infer(value)?))
        }
        Ast::Tuple(items) => Guess::Tuple(items.iter().map(infer).collect::<TextResult<_>>()?),
        Ast::Variant(child) => {
            // A variant states no child type, so the child must state its own.
            value_type(child)?;
            Guess::Variant
        }
    })
}

/// Returns `true` if a guess names a basic type.
///
/// The key of a dict entry must have a basic type. A key that states no type
/// is not basic, so the error for `{nothing: 1}` names the shape of the key,
/// with `dictionary keys must have basic types`.
fn guess_is_basic(guess: &Guess) -> bool {
    match guess {
        Guess::Int | Guess::Decimal | Guess::StringLit => true,
        Guess::Basic(ty) => ty.is_basic(),
        _ => false,
    }
}

/// Refuses a dictionary whose key is a container.
///
/// A dict entry cannot hold a container key. The error names the whole
/// dictionary, which is the span that the `ostree` command reports.
fn check_basic_key(key: &Guess, span: Span) -> TextResult<()> {
    if guess_is_basic(key) {
        return Ok(());
    }
    Err(TextError::new(
        span,
        "dictionary keys must have basic types",
    ))
}

// --- value construction ------------------------------------------------------

/// Returns `true` if a string is a valid object path.
///
/// A valid path is `/`, or `/` and one or more elements with single slashes
/// between them. An element holds letters, digits, and underscores.
fn is_object_path(text: &str) -> bool {
    if text == "/" {
        return true;
    }
    let Some(rest) = text.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest.split('/').all(|element| {
            !element.is_empty()
                && element
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

/// Returns `true` if a string is a valid signature.
///
/// A valid signature is zero or more complete types. It excludes the maybe and
/// the indefinite characters.
fn is_signature(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        if !scan_signature_type(bytes, &mut pos, 0) {
            return false;
        }
    }
    true
}

fn scan_signature_type(sig: &[u8], pos: &mut usize, depth: usize) -> bool {
    if depth > MAX_DECLARATION_DEPTH {
        return false;
    }
    let Some(&c) = sig.get(*pos) else {
        return false;
    };
    *pos += 1;
    match c {
        b'b' | b'y' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'h' | b'd' | b's' | b'o'
        | b'g' | b'v' => true,
        b'a' => scan_signature_type(sig, pos, depth + 1),
        b'(' => {
            while sig.get(*pos) != Some(&b')') {
                if !scan_signature_type(sig, pos, depth + 1) {
                    return false;
                }
            }
            *pos += 1;
            true
        }
        b'{' => {
            let key = sig.get(*pos).copied();
            if !key.is_some_and(|k| {
                matches!(
                    k,
                    b'b' | b'y'
                        | b'n'
                        | b'q'
                        | b'i'
                        | b'u'
                        | b'x'
                        | b't'
                        | b'h'
                        | b'd'
                        | b's'
                        | b'o'
                        | b'g'
                )
            }) {
                return false;
            }
            *pos += 1;
            if !scan_signature_type(sig, pos, depth + 1) {
                return false;
            }
            if sig.get(*pos) != Some(&b'}') {
                return false;
            }
            *pos += 1;
            true
        }
        _ => false,
    }
}

fn build(node: &Node, ty: &Type) -> TextResult<Value> {
    // A value beside a maybe takes the shape of the maybe, so
    // `['a', @ms 'b']` holds two `ms` values.
    if let Type::Maybe(elem) = ty
        && !matches!(node.ast, Ast::Maybe(_) | Ast::Typed(..))
    {
        return Ok(Value::Maybe(Some(Box::new(build(node, elem)?))));
    }
    match (&node.ast, ty) {
        (Ast::Typed(_, child), _) => build(child, ty),
        (Ast::Bool(b), Type::Bool) => Ok(Value::Bool(*b)),
        (Ast::Number(text), _) => number_value(text, ty, node.span),
        (Ast::Str(text), Type::Str) => Ok(Value::Str(text.clone())),
        (Ast::Str(text), Type::ObjectPath) => {
            if !is_object_path(text) {
                return Err(TextError::new(node.span, "not a valid object path"));
            }
            Ok(Value::Str(text.clone()))
        }
        (Ast::Str(text), Type::Signature) => {
            if !is_signature(text) {
                return Err(TextError::new(node.span, "not a valid signature"));
            }
            Ok(Value::Str(text.clone()))
        }
        (Ast::ByteString(bytes), Type::Array(elem)) if **elem == Type::Byte => {
            Ok(Value::Bytes(bytes.clone()))
        }
        (Ast::Maybe(None), Type::Maybe(_)) => Ok(Value::Maybe(None)),
        (Ast::Maybe(Some(child)), Type::Maybe(elem)) => {
            Ok(Value::Maybe(Some(Box::new(build(child, elem)?))))
        }
        (Ast::Array(items), Type::Array(elem)) if **elem == Type::Byte => {
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                match build(item, elem)? {
                    Value::Byte(b) => bytes.push(b),
                    _ => return Err(cannot_parse(item.span, elem)),
                }
            }
            Ok(Value::Bytes(bytes))
        }
        (Ast::Array(items), Type::Array(elem)) => Ok(Value::Array(
            items
                .iter()
                .map(|item| build(item, elem))
                .collect::<TextResult<_>>()?,
        )),
        (Ast::Dict(entries), Type::Array(elem)) => {
            let Type::DictEntry(key_ty, value_ty) = &**elem else {
                return Err(cannot_parse(node.span, ty));
            };
            let mut items = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                items.push(Value::Tuple(vec![
                    build(key, key_ty)?,
                    build(value, value_ty)?,
                ]));
            }
            Ok(Value::Array(items))
        }
        (Ast::Entry(key, value), Type::DictEntry(key_ty, value_ty)) => Ok(Value::Tuple(vec![
            build(key, key_ty)?,
            build(value, value_ty)?,
        ])),
        (Ast::Tuple(items), Type::Tuple(members)) if items.len() == members.len() => {
            Ok(Value::Tuple(
                items
                    .iter()
                    .zip(members)
                    .map(|(item, member)| build(item, member))
                    .collect::<TextResult<_>>()?,
            ))
        }
        (Ast::Variant(child), Type::Variant) => {
            let child_ty = value_type(child)?;
            let value = build(child, &child_ty)?;
            Ok(Value::variant(child_ty, value))
        }
        _ => Err(cannot_parse(node.span, ty)),
    }
}

/// Makes a value of `ty` from a numeric literal.
///
/// A double target reads the text as a double. An integer target reads the
/// text as an integer. The same text `017` is 17.0 under `d` and 15 under
/// `i`.
fn number_value(text: &str, ty: &Type, span: Span) -> TextResult<Value> {
    if matches!(ty, Type::Double) {
        return Ok(Value::double(double_literal(text, span)?));
    }
    if !is_numeric(ty) {
        return Err(cannot_parse(span, ty));
    }
    let (negative, magnitude) = integer_literal(text, span)?;
    let value = if negative {
        -i128::from(magnitude)
    } else {
        i128::from(magnitude)
    };
    let range = || {
        TextError::new(
            span,
            format!("number out of range for type '{}'", ty.signature()),
        )
    };
    Ok(match ty {
        Type::Byte => Value::Byte(u8::try_from(value).map_err(|_| range())?),
        Type::I16 => Value::I16(i16::try_from(value).map_err(|_| range())?),
        Type::U16 => Value::U16(u16::try_from(value).map_err(|_| range())?),
        Type::I32 | Type::Handle => Value::I32(i32::try_from(value).map_err(|_| range())?),
        Type::U32 => Value::U32(u32::try_from(value).map_err(|_| range())?),
        Type::I64 => Value::I64(i64::try_from(value).map_err(|_| range())?),
        Type::U64 => Value::U64(u64::try_from(value).map_err(|_| range())?),
        _ => return Err(cannot_parse(span, ty)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{to_bytes, to_text};

    /// Parses `text` and writes it back as text.
    ///
    /// The `ostree` command has the same pair of steps. The value goes in
    /// through `commit --add-metadata` and comes out through
    /// `show -B --print-metadata-key`.
    fn round(text: &str) -> String {
        let (ty, value) = from_text(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        // Every accepted value must also serialize.
        to_bytes(&ty, &value).unwrap_or_else(|e| panic!("{text}: {e:?}"));
        to_text(&ty, &value).unwrap()
    }

    fn refuse(text: &str) -> String {
        from_text(text)
            .map(|(ty, _)| ty.signature())
            .expect_err(&format!("{text} was accepted"))
            .to_string()
    }

    /// Parses `text` as a double and gives its value.
    fn double(text: &str) -> f64 {
        let (ty, value) = from_text(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(ty.signature(), "d", "type of {text}");
        match value {
            Value::Double(bits) => f64::from_bits(bits),
            other => panic!("{text}: {other:?}"),
        }
    }

    /// Each pair is one `--add-metadata` value and the text that
    /// `show -B --print-metadata-key` printed for it. The `ostree` command
    /// is version 2026.1.
    #[test]
    fn reads_the_forms_the_tool_accepts() {
        let cases: &[(&str, &str)] = &[
            ("'a string'", "'a string'"),
            ("\"double quoted\"", "'double quoted'"),
            ("uint32 42", "uint32 42"),
            ("42", "42"),
            ("-42", "-42"),
            ("+42", "42"),
            ("int64 -5", "int64 -5"),
            ("@x 5", "int64 5"),
            ("uint64 99", "uint64 99"),
            ("byte 0x41", "byte 0x41"),
            ("true", "true"),
            ("false", "false"),
            ("1.5", "1.5"),
            ("0.1", "0.10000000000000001"),
            ("1.0", "1.0"),
            ("1e3", "1000.0"),
            ("-0.0", "-0.0"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("int16 -5", "int16 -5"),
            ("uint16 5", "uint16 5"),
            ("handle 5", "handle 5"),
            ("objectpath '/a/b'", "objectpath '/a/b'"),
            ("objectpath '/'", "objectpath '/'"),
            ("objectpath '/a_b'", "objectpath '/a_b'"),
            ("objectpath '/A/9'", "objectpath '/A/9'"),
            ("signature 'ay'", "signature 'ay'"),
            ("signature ''", "signature ''"),
            ("signature 'ii'", "signature 'ii'"),
            ("signature '{sv}'", "signature '{sv}'"),
            ("@o '/a/b'", "objectpath '/a/b'"),
            ("@g 'ay'", "signature 'ay'"),
            ("['a','b']", "['a', 'b']"),
            ("@as ['a','b']", "['a', 'b']"),
            ("@ay [1,2,3]", "[byte 0x01, 0x02, 0x03]"),
            ("b'bytes'", "b'bytes'"),
            ("b\"double\"", "b'double'"),
            ("{'x': 'y'}", "{'x': 'y'}"),
            ("@a{ss} {'x': 'y'}", "{'x': 'y'}"),
            ("('a', 5)", "('a', 5)"),
            ("<'nested variant'>", "<'nested variant'>"),
            ("<<'x'>>", "<<'x'>>"),
            ("@v <'x'>", "<'x'>"),
            ("@ms 'just'", "@ms 'just'"),
            ("@ms nothing", "@ms nothing"),
            ("just 'x'", "@ms 'x'"),
            ("@mi 5", "@mi 5"),
            ("@mu 7", "@mu 7"),
            ("'a=b'", "'a=b'"),
            ("[2, 1.5]", "[2.0, 1.5]"),
            ("[1.5, 2]", "[1.5, 2.0]"),
            ("[[1],[2]]", "[[1], [2]]"),
            ("{'a': 1, 'b': 2}", "{'a': 1, 'b': 2}"),
            ("{1: 'a'}", "{1: 'a'}"),
            ("[@ms 'a', 'b']", "[@ms 'a', 'b']"),
            ("['a', @ms 'b']", "[@ms 'a', 'b']"),
            ("[nothing, 'a']", "[@ms nothing, 'a']"),
            ("[just 'a', nothing]", "[@ms 'a', nothing]"),
            ("@(si) ('a', 5)", "('a', 5)"),
            ("@ai []", "@ai []"),
            ("@as []", "@as []"),
            ("@a{sv} {}", "@a{sv} {}"),
            ("@aai [[], []]", "[@ai [], []]"),
            ("[b'x', b'y']", "[b'x', b'y']"),
            ("[@o '/a', '/b']", "[objectpath '/a', '/b']"),
            ("@ao ['/a','/b']", "[objectpath '/a', '/b']"),
            ("'\\x41'", "'x41'"),
            ("'a\\'b'", "\"a'b\""),
            ("\"a'b\"", "\"a'b\""),
            ("'\\''", "\"'\""),
            ("  42  ", "42"),
            ("@i 42", "42"),
            ("@au [1,2]", "[uint32 1, 2]"),
            ("[<'a'>, <5>]", "[<'a'>, <5>]"),
            ("0x41", "65"),
            ("017", "15"),
            ("(1,)", "(1,)"),
            ("()", "()"),
            ("[1,2,3]", "[1, 2, 3]"),
            ("{'a', 5}", "{'a', 5}"),
            ("'a\\0b'", "'a0b'"),
            ("'a\\tb'", "'a\\tb'"),
            ("'\\u00e9'", "'é'"),
            // A bytestring has no `\\u` escape, so the reader drops the
            // backslash and keeps the digits.
            ("b'\\u0000'", "b'u0000'"),
            ("b'a\\u0000b'", "b'au0000b'"),
            // A bytestring ends at a raw NUL, the same as at a NUL that an
            // octal escape names.
            ("b'a\0b'", "b'a'"),
        ];
        for (input, expected) in cases {
            assert_eq!(round(input), *expected, "reading {input}");
        }
    }

    /// Literals whose text alone does not tell which reader takes them.
    ///
    /// Each literal has its value beside it. `ostree` 2026.1 stores exactly
    /// these values.
    #[test]
    fn reads_the_numeric_literals_the_tool_accepts() {
        let cases: &[(&str, &str)] = &[
            // A binary literal, with both spellings of its prefix.
            ("0b101", "5"),
            ("0B101", "5"),
            ("0b0", "0"),
            ("byte 0b11111111", "byte 0xff"),
            ("@t 0b1", "uint64 1"),
            // A hexadecimal body is an integer until a `.` or a `p` is in it.
            ("0xe", "14"),
            ("0xE", "14"),
            ("0x1e5", "485"),
            ("-0x1", "-1"),
            ("+0x10", "16"),
            ("0x1.8p1", "3.0"),
            ("@d 0x1.8p1", "3.0"),
            ("@d 0x10", "16.0"),
            ("@t 0xFFFFFFFFFFFFFFFF", "uint64 18446744073709551615"),
            // A double target reads the same text as a decimal double.
            ("@d 017", "17.0"),
            ("double 0777", "777.0"),
            ("@d 08", "8.0"),
            ("@d 1E3", "1000.0"),
            ("double 1E3", "1000.0"),
            // The sign that the `ostree` command reads itself, and the body
            // that it gives to the integer reader.
            ("-", "0"),
            ("@i -", "0"),
            ("@y -", "byte 0x00"),
            ("@t -", "uint64 0"),
            ("-+5", "-5"),
            // Not-a-number and the infinities.
            ("nan", "nan"),
            ("-nan", "-nan"),
            ("inf", "inf"),
            ("-inf", "-inf"),
            ("+inf", "inf"),
            ("+nan", "nan"),
            ("-infinity", "-inf"),
            ("double nan", "nan"),
            ("double inf", "inf"),
            ("@d nan", "nan"),
            ("just nan", "@md nan"),
            ("[1, nan]", "[1.0, nan]"),
            ("[nan, 1]", "[nan, 1.0]"),
            // The reader keeps an underflow all the way to zero. It refuses a
            // subnormal.
            ("1e-400", "0.0"),
            ("-1e-400", "-0.0"),
            ("0.0e-400", "0.0"),
            ("2.2250738585072014e-308", "2.2250738585072014e-308"),
            // A decimal literal can omit the integer part or the fraction part
            // of the mantissa.
            ("1.", "1.0"),
            (".5", "0.5"),
            ("5.", "5.0"),
            ("-.5", "-0.5"),
            ("1.e3", "1000.0"),
        ];
        for (input, expected) in cases {
            assert_eq!(round(input), *expected, "reading {input}");
        }
    }

    /// The reader clamps a binary exponent that leaves the range of the shift.
    ///
    /// `ostree` 2026.1 stores 0.0 for each of these bodies.
    #[test]
    fn a_binary_exponent_out_of_range_is_clamped() {
        assert_eq!(round("0x0.0p-2147483645"), "0.0");
        assert_eq!(round("0x0.0p-9999999999"), "0.0");
        assert_eq!(round("0x1.0p-2147483645"), "0.0");
        assert_eq!(round("0x0.0p2147483647"), "0.0");
    }

    /// The reader rounds a hexadecimal body to the nearest double, ties to even.
    ///
    /// A hexadecimal body states a value in binary. `ostree` 2026.1 stores the
    /// value beside each literal.
    #[test]
    fn reads_the_hexadecimal_doubles_the_tool_stores() {
        let cases: &[(&str, f64)] = &[
            ("@d 0x1.8p1", 3.0),
            ("@d 0x1p1023", 8.98846567431158e307),
            ("@d 0x1.fffffffffffff7ffffffffp1023", f64::MAX),
            ("@d 0x1.00000000000008p0", 1.0),
            // If a mantissa has more digits than the accumulator holds, the
            // accumulator keeps its digits. The digits after them round the
            // result.
            (
                "@d 0xffffffffffffffffffffffffffffffffffffffffp0",
                1.461501637330903e48,
            ),
            ("@d 0x1.0000000000000000000000000000000000001p0", 1.0),
            ("@d 0x1000000000000000000000000000000000000p-140", 16.0),
            ("@d 0x1000000000000000000000000000000000001p-140", 16.0),
            (
                "@d 0x123456789abcdef123456789abcdef123456789abcdefp-100",
                8.596805828370696e22,
            ),
            // A subnormal that the literal states exactly.
            ("@d 0x1p-1023", f64::from_bits(0x0008_0000_0000_0000)),
            ("@d 0x1p-1074", f64::from_bits(1)),
            ("@d 0x2p-1074", f64::from_bits(2)),
            ("@d 0x3p-1074", f64::from_bits(3)),
            ("@d 0x1.8p-1073", f64::from_bits(3)),
            ("@d -0x1p-1074", -f64::from_bits(1)),
            ("@d 0x1.000001p-1030", f64::from_bits(0x0000_1000_0010_0000)),
            // A value under the smallest normal that rounds up to it.
            ("@d 0x1.fffffffffffffffp-1023", f64::MIN_POSITIVE),
            ("@d 0x1.fffffffffffff8p-1023", f64::MIN_POSITIVE),
            // The reader keeps an underflow all the way to zero, and a tie to
            // even that gives zero. A zero mantissa is zero under any exponent.
            ("@d 0x1p-1075", 0.0),
            ("@d 0x0.8p-1074", 0.0),
            ("@d 0x8000000000000000000000000000000000000000p-1234", 0.0),
            ("@d 0x1p-2000", 0.0),
            ("@d 0x1p-9999999999", 0.0),
            ("@d -0x1p-1075", -0.0),
            ("@d 0x0p2147483647", 0.0),
            ("@d 0x0p99999999999999999999", 0.0),
        ];
        for (input, expected) in cases {
            assert_eq!(
                double(input).to_bits(),
                expected.to_bits(),
                "reading {input}"
            );
        }
    }

    /// The reader refuses a hex body that rounds to an inexact subnormal.
    ///
    /// An inexact subnormal is a subnormal that the body does not state
    /// exactly. The reader also refuses a body over the double range. Each
    /// text is the text that `ostree` 2026.1 reports. The offsets are relative
    /// to the value.
    #[test]
    fn refuses_the_hexadecimal_doubles_the_tool_refuses() {
        let cases: &[(&str, &str)] = &[
            // The rounding gives a subnormal that the literal does not state
            // exactly.
            ("@d 0x1.8p-1074", "3-14:number too big for any type"),
            ("@d 0x1.8p-1075", "3-14:number too big for any type"),
            (
                "@d 0x1.0000000000001p-1030",
                "3-26:number too big for any type",
            ),
            (
                "@d 0x1.0000000000000001p-1030",
                "3-29:number too big for any type",
            ),
            (
                "@d 0x1.0000000000000000001p-1075",
                "3-32:number too big for any type",
            ),
            (
                "@d 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffp-1330",
                "3-80:number too big for any type",
            ),
            // A magnitude over the double range.
            ("@d 0x1p1024", "3-11:number too big for any type"),
            ("@d 0x2p1023", "3-11:number too big for any type"),
            ("@d -0x1p1024", "3-12:number too big for any type"),
            (
                "@d 0x1.fffffffffffff8p1023",
                "3-26:number too big for any type",
            ),
            ("@d 0x1p2147483647", "3-17:number too big for any type"),
            (
                "@d 0x1p99999999999999999999",
                "3-27:number too big for any type",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(refuse(input), *expected, "refusing {input}");
        }
    }

    /// Each pair is one refused `--add-metadata` value and the report of the
    /// `ostree` command.
    ///
    /// The report is the text after `Parsing <KEY=VALUE>: `. The version of
    /// the `ostree` command is 2026.1. The offsets are relative to the value.
    #[test]
    fn refuses_what_the_tool_refuses_in_its_own_words() {
        let cases: &[(&str, &str)] = &[
            ("[]", "0-2:unable to infer type"),
            ("", "0:expected value"),
            ("garbage syntax (((", "0-7:unknown keyword"),
            (
                "uint32 99999999999999999999",
                "7-27:integer too big for any type",
            ),
            ("'unterminated", "0-13:unterminated string constant"),
            ("(1,2", "4:expected ',' or ')' to follow tuple element"),
            ("{'a':}", "5:expected value"),
            ("nothing", "0-7:unable to infer type"),
            ("@i 'str'", "3-8:can not parse as value of type 'i'"),
            ("3000000000", "0-10:number out of range for type 'i'"),
            (
                "9223372036854775807",
                "0-19:number out of range for type 'i'",
            ),
            (
                "18446744073709551615",
                "0-20:number out of range for type 'i'",
            ),
            ("99999999999999999999", "0-20:integer too big for any type"),
            ("uint32 -1", "7-9:number out of range for type 'u'"),
            ("uint32 4294967296", "7-17:number out of range for type 'u'"),
            ("byte 256", "5-8:number out of range for type 'y'"),
            ("0o17", "1-2:invalid character in number"),
            ("['a', 5]", "1-4,6-7:unable to find a common type"),
            (
                "{'a': 'b', 'c': 5}",
                "16-17:can not parse as value of type 's'",
            ),
            ("42 43", "3:expected end of input"),
            ("true false", "5:expected end of input"),
            ("@u", "2:expected value"),
            ("@", "0-1:invalid type declaration"),
            ("[,]", "1:expected value"),
            ("{}", "0-2:unable to infer type"),
            (
                "{'a'}",
                "4:expected ':' or ',' to follow dictionary entry key",
            ),
            ("(,)", "1:expected value"),
            ("@b 1", "3-4:can not parse as value of type 'b'"),
            ("B", "0:expected value"),
            ("_x", "0:expected value"),
            ("Foo", "0:expected value"),
            ("uint32x", "0-7:unknown keyword"),
            ("x1", "0:expected value"),
            ("a", "0:expected value"),
            ("%", "0:expected value"),
            ("=x", "0:expected value"),
            ("trueX", "0-5:unknown keyword"),
            ("TRUE", "0:expected value"),
            ("aB", "0-2:unknown keyword"),
            ("a_b", "0:expected value"),
            ("byte0x41", "0-8:unknown keyword"),
            ("just1", "0-5:unknown keyword"),
            ("ju st", "0-2:unknown keyword"),
            ("{[1]: 'a'}", "0-10:dictionary keys must have basic types"),
            // A one-member tuple needs its comma.
            ("(1)", "2:expected ',' after first tuple element"),
            ("('a')", "4:expected ',' after first tuple element"),
            ("((1))", "3:expected ',' after first tuple element"),
            ("((1,))", "5:expected ',' after first tuple element"),
            ("@(i) (1)", "7:expected ',' after first tuple element"),
            ("(((1),2),3)", "4:expected ',' after first tuple element"),
            ("(1 2)", "3:expected ',' after first tuple element"),
            ("(1,2,)", "5:expected value"),
            ("(1,2 3)", "5:expected ',' or ')' to follow tuple element"),
            // The exponent marker is lower case. With `E`, the body is an
            // integer.
            ("1E3", "1-2:invalid character in number"),
            ("1E+3", "1-2:invalid character in number"),
            ("1E", "1-2:invalid character in number"),
            ("1d", "1-2:invalid character in number"),
            ("0x1p3", "3-4:invalid character in number"),
            // A subnormal is out of the range that the `ostree` command
            // accepts.
            ("5e-324", "0-6:number too big for any type"),
            ("1e-310", "0-6:number too big for any type"),
            ("1e-308", "0-6:number too big for any type"),
            ("1e400", "0-5:number too big for any type"),
            ("-1e400", "0-6:number too big for any type"),
            ("1.7976931348623157e309", "0-22:number too big for any type"),
            ("@d 5e-324", "3-9:number too big for any type"),
            // The character at which the number reader stopped.
            ("1.5.5", "3-4:invalid character in number"),
            ("1..5", "2-3:invalid character in number"),
            ("1e", "1-2:invalid character in number"),
            ("1e+", "1-2:invalid character in number"),
            ("1.5e", "3-4:invalid character in number"),
            ("+", "0-1:invalid character in number"),
            ("++5", "0-1:invalid character in number"),
            ("+-5", "0-1:invalid character in number"),
            ("--5", "0-3:number out of range for type 'i'"),
            ("0xg", "1-2:invalid character in number"),
            ("0b12", "3-4:invalid character in number"),
            ("0b102", "4-5:invalid character in number"),
            ("0b1e1", "1-2:invalid character in number"),
            ("-INF", "1-2:invalid character in number"),
            ("+INFINITY", "0-1:invalid character in number"),
            ("infinity", "0-8:unknown keyword"),
            ("nan5", "0-4:unknown keyword"),
            ("nan(0x1)", "3:expected end of input"),
            // An integer target reads the literal as an integer.
            ("byte nan", "5-6:invalid character in number"),
            ("@i nan", "3-4:invalid character in number"),
            ("uint64 nan", "7-8:invalid character in number"),
            ("byte 1.5", "6-7:invalid character in number"),
            ("uint32 1.5", "8-9:invalid character in number"),
            ("@x 1.5", "4-5:invalid character in number"),
            ("int32 1e3", "7-8:invalid character in number"),
            ("@d 0b101", "4-5:invalid character in number"),
            ("@d -", "3-4:invalid character in number"),
            // A magnitude that no 64-bit type holds, compared with a magnitude
            // that no target holds.
            (
                "int64 -9223372036854775809",
                "6-26:number out of range for type 'x'",
            ),
            (
                "-18446744073709551615",
                "0-21:number out of range for type 'i'",
            ),
            ("18446744073709551616", "0-20:integer too big for any type"),
            // The reader checks an object path and a signature.
            ("objectpath 'notapath'", "11-21:not a valid object path"),
            ("objectpath ''", "11-13:not a valid object path"),
            ("objectpath '/a/'", "11-16:not a valid object path"),
            ("objectpath '//'", "11-15:not a valid object path"),
            ("objectpath '/a-b'", "11-17:not a valid object path"),
            ("@o 'bad'", "3-8:not a valid object path"),
            ("signature 'zz'", "10-14:not a valid signature"),
            ("signature 'a'", "10-13:not a valid signature"),
            ("signature 'ms'", "10-14:not a valid signature"),
            ("signature 'r'", "10-13:not a valid signature"),
            ("signature '{vs}'", "10-16:not a valid signature"),
            ("@g 'zz'", "3-7:not a valid signature"),
            // The scan of a declaration stops at the first character that can
            // close something around it. The error for an indefinite
            // declaration names it as indefinite.
            ("@z 5", "0-2:invalid type declaration"),
            ("@r 5", "0-2:type declarations must be definite"),
            ("@* 5", "0-2:type declarations must be definite"),
            ("@? 5", "0-2:type declarations must be definite"),
            ("@** 5", "0-3:invalid type declaration"),
            ("@i5", "0-3:invalid type declaration"),
            ("@ii", "0-3:invalid type declaration"),
            ("@m", "0-2:invalid type declaration"),
            ("@i(5)", "0-5:invalid type declaration"),
            ("@i[5]", "0-4:invalid type declaration"),
            ("@i)", "2:expected value"),
            ("@i,", "2:expected value"),
            // A declaration drives the check into the members.
            ("@as [1]", "5-6:can not parse as value of type 's'"),
            ("@ab [1]", "5-6:can not parse as value of type 'b'"),
            ("@ai [1,'a']", "7-10:can not parse as value of type 'i'"),
            ("@as ['a', 5]", "10-11:can not parse as value of type 's'"),
            (
                "@a{ss} {'a': 5}",
                "13-14:can not parse as value of type 's'",
            ),
            (
                "@a{sv} {'a': 1}",
                "13-14:can not parse as value of type 'v'",
            ),
            ("@av [1]", "5-6:can not parse as value of type 'v'"),
            ("@ai 5", "4-5:can not parse as value of type 'ai'"),
            ("@i []", "3-5:can not parse as value of type 'i'"),
            ("@as [nothing]", "5-12:can not parse as value of type 's'"),
            // If a value states no type, the error names the whole value. The
            // child of a variant is a whole value of its own.
            ("[[]]", "0-4:unable to infer type"),
            ("just []", "0-7:unable to infer type"),
            ("just nothing", "0-12:unable to infer type"),
            ("just just nothing", "0-17:unable to infer type"),
            ("('a', [])", "0-9:unable to infer type"),
            ("[nothing]", "0-9:unable to infer type"),
            ("[nothing, nothing]", "0-18:unable to infer type"),
            ("{'a': nothing}", "0-14:unable to infer type"),
            ("[[[]]]", "0-6:unable to infer type"),
            ("[[], []]", "0-8:unable to infer type"),
            ("nothing 5", "0-7:unable to infer type"),
            ("nothing nothing", "0-7:unable to infer type"),
            ("[<[]>]", "2-4:unable to infer type"),
            ("<just nothing>", "1-13:unable to infer type"),
            // The error for a key that is not basic names its shape.
            ("{nothing: 1}", "0-12:dictionary keys must have basic types"),
            ("{{}: 'a'}", "0-9:dictionary keys must have basic types"),
            ("{<1>: 'a'}", "0-10:dictionary keys must have basic types"),
            // The error for keys that do not unify has the same form as for an
            // array.
            ("{'a': 1, 2: 'b'}", "1-4,9-10:unable to find a common type"),
            ("{1: 'a', 'b': 2}", "1-2,9-12:unable to find a common type"),
            (
                "{'a': 'b', 5: 'c'}",
                "1-4,11-12:unable to find a common type",
            ),
            (
                "{'a': 1, 'b': 2, 'c': 'x'}",
                "22-25:can not parse as value of type 'i'",
            ),
            // Each closing bracket has its own wording.
            ("<1 2>", "3:expected '>' to follow variant value"),
            ("{'a', 5, 6}", "7:expected '}' at end of dictionary entry"),
            (
                "{'a': 1 'b': 2}",
                "8:expected ',' or '}' to follow dictionary entry",
            ),
            ("[1 2]", "3:expected ',' or ']' to follow array element"),
            // The error for a unicode escape names the digits that are present.
            ("'\\uZZZZ'", "3:invalid 4-character unicode escape"),
            ("'\\u'", "3:invalid 4-character unicode escape"),
            ("'\\u12'", "3-5:invalid 4-character unicode escape"),
            ("'\\u00'", "3-5:invalid 4-character unicode escape"),
            ("'\\U110000'", "3-9:invalid 8-character unicode escape"),
            ("'\\U0001'", "3-7:invalid 8-character unicode escape"),
            // The reader refuses an escape that names U+0000, at any position
            // in the literal. The error names the escape at the offset of its
            // digits.
            ("'\\u0000'", "3-7:invalid 4-character unicode escape"),
            ("'\\U00000000'", "3-11:invalid 8-character unicode escape"),
            ("'a\\u0000b'", "4-8:invalid 4-character unicode escape"),
            ("'ab\\u0000'", "5-9:invalid 4-character unicode escape"),
            ("'\\u0000x'", "3-7:invalid 4-character unicode escape"),
            ("@s '\\u0000'", "6-10:invalid 4-character unicode escape"),
            ("@o '/a\\u0000b'", "8-12:invalid 4-character unicode escape"),
            (
                "objectpath '\\u0000'",
                "14-18:invalid 4-character unicode escape",
            ),
            ("@g '\\u0000'", "6-10:invalid 4-character unicode escape"),
            (
                "signature 'a\\u0000y'",
                "14-18:invalid 4-character unicode escape",
            ),
            ("{'\\u0000': 1}", "4-8:invalid 4-character unicode escape"),
            (
                "{'a': '\\u0000'}",
                "9-13:invalid 4-character unicode escape",
            ),
            (
                "['a', '\\u0000']",
                "9-13:invalid 4-character unicode escape",
            ),
            ("<'\\u0000'>", "4-8:invalid 4-character unicode escape"),
            ("@ms '\\u0000'", "7-11:invalid 4-character unicode escape"),
            ("('\\u0000',)", "4-8:invalid 4-character unicode escape"),
            // A surrogate and a code point past U+10FFFF take the same refusal.
            ("'\\ud800'", "3-7:invalid 4-character unicode escape"),
            ("'\\U0000d800'", "3-11:invalid 8-character unicode escape"),
            ("'\\U00110000'", "3-11:invalid 8-character unicode escape"),
            // The reader refuses a raw NUL byte in a string literal at its
            // position. The `ostree` command takes its value through `argv`,
            // which carries no NUL, so only ostrya has this refusal.
            ("'a\0b'", "2-3:NUL byte in string constant"),
            ("'\0'", "1-2:NUL byte in string constant"),
            ("@o '/a\0b'", "6-7:NUL byte in string constant"),
            ("{'\0': 1}", "2-3:NUL byte in string constant"),
        ];
        for (input, expected) in cases {
            assert_eq!(refuse(input), *expected, "refusing {input:?}");
        }
    }

    /// The first entry of an undeclared dictionary settles the value type.
    ///
    /// The reader reads every later value against that type. Each pair is one
    /// `--add-metadata` value and the text that `show -B --print-metadata-key`
    /// printed for it. The version of the `ostree` command is 2026.1.
    #[test]
    fn a_dictionary_reads_its_values_against_the_first_entry() {
        let cases: &[(&str, &str)] = &[
            // The order of the entries selects the type. The later value takes
            // that type.
            ("{'a': 1, 'b': uint32 2}", "{'a': 1, 'b': 2}"),
            ("{'a': uint32 2, 'b': 1}", "{'a': uint32 2, 'b': 1}"),
            ("{'a': 1.5, 'b': 1}", "{'a': 1.5, 'b': 1.0}"),
            ("{'a': 0x1.8p1, 'b': 1}", "{'a': 3.0, 'b': 1.0}"),
            ("{'a': 1.5, 'b': 1E3}", "{'a': 1.5, 'b': 1000.0}"),
            // A settled maybe absorbs the value beside it.
            ("{'a': just 'y', 'b': 'x'}", "{'a': @ms 'y', 'b': 'x'}"),
            ("{'a': just 2, 'b': 1}", "{'a': @mi 2, 'b': 1}"),
            (
                "{'a': @ms nothing, 'b': 'x'}",
                "{'a': @ms nothing, 'b': 'x'}",
            ),
            ("{'a': just 1, 'b': nothing}", "{'a': @mi 1, 'b': nothing}"),
            // A settled container type takes an empty container beside it.
            ("{'a': [1], 'b': []}", "{'a': [1], 'b': []}"),
            ("{'a': {'d': 2}, 'c': {}}", "{'a': {'d': 2}, 'c': {}}"),
            ("{'a': <1>, 'b': <'x'>}", "{'a': <1>, 'b': <'x'>}"),
            // The third entry follows the first as well.
            (
                "{'a': 1, 'b': 2, 'c': uint32 3}",
                "{'a': 1, 'b': 2, 'c': 3}",
            ),
            (
                "{'a': uint32 1, 'b': 2, 'c': 3}",
                "{'a': uint32 1, 'b': 2, 'c': 3}",
            ),
            // The keys unify to one common type, the same as the elements of
            // an array.
            ("{1: 'a', 2.5: 'b'}", "{1.0: 'a', 2.5: 'b'}"),
            ("{2.5: 'a', 1: 'b'}", "{2.5: 'a', 1.0: 'b'}"),
        ];
        for (input, expected) in cases {
            assert_eq!(round(input), *expected, "reading {input}");
        }
    }

    /// A type that is already in force drops a declaration beside a value.
    ///
    /// The type takes the value, so `@o` under `s` stores a string, and the
    /// object-path check does not run. Each pair is one `--add-metadata` value
    /// and the text that `show -B --print-metadata-key` printed for it. The
    /// version of the `ostree` command is 2026.1.
    #[test]
    fn a_declaration_under_a_driven_type_gives_up_its_type() {
        let cases: &[(&str, &str)] = &[
            ("@as [@o '/a']", "['/a']"),
            ("@as [@ms 'a']", "['a']"),
            ("@ai [@u 5]", "[5]"),
            ("@ao ['/a', @s '/b']", "[objectpath '/a', '/b']"),
            ("@a{ss} {'a': @o '/b'}", "{'a': '/b'}"),
            ("{'a': 'x', 'b': @o '/y'}", "{'a': 'x', 'b': '/y'}"),
            (
                "{'a': 'x', 'b': @o 'notapath'}",
                "{'a': 'x', 'b': 'notapath'}",
            ),
            ("{'a': 'x', 'b': @g 'ii'}", "{'a': 'x', 'b': 'ii'}"),
            ("{'a': 'x', 'b': @ms 'y'}", "{'a': 'x', 'b': 'y'}"),
            ("{'a': 1, 'b': @mi 2}", "{'a': 1, 'b': 2}"),
            (
                "{'a': @g 'ii', 'b': 'x'}",
                "{'a': signature 'ii', 'b': 'x'}",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(round(input), *expected, "reading {input}");
        }
        // The value beside the declaration must still fit the driven type.
        let refusals: &[(&str, &str)] = &[
            ("@as [@i 5]", "8-9:can not parse as value of type 's'"),
            ("@ai [@d 1.5]", "9-10:invalid character in number"),
            (
                "{'a': 1, 'b': @s 'x'}",
                "17-20:can not parse as value of type 'i'",
            ),
            (
                "{'a': 1, 'b': @b true}",
                "17-21:can not parse as value of type 'i'",
            ),
            (
                "{'a': true, 'b': @i 1}",
                "20-21:can not parse as value of type 'b'",
            ),
            ("{'a': 1, 'b': @d 1.5}", "18-19:invalid character in number"),
            (
                "{'a': 'x', 'b': @ms nothing}",
                "20-27:can not parse as value of type 's'",
            ),
            (
                "{'a': 1, 'b': uint32 4294967296}",
                "21-31:number out of range for type 'i'",
            ),
        ];
        for (input, expected) in refusals {
            assert_eq!(refuse(input), *expected, "refusing {input:?}");
        }
    }

    /// The error for a later dictionary value that does not fit names the
    /// settled type.
    ///
    /// If the first value states no type, the error names the whole value.
    /// Each pair is one refused `--add-metadata` value and the report of the
    /// `ostree` command. The report is the text after `Parsing <KEY=VALUE>: `.
    /// The version of the `ostree` command is 2026.1.
    #[test]
    fn refuses_a_dictionary_value_against_the_settled_type() {
        let cases: &[(&str, &str)] = &[
            // The integer reader takes the later literal and stops at the `.`.
            ("{'a': 1, 'b': 1.5}", "15-16:invalid character in number"),
            (
                "{'a': 1, 'b': 0x1.8p1}",
                "17-18:invalid character in number",
            ),
            ("{'a': 1, 'b': 1e3}", "15-16:invalid character in number"),
            (
                "{'a': 1, 'b': 2, 'c': 1.5}",
                "23-24:invalid character in number",
            ),
            // A maybe beside a settled plain type does not fit it.
            (
                "{'a': 'x', 'b': just 'y'}",
                "16-24:can not parse as value of type 's'",
            ),
            (
                "{'a': 'y', 'b': nothing}",
                "16-23:can not parse as value of type 's'",
            ),
            (
                "{'a': 1, 'b': just 2}",
                "14-20:can not parse as value of type 'i'",
            ),
            (
                "{'a': 1, 'b': 2, 'c': nothing}",
                "22-29:can not parse as value of type 'i'",
            ),
            (
                "{'a': 'x', 'b': 'y', 'c': just 'z'}",
                "26-34:can not parse as value of type 's'",
            ),
            // The check reaches into the later value one member at a time.
            (
                "{'a': (1,2), 'b': ('x','y')}",
                "19-22:can not parse as value of type 'i'",
            ),
            (
                "{'a': ('x','y'), 'b': (1,2)}",
                "23-24:can not parse as value of type 's'",
            ),
            (
                "{'a': [1], 'b': ['x']}",
                "17-20:can not parse as value of type 'i'",
            ),
            (
                "{'a': {'x': 1}, 'b': {'y': 'z'}}",
                "27-30:can not parse as value of type 'i'",
            ),
            ("{'a': @o '/y', 'b': 'x'}", "20-23:not a valid object path"),
            (
                "{'a': @o '/z', 'b': 'x', 'c': 'y'}",
                "20-23:not a valid object path",
            ),
            (
                "{'a': byte 1, 'b': 256}",
                "19-22:number out of range for type 'y'",
            ),
            (
                "{'a': 1, 'b': 99999999999999999999}",
                "14-34:integer too big for any type",
            ),
            // Type inference skips a later value, so the error names a later
            // shape against the settled type, also a shape that states its
            // own type.
            (
                "{'a': 1, 'b': ['x', 5]}",
                "14-22:can not parse as value of type 'i'",
            ),
            (
                "{'a': 1, 'b': {[1]: 'a'}}",
                "14-24:can not parse as value of type 'i'",
            ),
            (
                "{'a': 1, 'b': <[]>}",
                "14-18:can not parse as value of type 'i'",
            ),
            (
                "{'a': 1, 'b': {'y': 'z'}}",
                "14-24:can not parse as value of type 'i'",
            ),
            (
                "{'a': 5, 'b': []}",
                "14-16:can not parse as value of type 'i'",
            ),
            (
                "{'a': [1], 'b': 'x'}",
                "16-19:can not parse as value of type 'ai'",
            ),
            (
                "{'a': <1>, 'b': 'x'}",
                "16-19:can not parse as value of type 'v'",
            ),
            (
                "{'a': 'x', 'b': b'y'}",
                "16-20:can not parse as value of type 's'",
            ),
            (
                "{'a': b'x', 'b': 'y'}",
                "17-20:can not parse as value of type 'ay'",
            ),
            // A variant inside a later value is still a whole value of its own.
            ("{'a': <1>, 'b': <[]>}", "17-19:unable to infer type"),
            // If the first value states no type, the error names the whole
            // value. No later entry supplies the type.
            ("{'a': nothing, 'b': 'y'}", "0-24:unable to infer type"),
            (
                "{'a': nothing, 'b': 2, 'c': 3}",
                "0-30:unable to infer type",
            ),
            ("{'a': [], 'b': [1]}", "0-19:unable to infer type"),
            ("{'a': [], 'b': 5}", "0-17:unable to infer type"),
            ("{'a': [], 'b': 5, 'c': 6}", "0-25:unable to infer type"),
            ("{'a': [], 'b': ['x', 5]}", "0-24:unable to infer type"),
            ("{'a': {}, 'c': {'d': 2}}", "0-24:unable to infer type"),
            ("{'q': {'a': [], 'b': 5}}", "0-24:unable to infer type"),
            ("[{'a': [], 'b': 5}]", "0-19:unable to infer type"),
            ("({'a': [], 'b': 5},)", "0-20:unable to infer type"),
            ("just {'a': [], 'b': 5}", "0-22:unable to infer type"),
            ("<{'a': [], 'b': 5}>", "1-18:unable to infer type"),
            // The error for a key that does not unify with the settled key
            // type comes first. The value type is never resolved.
            (
                "{[1]: [], 'b': 5}",
                "1-4,10-13:unable to find a common type",
            ),
            (
                "{'a': [], [1]: 5}",
                "1-4,10-13:unable to find a common type",
            ),
            ("{'a': 1, @u 2: 3}", "1-4,9-13:unable to find a common type"),
            ("{@o '/a': 1, 'b': 2}", "13-16:not a valid object path"),
            ("{'a': 1, @o '/b': 2}", "1-4:not a valid object path"),
        ];
        for (input, expected) in cases {
            assert_eq!(refuse(input), *expected, "refusing {input:?}");
        }
    }

    /// A bytestring literal ends at the first NUL that its escapes produce.
    ///
    /// `b'\0'` and `b'\400'` are the one-byte array that the `ostree` command
    /// stores.
    #[test]
    fn a_bytestring_ends_at_its_first_nul() {
        let cases: &[(&str, &[u8])] = &[
            (r"b'\0'", &[0]),
            (r"b''", &[0]),
            (r"b'\400'", &[0]),
            (r"b'\0001'", &[0]),
            (r"b'\0\0'", &[0]),
            (r"b'a\0b'", &[b'a', 0]),
            (r"b'a\0'", &[b'a', 0]),
            (r"b'\101'", &[b'A', 0]),
            ("b'bytes'", b"bytes\0"),
        ];
        for (input, expected) in cases {
            let (ty, value) = from_text(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(ty.signature(), "ay", "type of {input}");
            assert_eq!(
                value,
                Value::Bytes((*expected).to_vec()),
                "value of {input}"
            );
        }
    }

    /// A backslash before a line feed is a line continuation.
    ///
    /// The rule applies to a string and to a bytestring. Both characters leave
    /// the value. `ostree` 2026.1 stores `'ab'` for `'a\<LF>b'`.
    #[test]
    fn a_backslash_before_a_line_feed_continues_the_line() {
        assert_eq!(round("'a\\\nb'"), "'ab'");
        assert_eq!(round("'\\\n'"), "''");
        assert_eq!(round("'a\\\n'"), "'a'");
        assert_eq!(round("'a\\\n\\\nb'"), "'ab'");
        // The line feed after a `\\` belongs to the literal, so it stays.
        assert_eq!(round("'a\\\\\nb'"), "'a\\\\\\nb'");
        // A raw line feed with no backslash before it stays as well.
        assert_eq!(round("'a\\\n\nb'"), "'a\\nb'");
        let (ty, value) = from_text("b'a\\\nb'").expect("the bytestring reads");
        assert_eq!(ty.signature(), "ay");
        assert_eq!(value, Value::Bytes(b"ab\0".to_vec()));
    }

    /// The nesting that the `ostree` command accepts, the next level, and the
    /// refusal.
    ///
    /// The test also checks the wording of the refusal. A value sits inside a
    /// maximum of 127 levels.
    #[test]
    fn refuses_the_level_past_the_nesting_cap() {
        // A tuple of one member needs its comma, so the tuple form closes
        // each level with `,)`. The other two forms close with the bracket
        // alone.
        for (open, close) in [("[", "]"), ("(", ",)"), ("<", ">")] {
            for depth in [125usize, 126, 127] {
                let text = format!("{}1{}", open.repeat(depth), close.repeat(depth));
                assert!(
                    from_text(&text).is_ok(),
                    "depth {depth} of {open} was refused"
                );
            }
            for depth in [128usize, 129, 200] {
                let text = format!("{}1{}", open.repeat(depth), close.repeat(depth));
                assert_eq!(
                    refuse(&text),
                    "128:variant nested too deeply",
                    "depth {depth} of {open}"
                );
            }
        }
        // A `just`, a declaration, and a type keyword each add a level too.
        assert!(from_text(&format!("{}5", "just ".repeat(127))).is_ok());
        assert!(from_text(&format!("{}5", "@i ".repeat(127))).is_ok());
        assert!(from_text(&format!("{}5", "uint32 ".repeat(127))).is_ok());
        for text in [
            format!("{}5", "just ".repeat(128)),
            format!("{}5", "@i ".repeat(128)),
            format!("{}5", "uint32 ".repeat(128)),
        ] {
            assert!(
                refuse(&text).ends_with("variant nested too deeply"),
                "{text}"
            );
        }
    }

    /// A signature value takes 129 levels, with the leaf counted.
    ///
    /// The reader checks a signature value as a type string on its own. Its
    /// levels are inside the string, so its level in the value does not
    /// narrow it. Measured against `ostree` 2026.1.
    #[test]
    fn a_signature_value_takes_129_levels() {
        let arrays = |count: usize| "a".repeat(count);
        for count in [0usize, 1, 65, 127, 128] {
            for text in [
                format!("signature '{}y'", arrays(count)),
                format!("@g '{}y'", arrays(count)),
            ] {
                assert!(from_text(&text).is_ok(), "{count} arrays was refused");
            }
        }
        assert_eq!(
            refuse(&format!("signature '{}y'", arrays(129))),
            "10-142:not a valid signature"
        );
        assert_eq!(
            refuse(&format!("@g '{}y'", arrays(129))),
            "3-135:not a valid signature"
        );
        // The deepest signature stands at the deepest level that a value
        // reaches.
        let deep = format!(
            "{}signature '{}y'{}",
            "[".repeat(100),
            arrays(128),
            "]".repeat(100)
        );
        assert!(from_text(&deep).is_ok());
    }

    /// A declaration takes the levels of its type, up to 128 levels in all.
    ///
    /// The count starts at the level where the declaration stands. A leaf is
    /// one level, and a container adds one over its deepest member. The empty
    /// tuple carries no level. A dict entry measures its value.
    ///
    /// A type string past 129 levels is invalid. The invalid refusal comes
    /// before the depth refusal. The depth refusal comes before the
    /// definiteness refusal. Measured against `ostree` 2026.1.
    #[test]
    fn a_declaration_takes_128_levels_from_where_it_stands() {
        let arrays = |count: usize| "a".repeat(count);
        for text in [
            format!("@{}y []", arrays(127)),
            format!("@{}() []", arrays(128)),
            format!("@{}(y) []", arrays(126)),
            format!("@{}(()) []", arrays(127)),
            format!("@{}{{sy}} []", arrays(126)),
            format!("@{}{{s()}} []", arrays(127)),
            format!("@{}(y()) []", arrays(126)),
            format!("@{}((y)y) []", arrays(125)),
            format!("[@{}y []]", arrays(126)),
            format!("[[@{}y []]]", arrays(125)),
        ] {
            assert!(from_text(&text).is_ok(), "{text} was refused");
        }
        let deep = "type declaration recurses too deeply";
        let invalid = "invalid type declaration";
        let indefinite = "type declarations must be definite";
        let cases: &[(String, String)] = &[
            (format!("@{}y []", arrays(128)), format!("0-130:{deep}")),
            (format!("@{}y []", arrays(129)), format!("0-131:{invalid}")),
            (format!("@{}(y) []", arrays(127)), format!("0-131:{deep}")),
            (format!("@{}() []", arrays(129)), format!("0-132:{invalid}")),
            (
                format!("@{}{{sy}} []", arrays(127)),
                format!("0-132:{deep}"),
            ),
            (
                format!("@{}(()) []", arrays(128)),
                format!("0-133:{invalid}"),
            ),
            (format!("@{}(y()) []", arrays(127)), format!("0-133:{deep}")),
            (
                format!("@{}((y)y) []", arrays(126)),
                format!("0-133:{deep}"),
            ),
            // The reader reports the definiteness only inside the cap.
            (format!("@{}r 5", arrays(66)), format!("0-68:{indefinite}")),
            (
                format!("@{}r 5", arrays(127)),
                format!("0-129:{indefinite}"),
            ),
            (format!("@{}r 5", arrays(128)), format!("0-130:{deep}")),
            (format!("@{}r 5", arrays(129)), format!("0-131:{invalid}")),
            (
                format!("@{}* 5", arrays(127)),
                format!("0-129:{indefinite}"),
            ),
            (format!("@{}* 5", arrays(128)), format!("0-130:{deep}")),
            (
                format!("@{}(r) 5", arrays(126)),
                format!("0-130:{indefinite}"),
            ),
            (format!("@{}(r) 5", arrays(127)), format!("0-131:{deep}")),
            // A declaration inside a container starts from that level.
            (format!("[@{}y []]", arrays(127)), format!("1-130:{deep}")),
            (format!("[[@{}y []]]", arrays(126)), format!("2-130:{deep}")),
        ];
        for (text, expected) in cases {
            assert_eq!(refuse(text), *expected, "refusing {text}");
        }
    }

    /// The reader parses, types, and builds the value before the trailing check.
    ///
    /// If the value has a fault, the error names that fault.
    #[test]
    fn a_fault_in_the_value_stands_ahead_of_trailing_input() {
        let cases: &[(&str, &str)] = &[
            ("@i 'x' 5", "3-6:can not parse as value of type 'i'"),
            ("3000000000 5", "0-10:number out of range for type 'i'"),
            ("@d 5e-324 5", "3-9:number too big for any type"),
            ("objectpath 'bad' 5", "11-16:not a valid object path"),
            ("nothing 5", "0-7:unable to infer type"),
            ("(1) 5", "2:expected ',' after first tuple element"),
            // A value with no fault of its own reports the trailing token.
            ("42 43", "3:expected end of input"),
            ("nan(0x1)", "3:expected end of input"),
        ];
        for (input, expected) in cases {
            assert_eq!(refuse(input), *expected, "refusing {input:?}");
        }
    }

    /// The depth limit of the parser bounds the node tree.
    ///
    /// The reader refuses a text far past the cap, and the stack does not
    /// overflow. This applies to the parser, type inference, construction, and
    /// the drop of the tree.
    #[test]
    fn deep_nesting_does_not_overflow_the_stack() {
        for text in [
            "[".repeat(50_000),
            format!("{}1{}", "[".repeat(50_000), "]".repeat(50_000)),
            format!("{}1{}", "(".repeat(50_000), ")".repeat(50_000)),
            format!("{}1{}", "<".repeat(50_000), ">".repeat(50_000)),
            format!("{}1", "just ".repeat(50_000)),
            format!("{}1{}", "{'a': ".repeat(20_000), "}".repeat(20_000)),
            format!("{}5", "@i ".repeat(50_000)),
            format!("@{}i 5", "a".repeat(50_000)),
        ] {
            assert!(from_text(&text).is_err(), "{:.20} was accepted", text);
        }
    }

    /// Every text that the printer writes reads back.
    ///
    /// A value can go out through `to_text` and come back in through
    /// `from_text`.
    #[test]
    fn the_printers_output_reads_back() {
        let cases = [
            "nan",
            "-nan",
            "inf",
            "-inf",
            "1.5",
            "-0.0",
            "0.10000000000000001",
            "1.7976931348623157e+308",
            "uint32 42",
            "byte 0x41",
            "@ms nothing",
            "b'bytes'",
            "{'x': 'y'}",
            "('a', 5)",
            "<'x'>",
            "objectpath '/a/b'",
            "signature 'ay'",
            "(1,)",
            "[byte 0x01, 0x02]",
            "@a{sv} {}",
            "[@ms 'a', nothing]",
            "{'a', 5}",
            "int64 -5",
            "handle 5",
            // Every escape that the string printer writes, its quote for a
            // string that holds a quote, and one character that it writes
            // unchanged.
            "'a\\ab'",
            "'a\\bb'",
            "'a\\fb'",
            "'a\\nb'",
            "'a\\rb'",
            "'a\\tb'",
            "'a\\vb'",
            "'a\\\\b'",
            "'a\\u001bb'",
            "'a\\u007fb'",
            "\"a'b\"",
            "'a\"b'",
            "\"a'\\\"b\"",
            "'héllo'",
            // Every escape that the bytestring printer writes, and the quote
            // that it selects for content with a single quote in it.
            "b'a\\tb'",
            "b'a\\nb'",
            "b'a\\rb'",
            "b'a\\bb'",
            "b'a\\fb'",
            "b'a\\vb'",
            "b'a\\\\b'",
            "b'a\\\"b'",
            "b\"a'b\"",
            "b\"a'\\\"b\"",
            "b'\\377'",
            "b'h\\303\\251'",
            // A nested maybe. The `just ` prefixes that the printer writes are
            // the only record of the number of set levels. If these prefixes do
            // not survive, the text reads back as a different value.
            "@mmi 5",
            "@mmi just nothing",
            "@mmi nothing",
            "@mmmi just just nothing",
            "@mmmi just nothing",
            "@mmmmi just just just nothing",
            "@mms just nothing",
            "@mmv just nothing",
            "@mmv <5>",
            "@mmay just nothing",
            "@mm() just nothing",
            "@mammi [just nothing]",
            "[@mmi just nothing, nothing, 5]",
            "[@mmmi just just nothing, just nothing, nothing, 5]",
            "{'a': @mmi just nothing, 'b': nothing, 'c': 5}",
            "{'a', @mmi just nothing}",
            "(@mmi just nothing,)",
            "(@mmi just nothing, @mmi nothing, @mmi 5)",
        ];
        for text in cases {
            let (ty, value) = from_text(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            let printed = to_text(&ty, &value).unwrap();
            assert_eq!(printed, text, "printing {text}");
            let (again_ty, again_value) =
                from_text(&printed).unwrap_or_else(|e| panic!("{printed}: {e}"));
            assert_eq!(again_ty, ty, "type of {text}");
            assert_eq!(again_value, value, "value of {text}");
        }
        // The reader refuses one text that the printer writes, a subnormal.
        // The `ostree` command also refuses a subnormal on the way in.
        let printed = to_text(&Type::Double, &Value::double(f64::from_bits(1))).unwrap();
        assert_eq!(printed, "4.9406564584124654e-324");
        assert_eq!(
            refuse(&printed),
            "0-23:number too big for any type",
            "the subnormal the printer writes"
        );
    }

    /// Every maybe chain that the printer writes reads back as the same value.
    ///
    /// If every level of a chain is set, the printer writes the value alone.
    /// Then the type states the level count. A chain that ends at `nothing`
    /// states its set levels, with one `just ` for each. Both readings must
    /// survive the trip. If not, the printed text names a different value.
    #[test]
    fn every_maybe_chain_the_printer_writes_reads_back() {
        let leaves: &[(&str, Value)] = &[
            ("i", Value::I32(5)),
            ("s", Value::Str("x".into())),
            ("v", Value::variant(Type::I32, Value::I32(5))),
            ("ay", Value::Bytes(vec![0x01])),
            ("()", Value::Tuple(Vec::new())),
            ("ai", Value::Array(vec![Value::I32(1)])),
            (
                "(is)",
                Value::Tuple(vec![Value::I32(1), Value::Str("x".into())]),
            ),
            (
                "a{si}",
                Value::Array(vec![Value::Tuple(vec![
                    Value::Str("k".into()),
                    Value::I32(1),
                ])]),
            ),
        ];
        for (element, leaf) in leaves {
            for depth in 1..=4usize {
                let signature = format!("{}{element}", "m".repeat(depth));
                let ty = Type::parse(&signature).unwrap();
                for set in 0..=depth {
                    let mut value = if set == depth {
                        leaf.clone()
                    } else {
                        Value::Maybe(None)
                    };
                    for _ in 0..set {
                        value = Value::Maybe(Some(Box::new(value)));
                    }
                    let printed = to_text(&ty, &value).unwrap();
                    let (again_ty, again_value) = from_text(&printed)
                        .unwrap_or_else(|e| panic!("{signature} set {set}: {printed}: {e}"));
                    assert_eq!(again_ty, ty, "type of {printed}");
                    assert_eq!(again_value, value, "value of {printed}");
                }
            }
        }
    }

    /// A value serializes to the bytes that the `ostree` command stores.
    ///
    /// The bytes of a `u` and a `d` are little-endian.
    #[test]
    fn serializes_in_host_byte_order() {
        let (ty, value) = from_text("uint32 42").unwrap();
        assert_eq!(ty.signature(), "u");
        assert_eq!(to_bytes(&ty, &value).unwrap(), 42u32.to_le_bytes());
        let (ty, value) = from_text("1.5").unwrap();
        assert_eq!(ty.signature(), "d");
        assert_eq!(to_bytes(&ty, &value).unwrap(), 1.5f64.to_le_bytes());
    }
}
