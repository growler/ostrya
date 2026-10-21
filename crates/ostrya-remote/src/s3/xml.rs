//! The reader of the XML bodies of the S3 responses.
//!
//! The reader walks a body with the pull parser of `quick-xml`, and gives the
//! text of each element at its end tag, with the path of element names from
//! the root. The typed readers below take the elements that the bucket
//! client reads, and skip each other element.
//!
//! The reader keeps to a small subset of XML:
//!
//! - The body is UTF-8 and at most [`MAX_BODY`] bytes. A UTF-8 byte order
//!   mark at the start is skipped. A declaration that names an encoding
//!   other than UTF-8 is refused.
//! - A `DOCTYPE` is refused. The parser does not read an entity definition,
//!   and the reader expands no entity. It accepts the five predefined
//!   entities and the character references of a character that XML 1.0
//!   allows. It refuses each other reference.
//! - The document has one root element, and ends with no open element.
//! - The elements are at most [`MAX_DEPTH`] deep.
//! - The reader ignores attributes, comments, and processing instructions.
//!   A CDATA section is text.
//! - Names compare in full. S3 uses a default namespace and no prefix.
//!
//! A message of the reader names the construct and the byte offset. A
//! refusal of the parser gives a fixed text for each kind of error, and holds
//! no text of the body. A message that names a value of the body, for example
//! the name of the root element or the value of `IsTruncated`, passes it
//! through [`shown`].

use quick_xml::errors::{Error as XmlError, IllFormedError, SyntaxError};
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// The largest body that the reader reads: 4 MiB.
pub(crate) const MAX_BODY: usize = 4 * 1024 * 1024;

/// The deepest element that the reader accepts. The S3 responses are three
/// levels deep.
const MAX_DEPTH: usize = 32;

/// The longest text of an element that a message of the bucket client shows.
const MAX_SHOWN: usize = 512;

/// The S3 `Error` document.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ErrorDoc {
    /// The `Code` element.
    pub(crate) code: Option<String>,
    /// The `Message` element.
    pub(crate) message: Option<String>,
    /// The `Region` element, which names the region of the bucket.
    pub(crate) region: Option<String>,
}

/// A document of the expected root, or an S3 `Error` document.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Doc<T> {
    /// The expected document.
    Result(T),
    /// An `Error` document in place of the expected one. S3 can send it with
    /// a 200.
    Error(ErrorDoc),
}

/// One page of `ListObjectsV2`: the `ListBucketResult` document.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ObjectsPage {
    /// `true` if `EncodingType` is `url`.
    pub(crate) encoded: bool,
    /// `IsTruncated`.
    pub(crate) truncated: bool,
    /// `NextContinuationToken`.
    pub(crate) token: Option<String>,
    /// The `Key` and the `Size` of each `Contents`.
    pub(crate) contents: Vec<(String, u64)>,
    /// The `Prefix` of each `CommonPrefixes`.
    pub(crate) prefixes: Vec<String>,
}

/// One page of `ListMultipartUploads`: the `ListMultipartUploadsResult`
/// document.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UploadsPage {
    /// `true` if `EncodingType` is `url`.
    pub(crate) encoded: bool,
    /// `IsTruncated`.
    pub(crate) truncated: bool,
    /// `NextKeyMarker`.
    pub(crate) next_key_marker: Option<String>,
    /// `NextUploadIdMarker`.
    pub(crate) next_upload_id_marker: Option<String>,
    /// The `Key`, the `UploadId`, and the `Initiated` of each `Upload`.
    pub(crate) uploads: Vec<(String, String, String)>,
}

/// The callback of [`walk`]: it gets the names from the root to an element
/// and the text of the element, and can refuse the document.
type OnEnd<'a> = dyn FnMut(&[&str], &str) -> Result<(), String> + 'a;

/// Reads `body` and calls `on_end` at the end tag of each element, with the
/// names from the root to the element and the text of the element.
///
/// The text of an element is the text after its start tag or after the end
/// tag of its last child.
fn walk(body: &[u8], on_end: &mut OnEnd<'_>) -> Result<(), String> {
    if body.len() > MAX_BODY {
        return Err(format!(
            "the body has {} bytes, more than the limit of {MAX_BODY}",
            body.len()
        ));
    }
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let text = std::str::from_utf8(body)
        .map_err(|e| format!("the body is not UTF-8 at byte {}", e.valid_up_to()))?;
    let mut reader = Reader::from_str(text);
    // The names of the open elements are `path[..depth]`. The strings past
    // `depth` keep their buffers for the next elements.
    let mut path: Vec<String> = Vec::new();
    let mut depth = 0;
    let mut content = String::new();
    let mut had_root = false;
    loop {
        let at = reader.buffer_position();
        let event = reader
            .read_event()
            .map_err(|e| format!("{} at byte {}", reader_error(&e), reader.error_position()))?;
        match event {
            Event::Start(_) | Event::Empty(_) if depth == 0 && had_root => {
                return Err(format!("a second root element at byte {at}"));
            }
            Event::Start(_) | Event::Empty(_) if depth >= MAX_DEPTH => {
                return Err(format!(
                    "an element deeper than {MAX_DEPTH} levels at byte {at}"
                ));
            }
            Event::Start(start) => {
                enter(&mut path, depth, start.name().as_ref());
                depth += 1;
                had_root = true;
                content.clear();
            }
            Event::Empty(start) => {
                enter(&mut path, depth, start.name().as_ref());
                had_root = true;
                leave(&path[..=depth], "", on_end)?;
                content.clear();
            }
            Event::End(_) => {
                leave(&path[..depth], &content, on_end)?;
                depth -= 1;
                content.clear();
            }
            Event::Text(text) if depth == 0 => {
                if !text.xml10_content().trim().is_empty() {
                    return Err(format!("text outside the root element at byte {at}"));
                }
            }
            Event::Text(text) => content.push_str(&text.xml10_content()),
            Event::CData(_) if depth == 0 => {
                return Err(format!(
                    "a CDATA section outside the root element at byte {at}"
                ));
            }
            Event::CData(data) => content.push_str(&data.xml10_content()),
            Event::GeneralRef(reference) => {
                if depth == 0 {
                    return Err(format!("a reference outside the root element at byte {at}"));
                }
                match reference.resolve_char_ref() {
                    Ok(Some(c)) if is_xml_char(c) => content.push(c),
                    Ok(Some(_)) | Err(_) => {
                        return Err(format!(
                            "a character reference to a character that XML 1.0 does not \
                             allow at byte {at}"
                        ));
                    }
                    Ok(None) => match resolve_predefined_entity(&reference) {
                        Some(expanded) => content.push_str(expanded),
                        None => {
                            return Err(format!(
                                "a reference to an entity other than the five predefined \
                                 entities at byte {at}"
                            ));
                        }
                    },
                }
            }
            Event::DocType(_) => return Err(format!("a DOCTYPE at byte {at}")),
            Event::Decl(declaration) => {
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|_| {
                        format!("an invalid attribute of the XML declaration at byte {at}")
                    })?;
                    if !encoding.eq_ignore_ascii_case("utf-8") {
                        return Err(format!(
                            "a declaration of an encoding other than UTF-8 at byte {at}"
                        ));
                    }
                }
            }
            Event::Comment(_) | Event::PI(_) => {}
            Event::Eof if !had_root => return Err("the body holds no element".to_owned()),
            Event::Eof if depth == 0 => return Ok(()),
            Event::Eof => {
                return Err(format!(
                    "the body ends inside the element {}",
                    shown(&path[depth - 1])
                ));
            }
        }
    }
}

/// Sets the name of the element at `depth` of `path` to `name`, and keeps
/// the buffer of a string that an earlier element left there.
fn enter(path: &mut Vec<String>, depth: usize, name: &str) {
    match path.get_mut(depth) {
        Some(slot) => {
            slot.clear();
            slot.push_str(name);
        }
        None => path.push(name.to_owned()),
    }
}

/// Calls `on_end` for the element whose path from the root is `path`, with
/// its text `text`.
///
/// The names go to `on_end` in an array on the stack, which holds the
/// [`MAX_DEPTH`] levels of the reader.
fn leave(path: &[String], text: &str, on_end: &mut OnEnd<'_>) -> Result<(), String> {
    let mut names = [""; MAX_DEPTH];
    for (name, element) in names.iter_mut().zip(path) {
        *name = element;
    }
    on_end(&names[..path.len()], text)
}

/// Returns the text of a refusal of the parser for each kind of error. The
/// text holds no part of the body.
fn reader_error(error: &XmlError) -> &'static str {
    match error {
        XmlError::Syntax(syntax) => match syntax {
            SyntaxError::InvalidBangMarkup => {
                "a `<!` that starts no comment, CDATA section, or DOCTYPE"
            }
            SyntaxError::UnclosedPI => "an unclosed processing instruction",
            SyntaxError::UnclosedXmlDecl => "an unclosed XML declaration",
            SyntaxError::UnclosedComment => "an unclosed comment",
            SyntaxError::UnclosedDoctype => "an unclosed DOCTYPE",
            SyntaxError::UnclosedCData => "an unclosed CDATA section",
            SyntaxError::UnclosedTag => "an unclosed tag",
            SyntaxError::UnclosedSingleQuotedAttributeValue
            | SyntaxError::UnclosedDoubleQuotedAttributeValue => "an unclosed attribute value",
        },
        XmlError::IllFormed(ill) => match ill {
            IllFormedError::MissingDeclVersion(_) => "an XML declaration with no version",
            IllFormedError::UnknownVersion => {
                "an XML declaration of a version other than 1.0 and 1.1"
            }
            IllFormedError::MissingDoctypeName => "a DOCTYPE with no name",
            IllFormedError::MissingEndTag(_) => "an element with no end tag",
            IllFormedError::UnmatchedEndTag(_) => "an end tag with no start tag",
            IllFormedError::MismatchedEndTag { .. } => {
                "an end tag that does not match its start tag"
            }
            IllFormedError::DoubleHyphenInComment => "a comment that holds `--`",
            IllFormedError::UnclosedReference => "an unclosed reference",
        },
        XmlError::Io(_) => "a failed read",
        XmlError::InvalidAttr(_) => "an invalid attribute",
        XmlError::Encoding(_) => "text that is not UTF-8",
        XmlError::Escape(_) => "an invalid reference",
        XmlError::Namespace(_) => "an invalid namespace",
    }
}

/// Returns `true` if XML 1.0 allows the character `c`.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}')
        || c >= '\u{10000}'
}

/// Returns `text` for a message: each control character (Unicode category
/// Cc) and each format character (Cf) replaced with U+FFFD, and at most
/// [`MAX_SHOWN`] bytes, cut at a character boundary.
///
/// A format character can change the order in which a terminal shows the
/// text, for example U+202E, which starts right-to-left text.
pub(crate) fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_SHOWN));
    for c in text.chars() {
        let c = if c.is_control() || is_format(c) {
            '\u{fffd}'
        } else {
            c
        };
        if out.len() + c.len_utf8() > MAX_SHOWN {
            break;
        }
        out.push(c);
    }
    out
}

/// Returns `true` for a format character: a character of the Unicode
/// category Cf, as of Unicode 15.1.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// Reads `body` as a document of one of the roots `roots`, or as an S3
/// `Error` document. `on_end` gets the end of each element under the root.
///
/// Returns the `Error` document if the root is `Error`, and `None` if the
/// root is one of `roots`.
fn read(
    body: &[u8],
    roots: &[&str],
    mut on_end: impl FnMut(&[&str], &str) -> Result<(), String>,
) -> Result<Option<ErrorDoc>, String> {
    let mut error: Option<ErrorDoc> = None;
    walk(body, &mut |path, text| match path {
        ["Error", rest @ ..] => {
            let doc = error.get_or_insert_with(ErrorDoc::default);
            match rest {
                ["Code"] => doc.code = Some(text.to_owned()),
                ["Message"] => doc.message = Some(text.to_owned()),
                ["Region"] => doc.region = Some(text.to_owned()),
                _ => {}
            }
            Ok(())
        }
        [first, rest @ ..] if roots.contains(first) => on_end(rest, text),
        [first, ..] => Err(format!(
            "the root element is {}, and {} or Error was expected",
            shown(first),
            roots.join(" or ")
        )),
        [] => Ok(()),
    })?;
    Ok(error)
}

/// Reads the text of `IsTruncated`.
fn truncated(text: &str) -> Result<bool, String> {
    match text.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("IsTruncated is {:?}", shown(other))),
    }
}

/// Reads an S3 `Error` document, or returns `None` if `body` is not one.
pub(crate) fn error(body: &[u8]) -> Option<ErrorDoc> {
    read(body, &["Error"], |_, _| Ok(())).ok().flatten()
}

/// Reads one page of `ListObjectsV2`.
pub(crate) fn list_objects(body: &[u8]) -> Result<Doc<ObjectsPage>, String> {
    let mut page = ObjectsPage::default();
    let mut key: Option<String> = None;
    let mut size: Option<u64> = None;
    let mut failure: Option<String> = None;
    let outcome = read(body, &["ListBucketResult"], |path, text| {
        match path {
            ["EncodingType"] => page.encoded = text.trim() == "url",
            ["IsTruncated"] => page.truncated = truncated(text)?,
            ["NextContinuationToken"] => page.token = Some(text.to_owned()),
            ["Contents", "Key"] => key = Some(text.to_owned()),
            ["Contents", "Size"] => {
                let parsed = text
                    .trim()
                    .parse()
                    .map_err(|_| format!("the Size {:?} is not a number", shown(text)))?;
                size = Some(parsed);
            }
            ["Contents"] => match (key.take(), size.take()) {
                (Some(key), Some(size)) => page.contents.push((key, size)),
                _ => failure = Some("a Contents element has no Key or no Size".to_owned()),
            },
            ["CommonPrefixes", "Prefix"] => page.prefixes.push(text.to_owned()),
            _ => {}
        }
        Ok(())
    })?;
    finish(outcome, failure, page)
}

/// Reads one page of `ListMultipartUploads`.
pub(crate) fn list_uploads(body: &[u8]) -> Result<Doc<UploadsPage>, String> {
    let mut page = UploadsPage::default();
    let (mut key, mut id, mut initiated) = (None, None, None);
    let mut failure: Option<String> = None;
    let outcome = read(body, &["ListMultipartUploadsResult"], |path, text| {
        match path {
            ["EncodingType"] => page.encoded = text.trim() == "url",
            ["IsTruncated"] => page.truncated = truncated(text)?,
            ["NextKeyMarker"] => page.next_key_marker = Some(text.to_owned()),
            ["NextUploadIdMarker"] => page.next_upload_id_marker = Some(text.to_owned()),
            ["Upload", "Key"] => key = Some(text.to_owned()),
            ["Upload", "UploadId"] => id = Some(text.to_owned()),
            ["Upload", "Initiated"] => initiated = Some(text.to_owned()),
            ["Upload"] => match (key.take(), id.take()) {
                (Some(key), Some(id)) => {
                    page.uploads
                        .push((key, id, initiated.take().unwrap_or_default()));
                }
                _ => failure = Some("an Upload element has no Key or no UploadId".to_owned()),
            },
            _ => {}
        }
        Ok(())
    })?;
    finish(outcome, failure, page)
}

/// Reads the answer that starts a multipart upload, and returns its
/// `UploadId`.
///
/// The root is `InitiateMultipartUploadResult`, the root of the AWS API
/// reference, or `InitiateMultipartUpload`, which `rclone serve s3` 1.75.1
/// writes. An `UploadId` that is absent, empty, or white space alone is
/// refused.
pub(crate) fn initiate(body: &[u8]) -> Result<Doc<String>, String> {
    let mut id: Option<String> = None;
    let outcome = read(
        body,
        &["InitiateMultipartUploadResult", "InitiateMultipartUpload"],
        |path, text| {
            if let ["UploadId"] = path {
                id = Some(text.to_owned());
            }
            Ok(())
        },
    )?;
    let (failure, id) = match id {
        None => (Some("the answer has no UploadId".to_owned()), String::new()),
        Some(id) if id.trim().is_empty() => {
            (Some("the UploadId of the answer is empty".to_owned()), id)
        }
        Some(id) => (None, id),
    };
    finish(outcome, failure, id)
}

/// Reads the `CompleteMultipartUploadResult` document, and returns its
/// `ETag`, as the server wrote it.
///
/// An `ETag` that is empty or white space alone reads as absent.
pub(crate) fn complete(body: &[u8]) -> Result<Doc<Option<String>>, String> {
    let mut etag: Option<String> = None;
    let outcome = read(body, &["CompleteMultipartUploadResult"], |path, text| {
        if let ["ETag"] = path {
            etag = (!text.trim().is_empty()).then(|| text.to_owned());
        }
        Ok(())
    })?;
    finish(outcome, None, etag)
}

/// Returns the result of a typed reader: the `Error` document of `outcome`,
/// else the refusal `failure`, else `page`.
fn finish<T>(
    outcome: Option<ErrorDoc>,
    failure: Option<String>,
    page: T,
) -> Result<Doc<T>, String> {
    match (outcome, failure) {
        (Some(doc), _) => Ok(Doc::Error(doc)),
        (None, Some(failure)) => Err(failure),
        (None, None) => Ok(Doc::Result(page)),
    }
}

#[cfg(test)]
mod tests;
