//! The splitter of PEM text into blocks.
//!
//! A key file can hold more than one PEM block, and text outside the blocks.
//! The splitter finds the boundary lines of each block. `pem-rfc7468` decodes
//! the body of each block.
//!
//! The rules:
//!
//! - A line ends at LF. The splitter removes one CR at the end of each line.
//!   A CR at another position is a byte of the line.
//! - The splitter removes the leading and trailing spaces and tabs of a line
//!   before it compares the line with a boundary. A BEGIN line is then
//!   `-----BEGIN LABEL-----`, and an END line is `-----END LABEL-----`. `LABEL`
//!   is not empty. A line with other text is not a boundary line.
//! - Outside a block, a BEGIN line opens a block, and each other line is text
//!   that the splitter ignores.
//! - In a block, an END line with the same label closes the block. An END
//!   line with another label, a BEGIN line, and the end of the text are
//!   errors. Each other line is a body line.
//!
//! The splitter works on bytes. The text outside the blocks can hold any byte.

/// The prefix of a BEGIN line.
const BEGIN: &[u8] = b"-----BEGIN ";
/// The prefix of an END line.
const END: &[u8] = b"-----END ";
/// The suffix of a boundary line.
const DASHES: &[u8] = b"-----";

/// One PEM block of a text.
pub(crate) struct Block<'a> {
    /// The label of the BEGIN line.
    pub(crate) label: &'a [u8],
    /// The 1-based number of the BEGIN line.
    pub(crate) line: usize,
    /// The body lines, each with its line end.
    body: &'a [u8],
}

impl Block<'_> {
    /// Returns the label as text, for a message.
    pub(crate) fn label_text(&self) -> String {
        String::from_utf8_lossy(self.label).into_owned()
    }

    /// Decodes the body of the block.
    ///
    /// The function removes the LF and the one CR at the end of each body
    /// line. It refuses a body line that is then empty or that holds a CR. It
    /// builds the block again with LF line ends and gives it to `pem-rfc7468`,
    /// which reads lines of 64 base64 characters, the last line shorter or
    /// equal, and no headers.
    ///
    /// # Errors
    ///
    /// - A message if a body line is empty or holds a CR. The message gives
    ///   the line number.
    /// - A message if `pem-rfc7468` refuses the block, or if the body holds no
    ///   data.
    pub(crate) fn decode(&self) -> Result<Vec<u8>, String> {
        let boundaries = BEGIN.len() + END.len() + 2 * (self.label.len() + DASHES.len() + 1);
        let mut text = Vec::with_capacity(self.body.len() + boundaries);
        text.extend_from_slice(BEGIN);
        text.extend_from_slice(self.label);
        text.extend_from_slice(DASHES);
        text.push(b'\n');
        for (index, line) in self.body.split_inclusive(|&byte| byte == b'\n').enumerate() {
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let number = self.line + 1 + index;
            if line.is_empty() {
                return Err(format!("line {number} is empty"));
            }
            if line.contains(&b'\r') {
                return Err(format!("line {number} holds a CR"));
            }
            text.extend_from_slice(line);
            text.push(b'\n');
        }
        text.extend_from_slice(END);
        text.extend_from_slice(self.label);
        text.extend_from_slice(DASHES);
        text.push(b'\n');
        let (_, bytes) = pem_rfc7468::decode_vec(&text).map_err(|e| e.to_string())?;
        if bytes.is_empty() {
            return Err("the block holds no data".into());
        }
        Ok(bytes)
    }
}

/// Splits `text` into its PEM blocks, in the order of the text.
///
/// # Errors
///
/// A message that gives the line number:
///
/// - An END line with a label other than the label of the open block.
/// - A BEGIN line in an open block.
/// - A block with no END line.
pub(crate) fn split(text: &[u8]) -> Result<Vec<Block<'_>>, String> {
    let mut blocks = Vec::new();
    // The open block, and the offset of its first body line.
    let mut open: Option<(Block<'_>, usize)> = None;
    let mut start = 0;
    for (index, raw) in text.split(|&byte| byte == b'\n').enumerate() {
        let number = index + 1;
        let line_start = start;
        start += raw.len() + 1;
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let bare = trim_blank(line);
        let Some((block, body_start)) = open.as_mut() else {
            if let Some(label) = boundary(bare, BEGIN) {
                let block = Block {
                    label,
                    line: number,
                    body: &[],
                };
                open = Some((block, start));
            }
            continue;
        };
        if let Some(label) = boundary(bare, END) {
            if label != block.label {
                return Err(format!(
                    "line {number}: the END label \"{}\" is not the label \"{}\" of the BEGIN \
                     line {}",
                    String::from_utf8_lossy(label),
                    block.label_text(),
                    block.line
                ));
            }
            block.body = &text[*body_start..line_start];
            blocks.extend(open.take().map(|(block, _)| block));
        } else if boundary(bare, BEGIN).is_some() {
            return Err(format!(
                "line {number}: a BEGIN line is in the block that starts at line {}",
                block.line
            ));
        }
    }
    if let Some((block, _)) = open {
        return Err(format!(
            "line {}: the block \"{}\" has no END line",
            block.line,
            block.label_text()
        ));
    }
    Ok(blocks)
}

/// Removes the leading and trailing spaces and tabs of `line`.
fn trim_blank(line: &[u8]) -> &[u8] {
    let blank = |byte: &u8| *byte == b' ' || *byte == b'\t';
    let start = line.iter().position(|b| !blank(b)).unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|b| !blank(b))
        .map_or(start, |i| i + 1);
    &line[start..end]
}

/// Returns the label of `line` if the line is `prefix`, a label that is not
/// empty, and `-----`.
fn boundary<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let label = line.strip_prefix(prefix)?.strip_suffix(DASHES)?;
    (!label.is_empty()).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body line of 64 base64 characters.
    const LINE64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8X83xylD3ibci0xjFKMR4bwUtTU/";
    /// The last, shorter body line of the same key.
    const LAST: &str = "YLloVEDxomUS2SHAfFnN3LHVVNYjok0Zm2RiiU7XpDnRAG1Ua8eR8SKbLQ==";

    /// Returns a block of `label` around the two body lines, with `eol` after
    /// each line.
    fn block(label: &str, eol: &str) -> String {
        format!("-----BEGIN {label}-----{eol}{LINE64}{eol}{LAST}{eol}-----END {label}-----{eol}")
    }

    /// Returns the labels and BEGIN line numbers of the blocks of `text`.
    fn labels(text: &[u8]) -> Vec<(String, usize)> {
        split(text)
            .unwrap()
            .iter()
            .map(|b| (b.label_text(), b.line))
            .collect()
    }

    /// Returns the length of the decoded data of each block of `text`.
    fn decoded(text: &[u8]) -> Vec<usize> {
        split(text)
            .unwrap()
            .iter()
            .map(|b| b.decode().unwrap().len())
            .collect()
    }

    #[test]
    fn lf_crlf_and_no_final_eol_split() {
        for text in [
            block("PUBLIC KEY", "\n"),
            block("PUBLIC KEY", "\r\n"),
            block("PUBLIC KEY", "\n").trim_end().to_owned(),
        ] {
            assert_eq!(labels(text.as_bytes()), [("PUBLIC KEY".into(), 1)]);
            assert_eq!(decoded(text.as_bytes()), [91], "{text:?}");
        }
    }

    #[test]
    fn blocks_come_in_text_order() {
        let text = format!(
            "{}{}{}",
            block("PUBLIC KEY", "\n"),
            block("PRIVATE KEY", "\n"),
            block("PUBLIC KEY", "\r\n")
        );
        assert_eq!(
            labels(text.as_bytes()),
            [
                ("PUBLIC KEY".into(), 1),
                ("PRIVATE KEY".into(), 5),
                ("PUBLIC KEY".into(), 9)
            ]
        );
    }

    #[test]
    fn text_outside_the_blocks_is_ignored() {
        let mut text = Vec::new();
        text.extend_from_slice(b"comment\n-----\n-----END PUBLIC KEY-----\n");
        text.extend_from_slice(format!("{LINE64}\n").as_bytes());
        text.extend_from_slice(b"\0\xff bytes\n");
        text.extend_from_slice(block("PUBLIC KEY", "\n").as_bytes());
        text.extend_from_slice(b"----- between -----\n\xff\n");
        text.extend_from_slice(block("PUBLIC KEY", "\n").as_bytes());
        text.extend_from_slice(b"trailer\0");
        assert_eq!(
            labels(&text),
            [("PUBLIC KEY".into(), 6), ("PUBLIC KEY".into(), 12)]
        );
        assert_eq!(decoded(&text), [91, 91]);
    }

    #[test]
    fn spaces_and_tabs_around_a_boundary_are_removed() {
        let text = format!(
            " \t-----BEGIN PUBLIC KEY-----\t \n{LINE64}\n{LAST}\n\t-----END PUBLIC KEY----- \r\n"
        );
        assert_eq!(decoded(text.as_bytes()), [91]);
    }

    #[test]
    fn a_boundary_with_other_text_is_text() {
        for begin in [
            "-----BEGIN PUBLIC KEY----- x",
            "x -----BEGIN PUBLIC KEY-----",
            "----BEGIN PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY----",
            "-----BEGIN-----",
            "-----BEGIN -----",
        ] {
            let text = format!("{begin}\n{LINE64}\n");
            assert!(labels(text.as_bytes()).is_empty(), "{begin}");
        }
    }

    #[test]
    fn a_begin_with_no_end_is_refused() {
        let text = format!("x\n-----BEGIN PUBLIC KEY-----\n{LINE64}\n");
        let err = split(text.as_bytes()).err().unwrap();
        assert_eq!(err, "line 2: the block \"PUBLIC KEY\" has no END line");
    }

    #[test]
    fn an_end_label_that_differs_is_refused() {
        let text = format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\n-----END PRIVATE KEY-----\n");
        let err = split(text.as_bytes()).err().unwrap();
        assert_eq!(
            err,
            "line 3: the END label \"PRIVATE KEY\" is not the label \"PUBLIC KEY\" of the \
             BEGIN line 1"
        );
        let lower = format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\n-----END public key-----\n");
        assert!(split(lower.as_bytes()).is_err());
    }

    #[test]
    fn a_nested_begin_is_refused() {
        let text = format!(
            "-----BEGIN PUBLIC KEY-----\n{LINE64}\n{}",
            block("PUBLIC KEY", "\n")
        );
        let err = split(text.as_bytes()).err().unwrap();
        assert_eq!(
            err,
            "line 3: a BEGIN line is in the block that starts at line 1"
        );
    }

    #[test]
    fn an_end_with_trailing_text_is_a_body_line() {
        // The END line with text after it does not close the block. The text
        // then ends in the block.
        let open = format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\n-----END PUBLIC KEY----- x\n");
        let err = split(open.as_bytes()).err().unwrap();
        assert_eq!(err, "line 1: the block \"PUBLIC KEY\" has no END line");
        // A BEGIN line that comes next is a BEGIN line in the block.
        let nested = format!("{open}{}", block("PUBLIC KEY", "\n"));
        let err = split(nested.as_bytes()).err().unwrap();
        assert_eq!(
            err,
            "line 4: a BEGIN line is in the block that starts at line 1"
        );
    }

    #[test]
    fn cr_line_ends_give_one_line_that_opens_a_block() {
        // The one line starts with `-----BEGIN ` and ends with `-----`, so it
        // is a BEGIN line. No END line follows it.
        let text = block("PUBLIC KEY", "\r");
        let err = split(text.as_bytes()).err().unwrap();
        assert!(
            err.starts_with("line 1: the block \"PUBLIC KEY-----\r"),
            "{err}"
        );
        assert!(err.ends_with("\" has no END line"), "{err}");
    }

    #[test]
    fn empty_text_has_no_block() {
        assert!(labels(b"").is_empty());
        assert!(labels(b"\n\n").is_empty());
    }

    #[test]
    fn a_private_key_block_splits() {
        let text = block("PRIVATE KEY", "\n");
        assert_eq!(labels(text.as_bytes()), [("PRIVATE KEY".into(), 1)]);
    }

    #[test]
    fn decode_refuses_other_bodies() {
        let long = format!("{LINE64}{}", &LAST[..12]);
        let refused = [
            // A 76-column body line.
            format!(
                "-----BEGIN PUBLIC KEY-----\n{long}\n{}\n-----END PUBLIC KEY-----\n",
                &LAST[12..]
            ),
            // A header.
            format!(
                "-----BEGIN PUBLIC KEY-----\nProc-Type: 4,ENCRYPTED\n{LINE64}\n{LAST}\n\
                 -----END PUBLIC KEY-----\n"
            ),
            // A character that is not base64.
            format!(
                "-----BEGIN PUBLIC KEY-----\n{LINE64}\n*{}\n-----END PUBLIC KEY-----\n",
                &LAST[1..]
            ),
            // A blank line in the body.
            format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\n\n{LAST}\n-----END PUBLIC KEY-----\n"),
            // No body.
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n".to_owned(),
        ];
        for text in refused {
            let blocks = split(text.as_bytes()).unwrap();
            assert_eq!(blocks.len(), 1, "{text}");
            assert!(blocks[0].decode().is_err(), "{text}");
        }
    }

    /// Returns the message of the refusal of the one block of `text`.
    fn decode_refusal(text: &str) -> String {
        let blocks = split(text.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 1, "{text:?}");
        blocks[0].decode().unwrap_err()
    }

    #[test]
    fn a_blank_line_before_the_end_line_is_refused() {
        let text =
            format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\n{LAST}\n\n-----END PUBLIC KEY-----\n");
        assert_eq!(decode_refusal(&text), "line 4 is empty");
        let crlf = text.replace('\n', "\r\n");
        assert_eq!(decode_refusal(&crlf), "line 4 is empty");
    }

    #[test]
    fn a_cr_in_a_body_line_is_refused() {
        let text =
            format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\r{LAST}\n-----END PUBLIC KEY-----\n");
        assert_eq!(decode_refusal(&text), "line 2 holds a CR");
    }

    #[test]
    fn two_crs_at_the_end_of_a_body_line_are_refused() {
        let text =
            format!("-----BEGIN PUBLIC KEY-----\n{LINE64}\r\r\n{LAST}\n-----END PUBLIC KEY-----\n");
        assert_eq!(decode_refusal(&text), "line 2 holds a CR");
    }
}
