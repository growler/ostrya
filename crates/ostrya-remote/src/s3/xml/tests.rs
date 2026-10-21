use super::*;

/// The elements that `walk` reports, as `path=text` lines with the names
/// joined by `/`.
fn ends(body: &[u8]) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    walk(body, &mut |path, text| {
        found.push(format!("{}={}", path.join("/"), text.trim()));
        Ok(())
    })?;
    Ok(found)
}

fn refusal(body: &[u8]) -> String {
    match ends(body) {
        Ok(found) => panic!("{} read as {found:?}", String::from_utf8_lossy(body)),
        Err(message) => message,
    }
}

/// The `ListObjectsV2` example of the AWS API reference, with the encoding
/// type `url` and a continuation token.
const LIST_OBJECTS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>bucket</Name>
    <Prefix>repo%2Fobjects%2F</Prefix>
    <KeyCount>2</KeyCount>
    <MaxKeys>2</MaxKeys>
    <EncodingType>url</EncodingType>
    <IsTruncated>true</IsTruncated>
    <ContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</ContinuationToken>
    <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwN=</NextContinuationToken>
    <Contents>
        <Key>repo/objects/ab/cd.commit</Key>
        <LastModified>2009-10-12T17:50:30.000Z</LastModified>
        <ETag>&quot;fba9dede5f27731c9771645a39863328&quot;</ETag>
        <Size>434234</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
    <Contents>
        <Key>repo/objects/ab/a%2Bb</Key>
        <Size>18446744073709551615</Size>
    </Contents>
</ListBucketResult>"#;

/// The `ListObjectsV2` example of the AWS API reference with a delimiter.
const LIST_DELIMITED: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example-bucket</Name>
  <Prefix></Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>sample.jpg</Key>
    <LastModified>2011-02-26T01:56:20.000Z</LastModified>
    <ETag>"bf1d737a4d46a19f3bced6905cc8b902"</ETag>
    <Size>142863</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes>
    <Prefix>photos/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;

/// The `ListMultipartUploads` example of the AWS API reference.
const LIST_UPLOADS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>bucket</Bucket>
  <KeyMarker></KeyMarker>
  <UploadIdMarker></UploadIdMarker>
  <NextKeyMarker>my-movie.m2ts</NextKeyMarker>
  <NextUploadIdMarker>YW55IGlkZWEgd2h5IGVsdmluZydzIHVwbG9hZCBmYWlsZWQ</NextUploadIdMarker>
  <MaxUploads>3</MaxUploads>
  <IsTruncated>true</IsTruncated>
  <Upload>
    <Key>my-divisor</Key>
    <UploadId>XMgbGlrZSBlbHZpbmcncyBub3QgaGF2aW5nIG11Y2ggbHVjaw</UploadId>
    <Initiator>
      <ID>arn:aws:iam::111122223333:user/user1-11111a31-17b5-4fb7-9df5-b111111f13de</ID>
      <DisplayName>user1-11111a31-17b5-4fb7-9df5-b111111f13de</DisplayName>
    </Initiator>
    <Owner>
      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
      <DisplayName>OwnerDisplayName</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2010-11-10T20:48:33.000Z</Initiated>
  </Upload>
  <Upload>
    <Key>my-movie.m2ts</Key>
    <UploadId>VXBsb2FkIElEIGZvciBlbHZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2010-11-10T20:48:33.000Z</Initiated>
  </Upload>
</ListMultipartUploadsResult>"#;

/// The `InitiateMultipartUploadResult` example of the AWS API reference.
const INITIATE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>example-bucket</Bucket>
  <Key>example-object</Key>
  <UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>
</InitiateMultipartUploadResult>"#;

/// The `CompleteMultipartUploadResult` example of the AWS API reference.
const COMPLETE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://Example-Bucket.s3.region.amazonaws.com/Example-Object</Location>
  <Bucket>Example-Bucket</Bucket>
  <Key>Example-Object</Key>
  <ETag>"3858f62230ac3c915f300c664312c11f-9"</ETag>
</CompleteMultipartUploadResult>"#;

/// The `Error` example of the AWS API reference, with the `Region` element
/// of a request signed for another region.
const ERROR: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AuthorizationHeaderMalformed</Code>
  <Message>The authorization header is malformed; the region 'us-east-1' is wrong; expecting 'eu-central-1'</Message>
  <Region>eu-central-1</Region>
  <RequestId>4442587FB7D0A2F9</RequestId>
</Error>"#;

#[test]
fn a_listing_gives_its_keys_sizes_and_token() {
    let Doc::Result(page) = list_objects(LIST_OBJECTS).unwrap() else {
        panic!("a listing");
    };
    assert_eq!(
        page,
        ObjectsPage {
            encoded: true,
            truncated: true,
            token: Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwN=".into()),
            contents: vec![
                ("repo/objects/ab/cd.commit".into(), 434_234),
                ("repo/objects/ab/a%2Bb".into(), u64::MAX),
            ],
            prefixes: Vec::new(),
        }
    );
}

#[test]
fn a_listing_with_a_delimiter_gives_its_common_prefixes() {
    let Doc::Result(page) = list_objects(LIST_DELIMITED).unwrap() else {
        panic!("a listing");
    };
    assert!(!page.encoded);
    assert!(!page.truncated);
    assert_eq!(page.token, None);
    assert_eq!(page.contents, [("sample.jpg".to_owned(), 142_863)]);
    assert_eq!(page.prefixes, ["photos/"]);
}

#[test]
fn a_listing_of_uploads_gives_each_upload_and_the_markers() {
    let Doc::Result(page) = list_uploads(LIST_UPLOADS).unwrap() else {
        panic!("a listing");
    };
    assert!(page.truncated);
    assert_eq!(page.next_key_marker.as_deref(), Some("my-movie.m2ts"));
    assert_eq!(
        page.next_upload_id_marker.as_deref(),
        Some("YW55IGlkZWEgd2h5IGVsdmluZydzIHVwbG9hZCBmYWlsZWQ")
    );
    assert_eq!(page.uploads.len(), 2);
    assert_eq!(page.uploads[0].0, "my-divisor");
    assert_eq!(
        page.uploads[1],
        (
            "my-movie.m2ts".to_owned(),
            "VXBsb2FkIElEIGZvciBlbHZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA".to_owned(),
            "2010-11-10T20:48:33.000Z".to_owned()
        )
    );
}

#[test]
fn the_results_of_a_multipart_upload_read_as_elements() {
    let found = ends(INITIATE).unwrap();
    assert!(
        found.contains(
            &"InitiateMultipartUploadResult/UploadId=\
          VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA"
                .to_owned()
        )
    );
    let found = ends(COMPLETE).unwrap();
    assert!(
        found.contains(
            &"CompleteMultipartUploadResult/ETag=\"3858f62230ac3c915f300c664312c11f-9\"".to_owned()
        ),
        "{found:?}"
    );
}

#[test]
fn an_error_document_gives_its_code_message_and_region() {
    let doc = error(ERROR).unwrap();
    assert_eq!(doc.code.as_deref(), Some("AuthorizationHeaderMalformed"));
    assert!(doc.message.unwrap().contains("expecting 'eu-central-1'"));
    assert_eq!(doc.region.as_deref(), Some("eu-central-1"));
    assert_eq!(error(LIST_OBJECTS), None);
    assert_eq!(error(b"not xml"), None);
    assert_eq!(error(b""), None);
}

#[test]
fn an_error_root_in_place_of_a_listing_is_an_error_document() {
    let body = b"<Error><Code>InternalError</Code><Message>retry</Message></Error>";
    let Doc::Error(doc) = list_objects(body).unwrap() else {
        panic!("an error document");
    };
    assert_eq!(doc.code.as_deref(), Some("InternalError"));
    let Doc::Error(doc) = list_uploads(body).unwrap() else {
        panic!("an error document");
    };
    assert_eq!(doc.message.as_deref(), Some("retry"));
}

#[test]
fn another_root_is_refused() {
    let message = list_objects(LIST_UPLOADS).unwrap_err();
    assert!(message.contains("ListMultipartUploadsResult"), "{message}");
    let message = list_uploads(LIST_OBJECTS).unwrap_err();
    assert!(message.contains("root element"), "{message}");
}

#[test]
fn a_listing_with_a_bad_value_is_refused() {
    for (body, part) in [
        (
            &b"<ListBucketResult><IsTruncated>yes</IsTruncated></ListBucketResult>"[..],
            "IsTruncated",
        ),
        (
            b"<ListBucketResult><Contents><Key>k</Key><Size>-1</Size></Contents></ListBucketResult>",
            "Size",
        ),
        (
            b"<ListBucketResult><Contents><Key>k</Key><Size>18446744073709551616</Size></Contents></ListBucketResult>",
            "Size",
        ),
        (
            b"<ListBucketResult><Contents><Key>k</Key></Contents></ListBucketResult>",
            "no Key or no Size",
        ),
        (
            b"<ListMultipartUploadsResult><Upload><Key>k</Key></Upload></ListMultipartUploadsResult>",
            "no Key or no UploadId",
        ),
    ] {
        let message = if body.starts_with(b"<ListBucket") {
            list_objects(body).unwrap_err()
        } else {
            list_uploads(body).unwrap_err()
        };
        assert!(message.contains(part), "{message}");
    }
}

#[test]
fn the_accepted_constructs_read() {
    let body = "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
        <!-- a comment -->\n\
        <?pi data?>\n\
        <Root xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\" a='1'>\
          <Empty/><Empty a=\"x\" />\
          <Text>a&amp;b&lt;c&gt;d&quot;e&apos;f&#65;&#x42;&#x1F600;</Text>\
          <Data><![CDATA[<raw>&amp;]]></Data>\
          <Unknown><Deep>x</Deep></Unknown>\
        </Root>\n";
    let found = ends(body.as_bytes()).unwrap();
    assert_eq!(
        found,
        [
            "Root/Empty=",
            "Root/Empty=",
            "Root/Text=a&b<c>d\"e'fAB\u{1F600}",
            "Root/Data=<raw>&amp;",
            "Root/Unknown/Deep=x",
            "Root/Unknown=",
            "Root=",
        ]
    );
}

#[test]
fn each_refused_construct_is_refused() {
    let cases: [(&[u8], &str); 16] = [
        (
            b"<?xml version=\"1.0\"?><!DOCTYPE Error [<!ENTITY e \"x\">]><Error><Code>&e;</Code></Error>",
            "DOCTYPE",
        ),
        (b"<Error><Code>&foo;</Code></Error>", "predefined"),
        (b"<Error><Code>&#0;</Code></Error>", "XML 1.0"),
        (b"<Error><Code>&#1;</Code></Error>", "XML 1.0"),
        (b"<Error><Code>&#xD800;</Code></Error>", "XML 1.0"),
        (b"<Error><Code>&#x110000;</Code></Error>", "XML 1.0"),
        (b"<Error><Code>&#xFFFE;</Code></Error>", "XML 1.0"),
        (b"<Error><Code>a & b</Code></Error>", "byte"),
        (b"<Error><Code>x</Message></Error>", "byte"),
        (b"<Error><Code>x</Code>", "ends inside the element Error"),
        (b"<Error/><Error/>", "second root"),
        (b"<Error></Error>text", "outside the root"),
        (
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><Error/>",
            "encoding other than UTF-8",
        ),
        (b"<Error><Code>caf\xe9</Code></Error>", "not UTF-8"),
        (b"", "no element"),
        (b"  <!-- only a comment -->  ", "no element"),
    ];
    for (body, part) in cases {
        let message = refusal(body);
        assert!(
            message.contains(part),
            "{}: {message}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_body_over_the_limit_is_refused() {
    let mut body = b"<Error><Message>".to_vec();
    let close = b"</Message></Error>";
    body.resize(MAX_BODY - close.len(), b'x');
    body.extend_from_slice(close);
    assert_eq!(body.len(), MAX_BODY);
    assert!(ends(&body).is_ok());
    body.insert(16, b'x');
    assert!(refusal(&body).contains("limit"));
}

#[test]
fn an_element_deeper_than_the_limit_is_refused() {
    let nested = |depth: usize| {
        let mut body = String::new();
        for _ in 0..depth {
            body.push_str("<a>");
        }
        for _ in 0..depth {
            body.push_str("</a>");
        }
        body
    };
    assert!(ends(nested(MAX_DEPTH).as_bytes()).is_ok());
    assert!(refusal(nested(MAX_DEPTH + 1).as_bytes()).contains("deeper"));
    // A deep body is refused at the limit, not at its end.
    let deep = "<a>".repeat(1_000_000);
    assert!(refusal(deep.as_bytes()).contains("deeper"));
}

#[test]
fn a_message_holds_no_text_of_the_body() {
    let message = refusal(b"<Error><Code>SECRET&foo;</Code></Error>");
    assert!(!message.contains("SECRET"), "{message}");
    assert!(!message.contains("foo"), "{message}");
    // A crafted end tag with a terminal escape and a bell. The refusal of the
    // parser names the kind of error and the byte offset alone.
    let bodies: [&[u8]; 4] = [
        b"<ListBucketResult><Contents><Key>x</K\x1b[2J\x07SECRET></Contents></ListBucketResult>",
        b"<Error><Code>x</Code></Error\x1b]0;SECRET\x07>",
        b"<Error><Code\x1b[2J\x07SECRET",
        b"<?xml version=\"1.0\" encoding=\"\x1b[2JSECRET\x07?><Error/>",
    ];
    for body in bodies {
        let message = refusal(body);
        assert!(!message.contains("SECRET"), "{message:?}");
        assert!(!message.contains('\x1b'), "{message:?}");
        assert!(!message.contains('\x07'), "{message:?}");
        assert!(message.contains("at byte"), "{message:?}");
    }
}

#[test]
fn shown_text_replaces_format_characters() {
    assert_eq!(
        shown("a\u{202e}b\u{2066}c\u{200f}d"),
        "a\u{fffd}b\u{fffd}c\u{fffd}d"
    );
    assert_eq!(
        shown("\u{feff}\u{200b}\u{ad}x"),
        "\u{fffd}\u{fffd}\u{fffd}x"
    );
    assert_eq!(shown("é\u{1f600}"), "é\u{1f600}");
}

#[test]
fn shown_text_replaces_control_characters_and_is_capped() {
    assert_eq!(shown("a\u{1b}[31mb\n"), "a\u{fffd}[31mb\u{fffd}");
    let long = "é".repeat(400);
    let cut = shown(&long);
    assert!(cut.len() <= MAX_SHOWN);
    assert_eq!(cut.len(), 512);
    assert_eq!(shown(&"x".repeat(600)).len(), 512);
}
