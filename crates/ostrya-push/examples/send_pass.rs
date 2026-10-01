//! Time the send pass of a tree push over a scripted server.
//!
//! Usage: `send_pass COUNT SIZE raw|deflate [DIR]`
//!
//! The program writes COUNT files of SIZE bytes each under DIR (a new
//! directory in the temporary directory by default). SIZE must be at least 8
//! when COUNT is more than 1. The program scans the files into a tree
//! model, and sends every content object to a server that needs each object.
//! The bytes of the session go to a sink, so the program holds no object.
//!
//! The program writes `send pass: start` to stderr just before the send, so a
//! trace of the process can be cut at that write. After the send it prints the
//! time for each file, and on Linux the peak resident set size (`VmHWM`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use futures_lite::io::{Cursor, sink};
use ostrya_core::ObjectType;
use ostrya_push::proto::{
    FrameWriter, HelloReply, MIN_FRAME_LIMIT, Message, ObjectsReply, RefState,
};
use ostrya_push::tree::{ScanOptions, TreeModel};
use ostrya_push::{Compression, Encoding, PushSession, SessionOptions};

/// The size of the buffer the files are written with.
const WRITE_CHUNK: usize = 1024 * 1024;

/// The replies of a server that lists `raw` and `deflate`, needs each
/// object, and takes one object stream.
async fn scripted_replies() -> io::Result<Vec<u8>> {
    let msgs = [
        Message::HelloReply(HelloReply {
            version: 1,
            mode: "archive".into(),
            collection_id: None,
            max_frame: MIN_FRAME_LIMIT,
            max_have: 16_384,
            encodings: vec![Encoding::Raw, Encoding::Deflate],
            parallel_uploads: 1,
            refs: vec![RefState {
                name: "main".into(),
                commit: None,
            }],
        }),
        Message::ObjectsReply(ObjectsReply {
            objects: 0,
            payload_bytes: 0,
        }),
    ];
    let mut w = FrameWriter::new(Vec::new());
    for msg in &msgs {
        w.write_message(msg).await.map_err(io::Error::other)?;
    }
    Ok(w.into_inner())
}

/// Write `count` files of `size` bytes under `dir`. The first 8 bytes of each
/// file hold its index, so no two files share a content object.
fn write_files(dir: &Path, count: u64, size: u64) -> io::Result<()> {
    let mut chunk = vec![0u8; WRITE_CHUNK];
    for (i, byte) in chunk.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    for index in 0..count {
        let mut file = io::BufWriter::new(fs::File::create(dir.join(format!("f{index:07}")))?);
        let mut left = size;
        let tag = index.to_le_bytes();
        let head = left.min(tag.len() as u64) as usize;
        file.write_all(&tag[..head])?;
        left -= head as u64;
        while left > 0 {
            let n = left.min(WRITE_CHUNK as u64) as usize;
            file.write_all(&chunk[..n])?;
            left -= n as u64;
        }
        file.flush()?;
    }
    Ok(())
}

/// The peak resident set size of the process, as `/proc/self/status` gives it.
fn peak_rss() -> Option<String> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    Some(line["VmHWM:".len()..].trim().to_owned())
}

fn usage() -> ExitCode {
    eprintln!("usage: send_pass COUNT SIZE raw|deflate [DIR]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(count), Some(size), Some(encoding)) = (
        args.first().and_then(|a| a.parse::<u64>().ok()),
        args.get(1).and_then(|a| a.parse::<u64>().ok()),
        args.get(2),
    ) else {
        return usage();
    };
    if count > 1 && size < 8 {
        return usage();
    }
    let compression = match encoding.as_str() {
        "raw" => Compression::None,
        "deflate" => Compression::Deflate { level: 6 },
        _ => return usage(),
    };
    let (dir, remove) = match args.get(3) {
        Some(dir) => (PathBuf::from(dir), false),
        None => (
            std::env::temp_dir().join(format!("ostrya-send-pass-{}", std::process::id())),
            true,
        ),
    };
    let result = run(&dir, count, size, compression);
    if remove {
        let _ = fs::remove_dir_all(&dir);
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("send_pass: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(dir: &Path, count: u64, size: u64, compression: Compression) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    write_files(dir, count, size)?;
    ostrya_rt::block_on(async {
        let model = TreeModel::scan(dir, ScanOptions::default())
            .await
            .map_err(io::Error::other)?;
        let names: Vec<_> = model
            .object_names()
            .into_iter()
            .filter(|name| name.ty == ObjectType::File)
            .collect();
        let session = PushSession::over_stream(
            Cursor::new(scripted_replies().await?),
            sink(),
            &["main".to_string()],
            SessionOptions::default(),
        )
        .await
        .map_err(io::Error::other)?;
        eprintln!("send pass: start");
        let start = Instant::now();
        session
            .send(&model, &names, &[], compression)
            .await
            .map_err(io::Error::other)?;
        let elapsed = start.elapsed();
        let files = names.len().max(1) as f64;
        println!(
            "{} files of {size} bytes: {:.1} us per file, {:.3} s in all",
            names.len(),
            elapsed.as_secs_f64() * 1e6 / files,
            elapsed.as_secs_f64()
        );
        if let Some(peak) = peak_rss() {
            println!("VmHWM: {peak}");
        }
        Ok(())
    })
}
