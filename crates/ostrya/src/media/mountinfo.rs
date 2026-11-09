//! The reader of the mount table of the process.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::error::Result;

/// One mount of the mount table.
#[derive(Debug)]
pub(super) struct Mount<'a> {
    /// The mount point, as the table writes it, with its octal escapes.
    pub(super) escaped_point: &'a [u8],
    /// The file system type.
    pub(super) fs_type: Vec<u8>,
}

impl Mount<'_> {
    /// Returns the mount point, with its octal escapes decoded.
    pub(super) fn point(&self) -> PathBuf {
        PathBuf::from(OsStr::from_bytes(&unescape(self.escaped_point)))
    }
}

/// Reads the mount table of the process, `/proc/self/mountinfo`.
///
/// The call refuses a table larger than 16 MiB. On a platform other than
/// Linux, the table is empty.
///
/// # Errors
///
/// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the table is
///   larger than 16 MiB.
/// - [`Error::Io`](crate::Error::Io) if the read fails.
#[cfg(target_os = "linux")]
pub(super) async fn read_table() -> Result<Vec<u8>> {
    use std::io::Read;

    /// The path of the mount table.
    const MOUNTINFO: &str = "/proc/self/mountinfo";
    /// The largest mount table that the call reads, in bytes.
    const MAX_TABLE: u64 = 16 << 20;

    ostrya_rt::unblock(|| {
        let mut table = Vec::new();
        std::fs::File::open(MOUNTINFO)?
            .take(MAX_TABLE + 1)
            .read_to_end(&mut table)?;
        if table.len() as u64 > MAX_TABLE {
            return Err(crate::Error::InvalidFormat(format!(
                "{MOUNTINFO} is larger than 16 MiB"
            )));
        }
        Ok(table)
    })
    .await
}

/// Reads the mount table of the process. On a platform other than Linux,
/// the table is empty.
#[cfg(not(target_os = "linux"))]
pub(super) async fn read_table() -> Result<Vec<u8>> {
    Ok(Vec::new())
}

/// Returns the mounts of the mount table `table`, in table order.
///
/// Each line holds the mount id, the parent id, the device, the root, the
/// mount point, the mount options, zero or more optional fields, a `-`, the
/// file system type, the source, and the superblock options. The call skips
/// a line of another form, and a line whose mount point is not an absolute
/// path.
///
/// A mount hides each earlier mount at the same mount point, so the call
/// keeps the last line of each mount point alone. The kernel writes one
/// escaped form for each mount point, so the call compares the escaped
/// fields.
pub(super) fn parse(table: &[u8]) -> Vec<Mount<'_>> {
    let mut points = HashSet::new();
    let mut mounts: Vec<Mount<'_>> = table
        .split(|b| *b == b'\n')
        .rev()
        .filter_map(parse_line)
        .filter(|mount| points.insert(mount.escaped_point))
        .collect();
    mounts.reverse();
    mounts
}

/// Reads one line of the mount table.
fn parse_line(line: &[u8]) -> Option<Mount<'_>> {
    let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
    let dash = fields.iter().skip(6).position(|f| *f == b"-")? + 6;
    let after = fields.get(dash + 1..dash + 4)?;
    if !fields[4].starts_with(b"/") {
        return None;
    }
    Some(Mount {
        escaped_point: fields[4],
        fs_type: unescape(after[0]),
    })
}

/// Decodes the octal escapes `\ooo` of a field. The kernel writes a space, a
/// tab, a newline, and a backslash in this form.
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        let octal = field
            .get(i + 1..i + 4)
            .filter(|d| field[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        match octal {
            Some(d) => {
                let value = d.iter().fold(0u32, |n, c| n * 8 + u32::from(c - b'0'));
                out.push(u8::try_from(value).unwrap_or(b'?'));
                i += 4;
            }
            None => {
                out.push(field[i]);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the mount point and the type of each mount of `table`.
    fn mounts(table: &[u8]) -> Vec<(PathBuf, String)> {
        parse(table)
            .iter()
            .map(|m| (m.point(), String::from_utf8(m.fs_type.clone()).unwrap()))
            .collect()
    }

    fn mount(point: &str, fs_type: &str) -> (PathBuf, String) {
        (PathBuf::from(point), fs_type.to_owned())
    }

    /// Each line gives its mount point and its file system type, with zero
    /// or more optional fields. The octal escapes of a space, a tab, a
    /// newline, and a backslash decode. A malformed line gives no mount.
    #[test]
    fn a_table_gives_the_mount_point_and_the_type_of_each_line() {
        let table = b"22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
            36 22 0:50 / /run/media/a\\040b\\011c rw shared:1 - vfat /dev/sdb1 rw\n\
            garbage\n\
            1 2 3 4 5 6 7\n\
            37 22 0:51 / relative rw - tmpfs tmpfs rw\n\
            38 22 0:52 / /mnt/x\\012y\\134z rw shared:2 master:3 - fuse.sshfs h:/ rw\n\
            39 22 0:53 / /mnt/short rw - tmpfs\n";
        assert_eq!(
            mounts(table),
            vec![
                mount("/", "ext4"),
                mount("/run/media/a b\tc", "vfat"),
                mount("/mnt/x\ny\\z", "fuse.sshfs"),
            ]
        );
        assert!(parse(b"").is_empty());
        assert_eq!(unescape(b"a\\134b\\011c\\9\\04"), b"a\\b\tc\\9\\04");
    }

    /// The last line of a mount point hides each earlier line of that mount
    /// point. The order of the mounts is the order of the lines that count.
    #[test]
    fn the_last_line_of_a_mount_point_counts() {
        let table = b"36 22 0:50 / /mnt/a rw - vfat /dev/sdb1 rw\n\
            37 22 0:51 / /mnt/b rw - ext4 /dev/sdc1 rw\n\
            38 36 0:52 / /mnt/a rw - nfs h:/ rw\n\
            39 22 0:53 / /mnt/c rw - exfat /dev/sdd1 rw\n";
        assert_eq!(
            mounts(table),
            vec![
                mount("/mnt/b", "ext4"),
                mount("/mnt/a", "nfs"),
                mount("/mnt/c", "exfat"),
            ]
        );
    }
}
