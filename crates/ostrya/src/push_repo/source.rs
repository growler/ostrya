//! The objects of a local repository, as a push session reads them.

use futures_lite::io::Cursor;
use ostrya_core::{Checksum, FileHeader, ObjectName, ObjectType, Value, loose_path};
use ostrya_rt::File as RtFile;

use crate::error::{Error, Result};
use crate::file::FileKind;
use crate::object;
use crate::pull::DetachedMetadataFilter;
use crate::push::{BoxFuture, Encoding, ObjectData, ObjectSource};
use crate::repo::Repo;

/// The [`ObjectSource`] over a local repository.
///
/// A metadata object is [`ObjectData::Encoded`] in `raw`, read whole: the
/// format caps its size. The session can send a file object of an `archive`
/// repository in `deflate`. Such an object is [`ObjectData::Encoded`] in
/// `deflate`: a stream over the stored `.filez` file, byte for byte. Every
/// other file object is [`ObjectData::Content`], with the file header and a
/// stream over its payload, and the session encodes it. No file content is
/// held in memory, and the source keeps no reader between calls.
///
/// The detached metadata of a commit comes with the filter applied.
pub(crate) struct RepoSource {
    repo: Repo,
    filter: DetachedMetadataFilter,
}

impl RepoSource {
    /// The source over `repo`, whose detached metadata passes `filter`.
    pub(crate) fn new(repo: Repo, filter: DetachedMetadataFilter) -> RepoSource {
        RepoSource { repo, filter }
    }

    async fn load(&self, name: &ObjectName, encoding: Encoding) -> Result<ObjectData> {
        if name.ty != ObjectType::File {
            let bytes = self.repo.load_object_bytes(name.ty, &name.checksum).await?;
            return Ok(ObjectData::Encoded {
                encoding: Encoding::Raw,
                reader: Box::new(Cursor::new(bytes)),
            });
        }
        if encoding == Encoding::Deflate && self.repo.mode().is_archive() {
            return self.stored_filez(&name.checksum).await;
        }
        let (file, reader) = self.repo.open_file(&name.checksum).await?;
        let (size, payload, symlink_target) = match file.kind {
            FileKind::Regular { size } => (size, Some(Box::new(reader) as _), String::new()),
            FileKind::Symlink { target } => (0, None, target),
        };
        Ok(ObjectData::Content {
            header: FileHeader {
                uid: file.uid,
                gid: file.gid,
                mode: file.mode,
                symlink_target,
                xattrs: file.xattrs,
            },
            size,
            payload,
        })
    }

    /// A stream over the stored `.filez` file of the file object `checksum`.
    async fn stored_filez(&self, checksum: &Checksum) -> Result<ObjectData> {
        let path = loose_path(checksum, ObjectType::File, self.repo.mode());
        let repo = self.repo.clone();
        let opened =
            ostrya_rt::unblock(move || object::open_content_file(repo.objects_fd(), &path, 0))
                .await;
        let file = match opened {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ObjectNotFound {
                    checksum: *checksum,
                    ty: ObjectType::File,
                });
            }
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(ObjectData::Encoded {
            encoding: Encoding::Deflate,
            reader: Box::new(RtFile::from(file)),
        })
    }

    /// The detached metadata of `commit` that the filter allows, or `None`
    /// when the commit has none or the filter allows no property.
    async fn detached(&self, commit: &Checksum) -> Result<Option<Value>> {
        let bytes = match self
            .repo
            .load_object_bytes(ObjectType::CommitMeta, commit)
            .await
        {
            Ok(bytes) => bytes,
            Err(Error::ObjectNotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        match crate::summary::parse_signature_dict(&bytes)? {
            Some(dict) => self.filter.apply_value(commit, dict),
            None => Ok(None),
        }
    }
}

fn source_error(e: Error) -> crate::push::Error {
    crate::push::Error::Source(Box::new(e))
}

impl ObjectSource for RepoSource {
    fn objects<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, crate::push::Result<Vec<ObjectName>>> {
        Box::pin(async move {
            let names = self
                .repo
                .traverse_commit(commit, 0)
                .await
                .map_err(source_error)?;
            Ok(names.into_iter().collect())
        })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, crate::push::Result<ObjectData>> {
        Box::pin(async move { self.load(name, encoding).await.map_err(source_error) })
    }

    fn detached_metadata<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, crate::push::Result<Option<Value>>> {
        Box::pin(async move { self.detached(commit).await.map_err(source_error) })
    }
}

/// The source moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RepoSource>();
    assert_send_sync::<DetachedMetadataFilter>();
};

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use futures_lite::AsyncReadExt;
    use ostrya_core::{DictBuilder, RepoMode};

    use super::super::test_repo::{Scratch, commit_tree};
    use super::*;

    /// A repository of `mode` with one commit on `main`, as the scratch
    /// directory, the repository, and the commit.
    async fn fixture(label: &str, mode: RepoMode) -> (Scratch, Repo, Checksum) {
        let scratch = Scratch::new(label);
        let repo = scratch.create(mode).await;
        let commit = commit_tree(&repo, &scratch, "main", None, b"file content\n").await;
        (scratch, repo, commit)
    }

    /// The file objects of `commit`, as the regular file and the symlink.
    async fn file_objects(repo: &Repo, commit: &Checksum) -> (ObjectName, ObjectName) {
        let mut regular = None;
        let mut symlink = None;
        for name in repo.traverse_commit(commit, 0).await.unwrap() {
            if name.ty != ObjectType::File {
                continue;
            }
            match repo.load_file(&name.checksum).await.unwrap().kind {
                FileKind::Regular { .. } => regular = Some(name),
                FileKind::Symlink { .. } => symlink = Some(name),
            }
        }
        (regular.unwrap(), symlink.unwrap())
    }

    fn stored(scratch: &Scratch, repo: &Repo, name: &ObjectName) -> Vec<u8> {
        let path = loose_path(&name.checksum, name.ty, repo.mode());
        std::fs::read(scratch.path().join("repo/objects").join(path)).unwrap()
    }

    async fn read_all(mut reader: Box<dyn crate::push::ObjectReader>) -> Vec<u8> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        out
    }

    fn source(repo: &Repo) -> RepoSource {
        RepoSource::new(repo.clone(), DetachedMetadataFilter::default())
    }

    fn keys(dict: &Value) -> Vec<&str> {
        dict.as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap())
            .collect()
    }

    #[test]
    fn the_objects_are_the_commit_and_its_tree() {
        ostrya_rt::block_on(async {
            let (scratch, repo, first) = fixture("objects", RepoMode::Archive).await;
            let commit = commit_tree(&repo, &scratch, "main", Some(first), b"other\n").await;
            let (loaded, _) = repo.load_commit(&commit).await.unwrap();
            assert_eq!(loaded.parent, Some(first));
            let tree = repo.load_dirtree(&loaded.root_dirtree).await.unwrap();
            assert!(tree.dirs.is_empty());
            let names: Vec<&str> = tree.files.iter().map(|(name, _)| name.as_str()).collect();
            assert_eq!(names, ["file", "link"]);

            let name = |checksum, ty| ObjectName { checksum, ty };
            let mut expected = HashSet::from([
                name(commit, ObjectType::Commit),
                name(loaded.root_dirtree, ObjectType::DirTree),
                name(loaded.root_dirmeta, ObjectType::DirMeta),
            ]);
            expected.extend(tree.files.iter().map(|(_, c)| name(*c, ObjectType::File)));
            assert_eq!(expected.len(), 5);

            let got = source(&repo).objects(&commit).await.unwrap();
            assert_eq!(got.len(), 5, "{got:?}");
            // The parent commit is no object of the commit.
            assert_eq!(got.into_iter().collect::<HashSet<_>>(), expected);
        });
    }

    #[test]
    fn a_metadata_object_is_its_stored_bytes_in_raw() {
        ostrya_rt::block_on(async {
            let (scratch, repo, commit) = fixture("metadata", RepoMode::Archive).await;
            let src = source(&repo);
            let names = repo.traverse_commit(&commit, 0).await.unwrap();
            let meta: Vec<_> = names.iter().filter(|n| n.ty != ObjectType::File).collect();
            assert_eq!(meta.len(), 3, "a commit, a dirtree, and a dirmeta");
            for name in meta {
                // The encoding the session asks for does not change a
                // metadata object.
                for encoding in [Encoding::Raw, Encoding::Deflate] {
                    match src.open(name, encoding).await.unwrap() {
                        ObjectData::Encoded {
                            encoding: Encoding::Raw,
                            reader,
                        } => assert_eq!(read_all(reader).await, stored(&scratch, &repo, name)),
                        other => panic!("{name:?}: {other:?}"),
                    }
                }
            }
        });
    }

    #[test]
    fn an_archive_file_object_in_deflate_is_the_stored_filez() {
        ostrya_rt::block_on(async {
            let (scratch, repo, commit) = fixture("filez", RepoMode::Archive).await;
            let src = source(&repo);
            let (regular, symlink) = file_objects(&repo, &commit).await;
            for name in [regular, symlink] {
                match src.open(&name, Encoding::Deflate).await.unwrap() {
                    ObjectData::Encoded {
                        encoding: Encoding::Deflate,
                        reader,
                    } => assert_eq!(read_all(reader).await, stored(&scratch, &repo, &name)),
                    other => panic!("{name:?}: {other:?}"),
                }
            }
        });
    }

    #[test]
    fn a_file_object_in_raw_is_content() {
        ostrya_rt::block_on(async {
            let (_scratch, repo, commit) = fixture("archive-raw", RepoMode::Archive).await;
            let (regular, _) = file_objects(&repo, &commit).await;
            let loaded = repo.load_file(&regular.checksum).await.unwrap();
            match source(&repo).open(&regular, Encoding::Raw).await.unwrap() {
                ObjectData::Content {
                    header,
                    size,
                    payload: Some(payload),
                } => {
                    assert_eq!(header, loaded.header());
                    assert_eq!(size, 13);
                    assert_eq!(read_all(payload).await, b"file content\n");
                }
                other => panic!("{other:?}"),
            }
        });
    }

    #[test]
    fn a_bare_file_object_is_content_in_every_encoding() {
        ostrya_rt::block_on(async {
            let (_scratch, repo, commit) = fixture("bare-user", RepoMode::BareUser).await;
            let (regular, _) = file_objects(&repo, &commit).await;
            let loaded = repo.load_file(&regular.checksum).await.unwrap();
            for encoding in [Encoding::Raw, Encoding::Deflate] {
                match source(&repo).open(&regular, encoding).await.unwrap() {
                    ObjectData::Content {
                        header,
                        size,
                        payload: Some(payload),
                    } => {
                        assert_eq!(header, loaded.header());
                        assert_eq!(size, 13);
                        assert_eq!(read_all(payload).await, b"file content\n");
                    }
                    other => panic!("{encoding:?}: {other:?}"),
                }
            }
        });
    }

    #[test]
    fn a_symlink_is_content_with_no_payload() {
        ostrya_rt::block_on(async {
            for (label, mode, encoding) in [
                ("symlink-bare-user", RepoMode::BareUser, Encoding::Deflate),
                ("symlink-archive", RepoMode::Archive, Encoding::Raw),
            ] {
                let (_scratch, repo, commit) = fixture(label, mode).await;
                let (_, symlink) = file_objects(&repo, &commit).await;
                match source(&repo).open(&symlink, encoding).await.unwrap() {
                    ObjectData::Content {
                        header,
                        size: 0,
                        payload: None,
                    } => assert_eq!(header.symlink_target, "file"),
                    other => panic!("{label}: {other:?}"),
                }
            }
        });
    }

    #[test]
    fn a_missing_object_is_object_not_found() {
        ostrya_rt::block_on(async {
            for (label, mode) in [
                ("missing-archive", RepoMode::Archive),
                ("missing-bare-user", RepoMode::BareUser),
                ("missing-bare-user-only", RepoMode::BareUserOnly),
            ] {
                check_missing_object(label, mode).await;
            }
        });
    }

    /// Every absent object of a repository of `mode` is `ObjectNotFound`.
    async fn check_missing_object(label: &str, mode: RepoMode) {
        let (_scratch, repo, _) = fixture(label, mode).await;
        let src = source(&repo);
        let absent = Checksum::from_bytes([7; 32]);
        for (ty, encoding) in [
            (ObjectType::Commit, Encoding::Raw),
            (ObjectType::DirTree, Encoding::Raw),
            (ObjectType::File, Encoding::Deflate),
            (ObjectType::File, Encoding::Raw),
        ] {
            let name = ObjectName {
                checksum: absent,
                ty,
            };
            let err = src.open(&name, encoding).await.unwrap_err();
            let crate::push::Error::Source(inner) = err else {
                panic!("{label} {ty:?} {encoding:?}: {err:?}");
            };
            assert!(
                matches!(
                    inner.downcast_ref::<Error>(),
                    Some(Error::ObjectNotFound { checksum, ty: t })
                        if *checksum == absent && *t == ty
                ),
                "{label} {ty:?} {encoding:?}: {inner:?}"
            );
        }
        // A commit that is absent has no objects to list.
        assert!(matches!(
            src.objects(&absent).await,
            Err(crate::push::Error::Source(_))
        ));
    }

    #[test]
    fn the_payload_streamed_is_the_stored_content() {
        ostrya_rt::block_on(async {
            let content: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
            for (label, mode) in [
                ("stream-archive", RepoMode::Archive),
                ("stream-bare-user", RepoMode::BareUser),
                ("stream-bare-user-only", RepoMode::BareUserOnly),
            ] {
                let scratch = Scratch::new(label);
                let repo = scratch.create(mode).await;
                let commit = commit_tree(&repo, &scratch, "main", None, &content).await;
                let (regular, _) = file_objects(&repo, &commit).await;
                let loaded = repo.load_file(&regular.checksum).await.unwrap();
                match source(&repo).open(&regular, Encoding::Raw).await.unwrap() {
                    ObjectData::Content {
                        header,
                        size,
                        payload: Some(payload),
                    } => {
                        assert_eq!(header, loaded.header(), "{label}");
                        assert_eq!(size, content.len() as u64, "{label}");
                        assert!(read_all(payload).await == content, "{label}");
                    }
                    other => panic!("{label}: {other:?}"),
                }
            }
        });
    }

    #[test]
    fn detached_metadata_comes_with_the_filter_applied() {
        ostrya_rt::block_on(async {
            let (_scratch, repo, commit) = fixture("detached", RepoMode::Archive).await;
            // No detached metadata.
            assert!(
                source(&repo)
                    .detached_metadata(&commit)
                    .await
                    .unwrap()
                    .is_none()
            );

            let mut dict = DictBuilder::new();
            dict.insert_str("xa.keep", "kept");
            dict.insert_str("xa.drop", "dropped");
            dict.insert_str("xa.other", "kept too");
            repo.write_commit_detached_metadata(&commit, Some(&dict.build()))
                .await
                .unwrap();

            let all = source(&repo)
                .detached_metadata(&commit)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(keys(&all), ["xa.keep", "xa.drop", "xa.other"]);

            let filtered =
                RepoSource::new(repo.clone(), DetachedMetadataFilter::excluding(["xa.drop"]));
            let kept = filtered.detached_metadata(&commit).await.unwrap().unwrap();
            assert_eq!(keys(&kept), ["xa.keep", "xa.other"]);

            // A filter that allows no property sends no detached metadata.
            let none = RepoSource::new(
                repo.clone(),
                DetachedMetadataFilter::excluding(["xa.keep", "xa.drop", "xa.other"]),
            );
            assert!(none.detached_metadata(&commit).await.unwrap().is_none());
        });
    }
}
