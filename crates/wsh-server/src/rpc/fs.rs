//! Confined file access for the `wsh-fs` rpc protocol.
//!
//! Port of `createFileAccess` in `src/server/fs.mjs`: every path a client
//! sends is resolved against one root directory; a path that would leave it --
//! by `..`, an absolute path, or a symlink -- is refused (`Denied`, answered
//! `-32003`). Other client mistakes are `Invalid` (`-32602`); anything the OS
//! reports is `Io` (`-32603`). The messages are the JS server's, word for word.

use super::{int, text, uint, RpcError};
use ciborium::value::Value;
use std::ffi::OsString;
use std::io::{ErrorKind, SeekFrom};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::OnceCell;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const FILE_CHUNK_BYTES: usize = 64 * 1024;

/// Why a file operation failed.
#[derive(Debug)]
pub enum FsError {
    /// Refused on policy grounds (confinement, read-only): `-32003`.
    Denied(String),
    /// The client asked for something malformed or impossible: `-32602`.
    Invalid(String),
    /// The OS said no: `-32603`.
    Io(std::io::Error),
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        FsError::Io(e)
    }
}

fn deny<T>(m: &str) -> Result<T, FsError> {
    Err(FsError::Denied(m.to_string()))
}
fn fail<T>(m: impl Into<String>) -> Result<T, FsError> {
    Err(FsError::Invalid(m.into()))
}

/// The Node-style error code for an I/O error, when it has a well-known one.
pub fn io_code(e: &std::io::Error) -> Option<&'static str> {
    if e.kind() == ErrorKind::NotFound {
        return Some("ENOENT");
    }
    match e.raw_os_error()? {
        1 => Some("EPERM"),
        2 => Some("ENOENT"),
        13 => Some("EACCES"),
        17 => Some("EEXIST"),
        20 => Some("ENOTDIR"),
        21 => Some("EISDIR"),
        22 => Some("EINVAL"),
        24 => Some("EMFILE"),
        28 => Some("ENOSPC"),
        30 => Some("EROFS"),
        36 => Some("ENAMETOOLONG"),
        39 => Some("ENOTEMPTY"),
        40 => Some("ELOOP"),
        _ => None,
    }
}

impl FsError {
    /// Map onto the JSON-RPC error `wsh-fs` answers with (`fsError` in `src/server/rpc.mjs`).
    pub fn into_rpc(self) -> RpcError {
        match self {
            FsError::Denied(m) => RpcError::new(super::code::UNAUTHORIZED, m),
            FsError::Invalid(m) => RpcError::invalid_params(m),
            FsError::Io(e) => match io_code(&e) {
                Some("ENOENT") => RpcError::with_data(
                    super::code::INTERNAL,
                    "no such file or directory",
                    super::map([("code", text("ENOENT"))]),
                ),
                Some(c) => RpcError::with_data(
                    super::code::INTERNAL,
                    "file operation failed",
                    super::map([("code", text(c))]),
                ),
                None => RpcError::new(super::code::INTERNAL, "file operation failed"),
            },
        }
    }
}

/// A byte range of a regular file, readable in chunks.
pub struct RangeReader {
    pub size: u64,
    pub offset: u64,
    /// Bytes that will be read (the requested range clipped to the file).
    pub length: u64,
    file: tokio::fs::File,
    left: u64,
    chunk: usize,
}

impl RangeReader {
    /// The next chunk, or `None` at the end of the range (or if the file was truncated underneath us).
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, FsError> {
        if self.left == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; (self.chunk as u64).min(self.left) as usize];
        let n = self.file.read(&mut buf).await?;
        if n == 0 {
            self.left = 0;
            return Ok(None);
        }
        buf.truncate(n);
        self.left -= n as u64;
        Ok(Some(buf))
    }
}

#[derive(Debug, Clone)]
pub struct FileAccess {
    base: PathBuf,
    read_only: bool,
    max_file_bytes: u64,
    real_base: Arc<OnceCell<PathBuf>>,
}

/// Lexically normalise an absolute path (`path.resolve` semantics): drop `.`, apply `..`.
fn normalise(path: &Path) -> Vec<OsString> {
    let mut stack: Vec<OsString> = Vec::new();
    for c in path.components() {
        match c {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => stack.clear(),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                stack.pop();
            }
            std::path::Component::Normal(s) => stack.push(s.to_os_string()),
        }
    }
    stack
}

fn join_components(parts: &[OsString]) -> PathBuf {
    let mut p = PathBuf::from("/");
    for s in parts {
        p.push(s);
    }
    p
}

impl FileAccess {
    pub fn new(root: &Path, read_only: bool, max_file_bytes: u64) -> std::io::Result<Self> {
        let abs = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()?.join(root)
        };
        Ok(Self {
            base: join_components(&normalise(&abs)),
            read_only,
            max_file_bytes,
            real_base: Arc::new(OnceCell::new()),
        })
    }

    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    pub fn root(&self) -> &Path {
        &self.base
    }

    fn assert_writable(&self) -> Result<(), FsError> {
        if self.read_only {
            return deny("file root is read-only");
        }
        Ok(())
    }

    /// Resolve a client path to an absolute path inside the root, or refuse.
    pub async fn resolve_inside(&self, client_path: &str) -> Result<PathBuf, FsError> {
        if client_path.contains('\0') {
            return fail("illegal path");
        }
        let real_base = self
            .real_base
            .get_or_try_init(|| async { tokio::fs::canonicalize(&self.base).await })
            .await?
            .clone();
        let base_parts = normalise(&self.base);
        let mut stack = base_parts.clone();
        let stripped = client_path.trim_start_matches(['/', '\\']);
        for seg in stripped.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    stack.pop();
                }
                s => stack.push(OsString::from(s)),
            }
        }
        if stack.len() < base_parts.len() || stack[..base_parts.len()] != base_parts[..] {
            return deny("path escapes the file root");
        }
        let target = join_components(&stack);
        // Symlink escape: the deepest existing ancestor must still be inside the real root.
        let mut probe = target.clone();
        loop {
            match tokio::fs::canonicalize(&probe).await {
                Ok(real) => {
                    if !real.starts_with(&real_base) {
                        return deny("path escapes the file root");
                    }
                    break;
                }
                Err(_) => match probe.parent() {
                    Some(parent) if parent != probe => probe = parent.to_path_buf(),
                    _ => break,
                },
            }
        }
        Ok(target)
    }

    async fn entry_for(&self, full: &Path, name: &str) -> std::io::Result<Value> {
        let st = tokio::fs::symlink_metadata(full).await?;
        let ft = st.file_type();
        let kind = if ft.is_symlink() {
            "symlink"
        } else if ft.is_dir() {
            "directory"
        } else if ft.is_file() {
            "file"
        } else if ft.is_block_device() || ft.is_char_device() {
            "device"
        } else if ft.is_fifo() {
            "pipe"
        } else if ft.is_socket() {
            "socket"
        } else {
            "file"
        };
        let modified = st
            .modified()
            .map(|t| match t.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(e) => -(e.duration().as_secs_f64().ceil() as i64),
            })
            .unwrap_or(0);
        let mut entries = vec![
            (text("name"), text(name)),
            (text("size"), uint(st.len())),
            (text("modified"), int(modified)),
            (text("type"), text(kind)),
        ];
        if ft.is_symlink() {
            if let Ok(t) = tokio::fs::read_link(full).await {
                entries.push((text("symlink_target"), text(&t.to_string_lossy())));
            }
        }
        Ok(Value::Map(entries))
    }

    /// `stat`: the entry for a path.
    pub async fn stat(&self, client_path: &str) -> Result<Value, FsError> {
        let full = self.resolve_inside(client_path).await?;
        let name = full
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(self.entry_for(&full, &name).await?)
    }

    /// `list`: the sorted entries of a directory.
    pub async fn list(&self, client_path: &str) -> Result<Vec<Value>, FsError> {
        let dir = self
            .resolve_inside(if client_path.is_empty() {
                "/"
            } else {
                client_path
            })
            .await?;
        let mut rd = tokio::fs::read_dir(&dir).await?;
        let mut names = Vec::new();
        while let Some(e) = rd.next_entry().await? {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        // JS sorts by UTF-16 code unit.
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let mut entries = Vec::new();
        for name in names {
            if let Ok(v) = self.entry_for(&dir.join(&name), &name).await {
                entries.push(v);
            }
        }
        Ok(entries)
    }

    pub async fn mkdir(&self, client_path: &str) -> Result<(), FsError> {
        self.assert_writable()?;
        let full = self.resolve_inside(client_path).await?;
        tokio::fs::create_dir_all(full).await?;
        Ok(())
    }

    pub async fn remove(&self, client_path: &str) -> Result<(), FsError> {
        self.assert_writable()?;
        let full = self.resolve_inside(client_path).await?;
        if full == self.base {
            return fail("refusing to remove the file root");
        }
        if tokio::fs::symlink_metadata(&full).await?.is_dir() {
            tokio::fs::remove_dir(&full).await?;
        } else {
            tokio::fs::remove_file(&full).await?;
        }
        Ok(())
    }

    pub async fn rename(&self, client_path: &str, new_path: &str) -> Result<(), FsError> {
        self.assert_writable()?;
        if new_path.is_empty() {
            return fail("rename needs a destination path");
        }
        let from = self.resolve_inside(client_path).await?;
        let to = self.resolve_inside(new_path).await?;
        if from == self.base || to == self.base {
            return fail("refusing to rename the file root");
        }
        if from == to {
            return Ok(());
        }
        if to.starts_with(&from) {
            return fail("cannot move a directory into itself");
        }
        tokio::fs::symlink_metadata(&from).await?; // ENOENT -> "no such file or directory"
        match tokio::fs::symlink_metadata(&to).await {
            Ok(_) => return fail("destination already exists"),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        tokio::fs::rename(&from, &to).await?;
        Ok(())
    }

    /// Write bytes into a regular file. `offset` `None`: replace the whole file
    /// (create/truncate). `Some`: write in place at that byte offset without
    /// truncating (creates the file if missing).
    pub async fn write_at(
        &self,
        client_path: &str,
        data: &[u8],
        offset: Option<u64>,
        mkdirs: bool,
    ) -> Result<(), FsError> {
        self.assert_writable()?;
        let full = self.resolve_inside(client_path).await?;
        if full == self.base {
            return fail("not a regular file");
        }
        if offset.unwrap_or(0).saturating_add(data.len() as u64) > self.max_file_bytes {
            return fail(format!(
                "write would exceed the {} byte limit",
                self.max_file_bytes
            ));
        }
        if mkdirs {
            if let Some(parent) = full.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        // A FIFO or device would block or misbehave on open: regular files only.
        match tokio::fs::metadata(&full).await {
            Ok(m) if !m.is_file() => return fail("not a regular file"),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        match offset {
            None => tokio::fs::write(&full, data).await?,
            Some(at) => {
                let mut f = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .mode(0o644)
                    .open(&full)
                    .await?;
                f.seek(SeekFrom::Start(at)).await?;
                f.write_all(data).await?;
                f.flush().await?;
            }
        }
        Ok(())
    }

    /// Open a byte range of a regular file for chunked reading (`read` / `download`).
    /// `length` `None` = to the end of the file; a range longer than the file
    /// limit is refused up front.
    pub async fn open_range(
        &self,
        client_path: &str,
        offset: Option<u64>,
        length: Option<u64>,
        chunk_bytes: usize,
    ) -> Result<RangeReader, FsError> {
        let full = self.resolve_inside(client_path).await?;
        let st = tokio::fs::metadata(&full).await?;
        if !st.is_file() {
            return fail("not a regular file");
        }
        let start = offset.unwrap_or(0);
        let available = st.len().saturating_sub(start);
        let want = length.map_or(available, |l| l.min(available));
        if want > self.max_file_bytes {
            return fail(format!(
                "read of {want} bytes exceeds the {} byte limit",
                self.max_file_bytes
            ));
        }
        let mut file = tokio::fs::File::open(&full).await?;
        file.seek(SeekFrom::Start(start)).await?;
        Ok(RangeReader {
            size: st.len(),
            offset: start,
            length: want,
            file,
            left: want,
            chunk: chunk_bytes.max(1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "wsh-fs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// (outside, root) with `root` inside a scratch dir that also holds a secret.
    fn setup(tag: &str) -> (PathBuf, PathBuf) {
        let outside = tempdir(tag);
        std::fs::write(outside.join("secret.txt"), "top secret").unwrap();
        let root = outside.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "hello").unwrap();
        (outside, root)
    }

    fn denied(r: Result<impl std::fmt::Debug, FsError>) -> bool {
        matches!(r, Err(FsError::Denied(m)) if m == "path escapes the file root")
    }

    #[tokio::test]
    async fn dotdot_and_absolute_paths_cannot_leave_the_root() {
        let (outside, root) = setup("esc");
        let fs = FileAccess::new(&root, false, 1 << 20).unwrap();
        assert!(denied(fs.stat("../secret.txt").await));
        assert!(denied(fs.stat("a/../../secret.txt").await));
        assert!(denied(fs.stat("/../secret.txt").await));
        assert!(denied(fs.resolve_inside("../../../../etc/passwd").await));
        // an absolute path is rooted at the file root, not the machine
        let abs = outside.join("secret.txt");
        assert!(matches!(
            fs.stat(abs.to_str().unwrap()).await,
            Err(FsError::Io(e)) if e.kind() == ErrorKind::NotFound
        ));
        // staying inside with .. is fine
        let e = fs.stat("x/../a.txt").await;
        assert!(
            matches!(e, Err(FsError::Io(_))) || e.is_ok(),
            "x does not exist: {e:?}"
        );
        assert!(fs.stat("./a.txt").await.is_ok());
        assert!(fs.stat("/a.txt").await.is_ok());
        assert!(
            fs.stat("\\a.txt").await.is_ok(),
            "leading backslashes are stripped like slashes"
        );
    }

    #[tokio::test]
    async fn symlinks_cannot_lead_out_of_the_root() {
        let (outside, root) = setup("sym");
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("link-file")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link-dir")).unwrap();
        std::os::unix::fs::symlink("a.txt", root.join("link-ok")).unwrap();
        let fs = FileAccess::new(&root, false, 1 << 20).unwrap();
        assert!(denied(fs.resolve_inside("link-file").await));
        assert!(denied(fs.resolve_inside("link-dir/secret.txt").await));
        assert!(denied(
            fs.resolve_inside("link-dir/not-yet-there.txt").await
        ));
        assert!(denied(
            fs.open_range("link-file", None, None, 64).await.map(|_| ())
        ));
        assert!(denied(
            fs.write_at("link-dir/new.txt", b"x", None, true).await
        ));
        assert!(!outside.join("new.txt").exists());
        // a symlink that stays inside is fine
        assert!(fs.resolve_inside("link-ok").await.is_ok());
        // stat of a link reports the link, it does not follow it
        let st = fs.stat("link-ok").await.unwrap();
        assert_eq!(super::super::get(&st, "type"), Some(&text("symlink")));
        assert_eq!(
            super::super::get(&st, "symlink_target"),
            Some(&text("a.txt"))
        );
    }

    #[tokio::test]
    async fn read_only_refuses_every_mutation_with_denied() {
        let (_o, root) = setup("ro");
        let fs = FileAccess::new(&root, true, 1 << 20).unwrap();
        for r in [
            fs.mkdir("d").await,
            fs.remove("a.txt").await,
            fs.rename("a.txt", "b.txt").await,
            fs.write_at("a.txt", b"x", None, false).await,
            fs.write_at("n.txt", b"x", None, true).await,
        ] {
            assert!(matches!(r, Err(FsError::Denied(m)) if m == "file root is read-only"));
        }
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "hello"
        );
        assert!(fs.stat("a.txt").await.is_ok());
        assert_eq!(fs.list("/").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn size_limits_apply_to_reads_and_writes() {
        let (_o, root) = setup("size");
        let fs = FileAccess::new(&root, false, 10).unwrap();
        assert!(matches!(
            fs.write_at("big", &[0; 11], None, false).await,
            Err(FsError::Invalid(m)) if m == "write would exceed the 10 byte limit"
        ));
        assert!(matches!(
            fs.write_at("big", &[0; 6], Some(5), false).await,
            Err(FsError::Invalid(m)) if m == "write would exceed the 10 byte limit"
        ));
        fs.write_at("ok", &[1; 10], None, false).await.unwrap();
        std::fs::write(root.join("huge"), vec![0; 50]).unwrap();
        assert!(matches!(
            fs.open_range("huge", None, None, 8).await.map(|_| ()),
            Err(FsError::Invalid(m)) if m == "read of 50 bytes exceeds the 10 byte limit"
        ));
        // a bounded range of a big file is fine
        let r = fs.open_range("huge", Some(40), Some(5), 8).await.unwrap();
        assert_eq!((r.size, r.offset, r.length), (50, 40, 5));
        // a range is clipped to the file
        let r = fs.open_range("huge", Some(48), Some(100), 8).await.unwrap();
        assert_eq!(r.length, 2);
    }

    #[tokio::test]
    async fn ranges_read_in_chunks() {
        let (_o, root) = setup("range");
        std::fs::write(root.join("n"), (0u8..100).collect::<Vec<_>>()).unwrap();
        let fs = FileAccess::new(&root, false, 1 << 20).unwrap();
        let mut r = fs.open_range("n", Some(10), Some(25), 10).await.unwrap();
        let mut got = Vec::new();
        let mut sizes = Vec::new();
        while let Some(c) = r.next_chunk().await.unwrap() {
            sizes.push(c.len());
            got.extend(c);
        }
        assert_eq!(sizes, vec![10, 10, 5]);
        assert_eq!(got, (10u8..35).collect::<Vec<_>>());
        assert!(matches!(
            fs.open_range(".", None, None, 8).await.map(|_| ()),
            Err(FsError::Invalid(m)) if m == "not a regular file"
        ));
    }

    #[tokio::test]
    async fn writes_create_truncate_and_patch_in_place() {
        let (_o, root) = setup("write");
        let fs = FileAccess::new(&root, false, 1 << 20).unwrap();
        fs.write_at("a.txt", b"HE", Some(0), false).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "HEllo"
        );
        fs.write_at("a.txt", b"!", Some(7), false).await.unwrap();
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"HEllo\0\0!");
        fs.write_at("a.txt", b"new", None, false).await.unwrap();
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "new");
        // no mkdirs: a missing parent is ENOENT; with mkdirs it is created
        assert!(matches!(
            fs.write_at("p/q.txt", b"x", None, false).await,
            Err(FsError::Io(e)) if e.kind() == ErrorKind::NotFound
        ));
        fs.write_at("p/q.txt", b"x", None, true).await.unwrap();
        assert_eq!(std::fs::read_to_string(root.join("p/q.txt")).unwrap(), "x");
        // the root and directories are not files
        assert!(
            matches!(fs.write_at("/", b"x", None, false).await, Err(FsError::Invalid(m)) if m == "not a regular file")
        );
        assert!(
            matches!(fs.write_at("p", b"x", None, false).await, Err(FsError::Invalid(m)) if m == "not a regular file")
        );
    }

    #[tokio::test]
    async fn rename_mkdir_remove_rules() {
        let (_o, root) = setup("ops");
        let fs = FileAccess::new(&root, false, 1 << 20).unwrap();
        fs.mkdir("d/e").await.unwrap();
        fs.rename("a.txt", "d/a2.txt").await.unwrap();
        assert!(root.join("d/a2.txt").exists() && !root.join("a.txt").exists());
        fs.write_at("b.txt", b"b", None, false).await.unwrap();
        assert!(
            matches!(fs.rename("b.txt", "d/a2.txt").await, Err(FsError::Invalid(m)) if m == "destination already exists")
        );
        assert!(
            matches!(fs.rename("d", "d/e/d").await, Err(FsError::Invalid(m)) if m == "cannot move a directory into itself")
        );
        assert!(
            matches!(fs.rename("/", "x").await, Err(FsError::Invalid(m)) if m == "refusing to rename the file root")
        );
        assert!(
            matches!(fs.rename("b.txt", "").await, Err(FsError::Invalid(m)) if m == "rename needs a destination path")
        );
        assert!(denied(fs.rename("b.txt", "../out.txt").await));
        assert!(
            matches!(fs.rename("nope", "x").await, Err(FsError::Io(e)) if e.kind() == ErrorKind::NotFound)
        );
        assert!(fs.rename("b.txt", "b.txt").await.is_ok());
        assert!(
            matches!(fs.remove("/").await, Err(FsError::Invalid(m)) if m == "refusing to remove the file root")
        );
        assert!(
            matches!(fs.remove("d").await, Err(FsError::Io(_))),
            "non-empty directory"
        );
        fs.remove("d/e").await.unwrap();
        fs.remove("b.txt").await.unwrap();
        assert!(!root.join("b.txt").exists());
        assert!(
            matches!(fs.resolve_inside("a\0b").await, Err(FsError::Invalid(m)) if m == "illegal path")
        );
    }

    #[tokio::test]
    async fn list_is_sorted_and_typed() {
        let (_o, root) = setup("list");
        std::fs::write(root.join("b"), "").unwrap();
        std::fs::create_dir(root.join("c")).unwrap();
        std::fs::write(root.join("B"), "").unwrap();
        let fs = FileAccess::new(&root, false, 1 << 20).unwrap();
        let names: Vec<String> = fs
            .list("")
            .await
            .unwrap()
            .iter()
            .map(|e| match super::super::get(e, "name") {
                Some(Value::Text(t)) => t.clone(),
                _ => panic!(),
            })
            .collect();
        assert_eq!(names, vec!["B", "a.txt", "b", "c"]);
        let e = fs.stat("c").await.unwrap();
        assert_eq!(super::super::get(&e, "type"), Some(&text("directory")));
        assert!(matches!(fs.list("a.txt").await, Err(FsError::Io(_))));
    }

    #[test]
    fn io_errors_map_onto_the_js_servers_rpc_errors() {
        let e = FsError::Io(std::io::Error::from(ErrorKind::NotFound)).into_rpc();
        assert_eq!(e.code, super::super::code::INTERNAL);
        assert_eq!(e.message, "no such file or directory");
        assert_eq!(
            super::super::get(e.data.as_ref().unwrap(), "code"),
            Some(&text("ENOENT"))
        );
        let e = FsError::Io(std::io::Error::from_raw_os_error(13)).into_rpc();
        assert_eq!(e.message, "file operation failed");
        assert_eq!(
            super::super::get(e.data.as_ref().unwrap(), "code"),
            Some(&text("EACCES"))
        );
        let e = FsError::Denied("x".into()).into_rpc();
        assert_eq!(e.code, super::super::code::UNAUTHORIZED);
        let e = FsError::Invalid("y".into()).into_rpc();
        assert_eq!(e.code, super::super::code::INVALID_PARAMS);
    }
}
