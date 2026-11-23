//! `wsh --share NAME=/dir[:ro|:rw]`: the file server behind an operator-side shared folder (#159).
//!
//! The HOST sends file requests and this module answers them. The host is not trusted: it may be
//! a page the operator opened an hour ago, or whatever a relay put on the other end of the pipe.
//! Every request is hostile input, and the rules below are what makes serving a directory to it
//! acceptable. Each one has a test in `tests.rs` that fails when the rule is broken.
//!
//! Confinement is by FILE DESCRIPTOR, never by comparing path strings:
//!
//! - the share root is opened once, at start-up, from its canonical path, and everything is
//!   resolved relative to that descriptor, one component at a time (`openat` with
//!   `O_NOFOLLOW | O_DIRECTORY`), so a symlink in the middle of a path is an error (`ELOOP`) and one
//!   swapped in between a check and its use is never followed: the open itself refuses it;
//! - the last component is opened (or `*at`-operated on) with `O_NOFOLLOW`, and what was opened is
//!   `fstat`ed afterwards: only regular files and directories exist for the host (sockets, devices
//!   and FIFOs answer `ENOENT` and are left out of listings). A planted FIFO cannot hang the server
//!   (`O_NONBLOCK`), and a planted symlink cannot redirect a write;
//! - `..` is refused outright; names that are not valid UTF-8 never appear; a directory on another
//!   device than the root (a mount) is not entered (`EXDEV`);
//! - the root's device and inode are compared with what they were at start-up before every
//!   request, so a root that was replaced or moved is noticed (`ESTALE`), not served;
//! - read-only unless `:rw` (`EROFS`); even with `:rw` a file with more than one hard link is
//!   never opened for writing nor chmod'ed nor truncated (`EPERM`): the other name may be outside;
//! - a created file or directory gets the requested mode limited to `0o755` bits (never setuid,
//!   never group/other writable), default `0o644` / `0o755`; creation is `O_CREAT | O_EXCL`, which
//!   does not follow a symlink that appeared in the name's place;
//! - bounded everything (see [`Limits`]): open handles, bytes per operation, directory entries,
//!   path length and depth, bytes per second overall. In-flight requests are bounded by the wire
//!   layer (`wsh_client::share`).
//!
//! What it does NOT do: it cannot stop the host from reading everything under the root, nor, with
//! `:rw`, from changing or deleting it, nor from filling the disk. It does not notice a symlink
//! that already exists inside the tree and points outside (it simply never follows it).

use std::collections::HashMap;
use std::ffi::CString;
use std::future::Future;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::fs::{
    fstat, ftruncate, futimens, mkdirat, openat, readlinkat, renameat, statat, unlinkat, AtFlags,
    Dir, FileType, Mode, OFlags, Stat, Timespec, Timestamps, CWD, UTIME_OMIT,
};
use rustix::io::Errno;
use serde_json::{json, Value};
use wsh_client::share::{error_reply, ShareProvider};
use wsh_core::messages::{ShareReplyPayload, ShareRequestPayload};

/// The bounds a share server holds the host to.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Open handles at once (`EMFILE` beyond).
    pub max_handles: usize,
    /// Data in one request or reply, in bytes (also advertised in `ShareOffer.max_bytes`).
    pub max_bytes: usize,
    /// Requests in flight (advertised in `ShareOffer.max_inflight`; enforced by the wire layer).
    pub max_inflight: u32,
    /// Entries in one directory the server will list (`EFBIG` beyond).
    pub max_dir_entries: usize,
    /// Entries in one `readdir` reply.
    pub page_entries: usize,
    /// Path length in bytes and depth in components; one component's length.
    pub max_path_bytes: usize,
    pub max_components: usize,
    pub max_name_bytes: usize,
    /// Largest file offset + length a write may reach.
    pub max_file_bytes: u64,
    /// Bytes read plus written per second over the whole session, and the burst allowed.
    pub bytes_per_sec: u64,
    pub burst_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_handles: 64,
            max_bytes: 256 * 1024,
            max_inflight: 16,
            max_dir_entries: 200_000,
            page_entries: 1000,
            max_path_bytes: 4096,
            max_components: 128,
            max_name_bytes: 255,
            max_file_bytes: 1 << 40,
            bytes_per_sec: 256 * 1024 * 1024,
            burst_bytes: 32 * 1024 * 1024,
        }
    }
}

/// What the operator asked for with one `--share`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareSpec {
    pub name: String,
    pub path: PathBuf,
    pub writable: bool,
}

/// Parse `NAME=/abs/dir[:ro|:rw]`.
pub fn parse_spec(spec: &str) -> Result<ShareSpec, String> {
    let (name, rest) = spec
        .split_once('=')
        .ok_or_else(|| format!("--share {spec:?}: expected NAME=/abs/dir[:ro|:rw]"))?;
    if !valid_name(name) {
        return Err(format!(
            "--share {spec:?}: the name must be letters, digits, '.', '_' or '-' (at most 64, starting with a letter or digit)"
        ));
    }
    let (path, writable) = if let Some(p) = rest.strip_suffix(":rw") {
        (p, true)
    } else if let Some(p) = rest.strip_suffix(":ro") {
        (p, false)
    } else {
        (rest, false)
    };
    if !path.starts_with('/') {
        return Err(format!(
            "--share {spec:?}: the directory must be an absolute path"
        ));
    }
    Ok(ShareSpec {
        name: name.to_string(),
        path: PathBuf::from(path),
        writable,
    })
}

pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// An error with the errno-like code the wire carries.
#[derive(Debug, Clone)]
pub struct ShareError {
    pub errno: &'static str,
    pub message: String,
}

type R<T> = Result<T, ShareError>;

fn err<T>(errno: &'static str, message: &str) -> R<T> {
    Err(ShareError {
        errno,
        message: message.to_string(),
    })
}

fn from_errno(e: Errno) -> ShareError {
    let (errno, message) = if e == Errno::NOENT {
        ("ENOENT", "no such file or directory")
    } else if e == Errno::EXIST {
        ("EEXIST", "file exists")
    } else if e == Errno::NOTDIR {
        ("ENOTDIR", "not a directory")
    } else if e == Errno::ISDIR {
        ("EISDIR", "is a directory")
    } else if e == Errno::NOTEMPTY {
        ("ENOTEMPTY", "directory not empty")
    } else if e == Errno::ACCESS {
        ("EACCES", "permission denied")
    } else if e == Errno::PERM {
        ("EPERM", "operation not permitted")
    } else if e == Errno::ROFS {
        ("EROFS", "read-only file system")
    } else if e == Errno::INVAL {
        ("EINVAL", "invalid argument")
    } else if e == Errno::BADF {
        ("EBADF", "bad handle")
    } else if e == Errno::LOOP {
        (
            "ELOOP",
            "too many levels of symbolic links (symlinks are never followed)",
        )
    } else if e == Errno::NAMETOOLONG {
        ("ENAMETOOLONG", "file name too long")
    } else if e == Errno::NOSPC || e == Errno::DQUOT {
        ("ENOSPC", "no space left on device")
    } else if e == Errno::MFILE || e == Errno::NFILE {
        ("EMFILE", "too many open files")
    } else if e == Errno::BUSY {
        ("EBUSY", "resource busy")
    } else if e == Errno::XDEV {
        ("EXDEV", "cross-device link")
    } else if e == Errno::FBIG {
        ("EFBIG", "file too large")
    } else if e == Errno::NXIO || e == Errno::OPNOTSUPP {
        // What opening a FIFO or a socket for writing says: they do not exist for the host.
        ("ENOENT", "no such file or directory")
    } else {
        ("EIO", "input/output error")
    };
    ShareError {
        errno,
        message: message.to_string(),
    }
}

trait Ctx<T> {
    fn ctx(self) -> R<T>;
}
impl<T> Ctx<T> for Result<T, Errno> {
    fn ctx(self) -> R<T> {
        self.map_err(from_errno)
    }
}

/// One shared directory.
pub struct Share {
    pub name: String,
    pub writable: bool,
    /// The canonical path it was opened from (for the start-up line and the replaced-root check).
    pub root_path: PathBuf,
    root: OwnedFd,
    dev: u64,
    ino: u64,
}

impl Share {
    /// Open the root: canonicalize (the operator typed this path, so a symlink HERE is followed
    /// once), open it by descriptor, remember its device and inode.
    pub fn open(spec: &ShareSpec) -> Result<Share, String> {
        let canon = std::fs::canonicalize(&spec.path)
            .map_err(|e| format!("--share {}: {}: {e}", spec.name, spec.path.display()))?;
        let root = openat(
            CWD,
            &canon,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("--share {}: {}: {e}", spec.name, canon.display()))?;
        let st = fstat(&root).map_err(|e| format!("--share {}: {e}", spec.name))?;
        Ok(Share {
            name: spec.name.clone(),
            writable: spec.writable,
            root_path: canon,
            root,
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
        })
    }

    /// Is the root still what it was? (Replaced, moved, or swapped for a symlink: no.)
    fn check_root(&self) -> R<()> {
        match rustix::fs::stat(&self.root_path) {
            Ok(st) if st.st_dev as u64 == self.dev && st.st_ino as u64 == self.ino => Ok(()),
            _ => err("ESTALE", "the shared directory was replaced or removed"),
        }
    }

    fn need_write(&self) -> R<()> {
        if self.writable {
            Ok(())
        } else {
            err("EROFS", "this share is read-only")
        }
    }
}

enum Kind {
    File,
    Dir,
    Symlink,
}

fn kind_of(st: &Stat) -> Option<Kind> {
    match FileType::from_raw_mode(st.st_mode as _) {
        FileType::RegularFile => Some(Kind::File),
        FileType::Directory => Some(Kind::Dir),
        FileType::Symlink => Some(Kind::Symlink),
        // Sockets, devices, FIFOs: invisible.
        _ => None,
    }
}

fn type_name(k: &Kind) -> &'static str {
    match k {
        Kind::File => "file",
        Kind::Dir => "directory",
        Kind::Symlink => "symlink",
    }
}

fn ms(sec: i64, nsec: i64) -> f64 {
    sec as f64 * 1000.0 + (nsec / 1_000_000) as f64
}

fn attr_of(st: &Stat, k: &Kind) -> Value {
    json!({
        "type": type_name(k),
        "size": st.st_size as u64,
        "mode": (st.st_mode as u32) & 0o777,
        "mtime_ms": ms(st.st_mtime as i64, st.st_mtime_nsec as i64),
        "atime_ms": ms(st.st_atime as i64, st.st_atime_nsec as i64),
        "ctime_ms": ms(st.st_ctime as i64, st.st_ctime_nsec as i64),
        "nlink": st.st_nlink as u64,
        "ino": st.st_ino as u64,
    })
}

/// The parts of a path: no `..`, no empty or `.` components.
fn components(limits: &Limits, path: &str) -> R<Vec<String>> {
    if path.len() > limits.max_path_bytes {
        return err("ENAMETOOLONG", "path too long");
    }
    if path.contains('\0') {
        return err("EINVAL", "path contains a NUL byte");
    }
    let mut out = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => return err("EINVAL", "\"..\" is not allowed in a share path"),
            c if c.len() > limits.max_name_bytes => {
                return err("ENAMETOOLONG", "file name too long")
            }
            c => out.push(c.to_string()),
        }
    }
    if out.len() > limits.max_components {
        return err("ENAMETOOLONG", "path too deep");
    }
    Ok(out)
}

fn cstr(name: &str) -> R<CString> {
    CString::new(name).map_err(|_| ShareError {
        errno: "EINVAL",
        message: "invalid name".into(),
    })
}

/// A directory (its descriptor) and the final name in it; `name` is None for the root itself.
struct Located {
    dir: OwnedFd,
    name: Option<String>,
}

struct Handle {
    fd: OwnedFd,
    share: Arc<Share>,
    readable: bool,
    writable: bool,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

struct Inner {
    shares: HashMap<String, Arc<Share>>,
    limits: Limits,
    handles: Mutex<(u32, HashMap<u32, Arc<Handle>>)>,
    bucket: Mutex<Bucket>,
}

/// The file server for one connection: a set of shares and the handles the host has open.
#[derive(Clone)]
pub struct ShareServer {
    inner: Arc<Inner>,
}

impl ShareServer {
    pub fn new(shares: Vec<Share>, limits: Limits) -> Self {
        let burst = limits.burst_bytes as f64;
        Self {
            inner: Arc::new(Inner {
                shares: shares
                    .into_iter()
                    .map(|s| (s.name.clone(), Arc::new(s)))
                    .collect(),
                limits,
                handles: Mutex::new((1, HashMap::new())),
                bucket: Mutex::new(Bucket {
                    tokens: burst,
                    last: Instant::now(),
                }),
            }),
        }
    }

    #[cfg(test)]
    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }

    /// Handle one request, blocking (tests call this directly).
    #[cfg(test)]
    pub fn exec(&self, req: &ShareRequestPayload) -> R<ShareReplyPayload> {
        self.inner.exec(req)
    }

    /// Open handles right now.
    #[cfg(test)]
    pub fn open_handles(&self) -> usize {
        self.inner.handles.lock().expect("handles").1.len()
    }

    /// Wait until `n` more bytes fit the session's rate (a token bucket: the burst first, then the
    /// steady rate).
    async fn throttle(&self, n: u64) {
        let lim = &self.inner.limits;
        if n == 0 || lim.bytes_per_sec == 0 {
            return;
        }
        let wait = {
            let mut b = self.inner.bucket.lock().expect("bucket");
            let now = Instant::now();
            let refill = now.duration_since(b.last).as_secs_f64() * lim.bytes_per_sec as f64;
            b.tokens = (b.tokens + refill).min(lim.burst_bytes as f64);
            b.last = now;
            b.tokens -= n as f64;
            if b.tokens < 0.0 {
                Duration::from_secs_f64(-b.tokens / lim.bytes_per_sec as f64)
            } else {
                Duration::ZERO
            }
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

impl ShareProvider for ShareServer {
    fn serve<'a>(
        &'a self,
        request: ShareRequestPayload,
    ) -> Pin<Box<dyn Future<Output = ShareReplyPayload> + Send + 'a>> {
        Box::pin(async move {
            let id = request.request_id;
            // Writes are paid for before they happen, reads after (we do not know the size).
            if let Some(d) = &request.data {
                self.throttle(d.len() as u64).await;
            }
            let inner = self.inner.clone();
            let outcome = tokio::task::spawn_blocking(move || inner.exec(&request)).await;
            match outcome {
                Ok(Ok(reply)) => {
                    if let Some(d) = &reply.data {
                        self.throttle(d.len() as u64).await;
                    }
                    reply
                }
                Ok(Err(e)) => error_reply(id, e.errno, &e.message),
                Err(_) => error_reply(id, "EIO", "internal error"),
            }
        })
    }

    fn shutdown(&self) {
        self.inner.handles.lock().expect("handles").1.clear();
    }
}

fn ok_reply(id: u32) -> ShareReplyPayload {
    ShareReplyPayload {
        request_id: id,
        ok: true,
        errno: None,
        message: None,
        attr: Value::Null,
        entries: Value::Null,
        cursor: None,
        handle: None,
        data: None,
        eof: None,
        written: None,
        target: None,
    }
}

impl Inner {
    fn share(&self, name: &str) -> R<Arc<Share>> {
        match self.shares.get(name) {
            Some(s) => Ok(s.clone()),
            None => err("EACCES", "no such share"),
        }
    }

    fn exec(&self, req: &ShareRequestPayload) -> R<ShareReplyPayload> {
        let share = self.share(&req.share)?;
        share.check_root()?;
        let id = req.request_id;
        let mut reply = ok_reply(id);
        match req.op.as_str() {
            "stat" | "lstat" => {
                reply.attr = self.stat(&share, req.path.as_deref().unwrap_or(""))?;
            }
            "readdir" => {
                let (entries, cursor) = self.readdir(
                    &share,
                    req.path.as_deref().unwrap_or(""),
                    req.cursor.as_deref(),
                    req.length,
                )?;
                reply.entries = Value::Array(entries);
                reply.cursor = cursor;
            }
            "readlink" => {
                reply.target = Some(self.readlink(&share, req.path.as_deref().unwrap_or(""))?);
            }
            "open" => {
                let flags = Flags::parse(&req.flags)?;
                let (handle, attr, data) = self.open(
                    &share,
                    req.path.as_deref().unwrap_or(""),
                    &flags,
                    req.mode,
                    req.length,
                )?;
                reply.handle = handle;
                reply.attr = attr;
                if let Some((d, eof)) = data {
                    reply.data = Some(d);
                    reply.eof = Some(eof);
                }
            }
            "create" => {
                let flags = Flags {
                    write: true,
                    create: true,
                    excl: true,
                    ..Flags::default()
                };
                let (handle, attr, _) = self.open(
                    &share,
                    req.path.as_deref().unwrap_or(""),
                    &flags,
                    req.mode,
                    None,
                )?;
                reply.handle = handle;
                reply.attr = attr;
            }
            "read" => {
                let (d, eof) = self.read(
                    req.handle.unwrap_or(0),
                    &req.share,
                    req.offset.unwrap_or(0),
                    req.length.unwrap_or(0),
                )?;
                reply.data = Some(d);
                reply.eof = Some(eof);
            }
            "write" => {
                let data = req.data.as_deref().unwrap_or(&[]);
                reply.written = Some(self.write(
                    req.handle.unwrap_or(0),
                    &req.share,
                    req.offset.unwrap_or(0),
                    data,
                )?);
            }
            "close" => {
                let h = req.handle.unwrap_or(0);
                match self.handles.lock().expect("handles").1.remove(&h) {
                    Some(_) => {}
                    None => return err("EBADF", "no such handle"),
                }
            }
            "mkdir" => {
                reply.attr = self.mkdir(&share, req.path.as_deref().unwrap_or(""), req.mode)?;
            }
            "unlink" => self.remove(&share, req.path.as_deref().unwrap_or(""), false)?,
            "rmdir" => self.remove(&share, req.path.as_deref().unwrap_or(""), true)?,
            "rename" => self.rename(
                &share,
                req.path.as_deref().unwrap_or(""),
                req.to.as_deref().unwrap_or(""),
            )?,
            "setattr" => {
                reply.attr = self.setattr(&share, req.path.as_deref(), req.handle, &req.attr)?;
            }
            _ => return err("ENOTSUP", "unknown operation"),
        }
        Ok(reply)
    }

    // ── resolution ───────────────────────────────────────────────────

    /// Walk to the directory holding `path`'s last component.
    fn locate(&self, share: &Share, path: &str) -> R<Located> {
        let comps = components(&self.limits, path)?;
        let mut dir = openat(
            &share.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ctx()?;
        let Some((last, parents)) = comps.split_last() else {
            return Ok(Located { dir, name: None });
        };
        for c in parents {
            let next = open_dir_component(&dir, c)?;
            let st = fstat(&next).ctx()?;
            if st.st_dev as u64 != share.dev {
                return err("EXDEV", "another file system is mounted there");
            }
            dir = next;
        }
        Ok(Located {
            dir,
            name: Some(last.clone()),
        })
    }

    /// lstat the located name; sockets, devices, FIFOs and other file systems do not exist.
    fn lstat(&self, share: &Share, loc: &Located) -> R<(Stat, Kind)> {
        let st = match &loc.name {
            None => fstat(&loc.dir).ctx()?,
            Some(n) => statat(&loc.dir, cstr(n)?.as_c_str(), AtFlags::SYMLINK_NOFOLLOW).ctx()?,
        };
        if st.st_dev as u64 != share.dev {
            return err("ENOENT", "no such file or directory");
        }
        match kind_of(&st) {
            Some(k) => Ok((st, k)),
            None => err("ENOENT", "no such file or directory"),
        }
    }

    // ── operations ───────────────────────────────────────────────────

    fn stat(&self, share: &Share, path: &str) -> R<Value> {
        let loc = self.locate(share, path)?;
        let (st, k) = self.lstat(share, &loc)?;
        Ok(attr_of(&st, &k))
    }

    fn readlink(&self, share: &Share, path: &str) -> R<String> {
        let loc = self.locate(share, path)?;
        let (_, k) = self.lstat(share, &loc)?;
        let (Kind::Symlink, Some(n)) = (k, &loc.name) else {
            return err("EINVAL", "not a symbolic link");
        };
        let t = readlinkat(&loc.dir, cstr(n)?.as_c_str(), Vec::new()).ctx()?;
        match t.into_string() {
            Ok(s) => Ok(s),
            Err(_) => err("EIO", "link target is not valid UTF-8"),
        }
    }

    fn readdir(
        &self,
        share: &Share,
        path: &str,
        cursor: Option<&str>,
        length: Option<u32>,
    ) -> R<(Vec<Value>, Option<String>)> {
        let loc = self.locate(share, path)?;
        // The directory itself: the root, or the last component opened without following a link.
        let dirfd = match &loc.name {
            None => loc.dir,
            Some(n) => {
                let fd = open_dir_component(&loc.dir, n)?;
                if fstat(&fd).ctx()?.st_dev as u64 != share.dev {
                    return err("EXDEV", "another file system is mounted there");
                }
                fd
            }
        };
        let mut names: Vec<String> = Vec::new();
        let dir = Dir::read_from(&dirfd).ctx()?;
        for entry in dir {
            let entry = entry.ctx()?;
            let raw = entry.file_name();
            if raw.to_bytes() == b"." || raw.to_bytes() == b".." {
                continue;
            }
            // A name that is not valid UTF-8 does not exist for the host.
            let Ok(name) = raw.to_str() else { continue };
            names.push(name.to_string());
            if names.len() > self.limits.max_dir_entries {
                return err("EFBIG", "directory has too many entries");
            }
        }
        names.sort();
        let start = match cursor {
            Some(c) => names.partition_point(|n| n.as_str() <= c),
            None => 0,
        };
        let want = (length.unwrap_or(self.limits.page_entries as u32) as usize)
            .clamp(1, self.limits.page_entries);
        let mut out = Vec::new();
        let mut budget = self.limits.max_bytes;
        let mut last = None;
        let mut i = start;
        while i < names.len() && out.len() < want {
            let name = &names[i];
            i += 1;
            last = Some(name.clone());
            let Ok(st) = statat(&dirfd, cstr(name)?.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) else {
                continue; // vanished since the listing
            };
            if st.st_dev as u64 != share.dev {
                continue;
            }
            let Some(k) = kind_of(&st) else { continue };
            let mut entry = attr_of(&st, &k);
            entry["name"] = Value::String(name.clone());
            if let Kind::Symlink = k {
                if let Ok(t) = readlinkat(&dirfd, cstr(name)?.as_c_str(), Vec::new()) {
                    if let Ok(t) = t.into_string() {
                        entry["target"] = Value::String(t);
                    }
                }
            }
            let cost = 200 + name.len();
            if cost > budget {
                // Stop before this one: it goes in the next page.
                i -= 1;
                last = out
                    .last()
                    .and_then(|e: &Value| e["name"].as_str().map(str::to_string));
                break;
            }
            budget -= cost;
            out.push(entry);
        }
        let more = i < names.len();
        // A cursor names the last entry examined, so a page that was all skipped entries still
        // makes progress.
        Ok((out, if more { last } else { None }))
    }

    fn open(
        &self,
        share: &Arc<Share>,
        path: &str,
        flags: &Flags,
        mode: Option<u32>,
        inline: Option<u32>,
    ) -> R<(Option<u32>, Value, Option<(Vec<u8>, bool)>)> {
        let want_write = flags.write || flags.create || flags.trunc;
        if want_write {
            share.need_write()?;
        }
        if !flags.read && !want_write {
            return err("EINVAL", "open needs \"read\" or \"write\"");
        }
        if self.handles.lock().expect("handles").1.len() >= self.limits.max_handles {
            return err("EMFILE", "too many open handles");
        }
        let loc = self.locate(share, path)?;
        let Some(name) = &loc.name else {
            return err("EISDIR", "is a directory");
        };
        let cname = cstr(name)?;
        if !(flags.create && flags.excl) {
            // Look before opening: opening a device node or a FIFO can have effects of its own. (What
            // is opened is looked at again below, so a swap in between is still caught.)
            match statat(&loc.dir, cname.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => match kind_of(&st) {
                    Some(Kind::File) => {}
                    Some(Kind::Dir) => return err("EISDIR", "is a directory"),
                    Some(Kind::Symlink) => return Err(from_errno(Errno::LOOP)),
                    None => return err("ENOENT", "no such file or directory"),
                },
                Err(e) if e == Errno::NOENT && flags.create => {}
                Err(e) => return Err(from_errno(e)),
            }
        }
        let access = match (flags.read, want_write) {
            (true, true) => OFlags::RDWR,
            (true, false) => OFlags::RDONLY,
            _ => OFlags::WRONLY,
        };
        // O_NONBLOCK: a FIFO that appears under the name cannot hang the server. No O_TRUNC here:
        // truncating happens after the checks below.
        let base = access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let create_mode = mode_of(create_mode(mode, 0o644));
        let fd = if flags.create && flags.excl {
            // Exclusive creation: straight to O_CREAT | O_EXCL, which fails (EEXIST) on anything
            // already there, a symlink included, and never follows one.
            openat(
                &loc.dir,
                cname.as_c_str(),
                base | OFlags::CREATE | OFlags::EXCL,
                create_mode,
            )
            .ctx()?
        } else if flags.create {
            match openat(&loc.dir, cname.as_c_str(), base, Mode::empty()) {
                Ok(fd) => fd,
                Err(e) if e == Errno::NOENT => openat(
                    &loc.dir,
                    cname.as_c_str(),
                    base | OFlags::CREATE | OFlags::EXCL,
                    create_mode,
                )
                .ctx()?,
                Err(e) => return Err(from_errno(e)),
            }
        } else {
            openat(&loc.dir, cname.as_c_str(), base, Mode::empty()).ctx()?
        };
        let st = fstat(&fd).ctx()?;
        match kind_of(&st) {
            Some(Kind::File) => {}
            Some(Kind::Dir) => return err("EISDIR", "is a directory"),
            _ => return err("ENOENT", "no such file or directory"),
        }
        if st.st_dev as u64 != share.dev {
            return err("ENOENT", "no such file or directory");
        }
        if want_write && st.st_nlink as u64 > 1 {
            return err(
                "EPERM",
                "this file has other hard links and is not writable",
            );
        }
        if flags.trunc {
            ftruncate(&fd, 0).ctx()?;
        }
        let mut data = None;
        if flags.read {
            if let Some(n) = inline {
                let n = (n as usize).min(self.limits.max_bytes);
                if (st.st_size as u64) <= n as u64 {
                    let mut buf = vec![0u8; st.st_size as usize];
                    let got = pread_full(&fd, &mut buf, 0)?;
                    buf.truncate(got);
                    data = Some((buf, true));
                }
            }
        }
        let st = fstat(&fd).ctx()?;
        let attr = attr_of(&st, &Kind::File);
        // The whole file came with the open and nothing can be written through it: there is
        // nothing left to read or close, so no handle is made (one message for a small file).
        if matches!(data, Some((_, true))) && !want_write {
            return Ok((None, attr, data));
        }
        let mut table = self.handles.lock().expect("handles");
        if table.1.len() >= self.limits.max_handles {
            return err("EMFILE", "too many open handles");
        }
        let id = table.0;
        table.0 = table.0.wrapping_add(1).max(1);
        table.1.insert(
            id,
            Arc::new(Handle {
                fd,
                share: share.clone(),
                readable: flags.read,
                writable: want_write,
            }),
        );
        Ok((Some(id), attr, data))
    }

    fn handle(&self, id: u32, share: &str) -> R<Arc<Handle>> {
        let h = self.handles.lock().expect("handles").1.get(&id).cloned();
        match h {
            Some(h) if h.share.name == share => {
                h.share.check_root()?;
                Ok(h)
            }
            _ => err("EBADF", "no such handle"),
        }
    }

    fn read(&self, id: u32, share: &str, offset: u64, length: u32) -> R<(Vec<u8>, bool)> {
        let h = self.handle(id, share)?;
        if !h.readable {
            return err("EBADF", "handle not open for reading");
        }
        let n = (length as usize).min(self.limits.max_bytes);
        let mut buf = vec![0u8; n];
        let got = pread_full(&h.fd, &mut buf, offset)?;
        buf.truncate(got);
        Ok((buf, got < n))
    }

    fn write(&self, id: u32, share: &str, offset: u64, data: &[u8]) -> R<u32> {
        let h = self.handle(id, share)?;
        if !h.writable {
            return err("EBADF", "handle not open for writing");
        }
        if data.len() > self.limits.max_bytes {
            return err("EINVAL", "write too large");
        }
        if offset.saturating_add(data.len() as u64) > self.limits.max_file_bytes {
            return err("EFBIG", "file too large");
        }
        let mut done = 0;
        while done < data.len() {
            match rustix::io::pwrite(&h.fd, &data[done..], offset + done as u64) {
                Ok(0) => return err("EIO", "short write"),
                Ok(n) => done += n,
                Err(e) if e == Errno::INTR => {}
                Err(e) => return Err(from_errno(e)),
            }
        }
        Ok(done as u32)
    }

    fn mkdir(&self, share: &Share, path: &str, mode: Option<u32>) -> R<Value> {
        share.need_write()?;
        let loc = self.locate(share, path)?;
        let Some(name) = &loc.name else {
            return err("EEXIST", "file exists");
        };
        let c = cstr(name)?;
        mkdirat(&loc.dir, c.as_c_str(), mode_of(create_mode(mode, 0o755))).ctx()?;
        let (st, k) = self.lstat(share, &loc)?;
        Ok(attr_of(&st, &k))
    }

    fn remove(&self, share: &Share, path: &str, dir: bool) -> R<()> {
        share.need_write()?;
        let loc = self.locate(share, path)?;
        let Some(name) = &loc.name else {
            return err("EBUSY", "the share's root cannot be removed");
        };
        let (_, k) = self.lstat(share, &loc)?;
        match (dir, k) {
            (true, Kind::Dir) => {}
            (true, _) => return err("ENOTDIR", "not a directory"),
            (false, Kind::Dir) => return err("EISDIR", "is a directory"),
            (false, _) => {}
        }
        let flags = if dir {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        unlinkat(&loc.dir, cstr(name)?.as_c_str(), flags).ctx()
    }

    fn rename(&self, share: &Share, from: &str, to: &str) -> R<()> {
        share.need_write()?;
        let a = self.locate(share, from)?;
        let b = self.locate(share, to)?;
        let (Some(an), Some(bn)) = (&a.name, &b.name) else {
            return err("EINVAL", "the share's root cannot be renamed");
        };
        self.lstat(share, &a)?;
        renameat(&a.dir, cstr(an)?.as_c_str(), &b.dir, cstr(bn)?.as_c_str()).ctx()
    }

    fn setattr(
        &self,
        share: &Arc<Share>,
        path: Option<&str>,
        handle: Option<u32>,
        attr: &Value,
    ) -> R<Value> {
        share.need_write()?;
        let new_mode = attr.get("mode").and_then(Value::as_u64);
        let atime = attr.get("atime_ms").and_then(Value::as_f64);
        let mtime = attr.get("mtime_ms").and_then(Value::as_f64);
        let size = attr.get("size").and_then(Value::as_u64);
        if let Some(sz) = size {
            if sz > self.limits.max_file_bytes {
                return err("EFBIG", "file too large");
            }
        }
        // The descriptor everything is applied to: the handle's, or the path opened without
        // following a link (never a symlink: that would change what it points at).
        let owned;
        let h;
        let fd: &OwnedFd = match (handle, path) {
            (Some(id), _) => {
                h = self.handle(id, &share.name)?;
                if size.is_some() && !h.writable {
                    return err("EBADF", "handle not open for writing");
                }
                &h.fd
            }
            (None, Some(p)) => {
                let loc = self.locate(share, p)?;
                let access = if size.is_some() {
                    OFlags::WRONLY
                } else {
                    OFlags::RDONLY
                };
                owned = match &loc.name {
                    None => {
                        if size.is_some() {
                            return err("EISDIR", "is a directory");
                        }
                        loc.dir
                    }
                    Some(n) => openat(
                        &loc.dir,
                        cstr(n)?.as_c_str(),
                        access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .ctx()?,
                };
                &owned
            }
            (None, None) => return err("EINVAL", "setattr needs a path or a handle"),
        };
        let st = fstat(fd).ctx()?;
        let k = match kind_of(&st) {
            Some(Kind::Symlink) | None => return err("ENOTSUP", "not supported on this entry"),
            Some(k) => k,
        };
        if st.st_dev as u64 != share.dev {
            return err("ENOENT", "no such file or directory");
        }
        if let Kind::File = k {
            if st.st_nlink as u64 > 1 {
                return err(
                    "EPERM",
                    "this file has other hard links and is not writable",
                );
            }
        }
        if let Some(sz) = size {
            ftruncate(fd, sz).ctx()?;
        }
        if let Some(m) = new_mode {
            // Permission bits only, and never setuid, setgid, sticky.
            rustix::fs::fchmod(fd, mode_of((m as u32) & 0o777)).ctx()?;
        }
        if atime.is_some() || mtime.is_some() {
            let omit = Timespec {
                tv_sec: 0,
                tv_nsec: UTIME_OMIT as _,
            };
            let ts = |v: Option<f64>| match v {
                Some(ms) => Timespec {
                    tv_sec: (ms / 1000.0).floor() as i64,
                    tv_nsec: ((ms % 1000.0 + 1000.0) % 1000.0 * 1_000_000.0) as _,
                },
                None => omit,
            };
            futimens(
                fd,
                &Timestamps {
                    last_access: ts(atime),
                    last_modification: ts(mtime),
                },
            )
            .ctx()?;
        }
        let st = fstat(fd).ctx()?;
        Ok(attr_of(&st, &k))
    }
}

fn mode_of(bits: u32) -> Mode {
    Mode::from_raw_mode(bits as _)
}

/// Open one directory on the way down a path, refusing a symlink (`O_NOFOLLOW`). What a symlink
/// answers differs by system (`ELOOP` or `ENOTDIR`), so a refusal is looked at to tell a symlink
/// (`ELOOP`) from a plain file (`ENOTDIR`).
fn open_dir_component(dir: &OwnedFd, name: &str) -> R<OwnedFd> {
    let c = cstr(name)?;
    match openat(
        dir,
        c.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(fd),
        Err(e) if e == Errno::NOTDIR || e == Errno::LOOP => {
            match statat(dir, c.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) if FileType::from_raw_mode(st.st_mode as _) == FileType::Symlink => {
                    Err(from_errno(Errno::LOOP))
                }
                _ => Err(from_errno(e)),
            }
        }
        Err(e) => Err(from_errno(e)),
    }
}

/// The mode for a new file or directory: what was asked, limited to `0o755`'s bits.
fn create_mode(asked: Option<u32>, default: u32) -> u32 {
    asked.unwrap_or(default) & 0o755
}

fn pread_full(fd: &OwnedFd, buf: &mut [u8], offset: u64) -> R<usize> {
    let mut got = 0;
    while got < buf.len() {
        match rustix::io::pread(fd.as_fd(), &mut buf[got..], offset + got as u64) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e == Errno::INTR => {}
            Err(e) => return Err(from_errno(e)),
        }
    }
    Ok(got)
}

#[derive(Default, Debug)]
struct Flags {
    read: bool,
    write: bool,
    create: bool,
    excl: bool,
    trunc: bool,
}

impl Flags {
    fn parse(list: &[String]) -> R<Flags> {
        let mut f = Flags::default();
        for s in list {
            match s.as_str() {
                "read" => f.read = true,
                "write" => f.write = true,
                "create" => f.create = true,
                "excl" => f.excl = true,
                "trunc" => f.trunc = true,
                _ => return err("EINVAL", "unknown open flag"),
            }
        }
        Ok(f)
    }
}

/// Open every share named on the command line, printing what is shared and how (once).
pub fn open_all(specs: &[ShareSpec]) -> Result<Vec<Share>, String> {
    let mut out: Vec<Share> = Vec::new();
    for s in specs {
        if out.iter().any(|o| o.name == s.name) {
            return Err(format!("--share {}: the name is used twice", s.name));
        }
        out.push(Share::open(s)?);
    }
    Ok(out)
}

pub fn describe(s: &Share) -> String {
    format!(
        "sharing {:?} = {} ({})",
        s.name,
        s.root_path.display(),
        if s.writable {
            "read-write"
        } else {
            "read-only"
        }
    )
}

#[cfg(test)]
mod tests;
