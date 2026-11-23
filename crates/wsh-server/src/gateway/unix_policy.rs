//! Which unix-domain socket paths may a client reach on (or create on) this host?
//!
//! The same policy as the Node host (`src/server/unix-policy.mjs`): default deny, nothing unless the
//! operator listed it. A pattern is an absolute path, exact (`/var/run/docker.sock`) or a directory prefix
//! with a trailing slash (`/run/user/1000/wsh/`), or, for the Linux abstract namespace, `@name` /
//! `@prefix/`. A requested path is accepted only when, AFTER the parent directory has been resolved with
//! `realpath`, it equals an exact pattern or lies under a prefix (patterns are resolved the same way, so
//! `/var/run` and `/private/var/run` agree). The file itself must be a socket and not a symlink. A `..`
//! segment is refused outright. This closes the "allowed directory contains a symlink to somewhere else"
//! escape; it cannot close the window between the check and the connect (the path is connected by its
//! resolved name, which narrows it), so allow only directories no other local user can write to.

use std::path::{Path, PathBuf};

/// Longest path or pattern accepted.
const MAX_PATH: usize = 4096;
/// Marks a Linux abstract-namespace socket name in a pattern or request.
pub const ABSTRACT_PREFIX: char = '@';

/// The `[gateway] unix_*` settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnixPolicy {
    /// Sockets a client may connect to (`OpenUnix`).
    pub connect: Vec<String>,
    /// Sockets a client may ask this host to create (`ListenUnix`).
    pub listen: Vec<String>,
    /// A client may ask to replace a stale socket file (OpenSSH `StreamLocalBindUnlink`).
    pub replace_stale: bool,
    /// Unix listeners per client connection.
    pub max_listeners: usize,
}

/// Default for [`UnixPolicy::max_listeners`].
pub const DEFAULT_MAX_UNIX_LISTENERS: usize = 4;

impl UnixPolicy {
    /// Validate the patterns the way the Node host does, so a bad configuration fails at start-up.
    pub fn new(
        connect: Vec<String>,
        listen: Vec<String>,
        replace_stale: bool,
        max_listeners: usize,
    ) -> Result<Self, String> {
        for (what, list) in [("unix_connect", &connect), ("unix_listen", &listen)] {
            for p in list {
                check_pattern(p).map_err(|e| format!("[gateway] {what}: {e}"))?;
            }
        }
        Ok(Self {
            connect,
            listen,
            replace_stale,
            max_listeners,
        })
    }

    /// Is any unix socket reachable at all? (What decides whether `gateway-unix` is advertised.)
    pub fn is_enabled(&self) -> bool {
        !self.connect.is_empty() || !self.listen.is_empty()
    }
}

fn check_pattern(p: &str) -> Result<(), String> {
    let shown = || format!("{:?}", p.chars().take(80).collect::<String>());
    if p.is_empty() || p.contains('\0') || p.len() > MAX_PATH {
        return Err(format!("bad pattern {}", shown()));
    }
    if !p.starts_with('/') && !p.starts_with(ABSTRACT_PREFIX) {
        return Err(format!(
            "{} must be an absolute path or an abstract name starting with \"@\"",
            shown()
        ));
    }
    if p == "/" || p == "@" || p == "@/" {
        return Err(format!(
            "{} would allow everything; list a specific path or directory",
            shown()
        ));
    }
    if p.split('/').any(|seg| seg == "..") {
        return Err(format!("{} must not contain \"..\"", shown()));
    }
    Ok(())
}

/// What an allowed request resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixTarget {
    /// A file-system socket, by its resolved path.
    Path(PathBuf),
    /// A Linux abstract-namespace socket (the name without the leading `@`).
    Abstract(String),
}

fn matches(pattern: &str, target: &str) -> bool {
    if pattern.ends_with('/') {
        target.starts_with(pattern)
    } else {
        target == pattern
    }
}

/// The pattern as the file system sees it today: its parent (or itself, for a prefix) through realpath.
/// `None` for a pattern whose directory does not exist: it matches nothing.
async fn resolve_pattern(p: &str) -> Option<String> {
    if p.ends_with('/') {
        let real = tokio::fs::canonicalize(p).await.ok()?;
        return Some(format!("{}/", real.to_string_lossy().trim_end_matches('/')));
    }
    let path = Path::new(p);
    let real = tokio::fs::canonicalize(path.parent()?).await.ok()?;
    Some(real.join(path.file_name()?).to_string_lossy().into_owned())
}

const NOT_ALLOWED: &str = "path not allowed by the gateway policy";

/// Check `requested` against `patterns`. `Ok` is what to connect to or bind: the resolved path, or the
/// abstract name.
pub async fn check_unix_path(requested: &str, patterns: &[String]) -> Result<UnixTarget, String> {
    if requested.is_empty()
        || requested.len() > MAX_PATH
        || requested.char_indices().any(|(i, c)| c == '\0' && i > 0)
    {
        return Err("malformed path".into());
    }
    // Abstract namespace: refused unless a pattern lists it; there is no file system to resolve.
    if requested.starts_with(ABSTRACT_PREFIX) || requested.starts_with('\0') {
        let name = format!("{ABSTRACT_PREFIX}{}", &requested[1..]);
        if name.len() < 2 || name.split('/').any(|s| s == "..") {
            return Err("malformed path".into());
        }
        let listed = patterns
            .iter()
            .any(|p| p.starts_with(ABSTRACT_PREFIX) && matches(p, &name));
        if !listed {
            return Err(NOT_ALLOWED.into());
        }
        if !cfg!(target_os = "linux") {
            return Err("abstract unix sockets exist only on Linux".into());
        }
        return Ok(UnixTarget::Abstract(name[1..].to_string()));
    }
    if !requested.starts_with('/') || requested.split('/').any(|s| s == "..") {
        return Err("path must be absolute and without \"..\"".into());
    }
    if requested.ends_with('/') {
        return Err("malformed path".into());
    }
    let path = Path::new(requested);
    let (Some(parent), Some(base)) = (path.parent(), path.file_name()) else {
        return Err("malformed path".into());
    };
    let Ok(real_parent) = tokio::fs::canonicalize(parent).await else {
        return Err(NOT_ALLOWED.into());
    };
    let resolved = real_parent.join(base);
    let resolved_str = resolved.to_string_lossy().into_owned();
    for p in patterns {
        if p.starts_with(ABSTRACT_PREFIX) {
            continue;
        }
        if let Some(rp) = resolve_pattern(p).await {
            if matches(&rp, &resolved_str) {
                return Ok(UnixTarget::Path(resolved));
            }
        }
    }
    Err(NOT_ALLOWED.into())
}

/// What `lstat` says about an allowed path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketStat {
    pub is_socket: bool,
    pub ino: u64,
    pub dev: u64,
}

/// `lstat`: `None` when absent (a symlink is never a socket here).
#[cfg(unix)]
pub async fn stat_socket(p: &Path) -> std::io::Result<Option<SocketStat>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match tokio::fs::symlink_metadata(p).await {
        Ok(m) => Ok(Some(SocketStat {
            is_socket: m.file_type().is_socket(),
            ino: m.ino(),
            dev: m.dev(),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
pub async fn stat_socket(_p: &Path) -> std::io::Result<Option<SocketStat>> {
    Ok(None)
}

/// Remove `p` if it is still the socket we made (same inode), never someone else's.
pub fn unlink_if_socket_sync(p: &Path, expect: Option<SocketStat>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let Ok(m) = std::fs::symlink_metadata(p) else {
            return;
        };
        if !m.file_type().is_socket() {
            return;
        }
        if let Some(e) = expect {
            if m.ino() != e.ino || m.dev() != e.dev {
                return;
            }
        }
        let _ = std::fs::remove_file(p);
    }
    #[cfg(not(unix))]
    {
        let _ = (p, expect);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    fn tmp() -> tempdir::Dir {
        tempdir::Dir::new()
    }

    /// A scratch directory that removes itself (this crate has no tempfile dependency).
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!(
                    "wup-{}-{}",
                    std::process::id(),
                    rand::random::<u16>()
                ));
                std::fs::create_dir_all(&p).unwrap();
                Self(std::fs::canonicalize(p).unwrap())
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn patterns_that_would_allow_too_much_are_refused_at_start_up() {
        for bad in ["/", "@", "@/", "relative/x", "", "/a/../b", "/a\0b"] {
            assert!(
                UnixPolicy::new(vec![bad.into()], vec![], false, 4).is_err(),
                "{bad:?} should be refused"
            );
            assert!(UnixPolicy::new(vec![], vec![bad.into()], false, 4).is_err());
        }
        assert!(UnixPolicy::new(
            vec![
                "/var/run/docker.sock".into(),
                "/run/x/".into(),
                "@abs".into()
            ],
            vec![],
            false,
            4
        )
        .is_ok());
    }

    #[tokio::test]
    async fn nothing_is_allowed_by_default() {
        let d = tmp();
        let p = s(&d.path().join("a.sock"));
        assert!(check_unix_path(&p, &[]).await.is_err());
    }

    #[tokio::test]
    async fn an_exact_path_and_a_directory_prefix_match() {
        let d = tmp();
        let exact = s(&d.path().join("a.sock"));
        let other = s(&d.path().join("b.sock"));
        let ok = check_unix_path(&exact, &[exact.clone()]).await.unwrap();
        assert_eq!(ok, UnixTarget::Path(d.path().join("a.sock")));
        assert!(check_unix_path(&other, &[exact.clone()]).await.is_err());
        let prefix = format!("{}/", d.path().display());
        assert!(check_unix_path(&other, &[prefix]).await.is_ok());
    }

    #[tokio::test]
    async fn a_prefix_does_not_match_a_sibling_with_the_same_leading_name() {
        let d = tmp();
        std::fs::create_dir(d.path().join("sock")).unwrap();
        std::fs::create_dir(d.path().join("sock-evil")).unwrap();
        let prefix = format!("{}/", d.path().join("sock").display());
        let evil = s(&d.path().join("sock-evil").join("x"));
        assert!(check_unix_path(&evil, &[prefix]).await.is_err());
    }

    #[tokio::test]
    async fn dotdot_relative_and_directory_paths_are_refused() {
        let d = tmp();
        let prefix = format!("{}/", d.path().display());
        for bad in [
            format!("{}/sub/../a.sock", d.path().display()),
            "a.sock".to_string(),
            format!("{}/", d.path().display()),
            String::new(),
        ] {
            assert!(
                check_unix_path(&bad, &[prefix.clone()]).await.is_err(),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_symlinked_directory_cannot_lead_out_of_the_allowed_one() {
        let allowed = tmp();
        let outside = tmp();
        symlink(outside.path(), allowed.path().join("out")).unwrap();
        let prefix = format!("{}/", allowed.path().display());
        let sneaky = s(&allowed.path().join("out").join("x.sock"));
        assert!(check_unix_path(&sneaky, &[prefix]).await.is_err());
        // Listing the symlinked name as the pattern resolves to the real place, which is fine.
        let via_link = format!("{}/", allowed.path().join("out").display());
        assert!(
            check_unix_path(&s(&outside.path().join("x.sock")), &[via_link])
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_symlink_to_a_socket_is_not_a_socket() {
        let allowed = tmp();
        let outside = tmp();
        let real = outside.path().join("real.sock");
        let _l = UnixListener::bind(&real).unwrap();
        let link = allowed.path().join("link.sock");
        symlink(&real, &link).unwrap();
        let st = stat_socket(&link).await.unwrap().unwrap();
        assert!(!st.is_socket, "lstat must not follow the link");
        assert!(stat_socket(&real).await.unwrap().unwrap().is_socket);
        assert!(stat_socket(&allowed.path().join("nope"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn the_abstract_namespace_is_refused_unless_listed() {
        assert_eq!(
            check_unix_path("@docker", &[]).await.unwrap_err(),
            NOT_ALLOWED
        );
        assert_eq!(
            check_unix_path("@docker", &["/tmp/x".into()])
                .await
                .unwrap_err(),
            NOT_ALLOWED
        );
        let r = check_unix_path("@docker", &["@docker".into()]).await;
        if cfg!(target_os = "linux") {
            assert_eq!(r.unwrap(), UnixTarget::Abstract("docker".into()));
        } else {
            assert!(r.is_err());
        }
        assert!(check_unix_path("@a/../b", &["@a/".into()]).await.is_err());
    }

    #[test]
    fn unlink_removes_only_the_socket_that_was_ours() {
        let d = tmp();
        let p = d.path().join("m.sock");
        let l = UnixListener::bind(&p).unwrap();
        let mine = {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::symlink_metadata(&p).unwrap();
            SocketStat {
                is_socket: true,
                ino: m.ino(),
                dev: m.dev(),
            }
        };
        // A different inode at the same path: leave it.
        unlink_if_socket_sync(
            &p,
            Some(SocketStat {
                ino: mine.ino + 1,
                ..mine
            }),
        );
        assert!(p.exists());
        unlink_if_socket_sync(&p, Some(mine));
        assert!(!p.exists());
        drop(l);
        // A regular file is never removed.
        let f = d.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        unlink_if_socket_sync(&f, None);
        assert!(f.exists());
    }
}
