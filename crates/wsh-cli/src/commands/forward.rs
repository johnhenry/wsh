//! `wsh -L` / `-R` / `-N`: port, unix-socket and named-endpoint forwarding through the host,
//! modelled on OpenSSH.
//!
//! ```text
//! wsh -L [bind_addr:]port:host:hostport   local TCP port   -> the HOST connects to host:hostport
//! wsh -L /local.sock:/remote.sock         local unix socket-> a unix socket on the host
//! wsh -L [bind_addr:]port:/remote.sock    local TCP port   -> a unix socket on the host
//! wsh -L /local.sock:host:hostport        local unix socket-> the HOST connects to host:hostport
//! wsh -L ...:endpoint=NAME                either local end -> the host's NAMED endpoint NAME
//!
//! wsh -R [bind_addr:]port:host:hostport   the HOST listens   -> we connect to host:hostport
//! wsh -R /remote.sock:/local.sock         the HOST listens on a unix socket -> a local socket
//! wsh -R /remote.sock:host:hostport       the HOST listens on a unix socket -> local host:hostport
//! wsh -R [bind_addr:]port:/local.sock     the HOST listens   -> a local unix socket
//! ```
//!
//! `-N` forwards without running a command; several `-L`/`-R` can be given. A named endpoint is
//! written `endpoint=NAME` (the `=` cannot occur in a host name, a port or a path, so it can never
//! be confused with a host called "endpoint", and `@NAME` already means an abstract-namespace unix
//! socket). Local unix sockets are created 0600, an existing socket file is refused unless
//! `--replace-socket` is given (and then only a stale one is replaced), and they are removed on
//! exit. Local TCP listeners bind loopback unless `bind_addr` says otherwise.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use wsh_client::gateway::{
    valid_endpoint_name, WatchablePeer, DEFAULT_HALF_CLOSE_IDLE, DEFAULT_HALF_CLOSE_PROBE,
};
use wsh_client::{GatewayHandle, WshClient};

/// How many forwarded connections may be open at once, per `wsh` process.
const MAX_FORWARDED_CONNECTIONS: usize = 128;

/// Where the host connects to for a `-L` forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Tcp { host: String, port: u16 },
    Unix(String),
    Endpoint(String),
}

/// Where `wsh` listens for a `-L` forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalListen {
    Tcp { bind: String, port: u16 },
    Unix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub spec: String,
    pub listen: LocalListen,
    pub target: Target,
}

/// Where the host listens for a `-R` forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteListen {
    Tcp { bind: String, port: u16 },
    Unix(String),
}

/// What `wsh` connects to when the host hands it a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTarget {
    Tcp { host: String, port: u16 },
    Unix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub spec: String,
    pub listen: RemoteListen,
    pub target: LocalTarget,
}

#[derive(Debug, Clone, Default)]
pub struct ForwardConfig {
    pub locals: Vec<Local>,
    pub remotes: Vec<Remote>,
    /// `--replace-socket`.
    pub replace: bool,
}

impl ForwardConfig {
    pub fn is_empty(&self) -> bool {
        self.locals.is_empty() && self.remotes.is_empty()
    }

    /// Parse the command-line specs, all of them, so every mistake is reported at once.
    pub fn parse(locals: &[String], remotes: &[String], replace: bool) -> Result<Self> {
        let mut errors = Vec::new();
        let mut cfg = ForwardConfig {
            replace,
            ..Default::default()
        };
        for s in locals {
            match parse_local(s) {
                Ok(l) => cfg.locals.push(l),
                Err(e) => errors.push(format!("-L {s}: {e}")),
            }
        }
        for s in remotes {
            match parse_remote(s) {
                Ok(r) => cfg.remotes.push(r),
                Err(e) => errors.push(format!("-R {s}: {e}")),
            }
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("\n"));
        }
        Ok(cfg)
    }
}

/// Split on `:` except inside `[...]` (an IPv6 literal).
fn tokens(spec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0;
    for c in spec.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ':' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn port(s: &str, what: &str) -> Result<u16, String> {
    match s.parse::<u16>() {
        Ok(p) => Ok(p),
        Err(_) => Err(format!("{what} {s:?} is not a port (0-65535)")),
    }
}

fn nonzero_port(s: &str, what: &str) -> Result<u16, String> {
    match port(s, what)? {
        0 => Err(format!("{what} must not be 0")),
        p => Ok(p),
    }
}

fn host_ok(h: &str) -> Result<String, String> {
    if h.is_empty() {
        return Err("empty host".into());
    }
    Ok(h.trim_start_matches('[').trim_end_matches(']').to_string())
}

fn local_unix_ok(p: &str) -> Result<String, String> {
    if p.starts_with('@') {
        return Err(format!(
            "{p:?}: a local abstract-namespace socket is not supported; use a path"
        ));
    }
    if p.contains('\0') || p.len() > 4096 {
        return Err("bad socket path".into());
    }
    Ok(p.to_string())
}

const USAGE_L: &str = "expected [bind_addr:]port:host:hostport, /local.sock:/remote.sock, \
[bind_addr:]port:/remote.sock, /local.sock:host:hostport, or either local end with \
:endpoint=NAME";
const USAGE_R: &str = "expected [bind_addr:]port:host:hostport, /remote.sock:/local.sock, \
/remote.sock:host:hostport, or [bind_addr:]port:/local.sock";

/// Parse a `-L` spec.
pub fn parse_local(spec: &str) -> Result<Local, String> {
    let t = tokens(spec);
    if t.len() < 2 {
        return Err(USAGE_L.into());
    }
    let n = t.len();
    let last = &t[n - 1];
    // The end the HOST connects to.
    let (target, head) = if let Some(name) = last.strip_prefix("endpoint=") {
        if !valid_endpoint_name(name) {
            return Err(format!(
                "{name:?} is not a valid endpoint name (letters, digits, \".\", \"_\", \"-\"; at most 64)"
            ));
        }
        (Target::Endpoint(name.to_string()), &t[..n - 1])
    } else if last.starts_with('/') || last.starts_with('@') {
        (Target::Unix(last.clone()), &t[..n - 1])
    } else {
        if n < 3 {
            return Err(USAGE_L.into());
        }
        let host = host_ok(&t[n - 2])?;
        let p = nonzero_port(last, "the remote port")?;
        (Target::Tcp { host, port: p }, &t[..n - 2])
    };
    // The end we listen on.
    let listen = match head {
        [only] if only.starts_with('/') => LocalListen::Unix(local_unix_ok(only)?),
        [p] => LocalListen::Tcp {
            bind: "127.0.0.1".into(),
            port: port(p, "the local port")?,
        },
        [bind, p] => LocalListen::Tcp {
            bind: host_ok(bind)?,
            port: port(p, "the local port")?,
        },
        _ => return Err(USAGE_L.into()),
    };
    Ok(Local {
        spec: spec.to_string(),
        listen,
        target,
    })
}

/// Parse a `-R` spec.
pub fn parse_remote(spec: &str) -> Result<Remote, String> {
    let t = tokens(spec);
    if t.len() < 2 {
        return Err(USAGE_R.into());
    }
    if t.last().is_some_and(|l| l.starts_with("endpoint=")) {
        return Err(
            "a named endpoint is something a host offers; the host cannot listen on one".into(),
        );
    }
    let n = t.len();
    let last = &t[n - 1];
    let (target, head) = if last.starts_with('/') {
        (LocalTarget::Unix(local_unix_ok(last)?), &t[..n - 1])
    } else if last.starts_with('@') {
        return Err(format!(
            "{last:?}: a local abstract-namespace socket is not supported; use a path"
        ));
    } else {
        if n < 3 {
            return Err(USAGE_R.into());
        }
        (
            LocalTarget::Tcp {
                host: host_ok(&t[n - 2])?,
                port: nonzero_port(last, "the local port")?,
            },
            &t[..n - 2],
        )
    };
    let listen = match head {
        [only] if only.starts_with('/') || only.starts_with('@') => {
            RemoteListen::Unix(only.clone())
        }
        [p] => RemoteListen::Tcp {
            bind: "127.0.0.1".into(),
            port: port(p, "the remote port")?,
        },
        [bind, p] => RemoteListen::Tcp {
            bind: host_ok(bind)?,
            port: port(p, "the remote port")?,
        },
        _ => return Err(USAGE_R.into()),
    };
    Ok(Remote {
        spec: spec.to_string(),
        listen,
        target,
    })
}

// ── process-wide state ───────────────────────────────────────────────

static CONFIG: OnceLock<ForwardConfig> = OnceLock::new();

/// Remember the forwards to start once the connection is up. A process-wide value, as `--via`
/// is, so `connect` and `wsh host command` get them without another argument each.
pub fn set(config: ForwardConfig) {
    let _ = CONFIG.set(config);
}

/// Sockets this process created, so they can be removed on the way out.
fn created() -> &'static Mutex<Vec<(PathBuf, Option<(u64, u64)>)>> {
    static CREATED: OnceLock<Mutex<Vec<(PathBuf, Option<(u64, u64)>)>>> = OnceLock::new();
    CREATED.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(unix)]
fn identity(p: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(p)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn identity(_p: &Path) -> Option<(u64, u64)> {
    None
}

/// A fresh private (`0700`) directory next to `path`, for a socket being bound or a file being
/// moved aside.
#[cfg(unix)]
fn scratch_dir(path: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let parent = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dir = parent.join(format!(
        ".w{:x}.{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// Remove `path` only while it is the socket `id` names: checked, then moved into a private
/// directory and checked again there before it is unlinked, so a file put at the name between the
/// first check and the removal is not deleted (it is put back, never replacing anything newer).
/// Returns whether `path` was removed.
#[cfg(unix)]
fn remove_if_identity(path: &Path, id: (u64, u64)) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let ours = |m: &std::fs::Metadata| m.file_type().is_socket() && (m.dev(), m.ino()) == id;
    match std::fs::symlink_metadata(path) {
        Ok(m) if ours(&m) => {}
        _ => return false,
    }
    let Ok(aside) = scratch_dir(path) else {
        return false;
    };
    let held = aside.join("x");
    let removed = if std::fs::rename(path, &held).is_err() {
        false
    } else {
        match std::fs::symlink_metadata(&held) {
            Ok(m) if ours(&m) => {
                let _ = std::fs::remove_file(&held);
                true
            }
            Ok(_) => {
                // A stranger took the name in that instant: give it back.
                let back = std::fs::hard_link(&held, path).is_ok()
                    || (std::fs::symlink_metadata(path).is_err()
                        && std::fs::rename(&held, path).is_ok());
                if back {
                    let _ = std::fs::remove_file(&held);
                } else {
                    eprintln!(
                        "wsh: {} was replaced while it was being removed; the replacement is kept at {}",
                        path.display(),
                        held.display()
                    );
                }
                false
            }
            Err(_) => false,
        }
    };
    let _ = std::fs::remove_dir(&aside); // not empty only when something is being kept there
    removed
}

#[cfg(not(unix))]
fn remove_if_identity(_path: &Path, _id: (u64, u64)) -> bool {
    false
}

/// Remove the local socket files this process created (and only those: the inode must still be
/// ours). Called before every exit.
pub fn cleanup() {
    let list = std::mem::take(&mut *created().lock().expect("created"));
    for (path, id) in list {
        if let Some(id) = id {
            remove_if_identity(&path, id);
        }
    }
}

// ── local unix sockets ───────────────────────────────────────────────

/// Create the listening socket for `path`: private from the first instant, an existing file
/// refused unless `replace` and then only a stale socket. The process umask is never touched (it
/// is process-wide, and a file another thread makes in that instant gets the wrong mode): the
/// socket is bound inside a fresh `0700` directory next to `path`, set to `0600` there, and then
/// hard-linked to its name, which fails if something appeared at that name meanwhile. The same
/// scheme as the server's `bind_private`.
#[cfg(unix)]
pub fn bind_local_unix(path: &str, replace: bool) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let p = Path::new(path);
    match std::fs::symlink_metadata(p) {
        Ok(m) => {
            if !m.file_type().is_socket() {
                bail!("{path} exists and is not a socket");
            }
            if !replace {
                bail!("{path} already exists (use --replace-socket to replace a stale socket)");
            }
            // Only a socket nothing is listening on.
            if std::os::unix::net::UnixStream::connect(p).is_ok() {
                bail!("{path} is in use by another process");
            }
            // The socket that was looked at, not whatever is at the name by now.
            use std::os::unix::fs::MetadataExt;
            if !remove_if_identity(p, (m.dev(), m.ino())) {
                bail!("{path} changed while it was being checked; not replacing it");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot look at {path}")),
    }
    let staging = scratch_dir(p)
        .with_context(|| format!("cannot listen on {path}: no private directory next to it"))?;
    let inner = staging.join("s");
    let bound = (|| -> Result<(std::os::unix::net::UnixListener, Option<(u64, u64)>)> {
        let l = std::os::unix::net::UnixListener::bind(&inner)
            .with_context(|| format!("cannot listen on {path}"))?;
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict {path} to its owner"))?;
        // The identity of the socket itself (read before it has a public name), so that what is
        // recorded for removal can never be a file that took the name in between.
        let id = identity(&inner);
        std::fs::hard_link(&inner, p).with_context(|| format!("cannot listen on {path}"))?;
        Ok((l, id))
    })();
    let _ = std::fs::remove_file(&inner);
    let _ = std::fs::remove_dir(&staging);
    let (l, id) = bound?;
    created()
        .lock()
        .expect("created")
        .push((p.to_path_buf(), id));
    l.set_nonblocking(true)?;
    Ok(tokio::net::UnixListener::from_std(l)?)
}

// ── starting the forwards ────────────────────────────────────────────

/// Start every configured forward on `client`. Any that cannot be set up is an error: a
/// forward that silently does not exist is worse than none.
pub async fn start_configured(client: &WshClient) -> Result<()> {
    let Some(cfg) = CONFIG.get() else {
        return Ok(());
    };
    if cfg.is_empty() {
        return Ok(());
    }
    let handle = client.gateway();
    let gate = Arc::new(Semaphore::new(MAX_FORWARDED_CONNECTIONS));
    for l in &cfg.locals {
        start_local(&handle, l.clone(), cfg.replace, gate.clone()).await?;
    }
    for r in &cfg.remotes {
        start_remote(&handle, r.clone(), cfg.replace, gate.clone()).await?;
    }
    Ok(())
}

fn describe_target(t: &Target) -> String {
    match t {
        Target::Tcp { host, port } => format!("{host}:{port}"),
        Target::Unix(p) => p.clone(),
        Target::Endpoint(n) => format!("endpoint {n}"),
    }
}

async fn open_target(
    handle: &GatewayHandle,
    t: &Target,
) -> wsh_client::WshResult<wsh_client::GatewayStream> {
    match t {
        Target::Tcp { host, port } => handle.open_tcp(host, *port).await,
        Target::Unix(path) => handle.open_unix(path).await,
        Target::Endpoint(name) => handle.open_endpoint(name).await,
    }
}

async fn start_local(
    handle: &GatewayHandle,
    l: Local,
    replace: bool,
    gate: Arc<Semaphore>,
) -> Result<()> {
    let what = describe_target(&l.target);
    match l.listen.clone() {
        LocalListen::Tcp { bind, port } => {
            let bind_addr = if bind == "*" {
                "0.0.0.0".to_string()
            } else {
                bind.clone()
            };
            let listener = TcpListener::bind((bind_addr.as_str(), port))
                .await
                .with_context(|| format!("-L {}: cannot listen on {bind_addr}:{port}", l.spec))?;
            let local = listener.local_addr()?;
            if !local.ip().is_loopback() {
                eprintln!(
                    "wsh: warning: -L {} listens on {local}, which other machines can reach; anyone who can connect uses this forward",
                    l.spec
                );
            }
            eprintln!("wsh: forwarding {local} -> {what} (through the host)");
            let handle = handle.clone();
            let spec = l.spec.clone();
            let target = l.target.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    };
                    let _ = sock.set_nodelay(true);
                    spawn_forward(&handle, &spec, &target, &gate, sock);
                }
            });
        }
        #[cfg(unix)]
        LocalListen::Unix(path) => {
            let listener =
                bind_local_unix(&path, replace).with_context(|| format!("-L {}", l.spec))?;
            eprintln!("wsh: forwarding {path} -> {what} (through the host)");
            let handle = handle.clone();
            let spec = l.spec.clone();
            let target = l.target.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    };
                    spawn_forward(&handle, &spec, &target, &gate, sock);
                }
            });
        }
        #[cfg(not(unix))]
        LocalListen::Unix(_) => {
            let _ = replace;
            bail!(
                "-L {}: local unix sockets are not available on this platform",
                l.spec
            );
        }
    }
    Ok(())
}

/// Join a forwarded connection (`-L`) to the local socket of the program that dialled it. A
/// local program that half-closed and then went away (killed, crashed) is noticed from the
/// socket's hang-up and the host is told the connection is discarded, instead of holding it until
/// the far side next sends (wsh #282); not covered on Windows, where this is a plain pump. Only for
/// the program that CONNECTED and reads the answer: a `-R`'s local service is not watched, since a
/// service that finished and closed completely is the normal end of a response.
async fn pump_local<S>(
    stream: wsh_client::gateway::GatewayStream,
    local: S,
) -> std::io::Result<(u64, u64)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static + WatchablePeer,
{
    stream
        .pump_watched(
            local,
            Some(DEFAULT_HALF_CLOSE_IDLE),
            Some(DEFAULT_HALF_CLOSE_PROBE),
        )
        .await
}

/// Open the remote end for an accepted local connection and join the two.
fn spawn_forward<S>(
    handle: &GatewayHandle,
    spec: &str,
    target: &Target,
    gate: &Arc<Semaphore>,
    local: S,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static + WatchablePeer,
{
    let Ok(permit) = gate.clone().try_acquire_owned() else {
        eprintln!(
            "wsh: forward {spec}: more than {MAX_FORWARDED_CONNECTIONS} connections are open; refusing another"
        );
        return;
    };
    let handle = handle.clone();
    let spec = spec.to_string();
    let target = target.clone();
    tokio::spawn(async move {
        let _permit = permit;
        match open_target(&handle, &target).await {
            Ok(stream) => {
                let _ = pump_local(stream, local).await;
            }
            Err(e) => eprintln!("wsh: forward {spec} -> {}: {e}", describe_target(&target)),
        }
    });
}

async fn start_remote(
    handle: &GatewayHandle,
    r: Remote,
    replace: bool,
    gate: Arc<Semaphore>,
) -> Result<()> {
    let (mut listener, shown) = match &r.listen {
        RemoteListen::Unix(path) => (
            handle
                .listen_unix(path, replace)
                .await
                .map_err(|e| anyhow::anyhow!("-R {}: {e}", r.spec))?,
            path.clone(),
        ),
        RemoteListen::Tcp { bind, port } => {
            let l = handle
                .listen_tcp(*port, bind)
                .await
                .map_err(|e| anyhow::anyhow!("-R {}: {e}", r.spec))?;
            let shown = format!("port {}", l.actual_port());
            (l, shown)
        }
    };
    eprintln!(
        "wsh: the host is listening on {shown} -> {} (this machine)",
        match &r.target {
            LocalTarget::Tcp { host, port } => format!("{host}:{port}"),
            LocalTarget::Unix(p) => p.clone(),
        }
    );
    let target = r.target.clone();
    let spec = r.spec.clone();
    tokio::spawn(async move {
        while let Some(pending) = listener.next().await {
            let Ok(permit) = gate.clone().try_acquire_owned() else {
                pending.reject("too many connections").await;
                continue;
            };
            let target = target.clone();
            let spec = spec.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match connect_local(&target).await {
                    // The local end of a `-R` is a service that answers: it is not watched (a service that
                    // finished and closed completely is the ordinary end of a response, and the caller may
                    // still be reading it; see `pump_local`).
                    Ok(Local_::Tcp(sock)) => {
                        if let Ok(stream) = pending.accept().await {
                            let _ = stream.pump(sock).await;
                        }
                    }
                    #[cfg(unix)]
                    Ok(Local_::Unix(sock)) => {
                        if let Ok(stream) = pending.accept().await {
                            let _ = stream.pump(sock).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("wsh: forward -R {spec}: cannot reach the local end: {e}");
                        pending.reject("local end unreachable").await;
                    }
                }
            });
        }
    });
    Ok(())
}

#[allow(non_camel_case_types)]
enum Local_ {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

async fn connect_local(t: &LocalTarget) -> std::io::Result<Local_> {
    match t {
        LocalTarget::Tcp { host, port } => {
            let s = TcpStream::connect((host.as_str(), *port)).await?;
            let _ = s.set_nodelay(true);
            Ok(Local_::Tcp(s))
        }
        #[cfg(unix)]
        LocalTarget::Unix(path) => Ok(Local_::Unix(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(not(unix))]
        LocalTarget::Unix(_) => Err(std::io::Error::other(
            "local unix sockets are not available on this platform",
        )),
    }
}

/// `wsh -N [user@]host`: connect, start the forwards, and wait.
pub async fn run_forward_only(
    target: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
) -> Result<()> {
    use crate::commands::common::{connect_client, resolve_target};
    let resolved = resolve_target(target, port, transport)?;
    let client = connect_client(&resolved, identity).await?;
    wait_for_exit(&client).await;
    Ok(())
}

/// Wait for Ctrl-C, SIGTERM, SIGHUP or the loss of the connection.
async fn wait_for_exit(client: &WshClient) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        let mut hup = signal(SignalKind::hangup()).ok();
        let lost = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if !client.is_connected().await {
                    return;
                }
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async { match term.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending::<()>().await } } => {}
            _ = async { match hup.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending::<()>().await } } => {}
            () = lost => {
                eprintln!("wsh: the connection to the host was lost");
                cleanup();
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = client;
        let _ = tokio::signal::ctrl_c().await;
    }
    cleanup();
    let _ = client.disconnect().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(spec: &str) -> Local {
        parse_local(spec).unwrap_or_else(|e| panic!("{spec}: {e}"))
    }

    #[test]
    fn every_documented_l_form_parses() {
        assert_eq!(
            local("8080:db:5432"),
            Local {
                spec: "8080:db:5432".into(),
                listen: LocalListen::Tcp {
                    bind: "127.0.0.1".into(),
                    port: 8080
                },
                target: Target::Tcp {
                    host: "db".into(),
                    port: 5432
                },
            }
        );
        let l = local("0.0.0.0:8080:db.example.com:5432");
        assert_eq!(
            l.listen,
            LocalListen::Tcp {
                bind: "0.0.0.0".into(),
                port: 8080
            }
        );
        assert_eq!(
            l.target,
            Target::Tcp {
                host: "db.example.com".into(),
                port: 5432
            }
        );
        assert_eq!(
            local("/tmp/l.sock:/var/run/docker.sock"),
            Local {
                spec: "/tmp/l.sock:/var/run/docker.sock".into(),
                listen: LocalListen::Unix("/tmp/l.sock".into()),
                target: Target::Unix("/var/run/docker.sock".into()),
            }
        );
        let l = local("127.0.0.1:2375:/var/run/docker.sock");
        assert_eq!(
            l.listen,
            LocalListen::Tcp {
                bind: "127.0.0.1".into(),
                port: 2375
            }
        );
        assert_eq!(l.target, Target::Unix("/var/run/docker.sock".into()));
        let l = local("2375:/var/run/docker.sock");
        assert_eq!(
            l.listen,
            LocalListen::Tcp {
                bind: "127.0.0.1".into(),
                port: 2375
            }
        );
        let l = local("/tmp/l.sock:db:5432");
        assert_eq!(l.listen, LocalListen::Unix("/tmp/l.sock".into()));
        assert_eq!(
            l.target,
            Target::Tcp {
                host: "db".into(),
                port: 5432
            }
        );
    }

    #[test]
    fn ipv6_literals_keep_their_colons() {
        let l = local("[::1]:8080:[2001:db8::1]:443");
        assert_eq!(
            l.listen,
            LocalListen::Tcp {
                bind: "::1".into(),
                port: 8080
            }
        );
        assert_eq!(
            l.target,
            Target::Tcp {
                host: "2001:db8::1".into(),
                port: 443
            }
        );
    }

    #[test]
    fn a_named_endpoint_is_endpoint_equals_name_and_a_host_called_endpoint_is_still_a_host() {
        let l = local("/tmp/docker.sock:endpoint=docker");
        assert_eq!(l.listen, LocalListen::Unix("/tmp/docker.sock".into()));
        assert_eq!(l.target, Target::Endpoint("docker".into()));
        let l = local("2375:endpoint=docker.sock");
        assert_eq!(l.target, Target::Endpoint("docker.sock".into()));
        // A host that happens to be called "endpoint" (or an endpoint whose name is numeric).
        let l = local("8080:endpoint:80");
        assert_eq!(
            l.target,
            Target::Tcp {
                host: "endpoint".into(),
                port: 80
            }
        );
        let l = local("/tmp/x.sock:endpoint=8080");
        assert_eq!(l.target, Target::Endpoint("8080".into()));
        assert!(parse_local("/tmp/x.sock:endpoint=bad name").is_err());
        assert!(parse_local("/tmp/x.sock:endpoint=").is_err());
    }

    #[test]
    fn remote_abstract_sockets_are_a_target_but_local_ones_are_not() {
        assert_eq!(local("8080:@name").target, Target::Unix("@name".into()));
        assert!(parse_local("@name:/remote.sock").is_err());
    }

    #[test]
    fn malformed_l_specs_are_refused_readably() {
        for bad in [
            "",
            "8080",
            "8080:db",
            "db:5432",
            "x:db:5432",
            "8080:db:0",
            "8080:db:99999",
            "8080:db:x",
            "a:b:c:d:e",
            ":db:5432",
            "70000:db:5432",
        ] {
            let e = parse_local(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} should not parse"));
            assert!(!e.is_empty(), "{bad:?}");
        }
        assert!(parse_local("8080").unwrap_err().contains("expected"));
    }

    #[test]
    fn r_forms_parse() {
        let r = parse_remote("9000:localhost:3000").unwrap();
        assert_eq!(
            r.listen,
            RemoteListen::Tcp {
                bind: "127.0.0.1".into(),
                port: 9000
            }
        );
        assert_eq!(
            r.target,
            LocalTarget::Tcp {
                host: "localhost".into(),
                port: 3000
            }
        );
        let r = parse_remote("/run/app.sock:/tmp/local.sock").unwrap();
        assert_eq!(r.listen, RemoteListen::Unix("/run/app.sock".into()));
        assert_eq!(r.target, LocalTarget::Unix("/tmp/local.sock".into()));
        let r = parse_remote("/run/app.sock:localhost:3000").unwrap();
        assert_eq!(r.listen, RemoteListen::Unix("/run/app.sock".into()));
        let r = parse_remote("0.0.0.0:9000:/tmp/local.sock").unwrap();
        assert_eq!(
            r.listen,
            RemoteListen::Tcp {
                bind: "0.0.0.0".into(),
                port: 9000
            }
        );
        assert_eq!(r.target, LocalTarget::Unix("/tmp/local.sock".into()));
        assert!(parse_remote("/run/app.sock:endpoint=x")
            .unwrap_err()
            .contains("cannot listen"));
        assert!(parse_remote("9000:@abstract").is_err());
        assert!(parse_remote("9000").is_err());
    }

    #[test]
    fn all_mistakes_are_reported_together() {
        let e = ForwardConfig::parse(
            &["nope".into(), "8080:db:5432".into()],
            &["also-nope".into()],
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("-L nope") && e.contains("-R also-nope"), "{e}");
        let ok = ForwardConfig::parse(&["8080:db:5432".into()], &[], true).unwrap();
        assert!(ok.replace && !ok.is_empty());
    }

    #[cfg(unix)]
    mod unix_sockets {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;

        /// The created-sockets list is process-wide, so these tests take turns.
        static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        fn turn() -> std::sync::MutexGuard<'static, ()> {
            TURN.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// A socket file nothing can ever accept on: a stream socket that is bound and never put into
        /// the listening state. (A listener that is merely dropped is not the same: a child forked by
        /// another test in this binary at that instant holds a copy of the descriptor until it execs,
        /// the socket stays listening meanwhile, and the liveness probe rightly finds it in use.)
        fn stale_socket(p: &std::path::Path) {
            use std::os::unix::ffi::OsStrExt;
            let b = p.as_os_str().as_bytes();
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                assert!(fd >= 0);
                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as _;
                assert!(b.len() < addr.sun_path.len());
                for (i, c) in b.iter().enumerate() {
                    addr.sun_path[i] = *c as _;
                }
                let r = libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                assert_eq!(r, 0, "bind");
                libc::close(fd);
            }
        }

        fn names(d: &std::path::Path) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }

        fn dir() -> tempfile::TempDir {
            // Short, so the path fits a unix socket address.
            tempfile::Builder::new()
                .prefix("wf")
                .tempdir_in("/tmp")
                .unwrap()
        }

        #[tokio::test]
        async fn a_local_socket_is_private_and_removed_by_cleanup() {
            let _turn = turn();
            let d = dir();
            let p = d.path().join("a.sock");
            let l = bind_local_unix(p.to_str().unwrap(), false).unwrap();
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            drop(l);
            cleanup();
            assert!(!p.exists());
        }

        /// The process umask is process-wide: a bind that swaps it hands a file or directory another
        /// thread creates in that instant the wrong mode (a directory at `0600` cannot be entered).
        #[tokio::test]
        async fn binding_a_local_socket_never_changes_the_umask_other_threads_see() {
            use std::os::unix::fs::PermissionsExt;
            let _turn = turn();
            let d = dir();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let binder = {
                let (stop, root) = (stop.clone(), d.path().to_path_buf());
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(async {
                        let mut n = 0;
                        while !stop.load(std::sync::atomic::Ordering::Relaxed) && n < 20_000 {
                            let p = root.join(format!("s{n}.sock"));
                            drop(bind_local_unix(p.to_str().unwrap(), false).unwrap());
                            let _ = std::fs::remove_file(&p);
                            n += 1;
                        }
                    })
                })
            };
            for i in 0..20_000 {
                let sub = d.path().join(format!("d{i}"));
                std::fs::create_dir(&sub).unwrap();
                let mode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
                std::fs::remove_dir(&sub).unwrap();
                assert_eq!(
                    mode & 0o700,
                    0o700,
                    "a directory made while a socket was bound came out {mode:o}"
                );
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            binder.join().unwrap();
        }

        #[tokio::test]
        async fn an_existing_socket_file_is_refused_without_the_flag() {
            let _turn = turn();
            let d = dir();
            let p = d.path().join("b.sock");
            let _stale = std::os::unix::net::UnixListener::bind(&p).unwrap();
            let e = bind_local_unix(p.to_str().unwrap(), false)
                .err()
                .unwrap()
                .to_string();
            assert!(
                e.contains("already exists") && e.contains("--replace-socket"),
                "{e}"
            );
            assert!(p.exists(), "the file is untouched");
        }

        #[tokio::test]
        async fn with_the_flag_only_a_stale_socket_is_replaced() {
            let _turn = turn();
            let d = dir();
            let stale = d.path().join("stale.sock");
            stale_socket(&stale);
            assert!(stale.exists());
            let l = bind_local_unix(stale.to_str().unwrap(), true).unwrap();
            drop(l);
            cleanup();

            let live = d.path().join("live.sock");
            let _alive = std::os::unix::net::UnixListener::bind(&live).unwrap();
            let e = bind_local_unix(live.to_str().unwrap(), true)
                .err()
                .unwrap()
                .to_string();
            assert!(e.contains("in use"), "{e}");
            assert!(live.exists());
        }

        #[tokio::test]
        async fn a_file_that_is_not_a_socket_is_never_touched() {
            let _turn = turn();
            let d = dir();
            let p = d.path().join("plain");
            std::fs::write(&p, b"keep me").unwrap();
            for replace in [false, true] {
                let e = bind_local_unix(p.to_str().unwrap(), replace)
                    .err()
                    .unwrap()
                    .to_string();
                assert!(e.contains("not a socket"), "{e}");
            }
            assert_eq!(std::fs::read(&p).unwrap(), b"keep me");
        }

        #[tokio::test]
        async fn cleanup_leaves_a_socket_someone_else_put_there() {
            let _turn = turn();
            let d = dir();
            let p = d.path().join("c.sock");
            let l = bind_local_unix(p.to_str().unwrap(), false).unwrap();
            drop(l);
            // Moved aside, not deleted: a freed inode number can be handed out again (Linux does), which
            // would make "someone else's socket" look like ours.
            std::fs::rename(&p, d.path().join("ours-moved.sock")).unwrap();
            let _other = std::os::unix::net::UnixListener::bind(&p).unwrap();
            cleanup();
            assert!(
                p.exists(),
                "a different socket at the same path is not ours to remove"
            );
        }

        #[tokio::test]
        async fn cleanup_leaves_a_regular_file_someone_else_put_there_and_no_directory_behind() {
            let _turn = turn();
            let d = dir();
            let p = d.path().join("f.sock");
            drop(bind_local_unix(p.to_str().unwrap(), false).unwrap());
            std::fs::remove_file(&p).unwrap();
            std::fs::write(&p, b"not ours").unwrap();
            cleanup();
            assert_eq!(std::fs::read(&p).unwrap(), b"not ours");
            assert_eq!(names(d.path()), ["f.sock"], "no scratch directory is left");
        }

        #[tokio::test]
        async fn cleanup_removes_our_socket_and_leaves_nothing_else() {
            let _turn = turn();
            let d = dir();
            let p = d.path().join("g.sock");
            drop(bind_local_unix(p.to_str().unwrap(), false).unwrap());
            assert_eq!(names(d.path()), ["g.sock"], "bound, no scratch directory");
            cleanup();
            assert!(names(d.path()).is_empty());
        }

        #[tokio::test]
        async fn a_stale_socket_that_was_swapped_since_it_was_looked_at_is_not_removed() {
            use std::os::unix::fs::MetadataExt;
            let _turn = turn();
            let d = dir();
            let p = d.path().join("h.sock");
            stale_socket(&p);
            let looked_at = std::fs::symlink_metadata(&p).unwrap();
            let id = (looked_at.dev(), looked_at.ino());
            std::fs::rename(&p, d.path().join("moved.sock")).unwrap();
            let _live = std::os::unix::net::UnixListener::bind(&p).unwrap();
            assert!(
                !remove_if_identity(&p, id),
                "a different socket is not removed"
            );
            assert!(std::os::unix::net::UnixStream::connect(&p).is_ok());
            std::fs::remove_file(&p).unwrap();
            std::fs::write(&p, b"file").unwrap();
            assert!(!remove_if_identity(&p, id));
            assert_eq!(std::fs::read(&p).unwrap(), b"file");
            assert_eq!(names(d.path()), ["h.sock", "moved.sock"]);
            // and the one that was looked at is removed
            let moved = d.path().join("moved.sock");
            assert!(remove_if_identity(&moved, id));
            assert_eq!(names(d.path()), ["h.sock"]);
        }
    }
}
