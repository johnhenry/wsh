//! `--share NAME=/abs/dir[:ro|:rw]` (#159): offer directories of THIS machine to the host for the
//! life of the connection. The file server is `crate::sharefs`; the wire half is
//! `wsh_client::share`. Shares exist only because they were named on the command line, and are
//! offered exactly once, after authentication.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use anyhow::{bail, Result};
use wsh_client::WshClient;

#[cfg(unix)]
use crate::sharefs::{self, ShareServer, ShareSpec};

/// The shares to offer, parsed (and checked) before any connection is made.
#[cfg(unix)]
static SHARES: OnceLock<Vec<ShareSpec>> = OnceLock::new();
#[cfg(not(unix))]
static SHARES: OnceLock<Vec<()>> = OnceLock::new();

/// `--share-hide-path`: leave each share's root path out of the offer (#164).
static HIDE_PATH: AtomicBool = AtomicBool::new(false);

/// Parse every `--share` and remember them. Opening the directories happens here too, so a bad
/// path is an error before the connection (and before anything is asked of the host).
#[cfg(unix)]
pub fn set(specs: &[String], hide_path: bool) -> Result<()> {
    HIDE_PATH.store(hide_path, Ordering::Relaxed);
    let mut parsed: Vec<ShareSpec> = Vec::new();
    for s in specs {
        let spec = sharefs::parse_spec(s).map_err(|e| anyhow::anyhow!(e))?;
        if parsed.iter().any(|p| p.name == spec.name) {
            bail!("--share {}: the name is used twice", spec.name);
        }
        parsed.push(spec);
    }
    // Fail now, not after dialing, when a directory cannot be opened.
    sharefs::open_all(&parsed).map_err(|e| anyhow::anyhow!(e))?;
    let _ = SHARES.set(parsed);
    Ok(())
}

#[cfg(not(unix))]
pub fn set(specs: &[String], hide_path: bool) -> Result<()> {
    HIDE_PATH.store(hide_path, Ordering::Relaxed);
    if specs.is_empty() {
        return Ok(());
    }
    let _ = &SHARES;
    bail!("--share is only available on unix systems");
}

/// Offer the configured shares on `client`. A host that cannot use shares is an error: a share
/// that silently does not exist is worse than none.
#[cfg(unix)]
pub async fn start_configured(client: &WshClient) -> Result<()> {
    use std::sync::Arc;

    let Some(specs) = SHARES.get() else {
        return Ok(());
    };
    if specs.is_empty() {
        return Ok(());
    }
    let shares = sharefs::open_all(specs).map_err(|e| anyhow::anyhow!(e))?;
    let lines: Vec<String> = shares.iter().map(sharefs::describe).collect();
    let limits = sharefs::Limits::default();
    let offer = sharefs::build_offer(specs, &limits, HIDE_PATH.load(Ordering::Relaxed));
    let server = Arc::new(ShareServer::new(shares, limits));
    client
        .gateway()
        .offer_shares(server, offer)
        .await
        .map_err(|e| anyhow::anyhow!("--share: {e}"))?;
    // Said once, to stderr, after the host accepted the offer's feature.
    for line in lines {
        eprintln!("wsh: {line}");
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn start_configured(_client: &WshClient) -> Result<()> {
    Ok(())
}
