//! `wsh agent` — long-lived reverse-host registration and status.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::warn;
use wsh_client::{auth, KeyStore};
use wsh_core::fingerprint;
use wsh_core::messages::{Envelope, MsgType, Payload};

use crate::commands::common::{connect_client, resolve_target};
use crate::commands::reverse_host::{
    self, ReverseHostOptions, ReverseHostRunOutcome, ReverseHostStatusEvent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupPlatform {
    Launchd,
    SystemdUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupUnitSpec {
    platform: StartupPlatform,
    label: String,
    path: PathBuf,
    contents: String,
    enable_hint: String,
    disable_hint: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AgentLifecycleStatus {
    Starting,
    Connecting,
    Registered,
    Backoff,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentStateSnapshot {
    version: u32,
    pid: u32,
    identity: String,
    relay_host: String,
    relay_port: u16,
    transport: Option<String>,
    peer_type: String,
    shell_backend: String,
    capabilities: Vec<String>,
    status: AgentLifecycleStatus,
    reconnect_attempt: u64,
    active_sessions: usize,
    fingerprint: Option<String>,
    updated_at_ms: u64,
    connected_at_ms: Option<u64>,
    last_error: Option<String>,
    last_event: Option<String>,
}

#[derive(Clone)]
struct AgentState {
    path: Arc<PathBuf>,
    snapshot: Arc<Mutex<AgentStateSnapshot>>,
}

impl AgentState {
    async fn new(
        identity: &str,
        relay_host: &str,
        relay_port: u16,
        transport: Option<&str>,
        options: &ReverseHostOptions,
        fingerprint: Option<String>,
    ) -> Result<Self> {
        let snapshot = AgentStateSnapshot {
            version: 1,
            pid: std::process::id(),
            identity: identity.to_string(),
            relay_host: relay_host.to_string(),
            relay_port,
            transport: transport.map(ToString::to_string),
            peer_type: options.peer_type.clone(),
            shell_backend: options.shell_backend.clone(),
            capabilities: options.capabilities.clone(),
            status: AgentLifecycleStatus::Starting,
            reconnect_attempt: 0,
            active_sessions: 0,
            fingerprint,
            updated_at_ms: now_ms(),
            connected_at_ms: None,
            last_error: None,
            last_event: None,
        };
        let state = Self {
            path: Arc::new(agent_state_path(identity, relay_host, relay_port)?),
            snapshot: Arc::new(Mutex::new(snapshot)),
        };
        state.persist().await?;
        Ok(state)
    }

    async fn update<F>(&self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut AgentStateSnapshot),
    {
        {
            let mut snapshot = self.snapshot.lock().await;
            updater(&mut snapshot);
            snapshot.updated_at_ms = now_ms();
        }
        self.persist().await
    }

    async fn persist(&self) -> Result<()> {
        let snapshot = self.snapshot.lock().await.clone();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let json =
            serde_json::to_vec_pretty(&snapshot).context("failed to serialize agent state")?;
        std::fs::write(self.path.as_ref(), json)
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        Ok(())
    }
}

pub async fn run(
    relay_host: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    reconnect_delay_secs: u64,
    capabilities: &[String],
) -> Result<()> {
    let options = reverse_host_options(capabilities)?;
    let fingerprint = load_fingerprint(identity)?;
    let state = AgentState::new(
        identity,
        relay_host,
        port,
        transport,
        &options,
        Some(fingerprint.clone()),
    )
    .await?;

    let keystore = KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;
    let (signing_key, verifying_key) = keystore
        .load(identity)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to load key '{identity}'"))?;
    let public_key = auth::public_key_bytes(&verifying_key);
    let reconnect_delay = Duration::from_secs(reconnect_delay_secs.max(1));
    let resolved = resolve_target(relay_host, port, transport)?;
    let mut options = options;
    crate::commands::common::apply_host_policy(&mut options, &signing_key)?;
    let mut service = reverse_host::ReverseHostService::new(options.clone());

    println!(
        "Starting wsh agent for {} on {}:{} (capabilities: {})",
        fingerprint,
        relay_host,
        port,
        options.capabilities.join(", ")
    );

    let mut reconnect_attempt = 0_u64;

    loop {
        reconnect_attempt += 1;
        state
            .update(|snapshot| {
                snapshot.status = AgentLifecycleStatus::Connecting;
                snapshot.reconnect_attempt = reconnect_attempt;
                snapshot.last_error = None;
                snapshot.last_event = Some("connecting".to_string());
            })
            .await?;

        let client = match connect_client(&resolved, identity).await {
            Ok(client) => Arc::new(client),
            Err(err) => {
                let error = err.to_string();
                state
                    .update(|snapshot| {
                        snapshot.status = AgentLifecycleStatus::Backoff;
                        snapshot.last_error = Some(error.clone());
                        snapshot.last_event = Some("connect-failed".to_string());
                    })
                    .await?;
                warn!("wsh agent connect failed: {error}");
                sleep(reconnect_delay).await;
                continue;
            }
        };

        let mut reverse_connect_rx = client
            .take_reverse_connect_rx()
            .await
            .expect("reverse connect receiver already taken");
        let mut relay_message_rx = client
            .take_relay_message_rx()
            .await
            .expect("relay message receiver already taken");

        let register = Envelope {
            msg_type: MsgType::ReverseRegister,
            payload: Payload::ReverseRegister(options.reverse_register_payload(
                resolved.user.clone(),
                public_key.clone(),
                &signing_key,
            )),
        };

        if let Err(err) = client
            .send_fire_and_forget(register)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
        {
            let error = err.to_string();
            state
                .update(|snapshot| {
                    snapshot.status = AgentLifecycleStatus::Backoff;
                    snapshot.last_error = Some(error.clone());
                    snapshot.last_event = Some("register-failed".to_string());
                })
                .await?;
            warn!("wsh agent registration failed: {error}");
            let _ = client.disconnect().await;
            sleep(reconnect_delay).await;
            continue;
        }

        state
            .update(|snapshot| {
                snapshot.status = AgentLifecycleStatus::Registered;
                snapshot.connected_at_ms = Some(now_ms());
                snapshot.last_event = Some("registered".to_string());
                snapshot.last_error = None;
                snapshot.active_sessions = 0;
            })
            .await?;

        let (status_tx, mut status_rx) = tokio::sync::mpsc::channel(32);
        let status_state = state.clone();
        let status_task = tokio::spawn(async move {
            while let Some(event) = status_rx.recv().await {
                match event {
                    ReverseHostStatusEvent::ReverseConnectionAccepted {
                        requester,
                        target_fingerprint,
                    } => {
                        let _ = status_state
                            .update(|snapshot| {
                                snapshot.last_event = Some(format!(
                                    "accepted {} for {}",
                                    requester, target_fingerprint
                                ));
                            })
                            .await;
                    }
                    ReverseHostStatusEvent::SessionCountChanged { active_sessions } => {
                        let _ = status_state
                            .update(|snapshot| {
                                snapshot.active_sessions = active_sessions;
                            })
                            .await;
                    }
                }
            }
        });

        let outcome = reverse_host::run_with_service(
            &mut service,
            client.clone(),
            &mut reverse_connect_rx,
            &mut relay_message_rx,
            Some(status_tx),
        )
        .await;
        let _ = status_task.await;
        let _ = client.disconnect().await;

        match outcome {
            Ok(ReverseHostRunOutcome::Interrupted) => {
                state
                    .update(|snapshot| {
                        snapshot.status = AgentLifecycleStatus::Stopped;
                        snapshot.last_event = Some("stopped".to_string());
                        snapshot.active_sessions = 0;
                    })
                    .await?;
                return Ok(());
            }
            Ok(ReverseHostRunOutcome::TransportClosed) => {
                state
                    .update(|snapshot| {
                        snapshot.status = AgentLifecycleStatus::Backoff;
                        snapshot.last_error = Some("transport closed".to_string());
                        snapshot.last_event = Some("transport-closed".to_string());
                    })
                    .await?;
            }
            Err(err) => {
                let error = err.to_string();
                state
                    .update(|snapshot| {
                        snapshot.status = AgentLifecycleStatus::Backoff;
                        snapshot.active_sessions = 0;
                        snapshot.last_error = Some(error.clone());
                        snapshot.last_event = Some("runtime-error".to_string());
                    })
                    .await?;
                warn!("wsh agent runtime failed: {error}");
            }
        }

        sleep(reconnect_delay).await;
    }
}

pub async fn run_install(
    relay_host: &str,
    relay_port: u16,
    identity: &str,
    transport: Option<&str>,
    reconnect_delay_secs: u64,
    capabilities: &[String],
    print: bool,
    force: bool,
) -> Result<()> {
    let spec = build_startup_unit_spec(
        identity,
        relay_host,
        relay_port,
        transport,
        reconnect_delay_secs,
        capabilities,
        None,
        None,
        None,
    )?;

    if print {
        println!("{}", spec.contents);
        return Ok(());
    }

    if let Some(parent) = spec.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if spec.path.exists() && !force {
        anyhow::bail!(
            "startup unit already exists at {}; rerun with --force to overwrite",
            spec.path.display()
        );
    }
    std::fs::write(&spec.path, spec.contents.as_bytes())
        .with_context(|| format!("failed to write {}", spec.path.display()))?;

    println!("Installed wsh-agent startup unit:");
    println!("  {}", spec.path.display());
    println!("Enable/start:");
    println!("  {}", spec.enable_hint);
    println!("Disable/remove later:");
    println!("  {}", spec.disable_hint);
    Ok(())
}

pub async fn run_uninstall(
    relay_host: &str,
    relay_port: u16,
    identity: &str,
    _transport: Option<&str>,
) -> Result<()> {
    let platform = detect_startup_platform()?;
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let label = startup_unit_label(identity, relay_host, relay_port);
    let path = startup_unit_path(platform, &home, &label);
    if !path.exists() {
        println!("No startup unit installed for {identity} on {relay_host}:{relay_port}.");
        return Ok(());
    }

    std::fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    println!("Removed wsh-agent startup unit:");
    println!("  {}", path.display());
    println!("If the agent is currently loaded, disable it with:");
    println!(
        "  {}",
        startup_disable_hint(platform, &label, path.as_os_str())
    );
    Ok(())
}

pub async fn run_status(
    relay_host: Option<&str>,
    relay_port: u16,
    identity: &str,
    json: bool,
) -> Result<()> {
    let snapshots = load_agent_snapshots(identity, relay_host, relay_port)?;
    if snapshots.is_empty() {
        println!("No wsh agent state found.");
        return Ok(());
    }

    if json {
        if relay_host.is_some() && snapshots.len() == 1 {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshots[0])
                    .context("failed to serialize agent status")?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshots)
                    .context("failed to serialize agent statuses")?
            );
        }
        return Ok(());
    }

    if snapshots.len() == 1 {
        print_snapshot(&snapshots[0]);
        return Ok(());
    }

    println!(
        "{:<18} {:<10} {:<16} {:<14} {}",
        "IDENTITY", "STATUS", "RELAY", "SESSIONS", "UPDATED"
    );
    println!(
        "{:<18} {:<10} {:<16} {:<14} {}",
        "────────", "──────", "─────", "────────", "───────"
    );
    for snapshot in snapshots {
        println!(
            "{:<18} {:<10} {:<16} {:<14} {}",
            snapshot.identity,
            format!("{:?}", snapshot.status).to_ascii_lowercase(),
            format!("{}:{}", snapshot.relay_host, snapshot.relay_port),
            snapshot.active_sessions,
            snapshot.updated_at_ms,
        );
    }
    Ok(())
}

fn reverse_host_options(capabilities: &[String]) -> Result<ReverseHostOptions> {
    let normalized = normalize_capabilities(capabilities);
    for capability in &normalized {
        if capability != "shell"
            && capability != "exec"
            && capability != "fs"
            && capability != "tools"
            && capability != "gateway"
        {
            anyhow::bail!(
                "unsupported reverse-host capability `{capability}`; supported capabilities are shell, exec, fs, tools, and gateway"
            );
        }
    }
    Ok(ReverseHostOptions {
        capabilities: normalized,
        supports_attach: true,
        supports_replay: true,
        ..ReverseHostOptions::default()
    })
}

fn build_startup_unit_spec(
    identity: &str,
    relay_host: &str,
    relay_port: u16,
    transport: Option<&str>,
    reconnect_delay_secs: u64,
    capabilities: &[String],
    platform_override: Option<StartupPlatform>,
    home_override: Option<&std::path::Path>,
    exe_override: Option<&std::path::Path>,
) -> Result<StartupUnitSpec> {
    let options = reverse_host_options(capabilities)?;
    let platform = match platform_override {
        Some(platform) => platform,
        None => detect_startup_platform()?,
    };
    let home = match home_override {
        Some(home) => home.to_path_buf(),
        None => dirs::home_dir().context("cannot determine home directory")?,
    };
    let exe = match exe_override {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe().context("failed to determine current executable")?,
    };
    let label = startup_unit_label(identity, relay_host, relay_port);
    let path = startup_unit_path(platform, &home, &label);
    let args = startup_command_arguments(
        &exe,
        identity,
        relay_host,
        relay_port,
        transport,
        reconnect_delay_secs,
        &options.capabilities,
        &crate::commands::common::identity_policy(),
    );

    let contents = match platform {
        StartupPlatform::Launchd => render_launchd_plist(&label, &home, &args),
        StartupPlatform::SystemdUser => render_systemd_unit(&label, &home, &args),
    };

    Ok(StartupUnitSpec {
        platform,
        label: label.clone(),
        path: path.clone(),
        contents,
        enable_hint: startup_enable_hint(platform, &label, path.as_os_str()),
        disable_hint: startup_disable_hint(platform, &label, path.as_os_str()),
    })
}

#[cfg(target_os = "macos")]
fn detect_startup_platform() -> Result<StartupPlatform> {
    Ok(StartupPlatform::Launchd)
}

#[cfg(target_os = "linux")]
fn detect_startup_platform() -> Result<StartupPlatform> {
    Ok(StartupPlatform::SystemdUser)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_startup_platform() -> Result<StartupPlatform> {
    anyhow::bail!("wsh agent install is currently supported on macOS and Linux only")
}

fn normalize_capabilities(capabilities: &[String]) -> Vec<String> {
    let requested = if capabilities.is_empty() {
        vec!["shell".to_string(), "exec".to_string()]
    } else {
        capabilities
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .collect()
    };

    let mut normalized = Vec::new();
    for capability in requested {
        if capability.is_empty() || normalized.iter().any(|existing| existing == &capability) {
            continue;
        }
        normalized.push(capability);
    }
    normalized
}

fn load_fingerprint(identity: &str) -> Result<String> {
    let keystore = KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;
    let (_signing_key, verifying_key) = keystore
        .load(identity)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to load key '{identity}'"))?;
    let public_bytes = auth::public_key_bytes(&verifying_key);
    Ok(fingerprint(&public_bytes))
}

fn agent_state_path(identity: &str, relay_host: &str, relay_port: u16) -> Result<PathBuf> {
    Ok(agent_state_dir()?.join(agent_state_file_name(identity, relay_host, relay_port)))
}

fn agent_state_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".wsh").join("agents"))
}

fn agent_state_file_name(identity: &str, relay_host: &str, relay_port: u16) -> String {
    format!(
        "{}__{}__{}.json",
        sanitize_component(identity),
        sanitize_component(relay_host),
        relay_port
    )
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn startup_unit_label(identity: &str, relay_host: &str, relay_port: u16) -> String {
    format!(
        "io.clawser.wsh-agent.{}.{}.{}",
        sanitize_component(identity),
        sanitize_component(relay_host),
        relay_port
    )
}

fn startup_unit_path(platform: StartupPlatform, home: &std::path::Path, label: &str) -> PathBuf {
    match platform {
        StartupPlatform::Launchd => home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{label}.plist")),
        StartupPlatform::SystemdUser => home
            .join(".config")
            .join("systemd")
            .join("user")
            .join(format!("{label}.service")),
    }
}

fn startup_command_arguments(
    exe: &std::path::Path,
    identity: &str,
    relay_host: &str,
    relay_port: u16,
    transport: Option<&str>,
    reconnect_delay_secs: u64,
    capabilities: &[String],
    policy: &crate::commands::common::IdentityPolicy,
) -> Vec<String> {
    let mut args = vec![
        exe.display().to_string(),
        "-i".to_string(),
        identity.to_string(),
        "-p".to_string(),
        relay_port.to_string(),
    ];
    if let Some(transport) = transport {
        args.push("-t".to_string());
        args.push(transport.to_string());
    }
    args.push("agent".to_string());
    args.push("run".to_string());
    args.push(relay_host.to_string());
    args.push("--reconnect-delay-secs".to_string());
    args.push(reconnect_delay_secs.to_string());
    for capability in capabilities {
        args.push("--capability".to_string());
        args.push(capability.clone());
    }
    // What narrows who may be served, how the relay and its certificate are checked, and what an operator may reach is the owner's
    // decision at install time: the installed agent carries exactly what `install` was given (a flag dropped here would leave the unit
    // running with a weaker rule than the one asked for). Deliberately NOT written: `--accept-new-host-key` (a first-use acceptance is
    // for that run only) and `--insecure-skip-cert-verification` (development only).
    for (on, flag) in [
        (policy.require_host_key, "--require-host-key"),
        (policy.require_channel_binding, "--require-channel-binding"),
        (policy.require_operator_proof, "--require-operator-proof"),
    ] {
        if on {
            args.push(flag.to_string());
        }
    }
    for hash in &policy.cert_hashes {
        args.push("--cert-hash".to_string());
        args.push(hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    for operator in &policy.allow_operators {
        args.push("--allow-operator".to_string());
        args.push(operator.clone());
    }
    if policy.max_operators > 1 {
        args.push("--max-operators".to_string());
        args.push(policy.max_operators.to_string());
    }
    for rule in &policy.relay_gateway_allow {
        args.push("--relay-gateway-allow".to_string());
        args.push(rule.clone());
    }
    for (scopes, flag) in [
        (&policy.relay_gateway_udp_for, "--relay-gateway-udp-for"),
        (&policy.relay_gateway_dns_for, "--relay-gateway-dns-for"),
        (
            &policy.relay_gateway_listen_for,
            "--relay-gateway-listen-for",
        ),
    ] {
        for scope in scopes {
            args.push(flag.to_string());
            args.push(scope.clone());
        }
    }
    for (on, flag) in [
        (policy.relay_gateway_udp, "--relay-gateway-udp"),
        (policy.relay_gateway_dns, "--relay-gateway-dns"),
        (policy.relay_gateway_listen, "--relay-gateway-listen"),
        (
            policy.relay_gateway_trust_relay,
            "--relay-gateway-trust-relay",
        ),
    ] {
        if on {
            args.push(flag.to_string());
        }
    }
    if policy.no_probe_answers {
        args.push("--no-half-close-probe-answers".to_string());
    }
    if policy.relay_gateway_max_connections != 0 {
        args.push("--relay-gateway-max-connections".to_string());
        args.push(policy.relay_gateway_max_connections.to_string());
    }
    args
}

fn render_launchd_plist(label: &str, home: &std::path::Path, args: &[String]) -> String {
    let program_arguments = args
        .iter()
        .map(|arg| format!("    <string>{}</string>", xml_escape(arg)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{program_arguments}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>{working_directory}</string>
</dict>
</plist>
"#,
        label = xml_escape(label),
        program_arguments = program_arguments,
        working_directory = xml_escape(&home.display().to_string()),
    )
}

fn render_systemd_unit(label: &str, home: &std::path::Path, args: &[String]) -> String {
    let exec_start = args
        .iter()
        .map(|arg| systemd_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"[Unit]
Description=wsh-agent reverse host ({label})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={working_directory}
ExecStart={exec_start}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"#,
        label = label,
        working_directory = systemd_quote(&home.display().to_string()),
        exec_start = exec_start,
    )
}

fn startup_enable_hint(platform: StartupPlatform, label: &str, path: &OsStr) -> String {
    match platform {
        StartupPlatform::Launchd => format!(
            "launchctl bootstrap gui/$(id -u) {} && launchctl kickstart -k gui/$(id -u)/{}",
            path.to_string_lossy(),
            label
        ),
        StartupPlatform::SystemdUser => {
            format!(
                "systemctl --user daemon-reload && systemctl --user enable --now {label}.service"
            )
        }
    }
}

fn startup_disable_hint(platform: StartupPlatform, label: &str, path: &OsStr) -> String {
    match platform {
        StartupPlatform::Launchd => format!(
            "launchctl bootout gui/$(id -u)/{} || launchctl bootout gui/$(id -u) {}",
            label,
            path.to_string_lossy()
        ),
        StartupPlatform::SystemdUser => format!(
            "systemctl --user disable --now {label}.service && systemctl --user daemon-reload"
        ),
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn load_agent_snapshots(
    identity: &str,
    relay_host: Option<&str>,
    relay_port: u16,
) -> Result<Vec<AgentStateSnapshot>> {
    if let Some(relay_host) = relay_host {
        let path = agent_state_path(identity, relay_host, relay_port)?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        return Ok(vec![load_agent_snapshot(&path)?]);
    }

    let dir = agent_state_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    for entry in
        std::fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let snapshot = load_agent_snapshot(&path)?;
        if snapshot.identity == identity {
            snapshots.push(snapshot);
        }
    }
    snapshots.sort_by(|left, right| {
        left.relay_host
            .cmp(&right.relay_host)
            .then(left.relay_port.cmp(&right.relay_port))
    });
    Ok(snapshots)
}

fn load_agent_snapshot(path: &PathBuf) -> Result<AgentStateSnapshot> {
    let content =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&content).with_context(|| format!("failed to parse {}", path.display()))
}

fn print_snapshot(snapshot: &AgentStateSnapshot) {
    println!("wsh agent");
    println!("  status: {:?}", snapshot.status);
    println!("  identity: {}", snapshot.identity);
    println!(
        "  relay: {}:{}{}",
        snapshot.relay_host,
        snapshot.relay_port,
        snapshot
            .transport
            .as_deref()
            .map(|value| format!(" ({value})"))
            .unwrap_or_default()
    );
    println!(
        "  backend: {} / {}",
        snapshot.peer_type, snapshot.shell_backend
    );
    println!("  capabilities: {}", snapshot.capabilities.join(", "));
    if let Some(fingerprint) = snapshot.fingerprint.as_deref() {
        println!("  fingerprint: {fingerprint}");
    }
    println!("  reconnect attempt: {}", snapshot.reconnect_attempt);
    println!("  active sessions: {}", snapshot.active_sessions);
    if let Some(last_error) = snapshot.last_error.as_deref() {
        println!("  last error: {last_error}");
    }
    if let Some(last_event) = snapshot.last_event.as_deref() {
        println!("  last event: {last_event}");
    }
    println!("  updated: {}", snapshot.updated_at_ms);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        agent_state_file_name, build_startup_unit_spec, normalize_capabilities,
        reverse_host_options, sanitize_component, startup_unit_label, startup_unit_path,
        systemd_quote, AgentLifecycleStatus, StartupPlatform,
    };

    #[test]
    fn normalize_capabilities_defaults_and_deduplicates() {
        assert_eq!(
            normalize_capabilities(&[
                "shell".to_string(),
                "exec".to_string(),
                "shell".to_string(),
                "".to_string(),
            ]),
            vec!["shell".to_string(), "exec".to_string()]
        );
        assert_eq!(
            normalize_capabilities(&[]),
            vec!["shell".to_string(), "exec".to_string()]
        );
    }

    #[test]
    fn reverse_host_options_rejects_unknown_capabilities() {
        let err = reverse_host_options(&["bogus".to_string()]).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported reverse-host capability"));
    }

    #[test]
    fn reverse_host_options_accepts_phase_7a_capabilities() {
        let options = reverse_host_options(&[
            "shell".to_string(),
            "fs".to_string(),
            "tools".to_string(),
            "gateway".to_string(),
        ])
        .unwrap();
        assert_eq!(
            options.capabilities,
            vec![
                "shell".to_string(),
                "fs".to_string(),
                "tools".to_string(),
                "gateway".to_string()
            ]
        );
        assert!(options.supports_attach);
        assert!(options.supports_replay);
    }

    #[test]
    fn lifecycle_status_serializes_as_kebab_case() {
        let json = serde_json::to_string(&AgentLifecycleStatus::Registered).unwrap();
        assert_eq!(json, "\"registered\"");
    }

    #[test]
    fn agent_state_file_name_is_unique_per_identity_and_relay() {
        assert_ne!(
            agent_state_file_name("ops", "relay.local", 4422),
            agent_state_file_name("ops", "relay.other", 4422)
        );
        assert_ne!(
            agent_state_file_name("ops", "relay.local", 4422),
            agent_state_file_name("other", "relay.local", 4422)
        );
    }

    #[test]
    fn sanitize_component_replaces_path_unsafe_characters() {
        assert_eq!(
            sanitize_component("relay.local:4422/foo"),
            "relay_local_4422_foo"
        );
    }

    #[test]
    fn startup_unit_label_includes_identity_and_relay() {
        assert_eq!(
            startup_unit_label("ops", "relay.local", 4422),
            "io.clawser.wsh-agent.ops.relay_local.4422"
        );
    }

    #[test]
    fn launchd_startup_spec_contains_agent_run_arguments() {
        let spec = build_startup_unit_spec(
            "ops",
            "relay.local",
            4422,
            Some("wt"),
            5,
            &["shell".to_string(), "gateway".to_string()],
            Some(StartupPlatform::Launchd),
            Some(Path::new("/tmp/home")),
            Some(Path::new("/tmp/bin/wsh")),
        )
        .unwrap();

        assert_eq!(
            spec.path,
            startup_unit_path(
                StartupPlatform::Launchd,
                Path::new("/tmp/home"),
                "io.clawser.wsh-agent.ops.relay_local.4422"
            )
        );
        assert!(spec.contents.contains("<key>ProgramArguments</key>"));
        assert!(spec.contents.contains("<string>/tmp/bin/wsh</string>"));
        assert!(spec.contents.contains("<string>agent</string>"));
        assert!(spec.contents.contains("<string>run</string>"));
        assert!(spec.contents.contains("<string>relay.local</string>"));
        assert!(spec.contents.contains("<string>--capability</string>"));
        assert!(spec.contents.contains("<string>gateway</string>"));
        assert!(spec.enable_hint.contains("launchctl bootstrap"));
    }

    #[test]
    fn systemd_startup_spec_renders_user_service_unit() {
        let spec = build_startup_unit_spec(
            "ops",
            "relay.local",
            4422,
            None,
            3,
            &[],
            Some(StartupPlatform::SystemdUser),
            Some(Path::new("/tmp/home")),
            Some(Path::new("/tmp/bin/wsh")),
        )
        .unwrap();

        assert_eq!(
            spec.path,
            startup_unit_path(
                StartupPlatform::SystemdUser,
                Path::new("/tmp/home"),
                "io.clawser.wsh-agent.ops.relay_local.4422"
            )
        );
        assert!(spec.contents.contains("[Install]"));
        assert!(spec.contents.contains("WantedBy=default.target"));
        assert!(spec
            .contents
            .contains("ExecStart=\"/tmp/bin/wsh\" \"-i\" \"ops\""));
        assert!(spec.enable_hint.contains("systemctl --user enable --now"));
        assert!(spec.disable_hint.contains("systemctl --user disable --now"));
    }

    #[test]
    fn systemd_quote_escapes_backslashes_and_quotes() {
        assert_eq!(
            systemd_quote(r#"/tmp/with "quotes"\and spaces"#),
            "\"/tmp/with \\\"quotes\\\"\\\\and spaces\""
        );
    }

    /// Every flag that narrows who a reverse host serves, how it checks the relay, or what an operator may reach is written into
    /// the unit, and reads back as the very policy it was written from (a flag dropped here is a weaker agent than the one asked for).
    #[test]
    fn the_unit_carries_every_security_flag_and_they_read_back() {
        use clap::Parser;
        let policy = crate::commands::common::IdentityPolicy {
            require_host_key: true,
            require_channel_binding: true,
            require_operator_proof: true,
            cert_hashes: vec![[0xab; 32], [0x01; 32]],
            allow_operators: vec!["0123456789abcdef".into(), "fedcba9876543210".into()],
            max_operators: 1,
            // scoped forms (wsh #296): an `=` in a rule and the three per-operator switches are written into the unit too
            relay_gateway_allow: vec![
                "db.example.com:5432".into(),
                "10.0.0.0/8".into(),
                "0123456789abcdef=10.1.0.0/16:22".into(),
                "fedcba98=*.internal.example:443".into(),
            ],
            relay_gateway_udp_for: vec!["0123456789ab".into()],
            relay_gateway_dns_for: vec!["fedcba98".into(), "0123456789ab".into()],
            relay_gateway_listen_for: vec!["fedcba98".into()],
            relay_gateway_udp: true,
            relay_gateway_dns: true,
            relay_gateway_listen: true,
            relay_gateway_trust_relay: true,
            relay_gateway_max_connections: 7,
            no_probe_answers: true,
            ..Default::default()
        };
        let args = super::startup_command_arguments(
            Path::new("/usr/bin/wsh"),
            "default",
            "relay.example",
            4422,
            Some("ws"),
            3,
            &["gateway".to_string(), "exec".to_string()],
            &policy,
        );
        let cli = crate::Cli::try_parse_from(&args).expect("the unit's command line parses");
        assert_eq!(cli.require_host_key, policy.require_host_key);
        assert_eq!(cli.require_channel_binding, policy.require_channel_binding);
        assert_eq!(cli.require_operator_proof, policy.require_operator_proof);
        assert_eq!(cli.cert_hashes, policy.cert_hashes);
        assert_eq!(cli.allow_operators, policy.allow_operators);
        assert_eq!(cli.relay_gateway_allow, policy.relay_gateway_allow);
        assert_eq!(cli.no_half_close_probe_answers, policy.no_probe_answers);
        assert_eq!(cli.relay_gateway_udp_for, policy.relay_gateway_udp_for);
        assert_eq!(cli.relay_gateway_dns_for, policy.relay_gateway_dns_for);
        assert_eq!(
            cli.relay_gateway_listen_for,
            policy.relay_gateway_listen_for
        );
        assert_eq!(cli.relay_gateway_udp, policy.relay_gateway_udp);
        assert_eq!(cli.relay_gateway_dns, policy.relay_gateway_dns);
        assert_eq!(cli.relay_gateway_listen, policy.relay_gateway_listen);
        assert_eq!(
            cli.relay_gateway_trust_relay,
            policy.relay_gateway_trust_relay
        );
        assert_eq!(
            cli.relay_gateway_max_connections as usize,
            policy.relay_gateway_max_connections
        );
        // several operators: written too
        let many = crate::commands::common::IdentityPolicy {
            max_operators: 4,
            ..Default::default()
        };
        let args = super::startup_command_arguments(
            Path::new("/usr/bin/wsh"),
            "default",
            "relay.example",
            4422,
            None,
            3,
            &["exec".to_string()],
            &many,
        );
        assert_eq!(crate::Cli::try_parse_from(&args).unwrap().max_operators, 4);
        // and an agent installed with nothing asked carries nothing extra
        let none = super::startup_command_arguments(
            Path::new("/usr/bin/wsh"),
            "default",
            "relay.example",
            4422,
            None,
            3,
            &["exec".to_string()],
            &crate::commands::common::IdentityPolicy::default(),
        );
        assert!(
            !none.iter().any(|a| a.starts_with("--require")
                || a.starts_with("--allow")
                || a.starts_with("--relay-gateway")
                || a == "--cert-hash"
                || a == "--max-operators"),
            "{none:?}"
        );
    }
}
