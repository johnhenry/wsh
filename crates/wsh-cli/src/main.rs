//! wsh — Web Shell client CLI.
//!
//! SSH-like remote access over WebTransport and WebSocket.
//! Provides interactive PTY sessions, one-off command execution,
//! key management, file transfer, and MCP tool discovery.

mod commands;
mod config;
#[allow(dead_code)]
mod known_hosts;
#[allow(dead_code)]
mod terminal;

use clap::{Parser, Subcommand};
use tracing::error;

/// wsh — Web Shell client
#[derive(Parser)]
#[command(
    name = "wsh",
    version = "0.1.0",
    about = "Web Shell client — SSH-like remote access over WebTransport/WebSocket"
)]
struct Cli {
    /// Server port
    #[arg(short, long, global = true, default_value_t = 4422)]
    port: u16,

    /// Key name to use for authentication
    #[arg(
        short = 'i',
        long = "identity",
        global = true,
        default_value = "default"
    )]
    identity: String,

    /// Force transport type (ws or wt)
    #[arg(short = 't', long = "transport", global = true)]
    transport: Option<String>,

    /// Config file path
    #[arg(long = "config", global = true)]
    config: Option<String>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Give a one-off command (`wsh host command...`) a terminal: raw keyboard input,
    /// and terminal resizes passed on. Needs standard input to be a terminal.
    #[arg(long = "tty")]
    tty: bool,

    /// Reach `[user@]host` through a pipe relay: the operator URL `wss://relay/r/<id>` (the
    /// rendezvous id both sides were given). `user@host` stays the identity: its host key is
    /// recorded in known_hosts under host:port, not under the relay's address.
    #[arg(long = "via", global = true, value_name = "URL")]
    via: Option<String>,

    /// Forward a local port or unix socket to somewhere the HOST can reach, as `ssh -L` does:
    /// `[bind_addr:]port:host:hostport`, `/local.sock:/remote.sock`, `[bind_addr:]port:/remote.sock`,
    /// `/local.sock:host:hostport`; end any of them with `endpoint=NAME` to reach a named endpoint
    /// of a host that has no file system (an in-page host). Repeatable. Local TCP binds loopback
    /// unless `bind_addr` says otherwise; local sockets are created 0600 and removed on exit.
    #[arg(short = 'L', value_name = "SPEC", action = clap::ArgAction::Append)]
    local_forwards: Vec<String>,

    /// Have the HOST listen and send each connection here, as `ssh -R` does:
    /// `[bind_addr:]port:host:hostport`, `/remote.sock:/local.sock`, `/remote.sock:host:hostport`,
    /// `[bind_addr:]port:/local.sock`. Repeatable. The host decides where it binds and which
    /// paths it allows.
    #[arg(short = 'R', value_name = "SPEC", action = clap::ArgAction::Append)]
    remote_forwards: Vec<String>,

    /// Do not run a command or a shell: only forward (with -L / -R). Stops on Ctrl-C.
    #[arg(short = 'N')]
    no_command: bool,

    /// Let -L /local.sock replace a stale socket file already there (never a live one, never a
    /// file that is not a socket); with -R, ask the host to replace its stale socket.
    #[arg(long = "replace-socket")]
    replace_socket: bool,

    /// Trust a host key seen for the first time (no known_hosts entry) without asking. Without
    /// this, a first use is refused unless you answer yes at a terminal. A host key that CHANGED
    /// is always refused, and only a key the host proved it holds is ever recorded.
    #[arg(long = "accept-new-host-key", global = true)]
    accept_new_host_key: bool,

    /// Refuse a host that proves no host key (a bare fingerprint is not a proof), before any
    /// credential is sent.
    #[arg(long = "require-host-key", global = true)]
    require_host_key: bool,

    /// Refuse to log in unless the signature is bound to this connection (the host's proven key
    /// and, for WebTransport, a pinned certificate): nothing is signed otherwise.
    #[arg(long = "require-channel-binding", global = true)]
    require_channel_binding: bool,

    #[command(subcommand)]
    command: Option<Command>,

    /// Positional arguments: [user@]host [command...]
    ///
    /// When no subcommand is given, the first positional arg is treated as
    /// [user@]host and any remaining args form the remote command to execute.
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Open an interactive PTY session
    Connect {
        /// Target in [user@]host format
        target: String,
    },

    /// List active sessions
    Sessions,

    /// Reattach to a named session
    Attach {
        /// Session name or ID
        session: String,
    },

    /// Detach from the current session
    Detach,

    /// Generate an Ed25519 key pair
    Keygen {
        /// Key name
        #[arg(default_value = "default")]
        name: String,
    },

    /// List stored keys with fingerprints
    Keys,

    /// Copy public key to a remote host
    CopyId {
        /// Target in [user@]host format
        target: String,
    },

    /// Transfer files (use [user@]host:path syntax)
    Scp {
        /// Source path (local or [user@]host:path)
        src: String,
        /// Destination path (local or [user@]host:path)
        dst: String,
    },

    /// One-shot remote directory listing (use [user@]host:path syntax)
    Ls {
        /// Target in [user@]host:path format
        target: String,
    },

    /// Interactive file-browsing session (ls/cd/pwd/get/put/lls/lcd/rm)
    Sftp {
        /// Target in [user@]host format
        target: String,

        /// Run commands from a batch file instead of an interactive prompt
        #[arg(short = 'b', long = "batch")]
        batch: Option<String>,
    },

    /// Register as a reverse-connectable peer
    Reverse {
        /// Relay host
        relay_host: String,

        /// Capabilities to expose (`shell`, `exec`, `fs`, `tools`, `gateway`)
        #[arg(long = "capability")]
        capabilities: Vec<String>,
    },

    /// Run a long-lived reverse-host agent
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    /// List peers available on a relay
    Peers {
        /// Relay host
        relay_host: String,

        /// Emit JSON instead of a human table
        #[arg(long)]
        json: bool,

        /// Filter peers by type (`host`, `browser-shell`, `vm-guest`, `worker`)
        #[arg(long = "type")]
        peer_type: Option<String>,

        /// Filter peers by shell backend (`pty`, `virtual-shell`, `vm-console`, `exec-only`)
        #[arg(long = "backend")]
        shell_backend: Option<String>,

        /// Filter peers by required capability
        #[arg(long)]
        capability: Option<String>,
    },

    /// Reverse connect to a browser peer via relay
    ReverseConnect {
        /// Target peer selector (fingerprint, short fingerprint, or @name)
        target: String,
        /// Relay host to connect through (optional if target is qualified as @name@relay.example.com)
        relay_host: Option<String>,
    },

    /// Run self-checks for common relay/bootstrap failures
    Check {
        #[command(subcommand)]
        command: CheckCommand,
    },

    /// List MCP tools available on a remote host
    Tools {
        /// Target host (optional, uses config default)
        host: Option<String>,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Run the reverse-host agent and keep reconnecting through the relay
    Run {
        /// Relay host
        relay_host: String,

        /// Delay before reconnect attempts
        #[arg(long, default_value_t = 3)]
        reconnect_delay_secs: u64,

        /// Capabilities to expose (`shell`, `exec`, `fs`, `tools`, `gateway`)
        #[arg(long = "capability")]
        capabilities: Vec<String>,
    },

    /// Install a user-level startup unit for the reverse-host agent
    Install {
        /// Relay host
        relay_host: String,

        /// Delay before reconnect attempts
        #[arg(long, default_value_t = 3)]
        reconnect_delay_secs: u64,

        /// Capabilities to expose (`shell`, `exec`, `fs`, `tools`, `gateway`)
        #[arg(long = "capability")]
        capabilities: Vec<String>,

        /// Print the generated unit instead of writing it
        #[arg(long)]
        print: bool,

        /// Overwrite any existing startup unit for this identity+relay
        #[arg(long)]
        force: bool,
    },

    /// Remove a previously installed user-level startup unit
    Uninstall {
        /// Relay host
        relay_host: String,
    },

    /// Show the most recent agent state snapshot
    Status {
        /// Emit JSON instead of human-readable output
        #[arg(long)]
        json: bool,

        /// Relay host for an exact agent status lookup
        relay_host: Option<String>,
    },
}

#[derive(Subcommand)]
enum CheckCommand {
    /// Check local key, known_hosts, relay connectivity, and relay auth
    Relay {
        /// Relay host (or use @name@relay.example.com in reverse-connect)
        relay_host: String,

        /// Emit JSON instead of human-readable output
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // rustls needs a process-wide crypto provider before the first TLS handshake;
    // without one every `wss://` connection panicked (#134).
    wsh_client::transport::install_crypto_provider();

    // Initialize tracing. Diagnostics go to stderr: stdout is the remote command's.
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter("wsh=debug,wsh_cli=debug,wsh_client=debug,wsh_core=debug")
            .with_target(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter("wsh=warn,wsh_cli=warn")
            .with_target(false)
            .init();
    }

    // Load config file.
    let config_path = cli.config.clone().unwrap_or_else(|| {
        let home = dirs::home_dir().unwrap_or_default();
        home.join(".wsh")
            .join("config.toml")
            .to_string_lossy()
            .to_string()
    });
    let cfg = config::Config::load(&config_path).unwrap_or_default();

    // Determine effective port, transport, and identity (CLI overrides config).
    let port = cli.port;
    let identity = cli.identity.clone();
    let transport = cli.transport.clone().or_else(|| {
        let t = cfg.default.transport.clone();
        if t == "auto" {
            None
        } else {
            Some(t)
        }
    });

    commands::common::set_identity_policy(commands::common::IdentityPolicy {
        accept_new_host_key: cli.accept_new_host_key,
        require_host_key: cli.require_host_key,
        require_channel_binding: cli.require_channel_binding,
    });

    if let Some(via) = cli.via.clone() {
        // Only the commands that dial one `[user@]host` can go through a pipe relay.
        let dials_a_host = match &cli.command {
            None => true,
            Some(
                Command::Connect { .. }
                | Command::CopyId { .. }
                | Command::Scp { .. }
                | Command::Ls { .. }
                | Command::Sftp { .. },
            ) => true,
            Some(_) => false,
        };
        if !dials_a_host {
            eprintln!(
                "wsh: --via applies to `wsh [user@]host`, connect, scp, ls, sftp and copy-id only"
            );
            std::process::exit(2);
        }
        commands::common::set_via(via);
    }

    // Forwarding (-L / -R / -N): only for the commands that dial one `[user@]host` and keep the
    // connection open (`wsh [user@]host [command...]` and `wsh connect`); it works with `--via`
    // exactly as they do, because the forwards ride whatever connection those open.
    let wants_forwarding = !cli.local_forwards.is_empty()
        || !cli.remote_forwards.is_empty()
        || cli.no_command
        || cli.replace_socket;
    if wants_forwarding {
        let allowed = matches!(&cli.command, None | Some(Command::Connect { .. }));
        if !allowed {
            eprintln!("wsh: -L, -R, -N and --replace-socket apply to `wsh [user@]host [command...]` and `wsh connect` only");
            std::process::exit(2);
        }
        let config = match commands::forward::ForwardConfig::parse(
            &cli.local_forwards,
            &cli.remote_forwards,
            cli.replace_socket,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("wsh: {e}");
                std::process::exit(2);
            }
        };
        if cli.no_command && config.is_empty() {
            eprintln!("wsh: -N has nothing to do without -L or -R");
            std::process::exit(2);
        }
        if cli.no_command && (!matches!(&cli.command, None) || cli.args.len() != 1) {
            eprintln!("wsh: -N takes just the host: wsh -N -L ... [user@]host");
            std::process::exit(2);
        }
        commands::forward::set(config);
    }

    let result = match cli.command {
        Some(Command::Connect { target }) => {
            commands::connect::run(&target, port, &identity, transport.as_deref()).await
        }
        Some(Command::Sessions) => commands::sessions::run_list().await,
        Some(Command::Attach { session }) => {
            commands::sessions::run_attach(&session, port, &identity, transport.as_deref()).await
        }
        Some(Command::Detach) => commands::sessions::run_detach().await,
        Some(Command::Keygen { name }) => commands::keygen::run(&name).await,
        Some(Command::Keys) => commands::keys::run().await,
        Some(Command::CopyId { target }) => {
            commands::copy_id::run(&target, port, &identity, transport.as_deref()).await
        }
        Some(Command::Scp { src, dst }) => {
            commands::scp::run(&src, &dst, port, &identity, transport.as_deref()).await
        }
        Some(Command::Ls { target }) => {
            commands::ls::run(&target, port, &identity, transport.as_deref()).await
        }
        Some(Command::Sftp { target, batch }) => {
            commands::sftp::run(
                &target,
                port,
                &identity,
                transport.as_deref(),
                batch.as_deref(),
            )
            .await
        }
        Some(Command::Reverse {
            relay_host,
            capabilities,
        }) => {
            commands::relay::run_reverse(
                &relay_host,
                port,
                &identity,
                transport.as_deref(),
                &capabilities,
            )
            .await
        }
        Some(Command::Agent { command }) => match command {
            AgentCommand::Run {
                relay_host,
                reconnect_delay_secs,
                capabilities,
            } => {
                commands::agent::run(
                    &relay_host,
                    port,
                    &identity,
                    transport.as_deref(),
                    reconnect_delay_secs,
                    &capabilities,
                )
                .await
            }
            AgentCommand::Install {
                relay_host,
                reconnect_delay_secs,
                capabilities,
                print,
                force,
            } => {
                commands::agent::run_install(
                    &relay_host,
                    port,
                    &identity,
                    transport.as_deref(),
                    reconnect_delay_secs,
                    &capabilities,
                    print,
                    force,
                )
                .await
            }
            AgentCommand::Uninstall { relay_host } => {
                commands::agent::run_uninstall(&relay_host, port, &identity, transport.as_deref())
                    .await
            }
            AgentCommand::Status { json, relay_host } => {
                commands::agent::run_status(relay_host.as_deref(), port, &identity, json).await
            }
        },
        Some(Command::Peers {
            relay_host,
            json,
            peer_type,
            shell_backend,
            capability,
        }) => {
            let options = commands::relay::PeerQueryOptions {
                json,
                peer_type,
                shell_backend,
                capability,
            };
            commands::relay::run_peers(&relay_host, port, &identity, transport.as_deref(), &options)
                .await
        }
        Some(Command::ReverseConnect { target, relay_host }) => {
            commands::relay::run_connect(
                &target,
                relay_host.as_deref(),
                port,
                &identity,
                transport.as_deref(),
            )
            .await
        }
        Some(Command::Check { command }) => match command {
            CheckCommand::Relay { relay_host, json } => {
                commands::check::run_relay(&relay_host, port, &identity, transport.as_deref(), json)
                    .await
            }
        },
        Some(Command::Tools { host }) => {
            commands::tools::run(host.as_deref(), port, &identity, transport.as_deref()).await
        }
        None => {
            // Positional args mode: wsh [user@]host [command...]
            if cli.args.is_empty() {
                eprintln!("Usage: wsh [user@]host [command...]\n       wsh <subcommand>\n\nRun `wsh --help` for full usage.");
                std::process::exit(1);
            }

            let target = &cli.args[0];
            if cli.no_command {
                // wsh -N -L ... user@host: forward only.
                commands::forward::run_forward_only(target, port, &identity, transport.as_deref())
                    .await
            } else if cli.args.len() > 1 {
                // One-off exec: wsh user@host command arg1 arg2 ...
                let command = cli.args[1..].join(" ");
                commands::exec::run(
                    target,
                    &command,
                    port,
                    &identity,
                    transport.as_deref(),
                    cli.tty,
                )
                .await
            } else {
                // Interactive connect: wsh user@host
                commands::connect::run(target, port, &identity, transport.as_deref()).await
            }
        }
    };

    if let Err(e) = result {
        commands::forward::cleanup();
        error!("{:#}", e);
        eprintln!("wsh: {e:#}");
        std::process::exit(1);
    }

    // The command is done. Leave now instead of waiting for the runtime to drain: a
    // reader thread blocked on the terminal or stdin cannot be cancelled, and
    // `connect` stayed running behind one after the session had ended (#136).
    commands::forward::cleanup();
    std::process::exit(0);
}
