//! The gateway of a reverse host (`wsh reverse`, `wsh agent run`) for an operator behind a relay (wsh #289).
//!
//! OFF unless the host's owner gave `--relay-gateway-allow` (and the `gateway` capability): then the host states `relay-gateway` in its
//! `ReverseAccept.features` on a relay that carries it, and each bridged operator gets one [`GatewaySession`], the SAME gateway
//! `wsh-server` serves a direct client (`wsh_core::gateway`): its destination policy (a rule must name the destination; an address
//! that is not public is refused after the name is resolved unless a rule names it), the connection bound, `gateway-credit` flow
//! control with bounded queues, the half-close rule, and reverse tunnels. This module is only the owner's switches in front of it:
//! UDP, name resolution and reverse tunnels are each OFF unless turned on.

use std::sync::Arc;

use tokio::sync::mpsc;
use wsh_core::gateway::policy::{GatewayPolicy, GatewayPolicyEnforcer};
use wsh_core::gateway::GatewaySession;
use wsh_core::gateway_credit::GATEWAY_CREDIT_FEATURE;
use wsh_core::messages::*;

/// `GatewayFail.code` of a request the policy refuses.
const FAIL_POLICY: u32 = 4;
/// Most connections one operator may hold open (TCP, UDP flows and listeners together) unless the owner says otherwise.
pub const DEFAULT_MAX_CONNECTIONS: usize = 32;
/// What an owner may set `--relay-gateway-max-connections` to.
pub const MAX_CONNECTIONS_LIMIT: usize = 1024;

/// What the owner of a reverse host turned on for operators behind the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGateway {
    /// Destination rules, as in `wsh-server`'s `[gateway] allowed_destinations` (`"host"`, `"host:port"`, `"10.0.0.0/8:5432"`, `"*"`).
    /// Nothing is reachable that no rule names, and no loopback, private or otherwise non-public address unless a rule names it.
    pub allow: Vec<String>,
    /// `OpenUdp` is answered (off by default).
    pub udp: bool,
    /// `ResolveDns` is answered (off by default).
    pub dns: bool,
    /// `ListenRequest` is answered, bound to loopback, ports 0 and 1024-65535 (off by default).
    pub listen: bool,
    /// Connections (TCP, UDP flows, listeners) one operator may hold open at once.
    pub max_connections: usize,
    /// Rules and switches scoped to an operator (wsh #296): `--relay-gateway-allow FINGERPRINT=RULE`, `--relay-gateway-udp-for`,
    /// `-dns-for`, `-listen-for`. They ADD to what is unscoped (`allow`, `udp`, `dns`, `listen`, which are every operator's). Empty = one
    /// list for every operator, as before.
    pub operators: Vec<OperatorGrant>,
}

/// What is granted to the operators whose fingerprint starts with `operator` (wsh #296).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorGrant {
    /// At least 8 lowercase hex digits of the fingerprint, as `--allow-operator` takes them.
    pub operator: String,
    /// Destination rules for these operators only.
    pub allow: Vec<String>,
    /// These operators may also open UDP flows / look names up / listen.
    pub udp: bool,
    pub dns: bool,
    pub listen: bool,
}

/// At least 8 hex digits, as `--allow-operator` takes an operator.
pub fn is_operator_scope(s: &str) -> bool {
    s.len() >= 8 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl RelayGateway {
    /// What the operator whose fingerprint is `fingerprint` gets, or `None` when nothing is granted to it: the unscoped rules and
    /// switches plus those of every grant whose scope is a prefix of the fingerprint. An operator with no rule at all (none scoped to it,
    /// none unscoped) has no gateway: its requests are refused. The result has no `operators` of its own.
    pub fn for_operator(&self, fingerprint: &str) -> Option<RelayGateway> {
        let fingerprint = fingerprint.to_ascii_lowercase();
        let mut own = RelayGateway {
            operators: Vec::new(),
            ..self.clone()
        };
        for g in self
            .operators
            .iter()
            .filter(|g| fingerprint.starts_with(g.operator.as_str()))
        {
            own.allow.extend(g.allow.iter().cloned());
            own.udp |= g.udp;
            own.dns |= g.dns;
            own.listen |= g.listen;
        }
        (!own.allow.is_empty()).then_some(own)
    }
}

impl RelayGateway {
    /// The policy a bridged operator is held to. A rule that does not parse is ignored by the policy (stricter, never wider).
    fn policy(&self) -> GatewayPolicy {
        GatewayPolicy {
            allowed_destinations: self.allow.clone(),
            max_connections: self.max_connections,
            enable_reverse_tunnels: self.listen,
            ..GatewayPolicy::default()
        }
    }

    /// Check what the command line gave: at least one rule, each of which parses, and a sane bound.
    pub fn validate(&self) -> Result<(), String> {
        if self.allow.is_empty() && self.operators.iter().all(|g| g.allow.is_empty()) {
            return Err(
                "the relay gateway needs at least one --relay-gateway-allow rule (default deny)"
                    .into(),
            );
        }
        for g in &self.operators {
            if !is_operator_scope(&g.operator) {
                return Err(format!(
                    "--relay-gateway-allow takes FINGERPRINT=RULE with at least 8 hex digits of the fingerprint, got `{}`",
                    g.operator
                ));
            }
        }
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS_LIMIT {
            return Err(format!(
                "--relay-gateway-max-connections must be between 1 and {MAX_CONNECTIONS_LIMIT}"
            ));
        }
        for rule in self
            .allow
            .iter()
            .chain(self.operators.iter().flat_map(|g| g.allow.iter()))
        {
            // The enforcer ignores a rule it cannot parse (which only narrows the policy); a typo should not do so silently.
            if wsh_core::gateway::policy::parse_rule_check(rule).is_err() {
                return Err(format!(
                    "--relay-gateway-allow: `{rule}` is not a destination rule"
                ));
            }
        }
        Ok(())
    }
}

/// One operator's gateway on this host.
pub struct OperatorGateway {
    pump: tokio::task::JoinHandle<()>,
    session: GatewaySession,
    udp: bool,
    dns: bool,
    out: mpsc::Sender<Envelope>,
}

/// What carries a gateway message to the operator (the relay link of the host).
pub trait GatewayLink: Clone + Send + Sync + 'static {
    fn send(&self, envelope: Envelope) -> impl std::future::Future<Output = ()> + Send;
}

impl Drop for OperatorGateway {
    fn drop(&mut self) {
        // The session (declared after the pump, dropped after this) closes every connection; nothing it queued is sent.
        self.pump.abort();
    }
}

impl OperatorGateway {
    /// A session for one bridged operator; what it says goes to `link`. Every connection is metered (`relay-gateway` implies
    /// `gateway-credit`), whatever the operator listed.
    pub fn new<L: GatewayLink>(gateway: &RelayGateway, link: L) -> Self {
        let policy = Arc::new(GatewayPolicyEnforcer::new(gateway.policy()));
        // Bounded: a relay link that does not take what the gateway has to say slows the connections down, not the memory up.
        let (tx, mut rx) = mpsc::channel::<Envelope>(64);
        // The forwarding task belongs to THIS bridge: it is stopped when the gateway is dropped, queue and all, so a frame this operator's
        // connections left behind can never reach the link when it serves the next operator (whose `gateway_id`s may be the same).
        let pump = tokio::spawn(async move {
            while let Some(envelope) = rx.recv().await {
                link.send(envelope).await;
            }
        });
        Self {
            pump,
            session: GatewaySession::new(
                policy,
                tx.clone(),
                true,
                &[GATEWAY_CREDIT_FEATURE.to_string()],
            ),
            udp: gateway.udp,
            dns: gateway.dns,
            out: tx,
        }
    }

    /// Handle one message of the operator. Answers go out through the link, never inline.
    pub async fn handle(&self, envelope: Envelope) {
        let refuse = |gateway_id: u32, what: &str| Envelope {
            msg_type: MsgType::GatewayFail,
            payload: Payload::GatewayFail(GatewayFailPayload {
                gateway_id,
                code: FAIL_POLICY,
                message: format!("{what} is not enabled on this reverse host"),
            }),
        };
        match &envelope.payload {
            Payload::OpenUdp(p) if !self.udp => {
                let _ = self.out.send(refuse(p.gateway_id, "UDP")).await;
            }
            Payload::ResolveDns(p) if !self.dns => {
                let _ = self.out.send(refuse(p.gateway_id, "name resolution")).await;
            }
            _ => self.session.handle(envelope),
        }
    }

    /// Open connections (for tests and logs).
    pub fn open_connections(&self) -> usize {
        self.session.open_connections()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(rules: &[&str]) -> RelayGateway {
        RelayGateway {
            allow: rules.iter().map(|r| r.to_string()).collect(),
            udp: false,
            dns: false,
            listen: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            operators: Vec::new(),
        }
    }

    const OP_A: &str = "aaaaaaaa11112222";
    const OP_B: &str = "bbbbbbbb33334444";
    const OP_C: &str = "cccccccc55556666";

    fn grant(operator: &str, rules: &[&str]) -> OperatorGrant {
        OperatorGrant {
            operator: operator.into(),
            allow: rules.iter().map(|r| r.to_string()).collect(),
            udp: false,
            dns: false,
            listen: false,
        }
    }

    /// Per operator (wsh #296): the rules scoped to an operator are its own, an unscoped rule is every operator's, and an operator with
    /// neither gets no gateway at all.
    #[test]
    fn an_operator_gets_the_unscoped_rules_and_its_own_and_not_another_operators() {
        let mut g = gateway(&["shared.example.com"]);
        g.operators = vec![
            grant("aaaaaaaa", &["a.example.com:1"]),
            grant("bbbbbbbb", &["b.example.com:2"]),
        ];
        assert_eq!(
            g.for_operator(OP_A).unwrap().allow,
            ["shared.example.com", "a.example.com:1"]
        );
        assert_eq!(
            g.for_operator(OP_B).unwrap().allow,
            ["shared.example.com", "b.example.com:2"]
        );
        assert_eq!(
            g.for_operator(OP_C).unwrap().allow,
            ["shared.example.com"],
            "an operator no rule is scoped to gets what is unscoped (every operator's)"
        );
    }

    #[test]
    fn an_unscoped_only_host_is_unchanged_for_every_operator() {
        let g = gateway(&["db.example.com:5432"]);
        for op in [OP_A, OP_B, OP_C] {
            assert_eq!(g.for_operator(op), Some(g.clone()));
        }
    }

    #[test]
    fn an_operator_with_no_rule_and_no_unscoped_rule_gets_nothing() {
        let mut g = gateway(&[]);
        g.operators = vec![grant("aaaaaaaa", &["a.example.com:1"])];
        assert!(g.for_operator(OP_A).is_some());
        assert!(g.for_operator(OP_B).is_none());
        assert!(g.for_operator("").is_none());
    }

    #[test]
    fn a_switch_scoped_to_an_operator_is_that_operators_only() {
        let mut g = gateway(&["*"]);
        let mut a = grant("aaaaaaaa", &[]);
        a.udp = true;
        a.dns = true;
        a.listen = true;
        g.operators = vec![a];
        let for_a = g.for_operator(OP_A).unwrap();
        assert!(for_a.udp && for_a.dns && for_a.listen);
        let for_b = g.for_operator(OP_B).unwrap();
        assert!(!for_b.udp && !for_b.dns && !for_b.listen);
        // and an unscoped switch is everyone's
        g.udp = true;
        assert!(g.for_operator(OP_B).unwrap().udp);
    }

    #[test]
    fn a_scope_is_a_prefix_of_the_fingerprint_and_a_longer_one_adds_to_a_shorter() {
        let mut g = gateway(&[]);
        g.operators = vec![
            grant("aaaaaaaa", &["short.example.com"]),
            grant("aaaaaaaa1111", &["long.example.com"]),
            grant("aaaaaaaa9999", &["other.example.com"]),
        ];
        assert_eq!(
            g.for_operator(OP_A).unwrap().allow,
            ["short.example.com", "long.example.com"]
        );
    }

    #[test]
    fn a_scoped_rule_must_parse_and_a_scope_must_be_a_fingerprint() {
        let mut g = gateway(&["*"]);
        g.operators = vec![grant("aaaaaaaa", &["10.0.0.0/33"])];
        assert!(g.validate().is_err());
        g.operators = vec![grant("aaaa", &["x.example.com"])];
        assert!(g.validate().is_err(), "fewer than 8 digits");
        g.operators = vec![grant("aaaaaaaz", &["x.example.com"])];
        assert!(g.validate().is_err(), "not hex");
        g.operators = vec![grant("aaaaaaaa", &["x.example.com"])];
        assert!(g.validate().is_ok());
        // only scoped rules is a gateway too
        let mut only = gateway(&[]);
        only.operators = vec![grant("aaaaaaaa", &["x.example.com"])];
        assert!(only.validate().is_ok());
    }

    #[tokio::test]
    async fn operator_a_reaches_what_its_rules_name_and_not_what_bs_name() {
        let mut g = gateway(&[]);
        g.operators = vec![
            grant("aaaaaaaa", &["a.invalid:9"]),
            grant("bbbbbbbb", &["b.invalid:9"]),
        ];
        let (tx, mut rx) = mpsc::unbounded_channel();
        let a = OperatorGateway::new(&g.for_operator(OP_A).unwrap(), Sink(tx));
        // B's destination is not on A's list: refused by the policy, nothing dialled
        a.handle(open_tcp(1, "b.invalid")).await;
        let f = fail_of(&mut rx).await;
        assert_eq!((f.gateway_id, f.code), (1, FAIL_POLICY));
        assert_eq!(a.open_connections(), 0);
    }

    #[test]
    fn nothing_is_allowed_without_a_rule() {
        assert!(gateway(&[]).validate().is_err());
        assert!(gateway(&["db.example.com:5432"]).validate().is_ok());
    }

    #[test]
    fn a_rule_that_is_not_one_is_refused_not_ignored() {
        assert!(gateway(&["10.0.0.0/33"]).validate().is_err());
        assert!(gateway(&[""]).validate().is_err());
    }

    #[test]
    fn the_bound_is_between_one_and_the_limit() {
        let mut g = gateway(&["*"]);
        g.max_connections = 0;
        assert!(g.validate().is_err());
        g.max_connections = MAX_CONNECTIONS_LIMIT + 1;
        assert!(g.validate().is_err());
        g.max_connections = 1;
        assert!(g.validate().is_ok());
    }

    #[test]
    fn udp_dns_and_listen_are_off_unless_turned_on() {
        let g = gateway(&["*"]);
        assert!(!g.udp && !g.dns && !g.listen);
        assert!(!g.policy().enable_reverse_tunnels);
        let mut on = gateway(&["*"]);
        on.listen = true;
        assert!(on.policy().enable_reverse_tunnels);
    }

    #[derive(Clone)]
    struct Sink(mpsc::UnboundedSender<Envelope>);
    impl GatewayLink for Sink {
        async fn send(&self, envelope: Envelope) {
            let _ = self.0.send(envelope);
        }
    }

    fn open_udp(id: u32) -> Envelope {
        Envelope {
            msg_type: MsgType::OpenUdp,
            payload: Payload::OpenUdp(OpenUdpPayload {
                gateway_id: id,
                host: "127.0.0.1".into(),
                port: 9,
            }),
        }
    }
    fn resolve(id: u32) -> Envelope {
        Envelope {
            msg_type: MsgType::ResolveDns,
            payload: Payload::ResolveDns(ResolveDnsPayload {
                gateway_id: id,
                name: "example.com".into(),
                record_type: "A".into(),
            }),
        }
    }
    fn open_tcp(id: u32, host: &str) -> Envelope {
        Envelope {
            msg_type: MsgType::OpenTcp,
            payload: Payload::OpenTcp(OpenTcpPayload {
                gateway_id: id,
                host: host.into(),
                port: 9,
            }),
        }
    }

    async fn fail_of(rx: &mut mpsc::UnboundedReceiver<Envelope>) -> GatewayFailPayload {
        match rx.recv().await.expect("an answer").payload {
            Payload::GatewayFail(f) => f,
            other => panic!("expected GatewayFail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_and_name_resolution_are_refused_unless_turned_on() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let g = OperatorGateway::new(&gateway(&["*"]), Sink(tx));
        g.handle(open_udp(1)).await;
        let f = fail_of(&mut rx).await;
        assert_eq!((f.gateway_id, f.code), (1, FAIL_POLICY));
        assert!(f.message.contains("UDP is not enabled"), "{}", f.message);
        g.handle(resolve(2)).await;
        let f = fail_of(&mut rx).await;
        assert_eq!((f.gateway_id, f.code), (2, FAIL_POLICY));
        assert!(
            f.message.contains("name resolution is not enabled"),
            "{}",
            f.message
        );
    }

    /// A link that takes nothing until released: what is queued for the bridge sits behind it.
    #[derive(Clone)]
    struct HeldSink {
        gate: Arc<tokio::sync::Notify>,
        out: mpsc::UnboundedSender<Envelope>,
    }
    impl GatewayLink for HeldSink {
        async fn send(&self, envelope: Envelope) {
            self.gate.notified().await;
            let _ = self.out.send(envelope);
        }
    }

    #[tokio::test]
    async fn what_a_bridge_had_queued_never_reaches_the_next_one() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let (out, mut rx) = mpsc::unbounded_channel();
        let g = OperatorGateway::new(
            &gateway(&["db.example.com:5432"]),
            HeldSink {
                gate: gate.clone(),
                out,
            },
        );
        // three answers (refusals) pile up behind a link that is not taking anything
        for id in 1..=3 {
            g.handle(open_tcp(id, "other.example.com")).await;
        }
        tokio::task::yield_now().await;
        // the bridge ends
        drop(g);
        // the link (now serving the NEXT operator) starts taking again: nothing of the old bridge may arrive, whatever gateway_id it had
        for _ in 0..5 {
            gate.notify_one();
            tokio::task::yield_now().await;
        }
        assert!(
            rx.try_recv().is_err(),
            "a frame of the ended bridge was delivered"
        );
    }

    #[tokio::test]
    async fn a_destination_no_rule_names_is_refused_by_the_policy() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let g = OperatorGateway::new(&gateway(&["db.example.com:5432"]), Sink(tx));
        g.handle(open_tcp(7, "other.example.com")).await;
        let f = fail_of(&mut rx).await;
        assert_eq!((f.gateway_id, f.code), (7, FAIL_POLICY));
        assert_eq!(g.open_connections(), 0);
    }

    #[tokio::test]
    async fn a_loopback_address_is_refused_even_under_the_wildcard() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let g = OperatorGateway::new(&gateway(&["*"]), Sink(tx));
        g.handle(open_tcp(8, "127.0.0.1")).await;
        let f = fail_of(&mut rx).await;
        assert_eq!((f.gateway_id, f.code), (8, FAIL_POLICY));
    }
}
