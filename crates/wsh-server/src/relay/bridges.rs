//! Which relay connections are bridged to which (wsh #93).
//!
//! Pure bookkeeping, no I/O: the relay in `server.rs` asks it who a message goes to and what a
//! departing connection leaves behind. It mirrors `RelayHub` of the JS server (`src/server/relay.mjs`):
//!
//! * an operator (the side that sent `ReverseConnect`) has one bridge, to one peer;
//! * a peer serves one operator, unless the relay allows more (`max_operators`) AND the peer stated
//!   `relay-multi-operator` in its `ReverseAccept.features` (it then addresses each message with
//!   `RelayForward.to_fingerprint` and is told with a `ReverseClose` when one operator leaves);
//! * a peer answers one `ReverseConnect` at a time, since a `ReverseAccept` does not name its operator.
//!
//! Connections are the server's own `conn_id`s; an operator's fingerprint is the relay's record of its
//! authenticated key, never a value from a payload.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// How long a `ReverseConnect` may wait for its peer's answer before the peer counts as free again.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// `ReverseReject.reason`: the peer already has an operator and does not take several.
pub const BUSY_PEER: &str = "busy: this peer already has an operator (the relay bridges one operator per peer at a time; retry when it leaves)";
/// `ReverseReject.reason`: the peer is answering another operator's request right now.
pub const BUSY_ANSWERING: &str =
    "busy: this peer is answering another operator's request (retry in a moment)";
/// `ReverseReject.reason`: the operator already has a bridge or a request in flight.
pub const BUSY_OPERATOR: &str =
    "busy: you already have a bridge or a pending connect on this relay (one at a time)";

/// `ReverseReject.reason`: a multi-operator peer at the relay's operator cap.
pub fn busy_peer_full(max: usize) -> String {
    format!("busy: this peer already has its maximum of {max} operators (retry when one leaves)")
}

#[derive(Debug)]
struct Pending {
    operator: u64,
    operator_fingerprint: String,
    since: Instant,
}

/// Where a message from a bridged connection goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// The connection has no bridge: the message is an ordinary one.
    NoBridge,
    /// It has a bridge but the recipient cannot be determined: drop the message.
    Drop(String),
    /// Deliver to this connection.
    To(u64),
}

/// What a departing connection leaves for the relay to do.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Departed {
    /// A multi-operator peer to tell, with `ReverseClose`, that this operator left: `(peer conn, operator fingerprint)`.
    pub reverse_close: Option<(u64, String)>,
}

#[derive(Debug)]
pub struct Bridges {
    max_operators: usize,
    /// peer conn -> the request it is answering.
    pending: HashMap<u64, Pending>,
    /// operator conn -> its peer conn (an operator has one bridge).
    operator_peer: HashMap<u64, u64>,
    /// peer conn -> its bridged operators `(conn, fingerprint)`, oldest first.
    peer_operators: HashMap<u64, Vec<(u64, String)>>,
    /// peers that stated `relay-multi-operator` in their last `ReverseAccept`.
    multi: HashSet<u64>,
}

impl Bridges {
    /// `max_operators` is the relay's cap per peer (1 = the original one-operator relay).
    pub fn new(max_operators: usize) -> Self {
        Self {
            max_operators: max_operators.max(1),
            pending: HashMap::new(),
            operator_peer: HashMap::new(),
            peer_operators: HashMap::new(),
            multi: HashSet::new(),
        }
    }

    /// An operator asks to be bridged to `peer`. `Err` carries the `ReverseReject` reason.
    pub fn begin_connect(
        &mut self,
        operator: u64,
        operator_fingerprint: &str,
        peer: u64,
        now: Instant,
    ) -> Result<(), String> {
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.since) <= CONNECT_TIMEOUT);
        if self.operator_peer.contains_key(&operator)
            || self.pending.values().any(|p| p.operator == operator)
        {
            return Err(BUSY_OPERATOR.into());
        }
        if self.pending.contains_key(&peer) {
            return Err(if self.max_operators > 1 {
                BUSY_ANSWERING
            } else {
                BUSY_PEER
            }
            .into());
        }
        if let Some(serving) = self.peer_operators.get(&peer).filter(|s| !s.is_empty()) {
            if self.max_operators < 2 || !self.multi.contains(&peer) {
                return Err(BUSY_PEER.into());
            }
            if serving.iter().any(|(_, fp)| fp == operator_fingerprint) {
                return Err(BUSY_OPERATOR.into());
            }
            if serving.len() >= self.max_operators {
                return Err(busy_peer_full(self.max_operators));
            }
        }
        self.pending.insert(
            peer,
            Pending {
                operator,
                operator_fingerprint: operator_fingerprint.to_string(),
                since: now,
            },
        );
        Ok(())
    }

    /// The operator whose request `peer` is answering, if any.
    pub fn pending_operator(&self, peer: u64) -> Option<u64> {
        self.pending.get(&peer).map(|p| p.operator)
    }

    /// The peer an operator's request is waiting on, if any.
    pub fn pending_peer(&self, operator: u64) -> Option<u64> {
        self.pending
            .iter()
            .find(|(_, p)| p.operator == operator)
            .map(|(peer, _)| *peer)
    }

    /// `peer` answered its pending request. Returns the operator to deliver the answer to. On an
    /// accept the bridge exists from here; `multi` says the peer stated `relay-multi-operator`.
    pub fn answer(&mut self, peer: u64, accepted: bool, multi: bool) -> Option<u64> {
        let p = self.pending.remove(&peer)?;
        if accepted {
            if multi && self.max_operators > 1 {
                self.multi.insert(peer);
            } else {
                self.multi.remove(&peer);
            }
            self.operator_peer.insert(p.operator, peer);
            self.peer_operators
                .entry(peer)
                .or_default()
                .push((p.operator, p.operator_fingerprint));
        }
        Some(p.operator)
    }

    /// Is `conn` one end of a bridge?
    #[cfg(test)]
    pub fn is_bridged(&self, conn: u64) -> bool {
        self.operator_peer.contains_key(&conn)
            || self
                .peer_operators
                .get(&conn)
                .is_some_and(|o| !o.is_empty())
    }

    /// Who a message from `conn` goes to. `to` is the `to_fingerprint` of a `RelayForward` the
    /// connection wrote itself.
    pub fn recipient(&self, conn: u64, to: Option<&str>) -> Route {
        if let Some(peer) = self.operator_peer.get(&conn) {
            return Route::To(*peer); // an operator has exactly one bridge
        }
        let Some(operators) = self.peer_operators.get(&conn).filter(|o| !o.is_empty()) else {
            return Route::NoBridge;
        };
        match to {
            Some(fp) => match operators.iter().find(|(_, f)| f == fp) {
                Some((c, _)) => Route::To(*c),
                None => Route::Drop(format!(
                    "a forward addressed to {}, which is not one of this peer's operators",
                    &fp[..fp.len().min(12)]
                )),
            },
            None if operators.len() == 1 => Route::To(operators[0].0),
            None => Route::Drop(format!(
                "an unaddressed forward from a peer that serves {} operators (to_fingerprint is required)",
                operators.len()
            )),
        }
    }

    /// Every connection the bridges know of (for a sweep of the ones that no longer exist).
    pub fn connections(&self) -> HashSet<u64> {
        let mut all: HashSet<u64> = self.pending.keys().copied().collect();
        all.extend(self.pending.values().map(|p| p.operator));
        all.extend(self.operator_peer.keys().copied());
        all.extend(self.peer_operators.keys().copied());
        all
    }

    /// `conn` ended. Its links are gone. An operator leaving a multi-operator peer is reported so the
    /// peer can be told; a peer of a one-operator relay is left connected (it may take the operator
    /// back), as before.
    pub fn depart(&mut self, conn: u64) -> Departed {
        let mut out = Departed::default();
        // conn as a peer: whatever it was answering, and everyone bridged to it
        self.pending.remove(&conn);
        self.peer_operators.remove(&conn);
        self.operator_peer.retain(|_, peer| *peer != conn);
        self.multi.remove(&conn);
        // conn as an operator
        self.pending.retain(|_, p| p.operator != conn);
        if let Some(peer) = self.operator_peer.remove(&conn) {
            let mut fingerprint = None;
            if let Some(ops) = self.peer_operators.get_mut(&peer) {
                if let Some(i) = ops.iter().position(|(c, _)| *c == conn) {
                    fingerprint = Some(ops.remove(i).1);
                }
                if ops.is_empty() {
                    self.peer_operators.remove(&peer);
                }
            }
            if let (true, Some(fp)) = (self.multi.contains(&peer), fingerprint) {
                out.reverse_close = Some((peer, fp));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP_A: u64 = 1;
    const OP_B: u64 = 2;
    const OP_C: u64 = 3;
    const PEER: u64 = 10;
    const PEER2: u64 = 11;

    fn bridged(b: &mut Bridges, op: u64, fp: &str, peer: u64, multi: bool) {
        b.begin_connect(op, fp, peer, Instant::now()).unwrap();
        assert_eq!(b.answer(peer, true, multi), Some(op));
    }

    #[test]
    fn one_operator_per_peer_by_default_and_a_second_is_busy() {
        let mut b = Bridges::new(1);
        bridged(&mut b, OP_A, "fa", PEER, false);
        assert_eq!(b.recipient(OP_A, None), Route::To(PEER));
        assert_eq!(b.recipient(PEER, None), Route::To(OP_A));
        assert_eq!(
            b.begin_connect(OP_B, "fb", PEER, Instant::now()),
            Err(BUSY_PEER.into())
        );
    }

    #[test]
    fn a_multi_peer_takes_operators_up_to_the_cap() {
        let mut b = Bridges::new(2);
        bridged(&mut b, OP_A, "fa", PEER, true);
        bridged(&mut b, OP_B, "fb", PEER, true);
        assert_eq!(
            b.begin_connect(OP_C, "fc", PEER, Instant::now()),
            Err(busy_peer_full(2))
        );
        // addressed by fingerprint; an unaddressed one is ambiguous; an unknown one is dropped
        assert_eq!(b.recipient(PEER, Some("fb")), Route::To(OP_B));
        assert_eq!(b.recipient(PEER, Some("fa")), Route::To(OP_A));
        assert!(matches!(b.recipient(PEER, None), Route::Drop(_)));
        assert!(matches!(b.recipient(PEER, Some("nobody")), Route::Drop(_)));
        // each operator only ever reaches its own peer
        assert_eq!(b.recipient(OP_B, None), Route::To(PEER));
    }

    #[test]
    fn a_peer_that_never_stated_the_feature_stays_at_one_operator_on_a_multi_relay() {
        let mut b = Bridges::new(4);
        bridged(&mut b, OP_A, "fa", PEER, false);
        assert_eq!(
            b.begin_connect(OP_B, "fb", PEER, Instant::now()),
            Err(BUSY_PEER.into())
        );
        // and the cap is the relay's: a peer stating the feature on a one-operator relay is held to one
        let mut one = Bridges::new(1);
        bridged(&mut one, OP_A, "fa", PEER, true);
        assert_eq!(
            one.begin_connect(OP_B, "fb", PEER, Instant::now()),
            Err(BUSY_PEER.into())
        );
    }

    #[test]
    fn an_unaddressed_forward_with_exactly_one_operator_still_goes_to_it() {
        let mut b = Bridges::new(3);
        bridged(&mut b, OP_A, "fa", PEER, true);
        assert_eq!(b.recipient(PEER, None), Route::To(OP_A));
        assert_eq!(b.recipient(PEER, Some("fa")), Route::To(OP_A));
        assert!(matches!(b.recipient(PEER, Some("fb")), Route::Drop(_)));
    }

    #[test]
    fn one_request_at_a_time_per_peer_and_per_operator() {
        let mut b = Bridges::new(3);
        let now = Instant::now();
        b.begin_connect(OP_A, "fa", PEER, now).unwrap();
        assert_eq!(
            b.begin_connect(OP_B, "fb", PEER, now),
            Err(BUSY_ANSWERING.into())
        );
        assert_eq!(
            b.begin_connect(OP_A, "fa", PEER2, now),
            Err(BUSY_OPERATOR.into())
        );
        assert_eq!(b.pending_operator(PEER), Some(OP_A));
        assert_eq!(b.pending_peer(OP_A), Some(PEER));
        // a reject frees both
        assert_eq!(b.answer(PEER, false, false), Some(OP_A));
        assert!(!b.is_bridged(OP_A));
        b.begin_connect(OP_B, "fb", PEER, now).unwrap();
    }

    #[test]
    fn an_unanswered_request_stops_blocking_the_peer_after_the_timeout() {
        let mut b = Bridges::new(1);
        let t0 = Instant::now();
        b.begin_connect(OP_A, "fa", PEER, t0).unwrap();
        assert!(b
            .begin_connect(OP_B, "fb", PEER, t0 + Duration::from_secs(1))
            .is_err());
        b.begin_connect(
            OP_B,
            "fb",
            PEER,
            t0 + CONNECT_TIMEOUT + Duration::from_secs(1),
        )
        .unwrap();
    }

    #[test]
    fn the_same_key_cannot_be_bridged_twice_to_one_peer() {
        let mut b = Bridges::new(3);
        bridged(&mut b, OP_A, "fa", PEER, true);
        assert_eq!(
            b.begin_connect(OP_B, "fa", PEER, Instant::now()),
            Err(BUSY_OPERATOR.into())
        );
    }

    #[test]
    fn an_operator_leaving_a_multi_peer_is_reported_and_the_others_stay() {
        let mut b = Bridges::new(3);
        bridged(&mut b, OP_A, "fa", PEER, true);
        bridged(&mut b, OP_B, "fb", PEER, true);
        assert_eq!(
            b.depart(OP_A),
            Departed {
                reverse_close: Some((PEER, "fa".into()))
            }
        );
        assert_eq!(b.recipient(PEER, None), Route::To(OP_B));
        assert!(matches!(b.recipient(PEER, Some("fa")), Route::Drop(_)));
        // the freed slot is usable again
        bridged(&mut b, OP_C, "fc", PEER, true);
    }

    #[test]
    fn an_operator_leaving_a_one_operator_peer_reports_nothing_and_frees_it() {
        let mut b = Bridges::new(1);
        bridged(&mut b, OP_A, "fa", PEER, false);
        assert_eq!(b.depart(OP_A), Departed::default());
        assert!(!b.is_bridged(PEER));
        bridged(&mut b, OP_B, "fb", PEER, false);
    }

    #[test]
    fn a_peer_leaving_forgets_every_bridge_and_pending_request_of_it() {
        let mut b = Bridges::new(3);
        bridged(&mut b, OP_A, "fa", PEER, true);
        bridged(&mut b, OP_B, "fb", PEER, true);
        b.begin_connect(OP_C, "fc", PEER2, Instant::now()).unwrap();
        assert_eq!(b.depart(PEER), Departed::default());
        assert!(!b.is_bridged(OP_A) && !b.is_bridged(OP_B));
        assert_eq!(b.recipient(OP_A, None), Route::NoBridge);
        // OP_C's request to the other peer is untouched, and the departed peer's state is not remembered
        assert_eq!(b.pending_operator(PEER2), Some(OP_C));
        bridged(&mut b, OP_A, "fa", PEER, false);
        assert_eq!(
            b.begin_connect(OP_B, "fb", PEER, Instant::now()),
            Err(BUSY_PEER.into()),
            "a re-registered peer starts without the feature it stated before"
        );
    }

    #[test]
    fn a_pending_request_of_a_departed_operator_is_dropped() {
        let mut b = Bridges::new(1);
        b.begin_connect(OP_A, "fa", PEER, Instant::now()).unwrap();
        b.depart(OP_A);
        assert_eq!(b.pending_operator(PEER), None);
        assert!(b.connections().is_empty());
    }

    #[test]
    fn only_the_answering_peer_can_answer() {
        let mut b = Bridges::new(1);
        b.begin_connect(OP_A, "fa", PEER, Instant::now()).unwrap();
        // the operator (or any other connection) is not the peer: no answer is taken from it
        assert_eq!(b.answer(OP_A, true, false), None);
        assert_eq!(b.answer(PEER2, true, false), None);
        assert!(!b.is_bridged(OP_A));
    }
}
