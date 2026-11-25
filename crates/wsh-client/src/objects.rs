//! A client of the `wsh-objects` protocol (remote objects, `spec/objects.md`): reach into the roots a host names
//! by path, and read, call, set, snapshot, describe and listen to what the host's allow-lists let through. The
//! Rust twin of `openObjects` in `@johnhenry/wsh/objects`; it speaks to a JavaScript host (a page host behind a
//! relay, `exposeObjects` on a memory host). It is a client only: nothing here serves objects.
//!
//! ```ignore
//! let objects = ObjectsClient::open(&client).await?;        // sealed session: virtual-mode rpc
//! let window = objects.root("window")?;
//! let title = window.get("document.title").await?;          // Reply::Value(Value::Text(..))
//! let n = window.call("app.cart.add", vec![Value::Int(1)]).await?;
//! let mut events = window.subscribe("app.bus", "ready", Default::default()).await?;
//! while let Some(event) = events.recv().await { /* event.data, event.dropped_by_host */ }
//! ```
//!
//! What this client does:
//! - **values mode**: `get`, `set`, `call`, `construct`, `snapshot`, `describe`, and a whole chain
//!   (`window.app.getCart().items`) as one request ([`Chain`]);
//! - **events**: [`Target::subscribe`] gives a bounded [`Subscription`]; what the host dropped and what this
//!   side dropped (its receiver was full) are both counted and told;
//! - **handles**: a host that states `handles` returns [`Handle`]s for what is not plain data; operations
//!   through one are [`Handle::target`]; [`Handle::release`] (or dropping it) gives its place back, and the end of
//!   the session releases all of them. A host that also states `handle-events` accepts [`Target::subscribe`] on
//!   a handle's target; releasing the handle ends the subscriptions made through it;
//! - **callbacks**: a host that states `callbacks` takes a function of this side as an argument of a call whose
//!   allow-list entry ends in `(callback)`. Here a function is a [`Callback`] ([`ObjectsClient::callback`]) passed
//!   with [`Target::call_with`]: the host's calls of it arrive, one way, in a bounded queue read with
//!   [`Callback::recv`]; the host never waits for this side and gets no return value;
//! - **types**: [`ObjectsClient::root_description`] asks a host that states `types` what this key may do on a root
//!   (the allow-list entries, the host's type map, the event fields), as plain data.
//!
//! What it does not do: serve objects (a `wsh-objects` host is a JavaScript thing; `wsh-server` has none, see
//! `spec/objects.md` section 11), return values from callbacks (the protocol has none).
//!
//! Everything the host says in text (names, previews, strings, error messages) is untrusted data: it is kept
//! as strings and never interpreted. A feature the host did not state (`events`, `handles`) is refused here,
//! locally, with [`ErrorKind::Unsupported`].

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::{mpsc, oneshot};
use wsh_core::error::WshError;
use wsh_core::rpc_codec::Cbor;

use crate::rpc::RpcChannel;
use crate::WshClient;

/// The rpc protocol name.
pub const OBJECTS_PROTOCOL: &str = "wsh-objects";
/// `roots` feature: the host serves `subscribe` / `unsubscribe` and sends `event` notifications.
pub const FEATURE_EVENTS: &str = "events";
/// `roots` feature: the host may return handles for what is not plain data.
pub const FEATURE_HANDLES: &str = "handles";
/// `roots` feature: the host accepts callbacks (a function of this side, passed to a call, that the host may call back).
pub const FEATURE_CALLBACKS: &str = "callbacks";
/// `roots` feature: the host accepts `subscribe` with a `handle` in place of a `root`.
pub const FEATURE_HANDLE_EVENTS: &str = "handle-events";
/// `roots` feature: the host answers the `types` method.
pub const FEATURE_TYPES: &str = "types";

/// How long a request waits for its answer unless [`OpenOptions::timeout`] says otherwise. (A host waits up to
/// 30 seconds for a call that returns a promise.)
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Events a [`Subscription`] holds for its reader unless [`SubscribeOptions::capacity`] says otherwise.
pub const DEFAULT_EVENT_CAPACITY: usize = 64;

const SEGMENT_MAX: usize = 256;
const TYPE_MAX: usize = 128;
const FIELDS_MAX: usize = 16;

// ── Values ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/// Plain data, as the protocol carries it: JSON's values plus native bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    /// Members in the order they arrived.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object.
    pub fn member(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// As CBOR, the form that goes on the channel.
    pub fn to_cbor(&self) -> Cbor {
        match self {
            Value::Null => Cbor::Null,
            Value::Bool(b) => Cbor::Bool(*b),
            Value::Int(i) => Cbor::Integer((*i).into()),
            Value::Float(f) => Cbor::Float(*f),
            Value::Text(s) => Cbor::Text(s.clone()),
            Value::Bytes(b) => Cbor::Bytes(b.clone()),
            Value::Array(a) => Cbor::Array(a.iter().map(Value::to_cbor).collect()),
            Value::Object(m) => Cbor::Map(
                m.iter()
                    .map(|(k, v)| (Cbor::Text(k.clone()), v.to_cbor()))
                    .collect(),
            ),
        }
    }

    /// From CBOR as it came off the channel. A map key that is not text, or an integer that does not fit
    /// 64 bits, is the host breaking the protocol.
    pub fn from_cbor(c: Cbor) -> Result<Value, ObjectsError> {
        Ok(match c {
            Cbor::Null => Value::Null,
            Cbor::Bool(b) => Value::Bool(b),
            Cbor::Integer(i) => match i64::try_from(i128::from(i)) {
                Ok(n) => Value::Int(n),
                Err(_) => {
                    return Err(ObjectsError::protocol(
                        "an integer that does not fit 64 bits",
                    ))
                }
            },
            Cbor::Float(f) => Value::Float(f),
            Cbor::Text(s) => Value::Text(s),
            Cbor::Bytes(b) => Value::Bytes(b),
            Cbor::Tag(_, inner) => Value::from_cbor(*inner)?,
            Cbor::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(Value::from_cbor)
                    .collect::<Result<_, _>>()?,
            ),
            Cbor::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    let Cbor::Text(key) = k else {
                        return Err(ObjectsError::protocol("a map key that is not text"));
                    };
                    out.push((key, Value::from_cbor(v)?));
                }
                Value::Object(out)
            }
            _ => {
                return Err(ObjectsError::protocol(
                    "a CBOR value the protocol does not use",
                ))
            }
        })
    }
}

impl From<serde_json::Value> for Value {
    fn from(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else {
                    // above i64::MAX, or not an integer: a float, as JavaScript would have it
                    Value::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(s) => Value::Text(s),
            serde_json::Value::Array(a) => Value::Array(a.into_iter().map(Value::from).collect()),
            serde_json::Value::Object(m) => {
                Value::Object(m.into_iter().map(|(k, v)| (k, Value::from(v))).collect())
            }
        }
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}
impl From<f64> for Value {
    fn from(f: f64) -> Self {
        Value::Float(f)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}
impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => s.serialize_unit(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(i) => s.serialize_i64(*i),
            Value::Float(f) => s.serialize_f64(*f),
            Value::Text(t) => s.serialize_str(t),
            Value::Bytes(b) => s.serialize_bytes(b),
            Value::Array(a) => {
                let mut seq = s.serialize_seq(Some(a.len()))?;
                for v in a {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Value::Object(m) => {
                let mut map = s.serialize_map(Some(m.len()))?;
                for (k, v) in m {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("plain data")
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Value, D2::Error> {
                Value::deserialize(d)
            }
            fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
                Ok(Value::Bool(b))
            }
            fn visit_i64<E>(self, i: i64) -> Result<Value, E> {
                Ok(Value::Int(i))
            }
            fn visit_u64<E>(self, u: u64) -> Result<Value, E> {
                Ok(i64::try_from(u).map_or(Value::Float(u as f64), Value::Int))
            }
            fn visit_f64<E>(self, f: f64) -> Result<Value, E> {
                Ok(Value::Float(f))
            }
            fn visit_str<E>(self, s: &str) -> Result<Value, E> {
                Ok(Value::Text(s.to_string()))
            }
            fn visit_string<E>(self, s: String) -> Result<Value, E> {
                Ok(Value::Text(s))
            }
            fn visit_bytes<E>(self, b: &[u8]) -> Result<Value, E> {
                Ok(Value::Bytes(b.to_vec()))
            }
            fn visit_byte_buf<E>(self, b: Vec<u8>) -> Result<Value, E> {
                Ok(Value::Bytes(b))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element()? {
                    out.push(v);
                }
                Ok(Value::Array(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    out.push((k, v));
                }
                Ok(Value::Object(out))
            }
        }
        d.deserialize_any(V)
    }
}

/// What the host could not clone, by name: a function, a symbol, a bigint, a date, an error, an object that is
/// not plain data. Never a handle. `kind` is the host's word (`function`, `symbol`, `bigint`, `number`, `Date`,
/// `RegExp`, `Error`, `object`, `undefined`); `type_name` the class or function name; `text` a short rendering.
/// All of it is the host's own text: untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonValue {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// What a request on the host's object came to.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Plain data.
    Value(Value),
    /// Something that cannot be cloned, by name.
    NonValue(NonValue),
    /// An opaque reference to it on the host (the host must have stated `handles`).
    Handle(Handle),
}

impl Reply {
    pub fn value(&self) -> Option<&Value> {
        match self {
            Reply::Value(v) => Some(v),
            _ => None,
        }
    }
}

/// A [`Target::snapshot`].
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub reply: Reply,
    /// A subtree deeper than the depth asked for was cut to null.
    pub truncated: bool,
}

/// One name a [`Target::describe`] listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub key: String,
    pub type_name: String,
    pub own: bool,
}

/// What [`Target::describe`] says of an object: only the names the host's allow-lists could walk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    pub type_name: String,
    pub keys: Vec<KeyInfo>,
    pub truncated: bool,
}

// ── Errors ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/// What kind of failure, from the code and reason the host gave (`spec/objects.md`, section 8) or from the local
/// check that refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The host's rules said no (`always-refused`, `not-allowed`, `needs-listing`, `authorize`, `not-permitted`, `gone`).
    Refused,
    /// A bound (`limit`).
    Limit,
    /// The request was malformed (`bad-request`).
    Invalid,
    /// A root, handle or path that is not there (`no-such-root`, `bad-path`, `not-a-function`, `not-an-event-source`).
    NotFound,
    /// The operation ran and failed (`threw`, `refused-by-object`, `cancelled`) or timed out.
    Failed,
    /// The host does not state what was asked of it (a feature, a protocol, a method). Refused locally where it
    /// can be.
    Unsupported,
    /// The channel ended.
    Closed,
    /// The host broke the protocol.
    Protocol,
}

/// An error of this client: the host's refusal with its reason, or a local one.
#[derive(Debug, Clone)]
pub struct ObjectsError {
    pub kind: ErrorKind,
    /// The JSON-RPC code (0 for a local error).
    pub code: i64,
    /// The rule that refused, as the host named it (`not-allowed`, ...), or a local one (`unsupported`).
    pub reason: Option<String>,
    /// A sentence. For an error from the host it is the host's text: untrusted.
    pub message: String,
    /// The host's `data`, if any.
    pub data: Option<Value>,
}

impl ObjectsError {
    fn local(kind: ErrorKind, reason: &str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: 0,
            reason: Some(reason.to_string()),
            message: message.into(),
            data: None,
        }
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::local(ErrorKind::Protocol, "bad-reply", message)
    }

    /// A feature (or channel, or method) the host did not state.
    pub fn unsupported(what: &str) -> Self {
        Self::local(
            ErrorKind::Unsupported,
            "unsupported",
            format!("the host does not state {what}: refused here, nothing was sent"),
        )
    }

    fn closed(why: &str) -> Self {
        Self::local(ErrorKind::Closed, "closed", why)
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::local(ErrorKind::Invalid, "bad-request", message)
    }

    /// From a JSON-RPC error object.
    pub fn from_rpc(code: i64, message: String, data: Option<Value>) -> Self {
        let reason = data
            .as_ref()
            .and_then(|d| d.member("reason"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let kind = match (code, reason.as_deref()) {
            (-32003, _) => ErrorKind::Refused,
            (-32002, _) => ErrorKind::Limit,
            (-32602, Some("no-such-root")) => ErrorKind::NotFound,
            (-32602, _) => ErrorKind::Invalid,
            (-32000, Some("bad-path" | "not-a-function" | "not-an-event-source")) => {
                ErrorKind::NotFound
            }
            (-32000, Some("closed")) => ErrorKind::Closed,
            (-32601, _) => ErrorKind::Unsupported,
            _ => ErrorKind::Failed,
        };
        Self {
            kind,
            code,
            reason,
            message,
            data,
        }
    }
}

impl fmt::Display for ObjectsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            Some(r) => write!(f, "{:?} ({r}): {}", self.kind, self.message),
            None => write!(f, "{:?}: {}", self.kind, self.message),
        }
    }
}

impl std::error::Error for ObjectsError {}

type Result<T, E = ObjectsError> = std::result::Result<T, E>;

// ── Paths and chains ────────────────────────────────────────────────────────────────────────────────────────────────

/// A path below a root or a handle: segments, each of 1 to 256 characters with no `.`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Path(Vec<String>);

impl Path {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// `"a.b.c"` as three segments; the empty text is the empty path.
    pub fn parse(text: &str) -> Self {
        if text.is_empty() {
            Self::new()
        } else {
            Self(text.split('.').map(str::to_string).collect())
        }
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The path with one more segment.
    pub fn join(mut self, segment: impl Into<String>) -> Self {
        self.0.push(segment.into());
        self
    }

    fn check(&self) -> Result<()> {
        for s in &self.0 {
            check_segment(s)?;
        }
        Ok(())
    }

    fn to_cbor(&self) -> Cbor {
        Cbor::Array(self.0.iter().map(|s| Cbor::Text(s.clone())).collect())
    }
}

fn check_segment(s: &str) -> Result<()> {
    if s.is_empty() || s.chars().count() > SEGMENT_MAX || s.contains('.') {
        return Err(ObjectsError::invalid(format!(
            "a path segment is 1 to {SEGMENT_MAX} characters with no \".\" ({} characters given)",
            s.chars().count()
        )));
    }
    Ok(())
}

impl From<&str> for Path {
    fn from(s: &str) -> Self {
        Path::parse(s)
    }
}
impl From<String> for Path {
    fn from(s: String) -> Self {
        Path::parse(&s)
    }
}
impl From<Vec<String>> for Path {
    fn from(v: Vec<String>) -> Self {
        Path(v)
    }
}
impl<const N: usize> From<[&str; N]> for Path {
    fn from(v: [&str; N]) -> Self {
        Path(v.iter().map(|s| s.to_string()).collect())
    }
}
impl From<&[&str]> for Path {
    fn from(v: &[&str]) -> Self {
        Path(v.iter().map(|s| s.to_string()).collect())
    }
}
impl From<()> for Path {
    fn from(_: ()) -> Self {
        Path::new()
    }
}

/// An argument of a call: plain data, or a function of this side (a [`Callback`]) that the host may call back.
#[derive(Debug, Clone)]
pub enum Arg {
    Value(Value),
    Callback(Callback),
}

impl From<Value> for Arg {
    fn from(v: Value) -> Self {
        Arg::Value(v)
    }
}
impl From<Callback> for Arg {
    fn from(c: Callback) -> Self {
        Arg::Callback(c)
    }
}
impl From<&Callback> for Arg {
    fn from(c: &Callback) -> Self {
        Arg::Callback(c.clone())
    }
}

#[derive(Debug, Clone)]
enum Op {
    Get(String),
    /// The key, the arguments (null where a callback stands) and the callbacks by argument index.
    Call(String, Vec<Value>, Vec<(usize, Callback)>),
    Construct(String, Vec<Value>, Vec<(usize, Callback)>),
}

/// A whole chain of operations, sent as one `resolve` request: `window.app.getCart().items` is
/// `chain.get("app").call("getCart", []).get("items")`. The chain continues on the result of each step.
#[derive(Debug, Clone, Default)]
pub struct Chain {
    ops: Vec<Op>,
}

impl Chain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a member (several, for a dotted path).
    pub fn get(mut self, path: impl Into<Path>) -> Self {
        self.ops.extend(path.into().0.into_iter().map(Op::Get));
        self
    }

    /// Call the method named by the last segment of the path (the earlier ones are read on the way).
    pub fn call(self, path: impl Into<Path>, args: Vec<Value>) -> Self {
        self.method(
            path.into(),
            args.into_iter().map(Arg::Value).collect(),
            false,
        )
    }

    /// Like [`Chain::call`], with functions of this side among the arguments (the host must state `callbacks`, and
    /// the allow-list entry of the method must end in `(callback)`).
    pub fn call_with(self, path: impl Into<Path>, args: Vec<Arg>) -> Self {
        self.method(path.into(), args, false)
    }

    /// Construct with the constructor named by the last segment of the path.
    pub fn construct(self, path: impl Into<Path>, args: Vec<Value>) -> Self {
        self.method(
            path.into(),
            args.into_iter().map(Arg::Value).collect(),
            true,
        )
    }

    /// Like [`Chain::construct`], with callbacks among the arguments.
    pub fn construct_with(self, path: impl Into<Path>, args: Vec<Arg>) -> Self {
        self.method(path.into(), args, true)
    }

    fn method(mut self, mut path: Path, args: Vec<Arg>, construct: bool) -> Self {
        let last = path.0.pop();
        self.ops.extend(path.0.into_iter().map(Op::Get));
        // A path with no segment names nothing to call: left as a call of "" which `check` refuses.
        let key = last.unwrap_or_default();
        let mut values = Vec::with_capacity(args.len());
        let mut callbacks = Vec::new();
        for (i, a) in args.into_iter().enumerate() {
            match a {
                Arg::Value(v) => values.push(v),
                Arg::Callback(c) => {
                    values.push(Value::Null);
                    callbacks.push((i, c));
                }
            }
        }
        self.ops.push(if construct {
            Op::Construct(key, values, callbacks)
        } else {
            Op::Call(key, values, callbacks)
        });
        self
    }

    /// The callbacks the chain passes.
    fn callbacks(&self) -> impl Iterator<Item = &Callback> {
        self.ops
            .iter()
            .flat_map(|op| match op {
                Op::Call(_, _, cbs) | Op::Construct(_, _, cbs) => cbs.as_slice(),
                Op::Get(_) => &[],
            })
            .map(|(_, c)| c)
    }

    fn to_cbor(&self) -> Result<Cbor> {
        let mut ops = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            ops.push(match op {
                Op::Get(k) => {
                    check_segment(k)?;
                    map([("get", Cbor::Text(k.clone()))])
                }
                Op::Call(k, args, cbs) | Op::Construct(k, args, cbs) => {
                    check_segment(k)?;
                    let name = if matches!(op, Op::Call(..)) {
                        "call"
                    } else {
                        "construct"
                    };
                    let mut entries = vec![
                        (name, Cbor::Text(k.clone())),
                        (
                            "args",
                            Cbor::Array(args.iter().map(Value::to_cbor).collect()),
                        ),
                    ];
                    if !cbs.is_empty() {
                        entries.push((
                            "callbacks",
                            Cbor::Array(
                                cbs.iter()
                                    .map(|(i, c)| {
                                        Cbor::Array(vec![
                                            Cbor::Integer((*i as u64).into()),
                                            Cbor::Integer(c.inner.id.into()),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ));
                    }
                    Cbor::Map(
                        entries
                            .into_iter()
                            .map(|(k, v)| (Cbor::Text(k.to_string()), v))
                            .collect(),
                    )
                }
            });
        }
        Ok(Cbor::Array(ops))
    }
}

fn map<const N: usize>(entries: [(&str, Cbor); N]) -> Cbor {
    Cbor::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Cbor::Text(k.to_string()), v))
            .collect(),
    )
}

fn cbor_get<'a>(c: &'a Cbor, key: &str) -> Option<&'a Cbor> {
    match c {
        Cbor::Map(m) => m
            .iter()
            .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
            .map(|(_, v)| v),
        _ => None,
    }
}

fn cbor_text<'a>(c: &'a Cbor, key: &str) -> Option<&'a str> {
    match cbor_get(c, key) {
        Some(Cbor::Text(t)) => Some(t),
        _ => None,
    }
}

fn cbor_u64(c: &Cbor, key: &str) -> Option<u64> {
    match cbor_get(c, key) {
        Some(Cbor::Integer(i)) => u64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

// ── The client ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// What [`ObjectsClient::open_with`] takes.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// How long a request waits for its answer.
    pub timeout: Duration,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// What [`Target::subscribe`] takes.
#[derive(Debug, Clone)]
pub struct SubscribeOptions {
    /// Events the subscription holds for its reader; more are dropped here and counted.
    pub capacity: usize,
    /// Extra event properties the host lists for the type (at most 16).
    pub fields: Vec<String>,
}

impl Default for SubscribeOptions {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_EVENT_CAPACITY,
            fields: Vec::new(),
        }
    }
}

/// What [`Target::snapshot`] takes.
#[derive(Debug, Clone, Default)]
pub struct SnapshotOptions {
    /// How deep (the host caps it at its own bound).
    pub depth: Option<u32>,
    /// How many bytes (the host caps it at its own bound).
    pub max_bytes: Option<u64>,
}

type Pending = oneshot::Sender<std::result::Result<Cbor, ObjectsError>>;

struct SubState {
    tx: mpsc::Sender<Event>,
    lost_here: Arc<AtomicU64>,
    lost_by_host: Arc<AtomicU64>,
    /// The handle it was made through: the host ends it with the handle.
    handle: Option<String>,
}

struct CallbackState {
    tx: mpsc::Sender<CallbackCall>,
    lost_here: Arc<AtomicU64>,
    lost_by_host: Arc<AtomicU64>,
}

struct Shared {
    pending: StdMutex<HashMap<u64, Pending>>,
    subs: StdMutex<HashMap<u64, SubState>>,
    callbacks: StdMutex<HashMap<u64, CallbackState>>,
    /// Why the host said it was ending the channel (`closing`), or `Some("")` for an end without a word.
    ended: StdMutex<Option<String>>,
    closed: AtomicBool,
}

struct Inner {
    channel: Arc<RpcChannel>,
    shared: Arc<Shared>,
    /// Set once, from the host's answer to `roots`.
    roots: OnceLock<Vec<String>>,
    features: OnceLock<Vec<String>>,
    next_id: AtomicU64,
    next_sub: AtomicU64,
    next_callback: AtomicU64,
    timeout: Duration,
}

impl Shared {
    /// The host ends the subscriptions made through a handle with it: forget them here too (their readers see the end).
    fn forget_handle_subs(&self, handle: &str) {
        self.subs
            .lock()
            .expect("objects state")
            .retain(|_, s| s.handle.as_deref() != Some(handle));
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The channel goes with the client: the host drops the listeners, the handles and the table.
        let channel = self.channel.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move { channel.close().await });
        }
    }
}

/// An open `wsh-objects` channel.
#[derive(Clone)]
pub struct ObjectsClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for ObjectsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectsClient")
            .field("roots", &self.roots())
            .field("features", &self.features())
            .finish()
    }
}

impl ObjectsClient {
    /// Open the `wsh-objects` channel of a connected client and ask for the roots. Refuses, before opening anything,
    /// a host that does not state the protocol ([`ErrorKind::Unsupported`]).
    pub async fn open(client: &WshClient) -> Result<Self> {
        Self::open_with(client, OpenOptions::default()).await
    }

    pub async fn open_with(client: &WshClient, options: OpenOptions) -> Result<Self> {
        let offer = client.rpc_offer().await;
        if !offer.serves(OBJECTS_PROTOCOL) {
            return Err(ObjectsError::unsupported(&format!(
                "the \"{OBJECTS_PROTOCOL}\" channel{}",
                if offer.protocols.is_empty() {
                    String::new()
                } else {
                    format!(" (it offers: {})", offer.protocols.join(", "))
                }
            )));
        }
        let channel = client
            .open_rpc_values(OBJECTS_PROTOCOL)
            .await
            .map_err(from_wsh)?;
        Self::from_channel(channel, options).await
    }

    /// Speak the protocol over a channel opened with [`WshClient::open_rpc_values`].
    pub async fn from_channel(channel: RpcChannel, options: OpenOptions) -> Result<Self> {
        let channel = Arc::new(channel);
        let shared = Arc::new(Shared {
            pending: StdMutex::new(HashMap::new()),
            subs: StdMutex::new(HashMap::new()),
            callbacks: StdMutex::new(HashMap::new()),
            ended: StdMutex::new(None),
            closed: AtomicBool::new(false),
        });
        tokio::spawn(read_loop(channel.clone(), shared.clone()));
        // If anything below fails the `Inner` is dropped, which closes the channel.
        let inner = Arc::new(Inner {
            channel: channel.clone(),
            shared,
            roots: OnceLock::new(),
            features: OnceLock::new(),
            next_id: AtomicU64::new(1),
            next_sub: AtomicU64::new(1),
            next_callback: AtomicU64::new(1),
            timeout: options.timeout,
        });
        let answer = inner.request("roots", Cbor::Map(Vec::new())).await?;
        let texts = |key: &str| match cbor_get(&answer, key) {
            Some(Cbor::Array(items)) => Some(
                items
                    .iter()
                    .filter_map(|c| match c {
                        Cbor::Text(t) => Some(t.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };
        let Some(roots) = texts("roots") else {
            return Err(ObjectsError::protocol("the host did not list its roots"));
        };
        // A host that says nothing (before 0.48.0) supports none of the features.
        let features = texts("features").unwrap_or_default();
        let _ = inner.roots.set(roots);
        let _ = inner.features.set(features);
        Ok(Self { inner })
    }

    /// The roots the host lists for this key.
    pub fn roots(&self) -> &[String] {
        self.inner.roots.get().map_or(&[], Vec::as_slice)
    }

    /// What the host says it supports (`events`, `handles`, `callbacks`).
    pub fn features(&self) -> &[String] {
        self.inner.features.get().map_or(&[], Vec::as_slice)
    }

    pub fn has_feature(&self, name: &str) -> bool {
        self.features().iter().any(|f| f == name)
    }

    /// A root, to build paths on. A name the host did not list for this key is [`ErrorKind::NotFound`], here.
    pub fn root(&self, name: &str) -> Result<Target> {
        if !self.roots().iter().any(|r| r == name) {
            return Err(ObjectsError::local(
                ErrorKind::NotFound,
                "no-such-root",
                format!(
                    "no such root: {name:?} (the host lists: {})",
                    self.roots().join(", ")
                ),
            ));
        }
        Ok(Target {
            inner: self.inner.clone(),
            start: Start::Root(name.to_string()),
        })
    }

    /// What this key may do on a root, as plain data: `{ version, root, ops, allow, eventFields, types, handles }` (the
    /// host's allow-list entries for the root, narrowed by the key's capabilities, and the host's type map for them).
    /// Needs the host to state `types`. Everything in it is the host's own text: untrusted, never evaluated.
    pub async fn root_description(&self, root: &str) -> Result<Value> {
        self.inner.require(FEATURE_TYPES)?;
        // the same local refusal as any request that names a root the host did not list
        self.root(root)?;
        let answer = self
            .inner
            .request("types", map([("root", Cbor::Text(root.to_string()))]))
            .await?;
        Value::from_cbor(answer)
    }

    /// A function of this side for the host to call: pass it to [`Target::call_with`]. The host's calls arrive in a
    /// queue of `capacity` calls ([`Callback::recv`]); more are dropped here and counted. Needs `capacity >= 1`; the
    /// host must state `callbacks` when it is passed.
    pub fn callback(&self, capacity: usize) -> Result<Callback> {
        if capacity == 0 {
            return Err(ObjectsError::invalid("a callback holds at least one call"));
        }
        if self.inner.shared.closed.load(Ordering::Relaxed) {
            return Err(self.inner.ended_error());
        }
        let id = self.inner.next_callback.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(capacity);
        let lost_here = Arc::new(AtomicU64::new(0));
        let lost_by_host = Arc::new(AtomicU64::new(0));
        self.inner
            .shared
            .callbacks
            .lock()
            .expect("objects state")
            .insert(
                id,
                CallbackState {
                    tx,
                    lost_here: lost_here.clone(),
                    lost_by_host: lost_by_host.clone(),
                },
            );
        Ok(Callback {
            inner: Arc::new(CallbackInner {
                client: self.inner.clone(),
                id,
                rx: tokio::sync::Mutex::new(rx),
                lost_here,
                lost_by_host,
                sent: AtomicBool::new(false),
                released: AtomicBool::new(false),
            }),
        })
    }

    /// Why the host ended the channel, if it said (`closing`).
    pub fn closing_reason(&self) -> Option<String> {
        self.inner
            .shared
            .ended
            .lock()
            .expect("objects state")
            .clone()
            .filter(|r| !r.is_empty())
    }

    /// Whether the channel has ended.
    pub fn is_closed(&self) -> bool {
        self.inner.shared.closed.load(Ordering::Relaxed) || self.inner.channel.is_closed()
    }

    /// End the channel: the host drops the listeners and releases every handle.
    pub async fn close(&self) {
        self.inner.channel.close().await;
    }
}

fn from_wsh(e: WshError) -> ObjectsError {
    let text = e.to_string();
    if text.contains("UNSUPPORTED_PROTOCOL") {
        ObjectsError::local(ErrorKind::Unsupported, "unsupported", text)
    } else if text.contains("rpc message limit") {
        ObjectsError::local(ErrorKind::Limit, "limit", text)
    } else if matches!(e, WshError::Channel(_)) && text.contains("closed") {
        ObjectsError::closed(&text)
    } else {
        ObjectsError::local(ErrorKind::Failed, "channel", text)
    }
}

impl Inner {
    /// One request; the answer's `result`, or the error. The wait is bounded by the timeout, and a request given up
    /// on is forgotten (a late answer is noise).
    async fn request(&self, method: &str, params: Cbor) -> Result<Cbor> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Err(self.ended_error());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.shared
            .pending
            .lock()
            .expect("objects state")
            .insert(id, tx);
        struct Forget<'a>(&'a Shared, u64);
        impl Drop for Forget<'_> {
            fn drop(&mut self) {
                self.0
                    .pending
                    .lock()
                    .expect("objects state")
                    .remove(&self.1);
            }
        }
        let _forget = Forget(&self.shared, id);
        let message = map([
            ("jsonrpc", Cbor::Text("2.0".into())),
            ("id", Cbor::Integer(id.into())),
            ("method", Cbor::Text(method.to_string())),
            ("params", params),
        ]);
        if let Err(e) = self.channel.send_values(&message).await {
            return Err(if self.shared.closed.load(Ordering::Relaxed) {
                self.ended_error()
            } else {
                from_wsh(e)
            });
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(self.ended_error()),
            Err(_) => Err(ObjectsError::local(
                ErrorKind::Failed,
                "timeout",
                format!("no answer to {method} in {} ms", self.timeout.as_millis()),
            )),
        }
    }

    fn ended_error(&self) -> ObjectsError {
        let why = self.shared.ended.lock().expect("objects state").clone();
        match why.filter(|w| !w.is_empty()) {
            Some(w) => ObjectsError::closed(&format!("the channel ended: the host said {w:?}")),
            None => ObjectsError::closed("the channel ended"),
        }
    }

    fn require(&self, feature: &str) -> Result<()> {
        if self
            .features
            .get()
            .is_some_and(|fs| fs.iter().any(|f| f == feature))
        {
            Ok(())
        } else {
            Err(ObjectsError::unsupported(&format!(
                "the \"{feature}\" feature"
            )))
        }
    }
}

/// Turns the host's messages into answers, events and the end of the channel.
async fn read_loop(channel: Arc<RpcChannel>, shared: Arc<Shared>) {
    while let Some(message) = channel.recv_values().await {
        let Ok(message) = message else { break };
        dispatch(&channel, &shared, message).await;
    }
    shared.closed.store(true, Ordering::Relaxed);
    {
        let mut ended = shared.ended.lock().expect("objects state");
        if ended.is_none() {
            *ended = Some(String::new());
        }
    }
    // Everything waiting is told; the subscriptions' senders go, which ends their receivers.
    let pending: Vec<Pending> = shared
        .pending
        .lock()
        .expect("objects state")
        .drain()
        .map(|(_, p)| p)
        .collect();
    let why = shared.ended.lock().expect("objects state").clone();
    for p in pending {
        let _ = p.send(Err(ObjectsError::closed(&match why.as_deref() {
            Some(w) if !w.is_empty() => format!("the channel ended: the host said {w:?}"),
            _ => "the channel ended".to_string(),
        })));
    }
    shared.subs.lock().expect("objects state").clear();
    shared.callbacks.lock().expect("objects state").clear();
}

async fn dispatch(channel: &RpcChannel, shared: &Shared, message: Cbor) {
    let id = cbor_u64(&message, "id");
    let method = cbor_text(&message, "method").map(str::to_string);
    match (method, id) {
        // An answer.
        (None, Some(id)) => {
            let waiting = shared.pending.lock().expect("objects state").remove(&id);
            let Some(tx) = waiting else { return };
            let answer = if let Some(err) = cbor_get(&message, "error") {
                let code = match cbor_get(err, "code") {
                    Some(Cbor::Integer(i)) => i64::try_from(i128::from(*i)).unwrap_or(-32603),
                    _ => -32603,
                };
                let text = cbor_text(err, "message").unwrap_or("error").to_string();
                let data = cbor_get(err, "data").and_then(|d| Value::from_cbor(d.clone()).ok());
                Err(ObjectsError::from_rpc(code, text, data))
            } else {
                Ok(cbor_get(&message, "result").cloned().unwrap_or(Cbor::Null))
            };
            let _ = tx.send(answer);
        }
        // A notification.
        (Some(method), None) => {
            let params = cbor_get(&message, "params");
            match (method.as_str(), params) {
                ("event", Some(p)) => deliver_event(shared, p),
                ("callback", Some(p)) => deliver_callback(shared, p),
                ("closing", Some(p)) => {
                    let reason = cbor_text(p, "reason").unwrap_or("closing");
                    *shared.ended.lock().expect("objects state") = Some(reason.to_string());
                }
                // progress and anything else: noise
                _ => {}
            }
        }
        // The host asks something of us: this client serves no method.
        (Some(_), Some(id)) => {
            let reply = map([
                ("jsonrpc", Cbor::Text("2.0".into())),
                ("id", Cbor::Integer(id.into())),
                (
                    "error",
                    map([
                        ("code", Cbor::Integer((-32601i64).into())),
                        ("message", Cbor::Text("method not found".into())),
                    ]),
                ),
            ]);
            let _ = channel.send_values(&reply).await;
        }
        (None, None) => {}
    }
}

fn deliver_event(shared: &Shared, params: &Cbor) {
    let (Some(id), Some(seq)) = (cbor_u64(params, "id"), cbor_u64(params, "seq")) else {
        return;
    };
    let by_host = cbor_u64(params, "dropped").unwrap_or(0);
    let Some(data) = cbor_get(params, "data").and_then(|d| Value::from_cbor(d.clone()).ok()) else {
        return;
    };
    let subs = shared.subs.lock().expect("objects state");
    let Some(sub) = subs.get(&id) else { return };
    // What was lost since the last event this reader got is told with this one.
    let owed_here = sub.lost_here.swap(0, Ordering::Relaxed);
    let owed_host = sub.lost_by_host.swap(0, Ordering::Relaxed) + by_host;
    let event = Event {
        seq,
        data,
        dropped_by_host: owed_host,
        dropped_here: owed_here,
    };
    // Never waits: a reader that cannot keep up loses events (counted), and every answer behind them still arrives.
    if sub.tx.try_send(event).is_err() {
        sub.lost_here.fetch_add(owed_here + 1, Ordering::Relaxed);
        sub.lost_by_host.fetch_add(owed_host, Ordering::Relaxed);
    }
}

fn deliver_callback(shared: &Shared, params: &Cbor) {
    let (Some(id), Some(seq)) = (cbor_u64(params, "id"), cbor_u64(params, "seq")) else {
        return;
    };
    let by_host = cbor_u64(params, "dropped").unwrap_or(0);
    let Some(Cbor::Array(items)) = cbor_get(params, "args") else {
        return;
    };
    let Ok(args) = items
        .iter()
        .map(|a| Value::from_cbor(a.clone()))
        .collect::<std::result::Result<Vec<_>, _>>()
    else {
        return;
    };
    let callbacks = shared.callbacks.lock().expect("objects state");
    let Some(cb) = callbacks.get(&id) else { return };
    let owed_here = cb.lost_here.swap(0, Ordering::Relaxed);
    let owed_host = cb.lost_by_host.swap(0, Ordering::Relaxed) + by_host;
    let call = CallbackCall {
        seq,
        args,
        dropped_by_host: owed_host,
        dropped_here: owed_here,
    };
    // Never waits, as for events: what does not fit is lost here, counted, and told with the next call that does.
    if cb.tx.try_send(call).is_err() {
        cb.lost_here.fetch_add(owed_here + 1, Ordering::Relaxed);
        cb.lost_by_host.fetch_add(owed_host, Ordering::Relaxed);
    }
}

// ── Targets: a root or a handle ─────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum Start {
    Root(String),
    Handle(Arc<HandleInner>),
}

/// Where requests start: a root, or a handle. Cheap to clone.
#[derive(Clone)]
pub struct Target {
    inner: Arc<Inner>,
    start: Start,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.start {
            Start::Root(r) => write!(f, "Target(root {r})"),
            Start::Handle(h) => write!(f, "Target(handle {})", h.kind),
        }
    }
}

impl Target {
    fn start_entry(&self) -> Result<(&'static str, Cbor)> {
        match &self.start {
            Start::Root(r) => Ok(("root", Cbor::Text(r.clone()))),
            Start::Handle(h) => {
                if h.released.load(Ordering::Relaxed) {
                    return Err(ObjectsError::invalid("the handle was released"));
                }
                Ok(("handle", Cbor::Text(h.id.clone())))
            }
        }
    }

    fn params(&self, rest: Vec<(&str, Cbor)>) -> Result<Cbor> {
        let (k, v) = self.start_entry()?;
        let mut entries = vec![(Cbor::Text(k.to_string()), v)];
        entries.extend(
            rest.into_iter()
                .map(|(k, v)| (Cbor::Text(k.to_string()), v)),
        );
        Ok(Cbor::Map(entries))
    }

    /// A chain of operations as one request: the last operation is the one the host's allow-list must allow.
    pub async fn resolve(&self, chain: Chain) -> Result<Reply> {
        // A function sent to a host that does not know callbacks would arrive there as null: refuse it here, by name.
        let mut passes_callbacks = false;
        for cb in chain.callbacks() {
            passes_callbacks = true;
            if !Arc::ptr_eq(&cb.inner.client, &self.inner) {
                return Err(ObjectsError::invalid(
                    "a callback of another channel cannot be passed here",
                ));
            }
            if cb.inner.released.load(Ordering::Relaxed) {
                return Err(ObjectsError::invalid("the callback was released"));
            }
        }
        if passes_callbacks {
            self.inner.require(FEATURE_CALLBACKS)?;
        }
        let ops = chain.to_cbor()?;
        // From here the host may know the callback (even if the call then fails or times out).
        for cb in chain.callbacks() {
            cb.inner.sent.store(true, Ordering::Relaxed);
        }
        let answer = self
            .inner
            .request("resolve", self.params(vec![("ops", ops)])?)
            .await?;
        parse_reply(&self.inner, &answer).map(|(r, _)| r)
    }

    /// Read the value at `path`.
    pub async fn get(&self, path: impl Into<Path>) -> Result<Reply> {
        let path = path.into();
        self.resolve(Chain::new().get(path)).await
    }

    /// Call the method the last segment of `path` names (the earlier segments are read on the way), with plain-data arguments.
    pub async fn call(&self, path: impl Into<Path>, args: Vec<Value>) -> Result<Reply> {
        let path = path.into();
        self.resolve(Chain::new().call(path, args)).await
    }

    /// Like [`Target::call`], with functions of this side ([`Callback`]) among the arguments. The host must state
    /// `callbacks`, and the allow-list entry of the method must end in `(callback)`.
    pub async fn call_with(&self, path: impl Into<Path>, args: Vec<Arg>) -> Result<Reply> {
        let path = path.into();
        self.resolve(Chain::new().call_with(path, args)).await
    }

    /// `new` the constructor the last segment of `path` names.
    pub async fn construct(&self, path: impl Into<Path>, args: Vec<Value>) -> Result<Reply> {
        let path = path.into();
        self.resolve(Chain::new().construct(path, args)).await
    }

    /// Assign `value` to the last segment of `path`.
    pub async fn set(&self, path: impl Into<Path>, value: Value) -> Result<()> {
        let path = path.into();
        if path.is_empty() {
            return Err(ObjectsError::invalid(
                "set needs a path of at least one segment",
            ));
        }
        path.check()?;
        self.inner
            .request(
                "set",
                self.params(vec![("path", path.to_cbor()), ("value", value.to_cbor())])?,
            )
            .await
            .map(|_| ())
    }

    /// A bounded deep copy of what `path` reaches.
    pub async fn snapshot(
        &self,
        path: impl Into<Path>,
        options: SnapshotOptions,
    ) -> Result<Snapshot> {
        let path = path.into();
        path.check()?;
        let mut rest = vec![("path", path.to_cbor())];
        if let Some(d) = options.depth {
            rest.push(("depth", Cbor::Integer(d.into())));
        }
        if let Some(b) = options.max_bytes {
            rest.push(("maxBytes", Cbor::Integer(b.into())));
        }
        let answer = self.inner.request("snapshot", self.params(rest)?).await?;
        let (reply, truncated) = parse_reply(&self.inner, &answer)?;
        Ok(Snapshot { reply, truncated })
    }

    /// The names under `path` the host's allow-lists could walk to.
    pub async fn describe(&self, path: impl Into<Path>) -> Result<Description> {
        let path = path.into();
        path.check()?;
        let answer = self
            .inner
            .request("describe", self.params(vec![("path", path.to_cbor())])?)
            .await?;
        let keys = match cbor_get(&answer, "keys") {
            Some(Cbor::Array(items)) => items
                .iter()
                .filter_map(|k| {
                    Some(KeyInfo {
                        key: cbor_text(k, "key")?.to_string(),
                        type_name: cbor_text(k, "type").unwrap_or("").to_string(),
                        own: matches!(cbor_get(k, "own"), Some(Cbor::Bool(true))),
                    })
                })
                .collect(),
            _ => return Err(ObjectsError::protocol("describe: no keys")),
        };
        Ok(Description {
            type_name: cbor_text(&answer, "type").unwrap_or("").to_string(),
            keys,
            truncated: matches!(cbor_get(&answer, "truncated"), Some(Cbor::Bool(true))),
        })
    }

    /// Listen to the events of type `event` of the source at `path` (an entry of the host's `allow.on`). Needs the
    /// host to state `events`. From a handle's target the host must also state `handle-events`: the source is the
    /// path that produced the handle, extended by `path`, judged as a path subscription for it (its own `allow.on`
    /// entry naming the type). Releasing the handle ends the subscription.
    pub async fn subscribe(
        &self,
        path: impl Into<Path>,
        event: &str,
        options: SubscribeOptions,
    ) -> Result<Subscription> {
        self.inner.require(FEATURE_EVENTS)?;
        let keepalive = match &self.start {
            Start::Root(_) => None,
            Start::Handle(h) => {
                self.inner.require(FEATURE_HANDLE_EVENTS)?;
                Some(h.clone())
            }
        };
        let (start_key, start_value) = self.start_entry()?;
        let path = path.into();
        path.check()?;
        if event.is_empty()
            || event.len() > TYPE_MAX
            || !event
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b':' | b'.' | b'-'))
        {
            return Err(ObjectsError::invalid(
                "an event type is a name of letters, digits and _ $ : . - (up to 128)",
            ));
        }
        if options.fields.len() > FIELDS_MAX {
            return Err(ObjectsError::invalid("at most 16 event fields"));
        }
        if options.capacity == 0 {
            return Err(ObjectsError::invalid(
                "a subscription holds at least one event",
            ));
        }
        let id = self.inner.next_sub.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(options.capacity);
        let lost_here = Arc::new(AtomicU64::new(0));
        let lost_by_host = Arc::new(AtomicU64::new(0));
        // Registered before the request: an event can follow the answer at once.
        self.inner
            .shared
            .subs
            .lock()
            .expect("objects state")
            .insert(
                id,
                SubState {
                    tx,
                    lost_here: lost_here.clone(),
                    lost_by_host: lost_by_host.clone(),
                    handle: keepalive.as_ref().map(|h| h.id.clone()),
                },
            );
        let mut params = vec![
            (Cbor::Text("id".into()), Cbor::Integer(id.into())),
            (Cbor::Text(start_key.to_string()), start_value),
            (Cbor::Text("path".into()), path.to_cbor()),
            (Cbor::Text("type".into()), Cbor::Text(event.to_string())),
        ];
        if !options.fields.is_empty() {
            params.push((
                Cbor::Text("fields".into()),
                Cbor::Array(options.fields.iter().cloned().map(Cbor::Text).collect()),
            ));
        }
        if let Err(e) = self.inner.request("subscribe", Cbor::Map(params)).await {
            self.inner
                .shared
                .subs
                .lock()
                .expect("objects state")
                .remove(&id);
            return Err(e);
        }
        Ok(Subscription {
            id,
            inner: self.inner.clone(),
            rx,
            lost_here,
            lost_by_host,
            done: false,
            _handle: keepalive,
        })
    }
}

fn parse_reply(inner: &Arc<Inner>, answer: &Cbor) -> Result<(Reply, bool)> {
    let truncated = matches!(cbor_get(answer, "truncated"), Some(Cbor::Bool(true)));
    if let Some(h) = cbor_text(answer, "h") {
        // What the host did not state it supports is not trusted: a handle from a host that never said `handles`.
        inner.require(FEATURE_HANDLES).map_err(|_| {
            ObjectsError::unsupported(
                "handles, yet it returned one: it is not a host this client understands",
            )
        })?;
        let preview = match cbor_get(answer, "preview").and_then(|p| cbor_get(p, "keys")) {
            Some(Cbor::Array(keys)) => keys
                .iter()
                .filter_map(|k| match k {
                    Cbor::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        return Ok((
            Reply::Handle(Handle {
                inner: Arc::new(HandleInner {
                    client: inner.clone(),
                    id: h.to_string(),
                    kind: cbor_text(answer, "kind").unwrap_or("object").to_string(),
                    type_name: cbor_text(answer, "type").map(str::to_string),
                    preview,
                    released: AtomicBool::new(false),
                }),
            }),
            truncated,
        ));
    }
    if let Some(u) = cbor_text(answer, "u") {
        return Ok((
            Reply::NonValue(NonValue {
                kind: u.to_string(),
                type_name: cbor_text(answer, "type").map(str::to_string),
                text: cbor_text(answer, "text").map(str::to_string),
            }),
            truncated,
        ));
    }
    match cbor_get(answer, "v") {
        Some(v) => Ok((Reply::Value(Value::from_cbor(v.clone())?), truncated)),
        None => Err(ObjectsError::protocol(
            "the answer is neither a value, a named non-value nor a handle",
        )),
    }
}

// ── Events ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/// An event the host delivered.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// The subscription's own count of delivered events, from 1 (the host's).
    pub seq: u64,
    /// Plain data: for an EventTarget source `{ type, timeStamp, isTrusted, ...fields }`, for an emitter `{ type, args }`.
    pub data: Value,
    /// Events the host dropped (rate, size, a full queue) before this one, since the last it delivered; plus those it
    /// reported for events this side then dropped.
    pub dropped_by_host: u64,
    /// Events this side dropped because the reader's queue was full, since the last one it was given.
    pub dropped_here: u64,
}

/// A live subscription: events arrive in a bounded queue.
pub struct Subscription {
    id: u64,
    inner: Arc<Inner>,
    rx: mpsc::Receiver<Event>,
    lost_here: Arc<AtomicU64>,
    lost_by_host: Arc<AtomicU64>,
    done: bool,
    /// The handle a subscription through one stands on lives as long as the subscription does.
    _handle: Option<Arc<HandleInner>>,
}

impl Subscription {
    /// The next event; `None` when the subscription or the channel has ended.
    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Events dropped here since the last one was read, not yet told to the reader.
    pub fn pending_dropped_here(&self) -> u64 {
        self.lost_here.load(Ordering::Relaxed)
    }

    /// Events the host reported dropped, for events this side then dropped, not yet told.
    pub fn pending_dropped_by_host(&self) -> u64 {
        self.lost_by_host.load(Ordering::Relaxed)
    }

    /// Stop listening. Returns how many events the host says it dropped and never told of.
    pub async fn unsubscribe(mut self) -> Result<u64> {
        self.done = true;
        let existed = self
            .inner
            .shared
            .subs
            .lock()
            .expect("objects state")
            .remove(&self.id)
            .is_some();
        if !existed {
            // Ended already (the handle it stood on was released, or the channel ended): the host forgot it too.
            return Ok(0);
        }
        let answer = self
            .inner
            .request("unsubscribe", map([("id", Cbor::Integer(self.id.into()))]))
            .await?;
        Ok(cbor_u64(&answer, "dropped").unwrap_or(0))
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let existed = self
            .inner
            .shared
            .subs
            .lock()
            .expect("objects state")
            .remove(&self.id)
            .is_some();
        // Best effort: the host removes the listener (it would anyway when the channel ends).
        let inner = self.inner.clone();
        let id = self.id;
        if existed && !inner.shared.closed.load(Ordering::Relaxed) {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = inner
                        .request("unsubscribe", map([("id", Cbor::Integer(id.into()))]))
                        .await;
                });
            }
        }
    }
}

// ── Handles ─────────────────────────────────────────────────────────────────────────────────────────────────────────

struct HandleInner {
    client: Arc<Inner>,
    id: String,
    kind: String,
    type_name: Option<String>,
    preview: Vec<String>,
    released: AtomicBool,
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        // A handle that is let go of gives its place back (the table holds 64 and evicts nothing).
        self.client.shared.forget_handle_subs(&self.id);
        if self.released.swap(true, Ordering::Relaxed)
            || self.client.shared.closed.load(Ordering::Relaxed)
        {
            return;
        }
        let client = self.client.clone();
        let id = self.id.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = client
                    .request("release", map([("handle", Cbor::Text(id))]))
                    .await;
            });
        }
    }
}

/// An opaque reference to something on the host that is not plain data: `kind` is `function` or `object`. It stands
/// at the path that produced it, and every operation through it is judged by the host's allow-lists for that path
/// extended by what you name: it never widens what the path grants. It means something on this channel only.
#[derive(Clone)]
pub struct Handle {
    inner: Arc<HandleInner>,
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The id is deliberately not shown.
        write!(f, "Handle({}", self.inner.kind)?;
        if let Some(t) = &self.inner.type_name {
            write!(f, " {t:?}")?;
        }
        write!(f, ")")
    }
}

impl Handle {
    /// `function` or `object`.
    pub fn kind(&self) -> &str {
        &self.inner.kind
    }

    /// The class or function name the host gave (the host's text: untrusted).
    pub fn type_name(&self) -> Option<&str> {
        self.inner.type_name.as_deref()
    }

    /// Up to 8 names of members, told only where a `get` of the path would be allowed.
    pub fn preview_keys(&self) -> &[String] {
        &self.inner.preview
    }

    /// Requests that start at this handle.
    pub fn target(&self) -> Target {
        Target {
            inner: self.inner.client.clone(),
            start: Start::Handle(self.inner.clone()),
        }
    }

    /// Give the handle's place back. Releasing a released handle does nothing. Every handle is released when the
    /// channel ends, and when the last reference to one is dropped.
    pub async fn release(&self) -> Result<()> {
        if self.inner.released.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        // The host ends the subscriptions made through the handle with it.
        self.inner.client.shared.forget_handle_subs(&self.inner.id);
        self.inner
            .client
            .request(
                "release",
                map([("handle", Cbor::Text(self.inner.id.clone()))]),
            )
            .await
            .map(|_| ())
    }

    pub fn is_released(&self) -> bool {
        self.inner.released.load(Ordering::Relaxed)
    }
}

// ── Callbacks ───────────────────────────────────────────────────────────────────────────────────────────────────────

/// One call of a [`Callback`] by the host.
#[derive(Debug, Clone, PartialEq)]
pub struct CallbackCall {
    /// The host's count of delivered calls of this callback, from 1.
    pub seq: u64,
    /// The arguments, copied as plain data (what the host could not clone is null).
    pub args: Vec<Value>,
    /// Calls the host dropped (rate, size, a full queue) before this one, since the last it delivered; plus those it
    /// reported for calls this side then dropped.
    pub dropped_by_host: u64,
    /// Calls this side dropped because the reader's queue was full, since the last one it was given.
    pub dropped_here: u64,
}

struct CallbackInner {
    client: Arc<Inner>,
    id: u64,
    rx: tokio::sync::Mutex<mpsc::Receiver<CallbackCall>>,
    lost_here: Arc<AtomicU64>,
    lost_by_host: Arc<AtomicU64>,
    /// Passed to a call at least once: the host may hold a stub for it.
    sent: AtomicBool,
    released: AtomicBool,
}

impl Drop for CallbackInner {
    fn drop(&mut self) {
        self.client
            .shared
            .callbacks
            .lock()
            .expect("objects state")
            .remove(&self.id);
        // The host holds a stub only for a callback that was passed (16 per channel): give its place back.
        if self.released.swap(true, Ordering::Relaxed)
            || !self.sent.load(Ordering::Relaxed)
            || self.client.shared.closed.load(Ordering::Relaxed)
        {
            return;
        }
        let client = self.client.clone();
        let id = self.id;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = client
                    .request("releaseCallback", map([("id", Cbor::Integer(id.into()))]))
                    .await;
            });
        }
    }
}

/// A function of this side for the host to call ([`ObjectsClient::callback`]), passed in the arguments of
/// [`Target::call_with`]. It is one-way: the host copies its arguments as plain data and queues the call; it never
/// waits for this side and gets nothing back. Calls arrive in a bounded queue ([`Callback::recv`]); what does not fit
/// is dropped and counted. The same `Callback` (or a clone of it) is the same function on the host, one place of the
/// host's 16 per channel. Cheap to clone; releasing it, or dropping the last reference, ends it.
#[derive(Clone)]
pub struct Callback {
    inner: Arc<CallbackInner>,
}

impl fmt::Debug for Callback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Callback({})", self.inner.id)
    }
}

impl Callback {
    /// The next call the host made; `None` once the callback was released or the channel ended (and the queue is empty).
    pub async fn recv(&self) -> Option<CallbackCall> {
        self.inner.rx.lock().await.recv().await
    }

    /// Calls dropped here since the last one was read, not yet told to the reader.
    pub fn pending_dropped_here(&self) -> u64 {
        self.inner.lost_here.load(Ordering::Relaxed)
    }

    /// Calls the host reported dropped, for calls this side then dropped, not yet told.
    pub fn pending_dropped_by_host(&self) -> u64 {
        self.inner.lost_by_host.load(Ordering::Relaxed)
    }

    /// Kill the host's stub of this function (a call of it is then a no-op there) and end the queue. Releasing a
    /// released callback does nothing, and one that was never passed to the host is only forgotten here. A host that
    /// says it has no such callback (a call that failed on the host takes its new callbacks with it) is not an error.
    pub async fn release(&self) -> Result<()> {
        if self.inner.released.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        self.inner
            .client
            .shared
            .callbacks
            .lock()
            .expect("objects state")
            .remove(&self.inner.id);
        if !self.inner.sent.load(Ordering::Relaxed) {
            return Ok(());
        }
        match self
            .inner
            .client
            .request(
                "releaseCallback",
                map([("id", Cbor::Integer(self.inner.id.into()))]),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind == ErrorKind::Invalid => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn is_released(&self) -> bool {
        self.inner.released.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
