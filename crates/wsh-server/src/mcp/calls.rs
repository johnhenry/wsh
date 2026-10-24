//! In-flight `McpCall`s of one connection, so `McpCancel` can stop them.
//!
//! A correlated call (one with a `call_id`) runs as a task the message loop does not wait
//! for. Exactly one of the task and a cancel sends the reply: whichever flips the call's
//! `done` flag first. A task that loses the race is already being aborted (or has nothing
//! left to send), so a call is never answered twice.

use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use wsh_core::messages::{Envelope, McpResultPayload, MsgType, Payload};

/// The `error` text of a cancelled call; the JS server sends the same.
pub const CANCELLED: &str = "cancelled by the caller";

struct Entry {
    seq: u64,
    done: Arc<AtomicBool>,
    abort: AbortHandle,
}

/// Abortable `McpCall` tasks, by call_id. Dropping it aborts every call still running.
#[derive(Default)]
pub struct McpCalls {
    next: AtomicU64,
    calls: Arc<Mutex<HashMap<String, Entry>>>,
}

fn result_envelope(call_id: &str, result: serde_json::Value) -> Envelope {
    Envelope {
        msg_type: MsgType::McpResult,
        payload: Payload::McpResult(McpResultPayload {
            call_id: Some(call_id.to_string()),
            result,
        }),
    }
}

impl McpCalls {
    /// Run `fut` as a task and send its result to `tx` when it finishes (unless cancelled).
    /// Dropping the future is how a cancel stops the work, so it should clean up after
    /// itself on drop (the CLI bridge kills its process group).
    pub fn spawn<F>(&self, call_id: String, tx: mpsc::Sender<Envelope>, fut: F)
    where
        F: Future<Output = McpResultPayload> + Send + 'static,
    {
        let seq = self.next.fetch_add(1, Ordering::Relaxed);
        let done = Arc::new(AtomicBool::new(false));
        // Held across spawn + insert so the task's own cleanup cannot run before the entry exists.
        let mut calls = self.calls.lock().unwrap();
        let task_done = done.clone();
        let task_calls = self.calls.clone();
        let id = call_id.clone();
        let handle = tokio::spawn(async move {
            let result = fut.await;
            if !task_done.swap(true, Ordering::SeqCst) {
                let _ = tx.send(result_envelope(&id, result.result)).await;
            }
            let mut calls = task_calls.lock().unwrap();
            if calls.get(&id).is_some_and(|e| e.seq == seq) {
                calls.remove(&id);
            }
        });
        // A repeated id replaces the older entry (that call just can't be cancelled any more).
        calls.insert(
            call_id,
            Entry {
                seq,
                done,
                abort: handle.abort_handle(),
            },
        );
    }

    /// Stop the call with this id. Returns the single cancelled reply, or `None` when the id
    /// is unknown or the call has already finished (or is replying right now).
    pub fn cancel(&self, call_id: &str) -> Option<Envelope> {
        let entry = self.calls.lock().unwrap().remove(call_id)?;
        if entry.done.swap(true, Ordering::SeqCst) {
            return None;
        }
        entry.abort.abort();
        Some(result_envelope(
            call_id,
            json!({ "success": false, "error": CANCELLED }),
        ))
    }
}

impl Drop for McpCalls {
    fn drop(&mut self) {
        if let Ok(calls) = self.calls.lock() {
            for e in calls.values() {
                e.abort.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ok(call_id: &str) -> McpResultPayload {
        McpResultPayload {
            call_id: Some(call_id.into()),
            result: json!({ "ok": true }),
        }
    }

    fn body(e: &Envelope) -> (&Option<String>, &serde_json::Value) {
        match &e.payload {
            Payload::McpResult(r) => (&r.call_id, &r.result),
            _ => panic!("not an McpResult"),
        }
    }

    #[tokio::test]
    async fn finished_call_replies_once_and_a_late_cancel_is_a_no_op() {
        let calls = McpCalls::default();
        let (tx, mut rx) = mpsc::channel(8);
        calls.spawn("a".into(), tx, async { ok("a") });
        let reply = rx.recv().await.unwrap();
        assert_eq!(body(&reply).1, &json!({ "ok": true }));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(calls.cancel("a").is_none());
        assert!(calls.cancel("never-issued").is_none());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancel_drops_the_future_and_answers_once() {
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(dropped.clone());
        let calls = McpCalls::default();
        let (tx, mut rx) = mpsc::channel(8);
        calls.spawn("slow".into(), tx.clone(), async move {
            let _guard = guard;
            tokio::time::sleep(Duration::from_secs(30)).await;
            ok("slow")
        });
        calls.spawn("other".into(), tx, async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            ok("other")
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let cancelled = calls.cancel("slow").expect("a cancelled reply");
        let (id, result) = body(&cancelled);
        assert_eq!(id.as_deref(), Some("slow"));
        assert_eq!(result, &json!({ "success": false, "error": CANCELLED }));
        assert!(calls.cancel("slow").is_none(), "cancel is idempotent");

        // The other call is unaffected, and nothing else was sent for the cancelled one.
        let reply = rx.recv().await.unwrap();
        assert_eq!(body(&reply).0.as_deref(), Some("other"));
        assert!(dropped.load(Ordering::SeqCst), "the future was dropped");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dropping_the_registry_aborts_what_is_running() {
        let dropped = Arc::new(AtomicBool::new(false));
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let guard = SetOnDrop(dropped.clone());
        let calls = McpCalls::default();
        let (tx, _rx) = mpsc::channel(8);
        calls.spawn("x".into(), tx, async move {
            let _guard = guard;
            tokio::time::sleep(Duration::from_secs(30)).await;
            ok("x")
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(calls);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(dropped.load(Ordering::SeqCst));
    }
}
