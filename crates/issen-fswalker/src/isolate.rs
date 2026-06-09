//! Per-artifact isolation backstop (task A1).
//!
//! Wraps one artifact's parse in a bounded unit so a single bad real-world
//! artifact cannot crash the whole ingest. A unit that returns an error **or
//! panics** is captured as an [`IsolationFailure`]; the pipeline records it,
//! skips that artifact, and continues — ingest always terminates.
//!
//! (A0 fixed the known DuckDB ingest hang; this is the defensive backstop for
//! the *unknown* ones. Hang/infinite-loop protection via a per-unit timeout
//! additionally requires the emitter to be `Send` across a worker thread — a
//! larger change tracked separately; this module delivers panic + error
//! capture, which is what makes the pipeline panic-resilient today.)

use std::fmt::Display;

/// Why an isolated unit failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The unit returned `Err(..)`.
    Error,
    /// The unit panicked (the panic was caught at the isolation boundary).
    Panic,
}

/// A captured failure of one isolated unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationFailure {
    /// Identifier of the unit (e.g. the artifact path).
    pub unit: String,
    /// How it failed.
    pub kind: FailureKind,
    /// Human-readable reason (error message or panic payload).
    pub reason: String,
}

impl IsolationFailure {
    /// A one-line description suitable for an `errors`/`scan_findings` entry.
    #[must_use]
    pub fn describe(&self) -> String {
        let kind = match self.kind {
            FailureKind::Error => "error",
            FailureKind::Panic => "panic",
        };
        format!(
            "isolated unit '{}' failed ({kind}): {}",
            self.unit, self.reason
        )
    }
}

/// The result of running an isolated unit.
#[derive(Debug)]
pub enum Isolated<T> {
    /// The unit completed and returned a value.
    Completed(T),
    /// The unit failed (error or panic) and was captured.
    Failed(IsolationFailure),
}

/// Run `f` under isolation: a returned `Err` or a panic is captured as an
/// [`IsolationFailure`] instead of propagating, so the caller can record it,
/// skip the artifact, and continue. The panic hook still fires (the panic is
/// logged) but unwinding stops at this boundary.
pub fn run_isolated<T, E: Display>(
    unit: impl Into<String>,
    f: impl FnOnce() -> Result<T, E>,
) -> Isolated<T> {
    let unit = unit.into();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(value)) => Isolated::Completed(value),
        Ok(Err(e)) => Isolated::Failed(IsolationFailure {
            unit,
            kind: FailureKind::Error,
            reason: e.to_string(),
        }),
        Err(payload) => Isolated::Failed(IsolationFailure {
            unit,
            kind: FailureKind::Panic,
            reason: panic_message(payload.as_ref()),
        }),
    }
}

/// Best-effort readable message from a caught panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_on_ok() {
        let outcome = run_isolated("u", || Ok::<_, String>(7));
        assert!(matches!(outcome, Isolated::Completed(7)));
    }

    #[test]
    fn captures_error_as_failure() {
        let outcome = run_isolated("parse-mft", || Err::<(), _>("bad header"));
        match outcome {
            Isolated::Failed(f) => {
                assert_eq!(f.kind, FailureKind::Error);
                assert_eq!(f.unit, "parse-mft");
                assert!(f.reason.contains("bad header"));
            }
            Isolated::Completed(()) => panic!("should have failed"),
        }
    }

    #[test]
    fn captures_panic_as_failure() {
        let outcome = run_isolated("parse-evtx", || -> Result<(), String> {
            panic!("index out of bounds: the len is 1024");
        });
        match outcome {
            Isolated::Failed(f) => {
                assert_eq!(f.kind, FailureKind::Panic);
                assert!(f.reason.contains("index out of bounds"));
            }
            Isolated::Completed(()) => panic!("should have failed"),
        }
    }

    #[test]
    fn describe_names_kind_and_unit() {
        let f = IsolationFailure {
            unit: "C:/x.evtx".to_string(),
            kind: FailureKind::Panic,
            reason: "boom".to_string(),
        };
        let d = f.describe();
        assert!(d.contains("panic") && d.contains("C:/x.evtx") && d.contains("boom"));
    }
}
