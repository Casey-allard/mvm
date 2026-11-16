//! Synchronous decision writes; failure accounting belongs exclusively to the sink.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use mvm_core::audit_sink::AuditSink;

use super::{FlowMuxError, FlowMuxSession, registry::FlowClass};

pub(super) fn record(
    sink: &dyn AuditSink,
    event: &str,
    labels: BTreeMap<String, String>,
) -> std::io::Result<()> {
    sink.record(event, labels).inspect_err(|error| {
        tracing::warn!(%error, event, "FlowMux audit write failed; epoch marked incomplete");
    })
}

/// The original relay deadline precedes label construction and crosses the
/// synchronous sink's runtime boundary without starting another timeout.
pub(super) fn record_before(
    sink: &dyn AuditSink,
    event: &str,
    deadline: std::time::Instant,
    labels: impl FnOnce() -> BTreeMap<String, String>,
) -> std::io::Result<()> {
    let deadline = crate::broker::registry::owned_call_deadline()
        .map_or(deadline, |outer| outer.min(deadline));
    if std::time::Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "original flow audit deadline expired",
        ));
    }
    crate::broker::registry::with_owned_call_deadline(deadline, || record(sink, event, labels()))
}

/// Shared by the session and its UDP relay; only successful writes enter the cache.
#[derive(Default)]
pub(super) struct UdpDenials(Mutex<BTreeSet<SocketAddr>>);

impl UdpDenials {
    pub(super) fn record(
        &self,
        sink: &dyn AuditSink,
        stream_id: u32,
        target: SocketAddr,
        reason: &str,
        capacity: usize,
    ) {
        let mut recorded = self.0.lock().expect("UDP denial cache poisoned");
        if recorded.contains(&target) {
            sink.suppress_denial();
            return;
        }
        let mut labels = udp_labels(stream_id, target);
        labels.insert("reason".into(), reason.into());
        if record(sink, "host.flow.denied", labels).is_ok() && recorded.len() < capacity {
            recorded.insert(target);
        }
    }
}

pub(super) fn udp_labels(stream_id: u32, target: SocketAddr) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("stream_id".into(), stream_id.to_string()),
        ("class".into(), "udp".into()),
        ("target".into(), target.to_string()),
    ])
}

impl FlowMuxSession {
    pub(super) fn record_protocol_refusal(&self, stream_id: u32, reason: &str) {
        self.record_denial(
            "host.flow.denied",
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("class".into(), "session".into()),
                ("reason".into(), reason.into()),
            ]),
        );
    }

    pub(super) fn record_handler_error(
        &self,
        stream_id: u32,
        class: FlowClass,
        error: &FlowMuxError,
    ) {
        if matches!(error, FlowMuxError::Audit(_)) {
            return;
        }
        let event = if class == FlowClass::Icmp {
            "icmp.refused"
        } else {
            "host.flow.denied"
        };
        self.record_denial(
            event,
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("class".into(), class.to_string()),
                ("reason".into(), "host_refused".into()),
            ]),
        );
    }

    pub(super) fn record_dns_refusal(&self, stream_id: u32, reason: &str) {
        self.record_denial(
            "dns.refused",
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("reason".into(), reason.into()),
            ]),
        );
    }

    pub(super) fn record_allow(
        &self,
        event: &str,
        labels: BTreeMap<String, String>,
    ) -> std::io::Result<()> {
        record(self.audit_sink.as_ref(), event, labels)
    }

    pub(super) fn record_denial(&self, event: &str, labels: BTreeMap<String, String>) {
        // A failed write has marked the epoch incomplete before returning.
        if record(self.audit_sink.as_ref(), event, labels).is_err() {
            tracing::debug!(event, "FlowMux preserves denial after audit failure");
        }
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use crate::supervisor::audit::{
        audit_recorder::Recorder,
        bound_sink::BoundRecorder,
        signer::{AuditError, AuditSigner, PlanAuditEntry},
    };

    #[derive(Default)]
    struct DeadlineProbe(Mutex<Vec<Option<Instant>>>);

    #[async_trait::async_trait]
    impl AuditSigner for DeadlineProbe {
        async fn sign_and_emit(&self, _: &PlanAuditEntry) -> Result<(), AuditError> {
            self.0
                .lock()
                .unwrap()
                .push(crate::broker::registry::owned_call_deadline());
            Ok(())
        }
    }

    // Real bound-recorder readiness/recording with a probe signer. This does
    // not construct an installed authority or establish journal transport.
    fn bound_sink(
        runtime: &tokio::runtime::Runtime,
        path: &std::path::Path,
        signer: Arc<DeadlineProbe>,
    ) -> (Arc<Recorder>, BoundRecorder) {
        let context = mvm_core::audit_sink::AuditContext::Workload {
            plan: Box::new(mvm_core::plan::test_support::PlanFixture::new().build()),
        };
        let recorder = Arc::new(Recorder::new(
            signer,
            mvm_core::plan::TenantId("local".into()),
        ));
        let sink = BoundRecorder::builder(recorder.clone(), runtime.handle().clone(), context)
            .health_file(path.join("health.json"))
            .build()
            .unwrap();
        (recorder, sink)
    }

    #[test]
    fn expired_flow_deadline_refuses_before_labels_or_signer() {
        let home = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let signer = Arc::new(DeadlineProbe::default());
        let (_, sink) = bound_sink(&runtime, home.path(), signer.clone());
        let labels_built = AtomicBool::new(false);
        let error = record_before(
            &sink,
            "host.flow.allowed",
            Instant::now() - Duration::from_secs(1),
            || {
                labels_built.store(true, Ordering::Release);
                BTreeMap::new()
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(!labels_built.load(Ordering::Acquire));
        crate::broker::registry::with_owned_call_deadline(
            Instant::now() - Duration::from_secs(1),
            || {
                let error = record_before(
                    &sink,
                    "host.flow.allowed",
                    Instant::now() + Duration::from_secs(30),
                    || {
                        labels_built.store(true, Ordering::Release);
                        BTreeMap::new()
                    },
                )
                .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            },
        );
        assert!(!labels_built.load(Ordering::Acquire));
        assert_eq!(
            signer.0.lock().unwrap().as_slice(),
            [None],
            "only readiness was recorded"
        );
        assert_eq!(crate::broker::registry::owned_call_deadline(), None);
    }

    #[test]
    fn flow_deadline_reaches_bound_recorder_and_nested_scope_only_narrows() {
        let home = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let signer = Arc::new(DeadlineProbe::default());
        let (_, sink) = bound_sink(&runtime, home.path(), signer.clone());
        let now = Instant::now();
        let outer = now + Duration::from_secs(30);
        let earlier = now + Duration::from_secs(20);
        let later = now + Duration::from_secs(60);
        crate::broker::registry::with_owned_call_deadline(outer, || {
            record_before(&sink, "host.flow.allowed", earlier, BTreeMap::new).unwrap();
            assert_eq!(crate::broker::registry::owned_call_deadline(), Some(outer));
            record_before(&sink, "host.flow.allowed", later, BTreeMap::new).unwrap();
            assert_eq!(crate::broker::registry::owned_call_deadline(), Some(outer));
        });
        assert_eq!(
            signer.0.lock().unwrap().as_slice(),
            [None, Some(earlier), Some(outer)]
        );
        assert_eq!(crate::broker::registry::owned_call_deadline(), None);
        assert_eq!(sink.health().write_failures, 0);
    }
    #[test]
    fn async_service_bridge_carries_absolute_deadline_without_leaking_it() {
        let home = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let signer = Arc::new(DeadlineProbe::default());
        let (recorder, sink) = bound_sink(&runtime, home.path(), signer.clone());
        let sink = Arc::new(sink);
        let shared: Arc<dyn AuditSink> = sink.clone();
        recorder.bind_audit_sink(&shared).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        crate::broker::registry::with_owned_call_deadline(deadline, || {
            runtime.block_on(recorder.record_unbound(
                crate::supervisor::audit::audit_recorder::EventCategory::Host,
                "host.flow.allowed",
                BTreeMap::new(),
            ))
        })
        .unwrap();
        runtime
            .block_on(recorder.record_unbound(
                crate::supervisor::audit::audit_recorder::EventCategory::Host,
                "host.flow.allowed",
                BTreeMap::new(),
            ))
            .unwrap();
        assert_eq!(
            signer.0.lock().unwrap().as_slice(),
            [None, Some(deadline), None]
        );
        assert_eq!(crate::broker::registry::owned_call_deadline(), None);
    }

    #[test]
    fn deadline_scope_restores_after_a_label_builder_panics() {
        let home = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let signer = Arc::new(DeadlineProbe::default());
        let (_, sink) = bound_sink(&runtime, home.path(), signer.clone());
        let outer = Instant::now() + Duration::from_secs(30);
        crate::broker::registry::with_owned_call_deadline(outer, || {
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = record_before(
                    &sink,
                    "host.flow.allowed",
                    outer - Duration::from_secs(1),
                    || panic!("injected label construction failure"),
                );
            }));
            assert!(panic.is_err());
            assert_eq!(crate::broker::registry::owned_call_deadline(), Some(outer));
        });
        assert_eq!(crate::broker::registry::owned_call_deadline(), None);
        assert_eq!(signer.0.lock().unwrap().as_slice(), [None]);
    }
}
