#![cfg(unix)]

use mvm_core::{
    host_lifetime::{
        HostLaunchBinding, HostLeaseExpectation, HostLifetimeInputs, PreparedHostLifetime,
    },
    vm_backend::{BackendKind, VmStartConfig},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Parent(Arc<AtomicUsize>);
impl Drop for Parent {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(feature = "test-support")]
struct Permit {
    binding: mvm_core::host_lifetime::HostLaunchBinding,
    open: std::sync::atomic::AtomicBool,
}
#[cfg(feature = "test-support")]
impl mvm_core::host_lifetime::CoreCurrentParentPermit for Permit {
    fn check_current(
        &self,
        binding: &mvm_core::host_lifetime::HostLaunchBinding,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            binding == &self.binding && self.open.load(Ordering::Acquire),
            "parent resource grant is not current"
        );
        Ok(())
    }
}

fn inputs(root: &std::path::Path) -> HostLifetimeInputs {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = b"bounded original active state";
    let state_path = root.join(".state");
    std::fs::write(&state_path, state).unwrap();
    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("holders.lock"))
        .unwrap();
    HostLifetimeInputs {
        directory: File::open(root).unwrap(),
        holder,
        expected: HostLeaseExpectation {
            state_name: ".state".into(),
            state_bytes: state.len() as u16,
            state_sha256: Sha256::digest(state).into(),
            absent_names: [".state.intent".into(), ".state.next".into()],
        },
        binding: HostLaunchBinding {
            installation: [1; 32],
            profile: [2; 32],
            generation: 3,
            grant_serial: 4,
            vm_name: "owned-test".into(),
            backend: BackendKind::Firecracker,
            cpus: 1,
            memory_mib: 1024,
        },
    }
}

#[test]
fn confinement_callback_borrows_only_readonly_current_state() {
    use std::io::{Read, Seek, SeekFrom, Write};
    let root = tempfile::tempdir().unwrap();
    let input = inputs(root.path());
    let lease = mvm_core::host_lifetime::PreparedHostLifetimeLease::bind(
        input.directory,
        input.holder,
        input.expected,
    )
    .unwrap();
    lease
        .with_verification_state(|state| {
            assert!(state.metadata()?.is_file());
            let mut observed = state.try_clone()?;
            observed.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            observed.read_to_end(&mut bytes)?;
            assert_eq!(bytes, b"bounded original active state");
            assert!(
                observed.write_all(b"x").is_err(),
                "the borrowed file is readonly"
            );
            Ok(())
        })
        .unwrap();
    let calls = AtomicUsize::new(0);
    std::fs::write(root.path().join(".state"), b"changed").unwrap();
    assert!(
        lease
            .with_verification_state(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn config_clones_retain_same_parent_and_refuse_substitution() {
    let root = tempfile::tempdir().unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let prepared =
        PreparedHostLifetime::bind(inputs(root.path()), Parent(dropped.clone())).unwrap();
    let anchor = prepared.into_anchor();
    let mut config = VmStartConfig {
        name: "owned-test".into(),
        cpus: 1,
        memory_mib: 1024,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let copy = config.clone();
    assert!(Arc::ptr_eq(
        config.host_lifetime.as_ref().unwrap(),
        copy.host_lifetime.as_ref().unwrap()
    ));
    anchor
        .verify_config(&copy, BackendKind::Firecracker)
        .unwrap();
    let mut wrong = copy.clone();
    wrong.memory_mib += 1;
    assert!(
        anchor
            .verify_config(&wrong, BackendKind::Firecracker)
            .is_err()
    );
    assert!(anchor.verify_config(&copy, BackendKind::Hvf).is_err());
    drop(wrong);
    drop(config);
    drop(anchor);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(copy);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn original_state_and_uncertainty_markers_are_checked_before_handoff() {
    let root = tempfile::tempdir().unwrap();
    let anchor = PreparedHostLifetime::bind(inputs(root.path()), ())
        .unwrap()
        .into_anchor();
    anchor.verify_current().unwrap();
    std::fs::write(root.path().join(".state.intent"), b"uncertain").unwrap();
    assert!(anchor.verify_current().is_err());
    std::fs::remove_file(root.path().join(".state.intent")).unwrap();
    std::fs::write(
        root.path().join(".state"),
        b"different original state bytes",
    )
    .unwrap();
    assert!(anchor.verify_current().is_err());
}

#[test]
fn holder_exclusion_outlives_preparation_and_config_aliases() {
    let root = tempfile::tempdir().unwrap();
    let anchor = PreparedHostLifetime::bind(inputs(root.path()), ())
        .unwrap()
        .into_anchor();
    let independent = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.path().join("holders.lock"))
        .unwrap();
    assert!(
        rustix::fs::flock(
            &independent,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        )
        .is_err()
    );
    let alias = anchor.clone();
    drop(anchor);
    assert!(
        rustix::fs::flock(
            &independent,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        )
        .is_err()
    );
    drop(alias);
    rustix::fs::flock(
        &independent,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}

#[cfg(feature = "test-support")]
#[test]
fn one_handoff_keeps_original_plan_body_and_nonce_across_aliases() {
    use mvm_core::plan::{sign_plan, test_support::PlanFixture};
    let root = tempfile::tempdir().unwrap();
    let anchor = PreparedHostLifetime::bind(inputs(root.path()), ())
        .unwrap()
        .into_anchor();
    let mut config = VmStartConfig {
        name: "owned-test".into(),
        cpus: 1,
        memory_mib: 1024,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().nonce([7; 16]).build();
    plan.resources.mem_mib = 1024;
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    config.plan_json = Some(serde_json::to_string(&sign_plan(&plan, &key, "test")).unwrap());
    assert!(
        anchor
            .claim_for_native(&config, BackendKind::Firecracker)
            .is_err()
    );
    anchor
        .bind_admitted(&config, BackendKind::Firecracker, &plan)
        .unwrap();
    anchor
        .bind_parent_permit(
            &config,
            BackendKind::Firecracker,
            Arc::new(Permit {
                binding: anchor.binding().clone(),
                open: std::sync::atomic::AtomicBool::new(true),
            }),
        )
        .unwrap();
    let mut substituted = config.clone();
    let mut changed = plan.clone();
    changed.workload.0 = "different-original-body".into();
    substituted.plan_json =
        Some(serde_json::to_string(&sign_plan(&changed, &key, "test")).unwrap());
    assert!(
        anchor
            .claim_for_native(&substituted, BackendKind::Firecracker)
            .is_err(),
        "a signed projection with a reused nonce cannot replace the admitted body"
    );
    let lease = anchor
        .claim_for_native(&config, BackendKind::Firecracker)
        .unwrap();
    lease.verify_current().unwrap();
    assert!(
        anchor
            .claim_for_native(&config.clone(), BackendKind::Firecracker)
            .is_err()
    );
}

#[cfg(feature = "test-support")]
#[test]
fn original_admission_without_actual_parent_permit_cannot_claim_native() {
    use mvm_core::plan::{sign_plan, test_support::PlanFixture};
    let root = tempfile::tempdir().unwrap();
    let anchor = PreparedHostLifetime::bind(inputs(root.path()), ())
        .unwrap()
        .into_anchor();
    let mut config = VmStartConfig {
        name: "owned-test".into(),
        cpus: 1,
        memory_mib: 1024,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().build();
    plan.resources.mem_mib = 1024;
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    config.plan_json = Some(
        serde_json::to_string(&sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
            "test",
        ))
        .unwrap(),
    );
    anchor
        .bind_admitted(&config, BackendKind::Firecracker, &plan)
        .unwrap();
    assert!(
        anchor
            .claim_for_native(&config, BackendKind::Firecracker)
            .is_err(),
        "retained () plus a valid original plan is not parent resource admission"
    );
}

#[cfg(feature = "test-support")]
#[test]
fn endpoint_handoff_requires_original_plan_and_one_current_typed_partition() {
    use mvm_core::host_lifetime::{
        CoreCurrentParentPermit, EndpointPartitionGuard, EndpointPartitionLimits,
        EndpointPartitionProjection, PreparedEndpointPartition,
    };
    use mvm_core::plan::{sign_plan, test_support::PlanFixture};
    struct Partition(EndpointPartitionProjection);
    impl EndpointPartitionGuard for Partition {
        fn check_current(&self, value: &EndpointPartitionProjection) -> anyhow::Result<()> {
            anyhow::ensure!(value == &self.0, "foreign fixture partition");
            Ok(())
        }
    }
    struct ParentPermit {
        projection: std::sync::Mutex<EndpointPartitionProjection>,
        calls: AtomicUsize,
    }
    impl CoreCurrentParentPermit for ParentPermit {
        fn check_current(&self, binding: &HostLaunchBinding) -> anyhow::Result<()> {
            anyhow::ensure!(
                *binding == self.projection.lock().unwrap().binding,
                "foreign fixture parent"
            );
            Ok(())
        }
        fn prepare_endpoint_partition(
            &self,
            _: &HostLaunchBinding,
        ) -> anyhow::Result<PreparedEndpointPartition> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let projection = self.projection.lock().unwrap().clone();
            PreparedEndpointPartition::new(projection.clone(), Arc::new(Partition(projection)))
        }
    }
    let root = tempfile::tempdir().unwrap();
    let anchor = PreparedHostLifetime::bind(inputs(root.path()), ())
        .unwrap()
        .into_anchor();
    let mut config = VmStartConfig {
        name: "owned-test".into(),
        cpus: 1,
        memory_mib: 1024,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().build();
    plan.resources.mem_mib = 1024;
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    config.plan_json = Some(
        serde_json::to_string(&sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
            "test",
        ))
        .unwrap(),
    );
    anchor
        .bind_admitted(&config, BackendKind::Firecracker, &plan)
        .unwrap();
    let parent = Arc::new(ParentPermit {
        projection: std::sync::Mutex::new(EndpointPartitionProjection {
            version: 1,
            binding: anchor.binding().clone(),
            admitted_plan_id: "wrong-original-plan".into(),
            session: [8; 32],
            partition_serial: 1,
            profile: 2,
            store: Some(mvm_core::host_lifetime::EndpointStoreLocator {
                version: 1,
                path: "/nonexistent-host-lifetime-fixture/store".into(),
                device: 1,
                inode: 1,
                reservation_serial: 1,
                tenant: [0; 32],
                session: [8; 32],
            }),
            limits: EndpointPartitionLimits {
                host_plaintext_bytes: 1,
                host_codec_bytes: 1,
                host_carrier_bytes: 1,
                host_metadata_bytes: 1,
                host_stack_bytes: 1,
                cache_disk_bytes: 0,
                staging_disk_bytes: 0,
                workers: 1,
                max_streams: 1,
            },
        }),
        calls: AtomicUsize::new(0),
    });
    anchor
        .bind_parent_permit(&config, BackendKind::Firecracker, parent.clone())
        .unwrap();
    assert!(
        anchor
            .prepare_endpoint_handoff(&config, BackendKind::Firecracker)
            .is_err()
    );
    parent.projection.lock().unwrap().admitted_plan_id = plan.plan_id.0.clone();
    let handoff = anchor
        .prepare_endpoint_handoff(&config, BackendKind::Firecracker)
        .unwrap();
    handoff.check_current().unwrap();
    assert_eq!(
        handoff.partition().projection().admitted_plan_id,
        plan.plan_id.0
    );
    let issued = parent.calls.load(Ordering::SeqCst);
    assert!(
        anchor
            .prepare_endpoint_handoff(&config, BackendKind::Firecracker)
            .is_err()
    );
    assert_eq!(
        parent.calls.load(Ordering::SeqCst),
        issued,
        "duplicate handoff must not reserve another partition"
    );
    // Endpoint handoff does not consume/replace original native authority.
    anchor
        .claim_for_native(&config, BackendKind::Firecracker)
        .unwrap();
}

#[cfg(feature = "test-support")]
#[test]
fn stale_foreign_and_replaced_parent_permits_refuse_without_changing_identity() {
    use mvm_core::plan::{sign_plan, test_support::PlanFixture};
    let root = tempfile::tempdir().unwrap();
    let anchor = PreparedHostLifetime::bind(inputs(root.path()), ())
        .unwrap()
        .into_anchor();
    let mut config = VmStartConfig {
        name: "owned-test".into(),
        cpus: 1,
        memory_mib: 1024,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config).unwrap();
    let mut plan = PlanFixture::new().build();
    plan.resources.mem_mib = 1024;
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    config.plan_json = Some(
        serde_json::to_string(&sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
            "test",
        ))
        .unwrap(),
    );
    anchor
        .bind_admitted(&config, BackendKind::Firecracker, &plan)
        .unwrap();
    let mut foreign = anchor.binding().clone();
    foreign.grant_serial += 1;
    assert!(
        anchor
            .bind_parent_permit(
                &config,
                BackendKind::Firecracker,
                Arc::new(Permit {
                    binding: foreign,
                    open: std::sync::atomic::AtomicBool::new(true)
                })
            )
            .is_err()
    );
    let permit = Arc::new(Permit {
        binding: anchor.binding().clone(),
        open: std::sync::atomic::AtomicBool::new(true),
    });
    anchor
        .bind_parent_permit(&config, BackendKind::Firecracker, permit.clone())
        .unwrap();
    assert!(
        anchor
            .bind_parent_permit(&config, BackendKind::Firecracker, permit.clone())
            .is_err()
    );
    permit.open.store(false, Ordering::Release);
    assert!(
        anchor
            .check_parent_current(&config, BackendKind::Firecracker)
            .is_err()
    );
    assert!(
        anchor
            .claim_for_native(&config, BackendKind::Firecracker)
            .is_err()
    );
    assert_eq!(anchor.binding().grant_serial, 4);
    assert_eq!(
        mvm_core::plan::plan_from_admitted_json(config.plan_json.as_deref().unwrap())
            .unwrap()
            .nonce,
        plan.nonce
    );
}

#[cfg(feature = "test-support")]
#[test]
fn portable_startup_workspace_is_single_use_and_owned_by_original_parent() {
    use mvm_core::{
        host_lifetime::CoreCurrentParentPermit,
        plan::{KeyId, PlanArtifact, sign_plan, test_support::PlanFixture},
        vm_backend::LegacyPortableRuntimeProof,
    };

    struct WorkspacePermit {
        binding: HostLaunchBinding,
        begins: AtomicUsize,
        completions: AtomicUsize,
        refuse_begin: bool,
    }
    impl CoreCurrentParentPermit for WorkspacePermit {
        fn check_current(&self, binding: &HostLaunchBinding) -> anyhow::Result<()> {
            anyhow::ensure!(*binding == self.binding, "foreign workspace binding");
            Ok(())
        }

        fn begin_startup_workspace(&self, binding: &HostLaunchBinding) -> anyhow::Result<()> {
            self.check_current(binding)?;
            self.begins.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(!self.refuse_begin, "workspace refused");
            Ok(())
        }

        fn complete_startup_workspace(&self, binding: &HostLaunchBinding) -> anyhow::Result<()> {
            self.check_current(binding)?;
            self.completions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    for (refuse_begin, complete) in [(false, true), (false, false), (true, false)] {
        let root = tempfile::tempdir().unwrap();
        let owner = PreparedHostLifetime::bind(inputs(root.path()), ())
            .unwrap()
            .into_anchor();
        let mut config = VmStartConfig {
            name: "owned-test".into(),
            cpus: 1,
            memory_mib: 1024,
            ..Default::default()
        };
        owner.bind_to_config(&mut config).unwrap();
        let mut plan = PlanFixture::new().build();
        plan.resources.mem_mib = 1024;
        let pin = PlanArtifact::new("a".repeat(64), &[7; 64], KeyId("test".into()));
        config.legacy_portable_runtime = Some(LegacyPortableRuntimeProof {
            archive: root.path().join("fixture.mvmpkg"),
            pin: pin.clone(),
            manifest_sha256: "b".repeat(64),
            arch: mvm_core::arch::GuestArch::host(),
        });
        plan.bundle = Some(pin);
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        config.plan_json = Some(
            serde_json::to_string(&sign_plan(
                &plan,
                &ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
                "test",
            ))
            .unwrap(),
        );
        let permit = Arc::new(WorkspacePermit {
            binding: owner.binding().clone(),
            begins: AtomicUsize::new(0),
            completions: AtomicUsize::new(0),
            refuse_begin,
        });
        let backend = BackendKind::Firecracker;
        assert!(owner.begin_startup_workspace(&config, backend).is_err());
        owner.bind_admitted(&config, backend, &plan).unwrap();
        assert!(owner.begin_startup_workspace(&config, backend).is_err());
        owner
            .bind_parent_permit(&config, backend, permit.clone())
            .unwrap();
        let mut foreign = config.clone();
        foreign.name = "foreign".into();
        assert!(owner.begin_startup_workspace(&foreign, backend).is_err());
        let mut wrong_bundle = config.clone();
        wrong_bundle
            .legacy_portable_runtime
            .as_mut()
            .unwrap()
            .pin
            .bundle_sha256 = "c".repeat(64);
        assert!(
            owner
                .begin_startup_workspace(&wrong_bundle, backend)
                .is_err()
        );
        assert_eq!(permit.begins.load(Ordering::SeqCst), 0);
        assert!(owner.claim_for_native(&config, backend).is_err());
        let mut stripped = config.clone();
        stripped.legacy_portable_runtime = None;
        assert!(owner.claim_for_native(&stripped, backend).is_err());
        assert!(owner.begin_startup_workspace(&stripped, backend).is_err());
        let workspace = owner.begin_startup_workspace(&config, backend);
        if refuse_begin {
            assert!(workspace.is_err());
        } else if complete {
            let workspace = workspace.unwrap();
            assert!(owner.claim_for_native(&config, backend).is_err());
            workspace.complete().unwrap();
        } else {
            drop(workspace.unwrap());
        }
        assert!(
            owner
                .clone()
                .begin_startup_workspace(&config.clone(), backend)
                .is_err()
        );
        assert_eq!(owner.claim_for_native(&config, backend).is_ok(), complete);
        assert_eq!(permit.begins.load(Ordering::SeqCst), 1);
        assert_eq!(
            permit.completions.load(Ordering::SeqCst),
            usize::from(complete)
        );
    }
}
