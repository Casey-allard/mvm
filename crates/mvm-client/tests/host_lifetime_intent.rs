use mvm_client::{HostLifetimeIntent, LaunchRequest, LifecycleMode, RootfsSource};

#[test]
fn plain_and_raw_signed_resource_hints_are_readonly_and_not_admission() {
    let source = RootfsSource::LocalPath("/unused-intent-rootfs".into());
    let request = LaunchRequest::builder(LifecycleMode::Transient, source.clone())
        .name("intent-plain")
        .cpus(2)
        .memory_mib(1024)
        .backend("firecracker")
        .build()
        .unwrap();
    let hint: HostLifetimeIntent = request.host_lifetime_intent();
    assert_eq!(hint.name.as_deref(), Some("intent-plain"));
    assert_eq!(hint.mode, LifecycleMode::Transient);
    assert_eq!((hint.cpus, hint.memory_mib), (2, 1024));
    assert_eq!(hint.backend.as_deref(), Some("firecracker"));
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    let signed = mvm_core::plan::sign_plan(
        &plan,
        &ed25519_dalek::SigningKey::from_bytes(&[42; 32]),
        "untrusted-fixture",
    );
    let request = LaunchRequest::builder(LifecycleMode::Transient, source)
        .name("intent-signed")
        .cpus(8)
        .memory_mib(4096)
        .signed_plan(signed)
        .build()
        .unwrap();
    let mut projection = request.host_lifetime_intent();
    assert_eq!(
        (projection.cpus, projection.memory_mib),
        (
            plan.resources.cpus,
            plan.resources.mem_mib.try_into().unwrap()
        )
    );
    assert_eq!((projection.cpus, projection.memory_mib), (1, 128));
    assert_eq!(projection.name.as_deref(), Some("intent-signed"));
    projection.memory_mib = 65535;
    assert_eq!(
        request.host_lifetime_intent().memory_mib,
        128,
        "modifying a copied hint cannot alter the canonical request"
    );
    // No signature verification, opaque AdmittedPlan, owner or boot is created.
}
