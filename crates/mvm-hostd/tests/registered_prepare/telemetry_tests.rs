use super::*;
use mvm_vmm::host::network_endpoint_spawn::spawn_telemetry_collector_installed_registered;

#[derive(Clone, Copy)]
enum Case {
    Collect,
    MissingRetainedCredit,
    ForeignRegistration,
    WrongRedaction,
}

fn telemetry_handoff(
    holder: &PreparedHostLifetimeLease,
    state: &Path,
    credit: bool,
) -> Result<(PreparedEndpointHandoff, Arc<Guard>)> {
    let policy = NetworkPolicy::deny_all();
    let mut plan = PlanFixture::new().workload("vm-1").build();
    plan.network_mode = mvm_core::plan::NetworkMode::HostVsockProxy;
    plan.asset_identities
        .push(mvm_core::plan::AssetIdentity::new(
            mvm_core::plan::AssetKind::Policy,
            "network_policy",
            mvm_core::policy::network_policy::content_sha256(&policy),
        )?);
    plan.plan_id = compute_plan_id(&plan);
    let issuer = SigningKey::from_bytes(&[8; 32]);
    let signed = sign_plan(&plan, &issuer, "fixture");
    let plan = mvm_core::plan::verify_plan(&signed, &[("fixture", &issuer.verifying_key())])?;
    let mut facts = fixture_projection(state, plan.plan_id.0.clone())?;
    facts.profile = 1;
    facts.store = None;
    facts.limits.host_codec_bytes = 0;
    facts.limits.staging_disk_bytes = 0;
    if !credit {
        facts.limits.cache_disk_bytes = 0;
    }
    let anchor = PreparedHostLifetime::bind(
        HostLifetimeInputs {
            directory: holder.directory().try_clone()?,
            holder: holder.holder().try_clone()?,
            expected: holder.expectation().clone(),
            binding: facts.binding.clone(),
        },
        (),
    )?
    .into_anchor();
    let mut config = VmStartConfig {
        name: "vm-1".into(),
        cpus: 1,
        memory_mib: 128,
        network_policy: policy,
        ..Default::default()
    };
    anchor.bind_to_config(&mut config)?;
    config.plan_json = Some(serde_json::to_string(&signed)?);
    anchor.bind_admitted(&config, BackendKind::Firecracker, &plan)?;
    let guard = Arc::new(Guard {
        projection: facts.clone(),
        store_credit: None,
        retained: Some(Mutex::new(FixtureRetention {
            state_path: state.into(),
            original_state: File::open(state)?,
            prepared: false,
            files: None,
        })),
    });
    anchor.bind_parent_permit(
        &config,
        BackendKind::Firecracker,
        Arc::new(Parent(facts, guard.clone())),
    )?;
    Ok((
        anchor.prepare_endpoint_handoff(&config, BackendKind::Firecracker)?,
        guard,
    ))
}

fn run_case(case: Case) -> Result<()> {
    let mut fixture = Fixture::new();
    fixture._env.set(
        "MVM_SUBSTITUTION_ENDPOINT_PATH",
        env!("CARGO_BIN_EXE_mvm-network-endpoint"),
    );
    let holder = fixture.inputs().holder;
    let mut agent = OwnedHostAgent::spawn(fixture.inputs())?;
    let registrar = agent.registrar();
    let (state, socket) = fixture.vm("vm-1");
    let original_directory = File::open(&state)?;
    let (registered_name, registered_state, registered_socket) = match case {
        Case::ForeignRegistration => {
            let (path, sock) = fixture.vm("vm-2");
            ("vm-2", path, sock)
        }
        Case::Collect | Case::MissingRetainedCredit | Case::WrongRedaction => {
            ("vm-1", state.clone(), socket.clone())
        }
    };
    let mut registration = register(
        &registrar,
        registered_name,
        &registered_state,
        &registered_socket,
    )?;
    let services = [ServiceId::parse("host.audit.v1")?];
    let original = InstalledHostServices::new(
        &registrar,
        &registration,
        HostAgentServicesParams {
            workload_id: registered_name,
            tenant_id: Some("local"),
            vm_name: registered_name,
            state_dir: &registered_state,
            broker_listen_socket: &registered_socket,
            services: &services,
            capability_bindings: &[],
            service_proxies: &[],
        },
    )?;
    let (handoff, guard) = telemetry_handoff(
        &holder,
        &state,
        !matches!(case, Case::MissingRetainedCredit),
    )?;
    let mut redaction = mvm_core::policy::RedactionPolicy::default();
    if matches!(case, Case::WrongRedaction) {
        redaction.default.pii.categories.push("email".into());
        ensure!(redaction != mvm_core::policy::RedactionPolicy::default());
    }
    let transport = state.join("collector-unbound.sock");
    // The fixture's one supplied ledger exercises actual child debits. It is
    // not an aggregate installation budget or a native guest admission claim.
    let launched = spawn_telemetry_collector_installed_registered(
        SubstitutionSpawnParams {
            vm_name: "vm-1",
            state_dir: &state,
            lifetime: EndpointLifetime::Launcher,
            telemetry: true,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            transport: EndpointTransport::Uds {
                path: transport.clone(),
            },
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: None,
            admitted_network_plan: None,
            network_policy: None,
            network_limits: Default::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        },
        handoff,
        &original,
    );
    if !matches!(case, Case::Collect) {
        ensure!(launched.is_err(), "unfunded or foreign collector started");
        let held = guard
            .retained
            .as_ref()
            .expect("fixture retention")
            .lock()
            .unwrap();
        ensure!(
            !held.prepared && held.files.is_none(),
            "refused collector made retained effects"
        );
        for name in [
            mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE,
            mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_KEY_FILE,
            mvm_vmm::host::telemetry_provisioning::TELEMETRY_COLLECTOR_STATUS_FILE,
        ] {
            ensure!(
                !state.join(name).exists(),
                "refused collector published state"
            );
        }
        drop(held);
    } else {
        let mut endpoint = launched?;
        ensure!(
            endpoint.take_retirement().is_err(),
            "Ready was treated as retirement"
        );
        ensure!(
            registration.shutdown().is_err(),
            "active collector lost its original audit pin"
        );
        endpoint.shutdown()?;
        let receipt = endpoint.take_retirement()?;
        let expected: Arc<dyn EndpointPartitionGuard> = guard.clone();
        ensure!(
            receipt.retains_partition_guard(&expected),
            "collector returned a foreign partition"
        );
        ensure!(
            endpoint
                .exit_status()
                .is_some_and(|status| status.success())
        );
        ensure!(file_id(&original_directory)? == file_id(&File::open(&state)?)?);
        let held = guard
            .retained
            .as_ref()
            .expect("fixture retention")
            .lock()
            .unwrap();
        let (records, key) = held
            .files
            .as_ref()
            .context("original retained files missing")?;
        ensure!(held.prepared);
        for (file, name) in [
            (
                records,
                mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_FILE,
            ),
            (
                key,
                mvm_vmm::host::telemetry_provisioning::TELEMETRY_RECORDS_KEY_FILE,
            ),
        ] {
            ensure!(file_id(file)? == file_id(&File::open(state.join(name))?)?);
        }
        ensure!(
            !transport.exists() && !state.join("network.sock").exists(),
            "collector created a network listener"
        );
        drop(held);
        drop(receipt);
    }
    registration.shutdown()?;
    agent.shutdown()?;
    Ok(())
}

#[test]
fn registered_telemetry_collects_its_original_child_and_retains_files() -> Result<()> {
    run_case(Case::Collect)
}

#[test]
fn registered_telemetry_refuses_missing_retained_credit_before_effects() -> Result<()> {
    run_case(Case::MissingRetainedCredit)
}

#[test]
fn registered_telemetry_refuses_foreign_registration_before_effects() -> Result<()> {
    run_case(Case::ForeignRegistration)
}

#[test]
fn registered_telemetry_refuses_changed_redaction_before_effects() -> Result<()> {
    run_case(Case::WrongRedaction)
}
