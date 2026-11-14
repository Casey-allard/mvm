//! Collector-only use of the original registered endpoint transaction.
use super::*;

/// Retain the actual collector Child, partition and protected files through
/// the same private Ready/Drained exchange as a network endpoint. No egress
/// identity, listener or proxy is admitted by this operation.
pub fn spawn_telemetry_collector_installed_registered(
    params: SubstitutionSpawnParams<'_>,
    handoff: PreparedEndpointHandoff,
    original: &InstalledHostServices<'_>,
) -> Result<OwnedEndpoint> {
    spawn_registered(params, handoff, original, RegisteredProgram::Collector)
}

pub(super) fn check_shape(
    params: &SubstitutionSpawnParams<'_>,
    handoff: &PreparedEndpointHandoff,
) -> Result<()> {
    let projection = handoff.partition().projection();
    anyhow::ensure!(
        cfg!(target_os = "linux")
            && params.egress_proxy.is_none()
            && params.session_marker.is_none()
            && params.tls_intermediate.is_none()
            && params.admitted_network_plan.is_none()
            && params.network_policy.is_none()
            && params.resolver_remote.is_none()
            && params.binding_store_dir.is_none()
            && params.flowmux_identity.is_none()
            && projection.limits.cache_disk_bytes
                >= crate::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP
                    + mvm_core::runtime_state_protection::INSTALLED_TELEMETRY_SIDECAR_BYTES,
        "installed collector shape or retained credit unsupported"
    );
    handoff.check_telemetry_only(params.redaction)
}

impl RegisteredProgram {
    pub(super) fn encode(
        self,
        params: &SubstitutionSpawnParams<'_>,
        telemetry: &super::super::collector::TelemetrySection<'_>,
        metadata: u64,
    ) -> Result<Box<serde_json::value::RawValue>> {
        if self == Self::Network {
            return encode_config_with_telemetry_credit(params, telemetry, metadata);
        }
        anyhow::ensure!(
            metadata >= INSTALLED_BOOTSTRAP_MIN_BYTES,
            "installed collector bootstrap credit missing"
        );
        #[derive(Serialize)]
        struct Program<'a, 'b> {
            telemetry_only: Config<'a, 'b>,
        }
        #[derive(Serialize)]
        struct Config<'a, 'b> {
            instance_id: &'a str,
            redaction: &'a mvm_core::policy::RedactionPolicy,
            telemetry: &'a super::super::collector::TelemetrySection<'b>,
        }
        let mut bounded = BoundedBytes {
            bytes: Zeroizing::new(Vec::with_capacity(CONFIG_LIMIT)),
            limit: CONFIG_LIMIT,
        };
        serde_json::to_writer(
            &mut bounded,
            &Program {
                telemetry_only: Config {
                    instance_id: params.vm_name,
                    redaction: params.redaction,
                    telemetry,
                },
            },
        )
        .map_err(|_| anyhow!("installed collector configuration exceeds bound"))?;
        let text = String::from_utf8(std::mem::take(&mut bounded.bytes))
            .map_err(|_| anyhow!("invalid installed collector configuration"))?;
        if installed_endpoint_bootstrap_requirement(&text)? > metadata {
            bail!("installed collector typed configuration credit missing")
        }
        serde_json::value::RawValue::from_string(text)
            .map_err(|_| anyhow!("invalid installed collector configuration"))
    }
}

pub(super) fn check_audit_config(
    raw: &str,
    audit: &audit::AuditProjection,
    vm: &str,
) -> Result<()> {
    #[derive(Deserialize)]
    struct Program<'a> {
        #[serde(borrow)]
        telemetry_only: Identity<'a>,
    }
    #[derive(Deserialize)]
    struct Identity<'a> {
        instance_id: &'a str,
        #[serde(borrow)]
        telemetry: Signer<'a>,
    }
    #[derive(Deserialize)]
    struct Signer<'a> {
        signer_sock: &'a str,
    }
    let program: Program<'_> = serde_json::from_str(raw)?;
    anyhow::ensure!(
        program.telemetry_only.instance_id == vm
            && Path::new(program.telemetry_only.telemetry.signer_sock)
                == mvm_core::config::host_agent_signer_helper_socket(audit.tenant()),
        "installed collector original audit target differs"
    );
    Ok(())
}
