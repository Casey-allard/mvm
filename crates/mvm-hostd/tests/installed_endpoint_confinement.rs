//! Actual single-thread confinement of a private child, without a VM.
#[cfg(target_os = "linux")]
#[path = "common/installed_resource_fixture.rs"]
mod installed_resource_fixture;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    if std::env::var_os("MVM_INSTALLED_RESOURCES_FIXTURE").is_some() {
        return child();
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(installed_resource_fixture::resource_exchange(
            "confined",
            &[],
        ));
    println!("installed endpoint exact-file confinement: PASS");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("installed endpoint Landlock: NOT_APPLICABLE on this host");
}

#[cfg(target_os = "linux")]
fn child() -> anyhow::Result<()> {
    use mvm_hostd::{installed_endpoint::InstalledEndpointResources, jailer::ConfinementSpec};
    use mvm_vmm::host::network_endpoint_spawn::InstalledEndpointChild;
    use std::{
        io,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };

    // SAFETY: this fixture inherited its original protocol stdout on fd199.
    anyhow::ensure!(
        unsafe { libc::dup2(199, 1) } >= 0,
        "restore protocol output"
    );
    let mut child = InstalledEndpointChild::from_stdio()?;
    let resources = InstalledEndpointResources::from_child(&mut child)?;
    let store = resources.store_locator().unwrap().path.clone();
    let other = store.parent().unwrap().join("other-endpoint-cache");
    std::fs::create_dir(&other)?;
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700))?;
    let private = other.join("private-object");
    std::fs::write(&private, b"sibling endpoint bytes")?;
    anyhow::ensure!(std::fs::read(&private)? == b"sibling endpoint bytes");
    let mut spec = ConfinementSpec::network_endpoint(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        None,
    );
    spec.readable_paths.clear();
    spec.read_write_paths.clear();
    resources.confine(&spec)?;
    let (_, lease, pool) = resources.into_parts();
    lease.check_current()?;
    let namespace = store.join("own-namespace");
    std::fs::create_dir(&namespace)?;
    let own = namespace.join("object");
    std::fs::write(&own, b"own exact bytes")?;
    anyhow::ensure!(std::fs::read(&own)? == b"own exact bytes");
    std::fs::remove_file(own)?;
    std::fs::remove_dir(namespace)?;
    anyhow::ensure!(
        std::fs::read(&private).unwrap_err().kind() == io::ErrorKind::PermissionDenied,
        "confinement must not grant sibling cache file reads"
    );
    let pool = pool.unwrap();
    let held =
        pool.reserve_profile(spiralcore_transfer::resource_profile::ResourceProfile::SmallV1)?;
    pool.close_admission()?;
    drop(held);
    anyhow::ensure!(pool.drained()?);
    child.send_ready(Default::default(), Instant::now() + Duration::from_secs(2))?;
    let mut event = libc::pollfd {
        fd: child.control_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded poll on the original private parent-control descriptor.
    anyhow::ensure!(unsafe { libc::poll(&mut event, 1, 3000) } > 0);
    anyhow::ensure!(lease.check_current().is_err());
    child.send_drained(Instant::now() + Duration::from_secs(2))?;
    Ok(())
}
