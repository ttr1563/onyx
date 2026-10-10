#[cfg(target_os = "linux")]
fn main() -> osmanthus_guard::Result<()> {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    use libbpf_rs::{Link, MapCore, MapFlags, MapHandle};
    use osmanthus_guard::daemon::EnforcementBackend;
    use osmanthus_guard::enforcement::{EnforcementPolicy, ProtectedAction, ProtectedRoot};
    use osmanthus_guard::linux_bpf::PersistentLinuxBpfBackend;

    if unsafe { libc::geteuid() } != 0 {
        return Err(osmanthus_guard::OsmanthusError::RootRequired);
    }
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            osmanthus_guard::OsmanthusError::InvalidState(
                "usage: bpf-persistence-smoke ABSOLUTE_TEST_DIRECTORY".to_owned(),
            )
        })?;
    let file = root.join("blocked-after-loader-exit");
    fs::create_dir_all(&root)?;
    fs::write(&file, b"kept")?;
    let policy = EnforcementPolicy::new(vec![ProtectedRoot::new(
        &root,
        BTreeSet::from([ProtectedAction::Delete]),
    )?])?;

    let backend = PersistentLinuxBpfBackend::install_or_open(&policy)?;
    drop(backend);
    let before_upgrade = Link::open("/sys/fs/bpf/osmanthus/path_unlink")
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!("open test BPF link: {error}"))
        })?
        .info()
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!("inspect test BPF link: {error}"))
        })?
        .prog_id;
    match fs::remove_file(&file) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error.into()),
        Ok(()) => {
            return Err(osmanthus_guard::OsmanthusError::InvalidState(
                "persistent BPF link did not block after loader exit".to_owned(),
            ));
        }
    }
    let reopened = PersistentLinuxBpfBackend::install_or_open(&policy)?;
    let after_upgrade = Link::open("/sys/fs/bpf/osmanthus/path_unlink")
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!("reopen test BPF link: {error}"))
        })?
        .info()
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!(
                "reinspect test BPF link: {error}"
            ))
        })?
        .prog_id;
    if before_upgrade == after_upgrade {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "persistent BPF program was not replaced in place".to_owned(),
        ));
    }
    drop(reopened);

    let metadata =
        MapHandle::from_pinned_path("/sys/fs/bpf/osmanthus/metadata").map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!(
                "open test BPF metadata map: {error}"
            ))
        })?;
    metadata
        .update(&0_u32.to_ne_bytes(), &5_u32.to_ne_bytes(), MapFlags::ANY)
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!(
                "write incompatible test BPF ABI: {error}"
            ))
        })?;
    let incompatible = PersistentLinuxBpfBackend::install_or_open(&policy);
    if !matches!(
        incompatible,
        Err(osmanthus_guard::OsmanthusError::InvalidState(message))
            if message.contains("BPF ABI is incompatible")
    ) {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "incompatible BPF ABI was not rejected".to_owned(),
        ));
    }
    match fs::remove_file(&file) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error.into()),
        Ok(()) => {
            return Err(osmanthus_guard::OsmanthusError::InvalidState(
                "incompatible BPF ABI rejection detached existing enforcement".to_owned(),
            ));
        }
    }
    metadata
        .update(&0_u32.to_ne_bytes(), &4_u32.to_ne_bytes(), MapFlags::ANY)
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!("restore test BPF ABI: {error}"))
        })?;
    drop(metadata);

    let mut reopened = PersistentLinuxBpfBackend::install_or_open(&policy)?;
    reopened.decommission()?;
    drop(reopened);
    fs::remove_file(&file)?;
    if std::path::Path::new("/sys/fs/bpf/osmanthus").exists() {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "decommission left the persistent BPF directory behind".to_owned(),
        ));
    }
    println!(
        "Osmanthus persistent BPF smoke test passed: {}",
        root.display()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the BPF persistence smoke test is available only on Linux");
    std::process::exit(1);
}
