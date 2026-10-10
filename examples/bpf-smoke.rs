#[cfg(target_os = "linux")]
fn main() -> osmanthus_guard::Result<()> {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::rc::Rc;
    use std::time::Duration;

    use libbpf_rs::{OpenObject, RingBufferBuilder};
    use osmanthus_guard::enforcement::{
        EnforcementPolicy, MaintenanceLease, ProtectedAction, ProtectedRoot,
    };
    use osmanthus_guard::linux_bpf::{KernelEventKind, LinuxBpfSession, parse_kernel_event};
    use tempfile::TempDir;
    use time::OffsetDateTime;

    if unsafe { libc::geteuid() } != 0 {
        return Err(osmanthus_guard::OsmanthusError::RootRequired);
    }
    let temporary = TempDir::new_in("/var/tmp")?;
    let protected = temporary.path().join("protected");
    let topology_protected = temporary.path().join("topology-protected");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&protected)?;
    fs::create_dir_all(&topology_protected)?;
    fs::create_dir_all(&outside)?;
    let blocked_mount = protected.join("blocked-mount");
    fs::create_dir(&blocked_mount)?;
    let actions = [
        ProtectedAction::Delete,
        ProtectedAction::Rename,
        ProtectedAction::Truncate,
        ProtectedAction::Write,
        ProtectedAction::ChangePermissions,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let root = ProtectedRoot::new(&protected, actions.clone())?;
    let topology_root = ProtectedRoot::new(
        &topology_protected,
        BTreeSet::from([ProtectedAction::Delete]),
    )?;
    let monitored_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|uid| *uid != 0)
        .unwrap_or(65_534);
    let policy =
        EnforcementPolicy::from_parts(vec![root, topology_root], BTreeSet::from([monitored_uid]))?;

    let blocked_delete = protected.join("blocked-delete");
    let blocked_truncate = protected.join("blocked-truncate");
    let blocked_direct_truncate = protected.join("blocked-direct-truncate");
    let blocked_link_source = protected.join("blocked-link-source");
    let protected_marker = protected.join("protected-marker");
    let outside_link_source = outside.join("outside-link-source");
    let imported_link_source = outside.join("imported-link-source");
    let imported_link_alias = outside.join("imported-link-alias");
    let ordinary_rename_source = outside.join("ordinary-rename-source");
    let blocked_rename = protected.join("blocked-rename");
    let blocked_chmod = protected.join("blocked-chmod");
    let blocked_write = protected.join("blocked-write");
    let blocked_mmap = protected.join("blocked-mmap");
    let outside_file = outside.join("allowed-delete");
    let mut deep_outside = outside.clone();
    for depth in 0..40 {
        deep_outside.push(format!("level-{depth}"));
    }
    fs::create_dir_all(&deep_outside)?;
    let deep_outside_file = deep_outside.join("allowed-delete");
    let mut deep_protected = protected.clone();
    for depth in 0..40 {
        deep_protected.push(format!("level-{depth}"));
    }
    fs::create_dir_all(&deep_protected)?;
    let deep_protected_file = deep_protected.join("blocked-delete");
    let mut excessive_depth = outside.clone();
    for depth in 0..260 {
        excessive_depth.push(format!("x{depth}"));
    }
    fs::create_dir_all(&excessive_depth)?;
    let excessive_depth_file = excessive_depth.join("fail-closed-delete");
    for path in [
        &blocked_delete,
        &blocked_truncate,
        &blocked_direct_truncate,
        &blocked_link_source,
        &protected_marker,
        &blocked_rename,
        &blocked_chmod,
        &blocked_write,
        &blocked_mmap,
    ] {
        fs::write(path, b"kept")?;
    }
    fs::write(&outside_file, b"delete")?;
    fs::write(&outside_link_source, b"outside")?;
    fs::write(&imported_link_source, b"linked")?;
    fs::hard_link(&imported_link_source, &imported_link_alias)?;
    fs::write(&ordinary_rename_source, b"ordinary")?;
    fs::write(&deep_outside_file, b"delete")?;
    fs::write(&deep_protected_file, b"kept")?;
    fs::write(&excessive_depth_file, b"kept")?;

    let mut object = MaybeUninit::<OpenObject>::uninit();
    let session = LinuxBpfSession::load(&mut object, &policy)?;
    let event_map = session.event_map_handle()?;
    let events = Rc::new(RefCell::new(Vec::new()));
    let callback_events = Rc::clone(&events);
    let mut ring_builder = RingBufferBuilder::new();
    ring_builder
        .add(&event_map, move |bytes| match parse_kernel_event(bytes) {
            Ok(event) => {
                callback_events.borrow_mut().push(event);
                0
            }
            Err(_) => -1,
        })
        .map_err(|error| {
            osmanthus_guard::OsmanthusError::InvalidState(format!(
                "create smoke ring buffer: {error}"
            ))
        })?;
    let ring = ring_builder.build().map_err(|error| {
        osmanthus_guard::OsmanthusError::InvalidState(format!("build smoke ring buffer: {error}"))
    })?;

    expect_permission_denied(fs::remove_file(&blocked_delete), "delete")?;
    if !blocked_delete.exists() {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked delete changed the target".to_owned(),
        ));
    }

    expect_permission_denied(
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&blocked_truncate),
        "truncate",
    )?;
    if fs::read(&blocked_truncate)? != b"kept" {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked truncate changed the target".to_owned(),
        ));
    }

    let direct_truncate = OpenOptions::new()
        .write(true)
        .open(&blocked_direct_truncate)?;
    expect_permission_denied(direct_truncate.set_len(0), "direct truncate")?;
    if fs::read(&blocked_direct_truncate)? != b"kept" {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked direct truncate changed the target".to_owned(),
        ));
    }

    expect_permission_denied(
        fs::hard_link(&blocked_link_source, outside.join("blocked-link-alias")),
        "hard link from a protected root",
    )?;
    expect_permission_denied(
        fs::hard_link(&outside_link_source, protected.join("blocked-link-import")),
        "hard link into a protected root",
    )?;
    expect_permission_denied(
        fs::rename(
            &imported_link_alias,
            topology_protected.join("blocked-existing-link-import"),
        ),
        "rename an existing hard link into a protected root",
    )?;
    fs::rename(
        &ordinary_rename_source,
        topology_protected.join("allowed-ordinary-rename"),
    )?;

    let exchange_source = outside.join("exchange-source");
    fs::create_dir(&exchange_source)?;
    fs::write(exchange_source.join("outside-marker"), b"outside")?;
    let exchange_source_c =
        std::ffi::CString::new(exchange_source.as_os_str().as_encoded_bytes()).unwrap();
    let protected_c = std::ffi::CString::new(protected.as_os_str().as_encoded_bytes()).unwrap();
    let exchange_result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            exchange_source_c.as_ptr(),
            libc::AT_FDCWD,
            protected_c.as_ptr(),
            2_u32,
        )
    };
    if exchange_result == 0 {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "RENAME_EXCHANGE replaced a protected root".to_owned(),
        ));
    }
    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::PermissionDenied {
        return Err(std::io::Error::last_os_error().into());
    }
    if !protected_marker.exists() || !exchange_source.join("outside-marker").exists() {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked RENAME_EXCHANGE changed a target".to_owned(),
        ));
    }

    let mut write_file = OpenOptions::new().write(true).open(&blocked_write)?;
    write_file.seek(SeekFrom::Start(0))?;
    expect_permission_denied(write_file.write_all(b"lost"), "non-truncating write")?;
    if fs::read(&blocked_write)? != b"kept" {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked non-truncating write changed the target".to_owned(),
        ));
    }

    let mmap_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&blocked_mmap)?;
    let writable_mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            mmap_file.as_raw_fd(),
            0,
        )
    };
    if writable_mapping != libc::MAP_FAILED {
        unsafe { libc::munmap(writable_mapping, 4) };
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "writable shared mapping was not blocked".to_owned(),
        ));
    }
    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::PermissionDenied {
        return Err(std::io::Error::last_os_error().into());
    }
    let read_mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4,
            libc::PROT_READ,
            libc::MAP_SHARED,
            mmap_file.as_raw_fd(),
            0,
        )
    };
    if read_mapping == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error().into());
    }
    let mprotect_result =
        unsafe { libc::mprotect(read_mapping, 4, libc::PROT_READ | libc::PROT_WRITE) };
    let mprotect_error = std::io::Error::last_os_error();
    unsafe { libc::munmap(read_mapping, 4) };
    if mprotect_result == 0 {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "mprotect to a writable shared mapping was not blocked".to_owned(),
        ));
    }
    if mprotect_error.kind() != std::io::ErrorKind::PermissionDenied {
        return Err(mprotect_error.into());
    }

    expect_permission_denied(
        fs::rename(&blocked_rename, protected.join("renamed")),
        "rename",
    )?;

    expect_permission_denied(
        fs::set_permissions(&blocked_chmod, fs::Permissions::from_mode(0o600)),
        "chmod",
    )?;

    let mount_source = std::ffi::CString::new("none").unwrap();
    let mount_target =
        std::ffi::CString::new(blocked_mount.as_os_str().as_encoded_bytes()).unwrap();
    let mount_type = std::ffi::CString::new("tmpfs").unwrap();
    let mount_result = unsafe {
        libc::mount(
            mount_source.as_ptr(),
            mount_target.as_ptr(),
            mount_type.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if mount_result == 0 {
        unsafe { libc::umount(mount_target.as_ptr()) };
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "mount inside a protected root was not blocked".to_owned(),
        ));
    }
    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::PermissionDenied {
        return Err(std::io::Error::last_os_error().into());
    }

    fs::remove_file(&outside_file)?;
    fs::remove_file(&deep_outside_file)?;
    expect_permission_denied(fs::remove_file(&deep_protected_file), "deep delete")?;
    match fs::remove_file(&excessive_depth_file) {
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {}
        Err(error) => return Err(error.into()),
        Ok(()) => {
            return Err(osmanthus_guard::OsmanthusError::InvalidState(
                "ancestor walk limit did not fail closed".to_owned(),
            ));
        }
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let cgroup_id = osmanthus_guard::linux_daemon::current_cgroup_id()?;
    let foreign_lease = MaintenanceLease::issue(
        &protected,
        [ProtectedAction::Delete].into_iter().collect(),
        now,
        60,
        0,
        cgroup_id.saturating_add(1),
    )?;
    session.grant_maintenance(&foreign_lease, now)?;
    expect_permission_denied(
        fs::remove_file(&blocked_delete),
        "delete from a cgroup outside the maintenance lease",
    )?;
    session.revoke_maintenance(&foreign_lease)?;
    let lease = MaintenanceLease::issue(
        &protected,
        [ProtectedAction::Delete].into_iter().collect(),
        now,
        60,
        0,
        cgroup_id,
    )?;
    session.grant_maintenance(&lease, now)?;
    fs::remove_file(&blocked_delete)?;
    session.revoke_maintenance(&lease)?;

    let status = Command::new("/usr/bin/true").uid(monitored_uid).status()?;
    if !status.success() {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "smoke exec command failed".to_owned(),
        ));
    }
    ring.poll(Duration::from_millis(100)).map_err(|error| {
        osmanthus_guard::OsmanthusError::InvalidState(format!("poll smoke ring buffer: {error}"))
    })?;
    let events = events.borrow();
    if !events.iter().any(|event| {
        event.kind == KernelEventKind::ProcessExec && event.filename == "/usr/bin/true"
    }) {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "exec event was not received".to_owned(),
        ));
    }
    if !events.iter().any(|event| {
        event.kind == KernelEventKind::ResourceBlocked
            && event.action == Some(ProtectedAction::Write)
    }) {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked write event was not received".to_owned(),
        ));
    }
    if !events
        .iter()
        .any(|event| event.kind == KernelEventKind::ResourceBlocked && event.action.is_none())
    {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked mount event was not received".to_owned(),
        ));
    }
    if !events.iter().any(|event| {
        event.kind == KernelEventKind::ResourceBlocked
            && event.action == Some(ProtectedAction::Delete)
    }) {
        return Err(osmanthus_guard::OsmanthusError::InvalidState(
            "blocked resource event was not received".to_owned(),
        ));
    }

    println!("Osmanthus BPF smoke test passed: {}", protected.display());
    drop(session);
    Ok(())
}

#[cfg(target_os = "linux")]
fn expect_permission_denied<T>(
    result: std::io::Result<T>,
    operation: &str,
) -> osmanthus_guard::Result<()> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(osmanthus_guard::OsmanthusError::InvalidState(format!(
            "BPF smoke test did not block {operation}"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the BPF smoke test is available only on Linux");
    std::process::exit(1);
}
