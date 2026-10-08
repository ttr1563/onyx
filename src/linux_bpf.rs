use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, MapHandle, OpenObject};

use crate::enforcement::{EnforcementPolicy, MaintenanceLease, ProtectedAction, ProtectedRoot};
use crate::protocol::BackendState;
use crate::{OsmanthusError, Result};

mod skeleton {
    include!(concat!(env!("OUT_DIR"), "/osmanthus_lsm.skel.rs"));
}

impl crate::daemon::EnforcementBackend for LinuxBpfSession<'_> {
    fn state(&self) -> BackendState {
        BackendState::Enforcing
    }

    fn grant_maintenance(&mut self, lease: &MaintenanceLease, now_unix: i64) -> Result<()> {
        LinuxBpfSession::grant_maintenance(self, lease, now_unix)
    }

    fn revoke_maintenance(&mut self, lease: &MaintenanceLease) -> Result<()> {
        LinuxBpfSession::revoke_maintenance(self, lease)
    }

    fn replace_policy(&mut self, policy: &EnforcementPolicy) -> Result<()> {
        LinuxBpfSession::replace_policy(self, policy)
    }

    fn decommission(&mut self) -> Result<()> {
        Err(OsmanthusError::InvalidState(
            "transient BPF sessions cannot be decommissioned".to_owned(),
        ))
    }
}

pub struct PersistentLinuxBpfBackend {
    metadata: MapHandle,
    protected_roots: MapHandle,
    protected_boundaries: MapHandle,
    maintenance_leases: MapHandle,
    monitored_uids: MapHandle,
    events: MapHandle,
}

impl PersistentLinuxBpfBackend {
    pub fn install_or_open(policy: &EnforcementPolicy) -> Result<Self> {
        crate::system_policy::require_root()?;
        policy.validate()?;
        if Path::new(LEGACY_PIN_DIRECTORY).exists() {
            return Err(OsmanthusError::InvalidState(format!(
                "legacy Onyx enforcement is still pinned at {LEGACY_PIN_DIRECTORY}; run the matching `sudo onyx daemon decommission` before starting Osmanthus"
            )));
        }
        let pin_directory = Path::new(PIN_DIRECTORY);
        if !pin_directory.exists() {
            fs::create_dir(pin_directory)?;
            fs::set_permissions(pin_directory, fs::Permissions::from_mode(0o700))?;
        }
        validate_pin_directory(pin_directory)?;
        recover_upgrade_pins()?;

        let expected = [
            METADATA_MAP,
            PROTECTED_ROOTS_MAP,
            PROTECTED_BOUNDARIES_MAP,
            MAINTENANCE_LEASES_MAP,
            MONITORED_UIDS_MAP,
            EVENTS_MAP,
        ]
        .into_iter()
        .chain(LINK_PATHS)
        .collect::<Vec<_>>();
        let existing = expected
            .iter()
            .filter(|path| Path::new(path).exists())
            .count();
        if existing != 0 && existing != expected.len() {
            return Err(OsmanthusError::InvalidState(format!(
                "incomplete persistent BPF state in {PIN_DIRECTORY}; refusing partial enforcement recovery"
            )));
        }
        if existing == 0 {
            let install_result = (|| -> Result<()> {
                let mut object = MaybeUninit::<OpenObject>::uninit();
                let mut session = LinuxBpfSession::load(&mut object, policy)?;
                session.pin_all()
            })();
            if let Err(error) = install_result {
                remove_created_pins();
                return Err(error);
            }
        } else {
            for path in LINK_PATHS {
                let _link = Link::open(path).map_err(bpf_error("open persistent BPF link"))?;
            }
        }

        let backend = Self {
            metadata: MapHandle::from_pinned_path(METADATA_MAP)
                .map_err(bpf_error("open metadata BPF map"))?,
            protected_roots: MapHandle::from_pinned_path(PROTECTED_ROOTS_MAP)
                .map_err(bpf_error("open protected-root BPF map"))?,
            protected_boundaries: MapHandle::from_pinned_path(PROTECTED_BOUNDARIES_MAP)
                .map_err(bpf_error("open protected-boundary BPF map"))?,
            maintenance_leases: MapHandle::from_pinned_path(MAINTENANCE_LEASES_MAP)
                .map_err(bpf_error("open maintenance BPF map"))?,
            monitored_uids: MapHandle::from_pinned_path(MONITORED_UIDS_MAP)
                .map_err(bpf_error("open monitored-UID BPF map"))?,
            events: MapHandle::from_pinned_path(EVENTS_MAP)
                .map_err(bpf_error("open event BPF map"))?,
        };
        backend.validate_maps()?;
        if existing == expected.len() {
            upgrade_pinned_programs()?;
        }
        backend.replace_policy(policy)?;
        clear_map(&backend.maintenance_leases)?;
        Ok(backend)
    }

    pub fn replace_policy(&self, policy: &EnforcementPolicy) -> Result<()> {
        policy.validate()?;
        let mut desired = std::collections::BTreeSet::new();
        let mut desired_boundaries = std::collections::BTreeSet::new();
        for root in &policy.protected_roots {
            for resource in resource_identities(root.path())? {
                desired_boundaries.insert(resource.boundary_key());
                for action in root.actions() {
                    desired.insert(resource.key(*action));
                }
            }
        }
        sync_map(&self.protected_boundaries, &desired_boundaries)?;
        for key in &desired {
            self.protected_roots
                .update(key, &ENABLED, MapFlags::ANY)
                .map_err(bpf_error("update persistent protected-root BPF map"))?;
        }
        for key in self.protected_roots.keys().collect::<Vec<_>>() {
            if !desired.contains(key.as_slice()) {
                self.protected_roots
                    .delete(&key)
                    .map_err(bpf_error("remove stale protected-root BPF entry"))?;
            }
        }
        set_write_protection_feature(
            &self.metadata,
            policy
                .protected_roots
                .iter()
                .any(|root| root.actions().contains(&ProtectedAction::Write)),
        )?;
        let desired_uids = policy
            .monitored_uids
            .iter()
            .map(|uid| uid.to_ne_bytes())
            .collect::<std::collections::BTreeSet<_>>();
        for key in &desired_uids {
            self.monitored_uids
                .update(key, &ENABLED, MapFlags::ANY)
                .map_err(bpf_error("update monitored-UID BPF map"))?;
        }
        for key in self.monitored_uids.keys().collect::<Vec<_>>() {
            if !desired_uids.contains(key.as_slice()) {
                self.monitored_uids
                    .delete(&key)
                    .map_err(bpf_error("remove stale monitored-UID BPF entry"))?;
            }
        }
        Ok(())
    }

    pub fn event_map_handle(&self) -> Result<MapHandle> {
        MapHandle::try_from(&self.events).map_err(bpf_error("duplicate event BPF map handle"))
    }

    fn validate_maps(&self) -> Result<()> {
        if self.metadata.map_type() != libbpf_rs::MapType::Array
            || self.metadata.key_size() != 4
            || self.metadata.value_size() != 4
            || self.metadata.max_entries() != 2
        {
            return Err(OsmanthusError::InvalidState(
                "persistent metadata BPF map has an incompatible schema".to_owned(),
            ));
        }
        let version = self
            .metadata
            .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)
            .map_err(bpf_error("read persistent BPF ABI version"))?
            .ok_or_else(|| {
                OsmanthusError::InvalidState(
                    "persistent BPF ABI version is missing; keeping existing enforcement attached"
                        .to_owned(),
                )
            })?;
        if version.as_slice() != BPF_ABI_VERSION.to_ne_bytes() {
            return Err(OsmanthusError::InvalidState(format!(
                "persistent BPF ABI is incompatible; expected version {BPF_ABI_VERSION}; keeping existing enforcement attached"
            )));
        }
        if self.protected_roots.key_size() != 16 || self.protected_roots.value_size() != 1 {
            return Err(OsmanthusError::InvalidState(
                "persistent protected-root BPF map has an incompatible schema".to_owned(),
            ));
        }
        if self.protected_boundaries.key_size() != 16 || self.protected_boundaries.value_size() != 1
        {
            return Err(OsmanthusError::InvalidState(
                "persistent protected-boundary BPF map has an incompatible schema".to_owned(),
            ));
        }
        if self.maintenance_leases.key_size() != 24 || self.maintenance_leases.value_size() != 8 {
            return Err(OsmanthusError::InvalidState(
                "persistent maintenance BPF map has an incompatible schema".to_owned(),
            ));
        }
        if self.monitored_uids.key_size() != 4 || self.monitored_uids.value_size() != 1 {
            return Err(OsmanthusError::InvalidState(
                "persistent monitored-UID BPF map has an incompatible schema".to_owned(),
            ));
        }
        if self.events.map_type() != libbpf_rs::MapType::RingBuf {
            return Err(OsmanthusError::InvalidState(
                "persistent event BPF map has an incompatible schema".to_owned(),
            ));
        }
        Ok(())
    }

    fn decommission_pins(&mut self) -> Result<()> {
        recover_upgrade_pins()?;
        let mut links = LINK_PATHS
            .iter()
            .map(|path| Link::open(path).map_err(bpf_error("open BPF link for decommission")))
            .collect::<Result<Vec<_>>>()?;
        for index in 0..links.len() {
            if let Err(error) = links[index].unpin() {
                restore_link_pins(&mut links)?;
                return Err(bpf_error("unpin BPF link during decommission")(error));
            }
        }
        for path in [
            METADATA_MAP,
            PROTECTED_ROOTS_MAP,
            PROTECTED_BOUNDARIES_MAP,
            MAINTENANCE_LEASES_MAP,
            MONITORED_UIDS_MAP,
            EVENTS_MAP,
        ] {
            if let Err(error) = fs::remove_file(path) {
                self.restore_map_pins()?;
                restore_link_pins(&mut links)?;
                return Err(error.into());
            }
        }
        if let Err(error) = fs::remove_dir(PIN_DIRECTORY) {
            self.restore_map_pins()?;
            restore_link_pins(&mut links)?;
            return Err(error.into());
        }
        drop(links);
        Ok(())
    }

    fn restore_map_pins(&mut self) -> Result<()> {
        for (path, map) in [
            (METADATA_MAP, &mut self.metadata),
            (PROTECTED_ROOTS_MAP, &mut self.protected_roots),
            (PROTECTED_BOUNDARIES_MAP, &mut self.protected_boundaries),
            (MAINTENANCE_LEASES_MAP, &mut self.maintenance_leases),
            (MONITORED_UIDS_MAP, &mut self.monitored_uids),
            (EVENTS_MAP, &mut self.events),
        ] {
            if !Path::new(path).exists() {
                map.pin(path)
                    .map_err(bpf_error("restore BPF map pin after failed decommission"))?;
            }
        }
        Ok(())
    }
}

fn restore_link_pins(links: &mut [Link]) -> Result<()> {
    for (path, link) in LINK_PATHS.into_iter().zip(links) {
        if !Path::new(path).exists() {
            link.pin(path)
                .map_err(bpf_error("restore BPF link pin after failed decommission"))?;
        }
    }
    Ok(())
}

fn upgrade_pinned_programs() -> Result<()> {
    let mut object = MaybeUninit::<OpenObject>::uninit();
    let mut open = OsmanthusLsmSkelBuilder::default()
        .open(&mut object)
        .map_err(bpf_error("open embedded BPF object for upgrade"))?;
    open.maps
        .osmanthus_metadata
        .reuse_pinned_map(METADATA_MAP)
        .map_err(bpf_error("reuse metadata BPF map"))?;
    open.maps
        .osmanthus_protected_roots
        .reuse_pinned_map(PROTECTED_ROOTS_MAP)
        .map_err(bpf_error("reuse protected-root BPF map"))?;
    open.maps
        .osmanthus_protected_boundaries
        .reuse_pinned_map(PROTECTED_BOUNDARIES_MAP)
        .map_err(bpf_error("reuse protected-boundary BPF map"))?;
    open.maps
        .osmanthus_maintenance_leases
        .reuse_pinned_map(MAINTENANCE_LEASES_MAP)
        .map_err(bpf_error("reuse maintenance BPF map"))?;
    open.maps
        .osmanthus_monitored_uids
        .reuse_pinned_map(MONITORED_UIDS_MAP)
        .map_err(bpf_error("reuse monitored-UID BPF map"))?;
    open.maps
        .osmanthus_events
        .reuse_pinned_map(EVENTS_MAP)
        .map_err(bpf_error("reuse event BPF map"))?;
    let mut skeleton = open
        .load()
        .map_err(bpf_error("load replacement BPF programs"))?;
    skeleton
        .attach()
        .map_err(bpf_error("attach replacement BPF programs"))?;
    let pin_result = (|| -> Result<()> {
        pin_link(
            &mut skeleton.links.osmanthus_path_unlink,
            NEXT_LINK_PATHS[0],
        )?;
        pin_link(&mut skeleton.links.osmanthus_path_rmdir, NEXT_LINK_PATHS[1])?;
        pin_link(
            &mut skeleton.links.osmanthus_path_rename,
            NEXT_LINK_PATHS[2],
        )?;
        pin_link(&mut skeleton.links.osmanthus_file_open, NEXT_LINK_PATHS[3])?;
        pin_link(
            &mut skeleton.links.osmanthus_file_permission,
            NEXT_LINK_PATHS[4],
        )?;
        pin_link(&mut skeleton.links.osmanthus_mmap_file, NEXT_LINK_PATHS[5])?;
        pin_link(
            &mut skeleton.links.osmanthus_file_mprotect,
            NEXT_LINK_PATHS[6],
        )?;
        pin_link(&mut skeleton.links.osmanthus_path_chmod, NEXT_LINK_PATHS[7])?;
        pin_link(&mut skeleton.links.osmanthus_path_chown, NEXT_LINK_PATHS[8])?;
        pin_link(&mut skeleton.links.osmanthus_execve, NEXT_LINK_PATHS[9])?;
        pin_link(&mut skeleton.links.osmanthus_execveat, NEXT_LINK_PATHS[10])?;
        pin_link(&mut skeleton.links.osmanthus_sb_mount, NEXT_LINK_PATHS[11])?;
        pin_link(
            &mut skeleton.links.osmanthus_move_mount,
            NEXT_LINK_PATHS[12],
        )?;
        Ok(())
    })();
    if let Err(error) = pin_result {
        remove_next_link_pins();
        return Err(error);
    }

    let old_links = LINK_PATHS
        .iter()
        .map(|path| Link::open(path).map_err(bpf_error("hold old BPF link during upgrade")))
        .collect::<Result<Vec<_>>>()?;
    for (current, next) in LINK_PATHS.into_iter().zip(NEXT_LINK_PATHS) {
        if let Err(error) = fs::remove_file(current).and_then(|()| fs::rename(next, current)) {
            let recovery = recover_upgrade_pins();
            drop(old_links);
            return match recovery {
                Ok(()) => Err(error.into()),
                Err(recovery_error) => Err(OsmanthusError::InvalidState(format!(
                    "BPF link promotion failed ({error}); recovery also failed ({recovery_error})"
                ))),
            };
        }
    }
    drop(old_links);
    Ok(())
}

impl crate::daemon::EnforcementBackend for PersistentLinuxBpfBackend {
    fn state(&self) -> BackendState {
        BackendState::Enforcing
    }

    fn grant_maintenance(&mut self, lease: &MaintenanceLease, now_unix: i64) -> Result<()> {
        update_maintenance_map(&self.maintenance_leases, lease, now_unix)
    }

    fn revoke_maintenance(&mut self, lease: &MaintenanceLease) -> Result<()> {
        delete_maintenance_map(&self.maintenance_leases, lease)
    }

    fn replace_policy(&mut self, policy: &EnforcementPolicy) -> Result<()> {
        PersistentLinuxBpfBackend::replace_policy(self, policy)
    }

    fn decommission(&mut self) -> Result<()> {
        self.decommission_pins()
    }
}

use skeleton::{OsmanthusLsmSkel, OsmanthusLsmSkelBuilder};

const ENABLED: [u8; 1] = [1];
const BPF_ABI_VERSION: u32 = 3;
const LEGACY_PIN_DIRECTORY: &str = "/sys/fs/bpf/onyx";
pub const PIN_DIRECTORY: &str = "/sys/fs/bpf/osmanthus";
const METADATA_MAP: &str = "/sys/fs/bpf/osmanthus/metadata";
const PROTECTED_ROOTS_MAP: &str = "/sys/fs/bpf/osmanthus/protected_roots";
const PROTECTED_BOUNDARIES_MAP: &str = "/sys/fs/bpf/osmanthus/protected_boundaries";
const MAINTENANCE_LEASES_MAP: &str = "/sys/fs/bpf/osmanthus/maintenance_leases";
const MONITORED_UIDS_MAP: &str = "/sys/fs/bpf/osmanthus/monitored_uids";
const EVENTS_MAP: &str = "/sys/fs/bpf/osmanthus/events";
const LINK_PATHS: [&str; 13] = [
    "/sys/fs/bpf/osmanthus/path_unlink",
    "/sys/fs/bpf/osmanthus/path_rmdir",
    "/sys/fs/bpf/osmanthus/path_rename",
    "/sys/fs/bpf/osmanthus/file_open",
    "/sys/fs/bpf/osmanthus/file_permission",
    "/sys/fs/bpf/osmanthus/mmap_file",
    "/sys/fs/bpf/osmanthus/file_mprotect",
    "/sys/fs/bpf/osmanthus/path_chmod",
    "/sys/fs/bpf/osmanthus/path_chown",
    "/sys/fs/bpf/osmanthus/execve",
    "/sys/fs/bpf/osmanthus/execveat",
    "/sys/fs/bpf/osmanthus/sb_mount",
    "/sys/fs/bpf/osmanthus/move_mount",
];
const NEXT_LINK_PATHS: [&str; 13] = [
    "/sys/fs/bpf/osmanthus/next_path_unlink",
    "/sys/fs/bpf/osmanthus/next_path_rmdir",
    "/sys/fs/bpf/osmanthus/next_path_rename",
    "/sys/fs/bpf/osmanthus/next_file_open",
    "/sys/fs/bpf/osmanthus/next_file_permission",
    "/sys/fs/bpf/osmanthus/next_mmap_file",
    "/sys/fs/bpf/osmanthus/next_file_mprotect",
    "/sys/fs/bpf/osmanthus/next_path_chmod",
    "/sys/fs/bpf/osmanthus/next_path_chown",
    "/sys/fs/bpf/osmanthus/next_execve",
    "/sys/fs/bpf/osmanthus/next_execveat",
    "/sys/fs/bpf/osmanthus/next_sb_mount",
    "/sys/fs/bpf/osmanthus/next_move_mount",
];

const KERNEL_EVENT_BYTES: usize = 320;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventKind {
    ProcessExec,
    ResourceBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelEvent {
    pub monotonic_nanoseconds: u64,
    pub inode: u64,
    pub kind: KernelEventKind,
    pub action: Option<ProtectedAction>,
    pub device: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: String,
    pub filename: String,
}

pub fn parse_kernel_event(bytes: &[u8]) -> Result<KernelEvent> {
    if bytes.len() != KERNEL_EVENT_BYTES {
        return Err(OsmanthusError::InvalidState(format!(
            "kernel event has invalid size: {}",
            bytes.len()
        )));
    }
    let event_type = read_u32(bytes, 16);
    let action_number = read_u32(bytes, 20);
    let kind = match event_type {
        1 => KernelEventKind::ProcessExec,
        2 => KernelEventKind::ResourceBlocked,
        _ => {
            return Err(OsmanthusError::InvalidState(format!(
                "kernel event has unknown type: {event_type}"
            )));
        }
    };
    let action = match action_number {
        0 => None,
        1 => Some(ProtectedAction::Delete),
        2 => Some(ProtectedAction::Rename),
        3 => Some(ProtectedAction::Truncate),
        4 => Some(ProtectedAction::ChangePermissions),
        5 => Some(ProtectedAction::Write),
        6 if kind == KernelEventKind::ResourceBlocked => None,
        _ => {
            return Err(OsmanthusError::InvalidState(format!(
                "kernel event has unknown action: {action_number}"
            )));
        }
    };
    if kind == KernelEventKind::ResourceBlocked && action.is_none() && action_number != 6 {
        return Err(OsmanthusError::InvalidState(
            "blocked kernel event has no operation class".to_owned(),
        ));
    }
    Ok(KernelEvent {
        monotonic_nanoseconds: read_u64(bytes, 0),
        inode: read_u64(bytes, 8),
        kind,
        action,
        device: read_u32(bytes, 24),
        pid: read_u32(bytes, 28),
        tgid: read_u32(bytes, 32),
        uid: read_u32(bytes, 36),
        gid: read_u32(bytes, 40),
        command: read_c_string(&bytes[44..60]),
        filename: read_c_string(&bytes[60..316]),
    })
}

pub struct LinuxBpfSession<'object> {
    skeleton: OsmanthusLsmSkel<'object>,
}

impl<'object> LinuxBpfSession<'object> {
    pub fn load(
        object: &'object mut MaybeUninit<OpenObject>,
        policy: &EnforcementPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let open = OsmanthusLsmSkelBuilder::default()
            .open(object)
            .map_err(bpf_error("open embedded BPF object"))?;
        let skeleton = open.load().map_err(bpf_error("load BPF programs"))?;
        let mut session = Self { skeleton };
        session
            .skeleton
            .maps
            .osmanthus_metadata
            .update(
                &0_u32.to_ne_bytes(),
                &BPF_ABI_VERSION.to_ne_bytes(),
                MapFlags::ANY,
            )
            .map_err(bpf_error("set BPF ABI version"))?;
        session.replace_policy(policy)?;
        session
            .skeleton
            .attach()
            .map_err(bpf_error("attach BPF LSM programs"))?;
        Ok(session)
    }

    pub fn replace_policy(&mut self, policy: &EnforcementPolicy) -> Result<()> {
        policy.validate()?;
        clear_map(&self.skeleton.maps.osmanthus_protected_roots)?;
        clear_map(&self.skeleton.maps.osmanthus_protected_boundaries)?;
        for root in &policy.protected_roots {
            self.add_root(root)?;
        }
        clear_map(&self.skeleton.maps.osmanthus_monitored_uids)?;
        for uid in &policy.monitored_uids {
            self.skeleton
                .maps
                .osmanthus_monitored_uids
                .update(&uid.to_ne_bytes(), &ENABLED, MapFlags::ANY)
                .map_err(bpf_error("install monitored UID in BPF map"))?;
        }
        set_write_protection_feature(
            &self.skeleton.maps.osmanthus_metadata,
            policy
                .protected_roots
                .iter()
                .any(|root| root.actions().contains(&ProtectedAction::Write)),
        )?;
        Ok(())
    }

    pub fn grant_maintenance(&self, lease: &MaintenanceLease, now_unix: i64) -> Result<()> {
        update_maintenance_map(
            &self.skeleton.maps.osmanthus_maintenance_leases,
            lease,
            now_unix,
        )
    }

    pub fn revoke_maintenance(&self, lease: &MaintenanceLease) -> Result<()> {
        delete_maintenance_map(&self.skeleton.maps.osmanthus_maintenance_leases, lease)
    }

    pub fn event_map_handle(&self) -> Result<MapHandle> {
        MapHandle::try_from(&self.skeleton.maps.osmanthus_events)
            .map_err(bpf_error("duplicate transient event BPF map handle"))
    }

    fn add_root(&self, root: &ProtectedRoot) -> Result<()> {
        for resource in resource_identities(root.path())? {
            self.skeleton
                .maps
                .osmanthus_protected_boundaries
                .update(&resource.boundary_key(), &ENABLED, MapFlags::ANY)
                .map_err(bpf_error("install protected boundary in BPF map"))?;
            for action in root.actions() {
                self.skeleton
                    .maps
                    .osmanthus_protected_roots
                    .update(&resource.key(*action), &ENABLED, MapFlags::ANY)
                    .map_err(bpf_error("install protected root in BPF map"))?;
            }
        }
        Ok(())
    }

    fn pin_all(&mut self) -> Result<()> {
        self.skeleton
            .maps
            .osmanthus_metadata
            .pin(METADATA_MAP)
            .map_err(bpf_error("pin metadata BPF map"))?;
        self.skeleton
            .maps
            .osmanthus_protected_roots
            .pin(PROTECTED_ROOTS_MAP)
            .map_err(bpf_error("pin protected-root BPF map"))?;
        self.skeleton
            .maps
            .osmanthus_protected_boundaries
            .pin(PROTECTED_BOUNDARIES_MAP)
            .map_err(bpf_error("pin protected-boundary BPF map"))?;
        self.skeleton
            .maps
            .osmanthus_maintenance_leases
            .pin(MAINTENANCE_LEASES_MAP)
            .map_err(bpf_error("pin maintenance BPF map"))?;
        self.skeleton
            .maps
            .osmanthus_monitored_uids
            .pin(MONITORED_UIDS_MAP)
            .map_err(bpf_error("pin monitored-UID BPF map"))?;
        self.skeleton
            .maps
            .osmanthus_events
            .pin(EVENTS_MAP)
            .map_err(bpf_error("pin event BPF map"))?;
        pin_link(
            &mut self.skeleton.links.osmanthus_path_unlink,
            LINK_PATHS[0],
        )?;
        pin_link(&mut self.skeleton.links.osmanthus_path_rmdir, LINK_PATHS[1])?;
        pin_link(
            &mut self.skeleton.links.osmanthus_path_rename,
            LINK_PATHS[2],
        )?;
        pin_link(&mut self.skeleton.links.osmanthus_file_open, LINK_PATHS[3])?;
        pin_link(
            &mut self.skeleton.links.osmanthus_file_permission,
            LINK_PATHS[4],
        )?;
        pin_link(&mut self.skeleton.links.osmanthus_mmap_file, LINK_PATHS[5])?;
        pin_link(
            &mut self.skeleton.links.osmanthus_file_mprotect,
            LINK_PATHS[6],
        )?;
        pin_link(&mut self.skeleton.links.osmanthus_path_chmod, LINK_PATHS[7])?;
        pin_link(&mut self.skeleton.links.osmanthus_path_chown, LINK_PATHS[8])?;
        pin_link(&mut self.skeleton.links.osmanthus_execve, LINK_PATHS[9])?;
        pin_link(&mut self.skeleton.links.osmanthus_execveat, LINK_PATHS[10])?;
        pin_link(&mut self.skeleton.links.osmanthus_sb_mount, LINK_PATHS[11])?;
        pin_link(
            &mut self.skeleton.links.osmanthus_move_mount,
            LINK_PATHS[12],
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ResourceIdentity {
    inode: u64,
    device: u32,
}

impl ResourceIdentity {
    fn key(self, action: ProtectedAction) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&self.inode.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.device.to_ne_bytes());
        bytes[12..].copy_from_slice(&action_number(action).to_ne_bytes());
        bytes
    }

    fn boundary_key(self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&self.inode.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.device.to_ne_bytes());
        bytes
    }

    fn maintenance_key(self, action: ProtectedAction, cgroup_id: u64) -> [u8; 24] {
        let mut bytes = [0_u8; 24];
        bytes[..16].copy_from_slice(&self.key(action));
        bytes[16..].copy_from_slice(&cgroup_id.to_ne_bytes());
        bytes
    }
}

fn resource_identity(path: &Path) -> Result<ResourceIdentity> {
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(OsmanthusError::InvalidState(format!(
            "protected resource must be canonical and must not traverse a symlink: {} resolves to {}",
            path.display(),
            canonical.display()
        )));
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(OsmanthusError::InvalidState(format!(
            "protected resource root must be a directory: {}",
            path.display()
        )));
    }
    let device = u32::try_from(metadata.dev()).map_err(|_| {
        OsmanthusError::InvalidState(format!(
            "device identifier is unsupported for protected root: {}",
            path.display()
        ))
    })?;
    Ok(ResourceIdentity {
        inode: metadata.ino(),
        device,
    })
}

fn resource_identities(root: &Path) -> Result<Vec<ResourceIdentity>> {
    let mut identities = std::collections::BTreeSet::from([resource_identity(root)?]);
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        let Some(encoded_mountpoint) = line.split_ascii_whitespace().nth(4) else {
            return Err(OsmanthusError::InvalidState(
                "/proc/self/mountinfo contains an incomplete record".to_owned(),
            ));
        };
        let mountpoint = PathBuf::from(decode_mountinfo_path(encoded_mountpoint)?);
        if mountpoint != root && mountpoint.starts_with(root) {
            identities.insert(resource_identity(&mountpoint)?);
        }
    }
    Ok(identities.into_iter().collect())
}

fn decode_mountinfo_path(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..index + 4].iter().all(u8::is_ascii_digit)
            {
                return Err(OsmanthusError::InvalidState(
                    "/proc/self/mountinfo contains an invalid escape".to_owned(),
                ));
            }
            let octal = std::str::from_utf8(&bytes[index + 1..index + 4]).map_err(|_| {
                OsmanthusError::InvalidState("mountinfo escape is not UTF-8".to_owned())
            })?;
            let byte = u8::from_str_radix(octal, 8).map_err(|_| {
                OsmanthusError::InvalidState("mountinfo escape is not octal".to_owned())
            })?;
            decoded.push(byte);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| OsmanthusError::InvalidState("mountinfo path is not UTF-8".to_owned()))
}

fn action_number(action: ProtectedAction) -> u32 {
    match action {
        ProtectedAction::Delete => 1,
        ProtectedAction::Rename => 2,
        ProtectedAction::Truncate => 3,
        ProtectedAction::ChangePermissions => 4,
        ProtectedAction::Write => 5,
    }
}

fn set_write_protection_feature(map: &impl MapCore, enabled: bool) -> Result<()> {
    map.update(
        &1_u32.to_ne_bytes(),
        &u32::from(enabled).to_ne_bytes(),
        MapFlags::ANY,
    )
    .map_err(bpf_error("update BPF write-protection feature flag"))
}

fn monotonic_nanoseconds() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| OsmanthusError::InvalidState("invalid monotonic clock".to_owned()))?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .map_err(|_| OsmanthusError::InvalidState("invalid monotonic clock".to_owned()))?;
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds))
}

fn update_maintenance_map(
    map: &impl MapCore,
    lease: &MaintenanceLease,
    now_unix: i64,
) -> Result<()> {
    let remaining_seconds = lease.expires_at_unix.saturating_sub(now_unix);
    if remaining_seconds <= 0 {
        return Err(OsmanthusError::InvalidState(
            "cannot install an expired maintenance lease".to_owned(),
        ));
    }
    let deadline = monotonic_nanoseconds()?
        .checked_add(
            u64::try_from(remaining_seconds)
                .map_err(|_| OsmanthusError::InvalidState("invalid maintenance expiry".to_owned()))?
                .saturating_mul(1_000_000_000),
        )
        .ok_or_else(|| OsmanthusError::InvalidState("maintenance expiry overflow".to_owned()))?;
    let mut installed: Vec<[u8; 24]> = Vec::new();
    for resource in resource_identities(&lease.scope)? {
        for action in &lease.actions {
            let key = resource.maintenance_key(*action, lease.cgroup_id);
            if let Err(error) = map.update(&key, &deadline.to_ne_bytes(), MapFlags::ANY) {
                let mut rollback_failures = Vec::new();
                for installed_key in installed {
                    if let Err(rollback_error) = map.delete(&installed_key) {
                        rollback_failures.push(rollback_error.to_string());
                    }
                }
                let install_error = bpf_error("install maintenance lease in BPF map")(error);
                if rollback_failures.is_empty() {
                    return Err(install_error);
                }
                return Err(OsmanthusError::InvalidState(format!(
                    "{install_error}; maintenance map rollback failed: {}",
                    rollback_failures.join(", ")
                )));
            }
            installed.push(key);
        }
    }
    Ok(())
}

fn delete_maintenance_map(map: &impl MapCore, lease: &MaintenanceLease) -> Result<()> {
    for resource in resource_identities(&lease.scope)? {
        for action in &lease.actions {
            let key = resource.maintenance_key(*action, lease.cgroup_id);
            match map.delete(&key) {
                Ok(()) => {}
                Err(error) if error.kind() == libbpf_rs::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(bpf_error("remove maintenance lease from BPF map")(error));
                }
            }
        }
    }
    Ok(())
}

fn pin_link(link: &mut Option<Link>, path: &str) -> Result<()> {
    link.as_mut()
        .ok_or_else(|| OsmanthusError::InvalidState(format!("BPF link missing for {path}")))?
        .pin(path)
        .map_err(bpf_error("pin BPF LSM link"))
}

fn validate_pin_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{PIN_DIRECTORY} must be a root-owned directory with mode 700"
        )));
    }
    Ok(())
}

fn remove_created_pins() {
    remove_next_link_pins();
    for path in LINK_PATHS.into_iter().rev() {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_file(MAINTENANCE_LEASES_MAP);
    let _ = fs::remove_file(PROTECTED_ROOTS_MAP);
    let _ = fs::remove_file(PROTECTED_BOUNDARIES_MAP);
    let _ = fs::remove_file(MONITORED_UIDS_MAP);
    let _ = fs::remove_file(EVENTS_MAP);
    let _ = fs::remove_file(METADATA_MAP);
}

fn remove_next_link_pins() {
    for path in NEXT_LINK_PATHS {
        let _ = fs::remove_file(path);
    }
}

fn recover_upgrade_pins() -> Result<()> {
    for (current, next) in LINK_PATHS.into_iter().zip(NEXT_LINK_PATHS) {
        match (Path::new(current).exists(), Path::new(next).exists()) {
            (true, true) => fs::remove_file(next)?,
            (false, true) => fs::rename(next, current)?,
            _ => {}
        }
    }
    Ok(())
}

fn clear_map(map: &impl MapCore) -> Result<()> {
    let keys = map.keys().collect::<Vec<_>>();
    for key in keys {
        map.delete(&key).map_err(bpf_error("clear BPF map"))?;
    }
    Ok(())
}

fn sync_map(map: &impl MapCore, desired: &std::collections::BTreeSet<[u8; 16]>) -> Result<()> {
    for key in desired {
        map.update(key, &ENABLED, MapFlags::ANY)
            .map_err(bpf_error("update persistent BPF map"))?;
    }
    for key in map.keys().collect::<Vec<_>>() {
        if !desired.contains(key.as_slice()) {
            map.delete(&key)
                .map_err(bpf_error("remove stale persistent BPF entry"))?;
        }
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated event size"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated event size"),
    )
}

fn read_c_string(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn bpf_error(context: &'static str) -> impl FnOnce(libbpf_rs::Error) -> OsmanthusError {
    move |error| OsmanthusError::InvalidState(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_key_has_stable_native_layout() {
        let identity = ResourceIdentity {
            inode: 0x0102_0304_0506_0708,
            device: 0x1112_1314,
        };
        let key = identity.key(ProtectedAction::Rename);
        assert_eq!(&key[..8], &identity.inode.to_ne_bytes());
        assert_eq!(&key[8..12], &identity.device.to_ne_bytes());
        assert_eq!(&key[12..], &2_u32.to_ne_bytes());
    }

    #[test]
    fn maintenance_key_includes_cgroup_identity() {
        let identity = ResourceIdentity {
            inode: 0x0102_0304_0506_0708,
            device: 0x1112_1314,
        };
        let key = identity.maintenance_key(ProtectedAction::Write, 0x2122_2324_2526_2728);
        assert_eq!(&key[..16], &identity.key(ProtectedAction::Write));
        assert_eq!(&key[16..], &0x2122_2324_2526_2728_u64.to_ne_bytes());
    }

    #[test]
    fn parses_fixed_size_kernel_event_without_unsafe_casts() {
        let mut bytes = [0_u8; KERNEL_EVENT_BYTES];
        bytes[0..8].copy_from_slice(&123_u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_ne_bytes());
        bytes[28..32].copy_from_slice(&44_u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(&43_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&1000_u32.to_ne_bytes());
        bytes[44..48].copy_from_slice(b"bash");
        bytes[60..67].copy_from_slice(b"/bin/ls");
        let event = parse_kernel_event(&bytes).unwrap();
        assert_eq!(event.kind, KernelEventKind::ProcessExec);
        assert_eq!(event.pid, 44);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.command, "bash");
        assert_eq!(event.filename, "/bin/ls");
    }

    #[test]
    fn parses_mount_boundary_event_as_a_resource_denial() {
        let mut bytes = [0_u8; KERNEL_EVENT_BYTES];
        bytes[16..20].copy_from_slice(&2_u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&6_u32.to_ne_bytes());
        let event = parse_kernel_event(&bytes).unwrap();
        assert_eq!(event.kind, KernelEventKind::ResourceBlocked);
        assert_eq!(event.action, None);
    }

    #[test]
    fn decodes_mountinfo_path_escapes() {
        assert_eq!(
            decode_mountinfo_path("/srv/app\\040data\\134archive").unwrap(),
            "/srv/app data\\archive"
        );
        assert!(decode_mountinfo_path("/srv/bad\\04").is_err());
    }
}
