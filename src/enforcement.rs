use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{OsmanthusError, Result};

pub const DEFAULT_MAINTENANCE_SECONDS: i64 = 300;
pub const DEFAULT_MAX_MAINTENANCE_SECONDS: i64 = 1_800;
pub const MAX_MAINTENANCE_SECONDS: i64 = 86_400;
const MAX_PROTECTED_ROOTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedAction {
    Delete,
    Rename,
    Truncate,
    Write,
    ChangePermissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceSettings {
    pub default_ttl_seconds: i64,
    pub max_ttl_seconds: i64,
}

impl Default for MaintenanceSettings {
    fn default() -> Self {
        Self {
            default_ttl_seconds: DEFAULT_MAINTENANCE_SECONDS,
            max_ttl_seconds: DEFAULT_MAX_MAINTENANCE_SECONDS,
        }
    }
}

impl MaintenanceSettings {
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_MAINTENANCE_SECONDS).contains(&self.max_ttl_seconds) {
            return Err(OsmanthusError::InvalidState(format!(
                "maintenance maximum must be 1-{MAX_MAINTENANCE_SECONDS} seconds"
            )));
        }
        if !(1..=self.max_ttl_seconds).contains(&self.default_ttl_seconds) {
            return Err(OsmanthusError::InvalidState(
                "maintenance default must be positive and no greater than the configured maximum"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedRoot {
    path: PathBuf,
    actions: BTreeSet<ProtectedAction>,
}

impl ProtectedRoot {
    pub fn new(path: impl AsRef<Path>, actions: BTreeSet<ProtectedAction>) -> Result<Self> {
        let path = normalize_absolute(path.as_ref())?;
        if path == Path::new("/") {
            return Err(OsmanthusError::InvalidState(
                "the filesystem root cannot be a normal protected root".to_owned(),
            ));
        }
        if actions.is_empty() {
            return Err(OsmanthusError::InvalidState(
                "a protected root requires at least one action".to_owned(),
            ));
        }
        Ok(Self { path, actions })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn actions(&self) -> &BTreeSet<ProtectedAction> {
        &self.actions
    }

    fn protects(&self, operation: &ResourceOperation) -> bool {
        self.actions.contains(&operation.action) && operation.target.starts_with(&self.path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPolicy {
    pub schema_version: u32,
    pub protected_roots: Vec<ProtectedRoot>,
    #[serde(default)]
    pub monitored_uids: BTreeSet<u32>,
    #[serde(default)]
    pub maintenance: MaintenanceSettings,
}

impl EnforcementPolicy {
    pub fn new(protected_roots: Vec<ProtectedRoot>) -> Result<Self> {
        Self::from_parts(protected_roots, BTreeSet::new())
    }

    pub fn from_parts(
        protected_roots: Vec<ProtectedRoot>,
        monitored_uids: BTreeSet<u32>,
    ) -> Result<Self> {
        Self::from_parts_with_maintenance(
            protected_roots,
            monitored_uids,
            MaintenanceSettings::default(),
        )
    }

    pub fn from_parts_with_maintenance(
        protected_roots: Vec<ProtectedRoot>,
        monitored_uids: BTreeSet<u32>,
        maintenance: MaintenanceSettings,
    ) -> Result<Self> {
        let policy = Self {
            schema_version: 1,
            protected_roots,
            monitored_uids,
            maintenance,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(OsmanthusError::InvalidState(format!(
                "unsupported enforcement policy schema version: {}",
                self.schema_version
            )));
        }
        self.maintenance.validate()?;
        if self.protected_roots.len() > MAX_PROTECTED_ROOTS {
            return Err(OsmanthusError::InvalidState(format!(
                "enforcement policy contains more than {MAX_PROTECTED_ROOTS} protected roots"
            )));
        }
        if self.monitored_uids.len() > 256 {
            return Err(OsmanthusError::InvalidState(
                "enforcement policy contains more than 256 monitored UIDs".to_owned(),
            ));
        }
        if self.monitored_uids.contains(&0) {
            return Err(OsmanthusError::InvalidState(
                "root cannot be enrolled as a monitored UID".to_owned(),
            ));
        }
        let mut paths = BTreeSet::new();
        for root in &self.protected_roots {
            ProtectedRoot::new(root.path(), root.actions().clone())?;
            if !paths.insert(root.path()) {
                return Err(OsmanthusError::InvalidState(format!(
                    "duplicate protected root: {}",
                    root.path().display()
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceOperation {
    pub action: ProtectedAction,
    pub target: PathBuf,
}

impl ResourceOperation {
    pub fn new(action: ProtectedAction, target: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            action,
            target: normalize_absolute(target.as_ref())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceLease {
    pub id: String,
    pub scope: PathBuf,
    pub actions: BTreeSet<ProtectedAction>,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub administrator_uid: u32,
    pub cgroup_id: u64,
}

impl MaintenanceLease {
    pub fn issue(
        scope: impl AsRef<Path>,
        actions: BTreeSet<ProtectedAction>,
        now_unix: i64,
        ttl_seconds: i64,
        administrator_uid: u32,
        cgroup_id: u64,
    ) -> Result<Self> {
        let scope = normalize_absolute(scope.as_ref())?;
        if scope == Path::new("/") {
            return Err(OsmanthusError::InvalidState(
                "an unscoped filesystem maintenance lease is not permitted".to_owned(),
            ));
        }
        if actions.is_empty() {
            return Err(OsmanthusError::InvalidState(
                "a maintenance lease requires at least one action".to_owned(),
            ));
        }
        if cgroup_id == 0 {
            return Err(OsmanthusError::InvalidState(
                "a maintenance lease requires a nonzero cgroup ID".to_owned(),
            ));
        }
        if !(1..=MAX_MAINTENANCE_SECONDS).contains(&ttl_seconds) {
            return Err(OsmanthusError::InvalidState(format!(
                "maintenance TTL must be 1-{MAX_MAINTENANCE_SECONDS} seconds"
            )));
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            scope,
            actions,
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + ttl_seconds,
            administrator_uid,
            cgroup_id,
        })
    }

    fn allows(&self, operation: &ResourceOperation, now_unix: i64, cgroup_id: u64) -> bool {
        now_unix <= self.expires_at_unix
            && self.cgroup_id == cgroup_id
            && self.actions.contains(&operation.action)
            && operation.target.starts_with(&self.scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum EnforcementDecision {
    Unprotected,
    Blocked { protected_root: PathBuf },
    MaintenanceAllowed { lease_id: String },
}

#[derive(Debug, Default)]
pub struct EnforcementEngine {
    protected_roots: Vec<ProtectedRoot>,
    monitored_uids: BTreeSet<u32>,
    maintenance: MaintenanceSettings,
    maintenance_leases: Vec<MaintenanceLease>,
}

impl EnforcementEngine {
    pub fn from_policy(policy: &EnforcementPolicy) -> Result<Self> {
        policy.validate()?;
        let mut engine = Self::new(policy.protected_roots.clone());
        engine.monitored_uids = policy.monitored_uids.clone();
        engine.maintenance = policy.maintenance;
        Ok(engine)
    }

    pub fn new(mut protected_roots: Vec<ProtectedRoot>) -> Self {
        protected_roots.sort_by(|left, right| {
            right
                .path
                .components()
                .count()
                .cmp(&left.path.components().count())
                .then_with(|| left.path.cmp(&right.path))
        });
        Self {
            protected_roots,
            monitored_uids: BTreeSet::new(),
            maintenance: MaintenanceSettings::default(),
            maintenance_leases: Vec::new(),
        }
    }

    pub fn grant_maintenance(&mut self, lease: MaintenanceLease) -> Result<()> {
        let covered = self.protected_roots.iter().any(|root| {
            lease.scope.starts_with(root.path())
                && lease
                    .actions
                    .iter()
                    .all(|action| root.actions().contains(action))
        });
        if !covered {
            return Err(OsmanthusError::InvalidState(
                "maintenance scope and actions must be covered by one protected root".to_owned(),
            ));
        }
        let overlaps_existing = self.maintenance_leases.iter().any(|existing| {
            (lease.scope.starts_with(&existing.scope) || existing.scope.starts_with(&lease.scope))
                && lease
                    .actions
                    .iter()
                    .any(|action| existing.actions.contains(action))
        });
        if overlaps_existing {
            return Err(OsmanthusError::InvalidState(
                "maintenance scope and action overlap an active lease".to_owned(),
            ));
        }
        self.maintenance_leases.push(lease);
        Ok(())
    }

    pub fn maintenance_lease(&self, lease_id: &str) -> Option<&MaintenanceLease> {
        self.maintenance_leases
            .iter()
            .find(|lease| lease.id == lease_id)
    }

    pub fn revoke_maintenance(&mut self, lease_id: &str) -> Option<MaintenanceLease> {
        let index = self
            .maintenance_leases
            .iter()
            .position(|lease| lease.id == lease_id)?;
        Some(self.maintenance_leases.remove(index))
    }

    pub fn maintenance_leases(&self) -> Vec<MaintenanceLease> {
        self.maintenance_leases.clone()
    }

    pub fn policy(&self) -> EnforcementPolicy {
        EnforcementPolicy {
            schema_version: 1,
            protected_roots: self.protected_roots.clone(),
            monitored_uids: self.monitored_uids.clone(),
            maintenance: self.maintenance,
        }
    }

    pub fn maintenance_settings(&self) -> MaintenanceSettings {
        self.maintenance
    }

    pub fn monitors_uid(&self, uid: u32) -> bool {
        self.monitored_uids.contains(&uid)
    }

    pub fn expire_maintenance(&mut self, now_unix: i64) -> Vec<MaintenanceLease> {
        let mut expired = Vec::new();
        self.maintenance_leases.retain(|lease| {
            if lease.expires_at_unix < now_unix {
                expired.push(lease.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn decide(
        &self,
        operation: &ResourceOperation,
        now_unix: i64,
        cgroup_id: u64,
    ) -> EnforcementDecision {
        let Some(root) = self
            .protected_roots
            .iter()
            .find(|root| root.protects(operation))
        else {
            return EnforcementDecision::Unprotected;
        };
        if let Some(lease) = self
            .maintenance_leases
            .iter()
            .find(|lease| lease.allows(operation, now_unix, cgroup_id))
        {
            return EnforcementDecision::MaintenanceAllowed {
                lease_id: lease.id.clone(),
            };
        }
        EnforcementDecision::Blocked {
            protected_root: root.path.clone(),
        }
    }
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(OsmanthusError::InvalidState(format!(
            "protected resource path must be absolute: {}",
            path.display()
        )));
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::CurDir | Component::ParentDir => {
                return Err(OsmanthusError::InvalidState(format!(
                    "protected resource path must not contain dot components: {}",
                    path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(OsmanthusError::InvalidState(format!(
                    "unsupported protected resource path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CGROUP_ID: u64 = 42;

    fn actions(values: &[ProtectedAction]) -> BTreeSet<ProtectedAction> {
        values.iter().copied().collect()
    }

    fn engine() -> EnforcementEngine {
        EnforcementEngine::new(vec![
            ProtectedRoot::new(
                "/var/www",
                actions(&[
                    ProtectedAction::Delete,
                    ProtectedAction::Rename,
                    ProtectedAction::Truncate,
                ]),
            )
            .unwrap(),
        ])
    }

    #[test]
    fn blocks_selected_actions_below_a_protected_root() {
        let engine = engine();
        let operation =
            ResourceOperation::new(ProtectedAction::Delete, "/var/www/releases/old").unwrap();
        assert_eq!(
            engine.decide(&operation, 100, TEST_CGROUP_ID),
            EnforcementDecision::Blocked {
                protected_root: PathBuf::from("/var/www")
            }
        );
    }

    #[test]
    fn allows_unrelated_paths_and_actions() {
        let engine = engine();
        let outside =
            ResourceOperation::new(ProtectedAction::Delete, "/var/www-backup/old").unwrap();
        let unprotected_action =
            ResourceOperation::new(ProtectedAction::ChangePermissions, "/var/www/app").unwrap();
        assert_eq!(
            engine.decide(&outside, 100, TEST_CGROUP_ID),
            EnforcementDecision::Unprotected
        );
        assert_eq!(
            engine.decide(&unprotected_action, 100, TEST_CGROUP_ID),
            EnforcementDecision::Unprotected
        );
    }

    #[test]
    fn maintenance_is_scoped_by_path_action_and_time() {
        let mut engine = engine();
        let lease = MaintenanceLease::issue(
            "/var/www/releases",
            actions(&[ProtectedAction::Delete]),
            100,
            300,
            0,
            TEST_CGROUP_ID,
        )
        .unwrap();
        let lease_id = lease.id.clone();
        engine.grant_maintenance(lease).unwrap();

        let allowed =
            ResourceOperation::new(ProtectedAction::Delete, "/var/www/releases/old").unwrap();
        let other_path = ResourceOperation::new(ProtectedAction::Delete, "/var/www/data").unwrap();
        let other_action =
            ResourceOperation::new(ProtectedAction::Rename, "/var/www/releases/old").unwrap();
        assert_eq!(
            engine.decide(&allowed, 400, TEST_CGROUP_ID),
            EnforcementDecision::MaintenanceAllowed { lease_id }
        );
        assert!(matches!(
            engine.decide(&allowed, 400, TEST_CGROUP_ID + 1),
            EnforcementDecision::Blocked { .. }
        ));
        assert!(matches!(
            engine.decide(&other_path, 400, TEST_CGROUP_ID),
            EnforcementDecision::Blocked { .. }
        ));
        assert!(matches!(
            engine.decide(&other_action, 400, TEST_CGROUP_ID),
            EnforcementDecision::Blocked { .. }
        ));
        assert!(matches!(
            engine.decide(&allowed, 401, TEST_CGROUP_ID),
            EnforcementDecision::Blocked { .. }
        ));
    }

    #[test]
    fn lease_must_be_inside_an_existing_protection_boundary() {
        let mut engine = engine();
        let lease = MaintenanceLease::issue(
            "/tmp",
            actions(&[ProtectedAction::Delete]),
            100,
            DEFAULT_MAINTENANCE_SECONDS,
            0,
            TEST_CGROUP_ID,
        )
        .unwrap();
        assert!(engine.grant_maintenance(lease).is_err());
    }

    #[test]
    fn overlapping_maintenance_scope_and_action_is_rejected() {
        let mut engine = engine();
        engine
            .grant_maintenance(
                MaintenanceLease::issue(
                    "/var/www/releases",
                    actions(&[ProtectedAction::Delete]),
                    100,
                    300,
                    0,
                    TEST_CGROUP_ID,
                )
                .unwrap(),
            )
            .unwrap();

        let overlapping = MaintenanceLease::issue(
            "/var/www/releases/old",
            actions(&[ProtectedAction::Delete]),
            100,
            300,
            0,
            TEST_CGROUP_ID,
        )
        .unwrap();
        assert!(engine.grant_maintenance(overlapping).is_err());

        let distinct_action = MaintenanceLease::issue(
            "/var/www/releases",
            actions(&[ProtectedAction::Rename]),
            100,
            300,
            0,
            TEST_CGROUP_ID,
        )
        .unwrap();
        assert!(engine.grant_maintenance(distinct_action).is_ok());
    }

    #[test]
    fn rejects_relative_root_global_lease_and_excessive_ttl() {
        assert!(ProtectedRoot::new("var/www", actions(&[ProtectedAction::Delete])).is_err());
        assert!(
            MaintenanceLease::issue(
                "/",
                actions(&[ProtectedAction::Delete]),
                100,
                300,
                0,
                TEST_CGROUP_ID,
            )
            .is_err()
        );
        assert!(
            MaintenanceLease::issue(
                "/var/www",
                actions(&[ProtectedAction::Delete]),
                100,
                MAX_MAINTENANCE_SECONDS + 1,
                0,
                TEST_CGROUP_ID,
            )
            .is_err()
        );
    }

    #[test]
    fn validates_configurable_maintenance_bounds() {
        let settings = MaintenanceSettings {
            default_ttl_seconds: 3_600,
            max_ttl_seconds: 28_800,
        };
        settings.validate().unwrap();
        assert!(
            MaintenanceSettings {
                default_ttl_seconds: 28_801,
                max_ttl_seconds: 28_800,
            }
            .validate()
            .is_err()
        );
        assert!(
            MaintenanceSettings {
                default_ttl_seconds: 300,
                max_ttl_seconds: MAX_MAINTENANCE_SECONDS + 1,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn rejects_root_as_a_monitored_identity() {
        assert!(EnforcementPolicy::from_parts(Vec::new(), BTreeSet::from([0])).is_err());
    }

    #[test]
    fn daemon_restart_drops_in_memory_maintenance() {
        let mut first = engine();
        first
            .grant_maintenance(
                MaintenanceLease::issue(
                    "/var/www",
                    actions(&[ProtectedAction::Delete]),
                    100,
                    300,
                    0,
                    TEST_CGROUP_ID,
                )
                .unwrap(),
            )
            .unwrap();
        let operation = ResourceOperation::new(ProtectedAction::Delete, "/var/www/data").unwrap();
        assert!(matches!(
            first.decide(&operation, 100, TEST_CGROUP_ID),
            EnforcementDecision::MaintenanceAllowed { .. }
        ));
        assert!(matches!(
            engine().decide(&operation, 100, TEST_CGROUP_ID),
            EnforcementDecision::Blocked { .. }
        ));
    }

    #[test]
    fn policy_round_trip_is_valid_and_duplicate_roots_fail() {
        let root = ProtectedRoot::new(
            "/srv/application",
            actions(&[ProtectedAction::Delete, ProtectedAction::Rename]),
        )
        .unwrap();
        let policy = EnforcementPolicy::new(vec![root.clone()]).unwrap();
        let encoded = serde_json::to_vec(&policy).unwrap();
        let decoded: EnforcementPolicy = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, policy);
        assert!(EnforcementPolicy::new(vec![root.clone(), root]).is_err());
    }
}
