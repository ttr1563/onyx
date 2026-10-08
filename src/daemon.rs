use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::config;
use crate::enforcement::{EnforcementEngine, EnforcementPolicy, MaintenanceLease};
use crate::protocol::{
    BackendState, PROTOCOL_VERSION, Request, RequestBody, Response, ResponseBody,
};
use crate::{OsmanthusError, Result};

pub const DAEMON_AUDIT_FILE: &str = "/var/log/osmanthus/audit.jsonl";
const SESSION_IDLE_TIMEOUT_SECONDS: i64 = 86_400;

#[derive(Debug, Clone, Copy)]
struct ActiveSession {
    uid: u32,
    cgroup_id: u64,
    last_activity_unix: i64,
}

pub trait AdministratorAuthenticator {
    fn verify(&mut self, code: &str, now_unix: i64) -> Result<()>;
}

pub trait DaemonAuditSink {
    fn append(&mut self, record: &DaemonAuditRecord) -> Result<()>;
}

pub trait EnforcementBackend {
    fn state(&self) -> BackendState;
    fn grant_maintenance(&mut self, lease: &MaintenanceLease, now_unix: i64) -> Result<()>;
    fn revoke_maintenance(&mut self, lease: &MaintenanceLease) -> Result<()>;
    fn replace_policy(&mut self, policy: &EnforcementPolicy) -> Result<()>;
    fn decommission(&mut self) -> Result<()>;
}

pub struct StateBackend(BackendState);

impl EnforcementBackend for StateBackend {
    fn state(&self) -> BackendState {
        self.0
    }

    fn grant_maintenance(&mut self, _lease: &MaintenanceLease, _now_unix: i64) -> Result<()> {
        Ok(())
    }

    fn revoke_maintenance(&mut self, _lease: &MaintenanceLease) -> Result<()> {
        Ok(())
    }

    fn replace_policy(&mut self, _policy: &EnforcementPolicy) -> Result<()> {
        Ok(())
    }

    fn decommission(&mut self) -> Result<()> {
        self.0 = BackendState::Unavailable;
        Ok(())
    }
}

pub struct SystemAdministratorAuthenticator;

impl AdministratorAuthenticator for SystemAdministratorAuthenticator {
    fn verify(&mut self, code: &str, now_unix: i64) -> Result<()> {
        let root = crate::system_policy::admin_state_dir();
        let config = config::load_config(root).map_err(|error| match error {
            OsmanthusError::NotInitialized => OsmanthusError::SystemPolicyNotInitialized,
            other => other,
        })?;
        crate::auth::with_verified_code(root, &config, code, now_unix, || Ok(()))
    }
}

pub struct JsonlDaemonAudit {
    path: PathBuf,
    expected_uid: u32,
}

impl JsonlDaemonAudit {
    pub fn production() -> Result<Self> {
        crate::system_policy::require_root()?;
        Self::open(Path::new(DAEMON_AUDIT_FILE), 0)
    }

    fn open(path: &Path, expected_uid: u32) -> Result<Self> {
        let directory = path
            .parent()
            .ok_or_else(|| OsmanthusError::UnsafePath(path.display().to_string()))?;
        if directory.exists() {
            validate_owned_directory(directory, expected_uid, 0o700)?;
        } else {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            validate_owned_directory(directory, expected_uid, 0o700)?;
        }
        if path.exists() {
            validate_owned_file(path, expected_uid, 0o600)?;
        } else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            validate_owned_file(path, expected_uid, 0o600)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            expected_uid,
        })
    }
}

impl DaemonAuditSink for JsonlDaemonAudit {
    fn append(&mut self, record: &DaemonAuditRecord) -> Result<()> {
        validate_owned_file(&self.path, self.expected_uid, 0o600)?;
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut bytes = serde_json::to_vec(record)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_data()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonAuditRecord {
    pub schema_version: u32,
    pub timestamp_unix: i64,
    pub action: &'static str,
    pub peer_uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_cgroup_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

pub struct DaemonCore<A, L, B = StateBackend> {
    backend: B,
    engine: EnforcementEngine,
    authenticator: A,
    audit: L,
    sessions: BTreeMap<String, ActiveSession>,
    shutdown_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub cgroup_id: u64,
}

#[cfg(test)]
impl From<u32> for PeerIdentity {
    fn from(uid: u32) -> Self {
        Self { uid, cgroup_id: 1 }
    }
}

impl<A: AdministratorAuthenticator, L: DaemonAuditSink> DaemonCore<A, L, StateBackend> {
    pub fn new(
        policy: &EnforcementPolicy,
        backend: BackendState,
        authenticator: A,
        audit: L,
    ) -> Result<Self> {
        Ok(Self {
            backend: StateBackend(backend),
            engine: EnforcementEngine::from_policy(policy)?,
            authenticator,
            audit,
            sessions: BTreeMap::new(),
            shutdown_requested: false,
        })
    }
}

impl<A: AdministratorAuthenticator, L: DaemonAuditSink, B: EnforcementBackend> DaemonCore<A, L, B> {
    pub fn new_with_backend(
        policy: &EnforcementPolicy,
        backend: B,
        authenticator: A,
        audit: L,
    ) -> Result<Self> {
        Ok(Self {
            backend,
            engine: EnforcementEngine::from_policy(policy)?,
            authenticator,
            audit,
            sessions: BTreeMap::new(),
            shutdown_requested: false,
        })
    }

    pub fn handle(
        &mut self,
        peer: impl Into<PeerIdentity>,
        request: Request,
        now_unix: i64,
    ) -> Result<Response> {
        let peer = peer.into();
        let peer_uid = peer.uid;
        let peer_cgroup_id = peer.cgroup_id;
        request.validate()?;
        for lease in self.engine.expire_maintenance(now_unix) {
            self.backend.revoke_maintenance(&lease)?;
            self.audit.append(&DaemonAuditRecord {
                schema_version: 1,
                timestamp_unix: now_unix,
                action: "maintenance_expired",
                peer_uid: 0,
                peer_cgroup_id: Some(lease.cgroup_id),
                session_id: None,
                target: None,
                operation: None,
                decision: None,
                lease_id: Some(lease.id),
            })?;
        }
        self.expire_sessions(now_unix)?;
        let request_id = request.request_id;
        let body = match request.body {
            RequestBody::Health => ResponseBody::Health {
                daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
                backend: self.backend.state(),
            },
            RequestBody::Evaluate {
                session_id,
                operation,
            } => {
                let decision = self.engine.decide(&operation, now_unix, peer.cgroup_id);
                self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "resource_evaluated",
                    peer_uid: peer.uid,
                    peer_cgroup_id: Some(peer.cgroup_id),
                    session_id: Some(session_id.clone()),
                    target: Some(operation.target.display().to_string()),
                    operation: Some(format!("{:?}", operation.action).to_ascii_lowercase()),
                    decision: Some(decision_name(&decision).to_owned()),
                    lease_id: decision_lease_id(&decision),
                })?;
                ResponseBody::Decision { decision }
            }
            RequestBody::MaintenanceGrant {
                scope,
                actions,
                ttl_seconds,
                authenticator_code,
            } => {
                require_root_peer(peer.uid)?;
                let code = Zeroizing::new(authenticator_code);
                self.authenticator.verify(&code, now_unix)?;
                let maximum = self.engine.maintenance_settings().max_ttl_seconds;
                if ttl_seconds > maximum {
                    return Err(OsmanthusError::InvalidState(format!(
                        "maintenance TTL exceeds the configured maximum of {maximum} seconds"
                    )));
                }
                let lease = MaintenanceLease::issue(
                    &scope,
                    actions.into_iter().collect(),
                    now_unix,
                    ttl_seconds,
                    peer.uid,
                    peer.cgroup_id,
                )?;
                let lease_id = lease.id.clone();
                let expires_at_unix = lease.expires_at_unix;
                self.engine.grant_maintenance(lease.clone())?;
                if let Err(error) = self.backend.grant_maintenance(&lease, now_unix) {
                    self.engine.revoke_maintenance(&lease_id);
                    return Err(error);
                }
                let audit_result = self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "maintenance_granted",
                    peer_uid: peer.uid,
                    peer_cgroup_id: Some(peer.cgroup_id),
                    session_id: None,
                    target: Some(scope.display().to_string()),
                    operation: None,
                    decision: None,
                    lease_id: Some(lease_id.clone()),
                });
                if let Err(error) = audit_result {
                    self.backend.revoke_maintenance(&lease)?;
                    self.engine.revoke_maintenance(&lease_id);
                    return Err(error);
                }
                ResponseBody::MaintenanceGranted {
                    lease_id,
                    expires_at_unix,
                }
            }
            RequestBody::MaintenanceRevoke {
                lease_id,
                authenticator_code,
            } => {
                require_root_peer(peer_uid)?;
                let code = Zeroizing::new(authenticator_code);
                self.authenticator.verify(&code, now_unix)?;
                let lease = self
                    .engine
                    .maintenance_lease(&lease_id)
                    .cloned()
                    .ok_or_else(|| {
                        OsmanthusError::InvalidState(format!(
                            "maintenance lease not found: {lease_id}"
                        ))
                    })?;
                self.backend.revoke_maintenance(&lease)?;
                self.engine.revoke_maintenance(&lease_id);
                self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "maintenance_revoked",
                    peer_uid,
                    peer_cgroup_id: Some(peer_cgroup_id),
                    session_id: None,
                    target: None,
                    operation: None,
                    decision: None,
                    lease_id: Some(lease_id),
                })?;
                ResponseBody::MaintenanceRevoked
            }
            RequestBody::MaintenanceList => {
                require_root_peer(peer_uid)?;
                ResponseBody::MaintenanceList {
                    leases: self.engine.maintenance_leases(),
                }
            }
            RequestBody::Decommission { authenticator_code } => {
                require_root_peer(peer_uid)?;
                if !self.engine.maintenance_leases().is_empty() || !self.sessions.is_empty() {
                    return Err(OsmanthusError::InvalidState(
                        "decommission requires no active maintenance leases or shell sessions"
                            .to_owned(),
                    ));
                }
                let code = Zeroizing::new(authenticator_code);
                self.authenticator.verify(&code, now_unix)?;
                self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "decommission_authorized",
                    peer_uid,
                    peer_cgroup_id: Some(peer_cgroup_id),
                    session_id: None,
                    target: None,
                    operation: None,
                    decision: Some("authorized".to_owned()),
                    lease_id: None,
                })?;
                self.backend.decommission()?;
                self.shutdown_requested = true;
                ResponseBody::Decommissioned
            }
            RequestBody::PolicyReload { policy } => {
                require_root_peer(peer_uid)?;
                if !self.engine.maintenance_leases().is_empty() {
                    return Err(OsmanthusError::InvalidState(
                        "policy reload is not allowed while a maintenance lease is active"
                            .to_owned(),
                    ));
                }
                if self
                    .sessions
                    .values()
                    .any(|session| !policy.monitored_uids.contains(&session.uid))
                {
                    return Err(OsmanthusError::InvalidState(
                        "policy reload would remove an active monitored session".to_owned(),
                    ));
                }
                let previous = self.engine.policy();
                if let Err(error) = self.backend.replace_policy(&policy) {
                    self.backend.replace_policy(&previous)?;
                    return Err(error);
                }
                self.engine = EnforcementEngine::from_policy(&policy)?;
                if let Err(error) = self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "policy_reloaded",
                    peer_uid,
                    peer_cgroup_id: Some(peer_cgroup_id),
                    session_id: None,
                    target: None,
                    operation: None,
                    decision: None,
                    lease_id: None,
                }) {
                    self.backend.replace_policy(&previous)?;
                    self.engine = EnforcementEngine::from_policy(&previous)?;
                    return Err(error);
                }
                ResponseBody::PolicyReloaded
            }
            RequestBody::SessionStart { session_id, shell } => {
                if !self.engine.monitors_uid(peer_uid) {
                    return Err(OsmanthusError::InvalidState(format!(
                        "UID {peer_uid} is not enrolled for shell monitoring"
                    )));
                }
                if self.sessions.len() >= 1024 {
                    return Err(OsmanthusError::InvalidState(
                        "too many active monitored sessions".to_owned(),
                    ));
                }
                if self
                    .sessions
                    .insert(
                        session_id.clone(),
                        ActiveSession {
                            uid: peer_uid,
                            cgroup_id: peer_cgroup_id,
                            last_activity_unix: now_unix,
                        },
                    )
                    .is_some()
                {
                    return Err(OsmanthusError::InvalidState(format!(
                        "session already exists: {session_id}"
                    )));
                }
                if let Err(error) = self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "shell_session_started",
                    peer_uid,
                    peer_cgroup_id: Some(peer_cgroup_id),
                    session_id: Some(session_id.clone()),
                    target: Some(shell),
                    operation: None,
                    decision: None,
                    lease_id: None,
                }) {
                    self.sessions.remove(&session_id);
                    return Err(error);
                }
                ResponseBody::SessionAccepted
            }
            RequestBody::SessionData {
                session_id,
                direction,
                data_base64,
            } => {
                self.require_session_owner(&session_id, peer_uid)?;
                self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: match direction {
                        crate::protocol::SessionDirection::Input => "shell_input",
                        crate::protocol::SessionDirection::Output => "shell_output",
                    },
                    peer_uid,
                    peer_cgroup_id: Some(peer_cgroup_id),
                    session_id: Some(session_id.clone()),
                    target: Some(data_base64),
                    operation: Some("base64".to_owned()),
                    decision: None,
                    lease_id: None,
                })?;
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.last_activity_unix = now_unix;
                }
                ResponseBody::SessionDataRecorded
            }
            RequestBody::SessionEnd {
                session_id,
                exit_code,
            } => {
                self.require_session_owner(&session_id, peer_uid)?;
                self.audit.append(&DaemonAuditRecord {
                    schema_version: 1,
                    timestamp_unix: now_unix,
                    action: "shell_session_ended",
                    peer_uid,
                    peer_cgroup_id: Some(peer_cgroup_id),
                    session_id: Some(session_id.clone()),
                    target: None,
                    operation: Some(exit_code.to_string()),
                    decision: None,
                    lease_id: None,
                })?;
                self.sessions.remove(&session_id);
                ResponseBody::SessionClosed
            }
        };
        Ok(Response {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            body,
        })
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    fn require_session_owner(&self, session_id: &str, peer_uid: u32) -> Result<()> {
        match self.sessions.get(session_id) {
            Some(session) if session.uid == peer_uid => Ok(()),
            Some(_) => Err(OsmanthusError::InvalidState(
                "monitored session belongs to a different UID".to_owned(),
            )),
            None => Err(OsmanthusError::InvalidState(format!(
                "monitored session not found: {session_id}"
            ))),
        }
    }

    fn expire_sessions(&mut self, now_unix: i64) -> Result<()> {
        let expired = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                now_unix.saturating_sub(session.last_activity_unix) > SESSION_IDLE_TIMEOUT_SECONDS
            })
            .map(|(id, session)| (id.clone(), session.uid, session.cgroup_id))
            .collect::<Vec<_>>();
        for (session_id, uid, cgroup_id) in expired {
            self.audit.append(&DaemonAuditRecord {
                schema_version: 1,
                timestamp_unix: now_unix,
                action: "shell_session_expired",
                peer_uid: uid,
                peer_cgroup_id: Some(cgroup_id),
                session_id: Some(session_id.clone()),
                target: None,
                operation: None,
                decision: None,
                lease_id: None,
            })?;
            self.sessions.remove(&session_id);
        }
        Ok(())
    }
}

fn require_root_peer(peer_uid: u32) -> Result<()> {
    if peer_uid != 0 {
        return Err(OsmanthusError::RootRequired);
    }
    Ok(())
}

fn decision_name(decision: &crate::enforcement::EnforcementDecision) -> &'static str {
    match decision {
        crate::enforcement::EnforcementDecision::Unprotected => "unprotected",
        crate::enforcement::EnforcementDecision::Blocked { .. } => "blocked",
        crate::enforcement::EnforcementDecision::MaintenanceAllowed { .. } => "maintenance_allowed",
    }
}

fn decision_lease_id(decision: &crate::enforcement::EnforcementDecision) -> Option<String> {
    match decision {
        crate::enforcement::EnforcementDecision::MaintenanceAllowed { lease_id } => {
            Some(lease_id.clone())
        }
        _ => None,
    }
}

fn validate_owned_directory(path: &Path, uid: u32, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{} must be a real directory owned by uid {uid} with mode {mode:o}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_owned_file(path: &Path, uid: u32, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{} must be a regular file owned by uid {uid} with mode {mode:o}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::enforcement::{
        DEFAULT_MAX_MAINTENANCE_SECONDS, EnforcementDecision, ProtectedAction, ProtectedRoot,
        ResourceOperation,
    };
    use crate::protocol::RequestBody;

    #[derive(Default)]
    struct FakeAuthenticator {
        accepted_code: String,
        calls: usize,
    }

    impl AdministratorAuthenticator for FakeAuthenticator {
        fn verify(&mut self, code: &str, _now_unix: i64) -> Result<()> {
            self.calls += 1;
            if code == self.accepted_code {
                Ok(())
            } else {
                Err(OsmanthusError::InvalidCode)
            }
        }
    }

    #[derive(Default)]
    struct MemoryAudit {
        records: Vec<DaemonAuditRecord>,
        fail: bool,
    }

    impl DaemonAuditSink for MemoryAudit {
        fn append(&mut self, record: &DaemonAuditRecord) -> Result<()> {
            if self.fail {
                return Err(OsmanthusError::Execution("audit unavailable".to_owned()));
            }
            self.records.push(record.clone());
            Ok(())
        }
    }

    fn actions(values: &[ProtectedAction]) -> BTreeSet<ProtectedAction> {
        values.iter().copied().collect()
    }

    fn core() -> DaemonCore<FakeAuthenticator, MemoryAudit> {
        let policy = EnforcementPolicy::from_parts(
            vec![
                ProtectedRoot::new(
                    "/var/www",
                    actions(&[ProtectedAction::Delete, ProtectedAction::Rename]),
                )
                .unwrap(),
            ],
            BTreeSet::from([1000]),
        )
        .unwrap();
        DaemonCore::new(
            &policy,
            BackendState::Enforcing,
            FakeAuthenticator {
                accepted_code: "123456".to_owned(),
                calls: 0,
            },
            MemoryAudit::default(),
        )
        .unwrap()
    }

    fn request(id: &str, body: RequestBody) -> Request {
        Request {
            protocol_version: PROTOCOL_VERSION,
            request_id: id.to_owned(),
            body,
        }
    }

    #[test]
    fn evaluates_protected_resources_and_audits_the_decision() {
        let mut core = core();
        let response = core
            .handle(
                1000,
                request(
                    "evaluate-1",
                    RequestBody::Evaluate {
                        session_id: "ssh.1000.1".to_owned(),
                        operation: ResourceOperation::new(
                            ProtectedAction::Delete,
                            "/var/www/releases/old",
                        )
                        .unwrap(),
                    },
                ),
                100,
            )
            .unwrap();
        assert!(matches!(
            response.body,
            ResponseBody::Decision {
                decision: EnforcementDecision::Blocked { .. }
            }
        ));
        assert_eq!(core.audit.records[0].action, "resource_evaluated");
        assert_eq!(core.audit.records[0].peer_uid, 1000);
    }

    #[test]
    fn maintenance_requires_root_and_authentication() {
        let grant = || {
            request(
                "grant-1",
                RequestBody::MaintenanceGrant {
                    scope: "/var/www/releases".into(),
                    actions: vec![ProtectedAction::Delete],
                    ttl_seconds: 300,
                    authenticator_code: "123456".to_owned(),
                },
            )
        };
        assert!(matches!(
            core().handle(1000, grant(), 100),
            Err(OsmanthusError::RootRequired)
        ));
        let mut invalid = core();
        let RequestBody::MaintenanceGrant {
            scope,
            actions,
            ttl_seconds,
            ..
        } = grant().body
        else {
            unreachable!()
        };
        assert!(matches!(
            invalid.handle(
                0,
                request(
                    "grant-invalid",
                    RequestBody::MaintenanceGrant {
                        scope,
                        actions,
                        ttl_seconds,
                        authenticator_code: "000000".to_owned(),
                    }
                ),
                100
            ),
            Err(OsmanthusError::InvalidCode)
        ));
    }

    #[test]
    fn maintenance_rejects_ttl_above_policy_maximum() {
        let mut core = core();
        assert!(matches!(
            core.handle(
                0,
                request(
                    "grant-too-long",
                    RequestBody::MaintenanceGrant {
                        scope: "/var/www".into(),
                        actions: vec![ProtectedAction::Delete],
                        ttl_seconds: DEFAULT_MAX_MAINTENANCE_SECONDS + 1,
                        authenticator_code: "123456".to_owned(),
                    },
                ),
                100,
            ),
            Err(OsmanthusError::InvalidState(message))
                if message.contains("configured maximum")
        ));
    }

    #[test]
    fn scoped_lease_allows_one_operation_class_until_expiry() {
        let mut core = core();
        let grant = core
            .handle(
                0,
                request(
                    "grant-1",
                    RequestBody::MaintenanceGrant {
                        scope: "/var/www/releases".into(),
                        actions: vec![ProtectedAction::Delete],
                        ttl_seconds: 300,
                        authenticator_code: "123456".to_owned(),
                    },
                ),
                100,
            )
            .unwrap();
        assert!(matches!(
            grant.body,
            ResponseBody::MaintenanceGranted { .. }
        ));
        let operation =
            ResourceOperation::new(ProtectedAction::Delete, "/var/www/releases/old").unwrap();
        let allowed = core
            .handle(
                1000,
                request(
                    "evaluate-1",
                    RequestBody::Evaluate {
                        session_id: "ssh.1000.1".to_owned(),
                        operation: operation.clone(),
                    },
                ),
                400,
            )
            .unwrap();
        assert!(matches!(
            allowed.body,
            ResponseBody::Decision {
                decision: EnforcementDecision::MaintenanceAllowed { .. }
            }
        ));
        let foreign = core
            .handle(
                PeerIdentity {
                    uid: 1000,
                    cgroup_id: 2,
                },
                request(
                    "evaluate-foreign",
                    RequestBody::Evaluate {
                        session_id: "ssh.1000.2".to_owned(),
                        operation: operation.clone(),
                    },
                ),
                400,
            )
            .unwrap();
        assert!(matches!(
            foreign.body,
            ResponseBody::Decision {
                decision: EnforcementDecision::Blocked { .. }
            }
        ));
        let expired = core
            .handle(
                1000,
                request(
                    "evaluate-2",
                    RequestBody::Evaluate {
                        session_id: "ssh.1000.1".to_owned(),
                        operation,
                    },
                ),
                401,
            )
            .unwrap();
        assert!(matches!(
            expired.body,
            ResponseBody::Decision {
                decision: EnforcementDecision::Blocked { .. }
            }
        ));
        assert!(
            core.audit
                .records
                .iter()
                .any(|record| record.action == "maintenance_expired")
        );
    }

    #[test]
    fn audit_failure_rolls_back_a_new_maintenance_lease() {
        let mut core = core();
        core.audit.fail = true;
        assert!(
            core.handle(
                0,
                request(
                    "grant-1",
                    RequestBody::MaintenanceGrant {
                        scope: "/var/www".into(),
                        actions: vec![ProtectedAction::Delete],
                        ttl_seconds: 300,
                        authenticator_code: "123456".to_owned(),
                    },
                ),
                100,
            )
            .is_err()
        );
        assert!(core.engine.maintenance_leases().is_empty());
    }

    #[test]
    fn decommission_requires_root_authentication_and_successful_audit() {
        let request = |code: &str| {
            request(
                "decommission-1",
                RequestBody::Decommission {
                    authenticator_code: code.to_owned(),
                },
            )
        };
        assert!(matches!(
            core().handle(1000, request("123456"), 100),
            Err(OsmanthusError::RootRequired)
        ));
        assert!(matches!(
            core().handle(0, request("000000"), 100),
            Err(OsmanthusError::InvalidCode)
        ));

        let mut failed_audit = core();
        failed_audit.audit.fail = true;
        assert!(failed_audit.handle(0, request("123456"), 100).is_err());
        assert_eq!(failed_audit.backend.state(), BackendState::Enforcing);
        assert!(!failed_audit.shutdown_requested());

        let mut valid = core();
        let response = valid.handle(0, request("123456"), 100).unwrap();
        assert!(matches!(response.body, ResponseBody::Decommissioned));
        assert_eq!(valid.backend.state(), BackendState::Unavailable);
        assert!(valid.shutdown_requested());
        assert_eq!(
            valid.audit.records.last().unwrap().action,
            "decommission_authorized"
        );
    }

    #[test]
    fn policy_reload_requires_root_and_replaces_the_active_boundary() {
        let replacement = EnforcementPolicy::new(vec![
            ProtectedRoot::new("/srv/app", actions(&[ProtectedAction::Delete])).unwrap(),
        ])
        .unwrap();
        assert!(matches!(
            core().handle(
                1000,
                request(
                    "reload-denied",
                    RequestBody::PolicyReload {
                        policy: replacement.clone()
                    }
                ),
                100
            ),
            Err(OsmanthusError::RootRequired)
        ));

        let mut core = core();
        let response = core
            .handle(
                0,
                request(
                    "reload-1",
                    RequestBody::PolicyReload {
                        policy: replacement,
                    },
                ),
                100,
            )
            .unwrap();
        assert!(matches!(response.body, ResponseBody::PolicyReloaded));
        assert!(matches!(
            core.engine.decide(
                &ResourceOperation::new(ProtectedAction::Delete, "/srv/app/data").unwrap(),
                100,
                1,
            ),
            EnforcementDecision::Blocked { .. }
        ));
        assert_eq!(core.audit.records.last().unwrap().action, "policy_reloaded");
    }

    #[test]
    fn policy_reload_is_rejected_during_maintenance() {
        let mut core = core();
        core.handle(
            0,
            request(
                "grant-1",
                RequestBody::MaintenanceGrant {
                    scope: "/var/www".into(),
                    actions: vec![ProtectedAction::Delete],
                    ttl_seconds: 300,
                    authenticator_code: "123456".to_owned(),
                },
            ),
            100,
        )
        .unwrap();
        let replacement = EnforcementPolicy::new(Vec::new()).unwrap();
        assert!(matches!(
            core.handle(
                0,
                request(
                    "reload-active-lease",
                    RequestBody::PolicyReload {
                        policy: replacement
                    }
                ),
                101
            ),
            Err(OsmanthusError::InvalidState(message)) if message.contains("maintenance lease")
        ));
    }

    #[test]
    fn monitored_session_records_input_output_and_exit() {
        let mut core = core();
        let session_id = "ssh.1000.test";
        let started = core
            .handle(
                1000,
                request(
                    "session-start",
                    RequestBody::SessionStart {
                        session_id: session_id.to_owned(),
                        shell: "/bin/bash".to_owned(),
                    },
                ),
                100,
            )
            .unwrap();
        assert!(matches!(started.body, ResponseBody::SessionAccepted));
        let data = data_encoding::BASE64.encode(b"echo safe\n");
        let recorded = core
            .handle(
                1000,
                request(
                    "session-data",
                    RequestBody::SessionData {
                        session_id: session_id.to_owned(),
                        direction: crate::protocol::SessionDirection::Input,
                        data_base64: data.clone(),
                    },
                ),
                101,
            )
            .unwrap();
        assert!(matches!(recorded.body, ResponseBody::SessionDataRecorded));
        let closed = core
            .handle(
                1000,
                request(
                    "session-end",
                    RequestBody::SessionEnd {
                        session_id: session_id.to_owned(),
                        exit_code: 0,
                    },
                ),
                102,
            )
            .unwrap();
        assert!(matches!(closed.body, ResponseBody::SessionClosed));
        assert_eq!(core.audit.records[1].target.as_deref(), Some(data.as_str()));
        assert!(core.sessions.is_empty());
    }

    #[test]
    fn shell_session_rejects_unenrolled_uid_and_cross_uid_writes() {
        let start = || {
            request(
                "session-start",
                RequestBody::SessionStart {
                    session_id: "ssh.test".to_owned(),
                    shell: "/bin/bash".to_owned(),
                },
            )
        };
        assert!(core().handle(2000, start(), 100).is_err());
        let mut core = core();
        core.handle(1000, start(), 100).unwrap();
        assert!(
            core.handle(
                2000,
                request(
                    "session-data",
                    RequestBody::SessionData {
                        session_id: "ssh.test".to_owned(),
                        direction: crate::protocol::SessionDirection::Output,
                        data_base64: data_encoding::BASE64.encode(b"forged"),
                    }
                ),
                101
            )
            .is_err()
        );
    }

    #[test]
    fn jsonl_audit_is_owner_only_and_rejects_permission_drift() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("log");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("audit.jsonl");
        let uid = unsafe { libc::geteuid() };
        let mut sink = JsonlDaemonAudit::open(&path, uid).unwrap();
        let record = DaemonAuditRecord {
            schema_version: 1,
            timestamp_unix: 100,
            action: "test",
            peer_uid: uid,
            peer_cgroup_id: Some(1),
            session_id: None,
            target: None,
            operation: None,
            decision: None,
            lease_id: None,
        };
        sink.append(&record).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(sink.append(&record).is_err());
    }
}
