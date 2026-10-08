use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use osmanthus_guard::audit::{self, AuditRecord};
use osmanthus_guard::auth;
use osmanthus_guard::config::{self, Config};
use osmanthus_guard::enforcement::{
    MAX_MAINTENANCE_SECONDS, MaintenanceSettings, ProtectedAction, ProtectedRoot, ResourceOperation,
};
use osmanthus_guard::login_shell;
use osmanthus_guard::policy;
use osmanthus_guard::policy::PolicyFile;
use osmanthus_guard::protocol::{RequestBody, ResponseBody};
use osmanthus_guard::state::{self, EventStatus, GuardEvent, StateLock};
use osmanthus_guard::system_policy;
use osmanthus_guard::{OsmanthusError, Result};
use qrcode::{EcLevel, QrCode, render::unicode::Dense1x2};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const BLOCKED_EXIT_CODE: u8 = 77;

#[derive(Debug, Parser)]
#[command(name = "osmanthus", version, about)]
struct Cli {
    /// Override the state directory (or set OSMANTHUS_STATE_DIR).
    #[arg(long, global = true, value_name = "PATH")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize TOTP authentication and local audit storage.
    Init {
        #[arg(long, default_value = "Osmanthus")]
        issuer: String,
        #[arg(long)]
        account: Option<String>,
        /// Do not render a terminal QR code.
        #[arg(long)]
        no_qr: bool,
    },
    /// Evaluate and, when permitted, execute a command.
    Run {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Evaluate a command without creating an event or executing it.
    Check {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Approve one blocked event using a TOTP authenticator code.
    Approve { event_id: String },
    /// Show initialization and event status.
    Status,
    /// Print recent JSONL audit records.
    Logs {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Manage site-specific command policy rules.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Grant, inspect, or revoke a scoped temporary maintenance lease.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommands,
    },
    /// Inspect the privileged enforcement daemon.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonCommands {
    /// Show daemon version and kernel backend state.
    Status,
    /// Authenticated removal of persistent kernel enforcement before uninstall.
    Decommission,
}

#[derive(Debug, Subcommand)]
enum MaintenanceCommands {
    /// Temporarily allow selected operations below one protected root.
    Grant {
        #[arg(long)]
        path: PathBuf,
        #[arg(long = "action", value_enum, required = true)]
        actions: Vec<CliProtectedAction>,
        #[arg(long = "for")]
        duration: Option<String>,
    },
    /// Temporarily allow every configured action below one protected path.
    Pause {
        #[arg(long)]
        path: PathBuf,
        #[arg(long = "for")]
        duration: Option<String>,
    },
    /// List active maintenance leases.
    List,
    /// Revoke one maintenance lease before it expires.
    Revoke { lease_id: String },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Initialize root-owned system policy and its administrator authenticator.
    Init {
        #[arg(long, default_value = "Osmanthus Policy")]
        issuer: String,
        #[arg(long)]
        account: Option<String>,
        /// Do not render a terminal QR code.
        #[arg(long)]
        no_qr: bool,
    },
    /// List custom policy rules. Built-in rules are always active.
    List,
    /// Add a system rule after root and authenticator verification.
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        executable: String,
        #[arg(long = "argument-contains")]
        argument_contains: Vec<String>,
        #[arg(long, value_enum, default_value_t = CliRisk::High)]
        risk: CliRisk,
        #[arg(long)]
        reason: String,
    },
    /// Remove a system rule after root and authenticator verification.
    Remove {
        #[arg(long)]
        id: String,
    },
    /// Manage protected filesystem roots for enforced monitoring.
    Protect {
        #[command(subcommand)]
        command: ProtectCommands,
    },
    /// Manage operating-system identities whose process executions are logged.
    Monitor {
        #[command(subcommand)]
        command: MonitorCommands,
    },
    /// Rotate the policy-administrator authenticator after current-code verification.
    Auth {
        #[command(subcommand)]
        command: PolicyAuthCommands,
    },
    /// Configure default and maximum scoped-maintenance durations.
    Maintenance {
        #[command(subcommand)]
        command: PolicyMaintenanceCommands,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyMaintenanceCommands {
    /// Change maintenance defaults after administrator authentication.
    Set {
        #[arg(long)]
        default: String,
        #[arg(long)]
        maximum: String,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyAuthCommands {
    /// Issue a new TOTP enrollment and invalidate the previous secret.
    Rotate {
        #[arg(long)]
        account: Option<String>,
        /// Do not render a terminal QR code.
        #[arg(long)]
        no_qr: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProtectCommands {
    /// Add a protected root after administrator authentication.
    Add {
        #[arg(long)]
        path: PathBuf,
        #[arg(long = "action", value_enum, required = true)]
        actions: Vec<CliProtectedAction>,
    },
    /// Remove a protected root after administrator authentication.
    Remove {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum MonitorCommands {
    /// Add one numeric operating-system user ID to automatic exec monitoring.
    Add {
        uid: u32,
        /// Original shell to launch through osmanthus-shell for terminal transcripts.
        #[arg(long)]
        shell: Option<PathBuf>,
    },
    /// Remove one numeric operating-system user ID from automatic exec monitoring.
    Remove { uid: u32 },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliRisk {
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliProtectedAction {
    Delete,
    Rename,
    Truncate,
    Write,
    ChangePermissions,
}

impl From<CliProtectedAction> for ProtectedAction {
    fn from(value: CliProtectedAction) -> Self {
        match value {
            CliProtectedAction::Delete => Self::Delete,
            CliProtectedAction::Rename => Self::Rename,
            CliProtectedAction::Truncate => Self::Truncate,
            CliProtectedAction::Write => Self::Write,
            CliProtectedAction::ChangePermissions => Self::ChangePermissions,
        }
    }
}

impl From<CliRisk> for policy::RiskLevel {
    fn from(value: CliRisk) -> Self {
        match value {
            CliRisk::High => Self::High,
            CliRisk::Critical => Self::Critical,
        }
    }
}

fn main() -> ExitCode {
    match run_cli(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(OsmanthusError::InvalidCode) => {
            eprintln!("osmanthus: invalid authenticator code");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("osmanthus: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(cli: Cli) -> Result<u8> {
    let root = config::state_dir(cli.state_dir.as_deref())?;
    match cli.command {
        Commands::Init {
            issuer,
            account,
            no_qr,
        } => initialize(&root, issuer, account, no_qr),
        Commands::Run { command } => run_command(&root, command),
        Commands::Check { command } => check_command(&root, command),
        Commands::Approve { event_id } => approve(&root, &event_id),
        Commands::Status => status(&root),
        Commands::Logs { limit } => logs(&root, limit),
        Commands::Policy { command } => policy_command(&root, command),
        Commands::Maintenance { command } => maintenance_command(command),
        Commands::Daemon { command } => daemon_command(command),
    }
}

fn daemon_command(command: DaemonCommands) -> Result<u8> {
    match command {
        DaemonCommands::Status => match daemon_request(RequestBody::Health)? {
            ResponseBody::Health {
                daemon_version,
                backend,
            } => {
                println!("osmanthusd: active");
                println!("Version: {daemon_version}");
                println!("Kernel backend: {backend:?}");
                Ok(0)
            }
            other => unexpected_daemon_response(other),
        },
        DaemonCommands::Decommission => {
            system_policy::require_root()?;
            let policy =
                system_policy::load()?.ok_or(OsmanthusError::SystemPolicyNotInitialized)?;
            if !policy.monitored_shells.is_empty() {
                return Err(OsmanthusError::InvalidState(
                    "restore every monitored login with `sudo osmanthus policy monitor remove UID` before decommission"
                        .to_owned(),
                ));
            }
            let code = Zeroizing::new(rpassword::prompt_password("Authenticator code: ")?);
            match daemon_request(RequestBody::Decommission {
                authenticator_code: code.to_string(),
            })? {
                ResponseBody::Decommissioned => {
                    println!("Osmanthus kernel enforcement decommissioned; osmanthusd stopped.");
                    Ok(0)
                }
                other => unexpected_daemon_response(other),
            }
        }
    }
}

fn maintenance_command(command: MaintenanceCommands) -> Result<u8> {
    system_policy::require_root()?;
    match command {
        MaintenanceCommands::Grant {
            path,
            actions,
            duration,
        } => grant_maintenance(
            path,
            actions.into_iter().map(Into::into).collect(),
            duration.as_deref(),
        ),
        MaintenanceCommands::Pause { path, duration } => {
            let scope = ResourceOperation::new(ProtectedAction::Delete, &path)?.target;
            let policy =
                system_policy::load()?.ok_or(OsmanthusError::SystemPolicyNotInitialized)?;
            let actions = policy.protected_actions_for_scope(&scope)?;
            grant_maintenance(scope, actions, duration.as_deref())
        }
        MaintenanceCommands::List => match daemon_request(RequestBody::MaintenanceList)? {
            ResponseBody::MaintenanceList { leases } => {
                if leases.is_empty() {
                    println!("No active maintenance leases.");
                }
                for lease in leases {
                    let actions = lease
                        .actions
                        .iter()
                        .map(|action| format!("{action:?}").to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{}\t{}\t{}\t{}\tcgroup:{}",
                        lease.id,
                        lease.scope.display(),
                        actions,
                        lease.expires_at_unix,
                        lease.cgroup_id,
                    );
                }
                Ok(0)
            }
            other => unexpected_daemon_response(other),
        },
        MaintenanceCommands::Revoke { lease_id } => {
            uuid::Uuid::parse_str(&lease_id).map_err(|_| {
                OsmanthusError::InvalidState("maintenance lease ID is invalid".to_owned())
            })?;
            let code = Zeroizing::new(rpassword::prompt_password("Authenticator code: ")?);
            match daemon_request(RequestBody::MaintenanceRevoke {
                lease_id,
                authenticator_code: code.to_string(),
            })? {
                ResponseBody::MaintenanceRevoked => {
                    println!("Maintenance lease revoked.");
                    Ok(0)
                }
                other => unexpected_daemon_response(other),
            }
        }
    }
}

fn grant_maintenance(
    path: PathBuf,
    actions: Vec<ProtectedAction>,
    duration: Option<&str>,
) -> Result<u8> {
    let scope = ResourceOperation::new(ProtectedAction::Delete, path)?.target;
    let policy = system_policy::load()?.ok_or(OsmanthusError::SystemPolicyNotInitialized)?;
    let ttl_seconds = duration
        .map(parse_duration_seconds)
        .transpose()?
        .unwrap_or(policy.maintenance.default_ttl_seconds);
    if ttl_seconds > policy.maintenance.max_ttl_seconds {
        return Err(OsmanthusError::InvalidState(format!(
            "maintenance duration exceeds the configured maximum of {} seconds",
            policy.maintenance.max_ttl_seconds
        )));
    }
    let code = Zeroizing::new(rpassword::prompt_password("Authenticator code: ")?);
    match daemon_request(RequestBody::MaintenanceGrant {
        scope,
        actions,
        ttl_seconds,
        authenticator_code: code.to_string(),
    })? {
        ResponseBody::MaintenanceGranted {
            lease_id,
            expires_at_unix,
        } => {
            println!("Maintenance lease: {lease_id}");
            println!("Expires at Unix time: {expires_at_unix}");
            println!(
                "Bound to current cgroup: {}",
                osmanthus_guard::linux_daemon::current_cgroup_id()?
            );
            Ok(0)
        }
        other => unexpected_daemon_response(other),
    }
}

fn daemon_request(body: RequestBody) -> Result<ResponseBody> {
    osmanthus_guard::daemon_client::request(body)
}

fn unexpected_daemon_response<T>(response: ResponseBody) -> Result<T> {
    Err(OsmanthusError::InvalidState(format!(
        "unexpected daemon response: {response:?}"
    )))
}

fn parse_duration_seconds(value: &str) -> Result<i64> {
    let (digits, multiplier) = if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3_600)
    } else {
        (value, 1)
    };
    let amount = digits.parse::<i64>().map_err(|_| {
        OsmanthusError::InvalidState(
            "maintenance duration must use seconds, minutes, or hours".to_owned(),
        )
    })?;
    let seconds = amount.checked_mul(multiplier).ok_or_else(|| {
        OsmanthusError::InvalidState("maintenance duration is too large".to_owned())
    })?;
    if !(1..=MAX_MAINTENANCE_SECONDS).contains(&seconds) {
        return Err(OsmanthusError::InvalidState(format!(
            "maintenance duration must be between 1s and {}h",
            MAX_MAINTENANCE_SECONDS / 3_600
        )));
    }
    Ok(seconds)
}

fn initialize(root: &Path, issuer: String, account: Option<String>, no_qr: bool) -> Result<u8> {
    let account = account.unwrap_or_else(default_account);
    let config = Config::new(issuer, account)?;
    config::initialize(root, &config)?;

    let record = AuditRecord::new("initialized")?;
    audit::append(root, &record)?;

    println!("Osmanthus initialized at {}", root.display());
    println!("Audit log: {}", root.join(config::AUDIT_FILE).display());
    println!("Run commands with: osmanthus run -- <command>");
    print_enrollment(&config, no_qr)?;
    let record = AuditRecord::new("enrollment_displayed")?;
    audit::append(root, &record)?;
    Ok(0)
}

fn print_enrollment(config: &Config, no_qr: bool) -> Result<()> {
    let uri = config.totp_uri();
    println!("TOTP URI (shown once): {uri}");
    if !no_qr {
        let rendered = render_enrollment_qr(&uri)?;
        println!("\nScan this QR code with a TOTP authenticator:\n{rendered}");
    }
    Ok(())
}

fn render_enrollment_qr(uri: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::L)
        .map_err(|error| OsmanthusError::InvalidState(format!("failed to render QR: {error}")))?;
    Ok(code
        .render::<Dense1x2>()
        .quiet_zone(false)
        .module_dimensions(1, 1)
        .build())
}

fn check_command(root: &Path, command: Vec<OsString>) -> Result<u8> {
    if command.is_empty() {
        return Err(OsmanthusError::MissingCommand);
    }
    let custom = load_effective_policy(root)?.rules;
    let findings = policy::evaluate_with_rules(&command, &custom);
    if findings.is_empty() {
        println!("allow: no built-in rule matched");
        return Ok(0);
    }
    for finding in findings {
        println!(
            "block: {} ({:?}) - {}",
            finding.rule_id, finding.risk, finding.reason
        );
    }
    Ok(BLOCKED_EXIT_CODE)
}

fn run_command(root: &Path, command: Vec<OsString>) -> Result<u8> {
    if command.is_empty() {
        return Err(OsmanthusError::MissingCommand);
    }
    let config = config::load_config(root)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let digest = state::command_digest(&command);
    let summary = policy::summarize(&command);
    let policy_file = load_effective_policy(root)?;
    let findings = policy::evaluate_with_rules(&command, &policy_file.rules);

    if findings.is_empty() {
        let mut record = AuditRecord::new("allowed")?;
        record.command_digest = Some(&digest);
        record.command = Some(&summary);
        audit::append(root, &record)?;
        return execute_and_record(root, command, digest, summary, None);
    }

    let _lock = StateLock::acquire(root)?;
    if let Some(event) = state::consume_matching_permit(root, &digest, now)? {
        let mut record = AuditRecord::new("permit_consumed")?;
        record.event_id = Some(&event.id);
        record.command_digest = Some(&digest);
        record.command = Some(&summary);
        record.rule_ids = Some(&event.rule_ids);
        audit::append(root, &record)?;
        drop(_lock);
        return execute_and_record(root, command, digest, summary, Some(event.id));
    }

    let event = GuardEvent::new(
        now,
        config.event_ttl_seconds,
        digest.clone(),
        summary.clone(),
        &findings,
    );
    state::save_event(root, &event)?;
    let mut record = AuditRecord::new("blocked")?;
    record.event_id = Some(&event.id);
    record.command_digest = Some(&digest);
    record.command = Some(&summary);
    record.rule_ids = Some(&event.rule_ids);
    audit::append(root, &record)?;

    eprintln!("BLOCKED by Osmanthus");
    eprintln!("Event: {}", event.id);
    eprintln!("Rules: {}", event.rule_ids.join(", "));
    eprintln!("Approve: osmanthus approve {}", event.id);
    eprintln!("Then rerun the exact command within the approval window.");
    Ok(BLOCKED_EXIT_CODE)
}

fn approve(root: &Path, event_id: &str) -> Result<u8> {
    let config = config::load_config(root)?;
    let preview = state::load_event(root, event_id)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    auth::ensure_pending(&preview, now)?;

    println!("Event: {}", preview.id);
    println!("Risk: {:?}", preview.risk);
    println!("Rules: {}", preview.rule_ids.join(", "));
    println!("Command: {}", preview.command.join(" "));
    let code = Zeroizing::new(rpassword::prompt_password("Authenticator code: ")?);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let event = match auth::approve_with_code(root, &config, event_id, &code, now) {
        Ok(event) => event,
        Err(OsmanthusError::InvalidCode) => {
            let event = state::load_event(root, event_id)?;
            let mut record = AuditRecord::new("approval_failed")?;
            record.event_id = Some(&event.id);
            record.command_digest = Some(&event.command_digest);
            audit::append(root, &record)?;
            return Err(OsmanthusError::InvalidCode);
        }
        Err(error) => return Err(error),
    };
    let mut record = AuditRecord::new("approved")?;
    record.event_id = Some(&event.id);
    record.command_digest = Some(&event.command_digest);
    record.rule_ids = Some(&event.rule_ids);
    audit::append(root, &record)?;

    println!(
        "Approved once for {} seconds. Rerun the exact command.",
        config.approval_ttl_seconds
    );
    Ok(0)
}

fn status(root: &Path) -> Result<u8> {
    let config = config::load_config(root)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let events = state::list_events(root)?;
    let pending = events
        .iter()
        .filter(|event| event.status == EventStatus::Pending && event.expires_at_unix >= now)
        .count();
    let approved = events
        .iter()
        .filter(|event| {
            event.status == EventStatus::Approved
                && event.approved_until_unix.is_some_and(|until| until >= now)
        })
        .count();
    println!("Osmanthus initialized: yes");
    println!("State directory: {}", root.display());
    println!("Authenticator: TOTP ({})", config.account);
    println!("Pending events: {pending}");
    println!("Active one-time permits: {approved}");
    println!(
        "System policy: {}",
        if system_policy::load()?.is_some() {
            "root-managed"
        } else {
            "not initialized (legacy user policy)"
        }
    );
    println!("Audit log: {}", root.join(config::AUDIT_FILE).display());
    Ok(0)
}

fn logs(root: &Path, limit: usize) -> Result<u8> {
    if !(1..=1000).contains(&limit) {
        return Err(OsmanthusError::InvalidState(
            "log limit must be between 1 and 1000".to_owned(),
        ));
    }
    config::load_config(root)?;
    let path = root.join(config::AUDIT_FILE);
    config::validate_private_path(&path)?;
    let file = fs::File::open(path)?;
    let mut lines = VecDeque::with_capacity(limit);
    for line in io::BufReader::new(file).lines() {
        if lines.len() == limit {
            lines.pop_front();
        }
        lines.push_back(line?);
    }
    for line in lines {
        println!("{line}");
    }
    Ok(0)
}

fn policy_command(root: &Path, command: PolicyCommands) -> Result<u8> {
    match command {
        PolicyCommands::Init {
            issuer,
            account,
            no_qr,
        } => initialize_system_policy(issuer, account, no_qr),
        PolicyCommands::List => {
            let (source, policy) = match system_policy::load()? {
                Some(policy) => ("system", policy),
                None => {
                    config::load_config(root)?;
                    ("legacy user", policy::PolicyFile::load(root)?)
                }
            };
            println!("Policy source: {source}");
            println!(
                "Maintenance duration: default={}s, maximum={}s",
                policy.maintenance.default_ttl_seconds, policy.maintenance.max_ttl_seconds
            );
            if policy.rules.is_empty() {
                println!("No custom rules. Built-in rules remain active.");
            }
            for rule in policy.rules {
                println!(
                    "{}\t{:?}\t{}\t{}\t{}",
                    rule.id,
                    rule.risk,
                    rule.executable,
                    rule.argument_contains.join(" && "),
                    rule.reason
                );
            }
            if policy.protected_roots.is_empty() {
                println!("No protected filesystem roots.");
            }
            for root in policy.protected_roots {
                let actions = root
                    .actions()
                    .iter()
                    .map(|action| format!("{action:?}"))
                    .collect::<Vec<_>>()
                    .join(",");
                println!("protected-root\t{}\t{actions}", root.path().display());
            }
            for uid in policy.monitored_uids {
                let shell = policy
                    .monitored_shells
                    .get(&uid)
                    .map_or("exec-only".to_owned(), |path| path.display().to_string());
                println!("monitored-uid\t{uid}\t{shell}");
            }
            Ok(0)
        }
        PolicyCommands::Add {
            id,
            executable,
            argument_contains,
            risk,
            reason,
        } => mutate_system_policy("add", |policy_file| {
            let rule = policy::CustomRule {
                id: id.clone(),
                executable: executable.clone(),
                argument_contains: argument_contains.clone(),
                risk: risk.into(),
                reason: reason.clone(),
            };
            let rule_id = rule.id.clone();
            policy_file.add(rule)?;
            Ok((rule_id, "policy_rule_added", "Added system policy rule"))
        }),
        PolicyCommands::Remove { id } => mutate_system_policy("remove", |policy_file| {
            let removed = policy_file.remove(&id)?;
            Ok((
                removed.id,
                "policy_rule_removed",
                "Removed system policy rule",
            ))
        }),
        PolicyCommands::Protect { command } => match command {
            ProtectCommands::Add { path, actions } => {
                osmanthus_guard::linux_bpf::validate_protected_root_path(&path)?;
                mutate_system_policy("protect add", |policy_file| {
                    let actions = actions.iter().copied().map(Into::into).collect();
                    let root = ProtectedRoot::new(&path, actions)?;
                    let display = root.path().display().to_string();
                    policy_file.add_protected_root(root)?;
                    Ok((
                        display,
                        "protected_root_added",
                        "Added protected filesystem root",
                    ))
                })
            }
            ProtectCommands::Remove { path } => {
                mutate_system_policy("protect remove", |policy_file| {
                    let normalized = ResourceOperation::new(ProtectedAction::Delete, &path)?.target;
                    let removed = policy_file.remove_protected_root(&normalized)?;
                    Ok((
                        removed.path().display().to_string(),
                        "protected_root_removed",
                        "Removed protected filesystem root",
                    ))
                })
            }
        },
        PolicyCommands::Monitor { command } => match command {
            MonitorCommands::Add { uid, shell } => {
                if let Some(expected_shell) = &shell {
                    login_shell::validate_osmanthus_shell()?;
                    login_shell::validate_real_shell(expected_shell)?;
                    let account = login_shell::account(uid)?;
                    if account.shell != *expected_shell {
                        return Err(OsmanthusError::InvalidState(format!(
                            "UID {uid} currently uses {}; --shell must name the current real shell",
                            account.shell.display()
                        )));
                    }
                }
                mutate_system_policy_with_hooks(
                    "monitor add",
                    |policy_file| {
                        policy_file.add_monitored_uid(uid, shell.clone())?;
                        Ok((
                            uid.to_string(),
                            "monitored_uid_added",
                            "Added monitored UID",
                        ))
                    },
                    apply_login_shell_transition,
                    rollback_login_shell_transition,
                )
            }
            MonitorCommands::Remove { uid } => mutate_system_policy_with_hooks(
                "monitor remove",
                |policy_file| {
                    policy_file.remove_monitored_uid(uid)?;
                    Ok((
                        uid.to_string(),
                        "monitored_uid_removed",
                        "Removed monitored UID",
                    ))
                },
                apply_login_shell_transition,
                rollback_login_shell_transition,
            ),
        },
        PolicyCommands::Auth { command } => match command {
            PolicyAuthCommands::Rotate { account, no_qr } => {
                rotate_policy_authenticator(account, no_qr)
            }
        },
        PolicyCommands::Maintenance { command } => match command {
            PolicyMaintenanceCommands::Set { default, maximum } => {
                let default_ttl_seconds = parse_duration_seconds(&default)?;
                let max_ttl_seconds = parse_duration_seconds(&maximum)?;
                let settings = MaintenanceSettings {
                    default_ttl_seconds,
                    max_ttl_seconds,
                };
                settings.validate()?;
                mutate_system_policy("maintenance set", |policy_file| {
                    policy_file.set_maintenance(settings)?;
                    Ok((
                        format!("default={default_ttl_seconds}s,max={max_ttl_seconds}s"),
                        "maintenance_settings_changed",
                        "Changed maintenance duration settings",
                    ))
                })
            }
        },
    }
}

fn rotate_policy_authenticator(account: Option<String>, no_qr: bool) -> Result<u8> {
    system_policy::require_root()?;
    let admin_root = system_policy::admin_state_dir();
    let current = config::load_config(admin_root).map_err(|error| match error {
        OsmanthusError::NotInitialized => OsmanthusError::SystemPolicyNotInitialized,
        other => other,
    })?;
    let mut replacement = Config::new(
        current.issuer.clone(),
        account.unwrap_or_else(|| current.account.clone()),
    )?;
    replacement.approval_ttl_seconds = current.approval_ttl_seconds;
    replacement.event_ttl_seconds = current.event_ttl_seconds;
    replacement.max_auth_failures = current.max_auth_failures;
    replacement.auth_lock_seconds = current.auth_lock_seconds;
    let code = Zeroizing::new(rpassword::prompt_password("Current authenticator code: ")?);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    auth::with_verified_code(admin_root, &current, &code, now, || {
        let previous_state = config::load_auth_state(admin_root)?;
        config::replace_authenticator(admin_root, &replacement, &config::AuthState::default())?;
        let mut record = AuditRecord::new("policy_authenticator_rotated")?;
        record.result = Some(0);
        if let Err(error) = audit::append(admin_root, &record) {
            config::replace_authenticator(admin_root, &current, &previous_state).map_err(
                |rollback_error| {
                    OsmanthusError::InvalidState(format!(
                        "authenticator audit failed ({error}); rollback also failed ({rollback_error})"
                    ))
                },
            )?;
            return Err(error);
        }
        Ok(())
    })?;
    println!("Policy administrator authenticator rotated.");
    print_enrollment(&replacement, no_qr)?;
    println!("The previous TOTP secret is no longer accepted.");
    Ok(0)
}

fn load_effective_policy(root: &Path) -> Result<PolicyFile> {
    if let Some(policy) = system_policy::load()? {
        return Ok(policy);
    }
    if root.join(config::POLICY_FILE).exists() {
        config::validate_state_root(root)?;
        return policy::PolicyFile::load(root);
    }
    Ok(PolicyFile::default())
}

fn initialize_system_policy(issuer: String, account: Option<String>, no_qr: bool) -> Result<u8> {
    system_policy::require_root()?;
    let account = account.unwrap_or_else(default_account);
    let admin_config = Config::new(issuer, account)?;
    system_policy::initialize(&admin_config)?;
    let mut record = AuditRecord::new("system_policy_initialized")?;
    record.result = Some(0);
    audit::append(system_policy::admin_state_dir(), &record)?;

    println!(
        "System policy initialized at {}",
        system_policy::SYSTEM_POLICY_DIR
    );
    print_enrollment(&admin_config, no_qr)?;
    println!("Policy changes require sudo and this authenticator.");
    Ok(0)
}

fn mutate_system_policy(
    action: &str,
    mutation: impl Fn(&mut PolicyFile) -> Result<(String, &'static str, &'static str)>,
) -> Result<u8> {
    mutate_system_policy_with_hooks(action, mutation, |_, _| Ok(()), |_, _| Ok(()))
}

fn mutate_system_policy_with_hooks(
    action: &str,
    mutation: impl Fn(&mut PolicyFile) -> Result<(String, &'static str, &'static str)>,
    apply: impl Fn(&PolicyFile, &PolicyFile) -> Result<()>,
    rollback: impl Fn(&PolicyFile, &PolicyFile) -> Result<()>,
) -> Result<u8> {
    system_policy::require_root()?;
    let admin_root = system_policy::admin_state_dir();
    let admin_config = config::load_config(admin_root).map_err(|error| match error {
        OsmanthusError::NotInitialized => OsmanthusError::SystemPolicyNotInitialized,
        other => other,
    })?;
    let mut preview = system_policy::load()?.ok_or(OsmanthusError::SystemPolicyNotInitialized)?;
    let (rule_id, _, _) = mutation(&mut preview)?;
    println!("System policy {action}: {rule_id}");
    let code = Zeroizing::new(rpassword::prompt_password("Authenticator code: ")?);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    auth::with_verified_code(admin_root, &admin_config, &code, now, || {
        let mut current =
            system_policy::load()?.ok_or(OsmanthusError::SystemPolicyNotInitialized)?;
        let previous = current.clone();
        let (rule_id, audit_action, success_message) = mutation(&mut current)?;
        system_policy::save(&current)?;
        if let Err(error) = reload_daemon_policy(&current) {
            restore_policy_and_daemon(&previous).map_err(|rollback_error| {
                OsmanthusError::InvalidState(format!(
                    "daemon policy reload failed ({error}); rollback also failed ({rollback_error})"
                ))
            })?;
            return Err(error);
        }
        if let Err(error) = apply(&previous, &current) {
            restore_policy_mutation(&previous, &current, &rollback).map_err(|rollback_error| {
                OsmanthusError::InvalidState(format!(
                    "policy hook failed ({error}); rollback also failed ({rollback_error})"
                ))
            })?;
            return Err(error);
        }
        let rule_ids = [rule_id.clone()];
        let mut record = AuditRecord::new(audit_action)?;
        record.rule_ids = Some(&rule_ids);
        if let Err(error) = audit::append(admin_root, &record) {
            restore_policy_mutation(&previous, &current, &rollback).map_err(|rollback_error| {
                OsmanthusError::InvalidState(format!(
                    "policy audit failed ({error}); rollback also failed ({rollback_error})"
                ))
            })?;
            return Err(error);
        }
        println!("{success_message}: {rule_id}");
        Ok(0)
    })
}

fn restore_policy_mutation(
    previous: &PolicyFile,
    current: &PolicyFile,
    rollback: &impl Fn(&PolicyFile, &PolicyFile) -> Result<()>,
) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) = rollback(previous, current) {
        failures.push(format!("external state: {error}"));
    }
    if let Err(error) = restore_policy_and_daemon(previous) {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(OsmanthusError::InvalidState(failures.join("; ")))
    }
}

fn restore_policy_and_daemon(previous: &PolicyFile) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) = system_policy::save(previous) {
        failures.push(format!("policy file: {error}"));
    }
    if let Err(error) = reload_daemon_policy(previous) {
        failures.push(format!("daemon policy: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(OsmanthusError::InvalidState(failures.join("; ")))
    }
}

fn apply_login_shell_transition(previous: &PolicyFile, current: &PolicyFile) -> Result<()> {
    change_login_shell(previous, current)
}

fn rollback_login_shell_transition(previous: &PolicyFile, current: &PolicyFile) -> Result<()> {
    change_login_shell(current, previous)
}

fn change_login_shell(from: &PolicyFile, to: &PolicyFile) -> Result<()> {
    let changed_uids = from
        .monitored_uids
        .symmetric_difference(&to.monitored_uids)
        .copied()
        .collect::<Vec<_>>();
    if changed_uids.len() != 1 {
        return Err(OsmanthusError::InvalidState(
            "a monitor mutation must change exactly one UID".to_owned(),
        ));
    }
    let uid = changed_uids[0];
    match (
        from.monitored_shells.get(&uid),
        to.monitored_shells.get(&uid),
    ) {
        (None, Some(real_shell)) => {
            login_shell::ensure_registered()?;
            login_shell::set_shell(uid, real_shell, Path::new(login_shell::OSMANTHUS_SHELL))
        }
        (Some(real_shell), None) => {
            login_shell::set_shell(uid, Path::new(login_shell::OSMANTHUS_SHELL), real_shell)
        }
        (None, None) => Ok(()),
        (Some(_), Some(_)) => Err(OsmanthusError::InvalidState(
            "changing a monitored UID shell in place is not supported".to_owned(),
        )),
    }
}

fn reload_daemon_policy(policy: &PolicyFile) -> Result<()> {
    let enforcement = osmanthus_guard::enforcement::EnforcementPolicy::from_parts_with_maintenance(
        policy.protected_roots.clone(),
        policy.monitored_uids.clone(),
        policy.maintenance,
    )?;
    match daemon_request(RequestBody::PolicyReload {
        policy: enforcement,
    })? {
        ResponseBody::PolicyReloaded => Ok(()),
        other => unexpected_daemon_response(other),
    }
}

fn execute_and_record(
    root: &Path,
    command: Vec<OsString>,
    digest: String,
    summary: Vec<String>,
    event_id: Option<String>,
) -> Result<u8> {
    let status = match Command::new(&command[0]).args(&command[1..]).status() {
        Ok(status) => status,
        Err(error) => {
            let mut record = AuditRecord::new("execution_failed")?;
            record.event_id = event_id.as_deref();
            record.command_digest = Some(&digest);
            record.command = Some(&summary);
            audit::append(root, &record)?;
            return Err(OsmanthusError::Execution(error.to_string()));
        }
    };
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    let mut record = AuditRecord::new("completed")?;
    record.event_id = event_id.as_deref();
    record.command_digest = Some(&digest);
    record.command = Some(&summary);
    record.result = Some(code);
    audit::append(root, &record)?;
    Ok(u8::try_from(code).unwrap_or(1))
}

fn default_account() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "linux-server".to_owned())
}
