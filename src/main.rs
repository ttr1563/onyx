use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use onyx_guard::audit::{self, AuditRecord};
use onyx_guard::auth;
use onyx_guard::config::{self, Config};
use onyx_guard::policy;
use onyx_guard::state::{self, EventStatus, GuardEvent, StateLock};
use onyx_guard::{OnyxError, Result};
use qrcode::QrCode;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const BLOCKED_EXIT_CODE: u8 = 77;

#[derive(Debug, Parser)]
#[command(name = "onyx", version, about)]
struct Cli {
    /// Override the state directory (or set ONYX_STATE_DIR).
    #[arg(long, global = true, value_name = "PATH")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize TOTP authentication and local audit storage.
    Init {
        #[arg(long, default_value = "Onyx")]
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
    /// List or add site-specific command policy rules.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// List custom policy rules. Built-in rules are always active.
    List,
    /// Add a custom rule. Every argument fragment must match.
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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliRisk {
    High,
    Critical,
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
        Err(OnyxError::InvalidCode) => {
            eprintln!("onyx: invalid authenticator code");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("onyx: {error}");
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
    }
}

fn initialize(root: &Path, issuer: String, account: Option<String>, no_qr: bool) -> Result<u8> {
    let account = account.unwrap_or_else(default_account);
    let config = Config::new(issuer, account)?;
    config::initialize(root, &config)?;

    let record = AuditRecord::new("initialized")?;
    audit::append(root, &record)?;

    let uri = config.totp_uri();
    println!("Onyx initialized at {}", root.display());
    if !no_qr {
        let code = QrCode::new(uri.as_bytes())
            .map_err(|error| OnyxError::InvalidState(format!("failed to render QR: {error}")))?;
        let rendered = code
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .build();
        println!("\nScan this QR code with a TOTP authenticator:\n{rendered}");
    }
    println!("TOTP URI (shown once): {uri}");
    println!("Audit log: {}", root.join(config::AUDIT_FILE).display());
    println!("Run commands with: onyx run -- <command>");
    let record = AuditRecord::new("enrollment_displayed")?;
    audit::append(root, &record)?;
    Ok(0)
}

fn check_command(root: &Path, command: Vec<OsString>) -> Result<u8> {
    if command.is_empty() {
        return Err(OnyxError::MissingCommand);
    }
    let custom = if root.join(config::POLICY_FILE).exists() {
        config::validate_state_root(root)?;
        policy::PolicyFile::load(root)?.rules
    } else {
        Vec::new()
    };
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
        return Err(OnyxError::MissingCommand);
    }
    let config = config::load_config(root)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let digest = state::command_digest(&command);
    let summary = policy::summarize(&command);
    let policy_file = policy::PolicyFile::load(root)?;
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

    eprintln!("BLOCKED by Onyx");
    eprintln!("Event: {}", event.id);
    eprintln!("Rules: {}", event.rule_ids.join(", "));
    eprintln!("Approve: onyx approve {}", event.id);
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
        Err(OnyxError::InvalidCode) => {
            let event = state::load_event(root, event_id)?;
            let mut record = AuditRecord::new("approval_failed")?;
            record.event_id = Some(&event.id);
            record.command_digest = Some(&event.command_digest);
            audit::append(root, &record)?;
            return Err(OnyxError::InvalidCode);
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
    println!("Onyx initialized: yes");
    println!("State directory: {}", root.display());
    println!("Authenticator: TOTP ({})", config.account);
    println!("Pending events: {pending}");
    println!("Active one-time permits: {approved}");
    println!("Audit log: {}", root.join(config::AUDIT_FILE).display());
    Ok(0)
}

fn logs(root: &Path, limit: usize) -> Result<u8> {
    if !(1..=1000).contains(&limit) {
        return Err(OnyxError::InvalidState(
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
    config::load_config(root)?;
    match command {
        PolicyCommands::List => {
            let policy = policy::PolicyFile::load(root)?;
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
            Ok(0)
        }
        PolicyCommands::Add {
            id,
            executable,
            argument_contains,
            risk,
            reason,
        } => {
            let _lock = StateLock::acquire(root)?;
            let mut policy_file = policy::PolicyFile::load(root)?;
            let rule = policy::CustomRule {
                id,
                executable,
                argument_contains,
                risk: risk.into(),
                reason,
            };
            let rule_id = rule.id.clone();
            policy_file.add(rule)?;
            policy_file.save(root)?;
            let rule_ids = [rule_id.clone()];
            let mut record = AuditRecord::new("policy_rule_added")?;
            record.rule_ids = Some(&rule_ids);
            audit::append(root, &record)?;
            println!("Added custom policy rule: {rule_id}");
            Ok(0)
        }
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
            return Err(OnyxError::Execution(error.to_string()));
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
