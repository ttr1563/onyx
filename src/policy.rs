use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{self, POLICY_FILE};
use crate::enforcement::{EnforcementPolicy, MaintenanceSettings, ProtectedAction, ProtectedRoot};
use crate::{OsmanthusError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub risk: RiskLevel,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub executable: String,
    #[serde(default)]
    pub argument_contains: Vec<String>,
    pub risk: RiskLevel,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub schema_version: u32,
    pub rules: Vec<CustomRule>,
    #[serde(default)]
    pub protected_roots: Vec<ProtectedRoot>,
    #[serde(default)]
    pub monitored_uids: std::collections::BTreeSet<u32>,
    #[serde(default)]
    pub monitored_shells: std::collections::BTreeMap<u32, PathBuf>,
    #[serde(default)]
    pub maintenance: MaintenanceSettings,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            rules: Vec::new(),
            protected_roots: Vec::new(),
            monitored_uids: std::collections::BTreeSet::new(),
            monitored_shells: std::collections::BTreeMap::new(),
            maintenance: MaintenanceSettings::default(),
        }
    }
}

impl PolicyFile {
    pub fn load(root: &Path) -> Result<Self> {
        let policy: Self = config::load_private_json(&root.join(POLICY_FILE))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        self.validate()?;
        config::atomic_write_json(&root.join(POLICY_FILE), self)
    }

    pub fn add(&mut self, rule: CustomRule) -> Result<()> {
        validate_rule(&rule)?;
        if self.rules.iter().any(|existing| existing.id == rule.id) {
            return Err(OsmanthusError::InvalidState(format!(
                "policy rule already exists: {}",
                rule.id
            )));
        }
        self.rules.push(rule);
        self.rules.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<CustomRule> {
        let index = self
            .rules
            .iter()
            .position(|rule| rule.id == id)
            .ok_or_else(|| OsmanthusError::InvalidState(format!("policy rule not found: {id}")))?;
        Ok(self.rules.remove(index))
    }

    pub fn add_protected_root(&mut self, root: ProtectedRoot) -> Result<()> {
        if self
            .protected_roots
            .iter()
            .any(|existing| existing.path() == root.path())
        {
            return Err(OsmanthusError::InvalidState(format!(
                "protected root already exists: {}",
                root.path().display()
            )));
        }
        let mut candidate = self.clone();
        candidate.protected_roots.push(root);
        candidate
            .protected_roots
            .sort_by(|left, right| left.path().cmp(right.path()));
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn remove_protected_root(&mut self, path: &Path) -> Result<ProtectedRoot> {
        let index = self
            .protected_roots
            .iter()
            .position(|root| root.path() == path)
            .ok_or_else(|| {
                OsmanthusError::InvalidState(format!(
                    "protected root not found: {}",
                    path.display()
                ))
            })?;
        Ok(self.protected_roots.remove(index))
    }

    pub fn protected_actions_for_scope(&self, scope: &Path) -> Result<Vec<ProtectedAction>> {
        let root = self
            .protected_roots
            .iter()
            .filter(|root| scope.starts_with(root.path()))
            .max_by_key(|root| root.path().components().count())
            .ok_or_else(|| {
                OsmanthusError::InvalidState(format!(
                    "maintenance pause path is outside every protected root: {}",
                    scope.display()
                ))
            })?;
        Ok(root.actions().iter().copied().collect())
    }

    pub fn add_monitored_uid(&mut self, uid: u32, shell: Option<PathBuf>) -> Result<()> {
        if let Some(shell) = &shell {
            validate_shell(shell)?;
        }
        if self.monitored_uids.contains(&uid) {
            return Err(OsmanthusError::InvalidState(format!(
                "monitored UID already exists: {uid}"
            )));
        }
        let mut candidate = self.clone();
        candidate.monitored_uids.insert(uid);
        if let Some(shell) = shell {
            candidate.monitored_shells.insert(uid, shell);
        }
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn remove_monitored_uid(&mut self, uid: u32) -> Result<()> {
        if !self.monitored_uids.remove(&uid) {
            return Err(OsmanthusError::InvalidState(format!(
                "monitored UID not found: {uid}"
            )));
        }
        self.monitored_shells.remove(&uid);
        Ok(())
    }

    pub fn set_maintenance(&mut self, settings: MaintenanceSettings) -> Result<()> {
        settings.validate()?;
        self.maintenance = settings;
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(OsmanthusError::InvalidState(format!(
                "unsupported policy schema version: {}",
                self.schema_version
            )));
        }
        if self.rules.len() > 1_000 {
            return Err(OsmanthusError::InvalidState(
                "policy contains more than 1000 custom rules".to_owned(),
            ));
        }
        let mut ids = std::collections::HashSet::new();
        for rule in &self.rules {
            validate_rule(rule)?;
            if !ids.insert(&rule.id) {
                return Err(OsmanthusError::InvalidState(format!(
                    "duplicate policy rule: {}",
                    rule.id
                )));
            }
        }
        EnforcementPolicy::from_parts_with_maintenance(
            self.protected_roots.clone(),
            self.monitored_uids.clone(),
            self.maintenance,
        )?;
        for (uid, shell) in &self.monitored_shells {
            if !self.monitored_uids.contains(uid) {
                return Err(OsmanthusError::InvalidState(format!(
                    "shell configured for unmonitored UID: {uid}"
                )));
            }
            validate_shell(shell)?;
        }
        Ok(())
    }
}

fn validate_shell(shell: &Path) -> Result<()> {
    if !shell.is_absolute()
        || shell.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(OsmanthusError::InvalidState(format!(
            "monitored shell must be a canonical absolute path: {}",
            shell.display()
        )));
    }
    if shell == Path::new("/usr/bin/osmanthus-shell") || shell == Path::new("/usr/bin/onyx-shell") {
        return Err(OsmanthusError::InvalidState(
            "monitored shell cannot point to an Osmanthus or legacy Onyx supervisor".to_owned(),
        ));
    }
    Ok(())
}

pub fn evaluate(command: &[OsString]) -> Vec<Finding> {
    let Some(program) = command
        .first()
        .and_then(|value| Path::new(value).file_name())
    else {
        return Vec::new();
    };
    let program = program.to_string_lossy();
    let args: Vec<String> = command[1..]
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    let mut findings = Vec::new();

    if program == "rm" && recursive_force(&args) && destructive_operand(&args) {
        findings.push(Finding {
            rule_id: "destructive-recursive-delete".to_owned(),
            risk: RiskLevel::Critical,
            reason: "recursive forced deletion of an absolute or current-directory target"
                .to_owned(),
        });
    }
    if matches!(program.as_ref(), "mkfs" | "wipefs") || program.starts_with("mkfs.") {
        findings.push(Finding {
            rule_id: "filesystem-destruction".to_owned(),
            risk: RiskLevel::Critical,
            reason: "filesystem formatting or signature removal".to_owned(),
        });
    }
    if program == "dd"
        && args.iter().any(|arg| {
            arg.strip_prefix("of=")
                .is_some_and(|path| path.starts_with("/dev/"))
        })
    {
        findings.push(Finding {
            rule_id: "raw-device-write".to_owned(),
            risk: RiskLevel::Critical,
            reason: "raw write to a device".to_owned(),
        });
    }
    if matches!(
        program.as_ref(),
        "shutdown" | "reboot" | "poweroff" | "halt"
    ) {
        findings.push(Finding {
            rule_id: "host-power-state".to_owned(),
            risk: RiskLevel::High,
            reason: "host shutdown or reboot".to_owned(),
        });
    }
    if program == "sudo" {
        findings.push(Finding {
            rule_id: "privilege-escalation".to_owned(),
            risk: RiskLevel::High,
            reason: "command requests execution through sudo".to_owned(),
        });
    }
    if matches!(program.as_ref(), "bash" | "sh" | "zsh" | "dash" | "ksh")
        && args.iter().any(|arg| arg == "-c")
    {
        findings.push(Finding {
            rule_id: "shell-command-string".to_owned(),
            risk: RiskLevel::High,
            reason: "shell command strings cannot be safely classified as argument vectors"
                .to_owned(),
        });
    }
    if program == "find"
        && args.first().is_some_and(|arg| arg.starts_with('/'))
        && args.iter().any(|arg| arg == "-delete")
    {
        findings.push(Finding {
            rule_id: "recursive-find-delete".to_owned(),
            risk: RiskLevel::Critical,
            reason: "find deletes entries below an absolute path".to_owned(),
        });
    }
    if matches!(program.as_ref(), "chmod" | "chown")
        && has_recursive_flag(&args)
        && args.iter().any(|arg| arg == "/" || arg == "/*")
    {
        findings.push(Finding {
            rule_id: "recursive-root-permission-change".to_owned(),
            risk: RiskLevel::Critical,
            reason: "recursive ownership or permission change at filesystem root".to_owned(),
        });
    }
    if matches!(
        program.as_ref(),
        "curl" | "wget" | "scp" | "rsync" | "nc" | "ncat"
    ) && args.iter().any(|arg| contains_sensitive_path(arg))
    {
        findings.push(Finding {
            rule_id: "sensitive-file-transfer".to_owned(),
            risk: RiskLevel::Critical,
            reason: "network transfer command references a sensitive path".to_owned(),
        });
    }
    if matches!(program.as_ref(), "bash" | "sh" | "zsh")
        && args
            .windows(2)
            .any(|pair| pair[0] == "-c" && (pair[1].contains("base64") && pair[1].contains("eval")))
    {
        findings.push(Finding {
            rule_id: "encoded-shell-evaluation".to_owned(),
            risk: RiskLevel::High,
            reason: "shell evaluates base64-decoded content".to_owned(),
        });
    }

    findings
}

pub fn evaluate_with_rules(command: &[OsString], rules: &[CustomRule]) -> Vec<Finding> {
    let mut findings = evaluate(command);
    let Some(program) = command
        .first()
        .and_then(|value| Path::new(value).file_name())
    else {
        return findings;
    };
    let program = program.to_string_lossy();
    let args: Vec<String> = command[1..]
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    for rule in rules {
        let arguments_match = rule
            .argument_contains
            .iter()
            .all(|needle| args.iter().any(|argument| argument.contains(needle)));
        if program == rule.executable && arguments_match {
            findings.push(Finding {
                rule_id: rule.id.clone(),
                risk: rule.risk,
                reason: rule.reason.clone(),
            });
        }
    }
    findings
}

pub fn validate_rule(rule: &CustomRule) -> Result<()> {
    let valid_id = !rule.id.is_empty()
        && rule.id.len() <= 64
        && rule
            .id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && rule.id.bytes().next().is_some_and(|byte| byte != b'-');
    if !valid_id {
        return Err(OsmanthusError::InvalidState(
            "policy rule ID must be 1-64 lowercase letters, digits, or hyphens and must not start with a hyphen"
                .to_owned(),
        ));
    }
    if rule.executable.is_empty()
        || rule.executable.len() > 128
        || rule.executable.chars().any(char::is_control)
        || Path::new(&rule.executable).file_name() != Some(OsStr::new(&rule.executable))
    {
        return Err(OsmanthusError::InvalidState(
            "policy executable must be a basename of 1-128 bytes".to_owned(),
        ));
    }
    if rule.argument_contains.len() > 16
        || rule.argument_contains.iter().any(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        })
    {
        return Err(OsmanthusError::InvalidState(
            "a policy rule may contain up to 16 non-empty argument fragments of at most 256 bytes"
                .to_owned(),
        ));
    }
    if rule.reason.trim().is_empty()
        || rule.reason.len() > 256
        || rule.reason.chars().any(char::is_control)
    {
        return Err(OsmanthusError::InvalidState(
            "policy reason must be 1-256 bytes".to_owned(),
        ));
    }
    Ok(())
}

pub fn summarize(command: &[OsString]) -> Vec<String> {
    command.iter().map(|arg| redact(arg)).collect()
}

fn redact(value: &OsStr) -> String {
    let text = value.to_string_lossy();
    let lower = text.to_ascii_lowercase();
    if ["password", "passwd", "token", "secret", "api_key", "apikey"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        if let Some((name, _)) = text.split_once('=') {
            return format!("{name}=<redacted>");
        }
        return "<redacted>".to_owned();
    }
    const MAX: usize = 256;
    if text.chars().count() > MAX {
        let mut shortened: String = text.chars().take(MAX).collect();
        shortened.push('…');
        shortened
    } else {
        sanitize_display(&text)
    }
}

fn sanitize_display(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            sanitized.extend(character.escape_default());
        } else {
            sanitized.push(character);
        }
    }
    sanitized
}

fn recursive_force(args: &[String]) -> bool {
    let recursive = args.iter().any(|arg| {
        arg == "--recursive"
            || (arg.starts_with('-')
                && !arg.starts_with("--")
                && (arg.contains('r') || arg.contains('R')))
    });
    let force = args.iter().any(|arg| {
        arg == "--force" || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('f'))
    });
    recursive && force
}

fn has_recursive_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--recursive"
            || arg == "-R"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('R'))
    })
}

fn destructive_operand(args: &[String]) -> bool {
    args.iter()
        .filter(|arg| !arg.starts_with('-'))
        .any(|arg| arg == "." || arg == "./" || arg == ".." || arg == "../" || arg.starts_with('/'))
}

fn contains_sensitive_path(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    [
        ".env",
        "/.ssh/",
        "/etc/shadow",
        "/etc/sudoers",
        "credentials",
        "id_rsa",
        "id_ed25519",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn blocks_recursive_absolute_delete() {
        let findings = evaluate(&command(&["rm", "-rf", "/var/www/data"]));
        assert_eq!(findings[0].rule_id, "destructive-recursive-delete");
        assert!(!evaluate(&command(&["rm", "-Rf", "/var/www/data"])).is_empty());
    }

    #[test]
    fn allows_relative_build_cleanup() {
        assert!(evaluate(&command(&["rm", "-rf", "target"])).is_empty());
    }

    #[test]
    fn blocks_common_wrapper_bypasses() {
        assert!(
            evaluate(&command(&["sudo", "rm", "-rf", "/var/www/data"]))
                .iter()
                .any(|finding| finding.rule_id == "privilege-escalation")
        );
        assert!(
            evaluate(&command(&["sh", "-c", "rm -rf /var/www/data"]))
                .iter()
                .any(|finding| finding.rule_id == "shell-command-string")
        );
        assert!(
            evaluate(&command(&["find", "/var/www", "-type", "f", "-delete"]))
                .iter()
                .any(|finding| finding.rule_id == "recursive-find-delete")
        );
    }

    #[test]
    fn blocks_sensitive_transfer() {
        let findings = evaluate(&command(&["curl", "-F", "file=@/root/.ssh/id_ed25519"]));
        assert_eq!(findings[0].rule_id, "sensitive-file-transfer");
    }

    #[test]
    fn redacts_secret_arguments() {
        assert_eq!(redact(OsStr::new("--token=abc")), "--token=<redacted>");
        assert_eq!(redact(OsStr::new("safe\u{1b}[2J")), "safe\\u{1b}[2J");
    }

    #[test]
    fn custom_rule_requires_all_fragments() {
        let rule = CustomRule {
            id: "production-terraform".to_owned(),
            executable: "terraform".to_owned(),
            argument_contains: vec!["apply".to_owned(), "production".to_owned()],
            risk: RiskLevel::Critical,
            reason: "production infrastructure change".to_owned(),
        };
        assert!(
            evaluate_with_rules(
                &command(&["terraform", "apply", "production.tfplan"]),
                std::slice::from_ref(&rule),
            )
            .iter()
            .any(|finding| finding.rule_id == rule.id)
        );
        assert!(
            evaluate_with_rules(
                &command(&["terraform", "plan", "production.tfplan"]),
                &[rule],
            )
            .is_empty()
        );
    }

    #[test]
    fn rejects_unsafe_custom_rule_identifiers() {
        let rule = CustomRule {
            id: "../replace-policy".to_owned(),
            executable: "rm".to_owned(),
            argument_contains: Vec::new(),
            risk: RiskLevel::High,
            reason: "test".to_owned(),
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn removes_custom_rule_by_id() {
        let mut policy = PolicyFile::default();
        let rule = CustomRule {
            id: "production-terraform".to_owned(),
            executable: "terraform".to_owned(),
            argument_contains: vec!["apply".to_owned()],
            risk: RiskLevel::Critical,
            reason: "production infrastructure change".to_owned(),
        };
        policy.add(rule.clone()).unwrap();

        assert_eq!(policy.remove(&rule.id).unwrap().id, rule.id);
        assert!(policy.rules.is_empty());
        assert!(policy.remove("missing-rule").is_err());
    }

    #[test]
    fn legacy_policy_json_defaults_to_no_protected_roots() {
        let policy: PolicyFile =
            serde_json::from_str(r#"{"schema_version":1,"rules":[]}"#).unwrap();
        assert!(policy.protected_roots.is_empty());
        assert!(policy.monitored_uids.is_empty());
        assert!(policy.monitored_shells.is_empty());
        assert_eq!(policy.maintenance, MaintenanceSettings::default());
        policy.validate().unwrap();
    }

    #[test]
    fn maintenance_settings_are_bounded_and_persisted() {
        let mut policy = PolicyFile::default();
        let settings = MaintenanceSettings {
            default_ttl_seconds: 3_600,
            max_ttl_seconds: 28_800,
        };
        policy.set_maintenance(settings).unwrap();
        assert_eq!(policy.maintenance, settings);
        assert!(
            policy
                .set_maintenance(MaintenanceSettings {
                    default_ttl_seconds: 28_801,
                    max_ttl_seconds: 28_800,
                })
                .is_err()
        );
    }

    #[test]
    fn monitored_uid_can_have_a_separate_real_shell() {
        let mut policy = PolicyFile::default();
        policy
            .add_monitored_uid(1000, Some(PathBuf::from("/bin/bash")))
            .unwrap();
        assert_eq!(
            policy.monitored_shells.get(&1000),
            Some(&PathBuf::from("/bin/bash"))
        );
        policy.remove_monitored_uid(1000).unwrap();
        assert!(policy.monitored_shells.is_empty());
        assert!(
            policy
                .add_monitored_uid(1000, Some(PathBuf::from("/usr/bin/osmanthus-shell")))
                .is_err()
        );
        assert!(
            policy
                .add_monitored_uid(1000, Some(PathBuf::from("/usr/bin/onyx-shell")))
                .is_err()
        );
        assert!(!policy.monitored_uids.contains(&1000));
    }

    #[test]
    fn pause_uses_the_most_specific_protected_root_actions() {
        let mut policy = PolicyFile::default();
        policy
            .add_protected_root(
                ProtectedRoot::new("/srv/app", [ProtectedAction::Delete].into_iter().collect())
                    .unwrap(),
            )
            .unwrap();
        policy
            .add_protected_root(
                ProtectedRoot::new(
                    "/srv/app/database",
                    [ProtectedAction::Write].into_iter().collect(),
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            policy
                .protected_actions_for_scope(Path::new("/srv/app/database/data"))
                .unwrap(),
            vec![ProtectedAction::Write]
        );
        assert!(
            policy
                .protected_actions_for_scope(Path::new("/srv/other"))
                .is_err()
        );
    }
}
