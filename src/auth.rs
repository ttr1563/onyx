use std::path::Path;

use crate::config::{self, Config};
use crate::state::{self, EventStatus, GuardEvent, StateLock};
use crate::{OsmanthusError, Result};

pub fn approve_with_code(
    root: &Path,
    config: &Config,
    event_id: &str,
    code: &str,
    now: i64,
) -> Result<GuardEvent> {
    with_verified_code(root, config, code, now, || {
        let mut event = state::load_event(root, event_id)?;
        ensure_pending(&event, now)?;
        event.status = EventStatus::Approved;
        event.approved_at_unix = Some(now);
        event.approved_until_unix = Some(now + config.approval_ttl_seconds);
        state::save_event(root, &event)?;
        Ok(event)
    })
}

pub fn with_verified_code<T>(
    root: &Path,
    config: &Config,
    code: &str,
    now: i64,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let _lock = StateLock::acquire(root)?;
    let mut auth_state = config::load_auth_state(root)?;
    if let Some(until) = auth_state.locked_until_unix {
        if now < until {
            return Err(OsmanthusError::AuthenticationLocked(until - now));
        }
        auth_state.locked_until_unix = None;
        auth_state.failed_attempts = 0;
    }

    let counter = crate::totp::verify_code(&config.totp_secret_base32, code, now)?;
    let valid_counter = counter.filter(|candidate| {
        auth_state
            .last_accepted_counter
            .is_none_or(|previous| *candidate > previous)
    });
    let Some(counter) = valid_counter else {
        auth_state.failed_attempts += 1;
        if auth_state.failed_attempts >= config.max_auth_failures {
            auth_state.locked_until_unix = Some(now + config.auth_lock_seconds);
        }
        config::save_auth_state(root, &auth_state)?;
        return Err(OsmanthusError::InvalidCode);
    };

    auth_state.failed_attempts = 0;
    auth_state.locked_until_unix = None;
    auth_state.last_accepted_counter = Some(counter);
    config::save_auth_state(root, &auth_state)?;
    action()
}

pub fn ensure_pending(event: &GuardEvent, now: i64) -> Result<()> {
    if event.status != EventStatus::Pending {
        return Err(OsmanthusError::EventNotPending(event.id.clone()));
    }
    if now > event.expires_at_unix {
        return Err(OsmanthusError::EventExpired(event.id.clone()));
    }
    Ok(())
}
